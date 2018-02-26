# Copyright (C) Italo Valcy S Brito <italovalcy@ufba.br>
#               Adriana V Ribeiro <adrianavr@dcc.ufba.br>
#
# Simple application that runs BGP, packet mirror to IDS and REST 
# API for an IPS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event,dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3,ofproto_v1_0
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib import mac
from ryu.lib import ofctl_v1_0
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from webob import Response
import networkx as nx
import json
import jsonpickle
import socket, os
import struct
import re
from threading import Thread
from time import sleep

myapp_name = 'sdnips_app'
base_url = '/sdnips'

REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'Success'
REST_NG = 'failure'

def ipv4_text_to_int(ip_text):
    if ip_text == 0 or not isinstance(ip_text, str):
        return ip_text
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]

class SDNIPSApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SDNIPSApp, self).__init__(*args, **kwargs)
        self.net = nx.DiGraph()
        wsgi = kwargs['wsgi']
        wsgi.register(SDNIPSWSGIApp,{myapp_name: self})
        self.eline_map = {}
        self.bgp_config = {}
        self.bgp_speaker = None
        self.rcv_prefixes = []
        self.flows = {}
        self.contention_vrf = {}
        self.quarantine = {}
        load_config_thread = Thread(target=self.load_config, args=())
        load_config_thread.start()

    def __exit__(self, exc_type, exc_value, traceback):
        for prefix in self.rcv_prefixes:
            os.system('/sbin/ip route del %s' % prefix)

    def load_config(self):
        try:
            with open('sdn-ips-config.json', 'r') as fp:
                data = jsonpickle.decode(fp.read())
        except Exception as e:
            print "Fail to load SDN-IPS config. Error: %s" % (e)
            return

        retry=0
        sleep(15)
        while set(data['nodes']) != set(self.net.nodes()) and retry < 10:
            print "Nodes are missing or topology is different! Trying in 15s.."
            sleep(15)
            retry += 1

        if retry == 10:
            print "Could not load config because some nodes are missing or topology is different!"
            return

        # Reinstall flows
        for dpid in data.get('flows', []):
            for flow in data['flows'][dpid]:
                dp = self.net.node[int(dpid)]['conn']
                self.add_flow(dp, flow['priority'],
                        flow['match'], flow['actions'])

        # Recreate BGP speaker
        if 'as_number' in data['bgp'] and 'router_id' in  data['bgp']:
            self.bgp_create(data['bgp']['as_number'], str(data['bgp']['router_id']))
            for neigh in data['bgp'].get('neighbors', []):
                neigh['address'] = str(neigh['address'])
                self.bgp_add_neighbor(**neigh)
            for prefix in data['bgp'].get('adv_prefixes', []):
                self.bgp_add_prefix(str(prefix))

        # save contention VRF
        self.contention_vrf = data['contention_vrf']

    def persist_config(self):
        data = {}
        # Topology information
        data['nodes'] = self.net.nodes()
        # BGP config
        data['bgp'] = self.bgp_config
        # OpenFlow rules
        data['flows'] = self.flows
        # Contention VRF
        data['contention_vrf'] = self.contention_vrf

        try:
            with open('sdn-ips-config.json', 'w') as fp:
                fp.write(jsonpickle.encode(data))
        except Exception as e:
            print "Fail to save SDN-IPS config! Error: %s" % (e)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        ofproto = ev.dp.ofproto
        if ev.enter:
            ports = {}
            for p in ev.ports:
                if p.port_no != ofproto.OFPP_LOCAL:
                    ports[p.port_no] = {'name' : p.name, 'hw_addr' : p.hw_addr}
            self.net.add_node(ev.dp.id, **{'ports': ports, 'conn': ev.dp})
            print 'OFPStateChange switch entered: dpid=%s' % (dpid_lib.dpid_to_str(ev.dp.id))
        else:
            print 'OFPStateChange switch leaves: dpid=%s' % (dpid_lib.dpid_to_str(ev.dp.id))
            self.net.remove_node(ev.dp.id)

    topo_events = [event.EventSwitchEnter, event.EventPortAdd, event.EventLinkAdd]
    @set_ev_cls(topo_events)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        links_list = get_link(self, None)
        links = []
        for link in links_list:
            # check for unwanted nodes and links
            if link.src.dpid not in self.net.nodes() or link.dst.dpid not in self.net.nodes():
                continue
            if self.net.has_edge(link.src.dpid, link.dst.dpid):
                continue
            links.append((link.src.dpid,link.dst.dpid,{'sport':link.src.port_no, 'dport':link.dst.port_no}))
        if not links:
            return
        print "Update graph edges:"
        for l in links:
            print "==> %s:%d <-> %s:%d" % (
                    dpid_lib.dpid_to_str(l[0]),
                    l[2]['sport'],
                    dpid_lib.dpid_to_str(l[1]),
                    l[2]['dport'])
        self.net.add_edges_from(links)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # invalidate all previews rules
        clear = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE)
        datapath.send_msg(clear)

        # install table-miss flow entry
        match = {}
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 65530, match, actions, visible=False)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and str(ip_pkt.src) in self.quarantine:
            vlan_pkt = pkt.get_protocol(vlan.vlan)
            vlan_id = 0
            if vlan_pkt:
                vlan_id = vlan_pkt.vid
            if vlan_id not in self.eline_map:
                print "Error: packet received from an infected host but with wrong vlanid"
                return
            redirect_to = self.quarantine[str(ip_pkt.src)]
            self.contention_quarantine_redirect(msg.datapath, ip_pkt, redirect_to, vlan_id)
            return

        print "PacketIn dpid=%s inport=%s src=%s dst=%s ethertype=0x%04x" % \
                (dpid, msg.in_port, eth_pkt.src, eth_pkt.dst, eth_pkt.ethertype)

    def get_access_ports(self, sw):
        if sw not in self.net.nodes():
            return None
        ports = self.net.node[sw]['ports'].keys()
        for e in self.net.edge[sw]:
            ports.remove(self.net.edge[sw][e]['sport'])
        return ports

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, visible=True):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_ofp = self.build_match(datapath, **match)
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                match=match_ofp, actions=actions)
        datapath.send_msg(mod)

        if visible:
            self.flows.setdefault(datapath.id, [])
            self.flows[datapath.id].append({'match': match, 'priority': priority, 'actions':actions})
            self.persist_config()

    def build_match(self, datapath, in_port=0, dl_type=0, dl_src=0, dl_dst=0, 
                 dl_vlan=0,nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, nw_tos=None, tp_src=0, tp_dst=0):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        # Match
        nw_tos = 0
        wildcards = ofp.OFPFW_ALL
        if in_port:
            wildcards &= ~ofp.OFPFW_IN_PORT
        if dl_type:
            wildcards &= ~ofp.OFPFW_DL_TYPE
        if dl_src:
            wildcards &= ~ofp.OFPFW_DL_SRC
        if dl_dst:
            wildcards &= ~ofp.OFPFW_DL_DST
        if dl_vlan:
            wildcards &= ~ofp.OFPFW_DL_VLAN
        if nw_tos:
            wildcards &= ~ofp.OFPFW_NW_TOS
        if nw_src:
            v = (32 - src_mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
        if nw_dst:
            v = (32 - dst_mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ofp.OFPFW_NW_DST_MASK
            wildcards &= v
        if nw_proto:
            wildcards &= ~ofp.OFPFW_NW_PROTO
        if tp_src:
            wildcards &= ~ofp.OFPFW_TP_SRC
        if tp_dst:
            wildcards &= ~ofp.OFPFW_TP_DST

        match = ofp_parser.OFPMatch(wildcards, in_port, dl_src, dl_dst, dl_vlan, 0,
                                    dl_type, nw_tos, nw_proto,
                                    nw_src, nw_dst, tp_src, tp_dst, src_mask, dst_mask)
        return match

    def create_eline(self, uniA_sw, uniA_port, uniB_sw, uniB_port, vlanid):
        # sanity check
        if vlanid in self.eline_map:
            return (False, "E-line already exists with the same vlan_id! Choose another vlanid")

        path = nx.shortest_path(self.net, uniA_sw, uniB_sw)
        print "==> create_eline(UNI-A=%s:%s, UNI-B=%s:%s, vlanid=%d): %s" % \
                (uniA_sw, uniA_port, uniB_sw, uniB_port, vlanid, path)
        for i in range(len(path)):
            sw = path[i]
            buff_id = None
            if i == 0: # first switch
                match_in_port = uniA_port
            else:
                prev_sw = path[i-1]
                match_in_port = self.net.edge[prev_sw][sw]['dport']
            if i == len(path)-1:
                action_out_port = uniB_port
            else:
                next_sw = path[i+1]
                action_out_port = self.net.edge[sw][next_sw]['sport']
            dp = self.net.node[sw]['conn']
            # uniA -> uniB
            self.logger.info("==> add_flow sw=%s (->) in_port=%s vlanid=%d action_out_port=%s", sw, match_in_port, vlanid, action_out_port)
            match = {'in_port': match_in_port, 'dl_vlan':vlanid}
            actions = [dp.ofproto_parser.OFPActionOutput(action_out_port)]
            self.add_flow(dp, 65533, match, actions)
            # uniB -> uniA
            match_in_port, action_out_port = action_out_port, match_in_port
            self.logger.info("==> add_flow sw=%s (<-) in_port=%s vlanid=%d action_out_port=%s", sw, match_in_port, vlanid, action_out_port)
            match = {'in_port':match_in_port, 'dl_vlan':vlanid}
            actions = [dp.ofproto_parser.OFPActionOutput(action_out_port)]
            self.add_flow(dp, 65533, match, actions)

        uniA_bkbport = self.net.edge[uniA_sw][path[1]]['sport']
        uniB_bkbport = self.net.edge[path[-2]][uniB_sw]['dport']
        self.eline_map.setdefault(vlanid, {})
        self.eline_map[vlanid][uniA_sw] = {'access_port': uniA_port, 'bkb_port': uniA_bkbport}
        self.eline_map[vlanid][uniB_sw] = {'access_port': uniB_port, 'bkb_port': uniB_bkbport}

        return (True, 'Success')

    def bgp_create(self, as_number, router_id):
        # MUDAR AQUI - INICIO
        try:
            self.bgp_speaker = BGPSpeaker(as_number=as_number, router_id=router_id,
                            best_path_change_handler=self.best_path_change_handler,
                            adj_rib_in_change_handler=self.adj_rib_in_change_handler,
                            peer_down_handler=self.peer_down_handler,
                            peer_up_handler=self.peer_up_handler)
        except Exception as e:
            print "Error creating bgp speaker: %s" % (e)
            return (False, 'Failed to create BGP speaker')
        # MUDAR AQUI - FIM

        self.bgp_config['as_number'] = as_number
        self.bgp_config['router_id'] = router_id
        self.bgp_config['neighbors'] = []
        self.bgp_config['adv_prefixes'] = []
        self.persist_config()
        return (True, 'Success')

    def bgp_add_neighbor(self, address, remote_as):
        # MUDAR AQUI - INICIO
        try:
            self.bgp_speaker.neighbor_add(address, remote_as)
        except Exception as e:
            print "Error on bgp_add_neighbor: %s" % (e)
            return (False, 'Failed to add BGP neighbor')
        # MUDAR AQUI - FIM

        self.bgp_config['neighbors'].append({'address': address,
            'remote_as': remote_as})
        self.persist_config()
        return (True, 'Success')

    def bgp_add_prefix(self, prefix):
        # MUDAR AQUI - INICIO
        try:
            self.bgp_speaker.prefix_add(prefix)
        except Exception as e:
            print "Error on bgp_add_prefix: %s" % (e)
            return (False, 'Failed to add prefix')
        # MUDAR AQUI - FIM

        self.bgp_config['adv_prefixes'].append(prefix)
        self.persist_config()
        return (True, 'Success')

    def best_path_change_handler(self, event):
        action = 'del' if event.is_withdraw else 'add'
        print 'the best path changed: remote-as=%s prefix=%s next-hop=%s action=%s' % \
                (event.remote_as, event.prefix, event.nexthop, action)
        os.system('/sbin/sysctl net.ipv4.ip_forward=1')
        os.system('/sbin/ip route %s %s via %s' % (action, event.prefix, event.nexthop))
        if event.is_withdraw:
            try:
                self.rcv_prefixes.remove(event.prefix)
            except:
                pass
        else:
            self.rcv_prefixes.append(event.prefix)
    
    def peer_down_handler(self, remote_ip, remote_as):
        print 'Peer down:', remote_ip, remote_as

    def peer_up_handler(self, remote_ip, remote_as):
        print 'Peer up:', remote_ip, remote_as

    def flow_create_mirror(self, dpid, flow, to_port):
        try:
            dp = self.net.node[dpid]['conn']
        except:
            return (False, 'dpid not found!')
        parser = dp.ofproto_parser

        new_action = parser.OFPActionOutput(to_port)

        # check if the port is already on flow actions, and just return
        # in this case since we have nothing to do
        if new_action in flow['actions']:
            return (True, 'Success - to_port already in flow actions')

        flow['actions'].append(new_action)

        try:
            match_ofp = self.build_match(dp, **flow['match'])
            mod = parser.OFPFlowMod(datapath=dp, priority=flow['priority'],
                                command=dp.ofproto.OFPFC_MODIFY_STRICT,
                                match=match_ofp, actions=flow['actions'])
            dp.send_msg(mod)
        except Exception as e:
            return(False, 'Error installing flow_mod: %s' % (e))

        return(True, 'Success')

    def flows_create_mirror(self, dpid, flows, target_sw, target_port):
        try:
            path = nx.shortest_path(self.net, dpid, target_sw)
        except:
            return (False, 'Failed to create mirror! Could not find a path from %s to %s' % (dpid_lib.dpid_to_str(dpid), dpid_lib.dpid_to_str(target_sw)))

        # determine the first output port for remote mirroring
        if len(path) == 1:
            return (False, 'Failed to create mirror. Currently we dont support mirror to the same switch')

        # for the first switch, we just modify the openflow rules adding a new action
        # to output the traffic to the next switch (remote mirroring)
        next_sw = path[1]
        first_port = self.net.edge[dpid][next_sw]['sport']
        for flow in flows:
            self.flow_create_mirror(dpid, flow, first_port)

        for i in range(1, len(path)):
            sw = path[i]
            dp = self.net.node[sw]['conn']
            prev_sw = path[i-1]
            match_in_port = self.net.edge[prev_sw][sw]['dport']

            actions = []
            if i == len(path)-1:
                action_out_port = target_port
                actions.append(dp.ofproto_parser.OFPActionSetDlDst(mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')))
            else:
                next_sw = path[i+1]
                action_out_port = self.net.edge[sw][next_sw]['sport']

            match = {'in_port': match_in_port}
            actions.append(dp.ofproto_parser.OFPActionOutput(action_out_port))
            self.add_flow(dp, 65533, match, actions)

        return(True, 'Success')

    # contention_add_vrf(rtcomm, nexthop)
    #  - rtcomm: Route-Target Community, describes the VRF
    #  - nexthop: ipv4 address which will be used for redirect
    #
    # Add a fake VRF which will be used just for traffic
    # redirection to a nexthop. Usefull for FlowSpec redirect
    # action, since draft-simpson-idr-flowspec-redirect-02 is
    # not yet avaliable
    def contention_add_vrf(self, rtcomm, nexthop):
        self.contention_vrf[rtcomm] = nexthop
        self.persist_config()
        return(True, 'Success')

    def contention_quarantine(self, ipaddr, redirect_to):
        for sw in self.net.nodes():
            dp = self.net.node[sw]['conn']
            actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER)]
            for port in self.get_access_ports(sw):
                for vlan in self.eline_map:
                    # the dl_vlan match is a workaround because flowvisor seems to bug when using
                    # dl_type=0x0800
                    match = {'in_port': port, 'dl_type': 0x0800, 'dl_vlan': vlan, 'nw_src': ipaddr}
                    self.add_flow(dp, 65534, match, actions)
        self.quarantine[ipaddr] = redirect_to
        return (True, 'Success')

    def contention_block(self, ipaddr):
        print "==> contention_block ipaddr=%s in all switches" % (ipaddr)
        actions = []
        for sw in self.net.nodes():
            dp = self.net.node[sw]['conn']
            for port in self.get_access_ports(sw):
                for vlan in self.eline_map:
                    # the dl_vlan match is a workaround because flowvisor seems to bug when using
                    # dl_type=0x0800
                    match = {'in_port': port, 'dl_type': 0x0800, 'dl_vlan': vlan, 'nw_src': ipaddr}
                    self.add_flow(dp, 65534, match, actions)
        return (True, 'Success')

    def contention_quarantine_redirect(self, dp, ip_pkt, redirect_to, vlan_id):
        print "==> create contention_quarantine_redirect in dpid=%s src=%s dst=%s redirect_to=%s" % (dpid_lib.dpid_to_str(dp.id), ip_pkt.src, ip_pkt.dst,  redirect_to)
        # the dl_vlan match is a workaround because flowvisor seems to bug when using
        # dl_type=0x0800
        match = {'nw_src': ip_pkt.src, 'nw_dst': ip_pkt.dst, 'dl_type': 0x0800, 'dl_vlan': vlan_id}
        actions = []
        actions.append(dp.ofproto_parser.OFPActionSetNwDst(redirect_to))
        actions.append(dp.ofproto_parser.OFPActionOutput(self.eline_map[vlan_id][dp.id]['bkb_port']))
        self.add_flow(dp, 65535, match, actions, idle_timeout=120)

        match = {'nw_src': redirect_to, 'nw_dst': ip_pkt.src, 'dl_type': 0x0800, 'dl_vlan': vlan_id}
        actions = []
        actions.append(dp.ofproto_parser.OFPActionSetNwSrc(str(ip_pkt.dst)))
        actions.append(dp.ofproto_parser.OFPActionOutput(self.eline_map[vlan_id][dp.id]['access_port']))
        self.add_flow(dp, 65535, match, actions, idle_timeout=120)


class SDNIPSWSGIApp(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNIPSWSGIApp, self).__init__(req, link, data, **config)
        self.myapp = data[myapp_name]

    @route(myapp_name, base_url + '/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        body = json.dumps(map(dpid_lib.dpid_to_str, self.myapp.net.nodes()))
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/switches/{dpid}/ports', methods=['GET'])
    def get_switch_ports(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in self.myapp.net.nodes():
            details = 'switch not found - invalid dpid'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=404, body=json.dumps(msg))

        body = json.dumps(self.myapp.get_access_ports(dpid))
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/e-line/create', methods=['POST'])
    def eline_create(self, req, **kwargs):
        try:
            eline_params = req.json if req.body else {}
        except ValueError:
            details = 'Missing E-Line parameters - uniA, uniB, vlanid'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            uniA_sw, uniA_port = eline_params['uniA'].split(':')
            uniA_sw = dpid_lib.str_to_dpid(uniA_sw)
            assert uniA_sw in self.myapp.net.nodes()
            uniA_port = int(uniA_port)
            assert uniA_port in self.myapp.get_access_ports(uniA_sw)
        except:
            details = 'Invalid UNI A parameter. Format: uniA : "dpid:port"'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            uniB_sw, uniB_port = eline_params['uniB'].split(':')
            uniB_sw = dpid_lib.str_to_dpid(uniB_sw)
            assert uniB_sw in self.myapp.net.nodes()
            uniB_port = int(uniB_port)
            assert uniB_port in self.myapp.get_access_ports(uniB_sw)
        except:
            details = 'Invalid UNI B parameter. Format: uniB : "dpid:port"'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            vlanid = int(eline_params['vlanid'])
            assert 0 < vlanid < 4096
        except:
            details = 'Invalid VLAN ID parameter.'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.create_eline(uniA_sw, uniA_port, uniB_sw, uniB_port, vlanid)

        body = json.dumps([msg])
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/bgp/create', methods=['POST'])
    def bgp_create(self, req, **kwargs):
        try:
            bgp_params = req.json if req.body else {}
        except ValueError:
            details = 'Missing BGP parameters - as_number, router_id'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            as_number = bgp_params['as_number']
            assert isinstance(as_number, int)
        except:
            details = 'Invalid as_number parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            router_id = str(bgp_params['router_id'])
            socket.inet_aton(router_id)
        except:
            details = 'Invalid router_id parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.bgp_create(as_number, router_id)

        body = json.dumps([msg])
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/bgp/add_neighbor', methods=['POST'])
    def bgp_add_neighbor(self, req, **kwargs):
        try:
            bgp_params = req.json if req.body else {}
        except ValueError:
            details = 'Missing BGP parameters - remote_as, address'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            address = str(bgp_params['address'])
            socket.inet_aton(address)
        except:
            details = 'Invalid address parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        try:
            remote_as = bgp_params['remote_as']
            assert isinstance(remote_as, int)
        except:
            details = 'Invalid remote_as parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.bgp_add_neighbor(address, remote_as)

        body = json.dumps([msg])
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/bgp/add_prefix', methods=['POST'])
    def bgp_add_prefix(self, req, **kwargs):
        try:
            prefix = str(req.json['prefix'])
        except:
            details = 'Invalid address parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.bgp_add_prefix(prefix)

        body = json.dumps([msg])
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/flows/{dpid}', methods=['GET'])
    def list_flows_switch(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in self.myapp.net.nodes():
            details = 'switch not found - invalid dpid'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=404, body=json.dumps(msg))

        flows = []
        for flow in self.myapp.flows.get(dpid, []):
            flows.append({'match': flow['match'], 'priority': flow['priority']})

        body = json.dumps(flows)
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/flows/{dpid}/mirror', methods=['POST'])
    def flows_create_mirror(self, req, **kwargs):
        try:
            params = req.json
            assert 'flows' in params
            assert 'to_target' in params
        except Exception as e:
            print "==> flows_create_mirror error: %s -- request=%s" % (e, req)
            details = 'Missing parameters - flows, to_target'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in self.myapp.net.nodes():
            details = 'switch not found - invalid dpid'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=404, body=json.dumps(msg))

        try:
            target_sw, target_port = params['to_target'].split(':')
            target_sw = dpid_lib.str_to_dpid(target_sw)
            assert target_sw in self.myapp.net.nodes()
            target_port = int(target_port)
            assert target_port in self.myapp.get_access_ports(target_sw)
        except:
            details = 'Invalid to_target parameter. Format: to_target : "dpid:port"'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        installed_flows = []
        installed_actions = []
        for flow in self.myapp.flows.get(dpid, []):
            installed_flows.append({'match': flow['match'], 'priority': flow['priority']})
            installed_actions.append(flow['actions'])

        access_ports = self.myapp.get_access_ports(dpid)

        if params['flows'] == 'all':
            params['flows'] = installed_flows

        # sanity checks
        for flow in params['flows']:
            try:
                idx = installed_flows.index(flow)
                flow['actions'] = installed_actions[idx]
            except:
                details = 'invalid flow entry specified (not found in switch): %s' % (flow)
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
                return Response(status=404, body=json.dumps(msg))

        status, msg = self.myapp.flows_create_mirror(dpid, params['flows'], target_sw, target_port)

        body = json.dumps([msg])

        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/contention/add_vrf', methods=['POST'])
    def contention_add_vrf(self, req, **kwargs):
        try:
            rtcomm = str(req.json['rtcomm'])
            assert re.match("^[0-9]+:[0-9]+$", rtcomm)
            nexthop = str(req.json['nexthop'])
            socket.inet_aton(nexthop)
        except Exception as e:
            print "add_vrf error: %s" % (e)
            details = 'Invalid address parameter'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.contention_add_vrf(rtcomm, nexthop)

        body = json.dumps([msg])
        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/contention/quarantine', methods=['POST'])
    def contention_quarantine(self, req, **kwargs):
        try:
            params = req.json
            assert 'ipaddr' in params
            assert 'redirect_to' in params
            socket.inet_aton(str(params['ipaddr']))
            socket.inet_aton(str(params['redirect_to']))
        except Exception as e:
            details = 'Missing or invalid parameters - ipaddr'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.contention_quarantine(params['ipaddr'], params['redirect_to'])

        body = json.dumps([msg])

        return Response(content_type='application/json', body=body)

    @route(myapp_name, base_url + '/contention/block', methods=['POST'])
    def contention_block(self, req, **kwargs):
        try:
            params = req.json
            assert 'ipaddr' in params
            socket.inet_aton(str(params['ipaddr']))
        except Exception as e:
            details = 'Missing or invalid parameters - ipaddr'
            msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
            return Response(status=400, body=json.dumps(msg))

        status, msg = self.myapp.contention_block(params['ipaddr'])

        body = json.dumps([msg])

        return Response(content_type='application/json', body=body)
