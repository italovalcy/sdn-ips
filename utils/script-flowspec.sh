curl -s -X POST -d '{"remote_as" : 100, "address" : "10.144.12.56", "enable_ipv4fs": "True"}'    http://localhost:8080/sdnips/bgp/add_neighbor | python -m json.tool

curl -s -X POST -d '{"rtcomm" : "100:666", "nexthop" : "192.168.100.200"}'    http://localhost:8080/sdnips/contention/add_vrf | python -m json.tool
