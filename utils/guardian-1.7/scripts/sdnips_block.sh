#!/bin/bash

IP=$1
INT=$2

ACTION=block
for net in $(egrep "^[ \t]+HOME_NET" /etc/suricata/suricata.yaml | egrep -o "[0-9.,/]+"| sed 's/,/\n/g'); do
	if python -c "import ipcalc; print '$IP' in ipcalc.Network('$net')" | grep -q True; then
		ACTION=quarantine
		break
	fi
done

CONTROLLER=$(grep "^RemoteController" /etc/guardian.conf | awk '{print $2}')

case $ACTION in
	block)
      curl -s -X POST -d "{\"ipaddr\": \"$IP\"}" http://$CONTROLLER:8080/sdnips/contention/block
	;;
	quarantine)
      curl -s -X POST -d "{\"ipaddr\": \"$IP\", \"redirect_to\": \"192.168.100.200\"}" http://$CONTROLLER:8080/sdnips/contention/quarantine
	;;
	*)
		print "Unknown action, exiting.."
	;;
esac
