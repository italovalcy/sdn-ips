#!/bin/bash

IP=$1
INT=$2

ACTION=unblock
for net in egrep "^[ \t]+HOME_NET" /etc/suricata/suricata.yaml | egrep -o "[0-9.,/]+"| sed 's/,/\n/g'; do
	if python -c "import ipcalc; print '$IP' in ipcalc.Network('$net')" | grep -q True; then
		ACTION=unquarantine
		break
	fi
done

CONTROLLER=$(grep "^RemoteController" /etc/guardian.conf | awk '{print $2}')

case $ACTION in:
	unblock)
      # not implemented
      #curl -s -X POST -d "{\"ipaddr\": \"$IP\"}" http://$CONTROLLER:8080/sdnips/contention/unblock
	;;
	unquarantine)
      # not implemented
      #curl -s -X POST -d "{\"ipaddr\": \"$IP\"}" http://$CONTROLLER:8080/sdnips/contention/quarantine
	;;
	*)
		print "Unknown action, exiting.."
	;;
esac
