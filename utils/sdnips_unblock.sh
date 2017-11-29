#!/bin/bash

CONTROLLER=X.Y.Z.W
IP=$1
INT=$2

ACTION=unblock
for net in egrep "^[ \t]+HOME_NET" /etc/suricata/suricata.yaml | egrep -o "[0-9.,/]+"| sed 's/,/\n/g'; do
	if python -c "import ipcalc; print '$IP' in ipcalc.Network('$net')" | grep -q True; then
		ACTION=unquarantine
		break
	fi
done

case $ACTION in:
	unblock)
      curl -s -X POST -d "{\"ipaddr\": \"$IP\"}" http://$CONTROLLER:8080/sdnips/contention/unblock
	;;
	unquarantine)
      curl -s -X POST -d "{\"ipaddr\": \"$IP\"}" http://$CONTROLLER:8080/sdnips/contention/quarantine
	;;
	*)
		print "Unknown action, exiting.."
	;;
esac
