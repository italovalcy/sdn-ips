#!/bin/sh

# this is a sample unblock script for guardian. This should work with ipfwadm. 
# This command gets called by guardian as such:
#  unblock.sh <source_ip> <interface>
# and the script will issue a command to remove the block that was created with # block.sh address. 
source=$1
interface=$2

/sbin/ipfwadm -I -d deny -W $interface -S $source

