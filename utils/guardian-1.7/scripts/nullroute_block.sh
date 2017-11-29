#!/bin/sh

# this is a sample block script for guardian. 
# This script is for those poor souls who don't have a more advanced packet 
# filter method. I make no guarentees that this is secure, but it's got
# to be better than nothing. 
# 
# This command gets called by guardian as such:
#  guardian_block.sh <source_ip> <interface>
# and the script will issue a command to block all traffic from that source ip
# address. The logic of weither or not it is safe to block that address is
# done inside guardian itself.
source=$1
interface=$2
# You should change this to your IP address or hostname
hostname=localhost

/sbin/route add $source gw $hostname $interface
#/sbin/ipchains -I input -s $source -i $interface -j DENY
