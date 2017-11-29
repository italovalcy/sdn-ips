#!/bin/sh

# this is a sample unblock script for guardian. This should work with freebsd. 
# This command gets called by guardian as such:
#  unblock.sh <source_ip> <interface>
# and the script will issue a command to remove the block that was created with # block.sh address. 
source=$1
interface=$2

# I don't have a FreeBsd machine to test this with, so please double
# check to make sure it works

num=`/sbin/ipfw list |grep "from $source to" |awk '{ print $1 }'`
/sbin/ipfw -q delete $num
