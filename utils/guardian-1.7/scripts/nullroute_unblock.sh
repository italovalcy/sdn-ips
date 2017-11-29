#!/bin/sh

# this is a sample unblock script for guardian. This works by adding a route
# that goes nowhere once an attack is detected.
# This script is for those poor souls who don't have a more advanced packet 
# filter method. I make no guarentees that this is secure, but it's got
# to be better than nothing. 
# This command gets called by guardian as such:
#  unblock.sh <source_ip> <interface>
# and the script will issue a command to remove the block that was created with # block.sh address. 
source=$1
interface=$2

/sbin/route delete $source

