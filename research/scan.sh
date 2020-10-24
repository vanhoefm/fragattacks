#!/bin/bash
# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
set -e

if ! [ $(id -u) = 0 ]; then
	echo "You must run the script as root"
	exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Illegal number of parameters"
    exit 2
fi
IFACE=$1

# Assure device is in managed mode
ifconfig $IFACE down
iw $IFACE set type managed
ifconfig $IFACE up

# Scan and list the results
RESULTS=( $(iwlist $IFACE scan | grep -E "Channel:|SSID") )
for chanidx in $(seq 0 2 ${#RESULTS[@]})
do
	ssididx=$((chanidx+1))
	echo ${RESULTS[$ssididx]} ${RESULTS[$chanidx]}
done

ifconfig $IFACE down
