#!/bin/bash
set -e

if ! [ $(id -u) = 0 ]; then
	echo "You must run the script as root"
	exit 1
fi

# Reinitialize mac80211_hwsim
rmmod mac80211_hwsim 2> /dev/null || true
modprobe mac80211_hwsim radios=2
sleep 1

# Display the created interface names
IFACES=$(ls /sys/devices/virtual/mac80211_hwsim/hwsim*/net/*/address | cut -d/ -f8)
for IFACE in $IFACES
do
	echo "Created hwsim interface $IFACE"
done

