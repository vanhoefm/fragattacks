#!/bin/bash

sudo modprobe mac80211_hwsim radios=4
sleep 2
ip link set wlan3 down
iw wlan3 set type monitor
ip link set wlan3 up
iw wlan3 set channel 1
