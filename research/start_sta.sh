#!/bin/bash
set -e

../wpa_supplicant/wpa_supplicant -D nl80211 -i wlan1 -c client.conf -dd -K
