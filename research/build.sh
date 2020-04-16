#!/bin/bash
set -e

cd ../hostapd
cp defconfig .config
make clean
make -j2

cd ../wpa_supplicant
cp defconfig .config
make clean
make -j2

