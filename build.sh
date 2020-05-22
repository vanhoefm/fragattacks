#!/bin/bash
set -e

cd wpa_supplicant
make clean
cp defconfig .config
make -j 4

cd ../hostapd
make clean
cp defconfig .config
make -j 4
