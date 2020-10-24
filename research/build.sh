#!/bin/bash
# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
set -e

cd ../hostapd
cp defconfig .config
make clean
make -j2

cd ../wpa_supplicant
cp defconfig .config
make clean
make -j2

