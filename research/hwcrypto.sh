#!/bin/bash

# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

set -e

NOHWCRYPT="ath5k ath9k ath9k_htc rt2800usb carl9170 b43 p54common rt2500usb rt2800pci rt2800usb rt73usb"
SWCRYPTO="iwlwifi iwl3945 iwl4965"
HWCRYPTO="ipw2200"

hwcrypt_remove_modules() {
	# Remove loaded modules so they'll reload parameters
	for MODULE in $NOHWCRYPT $SWCRYPTO $HWCRYPTO
	do rmmod $MODULE 2> /dev/null || true; done
}

hwcrypt_off() {
	# Create nohwcrypt.conf options file
	rm /etc/modprobe.d/nohwcrypt.conf 2> /dev/null || true

	for MODULE in $NOHWCRYPT
	do echo "options $MODULE nohwcrypt=1" >> /etc/modprobe.d/nohwcrypt.conf; done

	for MODULE in $SWCRYPTO
	do echo "options $MODULE swcrypto=1" >> /etc/modprobe.d/nohwcrypt.conf; done

	for MODULE in $HWCRYPTO
	do echo "options $MODULE hwcrypto=0" >> /etc/modprobe.d/nohwcrypt.conf; done

	# Done. To be sure parameters are reloaded, reboot computer.
	hwcrypt_remove_modules
	echo "Done. Reboot your computer."
}

hwcrypt_on() {
	rm -f /etc/modprobe.d/nohwcrypt.conf
	hwcrypt_remove_modules
	echo "Done. Reboot your computer."
}


if [[ $1 == "on" ]]; then
	hwcrypt_on
elif [[ $1 == "off" ]]; then
	hwcrypt_off
else
	echo "Usage: $0 on|off"
fi

