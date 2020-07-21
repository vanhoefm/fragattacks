#!/bin/bash
set -e

function install() {
	ORIGINAL=$1
	MODIFIED=$2

	# Create a backup of the original file
	if [[ ! -e $ORIGINAL.backup ]];
	then
		cp $ORIGINAL $ORIGINAL.backup
	fi

	# Overwrite it with the modified firmware image
	cp $MODIFIED $ORIGINAL
}

HTC7010=$(ls /lib/firmware/ath9k_htc/*7010* | grep -v backup)
HTC9271=$(ls /lib/firmware/ath9k_htc/*9271* | grep -v backup)

for ORIGINAL in $HTC7010
do
	install $ORIGINAL htc_7010.fw
done

for ORIGINAL in $HTC9271
do
	install $ORIGINAL htc_9271.fw
done
