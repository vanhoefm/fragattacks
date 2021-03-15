#!/usr/bin/env python3
# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from libwifi import *
import argparse, time, subprocess

def main():
	parser = argparse.ArgumentParser(description="Test packet injection properties of a device.")
	parser.add_argument('inject', help="Interface to use to inject frames.")
	parser.add_argument('monitor', nargs='?', help="Interface to use to monitor for frames.")
	parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
	options = parser.parse_args()

	peermac = "00:11:22:33:44:55"
	subprocess.check_output(["rfkill", "unblock", "wifi"])

	# Parse remaining options
	change_log_level(-options.debug)

	set_monitor_mode(options.inject)
	if options.monitor:
		set_monitor_mode(options.monitor)
		chan_inject = get_channel(options.inject)
		chan_monitor = get_channel(options.monitor)
		if chan_inject == None or chan_monitor == None:
			log(WARNING, "Unable to verify if both devices are on the same channel")
		elif chan_inject != chan_monitor:
			log(ERROR, "Both devices are not on the same channel")
			quit(1)
		peermac = get_macaddress(options.monitor)

	log(STATUS, "Performing injection tests")
	try:
		test_injection(options.inject, options.monitor, peermac)
	except OSError as ex:
		log(ERROR, str(ex))

if __name__ == "__main__":
	main()

