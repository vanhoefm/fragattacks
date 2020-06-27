#!/usr/bin/env python3
from libwifi import *
import argparse, time

def main():
	parser = argparse.ArgumentParser(description="Test packet injection properties of a device.")
	parser.add_argument('inject', help="Interface to use to inject frames.")
	parser.add_argument('monitor', nargs='?', help="Interface to use to monitor for frames.")
	options = parser.parse_args()

	peermac = "00:11:22:33:44:55"

	# TODO: Add a --debug parameter similar to fragattack

	subprocess.check_output(["rfkill", "unblock", "wifi"])

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
		peermac = get_mac_address(options.monitor)
	else:
		log(WARNING, "Only performing selftest. This can detect only injection issues caused by")
		log(WARNING, "the kernel. Many other issues cannot be detected in this self-test, so you")
		log(WARNING, "should not trust the output of the tests unless you know what you're doing.")

	log(STATUS, "Performing injection tests ...")
	try:
		test_injection(options.inject, options.monitor, peermac)
	except OSError as ex:
		log(ERROR, str(ex))

if __name__ == "__main__":
	main()

