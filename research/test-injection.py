#!/usr/bin/env python3
from libwifi import *
import argparse, time

def main():
	parser = argparse.ArgumentParser(description="Test packet injection properties of a device.")
	parser.add_argument('inject', help="Interface to use to inject frames.")
	parser.add_argument('monitor', help="Interface to use to monitor for frames.")
	options = parser.parse_args()

	subprocess.check_output(["rfkill", "unblock", "wifi"])

	set_monitor_mode(options.inject)
	set_monitor_mode(options.monitor)

	if get_channel(options.inject) != get_channel(options.monitor):
		log(ERROR, "Both devices are not on the same channel")
		quit(1)

	log(STATUS, "Performing injection tests ...")
	test_injection(options.inject, options.monitor, peermac="00:11:22:33:44:55")

if __name__ == "__main__":
	main()

