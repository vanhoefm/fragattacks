# Copyright (c) 2022, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from fraginternals import *

class PingBefore(Test):
	def __init__(self, ptype, opt=None):
		super().__init__([
				Action(Action.BeforeAuth, action=Action.Inject, enc=False),
				Action(Action.Connected,  action=Action.GetIp),
				Action(Action.Connected,  action=Action.Inject, enc=True)
		])
		self.ptype = ptype

		self.bcast_ra = False if opt == None else opt.bcast_ra
		self.bcast_dst = False if opt == None else opt.bcast_dst
		self.icmp_size = 0 if (opt == None or opt.icmp_size is None) else opt.icmp_size

		# This test currently only works against clients
		assert opt.ap, "This test currently only supports testing clients"

	def prepare(self, station):
		log(STATUS, "Generating ping-before test", color="green")

		# FIXME: This only works when acting as AP. And assumes no other client
		#        will request an IP before this station does.
		# The built-in DHCP server will pop() an IP address from the end of the list.
		peerip = station.daemon.dhcp.pool[-1] # station.peerip
		myip = station.daemon.arp_sender_ip
		log(WARNING, "My IP is {} and client IP will be {}".format(myip, peerip))

		header = station.get_header()

		label = b"test_ping_icmp_"
		payload = label + b"A" * min(10, max(0, self.icmp_size - len(label)))
		ping = ICMP()/Raw(payload)
		ip1, ip2 = fragment(IP(src=myip, dst=peerip)/ping, len(ping) // 2)
		self.check_fn = lambda p: ICMP in p and label in raw(p) and p[ICMP].type == 0

		frame1 = header/LLC()/SNAP()/ip1
		frame2 = header.copy()/LLC()/SNAP()/ip2

		if self.bcast_ra:
			frame1.addr1 = "ff:ff:ff:ff:ff:ff"
		if self.bcast_dst:
			if header.FCfield & Dot11(FCfield="to-DS").FCfield != 0:
				frame1.addr3 = "ff:ff:ff:ff:ff:ff"
			else:
				frame1.addr1 = "ff:ff:ff:ff:ff:ff"

		self.actions[0].frame = frame1
		self.actions[2].frame = frame2

