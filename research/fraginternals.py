#!/usr/bin/env python3
# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

# TODO: Other traffic on the interface might interfere with attacks. How to prevent?
from libwifi import *
import abc, sys, socket, struct, time, subprocess, atexit, select, copy
import argparse
import os.path
from wpaspy import Ctrl
from scapy.contrib.wpa_eapol import WPA_key
from scapy.arch.common import get_if_raw_hwaddr

# ----------------------------------- Utility Commands -----------------------------------

def wpaspy_clear_messages(ctrl):
	# Clear old replies and messages from the hostapd control interface. This is not
	# perfect and there may be new unrelated messages after executing this code.
	while ctrl.pending():
		ctrl.recv()

#TODO: Modify so we can ignore other messages over the command interface
def wpaspy_command(ctrl, cmd):
	wpaspy_clear_messages(ctrl)

	# Include console prefix so we can ignore other messages sent over the control interface
	rval = ctrl.request("> " + cmd)
	while not rval.startswith("> "):
		rval = ctrl.recv()

	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "wpa_supplicant did not recognize the command %s. Did you (re)compile wpa_supplicant?" % cmd.split()[0])
		quit(1)
	elif "FAIL" in rval:
		log(ERROR, f"Failed to execute command {cmd}")
		quit(1)

	return rval[2:]

def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True

def log_level2switch(options):
	if options.debug >= 2: return ["-dd", "-K"]
	elif options.debug >= 1: return ["-d", "-K"]
	return ["-K"]

def freebsd_create_eapolmsdu(src, dst, toinject):
	"""
	FreeBSD doesn't properly parse A-MSDU frames that start with an
	LLC/SNAP header. This is problematic when performing the EAPOL/AMSDU
	attack. Details why this happens are unclear. To better understand
	how the frames are parsed, see docs/freebsd_amsdu_bug.odt
	"""

	# Subframe 1: LLC/SNAP for EAPOL. The X's will be part of the first subframe.
	prefix = raw(LLC()/SNAP()/EAPOL()) + b"XXXXXXXX"

	# Subframe 1: content will be the X's (excluding the first 6 bytes). The actual
	#	ethernet payload length will be payload_len - 16 due to parsing bugs.
	payload_len = 16
	total_len   = payload_len + 6 + 6 + 2
	padding_len = 4 - (total_len % 4) if total_len % 4 != 0 else 0
	payload = prefix + struct.pack(">H", payload_len) + payload_len * b"X" + padding_len * b"Y"

	# Subframe 2: we can now append it normally
	payload += raw(create_msdu_subframe(src, dst, toinject))

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

	def __init__(self, trigger=Connected, action=Inject, meta_action=None, func=None, enc=False, frame=None, inc_pn=1, bad_mic=False, delay=None, wait=None, key=None):
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
		self.bad_mic = bad_mic
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
		self.check_fn = None
		self.time_completed = None
		self.done = False

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

	def check_finished(self):
		if self.done:
			return

		# If this was the last action, record the time
		if len(self.actions) == 0:
			if self.check_fn != None:
				self.time_completed = time.time()
			else:
				log(STATUS, "All frames sent. You must manually check if the test succeeded (see README).", color="green")
			self.done = True

	def get_actions(self, action):
		return [act for act in self.actions if act.action == action]

	def timedout(self):
		if self.time_completed == None:
			return False
		return self.time_completed + 5 < time.time()

	@abc.abstractmethod
	def prepare(self, station):
		pass

	def generate(self, station):
		self.prepare(station)
		self.enforce_delay()
		self.enforce_inc_pn()

	def check(self, p):
		if self.check_fn == None:
			return False
		return self.check_fn(p)

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
			log(STATUS, ">>> TEST COMPLETED SUCCESSFULLY!!!!", color="green")
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

		self.daemon.inject_mon(p)
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
		# TODO: Add argument to force a bad authenticity check

		idx = dot11_get_priority(frame) if self.options.pn_per_qos else 0
		self.pn[idx] += inc_pn

		key, keyid = (self.tk, 0) if int(frame.addr1[1], 16) & 1 == 0 else (self.gtk, self.gtk_idx)
		if force_key == 0:
			log(STATUS, "Encrypting with all-zero key")
			key = b"\x00" * len(key)

		if len(key) == 32:
			# TODO: Implement and test this function
			encrypted = encrypt_tkip(frame, key, self.pn[idx], keyid)
		elif len(key) == 16:
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
		# Ignore everything apart the 4-way handshake
		if not WPA_key in eapol: return None

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

				if self.options.inject_mf_workaround and frame.FCfield & 0x4 != 0:
					self.daemon.inject_mon(Dot11(addr1="ff:ff:ff:ff:ff:ff"))
					log(DEBUG, "[Injected packet] Prevented bug after fragment injection")


			# Stop processing actions if requested
			if act.wait: break

		self.test.check_finished()
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
		elif self.test != None and self.test.timedout():
			log(ERROR, ">>> Test timed out! Retry to be sure, or manually check result.")
			self.test = None

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
		self.nic_iface = self.options.iface

		# 1. Assign/create interfaces according to provided options
		if self.options.hwsim:
			# TODO: Automatically create both interfaces?
			self.nic_iface, self.nic_hwsim = self.options.hwsim.split(",")
			self.nic_mon = self.options.iface
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

			log(WARNING, "Remember to use a modified backports and ath9k_htc firmware!")

		# 2. Remember whether to need to use injection workarounds.
		driver = get_device_driver(self.nic_mon)
		if driver == None:
			log(WARNING, "Unable to detect driver of interface!")
			log(WARNING, "Injecting fragments may be unreliable.")
		elif driver in ["ath9k_htc", "iwlwifi"]:
			# Assure that fragmented frames are reliably injected on certain iwlwifi and ath9k_htc devices
			self.options.inject_mf_workaround = True
			log(STATUS, f"Detected {driver}, using injection bug workarounds")

		# 3. Enable monitor mode
		set_monitor_mode(self.nic_mon)
		log(STATUS, f"Using interface {self.nic_mon} ({get_device_driver(self.nic_mon)}) to inject frames.")
		if self.nic_hwsim:
			set_monitor_mode(self.nic_hwsim)

		# 4. Configure test interface if used
		if self.options.inject_test != None and self.options.inject_test != "self":
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
		# We use GET_CHANNEL of wpa_s/hostapd because it's more reliable than get_channel,
		# which can fail on certain devices such as the AWUS036ACH.
		channel = int(wpaspy_command(self.wpaspy_ctrl, "GET_CHANNEL"))
		if self.options.inject:
			set_channel(self.nic_mon, channel)
			log(STATUS, f"{self.nic_mon}: setting to channel {channel}")
		elif self.options.hwsim:
			set_channel(self.nic_hwsim, channel)
			set_channel(self.nic_mon, channel)
			log(STATUS, f"{self.nic_hwsim}: setting to channel {channel}")
			log(STATUS, f"{self.nic_mon}: setting to channel {channel}")

		if self.options.inject_test != None and self.options.inject_test != "self":
			set_channel(self.options.inject_test, channel)
			log(STATUS, f"{self.options.inject_test}: setting to channel {channel}")
			# When explicitly testing we can afford a longer timeout. Otherwise we should avoid it.
			time.sleep(0.5)

	def injection_test(self, peermac, ownmac, is_postauth):
		# Only perform the test when explicitly requested
		if self.options.inject_test == None:
			return

		# If requested perform the test after authentication
		if self.options.inject_test_postauth != is_postauth:
			return

		try:
			test_iface = None if self.options.inject_test == "self" else self.options.inject_test
			test_injection(self.nic_mon, test_iface, peermac, ownmac, testack=is_postauth)
		except IOError as ex:
			log(WARNING, ex.args[0])
			log(ERROR, "Unexpected error. Are you using the correct kernel/driver/device?")
			quit(1)

		log(DEBUG, f"Passed injection self-test on interface {self.nic_mon}.")
		quit(1)

	# TODO: Authentication and association has strict timing requirements in the Linux kernel.
	#       Can we make these lower somehow?
	def forward_hwsim(self, p, s):
		if p == None: return
		if not Dot11 in p: return
		if p.type != 0 and p.type != 2: return

		if len(p) >= 2200:
			log(DEBUG, f"Cannot forward frame longer than MTU (length {len(p)}).")
			return

		# Due to very strange buy in Scapy, we cannot directly forward frames with a
		# Dot11Encrypted layer. So we first convert them into a raw byte stream.
		p = Raw(raw(p))
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
			log(STATUS, "Deauthentication station to make it reconnect", color="green")
			cmd = f"DEAUTHENTICATE {station.get_peermac()} reason={WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA}"
		else:
			log(STATUS, "Disassociating station to make it reconnect", color="green")
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

		if "AP-STA-NEW" in msg:
			cmd, clientmac = msg.split()
			self.add_station(clientmac)

			log(STATUS, f"Client {clientmac} is connecting")
			station = self.stations[clientmac]
			station.handle_connecting(self.apmac)
			station.set_peermac(clientmac)

			# When in client mode, the scanning operation might interferes with this test.
			# So it must be executed once we are connecting so the channel is stable.
			self.injection_test(clientmac, self.apmac, False)

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

			self.injection_test(clientmac, self.apmac, True)

	def start_daemon(self):
		cmd = ["../hostapd/hostapd", "-i", self.nic_iface, "hostapd.conf"] + log_level2switch(self.options)
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

		if "Associated with" in msg:
			# When using a separate interface to inject, switch to correct channel
			self.follow_channel()

			p = re.compile("Associated with (.*) successfully")
			bss = p.search(msg).group(1)
			self.station.handle_connecting(bss)

			# With the ath9k_htc, injection in mixed managed/monitor only works after
			# sending the association request. So only perform injection test now.
			self.injection_test(self.station.bss, self.station.mac, False)

		elif "EAPOL-TX" in msg:
			cmd, srcaddr, payload = msg.split()
			self.station.handle_eapol_tx(bytes.fromhex(payload))

		# The "EAPOL processing" event only occurs with WEP
		if "WPA: Key negotiation completed with" in msg or \
		   "WPA: EAPOL processing complete" in msg:
			# This get's the current keys
			self.station.handle_authenticated()

			self.injection_test(self.station.bss, self.station.mac, True)

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
			"-cclient.conf", "-W"] + log_level2switch(self.options)
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

