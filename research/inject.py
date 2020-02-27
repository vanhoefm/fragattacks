#!/usr/bin/env python3
from libwifi import*
import sys, socket, struct, time, subprocess, atexit, select
from wpaspy import Ctrl

#def main(interface):
#	conf.iface = interface + "mon"
#	inject_fragmented()

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
		self.nic_mon = interface + "mon"
		self.clientmac = None

		self.sock  = None
		self.wpasupp = None
		self.wpasupp_ctrl = None

		self.apmac = None
		self.tk = None
		self.pn = 0x99

	def inject_fragments(self):
		time.sleep(5)
		payload1 = b"A" * 1450
		payload2 = b"B" * 1450
		seqnum = 0xAA
		frag1 = Dot11(type="Data", FCfield="to-DS+MF", addr1=self.apmac, addr2=self.clientmac, addr3=self.clientmac, SC=(seqnum << 4) | 0)/Raw(payload1)
		frag2 = Dot11(type="Data", FCfield="to-DS", addr1=self.apmac, addr2=self.clientmac, addr3=self.clientmac, SC=(seqnum << 4) | 1)/Raw(payload2)
		if self.tk:
			frag1 = encrypt_ccmp(frag1, self.tk, self.pn)
			frag2 = encrypt_ccmp(frag2, self.tk, self.pn+1)
			self.pn += 1000
		sendp(RadioTap()/frag1, iface=self.nic_mon)
		sendp(RadioTap()/frag2, iface=self.nic_mon)

	def handle_rx(self):
		p = self.sock.recv()
		if p == None: return

		#self.process_frame(p)

	def get_tk(self):
		self.tk = bytes.fromhex(wpaspy_command(self.wpasupp_ctrl, "GET tk"))
		log(STATUS, "TK: " + self.tk.hex())

	def handle_wpasupp(self):
		while self.wpasupp_ctrl.pending():
			msg =self.wpasupp_ctrl.recv()
			log(STATUS, "wpasupp: " + msg)

			if "CTRL-EVENT-CONNECTED" in msg:
				p = re.compile("Connection to (.*) completed")
				self.apmac = p.search(msg).group(1)
				self.get_tk()
				self.inject_fragments()

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
			# TODO: Need to monitor self.wpasupp as well
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

