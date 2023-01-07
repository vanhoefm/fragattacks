# Copyright (c) 2020-2023, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from scapy.all import *
from .wifi import *
import select

FLAG_FAIL, FLAG_NOCAPTURE = [2**i for i in range(2)]

#### Utility ####

def flush_socket(s):
	"""
	@param s	An L2Socket
	"""
	i = 0
	while i < 10000 and len(select.select([s], [], [], 0)[0]) > 0:
		L2Socket.recv(s, MTU)
		i += 1

def get_nearby_ap_addr(sin):
	# If this interface itself is also hosting an AP, the beacons transmitted by it might be
	# returned as well. We filter these out by the condition `p.dBm_AntSignal != None`.
	beacons = list(sniff(opened_socket=sin, timeout=0.5, lfilter=lambda p: (Dot11 in p or Dot11FCS in p) \
									and p.type == 0 and p.subtype == 8 \
									and p.dBm_AntSignal != None))
	if len(beacons) == 0:
		return None, None
	beacons.sort(key=lambda p: p.dBm_AntSignal, reverse=True)
	return beacons[0].addr2, get_ssid(beacons[0])

def inject_and_capture(sout, sin, p, count=0, retries=1):
	# Append unique label to recognize injected frame
	label = b"AAAA" + struct.pack(">II", random.randint(0, 2**32), random.randint(0, 2**32))
	toinject = p/Raw(label)

	attempt = 0
	while True:
		log(DEBUG, "Injecting test frame: " + repr(toinject))
		sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/toinject)

		# TODO:Move this to a shared socket interface?
		# Note: this workaround for Intel is only needed if the fragmented frame is injected using
		#       valid MAC addresses. But for simplicity just execute it after any fragmented frame.
		if sout.mf_workaround and toinject.FCfield & Dot11(FCfield="MF").FCfield != 0:
			fix = Dot11(type=p.type, subtype=p.subtype)
			# Note: for RT5572 the workaround is always needed. Additionally, we need to send
			#       the dummy frame using the same QoS TID. Just use same QoD TID for all devices.
			if Dot11QoS in p:
				fix = fix/Dot11QoS(TID=p[Dot11QoS].TID)
			sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/fix)
			log(DEBUG, "Sending dummy frame after injecting frame with MF flag set: {}".format(repr(fix)))

		# 1. When using a 2nd interface: capture the actual packet that was injected in the air.
		# 2. Not using 2nd interface: capture the "reflected" frame sent back by the kernel. This allows
		#    us to at least detect if the kernel (and perhaps driver) is overwriting fields. It generally
		#    doesn't allow us to detect if the device/firmware itself is overwriting fields.
		packets = sniff(opened_socket=sin, timeout=1, count=count, lfilter=lambda p: p != None and label in raw(p))

		if len(packets) > 0 or attempt >= retries:
			break

		log(STATUS, "     Unable to capture injected frame, retrying.")
		attempt += 1

	return packets

def capture_probe_response_ack(sout, sin, probe_req, count=0, retries=1):
	# Filter to use to capture frames from the independent monitor interface
	probe_resp_ack_filter = lambda p: p != None and ( \
		# Capture Probe Responses
		(p.addr1 == probe_req.addr2 and p.addr2 == probe_req.addr1 and Dot11ProbeResp in p) or \
		# Capture ACKs send by us
		(p.addr1 == probe_req.addr1 and p.type == FRAME_TYPE_CONTROL and p.subtype == FRAME_CONTROL_ACK) )

	attempt = 0
	while True:
		log(DEBUG, "Injecting probe request: " + repr(probe_req))
		flush_socket(sin)
		sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/probe_req)
		packets = sniff(opened_socket=sin, timeout=1, count=count, lfilter=probe_resp_ack_filter)
		rx_probes = [p for p in packets if Dot11ProbeResp in p]
		tx_acks = [p for p in packets if p.type == FRAME_TYPE_CONTROL and p.subtype == FRAME_CONTROL_ACK]
		if (len(rx_probes) > 0 and len(tx_acks) > 0) or attempt >= retries:
			break

		log(STATUS, "     Unable to capture probe request, retrying.")
		attempt += 1

	return rx_probes, tx_acks

#### Injection tests ####

def test_injection_more_fragments(sout, sin, ref, strtype):
	log(STATUS, "--- Testing injection of frame with more fragments flag using {}".format(strtype))
	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)
	p = p/Dot11QoS(TID=2)/LLC()/SNAP()/EAPOL()/EAP()
	p.FCfield |= Dot11(FCfield="MF").FCfield
	captured = inject_and_capture(sout, sin, p, count=1)
	if len(captured) == 0:
		log(ERROR,  "[-] Unable to inject frame with More Fragment flag using {}.".format(strtype))
	else:
		log(STATUS, "[+] Properly captured injected frame with More Fragment flag using {}.".format(strtype), color="green")
	return FLAG_FAIL if len(captured) == 0 else 0

def test_packet_injection(sout, sin, p, test_func, frametype, msgfail):
	"""Check if given property holds of all injected frames"""
	packets = inject_and_capture(sout, sin, p, count=1)
	if len(packets) < 1:
		log(ERROR,   "[-] Unable to capture injected {}.".format(frametype))
		return FLAG_NOCAPTURE
	if not all([test_func(cap) for cap in packets]):
		log(ERROR,   "[-] " + msgfail.format(frametype=frametype))
		return FLAG_FAIL
	log(STATUS, "    Properly captured injected {}.".format(frametype))
	return 0

def test_injection_fields(sout, sin, ref, strtype):
	log(STATUS, "--- Testing injection of fields using {}".format(strtype))
	status = 0

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=30<<4)/LLC()/SNAP()/EAPOL()/EAP()
	status |= test_packet_injection(sout, sin, p, lambda cap: EAPOL in cap, "EAPOL frame with {}".format(strtype),
					"Scapy thinks injected {frametype} is a different frame?")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=31<<4)
	status |= test_packet_injection(sout, sin, p, lambda cap: cap.SC == p.SC, "empty data frame with {}".format(strtype),
					"Sequence number of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=(32<<4)|1)
	status |= test_packet_injection(sout, sin, p, lambda cap: (cap.SC & 0xf) == 1, "fragmented empty data frame with {}".format(strtype),
					"Fragment number of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)
	status |= test_packet_injection(sout, sin, p, lambda cap: cap.TID == p.TID, "empty QoS data frame with {}".format(strtype),
					"QoS TID of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)/Raw("BBBB")
	set_amsdu(p[Dot11QoS])
	status |= test_packet_injection(sout, sin, p, \
					lambda cap: cap.TID == p.TID and is_amsdu(cap) and b"BBBB" in raw(cap), \
					"A-MSDU frame with {}",	"A-MSDU frame is not properly injected!".format(strtype))

	if status == 0: log(STATUS, "[+] All tested fields are properly injected when using {}.".format(strtype), color="green")
	return status

def test_injection_order(sout, sin, ref, strtype, retries=1):
	log(STATUS, "--- Testing order of injected QoS frames using {}".format(strtype))

	label = b"AAAA" + struct.pack(">II", random.randint(0, 2**32), random.randint(0, 2**32))
	p2 = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)
	p6 = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=6)

	for i in range(retries + 1):
		# First frame causes Tx queue to be busy. Next two frames tests if frames are reordered.
		for p in [p2] * 4 + [p6]:
			sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p/Raw(label))

		packets = sniff(opened_socket=sin, timeout=2.5, lfilter=lambda p: Dot11QoS in p and label in raw(p))
		tids = [p[Dot11QoS].TID for p in packets]
		log(STATUS, "Captured TIDs: " + str(tids))

		# Sanity check the captured TIDs, and then analyze the results
		if not (2 in tids and 6 in tids):
			log(STATUS,  "We didn't capture all injected QoS TID frames, retrying.")
		else:
			break

	if not (2 in tids and 6 in tids):
		log(ERROR,  "[-] We didn't capture all injected QoS TID frames with {}. Test failed.".format(strtype))
		return FLAG_NOCAPTURE
	elif tids != sorted(tids):
		log(ERROR,  "[-] Frames with different QoS TIDs are reordered during injection with {}.".format(strtype))
		return FLAG_FAIL
	else:
		log(STATUS, "[+] Frames with different QoS TIDs are not reordered during injection with {}.".format(strtype), color="green")
		return 0

def test_injection_retrans(sout, sin, addr1, addr2):
	suspicious = False
	test_fail = False

	# Test number of retransmissions
	p = Dot11(FCfield="to-DS", addr1="00:11:00:00:02:01", addr2="00:11:00:00:02:01", type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, "Injected frames seem to be (re)transitted {} times".format(num))
	if num == 0:
		log(ERROR, "Couldn't capture injected frame. Please restart the test.")
		test_fail = True
	elif num == 1:
		log(WARNING, "Injected frames don't seem to be retransmitted!")
		suspicious = True

	# Test receiving ACK towards an unassigned MAC address
	p = Dot11(FCfield="to-DS", addr1=addr1, addr2="00:22:00:00:00:01", type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, "Captured {} (re)transmitted frames to the AP when using a spoofed sender address".format(num))
	if num == 0:
		log(ERROR, "Couldn't capture injected frame. Please restart the test.")
		test_fail = True
	if num > 2:
		log(STATUS, "  => Acknowledged frames with a spoofed sender address are still retransmitted. This has low impact.")

	# Test receiving ACK towards an assigned MAC address
	p = Dot11(FCfield="to-DS", addr1=addr1, addr2=addr2, type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, "Captured {} (re)transmitted frames to the AP when using the real sender address".format(num))
	if num == 0:
		log(ERROR, "Couldn't capture injected frame. Please restart the test.")
		test_fail = True
	elif num > 2:
		log(STATUS, "  => Acknowledged frames with real sender address are still retransmitted. This might impact time-sensitive tests.")
		suspicious = True

	if suspicious:
		log(WARNING, "[-] Retransmission behaviour isn't ideal. This test can be unreliable (e.g. due to background noise).")
	elif not test_fail:
		log(STATUS, "[+] Retransmission behaviour is good. This test can be unreliable (e.g. due to background noise).", color="green")


def test_injection_txack(sout, sin, destmac, ownmac):
	# We have to use the current MAC address of the sending interface. Since we can't
	# expect the network card to ACK frames to other MAC addresses.
	p = Dot11(addr1=destmac, addr2=ownmac, addr3=destmac, SC=33<<4)/Dot11ProbeReq() \
			/ Dot11Elt(ID='SSID')/Dot11Elt(ID='Rates',info=b"\x03\x12\x96\x18")
	rx_probes, tx_acks = capture_probe_response_ack(sout, sin, p, retries=1)

	log(STATUS, "Captured {} probe responses and {} ACKs in response.".format(len(rx_probes), len(tx_acks)))
	if len(rx_probes) == 0:
		log(ERROR, "Didn't recieve a probe response to test ack generation. Re-run the test.")
		return FLAG_NOCAPTURE
	elif len(tx_acks) == 0:
		log(WARNING, "[-] Acknowledgement frames aren't sent when recieving a frame.")
		return FLAG_FAIL
	else:
		log(STATUS, "[+] Acknowledgement frames are sent when recieving a frame.", color="green")
		return 0


#### Main test function ####

def test_injection(iface_out, iface_in=None, peermac=None, ownmac=None, testack=True, skip_mf=False):
	"""
	@param iface_out	Interface used to inject frames
	@param iface_in		Interface used to capture injected frames. If not given, the
						iface_out is also used to monitor how/whether frames are sent.
	@param peermac		Destination MAC address used for retransmission tests, if no
	                    neary AP can be found. Also used in frames that have as sender
	                    MAC address the real MAC address of iface_out.
	@param ownmac		Can be used to override the real sender MAC address of iface_out.
	@param testack		Test whether frames are transmitted and whether a received ACK
	                    will stop the retransmission of frames.
	"""
	status = 0

	# We start monitoring iface_in already so injected frame won't be missed
	sout = L2Socket(type=ETH_P_ALL, iface=iface_out)
	driver_out = get_device_driver(iface_out)

	# Workaround to properly inject fragmented frames (and prevent it from blocking Tx queue).
	sout.mf_workaround = driver_out in ["iwlwifi", "ath9k_htc", "rt2800usb"]
	if sout.mf_workaround:
		log(WARNING, "Detected {}, using workaround to reliably inject fragmented frames.".format(driver_out))

	# Print out what we are tested. Abort if the driver is known not to support a self-test.
	log(STATUS, "Injection test: using {} ({}) to inject frames".format(iface_out, driver_out))
	if iface_in == None:
		log(WARNING, "Injection selftest: also using {} to capture frames. This means the tests can detect if the kernel".format(iface_out))
		log(WARNING, "                    interferes with injection, but it cannot check the behaviour of the network card itself.")
		if driver_out in ["mt76x2u"]:
			log(WARNING, "                    WARNING: self-test with the {} driver can be unreliable.".format(driver_out))
		elif not driver_out in ["iwlwifi", "ath9k_htc", "mac80211_hwsim", "rt2800usb"]:
			log(WARNING, "                    WARNING: it is unknown whether a self-test is reliable with the {} driver.".format(driver_out))

		sin = sout
	else:
		driver_in = get_device_driver(iface_in)
		log(STATUS, "Injection test: using {} ({}) to capture frames".format(iface_in, driver_in))
		sin = L2Socket(type=ETH_P_ALL, iface=iface_in)

	# Injection using the "own" MAC address is mainly a problem when using a second virtual
	# interface for injection when the first interface is used as client or AP. We want to
	# test injection when using the MAC address of the client or AP. The caller should supply
	# this address because the MAC address of the second virtual interface may be different
	# from the MAC address used by the client or AP. Only use the MAC address of sout.iface
	# if no "own" address is supplied by the caller.
	if ownmac == None:
		ownmac = get_macaddress(sout.iface)

	# Some devices only properly inject frames when either the to-DS or from-DS flag is set,
	# so set one of them as well.
	spoofed = Dot11(FCfield="from-DS", addr1="00:11:00:00:02:01", addr2="00:22:00:00:02:01")
	valid = Dot11(FCfield="from-DS", addr1=peermac, addr2=ownmac)
	if iface_in != None:
		log(STATUS, "NOTE: Frames sent using a (partly) valid MAC address may be harder to capture due to higher bitrates.")
		log(STATUS, "      Connecting using old Wi-Fi versions such as 802.11b can help with capturing injected frames.")

	# Test injection of More Fragment flags. Causes some device to crash, so make it
	# possible to easily skip this test.
	if not skip_mf:
		status |= test_injection_more_fragments(sout, sin, spoofed, "spoofed MAC addresses")
		status |= test_injection_more_fragments(sout, sin, valid, "(partly) valid MAC addresses")

	# Perform some actual injection tests
	status |= test_injection_fields(sout, sin, spoofed, "spoofed MAC addresses")
	status |= test_injection_fields(sout, sin, valid, "(partly) valid MAC addresses")
	status |= test_injection_order(sout, sin, spoofed, "spoofed MAC addresses")
	status |= test_injection_order(sout, sin, valid, "(partly) valid MAC addresses")

	# 1. Test retransmission behaviour and *recieving* of acknowledgements
	# 2. Test the *transmission* of acknowledgements on the reception of non-control frames
	if iface_in != None and testack:
		# We search for an AP on the interface that injects frames because:
		# 1. In mixed managed/monitor mode, we will otherwise detect our own AP on the sout interface
		# 2. If sout interface "sees" the AP this assure it will also receive its ACK frames
		# 3. The given peermac might be a client that goes into sleep mode
		channel = get_channel(sin.iface)
		log(STATUS, "--- Searching for AP on channel {} to test retransmission behaviour.".format(channel))
		apmac, ssid = get_nearby_ap_addr(sout)
		if apmac == None and peermac == None:
			raise IOError("Unable to find nearby AP to test injection")
		elif apmac == None:
			peer_description = "peer {}".format(peermac)
			log(WARNING, "Unable to find AP. Try a different channel? Testing retransmission behaviour with {}.".format(peer_description))
			destmac = peermac
		else:
			peer_description = "AP {} ({})".format(ssid, apmac)
			log(STATUS, "Testing retransmission behaviour by injecting frames to {}.".format(peer_description))
			destmac = apmac
		test_injection_retrans(sout, sin, addr1=destmac, addr2=ownmac)

		if apmac != None:
			log(STATUS, "--- Testing ACK generation by sending probe requests to {}.".format(peer_description))
			test_injection_txack(sout, sin, destmac, ownmac)
		else:
			log(WARNING, "--- Cannot test ACK generation behaviour because no nearby AP was found.")

	# Show a summary of results/advice
	log(STATUS, "")
	if status == 0:
		log(STATUS, "==> The most important tests have been passed successfully!", color="green")
	if status & FLAG_NOCAPTURE != 0:
		log(WARNING, "==> Failed to capture some frames. Try another channel or use another monitoring device.")
	if status & FLAG_FAIL !=0 :
		log(ERROR, "==> Some tests failed. Consider using/searching for patched drivers/firmware.")

	sout.close()
	sin.close()

