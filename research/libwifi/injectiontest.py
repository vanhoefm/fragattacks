# Copyright (c) 2020, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from scapy.all import *
from .wifi import *

FLAG_FAIL, FLAG_NOCAPTURE = [2**i for i in range(2)]

#### Utility ####

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
			sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/Dot11())
			log(DEBUG, "Sending dummy frame after injecting frame with MF flag set")

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


#### Injection tests ####

def test_injection_fragment(sout, sin, ref):
	log(STATUS, "--- Testing injection of fragmented frame using (partly) valid MAC addresses")
	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)
	p = p/Dot11QoS(TID=2)/LLC()/SNAP()/EAPOL()/EAP()
	p.FCfield |= Dot11(FCfield="MF").FCfield
	captured = inject_and_capture(sout, sin, p, count=1)
	if len(captured) == 0:
		log(ERROR,  "[-] Unable to inject frame with More Fragment flag using (partly) valid MAC addresses.")
	else:
		log(STATUS, "[+] Frame with More Fragment flag using (partly) valid MAC addresses can be injected.", color="green")
	return FLAG_FAIL if len(captured) == 0 else 0

def test_packet_injection(sout, sin, p, test_func, frametype, msgfail):
	"""Check if given property holds of all injected frames"""
	packets = inject_and_capture(sout, sin, p, count=1)
	if len(packets) < 1:
		log(ERROR,   f"[-] Unable to capture injected {frametype}.")
		return FLAG_NOCAPTURE
	if not all([test_func(cap) for cap in packets]):
		log(ERROR,   f"[-] " + msgfail.format(frametype=frametype))
		return FLAG_FAIL
	log(STATUS, f"    Properly captured injected {frametype}.")
	return 0

def test_injection_fields(sout, sin, ref, strtype):
	log(STATUS, f"--- Testing injection of fields using {strtype}")
	status = 0

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=30<<4)/LLC()/SNAP()/EAPOL()/EAP()
	status |= test_packet_injection(sout, sin, p, lambda cap: EAPOL in cap, f"EAPOL frame with {strtype}",
					"Scapy thinks injected {frametype} is a different frame?")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=31<<4)
	status |= test_packet_injection(sout, sin, p, lambda cap: cap.SC == p.SC, f"empty data frame with {strtype}",
					"Sequence number of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, SC=(32<<4)|1)
	status |= test_packet_injection(sout, sin, p, lambda cap: (cap.SC & 0xf) == 1, f"fragmented empty data frame with {strtype}",
					"Fragment number of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)
	status |= test_packet_injection(sout, sin, p, lambda cap: cap.TID == p.TID, f"empty QoS data frame with {strtype}",
					"QoS TID of injected {frametype} is being overwritten!")

	p = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, addr3=ref.addr3, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)/Raw("BBBB")
	set_amsdu(p[Dot11QoS])
	status |= test_packet_injection(sout, sin, p, \
					lambda cap: cap.TID == p.TID and is_amsdu(cap) and b"BBBB" in raw(cap), \
					f"A-MSDU frame with {strtype}",	"A-MSDU frame is not properly injected!")

	if status == 0: log(STATUS, f"[+] All tested fields are properly injected when using {strtype}.", color="green")
	return status

def test_injection_order(sout, sin, ref, strtype, retries=1):
	log(STATUS, f"--- Testing order of injected QoS frames using {strtype}")

	label = b"AAAA" + struct.pack(">II", random.randint(0, 2**32), random.randint(0, 2**32))
	p2 = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=2)
	p6 = Dot11(FCfield=ref.FCfield, addr1=ref.addr1, addr2=ref.addr2, type=2, subtype=8, SC=33<<4)/Dot11QoS(TID=6)

	for i in range(retries + 1):
		# First frame causes Tx queue to be busy. Next two frames tests if frames are reordered.
		for p in [p2] * 4 + [p6]:
			sout.send(RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")/p/Raw(label))

		packets = sniff(opened_socket=sin, timeout=1.5, lfilter=lambda p: Dot11QoS in p and label in raw(p))
		tids = [p[Dot11QoS].TID for p in packets]
		log(STATUS, "Captured TIDs: " + str(tids))

		# Sanity check the captured TIDs, and then analyze the results
		if not (2 in tids and 6 in tids):
			log(STATUS,  f"We didn't capture all injected QoS TID frames, retrying.")
		else:
			break

	if not (2 in tids and 6 in tids):
		log(ERROR,  f"[-] We didn't capture all injected QoS TID frames with {strtype}. Test failed.")
		return FLAG_NOCAPTURE
	elif tids != sorted(tids):
		log(ERROR,  f"[-] Frames with different QoS TIDs are reordered during injection with {strtype}.")
		return FLAG_FAIL
	else:
		log(STATUS, f"[+] Frames with different QoS TIDs are not reordered during injection with {strtype}.", color="green")
		return 0

def test_injection_ack(sout, sin, addr1, addr2):
	suspicious = False
	test_fail = False

	# Test number of retransmissions
	p = Dot11(FCfield="to-DS", addr1="00:11:00:00:02:01", addr2="00:11:00:00:02:01", type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, f"Injected frames seem to be (re)transitted {num} times")
	if num == 0:
		log(ERROR, "Couldn't capture injected frame. Please restart the test.")
		test_fail = True
	elif num == 1:
		log(WARNING, "Injected frames don't seem to be retransmitted!")
		suspicious = True

	# Test ACK towards an unassigned MAC address
	p = Dot11(FCfield="to-DS", addr1=addr1, addr2="00:22:00:00:00:01", type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, f"Captured {num} (re)transmitted frames to the AP when using a spoofed sender address")
	if num == 0:
		log(ERROR, "Couldn't capture injected frame. Please restart the test.")
		test_fail = True
	if num > 2:
		log(STATUS, "  => Acknowledged frames with a spoofed sender address are still retransmitted. This has low impact.")

	# Test ACK towards an assigned MAC address
	p = Dot11(FCfield="to-DS", addr1=addr1, addr2=addr2, type=2, SC=33<<4)
	num = len(inject_and_capture(sout, sin, p, retries=1))
	log(STATUS, f"Captured {num} (re)transmitted frames to the AP when using the real sender address")
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


#### Main test function ####

def test_injection(iface_out, iface_in=None, peermac=None, ownmac=None, testack=True):
	status = 0

	# We start monitoring iface_in already so injected frame won't be missed
	sout = L2Socket(type=ETH_P_ALL, iface=iface_out)
	driver_out = get_device_driver(iface_out)

	# Workaround to properly inject fragmented frames (and prevent it from blocking Tx queue).
	sout.mf_workaround = driver_out in ["iwlwifi", "ath9k_htc"]
	if sout.mf_workaround:
		log(WARNING, f"Detected {driver_out}, using workaround to reliably inject fragmented frames.")

	# Print out what we are tested. Abort if the driver is known not to support a self-test.
	log(STATUS, f"Injection test: using {iface_out} ({driver_out}) to inject frames")
	if iface_in == None:
		log(WARNING, f"Injection selftest: also using {iface_out} to capture frames. This means the tests can detect if the kernel")
		log(WARNING, f"                    interferes with injection, but it cannot check the behaviour of the device itself.")
		if driver_out in ["mt76x2u"]:
			log(WARNING, f"                    WARNING: self-test with the {driver_out} driver can be unreliable.")
		elif not driver_out in ["iwlwifi", "ath9k_htc"]:
			log(WARNING, f"                    WARNING: it is unknown whether a self-test works with the {driver_out} driver.")

		sin = sout
	else:
		driver_in = get_device_driver(iface_in)
		log(STATUS, f"Injection test: using {iface_in} ({driver_in}) to capture frames")
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

	# This tests basic injection capabilities
	status |= test_injection_fragment(sout, sin, valid)

	# Perform some actual injection tests
	status |= test_injection_fields(sout, sin, spoofed, "spoofed MAC addresses")
	status |= test_injection_fields(sout, sin, valid, "(partly) valid MAC addresses")
	status |= test_injection_order(sout, sin, spoofed, "spoofed MAC addresses")
	status |= test_injection_order(sout, sin, valid, "(partly) valid MAC addresses")

	# Acknowledgement behaviour tests
	if iface_in != None and testack:
		# We search for an AP on the interface that injects frames because:
		# 1. In mixed managed/monitor mode, we will otherwise detect our own AP on the sout interface
		# 2. If sout interface "sees" the AP this assure it will also receive its ACK frames
		# 3. The given peermac might be a client that goes into sleep mode
		channel = get_channel(sin.iface)
		log(STATUS, f"--- Searching for AP on channel {channel} to test ACK behaviour.")
		apmac, ssid = get_nearby_ap_addr(sout)
		if apmac == None and peermac == None:
			raise IOError("Unable to find nearby AP to test injection")
		elif apmac == None:
			log(WARNING, f"Unable to find AP. Try a different channel? Testing ACK behaviour with peer {peermac}.")
			destmac = peermac
		else:
			log(STATUS, f"Testing ACK behaviour by injecting frames to AP {ssid} ({apmac}).")
			destmac = apmac
		test_injection_ack(sout, sin, addr1=destmac, addr2=ownmac)

	# Show a summary of results/advice
	log(STATUS, "")
	if status == 0:
		log(STATUS, "==> The most important tests have been passed successfully!", color="green")
	if status & FLAG_NOCAPTURE != 0:
		log(WARNING, f"==> Failed to capture some frames. Try another channel or use another monitoring device.")
	if status & FLAG_FAIL !=0 :
		log(ERROR, f"==> Some tests failed. Are you using patched drivers/firmware?")

	sout.close()
	sin.close()

