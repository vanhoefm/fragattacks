#!/usr/bin/env python3
from libwifi import *

def netbsd_forcefrag_verify():
	# Capture made using independent TL-WN722N
	cap = rdpcap("../../captures/netbsd-forward-eapol-before-auth-fragmented-1.pcapng")
	fragments = []
	fragments.append(cap[1204][Dot11])
	fragments.append(cap[1207][Dot11])
	fragments.append(cap[1262][Dot11])
	fragments.append(cap[1262][Dot11])
	fragments.append(cap[1266][Dot11])
	fragments.append(cap[1270][Dot11])
	fragments.append(cap[1277][Dot11])
	fragments.append(cap[1355][Dot11])

	# Taken from debug output hostapd on NetBSD
	tk = "b7 2a 27 4c 50 6b c1 3b 86 3d 9a 97 fe 85 8b c9"
	tk = bytes.fromhex(tk.replace(" ", ""))

	print("Testing decryption")
	for frag in fragments:
		decrypt_ccmp(frag, tk)

	# Encrypt newly constructed packet
	pt = fragments[0].copy()
	pt.remove_payload()
	# Note: the import to give the original number of A's so the EAPOL length
	# fields are properly reconstructed. After this, we trim the length.
	payload = LLC()/SNAP()/EAPOL()/EAP(raw(EAP()/Raw(b"A" * 2600)))
	pt = pt/raw(payload)[:2314]
	test = encrypt_ccmp(pt, tk, pn=1)

	print("Testing reconstructed encryption")
	assert raw(fragments[0]) == raw(test)

def main():
	netbsd_forcefrag_verify()

if __name__ == "__main__":
	main()

