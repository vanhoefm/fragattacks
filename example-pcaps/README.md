# Example Packet Captures

The following captures are based on executing the test tool and **illustrate the root cause** of the vulnerabilities. In all captures the Wi-Fi network being used has SSID `testnetwork` with password `abcdefgh`.

Note that the captures were made on the same network card that was injecting packets (with hardware encryption disabled). On Linux, **injected packets are shown twice in a network capture**. First it shows the frame as injected by userspace (the test tool will always set the `Has Seqnum` and `Order` in the radiotap header). After the frame was sent, the Linux kernel echoes the actual transmitted frame a second time. This second frame for instance contains the bitrate that was used to send the frame and whether an acknowledgement was received in response.

## A-MSDU attacks

- [`amsdu-inject-fromap.pcapng`](amsdu-inject-fromap.pcapng): used command was `amsdu-inject --ap`. Frame 124 contains the attack ping packet.

## Mixed key attacks

- [`ping_I_F_BE_AE-fromap.pcapng`](ping_I_F_BE_AE-fromap.pcapng): used command was `ping I,F,BE,AE --ap`. Frame 170 contains the first fragment encrypted under TK `e4e41ad934f5caa7ff0064ad96609c2f` and frame 180 contains the second fragment encrypted under TK `1f38eee5960fb9d9d77e566c4b18008d`. The ping reply is shown in frame 185.

## Cache attacks

- [`ping_I_E_R_E-fromclient.pcapng`](ping_I_E_R_E-fromclient.pcapng): used command was `ping I,E,R,E`. Frame 69 contains the first fragment encrypted under TK `dda31c8516b9d92581fc17e4a8f1b47b`. Frame 72 and 74 shows that the client is reassociating. Frame 98 contains the second fragment encrypted under TK `b4d1a94a4d126dbd39ec3557969f430b`. The ping reply is contained in frame 101.

- [`ping_I_E_R_E__full-recon-fromclient.pcapng`](ping_I_E_R_E__full-recon-fromclient.pcapng): used command was `ping I,E,R,E --full-recon`. Frame 63 contains the first fragmented encrypted under TK `7911b7173daf49c898fa42119232885e`. Frame 66 shows the deauthentication frame, and frames 67 and 71 show that the client is authenticating and reassociating. Frame 107 contains the second fragment encrypted under TK `292184b9c862a4b640d4c920aba35a48`. The ping reply is contained in frame 110.

## Non-consecutive PNs attack

- [`ping_I_E_E___inc_pn_2-fromap.pcapng`](ping_I_E_E___inc_pn_2-fromap.pcapng): used command was `ping I,E,E --inc-pn 2 --ap`. Frame 130 contains the first fragment with CCMP Packet Number 0x101 and frame 132 contains the second fragment with CCMP Packet Number 0x103.

## Mixed plain/encrypt attack

- [`linux-plain-fromap.pcapng`](linux-plain-fromap.pcapng): used command was `linux-plain --ap`. Frame 79 contains the first legitimate encrypted fragment, frame 81 contains the second legitimate encrypted fragment but with a different sequence number, frame 83 contains the injected plaintext second fragment (with the same sequence number as the first fragment). The ping reply is in frame 94.

- [`ping_I_E_P-fromclient.pcapng`](ping_I_E_P-fromclient.pcapng): used command was `ping I,E,P`. Frame 51 contains the encrypted first fragment, frame 54 the plaintext second fragment, and frame 57 the encrypted ping reply.

- [`ping_I_P-fromclient.pcapng`](ping_I_P-fromclient.pcapng): used command was `ping I,P`. Frame 59 contains the injected plaintext ping request and frame 62 contains the encrypted ping reply.

## Broadcast fragment attack

- [`ping_D_BP___bcast_ra-fromap.pcapng`](ping_D_BP___bcast_ra-fromap.pcapng): used command was `ping D,BP --bcast-ra --ap`. Frame 21 contains the attack packet. Capture `ping_D_BP___bcast_ra-onclient.pcap` shows the result on the target device (Samsung i9305) where frame 13 contains the injected ping request.

## A-MSDU EAPOL attack

- [`eapol-amsdu_BP-fromap.pcapng`](eapol-amsdu_BP-fromap.pcapng): used command was `eapol-amsdu BP --ap`. Frame 43 contains the injected ping packet. Capture `eapol-amsdu_BP-onclient.pcapng` shows the result on the target device (Pixel 4 XL) where frame 4 contains the injected ping request. Note that frame 3 is an invalid packet that is a side-effect of the attack (it's the content of the first A-MSDU subframe whose purpose was to make the packet look like an EAPOL handshake message).

## AP forwards EAPOL attack

- [`eapol-inject-fromclient.pcapng`](eapol-inject-fromclient.pcapng): used command was `eapol-inject 7e:1e:cd:49:9f:c6`. Frame 39 contained the inject EAPOL packet sent from client `64:70:02:2f:d7:67` in plaintext before this client authenticated. The AP forwards this EAPOL towards the destination client `7e:1e:cd:49:9f:c6` as an encrypted frame in frame 50 (we confirmed on the destination with Wireshark that this indeed is the forwarded packet).

## No fragmentation support attack

- [`ping_I_D_E-fromap.pcapng`](ping_I_D_E-fromap.pcapng): used command was `ping I,D,E --ap`. Frame 51 contains the full ping request in the second fragment of a Wi-Fi frame (no other fragment is sent). Frame 58 contains the ping response from the vulnerable device.

