# <div align="center">Summary of Vulnerabilities</div>

This document contains a summary of the discovered vulnerabilities. Every bullet point corresponds to an individual vulnerability.

## Design Flaws

- **Accepting non-SSP A-MSDU frames**: The 802.11 standard doesn't mandate that the A-MSDU flag in the plaintext QoS field is authenticated. Against devices that support receiving non-SSP A-MSDU frames, an adversary can abuse this to inject arbitrary network packets. The attack applies to all protected Wi-Fi networks, including WEP, WPA, WPA2, and WPA3.

- **Accepting short A-MSDU frames in non-DMG networks**: The 802.11 standard doesn't mandate that the short A-MSDU flag in the plaintext QoS field is authenticated in non-DMG networks. Against devices that support receiving short A-MSDU frames, an adversary can abuse this to spoof short A-MSDU frames. The attack applies to all protected Wi-Fi networks, including WEP, WPA, WPA2, and WPA3. The practical impact of this vulnerability in practice is unclear.

- **Reassembling fragments encrypted under different keys**: The 802.11 standard doesn't mandate that all fragments of a frame are encryted using the same key. An adversary can abuse this to decrypt selected fragments. The attack works against the WEP, CCMP, and GCMP encryption protocol, meaning it works against WPA2 and WPA3 networks as well. A WPA network is unaffected if the TKIP encryption cipher is being used.

- **Not clearing fragments from memory when (re)connecting to a network:** The 802.11 standard doesn't mandate that received fragments must be cleared from memory after (re)connecting to a network. Under the right circumstances an adversary can abuse this to inject arbitrary network packets and/or decrypt user data. The attack works against the WEP, CCMP, and GCMP encryption cipher, meaning it works against WPA2 and WPA3 networks as well. A WPA network is unaffected if the TKIP encryption cipher is being used.

## Common Implementation Vulnerabilities

- **Reassembling encrypted fragments with non-consecutive packet numbers**: Vulnerable implementations defragment (i.e. reassemble) fragments with non-consecutive packet numbers. An adversary can abuse this to decrypt selected fragments. This vulnerability is exploitable under the right circumstances again the WEP, CCMP, and GCMP encryption ciphers, meaning it's exploitable in WPA2 and WPA3 networks as well.

- **Reassembling mixed encrypted/plaintext fragments**: Vulnerable implementations defragment (i.e. reassemble) fragments even though some of them were sent in plaintext while connected to a protected Wi-Fi network. An adversary can potentially abuse this to inject packets and decrypt selected fragments.

- **Accepting plaintext broadcast fragments as full frames (while connected to an encrypted network)**: Vulnerable implementations process broadcast fragments as full frames, and moreover accept plaintext broadcast fragments as full frames. An adversary can abuse this to inject arbitary network packets.

- **Accepting plaintext A-MSDU frames that start with an rfc1042 header (in an encrypted network)**: Vulnerable implementations accept plaintext A-MSDU frames as long as the first 6 to 8 bytes correspond to a valid rfc1042 (e.g. EAPOL LLC/SNAP) header. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

## Other Implementation Vulnerabilities

- **Accepting plaintext data frames when connected to an encrypted network**: Vulnerable implementations accept plaintext (fragmented) frames when connected to an encrypted network. An adversary can abuse this to inject arbitrary packets independent of the network configuration.

- **Forwarding EAPOL frames even though the sender is not yet authenticated**: Vulnerable APs will forward EAPOL frames to other clients even though the sender has not yet authenticated. Although on its own this cannot be abused to attack the AP, it facilitates attacks against connected clients.

- **Not verifying the TKIP MIC of (fragmented) frames**: Vulnerable implementations do not verify the  Message Integrity Check, i.e., authenticity, of (fragmented) TKIP frames. An adversary can abuse this to inject and possibly decrypt packets.

- **Processing fragmented frames as full frames**: Vulnerable implementations treat fragmented frames as full frames. An adversary can abuse this to inject arbitrary packets, independent of the network configuration.

