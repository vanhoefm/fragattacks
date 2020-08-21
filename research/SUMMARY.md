# <div align="center">Summary of Vulnerabilities</div>

This document contains a summary of the discovered vulnerabilities.

## Design Flaws

- **Accepting non-SSP A-MSDU frames**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving non-SSP A-MSDU frames, which is mandatory as part of 802.11n, an adversary can abuse this to inject arbitrary network packets.

- **Reassembling fragments encrypted under different keys**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption key is periodically renewed.

- **Not clearing fragments from memory when (re)connecting to a network:** The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that received fragments must be cleared from memory after (re)connecting to a network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or decrypt user data.

## Common Implementation Vulnerabilities

- **Reassembling encrypted fragments with non-consecutive packet numbers**: Vulnerable implementations defragment (i.e. reassemble) fragments with non-consecutive packet numbers. An adversary can abuse this to decrypt selected fragments. This vulnerability is exploitable when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption cipher is used (e.g. all WPA2 and WPA3 networks use CCMP or GCMP).

- **Reassembling mixed encrypted/plaintext fragments**: Vulnerable implementations defragment (i.e. reassemble) fragments even though some of them were sent in plaintext while connected to a protected Wi-Fi network. This vulnerability can be abused to inject packets and/or decrypt selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption cipher is used (e.g. all WPA2 and WPA3 networks use CCMP or GCMP).

- **Accepting plaintext broadcast fragments as full frames (while connected to an encrypted network)**: Vulnerable implementations process broadcast fragments as full frames, and moreover accept plaintext broadcast fragments as full frames. An adversary can abuse this to inject arbitary network packets.

- **Accepting plaintext A-MSDU frames that start with an rfc1042 header (in an encrypted network)**: Vulnerable implementations accept plaintext A-MSDU frames as long as the first 6 to 8 bytes correspond to a valid rfc1042 (i.e. EAPOL LLC/SNAP) header. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

## Other Implementation Vulnerabilities

- **Accepting plaintext data frames when connected to an encrypted network**: Vulnerable implementations accept plaintext frames when connected to a protected Wi-Fi network. An adversary can abuse this to inject arbitrary packets independent of the network configuration.

- **Accepting plaintext fragmented data frames when connected to an encrypted network**: Vulnerable implementations accept plaintext fragmented frames when connected to a projected Wi-Fi network. An adversary can abuse this to inject arbitrary packets independent of the network configuration.

- **Forwarding EAPOL frames even though the sender is not yet authenticated**: Vulnerable APs will forward EAPOL frames to other clients even though the sender has not yet successfully authenticated to the AP. This makes it easier to exploit vulnerabilities in connected clients.

- **Not verifying the TKIP MIC of fragmented frames**: Vulnerable implementations do not verify the Message Integrity Check, i.e., authenticity, of fragmented TKIP frames. An adversary can abuse this to inject and possibly decrypt packets.

- **Processing fragmented frames as full frames**: Vulnerable implementations treat fragmented frames as full frames. An adversary can abuse this to inject arbitrary packets, independent of the network configuration.

