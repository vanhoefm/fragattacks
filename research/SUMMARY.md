# <div align="center">Summary of Vulnerabilities</div>

## Design Flaws

- **CVE-2020-24588: Accepting non-SPP A-MSDU frames**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving non-SPP A-MSDU frames, which is mandatory as part of 802.11n, an adversary can abuse this to inject arbitrary network packets.

- **CVE-2020-24587: Reassembling fragments encrypted under different keys**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary can abuse this to exfiltrate selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption key is periodically renewed.

- **CVE-2020-24586: Not clearing fragments from memory when (re)connecting to a network:** The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that received fragments must be cleared from memory after (re)connecting to a network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.

## Implementation flaws allowing trivial packet injection

- **CVE-2020-26145: Accepting plaintext broadcast fragments as full frames (in an encrypted network)**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

- **CVE-2020-26144: Accepting plaintext A-MSDU frames that start with an RFC1042 header with EtherType EAPOL (in an encrypted network)**: Vulnerable Wi-Fi implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

- **CVE-2020-26140: Accepting plaintext data frames in a protected network**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept plaintext frames in a protected Wi-Fi network. An adversary can abuse this to inject arbitrary data frames independent of the network configuration.

- **CVE-2020-26143: Accepting _fragmented_ plaintext data frames in a protected network**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept fragmented plaintext frames in a protected Wi-Fi network. An adversary can abuse this to inject arbitrary data frames independent of the network configuration.

## Other Implementation Vulnerabilities

- **CVE-2020-26139: Forwarding EAPOL frames even though the sender is not yet authenticated**: Vulnerable Access Points (APs) forward EAPOL frames to other clients even though the sender has not yet successfully authenticated to the AP. An adversary might be able to abuse this in projected Wi-Fi networks to launch denial-of-service attacks against connected clients, and this makes it easier to exploit other vulnerabilities in connected clients.

- **CVE-2020-26146: Reassembling encrypted fragments with non-consecutive packet numbers**: Vulnerable WPA, WPA2, or WPA3 implementations reassemble fragments with non-consecutive packet numbers. An adversary can abuse this to exfiltrate selected fragments. This vulnerability is exploitable when another device sends fragmented frames and the WEP, CCMP, or GCMP data-confidentiality protocol is used. Note that WEP is vulnerable to this attack by design.

- **CVE-2020-26147: Reassembling mixed encrypted/plaintext fragments**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations reassemble fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP data-confidentiality protocol is used.

- **CVE-2020-26142: Processing fragmented frames as full frames**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations treat fragmented frames as full frames. An adversary can abuse this to inject arbitrary network packets, independent of the network configuration.

- **CVE-2020-26141: Not verifying the TKIP MIC of fragmented frames**: Vulnerable Wi-Fi implementations do not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-confidentiality protocol.

