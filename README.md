# <div align="center">FragAttacks: Fragmentation & Aggregation Attacks</div>

# 1. Introduction

This repository contains the **FragAttacks** tool. It can test Wi-Fi clients and access points for **fr**agmentation
and **ag**gregation **attacks**. These vulnerabilities affect _all_ protected Wi-Fi networks. For more information
about these vulnerabilities see [fragattacks.com](https://www.fragattacks.com).

The following additional resources are available:

- The [USENIX Security presentation](https://youtu.be/OJ9nFeuitIU) gives a summary of the discovered vulnerabilities.
- An overview of all [assigned CVEs](SUMMARY.md) is available.
- Slides that summarize the [root cause and impact](https://papers.mathyvanhoef.com/fragattacks-slides-summary-2021-03-8.pdf) of each vulnerability.
- A [2-page summary](https://papers.mathyvanhoef.com/fragattacks-overview.pdf) of resulting attacks and preconditions.
- [Handouts](https://papers.mathyvanhoef.com/fragattacks-slides-2021-03-8.pdf) that give extra background and explain the vulnerabilities in more detail.
- A [demonstration](https://youtu.be/88YZ4061tYw) of three example attacks.
- The [research paper](https://papers.mathyvanhoef.com/usenix2021.pdf) published at USENIX Security.
- Example [network captures](example-pcaps/) illustrating some of the vulnerabilities.
- A [live USB image](#id-live-image) with this tool and modified drivers pre-installed.
- A list of [known advisories](ADVISORIES.md) from companies

See the [change log](#id-change-log) for a detailed overview of updates to the tool made since 11 August 2020.
This change log also contains information on which version of hostap the FragAttacks tool is based on.

Note that the attacks are identical against WPA2 and WPA3 because their CCMP and GCMP encryption ciphers are identical.
Older WPA networks by default use TKIP for encryption, and the applicability of the [attacks against TKIP](https://www.fragattacks.com/index.html#tkip)
are discussed in the paper and on the website. To illustrate that Wi-Fi has been vulnerable since its creation, the paper
and website also briefly discusses the applicability of the [attacks against WEP](https://www.fragattacks.com/index.html#wep).


<a id="id-supported-cards"></a>
# 2. Supported Network Cards

Only specific wireless network cards are supported. This is because some network cards may overwrite the
sequence or fragment number of injected frames, or may reorder frames of different priority, and this
interferes with the test tool (i.e. the tool might say a device is secure although it's not).
I have confirmed that the following network cards work properly:

|      Network Card      | USB | 5GHz |        mixed mode       |      injection mode     |
| ---------------------- | --- | ---- | ----------------------- | ----------------------- |
| Technoethical N150 HGA | Yes | No   | patched driver/firmware | patched driver/firmware |
| TP-Link TL-WN722N v1.x | Yes | No   | patched driver/firmware | patched driver/firmware |
| Alfa AWUS036NHA        | Yes | No   | patched driver/firmware | patched driver/firmware |
| Intel Wireless-AC 8265 | No  | Yes  | patched driver          | yes                     |
| Intel Wireless-AC 3160 | No  | Yes  | patched driver          | yes                     |
| Alfa AWUS036ACM        | Yes | Yes  | patched driver          | yes                     |
| Netgear WN111v2        | Yes | No   | patched driver          | yes                     |
| Alfa AWUS036ACH        | Yes | Yes  | no                      | yes                     |

The three two colums signify:

1. Mixed mode: whether the network card can be used in the recommended [mixed mode](#id-mixed-mode).

2. Injection mode: whether the network card can be used as a second interface to inject frames in [injection mode](#id-injection-mode).

_Yes_ indicates the card works out-of-the-box in the given mode. _Patched driver/firmware_
means that the card is compatible when used with patched drivers and/or firmware.
_No_ means this mode is not supported by the network card.
**I recommend using the test tool in mixed mode.**

Note that USB devices can be used inside a virtual machine, and the modified drivers and/or firmware
can be installed in this virtual machine. However, I found that the usage of virtual machines can
make network cards less reliable, and I instead recommend the usage of a live USB image if you cannot
install the modified drivers/firmware natively.

My experience with the above network cards can be found [here](#id-notes-device-support). Summarized:

- I recommend the Technoethical N150 HGA in mixed mode. This device is identical to the TP-Link TL-WN722N v1.x
  and requires the usage of patched drivers and firmware.

- The Intel 3160 and 8265 are supported and extensively tested. Sometimes their firmware crashed but
  a reboot makes the network card usable again. The Intel AX200 is not compatible with the test tool.

- During my tests the AWUS036ACM dongle was unreliable when connected to a USB3.0 port, but worked
  well when connected to a USB2.0 port. This behaviour may depend on your computer.

- The WN111v2 seems to work well, although I did not test it extensively.

- The driver for the AWUS036ACH is not part of the Linux kernel and requires the installation of a separate
  driver. On Kali you can install this driver through the package manager. This card was not extensivly tested.

If you are unable to find one of the above network cards, you can search for [alternative network cards](#id-alternative-cards)
that have a high chance of also working. When using a network card that is not explicitly supported
I strongly recommend to first run the [injection tests](#id-injection-tests) before using it,
and using the tool against a known-vulnerable implementation to confirm the tool works properly.

<a id="id-prerequisites"></a>
# 3. Prerequisites

The test tool was tested on Kali Linux and Ubuntu 20.04. To install the required dependencies, execute:

	# Kali Linux and Ubuntu:
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools python3-venv \
		aircrack-ng rfkill
	# Kali Linux:
	sudo apt-get install firmware-atheros
	# Ubuntu/Debian:
	sudo apt-get install firmware-ath9k-htc

Now clone this repository, build the tools, and configure a virtual python3 environment:

	git clone https://github.com/vanhoefm/fragattacks.git fragattacks
	cd fragattacks/research
	./build.sh
	./pysetup.sh

The above instructions only have to be executed once. After pulling in new code using git you do
have to execute `./build.sh` and `./pysetup.sh` again.

<a id="id-patched-drivers"></a>
# 4. Patched Drivers

Install patched drivers using:

	sudo apt-get install bison flex linux-headers-$(uname -r)
	git clone https://github.com/vanhoefm/fragattacks-drivers58.git fragattacks-drivers58
	cd fragattacks-drivers58
	make defconfig-wifi
	make -j 4
	sudo make install

This compiles the drivers for most network cards supported by Linux. If you only want to compile
the drivers for network cards I explicitly tested, use `make defconfig-experiments` instead.
During the install command you may get several warnings containing `.. needs unknown symbol ..`. You can
ignore these warning as long they do not contain the directory `/lib/modules/*/updates/` and the
compiled drivers are working.

Now install patched `ath9k_htc` firmware:

	cd research/ath9k-firmware/
	./install.sh
	# Now reboot

The `./install.sh` script assumes the `ath9k_htc` firmware images are located in the
directory `/lib/firmware/ath9k_htc`. If this is not the case on your system you have
to manually copy `htc_7010.fw` and `htc_9271.fw` to the appropriate directory.

After installing the patched drivers and firmware you must unplug your Wi-Fi dongles
and **reboot your system**. The above instructions have to be executed again if your
Linux kernel gets updated or if the patched drivers get updated.

Note that even when your device works out of the box, I still recommend to install the modified
drivers, as this assures there are no unexpected regressions in kernel and driver code.

In case you cannot install the modified drivers/firmware natively, you can download a
**[live USB image](#id-live-image)** that contains the modified drivers/firmware along with our test tool.
Alternatively, you can use a virtual machine with USB network cards, although I found that
using a virtual machine is less reliable in pratice.

<a id="id-before-every-usage"></a>
# 5. Before every usage

Every time you want to use the test tool, you first have to load the virtual python environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with the test tool.
Also make sure no other network services are causing outgoing traffic. You can assure this by
using iptables to block traffic by executing `./droptraffic.sh` (you can revert this by rebooting).
Optionally check using `sudo airmon-ng check` to see which other processes might be using the
wireless network card and might interfere with our tool.

The test tool can test both clients and APs:

- Testing APs: **configure the AP you want to test** by editing `research/client.conf`. This is a
  standard `wpa_supplicant` configuration file, see the [hostap documentation](https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf)
  for an overview of all the options it supports.

- Testing clients: you must execute the test tool with the `--ap` parameter (see below). This
  instructs the tool into creating an AP with as name **testnetwork** and password **abcdefgh**. Connect
  to this network with the client you want to test. By default the client must request an IP
  using DHCP. To edit properties of the created AP, such as the channel it's created on, you
  can edit `research/hostapd.conf`.

<a id="id-interface-modes"></a>
# 6. Interface Modes

<a id="id-mixed-mode"></a>
## 6.1. Mixed mode

This mode requires only one wireless network card, but generally requires a patched driver and/or
firmware. See [Patched Drivers](#id-patched-drivers) on how to install patched drivers/firmware, and
[Supported Network Cards](#id-supported-cards) for compatible network cards. Execute the test
tool in this mode using:

	./fragattack.py wlan0 [--ap] $COMMAND

Possible values of `$COMMAND` are listed in [testing for vulnerabilities](#id-testing-for-flaws)
and [extended vulnerability tests](#id-extended-tests).

One advantage of this mode is that it works fairly well when testing clients that may enter a sleep state.
Nevertheless, if possible, I recommend disabling sleep functionality of the client being tested,
see [Handling sleep mode](#id-handling-sleep).

<a id="id-injection-mode"></a>
## 6.2. Injection mode

This mode requires two wireless network cards: one will act as an AP or the client, and the other
one will be used to inject frames. The advantage is that this mode way work without requiring patched
drivers. Execute the test tool in this mode using:

	./fragattack.py wlan0 --inject wlan1 [--ap] $COMMAND

Here interface wlan0 will act as a legitimate client or AP, and wlan1 will be used to inject
frames. For wlan0, any card that supports normal client or AP mode on Linux can be used. For
wlan1, a card must be used that supports injection mode according to [Supported Network Cards](#id-supported-cards).

When testing clients in this mode, injected frames may be sent when the client is in a sleep state.
This causes attacks to fail, so you must make sure the client will not enter a sleep state.

<a id="id-hwsim-mode"></a>
## 6.3. Hwsim mode

This mode is experimental and only for research purposes. See [hwsim mode details](#id-hwsim-details)
for more information.

<a id="id-testing-for-flaws"></a>
# 7. Testing for Vulnerabilities

You can test devices by running the test tool as discussed in [interface modes](#id-interface-modes)
and replacing `$COMMAND` with one of the commands in the table blow. We assume that clients will
request an IP using DHCP (if this is not the case see [static IP configuration](#id-static-ip-config)).
All commands work against both clients and APs unless noted otherwise.

The tool outputs `TEST COMPLETED SUCCESSFULLY` if the device is vulnerable to the attack corresponding
to the given `$COMMAND`, and outputs `Test timed out! Retry to be sure, or manually check result` if
the device is not vulnerable. After the test completed you can close the test tool using `CTRL+C`.
Most attacks have several slight variants represented by different `$COMMAND` values.

Verifying the result of some tests requires running tcpdump or wireshark on the device under test (the
table below states if tcpdump has to be used). This tcpdump packet capture must only include packets that
passed PHY and MAC layer processing. For instance, on Linux this capture should be made while the
wireless interface is in "managed" or "ap" mode, not in monitor mode, meaning the capture will only
contain packets that passed processing at the Wi-Fi layer. See [avoiding tcpdump on APs](#id-avoiding-tcpdump-aps)
for a discussion on how some tests can nevertheless be performed without having to run tcpdump on APs.

To **verify your test setup**, the first command in the table below performs a normal ping that must
succeed. The second command sends the ping as two fragmented Wi-Fi frames, and should only fail
in the rare case that the tested device doesn't support fragmentation. In case one of these tests
is not working, follow the instructions in [network card injection test](#id-injection-tests)
to assure your network card is properly injecting frames. If the client being tested might enter
sleep mode, see [Handling sleep mode](#id-handling-sleep).

The third, fourth, and fifth commands are not attacks but verify basic defragmentation behaviour of a
device and are further discussed below the table.

|             Command              | Short description
| -------------------------------- | ---------------------------------
| <div align="center">*[Sanity checks](#id-test-sanity)*</div>
| `ping`                           | Send a normal ping.
| `ping I,E,E`                     | Send a normal fragmented ping.
| <div align="center">*[Basic device behaviour](#id-test-behaviour)*</div>
| `ping I,E,E --delay 5`           | Send a normal fragmented ping with a 5 second delay between fragments.
| `ping-frag-sep`                  | Send a normal fragmented ping with fragments separated by another frame.
| `ping-frag-sep --pn-per-qos`     | Same as above, but also works if the target only accepts consecutive PNs.
| <div align="center">*[A-MSDU attacks (§3)](#id-test-amsdu)*</div>
| `ping I,E --amsdu`               | Send a ping encapsulated in a normal (non SPP protected) A-MSDU frame.
| `amsdu-inject`                   | Simulate attack: send A-MSDU frame whose start is also a valid rfc1042 header.
| `amsdu-inject-bad`               | Same as above, but against targets that incorrectly parse the frame.
| <div align="center">*[Mixed key attacks (§4)](#id-test-mixedkey)*</div>
| `ping I,F,BE,AE`                 | Inject two fragments encrypted under a different key.
| `ping I,F,BE,AE --pn-per-qos`    | Same as above, but also works if the target only accepts consecutive PNs.
| <div align="center">*[Cache attacks (§5)](#id-test-cache)*</div>
| `ping I,E,R,AE`                  | Inject a fragment, try triggering a _reassociation_, and inject second fragment.
| `ping I,E,R,E`                   | Same as above, but with a longer delay before sending the second fragment.
| `ping I,E,R,AE --full-recon`     | Inject a fragment, _deauthenticate_ and reconnect, then inject second fragment.
| `ping I,E,R,E --full-recon`      | Same as above, but with a longer delay before sending the second fragment.
| <div align="center">*[Non-consecutive PNs attack (§6.2)](#id-test-nonconsec)*</div>
| `ping I,E,E --inc-pn 2`          | Send a fragmented ping with non-consecutive packet numbers.
| <div align="center">*[Mixed plain/encrypt attack (§6.3)](#id-test-mixplainenc)*</div>
| `ping I,E,P`                     | Send a fragmented ping: first fragment encrypted, second fragment in plaintext.
| `ping I,P,E`                     | Send a fragmented ping: first fragment in plaintext, send fragment encrypted.
| `ping I,P`                       | Send a plaintext ping.
| `ping I,P,P`                     | Send a fragmented ping: both fragments are sent in plaintext.
| `linux-plain`                    | Mixed plaintext/encrypted fragmentation attack specific to Linux.
| <div align="center">*[Broadcast fragment attack (§6.4)](#id-test-broadcastfrag)*</div>
| `ping I,D,P --bcast-ra`          | Send a unicast ping in a plaintext broadcasted 2nd fragment once connected.
| `ping D,BP --bcast-ra`           | Same as above, but frame is sent during 4-way handshake (check with tcpdump).
| <div align="center">*[A-MSDU EAPOL attack (§6.5)](#id-test-cloackamsdu)*</div>
| `eapol-amsdu I,P`                | Send a plaintext A-MSDU containing a ping request cloacked as an EAPOL frame.
| `eapol-amsdu BP`                 | Same as above, but the frame is sent during the handshake (check with tcpdump).
| `eapol-amsdu-bad I,P`            | Send malformed plain. A-MSDU containing a ping req. cloacked as EAPOL frame.
| `eapol-amsdu-bad BP`             | Same as above, but the frame is sent while connecting (check with tcpdump).

How commands match to CVEs is listed below. Note that for implementation flaws we list a reference
CVE identifier, however, vendors may use different CVEs because an implementation vulnerability normally
receives a unique CVE for each affected codebase. We nevertheless recommend to always refer to these reference
CVEs as a way to easily refer to each type of discovered implementation flaw.

<a id="id-test-sanity"></a>
## 7.1. Sanity checks

- `ping`: This test must always succeed. If it fails, something is wrong with the test setup.

- `ping I,E,E`: This test should succeed against all modern laptops, smartphones, and APs. If it fails,
  something is likely wrong with the test setup. Try adding the `--icmp-size 100` parameter as a fix. If
  it works with this extra parameter, you have to execute all other tests with this extra parameter as well.
  The only time I encountered this test failing for valid reasons is when the tested device doesn't support
  receiving fragmented frames, which can be the case on lightweight IoT devices and, for example, OpenBSD.

<a id="id-test-behaviour"></a>
## 7.2. Basic device behaviour

- `ping I,E,E --delay 5`: This test is used to check the maximum accepted delay between two fragments.
  If this test doesn't work, try it again with `--delay 1.5` or lower. For instance, Linux removes fragments
  from memory after 2 seconds, meaning a delay of 1.8 will work while 2.2 will result in no reply. In case the maximum
  accepted delay is low, all fragments sent in other tests must be sent within this maximum accepted delay.
  Otherwise, tests will trivially fail and you might conclude a device isn't vulnerable to an attack even
  though it actually is.

- `ping-frag-sep`: This tests sends a fragmented Wi-Fi frame that is seperated by an unrelated frame.
  That is, it sends the first fragment, then a (normal) unrelated Wi-Fi frame, and finally the second fragment.
  In case this test fails, the mixed key attack and cache attack will likely also fail (since they require
  sending other frames between two fragments). The only purpose of this test is to better understand the
  behaviour of a device and to learn why other tests might be failing.

- `ping-frag-sep --pn-per-qos`: Same as above, but adding the `--pn-per-qos` parameter assures both fragments
  have a consecutive Packet Number (PN). This is something that a reciever should be verifying in order to be
  secure. Unfortunately, many implementations don't verify whether PNs are consecutive.

<a id="id-test-amsdu"></a>
## 7.3. A-MSDU attack tests (§3 -- CVE-2020-24588)

The test `ping I,E --amsdu` checks if an implementation supports non-SPP A-MSDUs, in which case it is likely
vulnerable to one of the below two attacks. To prevent attacks, ideally the network must mandate the usage of
SPP A-MSDUs (and drop all non-SPP A-MSDUs). In case it's not an option to drop non-SPP A-MSDUs, temporary
mitigations are discussed in Section 7.2 of the paper.

The last two tests are used to simulate our A-MSDU injection attack:

- `amsdu-inject`: This test simulates the A-MSDU injection attack described in Section 3.2 of the paper. In particular,
  it sends an A-MSDU frame whose start is also a valid LLC/SNAP header (since this is also what happens in our reference
  attack).

- `amsdu-inject-bad`: Some devices incorrectly parse A-MSDU frames that start with a valid LLC/SNAP header causing the
  above test to fail. In that case try `amsdu-inject-bad` instead (see Section 3.6 in the paper). Note that if this test
  succeeds, the impact of the attack is effectively identical to implementations that correctly parse such frames.

<a id="id-test-mixedkey"></a>
## 7.4. Mixed key attack tests (§4 -- CVE-2020-24587)

- When running the mixed key test against an AP, the AP must be configured to regularly  (e.g. every minute)
  renew the session key (PTK) by executing a new 4-way handshake. The tool will display
  `Client cannot force rekey. Waiting on AP to start PTK rekey` when waiting for this PTK rekey handshake.
  Against a low number of APs, the test tool can also request to renew the PTK by adding the `--rekey-req`
  parameter, meaning there is no need to configure the AP to periodically renew the key.

- Some APs cannot be configured to regularly renew the session key (PTK). Against these APs you can instead
  try a cache attack test. In case the AP is vulnerable to cache attacks, then it is likely also vulnerable
  to mixed key attacks (unless these is strong evidence that contradict this, e.g., a code audit indicates
  mixed key attacks are prevented). If the AP isn't vulnerable to cache attacks, then we cannot say anything
  about its susceptibility to mixed key attacks, and in that case I recommend doing a code audit instead.

- `ping I,F,BE,AE --pn-per-qos`: The extra `--pn-per-qos` parameter assures that both injected fragments have
  consecutive packet numbers, which is required for the mixed key attack to succeed against certain devices
  (e.g. against Linux).

- Several devices implement the 4-way handshake differently and this will impact whether these tests will
  succeed or not. In case the tests fail, it is recommended to also perform the mixed key attack
  tests listed in [Extended Vulnerability Tests](#id-extended-tests).

<a id="id-test-cache"></a>
## 7.5. Cache attack tests (§5 -- CVE-2020-24586)

- When testing an AP, the tool sends a first fragment, then tries to _reassociate_ with the AP, and finally
  sends the second fragment. However, not all APs properly support the reassociation process. In that case,
  add the `--full-reconnect` option as shown in the table, which makes the test tool to _deauthenticate_
  after sending the first fragment.

- When testing a client, the tools sends a first fragment, _disassociates_ the client, and once the client
  has reconnected will send the second fragment. Ideally the client will immediately reconnect after sending
  the disassociation frame. This may require disabling all other networks in the client being tested. I also
  found that some clients don't seem to properly handle the disassocation, and in that case you can add the
  `--full-reconnect` option as shown in the table to send a deauthentication frame instead.

- I have found that it's best to execute each cache attack test several times. Sometimes a cache attack test
  might fail although the implementation _is_ vulnerable. This can be due to background noise, other devices
  sending frames to the tested device, etc.

- `ping I,E,R,AE [--full-recon]`: Here the second fragment is sent immediately after reconnecting with the
  device under test, which is important in case the device clears fragments from memory after a short time.
  Note that `full-recon` is a shorthand of `full-reconnect`.

- `ping I,E,R,E [--full-recon]`: Here the second fragment is sent 1 second after reconnecting with the
  device under test, which can be useful in case there is a small delay between completion of the handshake
  and installing the negotiated key.

- Overall it can be tedious to test if a device is vulnerable to cache attacks. Therefore I also recommend to
  perform a code audit to check if fragments stay in the memory after disassociating or deauthenticating from
  a network or after reassociating (this can also be dynamically checking using debug prints). If fragments
  stay in memory, you should consider this as a risk, even if it's unknown whether it can be exploited. This
  is similar to knowing an implementation has a buffer overflow but not (yet) knowing how to exploit it.

<a id="id-test-nonconsec"></a>
## 7.6. Non-consecutive PNs attack (§6.2 -- CVE-2020-26146)

In our experiments, this test only failed against Linux and against devices that don't support fragmentation.

<a id="id-test-mixplainenc"></a>
## 7.7. Mixed plain/encrypt attack (§6.3 -- CVE-2020-26147/26140/26143)

- `ping I,E,P` and `linux-plain`: if this test succeeds the resulting attacks are described in Section 6.3
  of the paper. Summarized, in combintation with the A-MSDU or cache vulnerability, it can be exploited to
  inject packets. When not combined with any other vulnerabilities the impact is implementation-specific
  (CVE-2020-26147).

- `ping I,P,E`: if this test succeeds it is trivial to inject plaintext frames towards the device _if_
  fragmentation is being used by the network (CVE-2020-26147).

- `ping I,P`: if this tests succeeds the implementation accepts plaintext frames in a protected Wi-Fi
  network, allowing trivial packet injection (CVE-2020-26140).

- `ping I,P,P`: if this test succeeds the implementation accepts _fragmented_ plaintext frames in a protected
  Wi-Fi network, allowing trivial packet injection (CVE-2020-26143).

<a id="id-test-broadcastfrag"></a>
## 7.8. Broadcast fragment attack tests (§6.4 -- CVE-2020-26145)

The following two tests send broadcast frames, which are not automatically retransmitted, and it is therefore
recommended to **execute them several times**. This is because background noise may prevent the tested devices
from receiving the injected broadcast frame. In my experiments, mainly clients were affected (out of the tested
APs only Free/NetBSD ones were affected).

- `ping I,D,P --bcast-ra`: Send a unicast ping in a plaintext broadcasted 2nd fragment once connected. The result
  of this variant of the attack is checked automatically by the test tool.

- `ping D,BP --bcast-ra`: Here the above frame is sent while connecting to the network (i.e. during the 4-way handshake).
  This is important because several clients and APs are only vulnerable before completing the 4-way handshake. To
  confirm the result of this test you have to run wireshark or tcpdump on the victim, and monitor whether the
  injected ping request is received by the victim. In tcpdump you can use the filter `icmp` and in wireshark you
  can also use the filter `frame contains "test_ping_icmp"` to more easily detect this ping request. In my experiments
  mainly clients were affected.

<a id="id-test-cloackamsdu"></a>
## 7.9. A-MSDU EAPOL attack tests (§6.5 -- CVE-2020-26144)

- `eapol-amsdu I,P`: This is the standard test for the implementation-specific vulnerability discussed in
  Section 6.5 of the paper. Both clients and APs can be vulnerable. Its result is checked automatically by
  the test tool.

- Tests ending on `BP` (`eapol-amsdu BP` and `eapol-amsdu-bad BP`): These tests inject the malicious frame
  during the execution of the 4-way handshake. To confirm the result of this test you have to run wireshark
  or tcpdump on the victim, and monitor whether the injected ping request is received by the victim. In tcpdump
  you can use the filter `icmp` and in wireshark you can also use the filter `frame contains "test_ping_icmp"`
  to more easily detect this ping request.

- Tests starting with `eapol-amsdu-bad` (`eapol-amsdu-bad BP` and `eapol-amsdu-bad I,P`): Several implementations
  incorrectly process A-MSDU frames whose first 6 bytes also equal a valid RFC1042 header for EAPOL. To test these
  implementations, you have to use the `eapol-amsdu-bad` test variant. Note that if this tests succeeds, the impact
  of the attack is identical to implementations that correctly parse such frames (for details see Section 3.6 and
  6.6 in the paper).

<a id="id-troubleshooting"></a>
## 7.10. Troubleshooting checklist

In case the test tool doesn't appear to be working, check the following:

1. Check that no other process is using the network card (e.g. kill your network manager).

2. If everything worked previously, try unplugging your Wi-Fi dongle, restart your computer or virtual
   machine, and then try again.

3. Assure the device you are testing doesn't enter a sleep state (causing it to miss injected frames).
   I recommend running the test tool in [mixed mode](#id-mixed-mode) since this better handles clients
   that may go into a sleep state.

4. Run the [injection tests](#id-injection-tests) to make sure injection is working properly.
   Also assure that a 20 MHz channel is used, injection on other channels is untested.

5. Check that you machine isn't generating background traffic that interferes with the tests. In
   particular, disable networking in your OS, manually kill your DHCP client/server, etc. See
   also [Before every usage](#id-before-every-usage).

6. Confirm that you are connecting to the correct network. Double-check `client.conf`.

7. Make sure the AP being tested is using (AES-)CCMP as the encryption algorithm. Other encryption
   algorithms such as TKIP or GCMP are not supported.

8. If you updated the code using git, execute `./build.sh` and `./pysetup.sh` again (see [Prerequisites](#id-prerequisites)).
   In case the patched drivers got updated, remember to recompile them as well.

9. If you are using a virtual machine, try to run the test tool from a live USB image instead.

10. Check that the tested device doesn't block ICMP ping requests. In case it doesn't reply to pings, you
    can run tcpdump or wireshark on the device, or you can try any of the other methods listed in [No ICMP Support](#id-no-icmp).

11. Run the tool with the extra parameter `--debug 2` to get extra debug output from wpa_supplicant or
    hostapd and from the test tool itself.

12. Confirm using a second monitor interface that no other frames are sent in between fragments.
    For instance, I found that my Intel device sometimes sends Block Ack Response Action frames
    between fragments, and this interfered with the defragmentation process of the device under test.

13. Double-check that you are using modified firmware if needed for your wireless network card. The test
    tool already checks this automatically for `ath9k_htc` devices. The test tool also automatically checks
    if you are using modified drivers, though it might be good to manually double-check this on your
    specific Linux distribution.

<a id="id-extended-tests"></a>
# 8. Extended Vulnerability Tests

Due to implementation variations it can be difficult to confirm/exploit certain vulnerabilities, in particular
the mixed key and cache attack can be non-trivial to confirm in practice. Therefore, I recommend to only consider
a device secure if there are explicit checks in the code to prevent these attacks. Additionally, if time permits,
I also recommend the following more advanced tests. These have a lower chance of uncovering new vulnerabilities,
but might reveal attack variants or particular device behaviour that the normal tests can't detect.

If the normal tests in [Testing for Vulnerabilities](#id-testing-for-flaws) have already confirmed the
presence of a certain vulnerability class, there is little need to test the other attack variants of that vulnerability.
All commands work against both clients and APs unless noted otherwise.

|                Command                 | Short description
| -------------------------------------- | ---------------------------------
| <div align="center">*[A-MSDU attacks (§3)](#id-extended-amsdu)*</div>
| `ping I,E --amsdu-fake`                | If this test succeeds, the A-MSDU flag is ignored (§3.5).
| `ping I,E --amsdu-fake --amsdu-spp`    | Check if the A-MSDU flag is authenticated but then ignored (§3.5).
| <div align="center">*[Mixed key attacks (§4)](#id-extended-mixedkey)*</div>
| `ping I,F,BE,E`                        | In case the new key is installed relatively late.
| `ping I,E,F,AE`                        | Variant if no data frames are accepted during the rekey handshake.
| `ping I,E,F,AE --rekey-plain`          | If the device performs the rekey handshake in plaintext.
| `ping I,E,F,AE --rekey-plain --rekey-req` | Same as above, and actively request a rekey as client.
| `ping I,E,F,AE --rekey-early-install`  | Install the new key after sending message 3 of the 4-way handshake.
| `ping I,E,F,E [--rekey-pl] [--rekey-req]` | Same as above 4 tests, but with longer delay before 2nd fragment.
| `ping I,F,BE,AE --freebsd`             | Mixed key attack against FreeBSD or similar implementations.
| <div align="center">*[Cache attacks (§5)](#id-extended-cache)*</div>
| `ping I,E,R,AE --freebsd [--full-reconnect]` | Cache attack specific to FreeBSD implementations.
| `ping I,E,R,AP --freebsd [--full-reconnect]` | Cache attack specific to FreeBSD implementations.
| `ping I,E,R,AP [--full-reconnect]`     | Cache attack test where 2nd fragment is sent in plaintext.
| <div align="center">*[Mixed plain/encrypt attack (§6.3)](#id-extended-mixplainenc)*</div>
| `ping I,E,E --amsdu`                   | Send a normal ping as a fragmented A-MSDU frame.
| `ping I,E,P,E`                         | Ping with first frag. encrypted, second plaintext, third encrypted.
| `linux-plain 3`                        | Same as linux-plain but decoy fragment is sent using QoS priority 3.
| <div align="center">*[Broadcast checks (extensions of §6.4)](#id-extended-bcast-check)*</div>
| `ping I,P --bcast-ra`                  | Ping in a plaintext broadcast frame after 4-way HS.
| `ping BP --bcast-ra [--bcast-dst]`     | Ping in plaintext broadcast frame during 4-way HS (use tcpdump).
| `ping BP [--bcast-dst]`                | Ping in a plaintext frame during the 4-way handshake (use tcpdump).
| `eapfrag BP,BP`                        | Experimental broadcast fragment attack (use tcpdump).
| <div align="center">*[A-MSDU EAPOL attack (§6.5)](#id-extended-cloackamsdu)*</div>
| `eapol-amsdu[-bad] BP --bcast-dst`     | Same as `eapol-amsdu BP` but easier to verify against APs (use tcpdump).
| <div align="center">*[AP forwards EAPOL attack (§6.6)](#id-extended-apforward)*</div>
| `eapol-inject 00:11:22:33:44:55`       | Test if AP forwards EAPOL frames before authenticated (use tcpdump).
| `eapol-inject-large 00:11:22:33:44:55` | Make AP send fragmented frames by EAPOL injection (use tcpdump).
| <div align="center">*[No fragmentation support attack (§6.8)](#id-extended-nofrag)*</div>
| `ping I,D,E`                           | Send ping inside an encrypted second fragment (no 1st fragment).
| `ping I,E,D`                           | Send ping inside an encrypted first fragment (no 2nd fragment).

<a id="id-extended-amsdu"></a>
## 8.1. A-MSDU attack tests (§3 -- CVE-2020-24588)

It is only useful to execute these two tests if the main test `ping I,E --amsdu` fails and you want to better
understand how the tested device handles A-MSDU frames:

- `ping I,E --amsdu-fake`: If this tests succeeds, the receiver treats all frames as normal frames (meaning it doesn't
  support A-MSDU frames). This behaviour is not ideal, although it is unlikely that an attacker can abuse this in
  practice (see Section 3.5 in the paper).

- `ping I,E --amsdu-fake --amsdu-spp`: If this tests succeeds, the receiver authenticates the QoS A-MSDU flag of every
  received frame (i.e. it will not mask it to zero on reception) but then treats all received frames as normal frames
  (meaning it does not support the reception of real A-MSDU frames). This behaviour is not ideal, although it is unlikely
  that an attacker can abuse this in practice (see Section 3.5 in the paper).

<a id="id-extended-mixedkey"></a>
## 8.2. Mixed key attack tests (§4 -- CVE-2020-24587)

Most devices I tested are vulnerable to mixed key attacks. In case the normal mixed key attack tests indicate
that a device is not vulnerable, but the test `ping-frag-sep` does succeed, it is highly recommended to try
these alternative mixed key attack tests.

As a general remark, when testing an AP, you can add the `--rekey-req` parameter to any of the mixed key attack tests to
actively request a rekey handshake. A low number of APs will then perform the rekey handshake. Most APs will ignore
this request though, and have to be explicitly configured to regularly renew the session key (PTK).

Some notes regarding the tests:

- `ping I,F,BE,E` and `ping I,E,F,AE`: These are fairly straightforward mixed key attack tests where both fragments are
  injected at different times.

- `ping I,E,F,AE --rekey-plain`: Some drivers (e.g. MediaTek) will perform the rekey handshake in plaintext. To test
  devices that use such a driver you must add the `--rekey-plain` parameter.

- `ping I,E,F,AE --rekey-plain --rekey-req`: This particular combination is useful to test routers that use a MediaTek
  driver. These routers perform the rekey handshake in plaintext, and the client can actively request a rekey handshake.

- `ping I,E,F,AE --rekey-early-install`: A low number of clients (incorrectly) install the key too early during
  a pairwise session rekey. To reliably test these clients, add the `--rekey-early-install` parameter. This test
  is not meaningfull against APs.

- `ping I,E,F,E [--rekey-pl] [--rekey-req]`: This test variant is the same as the previous `ping I,E,F,AE *` tests,
  except that the second fragment is send 1 second after the 4-way handshake. This can be important because in a
  low number of devices there is a small delay before the new key is installed. Note that `--rekey-pl` is a shorthand
  of `--rekey-plain`.

Finally, in case the test `ping-frag-sep` doesn't succeed, you should try the following mixed key attack test:

- `ping I,F,BE,AE --freebsd`: This essentially performs the rekey handshake against a FreeBSD implementation, or
  a driver that borrows code from FreeBSD, without affecting the defragmentation process of data frames. See
  Appendix E in the paper for details.

<a id="id-extended-cache"></a>
## 8.3. Cache attack tests (§5 -- CVE-2020-24586)

- `ping I,E,R,AE --freebsd --full-reconnect`: This test can be used to check if a FreeBSD AP, or a driver that
  borrows code from FreeBSD, is vulnerable to a cache attack. See Appendix E in the paper for details on how this
  test works. You should also try this test without the `--full-reconnect` parameter. The test also works against
  clients, but these are unlikely to be affected.

- `ping I,E,R,AP --freebsd --full-reconnect`: This test is a variant against FreeBSD APs, or against a driver that
  borrows code from FreeBSD, where the second fragment is sent in plaintext after reconnecting with the AP. Against some
  dongles on FreeBSD this test was more reliable and still proves that old fragments remain in the AP's memory after
  reconnecting. You should also try this test without the `--full-reconnect` parameter. The test also works against
  clients, but these are unlikely to be affected.

- `ping I,E,R,AP [--full-reconnect]`: In this test the second fragment is sent in plaintext. This can be useful if
  the device being tested doesn't immediately install the key after the 4-way handshake. If this tests succeeds, it
  shows that the device keeps fragments in memory after (re)connecting to a network, meaning its vulnerable to cache
  attacks. Unlike the above two commands, this one is also useful to perform against clients (as well as APs).

<a id="id-extended-mixplainenc"></a>
## 8.4. Mixed plain/encrypt attack (§6.3 -- CVE-2020-26147)

- `ping I,E,E --amsdu`: This test sends a fragmented A-MSDU frame, which not all devices can properly receive.
  It does not test for a vulnerability. Instead, this test is useful to determine the practical exploitability
  of the "Mixed plain/encrypt attack". Namely, if this tests  succeeds, it's easier to attack the device if the
  second fragment can be sent in plaintext (test `ping I,E,P`). See Section 6.3 of the paper for details.

- `ping I,E,P,E` and `linux-plain 3`: If all the other mixed plain/encrypt attack tests didn't succeed, you
  can try these two extra tests as well. I think it's quite unlikely this will uncover a new vulnerability.

<a id="id-extended-bcast-check"></a>
## 8.5. Broadcast fragment attack tests (extensions of §6.4)

Most of the following tests send broadcast frames, which are not automatically retransmitted, and it is therefore
recommended to **execute them several times**. This is because background noise may prevent the tested devices
from receiving the injected broadcast frame. In my experiments, mainly clients were affected. Most clients are
only vulnerable while connecting to the network (i.e. during the execution of the 4-way handshake).

- `ping I,P --bcast-ra`: this sends a unicast ICMP ping request inside a plaintext broadcast Wi-Fi frame (CVE-2020-26145).
  This test can be performed against both clients and APs.

- `ping BP --bcast-ra`: similar to the above test `ping I,P --bcast-ra`, but the ping is sent before the client has
  authenticated with the network, i.e., during the execution of the 4-way handshake (CVE-2020-26145). You must run tcpdump
  or wireshark to check if the client accepts the frame. In tcpdump you can use the filter `icmp` and in wireshark you
  can also use the filter `frame contains "test_ping_icmp"` to more easily detect this ping request.

- `ping BP --bcast-ra --bcast-dst`: this test is the same as the previous one, but is useful if you cannot run tcpdump
  on the target AP. Note that this test is only meaningfull against APs. The extra `--bcast-dst` parameter in this test
  causes a vulnerable AP to broadcast the injected ping request to all connected clients. In other words, to check if an
  AP is vulnerable, execute this command, and listen for broadcast Wi-Fi frames on a second device that is connected to
  the AP by using the filter `icmp` or `frame contains "test_ping_icmp"`.

<a id="id-extended-bcast-check-ping-bp"></a>

- `ping BP [--bcast-dst]`: this is a variant of the above two tests `ping BP --bcast-ra [--bcast-dst]`, except that the ping
  request is now sent in a plaintext unicast frame instead of a broadcast one (no CVE is allocated yet - it's related to
  CVE-2020-26145). This test must be performed against both clients and APs. The ping is sent before the client has authenticated
  with the network (i.e. during the execution of the 4-way handshake), meaning you must run tcpdump or wireshark to check if the
  device accepts this frame. Alternatively, when testing APs, you can add the `--bcast-dst` parameter similar to the above test,
  and then use tcpdump or wireshark on a second device that is connected to the AP by using the filter `icmp` or
  `frame contains "test_ping_icmp"`.

- `eapfrag BP,BP`: this is a specialization of the above broadcast fragment tests that is performed before the client has
  authenticated. It is a _very experimental_ attack based on the analysis of leaked code. It first sends a plaintext fragment
  that starts with an EAPOL header, which is accepted because the 4-way handshake is still being executed. Then it sends a
  second broadcast fragment with the same sequence number. Based on the analysis of leaked code some devices may now accept
  this fragment (because the previous fragment was allowed), but the subsequent code will process it as a normal frame
  (because the fragment is broadcasted). You must use tcpdump or wireshark on the victim to determine whether the frame
  is properly received, for example using the filter `icmp` or `frame contains "test_ping_icmp"`. An alternative variant
  is `eapfrag BP,AE` in case the normal variant doesn't work.

<a id="id-extended-cloackamsdu"></a>
## 8.6. A-MSDU EAPOL attack tests (§6.5 -- CVE-2020-26144)

This test can be used in case you want to execute the `eapol-amsdu[-bad] BP` tests but cannot run tcpdump or wireshark on
the AP. This test is only meaningfull against APs: the command `eapol-amsdu[-bad] BP --bcast-dst` causes a vulnerable AP
to broadcast the injected ping request to all connected clients. In other words, to check if an AP is vulnerable, execute this
command, and listen for broadcast Wi-Fi frames on a second device that is connected to the AP by using the filter `icmp` or
`frame contains "test_ping_icmp"`.

<a id="id-extended-apforward"></a>
## 8.7. AP forwards EAPOL attack tests (§6.6 -- CVE-2020-26139)

- `eapol-inject 00:11:22:33:44:55`: This test is only meaningfull against APs. To perform this test you have to connect
  to the network using a second device and replace the MAC address `00:11:22:33:44:55` with the MAC address of this second
  device. _Before_ being authenticated, the test tool will send an EAPOL frame to the AP with as final destination this second
  device. If the AP forwards the EAPOL frame to the second device, the AP is considered vulnerable. To confirm if the AP forwards
  the EAPOL frame you must run tcpdump or wireshark on the second device. You can use the wireshark filter `frame contains "forwarded_data"`
  when monitoring decrypted traffic on the wireless interface of the second device (or the tcpdump filter `ether proto 0x888e`
  to monitor all EAPOL frames). See Section 6.6 of the paper for the details and impact of this.

- `eapol-inject-lage 00:11:22:33:44:55`: In case the above `eapol-inject` test succeeds, you can also try `eapol-inject-large` to see
  if this vulnerability can be abused to force the transmission of encrypted fragments. You again have to use tcpdump or wireshark
  to check this. Use the wireshark or tshark filter `(wlan.fc.frag == 1) || (wlan.frag > 0)` to detect fragmented frames. I found it
  very rare for this attack to work.

<a id="id-extended-nofrag"></a>
## 8.8. No fragmentation support attack test (§6.8 -- CVE-2020-26142)

- `ping I,D,E`: If this test succeeds, the client or AP doesn't support (de)fragmentation, but is still vulnerable to attacks.
  The problem is that the receiver treats the _last_ fragment as a full frame. See Section 6.8 in the paper for details and how
  this can be exploited.

- `ping I,E,D`: If this test succeeds, then the client or AP treats the _first_ fragment as a full frame. Although this behaviour
  is not ideal, it's currently unknown whether this, on its own, can be exploited in practice.

# 9. Advanced Usage

<a id="id-injection-tests"></a>
## 9.1. Network card injection tests

### Injection mode

The script `test-injection.py` can be used to test whether frames are properly injected when
using _injection mode_:

	./test-injection.py wlan0 wlan1

Here we test if the network card `wlan0` properly injects frames and we use network card `wlan1`
to monitor whether frames are properly injected. Note that both interfaces need to support
monitor mode for this test script to work.

In case you do not have a second network card, you can execute a partial injection test using:

	./test-injection.py wlan0

Unfortunately, the above test can only test if the kernel overwrites fields of injected frames,
it cannot test whether the firmware or wireless chip itself overwrites fields.

### Mixed mode

To test whether a network card properly injects frames in _mixed mode_, which is the mode I
recommend to use, you can execute the following two commands:

	./fragattack.py wlan0 ping --inject-test wlan1
	./fragattack.py wlan0 ping --inject-test wlan1 --ap

Here we test whether `wlan0` properly injects frames by monitoring the injected frames using the
second network card `wlan1`. The first command tests if frames are properly injected when using
mixed mode while acting as a client, and the second command when using mixed mode while acting
as an AP. In order to start the test, the client must be able to connect to a network, and the
AP waits until a client is connecting before starting the injection tests (see [Before every usage](#id-before-every-usage)
for configuring the connection setup of the client and AP).

If you also want to test the retransmission behaviour of `wlan0` in mixed mode you can execute:

	./fragattack.py wlan0 ping --inject-test-postauth wlan1
	./fragattack.py wlan0 ping --inject-test-postauth wlan1 --ap

In case you do not have a second network card, you can execute a partial mixed mode injection test
using:

	./fragattack.py wlan0 ping --inject-test[-postauth] self
	./fragattack.py wlan0 ping --inject-test[-postauth] self --ap

Unfortunately, the above tests can only test if the kernel overwrites fields of injected frames,
it cannot test whether the firmware or wireless chip itself overwrites fields.

### Interpreting test results

The test script will give detailed output on which tests succeeded or failed, and will conclude by outputting
either `==> The most important tests have been passed successfully` or a message indicating that either important
tests failed or that it couldn't capture certain injected frames.

Note that the injection scripts only test the most important behaviour. The best way to confirm that injection
is properly working is to **perform the vulnerability tests against devices that are known to be vulnerable**,
and confirming that the tool correctly identifies the device(s) as vulnerable.

When certain injected frames could not be captured, this may either be because of background noise, or because the
network card being tested is unable to properly inject certain frames (e.g. the firmware of the Intel AX200 crashes
when injecting fragmented frames). It could also be that frames are in fact properly injected, but that the network
card used to monitor whether frames are injected properly (`wlan1` in the above examples) is not reliable and is,
for example, missing most frames due to background noise. Try running the tests on a different channel as well.

When the injection tests are working, but you have problems reliably performing the attack tests, this may be
because the devices you are testing are entering sleep mode. See [Handling sleep mode](#id-handling-sleep) for
additional notes on this problem.

### Manual checks notes

When using wireshark to inspect the injection behaviour of a device it is recommended to use a second
device in monitor mode to see how frames are injected.

In case you open the interface used to inject frames then you should see injected frames twice: (1) first
you see the frame as injected by whatever tool is sending it, and then (2) a second time by how the frame
was injected by the driver. These two frames may slightly differ if the kernel overwrote certain fields.
If you only see an injected frame once it may have been dropped by the kernel.

<a id="id-static-ip-config"></a>
## 9.2. Static IP Configuration

In case the device you are testing doesn't support DHCP, you can manually specify the IP addresses
that the test tool should use. For example:

	./fragattack.py wlan0 [--ap] ping --inject wlan1 --ip 192.168.100.10 --peerip 192.168.100.1

Here the test tool will use IP address 192.168.100.10, and it will inject a ping request to the peer
IP address 192.168.100.1.

When a test sends IP packets before obtaining IP addresses using DHCP, it will use the default IP
address 127.0.0.1. To use different (default) IP addresses, you can also use the `--ip` and `-peerip`
parameters.

<a id="id-no-icmp"></a>
## 9.3. No ICMP Support

Most attack tests work by sending ICMP ping requests in special manners, and seeing wether we receive
an ICMP ping response. In case the device being tested does not support ICMP pings you can instead
use ARP requests by adding the `--arp` parameter to all tests. In case a test doesn't support sending
ARP requests the tool will display the error `Cannot override request type of the selected test`, in
which case the specific test can only be executed using ICMP ping requests.

**TODO: When acting as a client we can also inject DHCP requests intead.**

<a id="id-alternative-cards"><a/>
## 9.4. Alternative network cards

In case you cannot get access to one of the recommended wireless network cards, a second option
is to get a network card that uses the same drivers on Linux. In particular, you can try:

1. Network cards that use [ath9k_htc](https://wikidevi.wi-cat.ru/Ath9k_htc)

2. Network cards that use [carl9170](https://wikidevi.wi-cat.ru/carl9170)

3. Network cards that use [iwlmvm](https://wireless.wiki.kernel.org/en/users/drivers/iwlwifi).

I recommend cards based on `ath9k_htc`. Not all cards that use `iwlmvm` will be compatible. When
using an alternative network card, I strongly recommend to first run the [injection tests](#id-injection-tests)
to confirm that the network card is compatible.

## 9.5. 5 GHz support

In order to use the test tool on 5 GHz channels the network card being used must allow the injection
of frames in the 5 GHz channel. Unfortunately, this is not always possible due to regulatory
constraints. To see on which channels you can inject frames you can execute `iw list` and look under
Frequencies for channels that are _not_ marked as disabled, no IR, or radar detection. Note that these
conditions may depend on your network card, the current configured country, and the AP you are
connected to. For more information see, for example, the [Arch Linux documentation](https://wiki.archlinux.org/index.php/Network_configuration/Wireless#Respecting_the_regulatory_domain).

Note that a device may use different drivers to handle the 2.4 and 5 GHz band. As a result, it is
important to test devices in both these bands, since a device may behave differently depending on
which frequency band is being used.

Note that in mixed mode the Linux kernel may not allow the injection of frames even though it is
allowed to send normal frames. This is because in the function `ieee80211_monitor_start_xmit` the kernel refuses
to inject frames when `cfg80211_reg_can_beacon` returns false. As a result, Linux may refuse to
inject frames even though this is actually allowed. Making `cfg80211_reg_can_beacon` return true
under the correct conditions prevents this bug.

<a id="id-handling-sleep"></a>
## 9.6. Handling sleep mode

Devices such as mobile phones or IoT gadgets may put their Wi-Fi radio in sleep mode to reduce energy usage.
When in sleep mode, these devices are unable to receive Wi-Fi frames, which may interfere with our tests. There
are some options to try to mitigate this problem:

1. Try to disable sleep mode on the device being tested. This is the most reliable solution, but unfortunately
   not always possible.

2. Run the test tool in mixed mode. Most network cards will then queue injected frames until the device being
   tested is awake again.

3. Try a different network card to perform the tests. I found that different network cards will inject frames
   at (slightly) different times, and this may be the difference between injected frame properly arriving or
   being missed. For instance, against a Pixel 4 XL the test tool was unreliable when using a TL-WN722N but
   worked reliably with an Intel 8265.

4. Assign static IPs to the device under test and let the test tool use static IPs (see [Static IP Configuration](#id-static-ip-config)).
   With many tests this can be more reliable because the test tool can then immediately send the test frame instead
   of first having to use/wait on DHCP.

<a id="id-avoiding-tcpdump-aps"></a>
## 9.7. Avoiding tcpdump on APs

Some vulnerabilities can only be exploited while the device under test is connecting to the network,
i.e., when it's executing the 4-way handshake. This makes them harder to test automatically and typically
means that tcpdump or similar has to be used on the device under test. However, APs can be tested without running
tcpdump on it. In particular, the broadcast fragment attack tests (CVE-2020-26145) and A-MSDU EAPOL attack
tests (CVE-2020-26144) can be performed without running tcpdump on the device under test. Instead, tcpdump has
to run on another client connected to the AP. Concretely, the following commands can be used:

- `ping I,P --bcast-ra --bcast-dst` and `ping BP --bcast-ra --bcast-dst`

- `eapol-amsdu BP --bcast-dst` and `eapol-amsdu-bad BP --bcast-dst`

With these commands, you can monitor for the ping request on another client that is connected to the AP. In
case the ping request is received on this independent client, the AP under test is vulnerable. Unfortunately,
currently, it appears hard to test clients against these attack variants without running tcpdump on the client.

<a id="id-notes-device-support"></a>
## 9.8. Notes on device support

### ath9k_htc

The Technoethical N150 HGA, TP-Link TL-WN722N v1.x, and Alfa AWUS036NHA, all use the `ath9k_htc` driver.

For me these devices worked fairly well in a virtual machine, although like with all devices they are
more reliably when used natively. When using a VM, I recommend to configure the VM to use a USB2.0
controller, since that appeared more stable (at least with VirtualBox).

In recent kernels there was a ([now fixed](https://www.spinics.net/lists/linux-wireless/msg200825.html))
regression with the `ath9k_htc` driver causing it not to work. Simply use an up-to-date kernel or our patched
drivers to avoid this issue.

#### AWUS036ACM

If for some reason Linux does not automatically recognize this device, execute `sudo modprobe mt76x2u`
to manually load the driver. I found that, at least on my devices, this dongle was unstable when connected
to a USB3.0 port. Others seems to have reported [similar issues](https://www.spinics.net/lists/linux-wireless/msg200453.html)
with this dongle. When connected to a USB2.0 port I found this dongle to be reliable.

#### AWUS036ACH

This device is generally not supported by default in most Linux distributions and requires manual
installation of drivers. On Kali Linux you can install the driver using `sudo apt install realtek-rtl88xxau-dkms`.
To install the driver on other distributions check your package manager or follow the installation
instructions on [GitHub](https://github.com/aircrack-ng/rtl8812au). Before plugging in the device,
it is recommended to execute `modprobe 88XXau rtw_monitor_retransmit=1`.

Unfortunately, this device doesn't work in mixed mode, which is the recommended mode, and is difficult
to use in combination with our modified drivers. In practice, you will have to uninstall the modified
drivers and then run the test tool using the parameters `--no-drivercheck` and using `--inject wlan0`
where wlan0 refers to the AWUS036ACH card. Because of these limitations this device is not recommended.

### Intel AX200

I tested the Intel AX200 and found that it is _not_ compatible with the test tool: its firmware crashes
after injecting a frame with the More Fragments flag set. If an Intel developer is reading this, please
update the firmware and make it possible to inject fragmented frames.

<a id="id-hwsim-details"></a>
## 9.9. Hwsim mode details

**Warning**: *this is currently an experimental mode, only use it for research purposes.*

This mode requires only one network card that supports monitor mode, and in contrast to mixed mode, the
network card does not have to support virtual interfaces. The disadvantage is that in this mode frames
are handled a bit slower, and it is not reliable when the network card does not acknowledge frames:

- Due to commit 1672c0e31917 ("mac80211: start auth/assoc timeout on frame status") authentication
  as a client will instantly timeout, meaning we cannot use hwsim mode as a client currently.
  _TODO: We need to patch the kernel to avoid this timeout._

- If we test a client that uses commit 1672c0e31917 ("mac80211: start auth/assoc timeout on frame status")
  we (as an AP) must acknowledge frames sent towards us. Otherwise the client being tested will be
  unable to connected.
  _TODO: Test which devices acknowledge frames in monitor mode, and test `iw set wlanX monitor active`._

- Certain APs will also require that authentication and association frames are acknowlegded by the client.
  This means that we (as a client) must again acknowledge frames sent towards us.
  _TODO: Test which devices acknowledge frames in monitor mode, and test `iw set wlanX monitor active`._

- For some strange reason, the Intel/mvm cannot receive data frames from Android/iPhone/iPad
  after 4-way HS? This is a very strange bug. _TODO: Investigate this further._

Before using this mode, create two virtual network cards:

	./hwsim.sh

This will output the two created virtual "hwsim" interfaces, for example wlan1 and wlan2. When testing
an AP in this mode, you must first search for the channel of the AP, and put the real network card on
this channel:

	./scan.sh wlan0
	ifconfig wlan0 down
	iw wlan0 set type monitor
	ifconfig wlan0 up
	# Pick the channel that the AP is on (in this example 11)
	iw wlan0 set channel 11

Here wlan0 refers to the _real_ network card (not an interface created by `hwsim.sh`). hen testing a
client, do do not first have to configure the channel (it is taken from `hostapd.conf`). You can now
start the test tool as follows:

	./fragattack.py	 wlan0 --hwsim wlan1,wlan2 [--ap] $COMMAND

After the tool executed, you can directly run it again with a new `$COMMAND`.

<a id="id-wpa3-sae"></a>
## 9.10. Testing WPA3 and SAE devices

You can test a WPA3/SAE AP by including the following two lines in `client.conf`:

	key_mgmt=SAE
	ieee80211w=1

To test WPA3/SAE clients you can modify `hostapd.conf` and set the parameters:

	wpa_key_mgmt=SAE
	ieee80211w=2

We tested the above with an Intel 8265, Intel 3160, Netgear WN111v2 (`carl9170`),
TP-Link TL-WN722N (`ath9k_htc`) and WNDA3200 (`ath9k_htc`). With those
devices I was able to connect with the AP and run some tests. So it
seems this should work with all already supported dongles. Note that I
haven't tested this in detail: my assumption has been that whether a
device is operating in WPA2 or WPA3 mode won't impact test results.

The provided `client.conf` by default enables both the hunting-and-pecking method and
the hash-to-element method. To set up an AP that supports hash-to-element (and thereby
test the latest WPA3/SAE clients) you can modify `hostapd.conf` and set the parameter:

	sae_pwe=2

By setting this value the AP will accept both the hunting-and-pecking method and
the hash-to-element method.

<a id="id-live-image"></a>
## 9.11. Live USB image

Download the [live USB image](http://people.cs.kuleuven.be/~mathy.vanhoef/fragattacks/ubuntu-20.04.2-fragattacks-1.3.3-amd64.iso)
and write it to USB using:

	# Unmount in case there's an old partition on the USB
	sudo umount /dev/sdb*
	# Copy the image
	sudo dd bs=4M if=ubuntu-20.04.2-fragattacks-1.3.3-amd64.iso of=/dev/sdb conv=fdatasync status=progress

The sha256sum of the image is `4b973452a08b981778285a33accfd4ce58625a91e8e0eab20941facf54904bba`. Replace `/dev/sdb`
with your USB stick. If you're not running Linux, search online how to write an ISO image to your USB stick.

When starting the live image click on "Try Ubuntu" during startup. Start a terminal by right clicking on the
desktop and selecting "Open in Terminal" and execute:

	cd ~/fragattacks/research
	sudo su
	nmcli radio wifi off
	source venv/bin/activate

You can now run `./fragattacks.py` and follow the normal instructions in this README.
Remember to disable Wi-Fi using `nmcli radio wifi off` as shown above, otherwise the
network manager of Ubuntu will interfere with the test tool. This README is also present
on the live image at `~/fragattacks/README.md`.


<a id="id-change-log"></a>
# 10. Change log

**Version 1.3.3 (11 May 2021)**:

- Updated the modified drivers so they compile on Linux kernel 5.10, 5.11, and 5.12.

- Updated firmware for `ath9k_htc` devices (should have no impact on tests).

- Restructured the repository for pubic release. Removed internal documents and slides to instead reference
  the public versions of these documents.

- Basic support for 40 MHz channels when using `--inject-test[-postauth]` parameter to test injection. In actual
  vulnerability tests, the usage of 40 MHz channels is untested (use `disable_ht40` in `client.conf` if needed).

**Version 1.3.2 (8 March 2021)**:

- Added presentation [handouts](https://papers.mathyvanhoef.com/fragattacks-slides-2021-03-8.pdf) and a
  [summary](https://papers.mathyvanhoef.com/fragattacks-overview.pdf)
  of each vulnerability's root cause and impact.

- Updated this README to [explain](#id-test-sanity) that the parameter `--icmp-size 100` or similar can be added to
  all tests that send fragmented frames if the device under test only accepts fragments of a certain minimum size.

- Fixed minor typos in this README.

**Version 1.3.1 (1 March 2021)**:

- Added the test [`ping BP [--bcast-dst]`](#id-extended-bcast-check-ping-bp) to this README. It injects a plaintext ping
  while connecting (i.e. during the 4-way handshake). Both clients and APs can be vulnerable to this attack.

- Updated the [attack overview](#id-paper-clarifications) with new examples on how packet injection vulnerabilities
  can be abused in practice. This includes techniques to trick IPv4-only clients into using a malicious DNS server
  and techniques to directly communicate with devices behind a NAT/firewall (to e.g. exploit local services).

- Clarified that [broadcast fragment tests](#id-extended-bcast-check) can be performed against both clients and APs.

- The test tool will now check whether the expected version of the Python Scapy library has been loaded.

- Fixed some references to the paper in this README (now properly references sections 6.4, 6.6, and 6.8).

- Updated to draft version 3 of the paper. There are no major changes compared to draft version 2, only minor textual
  and structural tweaks. Content-wise this is now the final version of the paper.

**Version 1.3 (20 January 2021)**:

- This version is based on hostap commit `a337c1d7c` ("New TWT operations and attributes to TWT Setup and Nudge").

- Added an [overview](attacks.pdf) of attacks and their preconditions and created [these slides](amsduattack.pdf)
  to better illustrate how the aggregation attack (CVE-2020-24588) works in practice.

- Added <a href="#id-wpa3-sae">instructions</a> on how to test WPA3/SAE devices using either the hunting-and-pecking
  or hash-to-element method. This also implies that Management Frame Protection (MFP) is supported by the test tool.

- Added a clarification to this README on how to use tcpdump to verify the result of certain tests.

- Added the extra test `ping BP --bcast-ra --bcast-dst` to this README to be able to test for CVE-2020-26145
  against APs that cannot run tcpdump (with this test tcpdump has to be run on an independent connected client).

- Added the extra tests `ping I,E,F,E [--rekey-pl] [--rekey-req]` to this README to better detect mixed key
  attacks (CVE-2020-24587) in certain devices.

- Fixed injection of fragmented frames when using ath9k_htc dongles in combination with 802.11n.

- The `pysetup.sh` script has been added to create the python virtual environment. This script also fixes
  [a bug](https://github.com/secdev/scapy/commit/46fa40fde4049ad7770481f8806c59640df24059) in the scapy library
  when used with Python 3.9.

- The patched drivers have been updated to properly compile on Linux 5.9.0.

- Fixed the `ping-frag-sep` test. Previously it behaved like `ping-frag-sep --pn-per-qos`. Note that this test
  is not used to detect vulnerabilities but only to better understand implementations.

**Version 1.2 (15 November 2020)**:

- This version (and lower) is based on hostap commit `1c67a0760` ("tests: Add basic power saving tests for ap_open").

- Tool will automatically quit after a test completed or timed out.

- Tool detects if the 4-way handshake is looping or if there is no reply to a rekey request (`--rekey-req`).

- When using an external DHCP server, the tool will now always send EAPOL frames with as destination address
  the AP (instead of the DHCP server). This is important in mixed key and cache attack tests when using an
  external DHCP server.

- When testing an AP using `--rekey-req` the tool will now send EAPOL Rekey Request with a Replay Counter of
  one instead of zero.

- Debug output now shows the correct (group) key when encrypting broadcast/multicast frames. This does not
  influence any test results, it only changes the output of the test tool.

- Clarified that all commands in this README can test both clients and APs unless noted otherwise.

- Clarified the description of cache attacks, Broadcast fragment, and A-MSDU EAPOL attack tests in this README.

- Clarified that it's important to test both the 2.4 and 5 GHz band in this README.

**Version 1.1 (20 October 2020)**:

- Fixed a bug where the command `ping I,E,D` would send a normal encrypted ping request. It now sends an
  encrypted ping request with the More Fragments flag set in the header.

- Moved the `amsdu-inject-[bad]` commands to Section 7 of this README. These simulate real attacks and can
  be used to verify whether temporary mitigations are working (see Section 7.2 in the paper).

- Fixed spelling of A-MSDU SPPs in this README and the test tool. The new argument `--amsdu-spp` is now a
  synonym of the old `--amsdu-ssp` argument.

**Version 1.0 (11 August 2020)**:

- Prepared initial release for usage during the embargo.

