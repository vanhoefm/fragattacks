# Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation

## Introduction

The discovered attacks affect all Wi-Fi networks. Note that the recent WPA3 specification only
introduced a new authentication method, but its encryption ciphers (CCMP and GCMP) are identical
to WPA2. Because of this, the attacks are identical against WPA2 and WPA3 networks.

Older WPA networks by default use TKIP for encryption, and the applicability of the attacks
against this cipher is discussed in the paper. Out of completeness, and to illustrate that Wi-Fi
has been vulnerable since its creation, the paper also briefly discusses the applicability of
the attacks against WEP.

**A summary of the discoveries can be found in [SUMMARY.md](SUMMARY.md), although it is of course**
**strongly recommend that you read the paper as well.**

## Supported Network Cards

Only specific wireless network cards are supported. This is because some network cards may overwrite the
sequence of fragment number of injected frames, or may reorder frames of different priority, and this
interferes with the test tool (i.e. the tool might incorrectly say a device is secure although it's not).
I have confirmed that the following network cards work properly:

|      Network Card      | USB | 5GHz |        mixed mode       |      injection mode     | hwsim mode (experimental) |
| ---------------------- | --- | ---- | ----------------------- | ----------------------- | ------------------------- |
| Intel Wireless-AC 8265 | No  | Yes  | patched driver          | yes                     | _under development_       |
| Intel Wireless-AC 3160 | No  | Yes  | patched driver          | yes                     | _under development_       |
| Technoethical N150 HGA | Yes | No   | patched driver/firmware | patched driver/firmware | _under development_       |
| TP-Link TL-WN722N v1.x | Yes | No   | patched driver/firmware | patched driver/firmware | _under development_       |
| Alfa AWUS036NHA        | Yes | No   | patched driver/firmware | patched driver/firmware | _under development_       |
| Alfa AWUS036ACM        | Yes | Yes  | patched driver          | yes                     | _under development_       |
| Alfa AWUS036ACH        | Yes | Yes  | **TODO**                | **TODO**                | _under development_       |
| Netgear WN111v2        | Yes | No   | patched driver          | yes                     | _under development_       |

The three last colums signify:

1. Mixed mode: whether the network card can be used in [mixed mode](#Mixed-mode).

2. Injection mode: whether the network card can be used as a second interface to inject frames in [injection mode](#Injection-mode).

3. Hwsim mode: whether the network card can be used in the experimental [hwsim mode](#Hwsim-mode).

_Yes_ indicates the card works out-of-the-box in the given mode. _Patched driver/firmware_
means that the card is compatible when used in combination with patched drivers and/or firmware.
_No_ means this mode is not supported by the network card.

Note that USB devices can be used inside a virtual machine, and the modified drivers and/or firmware
can be installed in this virtual machine. However, I found that the usage of virtual machines can
make network cards less reliable, and I instead recommend the usage of a live CD if you cannot install
the modified drivers/firmware natively.

More details on my experience with the above devices can be found **here**. Briefly summarized:

- I recommend the use of the Technoethical N150 HGA in either injection mode or mixed mode. This deivce
  requires the use of a patched driver and firmware.

- During my tests the AWUS036ACM dongle was unreliable when connected to a USB3.0 port, but worked
  well when connected to a USB2.0 port. This behaviour may depend on your computer.

- The Intel 3160 and 8265 are supported and extensively tested. Sometimes their firmware crashed but
  a reboot makes the network card usable again. The Intel AX200 is not compatible with the test tool.

- The WN111v2 seems to work well, although I did not test it extensively.

- The driver for the AWUS036ACH is not part of the Linux kernel and requires the installation of a separate
  driver. On some Linux distributions such as Kali you can install this driver through the package manager.

If you are unable to find one of the above network cards, you can search for [alternative network cards](#Alternative-network-cards)
that have a high chance of also working. When using a network card that is not explicitly supported
I strongly recommend to first run the [injection tests](#Network-card-injection-test) before using it.

## Prerequisites

The test tool was tested on Kali Linux and Ubuntu 20.04. To install the required dependencies, execute:

	# Kali Linux and Ubuntu
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools python3-venv \
		aircrack-ng firmware-ath9k-htc rfkill

Now clone this repository, build the tools, and configure a virtual python3 environment:

	# **Self note: replace with real HTTP unauthenticated link on release**
	git clone https://gitlab.com/aconf/wifi.git fragattack --recursive
	cd fragattack
	./build.sh
	cd research
	python3 -m venv venv
	source venv/bin/activate
	pip install wheel
	pip install -r requirements.txt

By default the above instructions only have to be executed once. However, you do have to
execute `./build.sh` again after pulling in new code using git.

## Patched Drivers

Install patched drivers:

	sudo apt-get install bison flex linux-headers-$(uname -r)
	# **Self note: replace with real HTTP unauthenticated link on release instead of separate directory**
	cd driver-backports-5.8-rc2-1
	make defconfig-experiments
	make -j 4
	sudo make install

Install patched `ath9k_htc` firmware:

	cd research/ath9k-firmware/
	./install.sh
	# Now reboot

The `./install.sh` script assumes the `ath9k_htc` firmware images are located in the
directory `/lib/firmware/ath9k_htc`. If this is not the case on your system you have
to manually copy `htc_7010.fw` and `htc_9271.fw` to the appropriate directory.

After installing the patched drivers and firmware you must unplug your Wi-Fi dongles
and reboot your system. The above instructions have to be executed again if your Linux
kernel gets updated.

Note that even when your device works out of the box, I still recommend to install the modified
drivers, as this assures there are no unexpected regressions in kernel and driver code.

In case you cannot install the modified drivers/firmware natively, you can download a
**[live Ubuntu CD]()** that contains the modified drivers/firmware along with our test tool.
Alternatively, you can use a virtual machine with USB network cards, although I found that
using a virtual machine is less reliable in pratice.

## Before every usage

Every time you want to use the test tool, you first have to load the virtual python environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with the test tool.
Also make sure no other network services are causing outgoing traffic. You can assure this by
using iptables to block traffic by executing `./droptraffic.sh` (you can revert this by rebooting).
Optionally check using `sudo airmon-ng check` to see which other processing might interfere.

The test tool can test both clients and APs:

- Testing APs: **configure the AP you want to test** by editing `research/client.conf`. This is a
  standard `wpa_supplicant` configuration file, see the [hostap documentation](https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf)
  for an overview of all the options it supports.

- Testing clients: you must execute the test tool with the `--ap` parameter (see below). This
  instructs the tool into creating an AP with as name **testnetwork** and password **abcdefgh**. Connect
  to this network with the client you want to test. By default the client must request an IP
  using DHCP. To edit properties of the created AP, such as the channel it's created on, you
  can edit `research/hostapd.conf`.

## Interface Modes

### Mixed mode

This mode requires only one wireless network card, but generally requires a patched driver and/or
firmware and only specific network cards are supported. See [Patched Drivers](#Patched-Drivers) on
how to install patched drivers/firmware, and [Supported Network Cards](#Supported-Network-Cards)
for compatible network cards. Execute the test tool in this mode using:

	./fragattack wlan0 [--ap] $COMMAND

Possible values of `$COMMAND` are listed in [testing for vulnerabilities](#testing-for-vulnerabilities)
and [extended vulnerability tests](#extended-vulnerability-tests).

One advantage of this mode is that it works well when testing clients that may enter a sleep state.
Nevertheless, if possible, I recommend disabling sleep functionality of the client being tested.

### Injection mode

This mode requires two wireless network cards: one will act as an AP or the client, and the other
one will be used to inject frames. Execute the test tool in this mode using:

	./fragattack wlan0 --inject wlan1 [--ap] $COMMAND

Here interface wlan0 will act as a legitimate client or AP, and wlan1 will be used to inject
frames. For wlan0, any card that supports normal client or AP mode on Linux can be used. For
wlan1, a card must be used that supports injection mode according to [Supported Network Cards](#Supported-Network-Cards).

When testing clients in this mode, injected frames may be sent when the client is in a sleep state.
This causes attacks to fail, so you must make sure the client will not enter a sleep state.

### Hwsim mode

This mode is experimental and only for research purposes. See [hwsim mode details](#Hwsim-mode-details)
for more information.


## Testing for Vulnerabilities

You can test devices by running the test tool as discussed in [interface modes](#interface-modes)
and replacing `$COMMAND` with one of the commands in the table blow.

Before testing for vulnerabilities I recommend to execute the first four commands in the table
below. The first command performs a normal ping and can be used to confirm that the test setup
works. The second tests sends the ping request as as two fragmented Wi-Fi frames. In case one
of these tests is not working, follow the instructions in [network card injection test](#network-card-injection-test)
to confirm your network card is properly injecting frames. The third and fourth tests verify
basic defragmentation behaviour of a device and are further discussed below.

|             Command              | Short description
| -------------------------------- | ---------------------------------
| <div align="center">*Sanity checks*</div>
| `ping I,E`                       | Send a normal ping
| `ping I,E,E`                     | Send a normal fragmented ping
| <div align="center">*Basic defragmentation behaviour*</div>
| `ping I,E,E --delay 5`           | Send a normal fragmented ping with a 5 second delay between fragments
| `ping-frag-sep`                  | Send a normal fragmented ping with fragments separated by another frame
| <div align="center">*A-MSDU attacks (Section 3)*</div>
| `ping I,E --amsdu`               | Send a normal ping encapsulated in a normal A-MSDU frame.
| `ping I,E,E --amsdu`             | Send a normal ping an a fragmented A-MSDU frame.
| `amsdu-inject`                   | Send a valid A-MSDU frame whose start is also a valid LLC/SNAP header.
| `amsdu-inject linux`             | Same as above, but works against targets that incorrectly parse the frame.
| <div align="center">*Mixed key attacks (Section 4)*</div> | 
| `ping I,R,BE,AE`                 | Inject two fragments encrypted under a different key.
| `ping I,R,BE,AE --pn-per-qos`    | Same as above, but also works if the target only accepts consecutive fragments.
| <div align="center">*Cache attacks (Section 5)*</div> | 
| `ping I,E,C,AE`                  | Inject a fragment then reconnect (as client _reassociate_) and inject second fragment.
| `ping I,E,C,E`                   | Same as above, but with a longer delay before sending the second fragment.
| `ping I,E,C,AE --full-reconnect` | Inject a fragment, reconnect, then inject second fragment.
| `ping I,E,C,E --full-reconnect`  | Same as above, but with a longer delay before sending the second fragment.
| <div align="center">*Non-consecutive Packet Numbers (PNs) (Section 6.2)*</div> | 
| `ping I,E,E --inc-pn 2`          | Send a fragmented ping with non-consecutive packet numbers.
| <div align="center">*Mixed plaintext/encrypted fragments (Section 6.3)*</div> | 
| `ping I,E,P`                     | Send a fragmented ping: first fragment encrypted, second fragment in plaintext.
| `ping I,P,E`                     | Send a fragmented ping: first fragment in plaintext, send fragment encrypted.
| `ping I,P`                       | Send a plaintext ping.
| `ping I,P,P`                     | Send a fragmented ping: both fragments are sent in plaintext.
| `linux-plain`                    | Mixed plaintext/encrypted fragmentation attack specific to Linux.
| <div align="center">*EAPOL forwarding (Section 6.4)*</div> | 
| `eapol-inject 00:11:22:33:44:55` | Test if the AP forwards EAPOL frames before being connected.
| <div align="center">*Broadcast fragments (Section 6.7)*</div> | 
| `ping I,D,P --bcast-ra`          | Send ping in a 2nd plaintext broadcasted fragment.
| <div align="center">*A-MSDUs disguised as EAPOL frames (Section 6.8)*</div> | 
| `eapol-amsdu BB`                 | Send A-MSDU frame disguised as EAPOL frame. Use tcpdump to check if vulnerable.
| `eapol-amsdu I,CC`               | Same as above, except the frame is injected after obtaining an IP.
| `eapol-amsdu M,BB`               | Send a malformed A-MSDU disguised as EAPOL. Use tcpdump to check if vulnerable.
| `eapol-amsdu M,I,CC`             | Same as above, except the frame is injected after obtaining an IP.

**TODO: Explain when tcpdump is required to check if a device is vulnerable.**

#### Notes on sanity and implementation checks

- `ping I,E,E`: This test should only fail if the tested device doesn't support fragmentation. In case
  you encounter this, it is recommended to run also run this test against a device that _does_ support
  fragmentation to assure the test tool is properly injecting fragmented frames.

- `ping I,E,E --delay 5`: This test is used to check the maximum accepted delay between two fragments.
  If this test doesn't work, try it again with `--delay 1.5` or lower. In case the maximum accepted delay
  is low, all fragments sent in other tests must be sent within this maximum accepted delay. Otherwise
  tests will trivially fail and you might conclude a device isn't vulnerable to an attack even though
  it actually is.

- `ping-frag-sep`: This tests sends a fragmented Wi-Fi frame that is seperated by an unrelated frame.
  That is, it sends the first fragment, then a full unrelated Wi-Fi frame, and finally the second fragment.
  In case this test fails, the mixed key attack and cache attack will likely also fail. The only purpose
  of this test is to better understand the behaviour of a device and learn why other tests are failing.

### Notes on mixed key attack tests

- When running the mixed key test against an AP, the AP must be configured to regularly renew the session
  key (PTK) by executing a new 4-way handshake (e.g. every 30 seconds or minute). Against a low number of APs,
  the client can also request the AP to renew the PTK, meaning there is no need to configure the AP to
  periodically renew the key. In this case you can let the test tool request the AP to renew the PTK by
  adding the `--rekey-request` parameter.
  
- Home routers with a MediaTek driver will perform the rekey handshake in plaintext. To test these or
  similar devices, also must add the `--rekey-plaintext` parameter (see examples in [extended vulnerability tests](#extended-vulnerability-tests)).
  
- Certain clients install the key too early during a pairwise session rekey. To test these devices,
  add the `--rekey-early-install` parameter and retry the test (see examples in [extended vulnerability tests](#extended-vulnerability-tests)).

### Checklist

In case the test tool doesn't appear to be working, check the following:

1. Check that no other process is using the network card (e.g. kill your network manager).

2. Check that you are using modified drivers if needed for your wireless network card.
   If you updated your kernel, you will need to recompile and reinstall the drivers.

3. Check that you are using modified firmware if needed for your wireless network card.

4. Assure the device you are testing doesn't enter a sleep state (causing it to miss injected frames).
   I recommend running the test tool in [mixed mode](#mixed-mode) since this better handles clients
   that may go into a sleep state.

5. Run the [injection tests](#Network-card-injection-test) to make sure injection is working properly.

6. Check that you machine isn't generating background traffic that interferes with the tests. In
   particular, disable networking in your OS, manually kill your DHCP client/server, etc. See
   also [Before every usage](#before-every-usage).

7. Confirm that you are connecting to the correct network. Double-check `client.conf`.

8. Make sure the AP being tested is using (AES-)CCMP as the encryption algorithm. Other encryption
   algorithms such as TKIP or GCMP are not supported.

9. If you updated the code using git, execute `./build.sh` again (see [Prerequisites](#prerequisites))?

10. If your Wi-Fi dongle is unreliable, use it from a live CD or USB. A virtual machine can be unreliable.

11. Confirm using a second monitor interface that no other frames are sent in between fragments.
    For instance, I found that my Intel device sometimes sends Block Ack Response Action frames
    between fragments, and this interfered with the defragmentation process of the device under test.

## Extended Vulnerability Tests

Optionally you can also run more advanced tests. These have a lower chance of uncovering new vulnerabilities,
but against more exotic implementations these might reveal attack variants that the normal tests can't detect.

|              Command               | Short description
| ---------------------------------- | ---------------------------------
| <div align="center">*A-MSDU attacks (Section 3)*</div>
| `ping I,E --fake-amsdu`            | If this test succeeds, the A-MSDU flag is ignored (Section 3.5).
| <div align="center">*Mixed key attacks (Section 4)*</div>
| `ping I,E,R,AE`                    | In case the delay between fragments must be small.
| `ping I,E,R,AE --rekey-plaintext`  | If the device performs the rekey handshake in plaintext.
| `ping I,E,R,AE --rekey-req --rekey-plain`| Same as above, and actively request a rekey as client.
| `ping I,E,R,AE --rekey-early-install`| Install the new key before sending message 4 as an AP.
| `ping I,R,BE,AE --freebsd`         | Mixed key attack against FreeBSD.
| `ping I,R,BE,E`                    | In case the new key is installed relatively late.
| <div align="center">*Mixed plain/enc (Section 6.3)*</div>
| `ping I,E,P,E`                     | Ping with first frag. encrypted, second plaintext, third encrypted.
| `linux-plain 3`                    | Same as linux-plain but decoy fragment is sent using QoS priority 3.
| <div align="center">*EAPOL forwarding (Section 6.4)*</div>
| `eapol-inject L,00:11:22:33:44:55` | Try to make the AP send fragmented frames by EAPOL injection.
| <div align="center">*No fragmentation support (Section 6.6)*</div>
| `ping I,E,D`                       | Send ping inside an encrypted first fragment (no 2nd fragment).
| `ping I,D,E`                       | Send ping inside an encrypted second fragment (no 1st fragment).
| <div align="center">*Broadcast fragments (Section 6.7)*</div>
| `ping D,SP --bcast-ra`             | Ping in a 2nd plaintext broadcasted fragment before 4-way handshake.
| `ping D,BP --bcast-ra`             | Ping in a 2nd plaintext broadcasted fragment during 4-way handshake.
| `ping I,P --bcast-ra`              | Ping in a plaintext broadcast Wi-Fi frame after 4-way handshake.
| `macos CC`                         | Experimental attack against macos.
| `macos BB`                         | Same as above, but inject during 4-way handshake.
| <div align="center">*EAPOL A-MSDUs (Section 6.8)*</div>
| `eapol-amsdu [M,]BB --bcast-dst`   | Same as "eapol-amsdu [M,]BB" but ping is broadcasted.
| `eapol-amsdu [M,]I,CC --bcast-dst` | Same as "eapol-amsdu [M,]I,CC" but ping is broadcasted.
| `eapol-amsdu SS`                   | Same as "eapol-amsd BB" but inject frame before 4-way handshake.
| `eapol-amsdu AA`                   | Same as "eapol-amsd BB" but inject frame right after 4-way handshake.

## Advanced Usage

### Network card injection test

---
**In case the tests do not seem to be working, you can confirm that injection is properly working using:**

	./test-injection wlan1 wlan0

**This will inject frames using interface wlan1, and uses wlan0 to check if frames are properly**
**injected. Note that both interfaces need to support monitor mode for the test tool to work.**
---

#### Injection and hwsim mode

The script `test-injection.py` can be used to test whether frames are properly injected when
using _injection mode_:

	./test-injection.py wlan0 wlan1

Here we test if network card `wlan0` properly injects frames and we use network card `wlan1`
to monitor whether frames are properly injected.

**TODO: In case tests are not working, try to first unplug USB dongles and reboot the device(s).**
**If the tests still fail, try to use a different network card to monitor whether frames are**
**injected properly.**

**TODO: Testing the TP-Link against the Intel 3160 was very unreliable: many frames were not**
**received although they in fact were sent by the device.**

 case you do not have a second network
card, you can execute a partial injection test using:

	./test-injection.py wlan0

Unfortunately, the above test can only test if the kernel overwrites fields of injected frames,
it cannot test whether the firmware or wireless chip itself overwrites fields.

#### Mixed mode

To test whether a network card properly injects frames in _mixed mode_, you can execute the
following two commands:

	./fragattack wlan0 ping --inject-test wlan1
	./fragattack wlan0 ping --inject-test wlan1 --ap

**Ack behaviour is best tested postauth so the client will not disconnected.**

Here we test whether `wlan0` properly injects frames by monitor the injected frames using the
second network card `wlan1`. The first command tests if frames are properly injected when using
mixed mode as a client, and the second when using mixed mode as a client. In order to start the
test, the client must be able to connect to a network, and the AP waits until a client is
connecting. In case you do not have a second network card, you can execute a partial mixed mode
test using:

	./fragattack wlan0 ping --inject-selftest
	./fragattack wlan0 ping --inject-selftest --ap

Unfortunately, the above tests can only test if the kernel overwrites fields of injected frames,
it cannot test whether the firmware or wireless chip itself overwrites fields.

### Hwsim mode details

**Warning**: *this is currently an experimental mode, only use it for research purposes.*

This mode requires only one network card. The disadvantage is that this mode is the least reliable:

- Frames are handled slower, possibly causing the tested client/AP to timeout during authentication
  or association.

- When injeting frames, they may be retransmitted even though an acknowledgement was recieved.
  This slightly slows the handling of frames.

- Frames are not properly acknowledged depending on the wireless network card, which causes some
  tested clients or APs to disconnect during authentication or association.

Nevertheless, the advantage is that is mode requires only one wirelss network card and can,
depending on the network card, be used without patches to the driver and/or firmware. Before
using this mode, create two virtual network cards:

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

Here wlan0 refers to the _real_ network card (not an interface created by `hwsim.sh`).
You can now start the test tool as follows:

	./fragattack wlan0 --hwsim wlan1,wlan2 [--ap] $COMMAND

After the tool executed, you can directly run it again with a new command. When testing a client, do
do not first have to configure the channel (it is taken from `hostapd.conf`).

**TODOs:**

- Due to commit 1672c0e31917 ("mac80211: start auth/assoc timeout on frame status") authentication
  as a client will instantly timeout. We need to have a method to bypass this:

  1. We can patch the kernel

  2. Maybe configure wpa_supplicant to send auth frames using a monitor interface?


### Static IP Configuration

In case the device you are testing doesn't support DHCP, you can manually specify the IP addresses
that the test tool should use. For example:

	./fragattack.py wlan0 ping --inject wlan1 --ip 192.168.100.10 --peerip 192.168.100.1

Here the test tool will use address 192.168.100.10, and it will inject a ping request
to the peer IP address 192.168.100.1.

### Alternative network cards

In case you cannot get access to one of the recommended wireless network cards, a second option
is to get a network card that uses the same drivers on Linux. In particular, you can try:

- Network cards that use [ath9k_htc](https://wikidevi.wi-cat.ru/Ath9k_htc)

- Network cards that use [iwlmvm](https://wireless.wiki.kernel.org/en/users/drivers/iwlwifi)

I recommend cards based on `ath9khtc`. Not all cards that use `iwlmvm` will be compatible. When
using an alternative network card, I strongly recommend to first run the [injection tests](#Network-card-injection-test)
to confirm that the network card is compatible.

### 5 GHz support

In order to use the test tool on 5 GHz channels the network card being used must allow the injection
of frames in the 5 GHz channel. Unfortunately, this is not always possible due to regulatory
constraints. To see on which channels you can inject frames you can execute `iw list` and look under
Frequencies for channels that are _not_ marked as disabled, no IR, or radar detection. Note that these
conditions may depend on your network card, the current configured country, and the AP you are
connected to. For more information see, for example, the [Arch Linux documentation](https://wiki.archlinux.org/index.php/Network_configuration/Wireless#Respecting_the_regulatory_domain).

Although I have not yet encountered a device that behaved differently in the 2.4 GHz band compared
to the 5 GHz band, this may occur in practice if different drivers are used to handle both bands.
If you encounter such a case please let us know. Since I have not yet observed such differences
between the 2.4 and 5 GHz band I believe that it is sufficient to only test only one of these bands.

Note that in mixed mode the Linux kernel may not allow the injection of frames even though it is
allowed to send normal frames. This is because in `ieee80211_monitor_start_xmit` the kernel refuses
to inject frames when `cfg80211_reg_can_beacon` returns false. As a result, Linux may refuse to
inject frames even though this is actually allowed. Making `cfg80211_reg_can_beacon` return true
under the correct conditions prevents this bug.

### Notes on device support

**TODO: Reference or include the DEVICES.md file**

#### ath9k_htc

**Technoethical N150 HGA:, but since it's a USB dongle this can be**
**configured inside a virtual machine. When using Virtual Box, I recommend to configure the VM to**
**use a USB2.0 (OHCI + ECHI) controller, because I found the USB3.0 controller to be unreliable.**

With kernel 5.7.3+ and 5.8.x there is a known problem problem with the `ath9k_htc` driver, used by
the Technoethical N150 HGA, TP-Link TL-WN722N v1.x, and Alfa AWUS036NHA, causing it not to work.
Downgrading to kernel `5.7.2` fixes this issue. In the meantime a patch has also been submitted
to fix this problem on new kernels: https://www.spinics.net/lists/linux-wireless/msg200825.html

Older threads on this bug:
- https://bugzilla.kernel.org/show_bug.cgi?id=208251
- https://bugzilla.redhat.com/show_bug.cgi?id=1848631
- https://lore.kernel.org/lkml/CAEJqkgjV8p6LtBV8YUGbNb0vYzKOQt4-AMAvYw5mzFr3eicyTg@mail.gmail.com/

#### AWUS036ACM

**AWUS036ACM: but at times was not correctly recognized during our experiments. It may be necessairy to use a recent Linux kernel, and manually executing `sudo modprobe mt76x2u` to load the driver.**

**TODO: AWUS036ACM `iw set wlanX monitor active` in injection mode? (but in mixed mode that crashes)**

The reliability of my `AWUS036ACM` device, which uses the mt76x2u driver, varied depending on how
it was used. I found that:

- On kernel 5.5.0 this device didn't work properly when connected to a USB3.0 port. In particular,
  it kept showing `error: mt7602u_mcu_wait_resp failed with -108` when testing on Kali Linux. The
  device did work properly when connected to a USB2.0 port.

  Frame injection in the 2.4 GHz band was also working properly in the above setup. Frame injection
  was also working in the 5 GHz band (tested by running the `test-injection,py` script on channel 40
  and capturing the frame using an Intel 3160).

  Strangely, this device refuses to inject frames when: (1) it's a data frame; (2) the destination
  MAC address is not all-zeros; and (3) the to-DS and from-DS are both not set. This was independent
  of the sender MAC address. Such frames are generally never sent anyway, so this has no practical
  impact, but it required us to tweak the `test-injection.py` script to always set the to-DS or
  from-DS flags.

  In mixed mode frames using the MAC address of the AP or client as sender MAC address were only
  being injected when injected _after_ authentication. Before authenticating, these frames were
  dropped. In mixed client/monitor mode, the sequence counter of injected frames was being overwritten.
  In mixed AP/monitor mode, I was unable to inject frames towards the client when using the MAC
  address of the AP as the sender MAC address _correctly_ (without the sequence counter being
  overwritten - I confirmed this with a fragmented ping against a client).

  **TODO: test mixed mode with patched drivers**

  **Note: with an ath9k_htc I cannot inject frames with spoofed MAC addresses before and after**
  **authenticating in AP/monitor mode? It does inject frames (incorrectly) in client/monitor mode.**
  _This was likely because capturing with the Intel 3160 was very unreliable._

- On kernel 5.6.13 on Arch Linux, client mode didn't work properly when using an USB3.0 port. But
  AP mode did work properly on a USB3.0 port.

  In mixed mode, non-EAPOL data frames were not sent when injected before authentication. After
  authentication, these were transmitted. **Is that patchable?**

  **Note: with an ath9k_htc I can inject frames with spoofed MAC addresses before and after**
  **authenticating in client/monitor mode. Same thing in AP/monitor mode. But capturing is unreliable.**

#### AWUS036ACH

The AWUS036ACH was tested on Kali Linux after installing the driver using the instructions on
[https://github.com/aircrack-ng/rtl8812au](GitHub). Before pluggin in the device, you must
execute `modprobe 88XXau rtw_monitor_retransmit=1`. Once my changes have been accepted
upstream you can instead simply install the driver using `sudo apt install realtek-rtl88xxau-dkms`.
Note that this device is generally not supported by default in most Linux distributions and
requires manual installation of drivers.

#### Intel AX200

I tested the Intel AX200 as well and found that it is _not_ compatible with the test tool: its firmware
crashes after sending a fragmented frame.

## TODOs

- Confirm each device can detect all vulnerabilities in the recommended modes.

- Test the attacks against PEAP-MSchap for eduroam tests (basic test was working).

- TODO: Is it important to disable encryption? I don't think it is. Otherwise we need sysfsutils as a dependency too.

- Create an example pcap and debug output of all tests.

- Release a known vulnerable linux image to test against? Essential to confirm the tests are working!

- sudo iw wlan0 set monitor otherbss. Does airmon-ng handle this better? Move to general section?

- Describe AP mode in hwsim mode?

- Support non-20MHz channels?

