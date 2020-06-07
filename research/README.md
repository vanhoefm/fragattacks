This repository contains scripts to test for Wi-Fi fragmentation and aggregation vulnerabilities.

# Usage

## Supported Network Cards

Only specific wireless network cards are supported. This is because some network cards may overwrite the
sequence number of injected frames, may overwrite the fragment number, or reorder frames of different priority,
and this interferes with our scripts (i.e. our script might incorrectly say a device is secure although it's not).
We have confirmed that the following network cards work properly with our scripts:

|      Network Card      | USB |      injection mode     |        mixed mode       | hwsim mode (experimental) |
| ---------------------- | --- | ----------------------- | ----------------------- | ------------------------- |
| Intel AX200            | No  | ?                       | ?                       | ?                         |
| Intel Wireless-AC 8265 | No  | yes                     | patched driver          | as client                 |
| Intel Wireless-AC 3160 | No  | yes                     | patched driver/firmware | as client                 |
| Technoethical N150 HGA | Yes | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| TP-Link TL-WN722N v1.x | Yes | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| Alfa AWUS036NHA        | Yes | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| Alfa AWUS036ACM        | Yes | ?                       | ?                       | ?                         |
| Alfa AWUS036ACH        | Yes | ?                       | ?                       | ?                         |
| Netgear WN111v2        | Yes | yes                     | patched driver          | yes                       |

The three last colums signify:

1. __Injection mode__: whether the network card can be used as a second interface to inject frames in [injection mode].

2. __hwsim mode__: whether the network card can be used in [hwsim mode].

3. __Mixed mode__: whether the network card can be used in [mixed mode].


We recommend the use of the Technoethical N150 HGA in either injection mode or mixed mode. It
requires the use of a patched driver and firmware, but since it's a USB dongle this can be
configured inside a virtual machine. If you are unable to find one of the above devices, you
can search for [alternative devices] that have a high chance of also working.

## Prerequisites

Our scripts were tested on Kali Linux and Ubuntu 20.04. To install the required dependencies, execute:

	# Kali Linux and Ubuntu
	apt-get update
	apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev libdbus-1-dev git pkg-config build-essential macchanger net-tools python3-venv

Now clone this repository, build the tools, and configure a virtual python3 environment:

	git clone git@bitbucket.org:vanhoefm/fragattack-scripts.git --recursive
	cd fragattack-scripts
	./build.sh
	cd research
	python3 -m venv venv
	source venv/bin/activate
	pip install wheel
	pip install -r requirements.txt

The above instructions only have to be executed once.

## Patched Drivers

Install patched drivers:

	apt-get install bison flex linux-headers-$(uname -r)
	git clone git@bitbucket.org:vanhoefm/fragattack-backports57.git
	cd fragattack-backports57.git
	make defconfig-experiments
	make -j 4
	sudo make install

Install patched `ath9k_htc` firmware on Ubuntu:

	cd research/ath9k-firmware/
	cp htc_9271.fw /lib/firmware/ath9k_htc/htc_9271-1.4.0.fw
	cp htc_7010.fw /lib/firmware/ath9k_htc/htc_7010-1.4.0.fw

**TODO: How to install patched ath9k_htc drivers.**

## Before every usage

Every time you want to use the script, you first have to load the virtual python environment
as root. This can be done using:

	cd fragattack-scripts/research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with our scripts.

Our script can test both clients and APs:

- Testing APs: configure the AP you want to test by editing `research/client.conf`. This is a standard
  `wpa_supplicant` configuration file, see the [hostap documentation] on how to edit it.

- Testing clients: you must execute the script with the extra `--ap` parameter. This instructs
  the script into creating an AP with as name **testnetwork** and password **abcdefgh**. Connect
  to this network with the client you want to test. **By default the client must request an AP**
  **using DHCP.** To edit properties of the created AP, such as the channel it's created on, you
  can edit `research/hostapd.conf`.

# Testing Modes

## Injection Mode

This mode requires two devices: one will act as an AP or the client, and the other will be used to
inject frames. Execute the script in this mode using:

	./fragattack wlan0 --inject wlan1 [--ap] $COMMAND

Here interface wlan0 will act as a legitimate client or AP, and wlan1 will be used to inject
frames. For wlan0, any card that supports normal client or AP mode on Linux can be used. For wlan1,
a card must be used that supports injection mode according to [Supported Network Cards].

In case the tests do not seem to be working, you can confirm that injection is properly working using:

	./test-injection wlan1 wlan0

This will script will inject frames using interface wlan1, and uses wlan0 to check if frames are
properly injected. Note that both interfaces need to support monitor mode for this script to work.

### Mixed mode

This mode requires only one device. This disadvantage is that this mode requires a patched driver and/or firmware,
and that only a small amount of devices are supported. Execute the script in this mode using:

	./fragattack wlan0 [--ap] $COMMAND

**Reference how to compile and install backport drivers.**

### Hwsim mode (experimental)

**TODO: This mode isn't useful for Intel/mvm since it's too unreliable... Bootable Live CD is better!**

This mode requires only one device. The disadvantage is that this mode is the least reliable:

- Frames are handled slower, possibly causing the tested client/AP to timeout during authentication
  or association.

- When injeting frames, they may be retransmitted even though an acknowledgement was recieved.
  This will further slightly slowdown the handling of frames.

- Frames are not properly acknowledged depending on the wireless network card, which causes some
  tested clients or APs to disconnect during authentication or association.

Nevertheless, the advantage is that is mode can, depending on the network card, be used without
patches to the driver and/or firmware. Before using this mode, create two virtual network cards:

	./hwsim.sh

This will output the two created virtual "hwsim" interfaces, for example wlan1 and wlan2. Then
search for the channel of the AP you want to test, and put the real network card on this channel:
**TODO: recommend channel 1-13?**
**TODO: do we also support AP mode? I suppose for patched ath9k_htc it does work.**

	./scan.sh wlan0
	iw wlan0 set type monitor
	ifconfig wlan0 up
	iw wlan0 set channel 11
	**TODO: sudo iw wlan0 set monitor otherbss. Does airmon-ng handle this better? Move to general section?**

You can now start the script as follows:

	./fragattack wlan0 --hwsim wlan1,wlan2 [--ap] $COMMAND

After the script executed, you can directly run it again with a new command.

## Testing for Vulnerabilities

We recommend executing the following tests. The tests marked in bold correspond to vulnerabilities,
and the other tests are useful to understand the behaviour of the device under test.

|          Test          |             Command            | Short description
| ---------------------- | ------------------------------ | ---------------------------------
| Normal ping            | ping I,E                       | Send a normal ping
| Fragmented ping        | ping I,E,E                     | Send a fragmented ping
| Fragmentation timeout  | ping I,E,E --delay 5           | Send a fragmented ping with a 5s delay between fragments
| **Non-consecutive**    | ping I,E,E --inc-pn 2          | Send a fragmented ping with non-consecutive packet numbers.
| Seperator              | ping-frag-sep                  | Send a fragmented ping with fragments separated by a normal frame
| **Mixed key**          | ping I,R,BE,AE                 | As client wait for rekey and as AP force rekey, then encrypt fragments under different keys.
|                        | ping I,R,BE,AE --pn-per-qos    | Same as above, except it also work when the device doesn't accept non-consecutive fragments.
| **Cache Poison**       | ping I,E,C,AE                  | Inject a fragment, as client _reassociate_ and as AP force tested client to reconnect, then inject second fragment.
|                        | ping I,E,C,E                   | Same as above, except there is a longer delay before sending the second fragment.
|                        | ping I,E,C,AE --full-reconnect | Inject a fragment, as client _reconnect_ and as AP force tested client to reconnect, then inject second fragment.
|                        | ping I,E,C,E --full-reconnect  | Same as above, except there is a longer delay before sending the second fragment.
| **A-MSDU**             | ping I,E --amsdu               | Send a normal ping encapsulated in a normal A-MSDU frame.
|                        | ping I,E,E --amsdu             | Send a normal ping an a fragmented A-MSDU frame.
|                        | amsdu-inject                   | Send a valid A-MSDU frame whose start is also a valid LLC/SNAP header.
|                        | amsdu-inject linux             | Send an invalid A-MSDU frame whose start is also a valid LLC/SNAP header (frame treated as valid by Linux/FreeBSD).
| **Mixed Plain/Enc**    | ping I,E,P                     | Send a fragmented ping: first fragment encrypted, second fragment in plaintext.
|                        | ping I,P,E                     | Send a fragmented ping: first fragment in plaintext, send fragment encrypted.
|                        | ping I,P                       | Send a plaintext ping.
|                        | ping I,P,P                     | Send a fragmented ping: both fragments are sent in plaintext.
| **Linux Plain/Enc**    | linux-plain                    | Mixed plaintext/encrypted fragmentation attack specific to Linux.
| **EAPOL A-MSDU**       | eapol-amsdu BB                 | Send A-MSDU frame disguised as EAPOL frame. Run tcpdump on target to check if vulnerable.
|                        | eapol-amsdu I,CC               | Same as above, except the frame is injected after being connected and obtaining an IP.
|                        | eapol-amsdu M,BB               | Send a malformed A-MSDU frame disguised as EAPOL frame. Use tcpdump to check if vulnerable.
|                        | eapol-amsdu M,I,CC             | Same as above, except the frame is injected after being connected and obtaining an IP.
| **MacOS Plain Inject** | macos BB                       | Fragmented EAPOL attack (notably works against MacOS). Run tcpdump on target to check if vulnerable.
| **Broadcast ping**     | ping I,D,P --bcast-ra          | Send ping inside the second plaintext fragment of a broadcast Wi-Fi frame (no 1st fragment is sent).

Optionally you can also run more advanced tests. These have a lower chance of uncovering vulnerabilities,
but against more exotic implementations that might work (while the above tests could fail).

|          Test          |             Command             | Short description
| ---------------------- | ------------------------------- | ---------------------------------
| **Mixed key**          | ping I,E,R,AE                   | **Inspired by MediaTek case**
|                        | ping I,E,R,AE --rekey-plaintext | Mixed key attack against MediaTek
|                        | ping I,E,R,AE --rekey-request --rekey-plaintext | Mixed key attack against MediaTek
|                        | ping I,E,R,AE --rekey-early-install | **TODO**
|                        | ping I,R,BE,AE --freebsd        | Mixed key attack against FreeBSD
| **Mixed Plain/Enc**    | ping I,E,P,E                    | Send a fragmented ping: first fragment encrypted, second plaintext, third encrypted.
|                        | linux-plain 3                   | Mixed plaintext/encrypted fragmentation attack, decoy fragment is sent using QoS TID 3.
| **EAPOL A-MSDU**       | eapol-amsdu [M,]BB --bcast-dst  | Same as "eapol-amsdu [M,]BB" but ping is broadcasted. To test AP, check if a 2nd client receives the ping.
|                        | eapol-amsdu [M,]I,CC --bcast-dst| Same as "eapol-amsdu [M,]I,CC" but ping is broadcasted. To test AP, check if a 2nd client receives the ping.
|                        | eapol-amsdu SS                  |
|                        | eapol-amsdu AA                  |
| **MacOS Plain Inject** | macos CC                        | Fragmented EAPOL attack (notably works against MacOS). Run tcpdump on target to check if vulnerable.
| **Broadcast ping**     | ping I,P,P --bcast-ra           | Send ping inside two plaintext fragments of a broadcast Wi-Fi frame.
|                        | ping I,P --bcast-ra             | Send ping inside a plaintext broadcast Wi-Fi frame.

Details remarks:

- Fragmentation timeout: this test is used to check the maximum accepted delay between two fragments.
  If the default test doesn't work, try with `--delay 2` or lower. In case the maximum accepted delay
  is low, this may impact other tests. **All fragments sent in other tests must be sent within the**
  **maximum delay, otherwise the test will automatically fail (and you might conclude a device isn't.**
  **vulnerable to an attack even though it might be.**

- When running the mixed key test against an AP, the AP must be configured to regularly renew the PTK
  by executing a new 4-way handshake (e.g. every 30 seconds or minute). Against a low number of APs,
  the client can also request the AP to renew the PTK. This can be done by adding the `--rekey-request`
  parameter.
  
  Home routers with a MediaTek driver will perform the rekey handshake in plaintext. To test these
  devices, also add the `--rekey-plaintext` parameter.
  
  **Against unknown devices,** the PTK will be installed too early. To test these devices, add the
  `--rekey-early-install` parameter and retry the test.

In case you are testing a device which should be vulnerable, but the script doesn't detect that
it's vulnerable, double check the following things:

1. Check that you are using modified drivers if needed for your wireless network card.

2. Check that you are using modified firmware if needed for your wireless network card.

3. Run the [device injection tests] to make sure injection is working properly.

4. Check that he machine that executes the script doesn't generate background traffic that might interfere with
   the tests. In particular, remember to disable network in your OS, manually kill your DHCP client/server, etc.

5. Confirm that you are connecting to the correct network. Double-check `client.conf`.

6. Make sure the network is using (AES-)CCMP as the encryption algorithm.

# Advanced Usage

## Static IP Configuration

In case the device you are testing doesn't support DHCP, you can manually specify the IP addresses
that the script should use. For example:

	./fragattack.py wlan0 ping --inject wlan1 --ip 192.168.100.10 --peerip 192.168.100.1

Here the testing script will use address 192.168.100.10, and it will inject a ping request
to the peer IP address 192.168.100.1.




# TODOs

- Confirm each device can detect all vulnerabilities in the recommended modes.

- Test the attacks against PEAP-MSchap for eduroam tests (basic test was working).

- TODO: Is it important to disable encryption? I don't think it is. Otherwise we need sysfsutils as a dependency too.

- Include references to sections in the paper for the command overview table.

- Create an example pcap and debug output of all tests.

- Release a known vulnerable linux image to test against? Essential to confirm the tests are working!


## Live CD

- Boot Ubuntu with exactly the same kernel as the live CD
- Install the scripts
- Buil the backport drivers
- Run `depmod` manually
- Continue

