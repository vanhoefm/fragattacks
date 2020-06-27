# Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation

## Introduction

Our attacks affect all Wi-Fi networks. Note that the recent WPA3 specification only introduced
a new authentication method, but its encryption ciphers (CCMP and GCMP) are identical to WPA2.
Because of this, our attack is identical against WPA2 and WPA3 networks.

Older WPA networks by default use TKIP for encryption, and the applicability of our attacks
against this cipher is discussed in the paper. Out of completeness, and to illustrate that Wi-Fi
has been vulnerable since its creation, the paper also briefly discusses the applicability of
our results against WEP.

## Supported Network Cards

Only specific wireless network cards are supported. This is because some network cards may overwrite the
sequence number of injected frames, may overwrite the fragment number, or reorder frames of different priority,
and this interferes with our scripts (i.e. our script might incorrectly say a device is secure although it's not).
We have confirmed that the following network cards work properly with our scripts:

|      Network Card      | USB | 5GHz |        mixed mode       |      injection mode     | hwsim mode (experimental) |
| ---------------------- | --- | ---- | ----------------------- | ----------------------- | ------------------------- |
| Intel Wireless-AC 8265 | No  | Yes  | patched driver          | yes                     | as client                 |
| Intel Wireless-AC 3160 | No  | Yes  | patched driver          | yes                     | as client                 |
| Technoethical N150 HGA | Yes | No   | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| TP-Link TL-WN722N v1.x | Yes | No   | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| Alfa AWUS036NHA        | Yes | No   | patched driver/firmware | patched driver/firmware | patched driver/firmware   |
| Alfa AWUS036ACM        | Yes | Yes  | patched driver????      | yes                     | **yes?**                  |
| Alfa AWUS036ACH        | Yes | Yes  | no                      | patched driver          | _under development_       |
| Netgear WN111v2        | Yes | No   | patched driver          | yes                     | yes                       |

**TODO: Verify 5 GHz and test it in practice.**

**TODO: No longer recommend Virtual Machine, but instead show whether it supports 5GHz?**

**TODO: AWUS036ACM `iw set wlanX monitor active` in injection mode (but in mixed mode that crashes)**

The three last colums signify:

1. Injection mode: whether the network card can be used as a second interface to inject frames in [injection mode](#Injection-mode).

2. Mixed mode: whether the network card can be used in [mixed mode](#Mixed-mode).

3. Hwsim mode: whether the network card can be used in [hwsim mode](#Hwsim-mode).

_Yes_ indicates the card works out-of-the-box in the given mode. _Patched driver/firmware_
means that the card is compatible when used in combination with patched drivers (and/or firmware).
_As client_ means the mode only works when the test script is acting as a client (i.e. you
when are testing an AP). _No_ means this mode is not supported.

We recommend the use of the Technoethical N150 HGA in either injection mode or mixed mode. This deivce
requires the use of a patched driver and firmware, but since it's a USB dongle this can be
configured inside a virtual machine. When using Virtual Box, we recommend to configure the VM to
use a USB2.0 (OHCI + ECHI) controller, because we found the USB3.0 controller to be unreliable.

During our own tests, the AWUS036ACM dongle is supported by Linux, but at times was not correctly
recognized during our experiments. It may be necessairy to use a recent Linux kernel, and manually
executing `sudo modprobe mt76x2u` to load the driver. This devices then works out-of-the-box without
patched drives. We also found it to be unreliable when used inside VirtualBox.

The AWUS036ACH was tested on Kali Linux after installing the driver using `sudo apt install realtek-rtl88xxau-dkms`.
This device is generally not supported by default in most Linux distributions and requires manual
installation of drivers.
**modprobe 88XXau rtw_monitor_retransmit=1**

We tested the Intel AX200 as well and found that it is _not_ compatible with our tool: its firmware
crashes after sending a fragmented frame.

If you are unable to find one of the above network cards, you can search for [alternative network cards](#Alternative-network-cards)
that have a high chance of also working. When using a network card that is not explicitly support,
we strongly recommend to first run the [injection tests](#Network-card-injection-test).

## Prerequisites

Our scripts were tested on Kali Linux and Ubuntu 20.04. To install the required dependencies, execute:

	# Kali Linux and Ubuntu
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev libdbus-1-dev git pkg-config build-essential macchanger net-tools python3-venv

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

The above instructions only have to be executed once.

## Patched Drivers

Install patched drivers:

	sudo apt-get install bison flex linux-headers-$(uname -r)
	# **Self note: replace with real HTTP unauthenticated link on release instead of separate directory**
	cd driver-backports-5.7-rc3-1
	make defconfig-experiments
	make -j 4
	sudo make install

Install patched `ath9k_htc` firmware on Ubuntu:

	cd research/ath9k-firmware/
	sudo cp htc_9271.fw /lib/firmware/ath9k_htc/htc_9271-1.4.0.fw
	sudo cp htc_7010.fw /lib/firmware/ath9k_htc/htc_7010-1.4.0.fw
	# Now reboot the system

Note that the above directories depend on the specific Linux distribution you are running.
If you Wi-Fi donle already is plugged in, unplug it. After installing the patched drivers
and firmware you must reboot your system. The above instructions have to be executed again
if your Linix kernel ever gets updated.

## Before every usage

Every time you want to use the script, you first have to load the virtual python environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with our scripts.

Our script can test both clients and APs:

- Testing APs: **configure the AP you want to test** by editing `research/client.conf`. This is a
  standard `wpa_supplicant` configuration file, see the [hostap documentation] on how to edit it.

- Testing clients: you must execute the script with the extra `--ap` parameter. This instructs
  the script into creating an AP with as name **testnetwork** and password **abcdefgh**. Connect
  to this network with the client you want to test. By default the client must request an IP
  using DHCP. To edit properties of the created AP, such as the channel it's created on, you
  can edit `research/hostapd.conf`.

## Testing Modes

### Injection mode

This mode requires two wireless network cards: one will act as an AP or the client, and the other
one will be used to inject frames. Execute the script in this mode using:

	./fragattack wlan0 --inject wlan1 [--ap] $COMMAND

Here interface wlan0 will act as a legitimate client or AP, and wlan1 will be used to inject
frames. For wlan0, any card that supports normal client or AP mode on Linux can be used. For
wlan1, a card must be used that supports injection mode according to [Supported Network Cards](#Supported-Network-Cards).

In case the tests do not seem to be working, you can confirm that injection is properly working using:

	./test-injection wlan1 wlan0

This will script will inject frames using interface wlan1, and uses wlan0 to check if frames are
properly injected. Note that both interfaces need to support monitor mode for this script to work.

**TODO: First test a normal ping. Frames may not arrive because the target is sleeping!**

### Mixed mode

This mode requires only one wireless network card. This disadvantage is that this mode requires a patched
driver and/or firmware, and that only a small amount of network cards are supported. Execute the script
in this mode using:

	./fragattack wlan0 [--ap] $COMMAND

See [Supported Network Cards](#Supported-Network-Cards) for network cards that support this mode.
For most network cards, this mode requires the installation of modified drivers and/or firmware.
See [Patched Drivers](#Patched-Drivers) on how to install our patched drivers/firmware.

### Hwsim mode

This mode is experimental and only for research purposes. See [hwsim mode details](#Hwsim-mode-details)
for more information.


## Testing for Vulnerabilities

Before testing for vulnerabilities we recommand to execute the first five commands in the table
below. The first command performs a normal ping and can be used to confirm that the test setup
works. The second performs a fragmented ping, and the third can be used to determine how time-
sensitive attacks against the device would be.

The commands that test for vulnerabilities are grouped by their type along with a reference to
the paper in which section the vulnerability is explained.

|             Command              | Short description
| -------------------------------- | ---------------------------------
| `ping I,E`                       | Send a normal ping
| `ping I,E,E`                     | Send a normal fragmented ping
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
| `ping I,E,C,AE`                  | Inject a fragment, reconnect or as client _reassociate_, then inject second fragment.
| `ping I,E,C,E`                   | Same as above, but with a longer delay before sending the second fragment.
| `ping I,E,C,AE --full-reconnect` | Inject a fragment, reconnect, then inject second fragment.
| `ping I,E,C,E --full-reconnect`  | Same as above, but with a longer delay before sending the second fragment.
| <div align="center">*Non-consecutive (Section 6.2)*</div> | 
| `ping I,E,E --inc-pn 2`          | Send a fragmented ping with non-consecutive packet numbers.
| <div align="center">*Mixed plain/enc (Section 6.3)*</div> | 
| `ping I,E,P`                     | Send a fragmented ping: first fragment encrypted, second fragment in plaintext.
| `ping I,P,E`                     | Send a fragmented ping: first fragment in plaintext, send fragment encrypted.
| `ping I,P`                       | Send a plaintext ping.
| `ping I,P,P`                     | Send a fragmented ping: both fragments are sent in plaintext.
| `linux-plain`                    | Mixed plaintext/encrypted fragmentation attack specific to Linux.
| <div align="center">*EAPOL forwarding (Section 6.4)*</div> | 
| `eapol-inject 00:11:22:33:44:55` | Test if the AP forwards EAPOL frames before being connected.
| <div align="center">*Broadcast fragments (Section 6.7)*</div> | 
| `ping I,D,P --bcast-ra`          | Send ping in a 2nd plaintext broadcasted fragment.
| <div align="center">*EAPOL A-MSDUs (Section 6.8)*</div> | 
| `eapol-amsdu BB`                 | Send A-MSDU frame disguised as EAPOL frame. Use tcpdump to check if vulnerable.
| `eapol-amsdu I,CC`               | Same as above, except the frame is injected after obtaining an IP.
| `eapol-amsdu M,BB`               | Send a malformed A-MSDU disguised as EAPOL. Use tcpdump to check if vulnerable.
| `eapol-amsdu M,I,CC`             | Same as above, except the frame is injected after obtaining an IP.

Notable remarks:

- `ping I,E,E --delay 5`: this test is used to check the maximum accepted delay between two fragments.
  If the default test doesn't work, try with `--delay 1.5` or lower. In case the maximum accepted delay
  is low, this may impact other tests. In particular, all fragments sent in other tests must be sent
  within the maximum delay, otherwise the test will trivially fail (and you might conclude a device
  isn't vulnerable to an attack even though it might be).

- _Mixed key attacks_: When running the mixed key test against an AP, the AP must be configured to
  regularly renew the PTK by executing a new 4-way handshake (e.g. every 30 seconds or minute). Against
  a low number of APs, the client can also request the AP to renew the PTK. This can be done by adding
  the `--rekey-request` parameter.
  
  Home routers with a MediaTek driver will perform the rekey handshake in plaintext. To test these
  devices, also add the `--rekey-plaintext` parameter.
  
  Certain clients install the key too early during a pairwise session rekey. To test these devices,
  add the `--rekey-early-install` parameter and retry the test.

In case the script doesn't appear to be working, check the following:

1. Check that no other process is using the network card (e.g. kill your network manager).

2. Check that you are using modified drivers if needed for your wireless network card.

3. Check that you are using modified firmware if needed for your wireless network card.

4. Run the [injection tests](#Network-card-injection-test) to make sure injection is working properly.

5. Check that you machine isn't generating background traffic that interferes with the tests. In
   particular, disable networking in your OS, manually kill your DHCP client/server, etc.

6. Confirm that you are connecting to the correct network. Double-check `client.conf`.

7. Make sure the network is using (AES-)CCMP as the encryption algorithm.

## Extended Vulnerability Tests

Optionally you can also run more advanced tests. These have a lower chance of uncovering new vulnerabilities,
but against more exotic implementations these might reveal flaws that the normal tests could not detect.

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

The script `test-injection.py` can be used to test whether frames are properly injected when
using _injection mode_:

	./test-injection.py wlan0 wlan1

Here we test if network card `wlan0` properly injects frames and we use network card `wlan1`
to monitor whether frames are properly injected. In case you do not have a second network
card, you can execute a partial injection test using:

	./test-injection.py wlan0

Unfortunately, the above test can only test if the kernel overwrites fields of injected frames,
it cannot test whether the firmware or wireless chip itself overwrites fields.

To test whether a network card properly injects frames in _mixed mode_, you can execute the
following two commands:

	./fragattack wlan0 ping --inject-test wlan1
	./fragattack wlan0 ping --inject-test wlan1 --ap

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
  This will further slightly slowdown the handling of frames.

- Frames are not properly acknowledged depending on the wireless network card, which causes some
  tested clients or APs to disconnect during authentication or association.

Nevertheless, the advantage is that is mode requires only one wirelss network card and can,
depending on the network card, be used without patches to the driver and/or firmware. Before
using this mode, create two virtual network cards:

	./hwsim.sh

This will output the two created virtual "hwsim" interfaces, for example wlan1 and wlan2. Then
search for the channel of the AP you want to test, and put the real network card on this channel:

	./scan.sh wlan0
	iw wlan0 set type monitor
	ifconfig wlan0 up
	iw wlan0 set channel 11

You can now start the script as follows:

	./fragattack wlan0 --hwsim wlan1,wlan2 [--ap] $COMMAND

After the script executed, you can directly run it again with a new command.

### Static IP Configuration

In case the device you are testing doesn't support DHCP, you can manually specify the IP addresses
that the script should use. For example:

	./fragattack.py wlan0 ping --inject wlan1 --ip 192.168.100.10 --peerip 192.168.100.1

Here the testing script will use address 192.168.100.10, and it will inject a ping request
to the peer IP address 192.168.100.1.

### Alternative network cards

In case you cannot get access to one of the recommended wireless network cards, a second option
is to get a network card that uses the same drivers on Linux. In particular, you can try:

- Network cards that use [ath9k_htc](https://wikidevi.wi-cat.ru/Ath9k_htc)

- Network cards that use [iwlmvm](https://wireless.wiki.kernel.org/en/users/drivers/iwlwifi)

We recommend cards based on `ath9khtc`. Not all cards that use `iwlmvm` will be compatible. When
using an alternative network card, we strongly recommend to first run the [injection tests](#Network-card-injection-test)
to confirm that the network card is compatible.

### Notes on device support

#### ath9k_htc

There is a known problem with the `ath9k_htc` driver, used by the Technoethical N150 HGA, TP-Link
TL-WN722N v1.x, and Alfa AWUS036NHA, causing it not to work on kernel 5.7.3 and above. Downgrading
to kernel `5.7.2` fixes this issue for now. More details are available at:

- https://bugzilla.kernel.org/show_bug.cgi?id=208251

- https://bugzilla.redhat.com/show_bug.cgi?id=1848631

- https://lore.kernel.org/lkml/CAEJqkgjV8p6LtBV8YUGbNb0vYzKOQt4-AMAvYw5mzFr3eicyTg@mail.gmail.com/

#### AWUS036ACM

The reliability of our `AWUS036ACM` device, which uses the mt76x2u driver, varied depending on how
it was used. We found that:

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
  In mixed AP/monitor mode, we were unable to inject frames towards the client when using the MAC
  address of the AP as the sender MAC address _correctly_ (without the sequence counter being
  overwritten - we confirmed this with a fragmented ping against a client).

  **TODO: test mixed mode with patched drivers**

  **Note: with an ath9k_htc we cannot inject frames with spoofed MAC addresses before and after**
  **authenticating in AP/monitor mode? It does inject frames (incorrectly) in client/monitor mode.**

- On kernel **X.Y.Z**


## TODOs

- Confirm each device can detect all vulnerabilities in the recommended modes.

- Test the attacks against PEAP-MSchap for eduroam tests (basic test was working).

- TODO: Is it important to disable encryption? I don't think it is. Otherwise we need sysfsutils as a dependency too.

- Create an example pcap and debug output of all tests.

- Release a known vulnerable linux image to test against? Essential to confirm the tests are working!

- sudo iw wlan0 set monitor otherbss. Does airmon-ng handle this better? Move to general section?

- Describe AP mode in hwsim mode?

- Support non-20MHz channels?

