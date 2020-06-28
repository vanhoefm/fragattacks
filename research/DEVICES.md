# Device checklist

1. Confirm that the device is working normally on Linux.

2. Confirm that the device can be put in monitor mode:

        ifconfig wlan0 down
        iw wlan0 set type monitor
        ifconfig wlan0 up

2. Test normal injection using `aireplay-ng -9 wlan1` using the following command:

	**Put in monitor mode using iw. Use airmong-ng as a backup method.**

3. Test advanced injection using `test-injection.py wan0 wlan1`

   Note: it can be that `wlan0` is injecting frames properly, but that `wlan1`
   is not receiving them properly. So when injection tests on `wlan0` failed,
   try confirming it using a different `wlan1` device to monitor injection.

4. Test injection using `./fragattack.py wlan0 ping --ap --inject-test wlan1`

5. Test injection using `./fragattack.py wlan0 ping --inject-test wlan1`

6. Confirm that a normal ping works `./fragattack.py wlan0 ping I,E`.


Troubleshooting:

- If you cannot put the device in monitor mode, try executing `airmon-ng start wlan0` instead.


# Monitor mode injectin

Device that purely operate in monitor mode might overwrite certain fields of
injected frames. Here we document the default behaviour of some devices.

When using a single physical interface to create a virtual managed _and_ monitor
interface, there are additional unexpected consequences to injection of frames.
These depend on the specific driver/device being used, and we discuss some of
these issues here as well.


## Intel 8265 / 8275 (rev 78) devices

Summary: this can be used without driver/firmware changes in pure monitor mode,
         but care is still needed that frames with different priority are not
         reordered (**TODO: Explain parameter to force this**).

- When connecting normally on Arch Linux, while connecting it sends frames with
  all three address equal to it's own address. This frame contains the numbers
  1 to 0x27 as 32-bit numbers for some reason. This is a strange bug, but at
  least it is not caused by our driver modifications.

- In mixed mode: had to patch driver to prevent sequence number and QoS TID to
  be overwritten

- In mixed mode: unable to transmit any frames from a different transmitter address.
  This is because in `ieee80211_monitor_start_xmit` it cannot find a channel to transmit
  on (finding a valid chandef fails). We patched mac80211 to fix this.

- In mixed mode: cannot inject frames using a TID that is used for the first time.
  There's no queue in the driver allocated for it yet it seems, and this causes issues.
  To prevent this, and prevent frame reordering, we inject all frames on the
  same queue in the driver.

- It ignores `IEEE80211_RADIOTAP_DATA_RETRIES` and retransmites frames 15 times
  both in purely monitor more and mixed managed/monitor mode (before and after
  authenticating).

- Unlike, ath9k_htc, in mixed managed/monitor, we can inject frames before the
  association request is sent. Strangely, the Intel device also sends some strange
  frames while connecting (even on Windows 10). But that only seems to slow down
  the injection of frames.


## Ath9k_htc devices

Summary: when using this device, you must use a modified driver/firmware.
         Since this is a USB device, this can be done inside a virtual machine.

- The ath9k_htc devices by default overwrite the injected sequence number,
  **even when purely operating in monitor mode**.

  Interestingly, the device will not increment the sequence number when the
  MoreFragments flag is set, meaning we can inject fragmented frames (albeit
  with a different sequence number than then one we use in the user-space
  script).

- The above trick does not work when we want to inject other frames between
  two fragmented frames (the chip will assign them difference sequence numbers).
  Even when the fragments use different QoS TIDs, sending frames between them
  will make the chip assign difference sequence numbers to both fragments.
  **TODO: This only is the case in mixed manager/monitor mode I think?**

- Overwriting the sequence can be avoided by patching `ath_tgt_tx_seqno_normal`
  and commenting out the two lines that modify `i_seq`. Note that these changes
  are in the firmware of the device.

- After injecting a _fragmented_ frame with a valid sender MAC
  address, it will not properly inject other frames with a valid sender MAC
  address. This was not tested in other orders (i.e. it might be possible that
  using a spoofed MAC address to inject a fragmented frame, injecting frames
  afterwards with the same spoofed MAC address might also fail).

- In mixed AP/monitor mode, when injecting the first fragment of a frame, it will
  be injected properly, but afterards the chip won't second beacons for one second.
  This can be prevented by injected a dummy packet after the injected fragment.

- The at9k_htc dongle, like other Wi-Fi devices, will reorder frames with
  different QoS priorities. This means injected frames with differen priorities
  may get reordered by the driver/chip. We avoided this by modifying the ath9k_htc
  driver to send all frames using the transmission queue of priority zero,
  independent of the actual QoS priority value used in the frame.
  **This happens even when purely operating in monitor mode.**

- It doesn't retransmit frames in pure monitor mode. In mixed managed/monitor
  after (or right before authentication) it retransmits frames at most ones.
  But it **injects a lot of RTS** as times?!

- In mixed/managed mode, we can inject frames when the managed interface is up
  but not being controlled by wpa_supplicant (but unknown which channel will be
  used). When connecting using wpa_supplicant, it seems we can only inject frames
  after the association request has been sent.

# hwsim mode

- Linux clients need an authentication response _fast_ and we are too slow. Perhaps
  by implementing the packet forwarding in C we can become fast enough.
  
- For some strange reason, the Intel/mvm cannot receive data frames from Android/iPhone/iPad
  after 4-way HS. This is a very strange bug.

