# Device support checklist

1. Confirm that the device is working normally on Linux.

2. Confirm that the device can be put in monitor mode:

        ifconfig wlan0 down
        iw wlan0 set type monitor
        ifconfig wlan0 up

3. Test normal injection based on "Network card injection test" in [README.md](README.md).

4. Confirm that a normal and fragmented ping works:

	./fragattack.py wlan0 ping I,E
	./fragattack.py wlan0 ping I,E,E


## Intel 8265 / 8275 (rev 78) devices

Summary: this can be used without driver/firmware changes in pure monitor mode, but
         care is still needed that frames with different priority are not reordered.

- When connecting normally on Arch Linux, while connecting it sends frames with
  all three address equal to it's own address. This frame contains the numbers
  1 to 0x27 as 32-bit numbers for some reason. This is a strange bug, but at
  least it is not caused by our driver modifications.

- In mixed mode: had to patch _driver_ to prevent sequence number and QoS TID to
  be overwritten

- In mixed mode: unable to transmit any frames from a different transmitter address.
  This is because in `ieee80211_monitor_start_xmit` it cannot find a channel to transmit
  on (finding a valid chandef fails). We patched mac80211 to fix this (this patch has
  not been submitted upstream because it feels hacky).

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

- The ath9k_htc devices by default overwrite the injected sequence number,
  even when purely operating in monitor mode.

- Interestingly, the device will not increment the sequence number when the
  MoreFragments flag is set, meaning we can inject fragmented frames (albeit
  with a different sequence number than then one we use in the user-space
  script).

- The above trick does not work when we want to inject other frames between
  two fragmented frames (the chip will assign them difference sequence numbers).
  Even when the fragments use different QoS TIDs, sending frames between them
  will make the chip assign difference sequence numbers to both fragments.

- Overwriting the sequence number (in pure monitor mode) can be avoided by patching
  `ath_tgt_tx_seqno_normal` and commenting out the two lines that modify `i_seq`.
  Note that these changes are in the firmware of the device.

- After injecting a _fragmented_ frame with a valid sender MAC
  address, it will not properly inject other frames with a valid sender MAC
  address. This was not tested in other orders (i.e. it might be possible that
  using a spoofed MAC address to inject a fragmented frame, injecting frames
  afterwards with the same spoofed MAC address might also fail). We work around
  this by injecting a dummy frame after a fragmented one (= one of the MF flag set).

- In mixed AP/monitor mode, when injecting the first fragment of a frame, it will
  be injected properly, but afterards the chip won't second beacons for one second.
  This can (again) be prevented by injected a dummy packet after the injected fragment.

- The `at9k_htc` dongle, like other Wi-Fi devices, will reorder frames with different
  QoS priorities. This means injected frames with differen priorities may get reordered
  by the driver/chip. This happens even when purely operating in monitor mode. We avoided
  this by modifying the `ath9k_htc` driver to send allframes using the transmission queue
  of priority zero, independent of the actual QoS priority value used in the frame.

- It doesn't retransmit frames in pure monitor mode. In mixed managed/monitor
  after (or right before authentication) it retransmits frames at most once.
  But somtimes it injects a lot of RTS frames?!

- In mixed/managed mode, we can inject frames when the managed interface is up
  but not being controlled by wpa_supplicant (but unknown which channel will be
  used). When connecting using wpa_supplicant, it seems we can only inject frames
  after the association request has been sent.


# AWUS036ACM

- Strangely, this device refuses to inject frames when: (1) it's a data frame; (2) the destination
  MAC address is not all-zeros; and (3) the to-DS and from-DS are both not set. This was independent
  of the sender MAC address. Such frames are generally never sent anyway, so this has no practical
  impact, but it required us to tweak the `test-injection.py` script to always set the to-DS or
  from-DS flags.

- In mixed mode frames using the MAC address of the AP or client as sender MAC address were only
  being injected when injected _after_ authentication. Before authenticating, these frames were
  dropped. This is fixed in our mac80211 patches by allowing all injected frames in `ieee80211_tx_dequeue`.
  
- In mixed client/monitor mode, the sequence counter of injected frames was being overwritten.
  In mixed AP/monitor mode, I was unable to inject frames towards the client when using the MAC
  address of the AP as the sender MAC address _correctly_ (without the sequence counter being
  overwritten - I confirmed this with a fragmented ping against a client). This is fixed by our
  patches to `mac802111`.

- On kernel 5.6.13 on Arch Linux, client mode didn't work properly when using an USB3.0 port. But
  AP mode did work properly on a USB3.0 port at some point. But it general it's in practice still
  unstable on a USB3.0 port.

