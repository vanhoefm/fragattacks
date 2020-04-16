# Usage

## Installation

1. Install the dependencies in `../../requirements.txt` (Python3).

2. Compile the modified `hostapd` and `wpa_supplicant` using `cd research && ./build.sh`.
   If this fails install the required dependencies. The build.sh script is also very
   trivial so you can manually execute each command in that script to see
   where it fails and how to fix it.

3. Before proceding, make sure to have pulled all submodules (i.e., libwifi).

## Example Usage

Then you can run `./fragattack.py interface tests` where the first argument
is the interface to use. This inferface should NOT be set to monitor mode
(the script will handle this). The second parameter is the test to execute.

You can first execute a simple ping to see if everything is working:

	./fragattack.py wlan0 ping --ip 192.168.100.10 --peerip 192.168.100.1

Here `peerip` is the IP address of the AP/router we are testing, and `ip`
denotes the IP address we are assignment to the client. Edit the file
`client.conf` the specify the SSID and password of the network you are
testing. You should see a message "SUCCESSFULL INJECTION".

