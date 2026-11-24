# FritzMonitor

Local Internet traffic monitor for Linux Mint 22.2 and FRITZ!Box. FritzMonitor reads the router's diagnostic capture over HTTPS, uses TShark to extract metadata, and stores five-minute aggregates in SQLite. Open the dashboard at [127.0.0.1:8090](http://127.0.0.1:8090/). Capture requires only the router and the computer running FritzMonitor.

[Versione italiana](https://github.com/vroby65/FritzMonitor/tree/italiano)

## Verified compatibility

The test router was a **FRITZ!Box 7530 AX running FRITZ!OS 8.25**. Its `/jason_boxinfo.xml` reported version 256.08.25 on November 24, 2026. PBKDF2 sign-in through `/login_sid.lua?version=2` and session ID validation both worked. The `/html/capture.html` page opens the authenticated `/?lp=cap` page. On this firmware, the page returns HTML from `POST /data.lua` with `page=cap`.

| Interface | Local test result |
| --- | --- |
| `3-0`, routing | Client IPv4 before NAT and IPv6. Controlled tests covered 12 requests and 12 replies each for Wi-Fi IPv4, wired IPv4, and Wi-Fi IPv6. Each sequence appeared once per direction. |
| `1-lan`, `1-wl0`, `1-wl1` | The capture request returned an empty response during testing. |
| `3-17`, internet | Valid PCAP. The two expected private IPv4 addresses were absent. |
| `4-129`, Wi-Fi radio | Wi-Fi PCAP. The sample yielded no decoded IP packets. |
| `4-130`, Wi-Fi radio | The sample contained records in a different format from the one the capture pipeline handles. |

The extended test on `3-0` received 118,261 IP frames in 20 minutes and 50 seconds over a single stream. Both expected IPv4 clients appeared in both directions.

FritzMonitor captures on one interface, `3-0` by default. It counts traffic between one address in a local prefix and a public unicast peer. Offload, VPN paths, firmware changes, and guest subnet prefixes can affect the traffic visible at the capture point.

Interface `3-0` carries IP packets without Ethernet headers. The two IPv4 clients in the test were matched to their MAC addresses and names using the local TR-064 inventory over HTTPS. The daemon also uses the local system's IPv6 addresses and neighbor table when it finds an exact match. An observed IP identifies an endpoint when its hardware address is unavailable. [TR-064 Hosts specification](https://fritz.support/resources/TR-064_Hosts.pdf)

The firmware delivers modified PCAP with magic value `0xa1b2cd34` and eight extra bytes per record. TShark 4.2 rejects this variant on standard input. FritzMonitor converts it to standard PCAP in memory and preserves timestamps and original frame lengths. It maps the routing interface's link type 14 to the standard RAW IP link type 101. [Wireshark PCAP format](https://wiki.wireshark.org/Development/LibpcapFileFormat/) [Wireshark RAW IP link type mapping](https://github.com/wireshark/wireshark/blob/master/wiretap/pcap-common.c)

### References

- fritz-capture documents challenge-response sign-in and the `capture_notimeout` Start and Stop URLs. It reports tests on the FRITZ!Box 7530 and FRITZ!OS versions up to 7.29. [J-Gras/fritz-capture](https://github.com/J-Gras/fritz-capture)
- fritzdump documents FRITZ!OS 8.x and reading interface IDs from /data.lua. FritzMonitor also reads the Stop parameters from the router's HTML. [arn-c0de/fritzdump](https://github.com/arn-c0de/fritzdump)
- The vendor's technical note describes PBKDF2 sign-in and session ID validation. [FRITZ! technical note on session IDs](https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_english_2021-05-03.pdf)

## Installation

Install Python 3.12, the ip command from iproute2, and TShark. On Mint you can use the system package for TShark. If prompted to allow non-root users to capture from local network interfaces, choose **No**. FritzMonitor reads from a pipe and runs with ordinary user privileges. [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

~~~bash
sudo apt install tshark
python3 probe.py diagnostics
python3 configure.py
python3 probe.py diagnostics --authenticated
./install.sh
systemctl --user enable --now fritzmonitor.service
~~~

The setup command displays the SHA-256 fingerprint of the router's HTTPS certificate for confirmation. The terminal hides password input. If the router web page asks only for a password, press Enter at the username prompt to use the account selected by the router. FritzMonitor checks the saved fingerprint on subsequent connections. If the certificate changes, verify it and rerun `python3 configure.py --update`.

The configuration lives at `~/.config/fritzmonitor/config.toml` or under `XDG_CONFIG_HOME`. The service user must own the file and its permissions must be 600. Use the fields in [config.example.toml](config.example.toml) to set guest or additional prefixes, data retention, a different local port, or the path to TShark. If you omit the prefixes, FritzMonitor detects them on the Linux network interface used to reach the router. Restart the service after changing its configuration.

Use `loginctl show-user "$USER" -p Linger` to check whether systemd can start the user service at boot. An authorized account can run `loginctl enable-linger "$USER"`. To update FritzMonitor, run `./install.sh` again and restart the service.

~~~bash
systemctl --user status fritzmonitor.service
journalctl _SYSTEMD_USER_UNIT=fritzmonitor.service _UID="$(id -u)" -f
./uninstall.sh
~~~

Uninstall removes the program and service. Configuration and data remain in your user directories. The default SQLite path is `~/.local/state/fritzmonitor/monitor.sqlite3` or the equivalent under `XDG_STATE_HOME`.

## Dashboard and data

- The overview shows the last hour of traffic, capture status, and bytes sent and received. History groups traffic by day, week, or month in local time.
- Select a device to see its Internet connections. The dashboard shows local IP, available device name and MAC, remote IP, observed domain, protocol, remote port, byte counts, available country, and first and last observed times. Search also supports MAC, country, and protocol. CSV export includes every row that matches the filters.
- Domains come from visible TLS or HTTP metadata or from observed DNS answers that are still valid. Encrypted DNS, ECH, missing answers, and shared IPs can leave the domain blank. Country information comes from an optional local MMDB file set by `storage.geoip`. On Mint, install its reader with `sudo apt install python3-maxminddb`. [Supported GeoIP formats](https://dev.maxmind.com/geoip/docs/databases/)
- Byte counts use the original lengths reported by the capture point. SQLite retains metadata and counts for 90 days by default. All packet processing stays in memory. The dashboard binds to IPv4 loopback and uses local assets, with no CDN, telemetry, or remote service.
- The daemon validates its session every five minutes, handles temporary sign-in blocks, and backs off for up to one minute between connection attempts. A stream interruption can leave a gap in observations. Update the local configuration after a verified certificate change or a credential failure.

### Activity filters

- **New destinations** shows remote IPs first observed by FritzMonitor in the selected period. The comparison uses the retained history.
- **Unusual traffic volumes** shows five-minute intervals with at least 16 MiB and more than four times that device's recent average. The baseline uses at least 12 active intervals in the preceding seven days.
- **Unknown devices** shows connections from devices with no name in the inventory. **Unusual ports** uses a fixed list of common remote ports.
- **Recurring activity** looks for at least three consecutive gaps between active intervals. The longest gap can be at most 20% longer than the shortest. This may indicate background activity.
- **Nighttime activity** uses the configured local hours, initially 00:00 to 06:00. These filters describe traffic characteristics for review.

## Diagnostics and coverage

Stop the service before running a capture test to avoid overlapping captures. Note the IP and MAC of a Wi-Fi client and a wired client. Have both generate Internet traffic after each stream opens. The probe processes packets in memory.

~~~bash
systemctl --user stop fritzmonitor.service
python3 probe.py diagnostics --authenticated
python3 probe.py coverage --seconds 20 --interface 3-0 --interface 1-lan --interface 3-17 \
  --expected WIFI_IP@WIFI_MAC --expected WIRED_IP@WIRED_MAC
python3 probe.py capture --interface 3-0 --seconds 1200 \
  --expected WIFI_IP@WIFI_MAC --expected WIRED_IP@WIRED_MAC
systemctl --user start fritzmonitor.service
~~~

Replace the placeholders with actual addresses. `bidirectional` indicates that the IP and optional MAC appeared in both directions. `mac_source` distinguishes a MAC in the frame from one obtained from the inventory. Use `--destination IP` to isolate a peer. Omit `--seconds` from capture to run until Ctrl+C. Reports are cumulative for each attempt and appear every ten seconds. Repeat the test with an IPv6 client and peer to check IPv6 coverage.

If a firmware release prevents packet capture, the router's TR-064 host inventory and WAN counters can still provide a device list and connection totals. Per-device destinations require a capture point before NAT, such as a gateway or infrastructure with port mirroring. [FRITZ! interface documentation](https://fritz.com/en/pages/interfaces)

## Verification

~~~bash
python3 -m unittest discover -s tests -v
node --check web/app.js
bash -n install.sh uninstall.sh
systemd-analyze --user verify fritzmonitor.service
~~~
