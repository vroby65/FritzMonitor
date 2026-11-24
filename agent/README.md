# Project guide

FritzMonitor is a local Internet traffic monitor for Linux Mint, FRITZ!Box, Python 3.12, SQLite, and TShark. Capture interface `3-0` was verified on a FRITZ!Box 7530 AX running FRITZ!OS 8.25.

- `configure.py` verifies the router certificate and sign-in from the terminal and writes credentials to a TOML file with mode 0600. See `config.example.toml` for the available fields. `exclusive_capture` serializes the daemon and probes using the same configuration.
- `fritzrouter.py` handles certificate pinning, sessions, and capture interface discovery. It converts the router's modified PCAP in memory before passing it to TShark.
- `probe.py` provides diagnostics, coverage, and capture commands. It also contains the packet decoder and capture pipeline shared with the daemon.
- `hosts.py` reads the router's TR-064 device inventory and the IPv6 information available on the local system.
- `fritzmonitor.py` is the daemon entry point. `collector.py` attributes and buffers traffic. `archive.py` handles SQLite storage and queries. `webapp.py` serves the dashboard assets in web/, the API, and CSV on IPv4 loopback.
- `install.sh`, `uninstall.sh`, and `fritzmonitor.service` manage the systemd user service.

Use a single capture interface and pass packets to TShark in memory. SQLite stores aggregates. The dashboard uses parameterized queries and has no external dependencies. Identify endpoints using observed IP and MAC information or the local inventory. Leave unknown fields blank. TShark reads standard input and needs no privileges for capturing on Linux network interfaces.

Before handing off a change, run `python3 -m unittest discover -s tests -v`, `node --check web/app.js`, `bash -n install.sh uninstall.sh`, and `systemd-analyze --user verify fritzmonitor.service`. Follow the authenticated diagnostics and Wi-Fi/Ethernet coverage steps in the README for capture changes. For web changes, check filters, CSV export, and the small-screen layout on loopback. Keep the README aligned with commands, configuration, security, measured results, and user-facing behavior.
