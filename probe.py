#!/usr/bin/env python3
"""Test FRITZ!Box capture coverage before NAT without saving packets."""

from argparse import ArgumentParser
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPException
import ipaddress
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
from threading import Event, Thread
from time import monotonic

from configure import DEFAULT, exclusive_capture, load, local_host, read_settings, router_settings
from fritzrouter import (
    AuthenticationError, CertificateError, LoginBlocked, Router, RouterError, pcap_chunks,
)
from hosts import ERRORS as HOST_ERRORS, HostAPI, ipv6_neighbors, linux_ip

NETWORK_ERRORS = (OSError, HTTPException, RouterError)
FIELDS = (
    "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "eth.src", "eth.dst", "wlan.sa", "wlan.da", "frame.len",
    "frame.time_epoch", "ip.proto", "ipv6.nxt", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "tls.handshake.extensions_server_name", "http.host",
    "dns.flags.response", "dns.qry.name", "dns.a", "dns.aaaa", "dns.resp.ttl",
)


@dataclass(frozen=True)
class Packet:
    source: ipaddress.IPv4Address | ipaddress.IPv6Address
    destination: ipaddress.IPv4Address | ipaddress.IPv6Address
    source_mac: str
    destination_mac: str
    length: int
    timestamp: float = 0
    protocol: str = ""
    source_port: int = 0
    destination_port: int = 0
    server_name: str = ""
    dns_name: str = ""
    dns_addresses: tuple[str, ...] = ()
    dns_ttl: int = 0


def decode_packet(line):
    values = line.split("\t")
    if len(values) != len(FIELDS):
        return None
    layers, src4, dst4, src6, dst6, eth_src, eth_dst, wlan_src, wlan_dst, length, timestamp, *details = (
        value.partition(",")[0] for value in values
    )
    ip_protocol, ipv6_next, tcp_src, tcp_dst, udp_src, udp_dst, tls, http, dns, query, a, aaaa, ttl = details
    protocols = layers.split(":")
    for layer in protocols:
        if layer in ("ip", "ipv6"):
            src, dst = (src4, dst4) if layer == "ip" else (src6, dst6)
            if "tcp" in protocols:
                transport, sport, dport = "TCP", tcp_src, tcp_dst
            elif "udp" in protocols:
                transport, sport, dport = "UDP", udp_src, udp_dst
            elif "icmp" in protocols or "icmpv6" in protocols:
                transport = "ICMPv6" if "icmpv6" in protocols else "ICMP"
                sport = dport = ""
            else:
                number = ip_protocol if layer == "ip" else ipv6_next
                transport, sport, dport = "IP " + number if number else "IP", "", ""
            answers = values[21:23] if dns == "1" and (a or aaaa) else ()
            try:
                return Packet(ipaddress.ip_address(src), ipaddress.ip_address(dst),
                              eth_src or wlan_src, eth_dst or wlan_dst, int(length), float(timestamp),
                              transport, int(sport or 0), int(dport or 0), tls or http,
                              query if answers else "",
                              tuple(x for group in answers for x in group.split(",") if x),
                              int(ttl or 0))
            except ValueError:
                return None
    return None


def identify(packet, networks):
    source_local = any(packet.source in network for network in networks)
    destination_local = any(packet.destination in network for network in networks)
    if source_local == destination_local:
        return None
    peer = packet.destination if source_local else packet.source
    if peer.is_global and not peer.is_multicast:
        if source_local:
            return str(packet.source), packet.source_mac, True
        return str(packet.destination), packet.destination_mac, False
    return None


def detect_networks(host):
    route = linux_ip("route", "get", host)[0]
    if route.get("gateway"):
        raise RouterError("The router is not on a directly connected network. Specify local prefixes with --network")
    interface = linux_ip("address", "show", "dev", route["dev"])[0]
    networks = set()
    for entry in interface["addr_info"]:
        if entry["scope"] != "global" or "deprecated" in entry.get("flags", ()):
            continue
        address = ipaddress.ip_interface(f"{entry['local']}/{entry['prefixlen']}")
        if address.version == 6 or ipaddress.ip_address(host) in address.network:
            networks.add(address.network)
    if not networks:
        raise RouterError("No local prefixes detected. Specify local prefixes with --network")
    return sorted(networks, key=lambda network: (network.version, network.network_address, network.prefixlen))


class Sample:
    def __init__(self, networks, peer=None, hosts=None):
        self.networks = networks
        self.peer = peer
        self.devices = defaultdict(lambda: [0, 0, 0, 0])
        self.hosts = hosts or {}
        self.link_addresses = set()
        self.ip_frames = 0
        self.connection_open = False
        self.started = monotonic()
        self.elapsed = 0

    def add(self, packet):
        self.ip_frames += 1
        if self.peer and self.peer not in (packet.source, packet.destination):
            return
        device = identify(packet, self.networks)
        if device is None:
            return
        address, mac, outgoing = device
        if mac:
            self.link_addresses.add((address, mac))
        elif address in self.hosts:
            mac = self.hosts[address].mac
        counters = self.devices[(address, mac)]
        index = 0 if outgoing else 1
        counters[index] += 1
        counters[index + 2] += packet.length

    def report(self, interface, expected):
        devices = [
            {"ip": ip, "mac": mac or None, "packets_sent": sent, "packets_received": received,
             "bytes_sent": tx, "bytes_received": rx,
             "name": self.hosts[ip].name if ip in self.hosts and self.hosts[ip].mac == mac else None,
             "mac_source": "frame" if (ip, mac) in self.link_addresses else "inventory" if mac else None}
            for (ip, mac), (sent, received, tx, rx) in sorted(self.devices.items())
        ]
        observations = []
        for address, mac in expected:
            matches = [device for device in devices if device["ip"] == address
                       and (not mac or mac == device["mac"])]
            observations.append({
                "ip": address, "mac": mac or None, "observed": bool(matches),
                "bidirectional": any(item["packets_sent"] and item["packets_received"]
                                     for item in matches),
            })
        return {
            "time": datetime.now().astimezone().isoformat(timespec="seconds"),
            "interface": interface,
            "seconds": round(self.elapsed or monotonic() - self.started, 1),
            "pcap_stream": self.connection_open,
            "ip_frames": self.ip_frames,
            "devices": devices,
            "expected": observations,
        }


def capture(router, sid, interface, details, executable, sample, stop, deadline, report, tick=None):
    command = [executable, "-n", "-l", "-M", "50000", "-r", "-", "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=a"]
    for field in FIELDS:
        command.extend(["-e", field])
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    done = Event()
    accepted = Event()
    cleanup_failed = Event()
    errors = []

    def pump():
        try:
            with process.stdin, router.request(router.capture_path(sid, interface, "Start")) as response:
                chunks = pcap_chunks(response)
                header = next(chunks)
                accepted.set()
                try:
                    chunk = header
                    while not stop.is_set() and not done.is_set() and monotonic() < deadline:
                        pending = memoryview(chunk)
                        while pending:
                            written = process.stdin.write(pending)
                            pending = pending[written:]
                        chunk = next(chunks, None)
                        if chunk is None:
                            raise RouterError("The router closed the PCAP stream")
                finally:
                    try:
                        router.read(router.capture_path(sid, interface, "Stop", details.stop), timeout=3)
                    except NETWORK_ERRORS:
                        cleanup_failed.set()
        except NETWORK_ERRORS as error:
            errors.append(error)

    worker = Thread(target=pump, daemon=True)
    worker.start()
    buffer = b""
    next_report = monotonic() + 10
    stopped_at_deadline = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while not stop.is_set():
                now = monotonic()
                sample.connection_open = accepted.is_set()
                if tick is not None:
                    tick()
                if now >= deadline:
                    stopped_at_deadline = True
                    break
                if now >= next_report and report is not None:
                    report(sample)
                    next_report = now + 10
                if not selector.select(timeout=min(deadline - now, 0.5)):
                    continue
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                *lines, buffer = (buffer + data).split(b"\n")
                for line in lines:
                    packet = decode_packet(line.decode("utf-8", errors="replace"))
                    if packet is not None:
                        sample.add(packet)
    finally:
        sample.connection_open = accepted.is_set()
        sample.elapsed = monotonic() - sample.started
        done.set()
        if process.poll() is None:
            process.terminate()
        process.stdout.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        worker.join(router.timeout + 5)
    if cleanup_failed.is_set():
        print(f"The router did not confirm that it stopped {interface}.", file=sys.stderr)
    if not stop.is_set():
        if not sample.connection_open or not stopped_at_deadline:
            if errors:
                raise errors[0]
            raise RouterError(f"TShark closed the stream (exit code {process.returncode})")


def diagnostic(args):
    if args.authenticated:
        router, username, password = load(args.config.expanduser())
    else:
        router = Router(local_host(args.host))
        router.fingerprint = router.certificate()
    model, version = router.info()
    state = router.state()
    print(f"{model}, FRITZ!OS {version}")
    print(f"PBKDF2: {'yes' if state.findtext('Challenge', '').startswith('2$') else 'no'}")
    print(f"BlockTime: {state.findtext('BlockTime', '?')} seconds")
    with router.request("/html/capture.html"):
        print("Capture page /html/capture.html is reachable")
    if args.authenticated:
        sid = router.login(username, password)
        try:
            for interface, details in router.interfaces(sid).items():
                print(f"{interface}\t{details.label}")
        finally:
            with suppress(*NETWORK_ERRORS):
                router.logout(sid)
    return 0


def observe(args, stop):
    config = read_settings(args.config.expanduser())
    router, username, password = router_settings(config["router"])
    command = shutil.which(args.tshark or config.get("capture", {}).get("tshark", "tshark"))
    if not command:
        raise RouterError("TShark was not found. Install the tshark package or use --tshark")
    networks = args.network or detect_networks(router.host)
    hosts = {}
    try:
        hosts = HostAPI(router, username, password).hosts()
        route = linux_ip("route", "get", router.host)[0]
        if not route.get("gateway"):
            hosts.update(ipv6_neighbors(route["dev"], hosts))
    except (*HOST_ERRORS, KeyError, IndexError, subprocess.SubprocessError):
        print("TR-064 inventory unavailable for this sample.", file=sys.stderr)
    print("Monitored prefixes: " + ", ".join(map(str, networks)), file=sys.stderr)
    if args.action == "coverage" and not args.interface:
        sid = router.login(username, password)
        try:
            interfaces = list(router.interfaces(sid))
        finally:
            with suppress(*NETWORK_ERRORS):
                router.logout(sid)
    else:
        interfaces = args.interface if args.action == "coverage" else [args.interface]

    overall_deadline = monotonic() + args.seconds if args.seconds else float("inf")
    backoff = 2
    useful = False
    while not stop.is_set():
        for interface in interfaces:
            if stop.is_set():
                break
            sid = None
            sample = Sample(networks, args.destination, hosts)
            def report(data):
                print(json.dumps(data.report(interface, args.expected)), flush=True)
            delay = backoff
            try:
                sid = router.login(username, password)
                details = router.interfaces(sid).get(interface)
                if details is None:
                    raise RouterError("Interface ID missing from the router capture page")
                deadline = monotonic() + args.seconds if args.action == "coverage" else overall_deadline
                print(f"Opening stream {interface}.", file=sys.stderr, flush=True)
                capture(router, sid, interface, details, command, sample, stop, deadline,
                        report if args.action == "capture" else None)
            except (AuthenticationError, CertificateError):
                raise
            except LoginBlocked as error:
                if args.action == "coverage":
                    raise
                delay = max(error.seconds, delay)
                print(error, file=sys.stderr)
            except NETWORK_ERRORS as error:
                print(f"{interface}: {error}", file=sys.stderr)
            finally:
                if sid is not None:
                    with suppress(*NETWORK_ERRORS):
                        router.logout(sid)
            result = sample.report(interface, args.expected)
            print(json.dumps(result), flush=True)
            if result["devices"] and all(item["bidirectional"] for item in result["expected"]):
                useful = True
            if args.action == "capture":
                if stop.is_set() or monotonic() >= overall_deadline:
                    break
                if sample.elapsed >= 30 and sample.connection_open:
                    delay = backoff = 2
                else:
                    backoff = min(backoff * 2, 60)
                print(f"Retrying in {delay} seconds.", file=sys.stderr, flush=True)
                stop.wait(min(delay, max(0, overall_deadline - monotonic())))
        if args.action == "coverage" or monotonic() >= overall_deadline:
            break
    return 0 if useful else 1


def positive(value):
    seconds = int(value)
    if seconds <= 0:
        raise ValueError("The duration must be positive")
    return seconds


def expected_device(value):
    address, separator, mac = value.partition("@")
    mac = mac.lower()
    if separator and (len(mac.split(":")) != 6 or any(
        len(part) != 2 or any(char not in "0123456789abcdef" for char in part)
        for part in mac.split(":")
    )):
        raise ValueError("Use IP or IP@MAC")
    return str(ipaddress.ip_address(address)), mac


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT)
    commands = parser.add_subparsers(dest="action", required=True)
    diag = commands.add_parser("diagnostics")
    diag.add_argument("--host", default="192.168.178.1")
    diag.add_argument("--authenticated", action="store_true")
    for action in ("capture", "coverage"):
        command = commands.add_parser(action)
        command.add_argument("--tshark")
        command.add_argument("--network", action="append", type=ipaddress.ip_network)
        command.add_argument("--destination", type=ipaddress.ip_address)
        command.add_argument("--expected", action="append", type=expected_device, default=[])
        command.add_argument("--seconds", type=positive, default=30 if action == "coverage" else None)
        if action == "coverage":
            command.add_argument("--interface", action="append")
        else:
            command.add_argument("--interface", required=True)

    args = parser.parse_args()
    stop = Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    try:
        if args.action == "diagnostics":
            return diagnostic(args)
        with exclusive_capture(args.config):
            return observe(args, stop)
    except (ValueError, KeyError, subprocess.SubprocessError, *NETWORK_ERRORS) as error:
        print(f"FritzMonitor: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
