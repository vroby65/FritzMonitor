"""Classify packets in memory and update SQLite aggregates."""

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from ipaddress import ip_address
import re
from time import monotonic, time

from archive import (
    UPSERT_ALIAS, UPSERT_DESTINATION, UPSERT_DEVICE, UPSERT_FLOW, bucket_of, prune,
)
from probe import identify


def hostname(value):
    name = value.strip().rstrip(".").lower()
    if name.count(":") == 1:
        name, _, port = name.rpartition(":")
        if not port.isdecimal():
            return ""
    if len(name) > 253 or "." not in name:
        return ""
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in name.split(".")):
        return ""
    try:
        ip_address(name)
    except ValueError:
        return name
    return ""


class Names:
    def __init__(self):
        self.entries = OrderedDict()

    def set(self, key, name, until):
        self.entries[key] = name, until
        self.entries.move_to_end(key)
        if len(self.entries) > 32768:
            self.entries.popitem(last=False)

    def remember_dns(self, key, name, at, until):
        previous = self.entries.get(key)
        if previous and previous[1] >= at and previous[0] != name:
            name, until = "", max(previous[1], until)
        self.set(key, name, until)

    def get(self, key, at):
        entry = self.entries.get(key)
        if entry and at <= entry[1]:
            return entry[0]
        if entry:
            del self.entries[key]
        return ""


@dataclass
class Counters:
    first: float
    last: float
    country: str
    night: bool
    tx: int = 0
    rx: int = 0
    packets: int = 0

    def add(self, packet, outgoing):
        self.first = min(self.first, packet.timestamp)
        self.last = max(self.last, packet.timestamp)
        if outgoing:
            self.tx += packet.length
        else:
            self.rx += packet.length
        self.packets += 1

    def values(self):
        return (self.country, self.tx, self.rx, self.packets,
                self.first, self.last, int(self.night))


class Collector:
    def __init__(self, db, networks, hosts, settings, geo, status):
        self.db = db
        self.networks = networks
        self.hosts = hosts
        self.status = status
        self.retention = settings["retention_days"]
        self.night_start = settings["night_start"]
        self.night_end = settings["night_end"]
        self.geo = geo
        self.names = Names()
        self.batches = {}
        self.devices = {}
        self.destinations = {}
        self.aliases = {}
        self.last_flush = monotonic()
        self.next_prune = 0
        self.started = monotonic()
        self.elapsed = 0
        self.connection_open = False

    @lru_cache(maxsize=8192)
    def country(self, remote):
        if self.geo is None:
            return ""
        record = self.geo.get(remote) or {}
        return (record.get("country") or record.get("registered_country") or {}).get("iso_code", "")

    @lru_cache(maxsize=288)
    def night(self, bucket):
        hour = datetime.fromtimestamp(bucket).hour
        if self.night_start == self.night_end:
            return False
        if self.night_start < self.night_end:
            return self.night_start <= hour < self.night_end
        return hour >= self.night_start or hour < self.night_end

    def add(self, packet):
        at = packet.timestamp
        now = time()
        if at < now - self.retention * 86400 or at > now + 3600:
            return

        if packet.dns_name and packet.dns_ttl > 0 and any(packet.destination in net for net in self.networks):
            name = hostname(packet.dns_name)
            if name:
                for address in packet.dns_addresses:
                    try:
                        peer = str(ip_address(address))
                    except ValueError:
                        continue
                    self.names.remember_dns((str(packet.destination), peer), name, at,
                                            at + min(packet.dns_ttl, 86400))

        device = identify(packet, self.networks)
        if device is None:
            return
        local, frame_mac, outgoing = device
        host = self.hosts.get(local)
        mac = frame_mac if frame_mac and frame_mac != "00:00:00:00:00:00" else ""
        if host is not None:
            mac = mac or host.mac
        name = host.name if host is not None and host.mac == mac else ""
        device_id = mac or f"ip:{local}"
        remote = str(packet.destination if outgoing else packet.source)
        port = packet.destination_port if outgoing else packet.source_port
        local_port = packet.source_port if outgoing else packet.destination_port

        peer_key = local, remote
        flow_key = local, local_port, remote, port, packet.protocol
        named = hostname(packet.server_name) if outgoing else ""
        if named:
            self.names.set(flow_key, named, at + 1800)
        else:
            named = self.names.get(flow_key, at) or self.names.get(peer_key, at)

        bucket = bucket_of(at)
        key = bucket, device_id, local, remote, packet.protocol, port, named
        counts = self.batches.get(key)
        if counts is None:
            counts = Counters(at, at, self.country(remote), self.night(bucket))
            self.batches[key] = counts
        counts.add(packet, outgoing)

        previous_device = self.devices.get(device_id, ("", "", 0))
        self.devices[device_id] = mac, name or previous_device[1], max(at, previous_device[2])
        first, last = self.destinations.get(remote, (at, at))
        self.destinations[remote] = min(at, first), max(at, last)
        if mac and ":" in local:
            self.aliases[local] = mac, at

        self.status["last_packet"] = max(at, self.status.get("last_packet") or 0)
        if len(self.batches) >= 4000:
            self.flush()

    def flush(self):
        if self.batches:
            with self.db:
                self.db.executemany(UPSERT_DEVICE, ((key, *row) for key, row in self.devices.items()))
                self.db.executemany(UPSERT_DESTINATION, ((key, *row) for key, row in self.destinations.items()))
                self.db.executemany(UPSERT_ALIAS, ((key, *row) for key, row in self.aliases.items()))
                self.db.executemany(UPSERT_FLOW, ((*key, *row.values()) for key, row in self.batches.items()))
            self.batches.clear()
            self.devices.clear()
            self.destinations.clear()
            self.aliases.clear()
        self.last_flush = monotonic()

    def tick(self):
        now = monotonic()
        if self.connection_open and self.status["state"] != "running":
            self.status.update(state="running", message="")
        if now - self.last_flush >= 5:
            self.flush()
        if now >= self.next_prune:
            prune(self.db, self.retention)
            self.next_prune = now + 3600
