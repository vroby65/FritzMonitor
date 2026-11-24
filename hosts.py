"""Read the device inventory from the local TR-064 interface."""

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from http.client import HTTPSConnection, HTTPException
from ipaddress import ip_address
import json
from queue import Empty, Full, Queue
import re
import subprocess
from threading import Thread
from time import monotonic
from urllib.error import HTTPError
from urllib.request import (
    HTTPSHandler, HTTPDigestAuthHandler, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm,
    HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)
import xml.etree.ElementTree as ET

SERVICE = "urn:dslforum-org:service:Hosts:1"
ERRORS = (OSError, HTTPException, ET.ParseError, ValueError)


@dataclass(frozen=True)
class Host:
    mac: str
    name: str
    medium: str = ""


def host_from(fields, prefix=""):
    mac = (fields.get(prefix + "MACAddress") or "").lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or mac == "00:00:00:00:00:00":
        return None
    label = fields.get(prefix + "X_AVM-DE_FriendlyName") or fields.get(prefix + "HostName") or ""
    name = "".join(char for char in label if char.isprintable())[:200]
    return Host(mac, name, fields.get(prefix + "InterfaceType") or "")


class HostAPI:
    def __init__(self, router, username, password):
        self.address = router.host
        self.base = f"https://{router.host}:49443"

        class PinnedConnection(HTTPSConnection):
            def connect(self):
                super().connect()
                fingerprint = sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
                if not compare_digest(fingerprint, router.fingerprint):
                    self.close()
                    raise OSError("The TR-064 certificate does not match the configured fingerprint")

        class PinnedHTTPS(HTTPSHandler):
            def https_open(self, request):
                return self.do_open(PinnedConnection, request, context=router.tls)

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        passwords = HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, self.base, username, password)
        self.opener = build_opener(ProxyHandler({}), PinnedHTTPS(), NoRedirect(),
                                   HTTPDigestAuthHandler(passwords), HTTPBasicAuthHandler(passwords))

    def fetch(self, request):
        with self.opener.open(request, timeout=5) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("TR-064 response exceeds the size limit")
        return ET.fromstring(raw)

    def soap(self, action, address=None):
        if address is not None:
            payload = f"<NewIPAddress>{ip_address(address)}</NewIPAddress>"
        else:
            payload = ""
        envelope = (
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{SERVICE}">{payload}</u:{action}></s:Body></s:Envelope>'
        )
        request = Request(self.base + "/upnp/control/hosts", envelope.encode(), {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{SERVICE}#{action}"',
        })
        return {element.tag.rsplit("}", 1)[-1]: element.text for element in self.fetch(request).iter()}

    def hosts(self):
        fields = self.soap("X_AVM-DE_GetHostListPath")
        path = fields.get("NewX_AVM-DE_HostListPath", "")
        if not path or not re.match(r"^/[^/]", path):
            raise ValueError("The router returned an invalid TR-064 path")
        result = {}
        for row in self.fetch(self.base + path):
            info = {element.tag: element.text for element in row}
            if info.get("Active") != "1" or not info.get("IPAddress"):
                continue
            try:
                address = str(ip_address(info["IPAddress"]))
            except ValueError:
                continue
            host = host_from(info)
            if host:
                result[address] = host
        return result

    def lookup(self, address):
        try:
            info = self.soap("X_AVM-DE_GetSpecificHostEntryByIP", address)
        except HTTPError as error:
            with error:
                if error.code == 500:
                    root = ET.fromstring(error.read(16384))
                    code = next((el.text for el in root.iter() if el.tag.endswith("errorCode")), "")
                    if code in ("402", "714"):
                        return None
            raise
        return host_from(info, "New")


class HostDirectory:
    def __init__(self, api, stop, logger):
        self.api = api
        self.stop = stop
        self.logger = logger
        self.ipv4 = {}
        self.ipv6 = {}
        self.neighbors = {}
        self.requests = Queue(maxsize=128)
        self.requested = OrderedDict()
        self.worker = Thread(target=self.refresh, daemon=True, name="TR-064")

    def start(self):
        self.worker.start()

    def get(self, address):
        if ":" not in address:
            return self.ipv4.get(address)
        host = self.ipv6.get(address)
        if host is None:
            host = self.neighbors.get(address)
        if host is not None:
            return host
        if monotonic() >= self.requested.get(address, 0):
            try:
                self.requests.put_nowait(address)
            except Full:
                return None
            self.requested[address] = monotonic() + 600
            self.requested.move_to_end(address)
            if len(self.requested) > 4096:
                self.requested.popitem(last=False)
        return None

    def refresh(self):
        next_refresh = 0
        next_neighbors = 0
        adapter = ""
        while not self.stop.is_set():
            if monotonic() >= next_refresh:
                try:
                    self.ipv4 = self.api.hosts()
                    next_refresh = monotonic() + 300
                except ERRORS as error:
                    self.logger.warning("TR-064 inventory: %s", type(error).__name__)
                    next_refresh = monotonic() + 60
            if monotonic() >= next_neighbors:
                try:
                    if not adapter:
                        route = linux_ip("route", "get", self.api.address)[0]
                        if not route.get("gateway"):
                            adapter = route["dev"]
                    if adapter:
                        self.neighbors = ipv6_neighbors(adapter, self.ipv4)
                except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
                    self.logger.debug("Local IPv6 address table unavailable")
                next_neighbors = monotonic() + 30
            try:
                address = self.requests.get(timeout=0.5)
            except Empty:
                continue
            try:
                host = self.api.lookup(address)
                if host is not None:
                    self.ipv6[address] = host
                    if len(self.ipv6) > 4096:
                        self.ipv6.pop(next(iter(self.ipv6)))
            except ERRORS as error:
                self.logger.debug("TR-064 IPv6 lookup: %s", type(error).__name__)
            self.stop.wait(0.2)


def linux_ip(*options):
    return json.loads(subprocess.check_output(["ip", "-j", *options], text=True, timeout=5))


def ipv6_neighbors(adapter, v4_hosts):
    known = {host.mac: host for host in v4_hosts.values()}
    neighbors = {}
    iface = linux_ip("-6", "address", "show", "dev", adapter)[0]
    mac = iface.get("address", "").lower()
    if mac in known:
        for address in iface["addr_info"]:
            if address["scope"] == "global":
                neighbors[str(ip_address(address["local"]))] = known[mac]
    for entry in linux_ip("-6", "neigh", "show", "dev", adapter):
        mac = entry.get("lladdr", "").lower()
        if mac in known and not {"FAILED", "INCOMPLETE"}.intersection(entry.get("state", ())):
            neighbors[str(ip_address(entry["dst"]))] = known[mac]
    return neighbors
