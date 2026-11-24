"""Accesso HTTPS al FRITZ!Box e flusso PCAP della pagina di supporto."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from hmac import compare_digest
from http.client import HTTPSConnection
import html
from html.parser import HTMLParser
import json
import re
import ssl
import struct
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

LOGIN = "/login_sid.lua?version=2"
CAPTURE = "/cgi-bin/capture_notimeout"
PCAP_MAGIC = {bytes.fromhex(value) for value in (
    "a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a",
    "a1b2cd34", "34cdb2a1",
)}
MODIFIED_PCAP = {b"\x34\xcd\xb2\xa1": "<", b"\xa1\xb2\xcd\x34": ">"}


class RouterError(Exception):
    pass


class AuthenticationError(RouterError):
    pass


class LoginBlocked(RouterError):
    def __init__(self, seconds):
        super().__init__(f"Il router sospende l'accesso per {seconds} secondi")
        self.seconds = seconds


class CertificateError(RouterError):
    pass


def pcap_chunks(response):
    magic = response.read(4)
    if magic not in PCAP_MAGIC:
        raise RouterError("Il router non ha restituito uno stream PCAP")
    if magic not in MODIFIED_PCAP:
        yield magic
        while chunk := response.read1(65536):
            yield chunk
        return

    # Il PCAP modificato del router ha otto byte aggiuntivi per record.
    # TShark 4.2 richiede un formato non ambiguo quando legge da una pipe.
    byte_order = MODIFIED_PCAP[magic]
    header = response.read(20)
    if len(header) != 20:
        raise RouterError("Intestazione PCAP modificata incompleta")
    snaplen, link_type = struct.unpack_from(byte_order + "II", header, 12)
    yield struct.pack(byte_order + "I", 0xA1B2C3D4) + header[:16] + struct.pack(
        byte_order + "I", 101 if link_type == 14 else link_type,
    )
    buffer = b""
    lengths = struct.Struct(byte_order + "II")
    while chunk := response.read1(65536):
        buffer += chunk
        converted = bytearray()
        offset = 0
        while len(buffer) - offset >= 24:
            captured, original = lengths.unpack_from(buffer, offset + 8)
            if captured > min(original, snaplen, 262144):
                raise RouterError("Dimensione del record PCAP non valida")
            end = offset + 24 + captured
            if end > len(buffer):
                break
            converted.extend(buffer[offset:offset + 16])
            converted.extend(buffer[offset + 24:end])
            offset = end
        if offset:
            buffer = buffer[offset:]
            yield converted
    if buffer:
        raise RouterError("Record PCAP incompleto")


def solve_challenge(challenge, password):
    if not re.fullmatch(r"2\$[1-9]\d{0,6}\$[0-9a-fA-F]+\$[1-9]\d{0,6}\$[0-9a-fA-F]+", challenge):
        raise RouterError("Challenge PBKDF2 assente o non valido")
    _, rounds1, salt1, rounds2, salt2 = challenge.split("$")
    first = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt1), int(rounds1))
    second = hashlib.pbkdf2_hmac("sha256", first, bytes.fromhex(salt2), int(rounds2))
    return f"{salt2}${second.hex()}"


@dataclass(frozen=True)
class CaptureInterface:
    label: str
    stop: tuple[str, str, str] | None = None


class CapturePage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.interfaces = {}
        self.in_heading = False
        self.heading = ""
        self.start = ""
        self.stop = ""

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.heading = self.start = self.stop = ""
        elif tag == "th":
            self.in_heading = True
        elif tag == "button":
            fields = dict(attrs)
            if fields.get("name") == "start":
                self.start = fields.get("value") or ""
            elif fields.get("name") == "stop":
                self.stop = fields.get("value") or ""

    def handle_data(self, data):
        if self.in_heading:
            self.heading += data

    def handle_endtag(self, tag):
        if tag == "th":
            self.in_heading = False
        elif tag == "tr" and re.fullmatch(r"[\w.:-]{1,128}", self.start, re.ASCII):
            parts = self.stop.split(";")
            stop = tuple(parts) if len(parts) == 3 else None
            self.interfaces[self.start] = CaptureInterface(clean_label(self.heading), stop)


def clean_label(label):
    return " ".join("".join(c for c in label if c.isprintable() or c.isspace()).split())


def interfaces_from_page(raw):
    try:
        rows = json.loads(raw).get("data", {}).get("snapshot", {}).get("interfaces", [])
    except (ValueError, AttributeError):
        rows = []
    interfaces = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        interface = row.get("name") or row.get("id") or row.get("ifaceorminor")
        if not isinstance(interface, str) or not re.fullmatch(r"[\w.:-]{1,128}", interface, re.ASCII):
            continue
        label = " ".join(str(row.get(key) or "") for key in (
            "kind", "ifacename", "displayname", "description",
        ))
        label = html.unescape(re.sub(r"<[^>]+>", " ", label))
        interfaces[interface] = CaptureInterface(clean_label(label))
    if not interfaces:
        page = CapturePage()
        page.feed(raw.decode("utf-8", errors="replace"))
        interfaces = page.interfaces
    if not interfaces:
        raise RouterError("Elenco assente in data.lua (pagina cap). Verificare i permessi e la pagina di cattura")
    return interfaces


def default_username(state):
    last_user = state.findtext("Users/User[@last='1']", "")
    if last_user:
        return last_user
    users = state.findall("Users/User")
    if len(users) == 1 and users[0].text:
        return users[0].text
    raise AuthenticationError("Impostare esplicitamente il nome utente del FRITZ!Box")


class Router:
    def __init__(self, host, fingerprint="", timeout=12):
        self.host = host
        self.fingerprint = fingerprint
        self.timeout = timeout
        # Il certificato locale può essere autofirmato e senza SAN per l'IPv4.
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE

    @contextmanager
    def connect(self, timeout=None):
        conn = HTTPSConnection(self.host, timeout=timeout or self.timeout, context=self.tls)
        try:
            conn.connect()
            actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if self.fingerprint and not compare_digest(actual, self.fingerprint):
                raise CertificateError("Il certificato HTTPS è cambiato. Verificarlo prima di riconfigurare")
            yield conn, actual
        finally:
            conn.close()

    def certificate(self):
        with self.connect() as (_, fingerprint):
            return fingerprint

    @contextmanager
    def request(self, path, form=None, timeout=None):
        if not self.fingerprint:
            raise CertificateError("Configurare prima l'impronta del certificato HTTPS")
        headers = {"User-Agent": "FritzMonitor/0.1"}
        body = None
        if form is not None:
            body = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        with self.connect(timeout) as (conn, _):
            conn.request("POST" if body is not None else "GET", path, body, headers)
            with conn.getresponse() as response:
                if response.status != 200:
                    raise RouterError(f"Risposta HTTP {response.status} dal router")
                yield response

    def read(self, path, form=None, timeout=None):
        with self.request(path, form, timeout) as response:
            content = response.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            raise RouterError("Risposta di controllo del router troppo grande")
        return content

    def state(self, form=None, timeout=None):
        try:
            return ET.fromstring(self.read(LOGIN, form, timeout))
        except ET.ParseError as error:
            raise RouterError("Risposta XML di accesso non valida") from error

    def info(self):
        try:
            root = ET.fromstring(self.read("/jason_boxinfo.xml"))
        except ET.ParseError as error:
            raise RouterError("Descrizione XML del router non valida") from error
        fields = {node.tag.rsplit("}", 1)[-1]: node.text for node in root.iter()}
        version = fields.get("Version", "")
        if version.count(".") == 2:
            version = version.split(".", 1)[1]
        return fields.get("Name", ""), version

    def login(self, username, password):
        state = self.state()
        blocktime = int(state.findtext("BlockTime", "0"))
        if blocktime:
            raise LoginBlocked(blocktime)
        username = username or default_username(state)
        challenge = solve_challenge(state.findtext("Challenge", ""), password)
        sid = self.state({"username": username, "response": challenge}).findtext("SID", "")
        if not re.fullmatch(r"[0-9a-f]{16}", sid) or sid == "0" * 16:
            raise AuthenticationError("Accesso rifiutato. Verificare utente, password e permessi")
        return sid

    def logout(self, sid):
        self.read(LOGIN, {"sid": sid, "logout": "1"}, timeout=3)

    def interfaces(self, sid):
        return interfaces_from_page(self.read("/data.lua", {"sid": sid, "page": "cap", "lang": "en"}))

    def capture_path(self, sid, interface, action, stop=None):
        options = {"sid": sid, "capture": action, "ifaceorminor": interface}
        if action == "Start":
            options["snaplen"] = 256
            options["filter"] = f"not (host {self.host} and tcp port 443)"
        elif stop is not None:
            del options["ifaceorminor"]
            options.update(zip(("type", "minor", "iface"), stop))
        return f"{CAPTURE}?{urlencode(options)}"
