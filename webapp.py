"""Serve the read-only dashboard and API on loopback."""

from contextlib import closing
import csv
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
from time import time
from urllib.parse import parse_qs, urlsplit

import archive

ASSETS = Path(__file__).resolve().parent / "web"
FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
PAGE = 40
CSV_FIELDS = (
    ("device", "Device"), ("name", "Name"), ("mac", "MAC"), ("local", "Local IP"),
    ("remote", "Remote IP"), ("domain", "Domain"), ("country", "Country"),
    ("protocol", "Protocol"), ("port", "Remote port"), ("tx", "Bytes sent"),
    ("rx", "Bytes received"), ("packets", "Packets"), ("first", "First seen"),
    ("last", "Last seen"), ("first_destination", "Destination first seen"),
    ("new", "New destination"), ("night", "Night"), ("period_seconds", "Recurring interval (s)"),
)


def rows(items):
    return [dict(item) for item in items]


def date_value(value):
    return datetime.fromtimestamp(value).astimezone().isoformat(timespec="seconds") if value else ""


def csv_row(record):
    result = []
    for key, _ in CSV_FIELDS:
        value = record[key]
        if key in ("first", "last", "first_destination"):
            value = date_value(value)
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            value = "'" + value
        result.append(value)
    return result


class Server(ThreadingHTTPServer):
    request_queue_size = 12

    def __init__(self, port, db, state, settings, hosts):
        self.db = db
        self.state = state
        self.settings = settings
        self.hosts = hosts
        self.assets = {
            path: ((ASSETS / filename).read_bytes(), content_type)
            for path, (filename, content_type) in FILES.items()
        }
        super().__init__(("127.0.0.1", port), Handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(15)
        return sock, address


class Handler(BaseHTTPRequestHandler):
    server_version = "FritzMonitor"
    sys_version = ""

    def log_message(self, *_):
        pass

    def response_headers(self, code, content_type, size=None, attachment=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if size is not None:
            self.send_header("Content-Length", str(size))
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()

    def send_bytes(self, code, content, content_type):
        self.response_headers(code, content_type, len(content))
        self.wfile.write(content)

    def send_json(self, data, code=200):
        content = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_bytes(code, content, "application/json; charset=utf-8")

    def do_GET(self):
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if host not in ("127.0.0.1", "localhost"):
            self.send_json({"error": "HTTP host not allowed"}, 403)
            return
        parsed = urlsplit(self.path)
        if parsed.path in self.server.assets:
            content, content_type = self.server.assets[parsed.path]
            self.send_bytes(200, content, content_type)
            return
        if parsed.path == "/api/status":
            self.send_json(dict(self.server.state))
            return
        if parsed.path not in ("/api/dashboard", "/api/communications.csv"):
            self.send_json({"error": "Resource not found"}, 404)
            return
        try:
            self.dashboard(parsed.path, parse_qs(parsed.query, max_num_fields=20))
        except ValueError as error:
            self.send_json({"error": str(error)}, 400)
        except sqlite3.Error:
            self.send_json({"error": "Database temporarily unavailable"}, 503)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def dashboard(self, path, query):
        value = lambda name, default="": query.get(name, [default])[0][:250]
        now = time()
        retention = self.server.settings["retention_days"]
        cutoff = archive.date_cutoff(value("window", "day"), retention, now)
        device, search, mode = value("device"), value("q"), value("mode", "all")
        unit = value("group", "day")
        page = int(value("page", "0"))
        if not 0 <= page <= 1000000:
            raise ValueError("Invalid page")
        with closing(archive.reader(self.server.db)) as db:
            if path.endswith(".csv"):
                results = archive.communications(db, cutoff, device, search, mode, now)
                self.export(results)
                return
            flows = rows(archive.communications(db, cutoff, device, search, mode, now, PAGE + 1, page * PAGE))
            devices = rows(archive.devices(db, cutoff))
            by_id = {item["id"]: item for item in devices}
            for address, host in self.server.hosts.ipv4.items():
                existing = by_id.get(host.mac)
                if existing is not None:
                    if not existing["name"]:
                        existing["name"] = host.name
                    continue
                item = {"id": host.mac, "name": host.name, "mac": host.mac, "addresses": address,
                        "tx": 0, "rx": 0, "first": None, "last": None}
                devices.append(item)
                by_id[host.mac] = item
            self.send_json({
                "status": dict(self.server.state),
                "devices": devices,
                "servers": rows(archive.servers(db, cutoff, device, search)),
                "live": rows(archive.overview(db, archive.date_cutoff("hour", retention, now), device)),
                "history": rows(archive.timeline(db, cutoff, device, unit)),
                "now": now, "flows": flows[:PAGE], "has_next": len(flows) > PAGE, "page_size": PAGE,
            })

    def export(self, results):
        self.response_headers(200, "text/csv; charset=utf-8", attachment="fritzmonitor.csv")

        class Stream:
            def write(_, value):
                self.wfile.write(value.encode("utf-8"))

        output = csv.writer(Stream())
        output.writerow(label for _, label in CSV_FIELDS)
        for record in results:
            output.writerow(csv_row(record))
