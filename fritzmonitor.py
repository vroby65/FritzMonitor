#!/usr/bin/env python3
"""Demone di acquisizione e dashboard HTTP locale di FritzMonitor."""

from argparse import ArgumentParser
from contextlib import ExitStack, suppress
from fcntl import LOCK_EX, LOCK_NB, flock
from ipaddress import ip_network
import logging
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
from threading import Event, Thread
from time import monotonic

import archivio
from collector import Collector
from configurazione import DEFAULT, exclusive_capture, read_settings, router_settings
from fritzrouter import AuthenticationError, CertificateError, LoginBlocked, RouterError, default_username
from hosts import HostAPI, HostDirectory
from prototipo import NETWORK_ERRORS, capture, detect_networks
from webapp import Server

STATE = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "fritzmonitor"
LOG = logging.getLogger("fritzmonitor")


def settings_from(config, args):
    capture_options = config.get("capture", {})
    data = config.get("storage", {})
    web = config.get("web", {})
    night = config.get("night", {})
    return {
        "interface": capture_options.get("interface", "3-0"),
        "networks": [ip_network(raw) for raw in capture_options.get("local_networks", [])],
        "tshark": args.tshark or capture_options.get("tshark", "tshark"),
        "database": (args.database or Path(data.get("database", STATE / "monitor.sqlite3"))).expanduser(),
        "retention_days": integer(data.get("retention_days", 90), "retention_days", 1),
        "geoip": data.get("geoip", ""),
        "port": integer(web.get("port", 8090), "port", 1024, 65535),
        "night_start": integer(night.get("start_hour", 0), "start_hour", 0, 23),
        "night_end": integer(night.get("end_hour", 6), "end_hour", 0, 23),
    }


def integer(value, name, lower, upper=None):
    if type(value) is not int or value < lower or (upper is not None and value > upper):
        raise ValueError(f"Valore {name} non valido")
    return value


def run_capture(router, username, password, settings, collector, stop):
    interface = settings["interface"]
    pause = 2
    while not stop.is_set():
        sid = None
        delay = pause
        opened_at = monotonic()
        collector.connection_open = False
        collector.status.update(state="connessione", message="")
        try:
            if not settings["networks"]:
                with suppress(OSError, ValueError, RouterError, subprocess.SubprocessError):
                    collector.networks = detect_networks(router.host)
            sid = router.login(username, password)
            details = router.interfaces(sid).get(interface)
            if details is None:
                raise AuthenticationError(f"Interfaccia {interface} assente nella pagina di cattura")
            collector.started = monotonic()
            check_at = monotonic() + 300

            def tick():
                nonlocal check_at
                collector.tick()
                if monotonic() >= check_at:
                    if router.state({"sid": sid}, timeout=3).findtext("SID", "") != sid:
                        raise RouterError("Sessione del router scaduta")
                    if not settings["networks"]:
                        with suppress(OSError, ValueError, RouterError, subprocess.SubprocessError):
                            collector.networks = detect_networks(router.host)
                    check_at = monotonic() + 300

            LOG.info("Apertura interfaccia %s", interface)
            capture(router, sid, interface, details, settings["tshark"], collector, stop,
                    float("inf"), None, tick)
        except (AuthenticationError, CertificateError) as error:
            collector.status.update(state="configurazione", message=str(error))
            LOG.error("%s", error)
            stop.wait()
        except LoginBlocked as error:
            delay = max(delay, error.seconds)
            collector.status.update(state="riconnessione", message=str(error))
            LOG.warning("%s", error)
        except NETWORK_ERRORS as error:
            collector.status.update(state="riconnessione", message=str(error))
            LOG.warning("Cattura interrotta: %s", error)
        finally:
            collector.flush()
            if sid:
                with suppress(*NETWORK_ERRORS):
                    router.logout(sid)
        if monotonic() - opened_at >= 30 and collector.connection_open:
            delay = pause = 2
        else:
            pause = min(pause * 2, 60)
        stop.wait(delay)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--tshark")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    os.umask(0o077)

    stop = Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())

    try:
        config = read_settings(args.config.expanduser())
        router, username, password = router_settings(config["router"])
        settings = settings_from(config, args)
        executable = shutil.which(settings["tshark"])
        if not executable:
            raise ValueError("TShark assente. Installare il pacchetto tshark")
        settings["tshark"] = executable
        networks = settings["networks"] or detect_networks(router.host)
        database = settings["database"]
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        with ExitStack() as resources:
            resources.enter_context(exclusive_capture(args.config))
            lock = resources.enter_context(database.with_suffix(".lock").open("a"))
            try:
                flock(lock, LOCK_EX | LOCK_NB)
            except BlockingIOError:
                raise ValueError("Archivio già in uso da un altro demone") from None
            db = archivio.writer(database)
            resources.callback(db.close)
            geo = None
            if settings["geoip"]:
                try:
                    import maxminddb
                except ImportError:
                    raise ValueError("Per il GeoIP locale installare python3-maxminddb") from None
                geo = maxminddb.open_database(str(Path(settings["geoip"]).expanduser()))
                resources.callback(geo.close)

            username = username or default_username(router.state())
            hosts = HostDirectory(HostAPI(router, username, password), stop, LOG)
            status = {"state": "connessione", "message": "", "interface": settings["interface"],
                      "last_packet": None, "retention_days": settings["retention_days"]}
            http = Server(settings["port"], database, status, settings, hosts)
            resources.callback(http.server_close)
            thread = Thread(target=http.serve_forever, daemon=True, name="dashboard")
            thread.start()
            resources.callback(http.shutdown)
            collector = Collector(db, networks, hosts, settings, geo, status)
            LOG.info("Dashboard su http://127.0.0.1:%s", settings["port"])
            hosts.start()
            try:
                run_capture(router, username, password, settings, collector, stop)
            finally:
                stop.set()
                hosts.worker.join(6)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError,
            *NETWORK_ERRORS) as error:
        LOG.error("%s", error)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
