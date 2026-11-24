"""Configurazione locale del prototipo. Le credenziali restano nel file 0600."""

from argparse import ArgumentParser
from contextlib import contextmanager, suppress
from fcntl import LOCK_EX, LOCK_NB, flock
from getpass import getpass
from http.client import HTTPException
from ipaddress import IPv4Address
from pathlib import Path
import json
import os
import re
import stat
import sys
import tempfile
import tomllib

from fritzrouter import Router, RouterError, default_username

DEFAULT = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "fritzmonitor/config.toml"


def local_host(value):
    address = IPv4Address(value)
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError("Usare l'indirizzo IPv4 privato del FRITZ!Box")
    return str(address)


def read_settings(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise ValueError("La configurazione deve appartenere all'utente corrente e avere permessi 600")
        return tomllib.load(stream)


def router_settings(settings):
    host = local_host(settings["host"])
    pin = settings["certificate_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("Impronta SHA-256 non valida")
    if not isinstance(settings["username"], str) or not isinstance(settings["password"], str) or not settings["password"]:
        raise ValueError("Configurare le credenziali del router")
    return Router(host, pin), settings["username"], settings["password"]


def load(path):
    return router_settings(read_settings(path)["router"])


@contextmanager
def exclusive_capture(path):
    lock_path = path.expanduser().with_name("capture.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        try:
            flock(lock, LOCK_EX | LOCK_NB)
        except BlockingIOError:
            raise ValueError("Cattura già avviata con questa configurazione") from None
        yield


def configure(args):
    path = args.config.expanduser()
    if path.exists() and not args.aggiorna:
        raise ValueError("Il file esiste già. Usare --aggiorna per sostituire la configurazione")
    router = Router(local_host(args.host))
    pin = router.certificate()
    print(f"Certificato HTTPS di {router.host}\nSHA-256 {pin}")
    confirmation = input("Confermi il certificato del tuo router? [s/N] ").strip().lower()
    if confirmation not in ("s", "sì", "si"):
        raise ValueError("Certificato non confermato")
    router.fingerprint = pin
    model, version = router.info()
    print(f"{model}, FRITZ!OS {version}")
    username = input("Utente FRITZ!Box (Invio per l'ultimo utente noto al router) ").strip()
    username = username or default_username(router.state())
    password = getpass("Password FRITZ!Box (invisibile) ")
    if not password:
        raise ValueError("Password vuota")
    sid = router.login(username, password)
    with suppress(RouterError, OSError, HTTPException):
        router.logout(sid)
    print("Accesso riuscito.")

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stream = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False)
    temp = Path(stream.name)
    try:
        with stream:
            stream.write("[router]\n")
            for key, value in (
                ("host", router.host), ("certificate_sha256", pin),
                ("username", username), ("password", password),
            ):
                stream.write(f"{key} = {json.dumps(value, ensure_ascii=False)}\n")
        if args.aggiorna:
            temp.replace(path)
        else:
            os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    print(f"Configurazione salvata con permessi 600 in {path}.")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT)
    parser.add_argument("--host", default="192.168.178.1")
    parser.add_argument("--aggiorna", action="store_true")
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise ValueError("Eseguire la configurazione da un terminale interattivo")
        configure(args)
    except (ValueError, RouterError, OSError, HTTPException, KeyboardInterrupt, EOFError) as error:
        print(f"Configurazione interrotta. {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
