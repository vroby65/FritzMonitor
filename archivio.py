"""Persistenza e interrogazione degli aggregati di cinque minuti."""

import sqlite3
from time import time

BUCKET = 300
DAY = 86400
WINDOWS = {"ora": 3600, "giorno": DAY, "settimana": 7 * DAY, "mese": 30 * DAY, "storico": None}
HISTORY = {
    "giorno": "date(bucket,'unixepoch','localtime')",
    "settimana": "date(bucket,'unixepoch','localtime','-6 days','weekday 1')",
    "mese": "strftime('%Y-%m-01',bucket,'unixepoch','localtime')",
}
COMMON_PORTS = "20,21,22,25,53,80,110,123,143,443,465,587,853,993,995,3478,5228,5349"
SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    id TEXT PRIMARY KEY, mac TEXT NOT NULL, name TEXT NOT NULL, last REAL NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ipv6_aliases(
    ip TEXT PRIMARY KEY, device TEXT NOT NULL, last REAL NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destinations(
    ip TEXT PRIMARY KEY, first REAL NOT NULL, last REAL NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS flows(
    bucket INTEGER NOT NULL, device TEXT NOT NULL, local TEXT NOT NULL, remote TEXT NOT NULL,
    protocol TEXT NOT NULL, port INTEGER NOT NULL, domain TEXT NOT NULL, country TEXT NOT NULL,
    tx INTEGER NOT NULL, rx INTEGER NOT NULL, packets INTEGER NOT NULL, first REAL NOT NULL,
    last REAL NOT NULL, night INTEGER NOT NULL,
    PRIMARY KEY(bucket, device, local, remote, protocol, port, domain)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS flows_device_bucket ON flows(device, bucket);
"""
UPSERT_FLOW = """
INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(bucket,device,local,remote,protocol,port,domain) DO UPDATE SET
    country = coalesce(nullif(excluded.country,''),flows.country),
    tx = flows.tx + excluded.tx, rx = flows.rx + excluded.rx,
    packets = flows.packets + excluded.packets,
    first = min(flows.first,excluded.first), last = max(flows.last,excluded.last)
"""
UPSERT_DEVICE = """
INSERT INTO devices VALUES (?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
    mac = coalesce(nullif(excluded.mac,''),devices.mac),
    name = coalesce(nullif(excluded.name,''),devices.name),
    last = max(devices.last,excluded.last)
"""
UPSERT_DESTINATION = """
INSERT INTO destinations VALUES (?,?,?)
ON CONFLICT(ip) DO UPDATE SET first = min(destinations.first,excluded.first),
                               last = max(destinations.last,excluded.last)
"""
UPSERT_ALIAS = """
INSERT INTO ipv6_aliases VALUES (?,?,?)
ON CONFLICT(ip) DO UPDATE SET device = excluded.device, last = excluded.last
WHERE excluded.last >= ipv6_aliases.last
"""
RESOLVE_DEVICE = """
CASE WHEN f.device = 'ip:' || f.local THEN coalesce(a.device, f.device) ELSE f.device END
"""


def bucket_of(timestamp):
    return int(timestamp) // BUCKET * BUCKET


def writer(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA auto_vacuum=INCREMENTAL")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA journal_size_limit=4194304")
    db.executescript(SCHEMA)
    return db


def reader(path):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    return db


def prune(db, retention_days, now=None):
    cutoff = bucket_of((time() if now is None else now) - retention_days * DAY)
    with db:
        db.execute("DELETE FROM flows WHERE bucket < ?", (cutoff,))
        for table in ("destinations", "devices", "ipv6_aliases"):
            db.execute(f"DELETE FROM {table} WHERE last < ?", (cutoff,))
    db.execute("PRAGMA incremental_vacuum(512)")


def date_cutoff(window, retention, now):
    if window not in WINDOWS:
        raise ValueError("Intervallo non valido")
    days = retention * DAY
    limit = WINDOWS[window]
    return bucket_of(now - min(days, limit or days))


def filtered(cutoff, device, query):
    params = {"since": cutoff}
    clauses = ["f.bucket >= :since"]
    if device:
        clauses.append(f"({RESOLVE_DEVICE}) = :device")
        params["device"] = device
    if query:
        clauses.append(
            "(instr(lower(f.remote), :q) > 0 OR instr(lower(f.domain), :q) > 0 "
            "OR instr(lower(f.local), :q) > 0 OR instr(lower(d.name), :q) > 0 "
            "OR instr(lower(d.mac), :q) > 0 OR instr(lower(f.protocol), :q) > 0 "
            "OR instr(lower(f.country), :q) > 0 OR CAST(f.port AS TEXT) = :q)"
        )
        params["q"] = query.lower()
    sql = f"""
        SELECT f.*, ({RESOLVE_DEVICE}) AS device_id, coalesce(d.name,'') AS name,
               coalesce(d.mac,'') AS mac, coalesce(g.first,f.first) AS first_destination
        FROM flows AS f
        LEFT JOIN ipv6_aliases AS a ON a.ip = f.local AND f.device = 'ip:' || f.local
        LEFT JOIN devices AS d ON d.id = ({RESOLVE_DEVICE})
        LEFT JOIN destinations AS g ON g.ip = f.remote
        WHERE {" AND ".join(clauses)}
    """
    return sql, params


def devices(db, cutoff):
    return db.execute(f"""
        SELECT ({RESOLVE_DEVICE}) AS id, coalesce(d.name,'') AS name, coalesce(d.mac,'') AS mac,
               group_concat(DISTINCT f.local) AS addresses, sum(f.tx) AS tx, sum(f.rx) AS rx,
               min(f.first) AS first, max(f.last) AS last
        FROM flows AS f
        LEFT JOIN ipv6_aliases AS a ON a.ip = f.local AND f.device = 'ip:' || f.local
        LEFT JOIN devices AS d ON d.id = ({RESOLVE_DEVICE})
        WHERE f.bucket >= ?
        GROUP BY id ORDER BY tx+rx DESC, id
    """, (cutoff,)).fetchall()


def timeline(db, cutoff, device, unit):
    if unit not in HISTORY:
        raise ValueError("Raggruppamento non valido")
    base, params = filtered(cutoff, device, "")
    return db.execute(f"""
        SELECT {HISTORY[unit]} AS period, sum(tx) AS tx, sum(rx) AS rx
        FROM ({base}) GROUP BY period ORDER BY period
    """, params).fetchall()


def overview(db, cutoff, device):
    base, params = filtered(cutoff, device, "")
    return db.execute(f"""
        SELECT bucket, sum(tx) AS tx, sum(rx) AS rx, sum(packets) AS packets
        FROM ({base}) GROUP BY bucket ORDER BY bucket
    """, params).fetchall()


def servers(db, cutoff, device, query):
    base, params = filtered(cutoff, device, query)
    return db.execute(f"""
        SELECT remote, domain, max(country) AS country, sum(tx) AS tx, sum(rx) AS rx,
               min(first_destination) AS first, max(last) AS last
        FROM ({base}) GROUP BY remote,domain ORDER BY tx+rx DESC,remote,domain LIMIT 20
    """, params).fetchall()


def communications(db, cutoff, device, query, mode, now, limit=None, offset=0):
    base, params = filtered(cutoff, device, query)
    ctes = [f"base AS ({base})"]
    where = ""
    interval = "NULL"
    if mode == "nuove":
        where = "WHERE first_destination >= :since"
    elif mode == "notte":
        where = "WHERE night = 1"
    elif mode == "sconosciuti":
        where = "WHERE name = ''"
    elif mode == "porte":
        where = f"WHERE port > 0 AND port NOT IN ({COMMON_PORTS})"
    elif mode == "periodiche":
        ctes.append("""
            moments AS (
                SELECT DISTINCT device_id, remote, protocol, port, bucket FROM base
            ), gaps AS (
                SELECT device_id, remote, protocol, port,
                       bucket - lag(bucket) OVER (
                           PARTITION BY device_id, remote, protocol, port ORDER BY bucket
                       ) AS gap
                FROM moments
            ), repeated AS (
                SELECT device_id, remote, protocol, port, round(avg(gap)) AS seconds
                FROM gaps WHERE gap IS NOT NULL
                GROUP BY device_id, remote, protocol, port
                HAVING count(*) >= 3 AND max(gap) <= min(gap) * 1.2
            )
        """)
        where = "WHERE seconds IS NOT NULL"
        interval = "seconds"
    elif mode == "volume":
        params["baseline_since"] = bucket_of(now - 7 * DAY)
        params["baseline_until"] = bucket_of(now - 900)
        ctes.append("""
            volumes AS (
                SELECT device, bucket, sum(tx+rx) AS amount
                FROM flows WHERE bucket >= :baseline_since
                GROUP BY device,bucket
            ), baseline AS (
                SELECT device, avg(amount) AS usual FROM volumes
                WHERE bucket < :baseline_until
                GROUP BY device HAVING count(*) >= 12
            ), large AS (
                SELECT v.device, v.bucket
                FROM volumes v JOIN baseline b USING(device)
                WHERE v.amount >= 16777216 AND v.amount > 4 * b.usual
            )
        """)
        where = "WHERE EXISTS (SELECT 1 FROM large l WHERE l.device=base.device AND l.bucket=base.bucket)"
    elif mode != "tutte":
        raise ValueError("Filtro non valido")

    source = "base"
    if mode == "periodiche":
        source += " JOIN repeated USING(device_id,remote,protocol,port)"
    sql = f"""
        WITH {", ".join(ctes)}
        SELECT device_id AS device, name, mac, local, remote, protocol, port,
               domain, max(country) AS country, sum(tx) AS tx, sum(rx) AS rx,
               sum(packets) AS packets, min(first) AS first, max(last) AS last,
               min(first_destination) AS first_destination,
               min(first_destination) >= :since AS new, max(night) AS night,
               max({interval}) AS period_seconds
        FROM {source} {where}
        GROUP BY device_id,name,mac,local,remote,protocol,port,domain
        ORDER BY last DESC,device_id,local,remote,protocol,port,domain
    """
    if limit is not None:
        sql += " LIMIT :limit OFFSET :offset"
        params.update(limit=limit, offset=offset)
    return db.execute(sql, params)
