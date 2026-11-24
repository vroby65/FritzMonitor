from contextlib import closing
from io import BytesIO
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from time import time
import unittest

import archivio
from fritzrouter import pcap_chunks
from webapp import csv_row


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "monitor.sqlite3"
        self.db = archivio.writer(self.path)
        self.addCleanup(self.db.close)
        self.now = archivio.bucket_of(time()) + 30
        self.known = "00:01:02:03:04:05"
        self.address = "2001:db8::1"
        self.remote = "2001:db8::2"

    def record(self, bucket, device, domain, size=42, night=0):
        self.db.execute(archivio.UPSERT_FLOW, (
            bucket, device, self.address, self.remote, "TCP", 443, domain, "",
            size, size + 2, 2, bucket + 1, bucket + 10, night,
        ))
        self.db.execute(archivio.UPSERT_DESTINATION, (self.remote, bucket + 1, bucket + 10))

    def communications(self, db, mode="tutte", q=""):
        since = archivio.date_cutoff("giorno", 90, self.now)
        return archivio.communications(db, since, self.known, q, mode, self.now).fetchall()

    def test_aggregates_merge_and_ipv6_alias_preserves_earlier_traffic(self):
        bucket = archivio.bucket_of(self.now)
        with self.db:
            self.db.execute(archivio.UPSERT_DEVICE, (self.known, self.known, "client", self.now))
            self.db.execute(archivio.UPSERT_ALIAS, (self.address, self.known, self.now))
            self.record(bucket, "ip:" + self.address, "example.org")
            self.record(bucket, self.known, "example.org")
            self.record(bucket, self.known, "example.net")
            self.record(bucket, self.known, "example.net")
        with closing(archivio.reader(self.path)) as db:
            rows = self.communications(db, "nuove", "example.org")
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["name"], rows[0]["tx"], rows[0]["rx"]), ("client", 84, 88))
            self.assertEqual(len(self.communications(db)), 2)

    def test_periodic_and_night_queries(self):
        bucket = archivio.bucket_of(self.now)
        with self.db:
            for index in range(4):
                self.record(bucket - index * 600, self.known, "", night=int(index == 1))
        with closing(archivio.reader(self.path)) as db:
            periodic = self.communications(db, "periodiche")
            night = self.communications(db, "notte")
            self.assertEqual(periodic[0]["period_seconds"], 600)
            self.assertEqual(night[0]["tx"], 42)

    def test_retention_and_csv_exposes_utc_offset(self):
        with self.db:
            self.record(archivio.bucket_of(self.now - 91 * archivio.DAY), self.known, "")
            self.record(archivio.bucket_of(self.now), self.known, "")
        archivio.prune(self.db, 90, self.now)
        self.assertEqual(self.db.execute("SELECT count(*) FROM flows").fetchone()[0], 1)
        with closing(archivio.reader(self.path)) as db:
            values = csv_row(self.communications(db)[0])
            self.assertRegex(values[12], r"[+-]\d{2}:\d{2}$")

    def test_large_volume_requires_a_baseline_for_the_same_device(self):
        bucket = archivio.bucket_of(self.now)
        with self.db:
            for index in range(1, 13):
                self.record(bucket - 3600 - index * 300, self.known, "")
            self.record(bucket, self.known, "", size=9 * 1024 * 1024)
            self.record(bucket, "altro", "", size=10 * 1024 * 1024)
        with closing(archivio.reader(self.path)) as db:
            since = archivio.date_cutoff("giorno", 90, self.now)
            matches = archivio.communications(db, since, "", "", "volume", self.now).fetchall()
            self.assertEqual([row["device"] for row in matches], [self.known])


class PcapTests(unittest.TestCase):
    def test_modified_router_header_is_normalized_to_raw_ip_linktype(self):
        header = struct.pack("<IHHIIII", 0xa1b2cd34, 2, 4, 0, 0, 2048, 14)
        record = struct.pack("<IIIIIHBB", 1700000000, 1000, 8, 8, 0, 14, 4, 0)
        packet = bytes(8)
        normalized_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 2048, 101)
        result = b"".join(pcap_chunks(BytesIO(header + record + packet)))
        self.assertEqual(result, normalized_header + record[:16] + packet)

        class SplitReads(BytesIO):
            def read1(self, size):
                return super().read1(min(size, 13))

        fragmented = b"".join(pcap_chunks(SplitReads(header + (record + packet) * 2)))
        self.assertEqual(fragmented, normalized_header + (record[:16] + packet) * 2)
