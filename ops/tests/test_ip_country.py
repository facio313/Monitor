import datetime as dt
import gzip
import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.ip_country import CountryLookup, RuntimeCountryLookup, build_database

TODAY = dt.date(2026, 9, 13)
CSV = (b"1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n"
       b"2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n"
       b"2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,CA\n")


class IpCountryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "countries.csv"
        self.output = self.root / "countries.sqlite"
        self.write_source(CSV)

    def write_source(self, value):
        self.source.write_bytes(value)
        self.source.chmod(0o640)

    def build(self, **kwargs):
        return build_database(self.source, self.output, kwargs.pop("database_date", "2026-09-01"), today=TODAY, **kwargs)

    def test_ipv4_ipv6_boundaries_and_mapped_addresses_use_indexed_lookup(self):
        built = self.build()
        self.assertEqual(built["records"], 4)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
        self.assertIs(CountryLookup, RuntimeCountryLookup)
        with CountryLookup(self.output, today=TODAY) as lookup:
            for value in ("8.8.8.0", "8.8.8.255", "::ffff:8.8.8.8", "2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff"):
                self.assertEqual(lookup.lookup(value), {"countryCode": "US", "countryStatus": "estimated", "databaseDate": "2026-09-01"})
            self.assertEqual(lookup.lookup("2606:4700::1111")["countryCode"], "CA")
            for value in ("8.8.7.255", "8.8.9.0", "2001:4861::"):
                self.assertEqual(lookup.lookup(value)["countryStatus"], "not_found")
            self.assertEqual(lookup.connection.execute("PRAGMA cache_size").fetchone()[0], -2048)
            plan = lookup.connection.execute("EXPLAIN QUERY PLAN SELECT end,country FROM ranges WHERE version=? AND start<=? ORDER BY start DESC LIMIT 1", (4, b"\x08\x08\x08\x08")).fetchone()[3]
            self.assertIn("PRIMARY KEY", plan)
            with self.assertRaises(sqlite3.OperationalError):
                lookup.connection.execute("DELETE FROM ranges")
        self.assertIsNone(lookup.connection)
        self.assertIsNone(lookup.descriptor)
        self.assertFalse(list(self.root.glob("*.sqlite-*")))

    def test_special_private_invalid_and_missing_database_are_explicit(self):
        with CountryLookup(self.output, today=TODAY) as lookup:
            for address in ("127.0.0.1", "10.1.2.3", "100.64.0.1", "192.0.2.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:10.0.0.1"):
                self.assertEqual(lookup.lookup(address)["countryStatus"], "private", address)
            for address in ("8.8.8.8", "not-an-ip", "fe80::1%eth0", None):
                self.assertEqual(lookup.lookup(address)["countryStatus"], "unavailable")

    def test_database_date_staleness_and_future_rejection(self):
        self.build(database_date="2026-06-15")
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "estimated")
        with CountryLookup(self.output, today=TODAY + dt.timedelta(days=1)) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8"), {"countryCode": "US", "countryStatus": "stale", "databaseDate": "2026-06-15"})
        with CountryLookup(self.output, today=dt.date(2026, 6, 14)) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
            self.assertIsNone(lookup.database_date)
        with self.assertRaises(ValueError):
            self.build(database_date="2027-01-01")

    def test_gzip_and_checksum_verification(self):
        packed = gzip.compress(CSV)
        self.write_source(packed)
        result = self.build(sha256=hashlib.sha256(packed).hexdigest())
        self.assertEqual(result["records"], 4)
        before = self.output.read_bytes()
        with self.assertRaises(ValueError):
            self.build(sha256="0" * 64)
        self.assertEqual(self.output.read_bytes(), before)

    def test_provider_xk_is_retained_and_unknown_zz_does_not_invent_a_country(self):
        self.write_source(b"8.8.8.0,8.8.8.255,XK\n9.9.9.0,9.9.9.255,ZZ\n")
        self.build()
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8"), {"countryCode": "XK", "countryStatus": "estimated", "databaseDate": "2026-09-01"})
            self.assertEqual(lookup.lookup("9.9.9.9"), {"countryCode": None, "countryStatus": "not_found", "databaseDate": "2026-09-01"})
        with CountryLookup(self.output, today=dt.date(2027, 1, 1)) as lookup:
            self.assertEqual(lookup.lookup("9.9.9.9"), {"countryCode": None, "countryStatus": "stale", "databaseDate": "2026-09-01"})

    def test_invalid_csv_bounds_overlap_and_build_failure_preserve_old_database(self):
        self.build()
        before = self.output.read_bytes()
        invalid = [b"", b"header,start,country\n", b"1.0.0.0,1.0.0.255,us\n", b"1.0.0.255,1.0.0.0,AU\n",
                   b"1.0.0.0,2001:4860::,US\n", b"8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n",
                   b"8.8.8.0,8.8.8.255,US\n8.8.8.255,8.8.9.0,US\n", b"1" * 513 + b"\n", b"\xff\n"]
        for data in invalid:
            self.write_source(data)
            with self.assertRaises(ValueError):
                self.build()
            self.assertEqual(self.output.read_bytes(), before)
            self.assertFalse(list(self.root.glob(".countries.sqlite.*")))
        self.write_source(CSV)
        with patch("ops.ip_country.MAX_RECORDS", 2), self.assertRaises(ValueError):
            self.build()
        with patch("ops.ip_country.MAX_CSV_BYTES", 64), self.assertRaises(ValueError):
            self.build()
        with patch("ops.ip_country.os.replace", side_effect=OSError("replace failed")), self.assertRaises(OSError):
            self.build()
        self.assertEqual(self.output.read_bytes(), before)

    def test_unsafe_files_symlinks_links_and_parent_rejected(self):
        self.build()
        for mode in (0o664, 0o666):
            self.output.chmod(mode)
            with CountryLookup(self.output, today=TODAY) as lookup:
                self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        self.output.chmod(0o644)
        alias = self.root / "alias.sqlite"
        alias.symlink_to(self.output)
        with CountryLookup(alias, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        alias.unlink()
        os.link(self.output, alias)
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        alias.unlink()
        directory_alias = self.root / "alias-dir"
        directory_alias.symlink_to(self.root, target_is_directory=True)
        with CountryLookup(directory_alias / self.output.name, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        self.root.chmod(0o770)
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        self.root.chmod(0o700)

    def test_corrupt_database_unknown_schema_and_size_cap_rejected(self):
        self.output.write_bytes(b"not sqlite")
        self.output.chmod(0o644)
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        self.build()
        with sqlite3.connect(self.output) as connection:
            connection.execute("CREATE TABLE extra (value TEXT)")
        with CountryLookup(self.output, today=TODAY) as lookup:
            self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")
        with patch("ops.ip_country.MAX_DB_BYTES", 1):
            with CountryLookup(self.output, today=TODAY) as lookup:
                self.assertEqual(lookup.lookup("8.8.8.8")["countryStatus"], "unavailable")

    def test_open_database_is_frozen_during_atomic_replacement(self):
        self.build()
        with CountryLookup(self.output, today=TODAY) as old:
            self.write_source(CSV.replace(b",US", b",KR"))
            self.build()
            self.assertEqual(old.lookup("8.8.8.8")["countryCode"], "US")
            with CountryLookup(self.output, today=TODAY) as new:
                self.assertEqual(new.lookup("8.8.8.8")["countryCode"], "KR")


if __name__ == "__main__":
    unittest.main()
