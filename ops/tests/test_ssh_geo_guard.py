import contextlib
import datetime as dt
import hashlib
import io
import ipaddress
import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.ip_country import build_database
from ops.ssh_geo_guard import main, render_rules

TODAY = dt.date(2026, 9, 13)
CSV = (b"1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.127,KR\n"
       b"8.8.8.128,8.8.8.255,KR\n9.9.9.9,9.9.9.9,KR\n"
       b"11.0.0.0,11.0.0.255,US\n"
       b"2001:4860::1,2001:4860::3,KR\n"
       b"2404:6800::,2404:6800:ffff:ffff:ffff:ffff:ffff:ffff,KR\n"
       b"2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,US\n")


class SshGeoGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source.csv"
        self.database = self.root / "countries.sqlite"
        self.build()

    def build(self, data=CSV, date="2026-09-01"):
        self.source.write_bytes(data)
        self.source.chmod(0o640)
        build_database(self.source, self.database, date, today=TODAY)

    def render(self, **kwargs):
        return render_rules(self.database, today=kwargs.pop("today", TODAY), **kwargs)

    def rendered_ranges(self, output, version):
        elements = re.search(rf"set kr{version} \{{.*?elements = \{{(.*?)\}}", output, re.S)[1]
        values = []
        for element in elements.split(","):
            endpoints = element.strip().split("-")
            values.append(tuple(int(ipaddress.ip_address(value)) for value in (endpoints[0], endpoints[-1])))
        return values

    def test_exact_ipv4_ipv6_coverage_without_cidr_expansion(self):
        output = self.render()
        for version in (4, 6):
            with sqlite3.connect(self.database) as connection:
                expected = [(int.from_bytes(start, "big"), int.from_bytes(end, "big"))
                            for start, end in connection.execute(
                                "SELECT start,end FROM ranges WHERE country='KR' AND version=? ORDER BY start", (version,))]
            self.assertEqual(self.rendered_ranges(output, version), expected)
        self.assertIn("            9.9.9.9\n", output)
        self.assertIn("2001:4860::1-2001:4860::3,", output)
        self.assertIn("type ipv4_addr", output)
        self.assertIn("type ipv6_addr", output)
        self.assertEqual(output.count("flags interval"), 2)
        self.assertEqual(output.count("auto-merge"), 2)
        self.assertEqual(self.render(), output)

    def test_fixed_ssh_rules_drop_foreign_sources_but_leave_other_ports_and_hooks_alone(self):
        output = self.render()
        rules = [line.strip() for line in output.splitlines() if "tcp dport" in line]
        self.assertEqual(rules, [
            'iifname "lo" tcp dport { 22, 22022 } counter name ssh_geo_loopback return',
            'iifname "eth0" ip saddr 192.168.75.190 tcp dport { 22, 22022 } counter name ssh_geo_lan return',
            'ip saddr @kr4 tcp dport { 22, 22022 } counter name ssh_geo_kr4 return',
            'ip6 saddr @kr6 tcp dport { 22, 22022 } counter name ssh_geo_kr6 return',
            'tcp dport { 22, 22022 } limit rate 3/minute burst 5 packets log prefix "SSH_GEO_DROP " level info',
            'tcp dport { 22, 22022 } counter name ssh_geo_denied drop',
        ])
        self.assertEqual(output.count("table inet monitor_ssh_geo {"), 1)
        self.assertEqual(output.count("hook "), 1)
        self.assertIn("type filter hook input priority -10; policy accept;", output)
        self.assertIn("counter ssh_geo_denied { }", output)
        self.assertNotRegex(output, r"\b(flush|delete|include|forward|output|prerouting|postrouting|udp|established)\b")
        self.assertNotIn("ip daddr", output)
        self.assertNotIn("192.168.75.0/24", output)
        # Foreign IPv4, foreign IPv6, and unknown public addresses cannot match
        # either KR set, so the final SSH-only drop handles both families.
        for address in ("1.0.0.1", "11.0.0.1", "8.8.9.0", "2606:4700::1"):
            ip = ipaddress.ip_address(address)
            self.assertFalse(any(low <= int(ip) <= high for low, high in self.rendered_ranges(output, ip.version)))

    def test_limited_info_logging_cannot_limit_or_bypass_final_drop(self):
        rules = [line.strip() for line in self.render().splitlines() if "tcp dport" in line]
        self.assertEqual(rules[-2], 'tcp dport { 22, 22022 } limit rate 3/minute burst 5 packets log prefix "SSH_GEO_DROP " level info')
        self.assertEqual(rules[-1], 'tcp dport { 22, 22022 } counter name ssh_geo_denied drop')
        self.assertNotIn("limit", rules[-1])
        self.assertNotIn("drop", rules[-2])
        self.assertTrue(all(" return" in rule for rule in rules[:-2]))

    def test_metadata_checksums_and_management_exception_documented(self):
        output = self.render()
        self.assertIn("database_date: 2026-09-01", output)
        self.assertIn("source: DB-IP IP to Country Lite; license: CC BY 4.0", output)
        self.assertIn(f"source_sha256: {hashlib.sha256(CSV).hexdigest()}", output)
        self.assertIn(f"database_sha256: {hashlib.sha256(self.database.read_bytes()).hexdigest()}", output)
        self.assertIn("KR source ranges: IPv4=3; IPv6=2", output)
        self.assertIn("DHCP address changes", output)

    def test_stale_future_missing_and_empty_family_fail_closed(self):
        self.build(date="2026-06-15")
        self.assertIn("table inet", self.render())  # Exactly 90 days remains valid.
        for today in (TODAY + dt.timedelta(days=1), dt.date(2026, 6, 14)):
            with self.assertRaises(ValueError):
                self.render(today=today)
        with self.assertRaises(ValueError):
            render_rules(self.root / "missing.sqlite", today=TODAY)
        for data in (b"8.8.8.0,8.8.8.255,KR\n", b"2001:4860::,2001:4860::ff,KR\n", CSV.replace(b",KR", b",US")):
            self.build(data)
            with self.assertRaises(ValueError):
                self.render()

    def test_nonpublic_ranges_and_hidden_nonpublic_holes_fail_closed(self):
        cases = [
            ("10.0.0.0", "10.0.0.255"), ("127.0.0.1", "127.0.0.1"),
            ("100.64.0.0", "100.127.255.255"), ("224.0.0.0", "224.0.0.255"),
            ("8.0.0.0", "11.255.255.255"),  # Both endpoints global, private hole.
            ("192.0.1.0", "192.0.3.0"), ("fc00::", "fc00::ff"),
            ("::ffff:8.8.8.8", "::ffff:8.8.8.8"), ("2001:db8::", "2001:db8::ff"),
            ("2001:db7::", "2001:db9::"), ("3ffe::", "4000::"),
        ]
        for first, last in cases:
            version = ipaddress.ip_address(first).version
            data = f"{first},{last},KR\n".encode()
            data += b"2001:4860::,2001:4860::ff,KR\n" if version == 4 else b"8.8.8.0,8.8.8.255,KR\n"
            self.build(data)
            with self.assertRaises(ValueError, msg=first):
                self.render()

    def test_unknown_metadata_corrupt_schema_and_overlap_are_rejected(self):
        for sql in ("UPDATE metadata SET value='Unknown' WHERE key='source'",
                    "UPDATE metadata SET value='1' WHERE key='recordCount'",
                    "CREATE TABLE extra (value TEXT)",
                    "UPDATE ranges SET end=X'0B000001' WHERE start=X'09090909'",
                    "UPDATE ranges SET country='kr' WHERE country='KR'"):
            self.build()
            with sqlite3.connect(self.database) as connection:
                connection.execute(sql)
            with self.assertRaises(ValueError):
                self.render()
        self.database.write_bytes(b"invalid sqlite")
        with self.assertRaises(ValueError):
            self.render()

    def test_unsafe_files_links_parents_and_explicit_bounds_are_rejected(self):
        self.database.chmod(0o664)
        with self.assertRaises(ValueError):
            self.render()
        self.database.chmod(0o644)
        link = self.root / "link.sqlite"
        link.symlink_to(self.database)
        with self.assertRaises(ValueError):
            render_rules(link, today=TODAY)
        link.unlink()
        os.link(self.database, link)
        with self.assertRaises(ValueError):
            self.render()
        link.unlink()
        self.root.chmod(0o770)
        with self.assertRaises(ValueError):
            self.render()
        self.root.chmod(0o700)
        for constant in ("MAX_KR_RANGES", "MAX_OUTPUT_BYTES", "MAX_RECORDS", "MAX_DB_BYTES"):
            with patch(f"ops.ssh_geo_guard.{constant}", 1), self.assertRaises(ValueError):
                self.render()
        with patch("ops.ip_country.MAX_DB_BYTES", 1), self.assertRaises(ValueError):
            self.render()

    def test_cli_stdout_only_no_side_effects_and_no_partial_output_on_failure(self):
        before = {file.name: file.read_bytes() for file in self.root.iterdir()}
        expected = self.render()
        with patch("ops.ssh_geo_guard.render_rules", return_value=expected) as renderer:
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(main(["--database", str(self.database)]), 0)
            renderer.assert_called_once_with(self.database)
            self.assertEqual(output.getvalue(), expected)
            self.assertEqual(errors.getvalue(), "")
        with patch("ops.ssh_geo_guard.render_rules", side_effect=ValueError("sensitive internal detail")):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(main([]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("generation failed", errors.getvalue())
            self.assertNotIn("sensitive", errors.getvalue())
        self.assertEqual({file.name: file.read_bytes() for file in self.root.iterdir()}, before)


if __name__ == "__main__":
    unittest.main()
