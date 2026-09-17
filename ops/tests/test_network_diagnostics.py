import datetime as dt
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.network_diagnostics import load_probe_diagnostics, record_network_diagnostics
from ops.synthetic_probe import Probe, probe_once
from ops.tests.test_synthetic_probe import FakeSocket, FakeTlsContext, FailingSocket, answer

NOW = dt.datetime(2026, 9, 13, 12, tzinfo=dt.timezone.utc)


class NetworkPhaseTimingTests(unittest.TestCase):
    def run_probe(self, connection, resolver=None, tls=None):
        diagnostics = []
        tick = iter(range(1000))
        result = probe_once(Probe("public-monitor", "https://example.com/secret?token=private", 200, 5, 2),
                            resolver=resolver or (lambda *_: [answer()]), socket_factory=lambda *_: connection,
                            ssl_context_factory=lambda: tls or FakeTlsContext(), environment={},
                            now=lambda: NOW.timestamp(), monotonic=lambda: 10.0,
                            diagnostics=diagnostics, diagnostic_clock=lambda: next(tick) / 1000)
        return result, diagnostics[0]

    def test_success_measures_first_byte_and_keeps_payload_separate(self):
        legacy, diagnostic = self.run_probe(FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n"))
        self.assertEqual(diagnostic["status"], "ok")
        self.assertIsNone(diagnostic["errorPhase"])
        for phase in ("dnsMs", "tcpMs", "tlsMs", "ttfbMs"):
            self.assertGreater(diagnostic["timings"][phase], 0)
        self.assertNotIn("timings", legacy)
        for secret in ("example.com", "token", "private", "https", "8.8.8.8"):
            self.assertNotIn(secret, json.dumps(diagnostic))

    def test_tcp_timeout_preserves_completed_dns_but_not_unmeasured_phases(self):
        _, diagnostic = self.run_probe(FailingSocket(socket.timeout()))
        self.assertEqual(diagnostic["status"], "timeout")
        self.assertEqual(diagnostic["errorPhase"], "tcp")
        self.assertGreater(diagnostic["timings"]["dnsMs"], 0)
        for phase in ("tcpMs", "tlsMs", "ttfbMs"):
            self.assertIsNone(diagnostic["timings"][phase])

    def test_no_first_byte_and_truncated_headers_have_distinct_failure_phase(self):
        _, missing = self.run_probe(FakeSocket(b""))
        _, truncated = self.run_probe(FakeSocket(b"HTTP/1.1"))
        self.assertEqual(missing["errorPhase"], "ttfb")
        self.assertIsNone(missing["timings"]["ttfbMs"])
        self.assertEqual(truncated["errorPhase"], "headers")
        self.assertGreater(truncated["timings"]["ttfbMs"], 0)

    def test_dns_permission_error_is_classified_without_exception_leak(self):
        def resolver(*_):
            raise PermissionError(13, "sensitive hostname")
        _, diagnostic = self.run_probe(FakeSocket(b""), resolver=resolver)
        self.assertEqual(diagnostic["status"], "permission")
        self.assertEqual(diagnostic["errorPhase"], "dns")
        self.assertIsNone(diagnostic["timings"]["dnsMs"])


class NetworkHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / "proc"
        (self.proc / "net").mkdir(parents=True)
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("boot-one")
        (self.proc / "sys/kernel/random/boot_id").chmod(0o640)
        self.counters(100, 10_000)

    def counters(self, retransmitted, outbound):
        (self.proc / "net/snmp").write_text(f"Tcp: RetransSegs InSegs OutSegs\nTcp: {retransmitted} 999999 {outbound}\n")
        (self.proc / "net/snmp").chmod(0o640)

    def record(self, when=NOW, **kwargs):
        record_network_diagnostics(self.root, metrics={"cpuPercent": 25, "memoryPercent": 35, "networkRxErrorsPerSecond": 0},
                                   pressure={"cpu": {"someAvg10": 1, "fullAvg10": 0}}, proc_root=self.proc,
                                   diagnostic_input=kwargs.get("diagnostic_input"), now=when)
        return json.loads((self.root / "network-diagnostics/latest.json").read_text())

    def test_tcp_outbound_denominator_reset_and_contemporaneous_context(self):
        first = self.record()
        self.assertIsNone(first["tcp"]["retransmitPercent"])
        self.counters(120, 10_100)
        second = self.record(NOW + dt.timedelta(seconds=10))
        self.assertEqual(second["tcp"]["retransmittedSegments"], 20)
        self.assertEqual(second["tcp"]["outboundSegments"], 100)
        self.assertEqual(second["tcp"]["retransmitPercent"], 20)
        self.assertEqual(second["tcp"]["retransmittedPerSecond"], 2)
        self.assertEqual(second["context"]["cpuPercent"], 25)
        self.assertEqual(second["context"]["cpuPressureSomeAvg10"], 1)
        state_root = self.root / ".state/network-diagnostics"
        self.assertEqual(state_root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((state_root / "tcp.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("boot-one", (state_root / "tcp.json").read_text())
        self.assertFalse((self.root / "network-diagnostics/.tcp-state.json").exists())
        for exported in (self.root / "network-diagnostics").iterdir():
            self.assertNotIn("boot-one", exported.read_text())
        (self.proc / "sys/kernel/random/boot_id").write_text("boot-two")
        reset = self.record(NOW + dt.timedelta(seconds=20))
        self.assertIsNone(reset["tcp"]["retransmitPercent"])

    def test_zero_outbound_is_unknown_and_missing_snmp_is_error(self):
        self.record()
        unchanged = self.record(NOW + dt.timedelta(seconds=10))
        self.assertIsNone(unchanged["tcp"]["retransmitPercent"])
        self.assertEqual(unchanged["tcp"]["outboundSegments"], 0)
        (self.proc / "net/snmp").unlink()
        missing = self.record(NOW + dt.timedelta(seconds=20))
        self.assertEqual(missing["tcp"]["status"], "error")

    def test_daily_row_byte_retention_and_unrelated_files_preserved(self):
        self.record(NOW - dt.timedelta(days=30))
        history = self.root / "network-diagnostics"
        (history / "operator-notes.txt").write_text("preserve")
        with patch("ops.network_diagnostics.MAX_DAY_ROWS", 2):
            for offset in range(3):
                self.record(NOW + dt.timedelta(seconds=offset))
        self.assertFalse((history / "2026-08-14.jsonl").exists())
        self.assertTrue((history / "operator-notes.txt").exists())
        self.assertEqual(len((history / "2026-09-13.jsonl").read_text().splitlines()), 2)
        self.assertEqual((history / "latest.json").stat().st_mode & 0o777, 0o640)
        with patch("ops.network_diagnostics.MAX_DAY_BYTES", 1500):
            # Existing day must itself fit the configured bound to be admitted.
            (history / "2026-09-13.jsonl").unlink()
            self.record()
            self.record(NOW + dt.timedelta(seconds=10))
        self.assertLessEqual((history / "2026-09-13.jsonl").stat().st_size, 1500)

    def test_source_freshness_malformed_privacy_and_symlink_rejection(self):
        path = self.root / "diagnostics.json"
        self.assertEqual(load_probe_diagnostics(path, NOW)[0], "no_data")
        probe = {"id": "public-monitor", "checkedAt": "2026-09-13T12:00:00Z", "status": "ok", "httpStatus": 200,
                 "redirectCount": 0, "errorPhase": None, "timings": {"dnsMs": 1, "tcpMs": 2, "tlsMs": 3, "ttfbMs": 4, "totalMs": 10}}
        document = {"schemaVersion": 1, "generatedAt": "2026-09-13T12:00:00Z", "probes": [probe]}
        path.write_text(json.dumps(document))
        path.chmod(0o640)
        self.assertEqual(load_probe_diagnostics(path, NOW)[0], "fresh")
        self.assertEqual(load_probe_diagnostics(path, NOW + dt.timedelta(hours=1))[0], "stale")
        probe["url"] = "https://secret.example/token"
        path.write_text(json.dumps(document))
        self.assertEqual(load_probe_diagnostics(path, NOW), ("error", None, []))
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        self.assertEqual(load_probe_diagnostics(alias, NOW), ("error", None, []))
        row = self.record(diagnostic_input=path)
        self.assertEqual(row["probeStatus"], "error")
        self.assertEqual(row["probes"], [])
        self.assertNotIn("secret", json.dumps(row))


if __name__ == "__main__":
    unittest.main()
