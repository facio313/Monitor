"""Success stays observable while only failures remain eligible for SSH mail."""

import datetime as dt
import json
import unittest
from unittest import mock

from ops import notification_reports as reports
from ops import ssh_access
from ops.tests import test_notification_reports as fixtures
from ops.tests.test_security_signals import ssh_row
from ops.tests.test_ssh_access import Countries, acquisition, reduced, source


class LoginMailPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NotificationReportsTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def test_accepted_login_is_persisted_without_security_email(self):
        history = self.fixture.root / "access-history"
        history.mkdir(mode=0o750)
        line = reduced("Accepted password for example from 192.0.2.42 port 42123 ssh2",
                       reports._iso(fixtures.NOW))
        status, retry = ssh_access.collect_ssh_access(
            history, [source()], {"journal:ssh": acquisition([line])}, fixtures.NOW,
            country_lookup=Countries(),
        )
        self.assertFalse(retry)
        self.assertEqual(status["acceptedRecords"], 1)
        rows = [json.loads(row) for row in
                (history / "ssh-access/2026-09-13.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["eventType"], "accepted")
        self.fixture.write("generic-logs.jsonl", ssh_row(
            "Accepted password for [REDACTED_USER] from [REDACTED_IP] port 42123 ssh2"))
        result = self.fixture.run_producer()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertTrue(all(row["event"]["ruleId"] == "HourlyReport"
                            for row in self.fixture.queued()))

    def test_typed_success_remains_in_detections_but_not_mail_or_digest(self):
        signal = {"key": "ssh-login-policy-test", "kind": "ssh-auth-success",
                  "source": "ssh", "severity": "warning", "count": 1,
                  "windowSeconds": 300, "evidence": "successful-login-sentinel"}
        for seconds in (0, 60, 120, 180):
            now = fixtures.NOW + dt.timedelta(seconds=seconds)
            self.fixture.refresh(now)
            with mock.patch.object(reports.signals, "ssh_signals", return_value=[signal]):
                result = self.fixture.run_producer(now)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["immediate"]["enqueued"], 0)
            self.assertTrue(any(row["kind"] == "ssh-auth-success"
                                for row in result["detections"]))
        for row in self.fixture.queued():
            self.assertEqual(row["event"]["ruleId"], "HourlyReport")
            self.assertNotIn(signal["evidence"], row["presentation"]["body"])
        for seconds in (240, 300):
            now = fixtures.NOW + dt.timedelta(seconds=seconds)
            self.fixture.refresh(now)
            result = self.fixture.run_producer(now)
            self.assertEqual(result["immediate"]["enqueued"], 0)

    def test_success_recovery_cannot_enter_mail_queue(self):
        event = reports._event(
            "SecurityPattern", "test-success-recovery", "warning",
            reports._iso(fixtures.NOW), reports._iso(fixtures.NOW),
            "successful-login-sentinel", "resolved", 0, signal_kind="ssh-auth-success",
        )
        outbox = self.fixture.outbox()
        config = reports.delivery.parse_delivery_config(self.fixture.config)
        with outbox._connect() as connection:
            counts = reports._empty_counts()
            self.assertFalse(reports._emit(outbox, connection, config, event,
                                           fixtures.NOW, counts))
        self.assertEqual(counts["enqueued"], 0)

    def test_failed_login_burst_still_enqueues_security_mail(self):
        records = [ssh_row("Failed password for [REDACTED_USER] from [REDACTED_IP] "
                           f"port {42000 + number} ssh2") for number in range(20)]
        (self.fixture.root / "generic-logs.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in records))
        result = self.fixture.run_producer()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["immediate"]["enqueued"], 1)
        self.assertTrue(any(row["event"]["ruleId"] == "SecurityPattern"
                            for row in self.fixture.queued()))


if __name__ == "__main__":
    unittest.main()
