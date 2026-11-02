"""SSH policy, privacy, replay, source loss and UTC rollover regressions."""
import datetime as dt
import json
import unittest

from ops import security_signals as signals
from ops.ssh_access import parse_ssh_event
from ops.tests import test_notification_reports as fixtures
from ops.tests.test_security_signals import ssh_row

NOW = fixtures.NOW


class CountryLookup:
    def __init__(self, code, status="estimated"):
        self.code, self.status = code, status

    def lookup(self, _ip):
        return {"countryCode": self.code, "countryStatus": self.status,
                "databaseDate": "2026-09-01"}


def access(now=NOW, code="US", event="auth_failed", status="estimated"):
    messages = {
        "auth_failed": "Failed password for operator from 8.8.8.8 port 12345 ssh2",
        "accepted": ("Accepted publickey for operator from 8.8.8.8 port 12345 ssh2: "
                     "ED25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "preauth_closed": "Connection closed by 8.8.8.8 port 12345 [preauth]",
    }
    return parse_ssh_event("journal:ssh", "ssh.service", json.dumps({
        "timestamp": now.isoformat(), "severity": "info", "message": messages[event],
    }), lookup=CountryLookup(code, status))


class SshCountryPolicyTests(unittest.TestCase):
    def setUp(self):
        # Reuse the isolated outbox fixture without inheriting its full suite.
        self.fixture = fixtures.NotificationReportsTests(
            "test_ssh_episode_and_source_loss_do_not_false_recover",
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def persist(self, rows, now=NOW, status="fresh"):
        root = self.fixture.root / "ssh-access"
        root.mkdir(exist_ok=True)
        for day in {row["observedAt"][:10] for row in rows}:
            path = root / f"{day}.jsonl"
            path.write_text("\n".join(
                json.dumps(row) for row in rows if row["observedAt"].startswith(day)
            ))
            path.chmod(0o600)
        self.fixture.write("ssh-access-status.json", {
            "status": status, "observedAt": now.isoformat(), "droppedRecords": 0,
        })

    def trust(self, row, label="github-deploy-1"):
        state = self.fixture.root / ".state"
        state.mkdir(mode=0o700, exist_ok=True)
        path = state / "trusted-ssh-identities.json"
        path.write_text(json.dumps({"schemaVersion": 1, "identities": [{
            "targetAccount": row["targetAccount"],
            "publicKeyFingerprint": row["publicKeyFingerprint"],
            "label": label,
        }]}))
        path.chmod(0o600)

    def test_single_foreign_failure_is_detection_only_and_private_fields_do_not_leave_outbox(self):
        row = access()
        self.persist([row, row])
        self.fixture.write(
            "generic-logs.jsonl",
            ssh_row("Failed password for operator from [REDACTED_IP]"),
        )
        result = self.fixture.run_producer()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertEqual(len(result["detections"]), 1)
        evidence = result["detections"][0]["evidence"]
        self.assertIn("SSH 인증 실패·거부", evidence)
        self.assertIn("1개 로그 행", evidence)
        self.assertIn("US", evidence)
        self.assertIn("무단 접근 성공의 증거는 아닙니다", evidence)
        self.assertEqual(self.fixture.run_producer()["immediate"]["enqueued"], 0)
        payload = json.dumps(self.fixture.queued(), ensure_ascii=False)
        for sensitive in ("8.8.8.8", "operator", "12345"):
            self.assertNotIn(sensitive, payload)

    def test_five_foreign_failures_send_once_without_recovery_mail(self):
        rows = [access(now=NOW - dt.timedelta(seconds=index)) for index in range(5)]
        self.persist(rows)
        result = self.fixture.run_producer()
        self.assertEqual(result["immediate"]["enqueued"], 1)
        self.assertEqual(self.fixture.run_producer()["immediate"]["enqueued"], 0)
        for offset in (600, 660):
            later = NOW + dt.timedelta(seconds=offset)
            self.fixture.refresh(later)
            self.persist([], later)
            result = self.fixture.run_producer(later)
        self.assertTrue(any(row["status"] == "resolved" for row in result["detections"]))
        security = [row for row in self.fixture.queued()
                    if row["event"]["ruleId"] == "SecurityPattern"]
        self.assertEqual([row["event"]["transition"] for row in security], ["firing"])

    def test_one_foreign_row_does_not_hide_same_timestamp_generic_burst(self):
        rows = [ssh_row(
            f"Failed password for operator{index} from [REDACTED_IP] port {12000 + index}"
        ) for index in range(5)]
        failures = [row for row in signals.ssh_signals(rows, NOW, [access()])
                    if row["kind"].startswith("ssh-auth-")]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["count"], 5)
        self.assertIn("해외 추정 관측은 1개 로그 행", failures[0]["evidence"])

    def test_accepted_and_closed_are_classified_without_inventing_auth_failure(self):
        for event in ("accepted", "preauth_closed"):
            result = signals.ssh_signals([], NOW, [access(event=event)])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["severity"], "warning")
            self.assertIn(
                "신뢰 목록에 없는 SSH 인증 성공" if event == "accepted" else "인증 전 종료",
                result[0]["evidence"],
            )
        for row in (access(code="KR", event="accepted"),
                    access(code=None, event="accepted", status="unavailable")):
            result = signals.ssh_signals([], NOW, [row])
            self.assertEqual([item["key"] for item in result], ["ssh-untrusted-accepted"])
        self.assertIn("오래된 국가 DB",
                      signals.ssh_signals([], NOW, [access(status="stale")])[0]["evidence"])

    def test_account_and_public_key_fingerprint_never_leave_notification_outbox(self):
        row = access(event="accepted")
        self.persist([row])
        result = self.fixture.run_producer()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertTrue(any(item["kind"] == "ssh-auth-success" for item in result["detections"]))
        payload = json.dumps(self.fixture.queued(), ensure_ascii=False)
        self.assertNotIn("operator", payload)
        self.assertNotIn("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", payload)
        self.assertNotIn("신뢰 목록에 없는 SSH 인증 성공", payload)
        stored = self.fixture.root / "ssh-access" / f"{NOW.date().isoformat()}.jsonl"
        self.assertEqual(json.loads(stored.read_text()), row)

    def test_untrusted_success_remains_recorded_without_firing_or_recovery_mail(self):
        self.persist([access(code="KR", event="accepted")])
        self.assertEqual(self.fixture.run_producer()["immediate"]["enqueued"], 0)
        for offset in (600, 660):
            later = NOW + dt.timedelta(seconds=offset)
            self.fixture.refresh(later)
            self.persist([], later)
            result = self.fixture.run_producer(later)
        self.assertTrue(any(row["status"] == "resolved" for row in result["detections"]))
        security = [row for row in self.fixture.queued()
                    if row["event"]["ruleId"] == "SecurityPattern"]
        self.assertEqual(security, [])

    def test_exact_root_private_identity_suppresses_only_its_accepted_warning(self):
        approved = access(event="accepted")
        self.persist([approved])
        self.trust(approved)
        result = self.fixture.run_producer()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertFalse(any(row["kind"] == "ssh-auth-success" for row in result["detections"]))

    def test_unsafe_identity_config_trusts_nobody(self):
        approved = access(event="accepted")
        self.persist([approved])
        self.trust(approved)
        (self.fixture.root / ".state/trusted-ssh-identities.json").chmod(0o640)
        result = self.fixture.run_producer()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assertTrue(any(row["kind"] == "ssh-auth-success" for row in result["detections"]))

    def test_country_source_loss_does_not_resolve_foreign_episode(self):
        self.persist([access(now=NOW - dt.timedelta(seconds=index)) for index in range(5)])
        self.fixture.run_producer()
        later = NOW + dt.timedelta(minutes=10)
        for offset in (0, 60, 120):
            now = later + dt.timedelta(seconds=offset)
            self.fixture.refresh(now)
            self.persist([], now, status="stale")
            result = self.fixture.run_producer(now)
        self.assertTrue(any(row["status"] == "active" and "SSH 인증 실패" in row["evidence"]
                            for row in result["detections"]))
        self.assertEqual(result["sourceHealth"][2]["status"], "partial")

    def test_reported_ssh_log_drop_is_partial_and_cannot_prove_recovery(self):
        self.persist([access(event="accepted")])
        self.fixture.run_producer()
        later = NOW + dt.timedelta(minutes=10)
        self.fixture.refresh(later)
        self.persist([], later)
        text = fixtures.reports._iso(later)
        self.fixture.write("generic-log-sources.json", {"generatedAt": text, "sources": [{
            "sourceId": "journal:ssh", "status": "no_data", "observedAt": text,
            "droppedLines": 1, "dropped": {"sourceQuota": 1},
        }]})
        partial = self.fixture.run_producer(later)
        self.assertEqual(partial["sourceHealth"][2]["status"], "partial")
        self.assertTrue(any(row["status"] == "active" for row in partial["detections"]))

    def test_missing_access_status_marks_ssh_coverage_partial(self):
        (self.fixture.root / "ssh-access-status.json").unlink()
        result = self.fixture.run_producer()
        self.assertEqual(result["sourceHealth"][2]["status"], "partial")

    def test_malformed_country_record_leaves_generic_detection_available(self):
        row = access()
        row["countryCode"] = "<unsafe>"
        self.persist([row])
        self.fixture.write(
            "generic-logs.jsonl",
            ssh_row("Failed password for operator from [REDACTED_IP]"),
        )
        result = self.fixture.run_producer()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sourceHealth"][2]["status"], "partial")
        self.assertTrue(any("인증 실패" in row["evidence"] for row in result["detections"]))
        self.assertNotIn("<unsafe>", json.dumps(self.fixture.queued()))

    def test_utc_rollover_reads_previous_day_and_healthy_absence_resolves(self):
        now = NOW.replace(hour=0, minute=1)
        rows = [access(now=now - dt.timedelta(minutes=2, seconds=index))
                for index in range(5)]
        self.fixture.refresh(now)
        self.persist(rows, now)
        self.assertEqual(self.fixture.run_producer(now)["immediate"]["enqueued"], 1)
        for offset in (600, 660):
            later = now + dt.timedelta(seconds=offset)
            self.fixture.refresh(later)
            self.persist([], later)
            result = self.fixture.run_producer(later)
        self.assertTrue(any(row["status"] == "resolved" and "SSH 인증 실패" in row["evidence"]
                            for row in result["detections"]))
        security = [row for row in self.fixture.queued()
                    if row["event"]["ruleId"] == "SecurityPattern"]
        self.assertEqual([row["event"]["transition"] for row in security], ["firing"])
