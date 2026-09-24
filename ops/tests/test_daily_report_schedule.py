import contextlib
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from ops import alert_delivery as delivery
from ops import notification_reports as reports


def smtp_config():
    channel = {
        "id": "smtp-mail",
        "kind": "smtp",
        "enabled": True,
        "timeoutSeconds": 2,
        "maxAttempts": 3,
        "baseBackoffSeconds": 10,
        "maxBackoffSeconds": 25,
        "secretRef": {"provider": "env", "key": "SMTP_SECRET"},
        "settings": {
            "host": "smtp.example.test",
            "port": 465,
            "from": "monitor@example.test",
            "to": ["ops@example.test"],
            "username": "monitor@example.test",
            "tlsMode": "implicit",
        },
    }
    return {
        "schemaVersion": 1,
        "queue": {
            "maxPending": 10,
            "maxHistory": 20,
            "maxDeliveryLog": 40,
            "leaseSeconds": 90,
            "batchSize": 10,
            "replayWindowSeconds": 900,
        },
        "channels": [channel],
        "routes": [{
            "id": "all-operational",
            "priority": 100,
            "enabled": True,
            "severities": ["info", "warning", "critical"],
            "transitions": ["firing", "resolved"],
            "labels": {},
            "channels": ["smtp-mail"],
            "continue": False,
        }],
    }


class DailyReportScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "delivery.json"
        self.config = smtp_config()
        self._write("delivery.json", self.config)

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def _inputs(self, now):
        observed_at = reports._iso(now)
        current = {
            "generatedAt": observed_at,
            "latest": {
                "cpuPercent": 20,
                "memoryPercent": 25,
                "temperatureC": 65,
                "memoryPressureSomeAvg10": 0,
                "ioPressureSomeAvg10": 0,
            },
            "currentTraffic": [{
                "app": "monitor", "requestCount": 2, "status4xx": 0, "status5xx": 0,
            }],
            "disks": [],
        }
        evaluation = {"evaluatedAt": observed_at, "status": "ok", "states": {}}
        self._write("generic-log-sources.json", {
            "generatedAt": observed_at,
            "sources": [{"sourceId": "journal:ssh", "status": "no_data", "observedAt": observed_at}],
        })
        self._write("ssh-access-status.json", {
            "status": "fresh", "observedAt": observed_at, "droppedRecords": 0,
        })
        return current, evaluation

    def _produce(self, now):
        current, evaluation = self._inputs(now)
        return reports.produce_notifications(
            self.root,
            now,
            current=current,
            evaluation=evaluation,
            delivery_config_path=self.config_path,
        )

    def _outbox(self):
        parsed = delivery.parse_delivery_config(self.config)
        return delivery.DeliveryOutbox(
            self.root / ".state/alert-delivery/alert-delivery.sqlite", parsed.queue,
        )

    def _queued(self):
        with contextlib.closing(self._outbox()._connect()) as connection:
            return [json.loads(row[0]) for row in connection.execute(
                "SELECT payload_json FROM outbox ORDER BY created_at"
            )]

    def _replace_state(self, **updates):
        with contextlib.closing(self._outbox()._connect()) as connection:
            raw = connection.execute(
                "SELECT value FROM notification_producer_state WHERE id=1"
            ).fetchone()[0]
            state = {**json.loads(raw), **updates}
            connection.execute(
                "UPDATE notification_producer_state SET value=? WHERE id=1",
                (json.dumps(state),),
            )

    def test_before_nine_kst_has_no_slot_or_catch_up_report(self):
        before_nine = dt.datetime(2026, 9, 23, 23, 30, tzinfo=dt.timezone.utc)

        status = self._produce(before_nine)

        self.assertEqual(status["status"], "ok")
        self.assertIsNone(status["hourly"]["slot"])
        self.assertEqual(status["hourly"]["enqueued"], 0)
        self.assertIsNone(status["hourly"]["lastQueuedAt"])
        self.assertEqual(self._queued(), [])

    def test_legacy_hourly_checkpoint_does_not_block_daily_report_after_nine(self):
        before_nine = dt.datetime(2026, 9, 23, 23, 30, tzinfo=dt.timezone.utc)
        first_after_nine = dt.datetime(2026, 9, 24, 0, 5, tzinfo=dt.timezone.utc)
        expected_slot = "2026-09-24T00:00:00Z"
        legacy_hour = "2026-09-24T13:00:00Z"
        legacy_queued_at = "2026-09-24T13:01:00Z"
        self._produce(before_nine)
        self._replace_state(lastHour=legacy_hour, lastQueuedAt=legacy_queued_at)

        queued = self._produce(first_after_nine)

        self.assertEqual(queued["hourly"]["slot"], expected_slot)
        self.assertEqual(queued["hourly"]["enqueued"], 1)
        self.assertEqual(queued["hourly"]["lastQueuedAt"], reports._iso(first_after_nine))
        payloads = self._queued()
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["event"]["openedAt"], expected_slot)
        self.assertIn("09/24", payloads[0]["presentation"]["subject"])

        state = reports._readonly_producer_state(self.root)
        self.assertEqual(state["lastDailySlot"], expected_slot)
        self.assertEqual(state["lastDailyQueuedAt"], reports._iso(first_after_nine))
        self.assertEqual(state["lastHour"], legacy_hour)
        self.assertEqual(state["lastQueuedAt"], legacy_queued_at)

        second = self._produce(first_after_nine + dt.timedelta(minutes=1))
        self.assertEqual(second["hourly"]["enqueued"], 0)
        self.assertEqual(len(self._queued()), 1)

    def test_digest_subject_uses_explicit_daily_slot(self):
        now = dt.datetime(2026, 9, 25, 1, 0, tzinfo=dt.timezone.utc)
        current, evaluation = self._inputs(now)

        presentation = reports._digest(
            current,
            evaluation,
            [],
            {},
            [],
            now,
            report_slot="2026-09-24T00:00:00Z",
        )

        self.assertIn("09/24", presentation["subject"])
        self.assertNotIn("09/25", presentation["subject"])
        self.assertIn("GitHub Actions가 공개 readiness·TLS·SSO", presentation["body"])
        self.assertIn("예약 실행 간격은 SLA가 아닙니다", presentation["body"])
        self.assertIn("장애당 GitHub Issue 하나", presentation["body"])
        self.assertIn("전체 호스트 중단도 감지", presentation["body"])
        self.assertIn("SMTP는 보내지 않으며", presentation["body"])

    def test_same_slot_legacy_checkpoint_keeps_the_original_queue_time(self):
        first_after_nine = dt.datetime(2026, 9, 24, 0, 5, tzinfo=dt.timezone.utc)
        expected_slot = "2026-09-24T00:00:00Z"
        first = self._produce(first_after_nine)
        self.assertEqual(first["hourly"]["enqueued"], 1)
        original_queued_at = reports._iso(first_after_nine)
        self._replace_state(
            lastDailySlot=None,
            lastDailyQueuedAt=None,
            lastHour=expected_slot,
            lastQueuedAt=original_queued_at,
        )

        migrated = self._produce(first_after_nine + dt.timedelta(minutes=1))

        self.assertEqual(migrated["hourly"]["enqueued"], 0)
        self.assertEqual(migrated["hourly"]["lastQueuedAt"], original_queued_at)
        state = reports._readonly_producer_state(self.root)
        self.assertEqual(state["lastDailySlot"], expected_slot)
        self.assertEqual(state["lastDailyQueuedAt"], original_queued_at)
        self.assertEqual(len(self._queued()), 1)


if __name__ == "__main__":
    unittest.main()
