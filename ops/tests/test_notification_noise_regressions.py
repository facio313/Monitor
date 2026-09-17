import contextlib
import datetime as dt
import json
import unittest
from unittest import mock

from ops import alert_delivery as delivery
from ops import notification_reports as reports
from ops.tests import test_notification_reports as fixtures
from ops.tests.test_alert_delivery import event


class NotificationNoiseRegressions(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NotificationReportsTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def run_at(self, minute, rate=0, **extra_latest):
        now = fixtures.NOW + dt.timedelta(minutes=minute)
        self.fixture.refresh_network(now, rate=rate)
        self.fixture.current["latest"].update(extra_latest)
        result = self.fixture.run_producer(now)
        self.assertEqual(result["status"], "ok")
        return result

    def state(self):
        with contextlib.closing(self.fixture.outbox()._connect()) as connection:
            return json.loads(connection.execute(
                "SELECT value FROM notification_producer_state WHERE id=1"
            ).fetchone()[0])

    def signal_events(self):
        return [row["event"] for row in self.fixture.queued()
                if row["event"]["ruleId"] == "OperationalCaution"]

    def test_continuous_breach_across_severity_changes_warns_then_escalates_once(self):
        for minute, rate in enumerate((2, 0.5, 2, 0.5, 2, 0.5)):
            self.run_at(minute, rate)
        firing = [row for row in self.signal_events() if row["transition"] == "firing"]
        self.assertEqual([row["severity"] for row in firing], ["warning"])
        self.assertEqual(firing[0]["observedAt"], reports._iso(fixtures.NOW + dt.timedelta(minutes=2)))

        # Two sustained critical samples escalate the same incident. Returning
        # through warning and critical afterward must not emit it a third time.
        for minute, rate in enumerate((2, 2, 0.5, 2, 2), start=6):
            self.run_at(minute, rate)
        firing = [row for row in self.signal_events() if row["transition"] == "firing"]
        self.assertEqual([row["severity"] for row in firing], ["warning", "critical"])
        self.assertEqual(firing[0]["openedAt"], firing[1]["openedAt"])
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["notifiedSeverity"], "critical")

    def test_admitted_recovery_evicted_by_critical_is_readmitted_with_same_identity(self):
        fixture = self.fixture
        fixture.config["queue"]["maxPending"] = 1
        fixture.write("delivery.json", fixture.config)
        config = delivery.parse_delivery_config(fixture.config)
        outbox = fixture.outbox()

        def reboot_sample(minute, required):
            now = fixtures.NOW + dt.timedelta(minutes=minute)
            fixture.refresh(now)
            fixture.current["system"] = {"reboot": {
                "status": "ok", "required": required, "observedAt": reports._iso(now),
            }}
            result = fixture.run_producer(now)
            self.assertEqual(result["status"], "ok")
            return now

        now = reboot_sample(0, True)
        opening = outbox.claim_due(now, "regression-tests")[0]
        self.assertEqual(opening.payload["event"]["ruleId"], "OperationalCaution")
        outbox.complete(opening, delivery.DeliveryResult.success(), now)
        fixture.run_producer(now)
        reboot_sample(1, False)
        now = reboot_sample(2, False)
        recovery = next(row for row in self.signal_events() if row["transition"] == "resolved")

        blocker = event("recovery-evictor", severity="critical", observed_at=reports._iso(now))
        blocker["openedAt"] = reports._iso(now)
        outbox.enqueue(blocker, config.channels[0], "operational", now)
        with contextlib.closing(outbox._connect()) as connection:
            dropped = connection.execute(
                "SELECT state,attempts FROM outbox WHERE event_key=?", (recovery["idempotencyKey"],),
            ).fetchone()
        self.assertEqual((dropped["state"], dropped["attempts"]), ("dropped", 0))
        task = outbox.claim_due(now, "regression-tests")[0]
        self.assertEqual(task.event_key, blocker["idempotencyKey"])
        outbox.complete(task, delivery.DeliveryResult.success(), now)

        now = reboot_sample(3, False)
        retried = outbox.claim_due(now, "regression-tests")[0]
        self.assertEqual(retried.event_key, recovery["idempotencyKey"])
        self.assertEqual(retried.payload["event"]["transition"], "resolved")
        outbox.complete(retried, delivery.DeliveryResult.success(), now)
        fixture.run_producer(now)
        self.assertEqual(self.state()["pendingRecoveries"], [])
        self.assertEqual(len([row for row in self.signal_events() if row["transition"] == "resolved"]), 1)

    def test_processing_cap_cannot_resolve_a_still_observed_breach(self):
        for minute in range(3):
            self.run_at(minute, rate=0.5)
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["notifiedSeverity"], "warning")

        with mock.patch.object(reports, "MAX_SIGNALS", 1):
            for minute in (3, 4):
                # The critical memory signal receives the only processing slot.
                self.run_at(minute, rate=0.5, memoryPercent=95)
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["status"], "active")
        self.assertFalse(any(row["transition"] == "resolved" for row in self.signal_events()))

    def test_cached_and_backdated_absent_metric_cannot_reset_breach_or_recovery_streaks(self):
        self.run_at(0, rate=0.5)
        self.run_at(1, rate=0.5)
        before = self.state()["active"]["host:networkRxErrorsPerSecond"]
        self.assertEqual(before["breachSamples"], 2)
        del self.fixture.current["latest"]["networkRxErrorsPerSecond"]
        for sample_minute in (1, 0):
            self.fixture.current["generatedAt"] = reports._iso(
                fixtures.NOW + dt.timedelta(minutes=sample_minute)
            )
            result = self.fixture.run_producer(fixtures.NOW + dt.timedelta(seconds=90))
            self.assertEqual(result["status"], "ok")
            after = self.state()["active"]["host:networkRxErrorsPerSecond"]
            self.assertEqual(after["breachSamples"], 2)
            self.assertEqual(after["lastBreachSampleAt"], before["lastBreachSampleAt"])
        self.run_at(2, rate=0.5)
        self.assertEqual([row["severity"] for row in self.signal_events()], ["warning"])

        self.run_at(3, rate=0)
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["clearSamples"], 1)
        del self.fixture.current["latest"]["networkRxErrorsPerSecond"]
        for sample_minute in (3, 2):
            self.fixture.current["generatedAt"] = reports._iso(
                fixtures.NOW + dt.timedelta(minutes=sample_minute)
            )
            result = self.fixture.run_producer(fixtures.NOW + dt.timedelta(seconds=210))
            self.assertEqual(result["status"], "ok")
            self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["clearSamples"], 1)
        self.run_at(4, rate=0)
        self.assertEqual([row["transition"] for row in self.signal_events()], ["firing", "resolved"])


if __name__ == "__main__":
    unittest.main()
