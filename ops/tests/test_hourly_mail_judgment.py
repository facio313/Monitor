"""Independent end-to-end regressions for the hourly email verdict."""

import datetime as dt
import unittest
from unittest import mock

from ops import notification_reports as reports
from ops.tests import test_notification_reports as fixtures
from ops.tests.test_alert_delivery import event


NOW = fixtures.NOW


class HourlyMailJudgmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NotificationReportsTests()
        self.fixture.setUp()
        for minute in (-4, -3, -2, -1):
            self.tick(minute)

    def tearDown(self):
        self.fixture.tearDown()

    def refresh(self, minute, cpu=20):
        self.now = NOW + dt.timedelta(minutes=minute)
        fixture = self.fixture
        fixture.refresh(self.now, cpu)
        stamp = reports._iso(self.now)
        fixture.current.update({
            "identity": {"bootId": "a" * 32},
            "disks": [{"mount": "/", "usedPercent": 30}],
            "linux": {"collectedAt": stamp, "tcp": {
                "status": "supported", "rateStatus": "ok", "retransmissionPercent": 0,
                "counters": {"OutSegs": 10000 + minute * 1000, "RetransSegs": 0}}},
            "syntheticProbeCollection": {"status": "fresh", "observedAt": stamp},
            "syntheticProbes": [{"id": "monitor-test", "checkedAt": stamp,
                "status": "ok", "latencyMilliseconds": 100, "certificateDaysRemaining": 60}],
        })

    def produce(self):
        result = self.fixture.run_producer(self.now)
        self.assertEqual(result["status"], "ok")
        self.fixture.write("current.json", self.fixture.current)
        self.fixture.write("rule-evaluation.json", self.fixture.evaluation)
        return result

    def tick(self, minute, rate=0):
        self.refresh(minute)
        self.fixture.current["latest"]["networkRxErrorsPerSecond"] = rate
        return self.produce()

    def preview(self):
        return reports.build_hourly_presentation(self.fixture.root, self.now)

    def assert_verdict(self, mail, level):
        label = {"ok": "정상", "warning": "주의", "critical": "위험", "unknown": "관측 불가"}[level]
        self.assertIn("] " + label + " ·", mail["subject"])
        self.assertEqual(mail["visual"]["status"], level)
        self.assertEqual(mail["body"].splitlines()[0], "Monitor 매시간 서버 보고 · " + label)

    def state(self):
        return reports._readonly_producer_state(self.fixture.root)

    def test_single_raw_cpu_and_tcp_peaks_are_not_current_danger(self):
        self.refresh(0, 95)
        self.fixture.current["linux"]["tcp"]["retransmissionPercent"] = 99
        result = self.produce()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        hourly = [row for row in self.fixture.queued() if row["event"]["ruleId"] == "HourlyReport"][-1]
        self.assert_verdict(hourly["presentation"], "ok")
        self.assert_verdict(self.preview(), "ok")
        self.assertEqual(hourly["presentation"]["visual"]["cards"][0]["tone"], "neutral")
        self.assertEqual(hourly["presentation"]["visual"]["cards"][4]["value"], "0")

    def test_warning_critical_qualification_missing_input_and_two_sample_recovery(self):
        for minute in (0, 1, 2):
            self.tick(minute, 0.5)
        self.assert_verdict(self.preview(), "warning")
        self.tick(3, 2)
        self.assert_verdict(self.preview(), "warning")
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["qualifiedSeverity"], "warning")
        self.tick(4, 2)
        self.assert_verdict(self.preview(), "critical")
        self.tick(5, None)
        self.assert_verdict(self.preview(), "critical")
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["qualifiedSeverity"], "critical")
        self.tick(6)
        self.assert_verdict(self.preview(), "critical")
        self.assertIn("복구 확인 중", self.preview()["body"])
        self.tick(7)
        self.assert_verdict(self.preview(), "ok")

    def test_cooldown_does_not_erase_qualified_unnotified_warning(self):
        for minute in (0, 1, 2):
            self.tick(minute, 0.5)
        self.tick(3)
        self.tick(4)
        for minute in (5, 6, 7):
            result = self.tick(minute, 0.5)
        self.assertEqual(result["immediate"]["enqueued"], 0)
        active = self.state()["active"]["host:networkRxErrorsPerSecond"]
        self.assertIsNone(active["notifiedSeverity"])
        self.assertEqual(active["qualifiedSeverity"], "warning")
        self.assert_verdict(self.preview(), "warning")
        self.tick(8, None)
        self.assert_verdict(self.preview(), "warning")

    def test_confirmed_improvement_downgrades_current_danger_without_new_incident(self):
        self.tick(0, 2)
        self.tick(1, 2)
        self.assert_verdict(self.preview(), "critical")
        self.tick(2, 0.5)
        self.assert_verdict(self.preview(), "critical")
        self.assertEqual(self.state()["active"]["host:networkRxErrorsPerSecond"]["severity"], "warning")
        # A second producer call over the same source sample is not a second
        # observation of improvement, even though wall clock time has advanced.
        self.now += dt.timedelta(seconds=60)
        self.produce()
        self.assert_verdict(self.preview(), "critical")
        self.tick(3, 0.5)
        self.assert_verdict(self.preview(), "warning")
        active = self.state()["active"]["host:networkRxErrorsPerSecond"]
        self.assertEqual(active["qualifiedSeverity"], "warning")
        self.assertEqual(active["notifiedSeverity"], "critical")
        self.tick(4, 0.5)
        self.assert_verdict(self.preview(), "warning")
        firing = [row for row in self.fixture.queued()
                  if row["event"]["ruleId"] == "OperationalCaution"
                  and row["event"]["transition"] == "firing"]
        self.assertEqual(len(firing), 1)
        self.assertEqual(firing[0]["event"]["severity"], "critical")
        self.tick(5, 2)
        self.assert_verdict(self.preview(), "warning")
        self.tick(6, 2)
        self.assert_verdict(self.preview(), "critical")

    def test_observation_gap_breaks_downgrade_streak(self):
        self.tick(0, 2)
        self.tick(1, 2)
        self.tick(2, 0.5)
        self.tick(6, 0.5)
        self.assert_verdict(self.preview(), "critical")
        self.tick(7, 0.5)
        self.assert_verdict(self.preview(), "warning")

    def test_preview_does_not_write_any_checkpoint_or_access_secret_or_queue(self):
        self.tick(0)
        paths = [path for path in self.fixture.root.rglob("*") if path.is_file()]
        before = {str(path): path.read_bytes() for path in paths}
        with mock.patch.object(reports.delivery, "DeliveryOutbox", side_effect=AssertionError("queue opened")), \
                mock.patch.object(reports.delivery, "resolve_secret", side_effect=AssertionError("secret accessed")):
            self.assert_verdict(self.preview(), "ok")
        after = {str(path): path.read_bytes() for path in self.fixture.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def rule(self, rule_id="TemperatureHigh"):
        rule = event(severity="critical", observed_at=reports._iso(self.now))
        rule.update(ruleId=rule_id, openedAt=reports._iso(self.now))
        self.fixture.write("rule-alerts.jsonl", rule)
        self.fixture.evaluation["states"] = {"test-rule": {
            "ruleId": rule_id, "target": rule["target"], "openedAt": rule["openedAt"],
            "phase": "firing", "severity": "critical", "lastEvaluatedAt": reports._iso(self.now),
            "observationStatus": "ok", "lastValue": 99,
        }}

    def test_ready_rule_survives_evaluation_loss_until_fresh_resolution(self):
        self.refresh(0)
        self.rule()
        self.produce()
        self.assert_verdict(self.preview(), "critical")
        previous_evaluation = self.fixture.evaluation
        self.refresh(4)
        self.fixture.evaluation = previous_evaluation
        self.produce()
        self.assert_verdict(self.preview(), "critical")
        self.assertTrue(self.state()["reportRules"]["test-rule"]["reportRetained"])
        self.tick(5)
        # TCP needs to rebuild after the deliberate > 180s input gap.
        self.assertNotEqual(self.preview()["visual"]["status"], "critical")
        self.assertEqual(self.state()["reportRules"], {})

    def test_excluded_raw_tcp_rule_cannot_override_weighted_healthy_state(self):
        self.fixture.config["routes"][0]["excludeRuleIds"] = ["TcpRetransmissionHigh"]
        self.fixture.write("delivery.json", self.fixture.config)
        self.refresh(0)
        self.rule("TcpRetransmissionHigh")
        result = self.produce()
        self.assertEqual(result["immediate"]["enqueued"], 0)
        self.assert_verdict(self.preview(), "ok")
        self.assertEqual(self.state()["reportRules"], {})

    def test_public_firing_without_ready_authority_is_not_danger(self):
        self.refresh(0)
        self.rule()
        self.fixture.write("rule-alerts.jsonl", {})
        self.produce()
        self.assertNotEqual(self.preview()["visual"]["status"], "critical")
        self.assertEqual(self.state()["reportRules"], {})


if __name__ == "__main__":
    unittest.main()
