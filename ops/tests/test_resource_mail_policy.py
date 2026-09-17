import datetime as dt
import unittest

from ops import notification_reports as reports
from ops.tests import test_notification_reports as fixtures


class ResourceMailPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NotificationReportsTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def tick(self, minute, *, cpu=20, memory=25, timestamp=None):
        now = fixtures.NOW + dt.timedelta(minutes=minute)
        self.fixture.refresh(now, cpu)
        self.fixture.current["latest"]["memoryPercent"] = memory
        if timestamp is not None:
            self.fixture.current["latest"]["timestamp"] = reports._iso(timestamp)
        result = self.fixture.run_producer(now)
        self.assertEqual(result["status"], "ok")
        return reports._readonly_producer_state(self.fixture.root)

    def level(self, state, key="host:memoryPercent"):
        return reports._qualified_severity(key, state["active"][key]) if key in state["active"] else None

    def test_cpu_requires_five_samples_and_never_critical_on_usage_alone(self):
        for minute in range(4):
            self.assertIsNone(self.level(self.tick(minute, cpu=99), "host:cpuPercent"))
        self.assertEqual(self.level(self.tick(4, cpu=99), "host:cpuPercent"), "warning")
        self.assertEqual(self.level(self.tick(5, cpu=85), "host:cpuPercent"), "warning")
        for minute in (6, 7):
            self.assertEqual(self.level(self.tick(minute, cpu=80), "host:cpuPercent"), "warning")
        self.assertIsNone(self.level(self.tick(8, cpu=80), "host:cpuPercent"))

    def test_memory_critical_hysteresis_downgrade_and_full_recovery(self):
        for minute in range(3):
            state = self.tick(minute, memory=95)
        self.assertEqual(self.level(state), "critical")
        for minute in (3, 4, 5):
            self.assertEqual(self.level(self.tick(minute, memory=85)), "critical")
        for minute in (6, 7):
            self.assertEqual(self.level(self.tick(minute, memory=80)), "critical")
        self.assertEqual(self.level(self.tick(8, memory=80)), "warning")
        for minute in (9, 10, 11):
            self.assertEqual(self.level(self.tick(minute, memory=78)), "warning")
        for minute in (12, 13):
            self.assertEqual(self.level(self.tick(minute, memory=75)), "warning")
        self.assertIsNone(self.level(self.tick(14, memory=75)))

    def test_missing_or_cached_values_cannot_clear_confirmed_resource(self):
        for minute in range(3):
            self.tick(minute, memory=95)
        self.assertEqual(self.level(self.tick(3, memory=None)), "critical")
        self.assertEqual(self.level(self.tick(4, memory=20)), "critical")
        sample = fixtures.NOW + dt.timedelta(minutes=4)
        for minute in (5, 6):
            self.assertEqual(self.level(self.tick(minute, memory=20, timestamp=sample)), "critical")
        # Cached data contributes no clear samples; the next distinct reading
        # after a long gap must start a new recovery sequence.
        state = self.tick(8, memory=20)
        self.assertEqual(self.level(state), "critical")
        self.assertEqual(state["active"]["host:memoryPercent"]["clearSamples"], 1)

    def test_old_cpu_critical_policy_is_reclassified_not_false_recovered(self):
        legacy = {"status": "active", "severity": "critical", "notifiedSeverity": "critical",
                  "criticalSamples": 5, "breachSamples": 5,
                  "firstCriticalAt": reports._iso(fixtures.NOW),
                  "firstBreachAt": reports._iso(fixtures.NOW),
                  "lastBreachSampleAt": reports._iso(fixtures.NOW + dt.timedelta(minutes=4))}
        self.assertEqual(reports._qualified_severity("host:cpuPercent", legacy), "warning")
        self.assertFalse(reports._qualified({**legacy, "key": "host:cpuPercent"}, legacy))

    def test_external_monitoring_limit_is_explicit_without_inventing_failure(self):
        mail = reports._digest(self.fixture.current, self.fixture.evaluation, [], {}, [], fixtures.NOW)
        self.assertIn("외부 감시: 미구축", mail["body"])
        self.assertIn("서버 전체 정지", mail["body"])
        self.assertNotIn("] 위험", mail["subject"])

    def test_undefined_host_cpu_full_psi_never_retains_legacy_danger(self):
        legacy = {"status": "active", "severity": "critical", "qualifiedSeverity": "critical"}
        self.assertIsNone(reports._qualified_severity("host:cpuPressureFullAvg10", legacy))
