import datetime as dt
import unittest

from ops.alert_engine import Observation, RulePack, evaluate_rule_pack
from ops.tests.test_alert_engine import NOW, rule
from ops.alert_runtime import evaluate_snapshot


class ContainerInventoryContinuityTests(unittest.TestCase):
    def setUp(self):
        self.pack = RulePack(1, "test", (rule(rule_id="ContainerDown", metric="container.running",
            operator="lt", threshold=1, recovery_threshold=1, severity="critical"),))
        self.target = "container/monitor"
        self.key = "ContainerDown:" + self.target
        self.state, _ = evaluate_rule_pack(self.pack,
            {"ContainerDown": [Observation(self.target, 1)]}, {}, NOW)

    def tick(self, minute, complete=True, retired=(), sample_minute=None, present=False):
        now = NOW + dt.timedelta(minutes=minute)
        sample = NOW + dt.timedelta(minutes=minute if sample_minute is None else sample_minute)
        observations = {"ContainerDown": [Observation(self.target, 1)]} if present else {}
        self.state, events = evaluate_rule_pack(self.pack, observations, self.state, now,
            retired_targets=retired, container_inventory_complete=complete,
            container_inventory_sampled_at=sample)
        return events

    def test_previously_healthy_container_absence_fires_after_distinct_samples(self):
        self.assertEqual(self.tick(1), [])
        self.assertEqual(self.tick(2), [])
        self.assertEqual([event["transition"] for event in self.tick(3)], ["firing"])
        self.assertEqual(self.state[self.key]["phase"], "firing")

    def test_incomplete_inventory_neither_claims_failure_nor_forgets_expectation(self):
        for minute in (1, 2, 3):
            self.assertEqual(self.tick(minute, complete=False), [])
            self.assertNotEqual(self.state[self.key]["phase"], "firing")
        for minute in (4, 5):
            self.assertEqual(self.tick(minute), [])
        self.assertEqual(len(self.tick(6)), 1)

    def test_retirement_of_healthy_target_has_no_false_recovery_mail(self):
        self.assertEqual(self.tick(1, retired=(self.target,)), [])
        self.assertNotIn(self.key, self.state)
        self.assertEqual(self.tick(2), [])

    def test_cached_inventory_cannot_confirm_absence(self):
        self.tick(1)
        for minute in (2, 3):
            self.assertEqual(self.tick(minute, sample_minute=1), [])
            self.assertEqual(self.state[self.key]["phase"], "pending")

    def test_no_complete_inventory_default_preserves_existing_behavior(self):
        self.state, events = evaluate_rule_pack(self.pack, {}, self.state, NOW + dt.timedelta(minutes=1))
        self.assertEqual(events, [])
        self.assertNotEqual(self.state[self.key]["phase"], "firing")

    def test_excluded_fixture_is_not_evaluated_or_inferred(self):
        excluded_target = "container/wgang-fixture"
        prior = {"ContainerDown:" + excluded_target: dict(self.state[self.key])}
        snapshot = {"generatedAt": NOW.isoformat(), "containers": [
            {"name": "wgang-fixture", "state": "running"}],
            "containerCollection": {"status": "fresh", "observedAt": NOW.isoformat()}}
        states, events = evaluate_snapshot(self.pack, snapshot, prior, NOW)
        self.assertFalse(any("wgang" in key for key in states["states"]))
        self.assertEqual(events, [])
