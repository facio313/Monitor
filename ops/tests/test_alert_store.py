import datetime as dt
import json
import stat
import tempfile
import unittest
from pathlib import Path

from ops import alert_delivery
from ops.alert_engine import load_rule_pack
from ops.alert_runtime import observations_for_snapshot
from ops.alert_store import evaluate_and_persist, normalize_evaluation, normalize_event


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


def rule_pack(version: str = "2026.08.30.test") -> dict:
    return {
        "schemaVersion": 1,
        "version": version,
        "rules": [{
            "id": "CpuUsageHigh",
            "metric": "host.cpu.percent",
            "operator": "gte",
            "threshold": 90,
            "recoveryThreshold": 80,
            "severity": "warning",
            "forSamples": 2,
            "recoverySamples": 1,
            "noDataPolicy": "ignore",
            "noDataSamples": 2,
            "parentRuleId": None,
            "labels": {"scope": "host"},
            "description": "CPU usage remains high.",
            "runbook": "Inspect load and bounded process groups.",
            "enabled": True,
        }],
    }


def snapshot(cpu: float) -> dict:
    return {
        "host": {"hostname": "monitor-test", "logicalCpuCount": 4},
        "latest": {"cpuPercent": cpu},
        "disks": [],
        "containers": [],
        "containerCollection": {"status": "fresh", "observedAt": "2026-08-30T12:00:00Z"},
        "system": {},
    }


class AlertStoreTests(unittest.TestCase):
    def create_pack(self, root: Path, version: str = "2026.08.30.test") -> Path:
        path = root / "rules.json"
        path.write_text(json.dumps(rule_pack(version)), encoding="utf-8")
        return path

    def create_delivery_config(self, root: Path) -> Path:
        path = root / "delivery.json"
        path.write_text(json.dumps({
            "schemaVersion": 1,
            "queue": {
                "maxPending": 10, "maxHistory": 20, "maxDeliveryLog": 40,
                "leaseSeconds": 10, "batchSize": 5, "replayWindowSeconds": 900,
            },
            "channels": [{
                "id": "ops-webhook", "kind": "webhook", "enabled": True,
                "timeoutSeconds": 2, "maxAttempts": 3,
                "baseBackoffSeconds": 10, "maxBackoffSeconds": 60,
                "secretRef": {"provider": "env", "key": "MONITOR_TEST_WEBHOOK"},
                "settings": {"headers": {}},
            }],
            "routes": [{
                "id": "all", "priority": 100, "enabled": True,
                "severities": ["warning"], "transitions": ["firing", "resolved"],
                "labels": {}, "channels": ["ops-webhook"], "continue": False,
            }],
        }), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_notification_delivery_final_failure_is_a_real_rule_observation(self):
        pack = load_rule_pack(
            Path(__file__).resolve().parents[1] / "rules" / "default-rules.v1.json"
        )
        base = snapshot(10)
        base["_monitor"] = {
            "notificationDeliveryStatus": "ok",
            "notificationFinalFailureDelta": 2,
        }
        observed = observations_for_snapshot(pack, base)["NotificationDeliveryFailure"]
        self.assertEqual(len(observed), 1)
        self.assertEqual((observed[0].status, observed[0].value), ("ok", 2.0))

        base["_monitor"] = {
            "notificationDeliveryStatus": "collection_error",
            "notificationFinalFailureDelta": None,
        }
        failed = observations_for_snapshot(pack, base)["NotificationDeliveryFailure"]
        self.assertEqual((failed[0].status, failed[0].value), ("collection_error", None))

    def test_persists_pending_then_one_firing_event_with_exact_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            first = evaluate_and_persist(snapshot(95), NOW, pack, root)
            second = evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=1), pack, root)

            state = next(iter(second["states"].values()))
            self.assertEqual(first["summary"], {"pending": 1})
            self.assertEqual((state["phase"], state["openedAt"]), ("firing", "2026-08-30T12:00:00Z"))
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["transition"], "firing")
            self.assertEqual(stat.S_IMODE((root / "rule-evaluation.json").stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE((root / ".state" / "rule-state.json").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / "rule-alerts.jsonl").stat().st_mode), 0o640)

    def test_event_first_crash_replay_deduplicates_firing_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            state_path = root / ".state" / "rule-state.json"
            pending_state = state_path.read_bytes()
            evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=1), pack, root)
            state_path.write_bytes(pending_state)

            replay = evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=2), pack, root)
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual(replay["status"], "ok")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["openedAt"], "2026-08-30T12:00:00Z")

    def test_recent_durable_event_is_enqueued_after_delivery_subsystem_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            delivery = self.create_delivery_config(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=1), pack, root)
            self.assertFalse(
                (root / ".state" / "alert-delivery" / "alert-delivery.sqlite").exists()
            )

            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=2), pack, root,
                delivery_config_path=delivery,
            )
            self.assertEqual(evaluation["status"], "ok")
            config = alert_delivery.load_delivery_config(delivery)
            outbox = alert_delivery.DeliveryOutbox(
                root / ".state" / "alert-delivery" / "alert-delivery.sqlite",
                config.queue,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)
            enqueue_status = json.loads(
                (root / "alert-delivery-enqueue.json").read_text(encoding="utf-8")
            )
            self.assertEqual(enqueue_status["status"], "ok")
            self.assertEqual(enqueue_status["enqueued"], 1)
            self.assertEqual(
                stat.S_IMODE((root / "alert-delivery-enqueue.json").stat().st_mode),
                0o640,
            )

            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=3), pack, root,
                delivery_config_path=delivery,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)

    def test_delivery_failure_never_turns_rule_evaluation_into_collection_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            delivery = root / "delivery.json"
            delivery.write_text('{"inlineSecret":"forbidden"}', encoding="utf-8")
            first = evaluate_and_persist(
                snapshot(95), NOW, pack, root, delivery_config_path=delivery,
            )
            second = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
                delivery_config_path=delivery,
            )
            self.assertEqual(first["status"], "ok")
            self.assertEqual(second["summary"], {"firing": 1})
            enqueue_status = json.loads(
                (root / "alert-delivery-enqueue.json").read_text(encoding="utf-8")
            )
            self.assertEqual(enqueue_status, {
                "schemaVersion": 1,
                "status": "error",
                "observedAt": "2026-08-30T12:01:00Z",
                "enqueued": 0,
                "deduplicated": 0,
                "dropped": 0,
                "skipped": 0,
            })
            self.assertEqual(
                len((root / "rule-alerts.jsonl").read_text().splitlines()), 1,
            )

    def test_immediate_firing_crash_rehydrates_from_durable_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "rules.json"
            definition = rule_pack()
            definition["rules"][0]["forSamples"] = 1
            pack.write_text(json.dumps(definition), encoding="utf-8")

            first = evaluate_and_persist(snapshot(95), NOW, pack, root)
            self.assertEqual(first["summary"], {"firing": 1})
            (root / ".state" / "rule-state.json").unlink()

            replay = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
            )
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual(replay["summary"], {"firing": 1})
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["rulePackVersion"], "2026.08.30.test")
            self.assertEqual(events[0]["openedAt"], "2026-08-30T12:00:00Z")

    def test_event_first_crash_replay_deduplicates_resolution_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=1), pack, root)
            state_path = root / ".state" / "rule-state.json"
            firing_state = state_path.read_bytes()
            evaluate_and_persist(snapshot(10), NOW + dt.timedelta(minutes=2), pack, root)
            state_path.write_bytes(firing_state)

            replay = evaluate_and_persist(snapshot(10), NOW + dt.timedelta(minutes=3), pack, root)
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual(replay["status"], "ok")
            self.assertEqual([event["transition"] for event in events], ["firing", "resolved"])
            self.assertEqual(events[0]["openedAt"], events[1]["openedAt"])

    def test_pack_version_change_resets_streak_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            pack.write_text(json.dumps(rule_pack("2026.08.31.test")), encoding="utf-8")
            evaluation = evaluate_and_persist(snapshot(95), NOW + dt.timedelta(minutes=1), pack, root)
            self.assertEqual(evaluation["summary"], {"pending": 1})
            self.assertEqual((root / "rule-alerts.jsonl").read_text(), "")

    def test_invalid_pack_is_an_explicit_collection_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "rules.json"
            pack.write_text("{}", encoding="utf-8")
            evaluation = evaluate_and_persist(snapshot(95), NOW, pack, root)
            self.assertEqual(evaluation, {
                "schemaVersion": 1,
                "status": "collection_error",
                "rulePackVersion": None,
                "evaluatedAt": "2026-08-30T12:00:00Z",
                "summary": {},
                "states": {},
            })
            self.assertEqual(normalize_evaluation(json.loads((root / "rule-evaluation.json").read_text())), evaluation)

    def test_corrupt_event_log_fails_closed_without_erasing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            event_path = root / "rule-alerts.jsonl"
            event_path.write_text("not-json\n", encoding="utf-8")

            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
            )
            self.assertEqual(evaluation["status"], "collection_error")
            self.assertEqual(event_path.read_text(), "not-json\n")

    def test_symlinked_private_state_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            state_path = root / ".state" / "rule-state.json"
            state_path.unlink()
            outside = root / "outside.json"
            outside.write_text("private", encoding="utf-8")
            outside.chmod(0o600)
            state_path.symlink_to(outside)

            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
            )
            self.assertEqual(evaluation["status"], "collection_error")
            self.assertEqual(outside.read_text(), "private")
            self.assertTrue(state_path.is_symlink())

    def test_normalizers_reject_foreign_fields(self):
        with self.assertRaises(ValueError):
            normalize_evaluation({**{
                "schemaVersion": 1, "status": "collection_error", "rulePackVersion": None,
                "evaluatedAt": "2026-08-30T12:00:00Z", "summary": {}, "states": {},
            }, "raw": "secret"})
        with self.assertRaises(ValueError):
            normalize_event({"schemaVersion": 1})


if __name__ == "__main__":
    unittest.main()
