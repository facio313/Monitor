import datetime as dt
import json
import os
import stat
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from ops import alert_delivery, alert_store
from ops.alert_engine import load_rule_pack
from ops.alert_runtime import observations_for_snapshot
from ops.alert_store import (
    evaluate_and_persist,
    load_retired_targets,
    load_silences,
    normalize_evaluation,
    normalize_event,
)


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


def setUpModule():
    # Installed private config and the invoking shell must not affect fixtures.
    directory = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(directory.cleanup)
    environment = mock.patch.dict(os.environ)
    environment.start()
    unittest.addModuleCleanup(environment.stop)
    for kind, variable in (
        ("DELIVERY", alert_store.DELIVERY_CONFIG_ENV),
        ("SILENCE", alert_store.SILENCE_CONFIG_ENV),
        ("RETIREMENT", alert_store.RETIREMENT_CONFIG_ENV),
    ):
        patcher = mock.patch.object(
            alert_store, f"DEFAULT_{kind}_CONFIG_PATH",
            Path(directory.name) / f"absent-{kind.lower()}.json",
        )
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)
        os.environ.pop(variable, None)


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
            "evaluationIntervalSeconds": 60,
            "forSeconds": 60,
            "forSamples": 2,
            "recoverySeconds": 0,
            "recoverySamples": 1,
            "noDataPolicy": "ignore",
            "noDataSeconds": 60,
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
    def create_synthetic_pack(self, root: Path) -> Path:
        definition = rule_pack()
        definition["rules"][0].update({
            "id": "HttpLatencyHigh", "metric": "synthetic.http.latency_ms",
            "threshold": 1000, "recoveryThreshold": 800,
            "forSamples": 3, "forSeconds": 120,
            "recoverySamples": 2, "recoverySeconds": 60,
        })
        path = root / "rules.json"
        path.write_text(json.dumps(definition), encoding="utf-8")
        return path

    def synthetic_snapshot(self, minute: float, sampled_minute: float, latency: int) -> dict:
        timestamp = lambda value: (NOW + dt.timedelta(minutes=value)).isoformat().replace("+00:00", "Z")
        return {
            **snapshot(10),
            "generatedAt": timestamp(minute),
            "syntheticProbeCollection": {"status": "fresh", "observedAt": timestamp(sampled_minute)},
            "syntheticProbes": [{
                "id": "public-ready", "status": "ok", "checkedAt": timestamp(sampled_minute),
                "httpStatus": 200, "latencyMilliseconds": latency,
                "certificateDaysRemaining": 90,
            }],
        }

    def test_synthetic_checkpoint_survives_restart_and_delivers_only_real_transitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_synthetic_pack(root)
            key = "HttpLatencyHigh:synthetic/public-ready"
            for sampled_minute in range(5):
                # Reload persisted state for both a genuinely new minute's
                # export and a later evaluator tick reusing that same export.
                for minute in (sampled_minute, sampled_minute + 0.5):
                    evaluation = evaluate_and_persist(
                        self.synthetic_snapshot(minute, sampled_minute, 1500 if sampled_minute < 3 else 200),
                        NOW + dt.timedelta(minutes=minute), pack, root,
                    )
                    self.assertEqual(evaluation["status"], "ok")
                    state = evaluation["states"][key]
                    self.assertNotIn("lastSampledAt", state)
                    expected = "pending" if sampled_minute < 2 else "firing" if sampled_minute < 3 else "recovering" if sampled_minute < 4 else "inactive"
                    self.assertEqual(state["phase"], expected)
                    private = json.loads((root / ".state" / "rule-state.json").read_text())["states"][key]
                    self.assertEqual(private["lastSampledAt"], self.synthetic_snapshot(minute, sampled_minute, 0)["syntheticProbes"][0]["checkedAt"])
                    if sampled_minute < 2:
                        self.assertEqual(state["breachSamples"], sampled_minute + 1)
                    if sampled_minute == 3:
                        self.assertEqual(state["recoverySamples"], 1)
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual([event["transition"] for event in events], ["firing", "resolved"])
            self.assertEqual([event["observedAt"] for event in events], ["2026-08-30T12:02:00Z", "2026-08-30T12:04:00Z"])

    def test_synthetic_legacy_pending_state_resets_unverified_sample_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_synthetic_pack(root)
            key = "HttpLatencyHigh:synthetic/public-ready"
            evaluate_and_persist(self.synthetic_snapshot(0, 0, 1500), NOW, pack, root)
            state_path = root / ".state" / "rule-state.json"
            bundle = json.loads(state_path.read_text())
            prior = bundle["states"][key]
            prior.pop("lastSampledAt")
            prior["breachSamples"] = 3
            prior["conditionStartedAt"] = "2026-08-30T11:50:00Z"
            state_path.write_text(json.dumps(bundle), encoding="utf-8")
            for minute in (1, 2):
                evaluation = evaluate_and_persist(
                    self.synthetic_snapshot(minute, 0, 1500),
                    NOW + dt.timedelta(minutes=minute), pack, root,
                )
                self.assertEqual(evaluation["status"], "ok")
                self.assertEqual(evaluation["states"][key]["phase"], "pending")
                self.assertEqual(evaluation["states"][key]["breachSamples"], 1)
            self.assertEqual((root / "rule-alerts.jsonl").read_text(), "")

    def test_failed_http_probe_cannot_resolve_latency_incident(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_synthetic_pack(root)
            key = "HttpLatencyHigh:synthetic/public-ready"
            for minute in (0, 1, 2):
                evaluation = evaluate_and_persist(
                    self.synthetic_snapshot(minute, minute, 1500),
                    NOW + dt.timedelta(minutes=minute), pack, root,
                )
            self.assertEqual(evaluation["states"][key]["phase"], "firing")
            for minute, status in ((3, "tls"), (4, "http"), (5, "timeout"), (6, "dns")):
                failed = self.synthetic_snapshot(minute, minute, 10)
                failed["syntheticProbes"][0]["status"] = status
                evaluation = evaluate_and_persist(failed, NOW + dt.timedelta(minutes=minute), pack, root)
                self.assertEqual(evaluation["status"], "ok")
                self.assertEqual(evaluation["states"][key]["phase"], "firing")
                self.assertEqual(evaluation["states"][key]["recoverySamples"], 0)
            events = [json.loads(line) for line in (root / "rule-alerts.jsonl").read_text().splitlines()]
            self.assertEqual([event["transition"] for event in events], ["firing"])

    def test_invalid_private_sample_checkpoint_fails_closed_without_state_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_synthetic_pack(root)
            evaluate_and_persist(self.synthetic_snapshot(0, 0, 1500), NOW, pack, root)
            state_path = root / ".state" / "rule-state.json"
            bundle = json.loads(state_path.read_text())
            next(iter(bundle["states"].values()))["lastSampledAt"] = "invalid"
            state_path.write_text(json.dumps(bundle), encoding="utf-8")
            previous_bytes = state_path.read_bytes()
            evaluation = evaluate_and_persist(
                self.synthetic_snapshot(1, 0, 1500), NOW + dt.timedelta(minutes=1), pack, root,
            )
            self.assertEqual(evaluation["status"], "collection_error")
            self.assertEqual(state_path.read_bytes(), previous_bytes)

    def create_pack(self, root: Path, version: str = "2026.08.30.test") -> Path:
        path = root / "rules.json"
        path.write_text(json.dumps(rule_pack(version)), encoding="utf-8")
        return path

    def create_parent_pack(self, root: Path) -> Path:
        definition = rule_pack()
        base = definition["rules"][0]
        parent = {
            **base,
            "id": "HostDown",
            "metric": "host.heartbeat.age",
            "threshold": 90,
            "recoveryThreshold": 80,
            "forSeconds": 0,
            "forSamples": 1,
            "description": "Host heartbeat is missing.",
            "runbook": "Restore host reachability.",
        }
        child = {
            **base,
            "id": "ContainerDown",
            "metric": "container.running",
            "operator": "lte",
            "threshold": 0,
            "recoveryThreshold": 1,
            "forSeconds": 0,
            "forSamples": 1,
            "parentRuleId": "HostDown",
            "labels": {"scope": "container"},
            "description": "Container is down.",
            "runbook": "Restore the container after the host recovers.",
        }
        definition["rules"] = [parent, child]
        path = root / "parent-rules.json"
        path.write_text(json.dumps(definition), encoding="utf-8")
        return path

    def parent_snapshot(self, host_down: bool) -> dict:
        value = snapshot(10)
        value["generatedAt"] = "2026-08-30T12:00:00Z"
        value["heartbeat"] = {
            "lifecycle": "active",
            "receivedAt": (
                "2026-08-30T11:58:00Z"
                if host_down
                else "2026-08-30T12:00:00Z"
            ),
        }
        value["containers"] = [{"name": "app", "state": "exited"}]
        return value

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

    def create_silence_config(
        self,
        root: Path,
        ends_at: str = "2026-08-30T13:00:00Z",
    ) -> Path:
        path = root / "silences.json"
        path.write_text(json.dumps({
            "schemaVersion": 1,
            "silences": [{
                "id": "maintenance-1",
                "startsAt": "2026-08-30T11:59:00Z",
                "endsAt": ends_at,
                "ruleId": "CpuUsageHigh",
                "target": "host/monitor-test",
                "labels": {"scope": "host"},
            }],
        }), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_persistent_silence_config_suppresses_delivery_not_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            silences = self.create_silence_config(root)
            loaded = load_silences(silences)
            self.assertEqual((len(loaded), loaded[0].silence_id), (1, "maintenance-1"))

            evaluate_and_persist(
                snapshot(95), NOW, pack, root, silence_config_path=silences
            )
            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
                silence_config_path=silences,
            )
            self.assertEqual(evaluation["summary"], {"firing": 1})
            event = json.loads((root / "rule-alerts.jsonl").read_text().splitlines()[0])
            self.assertEqual(event["notificationState"], "silenced")

    def test_silenced_firing_is_enqueued_once_when_silence_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            delivery = self.create_delivery_config(root)
            silences = self.create_silence_config(
                root, ends_at="2026-08-30T12:02:00Z"
            )

            evaluate_and_persist(
                snapshot(95), NOW, pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )
            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )
            state_path = root / ".state" / "rule-state.json"
            state_before_release = state_path.read_bytes()
            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=2), pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )

            events = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
            ]
            firing = [event for event in events if event["transition"] == "firing"]
            self.assertEqual(evaluation["summary"], {"firing": 1})
            self.assertEqual(
                [event["notificationState"] for event in firing],
                ["silenced", "ready"],
            )
            self.assertEqual(firing[0]["openedAt"], firing[1]["openedAt"])
            self.assertNotEqual(firing[0]["idempotencyKey"], firing[1]["idempotencyKey"])

            config = alert_delivery.load_delivery_config(delivery)
            outbox = alert_delivery.DeliveryOutbox(
                root / ".state" / "alert-delivery" / "alert-delivery.sqlite",
                config.queue,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)

            # Simulate an event-first crash: the release event and outbox row
            # survived, but the private evaluator state replacement did not.
            state_path.write_bytes(state_before_release)
            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=3), pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )
            repeated = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(repeated), 2)
            self.assertEqual(outbox.status()["states"]["pending"], 1)

    def test_private_lifecycle_releases_after_muted_event_is_pruned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            delivery = self.create_delivery_config(root)
            silences = self.create_silence_config(
                root, ends_at="2026-08-30T12:02:00Z"
            )

            evaluate_and_persist(
                snapshot(95), NOW, pack, root, silence_config_path=silences,
            )
            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
                silence_config_path=silences,
            )
            private_bundle = json.loads(
                (root / ".state" / "rule-state.json").read_text()
            )
            private_state = next(iter(private_bundle["states"].values()))
            self.assertEqual(private_state["notificationState"], "silenced")

            # The bounded public event log can prune an old opening event after
            # unrelated churn; private incident state must remain sufficient.
            (root / "rule-alerts.jsonl").write_bytes(b"")
            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=2), pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )
            events = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [(event["transition"], event["notificationState"]) for event in events],
                [("firing", "ready")],
            )
            config = alert_delivery.load_delivery_config(delivery)
            outbox = alert_delivery.DeliveryOutbox(
                root / ".state" / "alert-delivery" / "alert-delivery.sqlite",
                config.queue,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)

    def test_late_silence_does_not_revoke_durable_ready_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            delivery = self.create_delivery_config(root)
            silences = self.create_silence_config(root)

            evaluate_and_persist(
                snapshot(95), NOW, pack, root, delivery_config_path=delivery,
            )
            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
                delivery_config_path=delivery,
            )
            ready_before_silence = json.loads(
                (root / "rule-alerts.jsonl").read_text().splitlines()[0]
            )
            self.assertEqual(ready_before_silence["notificationState"], "ready")
            config = alert_delivery.load_delivery_config(delivery)
            outbox = alert_delivery.DeliveryOutbox(
                root / ".state" / "alert-delivery" / "alert-delivery.sqlite",
                config.queue,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)

            evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=2), pack, root,
                delivery_config_path=delivery,
                silence_config_path=silences,
            )
            events = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
            ]
            self.assertEqual(events, [ready_before_silence])
            self.assertEqual(outbox.status()["states"]["pending"], 1)

    def test_parent_recovery_enqueues_child_release_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_parent_pack(root)
            delivery = self.create_delivery_config(root)

            first = evaluate_and_persist(
                self.parent_snapshot(True), NOW, pack, root,
                delivery_config_path=delivery,
            )
            self.assertEqual(first["summary"], {"firing": 2})
            config = alert_delivery.load_delivery_config(delivery)
            outbox = alert_delivery.DeliveryOutbox(
                root / ".state" / "alert-delivery" / "alert-delivery.sqlite",
                config.queue,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 1)

            second = evaluate_and_persist(
                self.parent_snapshot(False), NOW + dt.timedelta(minutes=1),
                pack, root, delivery_config_path=delivery,
            )
            self.assertEqual(second["summary"], {"firing": 1, "inactive": 1})
            events = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
            ]
            child_events = [
                event for event in events if event["ruleId"] == "ContainerDown"
            ]
            self.assertEqual(
                [
                    (event["transition"], event["notificationState"])
                    for event in child_events
                ],
                [("firing", "suppressed"), ("firing", "ready")],
            )
            self.assertEqual(child_events[0]["openedAt"], child_events[1]["openedAt"])
            self.assertEqual(outbox.status()["states"]["pending"], 3)
            enqueue_status = json.loads(
                (root / "alert-delivery-enqueue.json").read_text()
            )
            self.assertEqual(
                {
                    key: enqueue_status[key]
                    for key in ("enqueued", "deduplicated", "dropped", "skipped")
                },
                {"enqueued": 2, "deduplicated": 1, "dropped": 0, "skipped": 1},
            )

            evaluate_and_persist(
                self.parent_snapshot(False), NOW + dt.timedelta(minutes=2),
                pack, root, delivery_config_path=delivery,
            )
            self.assertEqual(outbox.status()["states"]["pending"], 3)
            repeated = [
                json.loads(line)
                for line in (root / "rule-alerts.jsonl").read_text().splitlines()
                if json.loads(line)["ruleId"] == "ContainerDown"
            ]
            self.assertEqual(len(repeated), 2)

    def test_silence_config_is_strict_private_and_duplicate_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.create_silence_config(root)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_silences(path)

            path.write_text(
                '{"schemaVersion":1,"schemaVersion":1,"silences":[]}',
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_silences(path)

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

    def test_private_state_without_lifecycle_fields_is_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            evaluate_and_persist(snapshot(95), NOW, pack, root)
            state_path = root / ".state" / "rule-state.json"
            bundle = json.loads(state_path.read_text())
            for state in bundle["states"].values():
                state.pop("notificationState")
                state.pop("notificationLabels")
                state.pop("lastSampledAt")
            state_path.write_text(json.dumps(bundle), encoding="utf-8")

            evaluation = evaluate_and_persist(
                snapshot(95), NOW + dt.timedelta(minutes=1), pack, root,
            )
            self.assertEqual(evaluation["summary"], {"firing": 1})
            migrated = json.loads(state_path.read_text())
            private_state = next(iter(migrated["states"].values()))
            self.assertEqual(private_state["notificationState"], "ready")
            self.assertEqual(private_state["notificationLabels"], {"scope": "host"})

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
            definition["rules"][0]["forSeconds"] = 0
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

    def test_pack_upgrade_ignores_an_older_private_state_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root, "2026.08.31.test")
            state_path = root / ".state" / "rule-state.json"
            state_path.parent.mkdir()
            state_path.write_text(json.dumps({
                "schemaVersion": 1,
                "rulePackVersion": "2026.08.30.test",
                "states": {
                    "CpuUsageHigh:host/monitor-test": {
                        "phase": "inactive",
                        "breachSamples": 0,
                        "recoverySamples": 0,
                        "missingSamples": 0,
                        "openedAt": None,
                        "changedAt": "2026-08-30T11:59:00Z",
                        "lastEvaluatedAt": "2026-08-30T11:59:00Z",
                        "lastValue": 10,
                        "observationStatus": "ok",
                    },
                },
            }), encoding="utf-8")
            state_path.chmod(0o600)

            evaluation = evaluate_and_persist(snapshot(95), NOW, pack, root)

            self.assertEqual(evaluation["status"], "ok")
            self.assertEqual(evaluation["summary"], {"pending": 1})
            rewritten = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(rewritten["rulePackVersion"], "2026.08.31.test")

    def test_current_pack_still_rejects_an_invalid_private_state_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = self.create_pack(root)
            state_path = root / ".state" / "rule-state.json"
            state_path.parent.mkdir()
            state_path.write_text(json.dumps({
                "schemaVersion": 1,
                "rulePackVersion": "2026.08.30.test",
                "states": {"CpuUsageHigh:host/monitor-test": {"phase": "inactive"}},
            }), encoding="utf-8")
            state_path.chmod(0o600)

            evaluation = evaluate_and_persist(snapshot(95), NOW, pack, root)

            self.assertEqual(evaluation["status"], "collection_error")

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


class AlertRetirementStoreTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        definition = rule_pack()
        definition["rules"][0].update({
            "id": "ContainerDown", "metric": "container.running",
            "operator": "lte", "threshold": 0, "recoveryThreshold": 1,
            "forSamples": 1, "forSeconds": 0,
            "labels": {"scope": "container"},
        })
        self.pack = self.root / "rules.json"
        self.pack.write_text(json.dumps(definition), encoding="utf-8")
        self.config = self.root / "retirements.json"
        self.target = "container/legacy"
        self.state_key = f"ContainerDown:{self.target}"
        self.state_path = self.root / ".state" / "rule-state.json"
        self.events_path = self.root / "rule-alerts.jsonl"
        # Production requires UID 0. Test fixtures use the current test owner
        # so the same safety and persistence tests also run without root.
        for patcher in (
            mock.patch.object(alert_store, "RETIREMENT_CONFIG_OWNER_UID", os.geteuid()),
            mock.patch.object(alert_store, "DEFAULT_RETIREMENT_CONFIG_PATH", self.root / "absent.json"),
            mock.patch.dict(os.environ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop(alert_store.RETIREMENT_CONFIG_ENV, None)
        self.write_config()

    def write_config(self, targets=None, **overrides):
        self.config.write_text(json.dumps({
            "schemaVersion": 1,
            "targets": [self.target] if targets is None else targets,
            **overrides,
        }), encoding="utf-8")
        self.config.chmod(0o600)

    def sample(self, minute=0, containers=None, **collection):
        value = snapshot(10)
        value["containers"] = [] if containers is None else containers
        value["containerCollection"] = {
            "status": "fresh",
            "observedAt": (NOW + dt.timedelta(minutes=minute)).isoformat().replace("+00:00", "Z"),
            **collection,
        }
        return value

    def evaluate(self, value, minute=0, configured=True):
        return evaluate_and_persist(
            value, NOW + dt.timedelta(minutes=minute), self.pack, self.root,
            retirement_config_path=self.config if configured else None,
        )

    def open_incident(self, extra=False):
        containers = [{"name": "legacy", "state": "exited"}]
        if extra:
            containers.append({"name": "legacy-new", "state": "exited"})
        evaluation = self.evaluate(self.sample(containers=containers))
        self.assertEqual(evaluation["states"][self.state_key]["phase"], "firing")
        return evaluation

    def events(self):
        return [json.loads(line) for line in self.events_path.read_text().splitlines()]

    def test_retirement_configuration_is_exact_strict_and_bounded(self):
        self.assertEqual(load_retired_targets(self.config), (self.target,))
        self.write_config([f"container/service-{index}" for index in range(128)])
        self.assertEqual(len(load_retired_targets(self.config)), 128)
        for targets in (
            [self.target, self.target], ["container/legacy*"], ["host/node-a"],
            ["container/legacy/child"], [None], "container/legacy",
            [f"container/service-{index}" for index in range(129)],
        ):
            with self.subTest(targets=targets):
                self.write_config(targets)
                with self.assertRaises(ValueError):
                    load_retired_targets(self.config)
        for changes in ({"schemaVersion": True}, {"schemaVersion": 2}, {"extra": True}):
            with self.subTest(changes=changes):
                self.write_config(**changes)
                with self.assertRaises(ValueError):
                    load_retired_targets(self.config)
        for text in (
            '{"schemaVersion":1,"targets":[],"targets":[]}',
            '{"schemaVersion":1,"targets":[NaN]}',
            " " * (alert_store.MAX_RETIREMENT_CONFIG_BYTES + 1),
        ):
            self.config.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_retired_targets(self.config)

    def test_retirement_configuration_rejects_wrong_owner_modes_and_links(self):
        with mock.patch.object(alert_store, "RETIREMENT_CONFIG_OWNER_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_retired_targets(self.config)
        self.config.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            load_retired_targets(self.config)
        self.config.chmod(0o600)
        linked = self.root / "linked.json"
        linked.symlink_to(self.config)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            load_retired_targets(linked)
        hardlink = self.root / "hardlink.json"
        os.link(self.config, hardlink)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            load_retired_targets(self.config)

    def test_missing_default_config_keeps_disappeared_incident_active(self):
        self.open_incident()
        evaluation = self.evaluate(self.sample(1), 1, configured=False)
        self.assertEqual(evaluation["states"][self.state_key]["phase"], "firing")
        self.assertEqual([event["transition"] for event in self.events()], ["firing"])

    def test_invalid_configuration_fails_closed_preserving_private_state_and_history(self):
        self.open_incident()
        state = self.state_path.read_bytes()
        events = self.events_path.read_bytes()
        self.write_config(["container/legacy*"])
        evaluation = self.evaluate(self.sample(1), 1)
        self.assertEqual(evaluation["status"], "collection_error")
        self.assertEqual(self.state_path.read_bytes(), state)
        self.assertEqual(self.events_path.read_bytes(), events)

    def test_unsafe_default_symlink_fails_closed_even_when_destination_is_missing(self):
        self.open_incident()
        default = self.root / "absent.json"
        default.symlink_to(self.root / "missing-destination.json")
        evaluation = self.evaluate(self.sample(1), 1, configured=False)
        self.assertEqual(evaluation["status"], "collection_error")
        self.assertEqual([event["transition"] for event in self.events()], ["firing"])

    def test_retirement_requires_recent_successful_complete_inventory(self):
        self.open_incident()
        failures = [
            self.sample(1, status=status)
            for status in ("last-known", "unavailable", "permission-denied", "unsupported", None)
        ] + [
            self.sample(1, observedAt=value)
            for value in (None, "invalid", "2026-08-30T11:57:59Z", "2026-08-30T12:01:01Z")
        ] + [
            self.sample(1, containers=value)
            for value in ({}, [{}], [{"name": "legacy/invalid"}])
        ]
        for value in failures:
            with self.subTest(value=value):
                evaluation = self.evaluate(value, 1)
                self.assertEqual(evaluation["status"], "ok")
                self.assertEqual(evaluation["states"][self.state_key]["phase"], "firing")
                self.assertEqual([event["transition"] for event in self.events()], ["firing"])

    def test_still_present_target_with_missing_metrics_remains_active(self):
        self.open_incident()
        evaluation = self.evaluate(self.sample(1, containers=[{"name": "legacy"}]), 1)
        self.assertEqual(evaluation["states"][self.state_key]["phase"], "firing")
        self.assertEqual([event["transition"] for event in self.events()], ["firing"])

    def test_retirement_persists_one_resolution_and_keeps_unconfigured_incidents(self):
        self.open_incident(extra=True)
        evaluation = self.evaluate(self.sample(1), 1)
        self.assertEqual(evaluation["status"], "ok")
        self.assertNotIn(self.state_key, evaluation["states"])
        self.assertNotIn(self.state_key, json.loads(self.state_path.read_text())["states"])
        self.assertEqual(evaluation["states"]["ContainerDown:container/legacy-new"]["phase"], "firing")
        event = self.events()[-1]
        self.assertEqual((event["transition"], event["status"], event["value"]), ("resolved", "unsupported", None))
        self.assertEqual(event["labels"]["retirement"], "service-retired")
        self.assertEqual(event["openedAt"], self.events()[0]["openedAt"])
        self.evaluate(self.sample(2), 2)
        self.assertEqual(len(self.events()), 3)

    def test_durable_retirement_prevents_reopening_after_event_first_crash(self):
        self.open_incident()
        previous = self.state_path.read_bytes()
        self.evaluate(self.sample(1), 1)
        durable_events = self.events_path.read_bytes()
        self.state_path.write_bytes(previous)
        # The durable resolution must also apply when config disappears and
        # container collection subsequently fails; it closed the old incident.
        evaluation = self.evaluate(self.sample(2, status="unavailable"), 2, configured=False)
        self.assertEqual(evaluation["status"], "ok")
        self.assertNotIn(self.state_key, evaluation["states"])
        self.assertEqual(self.events_path.read_bytes(), durable_events)
        self.state_path.unlink()
        replay = self.evaluate(self.sample(3), 3, configured=False)
        self.assertNotIn(self.state_key, replay["states"])
        self.assertEqual(self.events_path.read_bytes(), durable_events)

    def test_retained_retirement_applies_when_opening_event_was_pruned(self):
        self.open_incident()
        previous = self.state_path.read_bytes()
        self.evaluate(self.sample(1), 1)
        resolution = self.events()[-1]
        self.events_path.write_text(json.dumps(resolution) + "\n", encoding="utf-8")
        self.state_path.write_bytes(previous)
        evaluation = self.evaluate(self.sample(2), 2, configured=False)
        self.assertNotIn(self.state_key, evaluation["states"])
        self.assertEqual(self.events(), [resolution])

    def test_reappearing_target_creates_a_new_incident_despite_retirement_config(self):
        self.open_incident()
        self.evaluate(self.sample(1), 1)
        value = self.sample(2, containers=[{"name": "legacy", "state": "exited"}])
        evaluation = self.evaluate(value, 2)
        self.assertEqual(evaluation["states"][self.state_key]["phase"], "firing")
        events = self.events()
        self.assertEqual([event["transition"] for event in events], ["firing", "resolved", "firing"])
        self.assertNotEqual(events[0]["openedAt"], events[2]["openedAt"])
        replay = self.evaluate(self.sample(3, containers=[{"name": "legacy", "state": "exited"}]), 3)
        self.assertEqual(replay["states"][self.state_key]["openedAt"], events[2]["openedAt"])
        self.assertEqual(len(self.events()), 3)


if __name__ == "__main__":
    unittest.main()
