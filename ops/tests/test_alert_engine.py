import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from ops.alert_engine import (
    AlertRule,
    Observation,
    RulePack,
    RulePackError,
    Silence,
    evaluate_observation,
    evaluate_rule_pack,
    load_rule_pack,
    parse_rule_pack,
    release_notification_events,
)


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)

EXPECTED_DEFAULT_RULES = """
HostDown AgentHeartbeatMissing AgentDataStale CpuUsageHigh CpuIowaitHigh CpuStealHigh
LoadPerCoreHigh CpuPressureHigh MemoryAvailableLow MemoryPressureHigh SwapUsageHigh
SwapThrashing OOMKillDetected DiskUsageHigh DiskUsageCritical InodeUsageHigh DiskReadOnly
DiskLatencyHigh DiskIoErrors RaidDegraded SmartHealthFailed NetworkErrorsHigh NetworkDropsHigh
TcpRetransmissionHigh ConntrackUsageHigh FileDescriptorUsageHigh PidUsageHigh ZombieProcessesHigh
SystemdServiceFailed ClockSkewHigh UnexpectedReboot TemperatureHigh RaspberryPiThrottling
RaspberryPiUnderVoltage ContainerDown ContainerRestartLoop ContainerOOMKilled ContainerUnhealthy
ContainerCpuHigh ContainerCpuThrottlingHigh ContainerMemoryNearLimit ContainerPidNearLimit
ContainerNetworkErrors ContainerWritableLayerHigh ContainerNoMemoryLimit ContainerNoCpuLimit
ContainerNoHealthcheck ContainerPrivileged ContainerDockerSocketMounted ContainerImageDigestDrift
ContainerUsingLatestTag DockerDaemonUnavailable DockerEventStreamDisconnected HttpEndpointDown
HttpLatencyHigh HttpErrorRateHigh TlsCertificateExpiring TlsCertificateInvalid CronHeartbeatMissing
ServiceProcessDown ProcessCpuHigh ProcessMemoryHigh ProcessFileDescriptorHigh ServiceWorkerPoolNearMax
ServiceConnectionPoolExhausted DatabaseEndpointDown DatabaseConnectionsHigh DatabaseLongTransaction
DatabaseLockWaitHigh DatabaseDeadlockDetected DatabaseReplicationLag DatabaseDiskGrowthHigh
DatabaseMaintenanceProblem ReverseProxyUpstreamErrorsHigh IngestLagHigh MetricsQueueHigh LogsQueueHigh
DatabaseWriteFailure AlertEvaluationDelayed NotificationDeliveryFailure MonitoringDiskUsageHigh
MonitoringServiceUnavailable
""".split()


def rule(**overrides):
    values = {
        "rule_id": "CpuUsageHigh",
        "metric": "host.cpu.percent",
        "operator": "gte",
        "threshold": 90.0,
        "recovery_threshold": 80.0,
        "severity": "warning",
        "for_samples": 3,
        "recovery_samples": 2,
        "no_data_policy": "ignore",
        "no_data_samples": 3,
        "parent_rule_id": None,
        "labels": (("scope", "host"),),
        "description": "CPU usage remains high.",
        "runbook": "Inspect load and top processes.",
        "enabled": True,
    }
    values.update(overrides)
    values.setdefault("evaluation_interval_seconds", 60)
    values.setdefault("for_seconds", max(0, (values["for_samples"] - 1) * 60))
    values.setdefault(
        "recovery_seconds", max(0, (values["recovery_samples"] - 1) * 60)
    )
    values.setdefault(
        "no_data_seconds", max(0, (values["no_data_samples"] - 1) * 60)
    )
    return AlertRule(**values)


def raw_rule(**overrides):
    values = {
        "id": "CpuUsageHigh",
        "metric": "host.cpu.percent",
        "operator": "gte",
        "threshold": 90,
        "recoveryThreshold": 80,
        "severity": "warning",
        "forSamples": 3,
        "recoverySamples": 2,
        "noDataPolicy": "ignore",
        "noDataSamples": 3,
        "parentRuleId": None,
        "labels": {"scope": "host"},
        "description": "CPU usage remains high.",
        "runbook": "Inspect load and top processes.",
        "enabled": True,
    }
    values.update(overrides)
    values.setdefault("evaluationIntervalSeconds", 60)
    values.setdefault("forSeconds", max(0, (values["forSamples"] - 1) * 60))
    values.setdefault(
        "recoverySeconds", max(0, (values["recoverySamples"] - 1) * 60)
    )
    values.setdefault(
        "noDataSeconds", max(0, (values["noDataSamples"] - 1) * 60)
    )
    return values


class AlertEngineTests(unittest.TestCase):
    def test_default_rule_pack_matches_all_documented_rules_in_order(self):
        path = Path(__file__).parents[1] / "rules" / "default-rules.v1.json"
        pack = load_rule_pack(path)
        self.assertEqual([item.rule_id for item in pack.rules], EXPECTED_DEFAULT_RULES)
        self.assertEqual(len(pack.rules), 82)
        self.assertTrue(all(item.evaluation_interval_seconds == 60 for item in pack.rules))
        self.assertTrue(all(item.for_seconds >= 0 for item in pack.rules))
        self.assertTrue(all(item.recovery_seconds >= 0 for item in pack.rules))

    def test_rule_pack_is_strict_and_rejects_unknown_keys(self):
        value = {"schemaVersion": 1, "version": "2026.08.1", "rules": [raw_rule(extra=True)]}
        with self.assertRaisesRegex(RulePackError, "keys do not match"):
            parse_rule_pack(value)

    def test_rule_pack_rejects_invalid_hysteresis(self):
        value = {"schemaVersion": 1, "version": "2026.08.1", "rules": [raw_rule(recoveryThreshold=95)]}
        with self.assertRaisesRegex(RulePackError, "must not exceed"):
            parse_rule_pack(value)

    def test_rule_pack_rejects_invalid_duration_and_interval(self):
        for invalid in (
            raw_rule(forSeconds=-1),
            raw_rule(recoverySeconds=-1),
            raw_rule(noDataSeconds=-1),
            raw_rule(evaluationIntervalSeconds=0),
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                RulePackError, "must be an integer"
            ):
                parse_rule_pack({
                    "schemaVersion": 1, "version": "2026.08.1", "rules": [invalid],
                })

    def test_rule_pack_rejects_version_not_accepted_by_persistence(self):
        value = {"schemaVersion": 1, "version": "bad version", "rules": [raw_rule()]}
        with self.assertRaisesRegex(RulePackError, "version is invalid"):
            parse_rule_pack(value)

    def test_rule_pack_rejects_unknown_parent(self):
        value = {"schemaVersion": 1, "version": "2026.08.1", "rules": [raw_rule(parentRuleId="HostDown")]}
        with self.assertRaisesRegex(RulePackError, "unknown parent"):
            parse_rule_pack(value)

    def test_rule_pack_rejects_parent_cycle(self):
        parent = raw_rule(id="HostDown", parentRuleId="CpuUsageHigh")
        child = raw_rule(parentRuleId="HostDown")
        value = {"schemaVersion": 1, "version": "2026.08.1", "rules": [parent, child]}
        with self.assertRaisesRegex(RulePackError, "cycle"):
            parse_rule_pack(value)

    def test_rule_pack_load_is_bounded_and_does_not_follow_symlink(self):
        value = {"schemaVersion": 1, "version": "2026.08.1", "rules": [raw_rule()]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "rules.json"
            target.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(load_rule_pack(target).rules[0].rule_id, "CpuUsageHigh")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(RulePackError):
                load_rule_pack(link)

    def test_breach_requires_all_configured_samples(self):
        state = None
        phases = []
        transitions = []
        for index in range(3):
            state, transition = evaluate_observation(
                rule(), Observation("host-a", 95), state, NOW + dt.timedelta(minutes=index),
            )
            phases.append(state["phase"])
            transitions.append(transition)
        self.assertEqual(phases, ["pending", "pending", "firing"])
        self.assertEqual(transitions, ["pending", None, "firing"])
        self.assertEqual(state["openedAt"], "2026-08-30T12:00:00Z")

    def test_elapsed_duration_prevents_fast_evaluation_from_firing_early(self):
        alert_rule = rule(for_samples=2, for_seconds=120)
        state = None
        for seconds in (0, 30, 60, 90):
            state, _ = evaluate_observation(
                alert_rule,
                Observation("host-a", 95),
                state,
                NOW + dt.timedelta(seconds=seconds),
            )
            self.assertEqual(state["phase"], "pending")
        state, transition = evaluate_observation(
            alert_rule,
            Observation("host-a", 95),
            state,
            NOW + dt.timedelta(seconds=120),
        )
        self.assertEqual((state["phase"], transition), ("firing", "firing"))
        self.assertEqual(state["conditionStartedAt"], "2026-08-30T12:00:00Z")

    def test_evaluation_interval_change_resets_pending_duration(self):
        original = rule(for_samples=2, for_seconds=120, evaluation_interval_seconds=60)
        changed = rule(for_samples=2, for_seconds=120, evaluation_interval_seconds=30)
        state, _ = evaluate_observation(original, Observation("host-a", 95), None, NOW)
        state, _ = evaluate_observation(
            original, Observation("host-a", 95), state, NOW + dt.timedelta(seconds=60)
        )
        state, transition = evaluate_observation(
            changed, Observation("host-a", 95), state, NOW + dt.timedelta(seconds=90)
        )
        self.assertEqual((state["phase"], transition), ("pending", "pending"))
        self.assertEqual(state["breachSamples"], 1)
        self.assertEqual(state["conditionStartedAt"], "2026-08-30T12:01:30Z")

    def test_recovery_requires_elapsed_duration_as_well_as_samples(self):
        alert_rule = rule(
            for_samples=1,
            for_seconds=0,
            recovery_samples=2,
            recovery_seconds=120,
        )
        state, _ = evaluate_observation(
            alert_rule, Observation("host-a", 95), None, NOW
        )
        for seconds in (30, 60, 90):
            state, _ = evaluate_observation(
                alert_rule,
                Observation("host-a", 75),
                state,
                NOW + dt.timedelta(seconds=seconds),
            )
            self.assertEqual(state["phase"], "recovering")
        state, transition = evaluate_observation(
            alert_rule,
            Observation("host-a", 75),
            state,
            NOW + dt.timedelta(seconds=150),
        )
        self.assertEqual((state["phase"], transition), ("inactive", "resolved"))

    def test_missing_sample_does_not_advance_pending_breach(self):
        state, _ = evaluate_observation(rule(), Observation("host-a", 95), None, NOW)
        state, transition = evaluate_observation(
            rule(), Observation("host-a", None, "stale"), state, NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual(state["phase"], "no_data")
        self.assertEqual(state["breachSamples"], 0)
        self.assertEqual(transition, "no_data")

    def test_long_evaluation_gap_resets_pending_duration(self):
        state, _ = evaluate_observation(rule(), Observation("host-a", 95), None, NOW)
        state, transition = evaluate_observation(
            rule(),
            Observation("host-a", 95),
            state,
            NOW + dt.timedelta(minutes=5),
        )
        self.assertEqual(state["phase"], "pending")
        self.assertEqual(state["breachSamples"], 1)
        self.assertEqual(state["changedAt"], "2026-08-30T12:05:00Z")
        self.assertEqual(transition, "pending")

    def test_missing_sample_never_silently_resolves_an_active_alert(self):
        active_rule = rule(for_samples=1, recovery_samples=2)
        firing, _ = evaluate_observation(active_rule, Observation("host-a", 95), None, NOW)
        missing, transition = evaluate_observation(
            active_rule,
            Observation("host-a", None, "stale"),
            firing,
            NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual(missing["phase"], "firing")
        self.assertEqual(missing["openedAt"], firing["openedAt"])
        self.assertEqual(missing["observationStatus"], "stale")
        self.assertIsNone(transition)
        recovering, transition = evaluate_observation(
            active_rule,
            Observation("host-a", 75),
            missing,
            NOW + dt.timedelta(minutes=2),
        )
        self.assertEqual((recovering["phase"], transition), ("recovering", "recovering"))

    def test_permission_loss_preserves_active_incident_until_valid_recovery(self):
        active_rule = rule(for_samples=1, recovery_samples=1)
        firing, _ = evaluate_observation(active_rule, Observation("host-a", 95), None, NOW)
        denied, transition = evaluate_observation(
            active_rule,
            Observation("host-a", None, "permission_denied"),
            firing,
            NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual(denied["phase"], "firing")
        self.assertEqual(denied["observationStatus"], "permission_denied")
        self.assertIsNone(transition)
        resolved, transition = evaluate_observation(
            active_rule,
            Observation("host-a", 75),
            denied,
            NOW + dt.timedelta(minutes=2),
        )
        self.assertEqual((resolved["phase"], transition), ("inactive", "resolved"))

    def test_missing_active_target_is_carried_until_valid_recovery(self):
        active_rule = rule(for_samples=1, recovery_samples=1)
        pack = RulePack(1, "2026.08.1", (active_rule,))
        firing, _ = evaluate_observation(
            active_rule, Observation("container/service-a", 95), None, NOW,
        )
        state_key = "CpuUsageHigh:container/service-a"

        carried, events = evaluate_rule_pack(
            pack, {}, {state_key: firing}, NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual(carried[state_key]["phase"], "firing")
        self.assertEqual(carried[state_key]["observationStatus"], "no_data")
        self.assertEqual(carried[state_key]["openedAt"], firing["openedAt"])
        self.assertEqual(events, [])

        recovered, events = evaluate_rule_pack(
            pack,
            {"CpuUsageHigh": [Observation("container/service-a", 75)]},
            carried,
            NOW + dt.timedelta(minutes=2),
        )
        self.assertEqual(recovered[state_key]["phase"], "inactive")
        self.assertEqual([event["transition"] for event in events], ["resolved"])

    def test_missing_active_target_preserves_uniform_source_failure_status(self):
        active_rule = rule(for_samples=1, recovery_samples=1)
        pack = RulePack(1, "2026.08.1", (active_rule,))
        firing, _ = evaluate_observation(
            active_rule, Observation("container/service-a", 95), None, NOW,
        )
        state_key = "CpuUsageHigh:container/service-a"

        for status in ("stale", "permission_denied", "collection_error"):
            with self.subTest(status=status):
                carried, events = evaluate_rule_pack(
                    pack,
                    {"CpuUsageHigh": [Observation("host/node-a", None, status)]},
                    {state_key: firing},
                    NOW + dt.timedelta(minutes=1),
                )
                self.assertEqual(carried[state_key]["phase"], "firing")
                self.assertEqual(carried[state_key]["observationStatus"], status)
                self.assertEqual(events, [])

    def test_hysteresis_requires_recovery_samples(self):
        active = {
            "phase": "firing", "breachSamples": 3, "recoverySamples": 0,
            "missingSamples": 0, "openedAt": "2026-08-30T11:00:00Z", "changedAt": "2026-08-30T11:00:00Z",
        }
        recovering, transition = evaluate_observation(rule(), Observation("host-a", 75), active, NOW)
        self.assertEqual((recovering["phase"], transition), ("recovering", "recovering"))
        resolved, transition = evaluate_observation(
            rule(), Observation("host-a", 75), recovering, NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual((resolved["phase"], transition), ("inactive", "resolved"))

    def test_equality_rule_recovers_at_explicit_healthy_value(self):
        alert_rule = rule(
            operator="eq", threshold=1, recovery_threshold=0,
            for_samples=1, recovery_samples=1,
        )
        firing, _ = evaluate_observation(alert_rule, Observation("host-a", 1), None, NOW)
        resolved, transition = evaluate_observation(
            alert_rule, Observation("host-a", 0), firing, NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual((resolved["phase"], transition), ("inactive", "resolved"))

    def test_no_data_has_independent_duration(self):
        alert_rule = rule(no_data_policy="alert", no_data_samples=2)
        first, _ = evaluate_observation(alert_rule, Observation("host-a", None, "no_data"), None, NOW)
        second, transition = evaluate_observation(
            alert_rule, Observation("host-a", None, "no_data"), first, NOW + dt.timedelta(minutes=1),
        )
        self.assertEqual(first["phase"], "no_data")
        self.assertEqual((second["phase"], transition), ("firing", "firing"))

    def test_permission_and_unsupported_are_not_faults(self):
        permission, _ = evaluate_observation(rule(), Observation("host-a", None, "permission_denied"), None, NOW)
        unsupported, _ = evaluate_observation(rule(), Observation("host-a", None, "unsupported"), None, NOW)
        self.assertEqual(permission["phase"], "permission_denied")
        self.assertEqual(unsupported["phase"], "unsupported")

    def test_events_are_idempotent_and_silence_affects_delivery_only(self):
        alert_rule = rule(for_samples=1)
        pack = RulePack(1, "2026.08.1", (alert_rule,))
        silence = Silence(
            "maintenance-1", NOW - dt.timedelta(minutes=1), NOW + dt.timedelta(hours=1),
            rule_id="CpuUsageHigh", target="host-a",
        )
        states, events = evaluate_rule_pack(
            pack, {"CpuUsageHigh": [Observation("host-a", 99)]}, {}, NOW, [silence],
        )
        self.assertEqual(events[0]["notificationState"], "silenced")
        states_again, events_again = evaluate_rule_pack(
            pack, {"CpuUsageHigh": [Observation("host-a", 99)]}, states, NOW + dt.timedelta(minutes=1), [silence],
        )
        self.assertEqual(events_again, [])
        self.assertEqual(states_again["CpuUsageHigh:host-a"]["phase"], "firing")
        recovering_states, recovering_events = evaluate_rule_pack(
            pack,
            {"CpuUsageHigh": [Observation("host-a", 70)]},
            states_again,
            NOW + dt.timedelta(minutes=2),
            [silence],
        )
        self.assertEqual(recovering_events, [])
        _resolved_states, resolved_events = evaluate_rule_pack(
            pack,
            {"CpuUsageHigh": [Observation("host-a", 70)]},
            recovering_states,
            NOW + dt.timedelta(minutes=3),
            [silence],
        )
        self.assertEqual(resolved_events[0]["notificationState"], "silenced")

    def test_parent_firing_suppresses_child_notification(self):
        parent = rule(rule_id="HostDown", metric="host.heartbeat.age", for_samples=1)
        child = rule(
            rule_id="ContainerDown", metric="container.running", operator="lte",
            threshold=0, recovery_threshold=1, for_samples=1, parent_rule_id="HostDown",
        )
        pack = RulePack(1, "2026.08.1", (parent, child))
        _states, events = evaluate_rule_pack(pack, {
            "HostDown": [Observation("host-a", 120)],
            "ContainerDown": [Observation("host-a", 0)],
        }, {}, NOW)
        by_rule = {event["ruleId"]: event for event in events}
        self.assertEqual(by_rule["HostDown"]["notificationState"], "ready")
        self.assertEqual(by_rule["ContainerDown"]["notificationState"], "suppressed")

    def test_parent_target_label_suppresses_container_target(self):
        parent = rule(rule_id="HostDown", metric="host.heartbeat.age", for_samples=1)
        child = rule(
            rule_id="ContainerDown", metric="container.running", operator="lte",
            threshold=0, recovery_threshold=1, for_samples=1, parent_rule_id="HostDown",
        )
        pack = RulePack(1, "2026.08.1", (parent, child))
        _states, events = evaluate_rule_pack(pack, {
            "HostDown": [Observation("host-a", 120)],
            "ContainerDown": [Observation("container-a", 0, labels=(("parent_target", "host-a"),))],
        }, {}, NOW)
        by_rule = {event["ruleId"]: event for event in events}
        self.assertEqual(by_rule["ContainerDown"]["notificationState"], "suppressed")

    def test_parent_recovery_releases_still_firing_child_exactly_once(self):
        parent = rule(
            rule_id="HostDown", metric="host.heartbeat.age",
            for_samples=1, recovery_samples=1,
        )
        child = rule(
            rule_id="ContainerDown", metric="container.running", operator="lte",
            threshold=0, recovery_threshold=1, for_samples=1,
            parent_rule_id="HostDown",
        )
        pack = RulePack(1, "2026.08.1", (parent, child))
        states, firing_events = evaluate_rule_pack(pack, {
            "HostDown": [Observation("host-a", 120)],
            "ContainerDown": [Observation("host-a", 0)],
        }, {}, NOW)
        suppressed = next(
            event for event in firing_events if event["ruleId"] == "ContainerDown"
        )
        self.assertEqual(suppressed["notificationState"], "suppressed")

        states, recovery_events = evaluate_rule_pack(
            pack,
            {
                "HostDown": [Observation("host-a", 0)],
                "ContainerDown": [Observation("host-a", 0)],
            },
            states,
            NOW + dt.timedelta(minutes=1),
        )
        states_with_lifecycle = {
            **states,
            "ContainerDown:host-a": {
                **states["ContainerDown:host-a"],
                "notificationState": "suppressed",
                "notificationLabels": suppressed["labels"],
            },
        }
        recovery_events.extend(release_notification_events(
            pack,
            states_with_lifecycle,
            NOW + dt.timedelta(minutes=1),
        ))
        child_releases = [
            event for event in recovery_events
            if event["ruleId"] == "ContainerDown"
        ]
        self.assertEqual(len(child_releases), 1)
        self.assertEqual(
            (child_releases[0]["transition"], child_releases[0]["notificationState"]),
            ("firing", "ready"),
        )
        self.assertEqual(child_releases[0]["openedAt"], suppressed["openedAt"])
        self.assertNotEqual(
            child_releases[0]["idempotencyKey"], suppressed["idempotencyKey"]
        )

        states_with_lifecycle["ContainerDown:host-a"]["notificationState"] = "ready"
        repeated_events = release_notification_events(
            pack, states_with_lifecycle, NOW + dt.timedelta(minutes=2),
        )
        self.assertEqual(repeated_events, [])

    def test_runtime_labels_are_bounded(self):
        pack = RulePack(1, "2026.08.1", (rule(for_samples=1),))
        with self.assertRaisesRegex(ValueError, "invalid label"):
            evaluate_rule_pack(
                pack,
                {"CpuUsageHigh": [Observation("host-a", 99, labels=(("bad key", "secret"),))]},
                {},
                NOW,
            )

    def test_event_contains_no_raw_observation_metadata(self):
        pack = RulePack(1, "2026.08.1", (rule(for_samples=1),))
        _states, events = evaluate_rule_pack(
            pack, {"CpuUsageHigh": [Observation("host-a", 99, labels=(("environment", "prod"),))]}, {}, NOW,
        )
        self.assertRegex(events[0]["idempotencyKey"], r"^[a-f0-9]{64}$")
        self.assertEqual(events[0]["labels"], {"scope": "host", "environment": "prod"})
        self.assertNotIn("command", events[0])


if __name__ == "__main__":
    unittest.main()
