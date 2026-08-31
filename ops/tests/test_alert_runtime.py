import datetime as dt
import sys
import unittest
from pathlib import Path

OPS_ROOT = Path(__file__).parents[1]
if str(OPS_ROOT) not in sys.path:
    sys.path.insert(0, str(OPS_ROOT))

from alert_engine import load_rule_pack
from alert_runtime import evaluate_snapshot, observations_for_snapshot


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


class AlertRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = load_rule_pack(OPS_ROOT / "rules" / "default-rules.v1.json")

    def snapshot(self):
        return {
            "identity": {
                "hostId": "11111111-1111-4111-8111-111111111111",
            },
            "host": {"hostname": "node-a", "logicalCpuCount": 4},
            "generatedAt": "2026-08-30T12:00:00Z",
            "heartbeat": {
                "observedAt": "2026-08-30T11:59:30Z",
                "receivedAt": "2026-08-30T11:59:40Z",
                "lifecycle": "active",
            },
            "latest": {
                "timestamp": "2026-08-30T12:00:00Z",
                "cpuPercent": 95,
                "memoryPercent": 92,
                "swapPercent": 5,
                "load1": 8,
                "cpuPressureSomeAvg10": 22,
                "memoryPressureSomeAvg10": 12,
                "temperatureC": 82,
                "throttledFlags": 5,
                "networkRxErrorsPerSecond": 1,
                "networkTxErrorsPerSecond": 0,
                "networkRxDroppedPerSecond": 0,
                "networkTxDroppedPerSecond": 0,
            },
            "disks": [{
                "mount": "/private/path", "usedPercent": 96,
                "inodeUsedPercent": 91, "readOnly": False,
            }],
            "containers": [{
                "name": "monitor",
                "project": "monitor",
                "state": "running",
                "health": "healthy",
                "healthcheckConfigured": True,
                "cpuPercent": 75,
                "memoryBytes": 90,
                "memoryPercent": 90,
                "memoryLimitBytes": 100,
                "cpuLimitCores": 0.75,
                "pidLimit": 128,
                "restartCount": 4,
                "restartCountDelta": 3,
                "oomKilled": True,
                "startedAt": "2026-08-30T11:00:00Z",
                "finishedAt": None,
            }],
            "containerCollection": {"status": "fresh", "observedAt": "2026-08-30T12:00:00Z"},
            "system": {"kernel": {"oomKill": {"count": 0, "lastEventAt": None}}},
            "linux": {
                "cpu": {
                    "status": "supported",
                    "total": {"iowaitPercent": 21, "stealPercent": 11},
                    "load": {"onePerOnlineCpu": 1.75},
                },
                "memory": {
                    "status": "supported",
                    "swapInBytesPerSecond": 40_000_000,
                    "swapOutBytesPerSecond": 20_000_000,
                },
                "blockDevices": {
                    "status": "supported",
                    "items": [{"name": "nvme0n1", "averageLatencyMilliseconds": 60}],
                },
                "tcp": {
                    "status": "supported",
                    "retransmissionPercent": 6,
                    "conntrack": {"status": "supported", "usedPercent": 81},
                },
                "processes": {
                    "status": "supported",
                    "pidUsedPercent": 82,
                    "zombieCount": 12,
                    "systemFileDescriptors": {"status": "supported", "usedPercent": 83},
                },
                "systemd": {
                    "status": "supported",
                    "units": [{
                        "unit": "monitor-collector.service",
                        "activeState": "failed",
                        "result": "failed",
                    }],
                },
                "clock": {
                    "status": "supported",
                    "unexpectedReboot": True,
                    "timeSync": {
                        "status": "supported",
                        "clockDriftMilliseconds": -61_000,
                    },
                },
                "thermal": {
                    "status": "supported",
                    "raspberryPi": {
                        "status": "supported",
                        "currentThrottled": True,
                        "currentUnderVoltage": True,
                    },
                },
            },
            "_monitor": {
                "ingestStatus": "unsupported",
                "ingestLagSeconds": None,
                "metricsQueueStatus": "unsupported",
                "metricsQueueUsedPercent": None,
                "logsQueueStatus": "unsupported",
                "logsQueueUsedPercent": None,
                "storageWriteStatus": "ok",
                "storageWriteFailureDelta": 0,
                "alertEvaluationStatus": "ok",
                "alertEvaluationDelaySeconds": 61,
                "notificationDeliveryStatus": "ok",
                "notificationFinalFailureDelta": 0,
                "monitoringFilesystemStatus": "ok",
                "monitoringFilesystemUsedPercent": 86,
                "externalHeartbeatStatus": "unsupported",
                "externalHeartbeatAvailable": None,
            },
        }

    def test_current_signals_are_extracted_without_mount_path_leak(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        self.assertEqual(observations["CpuUsageHigh"][0].value, 95)
        self.assertEqual(
            observations["CpuUsageHigh"][0].target,
            "host/11111111-1111-4111-8111-111111111111",
        )
        self.assertEqual(observations["LoadPerCoreHigh"][0].value, 1.75)
        self.assertEqual(observations["MemoryAvailableLow"][0].value, 8)
        self.assertTrue(observations["DiskUsageCritical"][0].target.startswith("filesystem/"))
        self.assertNotIn("private", observations["DiskUsageCritical"][0].target)
        self.assertEqual(observations["ContainerDown"][0].value, 1)
        self.assertEqual(observations["ContainerNoHealthcheck"][0].value, 0)
        self.assertEqual(observations["HostDown"][0].value, 20)
        self.assertEqual(observations["AgentHeartbeatMissing"][0].value, 30)
        self.assertEqual(observations["AgentDataStale"][0].value, 0)
        self.assertEqual(observations["AlertEvaluationDelayed"][0].value, 61)
        self.assertEqual(observations["MonitoringDiskUsageHigh"][0].value, 86)
        self.assertEqual(observations["IngestLagHigh"][0].status, "unsupported")

    def test_swap_usage_requires_observed_memory_pressure(self):
        retained = self.snapshot()
        retained["latest"].update({
            "memoryPercent": 43.68,
            "memoryPressureSomeAvg10": 0,
            "memoryPressureFullAvg10": 0,
            "swapPercent": 65.59,
        })
        observation = observations_for_snapshot(
            self.pack, retained,
        )["SwapUsageHigh"][0]
        self.assertEqual((observation.status, observation.value), ("ok", 0))

        for field, threshold in (
            ("memoryPercent", 75),
            ("memoryPressureSomeAvg10", 1),
            ("memoryPressureFullAvg10", 0.2),
        ):
            with self.subTest(field=field):
                pressured = self.snapshot()
                pressured["latest"].update({
                    "memoryPercent": 43.68,
                    "memoryPressureSomeAvg10": 0,
                    "memoryPressureFullAvg10": 0,
                    "swapPercent": 65.59,
                    field: threshold,
                })
                observation = observations_for_snapshot(
                    self.pack, pressured,
                )["SwapUsageHigh"][0]
                self.assertEqual((observation.status, observation.value), ("ok", 65.59))

        no_context = self.snapshot()
        for field in (
            "memoryPercent", "memoryPressureSomeAvg10", "memoryPressureFullAvg10"
        ):
            no_context["latest"].pop(field, None)
        observation = observations_for_snapshot(
            self.pack, no_context,
        )["SwapUsageHigh"][0]
        self.assertEqual(observation.status, "no_data")
        self.assertIsNone(observation.value)

        active_without_swap = self.snapshot()
        active_without_swap["latest"].pop("swapPercent")
        observation = observations_for_snapshot(
            self.pack, active_without_swap,
        )["SwapUsageHigh"][0]
        self.assertEqual(observation.status, "no_data")
        self.assertIsNone(observation.value)

        retained_without_swap = retained.copy()
        retained_without_swap["latest"] = retained["latest"].copy()
        retained_without_swap["latest"].pop("swapPercent")
        observation = observations_for_snapshot(
            self.pack, retained_without_swap,
        )["SwapUsageHigh"][0]
        self.assertEqual((observation.status, observation.value), ("ok", 0))

        legacy = self.snapshot()
        legacy["latest"].update({"memoryPercent": 43.68, "swapPercent": 65.59})
        legacy["latest"].pop("memoryPressureSomeAvg10", None)
        legacy["latest"].pop("memoryPressureFullAvg10", None)
        observation = observations_for_snapshot(
            self.pack, legacy,
        )["SwapUsageHigh"][0]
        self.assertEqual((observation.status, observation.value), ("ok", 0))

    def test_retained_swap_resolves_through_existing_hysteresis(self):
        pressured = self.snapshot()
        pressured["latest"].update({
            "memoryPercent": 75,
            "memoryPressureSomeAvg10": 0,
            "memoryPressureFullAvg10": 0,
            "swapPercent": 65.59,
        })
        state = {}
        swap_rule = next(
            rule for rule in self.pack.rules if rule.rule_id == "SwapUsageHigh"
        )
        for minute in range(swap_rule.for_samples):
            result, _events = evaluate_snapshot(
                self.pack, pressured, state, NOW + dt.timedelta(minutes=minute)
            )
            state = result["states"]
        state_key = "SwapUsageHigh:host/11111111-1111-4111-8111-111111111111"
        self.assertEqual(state[state_key]["phase"], "firing")

        retained = self.snapshot()
        retained["latest"].update({
            "memoryPercent": 43.68,
            "memoryPressureSomeAvg10": 0,
            "memoryPressureFullAvg10": 0,
            "swapPercent": 65.59,
        })
        phases = []
        resolution_events = []
        for offset in range(swap_rule.recovery_samples):
            result, events = evaluate_snapshot(
                self.pack,
                retained,
                state,
                NOW + dt.timedelta(minutes=swap_rule.for_samples + offset),
            )
            state = result["states"]
            phases.append(state[state_key]["phase"])
            resolution_events.extend(
                event for event in events
                if event["ruleId"] == "SwapUsageHigh"
                and event["transition"] == "resolved"
            )
        self.assertEqual(phases, ["recovering", "recovering", "inactive"])
        self.assertEqual(len(resolution_events), 1)

    def test_synthetic_probe_evidence_feeds_http_and_tls_rules_without_deadman_aliasing(self):
        snapshot = self.snapshot()
        snapshot["syntheticProbeCollection"] = {
            "status": "fresh", "observedAt": "2026-08-30T12:00:00Z",
        }
        snapshot["syntheticProbes"] = [
            {
                "id": "public-ready", "status": "ok",
                "checkedAt": "2026-08-30T12:00:00Z", "httpStatus": 200,
                "redirectCount": 0, "latencyMilliseconds": 1500,
                "certificateExpiresAt": "2026-09-19T12:00:00Z",
                "certificateDaysRemaining": 20,
            },
            {
                "id": "bad-certificate", "status": "tls",
                "checkedAt": "2026-08-30T12:00:00Z", "httpStatus": None,
                "redirectCount": 0, "latencyMilliseconds": 25,
                "certificateExpiresAt": None, "certificateDaysRemaining": None,
            },
        ]
        observations = observations_for_snapshot(self.pack, snapshot)
        by_rule = {
            rule_id: {item.target: item for item in observations[rule_id]}
            for rule_id in (
                "HttpEndpointDown", "HttpLatencyHigh",
                "TlsCertificateExpiring", "TlsCertificateInvalid",
            )
        }
        ready = "synthetic/public-ready"
        broken = "synthetic/bad-certificate"
        self.assertEqual(by_rule["HttpEndpointDown"][ready].value, 1)
        self.assertEqual(by_rule["HttpEndpointDown"][broken].value, 0)
        self.assertEqual(by_rule["HttpLatencyHigh"][ready].value, 1500)
        self.assertEqual(by_rule["TlsCertificateExpiring"][ready].value, 20)
        self.assertEqual(by_rule["TlsCertificateInvalid"][ready].value, 0)
        self.assertEqual(by_rule["TlsCertificateInvalid"][broken].value, 1)
        self.assertEqual(by_rule["TlsCertificateExpiring"][broken].status, "no_data")
        self.assertEqual(
            observations["MonitoringServiceUnavailable"][0].status,
            "unsupported",
        )

    def test_synthetic_probe_source_failures_and_unsupported_targets_stay_explicit(self):
        for source, expected in (
            ("stale", "stale"),
            ("unsupported", "unsupported"),
            ("permission-denied", "permission_denied"),
            ("unavailable", "collection_error"),
            ("collection-error", "collection_error"),
        ):
            with self.subTest(source=source):
                snapshot = self.snapshot()
                snapshot["syntheticProbeCollection"] = {
                    "status": source, "observedAt": None,
                }
                snapshot["syntheticProbes"] = []
                observations = observations_for_snapshot(self.pack, snapshot)
                for rule_id in (
                    "HttpEndpointDown", "HttpLatencyHigh",
                    "TlsCertificateExpiring", "TlsCertificateInvalid",
                ):
                    self.assertEqual(observations[rule_id][0].status, expected)

        snapshot = self.snapshot()
        snapshot["syntheticProbeCollection"] = {
            "status": "fresh", "observedAt": "2026-08-30T12:00:00Z",
        }
        snapshot["syntheticProbes"] = [{
            "id": "operator-disabled", "status": "unsupported",
            "checkedAt": "2026-08-30T12:00:00Z", "httpStatus": None,
            "redirectCount": 0, "latencyMilliseconds": 0,
            "certificateExpiresAt": None, "certificateDaysRemaining": None,
        }]
        observations = observations_for_snapshot(self.pack, snapshot)
        for rule_id in (
            "HttpEndpointDown", "HttpLatencyHigh",
            "TlsCertificateExpiring", "TlsCertificateInvalid",
        ):
            self.assertEqual(observations[rule_id][0].status, "unsupported")

    def test_host_alert_identity_survives_rename_and_legacy_snapshots_fall_back(self):
        renamed = self.snapshot()
        renamed["host"]["hostname"] = "renamed-node"
        renamed_target = observations_for_snapshot(
            self.pack, renamed,
        )["CpuUsageHigh"][0].target
        self.assertEqual(
            renamed_target,
            "host/11111111-1111-4111-8111-111111111111",
        )

        legacy = self.snapshot()
        legacy.pop("identity")
        legacy_target = observations_for_snapshot(
            self.pack, legacy,
        )["CpuUsageHigh"][0].target
        self.assertEqual(legacy_target, "host/node-a")

        malformed = self.snapshot()
        malformed["identity"]["hostId"] = "not-a-valid-host-id"
        malformed_target = observations_for_snapshot(
            self.pack, malformed,
        )["CpuUsageHigh"][0].target
        self.assertEqual(malformed_target, "host/node-a")

    def test_container_lifecycle_and_limit_signals_use_authoritative_v2_fields(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        self.assertEqual(observations["ContainerRestartLoop"][0].value, 3)
        self.assertEqual(observations["ContainerOOMKilled"][0].value, 1)
        self.assertEqual(observations["ContainerUnhealthy"][0].value, 1)
        self.assertEqual(observations["ContainerCpuHigh"][0].value, 100)
        self.assertEqual(observations["ContainerMemoryNearLimit"][0].value, 90)
        self.assertEqual(observations["ContainerNoMemoryLimit"][0].value, 0)
        self.assertEqual(observations["ContainerNoCpuLimit"][0].value, 0)
        self.assertIn(("project", "monitor"), observations["ContainerDown"][0].labels)

    def test_container_v3_resources_security_image_and_event_status_feed_rules(self):
        snapshot = self.snapshot()
        snapshot["containers"][0].update({
            "pidCount": 120,
            "cpuThrottledPercent": 25,
            "networkErrorsPerSecond": 1.5,
            "writableLayerBytes": 1_500_000_000,
            "privileged": True,
            "dockerSocketMounted": True,
            "imageDigestDrift": True,
            "usesLatestTag": True,
        })
        snapshot["dockerEventCollection"] = {
            "status": "fresh",
            "observedAt": "2026-08-30T12:00:00Z",
            "cursorAt": "2026-08-30T12:00:00Z",
            "reconnectCount": 1,
            "gapCount": 0,
            "gapDetected": False,
            "logCollectionStatus": "unsupported",
        }
        observations = observations_for_snapshot(self.pack, snapshot)
        expected = {
            "ContainerCpuThrottlingHigh": 25,
            "ContainerPidNearLimit": 93.75,
            "ContainerNetworkErrors": 1.5,
            "ContainerWritableLayerHigh": 1_500_000_000,
            "ContainerPrivileged": 1,
            "ContainerDockerSocketMounted": 1,
            "ContainerImageDigestDrift": 1,
            "ContainerUsingLatestTag": 1,
            "DockerEventStreamDisconnected": 1,
        }
        for rule_id, value in expected.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(observations[rule_id][0].status, "ok")
                self.assertEqual(observations[rule_id][0].value, value)

        snapshot["dockerEventCollection"]["status"] = "unavailable"
        disconnected = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(disconnected["DockerEventStreamDisconnected"][0].value, 0)
        snapshot["dockerEventCollection"]["status"] = "permission-denied"
        denied = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(
            denied["DockerEventStreamDisconnected"][0].status,
            "permission_denied",
        )

    def test_explicit_missing_limits_and_healthcheck_are_configuration_signals(self):
        snapshot = self.snapshot()
        container = snapshot["containers"][0]
        container.update({
            "health": "none",
            "healthcheckConfigured": False,
            "memoryLimitBytes": 0,
            "cpuLimitCores": 0,
        })
        observations = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(observations["ContainerNoMemoryLimit"][0].value, 1)
        self.assertEqual(observations["ContainerNoCpuLimit"][0].value, 1)
        self.assertEqual(observations["ContainerNoHealthcheck"][0].value, 1)
        self.assertEqual(observations["ContainerUnhealthy"][0].status, "unsupported")

    def test_unimplemented_signal_is_explicitly_unsupported(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        self.assertEqual(observations["DiskIoErrors"][0].status, "unsupported")
        self.assertEqual(observations["DatabaseEndpointDown"][0].status, "unsupported")

    def test_detailed_linux_signals_feed_default_host_rules(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        expected = {
            "CpuIowaitHigh": 21,
            "CpuStealHigh": 11,
            "LoadPerCoreHigh": 1.75,
            "SwapThrashing": 60_000_000,
            "DiskLatencyHigh": 60,
            "TcpRetransmissionHigh": 6,
            "ConntrackUsageHigh": 81,
            "FileDescriptorUsageHigh": 83,
            "PidUsageHigh": 82,
            "ZombieProcessesHigh": 12,
            "SystemdServiceFailed": 1,
            "ClockSkewHigh": 61,
            "UnexpectedReboot": 1,
            "RaspberryPiThrottling": 1,
            "RaspberryPiUnderVoltage": 1,
        }
        for rule_id, value in expected.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(observations[rule_id][0].status, "ok")
                self.assertEqual(observations[rule_id][0].value, value)

    def test_hwmon_only_raspberry_pi_flags_do_not_create_false_throttle_normal(self):
        snapshot = self.snapshot()
        raspberry_pi = snapshot["linux"]["thermal"]["raspberryPi"]
        raspberry_pi["currentThrottled"] = None
        raspberry_pi["currentUnderVoltage"] = False
        observations = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(observations["RaspberryPiThrottling"][0].status, "unsupported")
        self.assertIsNone(observations["RaspberryPiThrottling"][0].value)
        self.assertEqual(observations["RaspberryPiUnderVoltage"][0].status, "ok")
        self.assertEqual(observations["RaspberryPiUnderVoltage"][0].value, 0)

    def test_legacy_snapshot_keeps_new_linux_rules_explicitly_unsupported(self):
        snapshot = self.snapshot()
        snapshot.pop("linux")
        observations = observations_for_snapshot(self.pack, snapshot)
        for rule_id in (
            "CpuIowaitHigh", "SwapThrashing", "DiskLatencyHigh",
            "TcpRetransmissionHigh", "FileDescriptorUsageHigh",
            "SystemdServiceFailed", "ClockSkewHigh",
        ):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(observations[rule_id][0].status, "unsupported")

    def test_stale_container_source_never_reuses_last_known_as_current(self):
        snapshot = self.snapshot()
        snapshot["containerCollection"]["status"] = "last-known"
        observations = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(observations["ContainerDown"][0].status, "stale")
        self.assertIsNone(observations["ContainerDown"][0].value)

    def test_permission_denied_is_distinct_from_down(self):
        snapshot = self.snapshot()
        snapshot["containerCollection"]["status"] = "permission-denied"
        observations = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(observations["ContainerDown"][0].status, "permission_denied")
        self.assertEqual(observations["DockerDaemonUnavailable"][0].status, "permission_denied")

    def test_source_failure_status_is_preserved_for_disappeared_active_container(self):
        snapshot = self.snapshot()
        active_snapshot = self.snapshot()
        container_down_rule = next(
            rule for rule in self.pack.rules if rule.rule_id == "ContainerDown"
        )
        active_snapshot["containers"][0]["state"] = "exited"
        state = {}
        for minute in range(container_down_rule.for_samples):
            result, _events = evaluate_snapshot(
                self.pack,
                active_snapshot,
                state,
                NOW + dt.timedelta(minutes=minute),
            )
            state = result["states"]
        state_key = "ContainerDown:container/monitor"
        self.assertEqual(state[state_key]["phase"], "firing")

        snapshot["containers"] = []
        snapshot["containerCollection"]["status"] = "permission-denied"
        result, events = evaluate_snapshot(
            self.pack,
            snapshot,
            state,
            NOW + dt.timedelta(minutes=container_down_rule.for_samples),
        )
        self.assertEqual(result["states"][state_key]["phase"], "firing")
        self.assertEqual(
            result["states"][state_key]["observationStatus"],
            "permission_denied",
        )
        self.assertEqual(events, [])

    def test_missing_collection_contract_never_defaults_to_fresh(self):
        snapshot = self.snapshot()
        snapshot.pop("containerCollection")
        observations = observations_for_snapshot(self.pack, snapshot)
        self.assertEqual(observations["ContainerDown"][0].status, "collection_error")
        self.assertEqual(observations["DockerDaemonUnavailable"][0].value, 0)

    def test_uncollected_container_signals_are_explicitly_unsupported(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        self.assertEqual(observations["ContainerPrivileged"][0].status, "unsupported")
        self.assertIsNone(observations["ContainerPrivileged"][0].value)

    def test_evaluation_reports_complete_rule_coverage(self):
        result, _events = evaluate_snapshot(self.pack, self.snapshot(), {}, NOW)
        self.assertEqual(result["status"], "ok")
        observed_rules = {key.split(":", 1)[0] for key in result["states"]}
        self.assertEqual(observed_rules, {rule.rule_id for rule in self.pack.rules})
        self.assertGreater(result["summary"]["unsupported"], 0)
        cpu_state = next(value for value in result["states"].values() if value["ruleId"] == "CpuUsageHigh")
        self.assertEqual(cpu_state["metric"], "host.cpu.percent")
        self.assertEqual(cpu_state["severity"], "warning")

    def test_persistent_gauge_requires_duration_before_firing(self):
        state = {}
        events = []
        for minute in range(5):
            result, events = evaluate_snapshot(
                self.pack, self.snapshot(), state, NOW + dt.timedelta(minutes=minute),
            )
            state = result["states"]
        self.assertTrue(any(event["ruleId"] == "CpuUsageHigh" for event in events))


if __name__ == "__main__":
    unittest.main()
