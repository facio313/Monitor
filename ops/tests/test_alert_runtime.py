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
            "host": {"hostname": "node-a", "logicalCpuCount": 4},
            "latest": {
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
        }

    def test_current_signals_are_extracted_without_mount_path_leak(self):
        observations = observations_for_snapshot(self.pack, self.snapshot())
        self.assertEqual(observations["CpuUsageHigh"][0].value, 95)
        self.assertEqual(observations["LoadPerCoreHigh"][0].value, 2)
        self.assertEqual(observations["MemoryAvailableLow"][0].value, 8)
        self.assertTrue(observations["DiskUsageCritical"][0].target.startswith("filesystem/"))
        self.assertNotIn("private", observations["DiskUsageCritical"][0].target)
        self.assertEqual(observations["ContainerDown"][0].value, 1)
        self.assertEqual(observations["ContainerNoHealthcheck"][0].value, 0)

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
        self.assertEqual(observations["TcpRetransmissionHigh"][0].status, "unsupported")
        self.assertEqual(observations["DatabaseEndpointDown"][0].status, "unsupported")

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
