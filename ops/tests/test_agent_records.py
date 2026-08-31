import copy
import unittest

from ops.agent_records import (
    AgentRecordError,
    LATEST_KEYS,
    SELF_METRICS_KEYS,
    project_records,
)


HOST_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
OBSERVED = "2026-08-31T00:20:00Z"


def current_snapshot(**latest_changes):
    latest = {name: None for name in LATEST_KEYS}
    latest.update({
        "timestamp": OBSERVED,
        "cpuPercent": 12.5,
        "memoryPercent": 50.0,
        "memoryUsedBytes": 50,
        "memoryTotalBytes": 100,
        "powerState": "normal",
        **latest_changes,
    })
    return {
        "schemaVersion": 2,
        "generatedAt": OBSERVED,
        "identity": {
            "hostId": HOST_ID,
            "agentId": AGENT_ID,
            "installationEpoch": "2026-08-30T00:00:00Z",
            "identityGeneration": 1,
            "machineIdentityStatus": "bound",
            "bootId": "a" * 32,
        },
        "heartbeat": {
            "sequence": 9,
            "observedAt": OBSERVED,
            "receivedAt": OBSERVED,
            "expectedIntervalSeconds": 60,
            "lifecycle": "active",
            "transport": "local-file",
        },
        "host": {},
        "latest": latest,
        "disks": [],
        "containers": [],
        "containerCollection": {},
        "dockerEventCollection": {},
        "dockerEvents": [],
        "currentTraffic": [],
        "reliability": {},
        "system": {},
        "linux": {},
    }


def self_metrics():
    value = {name: None for name in SELF_METRICS_KEYS}
    value.update({
        "schemaVersion": 1,
        "agentId": AGENT_ID,
        "observedAt": "2026-08-31T00:19:59.500Z",
        "runDurationSeconds": 0.25,
        "userCpuSeconds": 0.02,
        "systemCpuSeconds": 0.01,
        "maxRssBytes": 1_048_576,
        "ioReadBytes": 0,
        "ioWriteBytes": 4096,
        "ioReadSyscalls": 3,
        "ioWriteSyscalls": 2,
        "resourceUsageStatus": "available",
        "procIoStatus": "available",
        "priorStateStatus": "valid",
        "outcomes": {
            "enrollment": "not-pending",
            "heartbeat": "acknowledged",
            "ingest": "empty",
        },
        "retryStreaks": {"enrollment": 0, "heartbeat": 0, "ingest": 0},
        "lastHeartbeatAckAt": "2026-08-31T00:19:59.500Z",
        "heartbeatAckAgeSeconds": 0,
        "spool": {
            "entries": 1,
            "bytes": 512,
            "maxEntries": 8,
            "maxBytes": 4096,
            "entriesUsedPercent": 12.5,
            "bytesUsedPercent": 12.5,
            "oldestAgeSeconds": 30,
        },
        "quarantine": {
            "entries": 1,
            "bytes": 256,
            "oldestAgeSeconds": 45,
            "status": "retained",
            "batchTooOldEntries": 0,
            "dataTooOldEntries": 1,
        },
    })
    return value


class AgentRecordTests(unittest.TestCase):
    def test_exact_allowlist_projects_only_fixed_names_and_one_power_event(self):
        snapshot = current_snapshot(powerState="thermal-limit")
        snapshot["containers"] = [{"name": "secret-container", "command": "do-not-export"}]
        source, records = project_records(snapshot, None, self_metrics_status="missing")

        self.assertEqual(source["agentId"], AGENT_ID)
        names = {record["metric"] for record in records}
        self.assertIn("host.cpu.percent", names)
        self.assertIn("host.memory.used_bytes", names)
        self.assertIn("host.power.state", names)
        self.assertIn("agent.self.metrics_available", names)
        self.assertNotIn("secret-container", repr(records))
        power = next(record for record in records if record["metric"] == "host.power.state")
        self.assertEqual(power["kind"], "event")
        self.assertEqual(power["severity"], "critical")

    def test_exact_current_and_latest_schemas_reject_extensions(self):
        extra_top = current_snapshot()
        extra_top["rawLogs"] = []
        with self.assertRaisesRegex(AgentRecordError, "exact schema"):
            project_records(extra_top)

        extra_latest = current_snapshot()
        extra_latest["latest"]["processId"] = 123
        with self.assertRaisesRegex(AgentRecordError, "exact schema"):
            project_records(extra_latest)

        changed_timestamp = current_snapshot()
        changed_timestamp["heartbeat"]["observedAt"] = "2026-08-31T00:19:59Z"
        with self.assertRaisesRegex(AgentRecordError, "atomic snapshot"):
            project_records(changed_timestamp)

    def test_self_metrics_are_exact_identity_bound_and_fixed_prefixes(self):
        source, records = project_records(
            current_snapshot(), self_metrics(), self_metrics_status="valid"
        )
        self.assertEqual(source["sourceSequence"], 9)
        names = {record["metric"] for record in records}
        self.assertIn("agent.self.run_duration_seconds", names)
        self.assertIn("agent.self.heartbeat_outcome_code", names)
        self.assertIn("agent.self.ingest_retry_streak", names)
        self.assertIn("agent.spool.oldest_age_seconds", names)
        self.assertIn("agent.quarantine.data_too_old_entries", names)
        self.assertIn("agent.self.sample_age_seconds", names)
        self.assertTrue(all(
            name.startswith(("host.", "agent.self.", "agent.spool.", "agent.quarantine."))
            for name in names
        ))

        wrong_identity = self_metrics()
        wrong_identity["agentId"] = HOST_ID
        with self.assertRaisesRegex(AgentRecordError, "identity"):
            project_records(
                current_snapshot(), wrong_identity, self_metrics_status="valid"
            )

        extension = copy.deepcopy(self_metrics())
        extension["command"] = "forbidden"
        with self.assertRaisesRegex(AgentRecordError, "exact schema"):
            project_records(current_snapshot(), extension, self_metrics_status="valid")

    def test_missing_corrupt_and_unreadable_statuses_are_explicit_records(self):
        for status, code in (("missing", 1), ("corrupt", 2), ("unreadable", 3)):
            _source, records = project_records(
                current_snapshot(), None, self_metrics_status=status
            )
            by_name = {record["metric"]: record["value"] for record in records}
            self.assertEqual(by_name["agent.self.metrics_available"], 0)
            self.assertEqual(by_name["agent.self.metrics_status_code"], code)

    def test_stale_self_metrics_are_age_marked_and_never_timestamp_the_fresh_batch(self):
        stale = self_metrics()
        stale["observedAt"] = "2026-08-23T00:20:00Z"
        _source, records = project_records(
            current_snapshot(), stale, self_metrics_status="valid"
        )
        by_name = {record["metric"]: record for record in records}
        self.assertEqual(by_name["agent.self.metrics_available"]["value"], 0)
        self.assertEqual(by_name["agent.self.metrics_status_code"]["value"], 4)
        self.assertEqual(by_name["agent.self.sample_age_seconds"]["value"], 8 * 24 * 60 * 60)
        self.assertNotIn("agent.self.run_duration_seconds", by_name)
        self.assertTrue(all(record["observedAt"] == OBSERVED for record in records))


if __name__ == "__main__":
    unittest.main()
