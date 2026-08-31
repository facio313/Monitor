import base64
import gzip
import hashlib
import json
import stat
import tempfile
import unittest
import uuid
from pathlib import Path

from ops.agent_producer import AgentProducer, AgentProducerError, ProducerConfig
from ops.agent_records import LATEST_KEYS, project_records
from ops.agent_transport import AgentTransport, ContractError, SpoolFullError, TransportConfig
from ops.agent_transport.storage import atomic_private_write, canonical_json


NOW_MS = 1_788_135_600_000
HOST_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
OBSERVED = "2026-08-31T00:20:00Z"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class Clock:
    def __init__(self):
        self.value = NOW_MS

    def __call__(self):
        return self.value


class Uuids:
    def __init__(self):
        self.value = 1

    def __call__(self):
        result = uuid.UUID(f"00000000-0000-4000-8000-{self.value:012x}")
        self.value += 1
        return result


class NoNetworkRequester:
    def post(self, endpoint, body, content_encoding):  # pragma: no cover - enqueue never posts
        raise AssertionError(f"unexpected network call to {endpoint}")


def inventory(_version="1.0.0"):
    return {
        "agentVersion": "1.0.0",
        "hostname": "edge-a",
        "ipAddresses": ["192.0.2.10"],
        "operatingSystem": "Linux",
        "ubuntuVersion": "24.04",
        "kernelVersion": "6.8.0-test",
        "architecture": "aarch64",
        "cpuModel": "Test CPU",
        "memoryBytes": 8 * 1024**3,
    }


def current_snapshot(sequence=9, power_state="normal", agent_id=AGENT_ID):
    latest = {name: None for name in LATEST_KEYS}
    latest.update({
        "timestamp": OBSERVED,
        "cpuPercent": 12.5,
        "memoryPercent": 50.0,
        "memoryUsedBytes": 50,
        "memoryTotalBytes": 100,
        "powerState": power_state,
    })
    return {
        "schemaVersion": 2,
        "generatedAt": OBSERVED,
        "identity": {
            "hostId": HOST_ID,
            "agentId": agent_id,
            "installationEpoch": "2026-08-30T00:00:00Z",
            "identityGeneration": 1 if agent_id == AGENT_ID else 2,
            "machineIdentityStatus": "bound",
            "bootId": "a" * 32,
        },
        "heartbeat": {
            "sequence": sequence,
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


class AgentProducerTests(unittest.TestCase):
    def test_example_and_unit_use_the_standard_collector_publication(self):
        example = json.loads(
            (REPOSITORY_ROOT / "ops/agent-producer.example.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            example["collectorCurrentFile"],
            "/var/lib/monitor-export/current.json",
        )
        unit = (REPOSITORY_ROOT / "ops/systemd/monitor-agent-producer.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("ConditionPathExists=/var/lib/monitor-export/current.json", unit)
        self.assertIn("ReadOnlyPaths=/etc/machine-id /var/lib/monitor-export/current.json", unit)
        self.assertNotIn("/var/lib/server-watch/current.json", unit)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cert = self.root / "client.crt"
        self.key = self.root / "client.key"
        self.ca = self.root / "ca.crt"
        self.machine = self.root / "machine-id"
        for path, content, mode in [
            (self.cert, b"test certificate\n", 0o644),
            (self.key, b"test private key\n", 0o600),
            (self.ca, b"test CA\n", 0o644),
            (self.machine, b"0123456789abcdef0123456789abcdef\n", 0o444),
        ]:
            path.write_bytes(content)
            path.chmod(mode)
        self.current = self.root / "current.json"
        self.write_current(current_snapshot())
        self.clock = Clock()
        self.uuids = Uuids()

    def tearDown(self):
        self.temporary.cleanup()

    def write_current(self, value):
        self.current.write_bytes(canonical_json(value))
        self.current.chmod(0o644)

    def transport(self, **changes):
        mapping = {
            "schemaVersion": 1,
            "baseUrl": "https://agents.example.test/monitor/api",
            "stateDirectory": str(self.root / "transport-state"),
            "clientCertificateFile": str(self.cert),
            "clientKeyFile": str(self.key),
            "caCertificateFile": str(self.ca),
            "machineIdentityFile": str(self.machine),
            "agentVersion": "1.0.0",
            "heartbeatIntervalSeconds": 60,
            "lifecycle": "active",
            "requestTimeoutSeconds": 3,
            "maxBatchRecords": 500,
            "maxBatchBytes": 262144,
            "maxSpoolEntries": 8,
            "maxSpoolBytes": 2 * 1024 * 1024,
            "gzipMinimumBytes": 1024,
            "backoffInitialSeconds": 1,
            "backoffMaximumSeconds": 10,
            "retryAfterMaximumSeconds": 300,
        }
        mapping.update(changes)
        return AgentTransport(
            TransportConfig.from_mapping(mapping),
            requester=NoNetworkRequester(),
            now=self.clock,
            jitter=lambda: 0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )

    def producer(self, transport):
        config = ProducerConfig.from_mapping({
            "schemaVersion": 1,
            "collectorCurrentFile": str(self.current),
            "transportConfigFile": str(self.root / "unused-transport.json"),
            "transportSelfMetricsFile": str(transport.self_metrics_path),
            "stateDirectory": str(self.root / "producer-state"),
        })
        return AgentProducer(config, transport=transport)

    @staticmethod
    def batch_body(transport, batch_id):
        envelope = json.loads(
            (transport.spool_directory / f"{batch_id}.batch").read_text()
        )
        encoded = base64.b64decode(envelope["wireBodyBase64"])
        if envelope["contentEncoding"] == "gzip":
            encoded = gzip.decompress(encoded)
        return json.loads(encoded)

    def test_run_seeds_identity_commits_cursor_and_unchanged_source_is_noop(self):
        transport = self.transport()
        producer = self.producer(transport)
        result = producer.run_once()
        self.assertEqual(result.outcome, "queued")
        self.assertEqual(result.source_sequence, 9)
        self.assertEqual(result.self_metrics_status, "missing")
        self.assertFalse(producer.pending_path.exists())
        self.assertTrue(producer.cursor_path.exists())
        self.assertEqual(stat.S_IMODE(producer.cursor_path.stat().st_mode), 0o600)
        status = transport.status()
        self.assertEqual(status["agentId"], AGENT_ID)
        self.assertEqual(status["hostId"], HOST_ID)
        self.assertTrue(status["collectorIdentityBound"])
        next_sequence = status["nextSequence"]

        duplicate = producer.run_once()
        self.assertEqual(duplicate.outcome, "unchanged")
        self.assertEqual(duplicate.batch_ids, result.batch_ids)
        self.assertEqual(transport.status()["nextSequence"], next_sequence)

    def test_config_is_exact_and_requires_private_mode(self):
        mapping = {
            "schemaVersion": 1,
            "collectorCurrentFile": str(self.current),
            "transportConfigFile": str(self.root / "transport.json"),
            "transportSelfMetricsFile": str(self.root / "self-metrics.json"),
            "stateDirectory": str(self.root / "producer-state"),
        }
        with self.assertRaisesRegex(AgentProducerError, "exact schema"):
            ProducerConfig.from_mapping({**mapping, "unknown": True})
        path = self.root / "producer.json"
        path.write_bytes(canonical_json(mapping))
        path.chmod(0o644)
        with self.assertRaisesRegex(AgentProducerError, "unsafe"):
            ProducerConfig.load(path)
        path.chmod(0o600)
        self.assertEqual(ProducerConfig.load(path).collector_current_file, self.current)

    def test_pending_replay_after_enqueue_uses_same_batch_and_sequence(self):
        transport = self.transport()
        producer = self.producer(transport)
        current, source = producer._read_current()
        transport.bind_collector_identity(producer._identity_mapping(source))
        checkpoint = producer._checkpoint(source)
        _source, records = project_records(current, None, self_metrics_status="missing")
        pending = {
            "schemaVersion": 1,
            "installationEpoch": source["installationEpoch"],
            "checkpoint": checkpoint,
            "sourceSha256": hashlib.sha256(canonical_json(current)).hexdigest(),
            "recordsSha256": hashlib.sha256(canonical_json(records)).hexdigest(),
            "records": records,
        }
        atomic_private_write(producer.pending_path, canonical_json(pending), replace=False)
        batch_ids = transport.enqueue(records, checkpoint=checkpoint)
        next_sequence = transport.status()["nextSequence"]
        uuid_cursor = self.uuids.value

        replayed = producer.run_once()
        self.assertEqual(replayed.batch_ids, tuple(batch_ids))
        self.assertEqual(transport.status()["nextSequence"], next_sequence)
        self.assertEqual(self.uuids.value, uuid_cursor)
        self.assertFalse(producer.pending_path.exists())

    def test_spool_full_keeps_pending_and_commits_no_partial_kind_batch(self):
        self.write_current(current_snapshot(power_state="thermal-limit"))
        transport = self.transport(maxSpoolEntries=1)
        producer = self.producer(transport)
        with self.assertRaises(SpoolFullError):
            producer.run_once()
        self.assertTrue(producer.pending_path.exists())
        self.assertFalse(producer.cursor_path.exists())
        self.assertEqual(transport.status()["spoolEntries"], 0)
        self.assertEqual(transport.status()["nextSequence"], 1)

    def test_corrupt_self_metrics_is_explicit_and_does_not_block_checkpoint(self):
        transport = self.transport()
        transport.self_metrics_path.write_text("{}")
        transport.self_metrics_path.chmod(0o600)
        producer = self.producer(transport)
        result = producer.run_once()
        self.assertEqual(result.self_metrics_status, "corrupt")
        body = self.batch_body(transport, result.batch_ids[0])
        projected = {record["metric"]: record["value"] for record in body["records"]}
        self.assertEqual(projected["agent.self.metrics_available"], 0)
        self.assertEqual(projected["agent.self.metrics_status_code"], 2)

    def test_stale_self_metrics_are_explicit_and_cannot_poison_fresh_host_records(self):
        transport = self.transport()
        producer = self.producer(transport)
        producer.bind_identity()
        self.clock.value -= 8 * 24 * 60 * 60 * 1000
        transport.run_once()
        self.clock.value = NOW_MS

        result = producer.run_once()

        self.assertEqual(result.self_metrics_status, "stale")
        body = self.batch_body(transport, result.batch_ids[0])
        projected = {record["metric"]: record for record in body["records"]}
        self.assertEqual(projected["agent.self.metrics_available"]["value"], 0)
        self.assertEqual(projected["agent.self.metrics_status_code"]["value"], 4)
        self.assertEqual(
            projected["agent.self.sample_age_seconds"]["value"],
            8 * 24 * 60 * 60,
        )
        self.assertIn("host.cpu.percent", projected)
        fresh_at = projected["host.cpu.percent"]["observedAt"]
        self.assertTrue(all(record["observedAt"] == fresh_at for record in body["records"]))

    def test_changed_collector_identity_fails_without_advancing_cursor(self):
        transport = self.transport()
        producer = self.producer(transport)
        producer.run_once()
        cursor = producer.cursor_path.read_bytes()
        self.write_current(current_snapshot(
            sequence=1, agent_id="33333333-3333-4333-8333-333333333333"
        ))
        with self.assertRaisesRegex((AgentProducerError, ContractError), "identity|conflict"):
            producer.run_once()
        self.assertEqual(producer.cursor_path.read_bytes(), cursor)

    def test_changed_snapshot_without_new_source_sequence_conflicts(self):
        transport = self.transport()
        producer = self.producer(transport)
        producer.run_once()
        next_sequence = transport.status()["nextSequence"]
        changed = current_snapshot()
        changed["latest"]["cpuPercent"] = 99.0
        self.write_current(changed)
        with self.assertRaisesRegex(AgentProducerError, "changed without a new sequence"):
            producer.run_once()
        self.assertEqual(transport.status()["nextSequence"], next_sequence)

    def test_units_are_distinct_bounded_and_not_installed_by_default(self):
        root = Path(__file__).resolve().parents[2]
        service = (root / "ops/systemd/monitor-agent-producer.service").read_text()
        timer = (root / "ops/systemd/monitor-agent-producer.timer").read_text()
        installer = (root / "ops/install.sh").read_text()
        self.assertIn("ConditionPathExists=/etc/monitor-agent/producer.json", service)
        self.assertIn("MemoryMax=96M", service)
        self.assertIn("ReadWritePaths=/var/lib/monitor-agent /var/lib/monitor-agent-producer", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX\n", service)
        self.assertIn("OnUnitInactiveSec=15s", timer)
        self.assertNotIn("monitor-agent-producer", installer)


if __name__ == "__main__":
    unittest.main()
