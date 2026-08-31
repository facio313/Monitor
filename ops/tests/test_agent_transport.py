import base64
import gzip
import io
import json
import os
import stat
import tempfile
import tracemalloc
import unittest
import uuid
from pathlib import Path
from unittest import mock

from ops.agent_transport import (
    AgentTransport,
    AgentTransportError,
    ConfigError,
    ContractError,
    HttpResponse,
    SpoolFullError,
    TransportConfig,
)
from ops.agent_transport.__main__ import _read_records
from ops.agent_transport.config import (
    MAX_ENQUEUE_BYTES,
    MAX_ENQUEUE_RECORDS,
    MAX_SPOOL_BYTES,
    MAX_SPOOL_ENTRIES,
)
from ops.agent_transport.storage import (
    DEFAULT_LOCK_TIMEOUT_SECONDS,
    StorageError,
    atomic_private_write,
    canonical_json,
    ensure_private_directory,
    exclusive_lock,
    fsync_directory,
)
from ops.agent_transport.transport import HttpsRequester, MAX_SAFE_INTEGER


NOW_MS = 1_788_135_600_000  # 2026-08-31T00:20:00.000Z
TOKEN = "menr_" + "a" * 32 + "." + "B" * 43


def inventory(_version="1.0.0"):
    return {
        "agentVersion": "1.0.0",
        "hostname": "edge-a",
        "ipAddresses": ["192.0.2.10", "2001:db8::10"],
        "operatingSystem": "Linux",
        "ubuntuVersion": "24.04",
        "kernelVersion": "6.8.0-test",
        "architecture": "aarch64",
        "cpuModel": "Test CPU",
        "memoryBytes": 8 * 1024**3,
    }


def metric(observed_at="2026-08-31T00:20:00Z", value=1.0):
    return {
        "kind": "metric",
        "metric": "host.cpu.percent",
        "target": "host/primary",
        "observedAt": observed_at,
        "value": value,
        "severity": None,
    }


def event(observed_at="2026-08-31T00:20:00Z"):
    return {
        "kind": "event",
        "metric": "host.power.state",
        "target": "host/primary",
        "observedAt": observed_at,
        "value": None,
        "severity": "warning",
    }


def collector_binding():
    return {
        "hostId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "agentId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "installationEpoch": "2026-08-30T00:00:00Z",
        "identityGeneration": 1,
    }


def checkpoint(sequence=9):
    binding = collector_binding()
    return {
        "schemaVersion": 1,
        "hostId": binding["hostId"],
        "agentId": binding["agentId"],
        "identityGeneration": binding["identityGeneration"],
        "sourceSequence": sequence,
        "observedAt": "2026-08-31T00:20:00Z",
    }


class Clock:
    def __init__(self, value=NOW_MS):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, milliseconds):
        self.value += milliseconds


class Uuids:
    def __init__(self):
        self.value = 1

    def __call__(self):
        value = uuid.UUID(f"00000000-0000-4000-8000-{self.value:012x}")
        self.value += 1
        return value


class FakeRequester:
    def __init__(self):
        self.calls = []
        self.outcomes = {"/agent/enroll": [], "/agent/heartbeat": [], "/agent/ingest": []}

    def queue(self, endpoint, *outcomes):
        self.outcomes[endpoint].extend(outcomes)

    def post(self, endpoint, body, content_encoding):
        self.calls.append((endpoint, bytes(body), content_encoding))
        queued = self.outcomes[endpoint]
        if queued:
            outcome = queued.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            if callable(outcome):
                return outcome(body, content_encoding)
            return outcome
        if content_encoding == "gzip":
            decoded = gzip.decompress(body)
        else:
            decoded = body
        request = json.loads(decoded)
        if endpoint == "/agent/enroll":
            response = {
                "registered": True,
                "agentId": request["agentId"],
                "hostId": request["hostId"],
                "serverTime": "2026-08-31T00:20:00.000Z",
            }
            return HttpResponse(201, {}, canonical_json(response))
        if endpoint == "/agent/heartbeat":
            return HttpResponse(
                200,
                {},
                canonical_json({"accepted": True, "serverTime": "2026-08-31T00:20:00.000Z"}),
            )
        response = {
            "accepted": True,
            "batchId": request["batchId"],
            "acceptedRecords": len(request["records"]),
            "duplicateRecords": 0,
            "serverTime": "2026-08-31T00:20:00.000Z",
        }
        return HttpResponse(202, {}, canonical_json(response))


class AgentTransportTests(unittest.TestCase):
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
        self.clock = Clock()
        self.requester = FakeRequester()
        self.uuids = Uuids()

    def tearDown(self):
        self.temporary.cleanup()

    def mapping(self, **changes):
        value = {
            "schemaVersion": 1,
            "baseUrl": "https://agents.example.test/monitor/api",
            "stateDirectory": str(self.root / "state"),
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
        value.update(changes)
        return value

    def transport(self, **changes):
        config = TransportConfig.from_mapping(self.mapping(**changes))
        return AgentTransport(
            config,
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )

    def enroll(self, transport):
        result = transport.begin_enrollment(bytearray(TOKEN.encode()))
        self.assertEqual(result, "acknowledged")

    def test_config_is_exact_and_private_key_must_be_mode_0600(self):
        with self.assertRaisesRegex(ConfigError, "exact schema"):
            TransportConfig.from_mapping({**self.mapping(), "unknown": True})
        config_file = self.root / "transport.json"
        config_file.write_bytes(canonical_json(self.mapping()))
        config_file.chmod(0o600)
        parsed = TransportConfig.load(config_file)
        self.key.chmod(0o640)
        with self.assertRaisesRegex(ConfigError, "0600"):
            parsed.validate_credentials()

    def test_foreign_owned_mode_0700_ancestor_rejects_config_and_credentials(self):
        outer = self.root / "foreign-owned"
        credential_directory = outer / "credentials"
        credential_directory.mkdir(parents=True)
        outer.chmod(0o700)
        credential_directory.chmod(0o700)
        credential_paths = {
            "clientCertificateFile": credential_directory / "client.crt",
            "clientKeyFile": credential_directory / "client.key",
            "caCertificateFile": credential_directory / "ca.crt",
        }
        for name, path in credential_paths.items():
            path.write_bytes(name.encode("ascii"))
            path.chmod(0o600 if name == "clientKeyFile" else 0o644)
        config_file = credential_directory / "transport.json"
        config_file.write_bytes(canonical_json(self.mapping()))
        config_file.chmod(0o600)
        config = TransportConfig.from_mapping(
            self.mapping(**{name: str(path) for name, path in credential_paths.items()})
        )

        outer.chmod(0o770)
        with self.assertRaisesRegex(ConfigError, "group/world replacement"):
            config.validate_credentials()
        outer.chmod(0o700)

        original_lstat = os.lstat
        foreign_uid = next(uid for uid in (1, 2, 65534) if uid not in {0, os.geteuid()})

        def foreign_owned_ancestor(candidate):
            status = original_lstat(candidate)
            if Path(candidate) == outer:
                fields = list(status)
                fields[stat.ST_UID] = foreign_uid
                return os.stat_result(fields)
            return status

        with mock.patch(
            "ops.agent_transport.config.os.lstat", side_effect=foreign_owned_ancestor
        ):
            with self.assertRaisesRegex(ConfigError, "root or the effective service uid"):
                TransportConfig.load(config_file)
            with self.assertRaisesRegex(ConfigError, "root or the effective service uid"):
                config.validate_credentials()

    def test_foreign_owned_mode_0700_state_parent_is_rejected_before_creation(self):
        foreign_parent = self.root / "foreign-state-parent"
        foreign_parent.mkdir(mode=0o700)
        state_directory = foreign_parent / "state"
        original_lstat = os.lstat
        foreign_uid = next(uid for uid in (1, 2, 65534) if uid not in {0, os.geteuid()})

        def foreign_owned_ancestor(candidate):
            status = original_lstat(candidate)
            if Path(candidate) == foreign_parent:
                fields = list(status)
                fields[stat.ST_UID] = foreign_uid
                return os.stat_result(fields)
            return status

        with mock.patch(
            "ops.agent_transport.config.os.lstat", side_effect=foreign_owned_ancestor
        ):
            with self.assertRaisesRegex(StorageError, "root or the effective service uid"):
                self.transport(stateDirectory=str(state_directory))
        self.assertFalse(state_directory.exists())

    def test_state_parent_replacement_policy_rejects_nonsticky_and_allows_sticky(self):
        replaceable = self.root / "replaceable-state-parent"
        replaceable.mkdir(mode=0o770)
        replaceable.chmod(0o770)
        rejected_state = replaceable / "state"
        with self.assertRaisesRegex(StorageError, "group/world replacement"):
            self.transport(stateDirectory=str(rejected_state))
        self.assertFalse(rejected_state.exists())

        sticky = self.root / "sticky-state-parent"
        sticky.mkdir(mode=0o1700)
        sticky.chmod(0o1777)
        accepted_state = sticky / "state"
        transport = self.transport(stateDirectory=str(accepted_state))
        self.assertEqual(transport.config.state_directory, accepted_state)
        self.assertEqual(stat.S_IMODE(accepted_state.stat().st_mode), 0o700)

    def test_bound_state_root_rejects_real_directory_rollback(self):
        old_state = self.root / "old-state"
        current_state = self.root / "current-state"
        old_transport = self.transport(stateDirectory=str(old_state))
        current_transport = self.transport(stateDirectory=str(current_state))
        self.assertNotEqual(
            old_transport.status()["agentId"], current_transport.status()["agentId"]
        )

        retained_current = self.root / "current-state-retained"
        current_state.rename(retained_current)
        old_state.rename(current_state)
        with self.assertRaisesRegex(StorageError, "changed identity"):
            current_transport.status()

    def test_bound_spool_rejects_rename_to_symlink(self):
        transport = self.transport()
        retained_spool = self.root / "spool-retained"
        transport.spool_directory.rename(retained_spool)
        transport.spool_directory.symlink_to(retained_spool, target_is_directory=True)

        with self.assertRaisesRegex(StorageError, "owner-owned, non-linked"):
            transport.status()

    def test_directory_binding_rejects_rename_to_symlink_during_open(self):
        target = self.root / "bind-race"
        target.mkdir(mode=0o700)
        retained = self.root / "bind-race-retained"
        original_open = os.open
        replaced = False

        def replace_before_open(path, flags, *args, **kwargs):
            nonlocal replaced
            if Path(path) == target and not replaced:
                replaced = True
                target.rename(retained)
                target.symlink_to(retained, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)

        with mock.patch(
            "ops.agent_transport.storage.os.open", side_effect=replace_before_open
        ):
            with self.assertRaisesRegex(StorageError, "safely bind|changed while it was bound"):
                ensure_private_directory(target, create=False)
        self.assertTrue(replaced)

    def test_https_sink_rejects_rename_to_symlink_after_earlier_validation(self):
        original = self.root / "credential-slot"
        substitute = self.root / "substitute-credentials"
        for directory, marker in ((original, b"original"), (substitute, b"substitute")):
            directory.mkdir(mode=0o700)
            for name, mode in (
                ("client.crt", 0o644),
                ("client.key", 0o600),
                ("ca.crt", 0o644),
            ):
                path = directory / name
                path.write_bytes(marker + b" " + name.encode("ascii"))
                path.chmod(mode)
        config = TransportConfig.from_mapping(
            self.mapping(
                clientCertificateFile=str(original / "client.crt"),
                clientKeyFile=str(original / "client.key"),
                caCertificateFile=str(original / "ca.crt"),
            )
        )
        config.validate_credentials()

        retained = self.root / "credential-slot-retained"
        original.rename(retained)
        original.symlink_to(substitute, target_is_directory=True)
        with mock.patch("ops.agent_transport.transport.ssl.SSLContext") as context_factory:
            with self.assertRaisesRegex(ConfigError, "must be a real directory"):
                HttpsRequester(config)
        context_factory.assert_not_called()

    def test_machine_identity_rejects_rename_to_symlink_component(self):
        original = self.root / "machine-slot"
        substitute = self.root / "substitute-machine"
        original.mkdir(mode=0o700)
        substitute.mkdir(mode=0o700)
        original_identity = original / "machine-id"
        substitute_identity = substitute / "machine-id"
        original_identity.write_bytes(b"0123456789abcdef0123456789abcdef\n")
        substitute_identity.write_bytes(b"abcdef0123456789abcdef0123456789\n")
        original_identity.chmod(0o444)
        substitute_identity.chmod(0o444)

        retained = self.root / "machine-slot-retained"
        original.rename(retained)
        original.symlink_to(substitute, target_is_directory=True)
        with self.assertRaisesRegex(StorageError, "machine identity file is unavailable"):
            self.transport(machineIdentityFile=str(original / "machine-id"))

    def test_config_spool_bounds_fit_unit_memory_and_deadline_covers_requests(self):
        upper = TransportConfig.from_mapping(self.mapping(
            requestTimeoutSeconds=60,
            maxSpoolEntries=64,
            maxSpoolBytes=4 * 1024 * 1024,
        ))
        self.assertEqual(upper.max_spool_entries, MAX_SPOOL_ENTRIES)
        self.assertEqual(upper.max_spool_bytes, MAX_SPOOL_BYTES)
        with self.assertRaisesRegex(ConfigError, "maxSpoolEntries"):
            TransportConfig.from_mapping(self.mapping(maxSpoolEntries=65))
        with self.assertRaisesRegex(ConfigError, "maxSpoolBytes"):
            TransportConfig.from_mapping(
                self.mapping(maxSpoolBytes=4 * 1024 * 1024 + 1)
            )

        service = (
            Path(__file__).resolve().parents[1]
            / "systemd"
            / "monitor-agent-transport.service"
        ).read_text(encoding="utf-8")
        self.assertIn("MemoryMax=96M", service)
        self.assertIn("TimeoutStartSec=4min", service)
        self.assertGreater(4 * 60, 3 * upper.request_timeout_seconds)

    def test_transport_lock_contention_is_bounded_below_the_producer_deadline(self):
        lock_path = self.root / "bounded-transport.lock"
        with exclusive_lock(lock_path):
            with self.assertRaisesRegex(StorageError, "timed out waiting"):
                with exclusive_lock(lock_path, timeout_seconds=0.02):
                    self.fail("a contended transport lock must not be acquired")

        producer_service = (
            Path(__file__).resolve().parents[1]
            / "systemd"
            / "monitor-agent-producer.service"
        ).read_text(encoding="utf-8")
        self.assertIn("TimeoutStartSec=90s", producer_service)
        # Transport construction, producer construction/run, identity binding,
        # and enqueue can each take one bounded lock before the checkpoint is
        # retained for the next timer attempt.
        self.assertGreater(90, 5 * DEFAULT_LOCK_TIMEOUT_SECONDS)

    def test_sequence_exhaustion_is_rejected_before_enqueue_side_effects(self):
        transport = self.transport()
        state_path = transport.state_path
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["nextSequence"] = MAX_SAFE_INTEGER
        atomic_private_write(state_path, canonical_json(state))

        exhausted = self.transport()
        with self.assertRaisesRegex(StorageError, "sequence space is exhausted"):
            exhausted.enqueue([metric()])

        self.assertFalse(exhausted.journal_path.exists())
        self.assertEqual(list(exhausted.spool_directory.glob("*.batch")), [])
        self.assertEqual(exhausted.status()["nextSequence"], MAX_SAFE_INTEGER)

    def test_enqueue_input_exact_byte_bound_and_one_byte_over(self):
        exact = b'["' + b"x" * (MAX_ENQUEUE_BYTES - 4) + b'"]'
        self.assertEqual(len(exact), MAX_ENQUEUE_BYTES)
        self.assertEqual(len(_read_records(io.BytesIO(exact))), 1)
        with self.assertRaisesRegex(AgentTransportError, "bounded input size"):
            _read_records(io.BytesIO(exact + b" "))

    def test_maximum_enqueue_is_linear_and_stays_below_memory_proxy(self):
        transport = self.transport(
            maxSpoolEntries=MAX_SPOOL_ENTRIES,
            maxSpoolBytes=MAX_SPOOL_BYTES,
            gzipMinimumBytes=0,
        )
        with self.assertRaisesRegex(AgentTransportError, "2,000-record bound"):
            transport.enqueue(metric(value=float(index)) for index in range(MAX_ENQUEUE_RECORDS + 1))
        self.assertEqual(transport.status()["spoolEntries"], 0)

        canonical_calls = 0
        canonical_bytes = 0

        def measured_canonical(value):
            nonlocal canonical_calls, canonical_bytes
            encoded = canonical_json(value)
            canonical_calls += 1
            canonical_bytes += len(encoded)
            return encoded

        tracemalloc.start()
        try:
            with mock.patch(
                "ops.agent_transport.transport.canonical_json",
                side_effect=measured_canonical,
            ):
                batch_ids = transport.enqueue(
                    metric(value=float(index)) for index in range(MAX_ENQUEUE_RECORDS)
                )
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(len(batch_ids), 4)
        self.assertLess(canonical_calls, MAX_ENQUEUE_RECORDS * 4 + 100)
        self.assertLess(canonical_bytes, 8 * 1024 * 1024)
        self.assertLess(peak, 32 * 1024 * 1024)

    def test_https_requester_uses_only_explicit_mtls_files_and_exact_wire_length(self):
        config = TransportConfig.from_mapping(self.mapping())
        context = mock.Mock()
        response = mock.Mock(status=202)
        response.read.return_value = b"{}"
        response.getheaders.return_value = [("Cache-Control", "no-store")]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch("ops.agent_transport.transport.ssl.SSLContext", return_value=context),
            mock.patch(
                "ops.agent_transport.transport.http.client.HTTPSConnection",
                return_value=connection,
            ) as connection_factory,
        ):
            requester = HttpsRequester(config)
            result = requester.post("/agent/ingest", b"wire-body", "gzip")
        context.load_verify_locations.assert_called_once_with(cafile=str(self.ca))
        context.load_cert_chain.assert_called_once_with(certfile=str(self.cert), keyfile=str(self.key))
        connection_factory.assert_called_once_with(
            "agents.example.test", 443, timeout=3.0, context=context
        )
        _, _, request_kwargs = connection.method_calls[0]
        self.assertEqual(request_kwargs["headers"]["Content-Length"], "9")
        self.assertEqual(request_kwargs["headers"]["Content-Encoding"], "gzip")
        self.assertNotIn("X-Monitor-mTLS-Verified", request_kwargs["headers"])
        self.assertEqual(result.headers, {"cache-control": "no-store"})

    def test_stable_batch_wire_body_survives_retry_and_ack_precedes_delete(self):
        transport = self.transport(gzipMinimumBytes=9999)
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            AgentTransportError("network unavailable"),
        )
        first = transport.run_once()
        self.assertEqual(first.heartbeat, "acknowledged")
        self.assertEqual(first.ingest, "retry-scheduled")
        spool_path = transport.spool_directory / f"{batch_id}.batch"
        self.assertTrue(spool_path.exists())
        first_wire = [call[1] for call in self.requester.calls if call[0] == "/agent/ingest"][0]

        self.clock.advance(500)
        second = transport.run_once()
        self.assertEqual(second.ingest, "acknowledged")
        wires = [call[1] for call in self.requester.calls if call[0] == "/agent/ingest"]
        self.assertEqual(wires, [first_wire, first_wire])
        self.assertFalse(spool_path.exists())
        body = json.loads(first_wire)
        self.assertEqual(body["batchId"], batch_id)
        self.assertEqual(body["sentAt"], "2026-08-31T00:20:00.000Z")

    def test_invalid_success_response_is_not_an_ack(self):
        transport = self.transport()
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(
                202,
                {},
                canonical_json(
                    {
                        "accepted": True,
                        "batchId": "00000000-0000-4000-8000-999999999999",
                        "acceptedRecords": 1,
                        "duplicateRecords": 0,
                        "serverTime": "2026-08-31T00:20:00.000Z",
                    }
                ),
            ),
        )
        self.assertEqual(transport.run_once().ingest, "retry-scheduled")
        self.assertTrue((transport.spool_directory / f"{batch_id}.batch").exists())

    def test_permanent_rejection_moves_batch_to_private_bounded_quarantine(self):
        transport = self.transport()
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(422, {}, canonical_json({"code": "DATA_TOO_OLD"})),
        )

        result = transport.run_once()

        self.assertEqual(result.ingest, "quarantined")
        self.assertFalse((transport.spool_directory / f"{batch_id}.batch").exists())
        status = transport.status()
        self.assertEqual(status["spoolEntries"], 0)
        self.assertEqual(status["quarantine"]["entries"], 1)
        self.assertEqual(status["quarantine"]["dataTooOldEntries"], 1)
        self_metrics = json.loads(transport.self_metrics_path.read_text())
        self.assertEqual(self_metrics["outcomes"]["ingest"], "quarantined")
        self.assertEqual(self_metrics["quarantine"]["entries"], 1)
        self.assertEqual(self_metrics["quarantine"]["dataTooOldEntries"], 1)
        self.assertEqual(self_metrics["quarantine"]["oldestAgeSeconds"], 0)
        self.assertEqual(self_metrics["quarantine"]["status"], "retained")
        listing = transport.list_quarantine()
        self.assertEqual(listing["batches"][0]["batchId"], batch_id)
        self.assertEqual(listing["batches"][0]["reasonCode"], "DATA_TOO_OLD")
        self.assertNotIn("host.cpu.percent", repr(listing))
        quarantine_file = next(transport.quarantine_directory.iterdir())
        self.assertEqual(stat.S_IMODE(quarantine_file.stat().st_mode), 0o600)

        restarted = AgentTransport(
            transport.config,
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )
        self.assertEqual(restarted.status()["quarantine"]["entries"], 1)
        self.assertTrue(restarted.purge_quarantine(batch_id))
        self.assertFalse(restarted.purge_quarantine(batch_id))
        self.assertEqual(restarted.status()["quarantine"]["status"], "empty")

    def test_quarantine_rename_survives_crash_before_retry_state_cleanup(self):
        transport = self.transport()
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            AgentTransportError("temporary failure"),
        )
        self.assertEqual(transport.run_once().ingest, "retry-scheduled")
        self.clock.advance(500)
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(422, {}, canonical_json({"code": "BATCH_TOO_OLD"})),
        )
        with mock.patch(
            "ops.agent_transport.transport.fsync_directory",
            side_effect=StorageError("simulated crash after quarantine rename"),
        ):
            with self.assertRaisesRegex(StorageError, "simulated crash"):
                transport.run_once()

        self.assertFalse((transport.spool_directory / f"{batch_id}.batch").exists())
        self.assertEqual(len(list(transport.quarantine_directory.iterdir())), 1)
        recovered = AgentTransport(
            transport.config,
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )
        self.assertEqual(recovered.status()["quarantine"]["batchTooOldEntries"], 1)
        state = json.loads(recovered.state_path.read_text())
        self.assertNotIn(batch_id, state["retries"])

    def test_quarantine_shares_spool_bounds_until_explicit_purge(self):
        transport = self.transport(
            maxBatchBytes=1024,
            maxSpoolEntries=1,
            maxSpoolBytes=4096,
            gzipMinimumBytes=0,
        )
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(422, {}, canonical_json({"code": "DATA_TOO_OLD"})),
        )
        self.assertEqual(transport.run_once().ingest, "quarantined")
        with self.assertRaisesRegex(SpoolFullError, "spool/quarantine entry limit"):
            transport.enqueue([metric(value=2.0)])
        self.assertTrue(transport.purge_quarantine(batch_id))
        self.assertEqual(len(transport.enqueue([metric(value=2.0)])), 1)

    def test_unknown_422_is_retryable_and_not_silently_quarantined(self):
        transport = self.transport()
        self.enroll(transport)
        batch_id = transport.enqueue([metric()])[0]
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(422, {}, canonical_json({"code": "CLOCK_SKEW"})),
        )
        self.assertEqual(transport.run_once().ingest, "retry-scheduled")
        self.assertTrue((transport.spool_directory / f"{batch_id}.batch").exists())
        self.assertEqual(transport.status()["quarantine"]["entries"], 0)

    def test_gzip_is_selected_only_when_it_reduces_the_immutable_body(self):
        transport = self.transport(gzipMinimumBytes=0)
        batch_id = transport.enqueue([metric(value=1.25) for _ in range(20)])[0]
        envelope = json.loads((transport.spool_directory / f"{batch_id}.batch").read_text())
        self.assertEqual(envelope["contentEncoding"], "gzip")
        wire = base64.b64decode(envelope["wireBodyBase64"], validate=True)
        body = gzip.decompress(wire)
        self.assertEqual(hashlib_sha256(body), envelope["jsonSha256"])
        self.assertEqual(json.loads(body)["batchId"], batch_id)

    def test_retry_after_delays_ingest_but_heartbeat_still_bypasses_it(self):
        transport = self.transport(retryAfterMaximumSeconds=300)
        self.enroll(transport)
        transport.enqueue([metric()])
        self.requester.queue(
            "/agent/ingest",
            HttpResponse(429, {"retry-after": "120"}, b"{}"),
        )
        first = transport.run_once()
        self.assertEqual(first.heartbeat, "acknowledged")
        self.assertEqual(first.ingest, "retry-scheduled")
        ingest_count = sum(call[0] == "/agent/ingest" for call in self.requester.calls)
        heartbeat_count = sum(call[0] == "/agent/heartbeat" for call in self.requester.calls)

        self.clock.advance(60_000)
        second = transport.run_once()
        self.assertEqual(second.heartbeat, "acknowledged")
        self.assertEqual(second.ingest, "backoff")
        self.assertEqual(sum(call[0] == "/agent/ingest" for call in self.requester.calls), ingest_count)
        self.assertEqual(
            sum(call[0] == "/agent/heartbeat" for call in self.requester.calls), heartbeat_count + 1
        )
        self.clock.advance(60_000)
        self.assertEqual(transport.run_once().ingest, "acknowledged")

    def test_enrollment_replays_exact_body_and_erases_token_only_after_ack(self):
        transport = self.transport()
        token_file = self.root / "enrollment-token"
        token_file.write_text(TOKEN + "\n")
        token_file.chmod(0o600)
        self.requester.queue(
            "/agent/enroll",
            AgentTransportError("lost response"),
        )
        first = transport.enroll_from_file(token_file)
        self.assertEqual(first, "retry-scheduled")
        self.assertTrue(token_file.exists())
        self.assertTrue(transport.pending_enrollment_path.exists())
        first_body = [call[1] for call in self.requester.calls if call[0] == "/agent/enroll"][0]

        self.clock.advance(500)
        result = transport.run_once()
        self.assertEqual(result.enrollment, "acknowledged")
        bodies = [call[1] for call in self.requester.calls if call[0] == "/agent/enroll"]
        self.assertEqual(bodies, [first_body, first_body])
        self.assertFalse(token_file.exists())
        self.assertFalse(transport.pending_enrollment_path.exists())

    def test_spool_bounds_fail_closed_without_evicting_unacknowledged_batch(self):
        transport = self.transport(
            maxBatchBytes=1024,
            maxSpoolEntries=1,
            maxSpoolBytes=4096,
            gzipMinimumBytes=0,
        )
        first_id = transport.enqueue([metric()])[0]
        with self.assertRaisesRegex(SpoolFullError, "no acknowledged batch was evicted"):
            transport.enqueue([metric(value=2.0)])
        self.assertEqual(transport.status()["spoolEntries"], 1)
        self.assertTrue((transport.spool_directory / f"{first_id}.batch").exists())

    def test_pending_enqueue_journal_recovers_the_same_batch_after_crash_boundary(self):
        transport = self.transport()
        batch_id = transport.enqueue([metric()])[0]
        batch_path = transport.spool_directory / f"{batch_id}.batch"
        envelope = json.loads(batch_path.read_text())
        batch_path.unlink()
        fsync_directory(transport.spool_directory)
        atomic_private_write(
            transport.journal_path,
            canonical_json({"schemaVersion": 1, "entries": [envelope]}),
            replace=False,
        )

        recovered = AgentTransport(
            transport.config,
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )
        self.assertFalse(recovered.journal_path.exists())
        self.assertEqual(recovered.status()["spoolEntries"], 1)
        self.assertEqual(json.loads(batch_path.read_text()), envelope)

    def test_collector_identity_seeds_only_pristine_state_and_then_mismatch_fails(self):
        transport = self.transport()
        bound = transport.bind_collector_identity(collector_binding())
        status = transport.status()
        self.assertEqual(status["hostId"], collector_binding()["hostId"])
        self.assertEqual(status["agentId"], collector_binding()["agentId"])
        self.assertTrue(status["collectorIdentityBound"])
        self.assertEqual(bound["identityGeneration"], 1)

        transport.enqueue([metric()], checkpoint=checkpoint())
        changed = {**collector_binding(), "agentId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
        with self.assertRaisesRegex(ContractError, "conflict"):
            transport.bind_collector_identity(changed)

    def test_checkpoint_replay_returns_original_ids_without_new_sequences_and_conflicts(self):
        transport = self.transport()
        transport.bind_collector_identity(collector_binding())
        batch_ids = transport.enqueue([metric()], checkpoint=checkpoint(9))
        next_sequence = transport.status()["nextSequence"]
        uuid_cursor = self.uuids.value

        self.assertEqual(
            transport.enqueue([metric()], checkpoint=checkpoint(9)), batch_ids
        )
        self.assertEqual(transport.status()["nextSequence"], next_sequence)
        self.assertEqual(self.uuids.value, uuid_cursor)
        with self.assertRaisesRegex(ContractError, "different records"):
            transport.enqueue([metric(value=2.0)], checkpoint=checkpoint(9))
        changed_checkpoint = {
            **checkpoint(9),
            "observedAt": "2026-08-31T00:20:01Z",
        }
        with self.assertRaisesRegex(ContractError, "checkpoint content"):
            transport.enqueue([metric()], checkpoint=changed_checkpoint)

        transport.enqueue([metric(value=3.0)], checkpoint=checkpoint(10))
        with self.assertRaisesRegex(ContractError, "older"):
            transport.enqueue([metric()], checkpoint=checkpoint(9))

    def test_checkpoint_journal_recovery_persists_original_receipt_without_allocation(self):
        transport = self.transport()
        transport.bind_collector_identity(collector_binding())
        batch_id = transport.enqueue([metric()], checkpoint=checkpoint(9))[0]
        next_sequence = transport.status()["nextSequence"]
        uuid_cursor = self.uuids.value
        batch_path = transport.spool_directory / f"{batch_id}.batch"
        envelope = json.loads(batch_path.read_text())
        receipt = json.loads(transport.checkpoint_path.read_text())
        batch_path.unlink()
        transport.checkpoint_path.unlink()
        fsync_directory(transport.spool_directory)
        fsync_directory(transport.config.state_directory)
        atomic_private_write(
            transport.journal_path,
            canonical_json({
                "schemaVersion": 2,
                "checkpoint": receipt["checkpoint"],
                "recordsSha256": receipt["recordsSha256"],
                "entries": [envelope],
            }),
            replace=False,
        )

        recovered = AgentTransport(
            transport.config,
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
        )
        self.assertEqual(
            recovered.enqueue([metric()], checkpoint=checkpoint(9)), [batch_id]
        )
        self.assertEqual(recovered.status()["nextSequence"], next_sequence)
        self.assertEqual(self.uuids.value, uuid_cursor)

    def test_mixed_input_is_spooled_as_homogeneous_metric_and_event_batches(self):
        transport = self.transport()
        batch_ids = transport.enqueue([metric(), event(), metric(value=2.0)])
        self.assertEqual(len(batch_ids), 2)
        kinds = []
        for batch_id in batch_ids:
            envelope = json.loads(
                (transport.spool_directory / f"{batch_id}.batch").read_text()
            )
            wire = base64.b64decode(envelope["wireBodyBase64"])
            if envelope["contentEncoding"] == "gzip":
                wire = gzip.decompress(wire)
            body = json.loads(wire)
            batch_kinds = {record["kind"] for record in body["records"]}
            self.assertEqual(len(batch_kinds), 1)
            kinds.append(batch_kinds.pop())
        self.assertEqual(kinds, ["metric", "event"])

    def test_self_metrics_are_exact_nonblocking_and_track_ack_age(self):
        transport = AgentTransport(
            TransportConfig.from_mapping(self.mapping()),
            requester=self.requester,
            now=self.clock,
            jitter=lambda: 0.0,
            inventory_provider=inventory,
            uuid_factory=self.uuids,
            proc_self_io_path=self.root / "missing-proc-io",
        )
        result = transport.run_once()
        self.assertEqual(result.heartbeat, "not-enrolled")
        first = json.loads(transport.self_metrics_path.read_text())
        self.assertEqual(first["procIoStatus"], "missing")
        self.assertEqual(first["priorStateStatus"], "missing")
        self.assertIsInstance(first["runDurationSeconds"], float)
        self.assertEqual(first["resourceUsageStatus"], "available")
        self.assertIsInstance(first["userCpuSeconds"], float)
        self.assertIsInstance(first["systemCpuSeconds"], float)
        self.assertIsInstance(first["maxRssBytes"], int)
        self.assertIsNone(first["heartbeatAckAgeSeconds"])
        self.assertEqual(transport.status()["selfMetricsStatus"], "valid")

        transport.self_metrics_path.write_text("{}")
        transport.self_metrics_path.chmod(0o600)
        self.assertEqual(transport.run_once().heartbeat, "not-enrolled")
        second = json.loads(transport.self_metrics_path.read_text())
        self.assertEqual(second["priorStateStatus"], "corrupt")

        self.enroll(transport)
        acknowledged = transport.run_once()
        self.assertEqual(acknowledged.heartbeat, "acknowledged")
        third = json.loads(transport.self_metrics_path.read_text())
        self.assertEqual(third["outcomes"]["heartbeat"], "acknowledged")
        self.assertEqual(third["heartbeatAckAgeSeconds"], 0)
        self.assertEqual(third["spool"]["entries"], 0)
        self.assertEqual(third["quarantine"]["status"], "empty")
        self.clock.advance(10_000)
        self.assertEqual(transport.run_once().heartbeat, "not-due")
        fourth = json.loads(transport.self_metrics_path.read_text())
        self.assertEqual(fourth["heartbeatAckAgeSeconds"], 10)
        transport.self_metrics_path.chmod(0o644)
        self.assertEqual(transport.run_once().heartbeat, "not-due")
        self.assertEqual(transport.status()["selfMetricsStatus"], "corrupt")

    def test_every_durable_state_object_is_private(self):
        transport = self.transport()
        transport.enqueue([metric()])
        for path in [
            transport.config.state_directory,
            transport.spool_directory,
            transport.quarantine_directory,
        ]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in transport.config.state_directory.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


def hashlib_sha256(value):
    import hashlib

    return hashlib.sha256(value).hexdigest()


if __name__ == "__main__":
    unittest.main()
