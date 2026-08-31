"""Durable mTLS client for Monitor's optional central agent ingest API."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import email.utils
import gzip
import hashlib
import http.client
import ipaddress
import json
import math
import os
import random
import re
import resource
import ssl
import stat
import time
import uuid
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from urllib.parse import urlsplit

from .config import (
    MAX_ENQUEUE_BYTES,
    MAX_ENQUEUE_RECORDS,
    MAX_SPOOL_ENTRIES,
    ConfigError,
    TransportConfig,
    open_trusted_regular,
)
from .inventory import collect_inventory
from .storage import (
    DirectoryIdentity,
    StorageError,
    atomic_private_write,
    canonical_json,
    decode_exact_json,
    ensure_private_directory,
    erase_private_file,
    exclusive_lock,
    fsync_directory,
    read_private,
    unlink_durable,
    validate_private_file,
)


UUID_V4 = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")
HEX_SHA256 = re.compile(r"^[a-f0-9]{64}$")
ENROLLMENT_TOKEN = re.compile(r"^menr_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
RFC3339_MILLISECONDS = re.compile(
    r"^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T"
    r"([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
SPOOL_NAME = re.compile(
    r"^([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.batch$"
)
QUARANTINE_NAME = re.compile(
    r"^([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\."
    r"(BATCH_TOO_OLD|DATA_TOO_OLD)\.([0-9]{1,16})\.rejected$"
)
PERMANENT_INGEST_REJECTIONS = {"BATCH_TOO_OLD", "DATA_TOO_OLD"}
MAX_SAFE_INTEGER = 2**53 - 1
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_PENDING_ENROLLMENT_BYTES = 256 * 1024
MAX_HTTP_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 256

STATE_KEYS = {
    "schemaVersion",
    "hostId",
    "agentId",
    "installationEpoch",
    "machineIdentityDigest",
    "nextSequence",
    "registered",
    "nextHeartbeatDueAtEpochMs",
    "pendingHeartbeat",
    "enrollmentRetry",
    "retries",
}
RETRY_KEYS = {"attempts", "nextAttemptAtEpochMs"}
HEARTBEAT_KEYS = {
    "sequence",
    "bodyBase64",
    "bodySha256",
    "attempts",
    "nextAttemptAtEpochMs",
}
SPOOL_KEYS = {
    "schemaVersion",
    "agentId",
    "batchId",
    "contentEncoding",
    "wireBodyBase64",
    "wireSha256",
    "jsonSha256",
    "createdAtEpochMs",
    "firstSequence",
    "lastSequence",
    "recordCount",
}
JOURNAL_KEYS = {"schemaVersion", "entries"}
CHECKPOINT_JOURNAL_KEYS = {"schemaVersion", "checkpoint", "recordsSha256", "entries"}
JOURNAL_PREFIX = b'{"entries":['
JOURNAL_SUFFIX = b'],"schemaVersion":1}'
CHECKPOINT_KEYS = {
    "schemaVersion",
    "hostId",
    "agentId",
    "identityGeneration",
    "sourceSequence",
    "observedAt",
}
CHECKPOINT_RECEIPT_KEYS = {
    "schemaVersion",
    "checkpoint",
    "recordsSha256",
    "batchIds",
    "firstSequence",
    "lastSequence",
    "createdAtEpochMs",
}
COLLECTOR_BINDING_KEYS = {
    "schemaVersion",
    "hostId",
    "agentId",
    "installationEpoch",
    "identityGeneration",
}
SELF_METRICS_KEYS = {
    "schemaVersion",
    "agentId",
    "observedAt",
    "runDurationSeconds",
    "userCpuSeconds",
    "systemCpuSeconds",
    "maxRssBytes",
    "ioReadBytes",
    "ioWriteBytes",
    "ioReadSyscalls",
    "ioWriteSyscalls",
    "resourceUsageStatus",
    "procIoStatus",
    "priorStateStatus",
    "outcomes",
    "retryStreaks",
    "lastHeartbeatAckAt",
    "heartbeatAckAgeSeconds",
    "spool",
    "quarantine",
}
SELF_OUTCOME_KEYS = {"enrollment", "heartbeat", "ingest"}
SELF_SPOOL_KEYS = {
    "entries",
    "bytes",
    "maxEntries",
    "maxBytes",
    "entriesUsedPercent",
    "bytesUsedPercent",
    "oldestAgeSeconds",
}
SELF_QUARANTINE_KEYS = {
    "entries",
    "bytes",
    "oldestAgeSeconds",
    "status",
    "batchTooOldEntries",
    "dataTooOldEntries",
}
PROC_IO_FIELDS = {"read_bytes", "write_bytes", "syscr", "syscw"}
PROC_IO_ALL_FIELDS = {
    "rchar",
    "wchar",
    "syscr",
    "syscw",
    "read_bytes",
    "write_bytes",
    "cancelled_write_bytes",
}
MAX_SELF_METRICS_BYTES = 64 * 1024
MAX_BINDING_BYTES = 16 * 1024
MAX_CHECKPOINT_BYTES = 64 * 1024
PENDING_ENROLLMENT_KEYS = {
    "schemaVersion",
    "agentId",
    "hostId",
    "bodyBase64",
    "bodySha256",
    "sourcePath",
    "sourceDevice",
    "sourceInode",
    "sourceSize",
}


class AgentTransportError(RuntimeError):
    """Base error for a local or remote transport failure."""


class ContractError(AgentTransportError):
    """Locally supplied records or a remote acknowledgement violate the contract."""


class SpoolFullError(AgentTransportError):
    """The bounded local spool cannot durably admit more records."""


class EnrollmentError(AgentTransportError):
    """Enrollment could not be acknowledged or its token could not be handled safely."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class Requester(Protocol):
    def post(self, endpoint: str, body: bytes, content_encoding: str) -> HttpResponse:
        """Send one request, returning a bounded response."""


class HttpsRequester:
    """HTTPS-only stdlib requester with an explicitly configured mTLS trust root."""

    def __init__(self, config: TransportConfig):
        config.validate_credentials()
        parsed = urlsplit(config.base_url)
        self._host = parsed.hostname or ""
        self._port = parsed.port or 443
        self._base_path = parsed.path
        self._timeout = config.request_timeout_seconds
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        try:
            context.load_verify_locations(cafile=str(config.ca_certificate_file))
            context.load_cert_chain(
                certfile=str(config.client_certificate_file), keyfile=str(config.client_key_file)
            )
        except (OSError, ssl.SSLError) as error:
            raise AgentTransportError("mTLS certificate, key, or CA could not be loaded") from error
        self._context = context

    def post(self, endpoint: str, body: bytes, content_encoding: str) -> HttpResponse:
        if not endpoint.startswith("/agent/") or "?" in endpoint or "#" in endpoint:
            raise AgentTransportError("refusing an invalid central agent endpoint")
        connection = http.client.HTTPSConnection(
            self._host, self._port, timeout=self._timeout, context=self._context
        )
        headers = {
            "Accept": "application/json",
            "Connection": "close",
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
            "User-Agent": "monitor-agent-transport/1",
        }
        if content_encoding == "gzip":
            headers["Content-Encoding"] = "gzip"
        elif content_encoding != "identity":
            raise AgentTransportError("refusing an unsupported content encoding")
        try:
            connection.request("POST", f"{self._base_path}{endpoint}", body=body, headers=headers)
            response = connection.getresponse()
            encoded = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
            if len(encoded) > MAX_HTTP_RESPONSE_BYTES:
                raise AgentTransportError("central agent response exceeds its size bound")
            response_headers = {key.lower(): value.strip() for key, value in response.getheaders()}
            return HttpResponse(status=response.status, headers=response_headers, body=encoded)
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise AgentTransportError("central agent HTTPS request failed") from error
        finally:
            connection.close()


@dataclass(frozen=True)
class RunResult:
    enrollment: str
    heartbeat: str
    ingest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "enrollment": self.enrollment,
            "heartbeat": self.heartbeat,
            "ingest": self.ingest,
        }


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _encode_enqueue_journal(
    entries: list[bytes],
    checkpoint: dict[str, object] | None = None,
    records_sha256: str | None = None,
) -> bytes:
    if not entries:
        raise StorageError("pending enqueue journal cannot be empty")
    if checkpoint is not None:
        if records_sha256 is None or not HEX_SHA256.fullmatch(records_sha256):
            raise StorageError("checkpoint enqueue journal is missing its record digest")
        decoded_entries: list[object] = []
        for entry in entries:
            try:
                decoded_entries.append(json.loads(entry.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StorageError("checkpoint enqueue journal contains invalid JSON") from error
        return canonical_json({
            "schemaVersion": 2,
            "checkpoint": checkpoint,
            "recordsSha256": records_sha256,
            "entries": decoded_entries,
        })
    return JOURNAL_PREFIX + b",".join(entries) + JOURNAL_SUFFIX


def _now_rfc3339(epoch_ms: int) -> str:
    value = dt.datetime.fromtimestamp(epoch_ms / 1000, tz=dt.timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_rfc3339(value: object) -> int | None:
    if not isinstance(value, str) or not RFC3339_MILLISECONDS.fullmatch(value):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    epoch_ms = round(parsed.timestamp() * 1000)
    return epoch_ms if 0 <= epoch_ms <= 253_402_300_799_999 else None


def _uuid_v4(value: object) -> str | None:
    if not isinstance(value, str) or UUID_V4.fullmatch(value) is None:
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value and parsed.version == 4 else None


def _decode_base64(value: object, description: str) -> bytes:
    if not isinstance(value, str):
        raise StorageError(f"{description} is not base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise StorageError(f"{description} is not canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise StorageError(f"{description} is not canonical base64")
    return decoded


def _valid_retry(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == RETRY_KEYS
        and isinstance(value["attempts"], int)
        and not isinstance(value["attempts"], bool)
        and 0 <= value["attempts"] <= MAX_SAFE_INTEGER
        and isinstance(value["nextAttemptAtEpochMs"], int)
        and not isinstance(value["nextAttemptAtEpochMs"], bool)
        and 0 <= value["nextAttemptAtEpochMs"] <= MAX_SAFE_INTEGER
    )


def _validate_inventory(value: object) -> dict[str, object]:
    keys = {
        "agentVersion",
        "hostname",
        "ipAddresses",
        "operatingSystem",
        "ubuntuVersion",
        "kernelVersion",
        "architecture",
        "cpuModel",
        "memoryBytes",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError("inventory has an invalid exact schema")
    bounds = {
        "agentVersion": 64,
        "hostname": 253,
        "operatingSystem": 128,
        "kernelVersion": 128,
        "architecture": 32,
        "cpuModel": 256,
    }
    normalized: dict[str, object] = {}
    for name, maximum in bounds.items():
        item = value[name]
        if (
            not isinstance(item, str)
            or item != item.strip()
            or not item
            or len(item) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
        ):
            raise ContractError(f"inventory {name} is invalid")
        normalized[name] = item
    ubuntu = value["ubuntuVersion"]
    if ubuntu is not None and (
        not isinstance(ubuntu, str)
        or ubuntu != ubuntu.strip()
        or not ubuntu
        or len(ubuntu) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in ubuntu)
    ):
        raise ContractError("inventory ubuntuVersion is invalid")
    normalized["ubuntuVersion"] = ubuntu
    addresses = value["ipAddresses"]
    if not isinstance(addresses, list) or len(addresses) > 16:
        raise ContractError("inventory ipAddresses is invalid")
    parsed_addresses: list[str] = []
    for address in addresses:
        if not isinstance(address, str):
            raise ContractError("inventory IP address is invalid")
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise ContractError("inventory IP address is invalid") from error
        parsed_addresses.append(address)
    if len(set(parsed_addresses)) != len(parsed_addresses):
        raise ContractError("inventory IP addresses must be unique")
    normalized["ipAddresses"] = parsed_addresses
    memory = value["memoryBytes"]
    if not isinstance(memory, int) or isinstance(memory, bool) or not 1 <= memory <= MAX_SAFE_INTEGER:
        raise ContractError("inventory memoryBytes is invalid")
    normalized["memoryBytes"] = memory
    # Preserve the exact field order used by server/agent-control.ts.
    return {
        "agentVersion": normalized["agentVersion"],
        "hostname": normalized["hostname"],
        "ipAddresses": normalized["ipAddresses"],
        "operatingSystem": normalized["operatingSystem"],
        "ubuntuVersion": normalized["ubuntuVersion"],
        "kernelVersion": normalized["kernelVersion"],
        "architecture": normalized["architecture"],
        "cpuModel": normalized["cpuModel"],
        "memoryBytes": normalized["memoryBytes"],
    }


class AgentTransport:
    """Owns central identity, immutable batches, retry state, and acknowledgements."""

    def __init__(
        self,
        config: TransportConfig,
        *,
        requester: Requester | None = None,
        now: Callable[[], int] | None = None,
        jitter: Callable[[], float] | None = None,
        inventory_provider: Callable[[str], dict[str, object]] = collect_inventory,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        resource_usage_provider: Callable[[], object] | None = None,
        proc_self_io_path: Path = Path("/proc/self/io"),
    ):
        self.config = config
        self.config.validate_credentials()
        self._requester = requester or HttpsRequester(config)
        self._now = now or (lambda: int(dt.datetime.now(tz=dt.timezone.utc).timestamp() * 1000))
        self._jitter = jitter or random.SystemRandom().random
        self._inventory_provider = inventory_provider
        self._uuid_factory = uuid_factory
        self._monotonic_ns = monotonic_ns
        self._resource_usage_provider = resource_usage_provider or (
            lambda: resource.getrusage(resource.RUSAGE_SELF)
        )
        self._proc_self_io_path = proc_self_io_path
        self._state_directory_identity: DirectoryIdentity = ensure_private_directory(
            config.state_directory
        )
        self.spool_directory = config.state_directory / "spool"
        self._spool_directory_identity: DirectoryIdentity = ensure_private_directory(
            self.spool_directory
        )
        self.quarantine_directory = config.state_directory / "quarantine"
        self._quarantine_directory_identity: DirectoryIdentity = ensure_private_directory(
            self.quarantine_directory
        )
        self.state_path = config.state_directory / "transport-state.json"
        self.lock_path = config.state_directory / ".transport.lock"
        self.journal_path = config.state_directory / "pending-enqueue.json"
        self.pending_enrollment_path = config.state_directory / "pending-enrollment.json"
        self.checkpoint_path = config.state_directory / "enqueue-checkpoint.json"
        self.collector_binding_path = config.state_directory / "collector-binding.json"
        self.self_metrics_path = config.state_directory / "self-metrics.json"
        with self._locked_storage():
            self._cleanup_atomic_temps(config.state_directory)
            self._cleanup_atomic_temps(self.spool_directory)
            self._cleanup_atomic_temps(self.quarantine_directory)
            state = self._load_or_create_state()
            state = self._recover_enqueue(state)
            state = self._reconcile_state(state)
            self._reconcile_enrollment(state)

    def _validate_storage_bindings(self) -> None:
        ensure_private_directory(
            self.config.state_directory,
            create=False,
            expected=self._state_directory_identity,
        )
        ensure_private_directory(
            self.spool_directory,
            create=False,
            expected=self._spool_directory_identity,
        )
        ensure_private_directory(
            self.quarantine_directory,
            create=False,
            expected=self._quarantine_directory_identity,
        )

    @contextlib.contextmanager
    def _locked_storage(self) -> Iterator[None]:
        # Validate before resolving the lock path, then again after locking and
        # before any state/spool traversal or mutation.
        self._validate_storage_bindings()
        with exclusive_lock(self.lock_path):
            self._validate_storage_bindings()
            yield

    def _cleanup_atomic_temps(self, directory: Path) -> None:
        changed = False
        for path in directory.iterdir():
            if not path.name.startswith(".") or ".tmp-" not in path.name:
                continue
            target, suffix = path.name[1:].rsplit(".tmp-", 1)
            if directory == self.spool_directory:
                allowed_target = SPOOL_NAME.fullmatch(target) is not None
            elif directory == self.quarantine_directory:
                allowed_target = QUARANTINE_NAME.fullmatch(target) is not None
            else:
                allowed_target = target in {
                    self.state_path.name,
                    self.journal_path.name,
                    self.pending_enrollment_path.name,
                    self.checkpoint_path.name,
                    self.collector_binding_path.name,
                    self.self_metrics_path.name,
                }
            if not allowed_target:
                raise StorageError(f"unsafe unexpected private temporary file: {path}")
            try:
                uuid.UUID(suffix)
            except ValueError as error:
                raise StorageError(f"unsafe unexpected private temporary file: {path}") from error
            validate_private_file(path, maximum_bytes=max(self.config.max_spool_bytes, MAX_STATE_BYTES))
            path.unlink()
            changed = True
        if changed:
            fsync_directory(directory)

    def _machine_identity_digest(self) -> str:
        path = self.config.machine_identity_file
        try:
            descriptor, _ = open_trusted_regular(
                path, maximum_bytes=MAX_TOKEN_BYTES, exact_mode=None
            )
        except ConfigError as error:
            raise StorageError("machine identity file is unavailable") from error
        try:
            encoded = os.read(descriptor, MAX_TOKEN_BYTES + 1)
        finally:
            os.close(descriptor)
        raw = encoded.strip()
        if not re.fullmatch(rb"[A-Fa-f0-9]{32}", raw):
            raise StorageError("machine identity file has an invalid contract")
        return hashlib.sha256(b"monitor-agent-machine-identity-v1\0" + raw.lower()).hexdigest()

    def _initial_state(self) -> dict[str, object]:
        at = self._now()
        if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= MAX_SAFE_INTEGER:
            raise StorageError("clock returned an invalid epoch")
        host_id = str(self._uuid_factory())
        agent_id = str(self._uuid_factory())
        if not UUID_V4.fullmatch(host_id) or not UUID_V4.fullmatch(agent_id) or host_id == agent_id:
            raise StorageError("UUID provider did not return distinct UUIDv4 values")
        return {
            "schemaVersion": 1,
            "hostId": host_id,
            "agentId": agent_id,
            "installationEpoch": _now_rfc3339(at),
            "machineIdentityDigest": self._machine_identity_digest(),
            "nextSequence": 1,
            "registered": False,
            "nextHeartbeatDueAtEpochMs": at,
            "pendingHeartbeat": None,
            "enrollmentRetry": None,
            "retries": {},
        }

    def _validate_state(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != STATE_KEYS or value["schemaVersion"] != 1:
            raise StorageError("agent transport state has an invalid exact schema")
        if (
            not isinstance(value["hostId"], str)
            or not UUID_V4.fullmatch(value["hostId"])
            or not isinstance(value["agentId"], str)
            or not UUID_V4.fullmatch(value["agentId"])
            or value["hostId"] == value["agentId"]
            or _parse_rfc3339(value["installationEpoch"]) is None
            or not isinstance(value["machineIdentityDigest"], str)
            or not HEX_SHA256.fullmatch(value["machineIdentityDigest"])
            or not isinstance(value["nextSequence"], int)
            or isinstance(value["nextSequence"], bool)
            or not 1 <= value["nextSequence"] <= MAX_SAFE_INTEGER
            or not isinstance(value["registered"], bool)
            or not isinstance(value["nextHeartbeatDueAtEpochMs"], int)
            or isinstance(value["nextHeartbeatDueAtEpochMs"], bool)
            or not 0 <= value["nextHeartbeatDueAtEpochMs"] <= MAX_SAFE_INTEGER
            or value["enrollmentRetry"] is not None
            and not _valid_retry(value["enrollmentRetry"])
        ):
            raise StorageError("agent transport state has invalid identity or retry fields")
        pending = value["pendingHeartbeat"]
        if pending is not None:
            if (
                not isinstance(pending, dict)
                or set(pending) != HEARTBEAT_KEYS
                or not isinstance(pending["sequence"], int)
                or isinstance(pending["sequence"], bool)
                or not 1 <= pending["sequence"] <= MAX_SAFE_INTEGER
                or not isinstance(pending["bodySha256"], str)
                or not HEX_SHA256.fullmatch(pending["bodySha256"])
                or not _valid_retry(
                    {
                        "attempts": pending["attempts"],
                        "nextAttemptAtEpochMs": pending["nextAttemptAtEpochMs"],
                    }
                )
            ):
                raise StorageError("pending heartbeat has an invalid exact schema")
            body = _decode_base64(pending["bodyBase64"], "pending heartbeat body")
            if len(body) > 64 * 1024 or _sha256(body) != pending["bodySha256"]:
                raise StorageError("pending heartbeat body digest does not match")
            self._validate_heartbeat_body(body, value["agentId"], pending["sequence"])
        retries = value["retries"]
        if not isinstance(retries, dict) or len(retries) > self.config.max_spool_entries:
            raise StorageError("telemetry retry state has an invalid bound")
        for batch_id, retry in retries.items():
            if not isinstance(batch_id, str) or not UUID_V4.fullmatch(batch_id) or not _valid_retry(retry):
                raise StorageError("telemetry retry state has an invalid entry")
        return value

    def _load_or_create_state(self) -> dict[str, object]:
        if self.state_path.exists() or self.state_path.is_symlink():
            encoded = read_private(self.state_path, maximum_bytes=MAX_STATE_BYTES)
            try:
                value = json.loads(encoded.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StorageError("agent transport state is not valid UTF-8 JSON") from error
            state = self._validate_state(value)
            current_digest = self._machine_identity_digest()
            if state["machineIdentityDigest"] != current_digest:
                raise StorageError("machine identity changed; explicit re-enrollment is required")
            return state
        state = self._initial_state()
        self._persist_state(state)
        return state

    def _persist_state(self, state: dict[str, object]) -> None:
        self._validate_state(state)
        atomic_private_write(self.state_path, canonical_json(state))

    def _normalize_collector_binding(self, value: object) -> dict[str, object]:
        input_keys = {"hostId", "agentId", "installationEpoch", "identityGeneration"}
        if not isinstance(value, Mapping) or set(value) != input_keys:
            raise ContractError("collector identity mapping has an invalid exact schema")
        host_id = _uuid_v4(value["hostId"])
        agent_id = _uuid_v4(value["agentId"])
        installation = _parse_rfc3339(value["installationEpoch"])
        generation = value["identityGeneration"]
        if (
            host_id is None
            or agent_id is None
            or host_id == agent_id
            or installation is None
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= MAX_SAFE_INTEGER
        ):
            raise ContractError("collector identity mapping is invalid")
        return {
            "schemaVersion": 1,
            "hostId": host_id,
            "agentId": agent_id,
            "installationEpoch": _now_rfc3339(installation),
            "identityGeneration": generation,
        }

    def _validate_collector_binding(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != COLLECTOR_BINDING_KEYS:
            raise StorageError("collector binding has an invalid exact schema")
        if value["schemaVersion"] != 1:
            raise StorageError("collector binding schema version is invalid")
        try:
            normalized = self._normalize_collector_binding({
                key: value[key] for key in value if key != "schemaVersion"
            })
        except ContractError as error:
            raise StorageError("collector binding is invalid") from error
        return normalized

    def _load_collector_binding(self) -> dict[str, object] | None:
        if not (self.collector_binding_path.exists() or self.collector_binding_path.is_symlink()):
            return None
        encoded = read_private(self.collector_binding_path, maximum_bytes=MAX_BINDING_BYTES)
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("collector binding is not valid UTF-8 JSON") from error
        return self._validate_collector_binding(value)

    def _binding_matches_state(
        self, binding: Mapping[str, object], state: Mapping[str, object]
    ) -> bool:
        return (
            binding["hostId"] == state["hostId"]
            and binding["agentId"] == state["agentId"]
            and _parse_rfc3339(binding["installationEpoch"])
            == _parse_rfc3339(state["installationEpoch"])
        )

    def bind_collector_identity(self, value: object) -> dict[str, object]:
        """Bind/seed the transport from one validated collector identity.

        A differing random transport identity may be replaced only before any
        sequence, enrollment, or spool side effect.  Once bound, every mismatch
        is an explicit operator-reconciliation failure.
        """

        requested = self._normalize_collector_binding(value)
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            existing = self._load_collector_binding()
            if existing is not None:
                if existing != requested or not self._binding_matches_state(existing, state):
                    raise ContractError("collector and transport identity mappings conflict")
                return existing
            if self._binding_matches_state(requested, state):
                atomic_private_write(
                    self.collector_binding_path, canonical_json(requested), replace=False
                )
                return requested
            pristine = (
                state["registered"] is False
                and state["nextSequence"] == 1
                and state["pendingHeartbeat"] is None
                and state["enrollmentRetry"] is None
                and state["retries"] == {}
                and not (
                    self.pending_enrollment_path.exists()
                    or self.pending_enrollment_path.is_symlink()
                )
                and not self._spool_entries()
                and not self._quarantine_entries()
                and not (self.checkpoint_path.exists() or self.checkpoint_path.is_symlink())
            )
            if not pristine:
                raise ContractError(
                    "collector identity differs from non-pristine transport state; "
                    "explicit re-enrollment is required"
                )
            state["hostId"] = requested["hostId"]
            state["agentId"] = requested["agentId"]
            state["installationEpoch"] = requested["installationEpoch"]
            self._persist_state(state)
            atomic_private_write(
                self.collector_binding_path, canonical_json(requested), replace=False
            )
            return requested

    def _normalize_checkpoint(self, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != CHECKPOINT_KEYS:
            raise ContractError("source checkpoint has an invalid exact schema")
        if value["schemaVersion"] != 1:
            raise ContractError("source checkpoint schemaVersion must be 1")
        host_id = _uuid_v4(value["hostId"])
        agent_id = _uuid_v4(value["agentId"])
        generation = value["identityGeneration"]
        source_sequence = value["sourceSequence"]
        observed = _parse_rfc3339(value["observedAt"])
        if (
            host_id is None
            or agent_id is None
            or host_id == agent_id
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or not 1 <= generation <= MAX_SAFE_INTEGER
            or not isinstance(source_sequence, int)
            or isinstance(source_sequence, bool)
            or not 1 <= source_sequence <= MAX_SAFE_INTEGER
            or observed is None
        ):
            raise ContractError("source checkpoint identity, sequence, or time is invalid")
        return {
            "schemaVersion": 1,
            "hostId": host_id,
            "agentId": agent_id,
            "identityGeneration": generation,
            "sourceSequence": source_sequence,
            "observedAt": _now_rfc3339(observed),
        }

    def _validate_checkpoint_receipt(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != CHECKPOINT_RECEIPT_KEYS:
            raise StorageError("enqueue checkpoint receipt has an invalid exact schema")
        if value["schemaVersion"] != 1:
            raise StorageError("enqueue checkpoint receipt schema version is invalid")
        try:
            checkpoint = self._normalize_checkpoint(value["checkpoint"])
        except ContractError as error:
            raise StorageError("enqueue checkpoint receipt contains an invalid checkpoint") from error
        if not isinstance(value["recordsSha256"], str) or not HEX_SHA256.fullmatch(value["recordsSha256"]):
            raise StorageError("enqueue checkpoint receipt record digest is invalid")
        batch_ids = value["batchIds"]
        if (
            not isinstance(batch_ids, list)
            or not batch_ids
            or len(batch_ids) > MAX_SPOOL_ENTRIES
            or any(_uuid_v4(item) is None for item in batch_ids)
            or len(set(batch_ids)) != len(batch_ids)
        ):
            raise StorageError("enqueue checkpoint receipt batch IDs are invalid")
        for key in {"firstSequence", "lastSequence", "createdAtEpochMs"}:
            item = value[key]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or not 1 <= item <= MAX_SAFE_INTEGER
            ):
                raise StorageError(f"enqueue checkpoint receipt {key} is invalid")
        if value["lastSequence"] < value["firstSequence"]:
            raise StorageError("enqueue checkpoint receipt sequence range is reversed")
        return {**value, "checkpoint": checkpoint}

    def _load_checkpoint_receipt(self) -> dict[str, object] | None:
        if not (self.checkpoint_path.exists() or self.checkpoint_path.is_symlink()):
            return None
        encoded = read_private(self.checkpoint_path, maximum_bytes=MAX_CHECKPOINT_BYTES)
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("enqueue checkpoint receipt is not valid UTF-8 JSON") from error
        return self._validate_checkpoint_receipt(value)

    @staticmethod
    def _checkpoint_identity(checkpoint: Mapping[str, object]) -> tuple[object, object, object]:
        return (
            checkpoint["hostId"],
            checkpoint["agentId"],
            checkpoint["identityGeneration"],
        )

    def _validate_record_input(self, value: object) -> dict[str, object]:
        keys = {"kind", "metric", "target", "observedAt", "value", "severity"}
        if not isinstance(value, dict) or set(value) != keys:
            raise ContractError("telemetry record has an invalid exact input schema")
        kind = value["kind"]
        metric = value["metric"]
        target = value["target"]
        observed_at = _parse_rfc3339(value["observedAt"])
        if (
            kind not in {"metric", "event"}
            or not isinstance(metric, str)
            or not SAFE_NAME.fullmatch(metric)
            or not isinstance(target, str)
            or not SAFE_NAME.fullmatch(target)
            or observed_at is None
        ):
            raise ContractError("telemetry record identity or timestamp is invalid")
        if kind == "metric":
            number = value["value"]
            try:
                finite = (
                    isinstance(number, (int, float))
                    and not isinstance(number, bool)
                    and math.isfinite(float(number))
                )
            except OverflowError:
                finite = False
            if not finite or value["severity"] is not None:
                raise ContractError("metric records require a finite value and null severity")
        elif value["value"] is not None or value["severity"] not in {"info", "warning", "critical"}:
            raise ContractError("event records require null value and a supported severity")
        return {
            "kind": kind,
            "metric": metric,
            "target": target,
            "observedAt": _now_rfc3339(observed_at),
            "value": value["value"],
            "severity": value["severity"],
        }

    def _encode_spool_entry(self, batch: dict[str, object], at: int) -> dict[str, object]:
        json_body = canonical_json(batch)
        if len(json_body) > self.config.max_batch_bytes:
            raise ContractError("one telemetry batch exceeds maxBatchBytes")
        compressed = gzip.compress(json_body, compresslevel=6, mtime=0)
        if (
            len(json_body) >= self.config.gzip_minimum_bytes
            and len(compressed) < len(json_body)
        ):
            wire = compressed
            encoding = "gzip"
        else:
            wire = json_body
            encoding = "identity"
        if len(wire) > self.config.max_batch_bytes:
            raise ContractError("one telemetry wire body exceeds maxBatchBytes")
        records = batch["records"]
        assert isinstance(records, list)
        return {
            "schemaVersion": 1,
            "agentId": batch["agentId"],
            "batchId": batch["batchId"],
            "contentEncoding": encoding,
            "wireBodyBase64": base64.b64encode(wire).decode("ascii"),
            "wireSha256": _sha256(wire),
            "jsonSha256": _sha256(json_body),
            "createdAtEpochMs": at,
            "firstSequence": batch["firstSequence"],
            "lastSequence": batch["lastSequence"],
            "recordCount": len(records),
        }

    def _inflate_wire(self, wire: bytes, encoding: str) -> bytes:
        if encoding == "identity":
            decoded = wire
        elif encoding == "gzip":
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                decoded = inflater.decompress(wire, self.config.max_batch_bytes + 1)
                if inflater.unconsumed_tail or len(decoded) > self.config.max_batch_bytes:
                    raise StorageError("spooled gzip body exceeds its inflated bound")
                decoded += inflater.flush(self.config.max_batch_bytes + 1 - len(decoded))
            except zlib.error as error:
                raise StorageError("spooled gzip body is corrupt") from error
            if not inflater.eof or inflater.unused_data or len(decoded) > self.config.max_batch_bytes:
                raise StorageError("spooled gzip body has an invalid stream")
        else:
            raise StorageError("spooled batch uses an unsupported content encoding")
        if not 1 <= len(decoded) <= self.config.max_batch_bytes:
            raise StorageError("spooled JSON body exceeds its bound")
        return decoded

    def _validate_batch_body(self, body: bytes, entry: dict[str, object]) -> dict[str, object]:
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("spooled batch body is not valid UTF-8 JSON") from error
        keys = {
            "schemaVersion",
            "agentId",
            "batchId",
            "sentAt",
            "firstSequence",
            "lastSequence",
            "records",
        }
        if (
            not isinstance(value, dict)
            or set(value) != keys
            or value["schemaVersion"] != 1
            or value["agentId"] != entry["agentId"]
            or value["batchId"] != entry["batchId"]
            or _parse_rfc3339(value["sentAt"]) is None
            or value["firstSequence"] != entry["firstSequence"]
            or value["lastSequence"] != entry["lastSequence"]
            or not isinstance(value["records"], list)
            or len(value["records"]) != entry["recordCount"]
            or not 1 <= len(value["records"]) <= self.config.max_batch_records
        ):
            raise StorageError("spooled batch body has an invalid exact schema")
        sequences: list[int] = []
        kinds: set[object] = set()
        for record in value["records"]:
            if not isinstance(record, dict) or set(record) != {
                "kind",
                "metric",
                "target",
                "observedAt",
                "sequence",
                "value",
                "severity",
            }:
                raise StorageError("spooled record has an invalid exact schema")
            parsed = self._validate_record_input({
                key: record[key] for key in record if key != "sequence"
            })
            if parsed["observedAt"] != record["observedAt"]:
                raise StorageError("spooled record timestamp is not canonical")
            sequence = record["sequence"]
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or not 1 <= sequence <= MAX_SAFE_INTEGER
            ):
                raise StorageError("spooled record sequence is invalid")
            sequences.append(sequence)
            kinds.add(record["kind"])
        if (
            sequences != sorted(sequences)
            or min(sequences) != value["firstSequence"]
            or max(sequences) != value["lastSequence"]
            or len(kinds) != 1
        ):
            raise StorageError("spooled record sequence range or batch kind is invalid")
        return value

    def _validate_spool_entry(self, value: object, expected_batch_id: str | None = None) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != SPOOL_KEYS or value["schemaVersion"] != 1:
            raise StorageError("spooled batch envelope has an invalid exact schema")
        if (
            not isinstance(value["agentId"], str)
            or not UUID_V4.fullmatch(value["agentId"])
            or not isinstance(value["batchId"], str)
            or not UUID_V4.fullmatch(value["batchId"])
            or expected_batch_id is not None
            and value["batchId"] != expected_batch_id
            or value["contentEncoding"] not in {"identity", "gzip"}
            or not isinstance(value["wireSha256"], str)
            or not HEX_SHA256.fullmatch(value["wireSha256"])
            or not isinstance(value["jsonSha256"], str)
            or not HEX_SHA256.fullmatch(value["jsonSha256"])
        ):
            raise StorageError("spooled batch envelope identity is invalid")
        for key in ["createdAtEpochMs", "firstSequence", "lastSequence", "recordCount"]:
            item = value[key]
            if not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= MAX_SAFE_INTEGER:
                raise StorageError(f"spooled batch {key} is invalid")
        if value["lastSequence"] < value["firstSequence"]:
            raise StorageError("spooled batch sequence range is reversed")
        wire = _decode_base64(value["wireBodyBase64"], "spooled wire body")
        if not 1 <= len(wire) <= self.config.max_batch_bytes or _sha256(wire) != value["wireSha256"]:
            raise StorageError("spooled wire body digest or size is invalid")
        body = self._inflate_wire(wire, str(value["contentEncoding"]))
        if _sha256(body) != value["jsonSha256"]:
            raise StorageError("spooled JSON body digest does not match")
        self._validate_batch_body(body, value)
        return value

    def _spool_entries(self) -> list[tuple[Path, dict[str, object], int]]:
        entries: list[tuple[Path, dict[str, object], int]] = []
        for path in self.spool_directory.iterdir():
            match = SPOOL_NAME.fullmatch(path.name)
            if not match:
                raise StorageError(f"unexpected file in agent spool: {path}")
            status = validate_private_file(path, maximum_bytes=self.config.max_spool_bytes)
            encoded = read_private(path, maximum_bytes=self.config.max_spool_bytes)
            try:
                value = json.loads(encoded.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StorageError(f"spooled batch is not valid JSON: {path}") from error
            entry = self._validate_spool_entry(value, match.group(1))
            entries.append((path, entry, status.st_size))
        entries.sort(key=lambda item: (int(item[1]["createdAtEpochMs"]), str(item[1]["batchId"])))
        return entries

    def _quarantine_entries(
        self,
    ) -> list[tuple[Path, dict[str, object], int, str, int]]:
        entries: list[tuple[Path, dict[str, object], int, str, int]] = []
        for path in self.quarantine_directory.iterdir():
            match = QUARANTINE_NAME.fullmatch(path.name)
            if not match:
                raise StorageError(f"unexpected file in agent quarantine: {path}")
            status = validate_private_file(
                path, maximum_bytes=self.config.max_spool_bytes
            )
            encoded = read_private(path, maximum_bytes=self.config.max_spool_bytes)
            try:
                value = json.loads(encoded.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StorageError(f"quarantined batch is not valid JSON: {path}") from error
            entry = self._validate_spool_entry(value, match.group(1))
            quarantined_at = int(match.group(3))
            if not 0 <= quarantined_at <= MAX_SAFE_INTEGER:
                raise StorageError(f"quarantined batch time is invalid: {path}")
            entries.append((path, entry, status.st_size, match.group(2), quarantined_at))
        entries.sort(key=lambda item: (item[4], str(item[1]["batchId"])))
        return entries

    def _quarantine_summary(
        self,
        entries: list[tuple[Path, dict[str, object], int, str, int]],
        at: int,
    ) -> dict[str, object]:
        oldest = min((item[4] for item in entries), default=None)
        return {
            "entries": len(entries),
            "bytes": sum(item[2] for item in entries),
            "oldestAgeSeconds": (
                round(max(0, at - oldest) / 1000, 3) if oldest is not None else None
            ),
            "status": "retained" if entries else "empty",
            "batchTooOldEntries": sum(item[3] == "BATCH_TOO_OLD" for item in entries),
            "dataTooOldEntries": sum(item[3] == "DATA_TOO_OLD" for item in entries),
        }

    def _quarantine_spool_entry(
        self,
        path: Path,
        entry: dict[str, object],
        response_code: str,
        at: int,
    ) -> None:
        if response_code not in PERMANENT_INGEST_REJECTIONS:
            raise StorageError("refusing to quarantine a retryable ingest response")
        if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= MAX_SAFE_INTEGER:
            raise StorageError("clock returned an invalid quarantine epoch")
        batch_id = str(entry["batchId"])
        for existing_path, existing, _size, _code, _quarantined_at in self._quarantine_entries():
            if existing["batchId"] != batch_id:
                continue
            if canonical_json(existing) != canonical_json(entry):
                raise StorageError("quarantined batch ID conflicts with an active spool entry")
            raise StorageError(f"batch is already quarantined at {existing_path}")
        target = self.quarantine_directory / f"{batch_id}.{response_code}.{at}.rejected"
        if target.exists() or target.is_symlink():
            raise StorageError("quarantine target already exists")
        # Both private directories are on the same state filesystem.  The atomic
        # rename preserves the immutable envelope without a delete-before-copy
        # window or transiently exceeding the shared durable admission bound.
        path.rename(target)
        fsync_directory(self.quarantine_directory)
        fsync_directory(self.spool_directory)

    def _recover_enqueue(self, state: dict[str, object]) -> dict[str, object]:
        if not (self.journal_path.exists() or self.journal_path.is_symlink()):
            return state
        encoded = read_private(self.journal_path, maximum_bytes=self.config.max_spool_bytes)
        try:
            raw_journal = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("pending enqueue journal is not valid UTF-8 JSON") from error
        checkpoint: dict[str, object] | None = None
        records_sha256: str | None = None
        if isinstance(raw_journal, dict) and set(raw_journal) == JOURNAL_KEYS:
            journal = decode_exact_json(encoded, JOURNAL_KEYS, "pending enqueue journal")
            if journal["schemaVersion"] != 1:
                raise StorageError("pending enqueue journal schema version is invalid")
        elif isinstance(raw_journal, dict) and set(raw_journal) == CHECKPOINT_JOURNAL_KEYS:
            journal = raw_journal
            if journal["schemaVersion"] != 2:
                raise StorageError("checkpoint enqueue journal schema version is invalid")
            try:
                checkpoint = self._normalize_checkpoint(journal["checkpoint"])
            except ContractError as error:
                raise StorageError("pending enqueue journal checkpoint is invalid") from error
            records_sha256 = journal["recordsSha256"]
            if not isinstance(records_sha256, str) or not HEX_SHA256.fullmatch(records_sha256):
                raise StorageError("pending enqueue journal record digest is invalid")
        else:
            raise StorageError("pending enqueue journal has an invalid exact schema")
        if not isinstance(journal["entries"], list):
            raise StorageError("pending enqueue journal has an invalid contract")
        entries = [self._validate_spool_entry(item) for item in journal["entries"]]
        if not entries or len(entries) > self.config.max_spool_entries:
            raise StorageError("pending enqueue journal has an invalid entry bound")
        if (
            any(entry["agentId"] != state["agentId"] for entry in entries)
            or len({str(entry["batchId"]) for entry in entries}) != len(entries)
        ):
            raise StorageError("pending enqueue journal is not bound to this agent")
        for entry in entries:
            target = self.spool_directory / f"{entry['batchId']}.batch"
            expected = canonical_json(entry)
            if target.exists() or target.is_symlink():
                if read_private(target, maximum_bytes=self.config.max_spool_bytes) != expected:
                    raise StorageError("pending enqueue journal conflicts with an existing batch")
            else:
                atomic_private_write(target, expected, replace=False)
        highest = max(int(item["lastSequence"]) for item in entries)
        if int(state["nextSequence"]) <= highest:
            state["nextSequence"] = highest + 1
            if int(state["nextSequence"]) > MAX_SAFE_INTEGER:
                raise StorageError("agent sequence space is exhausted")
            self._persist_state(state)
        if checkpoint is not None and records_sha256 is not None:
            binding = self._load_collector_binding()
            if (
                binding is None
                or self._checkpoint_identity(checkpoint)
                != (
                    binding["hostId"],
                    binding["agentId"],
                    binding["identityGeneration"],
                )
                or checkpoint["agentId"] != state["agentId"]
                or checkpoint["hostId"] != state["hostId"]
            ):
                raise StorageError("pending enqueue checkpoint is not bound to this collector")
            receipt = {
                "schemaVersion": 1,
                "checkpoint": checkpoint,
                "recordsSha256": records_sha256,
                "batchIds": [str(item["batchId"]) for item in entries],
                "firstSequence": min(int(item["firstSequence"]) for item in entries),
                "lastSequence": highest,
                "createdAtEpochMs": min(int(item["createdAtEpochMs"]) for item in entries),
            }
            existing_receipt = self._load_checkpoint_receipt()
            if existing_receipt is not None:
                existing_checkpoint = existing_receipt["checkpoint"]
                assert isinstance(existing_checkpoint, dict)
                existing_sequence = int(existing_checkpoint["sourceSequence"])
                source_sequence = int(checkpoint["sourceSequence"])
                if self._checkpoint_identity(
                    existing_checkpoint
                ) != self._checkpoint_identity(checkpoint):
                    raise StorageError(
                        "pending enqueue checkpoint conflicts with its durable source identity"
                    )
                if existing_sequence > source_sequence:
                    raise StorageError("pending enqueue checkpoint is older than its durable receipt")
                if existing_sequence == source_sequence:
                    if existing_receipt != receipt:
                        raise StorageError("pending enqueue checkpoint conflicts with its durable receipt")
                else:
                    atomic_private_write(self.checkpoint_path, canonical_json(receipt))
            else:
                atomic_private_write(
                    self.checkpoint_path, canonical_json(receipt), replace=False
                )
        unlink_durable(self.journal_path, maximum_bytes=self.config.max_spool_bytes)
        return state

    def _reconcile_state(self, state: dict[str, object]) -> dict[str, object]:
        entries = self._spool_entries()
        quarantined = self._quarantine_entries()
        if (
            len(entries) + len(quarantined) > self.config.max_spool_entries
            or sum(item[2] for item in entries) + sum(item[2] for item in quarantined)
            > self.config.max_spool_bytes
        ):
            raise StorageError("agent spool and quarantine exceed their shared configured bound")
        highest = max(
            (
                int(item[1]["lastSequence"])
                for item in [*entries, *quarantined]
            ),
            default=0,
        )
        pending = state["pendingHeartbeat"]
        if isinstance(pending, dict):
            highest = max(highest, int(pending["sequence"]))
        changed = False
        if int(state["nextSequence"]) <= highest:
            state["nextSequence"] = highest + 1
            if int(state["nextSequence"]) > MAX_SAFE_INTEGER:
                raise StorageError("agent sequence space is exhausted")
            changed = True
        retries = state["retries"]
        assert isinstance(retries, dict)
        live_ids = {str(item[1]["batchId"]) for item in entries}
        for batch_id in list(retries):
            if batch_id not in live_ids:
                del retries[batch_id]
                changed = True
        if changed:
            self._persist_state(state)
        binding = self._load_collector_binding()
        if binding is not None and not self._binding_matches_state(binding, state):
            raise StorageError("collector binding does not match transport identity state")
        return state

    def enqueue(
        self,
        records: Iterable[object],
        *,
        checkpoint: object | None = None,
    ) -> list[str]:
        normalized_input: list[dict[str, object]] = []
        normalized_bytes = 2  # Canonical JSON array brackets.
        for record in records:
            if len(normalized_input) >= MAX_ENQUEUE_RECORDS:
                raise ContractError("one enqueue operation exceeds the 2,000-record bound")
            parsed = self._validate_record_input(record)
            encoded = canonical_json(parsed)
            candidate_bytes = normalized_bytes + len(encoded) + int(bool(normalized_input))
            if candidate_bytes > MAX_ENQUEUE_BYTES:
                raise ContractError("one enqueue operation exceeds the 2 MiB record bound")
            normalized_input.append(parsed)
            normalized_bytes = candidate_bytes
        if not normalized_input:
            raise ContractError("at least one telemetry record is required")
        normalized_checkpoint = self._normalize_checkpoint(checkpoint) if checkpoint is not None else None
        records_sha256 = _sha256(canonical_json(normalized_input))
        # One event makes a whole server queue entry priority.  Keep kinds in
        # separate immutable batches so reserved event capacity never carries
        # metric payloads.  Ordering within each kind is stable.
        normalized = [
            record
            for kind in ("metric", "event")
            for record in normalized_input
            if record["kind"] == kind
        ]
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            if normalized_checkpoint is not None:
                binding = self._load_collector_binding()
                if (
                    binding is None
                    or self._checkpoint_identity(normalized_checkpoint)
                    != (
                        binding["hostId"],
                        binding["agentId"],
                        binding["identityGeneration"],
                    )
                    or normalized_checkpoint["hostId"] != state["hostId"]
                    or normalized_checkpoint["agentId"] != state["agentId"]
                ):
                    raise ContractError("source checkpoint does not match the bound collector identity")
                receipt = self._load_checkpoint_receipt()
                if receipt is not None:
                    previous = receipt["checkpoint"]
                    assert isinstance(previous, dict)
                    if self._checkpoint_identity(previous) != self._checkpoint_identity(
                        normalized_checkpoint
                    ):
                        raise ContractError("source checkpoint identity conflicts with its durable receipt")
                    previous_sequence = int(previous["sourceSequence"])
                    source_sequence = int(normalized_checkpoint["sourceSequence"])
                    if source_sequence < previous_sequence:
                        raise ContractError("source checkpoint is older than its durable receipt")
                    if source_sequence == previous_sequence:
                        if previous != normalized_checkpoint:
                            raise ContractError(
                                "source checkpoint was reused with different checkpoint content"
                            )
                        if receipt["recordsSha256"] != records_sha256:
                            raise ContractError("source checkpoint was reused with different records")
                        batch_ids = receipt["batchIds"]
                        assert isinstance(batch_ids, list)
                        return [str(batch_id) for batch_id in batch_ids]
                    previous_observed = _parse_rfc3339(previous["observedAt"])
                    current_observed = _parse_rfc3339(normalized_checkpoint["observedAt"])
                    if (
                        previous_observed is None
                        or current_observed is None
                        or current_observed < previous_observed
                    ):
                        raise ContractError("source checkpoint time is older than its durable receipt")
            existing = self._spool_entries()
            quarantined = self._quarantine_entries()
            at = self._now()
            if not isinstance(at, int) or isinstance(at, bool) or not 1 <= at <= MAX_SAFE_INTEGER:
                raise StorageError("clock returned an invalid enqueue epoch")
            next_sequence = int(state["nextSequence"])
            # `nextSequence` itself must remain representable after recovery.
            # Reserve MAX_SAFE_INTEGER as the exhausted sentinel instead of
            # durably journaling a final record whose successor cannot be
            # encoded in the state schema.
            if next_sequence + len(normalized) > MAX_SAFE_INTEGER:
                raise StorageError("agent sequence space is exhausted")
            sent_at = _now_rfc3339(at)
            encoded_entries: list[bytes] = []
            batch_ids: list[str] = []
            new_entry_bytes = 0
            existing_bytes = sum(item[2] for item in existing)
            quarantined_bytes = sum(item[2] for item in quarantined)
            allocated_batch_ids = {
                str(item[1]["batchId"]) for item in [*existing, *quarantined]
            }
            cursor = 0
            pending_record: tuple[dict[str, object], int] | None = None
            while cursor < len(normalized):
                if (
                    len(existing) + len(quarantined) + len(encoded_entries)
                    >= self.config.max_spool_entries
                ):
                    raise SpoolFullError(
                        "agent spool/quarantine entry limit is full; no acknowledged batch was "
                        "evicted and quarantine requires explicit purge"
                    )
                batch_records: list[dict[str, object]] = []
                batch_record_bytes = 0
                batch_kind = normalized[cursor]["kind"]
                batch_id = str(self._uuid_factory())
                if not UUID_V4.fullmatch(batch_id):
                    raise StorageError("UUID provider did not return a UUIDv4 batch ID")
                if batch_id in allocated_batch_ids:
                    raise StorageError("UUID provider reused a retained batch ID")
                allocated_batch_ids.add(batch_id)
                while (
                    cursor < len(normalized)
                    and len(batch_records) < self.config.max_batch_records
                    and normalized[cursor]["kind"] == batch_kind
                ):
                    sequence = next_sequence + cursor
                    if pending_record is None:
                        candidate_record = {**normalized[cursor], "sequence": sequence}
                        candidate_record_bytes = len(canonical_json(candidate_record))
                    else:
                        candidate_record, candidate_record_bytes = pending_record
                    candidate_count = len(batch_records) + 1
                    empty_candidate = {
                        "schemaVersion": 1,
                        "agentId": state["agentId"],
                        "batchId": batch_id,
                        "sentAt": sent_at,
                        "firstSequence": next_sequence + cursor - len(batch_records),
                        "lastSequence": sequence,
                        "records": [],
                    }
                    candidate_size = (
                        len(canonical_json(empty_candidate))
                        + batch_record_bytes
                        + candidate_record_bytes
                        + candidate_count
                        - 1
                    )
                    if candidate_size > self.config.max_batch_bytes:
                        if not batch_records:
                            raise ContractError("one telemetry record cannot fit in maxBatchBytes")
                        pending_record = (candidate_record, candidate_record_bytes)
                        break
                    batch_records.append(candidate_record)
                    batch_record_bytes += candidate_record_bytes
                    pending_record = None
                    cursor += 1
                batch = {
                    "schemaVersion": 1,
                    "agentId": state["agentId"],
                    "batchId": batch_id,
                    "sentAt": sent_at,
                    "firstSequence": batch_records[0]["sequence"],
                    "lastSequence": batch_records[-1]["sequence"],
                    "records": batch_records,
                }
                entry = self._encode_spool_entry(batch, at)
                encoded_entry = canonical_json(entry)
                projected_entry_bytes = new_entry_bytes + len(encoded_entry)
                projected_count = len(encoded_entries) + 1
                projected_entries = [*encoded_entries, encoded_entry]
                projected_journal_bytes = len(_encode_enqueue_journal(
                    projected_entries, normalized_checkpoint, records_sha256
                ))
                # The journal and materialized entries coexist until sequence state is durable.
                if (
                    existing_bytes
                    + quarantined_bytes
                    + projected_entry_bytes
                    + projected_journal_bytes
                    > self.config.max_spool_bytes
                ):
                    raise SpoolFullError(
                        "agent spool/quarantine byte limit is full; no acknowledged batch was "
                        "evicted and quarantine requires explicit purge"
                    )
                encoded_entries.append(encoded_entry)
                batch_ids.append(batch_id)
                new_entry_bytes = projected_entry_bytes

            journal = _encode_enqueue_journal(
                encoded_entries, normalized_checkpoint, records_sha256
            )
            atomic_private_write(self.journal_path, journal, replace=False)
            state = self._recover_enqueue(state)
            return batch_ids

    def _read_token_file(self, path: Path) -> tuple[bytearray, tuple[int, int, int]]:
        self._validate_token_parent(path)
        status = validate_private_file(path, maximum_bytes=MAX_TOKEN_BYTES)
        encoded = bytearray(read_private(path, maximum_bytes=MAX_TOKEN_BYTES))
        return encoded, (status.st_dev, status.st_ino, status.st_size)

    @staticmethod
    def _validate_token_parent(path: Path) -> None:
        if not path.is_absolute() or ".." in path.parts or os.path.normpath(str(path)) != str(path):
            raise EnrollmentError("enrollment token file path must be absolute and normalized")
        try:
            parent = path.parent.stat(follow_symlinks=False)
        except OSError as error:
            raise EnrollmentError("enrollment token parent is unavailable") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise EnrollmentError("enrollment token parent must not be group/world writable")

    @staticmethod
    def read_token_stdin(stream: BinaryIO) -> bytearray:
        encoded = bytearray(stream.read(MAX_TOKEN_BYTES + 1))
        if len(encoded) > MAX_TOKEN_BYTES:
            for index in range(len(encoded)):
                encoded[index] = 0
            raise EnrollmentError("enrollment token input exceeds its size bound")
        return encoded

    def begin_enrollment(self, token: bytearray, *, source_path: Path | None = None) -> str:
        """Durably stage a one-use token and attempt enrollment once.

        Callers must supply token material from standard input or ``read_token_file``;
        it is deliberately never accepted as a command-line string.
        """

        try:
            supplied = bytes(token).strip()
            if not ENROLLMENT_TOKEN.fullmatch(supplied.decode("ascii", "strict")):
                raise EnrollmentError("enrollment token has an invalid contract")
            with self._locked_storage():
                state = self._recover_enqueue(self._load_or_create_state())
                if state["registered"]:
                    raise EnrollmentError("agent is already enrolled")
                if self.pending_enrollment_path.exists() or self.pending_enrollment_path.is_symlink():
                    raise EnrollmentError("a pending enrollment already exists; use run-once to resume it")
                source_identity: tuple[int, int, int] | None = None
                if source_path is not None:
                    self._validate_token_parent(source_path)
                    status = validate_private_file(source_path, maximum_bytes=MAX_TOKEN_BYTES)
                    actual = read_private(source_path, maximum_bytes=MAX_TOKEN_BYTES).strip()
                    if actual != supplied:
                        raise EnrollmentError("token file changed before enrollment was staged")
                    source_identity = (status.st_dev, status.st_ino, status.st_size)
                inventory = _validate_inventory(self._inventory_provider(self.config.agent_version))
                body = canonical_json(
                    {
                        "schemaVersion": 1,
                        "enrollmentToken": supplied.decode("ascii"),
                        "hostId": state["hostId"],
                        "agentId": state["agentId"],
                        "machineIdentityDigest": state["machineIdentityDigest"],
                        "installationEpoch": state["installationEpoch"],
                        "heartbeatIntervalSeconds": self.config.heartbeat_interval_seconds,
                        "inventory": inventory,
                    }
                )
                pending = {
                    "schemaVersion": 1,
                    "agentId": state["agentId"],
                    "hostId": state["hostId"],
                    "bodyBase64": base64.b64encode(body).decode("ascii"),
                    "bodySha256": _sha256(body),
                    "sourcePath": str(source_path) if source_path is not None else None,
                    "sourceDevice": source_identity[0] if source_identity else None,
                    "sourceInode": source_identity[1] if source_identity else None,
                    "sourceSize": source_identity[2] if source_identity else None,
                }
                atomic_private_write(self.pending_enrollment_path, canonical_json(pending), replace=False)
                state["enrollmentRetry"] = {"attempts": 0, "nextAttemptAtEpochMs": self._now()}
                self._persist_state(state)
                return self._attempt_enrollment(state, force=True)
        finally:
            for index in range(len(token)):
                token[index] = 0

    def enroll_from_file(self, path: Path) -> str:
        token, _ = self._read_token_file(path)
        return self.begin_enrollment(token, source_path=path)

    def _load_pending_enrollment(self) -> dict[str, object]:
        encoded = read_private(
            self.pending_enrollment_path, maximum_bytes=MAX_PENDING_ENROLLMENT_BYTES
        )
        value = decode_exact_json(encoded, PENDING_ENROLLMENT_KEYS, "pending enrollment")
        if (
            value["schemaVersion"] != 1
            or not isinstance(value["agentId"], str)
            or not UUID_V4.fullmatch(value["agentId"])
            or not isinstance(value["hostId"], str)
            or not UUID_V4.fullmatch(value["hostId"])
            or not isinstance(value["bodySha256"], str)
            or not HEX_SHA256.fullmatch(value["bodySha256"])
        ):
            raise StorageError("pending enrollment identity is invalid")
        source_values = [value["sourceDevice"], value["sourceInode"], value["sourceSize"]]
        if value["sourcePath"] is None:
            if any(item is not None for item in source_values):
                raise StorageError("pending enrollment source identity is invalid")
        elif (
            not isinstance(value["sourcePath"], str)
            or not Path(value["sourcePath"]).is_absolute()
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in source_values)
        ):
            raise StorageError("pending enrollment token source is invalid")
        body = _decode_base64(value["bodyBase64"], "pending enrollment body")
        if len(body) > 64 * 1024 or _sha256(body) != value["bodySha256"]:
            raise StorageError("pending enrollment body digest does not match")
        try:
            registration = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("pending enrollment body is invalid JSON") from error
        if (
            not isinstance(registration, dict)
            or set(registration)
            != {
                "schemaVersion",
                "enrollmentToken",
                "hostId",
                "agentId",
                "machineIdentityDigest",
                "installationEpoch",
                "heartbeatIntervalSeconds",
                "inventory",
            }
            or registration["schemaVersion"] != 1
            or registration["agentId"] != value["agentId"]
            or registration["hostId"] != value["hostId"]
            or not isinstance(registration["enrollmentToken"], str)
            or not ENROLLMENT_TOKEN.fullmatch(registration["enrollmentToken"])
            or not isinstance(registration["machineIdentityDigest"], str)
            or not HEX_SHA256.fullmatch(registration["machineIdentityDigest"])
            or _parse_rfc3339(registration["installationEpoch"]) is None
            or not isinstance(registration["heartbeatIntervalSeconds"], int)
            or isinstance(registration["heartbeatIntervalSeconds"], bool)
            or not 10 <= registration["heartbeatIntervalSeconds"] <= 86_400
        ):
            raise StorageError("pending enrollment request has an invalid exact schema")
        _validate_inventory(registration["inventory"])
        return value

    def _reconcile_enrollment(self, state: dict[str, object]) -> None:
        pending_exists = self.pending_enrollment_path.exists() or self.pending_enrollment_path.is_symlink()
        if state["registered"]:
            if pending_exists:
                self._erase_pending_enrollment()
            if state["enrollmentRetry"] is not None:
                state["enrollmentRetry"] = None
                self._persist_state(state)
            return
        if pending_exists:
            pending = self._load_pending_enrollment()
            if pending["agentId"] != state["agentId"] or pending["hostId"] != state["hostId"]:
                raise StorageError("pending enrollment is bound to another local identity")
            if state["enrollmentRetry"] is None:
                state["enrollmentRetry"] = {"attempts": 0, "nextAttemptAtEpochMs": self._now()}
                self._persist_state(state)
        elif state["enrollmentRetry"] is not None:
            state["enrollmentRetry"] = None
            self._persist_state(state)

    def _erase_pending_enrollment(self) -> None:
        pending = self._load_pending_enrollment()
        source_error: Exception | None = None
        if isinstance(pending["sourcePath"], str):
            expected = (
                int(pending["sourceDevice"]),
                int(pending["sourceInode"]),
                int(pending["sourceSize"]),
            )
            try:
                erase_private_file(Path(pending["sourcePath"]), expected=expected)
            except Exception as error:  # Preserve success, but report that erasure was not provable.
                source_error = error
        erase_private_file(self.pending_enrollment_path)
        if source_error is not None:
            raise EnrollmentError("enrollment succeeded but token-file erasure could not be verified") from source_error

    def _response_json(self, response: HttpResponse) -> dict[str, object] | None:
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _valid_enrollment_ack(self, response: HttpResponse, pending: dict[str, object]) -> bool:
        value = self._response_json(response)
        return (
            200 <= response.status < 300
            and value is not None
            and value.get("registered") is True
            and value.get("agentId") == pending["agentId"]
            and value.get("hostId") == pending["hostId"]
            and _parse_rfc3339(value.get("serverTime")) is not None
        )

    def _valid_heartbeat_ack(self, response: HttpResponse) -> bool:
        value = self._response_json(response)
        return (
            200 <= response.status < 300
            and value is not None
            and value.get("accepted") is True
            and _parse_rfc3339(value.get("serverTime")) is not None
        )

    def _valid_ingest_ack(self, response: HttpResponse, batch_id: str, record_count: int) -> bool:
        value = self._response_json(response)
        accepted = value.get("acceptedRecords") if value is not None else None
        duplicate = value.get("duplicateRecords") if value is not None else None
        return (
            200 <= response.status < 300
            and value is not None
            and value.get("accepted") is True
            and value.get("batchId") == batch_id
            and isinstance(accepted, int)
            and not isinstance(accepted, bool)
            and accepted >= 0
            and isinstance(duplicate, int)
            and not isinstance(duplicate, bool)
            and duplicate >= 0
            and accepted + duplicate == record_count
            and _parse_rfc3339(value.get("serverTime")) is not None
        )

    def _permanent_ingest_rejection(self, response: HttpResponse) -> str | None:
        if response.status != 422:
            return None
        value = self._response_json(response)
        code = value.get("code") if value is not None else None
        return str(code) if code in PERMANENT_INGEST_REJECTIONS else None

    def _retry_after_seconds(self, response: HttpResponse, at: int) -> float | None:
        if response.status != 429:
            return None
        raw = response.headers.get("retry-after")
        if raw is None:
            return None
        if re.fullmatch(r"[0-9]+", raw):
            if len(raw) > 10:
                return float(self.config.retry_after_maximum_seconds)
            parsed = float(int(raw))
        else:
            try:
                value = email.utils.parsedate_to_datetime(raw)
                if value.tzinfo is None:
                    value = value.replace(tzinfo=dt.timezone.utc)
                parsed = max(0.0, value.timestamp() - at / 1000)
            except (TypeError, ValueError, OverflowError):
                return None
        return min(parsed, float(self.config.retry_after_maximum_seconds))

    def _next_retry(self, attempts: int, at: int, response: HttpResponse | None) -> dict[str, int]:
        attempts = min(MAX_SAFE_INTEGER, attempts + 1)
        exponent = min(attempts - 1, 62)
        ceiling = min(
            self.config.backoff_maximum_seconds,
            self.config.backoff_initial_seconds * (2**exponent),
        )
        sample = self._jitter()
        if not isinstance(sample, (int, float)) or isinstance(sample, bool) or not 0 <= sample < 1:
            raise StorageError("jitter provider returned a value outside [0, 1)")
        delay = ceiling / 2 + float(sample) * ceiling / 2
        if response is not None:
            retry_after = self._retry_after_seconds(response, at)
            if retry_after is not None:
                delay = max(delay, retry_after)
        return {
            "attempts": attempts,
            "nextAttemptAtEpochMs": min(MAX_SAFE_INTEGER, at + max(1, math.ceil(delay * 1000))),
        }

    def _attempt_enrollment(self, state: dict[str, object], *, force: bool = False) -> str:
        if not (self.pending_enrollment_path.exists() or self.pending_enrollment_path.is_symlink()):
            return "not-pending"
        pending = self._load_pending_enrollment()
        if pending["agentId"] != state["agentId"] or pending["hostId"] != state["hostId"]:
            raise StorageError("pending enrollment is bound to another local identity")
        retry = state["enrollmentRetry"]
        if not _valid_retry(retry):
            raise StorageError("pending enrollment is missing retry state")
        at = self._now()
        assert isinstance(retry, dict)
        if not force and at < int(retry["nextAttemptAtEpochMs"]):
            return "backoff"
        body = _decode_base64(pending["bodyBase64"], "pending enrollment body")
        response: HttpResponse | None = None
        try:
            response = self._requester.post("/agent/enroll", body, "identity")
        except AgentTransportError:
            pass
        if response is not None and self._valid_enrollment_ack(response, pending):
            state["registered"] = True
            state["enrollmentRetry"] = None
            state["nextHeartbeatDueAtEpochMs"] = at
            self._persist_state(state)
            self._erase_pending_enrollment()
            return "acknowledged"
        state["enrollmentRetry"] = self._next_retry(int(retry["attempts"]), at, response)
        self._persist_state(state)
        return "retry-scheduled"

    def _validate_heartbeat_body(self, body: bytes, agent_id: object, sequence: object) -> None:
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StorageError("pending heartbeat is not valid UTF-8 JSON") from error
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schemaVersion",
                "agentId",
                "sequence",
                "observedAt",
                "expectedIntervalSeconds",
                "lifecycle",
                "inventory",
            }
            or value["schemaVersion"] != 1
            or value["agentId"] != agent_id
            or value["sequence"] != sequence
            or _parse_rfc3339(value["observedAt"]) is None
            or not isinstance(value["expectedIntervalSeconds"], int)
            or isinstance(value["expectedIntervalSeconds"], bool)
            or not 10 <= value["expectedIntervalSeconds"] <= 86_400
            or value["lifecycle"] not in {"active", "maintenance", "inactive"}
        ):
            raise StorageError("pending heartbeat has an invalid exact schema")
        _validate_inventory(value["inventory"])

    def _ensure_pending_heartbeat(self, state: dict[str, object], at: int) -> None:
        if state["pendingHeartbeat"] is not None or at < int(state["nextHeartbeatDueAtEpochMs"]):
            return
        sequence = int(state["nextSequence"])
        if sequence >= MAX_SAFE_INTEGER:
            raise StorageError("agent sequence space is exhausted")
        inventory = _validate_inventory(self._inventory_provider(self.config.agent_version))
        body = canonical_json(
            {
                "schemaVersion": 1,
                "agentId": state["agentId"],
                "sequence": sequence,
                "observedAt": _now_rfc3339(at),
                "expectedIntervalSeconds": self.config.heartbeat_interval_seconds,
                "lifecycle": self.config.lifecycle,
                "inventory": inventory,
            }
        )
        state["pendingHeartbeat"] = {
            "sequence": sequence,
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "bodySha256": _sha256(body),
            "attempts": 0,
            "nextAttemptAtEpochMs": at,
        }
        state["nextSequence"] = sequence + 1
        self._persist_state(state)

    def _attempt_heartbeat(self, state: dict[str, object]) -> str:
        at = self._now()
        self._ensure_pending_heartbeat(state, at)
        pending = state["pendingHeartbeat"]
        if not isinstance(pending, dict):
            return "not-due"
        if at < int(pending["nextAttemptAtEpochMs"]):
            return "backoff"
        body = _decode_base64(pending["bodyBase64"], "pending heartbeat body")
        response: HttpResponse | None = None
        try:
            response = self._requester.post("/agent/heartbeat", body, "identity")
        except AgentTransportError:
            pass
        if response is not None and self._valid_heartbeat_ack(response):
            state["pendingHeartbeat"] = None
            state["nextHeartbeatDueAtEpochMs"] = min(
                MAX_SAFE_INTEGER, at + self.config.heartbeat_interval_seconds * 1000
            )
            self._persist_state(state)
            return "acknowledged"
        retry = self._next_retry(int(pending["attempts"]), at, response)
        pending.update(retry)
        self._persist_state(state)
        return "retry-scheduled"

    def _attempt_ingest(self, state: dict[str, object]) -> str:
        entries = self._spool_entries()
        if not entries:
            return "empty"
        retries = state["retries"]
        assert isinstance(retries, dict)
        at = self._now()
        selected: tuple[Path, dict[str, object], int] | None = None
        selected_retry: dict[str, int] | None = None
        for entry in entries:
            batch_id = str(entry[1]["batchId"])
            retry = retries.get(batch_id, {"attempts": 0, "nextAttemptAtEpochMs": 0})
            if not _valid_retry(retry):
                raise StorageError("telemetry batch retry state is invalid")
            if at >= int(retry["nextAttemptAtEpochMs"]):
                selected = entry
                selected_retry = retry
                break
        if selected is None or selected_retry is None:
            return "backoff"
        path, entry, _ = selected
        wire = _decode_base64(entry["wireBodyBase64"], "spooled wire body")
        response: HttpResponse | None = None
        try:
            response = self._requester.post(
                "/agent/ingest", wire, str(entry["contentEncoding"])
            )
        except AgentTransportError:
            pass
        batch_id = str(entry["batchId"])
        if response is not None and self._valid_ingest_ack(
            response, batch_id, int(entry["recordCount"])
        ):
            # The remote acknowledgement is validated before the durable local deletion.
            unlink_durable(path, maximum_bytes=self.config.max_spool_bytes)
            retries.pop(batch_id, None)
            self._persist_state(state)
            return "acknowledged"
        if response is not None:
            rejection = self._permanent_ingest_rejection(response)
            if rejection is not None:
                self._quarantine_spool_entry(path, entry, rejection, at)
                retries.pop(batch_id, None)
                self._persist_state(state)
                return "quarantined"
        retries[batch_id] = self._next_retry(int(selected_retry["attempts"]), at, response)
        self._persist_state(state)
        return "retry-scheduled"

    def _resource_snapshot(self) -> tuple[str, tuple[float, float, int] | None]:
        try:
            usage = self._resource_usage_provider()
            user = float(getattr(usage, "ru_utime"))
            system = float(getattr(usage, "ru_stime"))
            max_rss_kib = int(getattr(usage, "ru_maxrss"))
        except (AttributeError, OverflowError, TypeError, ValueError, OSError):
            return "unavailable", None
        if (
            not math.isfinite(user)
            or not math.isfinite(system)
            or user < 0
            or system < 0
            or not 0 <= max_rss_kib <= MAX_SAFE_INTEGER // 1024
        ):
            return "unavailable", None
        return "available", (user, system, max_rss_kib * 1024)

    def _proc_io_snapshot(self) -> tuple[str, dict[str, int] | None]:
        path = self._proc_self_io_path
        if not path.is_absolute() or ".." in path.parts or os.path.normpath(str(path)) != str(path):
            return "unreadable", None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return "missing", None
        except OSError:
            return "unreadable", None
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_uid not in {0, os.geteuid()}:
                return "unreadable", None
            encoded = bytearray()
            while len(encoded) <= 4096:
                chunk = os.read(descriptor, 4097 - len(encoded))
                if not chunk:
                    break
                encoded.extend(chunk)
            if len(encoded) > 4096:
                return "corrupt", None
        except OSError:
            return "unreadable", None
        finally:
            os.close(descriptor)
        try:
            text = bytes(encoded).decode("ascii")
        except UnicodeDecodeError:
            return "corrupt", None
        values: dict[str, int] = {}
        for line in text.splitlines():
            match = re.fullmatch(r"([a-z_]+): ([0-9]+)", line)
            if match is None or match.group(1) not in PROC_IO_ALL_FIELDS:
                return "corrupt", None
            name = match.group(1)
            if name in values:
                return "corrupt", None
            try:
                parsed = int(match.group(2))
            except ValueError:
                return "corrupt", None
            if parsed > MAX_SAFE_INTEGER:
                return "corrupt", None
            values[name] = parsed
        if set(values) != PROC_IO_ALL_FIELDS:
            return "corrupt", None
        return "available", {name: values[name] for name in PROC_IO_FIELDS}

    def _validate_self_metrics(self, value: object, expected_agent_id: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != SELF_METRICS_KEYS:
            raise StorageError("agent self-metrics has an invalid exact schema")
        if (
            value["schemaVersion"] != 1
            or value["agentId"] != expected_agent_id
            or _parse_rfc3339(value["observedAt"]) is None
            or value["resourceUsageStatus"] not in {"available", "unavailable"}
            or value["procIoStatus"] not in {"available", "missing", "corrupt", "unreadable"}
            or value["priorStateStatus"] not in {"valid", "missing", "corrupt", "unwritable"}
        ):
            raise StorageError("agent self-metrics identity or status is invalid")
        numeric_fields = {
            "runDurationSeconds",
            "userCpuSeconds",
            "systemCpuSeconds",
            "maxRssBytes",
            "ioReadBytes",
            "ioWriteBytes",
            "ioReadSyscalls",
            "ioWriteSyscalls",
            "heartbeatAckAgeSeconds",
        }
        for name in numeric_fields:
            item = value[name]
            if item is not None and (
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not math.isfinite(float(item))
                or not 0 <= float(item) <= MAX_SAFE_INTEGER
            ):
                raise StorageError(f"agent self-metrics {name} is invalid")
        resource_values = (
            value["userCpuSeconds"], value["systemCpuSeconds"], value["maxRssBytes"]
        )
        if value["resourceUsageStatus"] == "available":
            if any(item is None for item in resource_values):
                raise StorageError("available resource usage is missing a measurement")
        elif any(item is not None for item in resource_values):
            raise StorageError("unavailable resource usage contains a measurement")
        io_values = (
            value["ioReadBytes"],
            value["ioWriteBytes"],
            value["ioReadSyscalls"],
            value["ioWriteSyscalls"],
        )
        if value["procIoStatus"] == "available":
            if any(item is None for item in io_values):
                raise StorageError("available proc I/O is missing a measurement")
        elif any(item is not None for item in io_values):
            raise StorageError("unavailable proc I/O contains a measurement")
        outcomes = value["outcomes"]
        retries = value["retryStreaks"]
        supported_outcomes = {
            "not-enrolled",
            "not-pending",
            "not-due",
            "empty",
            "backoff",
            "retry-scheduled",
            "acknowledged",
            "quarantined",
            "error",
        }
        if (
            not isinstance(outcomes, dict)
            or set(outcomes) != SELF_OUTCOME_KEYS
            or any(item not in supported_outcomes for item in outcomes.values())
            or not isinstance(retries, dict)
            or set(retries) != SELF_OUTCOME_KEYS
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or not 0 <= item <= MAX_SAFE_INTEGER
                for item in retries.values()
            )
        ):
            raise StorageError("agent self-metrics outcomes or retry streaks are invalid")
        last_ack = value["lastHeartbeatAckAt"]
        if last_ack is not None and _parse_rfc3339(last_ack) is None:
            raise StorageError("agent self-metrics last heartbeat acknowledgement is invalid")
        if (last_ack is None) != (value["heartbeatAckAgeSeconds"] is None):
            raise StorageError("agent self-metrics heartbeat acknowledgement fields disagree")
        spool = value["spool"]
        if not isinstance(spool, dict) or set(spool) != SELF_SPOOL_KEYS:
            raise StorageError("agent self-metrics spool has an invalid exact schema")
        for name in {"entries", "bytes", "maxEntries", "maxBytes"}:
            item = spool[name]
            minimum = 1 if name.startswith("max") else 0
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or not minimum <= item <= MAX_SAFE_INTEGER
            ):
                raise StorageError(f"agent self-metrics spool {name} is invalid")
        for name in {"entriesUsedPercent", "bytesUsedPercent"}:
            item = spool[name]
            if (
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not math.isfinite(float(item))
                or not 0 <= float(item) <= 100
            ):
                raise StorageError(f"agent self-metrics spool {name} is invalid")
        if spool["entries"] > spool["maxEntries"] or spool["bytes"] > spool["maxBytes"]:
            raise StorageError("agent self-metrics spool exceeds its declared maximum")
        oldest = spool["oldestAgeSeconds"]
        if oldest is not None and (
            not isinstance(oldest, (int, float))
            or isinstance(oldest, bool)
            or not math.isfinite(float(oldest))
            or not 0 <= float(oldest) <= MAX_SAFE_INTEGER
        ):
            raise StorageError("agent self-metrics spool oldestAgeSeconds is invalid")
        if (spool["entries"] == 0) != (oldest is None):
            raise StorageError("agent self-metrics spool age does not match its entry count")
        quarantine = value["quarantine"]
        if not isinstance(quarantine, dict) or set(quarantine) != SELF_QUARANTINE_KEYS:
            raise StorageError("agent self-metrics quarantine has an invalid exact schema")
        for name in {
            "entries",
            "bytes",
            "batchTooOldEntries",
            "dataTooOldEntries",
        }:
            item = quarantine[name]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or not 0 <= item <= MAX_SAFE_INTEGER
            ):
                raise StorageError(f"agent self-metrics quarantine {name} is invalid")
        quarantine_oldest = quarantine["oldestAgeSeconds"]
        if quarantine_oldest is not None and (
            not isinstance(quarantine_oldest, (int, float))
            or isinstance(quarantine_oldest, bool)
            or not math.isfinite(float(quarantine_oldest))
            or not 0 <= float(quarantine_oldest) <= MAX_SAFE_INTEGER
        ):
            raise StorageError("agent self-metrics quarantine oldestAgeSeconds is invalid")
        if (
            quarantine["status"] not in {"empty", "retained"}
            or (quarantine["entries"] == 0) != (quarantine_oldest is None)
            or (quarantine["entries"] == 0) != (quarantine["status"] == "empty")
            or quarantine["batchTooOldEntries"] + quarantine["dataTooOldEntries"]
            != quarantine["entries"]
        ):
            raise StorageError("agent self-metrics quarantine counters or status disagree")
        return value

    def _prior_self_metrics(
        self, expected_agent_id: object
    ) -> tuple[dict[str, object] | None, str]:
        if not (self.self_metrics_path.exists() or self.self_metrics_path.is_symlink()):
            return None, "missing"
        try:
            encoded = read_private(self.self_metrics_path, maximum_bytes=MAX_SELF_METRICS_BYTES)
            value = json.loads(encoded.decode("utf-8"))
            return self._validate_self_metrics(value, expected_agent_id), "valid"
        except (StorageError, UnicodeDecodeError, json.JSONDecodeError):
            return None, "corrupt"

    @staticmethod
    def _io_status(left: str, right: str) -> str:
        if left == right:
            return left
        for status in ("corrupt", "unreadable", "missing"):
            if status in {left, right}:
                return status
        return "unreadable"

    def _write_run_self_metrics(
        self,
        *,
        result: RunResult,
        state: dict[str, object] | None,
        entries: list[tuple[Path, dict[str, object], int]] | None,
        quarantine_entries: list[tuple[Path, dict[str, object], int, str, int]] | None,
        started_monotonic_ns: int | None,
        started_resource: tuple[str, tuple[float, float, int] | None],
        started_io: tuple[str, dict[str, int] | None],
    ) -> None:
        """Best-effort observability: measurement failure never blocks transport."""

        if state is None:
            return
        prior, prior_status = self._prior_self_metrics(state["agentId"])
        try:
            ended_monotonic_ns = self._monotonic_ns()
        except (OSError, OverflowError, TypeError, ValueError):
            ended_monotonic_ns = None
        ended_resource = self._resource_snapshot()
        ended_io = self._proc_io_snapshot()
        at = self._now()
        if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= MAX_SAFE_INTEGER:
            return

        duration: float | None = None
        if (
            isinstance(started_monotonic_ns, int)
            and isinstance(ended_monotonic_ns, int)
            and ended_monotonic_ns >= started_monotonic_ns
        ):
            duration = round((ended_monotonic_ns - started_monotonic_ns) / 1_000_000_000, 9)
        resource_status = "unavailable"
        user_cpu: float | None = None
        system_cpu: float | None = None
        max_rss: int | None = None
        if (
            started_resource[0] == "available"
            and ended_resource[0] == "available"
            and started_resource[1] is not None
            and ended_resource[1] is not None
            and ended_resource[1][0] >= started_resource[1][0]
            and ended_resource[1][1] >= started_resource[1][1]
        ):
            resource_status = "available"
            user_cpu = round(ended_resource[1][0] - started_resource[1][0], 9)
            system_cpu = round(ended_resource[1][1] - started_resource[1][1], 9)
            max_rss = ended_resource[1][2]

        io_status = self._io_status(started_io[0], ended_io[0])
        io_values: dict[str, int | None] = {name: None for name in PROC_IO_FIELDS}
        if (
            io_status == "available"
            and started_io[1] is not None
            and ended_io[1] is not None
            and all(ended_io[1][name] >= started_io[1][name] for name in PROC_IO_FIELDS)
        ):
            io_values = {
                name: ended_io[1][name] - started_io[1][name] for name in PROC_IO_FIELDS
            }
        elif io_status == "available":
            io_status = "corrupt"

        last_ack_ms: int | None = None
        if prior is not None and prior["lastHeartbeatAckAt"] is not None:
            last_ack_ms = _parse_rfc3339(prior["lastHeartbeatAckAt"])
        if result.heartbeat == "acknowledged":
            last_ack_ms = at
        last_ack = _now_rfc3339(last_ack_ms) if last_ack_ms is not None else None
        ack_age = (
            round(max(0, at - last_ack_ms) / 1000, 3) if last_ack_ms is not None else None
        )

        safe_entries = entries or []
        safe_quarantine = quarantine_entries or []
        spool_bytes = sum(item[2] for item in safe_entries)
        oldest = min(
            (int(item[1]["createdAtEpochMs"]) for item in safe_entries), default=None
        )
        pending = state["pendingHeartbeat"]
        enrollment_retry = state["enrollmentRetry"]
        retries = state["retries"]
        assert isinstance(retries, dict)
        payload: dict[str, object] = {
            "schemaVersion": 1,
            "agentId": state["agentId"],
            "observedAt": _now_rfc3339(at),
            "runDurationSeconds": duration,
            "userCpuSeconds": user_cpu,
            "systemCpuSeconds": system_cpu,
            "maxRssBytes": max_rss,
            "ioReadBytes": io_values["read_bytes"],
            "ioWriteBytes": io_values["write_bytes"],
            "ioReadSyscalls": io_values["syscr"],
            "ioWriteSyscalls": io_values["syscw"],
            "resourceUsageStatus": resource_status,
            "procIoStatus": io_status,
            "priorStateStatus": prior_status,
            "outcomes": result.as_dict(),
            "retryStreaks": {
                "enrollment": int(enrollment_retry["attempts"])
                if isinstance(enrollment_retry, dict)
                else 0,
                "heartbeat": int(pending["attempts"]) if isinstance(pending, dict) else 0,
                "ingest": max(
                    (int(item["attempts"]) for item in retries.values() if isinstance(item, dict)),
                    default=0,
                ),
            },
            "lastHeartbeatAckAt": last_ack,
            "heartbeatAckAgeSeconds": ack_age,
            "spool": {
                "entries": len(safe_entries),
                "bytes": spool_bytes,
                "maxEntries": self.config.max_spool_entries,
                "maxBytes": self.config.max_spool_bytes,
                "entriesUsedPercent": round(
                    100 * len(safe_entries) / self.config.max_spool_entries, 3
                ),
                "bytesUsedPercent": round(
                    100 * spool_bytes / self.config.max_spool_bytes, 3
                ),
                "oldestAgeSeconds": (
                    round(max(0, at - oldest) / 1000, 3) if oldest is not None else None
                ),
            },
            "quarantine": self._quarantine_summary(safe_quarantine, at),
        }
        try:
            self._validate_self_metrics(payload, state["agentId"])
            atomic_private_write(self.self_metrics_path, canonical_json(payload))
        except (StorageError, OSError, OverflowError, ValueError):
            # Self-observation is explicitly non-blocking; status()/the producer
            # report a missing/corrupt file instead of hiding transport work.
            return

    def _best_effort_write_run_self_metrics(self, **arguments: Any) -> None:
        try:
            self._write_run_self_metrics(**arguments)
        except Exception:
            # Instrumentation must never replace a transport result/failure.
            return

    def run_once(self) -> RunResult:
        """Attempt enrollment, an independently due heartbeat, and one due batch."""

        try:
            started_monotonic_ns: int | None = self._monotonic_ns()
        except (OSError, OverflowError, TypeError, ValueError):
            started_monotonic_ns = None
        started_resource = self._resource_snapshot()
        started_io = self._proc_io_snapshot()
        state: dict[str, object] | None = None
        entries: list[tuple[Path, dict[str, object], int]] | None = None
        quarantine_entries: list[
            tuple[Path, dict[str, object], int, str, int]
        ] | None = None
        result = RunResult(enrollment="error", heartbeat="error", ingest="error")
        try:
            with self._locked_storage():
                state = self._recover_enqueue(self._load_or_create_state())
                state = self._reconcile_state(state)
                self._reconcile_enrollment(state)
                entries = self._spool_entries()
                quarantine_entries = self._quarantine_entries()
                enrollment = self._attempt_enrollment(state)
                if not state["registered"]:
                    result = RunResult(
                        enrollment=enrollment,
                        heartbeat="not-enrolled",
                        ingest="not-enrolled",
                    )
                else:
                    # Heartbeat state/backoff remain independent from telemetry pressure.
                    heartbeat = self._attempt_heartbeat(state)
                    ingest = self._attempt_ingest(state)
                    result = RunResult(
                        enrollment=enrollment, heartbeat=heartbeat, ingest=ingest
                    )
                entries = self._spool_entries()
                quarantine_entries = self._quarantine_entries()
        except Exception:
            self._best_effort_write_run_self_metrics(
                result=result,
                state=state,
                entries=entries,
                quarantine_entries=quarantine_entries,
                started_monotonic_ns=started_monotonic_ns,
                started_resource=started_resource,
                started_io=started_io,
            )
            raise
        self._best_effort_write_run_self_metrics(
            result=result,
            state=state,
            entries=entries,
            quarantine_entries=quarantine_entries,
            started_monotonic_ns=started_monotonic_ns,
            started_resource=started_resource,
            started_io=started_io,
        )
        return result

    def list_quarantine(self) -> dict[str, object]:
        """Return bounded rejection metadata without exposing telemetry bodies."""

        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            self._reconcile_state(state)
            entries = self._quarantine_entries()
            at = self._now()
            if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= MAX_SAFE_INTEGER:
                raise StorageError("clock returned an invalid quarantine inspection epoch")
            return {
                "schemaVersion": 1,
                "summary": self._quarantine_summary(entries, at),
                "batches": [
                    {
                        "batchId": entry["batchId"],
                        "reasonCode": code,
                        "quarantinedAt": _now_rfc3339(quarantined_at),
                        "createdAt": _now_rfc3339(int(entry["createdAtEpochMs"])),
                        "firstSequence": entry["firstSequence"],
                        "lastSequence": entry["lastSequence"],
                        "recordCount": entry["recordCount"],
                        "bytes": size,
                    }
                    for _path, entry, size, code, quarantined_at in entries
                ],
            }

    def purge_quarantine(self, batch_id: str) -> bool:
        """Explicitly abandon one inspected permanent rejection by batch ID."""

        if _uuid_v4(batch_id) is None:
            raise ContractError("quarantine purge batch ID is not a canonical UUIDv4")
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            self._reconcile_state(state)
            matching = [
                item for item in self._quarantine_entries()
                if item[1]["batchId"] == batch_id
            ]
            if not matching:
                return False
            if len(matching) != 1:
                raise StorageError("quarantine contains duplicate batch IDs")
            unlink_durable(matching[0][0], maximum_bytes=self.config.max_spool_bytes)
            return True

    def status(self) -> dict[str, object]:
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            self._reconcile_enrollment(state)
            entries = self._spool_entries()
            quarantined = self._quarantine_entries()
            at = self._now()
            if not isinstance(at, int) or isinstance(at, bool) or not 0 <= at <= MAX_SAFE_INTEGER:
                raise StorageError("clock returned an invalid status epoch")
            _self_metrics, self_metrics_status = self._prior_self_metrics(state["agentId"])
            binding = self._load_collector_binding()
            return {
                "schemaVersion": 1,
                "agentId": state["agentId"],
                "hostId": state["hostId"],
                "registered": state["registered"],
                "enrollmentPending": self.pending_enrollment_path.exists(),
                "heartbeatPending": state["pendingHeartbeat"] is not None,
                "spoolEntries": len(entries),
                "spoolBytes": sum(item[2] for item in entries),
                "quarantine": self._quarantine_summary(quarantined, at),
                "durableEntries": len(entries) + len(quarantined),
                "durableBytes": sum(item[2] for item in entries) + sum(
                    item[2] for item in quarantined
                ),
                "maxSpoolEntries": self.config.max_spool_entries,
                "maxSpoolBytes": self.config.max_spool_bytes,
                "nextSequence": state["nextSequence"],
                "collectorIdentityBound": binding is not None,
                "selfMetricsStatus": self_metrics_status,
            }


__all__ = [
    "AgentTransport",
    "AgentTransportError",
    "ContractError",
    "EnrollmentError",
    "HttpResponse",
    "HttpsRequester",
    "Requester",
    "RunResult",
    "SpoolFullError",
]
