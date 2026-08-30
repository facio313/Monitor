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
import ssl
import stat
import uuid
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

from .config import (
    MAX_ENQUEUE_BYTES,
    MAX_ENQUEUE_RECORDS,
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
JOURNAL_PREFIX = b'{"entries":['
JOURNAL_SUFFIX = b'],"schemaVersion":1}'
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


def _encode_enqueue_journal(entries: list[bytes]) -> bytes:
    if not entries:
        raise StorageError("pending enqueue journal cannot be empty")
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
    ):
        self.config = config
        self.config.validate_credentials()
        self._requester = requester or HttpsRequester(config)
        self._now = now or (lambda: int(dt.datetime.now(tz=dt.timezone.utc).timestamp() * 1000))
        self._jitter = jitter or random.SystemRandom().random
        self._inventory_provider = inventory_provider
        self._uuid_factory = uuid_factory
        self._state_directory_identity: DirectoryIdentity = ensure_private_directory(
            config.state_directory
        )
        self.spool_directory = config.state_directory / "spool"
        self._spool_directory_identity: DirectoryIdentity = ensure_private_directory(
            self.spool_directory
        )
        self.state_path = config.state_directory / "transport-state.json"
        self.lock_path = config.state_directory / ".transport.lock"
        self.journal_path = config.state_directory / "pending-enqueue.json"
        self.pending_enrollment_path = config.state_directory / "pending-enrollment.json"
        with self._locked_storage():
            self._cleanup_atomic_temps(config.state_directory)
            self._cleanup_atomic_temps(self.spool_directory)
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
            else:
                allowed_target = target in {
                    self.state_path.name,
                    self.journal_path.name,
                    self.pending_enrollment_path.name,
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
            parsed = self._validate_record_input({key: record[key] for key in record if key != "sequence"})
            if parsed["observedAt"] != record["observedAt"]:
                raise StorageError("spooled record timestamp is not canonical")
            sequence = record["sequence"]
            if not isinstance(sequence, int) or isinstance(sequence, bool) or not 1 <= sequence <= MAX_SAFE_INTEGER:
                raise StorageError("spooled record sequence is invalid")
            sequences.append(sequence)
        if (
            sequences != sorted(sequences)
            or min(sequences) != value["firstSequence"]
            or max(sequences) != value["lastSequence"]
        ):
            raise StorageError("spooled record sequence range is invalid")
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

    def _recover_enqueue(self, state: dict[str, object]) -> dict[str, object]:
        if not (self.journal_path.exists() or self.journal_path.is_symlink()):
            return state
        encoded = read_private(self.journal_path, maximum_bytes=self.config.max_spool_bytes)
        journal = decode_exact_json(encoded, JOURNAL_KEYS, "pending enqueue journal")
        if journal["schemaVersion"] != 1 or not isinstance(journal["entries"], list):
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
        unlink_durable(self.journal_path, maximum_bytes=self.config.max_spool_bytes)
        return state

    def _reconcile_state(self, state: dict[str, object]) -> dict[str, object]:
        entries = self._spool_entries()
        if len(entries) > self.config.max_spool_entries or sum(item[2] for item in entries) > self.config.max_spool_bytes:
            raise StorageError("agent spool exceeds its configured bound")
        highest = max((int(item[1]["lastSequence"]) for item in entries), default=0)
        pending = state["pendingHeartbeat"]
        if isinstance(pending, dict):
            highest = max(highest, int(pending["sequence"]))
        changed = False
        if int(state["nextSequence"]) <= highest:
            state["nextSequence"] = highest + 1
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
        return state

    def enqueue(self, records: Iterable[object]) -> list[str]:
        normalized: list[dict[str, object]] = []
        normalized_bytes = 2  # Canonical JSON array brackets.
        for record in records:
            if len(normalized) >= MAX_ENQUEUE_RECORDS:
                raise ContractError("one enqueue operation exceeds the 2,000-record bound")
            parsed = self._validate_record_input(record)
            encoded = canonical_json(parsed)
            candidate_bytes = normalized_bytes + len(encoded) + int(bool(normalized))
            if candidate_bytes > MAX_ENQUEUE_BYTES:
                raise ContractError("one enqueue operation exceeds the 2 MiB record bound")
            normalized.append(parsed)
            normalized_bytes = candidate_bytes
        if not normalized:
            raise ContractError("at least one telemetry record is required")
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            existing = self._spool_entries()
            at = self._now()
            next_sequence = int(state["nextSequence"])
            if next_sequence + len(normalized) - 1 > MAX_SAFE_INTEGER:
                raise StorageError("agent sequence space is exhausted")
            sent_at = _now_rfc3339(at)
            encoded_entries: list[bytes] = []
            batch_ids: list[str] = []
            new_entry_bytes = 0
            existing_bytes = sum(item[2] for item in existing)
            cursor = 0
            pending_record: tuple[dict[str, object], int] | None = None
            while cursor < len(normalized):
                if len(existing) + len(encoded_entries) >= self.config.max_spool_entries:
                    raise SpoolFullError(
                        "agent spool entry limit is full; no acknowledged batch was evicted"
                    )
                batch_records: list[dict[str, object]] = []
                batch_record_bytes = 0
                batch_id = str(self._uuid_factory())
                if not UUID_V4.fullmatch(batch_id):
                    raise StorageError("UUID provider did not return a UUIDv4 batch ID")
                while cursor < len(normalized) and len(batch_records) < self.config.max_batch_records:
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
                projected_journal_bytes = (
                    len(JOURNAL_PREFIX)
                    + projected_entry_bytes
                    + projected_count
                    - 1
                    + len(JOURNAL_SUFFIX)
                )
                # The journal and materialized entries coexist until sequence state is durable.
                if (
                    existing_bytes + projected_entry_bytes + projected_journal_bytes
                    > self.config.max_spool_bytes
                ):
                    raise SpoolFullError(
                        "agent spool byte limit is full; no acknowledged batch was evicted"
                    )
                encoded_entries.append(encoded_entry)
                batch_ids.append(batch_id)
                new_entry_bytes = projected_entry_bytes

            journal = _encode_enqueue_journal(encoded_entries)
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
        retries[batch_id] = self._next_retry(int(selected_retry["attempts"]), at, response)
        self._persist_state(state)
        return "retry-scheduled"

    def run_once(self) -> RunResult:
        """Attempt enrollment, an independently due heartbeat, and one due batch."""

        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            self._reconcile_enrollment(state)
            enrollment = self._attempt_enrollment(state)
            if not state["registered"]:
                return RunResult(enrollment=enrollment, heartbeat="not-enrolled", ingest="not-enrolled")
            # Heartbeat state and backoff are independent from telemetry admission/backpressure.
            heartbeat = self._attempt_heartbeat(state)
            ingest = self._attempt_ingest(state)
            return RunResult(enrollment=enrollment, heartbeat=heartbeat, ingest=ingest)

    def status(self) -> dict[str, object]:
        with self._locked_storage():
            state = self._recover_enqueue(self._load_or_create_state())
            state = self._reconcile_state(state)
            self._reconcile_enrollment(state)
            entries = self._spool_entries()
            return {
                "schemaVersion": 1,
                "agentId": state["agentId"],
                "hostId": state["hostId"],
                "registered": state["registered"],
                "enrollmentPending": self.pending_enrollment_path.exists(),
                "heartbeatPending": state["pendingHeartbeat"] is not None,
                "spoolEntries": len(entries),
                "spoolBytes": sum(item[2] for item in entries),
                "maxSpoolEntries": self.config.max_spool_entries,
                "maxSpoolBytes": self.config.max_spool_bytes,
                "nextSequence": state["nextSequence"],
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
