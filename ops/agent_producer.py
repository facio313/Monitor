#!/usr/bin/env python3
"""Opt-in, crash-safe bridge from collector current.json to AgentTransport."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Package import in tests; direct script import in the installed layout.
    from .agent_records import (
        SELF_METRICS_STALE_AFTER_SECONDS,
        AgentRecordError,
        project_records,
        validate_current,
    )
    from .agent_transport import (
        AgentTransport,
        AgentTransportError,
        SpoolFullError,
        TransportConfig,
    )
    from .agent_transport.config import ConfigError, open_trusted_regular
    from .agent_transport.storage import (
        StorageError,
        atomic_private_write,
        canonical_json,
        ensure_private_directory,
        exclusive_lock,
        fsync_directory,
        read_private,
        unlink_durable,
        validate_private_file,
    )
except ImportError:  # pragma: no cover - exercised by the installed script.
    from agent_records import (
        SELF_METRICS_STALE_AFTER_SECONDS,
        AgentRecordError,
        project_records,
        validate_current,
    )
    from agent_transport import AgentTransport, AgentTransportError, SpoolFullError, TransportConfig
    from agent_transport.config import ConfigError, open_trusted_regular
    from agent_transport.storage import (
        StorageError,
        atomic_private_write,
        canonical_json,
        ensure_private_directory,
        exclusive_lock,
        fsync_directory,
        read_private,
        unlink_durable,
        validate_private_file,
    )


MAX_CONFIG_BYTES = 64 * 1024
MAX_CURRENT_BYTES = 8 * 1024 * 1024
MAX_SELF_METRICS_BYTES = 64 * 1024
MAX_PRODUCER_STATE_BYTES = 4 * 1024 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
UUID_V4 = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")
HEX_SHA256 = re.compile(r"^[a-f0-9]{64}$")
RFC3339_Z = re.compile(
    r"^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T"
    r"([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?Z$"
)

CONFIG_KEYS = {
    "schemaVersion",
    "collectorCurrentFile",
    "transportConfigFile",
    "transportSelfMetricsFile",
    "stateDirectory",
}
CHECKPOINT_KEYS = {
    "schemaVersion",
    "hostId",
    "agentId",
    "identityGeneration",
    "sourceSequence",
    "observedAt",
}
PENDING_KEYS = {
    "schemaVersion",
    "installationEpoch",
    "checkpoint",
    "sourceSha256",
    "recordsSha256",
    "records",
}
CURSOR_KEYS = {
    "schemaVersion",
    "installationEpoch",
    "checkpoint",
    "sourceSha256",
    "recordsSha256",
    "batchIds",
}
RECORD_KEYS = {"kind", "metric", "target", "observedAt", "value", "severity"}
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class AgentProducerError(RuntimeError):
    """The producer source/config/private state is invalid or inconsistent."""


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant {value} is forbidden")


def _decode_json(encoded: bytes, description: str) -> object:
    try:
        return json.loads(
            encoded.decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AgentProducerError(f"{description} is not strict UTF-8 JSON") from error


def _absolute_path(value: object, name: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AgentProducerError(f"{name} must be one bounded path string")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or os.path.normpath(value) != value:
        raise AgentProducerError(f"{name} must be an absolute normalized path")
    return path


def _read_open_descriptor(descriptor: int, expected_size: int, maximum_bytes: int) -> bytes:
    encoded = bytearray()
    while len(encoded) <= maximum_bytes:
        chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(encoded)))
        if not chunk:
            break
        encoded.extend(chunk)
    if len(encoded) > maximum_bytes or len(encoded) != expected_size:
        raise AgentProducerError("source file changed while it was read")
    return bytes(encoded)


def _load_trusted_json(path: Path, maximum_bytes: int, description: str) -> object:
    try:
        descriptor, status = open_trusted_regular(
            path, maximum_bytes=maximum_bytes, exact_mode=None
        )
    except ConfigError as error:
        raise AgentProducerError(f"{description} is unavailable or unsafe") from error
    try:
        encoded = _read_open_descriptor(descriptor, status.st_size, maximum_bytes)
    finally:
        os.close(descriptor)
    return _decode_json(encoded, description)


def _canonical_uuid(value: object, description: str) -> str:
    if not isinstance(value, str) or UUID_V4.fullmatch(value) is None:
        raise AgentProducerError(f"{description} is not a canonical UUIDv4")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise AgentProducerError(f"{description} is not a canonical UUIDv4") from error
    if str(parsed) != value or parsed.version != 4:
        raise AgentProducerError(f"{description} is not a canonical UUIDv4")
    return value


def _safe_integer(value: object, description: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        raise AgentProducerError(f"{description} is not a bounded integer")
    return value


def _timestamp(value: object, description: str) -> str:
    if not isinstance(value, str) or RFC3339_Z.fullmatch(value) is None:
        raise AgentProducerError(f"{description} is not a canonical UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AgentProducerError(f"{description} is not a real timestamp") from error
    if not 0 <= parsed.timestamp() * 1000 <= 253_402_300_799_999:
        raise AgentProducerError(f"{description} is outside the supported range")
    return value


def _timestamp_ms(value: object, description: str) -> int:
    normalized = _timestamp(value, description)
    parsed = dt.datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    return round(parsed.timestamp() * 1000)


def _validate_checkpoint(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != CHECKPOINT_KEYS:
        raise AgentProducerError("producer checkpoint has an invalid exact schema")
    if value["schemaVersion"] != 1:
        raise AgentProducerError("producer checkpoint schemaVersion must be 1")
    host_id = _canonical_uuid(value["hostId"], "producer checkpoint hostId")
    agent_id = _canonical_uuid(value["agentId"], "producer checkpoint agentId")
    if host_id == agent_id:
        raise AgentProducerError("producer checkpoint hostId and agentId must be distinct")
    generation = _safe_integer(value["identityGeneration"], "identity generation", 1)
    sequence = _safe_integer(value["sourceSequence"], "source sequence", 1)
    observed = _timestamp(value["observedAt"], "producer checkpoint observedAt")
    return {
        "schemaVersion": 1,
        "hostId": host_id,
        "agentId": agent_id,
        "identityGeneration": generation,
        "sourceSequence": sequence,
        "observedAt": observed,
    }


def _validate_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 2_000:
        raise AgentProducerError("producer pending records have an invalid bound")
    records: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != RECORD_KEYS:
            raise AgentProducerError("producer pending record has an invalid exact schema")
        kind = item["kind"]
        if (
            kind not in {"metric", "event"}
            or not isinstance(item["metric"], str)
            or SAFE_NAME.fullmatch(item["metric"]) is None
            or not isinstance(item["target"], str)
            or SAFE_NAME.fullmatch(item["target"]) is None
        ):
            raise AgentProducerError("producer pending record identity or kind is invalid")
        _timestamp(item["observedAt"], "producer pending record observedAt")
        if kind == "metric":
            number = item["value"]
            if (
                not isinstance(number, (int, float))
                or isinstance(number, bool)
                or not math.isfinite(float(number))
                or item["severity"] is not None
            ):
                raise AgentProducerError("producer pending metric value is invalid")
        elif item["value"] is not None or item["severity"] not in {
            "info", "warning", "critical"
        }:
            raise AgentProducerError("producer pending event value is invalid")
        records.append(item)
    return records


@dataclass(frozen=True)
class ProducerConfig:
    collector_current_file: Path
    transport_config_file: Path
    transport_self_metrics_file: Path
    state_directory: Path

    @classmethod
    def from_mapping(cls, value: object) -> "ProducerConfig":
        if not isinstance(value, Mapping) or set(value) != CONFIG_KEYS:
            raise AgentProducerError("agent producer configuration has an invalid exact schema")
        if value["schemaVersion"] != 1:
            raise AgentProducerError("agent producer schemaVersion must be 1")
        return cls(
            collector_current_file=_absolute_path(
                value["collectorCurrentFile"], "collectorCurrentFile"
            ),
            transport_config_file=_absolute_path(
                value["transportConfigFile"], "transportConfigFile"
            ),
            transport_self_metrics_file=_absolute_path(
                value["transportSelfMetricsFile"], "transportSelfMetricsFile"
            ),
            state_directory=_absolute_path(value["stateDirectory"], "stateDirectory"),
        )

    @classmethod
    def load(cls, path: Path) -> "ProducerConfig":
        try:
            descriptor, status = open_trusted_regular(
                path, maximum_bytes=MAX_CONFIG_BYTES, exact_mode=0o600
            )
        except ConfigError as error:
            raise AgentProducerError(
                "agent producer configuration is unavailable or unsafe"
            ) from error
        try:
            encoded = _read_open_descriptor(descriptor, status.st_size, MAX_CONFIG_BYTES)
        finally:
            os.close(descriptor)
        raw = _decode_json(encoded, "agent producer configuration")
        return cls.from_mapping(raw)


@dataclass(frozen=True)
class ProducerResult:
    outcome: str
    source_sequence: int | None
    batch_ids: tuple[str, ...]
    self_metrics_status: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "sourceSequence": self.source_sequence,
            "batchIds": list(self.batch_ids),
            "selfMetricsStatus": self.self_metrics_status,
        }


class AgentProducer:
    def __init__(
        self,
        config: ProducerConfig,
        *,
        transport: AgentTransport | None = None,
        transport_factory: Callable[[TransportConfig], AgentTransport] = AgentTransport,
    ):
        self.config = config
        self._state_identity = ensure_private_directory(config.state_directory)
        self.lock_path = config.state_directory / ".producer.lock"
        self.cursor_path = config.state_directory / "source-cursor.json"
        self.pending_path = config.state_directory / "pending-checkpoint.json"
        if transport is None:
            transport_config = TransportConfig.load(config.transport_config_file)
            transport = transport_factory(transport_config)
        expected_self_path = transport.config.state_directory / "self-metrics.json"
        if config.transport_self_metrics_file != expected_self_path:
            raise AgentProducerError(
                "transportSelfMetricsFile must be the selected transport state self-metrics path"
            )
        self.transport = transport
        with self._locked():
            self._cleanup_atomic_temps()
            allowed = {self.lock_path.name, self.cursor_path.name, self.pending_path.name}
            unexpected = [
                path.name for path in self.config.state_directory.iterdir()
                if path.name not in allowed
            ]
            if unexpected:
                raise AgentProducerError("producer state contains an unexpected entry")

    @contextlib.contextmanager
    def _locked(self):
        ensure_private_directory(
            self.config.state_directory, create=False, expected=self._state_identity
        )
        with exclusive_lock(self.lock_path):
            ensure_private_directory(
                self.config.state_directory, create=False, expected=self._state_identity
            )
            yield

    def _cleanup_atomic_temps(self) -> None:
        changed = False
        for path in self.config.state_directory.iterdir():
            if not path.name.startswith(".") or ".tmp-" not in path.name:
                continue
            target, suffix = path.name[1:].rsplit(".tmp-", 1)
            if target not in {self.cursor_path.name, self.pending_path.name}:
                raise AgentProducerError("producer state contains an unexpected temporary file")
            if UUID_V4.fullmatch(suffix) is None:
                raise AgentProducerError("producer state contains an unsafe temporary file")
            validate_private_file(path, maximum_bytes=MAX_PRODUCER_STATE_BYTES)
            path.unlink()
            changed = True
        if changed:
            fsync_directory(self.config.state_directory)

    def _read_private_json(self, path: Path, description: str) -> object | None:
        if not (path.exists() or path.is_symlink()):
            return None
        encoded = read_private(path, maximum_bytes=MAX_PRODUCER_STATE_BYTES)
        return _decode_json(encoded, description)

    def _validate_pending(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != PENDING_KEYS or value["schemaVersion"] != 1:
            raise AgentProducerError("pending producer checkpoint has an invalid exact schema")
        checkpoint = _validate_checkpoint(value["checkpoint"])
        installation = _timestamp(
            value["installationEpoch"], "pending producer installationEpoch"
        )
        source_digest = value["sourceSha256"]
        digest = value["recordsSha256"]
        records = _validate_records(value["records"])
        if (
            not isinstance(source_digest, str)
            or HEX_SHA256.fullmatch(source_digest) is None
            or not isinstance(digest, str)
            or HEX_SHA256.fullmatch(digest) is None
            or hashlib.sha256(canonical_json(records)).hexdigest() != digest
        ):
            raise AgentProducerError("pending producer record digest does not match")
        return {
            "schemaVersion": 1,
            "installationEpoch": installation,
            "checkpoint": checkpoint,
            "sourceSha256": source_digest,
            "recordsSha256": digest,
            "records": records,
        }

    def _validate_cursor(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != CURSOR_KEYS or value["schemaVersion"] != 1:
            raise AgentProducerError("producer source cursor has an invalid exact schema")
        checkpoint = _validate_checkpoint(value["checkpoint"])
        installation = _timestamp(
            value["installationEpoch"], "producer cursor installationEpoch"
        )
        source_digest = value["sourceSha256"]
        digest = value["recordsSha256"]
        batch_ids = value["batchIds"]
        if (
            not isinstance(source_digest, str)
            or HEX_SHA256.fullmatch(source_digest) is None
            or not isinstance(digest, str)
            or HEX_SHA256.fullmatch(digest) is None
            or not isinstance(batch_ids, list)
            or not batch_ids
            or any(not isinstance(item, str) or UUID_V4.fullmatch(item) is None for item in batch_ids)
            or len(set(batch_ids)) != len(batch_ids)
        ):
            raise AgentProducerError("producer source cursor fields are invalid")
        return {
            "schemaVersion": 1,
            "installationEpoch": installation,
            "checkpoint": checkpoint,
            "sourceSha256": source_digest,
            "recordsSha256": digest,
            "batchIds": batch_ids,
        }

    def _load_pending(self) -> dict[str, object] | None:
        value = self._read_private_json(self.pending_path, "pending producer checkpoint")
        return self._validate_pending(value) if value is not None else None

    def _load_cursor(self) -> dict[str, object] | None:
        value = self._read_private_json(self.cursor_path, "producer source cursor")
        return self._validate_cursor(value) if value is not None else None

    @staticmethod
    def _identity_mapping(source: Mapping[str, object]) -> dict[str, object]:
        return {
            "hostId": source["hostId"],
            "agentId": source["agentId"],
            "installationEpoch": source["installationEpoch"],
            "identityGeneration": source["identityGeneration"],
        }

    @staticmethod
    def _checkpoint(source: Mapping[str, object]) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "hostId": source["hostId"],
            "agentId": source["agentId"],
            "identityGeneration": source["identityGeneration"],
            "sourceSequence": source["sourceSequence"],
            "observedAt": source["observedAt"],
        }

    @staticmethod
    def _same_source_identity(
        left_checkpoint: Mapping[str, object],
        left_installation: object,
        right_checkpoint: Mapping[str, object],
        right_installation: object,
    ) -> bool:
        return (
            left_installation == right_installation
            and all(
                left_checkpoint[name] == right_checkpoint[name]
                for name in {"hostId", "agentId", "identityGeneration"}
            )
        )

    def _read_current(self) -> tuple[object, dict[str, Any]]:
        current = _load_trusted_json(
            self.config.collector_current_file, MAX_CURRENT_BYTES, "collector current.json"
        )
        try:
            return current, validate_current(current)
        except AgentRecordError as error:
            raise AgentProducerError("collector current.json failed strict validation") from error

    def _read_self_metrics(self) -> tuple[object | None, str]:
        path = self.config.transport_self_metrics_file
        try:
            path.lstat()
        except FileNotFoundError:
            return None, "missing"
        except OSError:
            return None, "unreadable"
        try:
            encoded = read_private(path, maximum_bytes=MAX_SELF_METRICS_BYTES)
        except StorageError:
            return None, "unreadable"
        try:
            return json.loads(
                encoded.decode("utf-8"), parse_constant=_reject_json_constant
            ), "valid"
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None, "corrupt"

    def bind_identity(self) -> ProducerResult:
        with self._locked():
            if self._load_pending() is not None:
                raise AgentProducerError("cannot bind-only while a producer checkpoint is pending")
            _current, source = self._read_current()
            self.transport.bind_collector_identity(self._identity_mapping(source))
            return ProducerResult(
                outcome="identity-bound",
                source_sequence=int(source["sourceSequence"]),
                batch_ids=(),
                self_metrics_status=None,
            )

    def _commit_pending(self, pending: Mapping[str, object]) -> ProducerResult:
        checkpoint = pending["checkpoint"]
        assert isinstance(checkpoint, dict)
        existing_cursor = self._load_cursor()
        if existing_cursor is not None:
            existing_checkpoint = existing_cursor["checkpoint"]
            assert isinstance(existing_checkpoint, dict)
            if not self._same_source_identity(
                existing_checkpoint,
                existing_cursor["installationEpoch"],
                checkpoint,
                pending["installationEpoch"],
            ):
                raise AgentProducerError("pending checkpoint conflicts with the source cursor identity")
            existing_sequence = int(existing_checkpoint["sourceSequence"])
            source_sequence = int(checkpoint["sourceSequence"])
            if existing_sequence > source_sequence:
                raise AgentProducerError("pending checkpoint is older than the source cursor")
            if existing_sequence == source_sequence and (
                existing_cursor["sourceSha256"] != pending["sourceSha256"]
                or existing_cursor["recordsSha256"] != pending["recordsSha256"]
            ):
                raise AgentProducerError("pending checkpoint conflicts with the durable source cursor")
        self.transport.bind_collector_identity({
            "hostId": checkpoint["hostId"],
            "agentId": checkpoint["agentId"],
            "installationEpoch": pending["installationEpoch"],
            "identityGeneration": checkpoint["identityGeneration"],
        })
        records = pending["records"]
        assert isinstance(records, list)
        batch_ids = self.transport.enqueue(records, checkpoint=checkpoint)
        cursor = {
            "schemaVersion": 1,
            "installationEpoch": pending["installationEpoch"],
            "checkpoint": checkpoint,
            "sourceSha256": pending["sourceSha256"],
            "recordsSha256": pending["recordsSha256"],
            "batchIds": batch_ids,
        }
        if existing_cursor is not None:
            existing_checkpoint = existing_cursor["checkpoint"]
            assert isinstance(existing_checkpoint, dict)
            if not self._same_source_identity(
                existing_checkpoint,
                existing_cursor["installationEpoch"],
                checkpoint,
                pending["installationEpoch"],
            ):
                raise AgentProducerError("pending checkpoint conflicts with the source cursor identity")
            existing_sequence = int(existing_checkpoint["sourceSequence"])
            source_sequence = int(checkpoint["sourceSequence"])
            if existing_sequence > source_sequence:
                raise AgentProducerError("pending checkpoint is older than the source cursor")
            if existing_sequence == source_sequence and existing_cursor != cursor:
                raise AgentProducerError("pending checkpoint conflicts with the durable source cursor")
        atomic_private_write(self.cursor_path, canonical_json(cursor))
        unlink_durable(self.pending_path, maximum_bytes=MAX_PRODUCER_STATE_BYTES)
        return ProducerResult(
            outcome="queued",
            source_sequence=int(checkpoint["sourceSequence"]),
            batch_ids=tuple(batch_ids),
            self_metrics_status=None,
        )

    def run_once(self) -> ProducerResult:
        with self._locked():
            pending = self._load_pending()
            if pending is not None:
                return self._commit_pending(pending)

            current, source = self._read_current()
            source_digest = hashlib.sha256(canonical_json(current)).hexdigest()
            self.transport.bind_collector_identity(self._identity_mapping(source))
            checkpoint = self._checkpoint(source)
            cursor = self._load_cursor()
            if cursor is not None:
                cursor_checkpoint = cursor["checkpoint"]
                assert isinstance(cursor_checkpoint, dict)
                if not self._same_source_identity(
                    cursor_checkpoint,
                    cursor["installationEpoch"],
                    checkpoint,
                    source["installationEpoch"],
                ):
                    raise AgentProducerError(
                        "collector identity changed; explicit transport re-enrollment is required"
                    )
                prior_sequence = int(cursor_checkpoint["sourceSequence"])
                source_sequence = int(checkpoint["sourceSequence"])
                if source_sequence < prior_sequence:
                    raise AgentProducerError("collector source sequence rolled back")
                if source_sequence == prior_sequence:
                    if cursor["sourceSha256"] != source_digest:
                        raise AgentProducerError(
                            "collector source checkpoint changed without a new sequence"
                        )
                    return ProducerResult(
                        outcome="unchanged",
                        source_sequence=source_sequence,
                        batch_ids=tuple(str(item) for item in cursor["batchIds"]),
                        self_metrics_status=None,
                    )
                if _timestamp_ms(
                    checkpoint["observedAt"], "collector checkpoint observedAt"
                ) < _timestamp_ms(
                    cursor_checkpoint["observedAt"], "producer cursor observedAt"
                ):
                    raise AgentProducerError("collector checkpoint time rolled back")

            self_metrics, self_status = self._read_self_metrics()
            if self_status == "valid" and isinstance(self_metrics, Mapping):
                try:
                    sample_age_ms = _timestamp_ms(
                        checkpoint["observedAt"], "collector checkpoint observedAt"
                    ) - _timestamp_ms(
                        self_metrics.get("observedAt"), "agent self-metrics observedAt"
                    )
                except AgentProducerError:
                    # The pure projection performs the full exact-schema check
                    # and converts malformed input into the explicit corrupt path.
                    pass
                else:
                    if sample_age_ms > SELF_METRICS_STALE_AFTER_SECONDS * 1000:
                        self_status = "stale"
            try:
                _validated_source, records = project_records(
                    current, self_metrics, self_metrics_status=self_status
                )
            except AgentRecordError:
                if self_status in {"valid", "stale"}:
                    # A malformed or wrong-identity self file is observable but
                    # must not block the collector checkpoint.
                    self_metrics = None
                    self_status = "corrupt"
                    _validated_source, records = project_records(
                        current, None, self_metrics_status=self_status
                    )
                else:
                    raise
            records_digest = hashlib.sha256(canonical_json(records)).hexdigest()
            pending = {
                "schemaVersion": 1,
                "installationEpoch": source["installationEpoch"],
                "checkpoint": checkpoint,
                "sourceSha256": source_digest,
                "recordsSha256": records_digest,
                "records": records,
            }
            atomic_private_write(
                self.pending_path, canonical_json(pending), replace=False
            )
            result = self._commit_pending(pending)
            return ProducerResult(
                outcome=result.outcome,
                source_sequence=result.source_sequence,
                batch_ids=result.batch_ids,
                self_metrics_status=self_status,
            )

    def status(self) -> dict[str, object]:
        with self._locked():
            pending = self._load_pending()
            cursor = self._load_cursor()
            return {
                "schemaVersion": 1,
                "pending": pending is not None,
                "lastSourceSequence": (
                    cursor["checkpoint"]["sourceSequence"]
                    if cursor is not None and isinstance(cursor["checkpoint"], dict)
                    else None
                ),
                "transport": self.transport.status(),
            }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="monitor-agent-producer")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "command", choices=("bind-identity", "run-once", "status"), nargs="?", default="run-once"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        producer = AgentProducer(ProducerConfig.load(arguments.config))
        if arguments.command == "bind-identity":
            result: object = producer.bind_identity().as_dict()
        elif arguments.command == "run-once":
            result = producer.run_once().as_dict()
        else:
            result = producer.status()
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except SpoolFullError as error:
        print(f"monitor-agent-producer: {error}", file=sys.stderr)
        return 75
    except (
        AgentProducerError,
        AgentRecordError,
        AgentTransportError,
        ConfigError,
        StorageError,
        OSError,
        ValueError,
    ) as error:
        print(f"monitor-agent-producer: {error}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AgentProducer",
    "AgentProducerError",
    "ProducerConfig",
    "ProducerResult",
    "main",
]
