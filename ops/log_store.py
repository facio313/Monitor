#!/usr/bin/env python3
"""Crash-safe bounded persistence for normalized generic logs and cursors."""

from __future__ import annotations

import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from log_pipeline import (
        PipelineLimits,
        QUOTA_STATE_SCHEMA_VERSION,
        REDACTION_VERSION,
        normalize_quota_state,
        normalize_record,
    )
    from log_sources import SourceDefinition, normalize_source_cursor
except ModuleNotFoundError:  # pragma: no cover - package-style test import
    from .log_pipeline import (
        PipelineLimits,
        QUOTA_STATE_SCHEMA_VERSION,
        REDACTION_VERSION,
        normalize_quota_state,
        normalize_record,
    )
    from .log_sources import SourceDefinition, normalize_source_cursor


STORE_SCHEMA_VERSION = 1
LEGACY_REDACTION_VERSIONS = frozenset({"monitor-log-redaction-v1"})
MAX_PENDING_BYTES = 32 * 1024 * 1024
MAX_STATUS_BYTES = 512 * 1024
MAX_STATE_BYTES = 512 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_STORED_RECORDS = 20_000
MAX_STORED_BYTES = 16 * 1024 * 1024
_SUCCESS_STATUSES = frozenset({"fresh", "no_data", "truncated"})
_SOURCE_STATUSES = _SUCCESS_STATUSES | frozenset({
    "unsupported", "permission_denied", "failed"
})
_ERROR_CLASSES = frozenset({
    "unsupported", "permission_denied", "timeout", "command_failed",
    "output_limit", "read_failed", "unsafe_source",
})
_DROP_FIELDS = (
    "inputLineLimit", "inputByteLimit", "oversizedLine", "multilineLineLimit",
    "oversizedEvent", "sourceQuota", "globalQuota", "acquisition",
)
_SOURCE_STATUS_FIELDS = (
    "schemaVersion", "sourceId", "sourceKind", "status", "observedAt",
    "lastSuccessAt", "errorClass", "seenLines", "seenBytes", "parsedEvents",
    "admittedEvents", "droppedLines", "dropped",
)


class LogStoreError(RuntimeError):
    """A durable log transaction or persisted contract is unsafe."""


def _iso(value: dt.datetime) -> str:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _parse_iso(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory(path: Path, mode: int, expected_uid: int) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
    ):
        raise LogStoreError("log store directory ownership, mode, or type is unsafe")


def _safe_existing_file(
    path: Path, *, expected_uid: int, maximum_bytes: int, private: bool
) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LogStoreError("persisted log file cannot be inspected") from exc
    unsafe_mode = metadata.st_mode & (0o077 if private else 0o027)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or unsafe_mode
        or metadata.st_size > maximum_bytes
    ):
        raise LogStoreError("persisted log file ownership, mode, link, type, or size is unsafe")
    return metadata


def _read_bounded(
    path: Path, *, expected_uid: int, maximum_bytes: int, private: bool
) -> bytes | None:
    metadata = _safe_existing_file(
        path, expected_uid=expected_uid, maximum_bytes=maximum_bytes, private=private
    )
    if metadata is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LogStoreError("persisted log file cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise LogStoreError("persisted log file changed while opening")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_bytes:
            raise LogStoreError("persisted log file exceeds its read bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_target(path: Path, expected_uid: int) -> None:
    metadata = _safe_existing_file(
        path, expected_uid=expected_uid,
        maximum_bytes=1024 * 1024 * 1024,
        private=path.parent.name == ".state",
    )
    if metadata is not None and metadata.st_nlink != 1:
        raise LogStoreError("refusing to replace multiply linked file")


def _atomic_write_bytes(path: Path, payload: bytes, mode: int, expected_uid: int) -> None:
    _validate_target(path, expected_uid)
    temporary = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically move one staged inode into an absent name on Linux."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise LogStoreError("atomic no-overwrite rename is unavailable") from exc
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    raise OSError(error_number, os.strerror(error_number), destination)


def _atomic_create_bytes(path: Path, payload: bytes, mode: int, expected_uid: int) -> None:
    if path.exists() or path.is_symlink():
        raise LogStoreError("pending generic-log transaction already exists")
    temporary = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, mode)
    try:
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short pending write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            # Linux renameat2(RENAME_NOREPLACE) publishes the already durable
            # inode under exactly one name and fails if another writer won.
            # Unlike a hard-link publication, there is no crash window where
            # the pending marker has link count two and cannot be replayed.
            _rename_noreplace(temporary, path)
        except FileExistsError as exc:
            raise LogStoreError(
                "pending generic-log transaction already exists"
            ) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        finally:
            # Persist the no-overwrite publication or cleanup of a staging file
            # left by a pre-publication error.
            _fsync_directory(path.parent)


def _unlink_durable(path: Path) -> None:
    path.unlink()
    _fsync_directory(path.parent)


def _record_lines(records: Sequence[Mapping[str, Any]]) -> list[bytes]:
    lines: list[bytes] = []
    for raw in records:
        normalized = normalize_record(raw, MAX_RECORD_BYTES)
        if normalized is None:
            raise LogStoreError("generic log row failed public schema validation")
        lines.append((json.dumps(
            normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ) + "\n").encode())
    return lines


def _records_digest(records: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for line in _record_lines(records):
        digest.update(line)
    return digest.hexdigest()


def _normalize_drops(value: Any) -> dict[str, int] | None:
    if not isinstance(value, Mapping) or set(value) != set(_DROP_FIELDS):
        return None
    result: dict[str, int] = {}
    for key in _DROP_FIELDS:
        count = value.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 2**63 - 1:
            return None
        result[key] = count
    return result


def normalize_source_status(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or tuple(value.keys()) != _SOURCE_STATUS_FIELDS:
        return None
    if (
        value.get("schemaVersion") != STORE_SCHEMA_VERSION
        or value.get("sourceKind") not in {"file", "journald", "docker"}
        or value.get("status") not in _SOURCE_STATUSES
        or not isinstance(value.get("sourceId"), str)
        or not 1 <= len(value["sourceId"].encode()) <= 128
    ):
        return None
    observed = _parse_iso(value.get("observedAt"))
    last_success = _parse_iso(value.get("lastSuccessAt")) if value.get("lastSuccessAt") else None
    if observed is None or _iso(observed) != value.get("observedAt"):
        return None
    if last_success is not None and _iso(last_success) != value.get("lastSuccessAt"):
        return None
    status = value["status"]
    error_class = value.get("errorClass")
    if status in _SUCCESS_STATUSES:
        if error_class not in {None, "output_limit"} or last_success is None:
            return None
    elif error_class not in _ERROR_CLASSES:
        return None
    for key in ("seenLines", "seenBytes", "parsedEvents", "admittedEvents", "droppedLines"):
        count = value.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 2**63 - 1:
            return None
    drops = _normalize_drops(value.get("dropped"))
    if drops is None or sum(drops.values()) != value["droppedLines"]:
        return None
    normalized = {key: value[key] for key in _SOURCE_STATUS_FIELDS}
    normalized["dropped"] = drops
    return normalized


def normalize_status_document(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {"schemaVersion", "generatedAt", "sources"}:
        return None
    generated = _parse_iso(value.get("generatedAt"))
    raw_sources = value.get("sources")
    if (
        value.get("schemaVersion") != STORE_SCHEMA_VERSION
        or generated is None or _iso(generated) != value.get("generatedAt")
        or not isinstance(raw_sources, list) or len(raw_sources) > 64
    ):
        return None
    sources: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for raw in raw_sources:
        normalized = normalize_source_status(raw)
        if normalized is None or normalized["sourceId"] in identifiers:
            return None
        identifiers.add(normalized["sourceId"])
        sources.append(normalized)
    return {
        "schemaVersion": STORE_SCHEMA_VERSION,
        "generatedAt": value["generatedAt"],
        "sources": sources,
    }


class GenericLogStore:
    def __init__(
        self,
        root: Path,
        definitions: Sequence[SourceDefinition],
        *,
        expected_uid: int | None = None,
        retention_days: int = 30,
        max_records: int = MAX_STORED_RECORDS,
        max_file_bytes: int = MAX_STORED_BYTES,
        pipeline_limits: PipelineLimits | None = None,
    ) -> None:
        self.root = Path(root)
        self.state_dir = self.root / ".state"
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days is outside its supported range")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 100 <= max_records <= MAX_STORED_RECORDS
        ):
            raise ValueError("max_records is outside its supported range")
        if (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or not 1024 * 1024 <= max_file_bytes <= MAX_STORED_BYTES
        ):
            raise ValueError("max_file_bytes is outside its supported range")
        if len(definitions) > 64:
            raise ValueError("too many log source definitions")
        self.definitions = {item.source.source_id: item for item in definitions}
        if len(self.definitions) != len(definitions):
            raise ValueError("duplicate source definitions")
        self.retention_days = retention_days
        self.max_records = max_records
        self.max_file_bytes = max_file_bytes
        self.pipeline_limits = pipeline_limits or PipelineLimits()
        _ensure_directory(self.root, 0o750, self.expected_uid)
        _ensure_directory(self.state_dir, 0o700, self.expected_uid)

    @property
    def records_path(self) -> Path:
        return self.root / "generic-logs.jsonl"

    @property
    def status_path(self) -> Path:
        return self.root / "generic-log-sources.json"

    @property
    def private_state_path(self) -> Path:
        return self.state_dir / "generic-log-state.json"

    @property
    def pending_path(self) -> Path:
        return self.state_dir / "pending-generic-log-commit.json"

    @staticmethod
    def _document_has_legacy_rows(value: Any) -> bool:
        rows = value.get("rows") if isinstance(value, Mapping) else None
        if not isinstance(rows, list):
            return False
        return any(
            isinstance(row, Mapping)
            and row.get("redactionVersion") in LEGACY_REDACTION_VERSIONS
            for row in rows
        )

    def _migrate_legacy_redaction_history(self) -> bool:
        """Drop v1 history rather than reprocessing possibly orphaned PEM bodies.

        v1 normalized physical lines independently, so a retained body row cannot
        be proven safe after its BEGIN row ages out. The only sound migration is
        to clear the whole v1 snapshot and pending transaction. Before doing so,
        persist recovery state for every source so a cursor already inside a PEM
        block cannot expose subsequent body lines after the upgrade.
        """

        records_raw = _read_bounded(
            self.records_path, expected_uid=self.expected_uid,
            # A deployment may lower its configured retention-byte ceiling at
            # the same time as this upgrade. Inspect up to the packaged historic
            # ceiling so a valid older v1 snapshot is still scrubbed.
            maximum_bytes=MAX_STORED_BYTES, private=False,
        )
        pending_raw = _read_bounded(
            self.pending_path, expected_uid=self.expected_uid,
            maximum_bytes=MAX_PENDING_BYTES, private=True,
        )
        legacy = False
        if records_raw:
            for line in records_raw.splitlines():
                try:
                    decoded = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    decoded = None
                if (
                    isinstance(decoded, Mapping)
                    and decoded.get("redactionVersion") in LEGACY_REDACTION_VERSIONS
                ):
                    legacy = True
                    break
        if pending_raw:
            try:
                pending_value = json.loads(pending_raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                pending_value = None
            legacy = legacy or self._document_has_legacy_rows(pending_value)
            raw_private = pending_value.get("privateState") if isinstance(pending_value, Mapping) else None
            raw_quota = raw_private.get("quotaState") if isinstance(raw_private, Mapping) else None
            legacy = legacy or (
                isinstance(raw_quota, Mapping)
                and raw_quota.get("schemaVersion") == 1
                and "redactionVersion" not in raw_quota
            )
        if not legacy:
            return False

        try:
            prior = self.load_private_state()
        except LogStoreError:
            prior = None
        if prior is None:
            cursors = {source_id: {} for source_id in self.definitions}
            quota_state = {
                "schemaVersion": QUOTA_STATE_SCHEMA_VERSION,
                "redactionVersion": REDACTION_VERSION,
                "windowStartedAt": 0,
                "admittedGlobal": 0,
                "admittedBySource": {},
                "pemRecoveryRequired": True,
                "pemSuppressionBySource": {},
            }
        else:
            cursors = prior["cursors"]
            quota_state = dict(prior["quotaState"])
            quota_state["pemRecoveryRequired"] = True
        recovery_state = self._normalize_private_state({
            "schemaVersion": STORE_SCHEMA_VERSION,
            "cursors": cursors,
            "quotaState": quota_state,
        })
        if recovery_state is None:
            raise LogStoreError("legacy generic-log state cannot be migrated safely")
        state_payload = (json.dumps(
            recovery_state, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
        ) + "\n").encode()
        # Persist recovery first. A crash before the v1 snapshot is cleared leaves
        # that snapshot rejected by the v2 reader; a retry repeats this migration.
        _atomic_write_bytes(
            self.private_state_path, state_payload, 0o600, self.expected_uid
        )
        _atomic_write_bytes(self.records_path, b"", 0o640, self.expected_uid)
        if pending_raw is not None:
            _unlink_durable(self.pending_path)
        return True

    def load_records(self) -> list[dict[str, Any]]:
        raw = _read_bounded(
            self.records_path, expected_uid=self.expected_uid,
            maximum_bytes=self.max_file_bytes, private=False,
        )
        if raw is None or raw == b"":
            return []
        records: list[dict[str, Any]] = []
        for line in raw.splitlines():
            if not line or len(line) > MAX_RECORD_BYTES:
                raise LogStoreError("generic log file contains an invalid line")
            try:
                decoded = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise LogStoreError("generic log file is malformed") from exc
            normalized = normalize_record(decoded, MAX_RECORD_BYTES)
            if normalized is None:
                raise LogStoreError("generic log file failed schema validation")
            records.append(normalized)
            if len(records) > self.max_records:
                raise LogStoreError("generic log file exceeds its record limit")
        return records

    def load_status_document(self) -> dict[str, Any] | None:
        raw = _read_bounded(
            self.status_path, expected_uid=self.expected_uid,
            maximum_bytes=MAX_STATUS_BYTES, private=False,
        )
        if raw is None:
            return None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LogStoreError("generic log source status is malformed") from exc
        normalized = normalize_status_document(decoded)
        if normalized is None:
            raise LogStoreError("generic log source status failed schema validation")
        return normalized

    def _normalize_private_state(self, value: Any) -> dict[str, Any] | None:
        kinds = {
            source_id: definition.source.kind
            for source_id, definition in self.definitions.items()
        }
        return self._normalize_private_state_for_kinds(value, kinds)

    def _normalize_private_state_for_kinds(
        self, value: Any, kinds: Mapping[str, str]
    ) -> dict[str, Any] | None:
        if not isinstance(value, Mapping) or set(value) != {"schemaVersion", "cursors", "quotaState"}:
            return None
        if value.get("schemaVersion") != STORE_SCHEMA_VERSION:
            return None
        raw_cursors = value.get("cursors")
        if not isinstance(raw_cursors, Mapping) or set(raw_cursors) != set(kinds):
            return None
        cursors: dict[str, dict[str, Any]] = {}
        for source_id, kind in kinds.items():
            raw_cursor = raw_cursors.get(source_id)
            if kind == "file":
                if not isinstance(raw_cursor, Mapping) or not set(raw_cursor).issubset({
                    "inode", "offset", "discardUntilNewline", "guardBytes", "guardSha256"
                }):
                    return None
                if raw_cursor:
                    inode = raw_cursor.get("inode")
                    offset = raw_cursor.get("offset")
                    discard = raw_cursor.get("discardUntilNewline", False)
                    guard_bytes = raw_cursor.get("guardBytes")
                    guard_sha256 = raw_cursor.get("guardSha256")
                    if (
                        isinstance(inode, bool) or not isinstance(inode, int) or inode < 0
                        or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
                        or not isinstance(discard, bool)
                        or (guard_bytes is None) != (guard_sha256 is None)
                        or guard_bytes is not None and (
                            isinstance(guard_bytes, bool)
                            or not isinstance(guard_bytes, int)
                            or not 1 <= guard_bytes <= 256
                            or guard_bytes > offset
                            or not isinstance(guard_sha256, str)
                            or len(guard_sha256) != 64
                            or any(character not in "0123456789abcdef" for character in guard_sha256)
                        )
                    ):
                        return None
                normalized = dict(raw_cursor)
            elif kind == "journald":
                if not isinstance(raw_cursor, Mapping) or set(raw_cursor) not in (set(), {"cursor"}):
                    return None
                cursor = raw_cursor.get("cursor")
                if cursor is not None and (
                    not isinstance(cursor, str)
                    or not 1 <= len(cursor) <= 2048
                    or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_=;:.,@+/-" for character in cursor)
                ):
                    return None
                normalized = {"cursor": cursor} if cursor else {}
            else:
                return None
            cursors[source_id] = normalized
        quota_state = normalize_quota_state(value.get("quotaState"), self.pipeline_limits)
        if quota_state is None:
            return None
        normalized_state = {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "cursors": cursors,
            "quotaState": quota_state,
        }
        encoded = json.dumps(normalized_state, separators=(",", ":"), allow_nan=False).encode()
        return normalized_state if len(encoded) <= MAX_STATE_BYTES else None

    def load_private_state(self) -> dict[str, Any] | None:
        raw = _read_bounded(
            self.private_state_path, expected_uid=self.expected_uid,
            maximum_bytes=MAX_STATE_BYTES, private=True,
        )
        if raw is None:
            return None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LogStoreError("generic log private state is malformed") from exc
        normalized = self._normalize_private_state(decoded)
        if normalized is not None:
            return normalized
        # A reviewed source allowlist may add or remove sources. Validate the
        # old state against its matching public status, then carry forward only
        # cursors for sources that still exist; the next commit publishes the
        # migrated exact state transactionally.
        previous_status = self.load_status_document()
        previous_kinds = {
            item["sourceId"]: item["sourceKind"]
            for item in previous_status["sources"]
        } if previous_status else {}
        previous = self._normalize_private_state_for_kinds(decoded, previous_kinds)
        if previous is None:
            raise LogStoreError("generic log private state failed schema validation")
        migrated_cursors: dict[str, dict[str, Any]] = {}
        for source_id, definition in self.definitions.items():
            candidate = previous["cursors"].get(source_id, {})
            normalized_cursor = normalize_source_cursor(definition, candidate)
            if normalized_cursor is None:
                raise LogStoreError("generic log cursor cannot be migrated safely")
            migrated_cursors[source_id] = normalized_cursor
        return {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "cursors": migrated_cursors,
            "quotaState": previous["quotaState"],
        }

    def build_status_document(
        self,
        observed_at: dt.datetime,
        acquisitions: Mapping[str, Mapping[str, Any]],
        pipeline_sources: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        observed = _iso(observed_at)
        if set(acquisitions) != set(self.definitions):
            raise ValueError("acquisition results do not match configured sources")
        stats_by_id = {
            item.get("sourceId"): item for item in pipeline_sources if isinstance(item, Mapping)
        }
        if set(stats_by_id) != set(self.definitions) or len(stats_by_id) != len(pipeline_sources):
            raise ValueError("pipeline source stats do not match configured sources")
        previous = self.load_status_document()
        previous_by_id = {
            item["sourceId"]: item for item in previous["sources"]
        } if previous else {}
        statuses: list[dict[str, Any]] = []
        for source_id, definition in self.definitions.items():
            acquisition = acquisitions[source_id]
            pipeline = stats_by_id[source_id]
            status = acquisition.get("status")
            if status not in _SOURCE_STATUSES:
                raise ValueError("acquisition status is invalid")
            raw_drops = pipeline.get("dropped")
            if not isinstance(raw_drops, Mapping):
                raise ValueError("pipeline drop counters are invalid")
            drops: dict[str, int] = {}
            for key in _DROP_FIELDS[:-1]:
                count = raw_drops.get(key, 0)
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise ValueError("pipeline drop counter is invalid")
                drops[key] = count
            acquisition_dropped = acquisition.get("droppedLines", 0)
            if isinstance(acquisition_dropped, bool) or not isinstance(acquisition_dropped, int) or acquisition_dropped < 0:
                raise ValueError("acquisition drop counter is invalid")
            drops["acquisition"] = acquisition_dropped
            last_success = observed if status in _SUCCESS_STATUSES else previous_by_id.get(
                source_id, {}
            ).get("lastSuccessAt")
            error_class = acquisition.get("errorClass")
            if status == "truncated":
                error_class = "output_limit"
            status_row = {
                "schemaVersion": STORE_SCHEMA_VERSION,
                "sourceId": source_id,
                "sourceKind": definition.source.kind,
                "status": status,
                "observedAt": observed,
                "lastSuccessAt": last_success,
                "errorClass": error_class,
                "seenLines": pipeline.get("seenLines"),
                "seenBytes": pipeline.get("seenBytes"),
                "parsedEvents": pipeline.get("parsedEvents"),
                "admittedEvents": pipeline.get("admittedEvents"),
                "droppedLines": sum(drops.values()),
                "dropped": drops,
            }
            normalized = normalize_source_status(status_row)
            if normalized is None:
                raise ValueError("source status failed public validation")
            statuses.append(normalized)
        document = {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "generatedAt": observed,
            "sources": statuses,
        }
        normalized_document = normalize_status_document(document)
        if normalized_document is None:
            raise ValueError("source status document failed validation")
        return normalized_document

    def _merge_records(
        self,
        existing: Sequence[Mapping[str, Any]],
        new_records: Sequence[Mapping[str, Any]],
        cutoff: dt.datetime,
    ) -> tuple[list[dict[str, Any]], int]:
        merged: list[dict[str, Any]] = []
        dropped = 0
        for raw in (*existing, *new_records):
            normalized = normalize_record(raw, MAX_RECORD_BYTES)
            if normalized is None:
                raise LogStoreError("generic log merge received an invalid row")
            observed = _parse_iso(normalized["observedAt"])
            if observed is None or observed < cutoff:
                dropped += 1
                continue
            merged.append(normalized)
        if len(merged) > self.max_records:
            dropped += len(merged) - self.max_records
            merged = merged[-self.max_records:]
        lines = _record_lines(merged)
        total = sum(len(line) for line in lines)
        remove = 0
        while total > self.max_file_bytes and remove < len(lines):
            total -= len(lines[remove])
            remove += 1
        if remove:
            dropped += remove
            merged = merged[remove:]
        return merged, dropped

    def _normalize_pending(self, value: Any) -> dict[str, Any] | None:
        fields = {
            "schemaVersion", "baseDigest", "baseCount", "finalDigest", "finalCount",
            "cutoff", "rows", "retentionDropped", "statusDocument", "privateState",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value.get("schemaVersion") != STORE_SCHEMA_VERSION:
            return None
        for key in ("baseDigest", "finalDigest"):
            digest = value.get(key)
            if not isinstance(digest, str) or re_full_sha256(digest) is False:
                return None
        for key, maximum in (
            ("baseCount", self.max_records), ("finalCount", self.max_records),
            ("retentionDropped", 2**63 - 1),
        ):
            count = value.get(key)
            if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= maximum:
                return None
        cutoff = _parse_iso(value.get("cutoff"))
        if cutoff is None or _iso(cutoff) != value.get("cutoff"):
            return None
        raw_rows = value.get("rows")
        if not isinstance(raw_rows, list) or len(raw_rows) > self.pipeline_limits.max_events_global_per_window:
            return None
        rows: list[dict[str, Any]] = []
        for raw in raw_rows:
            normalized = normalize_record(raw, MAX_RECORD_BYTES)
            if normalized is None:
                return None
            rows.append(normalized)
        status_document = normalize_status_document(value.get("statusDocument"))
        if status_document is None:
            return None
        pending_kinds = {
            row["sourceId"]: row["sourceKind"] for row in status_document["sources"]
        }
        private_state = self._normalize_private_state_for_kinds(
            value.get("privateState"), pending_kinds
        )
        if private_state is None:
            return None
        normalized_pending = {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "baseDigest": value["baseDigest"],
            "baseCount": value["baseCount"],
            "finalDigest": value["finalDigest"],
            "finalCount": value["finalCount"],
            "cutoff": value["cutoff"],
            "rows": rows,
            "retentionDropped": value["retentionDropped"],
            "statusDocument": status_document,
            "privateState": private_state,
        }
        encoded = json.dumps(
            normalized_pending, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
        return normalized_pending if len(encoded) <= MAX_PENDING_BYTES else None

    def _load_pending(self) -> dict[str, Any] | None:
        raw = _read_bounded(
            self.pending_path, expected_uid=self.expected_uid,
            maximum_bytes=MAX_PENDING_BYTES, private=True,
        )
        if raw is None:
            return None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LogStoreError("pending generic-log transaction is malformed") from exc
        normalized = self._normalize_pending(decoded)
        if normalized is None:
            raise LogStoreError("pending generic-log transaction failed validation")
        return normalized

    def replay(self) -> bool:
        migrated = self._migrate_legacy_redaction_history()
        pending = self._load_pending()
        if pending is None:
            return migrated
        current = self.load_records()
        current_digest = _records_digest(current)
        current_count = len(current)
        final_matches = (
            current_digest == pending["finalDigest"]
            and current_count == pending["finalCount"]
            and self.records_path.is_file()
        )
        if not final_matches:
            if current_digest != pending["baseDigest"] or current_count != pending["baseCount"]:
                raise LogStoreError("generic log output diverged from pending transaction")
            cutoff = _parse_iso(pending["cutoff"])
            assert cutoff is not None
            final, dropped = self._merge_records(current, pending["rows"], cutoff)
            if (
                _records_digest(final) != pending["finalDigest"]
                or len(final) != pending["finalCount"]
                or dropped != pending["retentionDropped"]
            ):
                raise LogStoreError("pending generic-log digest validation failed")
            _atomic_write_bytes(
                self.records_path, b"".join(_record_lines(final)), 0o640, self.expected_uid
            )
        status_payload = (json.dumps(
            pending["statusDocument"], ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        ) + "\n").encode()
        state_payload = (json.dumps(
            pending["privateState"], ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        ) + "\n").encode()
        _atomic_write_bytes(self.status_path, status_payload, 0o640, self.expected_uid)
        _atomic_write_bytes(self.private_state_path, state_payload, 0o600, self.expected_uid)
        _unlink_durable(self.pending_path)
        return True

    def commit(
        self,
        records: Sequence[Mapping[str, Any]],
        status_document: Mapping[str, Any],
        cursors: Mapping[str, Mapping[str, Any]],
        quota_state: Mapping[str, Any],
        observed_at: dt.datetime,
    ) -> dict[str, int]:
        self.replay()
        normalized_status = normalize_status_document(status_document)
        if normalized_status is None:
            raise ValueError("status document failed validation")
        observed_iso = _iso(observed_at)
        if normalized_status["generatedAt"] != observed_iso:
            raise ValueError("status document and commit observation time differ")
        private_state = self._normalize_private_state({
            "schemaVersion": STORE_SCHEMA_VERSION,
            "cursors": dict(cursors),
            "quotaState": dict(quota_state),
        })
        if private_state is None:
            raise ValueError("private generic-log state failed validation")
        new_rows: list[dict[str, Any]] = []
        for raw in records:
            normalized = normalize_record(raw, MAX_RECORD_BYTES)
            if normalized is None:
                raise ValueError("new generic log row failed validation")
            new_rows.append(normalized)
        if len(new_rows) > self.pipeline_limits.max_events_global_per_window:
            raise ValueError("generic log batch exceeds the configured event limit")
        base = self.load_records()
        observed = _parse_iso(observed_iso)
        assert observed is not None
        cutoff = observed - dt.timedelta(days=self.retention_days)
        final, retention_dropped = self._merge_records(base, new_rows, cutoff)
        pending = self._normalize_pending({
            "schemaVersion": STORE_SCHEMA_VERSION,
            "baseDigest": _records_digest(base),
            "baseCount": len(base),
            "finalDigest": _records_digest(final),
            "finalCount": len(final),
            "cutoff": _iso(cutoff),
            "rows": new_rows,
            "retentionDropped": retention_dropped,
            "statusDocument": normalized_status,
            "privateState": private_state,
        })
        if pending is None:
            raise ValueError("pending generic-log transaction exceeds its contract")
        payload = (json.dumps(
            pending, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ) + "\n").encode()
        _atomic_create_bytes(self.pending_path, payload, 0o600, self.expected_uid)
        self.replay()
        return {
            "stored": len(final),
            "accepted": len(new_rows),
            "retentionDropped": retention_dropped,
        }


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
