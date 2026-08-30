#!/usr/bin/env python3
"""Orchestrate reviewed generic-log sources without exposing raw input."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import uuid
from pathlib import Path
from time import monotonic as _monotonic
from typing import Any, Sequence

try:  # Installed modules share one directory.
    from log_pipeline import (
        PipelineLimits,
        SourceBatch,
        input_budget_per_source,
        process_batches,
    )
    from log_sources import (
        SourceConfigError,
        load_source_config,
        read_file_source,
        read_journal_source,
    )
    from log_store import (
        MAX_STORED_BYTES,
        MAX_STORED_RECORDS,
        GenericLogStore,
        LogStoreError,
    )
except ModuleNotFoundError:  # pragma: no cover - package-style tests
    from .log_pipeline import (
        PipelineLimits,
        SourceBatch,
        input_budget_per_source,
        process_batches,
    )
    from .log_sources import (
        SourceConfigError,
        load_source_config,
        read_file_source,
        read_journal_source,
    )
    from .log_store import (
        MAX_STORED_BYTES,
        MAX_STORED_RECORDS,
        GenericLogStore,
        LogStoreError,
    )


FAILURE_MARKER = "generic-log-collection-error.json"
FAILURE_SCHEMA_VERSION = 1


def _iso(value: dt.datetime) -> str:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_marker_metadata(path: Path, expected_uid: int) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o027
        or metadata.st_size > 4096
    ):
        raise LogStoreError("generic log failure marker is unsafe")
    return metadata


def _write_failure_marker(
    root: Path,
    observed_at: dt.datetime,
    error_class: str,
    expected_uid: int,
) -> None:
    if error_class not in {"unsafe_config", "collection_failed", "persistence_failed"}:
        raise ValueError("unsupported generic log failure class")
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
        raise LogStoreError("generic log output directory is unsafe")
    target = root / FAILURE_MARKER
    _safe_marker_metadata(target, expected_uid)
    payload = (json.dumps({
        "schemaVersion": FAILURE_SCHEMA_VERSION,
        "observedAt": _iso(observed_at),
        "errorClass": error_class,
    }, separators=(",", ":"), allow_nan=False) + "\n").encode()
    temporary = root / f".{FAILURE_MARKER}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o640)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short failure-marker write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, target)
        os.chmod(target, 0o640, follow_symlinks=False)
        _fsync_directory(root)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _clear_failure_marker(root: Path, expected_uid: int) -> None:
    target = root / FAILURE_MARKER
    if _safe_marker_metadata(target, expected_uid) is None:
        return
    target.unlink()
    _fsync_directory(root)


def _failure_class(error: Exception) -> str:
    if isinstance(error, SourceConfigError):
        return "unsafe_config"
    if isinstance(error, (LogStoreError, OSError)):
        return "persistence_failed"
    return "collection_failed"


def collect_generic_logs(
    output_dir: Path,
    source_config: Path,
    observed_at: dt.datetime,
    *,
    required: bool = False,
    expected_uid: int | None = None,
    allowed_file_roots: Sequence[Path] = (Path("/var/log"), Path("/run/log")),
    journalctl: str = "/usr/bin/journalctl",
    command_timeout: float = 3.0,
    total_timeout: float = 15.0,
    retention_days: int = 30,
    max_records: int = MAX_STORED_RECORDS,
    max_file_bytes: int = MAX_STORED_BYTES,
    pipeline_limits: PipelineLimits | None = None,
) -> dict[str, Any]:
    """Acquire, normalize, and atomically publish one bounded log batch.

    Expected acquisition failures remain per-source status. Configuration and
    persistence failures are isolated from host telemetry and published through
    a strict marker consumed by the HTTP read model.
    """

    owner = os.geteuid() if expected_uid is None else expected_uid
    root = Path(output_dir)
    active_limits = pipeline_limits or PipelineLimits()
    if not 1.0 <= total_timeout <= 30.0:
        raise ValueError("generic log total timeout is outside its supported range")
    try:
        definitions = load_source_config(
            Path(source_config),
            expected_uid=owner,
            allowed_file_roots=allowed_file_roots,
            required=required,
        )
        store = GenericLogStore(
            root,
            definitions,
            expected_uid=owner,
            retention_days=retention_days,
            max_records=max_records,
            max_file_bytes=max_file_bytes,
            pipeline_limits=active_limits,
        )
        store.replay()
        prior_state = store.load_private_state()
        prior_cursors = prior_state["cursors"] if prior_state else {
            definition.source.source_id: {} for definition in definitions
        }
        acquisitions: dict[str, dict[str, Any]] = {}
        batches: list[SourceBatch] = []
        next_cursors: dict[str, dict[str, Any]] = {}
        pem_recovery_sources: list[str] = []
        source_input_budget = input_budget_per_source(len(definitions), active_limits)
        deadline = _monotonic() + total_timeout
        for definition in definitions:
            source_id = definition.source.source_id
            cursor = prior_cursors.get(source_id, {})
            remaining = deadline - _monotonic()
            if remaining < 0.1:
                acquired = {
                    "status": "failed", "errorClass": "timeout", "lines": [],
                    "cursor": cursor, "droppedLines": 0,
                }
            else:
                try:
                    if definition.source.kind == "file":
                        acquired = read_file_source(
                            definition,
                            cursor,
                            maximum_bytes=source_input_budget,
                            maximum_line_bytes=min(
                                active_limits.max_line_bytes, source_input_budget
                            ),
                        )
                        if acquired.get("rotationGap") is True:
                            acquired = dict(acquired)
                            acquired["status"] = "truncated"
                            acquired["errorClass"] = "output_limit"
                    else:
                        acquired = read_journal_source(
                            definition,
                            cursor,
                            journalctl=journalctl,
                            timeout_seconds=max(0.1, min(command_timeout, remaining)),
                            maximum_bytes=source_input_budget,
                        )
                except (OSError, TypeError, ValueError):
                    acquired = {
                        "status": "failed", "errorClass": "read_failed", "lines": [],
                        "cursor": cursor, "droppedLines": 0,
                    }
            acquisitions[source_id] = acquired
            if (
                not cursor
                or acquired.get("rotationGap") is True
                or acquired.get("backlogGap") is True
                or acquired.get("droppedLines", 0) > 0
            ):
                pem_recovery_sources.append(source_id)
            batches.append(SourceBatch(definition.source, acquired["lines"]))
            next_cursors[source_id] = acquired["cursor"]
        pipeline = process_batches(
            batches,
            observed_at,
            limits=active_limits,
            prior_state=prior_state["quotaState"] if prior_state else None,
            pem_recovery_sources=pem_recovery_sources,
        )
        # Status construction does not consume raw lines. Release all-source
        # acquisition payloads before the store reads and serializes retained
        # history, rather than stacking both memory phases under MemoryMax.
        for acquisition in acquisitions.values():
            acquisition.pop("lines", None)
        batches.clear()
        status = store.build_status_document(
            observed_at, acquisitions, pipeline["sources"]
        )
        committed = store.commit(
            pipeline["records"],
            status,
            next_cursors,
            pipeline["quotaState"],
            observed_at,
        )
        _clear_failure_marker(root, owner)
        return {
            "schemaVersion": 1,
            "status": "ok",
            "sources": len(definitions),
            "admitted": pipeline["admittedTotal"],
            "dropped": pipeline["droppedTotal"],
            **committed,
        }
    except Exception as error:
        error_class = _failure_class(error)
        try:
            _write_failure_marker(root, observed_at, error_class, owner)
        except Exception:
            # The host collector still proceeds; unsafe storage remains closed
            # and the HTTP reader will reject any malformed/unsafe marker.
            pass
        return {
            "schemaVersion": 1,
            "status": "collection_error",
            "errorClass": error_class,
            "sources": 0,
            "admitted": 0,
            "dropped": 0,
            "stored": 0,
            "accepted": 0,
            "retentionDropped": 0,
        }
