#!/usr/bin/env python3
"""Crash-safe persistence for Monitor's fixed-schema alert evaluator.

Rule transitions are written before evaluator state.  If the process stops in
between, the next evaluation reconstructs active state from the durable event
and deterministic event identities prevent duplicates.  The host snapshot is
independent: callers may report a ``collection_error`` here without discarding
host data.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

try:  # Package imports for tests; direct imports for the installed scripts.
    from .alert_engine import (
        LABEL_NAME,
        LABEL_VALUE,
        METRIC_NAME,
        OBSERVATION_STATUSES,
        PACK_VERSION,
        RULE_ID,
        SEVERITIES,
        TARGET_ID,
        load_rule_pack,
    )
    from .alert_runtime import evaluate_snapshot
except ImportError:  # pragma: no cover - exercised by collector integration
    from alert_engine import (  # type: ignore[no-redef]
        LABEL_NAME,
        LABEL_VALUE,
        METRIC_NAME,
        OBSERVATION_STATUSES,
        PACK_VERSION,
        RULE_ID,
        SEVERITIES,
        TARGET_ID,
        load_rule_pack,
    )
    from alert_runtime import evaluate_snapshot  # type: ignore[no-redef]


SCHEMA_VERSION = 1
MAX_STATES = 8192
MAX_EVALUATION_BYTES = 8 * 1024 * 1024
MAX_EVENT_FILE_BYTES = 32 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 8192
MAX_EVENT_RECORDS = 5000
DELIVERY_CONFIG_ENV = "MONITOR_ALERT_DELIVERY_CONFIG"
DEFAULT_DELIVERY_CONFIG_PATH = Path("/etc/monitor/alert-delivery.json")
MAX_DELIVERY_STATUS_BYTES = 4096
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PHASES = frozenset({
    "inactive", "pending", "firing", "recovering", "no_data",
    "unsupported", "permission_denied", "collection_error",
})
NOTIFICATION_STATES = frozenset({"ready", "suppressed", "silenced"})
TRANSITIONS = frozenset({"firing", "resolved"})
STATE_FIELDS = frozenset({
    "ruleId", "target", "metric", "severity", "description", "runbook",
    "phase", "breachSamples", "recoverySamples", "missingSamples",
    "openedAt", "changedAt", "lastEvaluatedAt", "lastValue",
    "observationStatus",
})
EVALUATION_FIELDS = frozenset({
    "schemaVersion", "status", "rulePackVersion", "evaluatedAt", "summary", "states",
})
EVENT_FIELDS = frozenset({
    "schemaVersion", "rulePackVersion", "idempotencyKey", "ruleId", "target", "transition",
    "severity", "notificationState", "observedAt", "openedAt", "value",
    "status", "labels", "description", "runbook",
})
PRIVATE_STATE_FIELD_ORDER = (
    "phase", "breachSamples", "recoverySamples", "missingSamples", "openedAt",
    "changedAt", "lastEvaluatedAt", "lastValue", "observationStatus",
)
PRIVATE_STATE_FIELDS = frozenset(PRIVATE_STATE_FIELD_ORDER)
PRIVATE_BUNDLE_FIELDS = frozenset({"schemaVersion", "rulePackVersion", "states"})


def _utc_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _timestamp(value: Any, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise ValueError("alert timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("alert timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("alert timestamp is invalid")
    return value


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000:
        raise ValueError("alert counter is invalid")
    return value


def _number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("alert value is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("alert value is invalid")
    return result


def _text(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("alert text is invalid")
    return value


def _normalize_state(state_key: Any, value: Any) -> dict[str, Any]:
    if not isinstance(state_key, str) or not isinstance(value, Mapping) or frozenset(value) != STATE_FIELDS:
        raise ValueError("alert state does not match the schema")
    rule_id = value.get("ruleId")
    target = value.get("target")
    metric = value.get("metric")
    severity = value.get("severity")
    phase = value.get("phase")
    observation_status = value.get("observationStatus")
    if not isinstance(rule_id, str) or RULE_ID.fullmatch(rule_id) is None:
        raise ValueError("alert state rule id is invalid")
    if not isinstance(target, str) or TARGET_ID.fullmatch(target) is None:
        raise ValueError("alert state target is invalid")
    if state_key != f"{rule_id}:{target}":
        raise ValueError("alert state key is inconsistent")
    if not isinstance(metric, str) or METRIC_NAME.fullmatch(metric) is None:
        raise ValueError("alert state metric is invalid")
    if severity not in SEVERITIES or phase not in PHASES or observation_status not in OBSERVATION_STATUSES:
        raise ValueError("alert state enum is invalid")
    return {
        "ruleId": rule_id,
        "target": target,
        "metric": metric,
        "severity": severity,
        "description": _text(value.get("description"), 500),
        "runbook": _text(value.get("runbook"), 500),
        "phase": phase,
        "breachSamples": _count(value.get("breachSamples")),
        "recoverySamples": _count(value.get("recoverySamples")),
        "missingSamples": _count(value.get("missingSamples")),
        "openedAt": _timestamp(value.get("openedAt"), True),
        "changedAt": _timestamp(value.get("changedAt")),
        "lastEvaluatedAt": _timestamp(value.get("lastEvaluatedAt")),
        "lastValue": _number(value.get("lastValue")),
        "observationStatus": observation_status,
    }


def _private_state(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in PRIVATE_STATE_FIELD_ORDER}


def _normalize_private_bundle(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != PRIVATE_BUNDLE_FIELDS:
        raise ValueError("private rule state does not match the schema")
    version = value.get("rulePackVersion")
    raw_states = value.get("states")
    if (
        value.get("schemaVersion") != SCHEMA_VERSION
        or not isinstance(version, str)
        or PACK_VERSION.fullmatch(version) is None
        or not isinstance(raw_states, Mapping)
        or len(raw_states) > MAX_STATES
    ):
        raise ValueError("private rule state is invalid")
    states: dict[str, dict[str, Any]] = {}
    for key, raw_state in raw_states.items():
        if (
            not isinstance(key, str)
            or not isinstance(raw_state, Mapping)
            or frozenset(raw_state) != PRIVATE_STATE_FIELDS
        ):
            raise ValueError("private rule state is invalid")
        rule_id, separator, target = key.partition(":")
        if (
            separator != ":"
            or RULE_ID.fullmatch(rule_id) is None
            or TARGET_ID.fullmatch(target) is None
        ):
            raise ValueError("private rule state key is invalid")
        phase = raw_state.get("phase")
        observation_status = raw_state.get("observationStatus")
        opened_at_value = raw_state.get("openedAt")
        last_value_source = raw_state.get("lastValue")
        if phase not in PHASES or observation_status not in OBSERVATION_STATUSES:
            raise ValueError("private rule state enum is invalid")
        opened_at = _timestamp(opened_at_value, True)
        last_value = _number(last_value_source)
        if (
            (phase in {"firing", "recovering"}) != (opened_at is not None)
            or (observation_status != "ok" and last_value is not None)
        ):
            raise ValueError("private rule state is inconsistent")
        states[key] = {
            "phase": phase,
            "breachSamples": _count(raw_state.get("breachSamples")),
            "recoverySamples": _count(raw_state.get("recoverySamples")),
            "missingSamples": _count(raw_state.get("missingSamples")),
            "openedAt": opened_at,
            "changedAt": _timestamp(raw_state.get("changedAt")),
            "lastEvaluatedAt": _timestamp(raw_state.get("lastEvaluatedAt")),
            "lastValue": last_value,
            "observationStatus": observation_status,
        }
    return {"schemaVersion": SCHEMA_VERSION, "rulePackVersion": version, "states": states}


def normalize_evaluation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != EVALUATION_FIELDS:
        raise ValueError("rule evaluation does not match the schema")
    if value.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("rule evaluation schema is unsupported")
    status = value.get("status")
    if status not in {"ok", "collection_error"}:
        raise ValueError("rule evaluation status is invalid")
    evaluated_at = _timestamp(value.get("evaluatedAt"))
    raw_states = value.get("states")
    raw_summary = value.get("summary")
    if not isinstance(raw_states, Mapping) or len(raw_states) > MAX_STATES or not isinstance(raw_summary, Mapping):
        raise ValueError("rule evaluation collections are invalid")
    states = {key: _normalize_state(key, state) for key, state in raw_states.items()}
    summary: dict[str, int] = {}
    for key, count in raw_summary.items():
        if key not in PHASES:
            raise ValueError("rule evaluation summary phase is invalid")
        summary[key] = _count(count)
    calculated: dict[str, int] = {}
    for state in states.values():
        phase = state["phase"]
        calculated[phase] = calculated.get(phase, 0) + 1
    if dict(sorted(summary.items())) != dict(sorted(calculated.items())):
        raise ValueError("rule evaluation summary is inconsistent")
    version = value.get("rulePackVersion")
    if status == "ok":
        if not isinstance(version, str) or PACK_VERSION.fullmatch(version) is None or not states:
            raise ValueError("successful rule evaluation is incomplete")
    elif version is not None or states or summary:
        raise ValueError("failed rule evaluation must not publish partial state")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": status,
        "rulePackVersion": version,
        "evaluatedAt": evaluated_at,
        "summary": dict(sorted(summary.items())),
        "states": states,
    }


def normalize_event(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != EVENT_FIELDS or value.get("schemaVersion") != 1:
        raise ValueError("rule alert event does not match the schema")
    pack_version = value.get("rulePackVersion")
    key = value.get("idempotencyKey")
    rule_id = value.get("ruleId")
    target = value.get("target")
    transition = value.get("transition")
    severity = value.get("severity")
    notification_state = value.get("notificationState")
    status = value.get("status")
    if not isinstance(pack_version, str) or PACK_VERSION.fullmatch(pack_version) is None:
        raise ValueError("rule alert pack version is invalid")
    if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None:
        raise ValueError("rule alert idempotency key is invalid")
    if not isinstance(rule_id, str) or RULE_ID.fullmatch(rule_id) is None:
        raise ValueError("rule alert rule id is invalid")
    if not isinstance(target, str) or TARGET_ID.fullmatch(target) is None:
        raise ValueError("rule alert target is invalid")
    if transition not in TRANSITIONS or severity not in SEVERITIES:
        raise ValueError("rule alert transition is invalid")
    if notification_state not in NOTIFICATION_STATES or status not in OBSERVATION_STATUSES:
        raise ValueError("rule alert status is invalid")
    raw_labels = value.get("labels")
    if not isinstance(raw_labels, Mapping) or len(raw_labels) > 16:
        raise ValueError("rule alert labels are invalid")
    labels: dict[str, str] = {}
    for label, label_value in raw_labels.items():
        if not isinstance(label, str) or LABEL_NAME.fullmatch(label) is None:
            raise ValueError("rule alert label is invalid")
        if not isinstance(label_value, str) or LABEL_VALUE.fullmatch(label_value) is None:
            raise ValueError("rule alert label value is invalid")
        labels[label] = label_value
    return {
        "schemaVersion": 1,
        "rulePackVersion": pack_version,
        "idempotencyKey": key,
        "ruleId": rule_id,
        "target": target,
        "transition": transition,
        "severity": severity,
        "notificationState": notification_state,
        "observedAt": _timestamp(value.get("observedAt")),
        "openedAt": _timestamp(value.get("openedAt")),
        "value": _number(value.get("value")),
        "status": status,
        "labels": dict(sorted(labels.items())),
        "description": _text(value.get("description"), 500),
        "runbook": _text(value.get("runbook"), 500),
    }


def _safe_existing_file(path: Path, maximum_bytes: int, expected_mode: int | None) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
        or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
    ):
        raise ValueError("alert persistence file is unsafe")
    return metadata


def _read_file(path: Path, maximum_bytes: int, expected_mode: int | None) -> bytes | None:
    metadata = _safe_existing_file(path, maximum_bytes, expected_mode)
    if metadata is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_nlink != 1
        ):
            raise ValueError("alert persistence file changed while reading")
        payload = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
        raise ValueError("alert persistence file changed while reading")
    return payload


def _ensure_replaceable(path: Path) -> None:
    _safe_existing_file(path, max(MAX_EVALUATION_BYTES, MAX_EVENT_FILE_BYTES), None)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    _ensure_replaceable(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _json_payload(value: Any, maximum_bytes: int) -> bytes:
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if not 0 < len(payload) <= maximum_bytes:
        raise ValueError("alert persistence payload exceeds its byte limit")
    return payload


def _load_previous(path: Path, pack_version: str) -> dict[str, Any]:
    payload = _read_file(path, MAX_EVALUATION_BYTES, 0o600)
    if payload is None:
        return {}
    try:
        bundle = _normalize_private_bundle(json.loads(payload.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("private rule state is invalid") from error
    if bundle["rulePackVersion"] != pack_version:
        return {}
    return bundle["states"]


def _load_events(path: Path, limit: int) -> list[dict[str, Any]]:
    payload = _read_file(path, MAX_EVENT_FILE_BYTES, 0o640)
    if payload is None:
        return []
    if not payload:
        return []
    if not payload.endswith(b"\n"):
        raise ValueError("rule alert log has an incomplete final record")
    lines = payload.splitlines()
    if len(lines) > limit:
        raise ValueError("rule alert log exceeds its record limit")
    records: list[dict[str, Any]] = []
    for line in lines:
        if not line or len(line) > MAX_EVENT_LINE_BYTES:
            raise ValueError("rule alert log contains an invalid record")
        try:
            records.append(normalize_event(json.loads(line.decode("utf-8"))))
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise ValueError("rule alert log contains an invalid record") from None
    return records


def _merge_events(
    existing: Sequence[Mapping[str, Any]],
    additions: Sequence[Mapping[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in (*existing, *additions):
        event = normalize_event(raw)
        key = event["idempotencyKey"]
        prior = merged.get(key)
        if prior is not None:
            # A crash after the event rewrite but before the state replacement
            # replays the same transition at a later evaluation timestamp.
            # The first durable row is authoritative for that identity.
            continue
        merged[key] = event
        order.append(key)
    return [merged[key] for key in order[-limit:]]


def _rehydrate_active_states(
    previous: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    pack_version: str,
) -> dict[str, Any]:
    """Recover event-first commits whose private state replacement was lost."""

    result = dict(previous)
    active: dict[str, Mapping[str, Any]] = {}
    for raw in events:
        event = normalize_event(raw)
        if event["rulePackVersion"] != pack_version:
            continue
        state_key = f'{event["ruleId"]}:{event["target"]}'
        if event["transition"] == "firing":
            active[state_key] = event
        elif (
            state_key in active
            and active[state_key].get("openedAt") == event["openedAt"]
        ):
            active.pop(state_key, None)

    for state_key, event in active.items():
        prior = result.get(state_key)
        normalized_prior = prior if isinstance(prior, Mapping) else {}
        prior_phase = normalized_prior.get("phase")
        prior_evaluated = normalized_prior.get("lastEvaluatedAt")
        if prior_phase in {"firing", "recovering"}:
            continue
        if (
            isinstance(prior_evaluated, str)
            and prior_evaluated >= event["observedAt"]
        ):
            continue
        result[state_key] = {
            "phase": "firing",
            "breachSamples": 0,
            "recoverySamples": 0,
            "missingSamples": 0,
            "openedAt": event["openedAt"],
            "changedAt": event["observedAt"],
            "lastEvaluatedAt": event["observedAt"],
            "lastValue": event["value"] if event["status"] == "ok" else None,
            "observationStatus": event["status"],
        }
    return result


def _write_events(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    lines: list[bytes] = []
    total = 0
    for record in records:
        line = _json_payload(normalize_event(record), MAX_EVENT_LINE_BYTES)
        total += len(line)
        if total > MAX_EVENT_FILE_BYTES:
            raise ValueError("rule alert log exceeds its byte limit")
        lines.append(line)
    _atomic_write(path, b"".join(lines), 0o640)


def failure_evaluation(now: dt.datetime) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": "collection_error",
        "rulePackVersion": None,
        "evaluatedAt": _utc_timestamp(now),
        "summary": {},
        "states": {},
    }


def _delivery_config_path(explicit: Path | None) -> Path | None:
    if explicit is not None:
        candidate = explicit
    else:
        configured = os.environ.get(DELIVERY_CONFIG_ENV)
        if configured is not None:
            if not configured or len(configured) > 512 or "\x00" in configured:
                raise ValueError("alert delivery configuration path is invalid")
            candidate = Path(configured)
        elif DEFAULT_DELIVERY_CONFIG_PATH.exists():
            candidate = DEFAULT_DELIVERY_CONFIG_PATH
        else:
            return None
    if not candidate.is_absolute():
        raise ValueError("alert delivery configuration path must be absolute")
    return candidate


def _enqueue_delivery_events(
    events: Sequence[Mapping[str, Any]],
    now: dt.datetime,
    output_dir: Path,
    explicit_config: Path | None,
) -> dict[str, int] | None:
    """Enqueue without importing adapters or performing network I/O.

    This is deliberately called after event/state/evaluation persistence and
    isolated by the caller.  Replaying recent retained events is safe because
    the outbox delivery key is deterministic per event, channel, and purpose.
    """

    config_path = _delivery_config_path(explicit_config)
    if config_path is None:
        return None
    try:
        from .alert_delivery import (
            DeliveryOutbox, enqueue_operational_events, load_delivery_config,
        )
    except ImportError:  # pragma: no cover - installed modules are top-level
        from alert_delivery import (  # type: ignore[no-redef]
            DeliveryOutbox, enqueue_operational_events, load_delivery_config,
        )
    config = load_delivery_config(config_path)
    outbox = DeliveryOutbox(
        output_dir / ".state" / "alert-delivery" / "alert-delivery.sqlite",
        config.queue,
    )
    return enqueue_operational_events(outbox, config, events, now)


def _write_delivery_enqueue_status(
    output_dir: Path,
    now: dt.datetime,
    status: str,
    counts: Mapping[str, Any] | None = None,
) -> None:
    if status not in {"ok", "error"}:
        raise ValueError("alert delivery enqueue status is invalid")
    normalized_counts = {key: 0 for key in ("enqueued", "deduplicated", "dropped", "skipped")}
    if counts is not None:
        for key in normalized_counts:
            value = counts.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("alert delivery enqueue counters are invalid")
            normalized_counts[key] = value
    _atomic_write(
        output_dir / "alert-delivery-enqueue.json",
        _json_payload({
            "schemaVersion": 1,
            "status": status,
            "observedAt": _utc_timestamp(now),
            **normalized_counts,
        }, MAX_DELIVERY_STATUS_BYTES),
        0o640,
    )


def evaluate_and_persist(
    snapshot: Mapping[str, Any],
    now: dt.datetime,
    rule_pack_path: Path,
    output_dir: Path,
    max_records: int = MAX_EVENT_RECORDS,
    delivery_config_path: Path | None = None,
) -> dict[str, Any]:
    """Evaluate one snapshot and publish bounded state without raising.

    A returned ``collection_error`` is deliberately local to rule evaluation;
    the host collector can continue publishing its independently collected
    snapshot and history.
    """

    public_path = output_dir / "rule-evaluation.json"
    state_path = output_dir / ".state" / "rule-state.json"
    events_path = output_dir / "rule-alerts.jsonl"
    limit = max(10, min(MAX_EVENT_RECORDS, max_records))
    try:
        pack = load_rule_pack(rule_pack_path)
        previous = _load_previous(state_path, pack.version)
        existing_events = _load_events(events_path, limit)
        previous = _rehydrate_active_states(previous, existing_events, pack.version)
        raw_evaluation, additions = evaluate_snapshot(pack, snapshot, previous, now)
        evaluation = normalize_evaluation(raw_evaluation)
        events = _merge_events(existing_events, additions, limit)
        # Events precede state.  The next evaluation can rehydrate an active
        # transition if collection stops before the state replacement.
        if events != existing_events or not events_path.exists():
            _write_events(events_path, events)
        private_bundle = _normalize_private_bundle({
            "schemaVersion": SCHEMA_VERSION,
            "rulePackVersion": pack.version,
            "states": {
                key: _private_state(state)
                for key, state in evaluation["states"].items()
            },
        })
        _atomic_write(
            state_path,
            _json_payload(private_bundle, MAX_EVALUATION_BYTES),
            0o600,
        )
        _atomic_write(public_path, _json_payload(evaluation, MAX_EVALUATION_BYTES), 0o640)
        try:
            delivery_counts = _enqueue_delivery_events(
                events, now, output_dir, delivery_config_path,
            )
            if delivery_counts is not None:
                _write_delivery_enqueue_status(output_dir, now, "ok", delivery_counts)
        except Exception:
            # Delivery configuration, SQLite, and adapter installation are a
            # separate failure domain.  Recent events are retried on the next
            # evaluation and deterministic keys prevent duplicate queue rows.
            try:
                _write_delivery_enqueue_status(output_dir, now, "error")
            except Exception:
                pass
        return evaluation
    except Exception:
        failure = failure_evaluation(now)
        try:
            _atomic_write(public_path, _json_payload(failure, MAX_EVALUATION_BYTES), 0o640)
        except Exception:
            pass
        return failure
