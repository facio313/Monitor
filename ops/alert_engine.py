#!/usr/bin/env python3
"""Deterministic, bounded alert-rule evaluation for Monitor.

The evaluator deliberately accepts a small declarative schema instead of an
expression language.  It does not read host data, perform delivery, or mutate
state on its own.  Callers provide normalized observations and persist the
returned state atomically.  This keeps rule evaluation testable and prevents a
rule file from becoming an arbitrary-code execution surface.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


RULE_PACK_SCHEMA_VERSION = 1
MAX_RULE_PACK_BYTES = 512 * 1024
MAX_RULES = 256
MAX_LABELS = 16
MAX_TEXT = 500
RULE_ID = re.compile(r"^[A-Z][A-Za-z0-9]{2,63}$")
PACK_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
METRIC_NAME = re.compile(r"^[a-z][a-z0-9_.]{2,127}$")
TARGET_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,191}$")
LABEL_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
LABEL_VALUE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,95}$")
OPERATORS = frozenset({"gt", "gte", "lt", "lte", "eq", "neq"})
SEVERITIES = frozenset({"info", "warning", "critical"})
NO_DATA_POLICIES = frozenset({"ignore", "alert"})
OBSERVATION_STATUSES = frozenset({
    "ok", "no_data", "stale", "collection_error", "permission_denied", "unsupported",
})
MAX_CONTINUOUS_EVALUATION_GAP_SECONDS = 90
STATE_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class RulePackError(ValueError):
    """Raised when a rule pack violates the fixed public contract."""


@dataclass(frozen=True)
class AlertRule:
    rule_id: str
    metric: str
    operator: str
    threshold: float
    recovery_threshold: float
    severity: str
    for_samples: int
    recovery_samples: int
    no_data_policy: str
    no_data_samples: int
    parent_rule_id: str | None
    labels: tuple[tuple[str, str], ...]
    description: str
    runbook: str
    enabled: bool


@dataclass(frozen=True)
class RulePack:
    schema_version: int
    version: str
    rules: tuple[AlertRule, ...]


@dataclass(frozen=True)
class Observation:
    target: str
    value: float | None
    status: str = "ok"
    labels: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Silence:
    silence_id: str
    starts_at: dt.datetime
    ends_at: dt.datetime
    rule_id: str | None = None
    target: str | None = None
    labels: tuple[tuple[str, str], ...] = ()


def _bounded_text(value: Any, field: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise RulePackError(f"{field} must be text")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        raise RulePackError(f"{field} must contain 1-{maximum} characters")
    return normalized


def _bounded_count(value: Any, field: str, minimum: int = 1, maximum: int = 10_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RulePackError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _finite(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise RulePackError(f"{field} must be a finite number")
    return float(value)


def _labels(value: Any, field: str) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping) or len(value) > MAX_LABELS:
        raise RulePackError(f"{field} must be an object with at most {MAX_LABELS} labels")
    result: list[tuple[str, str]] = []
    for key, item in value.items():
        if not isinstance(key, str) or LABEL_NAME.fullmatch(key) is None:
            raise RulePackError(f"{field} contains an invalid label name")
        if not isinstance(item, str) or LABEL_VALUE.fullmatch(item) is None:
            raise RulePackError(f"{field}.{key} contains an invalid label value")
        result.append((key, item))
    return tuple(sorted(result))


def _runtime_labels(value: Sequence[tuple[str, str]], field: str) -> tuple[tuple[str, str], ...]:
    if len(value) > MAX_LABELS:
        raise ValueError(f"{field} contains too many labels")
    result: dict[str, str] = {}
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError(f"{field} labels must be key/value pairs")
        key, label_value = item
        if not isinstance(key, str) or LABEL_NAME.fullmatch(key) is None:
            raise ValueError(f"{field} contains an invalid label name")
        if not isinstance(label_value, str) or LABEL_VALUE.fullmatch(label_value) is None:
            raise ValueError(f"{field} contains an invalid label value")
        if key in result:
            raise ValueError(f"{field} contains duplicate labels")
        result[key] = label_value
    return tuple(sorted(result.items()))


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], field: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RulePackError(f"{field} keys do not match schema (missing={missing}, extra={extra})")


def parse_rule_pack(value: Any) -> RulePack:
    if not isinstance(value, Mapping):
        raise RulePackError("rule pack must be an object")
    _exact_keys(value, frozenset({"schemaVersion", "version", "rules"}), "rule pack")
    if value["schemaVersion"] != RULE_PACK_SCHEMA_VERSION:
        raise RulePackError("unsupported rule-pack schemaVersion")
    version = _bounded_text(value["version"], "version", 64)
    if PACK_VERSION.fullmatch(version) is None:
        raise RulePackError("version is invalid")
    raw_rules = value["rules"]
    if not isinstance(raw_rules, list) or not 1 <= len(raw_rules) <= MAX_RULES:
        raise RulePackError(f"rules must contain 1-{MAX_RULES} entries")

    expected = frozenset({
        "id", "metric", "operator", "threshold", "recoveryThreshold", "severity",
        "forSamples", "recoverySamples", "noDataPolicy", "noDataSamples",
        "parentRuleId", "labels", "description", "runbook", "enabled",
    })
    rules: list[AlertRule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        field = f"rules[{index}]"
        if not isinstance(raw, Mapping):
            raise RulePackError(f"{field} must be an object")
        _exact_keys(raw, expected, field)
        rule_id = _bounded_text(raw["id"], f"{field}.id", 64)
        if RULE_ID.fullmatch(rule_id) is None or rule_id in seen:
            raise RulePackError(f"{field}.id must be unique and stable")
        seen.add(rule_id)
        metric = _bounded_text(raw["metric"], f"{field}.metric", 128)
        if METRIC_NAME.fullmatch(metric) is None:
            raise RulePackError(f"{field}.metric is invalid")
        operator = raw["operator"]
        if operator not in OPERATORS:
            raise RulePackError(f"{field}.operator is unsupported")
        threshold = _finite(raw["threshold"], f"{field}.threshold")
        recovery_threshold = _finite(raw["recoveryThreshold"], f"{field}.recoveryThreshold")
        if operator in {"gt", "gte"} and recovery_threshold > threshold:
            raise RulePackError(f"{field}.recoveryThreshold must not exceed threshold")
        if operator in {"lt", "lte"} and recovery_threshold < threshold:
            raise RulePackError(f"{field}.recoveryThreshold must not be below threshold")
        severity = raw["severity"]
        if severity not in SEVERITIES:
            raise RulePackError(f"{field}.severity is unsupported")
        no_data_policy = raw["noDataPolicy"]
        if no_data_policy not in NO_DATA_POLICIES:
            raise RulePackError(f"{field}.noDataPolicy is unsupported")
        parent = raw["parentRuleId"]
        if parent is not None and (not isinstance(parent, str) or RULE_ID.fullmatch(parent) is None):
            raise RulePackError(f"{field}.parentRuleId is invalid")
        enabled = raw["enabled"]
        if not isinstance(enabled, bool):
            raise RulePackError(f"{field}.enabled must be boolean")
        rules.append(AlertRule(
            rule_id=rule_id,
            metric=metric,
            operator=operator,
            threshold=threshold,
            recovery_threshold=recovery_threshold,
            severity=severity,
            for_samples=_bounded_count(raw["forSamples"], f"{field}.forSamples"),
            recovery_samples=_bounded_count(raw["recoverySamples"], f"{field}.recoverySamples"),
            no_data_policy=no_data_policy,
            no_data_samples=_bounded_count(raw["noDataSamples"], f"{field}.noDataSamples"),
            parent_rule_id=parent,
            labels=_labels(raw["labels"], f"{field}.labels"),
            description=_bounded_text(raw["description"], f"{field}.description"),
            runbook=_bounded_text(raw["runbook"], f"{field}.runbook"),
            enabled=enabled,
        ))

    known = {rule.rule_id for rule in rules}
    for rule in rules:
        if rule.parent_rule_id is not None and rule.parent_rule_id not in known:
            raise RulePackError(f"{rule.rule_id} references an unknown parent rule")
        if rule.parent_rule_id == rule.rule_id:
            raise RulePackError(f"{rule.rule_id} cannot suppress itself")
    parents = {rule.rule_id: rule.parent_rule_id for rule in rules}
    for rule in rules:
        visited: set[str] = set()
        current: str | None = rule.rule_id
        while current is not None:
            if current in visited:
                raise RulePackError("parent-rule graph contains a cycle")
            visited.add(current)
            current = parents.get(current)
    return RulePack(RULE_PACK_SCHEMA_VERSION, version, tuple(rules))


def load_rule_pack(path: Path) -> RulePack:
    metadata = path.stat(follow_symlinks=False)
    if not path.is_file() or path.is_symlink() or metadata.st_size > MAX_RULE_PACK_BYTES:
        raise RulePackError("rule pack must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RulePackError("rule pack could not be read") from error
    return parse_rule_pack(value)


def _condition(operator: str, value: float, threshold: float) -> bool:
    return {
        "gt": value > threshold,
        "gte": value >= threshold,
        "lt": value < threshold,
        "lte": value <= threshold,
        "eq": value == threshold,
        "neq": value != threshold,
    }[operator]


def _recovered(rule: AlertRule, value: float) -> bool:
    if rule.operator in {"gt", "gte"}:
        return value < rule.recovery_threshold
    if rule.operator in {"lt", "lte"}:
        return value > rule.recovery_threshold
    return value == rule.recovery_threshold


def _timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _prior_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    phase = value.get("phase")
    if phase not in {"inactive", "pending", "firing", "recovering", "no_data", "unsupported", "permission_denied", "collection_error"}:
        return {}
    result = {"phase": phase}
    for key in ("breachSamples", "recoverySamples", "missingSamples"):
        item = value.get(key)
        result[key] = item if isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 10_000 else 0
    for key in ("openedAt", "changedAt"):
        item = value.get(key)
        result[key] = item if isinstance(item, str) and STATE_TIMESTAMP.fullmatch(item) else None
    last_evaluated = value.get("lastEvaluatedAt")
    result["lastEvaluatedAt"] = (
        last_evaluated
        if isinstance(last_evaluated, str) and STATE_TIMESTAMP.fullmatch(last_evaluated)
        else None
    )
    return result


def _parsed_state_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or STATE_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def evaluate_observation(
    rule: AlertRule,
    observation: Observation,
    previous: Any,
    now: dt.datetime,
) -> tuple[dict[str, Any], str | None]:
    """Evaluate one target and return state plus transition kind.

    Missing/stale/failed observations never advance a threshold breach.  A
    no-data alert advances only its independent missing counter.
    """

    if TARGET_ID.fullmatch(observation.target) is None:
        raise ValueError("observation target is invalid")
    if observation.status not in OBSERVATION_STATUSES:
        raise ValueError("observation status is invalid")
    _runtime_labels(observation.labels, "observation")
    previous_state = _prior_state(previous)
    previous_phase = previous_state.get("phase", "inactive")
    previous_evaluated_at = _parsed_state_timestamp(previous_state.get("lastEvaluatedAt"))
    normalized_now = now if now.tzinfo is not None else now.replace(tzinfo=dt.timezone.utc)
    normalized_now = normalized_now.astimezone(dt.timezone.utc)
    if previous_evaluated_at is not None:
        gap_seconds = (normalized_now - previous_evaluated_at).total_seconds()
        if gap_seconds < 0 or gap_seconds > MAX_CONTINUOUS_EVALUATION_GAP_SECONDS:
            if previous_phase in {"firing", "recovering"}:
                previous_state["phase"] = "firing"
                previous_state["recoverySamples"] = 0
            else:
                previous_state = {}
            previous_phase = previous_state.get("phase", "inactive")
    breach_samples = previous_state.get("breachSamples", 0)
    recovery_samples = previous_state.get("recoverySamples", 0)
    missing_samples = previous_state.get("missingSamples", 0)
    opened_at = previous_state.get("openedAt")
    phase = previous_phase

    if not rule.enabled:
        phase = "inactive"
        breach_samples = recovery_samples = missing_samples = 0
        opened_at = None
    elif observation.status in {"unsupported", "permission_denied", "collection_error"}:
        missing_samples = min(10_000, missing_samples + 1)
        if previous_phase in {"firing", "recovering"}:
            # Loss of observability is not evidence that an active condition
            # recovered. Preserve the incident identity and require a valid
            # recovery sample before resolving it.
            phase = "firing"
            recovery_samples = 0
        else:
            phase = observation.status
            breach_samples = recovery_samples = 0
            opened_at = None
    elif observation.status in {"no_data", "stale"} or observation.value is None:
        missing_samples = min(10_000, missing_samples + 1)
        if previous_phase in {"firing", "recovering"}:
            phase = "firing"
            recovery_samples = 0
        elif rule.no_data_policy == "alert" and missing_samples >= rule.no_data_samples:
            breach_samples = recovery_samples = 0
            if previous_phase != "firing":
                opened_at = opened_at or previous_state.get("changedAt") or _timestamp(now)
            phase = "firing"
        else:
            breach_samples = recovery_samples = 0
            phase = "no_data"
            opened_at = None
    else:
        value = float(observation.value)
        if not math.isfinite(value):
            raise ValueError("observation value must be finite")
        missing_samples = 0
        if previous_phase in {"firing", "recovering"}:
            if _recovered(rule, value):
                recovery_samples = min(rule.recovery_samples, recovery_samples + 1)
                phase = "inactive" if recovery_samples >= rule.recovery_samples else "recovering"
                if phase == "inactive":
                    opened_at = None
                    breach_samples = 0
            else:
                phase = "firing"
                recovery_samples = 0
        elif _condition(rule.operator, value, rule.threshold):
            breach_samples = min(rule.for_samples, breach_samples + 1)
            recovery_samples = 0
            if breach_samples >= rule.for_samples:
                phase = "firing"
                opened_at = opened_at or previous_state.get("changedAt") or _timestamp(now)
            else:
                phase = "pending"
        else:
            phase = "inactive"
            breach_samples = recovery_samples = 0
            opened_at = None

    transition: str | None = None
    if phase != previous_phase:
        if phase == "firing":
            transition = "firing"
        elif previous_phase in {"firing", "recovering"} and phase == "inactive":
            transition = "resolved"
        else:
            transition = phase

    now_text = _timestamp(now)
    state = {
        "phase": phase,
        "breachSamples": breach_samples,
        "recoverySamples": recovery_samples,
        "missingSamples": missing_samples,
        "openedAt": opened_at,
        "changedAt": now_text if phase != previous_phase else previous_state.get("changedAt") or now_text,
        "lastEvaluatedAt": now_text,
        "lastValue": observation.value if observation.status == "ok" else None,
        "observationStatus": observation.status,
    }
    return state, transition


def _silenced(rule: AlertRule, observation: Observation, silence: Silence, now: dt.datetime) -> bool:
    if TARGET_ID.fullmatch(silence.silence_id) is None:
        raise ValueError("silence id is invalid")
    if silence.rule_id is not None and RULE_ID.fullmatch(silence.rule_id) is None:
        raise ValueError("silence rule id is invalid")
    if silence.target is not None and TARGET_ID.fullmatch(silence.target) is None:
        raise ValueError("silence target is invalid")
    silence_labels = _runtime_labels(silence.labels, "silence")
    if not silence.starts_at <= now < silence.ends_at:
        return False
    if silence.rule_id is not None and silence.rule_id != rule.rule_id:
        return False
    if silence.target is not None and silence.target != observation.target:
        return False
    labels = dict(rule.labels) | dict(observation.labels)
    return all(labels.get(key) == value for key, value in silence_labels)


def evaluate_rule_pack(
    pack: RulePack,
    observations: Mapping[str, Sequence[Observation]],
    previous_states: Mapping[str, Any],
    now: dt.datetime,
    silences: Sequence[Silence] = (),
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Evaluate a pack and emit only idempotent state transitions."""

    states: dict[str, dict[str, Any]] = {}
    pending_events: list[tuple[AlertRule, Observation, str, dict[str, Any]]] = []
    for rule in pack.rules:
        for observation in observations.get(rule.rule_id, ()):
            state_key = f"{rule.rule_id}:{observation.target}"
            state, transition = evaluate_observation(
                rule, observation, previous_states.get(state_key), now,
            )
            states[state_key] = state
            if transition in {"firing", "resolved"}:
                pending_events.append((rule, observation, transition, state))

    # A source failure or target disappearance must not silently erase an
    # unresolved incident. Carry only active prior targets that had no current
    # observation, mark their evidence as no-data, and require a later valid
    # recovery sample (or an explicit future retirement model) to resolve them.
    rules_by_id = {rule.rule_id: rule for rule in pack.rules}
    for state_key in sorted(previous_states):
        if state_key in states:
            continue
        rule_id, separator, target = state_key.partition(":")
        prior = _prior_state(previous_states.get(state_key))
        rule = rules_by_id.get(rule_id)
        if (
            separator != ":"
            or rule is None
            or TARGET_ID.fullmatch(target) is None
            or prior.get("phase") not in {"firing", "recovering"}
        ):
            continue
        current_statuses = {
            observation.status
            for observation in observations.get(rule_id, ())
        }
        # Runtime source failures are represented by non-target placeholder
        # observations (or by every retained target carrying the same status).
        # Preserve that evidence for a disappeared active target instead of
        # flattening permission/stale/collection failures into generic no-data.
        carry_status = (
            next(iter(current_statuses))
            if len(current_statuses) == 1 and "ok" not in current_statuses
            else "no_data"
        )
        synthetic = Observation(target, None, carry_status)
        state, _transition = evaluate_observation(rule, synthetic, prior, now)
        states[state_key] = state

    events: list[dict[str, Any]] = []
    for rule, observation, transition, state in pending_events:
        observation_labels = dict(_runtime_labels(observation.labels, "observation"))
        labels = dict(rule.labels) | observation_labels
        notification_state = "ready"
        parent_target = observation_labels.get("parent_target", observation.target)
        parent_key = f"{rule.parent_rule_id}:{parent_target}" if rule.parent_rule_id else None
        if parent_key and states.get(parent_key, {}).get("phase") in {"firing", "recovering"}:
            notification_state = "suppressed"
        elif any(_silenced(rule, observation, silence, now) for silence in silences):
            notification_state = "silenced"
        state_key = f"{rule.rule_id}:{observation.target}"
        prior_opened_at = _prior_state(previous_states.get(state_key)).get("openedAt")
        opened_at = (
            prior_opened_at
            if transition == "resolved" and prior_opened_at is not None
            else state.get("openedAt") or state.get("changedAt")
        )
        identity = f"{pack.version}\0{rule.rule_id}\0{observation.target}\0{opened_at}\0{transition}"
        events.append({
            "schemaVersion": 1,
            "rulePackVersion": pack.version,
            "idempotencyKey": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "ruleId": rule.rule_id,
            "target": observation.target,
            "transition": transition,
            "severity": rule.severity,
            "notificationState": notification_state,
            "observedAt": state["lastEvaluatedAt"],
            "openedAt": opened_at,
            "value": state["lastValue"],
            "status": state["observationStatus"],
            "labels": labels,
            "description": rule.description,
            "runbook": rule.runbook,
        })
    return states, events
