#!/usr/bin/env python3
"""Bounded, privacy-first normalization for heterogeneous log sources.

The collector owns source acquisition and crash-safe cursor publication.  This
module deliberately owns the step in between: it accepts already bounded lines,
redacts them before parsing, joins bounded multiline events, emits one exact
public schema, and applies persistent per-window admission limits.  It never
stores raw input and it never accepts arbitrary structured dimensions.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import math
import re
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
QUOTA_STATE_SCHEMA_VERSION = 2
REDACTION_VERSION = "monitor-log-redaction-v2"
SUPPORTED_SOURCE_KINDS = frozenset({"docker", "journald", "file"})
SUPPORTED_PARSERS = frozenset({"auto", "json", "logfmt", "syslog", "plain"})
SUPPORTED_MULTILINE = frozenset({"auto", "off"})
SUPPORTED_PRIORITIES = frozenset({"debug", "normal", "incident", "security"})
SUPPORTED_STREAMS = frozenset({"stdout", "stderr"})
PRIORITY_ORDER = {"security": 0, "incident": 1, "normal": 2, "debug": 3}

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}")
_SAFE_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_RAW_CONTAINER_ID = re.compile(r"[0-9a-f]{32,64}", re.IGNORECASE)
_SECRET_LABEL_PATTERN = (
    r"(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|"
    r"password|passwd|pwd|secret|token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|api[-_]?key|apikey|client[-_]?secret|session[-_]?(?:id)?|"
    r"private[-_]?key|access[-_]?key(?:[-_]?id)?)"
)
_SECRET_KEY = re.compile(_SECRET_LABEL_PATTERN, re.IGNORECASE)
_SECRET_LABELED_KEY_PATTERN = (
    rf"[A-Za-z0-9_.-]{{0,127}}{_SECRET_LABEL_PATTERN}[A-Za-z0-9_.-]{{0,127}}"
)
_JSON_SECRET = re.compile(
    rf'(?P<prefix>"{_SECRET_LABELED_KEY_PATTERN}"\s*:\s*)"(?:\\.|[^"\\])*"',
    re.IGNORECASE,
)
_KEY_VALUE_SECRET_PREFIX = re.compile(
    rf"(?P<prefix>(?<![A-Za-z0-9_.-]){_SECRET_LABELED_KEY_PATTERN}\s*[:=]\s*)",
    re.IGNORECASE,
)
_QUERY_SECRET = re.compile(
    rf"(?P<prefix>[?&]{_SECRET_LABELED_KEY_PATTERN}=)"
    r"[^&#\s]+",
    re.IGNORECASE,
)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|SECRET)[A-Z0-9 ]*-----.*?"
    r"-----END [A-Z0-9 ]*(?:PRIVATE KEY|SECRET)[A-Z0-9 ]*-----",
    re.DOTALL,
)
_PEM_BEGIN = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]{1,128})-----")
_PEM_END = re.compile(r"-----END (?P<label>[A-Z0-9 ]{1,128})-----")
_PEM_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_PEM_METADATA = re.compile(
    r"(?:Proc-Type|DEK-Info):[\x20-\x7e]{1,256}", re.IGNORECASE
)
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}")
_IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6 = re.compile(r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])")
_CARD = re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])")
_PHONE = re.compile(r"(?<![0-9])(?:\+82[- ]?|0)10[- ]?[0-9]{3,4}[- ]?[0-9]{4}(?![0-9])")
_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{16,})(?![A-Za-z0-9])"
)
_URL_USERINFO = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]{1,15}://)(?P<userinfo>[^/@\s]{1,256})@",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_ISO_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}))\s+(?P<body>.*)$",
    re.DOTALL,
)
_RFC3164_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+[ 0-9]\d\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?:(?P<host>[^\s]+)\s+)?(?P<body>.*)$"
)
_RFC5424_PREFIX = re.compile(
    r"^<(?P<priority>\d{1,3})>\d\s+(?P<timestamp>\S+)\s+\S+\s+\S+\s+"
    r"\S+\s+\S+\s+(?:-|\[[^\]]*\])\s*(?P<body>.*)$",
    re.DOTALL,
)
_CONTINUATION = re.compile(
    r"^(?:\s+|at\s+|Caused by:|Suppressed:|Traceback \(most recent call last\):|"
    r"During handling of the above exception|\.\.\. \d+ more)",
    re.IGNORECASE,
)
_LOGFMT_HINT = re.compile(r"(?:^|\s)[A-Za-z][A-Za-z0-9_.-]{0,63}=")

_LEVELS = {
    "trace": "trace",
    "debug": "debug",
    "info": "info",
    "notice": "notice",
    "warn": "warning",
    "warning": "warning",
    "err": "error",
    "error": "error",
    "crit": "critical",
    "critical": "critical",
    "alert": "critical",
    "emerg": "critical",
    "emergency": "critical",
    "fatal": "critical",
    "panic": "critical",
}

_PUBLIC_RECORD_FIELDS = (
    "schemaVersion", "timestamp", "observedAt", "timestampSource", "sourceKind",
    "sourceId", "priority", "severity", "parser", "message", "truncated",
    "multilineLineCount", "hostId", "containerName", "composeProject",
    "composeService", "processName", "systemdUnit", "stream", "fields",
    "redactionVersion",
)
_PUBLIC_SEVERITIES = frozenset({
    "trace", "debug", "info", "notice", "warning", "error", "critical"
})


def _validate_identifier(value: str, field_name: str, *, allow_raw_hex: bool = False) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{field_name} is not a bounded safe identifier")
    if not allow_raw_hex and _RAW_CONTAINER_ID.fullmatch(value) is not None:
        raise ValueError(f"{field_name} must not be a raw container identifier")
    if _SECRET_KEY.search(value):
        raise ValueError(f"{field_name} must not contain a credential label")
    return value


def _validate_optional_identifier(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _validate_identifier(value, field_name)


@dataclass(frozen=True)
class LogSource:
    """Reviewed, fixed-cardinality metadata for one configured source."""

    source_id: str
    kind: str
    priority: str = "normal"
    parser: str = "auto"
    multiline: str = "auto"
    host_id: str | None = None
    container_name: str | None = None
    compose_project: str | None = None
    compose_service: str | None = None
    process_name: str | None = None
    systemd_unit: str | None = None
    stream: str | None = None
    field_allowlist: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_identifier(self.source_id, "source_id")
        if self.kind not in SUPPORTED_SOURCE_KINDS:
            raise ValueError("unsupported log source kind")
        if self.priority not in SUPPORTED_PRIORITIES:
            raise ValueError("unsupported log priority")
        if self.parser not in SUPPORTED_PARSERS:
            raise ValueError("unsupported log parser")
        if self.multiline not in SUPPORTED_MULTILINE:
            raise ValueError("unsupported multiline mode")
        if self.stream is not None and self.stream not in SUPPORTED_STREAMS:
            raise ValueError("unsupported stream")
        if self.host_id is not None:
            try:
                parsed = uuid.UUID(self.host_id)
            except (ValueError, AttributeError) as exc:
                raise ValueError("host_id must be a UUID") from exc
            if str(parsed) != self.host_id.lower():
                raise ValueError("host_id must be canonical")
        for name, value in (
            ("container_name", self.container_name),
            ("compose_project", self.compose_project),
            ("compose_service", self.compose_service),
            ("process_name", self.process_name),
            ("systemd_unit", self.systemd_unit),
        ):
            _validate_optional_identifier(value, name)
        if len(self.field_allowlist) > 16 or len(set(self.field_allowlist)) != len(self.field_allowlist):
            raise ValueError("field_allowlist must contain at most 16 unique fields")
        for key in self.field_allowlist:
            if not isinstance(key, str) or _SAFE_FIELD.fullmatch(key) is None:
                raise ValueError("structured field name is invalid")
            if _SECRET_KEY.search(key):
                raise ValueError("credential fields cannot be allowlisted")


@dataclass(frozen=True)
class SourceBatch:
    source: LogSource
    lines: Sequence[str | bytes]

    def __post_init__(self) -> None:
        if isinstance(self.lines, (str, bytes, bytearray)) or not isinstance(self.lines, Sequence):
            raise ValueError("lines must be a bounded sequence")


@dataclass(frozen=True)
class PipelineLimits:
    max_sources: int = 64
    max_input_lines_per_source: int = 10_000
    max_input_bytes_per_source: int = 2 * 1024 * 1024
    max_input_bytes_global: int = 16 * 1024 * 1024
    max_line_bytes: int = 128 * 1024
    max_multiline_lines: int = 64
    max_event_bytes: int = 16 * 1024
    max_events_per_source_per_window: int = 2_000
    max_events_global_per_window: int = 10_000
    max_events_per_run: int = 2_000
    max_record_bytes_per_run: int = 16 * 1024 * 1024
    window_seconds: int = 60
    max_past_seconds: int = 31 * 24 * 60 * 60
    max_future_seconds: int = 5 * 60

    def __post_init__(self) -> None:
        ranges = {
            "max_sources": (self.max_sources, 1, 256),
            "max_input_lines_per_source": (self.max_input_lines_per_source, 1, 100_000),
            "max_input_bytes_per_source": (self.max_input_bytes_per_source, 1_024, 32 * 1024 * 1024),
            "max_input_bytes_global": (self.max_input_bytes_global, 1024 * 1024, 32 * 1024 * 1024),
            "max_line_bytes": (self.max_line_bytes, 64, 1024 * 1024),
            "max_multiline_lines": (self.max_multiline_lines, 1, 1_024),
            "max_event_bytes": (self.max_event_bytes, 256, 1024 * 1024),
            "max_events_per_source_per_window": (self.max_events_per_source_per_window, 1, 100_000),
            "max_events_global_per_window": (self.max_events_global_per_window, 1, 1_000_000),
            "max_events_per_run": (self.max_events_per_run, 1, 10_000),
            "max_record_bytes_per_run": (self.max_record_bytes_per_run, 1024 * 1024, 32 * 1024 * 1024),
            "window_seconds": (self.window_seconds, 1, 3_600),
            "max_past_seconds": (self.max_past_seconds, 0, 366 * 24 * 60 * 60),
            "max_future_seconds": (self.max_future_seconds, 0, 24 * 60 * 60),
        }
        for name, (value, minimum, maximum) in ranges.items():
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} is outside its supported range")
        if self.max_line_bytes > self.max_input_bytes_per_source:
            raise ValueError("max_line_bytes cannot exceed the per-source input budget")
        if self.max_input_bytes_global < self.max_sources * 1024:
            raise ValueError("global input budget must reserve at least 1 KiB per source")
        if self.max_event_bytes > self.max_input_bytes_per_source:
            raise ValueError("max_event_bytes cannot exceed the per-source input budget")
        if self.max_events_per_source_per_window > self.max_events_global_per_window:
            raise ValueError("per-source quota cannot exceed the global quota")


def input_budget_per_source(source_count: int, limits: PipelineLimits) -> int:
    """Return a fixed fair share that keeps one run below the aggregate cap."""

    if (
        isinstance(source_count, bool)
        or not isinstance(source_count, int)
        or not 0 <= source_count <= limits.max_sources
    ):
        raise ValueError("source_count is outside the configured limit")
    if source_count == 0:
        return 0
    budget = min(
        limits.max_input_bytes_per_source,
        limits.max_input_bytes_global // source_count,
    )
    if budget < 1024:  # Defended by PipelineLimits, retained as a local invariant.
        raise ValueError("aggregate input budget cannot give every source a safe share")
    return budget


def _utc(value: dt.datetime) -> dt.datetime:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware")
    return value.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return _utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _truncate_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return value, False
    suffix = "…"
    budget = max(0, maximum_bytes - len(suffix.encode()))
    return encoded[:budget].decode("utf-8", errors="ignore") + suffix, True


def _valid_ipv4(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        valid = all(0 <= int(part) <= 255 for part in raw.split("."))
    except ValueError:
        valid = False
    return "[REDACTED_IP]" if valid else raw


def _valid_ipv6(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        ipaddress.IPv6Address(raw)
    except ipaddress.AddressValueError:
        return raw
    return "[REDACTED_IP]"


def _luhn_candidate(match: re.Match[str]) -> str:
    raw = match.group(0)
    digits = [int(value) for value in raw if value.isdigit()]
    if not 13 <= len(digits) <= 19:
        return raw
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return "[REDACTED_CARD]" if total % 10 == 0 else raw


def _containing_line_quote(value: str, position: int) -> str | None:
    """Return an open quote containing position within its physical line."""

    line_start = value.rfind("\n", 0, position) + 1
    quote: str | None = None
    escaped = False
    for character in value[line_start:position]:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is None and character in {'"', "'"}:
            quote = character
        elif quote == character:
            quote = None
    return quote


def _closing_quote(value: str, start: int, end: int, quote: str) -> int:
    escaped = False
    for index in range(start, end):
        character = value[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == quote:
            return index
    return end


def _redact_key_value_secrets(value: str) -> str:
    """Redact a secret value without letting malformed quoting create a tail leak.

    Outside an already-open quoted log field, the remainder of that physical
    line is discarded. Within a JSON/log message string, content is discarded
    only up to the containing quote so the surrounding structure remains
    parseable. This deliberately prefers lost diagnostic context to a leaked
    credential when an input is ambiguous or malformed.
    """

    parts: list[str] = []
    cursor = 0
    while True:
        match = _KEY_VALUE_SECRET_PREFIX.search(value, cursor)
        if match is None:
            parts.append(value[cursor:])
            break
        parts.append(value[cursor:match.end()])
        parts.append("[REDACTED]")
        line_end = value.find("\n", match.end())
        if line_end < 0:
            line_end = len(value)
        quote = _containing_line_quote(value, match.start())
        cursor = (
            _closing_quote(value, match.end(), line_end, quote)
            if quote is not None
            else line_end
        )
    return "".join(parts)


def _sensitive_pem_label(value: str) -> bool:
    return (
        1 <= len(value) <= 128
        and all(character == " " or character.isdigit() or "A" <= character <= "Z" for character in value)
        and ("PRIVATE KEY" in value or "SECRET" in value)
    )


def _redact_pem_boundaries(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return "[REDACTED_PRIVATE_KEY]" if _sensitive_pem_label(match.group("label")) else match.group(0)

    return _PEM_END.sub(replace, _PEM_BEGIN.sub(replace, value))


def redact_text(value: str, maximum_bytes: int = 64 * 1024) -> str:
    """Redact credentials and common personal identifiers before parsing."""

    bounded, _ = _truncate_utf8(str(value), maximum_bytes)
    bounded = _CONTROL.sub("�", bounded)
    bounded = _PEM.sub("[REDACTED_PRIVATE_KEY]", bounded)
    bounded = _redact_pem_boundaries(bounded)
    bounded = _JSON_SECRET.sub(lambda match: f'{match.group("prefix")}"[REDACTED]"', bounded)
    bounded = _redact_key_value_secrets(bounded)
    bounded = _QUERY_SECRET.sub(lambda match: f'{match.group("prefix")}[REDACTED]', bounded)
    bounded = _JWT.sub("[REDACTED_JWT]", bounded)
    bounded = _KNOWN_TOKEN.sub("[REDACTED_TOKEN]", bounded)
    bounded = _URL_USERINFO.sub(lambda match: f'{match.group("scheme")}[REDACTED]@', bounded)
    bounded = _EMAIL.sub("[REDACTED_EMAIL]", bounded)
    bounded = _IPV6.sub(_valid_ipv6, bounded)
    bounded = _IPV4.sub(_valid_ipv4, bounded)
    bounded = _CARD.sub(_luhn_candidate, bounded)
    bounded = _PHONE.sub("[REDACTED_PHONE]", bounded)
    return bounded


def _safe_scalar(value: Any, maximum_bytes: int = 1024) -> str | int | float | bool | None:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _truncate_utf8(redact_text(value, maximum_bytes), maximum_bytes)[0]
    return None


def normalize_record(value: Any, maximum_bytes: int = 1024 * 1024) -> dict[str, Any] | None:
    """Return the canonical public log record or reject the whole value."""

    if (
        not isinstance(value, Mapping)
        or tuple(value.keys()) != _PUBLIC_RECORD_FIELDS
        or value.get("schemaVersion") != SCHEMA_VERSION
        or value.get("timestampSource") not in {"event", "observed"}
        or value.get("sourceKind") not in SUPPORTED_SOURCE_KINDS
        or value.get("priority") not in SUPPORTED_PRIORITIES
        or value.get("severity") not in _PUBLIC_SEVERITIES
        or value.get("parser") not in {"json", "logfmt", "syslog", "plain"}
        or not isinstance(value.get("message"), str)
        or not isinstance(value.get("truncated"), bool)
        or isinstance(value.get("multilineLineCount"), bool)
        or not isinstance(value.get("multilineLineCount"), int)
        or not 1 <= value["multilineLineCount"] <= 1_024
        or value.get("redactionVersion") != REDACTION_VERSION
    ):
        return None
    timestamp = value.get("timestamp")
    observed_at = value.get("observedAt")
    parsed_timestamp = _parse_iso(timestamp) if isinstance(timestamp, str) else None
    parsed_observed = _parse_iso(observed_at) if isinstance(observed_at, str) else None
    if (
        parsed_timestamp is None or parsed_observed is None
        or _iso(parsed_timestamp) != timestamp or _iso(parsed_observed) != observed_at
    ):
        return None
    try:
        _validate_identifier(value["sourceId"], "sourceId")
        if value.get("hostId") is not None:
            parsed_host = uuid.UUID(value["hostId"])
            if str(parsed_host) != value["hostId"].lower():
                return None
        for key in (
            "containerName", "composeProject", "composeService", "processName", "systemdUnit"
        ):
            _validate_optional_identifier(value.get(key), key)
    except (ValueError, TypeError, AttributeError):
        return None
    if value.get("stream") is not None and value.get("stream") not in SUPPORTED_STREAMS:
        return None
    message = value["message"]
    if redact_text(message, maximum_bytes) != message:
        return None
    raw_fields = value.get("fields")
    if not isinstance(raw_fields, Mapping) or len(raw_fields) > 16:
        return None
    fields: dict[str, Any] = {}
    for key, raw in raw_fields.items():
        if (
            not isinstance(key, str) or _SAFE_FIELD.fullmatch(key) is None
            or _SECRET_KEY.search(key)
        ):
            return None
        scalar = _safe_scalar(raw)
        if scalar != raw:
            return None
        fields[key] = scalar
    normalized = {key: value[key] for key in _PUBLIC_RECORD_FIELDS}
    normalized["fields"] = fields
    try:
        encoded = json.dumps(
            normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError):
        return None
    return normalized if len(encoded) <= maximum_bytes else None


def _severity(value: Any, fallback: str = "info") -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = int(value)
        return {
            0: "critical", 1: "critical", 2: "critical", 3: "error",
            4: "warning", 5: "notice", 6: "info", 7: "debug",
        }.get(number, fallback)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.isdigit():
            return _severity(int(normalized), fallback)
        return _LEVELS.get(normalized, fallback)
    return fallback


def _parse_iso(value: str) -> dt.datetime | None:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _timestamp(value: Any, observed: dt.datetime, limits: PipelineLimits) -> tuple[str, str, bool]:
    parsed: dt.datetime | None = None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        seconds = float(value) / 1000 if abs(float(value)) > 10_000_000_000 else float(value)
        try:
            parsed = dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            parsed = None
    elif isinstance(value, str):
        parsed = _parse_iso(value)
    if parsed is None:
        return _iso(observed), "observed", value is not None
    delta = (parsed - observed).total_seconds()
    if delta > limits.max_future_seconds or delta < -limits.max_past_seconds:
        return _iso(observed), "observed", True
    return _iso(parsed), "event", False


def _parse_logfmt(value: str) -> dict[str, str]:
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        return {}
    if len(tokens) > 64:
        return {}
    parsed: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, raw = token.split("=", 1)
        if _SAFE_FIELD.fullmatch(key) is None or len(raw.encode("utf-8")) > 4096:
            continue
        parsed[key] = raw
    return parsed


def _extract_allowed_fields(payload: Mapping[str, Any], source: LogSource) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in source.field_allowlist:
        current: Any = payload
        for component in key.split("."):
            if not isinstance(current, Mapping) or component not in current:
                current = None
                break
            current = current[component]
        scalar = _safe_scalar(current)
        if scalar is not None:
            output[key] = scalar
    return output


def _pem_recovery_state() -> dict[str, Any]:
    """Return a raw-free state used when an older cursor may be inside a PEM block."""

    return {"label": None, "lineCount": 0, "byteCount": 0, "overflow": True}


def _pem_state(label: str, line_bytes: int, limits: PipelineLimits) -> dict[str, Any]:
    return {
        "label": label,
        "lineCount": 1,
        "byteCount": min(line_bytes, limits.max_event_bytes),
        "overflow": line_bytes > limits.max_event_bytes,
    }


def _advance_pem_state(
    state: Mapping[str, Any], line_bytes: int, limits: PipelineLimits
) -> dict[str, Any]:
    line_count = int(state["lineCount"])
    byte_count = int(state["byteCount"])
    overflow = bool(state["overflow"])
    if not overflow and (
        line_count >= limits.max_multiline_lines
        or byte_count + 1 + line_bytes > limits.max_event_bytes
    ):
        overflow = True
    return {
        "label": state["label"],
        "lineCount": min(limits.max_multiline_lines, line_count + 1),
        "byteCount": min(limits.max_event_bytes, byte_count + 1 + line_bytes),
        "overflow": overflow,
    }


def _pem_boundaries(value: str) -> list[tuple[int, str, str]]:
    boundaries: list[tuple[int, str, str]] = []
    for kind, pattern in (("begin", _PEM_BEGIN), ("end", _PEM_END)):
        for match in pattern.finditer(value):
            label = match.group("label")
            if _sensitive_pem_label(label):
                boundaries.append((match.start(), kind, label))
    return sorted(boundaries)


def _pem_payload_candidates(value: str) -> list[str]:
    stripped = value.strip()
    candidates = [stripped]
    if stripped.startswith("{"):
        try:
            decoded = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeError):
            decoded = None
        if isinstance(decoded, Mapping):
            candidates.extend(
                candidate.strip()
                for key in ("message", "msg", "log")
                if isinstance((candidate := decoded.get(key)), str)
            )
    if _LOGFMT_HINT.search(stripped):
        decoded_logfmt = _parse_logfmt(stripped)
        candidates.extend(
            candidate.strip()
            for key in ("message", "msg", "log")
            if isinstance((candidate := decoded_logfmt.get(key)), str)
        )
    for pattern in (_RFC5424_PREFIX, _ISO_PREFIX, _RFC3164_PREFIX):
        match = pattern.match(stripped)
        if match is not None:
            body = match.groupdict().get("body")
            if isinstance(body, str):
                candidates.append(body.strip())
            break
    return candidates


def _looks_like_pem_payload(value: str) -> bool:
    """Conservatively identify continuation data only after PEM recovery overflow."""

    for candidate in _pem_payload_candidates(value):
        if candidate == "" or _PEM_METADATA.fullmatch(candidate) is not None:
            return True
        if (
            len(candidate) >= 4
            and len(candidate) % 4 == 0
            and _PEM_BASE64.fullmatch(candidate) is not None
        ):
            return True
    return False


def _filter_pem_line(
    value: str,
    prior_state: Mapping[str, Any] | None,
    limits: PipelineLimits,
    *,
    persistable: bool,
) -> tuple[str | None, dict[str, Any] | None]:
    """Remove one physical sensitive-PEM line and advance only bounded state."""

    line_bytes = len(value.encode("utf-8", errors="replace"))
    state = _advance_pem_state(prior_state, line_bytes, limits) if prior_state else None
    boundaries = _pem_boundaries(value)
    ambiguous = False
    for _position, kind, label in boundaries:
        if kind == "begin":
            if state is not None:
                ambiguous = True
            else:
                state = _pem_state(label, line_bytes, limits)
        elif state is not None:
            active_label = state.get("label")
            if active_label is None or active_label == label:
                state = None
            else:
                ambiguous = True
    if ambiguous:
        state = _pem_recovery_state()
    if boundaries:
        # A delimiter-bearing physical line is never partially retained, even if
        # ordinary text appears before or after the armor marker.
        return ("[REDACTED_PRIVATE_KEY]" if prior_state is None and persistable else None), state
    if prior_state is None:
        return (value if persistable else None), None
    assert state is not None
    if not state["overflow"] or _looks_like_pem_payload(value) or not persistable:
        return None, state
    # An unterminated/oversized block cannot suppress a source forever. Once its
    # bounded state overflows, the first ordinary non-PEM-looking line recovers.
    return value, None


def _looks_like_new_event(value: str) -> bool:
    stripped = value.lstrip()
    return bool(
        stripped.startswith("{")
        or _ISO_PREFIX.match(stripped)
        or _RFC3164_PREFIX.match(stripped)
        or _RFC5424_PREFIX.match(stripped)
        or _LOGFMT_HINT.search(stripped)
    )


def _multiline_events(
    lines: Sequence[str], source: LogSource, limits: PipelineLimits
) -> tuple[list[tuple[str, int, bool]], dict[str, int]]:
    events: list[tuple[str, int, bool]] = []
    counters = {"multilineLines": 0, "oversizedEvents": 0}
    current: list[str] = []
    current_bytes = 0
    current_lines = 0
    truncated = False

    def flush() -> None:
        nonlocal current, current_bytes, current_lines, truncated
        if current:
            events.append(("\n".join(current), current_lines, truncated))
        current = []
        current_bytes = 0
        current_lines = 0
        truncated = False

    for line in lines:
        is_continuation = source.multiline == "auto" and bool(current) and (
            _CONTINUATION.match(line) is not None and not _looks_like_new_event(line)
        )
        if current and not is_continuation:
            flush()
        if not current:
            current = []
            current_bytes = 0
            current_lines = 0
            truncated = False
        current_lines += 1
        separator = 1 if current else 0
        encoded_size = len(line.encode("utf-8", errors="replace"))
        if current_lines > limits.max_multiline_lines:
            counters["multilineLines"] += 1
            truncated = True
            continue
        if current_bytes + separator + encoded_size > limits.max_event_bytes:
            remaining = max(0, limits.max_event_bytes - current_bytes - separator)
            if remaining and not truncated:
                clipped, _ = _truncate_utf8(line, remaining)
                if clipped:
                    current.append(clipped)
                    current_bytes += separator + len(clipped.encode("utf-8"))
            counters["oversizedEvents"] += 1
            truncated = True
            continue
        current.append(line)
        current_bytes += separator + encoded_size
    flush()
    return events, counters


def _parse_event(
    raw_value: str,
    line_count: int,
    multiline_truncated: bool,
    source: LogSource,
    observed: dt.datetime,
    limits: PipelineLimits,
) -> tuple[dict[str, Any], bool]:
    # This is intentionally the first transformation applied to event content.
    value = redact_text(raw_value, limits.max_event_bytes)
    parser = source.parser
    payload: Mapping[str, Any] = {}
    timestamp_value: Any = None
    severity_value: Any = None
    message: Any = None

    if parser in {"auto", "json"} and value.lstrip().startswith("{"):
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, UnicodeError):
            decoded = None
        if isinstance(decoded, Mapping) and len(decoded) <= 128:
            parser = "json"
            payload = decoded
            timestamp_value = next(
                (decoded.get(key) for key in ("timestamp", "@timestamp", "time", "ts") if key in decoded),
                None,
            )
            severity_value = next(
                (decoded.get(key) for key in ("severity", "level", "log.level") if key in decoded),
                None,
            )
            message = next(
                (decoded.get(key) for key in ("message", "msg", "log") if key in decoded),
                "[structured log]",
            )
        elif source.parser == "json":
            parser = "plain"

    if parser in {"auto", "logfmt"} and not payload and _LOGFMT_HINT.search(value):
        decoded_logfmt = _parse_logfmt(value)
        if decoded_logfmt:
            parser = "logfmt"
            payload = decoded_logfmt
            timestamp_value = next(
                (decoded_logfmt.get(key) for key in ("timestamp", "time", "ts") if key in decoded_logfmt),
                None,
            )
            severity_value = next(
                (decoded_logfmt.get(key) for key in ("severity", "level") if key in decoded_logfmt),
                None,
            )
            message = decoded_logfmt.get("message", decoded_logfmt.get("msg", "[structured log]"))
        elif source.parser == "logfmt":
            parser = "plain"

    if parser in {"auto", "syslog"} and not payload:
        match = _RFC5424_PREFIX.match(value) or _ISO_PREFIX.match(value) or _RFC3164_PREFIX.match(value)
        if match is not None:
            parser = "syslog"
            groups = match.groupdict()
            timestamp_value = groups.get("timestamp")
            severity_value = groups.get("priority")
            message = groups.get("body", value)
            if _RFC3164_PREFIX.match(value) is not None and isinstance(timestamp_value, str):
                try:
                    partial = dt.datetime.strptime(timestamp_value, "%b %d %H:%M:%S")
                    parsed = partial.replace(year=observed.year, tzinfo=dt.timezone.utc)
                    if parsed - observed > dt.timedelta(days=2):
                        parsed = parsed.replace(year=observed.year - 1)
                    timestamp_value = _iso(parsed)
                except ValueError:
                    timestamp_value = None
        elif source.parser == "syslog":
            parser = "plain"

    if parser == "auto":
        parser = "plain"
    if message is None:
        message = value
    if not isinstance(message, str):
        message = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    message, message_truncated = _truncate_utf8(
        redact_text(message, limits.max_event_bytes), limits.max_event_bytes
    )
    event_timestamp, timestamp_source, timestamp_invalid = _timestamp(
        timestamp_value, observed, limits
    )
    record = {
        "schemaVersion": SCHEMA_VERSION,
        "timestamp": event_timestamp,
        "observedAt": _iso(observed),
        "timestampSource": timestamp_source,
        "sourceKind": source.kind,
        "sourceId": source.source_id,
        "priority": source.priority,
        "severity": _severity(severity_value),
        "parser": parser,
        "message": message,
        "truncated": bool(multiline_truncated or message_truncated),
        "multilineLineCount": line_count,
        "hostId": source.host_id,
        "containerName": source.container_name,
        "composeProject": source.compose_project,
        "composeService": source.compose_service,
        "processName": source.process_name,
        "systemdUnit": source.systemd_unit,
        "stream": source.stream,
        "fields": _extract_allowed_fields(payload, source),
        "redactionVersion": REDACTION_VERSION,
    }
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > limits.max_event_bytes + 4096:
        record["message"], _ = _truncate_utf8(record["message"], max(256, limits.max_event_bytes // 2))
        record["truncated"] = True
    normalized = normalize_record(record)
    if normalized is None:
        raise ValueError("normalized log record failed its public contract")
    return normalized, timestamp_invalid


def _empty_drops() -> dict[str, int]:
    return {
        "inputLineLimit": 0,
        "inputByteLimit": 0,
        "oversizedLine": 0,
        "multilineLineLimit": 0,
        "oversizedEvent": 0,
        "sourceQuota": 0,
        "globalQuota": 0,
    }


def _normalize_prior_state(
    value: Mapping[str, Any] | None, window_start: int, limits: PipelineLimits
) -> tuple[int, dict[str, int], int, dict[str, dict[str, Any]], bool]:
    if value is None:
        return window_start, {}, 0, {}, False
    legacy_fields = {
        "schemaVersion", "windowStartedAt", "admittedGlobal", "admittedBySource"
    }
    current_fields = legacy_fields | {
        "redactionVersion", "pemRecoveryRequired", "pemSuppressionBySource"
    }
    if not isinstance(value, Mapping) or set(value) not in (legacy_fields, current_fields):
        raise ValueError("log quota state failed schema validation")
    legacy = set(value) == legacy_fields and value.get("schemaVersion") == SCHEMA_VERSION
    if not legacy and (
        value.get("schemaVersion") != QUOTA_STATE_SCHEMA_VERSION
        or value.get("redactionVersion") != REDACTION_VERSION
    ):
        raise ValueError("unsupported log quota state version")
    prior_start = value.get("windowStartedAt")
    admitted_global = value.get("admittedGlobal")
    raw_sources = value.get("admittedBySource")
    if (
        isinstance(prior_start, bool) or not isinstance(prior_start, int)
        or isinstance(admitted_global, bool) or not isinstance(admitted_global, int)
        or admitted_global < 0 or admitted_global > limits.max_events_global_per_window
        or not isinstance(raw_sources, Mapping) or len(raw_sources) > limits.max_sources
    ):
        raise ValueError("log quota state contains invalid counters")
    sources: dict[str, int] = {}
    for source_id, count in raw_sources.items():
        _validate_identifier(source_id, "state source_id")
        if (
            isinstance(count, bool) or not isinstance(count, int)
            or count < 0 or count > limits.max_events_per_source_per_window
        ):
            raise ValueError("log quota state contains invalid source counter")
        sources[source_id] = count
    pem_states: dict[str, dict[str, Any]] = {}
    recovery_required = legacy
    if not legacy:
        recovery_required = value.get("pemRecoveryRequired")
        raw_pem_states = value.get("pemSuppressionBySource")
        if (
            not isinstance(recovery_required, bool)
            or not isinstance(raw_pem_states, Mapping)
            or len(raw_pem_states) > limits.max_sources
        ):
            raise ValueError("log PEM suppression state is invalid")
        for source_id, raw_state in raw_pem_states.items():
            _validate_identifier(source_id, "PEM state source_id")
            if not isinstance(raw_state, Mapping) or set(raw_state) != {
                "label", "lineCount", "byteCount", "overflow"
            }:
                raise ValueError("log PEM suppression state is invalid")
            label = raw_state.get("label")
            line_count = raw_state.get("lineCount")
            byte_count = raw_state.get("byteCount")
            overflow = raw_state.get("overflow")
            if (
                label is not None and (
                    not isinstance(label, str) or not _sensitive_pem_label(label)
                )
                or isinstance(line_count, bool) or not isinstance(line_count, int)
                or not 0 <= line_count <= limits.max_multiline_lines
                or isinstance(byte_count, bool) or not isinstance(byte_count, int)
                or not 0 <= byte_count <= limits.max_event_bytes
                or not isinstance(overflow, bool)
                or label is None and not overflow
            ):
                raise ValueError("log PEM suppression state is invalid")
            pem_states[source_id] = {
                "label": label,
                "lineCount": line_count,
                "byteCount": byte_count,
                "overflow": overflow,
            }
    if prior_start != window_start:
        return window_start, {}, 0, pem_states, recovery_required
    if sum(sources.values()) != admitted_global:
        raise ValueError("log quota state counters are inconsistent")
    return prior_start, sources, admitted_global, pem_states, recovery_required


def normalize_quota_state(
    value: Mapping[str, Any], limits: PipelineLimits | None = None
) -> dict[str, Any] | None:
    """Validate quota state without advancing or resetting its time window."""

    active_limits = limits or PipelineLimits()
    if not isinstance(value, Mapping):
        return None
    window_start = value.get("windowStartedAt")
    if isinstance(window_start, bool) or not isinstance(window_start, int) or window_start < 0:
        return None
    try:
        normalized_start, sources, admitted, pem_states, recovery_required = _normalize_prior_state(
            value, window_start, active_limits
        )
    except ValueError:
        return None
    if normalized_start % active_limits.window_seconds:
        return None
    return {
        "schemaVersion": QUOTA_STATE_SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "windowStartedAt": normalized_start,
        "admittedGlobal": admitted,
        "admittedBySource": dict(sorted(sources.items())),
        "pemRecoveryRequired": recovery_required,
        "pemSuppressionBySource": {
            source_id: pem_states[source_id] for source_id in sorted(pem_states)
        },
    }


def process_batches(
    batches: Sequence[SourceBatch],
    observed_at: dt.datetime,
    *,
    limits: PipelineLimits | None = None,
    prior_state: Mapping[str, Any] | None = None,
    pem_recovery_sources: Sequence[str] = (),
) -> dict[str, Any]:
    """Normalize and admit one bounded batch without retaining raw input."""

    if isinstance(batches, (str, bytes, bytearray)) or not isinstance(batches, Sequence):
        raise ValueError("batches must be a sequence")
    active_limits = limits or PipelineLimits()
    if len(batches) > active_limits.max_sources:
        raise ValueError("too many configured log sources")
    source_ids = [batch.source.source_id for batch in batches]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("duplicate source_id in one collection batch")
    if (
        isinstance(pem_recovery_sources, (str, bytes, bytearray))
        or not isinstance(pem_recovery_sources, Sequence)
        or len(pem_recovery_sources) > active_limits.max_sources
        or not all(isinstance(source_id, str) for source_id in pem_recovery_sources)
        or len(set(pem_recovery_sources)) != len(pem_recovery_sources)
        or any(source_id not in source_ids for source_id in pem_recovery_sources)
    ):
        raise ValueError("PEM recovery sources must be unique configured source IDs")
    observed = _utc(observed_at)
    epoch = int(observed.timestamp())
    window_start = epoch - (epoch % active_limits.window_seconds)
    _, admitted_by_source, admitted_global, pem_states, recovery_required = _normalize_prior_state(
        prior_state, window_start, active_limits
    )
    configured_source_ids = set(source_ids)
    pem_states = {
        source_id: state for source_id, state in pem_states.items()
        if source_id in configured_source_ids
    }
    if recovery_required:
        for source_id in source_ids:
            pem_states.setdefault(source_id, _pem_recovery_state())
    for source_id in pem_recovery_sources:
        pem_states[source_id] = _pem_recovery_state()

    source_stats: dict[str, dict[str, Any]] = {}
    admitted: list[tuple[tuple[int, int], dict[str, Any]]] = []
    admitted_this_run = 0
    admitted_record_bytes = 0
    record_budget_exhausted = False
    input_budget = input_budget_per_source(len(batches), active_limits)
    indexed_batches = list(enumerate(batches))
    # Admit while each source is normalized. Priority-sorting sources first
    # preserves the shared-quota policy without retaining every candidate.
    # Final rows are restored to configured source/event order below.
    prioritized_batches = sorted(
        indexed_batches,
        key=lambda item: (PRIORITY_ORDER[item[1].source.priority], item[0]),
    )
    for batch_index, batch in prioritized_batches:
        source = batch.source
        drops = _empty_drops()
        accepted_lines: list[str] = []
        pem_state = pem_states.get(source.source_id)
        consumed_bytes = 0
        seen_lines = 0
        total_lines = len(batch.lines)
        for index, raw_line in enumerate(batch.lines):
            if seen_lines >= active_limits.max_input_lines_per_source:
                drops["inputLineLimit"] += total_lines - index
                break
            if not isinstance(raw_line, (str, bytes)):
                drops["oversizedLine"] += 1
                continue
            encoded = raw_line.encode("utf-8", errors="replace") if isinstance(raw_line, str) else bytes(raw_line)
            if consumed_bytes + len(encoded) > input_budget:
                drops["inputByteLimit"] += total_lines - index
                break
            consumed_bytes += len(encoded)
            seen_lines += 1
            decoded_line = encoded.decode("utf-8", errors="replace").rstrip("\r\n")
            persistable = len(encoded) <= active_limits.max_line_bytes
            filtered_line, pem_state = _filter_pem_line(
                decoded_line, pem_state, active_limits, persistable=persistable
            )
            if not persistable:
                drops["oversizedLine"] += 1
                continue
            if filtered_line is not None:
                accepted_lines.append(filtered_line)
        if pem_state is None:
            pem_states.pop(source.source_id, None)
        else:
            pem_states[source.source_id] = pem_state
        grouped, multiline_drops = _multiline_events(accepted_lines, source, active_limits)
        drops["multilineLineLimit"] += multiline_drops["multilineLines"]
        drops["oversizedEvent"] += multiline_drops["oversizedEvents"]
        parser_counts = {name: 0 for name in ("json", "logfmt", "syslog", "plain")}
        invalid_timestamps = 0
        admitted_for_source = 0
        for event_index, (raw_event, line_count, truncated) in enumerate(grouped):
            record, invalid_timestamp = _parse_event(
                raw_event, line_count, truncated, source, observed, active_limits
            )
            parser_counts[record["parser"]] += 1
            invalid_timestamps += int(invalid_timestamp)
            source_count = admitted_by_source.get(source.source_id, 0)
            if source_count >= active_limits.max_events_per_source_per_window:
                drops["sourceQuota"] += 1
                continue
            if (
                admitted_global >= active_limits.max_events_global_per_window
                or admitted_this_run >= active_limits.max_events_per_run
                or record_budget_exhausted
            ):
                drops["globalQuota"] += 1
                continue
            record_bytes = len(json.dumps(
                record, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode()) + 1
            if admitted_record_bytes + record_bytes > active_limits.max_record_bytes_per_run:
                record_budget_exhausted = True
                drops["globalQuota"] += 1
                continue
            admitted_by_source[source.source_id] = source_count + 1
            admitted_global += 1
            admitted_this_run += 1
            admitted_record_bytes += record_bytes
            admitted_for_source += 1
            admitted.append(((batch_index, event_index), record))
        source_stats[source.source_id] = {
            "sourceId": source.source_id,
            "status": "fresh" if accepted_lines else "no_data",
            "seenLines": seen_lines,
            "seenBytes": consumed_bytes,
            "parsedEvents": len(grouped),
            "admittedEvents": admitted_for_source,
            "invalidTimestamps": invalid_timestamps,
            "parserCounts": parser_counts,
            "dropped": drops,
        }

    records = [record for _order, record in sorted(admitted, key=lambda item: item[0])]
    ordered_stats = [source_stats[source_id] for source_id in source_ids]
    dropped_total = sum(
        sum(int(count) for count in item["dropped"].values()) for item in ordered_stats
    )
    state = {
        "schemaVersion": QUOTA_STATE_SCHEMA_VERSION,
        "redactionVersion": REDACTION_VERSION,
        "windowStartedAt": window_start,
        "admittedGlobal": admitted_global,
        "admittedBySource": dict(sorted(admitted_by_source.items())),
        "pemRecoveryRequired": False,
        "pemSuppressionBySource": {
            source_id: pem_states[source_id] for source_id in sorted(pem_states)
        },
    }
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "observedAt": _iso(observed),
        "redactionVersion": REDACTION_VERSION,
        "records": records,
        "sources": ordered_stats,
        "admittedTotal": len(records),
        "droppedTotal": dropped_total,
        "quotaState": state,
    }
    # Public/state output must always be strict JSON without non-finite values.
    json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return result
