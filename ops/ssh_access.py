"""Bounded OpenSSH access metadata, extracted before generic-log redaction.

Only reviewed SSH journal batches are accepted. No username, journal cursor,
fingerprint, or raw message reaches this separate export. Rows are observations,
not sessions: a denied login and its preauth close remain distinct event types.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__:
    from .log_store import LogStoreError, _atomic_write_bytes, _read_bounded, _fsync_directory
else:
    from log_store import LogStoreError, _atomic_write_bytes, _read_bounded, _fsync_directory


STATUS_FILENAME = "ssh-access-status.json"
RETENTION_DAYS = 30
MAX_DAY_ROWS = 10_000
MAX_DAY_BYTES = 4 * 1024 * 1024
MAX_STATUS_BYTES = 8192
MAX_INPUT_BYTES = 128 * 1024
SOURCE_UNITS = {"journal:ssh": "ssh.service", "journal:sshd": "sshd.service"}
EVENT_TYPES = {"denied", "invalid_user", "auth_failed", "accepted", "preauth_closed"}
AUTH_METHODS = {None, "publickey", "password", "keyboard-interactive"}
COUNTRY_STATUSES = {"estimated", "private", "unavailable", "not_found", "stale"}
SOURCE_STATUSES = {"fresh", "partial", "unavailable", "stale"}
ERROR_CLASSES = {None, "not_configured", "acquisition_failed", "acquisition_partial", "persistence_failed", "invalid_input"}
RECORD_FIELDS = {"schemaVersion", "id", "observedAt", "sourceId", "sourceIp", "sourcePort",
                 "eventType", "authMethod", "countryCode", "countryStatus", "databaseDate"}
STATUS_FIELDS = {"schemaVersion", "observedAt", "status", "lastSuccessAt", "errorClass", "sources",
                 "acceptedRecords", "deduplicatedRecords", "droppedRecords", "retentionDays"}
SOURCE_FIELDS = {"sourceId", "status", "observedAt", "lastSuccessAt", "errorClass"}
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_USER = r"[^\s\x00-\x1f\x7f]{1,256}"
_IP = r"(?P<ip>[0-9A-Fa-f:.]{2,45})"
_PORT = r"(?P<port>[0-9]{1,5})"
_METHOD = r"(?P<method>publickey|password|keyboard-interactive(?:/pam)?)"
_FINGERPRINT = r"(?:: (?:RSA|DSA|ECDSA|ED25519|ECDSA-SK|ED25519-SK)(?:-CERT)? SHA256:[A-Za-z0-9+/=]{1,128})?"
_PATTERNS = (
    ("denied", re.compile(r"User " + _USER + r" from " + _IP + r" not allowed because (?:not listed in AllowUsers|listed in DenyUsers|none of user's groups are listed in AllowGroups|a group is listed in DenyGroups)")),
    ("invalid_user", re.compile(r"Invalid user " + _USER + r" from " + _IP + r" port " + _PORT)),
    ("auth_failed", re.compile(r"Failed " + _METHOD + r" for (?:invalid user )?" + _USER + r" from " + _IP + r" port " + _PORT + r" ssh2" + _FINGERPRINT)),
    ("accepted", re.compile(r"Accepted " + _METHOD + r" for " + _USER + r" from " + _IP + r" port " + _PORT + r" ssh2" + _FINGERPRINT)),
    ("preauth_closed", re.compile(r"(?:Connection closed by|Disconnected from) (?:(?:invalid user|authenticating user) " + _USER + r" )?" + _IP + r" port " + _PORT + r" \[preauth\]")),
)


def _iso(value: dt.datetime) -> str:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise ValueError("SSH observation time must be timezone-aware")
    return value.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str) or _ISO.fullmatch(value) is None:
        raise ValueError("invalid SSH timestamp")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def _excluded(value: Any) -> bool:
    if isinstance(value, bytes):
        return b"wgang" in value.lower()
    return "wgang" in str(value).casefold()


def _json(raw: str | bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate SSH JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> Any:
        raise ValueError("invalid SSH JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def is_ssh_source(definition: Any) -> bool:
    source = getattr(definition, "source", None)
    return (source is not None and not _excluded(vars(source))
            and getattr(source, "kind", None) == "journald"
            and SOURCE_UNITS.get(getattr(source, "source_id", None)) == getattr(definition, "unit", None)
            and getattr(source, "source_id", None) in SOURCE_UNITS)


def _identity(row: Mapping[str, Any]) -> str:
    return hashlib.sha256("\0".join(str(row[key]) for key in (
        "observedAt", "sourceId", "eventType", "sourceIp", "sourcePort")).encode()).hexdigest()


def _country(ip: str, lookup: Any) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    fallback = {"countryCode": None, "countryStatus": "private" if not address.is_global or address.is_multicast or address.is_reserved else "unavailable", "databaseDate": None}
    if lookup is None:
        return fallback
    try:
        value = lookup.lookup(ip)
        if not isinstance(value, Mapping) or set(value) != set(fallback):
            return fallback
        code, status, day = value["countryCode"], value["countryStatus"], value["databaseDate"]
        if (status not in COUNTRY_STATUSES or (code is not None and (not isinstance(code, str) or re.fullmatch(r"[A-Z]{2}", code) is None))
                or (day is not None and (not isinstance(day, str) or _DAY.fullmatch(day) is None))):
            return fallback
        if day is not None:
            dt.date.fromisoformat(day)
        if (status == "estimated" and code is None) or (status not in {"estimated", "stale"} and code is not None):
            return fallback
        return dict(value)
    except Exception:
        return fallback


def parse_ssh_event(source_id: str, unit: str, line: str, *, lookup: Any = None) -> dict[str, Any] | None:
    """Parse one reduced journal JSON line; unmatched or excluded input is ignored.

    Full-message matching and a single non-whitespace username field prevent
    attacker-controlled username text from spoofing a second `from IP` clause.
    """
    if (source_id not in SOURCE_UNITS or SOURCE_UNITS[source_id] != unit
            or not isinstance(line, str) or len(line.encode()) > MAX_INPUT_BYTES or _excluded(line)):
        return None
    raw = _json(line)
    if not isinstance(raw, Mapping) or set(raw) != {"timestamp", "severity", "message"}:
        raise ValueError("invalid reduced SSH journal row")
    if _excluded(raw):
        return None
    message = raw["message"]
    if not isinstance(message, str) or any(ord(char) < 32 or ord(char) == 127 for char in message):
        return None
    for event_type, pattern in _PATTERNS:
        match = pattern.fullmatch(message)
        if match is None:
            continue
        fields = match.groupdict()
        address = ipaddress.ip_address(fields["ip"])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        port = int(fields["port"]) if fields.get("port") is not None else None
        if port is not None and not 1 <= port <= 65535:
            return None
        method = fields.get("method")
        row = {"schemaVersion": 1, "observedAt": _iso(_timestamp(raw["timestamp"])),
               "sourceId": source_id, "sourceIp": address.compressed, "sourcePort": port,
               "eventType": event_type, "authMethod": "keyboard-interactive" if method and method.startswith("keyboard-interactive") else method,
               **_country(address.compressed, lookup)}
        row["id"] = _identity(row)
        return row
    return None


def normalize_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != RECORD_FIELDS or _excluded(value):
        raise ValueError("invalid SSH access record fields")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        raise ValueError("invalid SSH access schema")
    if (_iso(_timestamp(value["observedAt"])) != value["observedAt"] or value["sourceId"] not in SOURCE_UNITS
            or value["eventType"] not in EVENT_TYPES or value["authMethod"] not in AUTH_METHODS):
        raise ValueError("invalid SSH access record")
    if not isinstance(value["sourceIp"], str) or ipaddress.ip_address(value["sourceIp"]).compressed != value["sourceIp"] or "%" in value["sourceIp"]:
        raise ValueError("invalid SSH source IP")
    address = ipaddress.ip_address(value["sourceIp"])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ValueError("SSH mapped IPv6 must use its IPv4 identity")
    port = value["sourcePort"]
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("invalid SSH source port")
    if value["id"] != _identity(value):
        raise ValueError("invalid SSH identity")
    country = {key: value[key] for key in ("countryCode", "countryStatus", "databaseDate")}
    class ExistingCountry:
        def lookup(self, _ip: str) -> dict[str, Any]:
            return country
    if _country(value["sourceIp"], ExistingCountry()) != country:
        raise ValueError("invalid SSH country data")
    return dict(value)


def _directory(path: Path, owner: int, *, create: bool = False) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise LogStoreError("SSH output path is not absolute")
    for ancestor in reversed(path.parents):
        metadata = ancestor.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, owner}
                or (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX)):
            raise LogStoreError("SSH output ancestor is unsafe")
    if create:
        path.mkdir(mode=0o750, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or metadata.st_mode & 0o022:
        raise LogStoreError("SSH output directory is unsafe")


def _read(path: Path, owner: int, maximum: int) -> bytes | None:
    return _read_bounded(path, expected_uid=owner, maximum_bytes=maximum, private=False)


def _write(path: Path, value: bytes, owner: int, maximum: int) -> None:
    if len(value) > maximum:
        raise ValueError("SSH export exceeds its bound")
    _read(path, owner, maximum)  # Reject unsafe pre-existing file, including symlink/hardlink.
    _atomic_write_bytes(path, value, 0o640, owner)


def _encoded(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _prior_status(root: Path, owner: int) -> dict[str, Any]:
    raw = _read(root / STATUS_FILENAME, owner, MAX_STATUS_BYTES)
    if raw is None:
        return {}
    value = _json(raw)
    if (not isinstance(value, dict) or set(value) != STATUS_FIELDS or _excluded(value)
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["status"] not in SOURCE_STATUSES or value["errorClass"] not in ERROR_CLASSES
            or value["retentionDays"] != RETENTION_DAYS or not isinstance(value["sources"], list) or len(value["sources"]) > 2):
        raise ValueError("invalid SSH status")
    _timestamp(value["observedAt"])
    if value["lastSuccessAt"] is not None:
        _timestamp(value["lastSuccessAt"])
    for key in ("acceptedRecords", "deduplicatedRecords", "droppedRecords"):
        if type(value[key]) is not int or not 0 <= value[key] <= 1_000_000:
            raise ValueError("invalid SSH status count")
    seen = set()
    for row in value["sources"]:
        if (not isinstance(row, Mapping) or set(row) != SOURCE_FIELDS or row["sourceId"] not in SOURCE_UNITS
                or row["sourceId"] in seen or row["status"] not in SOURCE_STATUSES or row["errorClass"] not in ERROR_CLASSES):
            raise ValueError("invalid SSH source status")
        seen.add(row["sourceId"])
        _timestamp(row["observedAt"])
        if row["lastSuccessAt"] is not None:
            _timestamp(row["lastSuccessAt"])
    return value


def _empty_status(now: dt.datetime) -> dict[str, Any]:
    return {"schemaVersion": 1, "observedAt": _iso(now), "status": "unavailable", "lastSuccessAt": None,
            "errorClass": "not_configured", "sources": [], "acceptedRecords": 0,
            "deduplicatedRecords": 0, "droppedRecords": 0, "retentionDays": RETENTION_DAYS}


def record_failure(output_dir: Path, definitions: Sequence[Any], observed_at: dt.datetime,
                   *, expected_uid: int | None = None) -> dict[str, Any]:
    """Best-effort sanitized failure marker. Never replaces unsafe history."""
    owner = os.geteuid() if expected_uid is None else expected_uid
    status = _empty_status(observed_at)
    status["errorClass"] = "persistence_failed"
    try:
        _directory(output_dir, owner)
        try:
            prior = _prior_status(output_dir, owner)
        except Exception:
            prior = {}
        status["lastSuccessAt"] = prior.get("lastSuccessAt")
        status["sources"] = [{"sourceId": item.source.source_id, "status": "unavailable", "observedAt": status["observedAt"],
                               "lastSuccessAt": next((row["lastSuccessAt"] for row in prior.get("sources", []) if row["sourceId"] == item.source.source_id), None),
                               "errorClass": "persistence_failed"} for item in definitions if is_ssh_source(item)]
        _write(output_dir / STATUS_FILENAME, _encoded(status), owner, MAX_STATUS_BYTES)
    except Exception:
        pass
    return status


def _merge_days(root: Path, records: Sequence[Mapping[str, Any]], now: dt.datetime, owner: int) -> tuple[int, int, int]:
    directory = root / "ssh-access"
    _directory(directory, owner, create=True)
    cutoff = now.astimezone(dt.timezone.utc).date() - dt.timedelta(days=RETENTION_DAYS - 1)
    dates: dict[str, list[Mapping[str, Any]]] = {}
    dropped = 0
    for row in records:
        day = row["observedAt"][:10]
        if dt.date.fromisoformat(day) < cutoff or _timestamp(row["observedAt"]) > now + dt.timedelta(seconds=60):
            dropped += 1
        else:
            dates.setdefault(day, []).append(row)
    accepted = duplicates = 0
    for day, incoming in sorted(dates.items()):
        path = directory / f"{day}.jsonl"
        raw = _read(path, owner, MAX_DAY_BYTES)
        retained = {}
        if raw is not None:
            if raw and not raw.endswith(b"\n"):
                raise ValueError("incomplete SSH history")
            if len(raw.splitlines()) > MAX_DAY_ROWS:
                raise ValueError("SSH history row bound exceeded")
            for line in raw.splitlines():
                if _excluded(line):
                    dropped += 1
                    continue
                row = normalize_record(_json(line))
                if row["observedAt"][:10] != day or row["id"] in retained:
                    raise ValueError("invalid SSH history date or duplicate")
                retained[row["id"]] = row
        new_ids = set()
        for row in incoming:
            if row["id"] in retained:
                duplicates += 1
            else:
                retained[row["id"]] = row
                new_ids.add(row["id"])
        ordered = sorted(retained.values(), key=lambda row: (row["observedAt"], row["id"]))
        lines = [_encoded(row) for row in ordered]
        size = sum(map(len, lines))
        trim = 0
        while len(lines) - trim > MAX_DAY_ROWS or size > MAX_DAY_BYTES:
            size -= len(lines[trim])
            trim += 1
        dropped += trim
        _write(path, b"".join(lines[trim:]), owner, MAX_DAY_BYTES)
        accepted += sum(row["id"] in new_ids for row in ordered[trim:])
    # Visit only exact UTC date filenames, never arbitrary files or workload names.
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index >= 128:
                raise ValueError("SSH history directory bound exceeded")
            if _excluded(entry.name) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", entry.name):
                continue
            day = dt.date.fromisoformat(entry.name[:-6])
            if day < cutoff:
                path = directory / entry.name
                raw = _read(path, owner, MAX_DAY_BYTES)
                if raw is not None:
                    # Expected expiry outside the advertised 30-day window is
                    # not a gap in this acquisition's coverage or a noisy alert.
                    path.unlink()
                    _fsync_directory(directory)
    return accepted, duplicates, dropped


def _lookup_context() -> Any:
    try:
        if __package__:
            from .ip_country import CountryLookup
        else:
            from ip_country import CountryLookup
        return CountryLookup()
    except Exception:
        return contextlib.nullcontext(None)


def collect_ssh_access(output_dir: Path, definitions: Sequence[Any], acquisitions: Mapping[str, Mapping[str, Any]],
                       observed_at: dt.datetime, *, expected_uid: int | None = None,
                       country_lookup: Any = None) -> tuple[dict[str, Any], set[str]]:
    """Persist sanitized SSH rows before the caller commits journal cursors.

    Returned source IDs must retain their old cursor on persistence failure.
    Completed daily writes are idempotent if a later status/generic commit fails.
    """
    owner = os.geteuid() if expected_uid is None else expected_uid
    relevant = [item for item in definitions if is_ssh_source(item)]
    identifiers = {item.source.source_id for item in relevant}
    status = _empty_status(observed_at)
    try:
        _directory(output_dir, owner)
        prior = _prior_status(output_dir, owner)
        prior_sources = {row["sourceId"]: row for row in prior.get("sources", [])}
        status["lastSuccessAt"] = prior.get("lastSuccessAt")
        records = []
        # Country DB failure is enrichment failure only, never an IP collection failure.
        context = contextlib.nullcontext(country_lookup) if country_lookup is not None else _lookup_context()
        try:
            lookup = context.__enter__()
        except Exception:
            context = contextlib.nullcontext(None)
            lookup = context.__enter__()
        try:
            for definition in relevant:
                source_id = definition.source.source_id
                acquired = acquisitions.get(source_id, {})
                acquisition_state = acquired.get("status")
                state = "fresh" if acquisition_state in {"fresh", "no_data"} else "partial" if acquisition_state == "truncated" else "unavailable"
                error = None if state == "fresh" else "acquisition_partial" if state == "partial" else "acquisition_failed"
                last_success = prior_sources.get(source_id, {}).get("lastSuccessAt")
                if state != "unavailable":
                    lines = acquired.get("lines", [])
                    if not isinstance(lines, list) or len(lines) > 5000:
                        raise ValueError("SSH acquisition line bound exceeded")
                    for line in lines:
                        try:
                            record = parse_ssh_event(source_id, definition.unit, line, lookup=lookup)
                        except (ValueError, TypeError, UnicodeError, RecursionError):
                            status["droppedRecords"] += 1
                            state, error = "partial", "invalid_input"
                            continue
                        if record is not None:
                            records.append(record)
                    dropped = acquired.get("droppedLines", 0)
                    if type(dropped) is int and dropped > 0:
                        status["droppedRecords"] += min(dropped, 100_000)
                        state, error = "partial", error or "acquisition_partial"
                    last_success = status["observedAt"]
                status["sources"].append({"sourceId": source_id, "status": state, "observedAt": status["observedAt"],
                                          "lastSuccessAt": last_success, "errorClass": error})
        finally:
            try:
                context.__exit__(None, None, None)
            except Exception:
                pass  # Closing optional enrichment must not invalidate access rows.
        accepted, duplicates, dropped = _merge_days(output_dir, records, observed_at, owner)
        status.update(acceptedRecords=accepted, deduplicatedRecords=duplicates)
        status["droppedRecords"] += dropped
        if status["sources"]:
            states = {row["status"] for row in status["sources"]}
            status["status"] = "fresh" if states == {"fresh"} and not dropped else "unavailable" if states == {"unavailable"} else "partial"
            status["errorClass"] = None if status["status"] == "fresh" else next((row["errorClass"] for row in status["sources"] if row["errorClass"]), "acquisition_partial")
            if "fresh" in states or "partial" in states:
                status["lastSuccessAt"] = status["observedAt"]
        _write(output_dir / STATUS_FILENAME, _encoded(status), owner, MAX_STATUS_BYTES)
        return status, set()
    except Exception:
        return record_failure(output_dir, relevant, observed_at, expected_uid=owner), identifiers
