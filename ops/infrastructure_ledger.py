#!/usr/bin/env python3
"""Maintain Monitor's append-only infrastructure work ledger.

The canonical event stream is root-only.  This program materializes a bounded,
credential-free snapshot in Monitor's existing read-only export directory.
Browser/API code never writes either file.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import grp
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
MAX_SEED_BYTES = 16 * 1024 * 1024
MAX_CANONICAL_BYTES = 64 * 1024 * 1024
MAX_PUBLIC_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 5_000
MAX_REFERENCES = 256
MAX_EVIDENCE = 24
MAX_RELATED = 32
MAX_SCOPES = 24
MAX_SOURCES = 64
MAX_LIMITATIONS = 32
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)

CATEGORIES = frozenset({
    "network", "security", "identity-access", "dns-edge", "reliability",
    "compute-kernel", "storage-filesystem", "backup-recovery",
    "observability-logging", "service-deployment", "containers",
    "packages-firmware", "governance-documentation", "hardware-physical",
})
STATUSES = frozenset({
    "completed", "in-progress", "pending", "deferred", "recommended",
    "observed", "superseded", "not-applicable",
})
WORK_TYPES = frozenset({
    "change", "configuration", "audit", "hardening", "mitigation", "update",
    "verification", "incident", "maintenance", "recommendation", "decision", "documentation",
})
PRIORITIES = frozenset({"critical", "high", "medium", "low", "informational"})
CONFIDENCE = frozenset({"current-state", "documented", "inferred", "recommendation"})
VERIFICATION = frozenset({"verified", "partially-verified", "unverified", "not-applicable"})
APPLICABILITY = frozenset({"applicable", "needs-assessment", "not-applicable"})
IMPACTS = frozenset({
    "none", "observed-none", "low", "brief", "maintenance-window-required", "unknown",
})
SENSITIVITY = frozenset({"public", "internal", "restricted"})
CSF_FUNCTIONS = frozenset({"govern", "identify", "protect", "detect", "respond", "recover"})
EVIDENCE_KINDS = frozenset({
    "runtime", "file", "journal", "package-log", "repository", "session",
    "standard", "operator",
})

ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{1,127}$")
SCOPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,63}$")
FORBIDDEN_PATTERNS = (
    re.compile(r"\bwgang\b", re.IGNORECASE),
    re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?:https?|ssh)://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
)


class LedgerError(ValueError):
    """Raised when a ledger cannot be safely validated or published."""


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _record(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError(f"{label} must be an object")
    return value


def _array(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise LedgerError(f"{label} must be an array with at most {maximum} values")
    return value


def _text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise LedgerError(f"{label} must be a string")
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > maximum or any(pattern.search(cleaned) for pattern in FORBIDDEN_PATTERNS):
        raise LedgerError(f"{label} contains unsafe or invalid text")
    return cleaned


def _identifier(value: Any, label: str) -> str:
    cleaned = _text(value, label, 128)
    if not ID_PATTERN.fullmatch(cleaned):
        raise LedgerError(f"{label} is not a stable identifier")
    return cleaned


def _localized(value: Any, label: str, maximum: int) -> dict[str, str]:
    record = _record(value, label)
    if set(record) != {"ko", "en"}:
        raise LedgerError(f"{label} must contain exactly ko and en")
    return {
        "ko": _text(record["ko"], f"{label}.ko", maximum),
        "en": _text(record["en"], f"{label}.en", maximum),
    }


def _timestamp(value: Any, label: str, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    raw = _text(value, label, 64)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise LedgerError(f"{label} is not an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise LedgerError(f"{label} must include a time zone")
    normalized = parsed.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds")
    return normalized.replace("+00:00", "Z")


def _enum(value: Any, label: str, accepted: frozenset[str]) -> str:
    cleaned = _text(value, label, 64)
    if cleaned not in accepted:
        raise LedgerError(f"{label} has an unsupported value")
    return cleaned


def _id_list(value: Any, label: str, maximum: int) -> list[str]:
    values = [_identifier(item, f"{label}[]") for item in _array(value, label, maximum)]
    if len(set(values)) != len(values):
        raise LedgerError(f"{label} contains duplicates")
    return values


def _scope_list(value: Any, label: str) -> list[str]:
    values = [_text(item, f"{label}[]", 64) for item in _array(value, label, MAX_SCOPES)]
    if any(not SCOPE_PATTERN.fullmatch(item) for item in values) or len(set(values)) != len(values):
        raise LedgerError(f"{label} contains invalid or duplicate scopes")
    return values


def normalize_evidence(value: Any, label: str) -> dict[str, Any]:
    record = _record(value, label)
    expected = {"kind", "reference", "observedAt", "note"}
    if set(record) != expected:
        raise LedgerError(f"{label} has unexpected fields")
    return {
        "kind": _enum(record["kind"], f"{label}.kind", EVIDENCE_KINDS),
        "reference": _text(record["reference"], f"{label}.reference", 320),
        "observedAt": _timestamp(record["observedAt"], f"{label}.observedAt"),
        "note": _localized(record["note"], f"{label}.note", 600),
    }


def normalize_entry(value: Any, label: str = "entry") -> dict[str, Any]:
    record = _record(value, label)
    expected = {
        "id", "itemKey", "revision", "occurredAt", "recordedAt", "category",
        "workType", "status", "priority", "confidence", "verification",
        "applicability", "impact", "title", "summary", "rationale", "details",
        "sensitivity", "csfFunctions", "outcome", "nextAction", "actor", "scope", "evidence", "referenceIds",
        "relatedIds", "supersedes", "dueAt", "recurrence",
    }
    if set(record) != expected:
        raise LedgerError(f"{label} has unexpected or missing fields")
    revision = record["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise LedgerError(f"{label}.revision must be a positive integer")
    raw_evidence = _array(record["evidence"], f"{label}.evidence", MAX_EVIDENCE)
    csf_functions = [
        _enum(item, f"{label}.csfFunctions[]", CSF_FUNCTIONS)
        for item in _array(record["csfFunctions"], f"{label}.csfFunctions", len(CSF_FUNCTIONS))
    ]
    if not csf_functions or len(set(csf_functions)) != len(csf_functions):
        raise LedgerError(f"{label}.csfFunctions must contain unique values")
    recurrence = None if record["recurrence"] is None else _localized(record["recurrence"], f"{label}.recurrence", 300)
    supersedes = None if record["supersedes"] is None else _identifier(record["supersedes"], f"{label}.supersedes")
    entry = {
        "id": _identifier(record["id"], f"{label}.id"),
        "itemKey": _identifier(record["itemKey"], f"{label}.itemKey"),
        "revision": revision,
        "occurredAt": _timestamp(record["occurredAt"], f"{label}.occurredAt"),
        "recordedAt": _timestamp(record["recordedAt"], f"{label}.recordedAt"),
        "category": _enum(record["category"], f"{label}.category", CATEGORIES),
        "workType": _enum(record["workType"], f"{label}.workType", WORK_TYPES),
        "status": _enum(record["status"], f"{label}.status", STATUSES),
        "priority": _enum(record["priority"], f"{label}.priority", PRIORITIES),
        "confidence": _enum(record["confidence"], f"{label}.confidence", CONFIDENCE),
        "verification": _enum(record["verification"], f"{label}.verification", VERIFICATION),
        "applicability": _enum(record["applicability"], f"{label}.applicability", APPLICABILITY),
        "impact": _enum(record["impact"], f"{label}.impact", IMPACTS),
        "sensitivity": _enum(record["sensitivity"], f"{label}.sensitivity", SENSITIVITY),
        "csfFunctions": csf_functions,
        "title": _localized(record["title"], f"{label}.title", 180),
        "summary": _localized(record["summary"], f"{label}.summary", 800),
        "rationale": _localized(record["rationale"], f"{label}.rationale", 1_600),
        "details": _localized(record["details"], f"{label}.details", 4_000),
        "outcome": _localized(record["outcome"], f"{label}.outcome", 1_600),
        "nextAction": _localized(record["nextAction"], f"{label}.nextAction", 1_600),
        "actor": _text(record["actor"], f"{label}.actor", 96),
        "scope": _scope_list(record["scope"], f"{label}.scope"),
        "evidence": [normalize_evidence(item, f"{label}.evidence[{index}]") for index, item in enumerate(raw_evidence)],
        "referenceIds": _id_list(record["referenceIds"], f"{label}.referenceIds", MAX_REFERENCES),
        "relatedIds": _id_list(record["relatedIds"], f"{label}.relatedIds", MAX_RELATED),
        "supersedes": supersedes,
        "dueAt": _timestamp(record["dueAt"], f"{label}.dueAt", optional=True),
        "recurrence": recurrence,
    }
    if entry["occurredAt"] > entry["recordedAt"]:
        raise LedgerError(f"{label}.recordedAt cannot precede occurredAt")
    if entry["status"] == "completed" and (
        entry["verification"] not in {"verified", "partially-verified"} or not entry["evidence"]
    ):
        raise LedgerError(f"{label}: completed work requires verification evidence")
    if entry["status"] == "not-applicable" and entry["applicability"] != "not-applicable":
        raise LedgerError(f"{label}: not-applicable status requires matching applicability")
    return entry


def normalize_reference(value: Any, label: str) -> dict[str, Any]:
    record = _record(value, label)
    expected = {"id", "title", "publisher", "url", "publishedAt", "accessedAt"}
    if set(record) != expected:
        raise LedgerError(f"{label} has unexpected fields")
    url = _text(record["url"], f"{label}.url", 600)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise LedgerError(f"{label}.url must be a credential-free HTTPS URL without a fragment")
    return {
        "id": _identifier(record["id"], f"{label}.id"),
        "title": _text(record["title"], f"{label}.title", 240),
        "publisher": _text(record["publisher"], f"{label}.publisher", 160),
        "url": url,
        "publishedAt": _timestamp(record["publishedAt"], f"{label}.publishedAt", optional=True),
        "accessedAt": _timestamp(record["accessedAt"], f"{label}.accessedAt"),
    }


def normalize_coverage(value: Any) -> dict[str, Any]:
    record = _record(value, "coverage")
    expected = {"from", "through", "sources", "limitations"}
    if set(record) != expected:
        raise LedgerError("coverage has unexpected fields")
    sources: list[dict[str, Any]] = []
    for index, value in enumerate(_array(record["sources"], "coverage.sources", MAX_SOURCES)):
        source = _record(value, f"coverage.sources[{index}]")
        if set(source) != {"id", "label", "from", "through"}:
            raise LedgerError(f"coverage.sources[{index}] has unexpected fields")
        sources.append({
            "id": _identifier(source["id"], f"coverage.sources[{index}].id"),
            "label": _localized(source["label"], f"coverage.sources[{index}].label", 240),
            "from": _timestamp(source["from"], f"coverage.sources[{index}].from", optional=True),
            "through": _timestamp(source["through"], f"coverage.sources[{index}].through", optional=True),
        })
    if len({source["id"] for source in sources}) != len(sources):
        raise LedgerError("coverage source IDs must be unique")
    limitations = [
        _localized(item, f"coverage.limitations[{index}]", 800)
        for index, item in enumerate(_array(record["limitations"], "coverage.limitations", MAX_LIMITATIONS))
    ]
    return {
        "from": _timestamp(record["from"], "coverage.from", optional=True),
        "through": _timestamp(record["through"], "coverage.through"),
        "sources": sources,
        "limitations": limitations,
    }


def validate_document(value: Any) -> dict[str, Any]:
    record = _record(value, "ledger")
    if set(record) != {"schemaVersion", "updatedAt", "coverage", "references", "entries"}:
        raise LedgerError("ledger has unexpected fields")
    if record["schemaVersion"] != SCHEMA_VERSION:
        raise LedgerError("unsupported ledger schemaVersion")
    references = [
        normalize_reference(item, f"references[{index}]")
        for index, item in enumerate(_array(record["references"], "references", MAX_REFERENCES))
    ]
    entries = [
        normalize_entry(item, f"entries[{index}]")
        for index, item in enumerate(_array(record["entries"], "entries", MAX_ENTRIES))
    ]
    reference_ids = {item["id"] for item in references}
    entry_by_id = {item["id"]: item for item in entries}
    if len(reference_ids) != len(references) or len(entry_by_id) != len(entries):
        raise LedgerError("reference and entry IDs must be unique")
    seen_revisions: set[tuple[str, int]] = set()
    for entry in entries:
        revision_key = (entry["itemKey"], entry["revision"])
        if revision_key in seen_revisions:
            raise LedgerError("work-item revisions must be unique")
        seen_revisions.add(revision_key)
        if any(reference_id not in reference_ids for reference_id in entry["referenceIds"]):
            raise LedgerError(f"{entry['id']} references an unknown source")
        if any(related_id not in entry_by_id or related_id == entry["id"] for related_id in entry["relatedIds"]):
            raise LedgerError(f"{entry['id']} has an invalid related record")
        if entry["supersedes"] is None:
            if entry["revision"] != 1:
                raise LedgerError(f"{entry['id']} must supersede revision {entry['revision'] - 1}")
        else:
            previous = entry_by_id.get(entry["supersedes"])
            if (
                previous is None
                or previous["itemKey"] != entry["itemKey"]
                or previous["revision"] + 1 != entry["revision"]
                or previous["occurredAt"] >= entry["occurredAt"]
            ):
                raise LedgerError(f"{entry['id']} has an invalid supersedes chain")
    normalized = {
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": _timestamp(record["updatedAt"], "updatedAt"),
        "coverage": normalize_coverage(record["coverage"]),
        "references": sorted(references, key=lambda item: item["id"]),
        "entries": sorted(entries, key=lambda item: (item["occurredAt"], item["id"]), reverse=True),
    }
    if entries and normalized["updatedAt"] < max(item["recordedAt"] for item in entries):
        raise LedgerError("updatedAt cannot precede the newest recorded event")
    coverage = normalized["coverage"]
    if coverage["from"] is not None and coverage["from"] > coverage["through"]:
        raise LedgerError("coverage.from cannot follow coverage.through")
    for source in coverage["sources"]:
        if source["from"] is not None and source["through"] is not None and source["from"] > source["through"]:
            raise LedgerError(f"coverage source {source['id']} has an inverted interval")
    if entries and coverage["through"] < max(item["recordedAt"] for item in entries):
        raise LedgerError("coverage.through cannot precede the newest recorded event")

    future_limit = _utc_now() + MAX_FUTURE_SKEW
    timestamps: list[tuple[str, str | None]] = [
        ("updatedAt", normalized["updatedAt"]),
        ("coverage.from", coverage["from"]),
        ("coverage.through", coverage["through"]),
    ]
    timestamps.extend(
        (f"coverage source {source['id']} {field}", source[field])
        for source in coverage["sources"]
        for field in ("from", "through")
    )
    timestamps.extend(
        (f"reference {reference['id']} {field}", reference[field])
        for reference in normalized["references"]
        for field in ("publishedAt", "accessedAt")
    )
    timestamps.extend(
        (f"entry {entry['id']} {field}", entry[field])
        for entry in entries
        for field in ("occurredAt", "recordedAt")
    )
    timestamps.extend(
        (f"entry {entry['id']} evidence", evidence["observedAt"])
        for entry in entries
        for evidence in entry["evidence"]
    )
    for label, timestamp in timestamps:
        if timestamp is None:
            continue
        parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed > future_limit:
            raise LedgerError(f"{label} is unreasonably far in the future")
    return normalized


def _safe_read_json(
    path: Path,
    maximum: int,
    private: bool = False,
    trusted_uid: int | None = None,
) -> Any:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0 or before.st_size > maximum:
        raise LedgerError(f"unsafe or oversized file: {path}")
    if private and before.st_mode & 0o077:
        raise LedgerError(f"private file has broad permissions: {path}")
    if trusted_uid is not None and (before.st_uid != trusted_uid or before.st_mode & 0o022):
        raise LedgerError(f"mutation input is not owned and protected by the trusted operator: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise LedgerError(f"file changed while opening: {path}")
        content = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise LedgerError(f"file changed while reading: {path}")
    finally:
        os.close(descriptor)
    if len(content) > maximum:
        raise LedgerError(f"oversized file: {path}")
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LedgerError(f"invalid JSON: {path}") from error


def _safe_read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > MAX_CANONICAL_BYTES:
        raise LedgerError("canonical event stream is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise LedgerError("canonical event stream changed while opening")
        content = os.read(descriptor, MAX_CANONICAL_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise LedgerError("canonical event stream changed while reading")
    finally:
        os.close(descriptor)
    if len(content) > MAX_CANONICAL_BYTES:
        raise LedgerError("canonical event stream is oversized")
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LedgerError("canonical event stream is not UTF-8") from error
    events: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            events.append(normalize_entry(json.loads(line), f"canonical event line {index + 1}"))
        except json.JSONDecodeError as error:
            raise LedgerError(f"invalid canonical event line {index + 1}") from error
    if len(events) > MAX_ENTRIES:
        raise LedgerError("canonical event count exceeds the public schema limit")
    return events


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: Any, mode: int, uid: int, gid: int, maximum: int) -> None:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > maximum:
        raise LedgerError(f"materialized file exceeds {maximum} bytes")
    if path.exists() or path.is_symlink():
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o022:
            raise LedgerError(f"refusing to replace unsafe target: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _append_events(path: Path, events: Sequence[Mapping[str, Any]], uid: int, gid: int) -> None:
    if not events:
        return
    payload = b"".join(
        (json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for event in events
    )
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o077:
            raise LedgerError("canonical event stream is unsafe")
        if opened.st_size + len(payload) > MAX_CANONICAL_BYTES:
            raise LedgerError("canonical event stream would exceed its safety bound")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _catalog_from(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": document["updatedAt"],
        "coverage": document["coverage"],
        "references": document["references"],
    }


def _document_from(catalog: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return validate_document({
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": catalog["updatedAt"],
        "coverage": catalog["coverage"],
        "references": catalog["references"],
        "entries": list(events),
    })


def _merge_catalog(existing: Mapping[str, Any] | None, seed: Mapping[str, Any]) -> dict[str, Any]:
    if existing is None:
        return _catalog_from(seed)
    if existing.get("schemaVersion") != SCHEMA_VERSION:
        raise LedgerError("canonical catalog schema is unsupported")
    existing_document = validate_document({**existing, "entries": []})
    existing_references = {item["id"]: item for item in existing_document["references"]}
    for reference in seed["references"]:
        previous = existing_references.get(reference["id"])
        if previous is not None and previous != reference:
            raise LedgerError(f"reference {reference['id']} conflicts with the canonical catalog")
        existing_references[reference["id"]] = reference
    existing_sources = {item["id"]: item for item in existing_document["coverage"]["sources"]}
    for source in seed["coverage"]["sources"]:
        previous = existing_sources.get(source["id"])
        if previous is not None:
            if previous["label"] != source["label"]:
                raise LedgerError(f"coverage source {source['id']} conflicts with the canonical catalog")
            source_from = [value for value in (previous["from"], source["from"]) if value]
            source_through = [value for value in (previous["through"], source["through"]) if value]
            existing_sources[source["id"]] = {
                **previous,
                "from": min(source_from) if source_from else None,
                "through": max(source_through) if source_through else None,
            }
        else:
            existing_sources[source["id"]] = source
    limitations = existing_document["coverage"]["limitations"][:]
    for limitation in seed["coverage"]["limitations"]:
        if limitation not in limitations:
            limitations.append(limitation)
    from_values = [value for value in [existing_document["coverage"]["from"], seed["coverage"]["from"]] if value]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": max(existing_document["updatedAt"], seed["updatedAt"]),
        "coverage": {
            "from": min(from_values) if from_values else None,
            "through": max(existing_document["coverage"]["through"], seed["coverage"]["through"]),
            "sources": sorted(existing_sources.values(), key=lambda item: item["id"]),
            "limitations": limitations,
        },
        "references": sorted(existing_references.values(), key=lambda item: item["id"]),
    }


def _ensure_directory(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    opened = path.lstat()
    if not stat.S_ISDIR(opened.st_mode) or opened.st_mode & 0o022:
        raise LedgerError(f"unsafe ledger directory: {path}")
    os.chmod(path, mode)
    os.chown(path, uid, gid)


@contextlib.contextmanager
def _exclusive_lock(path: Path, uid: int, gid: int) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o077:
            raise LedgerError("unsafe ledger lock file")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def sync_seed(
    seed_path: Path,
    canonical_directory: Path,
    public_file: Path,
    *,
    private_uid: int = 0,
    private_gid: int = 0,
    public_gid: int,
) -> tuple[int, int]:
    seed = validate_document(_safe_read_json(seed_path, MAX_SEED_BYTES, trusted_uid=private_uid))
    _ensure_directory(canonical_directory, 0o700, private_uid, private_gid)
    _ensure_directory(public_file.parent, 0o750, private_uid, public_gid)
    catalog_path = canonical_directory / "catalog.json"
    events_path = canonical_directory / "events.jsonl"
    with _exclusive_lock(canonical_directory / "ledger.lock", private_uid, private_gid):
        existing_events = _safe_read_events(events_path)
        existing_by_id = {entry["id"]: entry for entry in existing_events}
        new_events: list[dict[str, Any]] = []
        for entry in reversed(seed["entries"]):
            previous = existing_by_id.get(entry["id"])
            if previous is not None and previous != entry:
                raise LedgerError(f"event {entry['id']} conflicts with the canonical stream")
            if previous is None:
                new_events.append(entry)
                existing_by_id[entry["id"]] = entry
        existing_catalog = _safe_read_json(catalog_path, MAX_SEED_BYTES, private=True) if catalog_path.exists() else None
        catalog = _merge_catalog(existing_catalog, seed)
        combined = _document_from(catalog, list(existing_by_id.values()))
        _atomic_json(catalog_path, catalog, 0o600, private_uid, private_gid, MAX_SEED_BYTES)
        _append_events(events_path, new_events, private_uid, private_gid)
        _atomic_json(public_file, combined, 0o640, private_uid, public_gid, MAX_PUBLIC_BYTES)
        return len(new_events), len(combined["entries"])


def append_entry(
    input_path: Path,
    canonical_directory: Path,
    public_file: Path,
    *,
    private_uid: int = 0,
    private_gid: int = 0,
    public_gid: int,
) -> bool:
    candidate = normalize_entry(
        _safe_read_json(input_path, 256 * 1024, trusted_uid=private_uid),
        "entry",
    )
    _ensure_directory(canonical_directory, 0o700, private_uid, private_gid)
    _ensure_directory(public_file.parent, 0o750, private_uid, public_gid)
    catalog_path = canonical_directory / "catalog.json"
    events_path = canonical_directory / "events.jsonl"
    with _exclusive_lock(canonical_directory / "ledger.lock", private_uid, private_gid):
        if not catalog_path.exists():
            raise LedgerError("canonical catalog is missing; sync a seed first")
        catalog_document = validate_document({
            **_safe_read_json(catalog_path, MAX_SEED_BYTES, private=True),
            "entries": [],
        })
        catalog = _catalog_from(catalog_document)
        events = _safe_read_events(events_path)
        by_id = {entry["id"]: entry for entry in events}
        if candidate["id"] in by_id:
            if by_id[candidate["id"]] != candidate:
                raise LedgerError(f"event {candidate['id']} conflicts with the canonical stream")
            combined = _document_from(catalog, events)
            _atomic_json(public_file, combined, 0o640, private_uid, public_gid, MAX_PUBLIC_BYTES)
            return False
        catalog["updatedAt"] = max(catalog["updatedAt"], candidate["recordedAt"])
        catalog["coverage"]["through"] = max(catalog["coverage"]["through"], candidate["recordedAt"])
        combined = _document_from(catalog, [*events, candidate])
        _atomic_json(catalog_path, catalog, 0o600, private_uid, private_gid, MAX_SEED_BYTES)
        _append_events(events_path, [candidate], private_uid, private_gid)
        _atomic_json(public_file, combined, 0o640, private_uid, public_gid, MAX_PUBLIC_BYTES)
        return True


def publish(
    canonical_directory: Path,
    public_file: Path,
    *,
    private_uid: int = 0,
    private_gid: int = 0,
    public_gid: int,
) -> int:
    _ensure_directory(canonical_directory, 0o700, private_uid, private_gid)
    _ensure_directory(public_file.parent, 0o750, private_uid, public_gid)
    with _exclusive_lock(canonical_directory / "ledger.lock", private_uid, private_gid):
        catalog = _safe_read_json(canonical_directory / "catalog.json", MAX_SEED_BYTES, private=True)
        events = _safe_read_events(canonical_directory / "events.jsonl")
        document = _document_from(catalog, events)
        _atomic_json(public_file, document, 0o640, private_uid, public_gid, MAX_PUBLIC_BYTES)
        return len(document["entries"])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify", help="validate a complete ledger document")
    verify_parser.add_argument("--input", type=Path, required=True)
    for name in ("sync-seed", "append", "publish"):
        command = subparsers.add_parser(name)
        command.add_argument("--canonical-dir", type=Path, default=Path("/var/lib/monitor-infrastructure-ledger"))
        command.add_argument("--public-file", type=Path, default=Path("/var/lib/monitor-export/infrastructure-ledger.json"))
        if name == "sync-seed":
            command.add_argument("--seed", type=Path, required=True)
        if name == "append":
            command.add_argument("--input", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        validate_document(_safe_read_json(args.input, MAX_SEED_BYTES))
        print("Infrastructure ledger is valid.")
        return 0
    if os.geteuid() != 0:
        raise SystemExit("ledger mutation commands must run as root")
    public_gid = grp.getgrnam("cks").gr_gid
    if args.command == "sync-seed":
        added, total = sync_seed(args.seed, args.canonical_dir, args.public_file, public_gid=public_gid)
        print(f"Synchronized {added} new event(s); public ledger contains {total} event(s).")
    elif args.command == "append":
        changed = append_entry(args.input, args.canonical_dir, args.public_file, public_gid=public_gid)
        print("Appended and published event." if changed else "Event already exists; no change.")
    else:
        total = publish(args.canonical_dir, args.public_file, public_gid=public_gid)
        print(f"Published {total} event(s).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        raise SystemExit(f"infrastructure ledger error: {error}") from error
