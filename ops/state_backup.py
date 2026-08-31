#!/usr/bin/env python3
"""Encrypted, bounded backup/verification/restore for Monitor state.

The trusted source map is deliberately separate from the archive.  Archive
member names can therefore never select a restore destination.  JSON and JSONL
sources are copied byte-for-byte after validation; SQLite sources are captured
with SQLite's online backup API so committed WAL pages are included.

The gzip tar stream is signed by a pinned producer key and the opaque SignedData
is then encrypted to the recovery recipient.  No plaintext tar archive or
decrypted archive is written to disk by this module.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Sequence, cast
from urllib.parse import quote


FORMAT_NAME = "monitor-state-backup"
SCHEMA_VERSION = 1
SOURCE_MAP_SCHEMA_VERSIONS = frozenset({1, 2})
MANIFEST_NAME = "manifest.json"
MANIFEST_DIGEST_NAME = "manifest.sha256"
MAX_SOURCE_MAP_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RESTORE_JOURNAL_BYTES = 1024 * 1024
MAX_SOURCES = 64
MAX_FAMILIES = 8
MAX_FAMILY_MEMBERS = 16
MAX_RESTORE_DIRECTORIES = 512
MAX_SOURCE_BYTES = 64 * 1024 * 1024
# Leave deterministic room for the manifest, USTAR framing, gzip framing, and
# the outer SignedData structure while keeping every decrypted/plaintext layer
# at or below 64 MiB.  Ciphertext has a separate small framing allowance.
MAX_TOTAL_BYTES = 62 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_PLAINTEXT_BYTES + 2 * 1024 * 1024
MAX_TAR_BYTES = MAX_PLAINTEXT_BYTES
MAX_PATH_BYTES = 1024
MAX_COMPONENT_BYTES = 100
MAX_AUXILIARY_BYTES = 1024 * 1024
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_JSONL_RECORDS = 100_000
OPENSSL_TIMEOUT_SECONDS = 120
SQLITE_BACKUP_TIMEOUT_SECONDS = 30
READ_CHUNK_BYTES = 64 * 1024
ALLOWED_SOURCE_MODES = frozenset({0o600, 0o640})
SOURCE_KINDS = frozenset({"json", "jsonl", "sqlite"})
FAMILY_MEMBER_KINDS = frozenset({"json", "jsonl"})
SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TRANSACTION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
RESTORE_JOURNAL_NAME = ".monitor-state-restore.json"
RESTORE_JOURNAL_PENDING_NAME = ".monitor-state-restore.pending"
RESTORE_JOURNAL_SCHEMA_VERSION = 1
RESTORE_JOURNAL_STATES = frozenset({"active", "committed", "rolled-back"})
RESTORE_ACTIONS = frozenset(
    {
        "commit",
        "create-directory",
        "install-target",
        "preserve-target",
        "remove-directory",
        "rollback-preserved",
        "rollback-stage",
        "rollback-target",
        "stage-target",
    }
)


class StateBackupError(RuntimeError):
    """The requested backup operation is unsafe or invalid."""


@dataclasses.dataclass(frozen=True)
class SourceSpec:
    source_id: str
    kind: str
    path: Path
    restore_path: PurePosixPath
    uid: int
    gid: int
    mode: int
    max_bytes: int
    required: bool = True
    family_id: str | None = None

    @property
    def archive_path(self) -> str:
        return f"data/{self.source_id}.{self.kind}"


@dataclasses.dataclass(frozen=True)
class SourcePlan:
    sources: tuple[SourceSpec, ...]
    sha256: str
    raw: bytes
    families: tuple["SourceFamily", ...] = ()


@dataclasses.dataclass(frozen=True)
class SourceFamily:
    family_id: str
    path: Path
    restore_path: PurePosixPath
    uid: int
    gid: int
    mode: int
    members: tuple[SourceSpec, ...]


@dataclasses.dataclass(frozen=True)
class SourceSnapshot:
    spec: SourceSpec
    payload: bytes
    mtime_ns: int
    identity: tuple[int, int]


@dataclasses.dataclass(frozen=True)
class VerifiedBackup:
    manifest: dict[str, Any]
    plan: SourcePlan
    payloads: tuple[bytes, ...]
    archive_sha256: str


@dataclasses.dataclass(frozen=True)
class RestoreResult:
    targets: tuple[Path, ...]
    preserved: tuple[Path, ...]


@dataclasses.dataclass(frozen=True)
class RecoveryResult:
    journal_found: bool
    action: str
    targets: tuple[Path, ...]


@dataclasses.dataclass
class _RestoreRecord:
    spec: SourceSpec
    target: Path
    stage: Path
    stage_identity: tuple[int, int] | None = None
    preserved: Path | None = None
    target_existed: bool = False
    old_sha256: str | None = None
    installed: bool = False


def _mode(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


def _require_exact_keys(value: object, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise StateBackupError(f"{field} must contain exactly {sorted(expected)}")
    return cast(dict[str, Any], value)


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise StateBackupError(f"duplicate JSON member: {key}")
        value[key] = member
    return value


def _reject_json_constant(value: str) -> None:
    raise StateBackupError(f"non-finite JSON constant is not allowed: {value}")


def _decode_json(payload: bytes, field: str) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=_reject_json_constant,
        )
    except StateBackupError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise StateBackupError(f"{field} is not valid strict UTF-8 JSON") from error


def _positive_int(value: object, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise StateBackupError(f"{field} must be an integer between 1 and {maximum}")
    return value


def _identity_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise StateBackupError(f"{field} must be a non-negative numeric identity")
    return value


def _path_size(value: str, field: str) -> None:
    if "\x00" in value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise StateBackupError(f"{field} exceeds the safe path bound")


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise StateBackupError(f"{field} must be a non-empty absolute path")
    _path_size(value, field)
    if not value.startswith("/") or os.path.normpath(value) != value:
        raise StateBackupError(f"{field} must be a normalized absolute path")
    return Path(value)


def _restore_path(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise StateBackupError(f"{field} must be a normalized relative POSIX path")
    _path_size(value, field)
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise StateBackupError(f"{field} must not contain empty, dot, or parent components")
    for part in path.parts:
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise StateBackupError(f"{field} contains an oversized path component")
    return path


def _parse_mode(value: object, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0[0-7]{3}", value):
        raise StateBackupError(f"{field} must be a four-digit octal string")
    parsed = int(value, 8)
    if parsed not in ALLOWED_SOURCE_MODES:
        allowed = ", ".join(f"{candidate:04o}" for candidate in sorted(ALLOWED_SOURCE_MODES))
        raise StateBackupError(f"{field} must be one of: {allowed}")
    return parsed


def _parse_family_mode(value: object, field: str) -> int:
    if value != "0700":
        raise StateBackupError(f"{field} must be 0700")
    return 0o700


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise StateBackupError(f"{field} must be boolean")
    return value


def _family_member_name(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,99}", value)
        or PurePosixPath(value).name != value
    ):
        raise StateBackupError(f"{field} must be one fixed safe filename without a glob")
    _path_size(value, field)
    return value


def _validate_absolute_no_symlinks(path: Path, *, strict: bool = True) -> None:
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise StateBackupError(f"path must be normalized and absolute: {path}")
    try:
        resolved = path.resolve(strict=strict)
    except (OSError, RuntimeError) as error:
        raise StateBackupError(f"path cannot be resolved safely: {path}") from error
    if resolved != path:
        raise StateBackupError(f"path must not contain symlinks: {path}")


def _open_checked_regular(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int | None,
    expected_mode: int,
    max_bytes: int,
    allow_empty: bool,
) -> tuple[int, os.stat_result]:
    _validate_absolute_no_symlinks(path)
    try:
        path_metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"required file is unavailable: {path}") from error
    invalid_size = path_metadata.st_size > max_bytes or (
        not allow_empty and path_metadata.st_size <= 0
    )
    if (
        not stat.S_ISREG(path_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or path_metadata.st_nlink != 1
        or path_metadata.st_uid != expected_uid
        or (expected_gid is not None and path_metadata.st_gid != expected_gid)
        or stat.S_IMODE(path_metadata.st_mode) != expected_mode
        or invalid_size
    ):
        raise StateBackupError(f"file ownership, mode, link count, type, or size is unsafe: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StateBackupError(f"file could not be opened safely: {path}") from error
    opened = os.fstat(descriptor)
    opened_invalid_size = opened.st_size > max_bytes or (not allow_empty and opened.st_size <= 0)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != expected_uid
        or (expected_gid is not None and opened.st_gid != expected_gid)
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or opened_invalid_size
        or (opened.st_dev, opened.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        raise StateBackupError(f"file changed while it was opened: {path}")
    return descriptor, opened


def _open_checked_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> tuple[int, os.stat_result]:
    _validate_absolute_no_symlinks(path)
    try:
        path_metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"required family directory is unavailable: {path}") from error
    if (
        not stat.S_ISDIR(path_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or path_metadata.st_uid != expected_uid
        or path_metadata.st_gid != expected_gid
        or stat.S_IMODE(path_metadata.st_mode) != expected_mode
    ):
        raise StateBackupError(f"family directory ownership, mode, or type is unsafe: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StateBackupError(f"family directory could not be opened safely: {path}") from error
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != expected_uid
        or opened.st_gid != expected_gid
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or (opened.st_dev, opened.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        raise StateBackupError(f"family directory changed while it was opened: {path}")
    return descriptor, opened


def _read_descriptor(descriptor: int, expected_size: int, field: str) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) != expected_size:
        raise StateBackupError(f"{field} changed while it was read")
    return payload


def _hash_descriptor(descriptor: int, expected_size: int, field: str) -> bytes:
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
        if not chunk:
            raise StateBackupError(f"{field} changed while it was revalidated")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.digest()


def _same_opened_file(path: Path, descriptor: int, initial: os.stat_result, *, content: bool) -> bool:
    try:
        path_metadata = path.lstat()
        opened = os.fstat(descriptor)
    except OSError:
        return False
    common = (
        stat.S_ISREG(path_metadata.st_mode)
        and not stat.S_ISLNK(path_metadata.st_mode)
        and path_metadata.st_nlink == opened.st_nlink == 1
        and (path_metadata.st_dev, path_metadata.st_ino) == (opened.st_dev, opened.st_ino)
        and (opened.st_dev, opened.st_ino) == (initial.st_dev, initial.st_ino)
        and path_metadata.st_uid == opened.st_uid == initial.st_uid
        and path_metadata.st_gid == opened.st_gid == initial.st_gid
        and stat.S_IMODE(path_metadata.st_mode)
        == stat.S_IMODE(opened.st_mode)
        == stat.S_IMODE(initial.st_mode)
    )
    if not common:
        return False
    if content:
        return (
            path_metadata.st_size == opened.st_size == initial.st_size
            and path_metadata.st_mtime_ns == opened.st_mtime_ns == initial.st_mtime_ns
            and path_metadata.st_ctime_ns == opened.st_ctime_ns == initial.st_ctime_ns
        )
    return True


def _same_opened_directory(path: Path, descriptor: int, initial: os.stat_result) -> bool:
    try:
        path_metadata = path.lstat()
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_metadata.st_mode)
        and not stat.S_ISLNK(path_metadata.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and (path_metadata.st_dev, path_metadata.st_ino)
        == (opened.st_dev, opened.st_ino)
        == (initial.st_dev, initial.st_ino)
        and path_metadata.st_uid == opened.st_uid == initial.st_uid
        and path_metadata.st_gid == opened.st_gid == initial.st_gid
        and stat.S_IMODE(path_metadata.st_mode)
        == stat.S_IMODE(opened.st_mode)
        == stat.S_IMODE(initial.st_mode)
        and path_metadata.st_mtime_ns == opened.st_mtime_ns == initial.st_mtime_ns
        and path_metadata.st_ctime_ns == opened.st_ctime_ns == initial.st_ctime_ns
    )


def _open_checked_family_member(
    directory_descriptor: int,
    spec: SourceSpec,
) -> tuple[int, os.stat_result] | None:
    name = spec.path.name
    try:
        path_metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if spec.required:
            raise StateBackupError(f"required family member is unavailable: {spec.path}")
        return None
    except OSError as error:
        raise StateBackupError(f"family member cannot be inspected: {spec.path}") from error
    invalid_size = path_metadata.st_size > spec.max_bytes or (
        spec.kind != "jsonl" and path_metadata.st_size <= 0
    )
    if (
        not stat.S_ISREG(path_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or path_metadata.st_nlink != 1
        or path_metadata.st_uid != spec.uid
        or path_metadata.st_gid != spec.gid
        or stat.S_IMODE(path_metadata.st_mode) != spec.mode
        or invalid_size
    ):
        raise StateBackupError(f"family member metadata is unsafe: {spec.path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise StateBackupError(f"family member could not be opened safely: {spec.path}") from error
    opened = os.fstat(descriptor)
    opened_invalid_size = opened.st_size > spec.max_bytes or (
        spec.kind != "jsonl" and opened.st_size <= 0
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != spec.uid
        or opened.st_gid != spec.gid
        or stat.S_IMODE(opened.st_mode) != spec.mode
        or opened_invalid_size
        or (opened.st_dev, opened.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        raise StateBackupError(f"family member changed while it was opened: {spec.path}")
    return descriptor, opened


def _same_opened_family_member(
    directory_descriptor: int,
    name: str,
    descriptor: int,
    initial: os.stat_result,
) -> bool:
    try:
        path_metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISREG(path_metadata.st_mode)
        and stat.S_ISREG(opened.st_mode)
        and path_metadata.st_nlink == opened.st_nlink == initial.st_nlink == 1
        and (path_metadata.st_dev, path_metadata.st_ino)
        == (opened.st_dev, opened.st_ino)
        == (initial.st_dev, initial.st_ino)
        and path_metadata.st_uid == opened.st_uid == initial.st_uid
        and path_metadata.st_gid == opened.st_gid == initial.st_gid
        and stat.S_IMODE(path_metadata.st_mode)
        == stat.S_IMODE(opened.st_mode)
        == stat.S_IMODE(initial.st_mode)
        and path_metadata.st_size == opened.st_size == initial.st_size
        and path_metadata.st_mtime_ns == opened.st_mtime_ns == initial.st_mtime_ns
        and path_metadata.st_ctime_ns == opened.st_ctime_ns == initial.st_ctime_ns
    )


def _read_control_file(path: Path, expected_owner_uid: int) -> bytes:
    descriptor, metadata = _open_checked_regular(
        path,
        expected_uid=expected_owner_uid,
        expected_gid=None,
        expected_mode=0o600,
        max_bytes=MAX_SOURCE_MAP_BYTES,
        allow_empty=False,
    )
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, "source map")
        if not _same_opened_file(path, descriptor, metadata, content=True):
            raise StateBackupError("source map changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def load_source_map(path: Path, *, owner_uid: int | None = None) -> SourcePlan:
    """Load a strict, owner-controlled source map without touching its sources."""

    expected_owner = os.geteuid() if owner_uid is None else owner_uid
    if os.geteuid() != 0 and expected_owner != os.geteuid():
        raise StateBackupError("only root may trust a source map owned by another uid")
    raw = _read_control_file(path, expected_owner)
    decoded = _require_exact_keys(
        _decode_json(raw, "source map"), {"schemaVersion", "sources"}, "source map"
    )
    schema_version = decoded["schemaVersion"]
    if (
        type(schema_version) is not int
        or schema_version not in SOURCE_MAP_SCHEMA_VERSIONS
    ):
        raise StateBackupError("source map schemaVersion must be 1 or 2")
    raw_sources = decoded["sources"]
    if not isinstance(raw_sources, list) or not 0 < len(raw_sources) <= MAX_SOURCES:
        raise StateBackupError(f"source map must contain between 1 and {MAX_SOURCES} sources")

    specs: list[SourceSpec] = []
    families: list[SourceFamily] = []
    family_ids: set[str] = set()
    source_ids: set[str] = set()
    source_paths: set[Path] = set()
    restore_paths: set[PurePosixPath] = set()
    advertised_total = 0

    def register(spec: SourceSpec, field: str) -> None:
        nonlocal advertised_total
        if len(specs) >= MAX_SOURCES:
            raise StateBackupError(f"expanded source map exceeds {MAX_SOURCES} sources")
        advertised_total += spec.max_bytes
        if advertised_total > MAX_TOTAL_BYTES:
            raise StateBackupError("source map advertised byte bounds exceed the global limit")
        if (
            spec.source_id in source_ids
            or spec.path in source_paths
            or spec.restore_path in restore_paths
        ):
            raise StateBackupError("source ids, paths, and restore paths must each be unique")
        if spec.restore_path.parts[0] in {
            RESTORE_JOURNAL_NAME,
            RESTORE_JOURNAL_PENDING_NAME,
        }:
            raise StateBackupError(f"{field}.restorePath collides with restore control state")
        source_ids.add(spec.source_id)
        source_paths.add(spec.path)
        restore_paths.add(spec.restore_path)
        specs.append(spec)

    for index, raw_source in enumerate(raw_sources):
        field = f"sources[{index}]"
        if not isinstance(raw_source, dict):
            raise StateBackupError(f"{field} must be an object")
        raw_kind = raw_source.get("kind")
        if raw_kind == "family":
            if schema_version != 2:
                raise StateBackupError("family sources require source map schemaVersion 2")
            source = _require_exact_keys(
                raw_source,
                {"id", "kind", "path", "restorePath", "uid", "gid", "mode", "members"},
                field,
            )
            family_id = source["id"]
            if not isinstance(family_id, str) or not SOURCE_ID_PATTERN.fullmatch(family_id):
                raise StateBackupError(f"{field}.id is not a safe stable identifier")
            if family_id in family_ids:
                raise StateBackupError("source family ids must be unique")
            family_ids.add(family_id)
            if len(families) >= MAX_FAMILIES:
                raise StateBackupError(f"source map exceeds {MAX_FAMILIES} families")
            family_path = _absolute_path(source["path"], f"{field}.path")
            family_restore_path = _restore_path(
                source["restorePath"], f"{field}.restorePath"
            )
            if family_restore_path.parts[0] in {
                RESTORE_JOURNAL_NAME,
                RESTORE_JOURNAL_PENDING_NAME,
            }:
                raise StateBackupError(f"{field}.restorePath collides with restore control state")
            uid = _identity_int(source["uid"], f"{field}.uid")
            gid = _identity_int(source["gid"], f"{field}.gid")
            if os.geteuid() != 0 and uid != os.geteuid():
                raise StateBackupError("a non-root source map may include only files owned by its uid")
            family_mode = _parse_family_mode(source["mode"], f"{field}.mode")
            raw_members = source["members"]
            if (
                not isinstance(raw_members, list)
                or not 0 < len(raw_members) <= MAX_FAMILY_MEMBERS
            ):
                raise StateBackupError(
                    f"{field}.members must contain between 1 and {MAX_FAMILY_MEMBERS} entries"
                )
            family_members: list[SourceSpec] = []
            member_ids: set[str] = set()
            member_names: set[str] = set()
            for member_index, raw_member in enumerate(raw_members):
                member_field = f"{field}.members[{member_index}]"
                member = _require_exact_keys(
                    raw_member,
                    {"id", "name", "kind", "mode", "maxBytes", "required"},
                    member_field,
                )
                member_id = member["id"]
                if not isinstance(member_id, str) or not SOURCE_ID_PATTERN.fullmatch(member_id):
                    raise StateBackupError(f"{member_field}.id is not a safe stable identifier")
                name = _family_member_name(member["name"], f"{member_field}.name")
                if member_id in member_ids or name in member_names:
                    raise StateBackupError("family member ids and names must each be unique")
                member_ids.add(member_id)
                member_names.add(name)
                kind = member["kind"]
                if not isinstance(kind, str) or kind not in FAMILY_MEMBER_KINDS:
                    raise StateBackupError(f"{member_field}.kind must be json or jsonl")
                source_id = f"{family_id}.{member_id}"
                if not SOURCE_ID_PATTERN.fullmatch(source_id):
                    raise StateBackupError(f"{member_field}.id makes the family id too long")
                member_spec = SourceSpec(
                    source_id=source_id,
                    kind=kind,
                    path=_absolute_path(str(family_path / name), f"{member_field}.name"),
                    restore_path=_restore_path(
                        str(family_restore_path / name), f"{member_field}.name"
                    ),
                    uid=uid,
                    gid=gid,
                    mode=_parse_mode(member["mode"], f"{member_field}.mode"),
                    max_bytes=_positive_int(
                        member["maxBytes"], f"{member_field}.maxBytes", MAX_SOURCE_BYTES
                    ),
                    required=_boolean(member["required"], f"{member_field}.required"),
                    family_id=family_id,
                )
                register(member_spec, member_field)
                family_members.append(member_spec)
            if not any(member.required for member in family_members):
                raise StateBackupError(f"{field} must contain at least one required member")
            families.append(
                SourceFamily(
                    family_id=family_id,
                    path=family_path,
                    restore_path=family_restore_path,
                    uid=uid,
                    gid=gid,
                    mode=family_mode,
                    members=tuple(family_members),
                )
            )
            continue

        source = _require_exact_keys(
            raw_source,
            {"id", "kind", "path", "restorePath", "uid", "gid", "mode", "maxBytes"},
            field,
        )
        source_id = source["id"]
        kind = source["kind"]
        if not isinstance(source_id, str) or not SOURCE_ID_PATTERN.fullmatch(source_id):
            raise StateBackupError(f"{field}.id is not a safe stable identifier")
        if not isinstance(kind, str) or kind not in SOURCE_KINDS:
            raise StateBackupError(f"{field}.kind must be json, jsonl, or sqlite")
        path_value = _absolute_path(source["path"], f"{field}.path")
        restore_value = _restore_path(source["restorePath"], f"{field}.restorePath")
        uid = _identity_int(source["uid"], f"{field}.uid")
        gid = _identity_int(source["gid"], f"{field}.gid")
        if os.geteuid() != 0 and uid != os.geteuid():
            raise StateBackupError("a non-root source map may include only files owned by its uid")
        mode = _parse_mode(source["mode"], f"{field}.mode")
        max_bytes = _positive_int(source["maxBytes"], f"{field}.maxBytes", MAX_SOURCE_BYTES)
        register(
            SourceSpec(
                source_id=source_id,
                kind=kind,
                path=path_value,
                restore_path=restore_value,
                uid=uid,
                gid=gid,
                mode=mode,
                max_bytes=max_bytes,
            ),
            field,
        )

    for family_index, family in enumerate(families):
        for other_family in families[family_index + 1 :]:
            if (
                family.path == other_family.path
                or family.restore_path == other_family.restore_path
                or family.path in other_family.path.parents
                or other_family.path in family.path.parents
                or family.restore_path in other_family.restore_path.parents
                or other_family.restore_path in family.restore_path.parents
            ):
                raise StateBackupError("source families must not be nested")
        for spec in specs:
            if spec.family_id != family.family_id and (
                family.path in spec.path.parents
                or family.restore_path in spec.restore_path.parents
            ):
                raise StateBackupError("a source family must exhaustively own its directory")

    for left in restore_paths:
        for right in restore_paths:
            if left != right and left in right.parents:
                raise StateBackupError("one restore file path must not be the parent of another")
    restore_directories = {
        str(PurePosixPath(*path.parts[:index]))
        for path in restore_paths
        for index in range(1, len(path.parts))
    }
    if len(restore_directories) > MAX_RESTORE_DIRECTORIES:
        raise StateBackupError("source map restore directory count exceeds the journal bound")
    return SourcePlan(
        tuple(specs), hashlib.sha256(raw).hexdigest(), raw, tuple(families)
    )


def _validate_json_payload(payload: bytes, kind: str, field: str) -> None:
    if kind == "json":
        _decode_json(payload, field)
        return
    if kind != "jsonl":
        raise StateBackupError(f"unsupported JSON validation kind: {kind}")
    if not payload:
        return
    if not payload.endswith(b"\n"):
        raise StateBackupError(f"{field} must end with a complete newline-delimited record")
    lines = payload.splitlines()
    if len(lines) > MAX_JSONL_RECORDS:
        raise StateBackupError(f"{field} exceeds the JSONL record count bound")
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise StateBackupError(f"{field} contains a blank JSONL row at line {line_number}")
        if len(line) > MAX_JSONL_LINE_BYTES:
            raise StateBackupError(f"{field} contains an oversized JSONL row at line {line_number}")
        _decode_json(line, f"{field} line {line_number}")


def _capture_plain_source(spec: SourceSpec) -> SourceSnapshot:
    descriptor, metadata = _open_checked_regular(
        spec.path,
        expected_uid=spec.uid,
        expected_gid=spec.gid,
        expected_mode=spec.mode,
        max_bytes=spec.max_bytes,
        allow_empty=spec.kind == "jsonl",
    )
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, spec.source_id)
        if not _same_opened_file(spec.path, descriptor, metadata, content=True):
            raise StateBackupError(f"source changed during snapshot: {spec.path}")
    finally:
        os.close(descriptor)
    _validate_json_payload(payload, spec.kind, spec.source_id)
    return SourceSnapshot(
        spec,
        payload,
        metadata.st_mtime_ns,
        (metadata.st_dev, metadata.st_ino),
    )


def _capture_family(family: SourceFamily) -> tuple[SourceSnapshot, ...]:
    descriptor, directory_metadata = _open_checked_directory(
        family.path,
        expected_uid=family.uid,
        expected_gid=family.gid,
        expected_mode=family.mode,
    )
    snapshots: list[SourceSnapshot] = []
    captured_metadata: dict[str, os.stat_result] = {}
    expected_names = {member.path.name for member in family.members}
    try:
        try:
            initial_names = set(os.listdir(descriptor))
        except OSError as error:
            raise StateBackupError(
                f"family directory could not be enumerated: {family.path}"
            ) from error
        unexpected = initial_names - expected_names
        if unexpected:
            raise StateBackupError(
                f"family directory contains an unreviewed entry: {family.path}"
            )
        initial_members: dict[str, os.stat_result] = {}
        for name in initial_names:
            try:
                initial_members[name] = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
            except OSError as error:
                raise StateBackupError(
                    f"family member changed during preflight: {family.path / name}"
                ) from error
        for spec in family.members:
            opened = _open_checked_family_member(descriptor, spec)
            if opened is None:
                if spec.path.name in initial_members:
                    raise StateBackupError(
                        f"family member changed during snapshot: {spec.path}"
                    )
                continue
            member_descriptor, metadata = opened
            preflight = initial_members.get(spec.path.name)
            if preflight is None or (
                preflight.st_dev,
                preflight.st_ino,
                preflight.st_mode,
                preflight.st_nlink,
                preflight.st_uid,
                preflight.st_gid,
                preflight.st_size,
                preflight.st_mtime_ns,
                preflight.st_ctime_ns,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ):
                os.close(member_descriptor)
                raise StateBackupError(
                    f"family member changed after preflight: {spec.path}"
                )
            try:
                payload = _read_descriptor(
                    member_descriptor, metadata.st_size, spec.source_id
                )
                if not _same_opened_family_member(
                    descriptor,
                    spec.path.name,
                    member_descriptor,
                    metadata,
                ):
                    raise StateBackupError(
                        f"family member changed during snapshot: {spec.path}"
                    )
            finally:
                os.close(member_descriptor)
            _validate_json_payload(payload, spec.kind, spec.source_id)
            snapshots.append(
                SourceSnapshot(
                    spec,
                    payload,
                    metadata.st_mtime_ns,
                    (metadata.st_dev, metadata.st_ino),
                )
            )
            captured_metadata[spec.source_id] = metadata

        reopened: list[tuple[SourceSnapshot, int]] = []
        try:
            for snapshot in snapshots:
                opened = _open_checked_family_member(descriptor, snapshot.spec)
                if opened is None:
                    raise StateBackupError(
                        f"family member disappeared before final revalidation: "
                        f"{snapshot.spec.path}"
                    )
                member_descriptor, _ = opened
                reopened.append((snapshot, member_descriptor))
                if not _same_opened_family_member(
                    descriptor,
                    snapshot.spec.path.name,
                    member_descriptor,
                    captured_metadata[snapshot.spec.source_id],
                ):
                    raise StateBackupError(
                        f"family member changed before final revalidation: "
                        f"{snapshot.spec.path}"
                    )

            for snapshot, member_descriptor in reopened:
                digest = _hash_descriptor(
                    member_descriptor,
                    len(snapshot.payload),
                    snapshot.spec.source_id,
                )
                if not secrets.compare_digest(
                    digest,
                    hashlib.sha256(snapshot.payload).digest(),
                ):
                    raise StateBackupError(
                        f"family member content changed during final revalidation: "
                        f"{snapshot.spec.path}"
                    )

            for snapshot, member_descriptor in reopened:
                if not _same_opened_family_member(
                    descriptor,
                    snapshot.spec.path.name,
                    member_descriptor,
                    captured_metadata[snapshot.spec.source_id],
                ):
                    raise StateBackupError(
                        f"family member changed during final revalidation: "
                        f"{snapshot.spec.path}"
                    )
        finally:
            for _, member_descriptor in reopened:
                os.close(member_descriptor)

        try:
            final_names = set(os.listdir(descriptor))
        except OSError as error:
            raise StateBackupError(
                f"family directory could not be re-enumerated: {family.path}"
            ) from error
        if final_names != initial_names or not _same_opened_directory(
            family.path, descriptor, directory_metadata
        ):
            raise StateBackupError(
                f"family directory changed during quiesced snapshot: {family.path}"
            )
    finally:
        os.close(descriptor)
    return tuple(snapshots)


def _validate_sqlite_companions(spec: SourceSpec) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{spec.path}{suffix}")
        if not os.path.lexists(companion):
            continue
        descriptor, _ = _open_checked_regular(
            companion,
            expected_uid=spec.uid,
            expected_gid=spec.gid,
            expected_mode=spec.mode,
            max_bytes=spec.max_bytes,
            allow_empty=True,
        )
        os.close(descriptor)


def _sqlite_integrity(connection: sqlite3.Connection, field: str) -> None:
    try:
        rows = connection.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error as error:
        raise StateBackupError(f"SQLite integrity check failed for {field}") from error
    if rows != [("ok",)]:
        raise StateBackupError(f"SQLite integrity check did not return exactly ok for {field}")


def _capture_sqlite_source(spec: SourceSpec, scratch_directory: Path) -> SourceSnapshot:
    descriptor, metadata = _open_checked_regular(
        spec.path,
        expected_uid=spec.uid,
        expected_gid=spec.gid,
        expected_mode=spec.mode,
        max_bytes=spec.max_bytes,
        allow_empty=False,
    )
    _validate_sqlite_companions(spec)
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    snapshot_path, snapshot_descriptor = _allocate_temporary(
        scratch_directory, f"{spec.source_id}.sqlite-snapshot"
    )
    os.close(snapshot_descriptor)
    try:
        uri = f"file:{quote(str(spec.path), safe='/')}?mode=ro"
        source = sqlite3.connect(uri, uri=True, timeout=5.0)
        source.execute("PRAGMA query_only=ON")
        source.execute("PRAGMA trusted_schema=OFF")
        page_size_row = source.execute("PRAGMA page_size").fetchone()
        if not page_size_row or not isinstance(page_size_row[0], int) or page_size_row[0] <= 0:
            raise StateBackupError(f"SQLite page size is invalid: {spec.path}")
        page_size = page_size_row[0]
        deadline = time.monotonic() + SQLITE_BACKUP_TIMEOUT_SECONDS

        def progress(_status: int, _remaining: int, total: int) -> None:
            if time.monotonic() > deadline:
                raise StateBackupError(f"SQLite online backup exceeded its deadline: {spec.path}")
            if total < 0 or total * page_size > spec.max_bytes:
                raise StateBackupError(f"SQLite snapshot exceeds configured maxBytes: {spec.path}")

        destination = sqlite3.connect(snapshot_path)
        destination.execute("PRAGMA trusted_schema=OFF")
        source.backup(destination, pages=256, progress=progress, sleep=0.05)
        destination.commit()
        journal_mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()
        if journal_mode != ("delete",):
            raise StateBackupError(f"SQLite snapshot could not leave WAL mode: {spec.path}")
        _sqlite_integrity(destination, spec.source_id)
        destination.close()
        destination = None
        snapshot_read_descriptor, snapshot_metadata = _open_checked_regular(
            snapshot_path,
            expected_uid=os.geteuid(),
            expected_gid=None,
            expected_mode=0o600,
            max_bytes=spec.max_bytes,
            allow_empty=False,
        )
        try:
            os.fsync(snapshot_read_descriptor)
            payload = _read_descriptor(
                snapshot_read_descriptor, snapshot_metadata.st_size, spec.source_id
            )
            if not _same_opened_file(
                snapshot_path, snapshot_read_descriptor, snapshot_metadata, content=True
            ):
                raise StateBackupError("private SQLite snapshot changed while it was read")
        finally:
            os.close(snapshot_read_descriptor)
        _validate_sqlite_payload(payload, spec.source_id)
        _validate_sqlite_companions(spec)
        if not _same_opened_file(spec.path, descriptor, metadata, content=False):
            raise StateBackupError(f"SQLite source path changed during snapshot: {spec.path}")
        return SourceSnapshot(
            spec,
            payload,
            metadata.st_mtime_ns,
            (metadata.st_dev, metadata.st_ino),
        )
    except sqlite3.Error as error:
        raise StateBackupError(f"SQLite online backup failed: {spec.path}") from error
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
        os.close(descriptor)
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                Path(f"{snapshot_path}{suffix}").unlink()
            except FileNotFoundError:
                pass


def _validate_sqlite_payload(payload: bytes, field: str) -> None:
    if not hasattr(sqlite3.Connection, "deserialize"):
        raise StateBackupError("this Python SQLite build cannot verify an in-memory backup")
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(payload)
        _sqlite_integrity(connection, field)
    except sqlite3.Error as error:
        raise StateBackupError(f"SQLite snapshot is invalid: {field}") from error
    finally:
        connection.close()


def _capture_sources(plan: SourcePlan, scratch_directory: Path) -> tuple[SourceSnapshot, ...]:
    snapshots: list[SourceSnapshot] = []
    identities: set[tuple[int, int]] = set()
    total = 0
    families = {family.family_id: family for family in plan.families}
    captured_families: set[str] = set()
    for spec in plan.sources:
        if spec.family_id is not None:
            if spec.family_id in captured_families:
                continue
            captured_families.add(spec.family_id)
            family_snapshots = _capture_family(families[spec.family_id])
        else:
            family_snapshots = (
                _capture_sqlite_source(spec, scratch_directory)
                if spec.kind == "sqlite"
                else _capture_plain_source(spec),
            )
        for snapshot in family_snapshots:
            if snapshot.identity in identities:
                raise StateBackupError("the source map resolves multiple entries to one inode")
            identities.add(snapshot.identity)
            total += len(snapshot.payload)
            if total > MAX_TOTAL_BYTES:
                raise StateBackupError("captured sources exceed the global byte limit")
            snapshots.append(snapshot)
    return tuple(snapshots)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _created_epoch(value: str) -> int:
    if not UTC_PATTERN.fullmatch(value):
        raise StateBackupError("manifest createdAt must be second-precision UTC")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise StateBackupError("manifest createdAt is invalid") from error
    return int(parsed.timestamp())


def _build_manifest(plan: SourcePlan, snapshots: Sequence[SourceSnapshot], created_at: str) -> bytes:
    manifest = {
        "createdAt": created_at,
        "format": FORMAT_NAME,
        "schemaVersion": SCHEMA_VERSION,
        "sourceMapSha256": plan.sha256,
        "sources": [
            {
                "archivePath": snapshot.spec.archive_path,
                "id": snapshot.spec.source_id,
                "kind": snapshot.spec.kind,
                "metadata": {
                    "gid": snapshot.spec.gid,
                    "mode": f"{snapshot.spec.mode:04o}",
                    "mtimeNs": snapshot.mtime_ns,
                    "uid": snapshot.spec.uid,
                },
                "restorePath": str(snapshot.spec.restore_path),
                "sha256": hashlib.sha256(snapshot.payload).hexdigest(),
                "size": len(snapshot.payload),
            }
            for snapshot in snapshots
        ],
    }
    payload = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8") + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise StateBackupError("generated manifest exceeds its byte limit")
    return payload


def _validate_private_directory(path: Path, owner_uid: int) -> None:
    _validate_absolute_no_symlinks(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"private directory is unavailable: {path}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StateBackupError(f"directory must be owner-controlled mode 0700: {path}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_auxiliary(path: Path, *, private: bool) -> int:
    _validate_absolute_no_symlinks(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"cryptographic input is unavailable: {path}") from error
    permitted_owners = {0, os.geteuid()}
    mode = stat.S_IMODE(metadata.st_mode)
    unsafe_mode = mode != 0o600 if private else bool(mode & 0o022)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in permitted_owners
        or unsafe_mode
        or not 0 < metadata.st_size <= MAX_AUXILIARY_BYTES
    ):
        raise StateBackupError(f"cryptographic input has unsafe metadata: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or opened.st_nlink != 1
        or opened.st_uid not in permitted_owners
        or (stat.S_IMODE(opened.st_mode) != 0o600 if private else bool(stat.S_IMODE(opened.st_mode) & 0o022))
    ):
        os.close(descriptor)
        raise StateBackupError(f"cryptographic input changed while it was opened: {path}")
    return descriptor


def _open_single_pem_certificate(path: Path, field: str) -> int:
    """Open one exact PEM certificate, never an attacker-selectable bundle."""

    descriptor = _open_auxiliary(path, private=False)
    metadata = os.fstat(descriptor)
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, field)
        if not _same_opened_file(path, descriptor, metadata, content=True):
            raise StateBackupError(f"{field} changed while it was read")
        if (
            payload.count(b"-----BEGIN CERTIFICATE-----") != 1
            or payload.count(b"-----END CERTIFICATE-----") != 1
            or re.fullmatch(
                rb"\s*-----BEGIN CERTIFICATE-----\r?\n"
                rb"[A-Za-z0-9+/=\r\n]+"
                rb"-----END CERTIFICATE-----\s*",
                payload,
            )
            is None
        ):
            raise StateBackupError(f"{field} must contain exactly one PEM certificate")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _openssl_path(explicit: Path | None) -> str:
    if explicit is not None:
        _validate_absolute_no_symlinks(explicit)
        return str(explicit)
    located = shutil.which("openssl")
    if located is None:
        raise StateBackupError("OpenSSL is required for CMS encryption")
    return located


def _tar_info(name: str, size: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = mtime
    info.type = tarfile.REGTYPE
    return info


def _write_plain_archive(
    destination: BinaryIO,
    manifest: bytes,
    snapshots: Sequence[SourceSnapshot],
    created_epoch: int,
) -> None:
    digest = hashlib.sha256(manifest).hexdigest().encode("ascii") + b"  manifest.json\n"
    gzip_stream = gzip.GzipFile(
        filename="", mode="wb", compresslevel=6, fileobj=destination, mtime=created_epoch
    )
    try:
        with tarfile.open(fileobj=gzip_stream, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            archive.addfile(_tar_info(MANIFEST_NAME, len(manifest), created_epoch), io.BytesIO(manifest))
            archive.addfile(
                _tar_info(MANIFEST_DIGEST_NAME, len(digest), created_epoch), io.BytesIO(digest)
            )
            for snapshot in snapshots:
                archive.addfile(
                    _tar_info(snapshot.spec.archive_path, len(snapshot.payload), created_epoch),
                    io.BytesIO(snapshot.payload),
                )
    finally:
        gzip_stream.close()


def _allocate_temporary(parent: Path, name: str) -> tuple[Path, int]:
    for _ in range(64):
        candidate = parent / f".{name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        os.fchmod(descriptor, 0o600)
        return candidate, descriptor
    raise StateBackupError("could not allocate a unique private temporary file")


def _publish_no_replace(temporary: Path, destination: Path) -> None:
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError as error:
        raise StateBackupError(f"refusing to replace an existing backup: {destination}") from error
    except OSError as error:
        raise StateBackupError(f"could not publish encrypted backup: {destination}") from error
    temporary.unlink()


def create_backup(
    source_map: Path,
    destination: Path,
    recipient_certificate: Path,
    *,
    signer_certificate: Path,
    signer_private_key: Path,
    map_owner_uid: int | None = None,
    confirm_quiesced: bool = False,
    openssl: Path | None = None,
) -> dict[str, Any]:
    """Create a signed, atomic CMS AES-256-GCM encrypted state backup."""

    _absolute_path(str(destination), "destination")
    _validate_private_directory(destination.parent, os.geteuid())
    if os.path.lexists(destination):
        raise StateBackupError(f"refusing to replace an existing backup: {destination}")
    plan = load_source_map(source_map, owner_uid=map_owner_uid)
    if plan.families and not confirm_quiesced:
        raise StateBackupError("family backup requires --confirm-quiesced")
    snapshots = _capture_sources(plan, destination.parent)
    created_at = _utc_now()
    created_epoch = _created_epoch(created_at)
    manifest = _build_manifest(plan, snapshots, created_at)

    recipient_descriptor = _open_auxiliary(recipient_certificate, private=False)
    signer_cert_descriptor = _open_single_pem_certificate(
        signer_certificate, "producer signer certificate"
    )
    signer_key_descriptor = _open_auxiliary(signer_private_key, private=True)
    temporary, output_descriptor = _allocate_temporary(destination.parent, destination.name)
    signer_process: subprocess.Popen[bytes] | None = None
    encryption_process: subprocess.Popen[bytes] | None = None
    committed = False
    try:
        binary = _openssl_path(openssl)
        signer_command = [
            binary,
            "cms",
            "-sign",
            "-binary",
            "-stream",
            "-outform",
            "DER",
            "-signer",
            f"/proc/self/fd/{signer_cert_descriptor}",
            "-inkey",
            f"/proc/self/fd/{signer_key_descriptor}",
            "-passin",
            "pass:",
            "-md",
            "sha256",
            "-nodetach",
            "-nocerts",
            "-noattr",
        ]
        encryption_command = [
            binary,
            "cms",
            "-encrypt",
            "-binary",
            "-stream",
            "-outform",
            "DER",
            "-aes-256-gcm",
            f"/proc/self/fd/{recipient_descriptor}",
        ]
        signer_process = subprocess.Popen(
            signer_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(signer_cert_descriptor, signer_key_descriptor),
        )
        assert signer_process.stdin is not None and signer_process.stdout is not None
        encryption_process = subprocess.Popen(
            encryption_command,
            stdin=signer_process.stdout,
            stdout=output_descriptor,
            stderr=subprocess.PIPE,
            pass_fds=(recipient_descriptor,),
        )
        signer_process.stdout.close()
        signer_process.stdout = None
        try:
            _write_plain_archive(signer_process.stdin, manifest, snapshots, created_epoch)
        finally:
            signer_process.stdin.close()
            signer_process.stdin = None
        _, signer_stderr = signer_process.communicate(timeout=OPENSSL_TIMEOUT_SECONDS)
        _, encryption_stderr = encryption_process.communicate(timeout=OPENSSL_TIMEOUT_SECONDS)
        if signer_process.returncode != 0 or encryption_process.returncode != 0:
            detail = (signer_stderr + encryption_stderr).decode("utf-8", "replace")[:512].strip()
            raise StateBackupError(
                f"OpenSSL CMS signing/encryption failed: {detail or 'unknown error'}"
            )
        metadata = os.fstat(output_descriptor)
        if not 0 < metadata.st_size <= MAX_ARCHIVE_BYTES:
            raise StateBackupError("encrypted archive size is outside the safe bound")
        os.fchmod(output_descriptor, 0o600)
        os.fsync(output_descriptor)
        os.close(output_descriptor)
        output_descriptor = -1
        _publish_no_replace(temporary, destination)
        _fsync_directory(destination.parent)
        committed = True
    except subprocess.TimeoutExpired as error:
        for process in (signer_process, encryption_process):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        raise StateBackupError("OpenSSL CMS signing/encryption exceeded its deadline") from error
    except (BrokenPipeError, OSError, tarfile.TarError) as error:
        for process in (signer_process, encryption_process):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        raise StateBackupError("encrypted archive streaming failed") from error
    finally:
        os.close(recipient_descriptor)
        os.close(signer_cert_descriptor)
        os.close(signer_key_descriptor)
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if not committed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return cast(dict[str, Any], _decode_json(manifest, "generated manifest"))


def _read_encrypted_archive(path: Path, owner_uid: int) -> bytes:
    descriptor, metadata = _open_checked_regular(
        path,
        expected_uid=owner_uid,
        expected_gid=None,
        expected_mode=0o600,
        max_bytes=MAX_ARCHIVE_BYTES,
        allow_empty=False,
    )
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, "encrypted archive")
        if not _same_opened_file(path, descriptor, metadata, content=True):
            raise StateBackupError("encrypted archive changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _run_openssl(
    command: Sequence[str],
    payload: bytes,
    *,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            check=False,
            pass_fds=tuple(pass_fds),
        )
    except subprocess.TimeoutExpired as error:
        raise StateBackupError("OpenSSL CMS operation exceeded its deadline") from error
    except OSError as error:
        raise StateBackupError("OpenSSL CMS operation could not start") from error


def _run_openssl_inspection(
    command: Sequence[str],
    payload: bytes,
) -> subprocess.CompletedProcess[bytes]:
    """Fully drain verbose CMS printing while retaining bounded head/tail text."""

    prefix_limit = 128 * 1024
    suffix_limit = 128 * 1024
    stderr_limit = 64 * 1024
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise StateBackupError("OpenSSL CMS inspection could not start") from error
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    prefix = bytearray()
    suffix = bytearray()
    stderr = bytearray()
    total_stdout = 0
    worker_errors: list[BaseException] = []

    def feed() -> None:
        try:
            view = memoryview(payload)
            while view:
                written = process.stdin.write(view[:READ_CHUNK_BYTES])
                if written is None or written <= 0:
                    break
                view = view[written:]
        except (BrokenPipeError, OSError):
            pass
        except BaseException as error:  # retained and re-raised on the caller thread
            worker_errors.append(error)
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def drain_stdout() -> None:
        nonlocal total_stdout
        try:
            while True:
                chunk = process.stdout.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total_stdout += len(chunk)
                if len(prefix) < prefix_limit:
                    prefix.extend(chunk[: prefix_limit - len(prefix)])
                suffix.extend(chunk)
                if len(suffix) > suffix_limit:
                    del suffix[: len(suffix) - suffix_limit]
        except BaseException as error:
            worker_errors.append(error)
        finally:
            process.stdout.close()

    def drain_stderr() -> None:
        try:
            while True:
                chunk = process.stderr.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                if len(stderr) < stderr_limit:
                    stderr.extend(chunk[: stderr_limit - len(stderr)])
        except BaseException as error:
            worker_errors.append(error)
        finally:
            process.stderr.close()

    workers = [
        threading.Thread(target=feed, daemon=True),
        threading.Thread(target=drain_stdout, daemon=True),
        threading.Thread(target=drain_stderr, daemon=True),
    ]
    for worker in workers:
        worker.start()
    try:
        returncode = process.wait(timeout=OPENSSL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        for worker in workers:
            worker.join(timeout=5.0)
        raise StateBackupError("OpenSSL CMS inspection exceeded its deadline") from error
    for worker in workers:
        worker.join(timeout=5.0)
    if any(worker.is_alive() for worker in workers):
        raise StateBackupError("OpenSSL CMS inspection pipe did not terminate")
    if worker_errors:
        raise StateBackupError("OpenSSL CMS inspection pipe failed") from worker_errors[0]

    if total_stdout <= prefix_limit:
        captured_stdout = bytes(prefix)
    else:
        overlap = max(0, len(prefix) + len(suffix) - total_stdout)
        marker = b"\n... bounded CMS inspection output omitted ...\n" if total_stdout > (
            len(prefix) + len(suffix)
        ) else b""
        captured_stdout = bytes(prefix) + marker + bytes(suffix[overlap:])
    return subprocess.CompletedProcess(command, returncode, captured_stdout, bytes(stderr))


def _decrypt_cms(
    ciphertext: bytes,
    recipient_certificate: Path,
    private_key: Path,
    openssl: Path | None,
) -> bytes:
    binary = _openssl_path(openssl)
    _validate_single_ber_value(ciphertext)
    inspection = _run_openssl_inspection(
        [binary, "cms", "-cmsout", "-inform", "DER", "-print", "-noout"], ciphertext
    )
    printed = inspection.stdout.decode("utf-8", "replace")
    if (
        inspection.returncode != 0
        or re.match(
            r"\ACMS_ContentInfo:\s*\n\s+contentType: "
            r"id-smime-ct-authEnvelopedData \(1\.2\.840\.113549\.1\.9\.16\.1\.23\)",
            printed,
        )
        is None
        or re.search(
            r"\n\s+authEncryptedContentInfo:\s*\n"
            r"\s+contentType: pkcs7-data \(1\.2\.840\.113549\.1\.7\.1\)\s*\n"
            r"\s+contentEncryptionAlgorithm:\s*\n"
            r"\s+algorithm: aes-256-gcm \(2\.16\.840\.1\.101\.3\.4\.1\.46\)",
            printed,
        )
        is None
    ):
        raise StateBackupError("archive is not OpenSSL CMS AuthEnvelopedData using AES-256-GCM")

    cert_descriptor = _open_auxiliary(recipient_certificate, private=False)
    key_descriptor = _open_auxiliary(private_key, private=True)
    try:
        result = _run_openssl(
            [
                binary,
                "cms",
                "-decrypt",
                "-binary",
                "-inform",
                "DER",
                "-recip",
                f"/proc/self/fd/{cert_descriptor}",
                "-inkey",
                f"/proc/self/fd/{key_descriptor}",
                "-passin",
                "pass:",
            ],
            ciphertext,
            pass_fds=(cert_descriptor, key_descriptor),
        )
    finally:
        os.close(cert_descriptor)
        os.close(key_descriptor)
    if result.returncode != 0:
        raise StateBackupError("CMS decryption or AES-GCM authentication failed")
    if not result.stdout or len(result.stdout) > MAX_PLAINTEXT_BYTES:
        raise StateBackupError("decrypted SignedData size exceeds the 64 MiB plaintext bound")
    return result.stdout


def _ber_value_end(payload: bytes, offset: int, depth: int, budget: list[int]) -> int:
    if depth > 64 or budget[0] <= 0 or offset >= len(payload):
        raise StateBackupError("CMS BER structure exceeds safe parser bounds")
    budget[0] -= 1
    first = payload[offset]
    offset += 1
    if first == 0:
        raise StateBackupError("unexpected BER end-of-content marker")
    if first & 0x1F == 0x1F:
        tag_octets = 0
        while True:
            if offset >= len(payload) or tag_octets >= 8:
                raise StateBackupError("invalid BER high-tag encoding")
            tag = payload[offset]
            offset += 1
            tag_octets += 1
            if not tag & 0x80:
                break
    if offset >= len(payload):
        raise StateBackupError("truncated BER length")
    length_first = payload[offset]
    offset += 1
    if length_first == 0x80:
        if not first & 0x20:
            raise StateBackupError("primitive BER value must not use indefinite length")
        while True:
            if offset + 2 > len(payload):
                raise StateBackupError("unterminated BER indefinite-length value")
            if payload[offset : offset + 2] == b"\x00\x00":
                return offset + 2
            offset = _ber_value_end(payload, offset, depth + 1, budget)
    if not length_first & 0x80:
        length = length_first
    else:
        length_octets = length_first & 0x7F
        if length_octets == 0 or length_octets > 8 or offset + length_octets > len(payload):
            raise StateBackupError("invalid BER definite length")
        encoded = payload[offset : offset + length_octets]
        if encoded[0] == 0:
            raise StateBackupError("non-minimal BER definite length")
        length = int.from_bytes(encoded, "big")
        offset += length_octets
    end = offset + length
    if end > len(payload):
        raise StateBackupError("truncated BER value")
    return end


def _validate_single_ber_value(payload: bytes) -> None:
    end = _ber_value_end(payload, 0, 0, [1_000_000])
    if end != len(payload):
        raise StateBackupError("CMS archive contains trailing or concatenated data")


def _verify_signed_cms(
    signed_content: bytes,
    signer_certificate: Path,
    openssl: Path | None,
) -> bytes:
    binary = _openssl_path(openssl)
    _validate_single_ber_value(signed_content)
    inspection = _run_openssl_inspection(
        [binary, "cms", "-cmsout", "-inform", "DER", "-print", "-noout"],
        signed_content,
    )
    printed = inspection.stdout.decode("utf-8", "replace")
    if (
        inspection.returncode != 0
        or re.match(
            r"\ACMS_ContentInfo:\s*\n\s+contentType: "
            r"pkcs7-signedData \(1\.2\.840\.113549\.1\.7\.2\)",
            printed,
        )
        is None
        or re.search(
            r"\n\s+digestAlgorithms:\s*\n"
            r"\s+algorithm: sha256 \(2\.16\.840\.1\.101\.3\.4\.2\.1\)",
            printed,
        )
        is None
        or re.search(
            r"\n\s+encapContentInfo:\s*\n"
            r"\s+eContentType: pkcs7-data \(1\.2\.840\.113549\.1\.7\.1\)",
            printed,
        )
        is None
        or re.search(r"\n\s+certificates:\s*\n\s+<ABSENT>", printed) is None
        or re.search(r"\n\s+crls:\s*\n\s+<ABSENT>", printed) is None
        or re.search(
            r"\n\s+digestAlgorithm:\s*\n"
            r"\s+algorithm: sha256 \(2\.16\.840\.1\.101\.3\.4\.2\.1\)",
            printed,
        )
        is None
        or re.search(r"\n\s+signedAttrs:\s*\n\s+<ABSENT>", printed) is None
    ):
        raise StateBackupError("decrypted content is not opaque CMS SignedData using SHA-256")
    signer_descriptor = _open_single_pem_certificate(
        signer_certificate, "pinned producer signer certificate"
    )
    try:
        result = _run_openssl(
            [
                binary,
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-noverify",
                "-nointern",
                "-certfile",
                f"/proc/self/fd/{signer_descriptor}",
            ],
            signed_content,
            pass_fds=(signer_descriptor,),
        )
    finally:
        os.close(signer_descriptor)
    if result.returncode != 0:
        raise StateBackupError("backup producer signature does not match the pinned signer")
    if not result.stdout or len(result.stdout) > MAX_PLAINTEXT_BYTES:
        raise StateBackupError("verified gzip stream exceeds the 64 MiB plaintext bound")
    return result.stdout


class _BoundedReader:
    def __init__(self, source: BinaryIO, limit: int):
        self.source = source
        self.limit = limit
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.count
        if remaining < 0:
            raise StateBackupError("decompressed tar exceeds the global byte bound")
        request = remaining + 1 if size < 0 else min(size, remaining + 1)
        payload = self.source.read(request)
        self.count += len(payload)
        if self.count > self.limit:
            raise StateBackupError("decompressed tar exceeds the global byte bound")
        return payload


def _safe_archive_name(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or len(name.encode("utf-8")) > MAX_PATH_BYTES:
        return False
    path = PurePosixPath(name)
    return str(path) == name and all(part not in {"", ".", ".."} for part in path.parts)


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size < 0 or member.size > limit:
        raise StateBackupError(f"archive member exceeds its bound: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise StateBackupError(f"archive member has no regular payload: {member.name}")
    payload = stream.read(member.size + 1)
    if len(payload) != member.size:
        raise StateBackupError(f"archive member size does not match its header: {member.name}")
    return payload


def _validate_manifest(
    payload: bytes,
    plan: SourcePlan,
) -> tuple[dict[str, Any], int, SourcePlan]:
    manifest = _require_exact_keys(
        _decode_json(payload, "manifest"),
        {"createdAt", "format", "schemaVersion", "sourceMapSha256", "sources"},
        "manifest",
    )
    if (
        manifest["format"] != FORMAT_NAME
        or type(manifest["schemaVersion"]) is not int
        or manifest["schemaVersion"] != SCHEMA_VERSION
    ):
        raise StateBackupError("manifest format or schemaVersion is unsupported")
    if manifest["sourceMapSha256"] != plan.sha256:
        raise StateBackupError("manifest does not match the trusted source map")
    created_at = manifest["createdAt"]
    if not isinstance(created_at, str):
        raise StateBackupError("manifest createdAt must be UTC text")
    created_epoch = _created_epoch(created_at)
    sources = manifest["sources"]
    if not isinstance(sources, list) or len(sources) > len(plan.sources):
        raise StateBackupError("manifest source count does not match the trusted source map")
    source_ids: list[str] = []
    for index, raw_entry in enumerate(sources):
        if not isinstance(raw_entry, dict) or not isinstance(raw_entry.get("id"), str):
            raise StateBackupError(f"manifest.sources[{index}] has no valid source id")
        source_ids.append(cast(str, raw_entry["id"]))
    resolved_plan = _resolve_plan_for_ids(plan, source_ids, "manifest")
    total = 0
    for index, (raw_entry, spec) in enumerate(
        zip(sources, resolved_plan.sources, strict=True)
    ):
        field = f"manifest.sources[{index}]"
        entry = _require_exact_keys(
            raw_entry,
            {"archivePath", "id", "kind", "metadata", "restorePath", "sha256", "size"},
            field,
        )
        metadata = _require_exact_keys(
            entry["metadata"], {"gid", "mode", "mtimeNs", "uid"}, f"{field}.metadata"
        )
        static_matches = (
            entry["archivePath"] == spec.archive_path
            and entry["id"] == spec.source_id
            and entry["kind"] == spec.kind
            and entry["restorePath"] == str(spec.restore_path)
            and metadata["uid"] == spec.uid
            and metadata["gid"] == spec.gid
            and metadata["mode"] == f"{spec.mode:04o}"
        )
        if not static_matches:
            raise StateBackupError(f"{field} does not match the trusted source map")
        size = entry["size"]
        mtime_ns = metadata["mtimeNs"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > spec.max_bytes
            or isinstance(mtime_ns, bool)
            or not isinstance(mtime_ns, int)
            or mtime_ns < 0
            or not isinstance(entry["sha256"], str)
            or not SHA256_PATTERN.fullmatch(entry["sha256"])
        ):
            raise StateBackupError(f"{field} contains invalid dynamic metadata")
        if spec.kind != "jsonl" and size == 0:
            raise StateBackupError(f"{field} must not be empty")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise StateBackupError("manifest source sizes exceed the global bound")
    return manifest, created_epoch, resolved_plan


def _resolve_plan_for_ids(
    plan: SourcePlan,
    source_ids: Sequence[str],
    field: str,
) -> SourcePlan:
    if len(source_ids) > len(plan.sources) or len(set(source_ids)) != len(source_ids):
        raise StateBackupError(f"{field} source ids are invalid")
    selected: list[SourceSpec] = []
    source_index = 0
    for spec in plan.sources:
        if source_index < len(source_ids) and source_ids[source_index] == spec.source_id:
            selected.append(spec)
            source_index += 1
        elif spec.required:
            raise StateBackupError(f"{field} omits required source {spec.source_id}")
    if source_index != len(source_ids):
        raise StateBackupError(f"{field} sources are unknown or out of trusted order")
    return dataclasses.replace(plan, sources=tuple(selected))


def _parse_plain_archive(plaintext: bytes, plan: SourcePlan) -> VerifiedBackup:
    expected_names = [MANIFEST_NAME, MANIFEST_DIGEST_NAME]
    member_limits = [MAX_MANIFEST_BYTES, 80]
    payloads: list[bytes] = []
    members: list[tarfile.TarInfo] = []
    manifest: dict[str, Any] | None = None
    created_epoch: int | None = None
    resolved_plan: SourcePlan | None = None
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(plaintext), mode="rb") as uncompressed:
            bounded = _BoundedReader(uncompressed, MAX_TAR_BYTES)
            with tarfile.open(fileobj=bounded, mode="r|", format=tarfile.USTAR_FORMAT) as archive:
                seen: set[str] = set()
                for index, member in enumerate(archive):
                    if index >= len(expected_names):
                        raise StateBackupError("archive contains unexpected extra members")
                    if not _safe_archive_name(member.name) or member.name in seen:
                        raise StateBackupError("archive contains traversal or duplicate member names")
                    seen.add(member.name)
                    if member.name != expected_names[index]:
                        raise StateBackupError("archive member set or order does not match the source map")
                    if (
                        not member.isreg()
                        or member.linkname
                        or member.pax_headers
                        or stat.S_IMODE(member.mode) != 0o600
                        or member.uid != 0
                        or member.gid != 0
                    ):
                        raise StateBackupError(f"archive member metadata is unsafe: {member.name}")
                    payloads.append(_read_tar_member(archive, member, member_limits[index]))
                    members.append(member)
                    if index == 1:
                        manifest_payload = payloads[0]
                        expected_digest = (
                            hashlib.sha256(manifest_payload).hexdigest().encode("ascii")
                            + b"  manifest.json\n"
                        )
                        if payloads[1] != expected_digest:
                            raise StateBackupError(
                                "manifest SHA-256 member does not match manifest.json"
                            )
                        manifest, created_epoch, resolved_plan = _validate_manifest(
                            manifest_payload, plan
                        )
                        expected_names.extend(
                            source.archive_path for source in resolved_plan.sources
                        )
                        member_limits.extend(
                            source.max_bytes for source in resolved_plan.sources
                        )
                if len(members) != len(expected_names):
                    raise StateBackupError("archive is missing required exact members")
            while True:
                tail = bounded.read(READ_CHUNK_BYTES)
                if not tail:
                    break
                if any(tail):
                    raise StateBackupError("archive has non-zero trailing tar data")
    except StateBackupError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError) as error:
        raise StateBackupError("decrypted content is not a valid bounded gzip tar archive") from error

    if manifest is None or created_epoch is None or resolved_plan is None:
        raise StateBackupError("archive is missing its manifest control members")
    for member in members:
        if int(member.mtime) != created_epoch:
            raise StateBackupError("archive member UTC metadata is inconsistent")
    data_payloads = tuple(payloads[2:])
    entries = cast(list[dict[str, Any]], manifest["sources"])
    for spec, entry, payload in zip(
        resolved_plan.sources, entries, data_payloads, strict=True
    ):
        if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise StateBackupError(f"archive hash or size mismatch for {spec.source_id}")
        if spec.kind == "sqlite":
            _validate_sqlite_payload(payload, spec.source_id)
        else:
            _validate_json_payload(payload, spec.kind, spec.source_id)
    return VerifiedBackup(manifest, resolved_plan, data_payloads, "")


def verify_backup(
    source_map: Path,
    archive: Path,
    recipient_certificate: Path,
    private_key: Path,
    signer_certificate: Path,
    *,
    map_owner_uid: int | None = None,
    archive_owner_uid: int | None = None,
    openssl: Path | None = None,
) -> VerifiedBackup:
    """Authenticate, decrypt, and fully validate an encrypted backup in memory."""

    plan = load_source_map(source_map, owner_uid=map_owner_uid)
    expected_archive_owner = os.geteuid() if archive_owner_uid is None else archive_owner_uid
    if os.geteuid() != 0 and expected_archive_owner != os.geteuid():
        raise StateBackupError("only root may verify an archive owned by another uid")
    ciphertext = _read_encrypted_archive(archive, expected_archive_owner)
    signed_content = _decrypt_cms(ciphertext, recipient_certificate, private_key, openssl)
    archive_sha256 = hashlib.sha256(ciphertext).hexdigest()
    ciphertext = b""
    plaintext = _verify_signed_cms(signed_content, signer_certificate, openssl)
    signed_content = b""
    return dataclasses.replace(
        _parse_plain_archive(plaintext, plan), archive_sha256=archive_sha256
    )


def _validate_restore_root(path: Path) -> None:
    _validate_absolute_no_symlinks(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"restore root is unavailable: {path}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise StateBackupError(
            "restore root must be operator-owned, real, and not writable by group or world"
        )


def _acquire_restore_root_lock(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise StateBackupError("restore root changed while acquiring its transaction lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise StateBackupError("another restore or recovery owns this target root") from error
    except StateBackupError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise StateBackupError("could not acquire the restore-root transaction lock") from error


def _journal_path(root: Path) -> Path:
    return root / RESTORE_JOURNAL_NAME


def _journal_pending_path(root: Path) -> Path:
    return root / RESTORE_JOURNAL_PENDING_NAME


def _identity_value(value: object, field: str) -> tuple[int, int] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 2:
        raise StateBackupError(f"{field} must be null or a [device,inode] pair")
    parsed: list[int] = []
    for index, member in enumerate(value):
        if (
            isinstance(member, bool)
            or not isinstance(member, int)
            or member < 0
            or member > 2**64 - 1
        ):
            raise StateBackupError(f"{field}[{index}] is not a safe filesystem identity")
        parsed.append(member)
    return parsed[0], parsed[1]


def _journal_relative(value: object, field: str) -> PurePosixPath:
    return _restore_path(value, field)


def _absolute_restore_path(root: Path, relative: PurePosixPath) -> Path:
    return root.joinpath(*relative.parts)


def _relative_restore_path(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise StateBackupError(f"restore path escapes target root: {path}") from error
    return str(PurePosixPath(*relative.parts))


def _restore_parent_exists_safely(root: Path, path: Path) -> bool:
    """Reject ancestor swaps; return False only for a genuinely missing parent."""

    try:
        relative_parent = path.parent.relative_to(root)
    except ValueError as error:
        raise StateBackupError(f"restore path escapes target root: {path}") from error
    current = root
    for component in relative_parent.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise StateBackupError(f"restore parent cannot be inspected: {current}") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise StateBackupError(f"restore parent is unsafe: {current}")
    return True


def _validate_stage_relative(value: object, spec: SourceSpec, field: str) -> PurePosixPath:
    relative = _journal_relative(value, field)
    target = spec.restore_path
    if relative.parent != target.parent:
        raise StateBackupError(f"{field} must be a sibling of its restore target")
    expected = re.compile(
        rf"^\.{re.escape(target.name)}\.restore\.tmp-[0-9]+-[0-9a-f]{{12}}$"
    )
    if not expected.fullmatch(relative.name):
        raise StateBackupError(f"{field} is not a tool-generated staging path")
    return relative


def _validate_preserved_relative(
    value: object, spec: SourceSpec, field: str
) -> PurePosixPath | None:
    if value is None:
        return None
    relative = _journal_relative(value, field)
    target = spec.restore_path
    if relative.parent != target.parent:
        raise StateBackupError(f"{field} must be a sibling of its restore target")
    expected = re.compile(
        rf"^\.{re.escape(target.name)}\.pre-restore-"
        r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$"
    )
    if not expected.fullmatch(relative.name):
        raise StateBackupError(f"{field} is not a tool-generated preservation path")
    return relative


def _validate_restore_journal(
    value: object,
    plan: SourcePlan,
    target_root: Path,
) -> dict[str, Any]:
    journal = _require_exact_keys(
        value,
        {
            "archiveSha256",
            "createdAt",
            "createdDirectories",
            "manifestCreatedAt",
            "operatorUid",
            "pendingAction",
            "records",
            "schemaVersion",
            "sourceMapSha256",
            "state",
            "targetRoot",
            "transactionId",
        },
        "restore journal",
    )
    if (
        type(journal["schemaVersion"]) is not int
        or journal["schemaVersion"] != RESTORE_JOURNAL_SCHEMA_VERSION
    ):
        raise StateBackupError("restore journal schemaVersion is unsupported")
    if journal["sourceMapSha256"] != plan.sha256:
        raise StateBackupError("restore journal does not match the trusted source map")
    if not isinstance(journal["targetRoot"], str) or journal["targetRoot"] != str(
        target_root
    ):
        raise StateBackupError("restore journal targetRoot does not match the requested root")
    if (
        isinstance(journal["operatorUid"], bool)
        or not isinstance(journal["operatorUid"], int)
        or journal["operatorUid"] != os.geteuid()
    ):
        raise StateBackupError("restore journal was not created by the current operator uid")
    if (
        not isinstance(journal["transactionId"], str)
        or not TRANSACTION_ID_PATTERN.fullmatch(journal["transactionId"])
    ):
        raise StateBackupError("restore journal transactionId is invalid")
    if (
        not isinstance(journal["archiveSha256"], str)
        or not SHA256_PATTERN.fullmatch(journal["archiveSha256"])
    ):
        raise StateBackupError("restore journal archiveSha256 is invalid")
    for field in ("createdAt", "manifestCreatedAt"):
        if not isinstance(journal[field], str):
            raise StateBackupError(f"restore journal {field} must be UTC text")
        _created_epoch(cast(str, journal[field]))
    if not isinstance(journal["state"], str) or journal["state"] not in RESTORE_JOURNAL_STATES:
        raise StateBackupError("restore journal state is invalid")

    pending = journal["pendingAction"]
    if pending is not None:
        pending_object = _require_exact_keys(pending, {"kind", "subject"}, "pendingAction")
        if (
            not isinstance(pending_object["kind"], str)
            or pending_object["kind"] not in RESTORE_ACTIONS
        ):
            raise StateBackupError("restore journal pending action is invalid")
        subject = pending_object["subject"]
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject.encode("utf-8")) > MAX_PATH_BYTES
        ):
            raise StateBackupError("restore journal pending action subject is invalid")

    raw_records = journal["records"]
    if not isinstance(raw_records, list) or len(raw_records) > len(plan.sources):
        raise StateBackupError("restore journal record count does not match the source map")
    record_ids: list[str] = []
    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict) or not isinstance(raw_record.get("id"), str):
            raise StateBackupError(f"restore journal records[{index}] has no valid source id")
        record_ids.append(cast(str, raw_record["id"]))
    effective_plan = _resolve_plan_for_ids(plan, record_ids, "restore journal")

    raw_directories = journal["createdDirectories"]
    if (
        not isinstance(raw_directories, list)
        or len(raw_directories) > MAX_RESTORE_DIRECTORIES
    ):
        raise StateBackupError("restore journal createdDirectories is invalid")
    allowed_directories = {
        str(PurePosixPath(*spec.restore_path.parts[:index]))
        for spec in effective_plan.sources
        for index in range(1, len(spec.restore_path.parts))
    }
    seen_directories: set[str] = set()
    for index, raw_directory in enumerate(raw_directories):
        relative = _journal_relative(raw_directory, f"createdDirectories[{index}]")
        text = str(relative)
        if text not in allowed_directories or text in seen_directories:
            raise StateBackupError("restore journal contains an unexpected created directory")
        seen_directories.add(text)

    for index, (raw_record, spec) in enumerate(
        zip(raw_records, effective_plan.sources, strict=True)
    ):
        field = f"restore journal records[{index}]"
        record = _require_exact_keys(
            raw_record,
            {
                "id",
                "installed",
                "oldIdentity",
                "oldSha256",
                "payloadSha256",
                "payloadSize",
                "preserved",
                "preservedPath",
                "restorePath",
                "stageIdentity",
                "stagePath",
                "targetExisted",
                "verified",
            },
            field,
        )
        if record["id"] != spec.source_id or record["restorePath"] != str(spec.restore_path):
            raise StateBackupError(f"{field} does not match the trusted source map")
        _validate_stage_relative(record["stagePath"], spec, f"{field}.stagePath")
        preserved_relative = _validate_preserved_relative(
            record["preservedPath"], spec, f"{field}.preservedPath"
        )
        old_identity = _identity_value(record["oldIdentity"], f"{field}.oldIdentity")
        stage_identity = _identity_value(record["stageIdentity"], f"{field}.stageIdentity")
        payload_size = record["payloadSize"]
        if (
            isinstance(payload_size, bool)
            or not isinstance(payload_size, int)
            or payload_size < 0
            or payload_size > spec.max_bytes
            or (spec.kind != "jsonl" and payload_size == 0)
            or not isinstance(record["payloadSha256"], str)
            or not SHA256_PATTERN.fullmatch(record["payloadSha256"])
        ):
            raise StateBackupError(f"{field} contains invalid payload metadata")
        if not isinstance(record["installed"], bool) or not isinstance(record["verified"], bool):
            raise StateBackupError(f"{field} install state must be boolean")
        if not isinstance(record["preserved"], bool):
            raise StateBackupError(f"{field}.preserved must be boolean")
        target_existed = record["targetExisted"]
        if target_existed is not None and not isinstance(target_existed, bool):
            raise StateBackupError(f"{field}.targetExisted must be boolean or null")
        old_hash = record["oldSha256"]
        if old_hash is not None and (
            not isinstance(old_hash, str) or not SHA256_PATTERN.fullmatch(old_hash)
        ):
            raise StateBackupError(f"{field}.oldSha256 is invalid")
        if target_existed is True:
            if old_identity is None or old_hash is None or preserved_relative is None:
                raise StateBackupError(f"{field} is missing existing-target rollback metadata")
        elif any(
            member is not None for member in (old_identity, old_hash, preserved_relative)
        ) or record["preserved"]:
            raise StateBackupError(f"{field} has rollback metadata for a clean or unplanned target")
        if record["installed"] and stage_identity is None:
            raise StateBackupError(f"{field} installed state lacks an inode identity")
        if record["verified"] and not record["installed"]:
            raise StateBackupError(f"{field} cannot be verified before installation")

    if journal["state"] == "committed" and any(
        not record["installed"] or not record["verified"]
        for record in cast(list[dict[str, Any]], raw_records)
    ):
        raise StateBackupError("committed restore journal has incomplete records")
    if journal["state"] == "rolled-back" and any(
        record["installed"]
        or record["verified"]
        or record["preserved"]
        or record["stageIdentity"] is not None
        for record in cast(list[dict[str, Any]], raw_records)
    ):
        raise StateBackupError("rolled-back restore journal has incomplete cleanup state")
    return journal


def _read_restore_journal(target_root: Path, plan: SourcePlan) -> dict[str, Any]:
    path = _journal_path(target_root)
    descriptor, metadata = _open_checked_regular(
        path,
        expected_uid=os.geteuid(),
        expected_gid=None,
        expected_mode=0o600,
        max_bytes=MAX_RESTORE_JOURNAL_BYTES,
        allow_empty=False,
    )
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, "restore journal")
        if not _same_opened_file(path, descriptor, metadata, content=True):
            raise StateBackupError("restore journal changed while it was read")
    finally:
        os.close(descriptor)
    return _validate_restore_journal(_decode_json(payload, "restore journal"), plan, target_root)


def _write_all(descriptor: int, payload: bytes, field: str) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise StateBackupError(f"short write while writing {field}")
        view = view[written:]


def _write_restore_journal(
    target_root: Path,
    plan: SourcePlan,
    journal: dict[str, Any],
    *,
    initial: bool = False,
) -> None:
    _validate_restore_journal(journal, plan, target_root)
    encoded = json.dumps(
        journal, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8") + b"\n"
    if not 0 < len(encoded) <= MAX_RESTORE_JOURNAL_BYTES:
        raise StateBackupError("restore journal exceeds its byte bound")
    journal_path = _journal_path(target_root)
    pending_path = _journal_pending_path(target_root)
    if os.path.lexists(pending_path):
        raise StateBackupError("a pending restore-journal update exists; explicit recovery is required")
    if initial:
        if os.path.lexists(journal_path):
            raise StateBackupError("an unfinished restore journal exists; run recover first")
    else:
        current = _read_restore_journal(target_root, plan)
        if current["transactionId"] != journal["transactionId"]:
            raise StateBackupError("restore journal transaction changed unexpectedly")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    owns_pending = False
    try:
        descriptor = os.open(pending_path, flags, 0o600)
        owns_pending = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded, "restore journal")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(pending_path, journal_path)
        _fsync_directory(target_root)
    except OSError as error:
        raise StateBackupError("could not durably update the restore journal") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if owns_pending and os.path.lexists(pending_path):
            try:
                pending_path.unlink()
                _fsync_directory(target_root)
            except OSError:
                pass


def _discard_pending_journal_update(target_root: Path) -> bool:
    path = _journal_pending_path(target_root)
    if not os.path.lexists(path):
        return False
    descriptor, metadata = _open_checked_regular(
        path,
        expected_uid=os.geteuid(),
        expected_gid=None,
        expected_mode=0o600,
        max_bytes=MAX_RESTORE_JOURNAL_BYTES,
        allow_empty=True,
    )
    try:
        if not _same_opened_file(path, descriptor, metadata, content=False):
            raise StateBackupError("pending restore-journal update changed while inspected")
        path.unlink()
        _fsync_directory(target_root)
    finally:
        os.close(descriptor)
    return True


def _journal_before_action(
    target_root: Path,
    plan: SourcePlan,
    journal: dict[str, Any],
    kind: str,
    subject: str,
) -> None:
    journal["pendingAction"] = {"kind": kind, "subject": subject}
    _write_restore_journal(target_root, plan, journal)


def _journal_after_action(
    target_root: Path,
    plan: SourcePlan,
    journal: dict[str, Any],
) -> None:
    journal["pendingAction"] = None
    _write_restore_journal(target_root, plan, journal)


def _family_for_restore_directory(
    plan: SourcePlan,
    relative: PurePosixPath,
) -> SourceFamily | None:
    return next(
        (family for family in plan.families if family.restore_path == relative),
        None,
    )


def _validate_family_directory_metadata(path: Path, family: SourceFamily) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"restored family directory is unavailable: {path}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != family.uid
        or metadata.st_gid != family.gid
        or stat.S_IMODE(metadata.st_mode) != family.mode
    ):
        raise StateBackupError(f"restored family directory metadata is unsafe: {path}")


def _apply_family_directory_metadata(path: Path, family: SourceFamily) -> None:
    effective_uid = os.geteuid()
    if effective_uid != 0:
        allowed_groups = {os.getegid(), *os.getgroups()}
        if family.uid != effective_uid or family.gid not in allowed_groups:
            raise StateBackupError("non-root restore cannot recreate family directory ownership")
    try:
        os.chown(path, family.uid, family.gid, follow_symlinks=False)
        os.chmod(path, family.mode, follow_symlinks=False)
        _fsync_directory(path)
    except OSError as error:
        raise StateBackupError("could not apply family directory ownership and mode") from error
    _validate_family_directory_metadata(path, family)


def _validate_restore_family_destinations(
    plan: SourcePlan,
    target_root: Path,
) -> None:
    selected_ids = {spec.source_id for spec in plan.sources}
    for family in plan.families:
        directory = _absolute_restore_path(target_root, family.restore_path)
        if not os.path.lexists(directory):
            continue
        if not _restore_parent_exists_safely(target_root, directory / ".family-boundary"):
            raise StateBackupError(f"restore family parent is unavailable: {directory}")
        _validate_family_directory_metadata(directory, family)
        try:
            names = set(os.listdir(directory))
        except OSError as error:
            raise StateBackupError(
                f"restore family directory cannot be enumerated: {directory}"
            ) from error
        reviewed_names = {member.path.name for member in family.members}
        if names - reviewed_names:
            raise StateBackupError(
                f"restore family directory contains an unreviewed entry: {directory}"
            )
        for member in family.members:
            if member.source_id not in selected_ids and member.path.name in names:
                raise StateBackupError(
                    f"restore destination contains a member absent from the backup: {member.path.name}"
                )


def _read_back_restored_families(
    plan: SourcePlan,
    target_root: Path,
    records: Sequence[dict[str, Any]],
) -> None:
    selected_ids = {spec.source_id for spec in plan.sources}
    preserved_by_parent: dict[PurePosixPath, set[str]] = {}
    for record in records:
        preserved = record["preservedPath"]
        if record["preserved"] and isinstance(preserved, str):
            path = _journal_relative(preserved, "preservedPath")
            preserved_by_parent.setdefault(path.parent, set()).add(path.name)
    for family in plan.families:
        directory = _absolute_restore_path(target_root, family.restore_path)
        _validate_family_directory_metadata(directory, family)
        expected_names = {
            member.path.name
            for member in family.members
            if member.source_id in selected_ids
        }
        expected_names.update(preserved_by_parent.get(family.restore_path, set()))
        try:
            actual_names = set(os.listdir(directory))
        except OSError as error:
            raise StateBackupError(
                f"restored family directory cannot be enumerated: {directory}"
            ) from error
        if actual_names != expected_names:
            raise StateBackupError(
                f"restored family directory does not match the signed family snapshot: {directory}"
            )


def _prepare_restore_parent_transaction(
    root: Path,
    relative: PurePosixPath,
    plan: SourcePlan,
    journal: dict[str, Any],
) -> Path:
    parent = root
    for component in relative.parts[:-1]:
        parent = parent / component
        relative_parent = PurePosixPath(*relative.parts[: len(parent.relative_to(root).parts)])
        family = _family_for_restore_directory(plan, relative_parent)
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            relative_parent_text = _relative_restore_path(root, parent)
            _journal_before_action(
                root, plan, journal, "create-directory", relative_parent_text
            )
            try:
                parent.mkdir(mode=0o700)
                os.chmod(parent, 0o700, follow_symlinks=False)
                if family is not None:
                    _apply_family_directory_metadata(parent, family)
                _fsync_directory(parent.parent)
            except OSError as error:
                raise StateBackupError(f"could not create restore directory: {parent}") from error
            cast(list[str], journal["createdDirectories"]).append(relative_parent_text)
            _journal_after_action(root, plan, journal)
            continue
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise StateBackupError(f"restore path contains an unsafe directory: {parent}")
        if family is not None:
            _validate_family_directory_metadata(parent, family)
    return parent


def _existing_restore_target(path: Path, spec: SourceSpec) -> os.stat_result | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"restore target cannot be inspected: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != spec.uid
        or metadata.st_gid != spec.gid
        or stat.S_IMODE(metadata.st_mode) != spec.mode
    ):
        raise StateBackupError(f"existing restore target has unsafe metadata: {path}")
    return metadata


def _reject_restore_sqlite_sidecars(path: Path, spec: SourceSpec) -> None:
    if spec.kind != "sqlite":
        return
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        if os.path.lexists(sidecar):
            raise StateBackupError(
                f"SQLite restore target has a sidecar; keep the service stopped and "
                f"checkpoint it through the owning service before recovery: {sidecar}"
            )


def _set_restored_ownership(descriptor: int, spec: SourceSpec) -> None:
    effective_uid = os.geteuid()
    if effective_uid != 0:
        allowed_groups = {os.getegid(), *os.getgroups()}
        if spec.uid != effective_uid or spec.gid not in allowed_groups:
            raise StateBackupError("non-root restore cannot recreate the manifest ownership")
    try:
        os.fchown(descriptor, spec.uid, spec.gid)
        os.fchmod(descriptor, spec.mode)
    except OSError as error:
        raise StateBackupError("could not apply restored ownership and mode") from error


def _allocate_restore_stage_path(
    parent: Path,
    target_name: str,
    *,
    forbidden: set[Path] | None = None,
) -> Path:
    for _ in range(64):
        stage = parent / (
            f".{target_name}.restore.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        )
        if len(stage.name.encode("utf-8")) > 255:
            raise StateBackupError("restore staging filename would exceed NAME_MAX")
        if not os.path.lexists(stage) and (forbidden is None or stage not in forbidden):
            return stage
    raise StateBackupError("could not allocate a restore staging path")


def _write_restore_stage(stage: Path, payload: bytes, spec: SourceSpec) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(stage, flags, 0o600)
    except OSError as error:
        raise StateBackupError(f"could not create restore staging file: {stage}") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StateBackupError("short write while staging restored state")
            view = view[written:]
        _set_restored_ownership(descriptor, spec)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino
    except Exception:
        try:
            stage.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def _hash_restore_file(path: Path, spec: SourceSpec) -> tuple[str, tuple[int, int]]:
    descriptor, metadata = _open_checked_regular(
        path,
        expected_uid=spec.uid,
        expected_gid=spec.gid,
        expected_mode=spec.mode,
        max_bytes=spec.max_bytes,
        allow_empty=spec.kind == "jsonl",
    )
    digest = hashlib.sha256()
    remaining = metadata.st_size
    try:
        while remaining:
            chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
            if not chunk:
                raise StateBackupError(f"file changed while hashing: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if not _same_opened_file(path, descriptor, metadata, content=True):
            raise StateBackupError(f"file changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), (metadata.st_dev, metadata.st_ino)


def _regular_file_identity(path: Path, field: str) -> tuple[int, int] | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"could not inspect {field}: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise StateBackupError(f"{field} is not a safe single-link regular file: {path}")
    return metadata.st_dev, metadata.st_ino


def _assert_identity(path: Path, expected: tuple[int, int], field: str) -> None:
    if _regular_file_identity(path, field) != expected:
        raise StateBackupError(f"{field} inode identity changed: {path}")


def _assert_hashed_restore_file(
    path: Path,
    spec: SourceSpec,
    expected_identity: tuple[int, int],
    expected_sha256: str,
    expected_size: int | None,
    field: str,
) -> None:
    digest, identity = _hash_restore_file(path, spec)
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError as error:
        raise StateBackupError(f"could not inspect {field} size: {path}") from error
    if (
        identity != expected_identity
        or not secrets.compare_digest(digest, expected_sha256)
        or (expected_size is not None and size != expected_size)
    ):
        raise StateBackupError(f"{field} identity, size, or hash changed: {path}")


def _allocate_preserved_path(
    target: Path,
    timestamp: str,
    *,
    forbidden: set[Path] | None = None,
) -> Path:
    compact = timestamp.replace("-", "").replace(":", "")
    for _ in range(64):
        candidate = target.parent / (
            f".{target.name}.pre-restore-{compact}-{secrets.token_hex(4)}"
        )
        if len(candidate.name.encode("utf-8")) > 255:
            raise StateBackupError("pre-restore preservation filename would exceed NAME_MAX")
        if not os.path.lexists(candidate) and (
            forbidden is None or candidate not in forbidden
        ):
            return candidate
    raise StateBackupError("could not allocate a pre-restore preservation path")


def _new_restore_journal(
    verified: VerifiedBackup,
    target_root: Path,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    reserved_paths = {
        _absolute_restore_path(target_root, spec.restore_path)
        for spec in verified.plan.sources
    }
    for spec, payload in zip(verified.plan.sources, verified.payloads, strict=True):
        target = _absolute_restore_path(target_root, spec.restore_path)
        stage = _allocate_restore_stage_path(
            target.parent, target.name, forbidden=reserved_paths
        )
        reserved_paths.add(stage)
        records.append(
            {
                "id": spec.source_id,
                "installed": False,
                "oldIdentity": None,
                "oldSha256": None,
                "payloadSha256": hashlib.sha256(payload).hexdigest(),
                "payloadSize": len(payload),
                "preserved": False,
                "preservedPath": None,
                "restorePath": str(spec.restore_path),
                "stageIdentity": None,
                "stagePath": _relative_restore_path(target_root, stage),
                "targetExisted": None,
                "verified": False,
            }
        )
    journal: dict[str, Any] = {
        "archiveSha256": verified.archive_sha256,
        "createdAt": _utc_now(),
        "createdDirectories": [],
        "manifestCreatedAt": verified.manifest["createdAt"],
        "operatorUid": os.geteuid(),
        "pendingAction": None,
        "records": records,
        "schemaVersion": RESTORE_JOURNAL_SCHEMA_VERSION,
        "sourceMapSha256": verified.plan.sha256,
        "state": "active",
        "targetRoot": str(target_root),
        "transactionId": secrets.token_hex(16),
    }
    return _validate_restore_journal(journal, verified.plan, target_root)


def _preserve_existing_target(target: Path, destination: Path) -> None:
    os.rename(target, destination)


def _install_staged_file(stage: Path, target: Path) -> None:
    os.replace(stage, target)


def _unlink_installed(path: Path, identity: tuple[int, int]) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != identity
    ):
        raise StateBackupError(f"installed restore target changed before rollback: {path}")
    path.unlink()


def _read_back_restored_target(record: _RestoreRecord, expected_payload: bytes) -> None:
    descriptor, metadata = _open_checked_regular(
        record.target,
        expected_uid=record.spec.uid,
        expected_gid=record.spec.gid,
        expected_mode=record.spec.mode,
        max_bytes=record.spec.max_bytes,
        allow_empty=record.spec.kind == "jsonl",
    )
    try:
        payload = _read_descriptor(descriptor, metadata.st_size, str(record.target))
        if not _same_opened_file(record.target, descriptor, metadata, content=True):
            raise StateBackupError(f"restored target changed during readback: {record.target}")
    finally:
        os.close(descriptor)
    if not secrets.compare_digest(
        hashlib.sha256(payload).digest(), hashlib.sha256(expected_payload).digest()
    ) or len(payload) != len(expected_payload):
        raise StateBackupError(f"restored target failed byte-exact readback: {record.target}")
    if record.spec.kind == "sqlite":
        _validate_sqlite_payload(payload, str(record.target))
    else:
        _validate_json_payload(payload, record.spec.kind, str(record.target))


def _remove_restore_journal(
    target_root: Path,
    plan: SourcePlan,
    transaction_id: str,
) -> None:
    current = _read_restore_journal(target_root, plan)
    if current["transactionId"] != transaction_id:
        raise StateBackupError("restore journal transaction changed before cleanup")
    path = _journal_path(target_root)
    identity = _regular_file_identity(path, "restore journal")
    if identity is None:
        raise StateBackupError("restore journal disappeared before cleanup")
    try:
        _assert_identity(path, identity, "restore journal")
        path.unlink()
        _fsync_directory(target_root)
    except OSError as error:
        raise StateBackupError("could not durably remove the restore journal") from error


def _record_paths(
    target_root: Path,
    spec: SourceSpec,
    record: dict[str, Any],
) -> tuple[Path, Path, Path | None]:
    target = _absolute_restore_path(target_root, spec.restore_path)
    stage_relative = _validate_stage_relative(record["stagePath"], spec, "stagePath")
    preserved_relative = _validate_preserved_relative(
        record["preservedPath"], spec, "preservedPath"
    )
    return (
        target,
        _absolute_restore_path(target_root, stage_relative),
        (
            _absolute_restore_path(target_root, preserved_relative)
            if preserved_relative is not None
            else None
        ),
    )


def _stage_partial_is_safe(
    path: Path,
    spec: SourceSpec,
    payload_size: int,
) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise StateBackupError(f"could not inspect interrupted restore stage: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {os.geteuid(), spec.uid}
        or stat.S_IMODE(metadata.st_mode) not in {0o600, spec.mode}
        or metadata.st_size < 0
        or metadata.st_size > payload_size
    ):
        raise StateBackupError(f"interrupted restore stage has unsafe metadata: {path}")
    return metadata.st_dev, metadata.st_ino


def _rollback_restore_journal(
    target_root: Path,
    plan: SourcePlan,
    journal: dict[str, Any],
) -> tuple[Path, ...]:
    if journal["state"] == "committed":
        raise StateBackupError("a committed restore transaction must be finalized, not rolled back")
    original_pending = journal["pendingAction"]
    pending_directory = (
        original_pending["subject"]
        if isinstance(original_pending, dict)
        and original_pending.get("kind") == "create-directory"
        else None
    )
    records = cast(list[dict[str, Any]], journal["records"])
    touched: list[Path] = []

    for spec, record in reversed(tuple(zip(plan.sources, records, strict=True))):
        target, stage, preserved = _record_paths(target_root, spec, record)
        _restore_parent_exists_safely(target_root, target)
        if record["targetExisted"] is not None or record["stageIdentity"] is not None:
            _reject_restore_sqlite_sidecars(target, spec)
        touched.append(target)
        stage_identity = _identity_value(record["stageIdentity"], "stageIdentity")
        old_identity = _identity_value(record["oldIdentity"], "oldIdentity")
        target_identity = _regular_file_identity(target, "restore target")
        old_at_target = False

        if target_identity is not None:
            if old_identity is not None and target_identity == old_identity:
                _assert_hashed_restore_file(
                    target,
                    spec,
                    old_identity,
                    cast(str, record["oldSha256"]),
                    None,
                    "original restore target",
                )
                old_at_target = True
            elif stage_identity is not None and target_identity == stage_identity:
                _assert_hashed_restore_file(
                    target,
                    spec,
                    stage_identity,
                    cast(str, record["payloadSha256"]),
                    cast(int, record["payloadSize"]),
                    "installed restore target",
                )
                _journal_before_action(
                    target_root, plan, journal, "rollback-target", spec.source_id
                )
                _unlink_installed(target, stage_identity)
                _fsync_directory(target.parent)
                record["installed"] = False
                record["verified"] = False
                record["stageIdentity"] = None
                _journal_after_action(target_root, plan, journal)
                target_identity = None
                stage_identity = None
            elif record["targetExisted"] is None:
                # Target discovery had not completed, so this path was never
                # selected for mutation by the interrupted transaction.
                old_at_target = True
            else:
                raise StateBackupError(
                    f"restore target has an unknown inode during rollback: {target}"
                )

        preserved_identity = (
            _regular_file_identity(preserved, "preserved restore target")
            if preserved is not None
            else None
        )
        if preserved_identity is not None:
            if old_identity is None or preserved_identity != old_identity:
                raise StateBackupError(
                    f"preserved restore target has an unknown inode: {preserved}"
                )
            _assert_hashed_restore_file(
                cast(Path, preserved),
                spec,
                old_identity,
                cast(str, record["oldSha256"]),
                None,
                "preserved restore target",
            )

        if record["targetExisted"] is True:
            if old_at_target:
                if preserved_identity is not None:
                    raise StateBackupError(
                        f"original target exists in two locations during rollback: {target}"
                    )
                record["preserved"] = False
            else:
                if preserved is None or preserved_identity is None or old_identity is None:
                    raise StateBackupError(
                        f"original target is unavailable for rollback: {target}"
                    )
                if os.path.lexists(target):
                    raise StateBackupError(
                        f"rollback target unexpectedly exists before preservation restore: {target}"
                    )
                _journal_before_action(
                    target_root, plan, journal, "rollback-preserved", spec.source_id
                )
                os.replace(preserved, target)
                _fsync_directory(target.parent)
                _assert_hashed_restore_file(
                    target,
                    spec,
                    old_identity,
                    cast(str, record["oldSha256"]),
                    None,
                    "rolled-back restore target",
                )
                record["preserved"] = False
                record["installed"] = False
                record["verified"] = False
                _journal_after_action(target_root, plan, journal)
        elif record["targetExisted"] is False:
            if os.path.lexists(target):
                raise StateBackupError(f"clean restore target survived rollback: {target}")
            record["installed"] = False
            record["verified"] = False

        if os.path.lexists(stage):
            current_stage_identity = _regular_file_identity(stage, "restore stage")
            if current_stage_identity is None:
                raise StateBackupError(f"restore stage disappeared during rollback: {stage}")
            if stage_identity is not None:
                if current_stage_identity != stage_identity:
                    raise StateBackupError(f"restore stage inode changed: {stage}")
                _assert_hashed_restore_file(
                    stage,
                    spec,
                    stage_identity,
                    cast(str, record["payloadSha256"]),
                    cast(int, record["payloadSize"]),
                    "restore stage",
                )
            else:
                current_stage_identity = _stage_partial_is_safe(
                    stage, spec, cast(int, record["payloadSize"])
                )
            _journal_before_action(
                target_root, plan, journal, "rollback-stage", spec.source_id
            )
            _assert_identity(stage, current_stage_identity, "restore stage")
            stage.unlink()
            _fsync_directory(stage.parent)
            record["stageIdentity"] = None
            record["installed"] = False
            record["verified"] = False
            _journal_after_action(target_root, plan, journal)
        elif record["stageIdentity"] is not None:
            # The same inode may already have been removed from the target.
            record["stageIdentity"] = None
            record["installed"] = False
            record["verified"] = False
            _write_restore_journal(target_root, plan, journal)

    directory_values = list(cast(list[str], journal["createdDirectories"]))
    if isinstance(pending_directory, str) and pending_directory not in directory_values:
        directory_values.append(pending_directory)
    directory_values.sort(key=lambda value: len(PurePosixPath(value).parts), reverse=True)
    for value in directory_values:
        relative = _journal_relative(value, "created restore directory")
        directory = _absolute_restore_path(target_root, relative)
        family = _family_for_restore_directory(plan, relative)
        recorded_created = value in cast(list[str], journal["createdDirectories"])
        _restore_parent_exists_safely(target_root, directory)
        if os.path.lexists(directory):
            try:
                metadata = directory.lstat()
            except OSError as error:
                raise StateBackupError(
                    f"could not inspect created restore directory: {directory}"
                ) from error
            operator_created = (
                metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700
            )
            family_created = family is not None and (
                metadata.st_uid == family.uid
                and metadata.st_gid == family.gid
                and stat.S_IMODE(metadata.st_mode) == family.mode
            )
            safe_created_metadata = (
                family_created
                if recorded_created and family is not None
                else operator_created or family_created
            )
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or not safe_created_metadata
            ):
                raise StateBackupError(
                    f"created restore directory has unsafe metadata: {directory}"
                )
            _journal_before_action(
                target_root, plan, journal, "remove-directory", value
            )
            try:
                directory.rmdir()
                _fsync_directory(directory.parent)
            except OSError as error:
                raise StateBackupError(
                    f"created restore directory is not empty or removable: {directory}"
                ) from error
        if value in cast(list[str], journal["createdDirectories"]):
            cast(list[str], journal["createdDirectories"]).remove(value)
        _journal_after_action(target_root, plan, journal)

    journal["state"] = "rolled-back"
    journal["pendingAction"] = None
    _write_restore_journal(target_root, plan, journal)
    transaction_id = cast(str, journal["transactionId"])
    _remove_restore_journal(target_root, plan, transaction_id)
    return tuple(reversed(touched))


def _finalize_committed_restore(
    target_root: Path,
    plan: SourcePlan,
    journal: dict[str, Any],
) -> tuple[Path, ...]:
    targets: list[Path] = []
    for spec, record in zip(
        plan.sources, cast(list[dict[str, Any]], journal["records"]), strict=True
    ):
        target, stage, preserved = _record_paths(target_root, spec, record)
        if not _restore_parent_exists_safely(target_root, target):
            raise StateBackupError(f"committed restore parent is unavailable: {target.parent}")
        _reject_restore_sqlite_sidecars(target, spec)
        targets.append(target)
        stage_identity = _identity_value(record["stageIdentity"], "stageIdentity")
        if stage_identity is None:
            raise StateBackupError("committed restore record lacks an installed inode")
        _assert_hashed_restore_file(
            target,
            spec,
            stage_identity,
            cast(str, record["payloadSha256"]),
            cast(int, record["payloadSize"]),
            "committed restore target",
        )
        if os.path.lexists(stage):
            raise StateBackupError(f"committed restore left a staging file: {stage}")
        if record["targetExisted"] is True:
            old_identity = _identity_value(record["oldIdentity"], "oldIdentity")
            if preserved is None or old_identity is None or not record["preserved"]:
                raise StateBackupError("committed replacement lacks preserved-state metadata")
            _assert_hashed_restore_file(
                preserved,
                spec,
                old_identity,
                cast(str, record["oldSha256"]),
                None,
                "committed preserved target",
            )
    _read_back_restored_families(
        plan,
        target_root,
        cast(list[dict[str, Any]], journal["records"]),
    )
    _remove_restore_journal(
        target_root, plan, cast(str, journal["transactionId"])
    )
    return tuple(targets)


def _recover_restore_unlocked(
    source_map: Path,
    target_root: Path,
    *,
    confirm_rollback: bool,
    map_owner_uid: int | None = None,
) -> RecoveryResult:
    """Explicitly reconcile a SIGKILL/interrupted restore transaction."""

    if not confirm_rollback:
        raise StateBackupError("recover requires --confirm-rollback")
    plan = load_source_map(source_map, owner_uid=map_owner_uid)
    _validate_restore_root(target_root)
    pending_removed = _discard_pending_journal_update(target_root)
    if not os.path.lexists(_journal_path(target_root)):
        return RecoveryResult(
            journal_found=False,
            action="discarded-pending-update" if pending_removed else "none",
            targets=(),
        )
    journal = _read_restore_journal(target_root, plan)
    records = cast(list[dict[str, Any]], journal["records"])
    plan = _resolve_plan_for_ids(
        plan,
        [cast(str, record["id"]) for record in records],
        "restore journal",
    )
    if journal["state"] == "committed":
        targets = _finalize_committed_restore(target_root, plan, journal)
        return RecoveryResult(True, "finalized-committed", targets)
    targets = _rollback_restore_journal(target_root, plan, journal)
    return RecoveryResult(True, "rolled-back", targets)


def _restore_backup_unlocked(
    source_map: Path,
    archive: Path,
    recipient_certificate: Path,
    private_key: Path,
    signer_certificate: Path,
    target_root: Path,
    *,
    map_owner_uid: int | None = None,
    archive_owner_uid: int | None = None,
    replace_existing: bool = False,
    confirm_quiesced: bool = False,
    openssl: Path | None = None,
) -> RestoreResult:
    """Restore verified state with a durable, crash-recoverable transaction."""

    if replace_existing != confirm_quiesced:
        raise StateBackupError(
            "existing-target recovery requires both replace_existing and confirm_quiesced"
        )
    verified = verify_backup(
        source_map,
        archive,
        recipient_certificate,
        private_key,
        signer_certificate,
        map_owner_uid=map_owner_uid,
        archive_owner_uid=archive_owner_uid,
        openssl=openssl,
    )
    _validate_restore_root(target_root)
    _validate_restore_family_destinations(verified.plan, target_root)
    if os.path.lexists(_journal_path(target_root)) or os.path.lexists(
        _journal_pending_path(target_root)
    ):
        raise StateBackupError("an unfinished restore transaction exists; run recover first")
    journal = _new_restore_journal(verified, target_root)
    _write_restore_journal(target_root, verified.plan, journal, initial=True)
    records = cast(list[dict[str, Any]], journal["records"])
    reserved_restore_paths: set[Path] = set()
    for reserved_spec, reserved_record in zip(
        verified.plan.sources, records, strict=True
    ):
        reserved_target, reserved_stage, _ = _record_paths(
            target_root, reserved_spec, reserved_record
        )
        reserved_restore_paths.update({reserved_target, reserved_stage})
    committed = False
    try:
        for spec, payload, record in zip(
            verified.plan.sources, verified.payloads, records, strict=True
        ):
            parent = _prepare_restore_parent_transaction(
                target_root, spec.restore_path, verified.plan, journal
            )
            target = parent / spec.restore_path.name
            if not _restore_parent_exists_safely(target_root, target):
                raise StateBackupError(f"restore parent is unavailable: {parent}")
            _reject_restore_sqlite_sidecars(target, spec)
            existing = _existing_restore_target(target, spec)
            if existing is not None and not replace_existing:
                raise StateBackupError(
                    f"restore target exists; quiesced replacement was not confirmed: {target}"
                )
            if existing is None:
                record["targetExisted"] = False
            else:
                old_hash, old_identity = _hash_restore_file(target, spec)
                if old_identity != (existing.st_dev, existing.st_ino):
                    raise StateBackupError(f"restore target changed during planning: {target}")
                preserved = _allocate_preserved_path(
                    target,
                    cast(str, verified.manifest["createdAt"]),
                    forbidden=reserved_restore_paths,
                )
                reserved_restore_paths.add(preserved)
                record["targetExisted"] = True
                record["oldIdentity"] = [old_identity[0], old_identity[1]]
                record["oldSha256"] = old_hash
                record["preservedPath"] = _relative_restore_path(target_root, preserved)
            _write_restore_journal(target_root, verified.plan, journal)

            _, stage, _ = _record_paths(target_root, spec, record)
            _journal_before_action(
                target_root, verified.plan, journal, "stage-target", spec.source_id
            )
            identity = _write_restore_stage(stage, payload, spec)
            _fsync_directory(parent)
            record["stageIdentity"] = [identity[0], identity[1]]
            _journal_after_action(target_root, verified.plan, journal)

        for spec, payload, record in zip(
            verified.plan.sources, verified.payloads, records, strict=True
        ):
            target, stage, preserved = _record_paths(target_root, spec, record)
            if not _restore_parent_exists_safely(target_root, target):
                raise StateBackupError(f"restore parent is unavailable: {target.parent}")
            _reject_restore_sqlite_sidecars(target, spec)
            stage_identity = cast(
                tuple[int, int], _identity_value(record["stageIdentity"], "stageIdentity")
            )
            if record["targetExisted"] is True:
                old_identity = cast(
                    tuple[int, int], _identity_value(record["oldIdentity"], "oldIdentity")
                )
                if preserved is None:
                    raise StateBackupError("replacement record lacks a preservation path")
                _assert_hashed_restore_file(
                    target,
                    spec,
                    old_identity,
                    cast(str, record["oldSha256"]),
                    None,
                    "restore target before preservation",
                )
                if os.path.lexists(preserved):
                    raise StateBackupError(f"preservation destination already exists: {preserved}")
                _journal_before_action(
                    target_root,
                    verified.plan,
                    journal,
                    "preserve-target",
                    spec.source_id,
                )
                _preserve_existing_target(target, preserved)
                _fsync_directory(target.parent)
                _assert_hashed_restore_file(
                    preserved,
                    spec,
                    old_identity,
                    cast(str, record["oldSha256"]),
                    None,
                    "preserved restore target",
                )
                record["preserved"] = True
                _journal_after_action(target_root, verified.plan, journal)

            if os.path.lexists(target):
                raise StateBackupError(f"restore target unexpectedly exists before install: {target}")
            _assert_hashed_restore_file(
                stage,
                spec,
                stage_identity,
                cast(str, record["payloadSha256"]),
                cast(int, record["payloadSize"]),
                "restore stage before install",
            )
            _journal_before_action(
                target_root, verified.plan, journal, "install-target", spec.source_id
            )
            _install_staged_file(stage, target)
            _fsync_directory(target.parent)
            record["installed"] = True
            _journal_after_action(target_root, verified.plan, journal)

            readback_record = _RestoreRecord(
                spec=spec,
                target=target,
                stage=stage,
                stage_identity=stage_identity,
                preserved=preserved,
                target_existed=cast(bool, record["targetExisted"]),
                old_sha256=cast(str | None, record["oldSha256"]),
                installed=True,
            )
            _read_back_restored_target(readback_record, payload)
            record["verified"] = True
            _write_restore_journal(target_root, verified.plan, journal)

        _read_back_restored_families(verified.plan, target_root, records)
        _journal_before_action(
            target_root,
            verified.plan,
            journal,
            "commit",
            cast(str, journal["transactionId"]),
        )
        journal["state"] = "committed"
        _journal_after_action(target_root, verified.plan, journal)
        committed = True
        _remove_restore_journal(
            target_root, verified.plan, cast(str, journal["transactionId"])
        )
    except Exception as original_error:
        rollback_error: Exception | None = None
        try:
            _discard_pending_journal_update(target_root)
            if os.path.lexists(_journal_path(target_root)):
                current = _read_restore_journal(target_root, verified.plan)
                if current["state"] == "active":
                    _rollback_restore_journal(target_root, verified.plan, current)
                elif current["state"] == "committed":
                    committed = True
        except Exception as error:
            rollback_error = error
        if committed:
            raise StateBackupError(
                "restore committed, but durable journal cleanup was interrupted; "
                "run recover --confirm-rollback to finalize"
            ) from original_error
        if rollback_error is not None:
            raise StateBackupError(
                f"restore failed and durable rollback is incomplete: {rollback_error}"
            ) from original_error
        if isinstance(original_error, StateBackupError):
            raise
        raise StateBackupError("restore failed; all changed targets were rolled back") from original_error
    return RestoreResult(
        targets=tuple(
            _absolute_restore_path(target_root, spec.restore_path)
            for spec in verified.plan.sources
        ),
        preserved=tuple(
            cast(Path, _record_paths(target_root, spec, record)[2])
            for spec, record in zip(verified.plan.sources, records, strict=True)
            if record["preserved"]
        ),
    )


def restore_backup(
    source_map: Path,
    archive: Path,
    recipient_certificate: Path,
    private_key: Path,
    signer_certificate: Path,
    target_root: Path,
    *,
    map_owner_uid: int | None = None,
    archive_owner_uid: int | None = None,
    replace_existing: bool = False,
    confirm_quiesced: bool = False,
    openssl: Path | None = None,
) -> RestoreResult:
    """Serialize and execute one crash-recoverable restore per root inode."""

    _validate_restore_root(target_root)
    lock_descriptor = _acquire_restore_root_lock(target_root)
    try:
        return _restore_backup_unlocked(
            source_map,
            archive,
            recipient_certificate,
            private_key,
            signer_certificate,
            target_root,
            map_owner_uid=map_owner_uid,
            archive_owner_uid=archive_owner_uid,
            replace_existing=replace_existing,
            confirm_quiesced=confirm_quiesced,
            openssl=openssl,
        )
    finally:
        os.close(lock_descriptor)


def recover_restore(
    source_map: Path,
    target_root: Path,
    *,
    confirm_rollback: bool,
    map_owner_uid: int | None = None,
) -> RecoveryResult:
    """Serialize and reconcile one interrupted restore per root inode."""

    if not confirm_rollback:
        raise StateBackupError("recover requires --confirm-rollback")
    _validate_restore_root(target_root)
    lock_descriptor = _acquire_restore_root_lock(target_root)
    try:
        return _recover_restore_unlocked(
            source_map,
            target_root,
            confirm_rollback=True,
            map_owner_uid=map_owner_uid,
        )
    finally:
        os.close(lock_descriptor)


def _uid_argument(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("uid must be a non-negative integer") from error
    if parsed < 0 or parsed > 2**31 - 1:
        raise argparse.ArgumentTypeError("uid must be a non-negative integer")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup", help="create an encrypted backup")
    backup_parser.add_argument("--source-map", type=Path, required=True)
    backup_parser.add_argument("--recipient-cert", type=Path, required=True)
    backup_parser.add_argument("--signer-cert", type=Path, required=True)
    backup_parser.add_argument("--signer-key", type=Path, required=True)
    backup_parser.add_argument("--output", type=Path, required=True)
    backup_parser.add_argument("--map-owner-uid", type=_uid_argument, default=os.geteuid())
    backup_parser.add_argument("--confirm-quiesced", action="store_true")

    for name in ("verify", "restore"):
        command = subparsers.add_parser(name, help=f"{name} an encrypted backup")
        command.add_argument("--source-map", type=Path, required=True)
        command.add_argument("--archive", type=Path, required=True)
        command.add_argument("--recipient-cert", type=Path, required=True)
        command.add_argument("--private-key", type=Path, required=True)
        command.add_argument("--signer-cert", type=Path, required=True)
        command.add_argument("--map-owner-uid", type=_uid_argument, default=os.geteuid())
        command.add_argument("--archive-owner-uid", type=_uid_argument, default=os.geteuid())
        if name == "restore":
            command.add_argument("--target-root", type=Path, required=True)
            command.add_argument("--replace-existing", action="store_true")
            command.add_argument("--confirm-quiesced", action="store_true")
    recover_parser = subparsers.add_parser(
        "recover", help="rollback or finalize an interrupted restore"
    )
    recover_parser.add_argument("--source-map", type=Path, required=True)
    recover_parser.add_argument("--target-root", type=Path, required=True)
    recover_parser.add_argument("--map-owner-uid", type=_uid_argument, default=os.geteuid())
    recover_parser.add_argument("--confirm-rollback", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "backup":
            manifest = create_backup(
                arguments.source_map,
                arguments.output,
                arguments.recipient_cert,
                signer_certificate=arguments.signer_cert,
                signer_private_key=arguments.signer_key,
                map_owner_uid=arguments.map_owner_uid,
                confirm_quiesced=arguments.confirm_quiesced,
            )
            print(
                f"backup={arguments.output} createdAt={manifest['createdAt']} "
                f"sources={len(manifest['sources'])}"
            )
        elif arguments.command == "verify":
            verified = verify_backup(
                arguments.source_map,
                arguments.archive,
                arguments.recipient_cert,
                arguments.private_key,
                arguments.signer_cert,
                map_owner_uid=arguments.map_owner_uid,
                archive_owner_uid=arguments.archive_owner_uid,
            )
            print(
                f"verified=true createdAt={verified.manifest['createdAt']} "
                f"sources={len(verified.payloads)}"
            )
        elif arguments.command == "restore":
            result = restore_backup(
                arguments.source_map,
                arguments.archive,
                arguments.recipient_cert,
                arguments.private_key,
                arguments.signer_cert,
                arguments.target_root,
                map_owner_uid=arguments.map_owner_uid,
                archive_owner_uid=arguments.archive_owner_uid,
                replace_existing=arguments.replace_existing,
                confirm_quiesced=arguments.confirm_quiesced,
            )
            print(f"restored={len(result.targets)} preserved={len(result.preserved)}")
        else:
            recovery = recover_restore(
                arguments.source_map,
                arguments.target_root,
                confirm_rollback=arguments.confirm_rollback,
                map_owner_uid=arguments.map_owner_uid,
            )
            print(
                f"journalFound={str(recovery.journal_found).lower()} "
                f"action={recovery.action} targets={len(recovery.targets)}"
            )
    except StateBackupError as error:
        print(f"state-backup error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
