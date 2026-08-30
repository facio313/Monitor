#!/usr/bin/env python3
"""Safe acquisition adapters for configured file and journald log sources."""

from __future__ import annotations

import datetime as dt
import errno
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

try:  # Installed scripts share one directory; package tests use a relative import.
    from log_pipeline import LogSource
except ModuleNotFoundError:  # pragma: no cover - exercised by package-style tests
    from .log_pipeline import LogSource


CONFIG_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_SOURCES = 64
FILE_CURSOR_GUARD_BYTES = 256
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.(?:service|socket|timer|path|scope)")
_JOURNAL_CURSOR = re.compile(r"[A-Za-z0-9_=;:.,@+/-]{1,2048}")
_SOURCE_COMMON = frozenset({
    "id", "kind", "priority", "parser", "multiline", "fieldAllowlist",
    "hostId", "containerName", "composeProject", "composeService",
    "processName", "systemdUnit", "stream", "maxLines",
})


class SourceConfigError(ValueError):
    """The reviewed source configuration is unsafe or malformed."""


@dataclass(frozen=True)
class SourceDefinition:
    source: LogSource
    path: Path | None = None
    file_root: Path | None = None
    unit: str | None = None
    max_lines: int = 1_000

    def __post_init__(self) -> None:
        if self.source.kind == "file":
            if self.path is None or self.file_root is None or self.unit is not None:
                raise ValueError("file source requires only path and reviewed root")
        elif self.source.kind == "journald":
            if self.unit is None or self.path is not None or self.file_root is not None:
                raise ValueError("journald source requires only unit")
            if _UNIT.fullmatch(self.unit) is None:
                raise ValueError("journald unit is invalid")
        else:
            raise ValueError("collector source config supports file and journald only")
        if isinstance(self.max_lines, bool) or not isinstance(self.max_lines, int) or not 1 <= self.max_lines <= 5_000:
            raise ValueError("max_lines is outside its supported range")


@dataclass(frozen=True)
class CommandResult:
    status: str
    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = None


def _json_without_duplicates(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise SourceConfigError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SourceConfigError("source config is not valid UTF-8 JSON") from exc


def _read_secure_file(path: Path, *, expected_uid: int, maximum_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceConfigError("source config cannot be inspected") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
        or metadata.st_size > maximum_bytes
    ):
        raise SourceConfigError("source config ownership, mode, link, type, or size is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceConfigError("source config cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SourceConfigError("source config changed while opening")
        raw = os.read(descriptor, maximum_bytes + 1)
        if len(raw) > maximum_bytes or os.read(descriptor, 1):
            raise SourceConfigError("source config exceeds the size limit")
        return raw
    finally:
        os.close(descriptor)


def _safe_absolute_log_path(value: Any, allowed_roots: Sequence[Path]) -> tuple[Path, Path]:
    if not isinstance(value, str) or not value.startswith("/") or len(value.encode()) > 4096:
        raise SourceConfigError("log path must be a bounded absolute path")
    path = Path(value)
    if any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise SourceConfigError("log path contains an unsafe component")
    for root in allowed_roots:
        if not root.is_absolute() or any(part in {"", ".", ".."} for part in root.parts[1:]):
            raise SourceConfigError("reviewed log root is not a normalized absolute path")
        root_parts = root.parts
        if path.parts[:len(root_parts)] == root_parts and len(path.parts) > len(root_parts):
            return path, root
    raise SourceConfigError("log path is outside reviewed roots")


def load_source_config(
    path: Path,
    *,
    expected_uid: int = 0,
    allowed_file_roots: Sequence[Path] = (Path("/var/log"), Path("/run/log")),
    required: bool = False,
) -> tuple[SourceDefinition, ...]:
    """Load an exact-schema, owner-controlled source allowlist."""

    try:
        exists = path.exists()
    except OSError:
        exists = False
    if not exists:
        if required:
            raise SourceConfigError("required source config is missing")
        return ()
    decoded = _json_without_duplicates(
        _read_secure_file(path, expected_uid=expected_uid, maximum_bytes=MAX_CONFIG_BYTES)
    )
    if not isinstance(decoded, Mapping) or set(decoded) != {"schemaVersion", "sources"}:
        raise SourceConfigError("source config top-level schema is invalid")
    if decoded.get("schemaVersion") != CONFIG_SCHEMA_VERSION:
        raise SourceConfigError("unsupported source config version")
    raw_sources = decoded.get("sources")
    if not isinstance(raw_sources, list) or len(raw_sources) > MAX_SOURCES:
        raise SourceConfigError("source config has too many sources")
    definitions: list[SourceDefinition] = []
    identifiers: set[str] = set()
    for raw in raw_sources:
        if not isinstance(raw, Mapping):
            raise SourceConfigError("source entry must be an object")
        kind = raw.get("kind")
        specific = {"path"} if kind == "file" else {"unit"} if kind == "journald" else set()
        if not specific or not set(raw).issubset(_SOURCE_COMMON | specific) or not specific.issubset(raw):
            raise SourceConfigError("source entry fields are invalid")
        if not {"id", "kind"}.issubset(raw):
            raise SourceConfigError("source entry is missing identity")
        source_id = raw.get("id")
        if not isinstance(source_id, str) or source_id in identifiers:
            raise SourceConfigError("source IDs must be unique strings")
        identifiers.add(source_id)
        allowlist = raw.get("fieldAllowlist", [])
        if not isinstance(allowlist, list) or any(not isinstance(item, str) for item in allowlist):
            raise SourceConfigError("fieldAllowlist must be a string array")
        try:
            source = LogSource(
                source_id=source_id,
                kind=kind,
                priority=raw.get("priority", "normal"),
                parser=raw.get("parser", "auto"),
                multiline=raw.get("multiline", "auto"),
                host_id=raw.get("hostId"),
                container_name=raw.get("containerName"),
                compose_project=raw.get("composeProject"),
                compose_service=raw.get("composeService"),
                process_name=raw.get("processName"),
                systemd_unit=raw.get("systemdUnit"),
                stream=raw.get("stream"),
                field_allowlist=tuple(allowlist),
            )
            max_lines = raw.get("maxLines", 1_000)
            if kind == "file":
                source_path, file_root = _safe_absolute_log_path(
                    raw.get("path"), allowed_file_roots
                )
                definition = SourceDefinition(
                    source=source,
                    path=source_path,
                    file_root=file_root,
                    max_lines=max_lines,
                )
            else:
                unit = raw.get("unit")
                if source.systemd_unit is not None and source.systemd_unit != unit:
                    raise ValueError("journald unit and public systemdUnit must match")
                journal_source = source if source.systemd_unit is not None else LogSource(
                    source_id=source.source_id,
                    kind=source.kind,
                    priority=source.priority,
                    parser=source.parser,
                    multiline=source.multiline,
                    host_id=source.host_id,
                    container_name=source.container_name,
                    compose_project=source.compose_project,
                    compose_service=source.compose_service,
                    process_name=source.process_name,
                    systemd_unit=unit,
                    stream=source.stream,
                    field_allowlist=source.field_allowlist,
                )
                definition = SourceDefinition(
                    source=journal_source, unit=unit, max_lines=max_lines
                )
        except (TypeError, ValueError) as exc:
            raise SourceConfigError("source entry failed semantic validation") from exc
        definitions.append(definition)
    return tuple(definitions)


def _classify_os_error(exc: OSError) -> str:
    return "permission_denied" if exc.errno in {errno.EACCES, errno.EPERM} else "failed"


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_log_at(parent_descriptor: int, name: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError(errno.EPERM, "unsafe linked log source") from exc
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o002:
            raise OSError(errno.EPERM, "unsafe log source")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _open_log_parent(definition: SourceDefinition) -> tuple[int, str]:
    """Walk from `/` with O_NOFOLLOW so no intermediate link can escape a root."""

    if definition.path is None or definition.file_root is None:
        raise OSError(errno.EPERM, "file source has no reviewed root")
    root_parts = definition.file_root.parts
    path_parts = definition.path.parts
    if (
        path_parts[:len(root_parts)] != root_parts
        or len(path_parts) <= len(root_parts)
        or root_parts[0] != "/"
    ):
        raise OSError(errno.EPERM, "file source escaped its reviewed root")
    descriptor = os.open("/", _directory_flags())
    try:
        for component in path_parts[1:-1]:
            try:
                next_descriptor = os.open(
                    component, _directory_flags(), dir_fd=descriptor
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise OSError(errno.EPERM, "unsafe log path component") from exc
                raise
            try:
                metadata = os.fstat(next_descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise OSError(errno.EPERM, "unsafe log path component")
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, path_parts[-1]
    except Exception:
        os.close(descriptor)
        raise


def _open_configured_log(
    definition: SourceDefinition,
) -> tuple[int, int, os.stat_result, str]:
    parent_descriptor, name = _open_log_parent(definition)
    try:
        descriptor, metadata = _open_log_at(parent_descriptor, name)
    except Exception:
        os.close(parent_descriptor)
        raise
    return parent_descriptor, descriptor, metadata, name


def _read_segment(
    descriptor: int,
    start: int,
    maximum_bytes: int,
    maximum_line_bytes: int,
    discard_until_newline: bool,
) -> tuple[list[str], int, bool, int]:
    content = os.pread(descriptor, maximum_bytes, start)
    if not content:
        return [], start, discard_until_newline, 0
    last_newline = content.rfind(b"\n")
    if last_newline < 0:
        if len(content) >= maximum_line_bytes:
            return [], start + len(content), True, 1
        return [], start, discard_until_newline, 0
    complete = content[:last_newline + 1]
    next_offset = start + last_newline + 1
    raw_lines = complete.splitlines()
    dropped = 0
    if discard_until_newline and raw_lines:
        raw_lines = raw_lines[1:]
        dropped += 1
    lines: list[str] = []
    for raw in raw_lines:
        if len(raw) > maximum_line_bytes:
            dropped += 1
        else:
            lines.append(raw.decode("utf-8", errors="replace"))
    trailing = content[last_newline + 1:]
    discard_next = len(trailing) > maximum_line_bytes
    if discard_next:
        next_offset = start + len(content)
        dropped += 1
    return lines, next_offset, discard_next, dropped


def _open_rotated_log(
    parent_descriptor: int,
    current_name: str,
    inode: int,
) -> tuple[int, os.stat_result] | None:
    try:
        entries = os.scandir(parent_descriptor)
    except OSError:
        return None
    with entries:
        for _index in range(256):
            try:
                entry = next(entries)
            except StopIteration:
                break
            candidate = entry.name
            if candidate == current_name or not candidate.startswith(current_name):
                continue
            try:
                metadata = os.stat(
                    candidate, dir_fd=parent_descriptor, follow_symlinks=False
                )
            except OSError:
                continue
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_ino == inode
            ):
                try:
                    descriptor, opened = _open_log_at(parent_descriptor, candidate)
                except OSError:
                    continue
                if opened.st_ino == inode:
                    return descriptor, opened
                os.close(descriptor)
    return None


def _normalize_file_cursor(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or not set(value).issubset({
        "inode", "offset", "discardUntilNewline", "guardBytes", "guardSha256"
    }):
        raise ValueError("file cursor failed schema validation")
    inode = value.get("inode")
    offset = value.get("offset")
    discard = value.get("discardUntilNewline", False)
    guard_bytes = value.get("guardBytes")
    guard_sha256 = value.get("guardSha256")
    if (
        isinstance(inode, bool) or not isinstance(inode, int) or inode < 0
        or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
        or not isinstance(discard, bool)
        or (guard_bytes is None) != (guard_sha256 is None)
        or guard_bytes is not None and (
            isinstance(guard_bytes, bool)
            or not isinstance(guard_bytes, int)
            or not 1 <= guard_bytes <= FILE_CURSOR_GUARD_BYTES
            or guard_bytes > offset
            or not isinstance(guard_sha256, str)
            or _SHA256_HEX.fullmatch(guard_sha256) is None
        )
    ):
        if not value:
            return {}
        raise ValueError("file cursor has invalid values")
    result = {"inode": inode, "offset": offset}
    if discard:
        result["discardUntilNewline"] = True
    if guard_bytes is not None:
        result["guardBytes"] = guard_bytes
        result["guardSha256"] = guard_sha256
    return result


def _file_cursor_guard(descriptor: int, offset: int) -> dict[str, Any] | None:
    if offset <= 0:
        return {}
    length = min(offset, FILE_CURSOR_GUARD_BYTES)
    content = os.pread(descriptor, length, offset - length)
    if len(content) != length:
        return None
    return {
        "guardBytes": length,
        "guardSha256": hashlib.sha256(content).hexdigest(),
    }


def _file_cursor_guard_matches(
    descriptor: int, offset: int, cursor: Mapping[str, Any]
) -> bool:
    guard_bytes = cursor.get("guardBytes")
    guard_sha256 = cursor.get("guardSha256")
    if guard_bytes is None or guard_sha256 is None:
        # One compatibility read upgrades cursors written before guard support.
        return True
    content = os.pread(descriptor, int(guard_bytes), offset - int(guard_bytes))
    return (
        len(content) == guard_bytes
        and hashlib.sha256(content).hexdigest() == guard_sha256
    )


def read_file_source(
    definition: SourceDefinition,
    cursor: Mapping[str, Any] | None,
    *,
    maximum_bytes: int = 2 * 1024 * 1024,
    maximum_line_bytes: int = 128 * 1024,
) -> dict[str, Any]:
    """Read complete lines once, including one bounded rotated residual tail."""

    if definition.source.kind != "file" or definition.path is None or definition.file_root is None:
        raise ValueError("definition is not a file source")
    if not 1024 <= maximum_bytes <= 32 * 1024 * 1024:
        raise ValueError("maximum_bytes is outside its supported range")
    if not 64 <= maximum_line_bytes <= min(maximum_bytes, 1024 * 1024):
        raise ValueError("maximum_line_bytes is outside its supported range")
    prior = _normalize_file_cursor(cursor)
    try:
        parent_fd, current_fd, current_metadata, current_name = _open_configured_log(definition)
    except FileNotFoundError:
        return {"status": "no_data", "errorClass": None, "lines": [], "cursor": prior, "droppedLines": 0, "rotationGap": False}
    except OSError as exc:
        status = _classify_os_error(exc)
        return {"status": status, "errorClass": status if status == "permission_denied" else "read_failed", "lines": [], "cursor": prior, "droppedLines": 0, "rotationGap": False}
    lines: list[str] = []
    dropped = 0
    rotation_gap = False
    backlog_gap = False
    try:
        inode = int(current_metadata.st_ino)
        size = int(current_metadata.st_size)
        old_inode = prior.get("inode")
        old_offset = prior.get("offset", 0)
        old_discard = prior.get("discardUntilNewline") is True
        same_inode_rewrite = (
            old_inode == inode
            and (
                old_offset > size
                or not _file_cursor_guard_matches(current_fd, old_offset, prior)
            )
        )
        same = old_inode == inode and old_offset <= size and not same_inode_rewrite
        if same:
            start = old_offset
            discard = old_discard
            if size - start > maximum_bytes:
                start = size - maximum_bytes
                discard = True
                backlog_gap = True
            lines, next_offset, discard_next, dropped = _read_segment(
                current_fd, start, maximum_bytes, maximum_line_bytes, discard
            )
        elif same_inode_rewrite:
            backlog_gap = True
            start = max(0, size - maximum_bytes)
            lines, next_offset, discard_next, dropped = _read_segment(
                current_fd,
                start,
                maximum_bytes,
                maximum_line_bytes,
                start > 0,
            )
        else:
            half = max(512, maximum_bytes // 2)
            if isinstance(old_inode, int):
                rotated = _open_rotated_log(parent_fd, current_name, old_inode)
                if rotated is None:
                    rotation_gap = True
                else:
                    rotated_fd, rotated_metadata = rotated
                    try:
                        rotated_start = min(int(old_offset), int(rotated_metadata.st_size))
                        if int(rotated_metadata.st_size) - rotated_start > half:
                            rotated_start = int(rotated_metadata.st_size) - half
                            old_discard = True
                            rotation_gap = True
                        residual, _offset, _discard, lost = _read_segment(
                            rotated_fd, rotated_start, half, maximum_line_bytes, old_discard
                        )
                        lines.extend(residual)
                        dropped += lost
                    finally:
                        os.close(rotated_fd)
            current_budget = half if isinstance(old_inode, int) else maximum_bytes
            start = max(0, size - current_budget)
            if isinstance(old_inode, int) and start > 0:
                rotation_gap = True
            current_lines, next_offset, discard_next, lost = _read_segment(
                current_fd, start, current_budget, maximum_line_bytes, start > 0
            )
            lines.extend(current_lines)
            dropped += lost
        next_cursor: dict[str, Any] = {"inode": inode, "offset": next_offset}
        if discard_next:
            next_cursor["discardUntilNewline"] = True
        guard = _file_cursor_guard(current_fd, next_offset)
        if guard is None:
            return {
                "status": "failed",
                "errorClass": "read_failed",
                "lines": [],
                "cursor": prior,
                "droppedLines": 0,
                "rotationGap": False,
                "backlogGap": False,
            }
        next_cursor.update(guard)
        if len(lines) > definition.max_lines:
            dropped += len(lines) - definition.max_lines
            lines = lines[-definition.max_lines:]
        if backlog_gap or rotation_gap:
            # The exact number of skipped complete lines cannot be recovered
            # after a byte-range jump. Count one acquisition-gap sentinel and
            # surface truncation instead of claiming a fresh lossless read.
            dropped += 1
        truncated = backlog_gap or rotation_gap or dropped > 0
        return {
            "status": "truncated" if truncated else "fresh" if lines else "no_data",
            "errorClass": "output_limit" if truncated else None,
            "lines": lines,
            "cursor": next_cursor,
            "droppedLines": dropped,
            "rotationGap": rotation_gap,
            "backlogGap": backlog_gap,
        }
    finally:
        os.close(current_fd)
        os.close(parent_fd)


def run_bounded_command(
    command: Sequence[str], timeout_seconds: float, maximum_bytes: int
) -> CommandResult:
    """Execute a fixed argv with a hard combined-output and wall-clock cap."""

    if not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("command must be a non-empty argv")
    if not 0.1 <= timeout_seconds <= 30 or not 1024 <= maximum_bytes <= 32 * 1024 * 1024:
        raise ValueError("bounded command limits are invalid")
    try:
        process = subprocess.Popen(
            list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
        )
    except FileNotFoundError:
        return CommandResult("unsupported")
    except OSError:
        return CommandResult("failed")
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    status = "completed"
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            ready = selector.select(min(0.1, remaining))
            if not ready and process.poll() is not None:
                ready = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in ready:
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                if len(buffers["stdout"]) + len(buffers["stderr"]) > maximum_bytes:
                    status = "limit_exceeded"
                    break
            if status != "completed":
                break
        if status != "completed":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
        returncode = process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait()
        return CommandResult("failed")
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        status,
        bytes(buffers["stdout"][:maximum_bytes]),
        bytes(buffers["stderr"][:maximum_bytes]),
        returncode,
    )


def _normalize_journal_cursor(value: Mapping[str, Any] | None) -> str | None:
    if value is None or value == {}:
        return None
    if not isinstance(value, Mapping) or set(value) != {"cursor"}:
        raise ValueError("journal cursor failed schema validation")
    cursor = value.get("cursor")
    if not isinstance(cursor, str) or _JOURNAL_CURSOR.fullmatch(cursor) is None:
        raise ValueError("journal cursor is invalid")
    return cursor


def _cursor_from_oversized_journal_row(raw: bytes) -> str | None:
    """Recover only a bounded cursor from a row that is intentionally dropped."""

    try:
        decoded = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, Mapping):
        cursor = decoded.get("__CURSOR")
        if isinstance(cursor, str) and _JOURNAL_CURSOR.fullmatch(cursor) is not None:
            return cursor
    # run_bounded_command may have cut an oversized JSON row after the cursor
    # but before its closing object. Journald cursors use this strict alphabet;
    # JSON string content cannot forge the unescaped field syntax below.
    match = re.search(
        rb'(?<!\\)"__CURSOR"\s*:\s*"([A-Za-z0-9_=;:.,@+/\-]{1,2048})"',
        raw,
    )
    if match is None:
        return None
    try:
        cursor = match.group(1).decode("ascii", errors="strict")
    except UnicodeError:
        return None
    return cursor if _JOURNAL_CURSOR.fullmatch(cursor) is not None else None


def normalize_source_cursor(
    definition: SourceDefinition, value: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """Return one canonical private cursor for the reviewed source."""

    try:
        if definition.source.kind == "file":
            return _normalize_file_cursor(value)
        cursor = _normalize_journal_cursor(value)
        return {"cursor": cursor} if cursor else {}
    except ValueError:
        return None


def read_journal_source(
    definition: SourceDefinition,
    cursor: Mapping[str, Any] | None,
    *,
    journalctl: str = "/usr/bin/journalctl",
    timeout_seconds: float = 3.0,
    maximum_bytes: int = 2 * 1024 * 1024,
    runner: Callable[[Sequence[str], float, int], CommandResult] = run_bounded_command,
) -> dict[str, Any]:
    """Read one allowlisted systemd unit and reduce journald metadata immediately."""

    if definition.source.kind != "journald" or definition.unit is None:
        raise ValueError("definition is not a journald source")
    prior_cursor = _normalize_journal_cursor(cursor)
    # An initial read intentionally tails the unit.  Once a cursor exists,
    # consume the oldest unseen entries instead: journalctl's plain -n form
    # would return the newest matches and silently jump over a large backlog.
    # One extra entry is a lookahead used only to report pending backlog; it is
    # neither emitted nor counted as dropped, and its cursor is left for the
    # next collection run.
    line_limit = definition.max_lines + 1 if prior_cursor else definition.max_lines
    line_argument = f"+{line_limit}" if prior_cursor else str(line_limit)
    command = [
        journalctl, "--no-pager", "--quiet", "--output=json", "--all",
        f"--unit={definition.unit}", f"--lines={line_argument}",
    ]
    if prior_cursor:
        command.append(f"--after-cursor={prior_cursor}")
    result = runner(command, timeout_seconds, maximum_bytes)
    if result.status == "unsupported":
        return {"status": "unsupported", "errorClass": "unsupported", "lines": [], "cursor": cursor or {}, "droppedLines": 0}
    if result.status == "timeout":
        return {"status": "failed", "errorClass": "timeout", "lines": [], "cursor": cursor or {}, "droppedLines": 0}
    if result.status not in {"completed", "limit_exceeded"}:
        return {"status": "failed", "errorClass": "read_failed", "lines": [], "cursor": cursor or {}, "droppedLines": 0}
    stderr_lower = result.stderr[:4096].decode("utf-8", errors="replace").lower()
    if "permission denied" in stderr_lower or "insufficient permission" in stderr_lower:
        return {"status": "permission_denied", "errorClass": "permission_denied", "lines": [], "cursor": cursor or {}, "droppedLines": 0}
    if result.returncode not in {0, None} and result.status == "completed":
        return {"status": "failed", "errorClass": "command_failed", "lines": [], "cursor": cursor or {}, "droppedLines": 0}

    lines: list[str] = []
    next_cursor = prior_cursor
    dropped = 0
    raw_lines = result.stdout.splitlines()
    backlog_pending = prior_cursor is not None and len(raw_lines) > definition.max_lines
    for raw_line in raw_lines[:definition.max_lines]:
        if len(raw_line) > 128 * 1024:
            oversized_cursor = _cursor_from_oversized_journal_row(raw_line)
            if oversized_cursor is not None:
                next_cursor = oversized_cursor
            dropped += 1
            continue
        try:
            decoded = json.loads(raw_line.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError):
            dropped += 1
            continue
        if not isinstance(decoded, Mapping):
            dropped += 1
            continue
        raw_cursor = decoded.get("__CURSOR")
        if not isinstance(raw_cursor, str) or _JOURNAL_CURSOR.fullmatch(raw_cursor) is None:
            dropped += 1
            continue
        # A row with a valid journal cursor but unusable content is an
        # intentional, counted drop. Advance through it to prevent one poison
        # entry from blocking every later record. The +1 lookahead is outside
        # this loop and is never acknowledged.
        next_cursor = raw_cursor
        message = decoded.get("MESSAGE")
        if isinstance(message, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in message[:128 * 1024]):
            message = bytes(message[:128 * 1024]).decode("utf-8", errors="replace")
        if not isinstance(message, str):
            dropped += 1
            continue
        timestamp: str | None = None
        raw_timestamp = decoded.get("__REALTIME_TIMESTAMP")
        try:
            micros = int(raw_timestamp)
            timestamp = dt.datetime.fromtimestamp(
                micros / 1_000_000, tz=dt.timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        except (TypeError, ValueError, OverflowError, OSError):
            timestamp = None
        reduced = {
            "timestamp": timestamp,
            "severity": decoded.get("PRIORITY"),
            "message": message,
        }
        lines.append(json.dumps(reduced, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
    truncated = result.status == "limit_exceeded" or backlog_pending or dropped > 0
    status = "truncated" if truncated else "fresh" if lines else "no_data"
    return {
        "status": status,
        "errorClass": "output_limit" if truncated else None,
        "lines": lines,
        "cursor": {"cursor": next_cursor} if next_cursor else {},
        "droppedLines": dropped,
    }
