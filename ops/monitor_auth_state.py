#!/usr/bin/env python3
"""Prepare, inspect, back up, and restore Monitor password-hash state.

The helper intentionally never prints the state contents.  The application owns
initial creation and password updates; this tool only manages the host directory
and byte-for-byte, owner-only snapshots.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import cast


DEFAULT_STATE_DIR = Path("/home/cks/.local/state/monitor-auth")
DEFAULT_BACKUP_DIR = Path("/home/cks/backups/monitor-auth")
STATE_FILENAME = "password.json"
MAX_STATE_BYTES = 4 * 1024
# Keep this version-1 disk contract aligned with server/password-store.ts.
STATE_VERSION = 1
SCRYPT_N = 65_536
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32
SALT_BYTES = 16
SESSION_EPOCH_BYTES = 32
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class StateError(RuntimeError):
    """An unsafe or unusable auth-state path."""


def _mode(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_existing_ancestor(path: Path) -> None:
    probe = Path(os.path.abspath(path))
    while not os.path.lexists(probe):
        if probe.parent == probe:
            break
        probe = probe.parent
    metadata = probe.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise StateError(f"path must not be created through a symlink: {path}")
    if probe.resolve(strict=True) != probe:
        raise StateError(f"path must not contain symlink ancestors: {path}")


def _validate_directory(path: Path, uid: int, *, allow_missing: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return False
        raise StateError(f"directory does not exist: {path}")

    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise StateError(f"path is not a real directory: {path}")
    absolute_path = Path(os.path.abspath(path))
    if path.resolve(strict=True) != absolute_path:
        raise StateError(f"directory path must not contain symlinks: {path}")
    if metadata.st_uid != uid:
        raise StateError(
            f"directory owner mismatch: {path} is uid {metadata.st_uid}, expected {uid}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise StateError(
            f"unsafe directory mode {_mode(metadata.st_mode)} for {path}; expected 0700"
        )
    return True


def _open_regular_file(path: Path, uid: int) -> tuple[int, os.stat_result]:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        raise StateError(f"state file does not exist: {path}")

    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise StateError(f"state path is not a regular file: {path}")
    if path_metadata.st_nlink != 1:
        raise StateError(f"state file must not have additional hard links: {path}")
    if path_metadata.st_uid != uid:
        raise StateError(
            f"state file owner mismatch: {path} is uid {path_metadata.st_uid}, expected {uid}"
        )
    if stat.S_IMODE(path_metadata.st_mode) != 0o600:
        raise StateError(
            f"unsafe state file mode {_mode(path_metadata.st_mode)} for {path}; expected 0600"
        )
    if path_metadata.st_size <= 0 or path_metadata.st_size > MAX_STATE_BYTES:
        raise StateError(f"state file size is outside the accepted bounds: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    opened_metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened_metadata.st_mode)
        or opened_metadata.st_nlink != 1
        or opened_metadata.st_uid != uid
        or stat.S_IMODE(opened_metadata.st_mode) != 0o600
        or opened_metadata.st_size <= 0
        or opened_metadata.st_size > MAX_STATE_BYTES
        or opened_metadata.st_dev != path_metadata.st_dev
        or opened_metadata.st_ino != path_metadata.st_ino
    ):
        os.close(descriptor)
        raise StateError(f"state file changed while it was opened: {path}")
    return descriptor, opened_metadata


def _is_expected_json_number(value: object, expected: int) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == expected


def _valid_base64url(value: object, expected_bytes: int) -> bool:
    if not isinstance(value, str) or not BASE64URL_PATTERN.fullmatch(value):
        return False
    if len(value) > (expected_bytes * 4 + 2) // 3 + 1:
        return False
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(decoded) == expected_bytes


def _validate_state_schema(decoded: object, path: Path) -> None:
    if not isinstance(decoded, dict):
        raise StateError(f"state file must contain a JSON object: {path}")
    password = decoded.get("password")
    valid = (
        _is_expected_json_number(decoded.get("version"), STATE_VERSION)
        and isinstance(password, dict)
        and password.get("algorithm") == "scrypt"
        and _is_expected_json_number(password.get("n"), SCRYPT_N)
        and _is_expected_json_number(password.get("r"), SCRYPT_R)
        and _is_expected_json_number(password.get("p"), SCRYPT_P)
        and _is_expected_json_number(password.get("keyLength"), SCRYPT_KEY_LENGTH)
        and _valid_base64url(password.get("salt"), SALT_BYTES)
        and _valid_base64url(password.get("digest"), SCRYPT_KEY_LENGTH)
        and _valid_base64url(decoded.get("sessionEpoch"), SESSION_EPOCH_BYTES)
    )
    if not valid:
        raise StateError(f"state file has an invalid or unsupported schema: {path}")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _read_state(path: Path, uid: int) -> tuple[bytes, dict[str, object]]:
    descriptor, metadata = _open_regular_file(path, uid)
    try:
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)

    if len(payload) != metadata.st_size:
        raise StateError(f"state file changed while it was read: {path}")
    try:
        decoded = json.loads(
            payload,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise StateError(f"state file is not valid JSON: {path}") from error
    _validate_state_schema(decoded, path)
    return payload, cast(dict[str, object], decoded)


def _atomic_write(path: Path, payload: bytes, uid: int) -> None:
    _validate_directory(path.parent, uid)
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StateError(f"failed to write an atomic state snapshot: {path}")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        try:
            _fsync_directory(path.parent)
        except OSError:
            # The rename has already committed. Report reduced crash durability
            # without making the caller believe the old state is still active.
            print(
                "warning: auth-state was committed but directory durability sync failed",
                file=sys.stderr,
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def prepare(state_dir: Path, uid: int) -> None:
    _validate_existing_ancestor(state_dir)
    if not _validate_directory(state_dir, uid, allow_missing=True):
        state_dir.mkdir(parents=True, mode=0o700)
        os.chmod(state_dir, 0o700, follow_symlinks=False)
        _validate_directory(state_dir, uid)
        _fsync_directory(state_dir.parent)

    state_file = state_dir / STATE_FILENAME
    if state_file.exists() or state_file.is_symlink():
        _read_state(state_file, uid)


def status(state_dir: Path, uid: int) -> str:
    if not _validate_directory(state_dir, uid, allow_missing=True):
        return "directory=absent state=absent"
    state_file = state_dir / STATE_FILENAME
    if not state_file.exists() and not state_file.is_symlink():
        return "directory=ready state=awaiting-initialization"
    _read_state(state_file, uid)
    return "directory=ready state=ready"


def _new_backup_path(backup_dir: Path, prefix: str) -> Path:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    for _ in range(16):
        candidate = backup_dir / f"{prefix}-{timestamp}-{secrets.token_hex(4)}.json"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise StateError("could not allocate a unique backup filename")


def _validate_backup_location(state_dir: Path, backup_dir: Path) -> None:
    state_path = state_dir.resolve(strict=True)
    backup_path = Path(os.path.abspath(backup_dir))
    if backup_path == state_path or state_path in backup_path.parents:
        raise StateError("backup directory must be outside the mounted auth-state directory")


def backup(
    state_dir: Path,
    backup_dir: Path,
    uid: int,
    *,
    prefix: str = "password",
) -> Path:
    _validate_directory(state_dir, uid)
    _validate_backup_location(state_dir, backup_dir)
    prepare(backup_dir, uid)
    payload, _ = _read_state(state_dir / STATE_FILENAME, uid)
    destination = _new_backup_path(backup_dir, prefix)
    _atomic_write(destination, payload, uid)
    return destination


def restore(
    source: Path,
    state_dir: Path,
    backup_dir: Path,
    uid: int,
) -> tuple[Path | None, Path]:
    prepare(state_dir, uid)
    _validate_backup_location(state_dir, backup_dir)
    prepare(backup_dir, uid)
    _, restored_state = _read_state(source, uid)
    state_file = state_dir / STATE_FILENAME

    previous_backup: Path | None = None
    if state_file.exists() or state_file.is_symlink():
        previous_backup = backup(state_dir, backup_dir, uid, prefix="pre-restore")

    restored_state["sessionEpoch"] = base64.urlsafe_b64encode(
        secrets.token_bytes(SESSION_EPOCH_BYTES)
    ).rstrip(b"=").decode("ascii")
    serialized = json.dumps(restored_state, ensure_ascii=False, separators=(",", ":"))
    payload = f"{serialized}\n".encode("utf-8")
    if len(payload) > MAX_STATE_BYTES:
        raise StateError("restored state exceeds the application size limit")
    _atomic_write(state_file, payload, uid)
    return previous_backup, state_file


def retire(state_dir: Path, backup_dir: Path, uid: int) -> Path | None:
    """Deactivate the local credential record after an owner-only snapshot.

    This is intentionally idempotent. The caller must stop Monitor first so a
    local-mode process cannot keep the retired password/session epoch in memory.
    """

    if not _validate_directory(state_dir, uid, allow_missing=True):
        return None
    state_file = state_dir / STATE_FILENAME
    if not state_file.exists() and not state_file.is_symlink():
        return None
    descriptor, before = _open_regular_file(state_file, uid)
    os.close(descriptor)
    snapshot = backup(state_dir, backup_dir, uid, prefix="retired-sso")
    after = state_file.lstat()
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise StateError(f"state file changed while it was retired: {state_file}")
    state_file.unlink()
    try:
        _fsync_directory(state_dir)
    except OSError:
        # The unlink has already committed. Do not imply that the active state
        # still exists when only crash durability could not be confirmed.
        print(
            "warning: auth-state was retired but directory durability sync failed",
            file=sys.stderr,
        )
    return snapshot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage Monitor password-hash state without displaying its contents."
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("MONITOR_AUTH_STATE_PATH", DEFAULT_STATE_DIR)),
        help=f"host auth-state directory (default: {DEFAULT_STATE_DIR})",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path(os.environ.get("MONITOR_AUTH_BACKUP_PATH", DEFAULT_BACKUP_DIR)),
        help=f"owner-only backup directory (default: {DEFAULT_BACKUP_DIR})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("prepare", help="create or validate the owner-only state directory")
    subparsers.add_parser("status", help="validate paths and report metadata-only status")
    subparsers.add_parser("backup", help="atomically snapshot the current state")
    restore_parser = subparsers.add_parser(
        "restore", help="atomically restore a snapshot while preserving the current state"
    )
    restore_parser.add_argument("snapshot", type=Path)
    restore_parser.add_argument(
        "--confirm-container-stopped",
        action="store_true",
        help="confirm that Monitor is stopped so it cannot race or cache the restored state",
    )
    retire_parser = subparsers.add_parser(
        "retire",
        help="back up and deactivate local password state before an SSO-only deployment",
    )
    retire_parser.add_argument(
        "--confirm-container-stopped",
        action="store_true",
        help="confirm that Monitor is stopped so it cannot cache the retired state",
    )
    retire_parser.add_argument(
        "--confirm-sso-mode",
        action="store_true",
        help="confirm that the replacement deployment uses central SSO",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    uid = os.geteuid()

    if uid == 0:
        parser.error("run this helper as the auth-state owner, not root (production: sudo -u cks)")

    try:
        if arguments.command == "prepare":
            prepare(arguments.state_dir, uid)
            print(f"auth-state prepared: {arguments.state_dir}")
        elif arguments.command == "status":
            print(f"auth-state {status(arguments.state_dir, uid)}")
        elif arguments.command == "backup":
            destination = backup(arguments.state_dir, arguments.backup_dir, uid)
            print(f"auth-state backup created: {destination}")
        elif arguments.command == "restore":
            if not arguments.confirm_container_stopped:
                parser.error("restore requires --confirm-container-stopped")
            previous, restored = restore(
                arguments.snapshot,
                arguments.state_dir,
                arguments.backup_dir,
                uid,
            )
            if previous is not None:
                print(f"previous auth-state backup created: {previous}")
            print(f"auth-state password hash restored with a fresh session epoch: {restored}")
            print("restart Monitor before accepting authentication requests")
        elif arguments.command == "retire":
            if not arguments.confirm_container_stopped or not arguments.confirm_sso_mode:
                parser.error(
                    "retire requires --confirm-container-stopped and --confirm-sso-mode"
                )
            snapshot = retire(
                arguments.state_dir,
                arguments.backup_dir,
                uid,
            )
            if snapshot is None:
                print("auth-state already retired: no active local credential record")
            else:
                print(f"auth-state retired; owner-only recovery snapshot: {snapshot}")
    except StateError as error:
        print(f"auth-state operation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
