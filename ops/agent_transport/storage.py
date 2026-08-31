"""Private, crash-safe filesystem primitives used only by agent_transport."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

from .config import ConfigError, validate_trusted_ancestor_chain


class StorageError(RuntimeError):
    """The local transport state is unsafe or corrupt."""


DirectoryIdentity = tuple[int, int]
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.05


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_storage_ancestors(path: Path, child_uid: int) -> None:
    try:
        validate_trusted_ancestor_chain(path, child_uid)
    except ConfigError as error:
        raise StorageError(str(error)) from error


def ensure_private_directory(
    path: Path,
    *,
    create: bool = True,
    expected: DirectoryIdentity | None = None,
) -> DirectoryIdentity:
    if not path.is_absolute() or ".." in path.parts or os.path.normpath(str(path)) != str(path):
        raise StorageError(f"private directory path must be absolute and normalized: {path}")
    if create:
        try:
            path.lstat()
        except FileNotFoundError:
            # A newly created owner-owned child is protected by a trusted
            # sticky parent, but not by a foreign or non-sticky writable one.
            _validate_storage_ancestors(path, os.geteuid())
            try:
                path.mkdir(mode=0o700, parents=False, exist_ok=False)
                fsync_directory(path.parent)
            except FileExistsError:
                pass
            except FileNotFoundError as error:
                raise StorageError(f"parent directory does not exist for {path}") from error
            except OSError as error:
                raise StorageError(f"cannot safely create private directory {path}") from error
        except OSError as error:
            raise StorageError(f"cannot inspect private directory {path}") from error
    try:
        status = path.lstat()
    except OSError as error:
        raise StorageError(f"cannot inspect private directory {path}") from error
    if (
        not stat.S_ISDIR(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        raise StorageError(f"{path} must be an owner-owned, non-linked mode-0700 directory")
    _validate_storage_ancestors(path, status.st_uid)
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StorageError(f"cannot safely bind private directory {path}") from error
    try:
        opened = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as error:
            raise StorageError(f"private directory {path} changed while it was bound") from error
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or identity != (status.st_dev, status.st_ino)
            or identity != (current.st_dev, current.st_ino)
        ):
            raise StorageError(f"private directory {path} changed while it was bound")
        if expected is not None and identity != expected:
            raise StorageError(f"private directory {path} changed identity")
        return identity
    finally:
        os.close(descriptor)


def validate_private_file(path: Path, *, maximum_bytes: int, allow_empty: bool = False) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as error:
        raise StorageError(f"cannot inspect private file {path}") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid != os.geteuid()
        or status.st_nlink != 1
        or stat.S_IMODE(status.st_mode) != 0o600
        or (not allow_empty and status.st_size < 1)
        or status.st_size > maximum_bytes
    ):
        raise StorageError(f"{path} is not a safe mode-0600 regular file")
    return status


def read_private(path: Path, *, maximum_bytes: int) -> bytes:
    expected = validate_private_file(path, maximum_bytes=maximum_bytes)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StorageError(f"cannot safely open {path}") from error
    try:
        actual = os.fstat(descriptor)
        if (
            (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
            or not stat.S_ISREG(actual.st_mode)
            or actual.st_uid != os.geteuid()
            or actual.st_nlink != 1
            or stat.S_IMODE(actual.st_mode) != 0o600
        ):
            raise StorageError(f"{path} changed while it was opened")
        encoded = bytearray()
        while len(encoded) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(encoded)))
            if not chunk:
                break
            encoded.extend(chunk)
        if len(encoded) > maximum_bytes:
            raise StorageError(f"{path} exceeds its size bound")
        return bytes(encoded)
    finally:
        os.close(descriptor)


def atomic_private_write(path: Path, encoded: bytes, *, replace: bool = True) -> None:
    ensure_private_directory(path.parent, create=False)
    if not encoded:
        raise StorageError(f"refusing to write an empty private file at {path}")
    if path.exists() or path.is_symlink():
        if not replace:
            raise StorageError(f"private file already exists: {path}")
        validate_private_file(path, maximum_bytes=max(len(encoded) * 8, 64 * 1024 * 1024))
    temporary = path.parent / f".{path.name}.tmp-{uuid.uuid4()}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StorageError(f"short write while staging {path}")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        try:
            temporary.unlink()
            fsync_directory(path.parent)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def unlink_durable(path: Path, *, maximum_bytes: int) -> None:
    validate_private_file(path, maximum_bytes=maximum_bytes)
    path.unlink()
    fsync_directory(path.parent)


def erase_private_file(path: Path, *, expected: tuple[int, int, int] | None = None) -> None:
    """Best-effort overwrite/truncate/unlink with identity checks and durable unlink."""

    try:
        before = validate_private_file(path, maximum_bytes=16 * 1024 * 1024, allow_empty=True)
    except StorageError:
        if not path.exists() and not path.is_symlink():
            return
        raise
    if expected is not None and (before.st_dev, before.st_ino, before.st_size) != expected:
        raise StorageError(f"refusing to erase replaced token file {path}")
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise StorageError(f"refusing to erase changed token file {path}")
        remaining = opened.st_size
        zeros = b"\0" * min(64 * 1024, max(1, remaining))
        os.lseek(descriptor, 0, os.SEEK_SET)
        while remaining:
            written = os.write(descriptor, zeros[: min(remaining, len(zeros))])
            if written <= 0:
                raise StorageError(f"short overwrite while erasing {path}")
            remaining -= written
        os.fsync(descriptor)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise StorageError(f"refusing to unlink replaced token file {path}")
    path.unlink()
    fsync_directory(path.parent)


@contextlib.contextmanager
def exclusive_lock(
    path: Path,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 60
    ):
        raise StorageError("transport lock timeout is invalid")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    locked = False
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.geteuid()
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            raise StorageError(f"{path} is not a safe transport lock")
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StorageError(
                        "timed out waiting for the private transport lock"
                    ) from error
                time.sleep(min(LOCK_POLL_SECONDS, remaining))
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def decode_exact_json(encoded: bytes, keys: set[str], description: str) -> dict[str, object]:
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StorageError(f"{description} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != keys:
        raise StorageError(f"{description} has an invalid exact schema")
    return value


__all__ = [
    "DirectoryIdentity",
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "StorageError",
    "atomic_private_write",
    "canonical_json",
    "decode_exact_json",
    "ensure_private_directory",
    "erase_private_file",
    "exclusive_lock",
    "fsync_directory",
    "read_private",
    "unlink_durable",
    "validate_private_file",
]
