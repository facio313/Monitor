"""Strict configuration and private-file validation for the central agent client."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MAX_CONFIG_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 4 * 1024 * 1024
MAX_ENQUEUE_RECORDS = 2_000
MAX_ENQUEUE_BYTES = 2 * 1024 * 1024
MAX_SPOOL_ENTRIES = 64
MAX_SPOOL_BYTES = 4 * 1024 * 1024

_CONFIG_KEYS = {
    "schemaVersion",
    "baseUrl",
    "stateDirectory",
    "clientCertificateFile",
    "clientKeyFile",
    "caCertificateFile",
    "machineIdentityFile",
    "agentVersion",
    "heartbeatIntervalSeconds",
    "lifecycle",
    "requestTimeoutSeconds",
    "maxBatchRecords",
    "maxBatchBytes",
    "maxSpoolEntries",
    "maxSpoolBytes",
    "gzipMinimumBytes",
    "backoffInitialSeconds",
    "backoffMaximumSeconds",
    "retryAfterMaximumSeconds",
}


class ConfigError(ValueError):
    """The client configuration or a referenced private file is unsafe."""


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _number(value: object, name: str, minimum: float, maximum: float) -> float:
    if not _is_number(value):
        raise ConfigError(f"{name} must be a number from {minimum} through {maximum}")
    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be a number from {minimum} through {maximum}")
    return parsed


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > maximum:
        raise ConfigError(f"{name} must be a non-empty string no longer than {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ConfigError(f"{name} contains a control character")
    return value


def _absolute_path(value: object, name: str) -> Path:
    text = _text(value, name, 4096)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or os.path.normpath(text) != text:
        raise ConfigError(f"{name} must be an absolute normalized path")
    return path


def validate_trusted_ancestor_chain(path: Path, child_uid: int) -> None:
    """Reject path components an identity other than root/the service uid can replace."""

    trusted_uids = {0, os.geteuid()}
    for ancestor in path.parents:
        try:
            status = os.lstat(ancestor)
        except OSError as error:
            raise ConfigError(f"cannot safely inspect ancestor {ancestor}") from error
        if not stat.S_ISDIR(status.st_mode):
            raise ConfigError(f"ancestor {ancestor} must be a real directory")
        if status.st_uid not in trusted_uids:
            raise ConfigError(
                f"ancestor {ancestor} must be owned by root or the effective service uid"
            )
        mode = stat.S_IMODE(status.st_mode)
        sticky_protects_child = bool(mode & stat.S_ISVTX) and child_uid in trusted_uids
        if mode & 0o022 and not sticky_protects_child:
            raise ConfigError(
                f"ancestor {ancestor} must not permit group/world replacement"
            )
        child_uid = status.st_uid


def open_trusted_regular(
    path: Path, *, maximum_bytes: int, exact_mode: int | None
) -> tuple[int, os.stat_result]:
    """Open and bind one regular file beneath a root/service-owned path chain."""

    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"{path} must be an absolute normalized path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigError(f"cannot safely open {path}") from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise ConfigError(f"{path} must be one regular, unlinked file")
        if status.st_uid not in {0, os.geteuid()}:
            raise ConfigError(f"{path} must be owned by root or the effective service uid")
        mode = stat.S_IMODE(status.st_mode)
        if exact_mode is not None and mode != exact_mode:
            raise ConfigError(f"{path} must have mode {exact_mode:04o}")
        if exact_mode is None and mode & 0o022:
            raise ConfigError(f"{path} must not be group/world writable")
        if status.st_size < 1 or status.st_size > maximum_bytes:
            raise ConfigError(f"{path} has an invalid size")
        validate_trusted_ancestor_chain(path, status.st_uid)
        try:
            current = os.lstat(path)
        except OSError as error:
            raise ConfigError(f"{path} changed while its path was validated") from error
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
            status.st_dev,
            status.st_ino,
        ):
            raise ConfigError(f"{path} changed while its path was validated")
        return descriptor, status
    except Exception:
        os.close(descriptor)
        raise


def read_private_file(path: Path, maximum_bytes: int, *, exact_mode: int = 0o600) -> bytes:
    """Read a root/service-owned regular file without following its final component."""

    descriptor, status = open_trusted_regular(
        path, maximum_bytes=maximum_bytes, exact_mode=exact_mode
    )
    try:
        chunks: list[bytes] = []
        remaining = status.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ConfigError(f"{path} changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ConfigError(f"{path} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_public_credential(path: Path) -> None:
    """Validate a certificate/CA file. Public material may be 0644 but never writable."""

    descriptor, _ = open_trusted_regular(
        path, maximum_bytes=MAX_CREDENTIAL_BYTES, exact_mode=None
    )
    os.close(descriptor)


@dataclass(frozen=True)
class TransportConfig:
    base_url: str
    state_directory: Path
    client_certificate_file: Path
    client_key_file: Path
    ca_certificate_file: Path
    machine_identity_file: Path
    agent_version: str
    heartbeat_interval_seconds: int
    lifecycle: str
    request_timeout_seconds: float
    max_batch_records: int
    max_batch_bytes: int
    max_spool_entries: int
    max_spool_bytes: int
    gzip_minimum_bytes: int
    backoff_initial_seconds: float
    backoff_maximum_seconds: float
    retry_after_maximum_seconds: int

    @classmethod
    def from_mapping(cls, value: object) -> "TransportConfig":
        if not isinstance(value, dict) or set(value) != _CONFIG_KEYS:
            raise ConfigError("agent transport configuration has an invalid exact schema")
        if value.get("schemaVersion") != 1:
            raise ConfigError("schemaVersion must be 1")

        base_url = _text(value["baseUrl"], "baseUrl", 2048)
        parsed_url = urlsplit(base_url)
        try:
            port = parsed_url.port
        except ValueError as error:
            raise ConfigError("baseUrl has an invalid port") from error
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
            or parsed_url.path != "/monitor/api"
            or base_url.endswith("/")
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ConfigError("baseUrl must be an HTTPS origin ending exactly in /monitor/api")

        agent_version = _text(value["agentVersion"], "agentVersion", 64)
        heartbeat_interval = _integer(
            value["heartbeatIntervalSeconds"], "heartbeatIntervalSeconds", 10, 86_400
        )
        lifecycle = value["lifecycle"]
        if lifecycle not in {"active", "maintenance", "inactive"}:
            raise ConfigError("lifecycle must be active, maintenance, or inactive")
        request_timeout = _number(value["requestTimeoutSeconds"], "requestTimeoutSeconds", 0.1, 60)
        max_batch_records = _integer(value["maxBatchRecords"], "maxBatchRecords", 1, 500)
        max_batch_bytes = _integer(value["maxBatchBytes"], "maxBatchBytes", 1024, 262_144)
        max_spool_entries = _integer(
            value["maxSpoolEntries"], "maxSpoolEntries", 1, MAX_SPOOL_ENTRIES
        )
        max_spool_bytes = _integer(
            value["maxSpoolBytes"],
            "maxSpoolBytes",
            max_batch_bytes * 4,
            MAX_SPOOL_BYTES,
        )
        gzip_minimum = _integer(value["gzipMinimumBytes"], "gzipMinimumBytes", 0, max_batch_bytes)
        backoff_initial = _number(value["backoffInitialSeconds"], "backoffInitialSeconds", 0.1, 60)
        backoff_maximum = _number(value["backoffMaximumSeconds"], "backoffMaximumSeconds", 0.1, 3600)
        if backoff_maximum < backoff_initial:
            raise ConfigError("backoffMaximumSeconds must not be less than backoffInitialSeconds")
        retry_after_maximum = _integer(
            value["retryAfterMaximumSeconds"], "retryAfterMaximumSeconds", 1, 86_400
        )

        return cls(
            base_url=base_url,
            state_directory=_absolute_path(value["stateDirectory"], "stateDirectory"),
            client_certificate_file=_absolute_path(
                value["clientCertificateFile"], "clientCertificateFile"
            ),
            client_key_file=_absolute_path(value["clientKeyFile"], "clientKeyFile"),
            ca_certificate_file=_absolute_path(value["caCertificateFile"], "caCertificateFile"),
            machine_identity_file=_absolute_path(
                value["machineIdentityFile"], "machineIdentityFile"
            ),
            agent_version=agent_version,
            heartbeat_interval_seconds=heartbeat_interval,
            lifecycle=str(lifecycle),
            request_timeout_seconds=request_timeout,
            max_batch_records=max_batch_records,
            max_batch_bytes=max_batch_bytes,
            max_spool_entries=max_spool_entries,
            max_spool_bytes=max_spool_bytes,
            gzip_minimum_bytes=gzip_minimum,
            backoff_initial_seconds=backoff_initial,
            backoff_maximum_seconds=backoff_maximum,
            retry_after_maximum_seconds=retry_after_maximum,
        )

    @classmethod
    def load(cls, path: Path) -> "TransportConfig":
        encoded = read_private_file(path, MAX_CONFIG_BYTES)
        try:
            value: Any = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConfigError("agent transport configuration is not valid UTF-8 JSON") from error
        return cls.from_mapping(value)

    def validate_credentials(self) -> None:
        validate_public_credential(self.client_certificate_file)
        validate_public_credential(self.ca_certificate_file)
        descriptor, _ = open_trusted_regular(
            self.client_key_file, maximum_bytes=MAX_CREDENTIAL_BYTES, exact_mode=0o600
        )
        os.close(descriptor)


__all__ = [
    "ConfigError",
    "MAX_CONFIG_BYTES",
    "MAX_ENQUEUE_BYTES",
    "MAX_ENQUEUE_RECORDS",
    "MAX_SPOOL_BYTES",
    "MAX_SPOOL_ENTRIES",
    "TransportConfig",
    "open_trusted_regular",
    "read_private_file",
    "validate_trusted_ancestor_chain",
    "validate_public_credential",
]
