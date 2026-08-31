#!/usr/bin/env python3
"""Durable, bounded alert delivery outbox and channel worker.

The evaluator only enqueues normalized transitions.  Network I/O happens in a
separate worker process.  Channel credentials are resolved at send time from an
environment variable or a root-owned file and are never stored in SQLite,
delivery logs, exceptions, or command output.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import email.message
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import smtplib
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

try:  # Package imports for tests; direct imports for installed scripts.
    from .alert_engine import LABEL_NAME, LABEL_VALUE, SEVERITIES
    from .alert_store import normalize_event
except ImportError:  # pragma: no cover - exercised by the installed script
    from alert_engine import LABEL_NAME, LABEL_VALUE, SEVERITIES  # type: ignore[no-redef]
    from alert_store import normalize_event  # type: ignore[no-redef]


CONFIG_SCHEMA_VERSION = 1
OUTBOX_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_SECRET_BYTES = 8192
MAX_STAT_COUNTER = (1 << 63) - 1
MAX_CHANNELS = 64
MAX_ROUTES = 128
MAX_HEADERS = 16
MAX_RECIPIENTS = 20
MAX_HTTPS_DNS_ANSWERS = 32
MAX_ENQUEUE_BATCH = 4096
MAX_WORKER_RUNTIME_SECONDS = 300.0
DEFAULT_WORKER_RUNTIME_SECONDS = 45.0
DELIVERY_LEASE_MARGIN_SECONDS = 5.0
# Budget all three smtplib authentication mechanisms, including their bounded
# challenge exchanges, before the remaining connection/message operations.
SMTP_AUTH_TIMEOUT_STEPS = 18
SMTP_IMPLICIT_FIXED_TIMEOUT_STEPS = SMTP_AUTH_TIMEOUT_STEPS + 9
SMTP_STARTTLS_FIXED_TIMEOUT_STEPS = SMTP_AUTH_TIMEOUT_STEPS + 11
DEFAULT_CONFIG_PATH = Path("/etc/monitor/alert-delivery.json")
DEFAULT_DB_PATH = Path("/var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite")
CHANNEL_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
ROUTE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
WORKER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$")
ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
TEST_REQUEST_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
SMTP_HOST = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")
EMAIL_ADDRESS = re.compile(r"^[^\s@<>\r\n]{1,64}@[^\s@<>\r\n]{1,189}$")
TELEGRAM_CHAT = re.compile(r"^-?[0-9]{1,20}$")
TELEGRAM_TOKEN = re.compile(r"^[0-9]{6,16}:[A-Za-z0-9_-]{20,128}$")
HTTP_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
HTTP_HEADER_VALUE = re.compile(r"^[\x20-\x7e]{0,256}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
FORBIDDEN_HEADERS = frozenset({
    "authorization", "cookie", "proxy-authorization", "set-cookie",
    "host", "content-length", "transfer-encoding", "content-type",
    "user-agent", "idempotency-key",
})
CHANNEL_KINDS = frozenset({"webhook", "slack", "discord", "telegram", "smtp"})
TRANSITIONS = frozenset({"firing", "resolved"})
OUTBOX_STATES = frozenset({"pending", "retry", "leased", "succeeded", "failed", "dropped"})
PURPOSES = frozenset({"operational", "test"})
NON_DELIVERABLE_OPERATIONAL_RULES = frozenset({"NotificationDeliveryFailure"})


@dataclass(frozen=True)
class SecretRef:
    provider: str
    key: str


@dataclass(frozen=True)
class ChannelConfig:
    channel_id: str
    kind: str
    enabled: bool
    timeout_seconds: float
    max_attempts: int
    base_backoff_seconds: float
    max_backoff_seconds: float
    secret_ref: SecretRef
    settings: Mapping[str, Any]


@dataclass(frozen=True)
class RouteConfig:
    route_id: str
    priority: int
    enabled: bool
    severities: frozenset[str]
    transitions: frozenset[str]
    labels: tuple[tuple[str, str], ...]
    channel_ids: tuple[str, ...]
    continue_matching: bool


@dataclass(frozen=True)
class QueueConfig:
    max_pending: int
    max_history: int
    max_delivery_log: int
    lease_seconds: int
    batch_size: int
    replay_window_seconds: int


@dataclass(frozen=True)
class DeliveryConfig:
    channels: tuple[ChannelConfig, ...]
    routes: tuple[RouteConfig, ...]
    queue: QueueConfig

    def channel(self, channel_id: str) -> ChannelConfig | None:
        return next((item for item in self.channels if item.channel_id == channel_id), None)


@dataclass(frozen=True)
class DeliveryTask:
    delivery_key: str
    event_key: str
    channel_id: str
    purpose: str
    payload: Mapping[str, Any]
    priority: int
    attempt: int
    max_attempts: int
    base_backoff_seconds: float
    max_backoff_seconds: float
    lease_owner: str


@dataclass(frozen=True)
class DeliveryResult:
    outcome: str
    status_code: int | None = None
    error_code: str | None = None
    retry_after_seconds: float | None = None

    @classmethod
    def success(cls, status_code: int | None = None) -> "DeliveryResult":
        return cls("success", status_code)

    @classmethod
    def retryable(
        cls, error_code: str, status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> "DeliveryResult":
        return cls("retryable", status_code, error_code, retry_after_seconds)

    @classmethod
    def permanent(
        cls, error_code: str, status_code: int | None = None,
    ) -> "DeliveryResult":
        return cls("permanent", status_code, error_code)


@dataclass(frozen=True)
class _HttpsEndpoint:
    hostname: str
    port: int
    authority: str
    request_target: str
    url: str


@dataclass(frozen=True)
class _ResolvedDestination:
    family: int
    address: str
    sockaddr: tuple[Any, ...]


class _UnsafeHttpsDestination(ValueError):
    """The endpoint or one of its DNS answers is not safe for egress."""


class _DeliveryDeadlineExpired(BaseException):
    """Escape transport-library ``except Exception`` handlers on wall expiry."""


def _raise_delivery_deadline(_signum: int, _frame: Any) -> None:
    raise _DeliveryDeadlineExpired()


def _exact(value: Mapping[str, Any], expected: frozenset[str], field: str) -> None:
    if frozenset(value) != expected:
        raise ValueError(f"{field} does not match the schema")


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} is invalid")
    return value


def _finite(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} is invalid")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} is invalid")
    return result


def _string(value: Any, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not allow_empty):
        raise ValueError(f"{field} is invalid")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError(f"{field} is invalid")
    return value


def _parse_secret_ref(value: Any, field: str) -> SecretRef:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} is invalid")
    _exact(value, frozenset({"provider", "key"}), field)
    provider = value.get("provider")
    key = value.get("key")
    if provider == "env":
        if not isinstance(key, str) or ENV_NAME.fullmatch(key) is None:
            raise ValueError(f"{field} environment reference is invalid")
    elif provider == "file":
        if (
            not isinstance(key, str)
            or len(key) > 512
            or not Path(key).is_absolute()
            or "\x00" in key
        ):
            raise ValueError(f"{field} file reference is invalid")
    else:
        raise ValueError(f"{field} provider is unsupported")
    return SecretRef(provider, str(key))


def _headers(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > MAX_HEADERS:
        raise ValueError(f"{field} is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or HTTP_HEADER.fullmatch(key) is None
            or key.lower() in FORBIDDEN_HEADERS
            or not isinstance(item, str)
            or HTTP_HEADER_VALUE.fullmatch(item) is None
        ):
            raise ValueError(f"{field} contains an unsafe header")
        result[key] = item
    return dict(sorted(result.items()))


def _settings(kind: str, value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} is invalid")
    if kind == "webhook":
        _exact(value, frozenset({"headers"}), field)
        return {"headers": _headers(value.get("headers"), f"{field}.headers")}
    if kind in {"slack", "discord"}:
        _exact(value, frozenset({"username"}), field)
        username = _string(value.get("username"), f"{field}.username", 64, True)
        return {"username": username}
    if kind == "telegram":
        _exact(value, frozenset({"chatId", "disableNotification"}), field)
        chat_id = value.get("chatId")
        disabled = value.get("disableNotification")
        if not isinstance(chat_id, str) or TELEGRAM_CHAT.fullmatch(chat_id) is None:
            raise ValueError(f"{field}.chatId is invalid")
        if not isinstance(disabled, bool):
            raise ValueError(f"{field}.disableNotification is invalid")
        return {"chatId": chat_id, "disableNotification": disabled}
    if kind == "smtp":
        _exact(value, frozenset({"host", "port", "from", "to", "username", "tlsMode"}), field)
        host = value.get("host")
        sender = value.get("from")
        username = value.get("username")
        recipients = value.get("to")
        tls_mode = value.get("tlsMode")
        if not isinstance(host, str) or SMTP_HOST.fullmatch(host) is None:
            raise ValueError(f"{field}.host is invalid")
        if not isinstance(sender, str) or EMAIL_ADDRESS.fullmatch(sender) is None:
            raise ValueError(f"{field}.from is invalid")
        if not isinstance(username, str) or len(username) > 254 or "\n" in username or "\r" in username:
            raise ValueError(f"{field}.username is invalid")
        if (
            not isinstance(recipients, list)
            or not 1 <= len(recipients) <= MAX_RECIPIENTS
            or any(not isinstance(item, str) or EMAIL_ADDRESS.fullmatch(item) is None for item in recipients)
        ):
            raise ValueError(f"{field}.to is invalid")
        if tls_mode not in {"starttls", "implicit"}:
            raise ValueError(f"{field}.tlsMode is invalid")
        return {
            "host": host,
            "port": _integer(value.get("port"), f"{field}.port", 1, 65535),
            "from": sender,
            "to": tuple(recipients),
            "username": username,
            "tlsMode": tls_mode,
        }
    raise ValueError(f"{field} channel kind is unsupported")


def _channel_delivery_deadline_seconds(channel: ChannelConfig) -> float:
    if channel.kind != "smtp":
        return channel.timeout_seconds * 2
    fixed_steps = (
        SMTP_STARTTLS_FIXED_TIMEOUT_STEPS
        if channel.settings["tlsMode"] == "starttls"
        else SMTP_IMPLICIT_FIXED_TIMEOUT_STEPS
    )
    # This multiplier defines an explicit end-to-end policy budget; it does not
    # assume that per-socket timeouts bound an SMTP session. The SIGALRM
    # watchdog below enforces the resulting wall deadline across DNS, TLS,
    # authentication, every recipient, DATA, and response parsing.
    timeout_steps = fixed_steps + len(channel.settings["to"])
    return channel.timeout_seconds * timeout_steps


def _required_channel_lease_seconds(channel: ChannelConfig) -> int:
    return int(math.ceil(
        _channel_delivery_deadline_seconds(channel) + DELIVERY_LEASE_MARGIN_SECONDS,
    ))


def parse_delivery_config(value: Any) -> DeliveryConfig:
    if not isinstance(value, Mapping):
        raise ValueError("delivery configuration must be an object")
    _exact(value, frozenset({"schemaVersion", "queue", "channels", "routes"}), "delivery configuration")
    if value.get("schemaVersion") != CONFIG_SCHEMA_VERSION:
        raise ValueError("delivery configuration schema is unsupported")

    raw_queue = value.get("queue")
    if not isinstance(raw_queue, Mapping):
        raise ValueError("delivery queue configuration is invalid")
    _exact(raw_queue, frozenset({
        "maxPending", "maxHistory", "maxDeliveryLog", "leaseSeconds",
        "batchSize", "replayWindowSeconds",
    }), "delivery queue configuration")
    queue = QueueConfig(
        max_pending=_integer(raw_queue.get("maxPending"), "maxPending", 1, 10_000),
        max_history=_integer(raw_queue.get("maxHistory"), "maxHistory", 10, 20_000),
        max_delivery_log=_integer(raw_queue.get("maxDeliveryLog"), "maxDeliveryLog", 10, 50_000),
        lease_seconds=_integer(raw_queue.get("leaseSeconds"), "leaseSeconds", 5, 300),
        batch_size=_integer(raw_queue.get("batchSize"), "batchSize", 1, 100),
        replay_window_seconds=_integer(
            raw_queue.get("replayWindowSeconds"), "replayWindowSeconds", 60, 86_400,
        ),
    )

    raw_channels = value.get("channels")
    if not isinstance(raw_channels, list) or len(raw_channels) > MAX_CHANNELS:
        raise ValueError("delivery channels are invalid")
    channels: list[ChannelConfig] = []
    seen_channels: set[str] = set()
    channel_fields = frozenset({
        "id", "kind", "enabled", "timeoutSeconds", "maxAttempts",
        "baseBackoffSeconds", "maxBackoffSeconds", "secretRef", "settings",
    })
    for index, raw in enumerate(raw_channels):
        field = f"channels[{index}]"
        if not isinstance(raw, Mapping):
            raise ValueError(f"{field} is invalid")
        _exact(raw, channel_fields, field)
        channel_id = raw.get("id")
        kind = raw.get("kind")
        enabled = raw.get("enabled")
        if (
            not isinstance(channel_id, str)
            or CHANNEL_ID.fullmatch(channel_id) is None
            or channel_id in seen_channels
        ):
            raise ValueError(f"{field}.id is invalid")
        if not isinstance(kind, str) or kind not in CHANNEL_KINDS or not isinstance(enabled, bool):
            raise ValueError(f"{field} kind or enabled state is invalid")
        seen_channels.add(channel_id)
        base = _finite(raw.get("baseBackoffSeconds"), f"{field}.baseBackoffSeconds", 0.25, 3600)
        maximum = _finite(raw.get("maxBackoffSeconds"), f"{field}.maxBackoffSeconds", base, 86_400)
        channels.append(ChannelConfig(
            channel_id=channel_id,
            kind=str(kind),
            enabled=enabled,
            timeout_seconds=_finite(raw.get("timeoutSeconds"), f"{field}.timeoutSeconds", 0.25, 30),
            max_attempts=_integer(raw.get("maxAttempts"), f"{field}.maxAttempts", 1, 12),
            base_backoff_seconds=base,
            max_backoff_seconds=maximum,
            secret_ref=_parse_secret_ref(raw.get("secretRef"), f"{field}.secretRef"),
            settings=_settings(str(kind), raw.get("settings"), f"{field}.settings"),
        ))

    required_lease = max(
        (
            _required_channel_lease_seconds(item)
            for item in channels if item.enabled
        ),
        default=5,
    )
    if queue.lease_seconds < required_lease:
        raise ValueError("delivery leaseSeconds is too short for enabled channel timeouts")

    raw_routes = value.get("routes")
    if not isinstance(raw_routes, list) or len(raw_routes) > MAX_ROUTES:
        raise ValueError("delivery routes are invalid")
    routes: list[RouteConfig] = []
    seen_routes: set[str] = set()
    route_fields = frozenset({
        "id", "priority", "enabled", "severities", "transitions", "labels",
        "channels", "continue",
    })
    for index, raw in enumerate(raw_routes):
        field = f"routes[{index}]"
        if not isinstance(raw, Mapping):
            raise ValueError(f"{field} is invalid")
        _exact(raw, route_fields, field)
        route_id = raw.get("id")
        enabled = raw.get("enabled")
        continue_matching = raw.get("continue")
        if (
            not isinstance(route_id, str)
            or ROUTE_ID.fullmatch(route_id) is None
            or route_id in seen_routes
            or not isinstance(enabled, bool)
            or not isinstance(continue_matching, bool)
        ):
            raise ValueError(f"{field} identity is invalid")
        seen_routes.add(route_id)
        raw_severities = raw.get("severities")
        raw_transitions = raw.get("transitions")
        raw_channel_ids = raw.get("channels")
        if (
            not isinstance(raw_severities, list)
            or not raw_severities
            or not all(isinstance(item, str) for item in raw_severities)
            or len(raw_severities) != len(set(raw_severities))
            or not set(raw_severities) <= SEVERITIES
            or not isinstance(raw_transitions, list)
            or not raw_transitions
            or not all(isinstance(item, str) for item in raw_transitions)
            or len(raw_transitions) != len(set(raw_transitions))
            or not set(raw_transitions) <= TRANSITIONS
            or not isinstance(raw_channel_ids, list)
            or not raw_channel_ids
            or not all(isinstance(item, str) for item in raw_channel_ids)
            or len(raw_channel_ids) != len(set(raw_channel_ids))
            or any(item not in seen_channels for item in raw_channel_ids)
        ):
            raise ValueError(f"{field} selectors are invalid")
        raw_labels = raw.get("labels")
        if not isinstance(raw_labels, Mapping) or len(raw_labels) > 16:
            raise ValueError(f"{field}.labels is invalid")
        labels: list[tuple[str, str]] = []
        for key, item in raw_labels.items():
            if (
                not isinstance(key, str)
                or LABEL_NAME.fullmatch(key) is None
                or not isinstance(item, str)
                or LABEL_VALUE.fullmatch(item) is None
            ):
                raise ValueError(f"{field}.labels is invalid")
            labels.append((key, item))
        routes.append(RouteConfig(
            route_id=route_id,
            priority=_integer(raw.get("priority"), f"{field}.priority", 0, 10_000),
            enabled=enabled,
            severities=frozenset(raw_severities),
            transitions=frozenset(raw_transitions),
            labels=tuple(sorted(labels)),
            channel_ids=tuple(raw_channel_ids),
            continue_matching=continue_matching,
        ))
    return DeliveryConfig(
        channels=tuple(channels),
        routes=tuple(sorted(routes, key=lambda item: (-item.priority, item.route_id))),
        queue=queue,
    )


def _read_bounded_regular(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ValueError("delivery configuration file is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_nlink != 1
            or opened.st_size != metadata.st_size
        ):
            raise ValueError("delivery configuration file changed while reading")
        payload = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or len(payload) > maximum:
        raise ValueError("delivery configuration file changed while reading")
    return payload


def load_delivery_config(path: Path) -> DeliveryConfig:
    try:
        payload = _read_bounded_regular(path, MAX_CONFIG_BYTES)
        return parse_delivery_config(json.loads(payload.decode("utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("delivery configuration could not be read") from error


def resolve_secret(reference: SecretRef) -> str:
    if reference.provider == "env":
        value = os.environ.get(reference.key)
        if value is None:
            raise ValueError("delivery secret is unavailable")
        try:
            payload = value.encode("utf-8", "strict")
        except UnicodeError as error:
            raise ValueError("delivery secret is unavailable") from error
    elif reference.provider == "file":
        path = Path(reference.key)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or not 0 < metadata.st_size <= MAX_SECRET_BYTES
        ):
            raise ValueError("delivery secret is unavailable")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_nlink != 1
                or opened.st_size != metadata.st_size
            ):
                raise ValueError("delivery secret is unavailable")
            payload = os.read(descriptor, MAX_SECRET_BYTES + 1)
        finally:
            os.close(descriptor)
    else:  # Config parsing prevents this, but keep the send boundary fail-closed.
        raise ValueError("delivery secret is unavailable")
    if not 0 < len(payload) <= MAX_SECRET_BYTES:
        raise ValueError("delivery secret is unavailable")
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeError as error:
        raise ValueError("delivery secret is unavailable") from error
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("delivery secret is unavailable")
    return value


def _epoch(value: dt.datetime | float | int) -> float:
    if isinstance(value, bool):
        raise ValueError("delivery time is invalid")
    if isinstance(value, (float, int)):
        result = float(value)
    elif isinstance(value, dt.datetime):
        normalized = value if value.tzinfo is not None else value.replace(tzinfo=dt.timezone.utc)
        result = normalized.astimezone(dt.timezone.utc).timestamp()
    else:
        raise ValueError("delivery time is invalid")
    if not math.isfinite(result) or result < 0:
        raise ValueError("delivery time is invalid")
    return result


def delivery_identity(event_key: str, channel_id: str, purpose: str) -> str:
    if (
        not isinstance(event_key, str)
        or re.fullmatch(r"[0-9a-f]{64}", event_key) is None
        or not isinstance(channel_id, str)
        or CHANNEL_ID.fullmatch(channel_id) is None
        or not isinstance(purpose, str)
        or purpose not in PURPOSES
    ):
        raise ValueError("delivery identity is invalid")
    return hashlib.sha256(
        f"{event_key}\0{channel_id}\0{purpose}".encode("utf-8")
    ).hexdigest()


def _validate_db_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_DB_BYTES
    ):
        raise ValueError("delivery outbox file is unsafe")


class DeliveryOutbox:
    """SQLite-backed finite queue with atomic leasing and bounded history."""

    def __init__(self, path: Path, queue: QueueConfig):
        if not path.is_absolute():
            raise ValueError("delivery outbox path must be absolute")
        self.path = path
        self.queue = queue
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        _validate_db_file(self.path)
        connection = sqlite3.connect(
            self.path,
            timeout=2.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 2000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        connection.execute(f"PRAGMA max_page_count = {max(1, MAX_DB_BYTES // page_size)}")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_metadata = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise ValueError("delivery outbox directory is unsafe")
        _validate_db_file(self.path)
        if not self.path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        os.chmod(self.path, 0o600, follow_symlinks=False)
        _validate_db_file(self.path)
        with contextlib.closing(self._connect()) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, OUTBOX_SCHEMA_VERSION}:
                raise ValueError("delivery outbox schema is unsupported")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS outbox (
                    delivery_key TEXT PRIMARY KEY CHECK(length(delivery_key) = 64),
                    event_key TEXT NOT NULL CHECK(length(event_key) = 64),
                    channel_id TEXT NOT NULL CHECK(length(channel_id) BETWEEN 2 AND 64),
                    purpose TEXT NOT NULL CHECK(purpose IN ('operational','test')),
                    payload_json TEXT NOT NULL CHECK(length(payload_json) <= 16384),
                    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100000),
                    state TEXT NOT NULL CHECK(state IN ('pending','retry','leased','succeeded','failed','dropped')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 12),
                    max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 12),
                    base_backoff_seconds REAL NOT NULL CHECK(base_backoff_seconds BETWEEN 0.25 AND 3600),
                    max_backoff_seconds REAL NOT NULL CHECK(max_backoff_seconds BETWEEN base_backoff_seconds AND 86400),
                    next_attempt_at REAL,
                    lease_owner TEXT,
                    lease_expires_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    completed_at REAL,
                    last_status_code INTEGER,
                    last_error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS outbox_due
                    ON outbox(state, next_attempt_at, priority DESC, created_at);
                CREATE TABLE IF NOT EXISTS delivery_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_key TEXT NOT NULL CHECK(length(delivery_key) = 64),
                    channel_id TEXT NOT NULL,
                    purpose TEXT NOT NULL CHECK(purpose IN ('operational','test')),
                    attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 12),
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    outcome TEXT NOT NULL CHECK(outcome IN (
                        'leased','success','retry','permanent_failure','exhausted',
                        'lease_expired','dropped','evicted'
                    )),
                    status_code INTEGER,
                    error_code TEXT,
                    UNIQUE(delivery_key, attempt)
                );
                CREATE INDEX IF NOT EXISTS delivery_log_recent
                    ON delivery_log(id DESC);
                CREATE TABLE IF NOT EXISTS delivery_stats (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL CHECK(value >= 0)
                );
            """)
            if version == 0:
                connection.execute(f"PRAGMA user_version = {OUTBOX_SCHEMA_VERSION}")
        _validate_db_file(self.path)

    @staticmethod
    def _increment(connection: sqlite3.Connection, name: str, amount: int = 1) -> None:
        if amount <= 0:
            return
        connection.execute(
            """INSERT INTO delivery_stats(name,value) VALUES(?,?)
               ON CONFLICT(name) DO UPDATE SET value = CASE
                   WHEN value > ? - excluded.value THEN ?
                   ELSE value + excluded.value END""",
            (name, min(amount, MAX_STAT_COUNTER), MAX_STAT_COUNTER, MAX_STAT_COUNTER),
        )

    def _prune(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """DELETE FROM outbox
               WHERE state IN ('succeeded','failed','dropped')
                 AND delivery_key NOT IN (
                     SELECT delivery_key FROM outbox
                     WHERE state IN ('succeeded','failed','dropped')
                     ORDER BY updated_at DESC, delivery_key DESC LIMIT ?
                 )""",
            (self.queue.max_history,),
        )
        connection.execute(
            """DELETE FROM delivery_log
               WHERE id NOT IN (
                   SELECT id FROM delivery_log ORDER BY id DESC LIMIT ?
               )""",
            (self.queue.max_delivery_log,),
        )

    def enqueue(
        self,
        event: Mapping[str, Any],
        channel: ChannelConfig,
        purpose: str,
        now: dt.datetime | float | int,
    ) -> str:
        prepared = self._prepare_enqueue(event, channel, purpose, _epoch(now))
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            disposition = self._enqueue_prepared(connection, prepared)
            self._prune(connection)
            connection.execute("COMMIT")
            return disposition

    def _prepare_enqueue(
        self,
        event: Mapping[str, Any],
        channel: ChannelConfig,
        purpose: str,
        created_at: float,
    ) -> tuple[dict[str, Any], ChannelConfig, str, str, str, int, float]:
        normalized = normalize_event(event)
        if (
            not isinstance(purpose, str)
            or purpose not in PURPOSES
            or CHANNEL_ID.fullmatch(channel.channel_id) is None
        ):
            raise ValueError("delivery enqueue identity is invalid")
        event_key = normalized["idempotencyKey"]
        delivery_key = delivery_identity(event_key, channel.channel_id, purpose)
        payload_value = {
            "schemaVersion": 1,
            "purpose": purpose,
            "test": purpose == "test",
            "event": normalized,
        }
        payload_json = json.dumps(
            payload_value, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
        )
        if len(payload_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("delivery payload exceeds its byte limit")
        severity_priority = {"info": 100, "warning": 200, "critical": 300}[normalized["severity"]]
        transition_priority = 20 if normalized["transition"] == "firing" else 10
        purpose_priority = 0 if purpose == "operational" else -50
        priority = severity_priority + transition_priority + purpose_priority
        return (
            normalized, channel, purpose, delivery_key, payload_json, priority, created_at,
        )

    def _enqueue_prepared(
        self,
        connection: sqlite3.Connection,
        prepared: tuple[dict[str, Any], ChannelConfig, str, str, str, int, float],
    ) -> str:
        normalized, channel, purpose, delivery_key, payload_json, priority, created_at = prepared
        event_key = normalized["idempotencyKey"]
        if connection.execute(
            """SELECT 1 FROM outbox WHERE delivery_key = ?
               UNION ALL
               SELECT 1 FROM delivery_log WHERE delivery_key = ?
               LIMIT 1""",
            (delivery_key, delivery_key),
        ).fetchone() is not None:
            return "deduplicated"
        active_count = int(connection.execute(
            "SELECT count(*) FROM outbox WHERE state IN ('pending','retry','leased')"
        ).fetchone()[0])
        dropped = False
        if active_count >= self.queue.max_pending:
            victim = connection.execute(
                """SELECT delivery_key,channel_id,purpose,priority
                   FROM outbox WHERE state IN ('pending','retry')
                   ORDER BY priority ASC, created_at ASC, delivery_key ASC LIMIT 1"""
            ).fetchone()
            if victim is not None and priority > int(victim["priority"]):
                connection.execute(
                    """UPDATE outbox SET state='dropped', updated_at=?, completed_at=?,
                       lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=NULL,
                       last_error_code='queue_evicted'
                       WHERE delivery_key=? AND state IN ('pending','retry')""",
                    (created_at, created_at, victim["delivery_key"]),
                )
                connection.execute(
                    """INSERT INTO delivery_log(
                       delivery_key,channel_id,purpose,attempt,started_at,finished_at,
                       outcome,status_code,error_code
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        victim["delivery_key"], victim["channel_id"], victim["purpose"],
                        0, created_at, created_at,
                        "evicted", None, "queue_evicted",
                    ),
                )
                self._increment(connection, "queue_evicted")
                self._increment(connection, f"{victim['purpose']}_dropped")
            else:
                dropped = True
        state = "dropped" if dropped else "pending"
        error_code = "queue_full" if dropped else None
        connection.execute(
            """INSERT INTO outbox(
               delivery_key,event_key,channel_id,purpose,payload_json,priority,state,
               attempts,max_attempts,base_backoff_seconds,max_backoff_seconds,
               next_attempt_at,lease_owner,lease_expires_at,created_at,updated_at,
               completed_at,last_status_code,last_error_code
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                delivery_key, event_key, channel.channel_id, purpose, payload_json,
                priority, state, 0, channel.max_attempts,
                channel.base_backoff_seconds, channel.max_backoff_seconds,
                None if dropped else created_at, None, None, created_at, created_at,
                created_at if dropped else None, None, error_code,
            ),
        )
        if dropped:
            connection.execute(
                """INSERT INTO delivery_log(
                   delivery_key,channel_id,purpose,attempt,started_at,finished_at,
                   outcome,status_code,error_code
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    delivery_key, channel.channel_id, purpose, 0, created_at, created_at,
                    "dropped", None, "queue_full",
                ),
            )
            self._increment(connection, f"{purpose}_dropped")
            self._increment(connection, "queue_full")
        else:
            self._increment(connection, f"{purpose}_enqueued")
        return "dropped" if dropped else "enqueued"

    def enqueue_many(
        self,
        items: Sequence[tuple[Mapping[str, Any], ChannelConfig, str]],
        now: dt.datetime | float | int,
    ) -> dict[str, int]:
        if len(items) > MAX_ENQUEUE_BATCH:
            raise ValueError("delivery enqueue batch exceeds its limit")
        created_at = _epoch(now)
        prepared = [
            self._prepare_enqueue(event, channel, purpose, created_at)
            for event, channel, purpose in items
        ]
        counts = {"enqueued": 0, "deduplicated": 0, "dropped": 0}
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for item in prepared:
                counts[self._enqueue_prepared(connection, item)] += 1
            self._prune(connection)
            connection.execute("COMMIT")
        return counts

    def record_enqueue_overflow(self, purpose: str, count: int) -> None:
        if (
            not isinstance(purpose, str)
            or purpose not in PURPOSES
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise ValueError("delivery overflow count is invalid")
        if count == 0:
            return
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._increment(connection, "enqueue_batch_overflow", count)
            self._increment(connection, f"{purpose}_dropped", count)
            connection.execute("COMMIT")

    def _recover_expired(self, connection: sqlite3.Connection, now: float) -> None:
        expired = connection.execute(
            """SELECT delivery_key,channel_id,purpose,attempts,max_attempts
               FROM outbox WHERE state='leased' AND lease_expires_at <= ?
               ORDER BY lease_expires_at,delivery_key""",
            (now,),
        ).fetchall()
        for row in expired:
            attempt = int(row["attempts"])
            exhausted = attempt >= int(row["max_attempts"])
            outcome = "exhausted" if exhausted else "lease_expired"
            error_code = "lease_expired"
            connection.execute(
                """UPDATE delivery_log SET finished_at=?,outcome=?,error_code=?
                   WHERE delivery_key=? AND attempt=? AND outcome='leased'""",
                (now, outcome, error_code, row["delivery_key"], attempt),
            )
            connection.execute(
                """UPDATE outbox SET state=?,next_attempt_at=?,lease_owner=NULL,
                   lease_expires_at=NULL,updated_at=?,completed_at=?,last_error_code=?
                   WHERE delivery_key=? AND state='leased'""",
                (
                    "failed" if exhausted else "retry",
                    None if exhausted else now,
                    now,
                    now if exhausted else None,
                    error_code,
                    row["delivery_key"],
                ),
            )
            self._increment(connection, "lease_recovered")
            if exhausted:
                self._increment(connection, f"{row['purpose']}_final_failure")

    def claim_due(
        self,
        now: dt.datetime | float | int,
        worker_id: str,
        limit: int = 1,
    ) -> list[DeliveryTask]:
        if not isinstance(worker_id, str) or WORKER_ID.fullmatch(worker_id) is None:
            raise ValueError("delivery worker id is invalid")
        claim_limit = _integer(limit, "delivery claim limit", 1, 100)
        now_value = _epoch(now)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_expired(connection, now_value)
            rows = connection.execute(
                """SELECT * FROM outbox
                   WHERE state IN ('pending','retry') AND next_attempt_at <= ?
                   ORDER BY priority DESC,next_attempt_at ASC,created_at ASC,delivery_key ASC
                   LIMIT ?""",
                (now_value, claim_limit),
            ).fetchall()
            tasks: list[DeliveryTask] = []
            for row in rows:
                attempt = int(row["attempts"]) + 1
                updated = connection.execute(
                    """UPDATE outbox SET state='leased',attempts=?,lease_owner=?,
                       lease_expires_at=?,updated_at=?
                       WHERE delivery_key=? AND state IN ('pending','retry')""",
                    (
                        attempt, worker_id, now_value + self.queue.lease_seconds,
                        now_value, row["delivery_key"],
                    ),
                )
                if updated.rowcount != 1:
                    continue
                connection.execute(
                    """INSERT INTO delivery_log(
                       delivery_key,channel_id,purpose,attempt,started_at,finished_at,
                       outcome,status_code,error_code
                       ) VALUES(?,?,?,?,?,NULL,'leased',NULL,NULL)""",
                    (
                        row["delivery_key"], row["channel_id"], row["purpose"],
                        attempt, now_value,
                    ),
                )
                try:
                    payload = json.loads(row["payload_json"])
                except json.JSONDecodeError as error:
                    raise ValueError("delivery outbox payload is corrupt") from error
                if not isinstance(payload, Mapping):
                    raise ValueError("delivery outbox payload is corrupt")
                tasks.append(DeliveryTask(
                    delivery_key=row["delivery_key"],
                    event_key=row["event_key"],
                    channel_id=row["channel_id"],
                    purpose=row["purpose"],
                    payload=payload,
                    priority=int(row["priority"]),
                    attempt=attempt,
                    max_attempts=int(row["max_attempts"]),
                    base_backoff_seconds=float(row["base_backoff_seconds"]),
                    max_backoff_seconds=float(row["max_backoff_seconds"]),
                    lease_owner=worker_id,
                ))
            connection.execute("COMMIT")
            return tasks

    def complete(
        self,
        task: DeliveryTask,
        result: DeliveryResult,
        now: dt.datetime | float | int,
        jitter: Callable[[], float] | None = None,
    ) -> bool:
        if (
            not isinstance(result.outcome, str)
            or result.outcome not in {"success", "retryable", "permanent"}
        ):
            raise ValueError("delivery result outcome is invalid")
        if result.status_code is not None and (
            isinstance(result.status_code, bool)
            or not isinstance(result.status_code, int)
            or not 100 <= result.status_code <= 599
        ):
            raise ValueError("delivery result status is invalid")
        if result.error_code is not None and (
            not isinstance(result.error_code, str)
            or ERROR_CODE.fullmatch(result.error_code) is None
        ):
            raise ValueError("delivery result error code is invalid")
        retry_after = result.retry_after_seconds
        if retry_after is not None:
            retry_after = _finite(retry_after, "retry-after", 0, 86_400)
        now_value = _epoch(now)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state,attempts,max_attempts,purpose,lease_owner FROM outbox WHERE delivery_key=?",
                (task.delivery_key,),
            ).fetchone()
            if (
                row is None
                or row["state"] != "leased"
                or row["lease_owner"] != task.lease_owner
                or int(row["attempts"]) != task.attempt
            ):
                connection.execute("ROLLBACK")
                return False
            final = False
            if result.outcome == "success":
                state = "succeeded"
                log_outcome = "success"
                next_attempt = None
                final = True
                error_code = None
                self._increment(connection, f"{row['purpose']}_succeeded")
            elif result.outcome == "permanent":
                state = "failed"
                log_outcome = "permanent_failure"
                next_attempt = None
                final = True
                error_code = result.error_code or "permanent_failure"
                self._increment(connection, f"{row['purpose']}_final_failure")
            elif task.attempt >= int(row["max_attempts"]):
                state = "failed"
                log_outcome = "exhausted"
                next_attempt = None
                final = True
                error_code = result.error_code or "retry_exhausted"
                self._increment(connection, f"{row['purpose']}_final_failure")
            else:
                state = "retry"
                log_outcome = "retry"
                raw_jitter = (jitter or (lambda: secrets.SystemRandom().uniform(-0.2, 0.2)))()
                if isinstance(raw_jitter, bool) or not isinstance(raw_jitter, (int, float)) or not math.isfinite(float(raw_jitter)):
                    raise ValueError("delivery jitter is invalid")
                jitter_value = max(-0.2, min(0.2, float(raw_jitter)))
                base_delay = min(
                    task.max_backoff_seconds,
                    task.base_backoff_seconds * (2 ** max(0, task.attempt - 1)),
                )
                delay = min(task.max_backoff_seconds, max(0.0, base_delay * (1 + jitter_value)))
                if retry_after is not None:
                    delay = min(task.max_backoff_seconds, max(delay, retry_after))
                next_attempt = now_value + delay
                error_code = result.error_code or "retryable_failure"
                self._increment(connection, f"{row['purpose']}_retry_scheduled")
            connection.execute(
                """UPDATE outbox SET state=?,next_attempt_at=?,lease_owner=NULL,
                   lease_expires_at=NULL,updated_at=?,completed_at=?,last_status_code=?,
                   last_error_code=? WHERE delivery_key=? AND state='leased'""",
                (
                    state, next_attempt, now_value, now_value if final else None,
                    result.status_code, error_code, task.delivery_key,
                ),
            )
            connection.execute(
                """UPDATE delivery_log SET finished_at=?,outcome=?,status_code=?,error_code=?
                   WHERE delivery_key=? AND attempt=? AND outcome='leased'""",
                (
                    now_value, log_outcome, result.status_code, error_code,
                    task.delivery_key, task.attempt,
                ),
            )
            self._prune(connection)
            connection.execute("COMMIT")
            return True

    def status(self) -> dict[str, Any]:
        with contextlib.closing(self._connect()) as connection:
            states = {
                row["state"]: int(row["count"])
                for row in connection.execute(
                    "SELECT state,count(*) AS count FROM outbox GROUP BY state"
                )
            }
            stats = {
                row["name"]: int(row["value"])
                for row in connection.execute("SELECT name,value FROM delivery_stats ORDER BY name")
            }
            return {
                "schemaVersion": OUTBOX_SCHEMA_VERSION,
                "states": {key: states.get(key, 0) for key in sorted(OUTBOX_STATES)},
                "stats": stats,
            }

    def delivery_log(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = _integer(limit, "delivery log limit", 1, 1000)
        with contextlib.closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT delivery_key,channel_id,purpose,attempt,started_at,finished_at,
                   outcome,status_code,error_code FROM delivery_log
                   ORDER BY id DESC LIMIT ?""",
                (bounded_limit,),
            ).fetchall()
            return [dict(row) for row in rows]


def _event_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed.astimezone(dt.timezone.utc)


def route_channels(config: DeliveryConfig, event: Mapping[str, Any]) -> tuple[ChannelConfig, ...]:
    normalized = normalize_event(event)
    if (
        normalized["notificationState"] != "ready"
        or normalized["ruleId"] in NON_DELIVERABLE_OPERATIONAL_RULES
    ):
        return ()
    event_labels = normalized["labels"]
    selected: dict[str, ChannelConfig] = {}
    for route in config.routes:
        if not route.enabled:
            continue
        if (
            normalized["severity"] not in route.severities
            or normalized["transition"] not in route.transitions
            or any(event_labels.get(key) != value for key, value in route.labels)
        ):
            continue
        for channel_id in route.channel_ids:
            channel = config.channel(channel_id)
            if channel is not None and channel.enabled:
                selected[channel_id] = channel
        if not route.continue_matching:
            break
    return tuple(selected[key] for key in sorted(selected))


def enqueue_operational_events(
    outbox: DeliveryOutbox,
    config: DeliveryConfig,
    events: Sequence[Mapping[str, Any]],
    now: dt.datetime,
) -> dict[str, int]:
    normalized_now = now if now.tzinfo is not None else now.replace(tzinfo=dt.timezone.utc)
    normalized_now = normalized_now.astimezone(dt.timezone.utc)
    counts = {"enqueued": 0, "deduplicated": 0, "dropped": 0, "skipped": 0}
    eligible: list[dict[str, Any]] = []
    for raw in events:
        event = normalize_event(raw)
        observed_at = _event_time(event["observedAt"])
        if (
            observed_at is None
            or observed_at > normalized_now + dt.timedelta(seconds=60)
            or (normalized_now - observed_at).total_seconds() > config.queue.replay_window_seconds
        ):
            counts["skipped"] += 1
            continue
        if event["notificationState"] != "ready":
            counts["skipped"] += 1
            continue
        eligible.append(event)
    severity_order = {"info": 1, "warning": 2, "critical": 3}
    eligible.sort(
        key=lambda item: (
            severity_order[item["severity"]],
            1 if item["transition"] == "firing" else 0,
            item["observedAt"],
            item["idempotencyKey"],
        ),
        reverse=True,
    )
    batch: list[tuple[Mapping[str, Any], ChannelConfig, str]] = []
    overflow = 0
    for event in eligible:
        channels = route_channels(config, event)
        if not channels:
            counts["skipped"] += 1
            continue
        for channel in channels:
            if len(batch) < MAX_ENQUEUE_BATCH:
                batch.append((event, channel, "operational"))
            else:
                overflow += 1
    if batch:
        dispositions = outbox.enqueue_many(batch, normalized_now)
        for key, count in dispositions.items():
            counts[key] += count
    if overflow:
        outbox.record_enqueue_overflow("operational", overflow)
        counts["dropped"] += overflow
    return counts


def enqueue_test_delivery(
    outbox: DeliveryOutbox,
    config: DeliveryConfig,
    channel_id: str,
    request_id: str,
    message: str,
    now: dt.datetime,
) -> tuple[str, str, str]:
    channel = config.channel(channel_id)
    if channel is None or not channel.enabled:
        raise ValueError("test delivery channel is unavailable")
    if TEST_REQUEST_ID.fullmatch(request_id) is None:
        raise ValueError("test delivery request id is invalid")
    normalized_message = " ".join(_string(message, "test delivery message", 500).split())
    if not normalized_message:
        raise ValueError("test delivery message is invalid")
    timestamp = now if now.tzinfo is not None else now.replace(tzinfo=dt.timezone.utc)
    timestamp_text = timestamp.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    event_key = hashlib.sha256(f"test\0{request_id}\0{channel_id}".encode("utf-8")).hexdigest()
    event = {
        "schemaVersion": 1,
        "rulePackVersion": "delivery-test-v1",
        "idempotencyKey": event_key,
        "ruleId": "TestNotification",
        "target": f"test/{channel_id}",
        "transition": "firing",
        "severity": "info",
        "notificationState": "ready",
        "observedAt": timestamp_text,
        "openedAt": timestamp_text,
        "value": None,
        "status": "ok",
        "labels": {"purpose": "test"},
        "description": normalized_message,
        "runbook": "This is a delivery test and does not create or update an incident.",
    }
    disposition = outbox.enqueue(event, channel, "test", timestamp)
    return disposition, event_key, delivery_identity(event_key, channel_id, "test")


def _validated_payload(task: DeliveryTask) -> dict[str, Any]:
    value = task.payload
    if not isinstance(value, Mapping) or frozenset(value) != {
        "schemaVersion", "purpose", "test", "event",
    }:
        raise ValueError("delivery payload is corrupt")
    if (
        value.get("schemaVersion") != 1
        or value.get("purpose") != task.purpose
        or value.get("test") is not (task.purpose == "test")
    ):
        raise ValueError("delivery payload is corrupt")
    event = normalize_event(value.get("event"))
    if event["idempotencyKey"] != task.event_key:
        raise ValueError("delivery payload identity is corrupt")
    return {
        "schemaVersion": 1,
        "purpose": task.purpose,
        "test": task.purpose == "test",
        "event": event,
    }


def _message_text(payload: Mapping[str, Any]) -> str:
    event = payload["event"]
    marker = "[TEST]" if payload["test"] else "[ALERT]"
    transition = "FIRING" if event["transition"] == "firing" else "RESOLVED"
    return (
        f"{marker} {event['severity'].upper()} {transition} "
        f"{event['ruleId']} on {event['target']} at {event['observedAt']}: "
        f"{event['description']} Idempotency-Key={event['idempotencyKey']}"
    )[:2000]


def _canonical_https_hostname(value: str) -> str:
    if not value or len(value) > 255 or "%" in value:
        raise ValueError("delivery endpoint is invalid")
    # A final root label is semantically equivalent but must not bypass a
    # channel host allowlist or produce a different Host/SNI representation.
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate:
        raise ValueError("delivery endpoint is invalid")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            hostname = candidate.encode("idna", "strict").decode("ascii").lower()
        except (UnicodeError, ValueError) as error:
            raise ValueError("delivery endpoint is invalid") from error
        labels = hostname.split(".")
        if (
            len(hostname) > 253
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise ValueError("delivery endpoint is invalid")
        return hostname
    return str(address)


def _parse_https_endpoint(
    value: str,
    allowed_hosts: frozenset[str] | None = None,
) -> _HttpsEndpoint:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(character) <= 0x20 or ord(character) == 0x7f for character in value)
    ):
        raise ValueError("delivery endpoint is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        raw_hostname = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError("delivery endpoint is invalid") from error
    if (
        parsed.scheme != "https"
        or raw_hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("delivery endpoint is invalid")
    try:
        parsed.path.encode("ascii", "strict")
        parsed.query.encode("ascii", "strict")
    except UnicodeError as error:
        raise ValueError("delivery endpoint is invalid") from error
    hostname = _canonical_https_hostname(raw_hostname)
    if allowed_hosts is not None:
        normalized_allowed = frozenset(
            _canonical_https_hostname(item) for item in allowed_hosts
        )
        if hostname not in normalized_allowed:
            raise ValueError("delivery endpoint is invalid")
    normalized_port = 443 if port is None else port
    if not 1 <= normalized_port <= 65535:
        raise ValueError("delivery endpoint is invalid")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        authority_host = hostname
    else:
        authority_host = f"[{hostname}]" if address.version == 6 else hostname
    authority = (
        authority_host
        if normalized_port == 443
        else f"{authority_host}:{normalized_port}"
    )
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return _HttpsEndpoint(
        hostname=hostname,
        port=normalized_port,
        authority=authority,
        request_target=request_target,
        url=f"https://{authority}{request_target}",
    )


def _https_url(value: str, allowed_hosts: frozenset[str] | None = None) -> str:
    return _parse_https_endpoint(value, allowed_hosts).url


def _address_is_global(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        # Never reinterpret an IPv4 policy decision through an IPv6 spelling.
        # Transition formats are also unnecessary for alert receivers and can
        # delegate routing to a gateway that interprets an embedded IPv4 value.
        if (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
            or address.is_site_local
        ):
            return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def _resolve_global_destinations(
    endpoint: _HttpsEndpoint,
    resolver: Callable[..., Sequence[tuple[Any, ...]]],
) -> tuple[_ResolvedDestination, ...]:
    answers = resolver(
        endpoint.hostname,
        endpoint.port,
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
    )
    destinations: list[_ResolvedDestination] = []
    seen: set[tuple[int, str]] = set()
    for answer_index, answer in enumerate(answers):
        if answer_index >= MAX_HTTPS_DNS_ANSWERS:
            raise _UnsafeHttpsDestination("delivery DNS answer set is too large")
        if not isinstance(answer, tuple) or len(answer) != 5:
            raise _UnsafeHttpsDestination("delivery DNS answer is invalid")
        family, socktype, protocol, _canonical_name, raw_sockaddr = answer
        if (
            family not in {socket.AF_INET, socket.AF_INET6}
            or socktype != socket.SOCK_STREAM
            or protocol not in {0, socket.IPPROTO_TCP}
            or not isinstance(raw_sockaddr, tuple)
        ):
            raise _UnsafeHttpsDestination("delivery DNS answer is invalid")
        expected_length = 2 if family == socket.AF_INET else 4
        if len(raw_sockaddr) != expected_length:
            raise _UnsafeHttpsDestination("delivery DNS answer is invalid")
        raw_address = raw_sockaddr[0]
        raw_port = raw_sockaddr[1]
        if (
            not isinstance(raw_address, str)
            or "%" in raw_address
            or isinstance(raw_port, bool)
            or not isinstance(raw_port, int)
            or raw_port != endpoint.port
        ):
            raise _UnsafeHttpsDestination("delivery DNS answer is invalid")
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as error:
            raise _UnsafeHttpsDestination("delivery DNS answer is invalid") from error
        if (
            (family == socket.AF_INET and address.version != 4)
            or (family == socket.AF_INET6 and address.version != 6)
            or not _address_is_global(address)
        ):
            raise _UnsafeHttpsDestination("delivery destination is not global")
        if family == socket.AF_INET6:
            flow_info, scope_id = raw_sockaddr[2], raw_sockaddr[3]
            if (
                isinstance(flow_info, bool)
                or not isinstance(flow_info, int)
                or isinstance(scope_id, bool)
                or not isinstance(scope_id, int)
                or flow_info != 0
                or scope_id != 0
            ):
                raise _UnsafeHttpsDestination("delivery DNS answer is invalid")
            sockaddr: tuple[Any, ...] = (str(address), endpoint.port, 0, 0)
        else:
            sockaddr = (str(address), endpoint.port)
        identity = (family, str(address))
        if identity not in seen:
            seen.add(identity)
            destinations.append(_ResolvedDestination(family, str(address), sockaddr))
    if not destinations:
        raise socket.gaierror(socket.EAI_NONAME, "no HTTPS address")
    return tuple(destinations)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that never resolves the validated hostname again."""

    def __init__(
        self,
        endpoint: _HttpsEndpoint,
        destination: _ResolvedDestination,
        timeout: float,
        context: ssl.SSLContext | None = None,
        socket_factory: Callable[..., socket.socket] = socket.socket,
    ):
        super().__init__(
            endpoint.hostname,
            endpoint.port,
            timeout=timeout,
            context=context or ssl.create_default_context(),
        )
        self._destination = destination
        self._socket_factory = socket_factory

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise OSError("HTTPS proxy tunneling is disabled")
        raw_socket = self._socket_factory(
            self._destination.family,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        try:
            raw_socket.settimeout(self.timeout)
            raw_socket.connect(self._destination.sockaddr)
            # ``host`` is the canonical original URL hostname, not the pinned
            # address.  Certificate verification and SNI therefore retain the
            # authority the operator configured while routing cannot rebind.
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except BaseException:
            raw_socket.close()
            raise


def _default_https_connection(
    endpoint: _HttpsEndpoint,
    destination: _ResolvedDestination,
    timeout: float,
) -> http.client.HTTPSConnection:
    return _PinnedHTTPSConnection(endpoint, destination, timeout)


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = headers.get("Retry-After")
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and 0 <= value <= 86_400 else None


def _classify_http_status(status: int, retry_after: float | None = None) -> DeliveryResult:
    if 200 <= status < 300:
        return DeliveryResult.success(status)
    if status in {408, 425, 429} or 500 <= status <= 599:
        return DeliveryResult.retryable("http_retryable", status, retry_after)
    return DeliveryResult.permanent("http_permanent", status)


def _http_post(
    url: str,
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout: float,
    resolver: Callable[..., Sequence[tuple[Any, ...]]] | None = None,
    connection_factory: Callable[
        [_HttpsEndpoint, _ResolvedDestination, float], Any
    ] | None = None,
) -> DeliveryResult:
    payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        return DeliveryResult.permanent("payload_too_large")
    try:
        endpoint = _parse_https_endpoint(url)
    except ValueError:
        return DeliveryResult.permanent("endpoint_invalid")
    try:
        destinations = _resolve_global_destinations(
            endpoint,
            resolver or socket.getaddrinfo,
        )
    except _UnsafeHttpsDestination:
        return DeliveryResult.permanent("endpoint_not_global")
    except (OSError, TypeError, ValueError):
        return DeliveryResult.retryable("dns_error")
    if any(
        not isinstance(key, str)
        or HTTP_HEADER.fullmatch(key) is None
        or key.lower() in {"host", "content-length", "transfer-encoding"}
        or not isinstance(value, str)
        or HTTP_HEADER_VALUE.fullmatch(value) is None
        for key, value in headers.items()
    ):
        return DeliveryResult.permanent("headers_invalid")
    request_headers = {
        "Content-Type": "application/json",
        "User-Agent": "Monitor-Alert-Delivery/1",
        **headers,
        "Host": endpoint.authority,
    }
    client: Any = None
    try:
        factory = connection_factory or _default_https_connection
        client = factory(endpoint, destinations[0], timeout)
        client.request(
            "POST",
            endpoint.request_target,
            body=payload,
            headers=request_headers,
        )
        response = client.getresponse()
        return _classify_http_status(
            int(response.status),
            _retry_after(response.headers),
        )
    except ssl.SSLCertVerificationError:
        return DeliveryResult.permanent("tls_verification_failed")
    except (TimeoutError, socket.timeout):
        return DeliveryResult.retryable("timeout")
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return DeliveryResult.retryable("transport_error")
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()


class ChannelAdapter(Protocol):
    def send(
        self,
        channel: ChannelConfig,
        task: DeliveryTask,
        payload: Mapping[str, Any],
        secret: str,
    ) -> DeliveryResult: ...


class _HttpsAdapter:
    def __init__(
        self,
        resolver: Callable[..., Sequence[tuple[Any, ...]]] | None = None,
        connection_factory: Callable[
            [_HttpsEndpoint, _ResolvedDestination, float], Any
        ] | None = None,
    ):
        self.resolver = resolver
        self.connection_factory = connection_factory

    def _post(
        self,
        endpoint: str,
        body: Mapping[str, Any],
        headers: Mapping[str, str],
        timeout: float,
    ) -> DeliveryResult:
        return _http_post(
            endpoint,
            body,
            headers,
            timeout,
            self.resolver,
            self.connection_factory,
        )


class WebhookAdapter(_HttpsAdapter):

    def send(self, channel: ChannelConfig, task: DeliveryTask, payload: Mapping[str, Any], secret: str) -> DeliveryResult:
        endpoint = _https_url(secret)
        headers = {
            **channel.settings["headers"],
            "Idempotency-Key": task.delivery_key,
        }
        return self._post(endpoint, payload, headers, channel.timeout_seconds)


class SlackAdapter(_HttpsAdapter):

    def send(self, channel: ChannelConfig, task: DeliveryTask, payload: Mapping[str, Any], secret: str) -> DeliveryResult:
        endpoint = _https_url(secret, frozenset({"hooks.slack.com"}))
        body: dict[str, Any] = {"text": _message_text(payload)}
        if channel.settings["username"]:
            body["username"] = channel.settings["username"]
        return self._post(
            endpoint, body, {"Idempotency-Key": task.delivery_key},
            channel.timeout_seconds,
        )


class DiscordAdapter(_HttpsAdapter):

    def send(self, channel: ChannelConfig, task: DeliveryTask, payload: Mapping[str, Any], secret: str) -> DeliveryResult:
        endpoint = _https_url(secret, frozenset({"discord.com", "discordapp.com"}))
        body: dict[str, Any] = {"content": _message_text(payload)}
        if channel.settings["username"]:
            body["username"] = channel.settings["username"]
        return self._post(
            endpoint, body, {"Idempotency-Key": task.delivery_key},
            channel.timeout_seconds,
        )


class TelegramAdapter(_HttpsAdapter):

    def send(self, channel: ChannelConfig, task: DeliveryTask, payload: Mapping[str, Any], secret: str) -> DeliveryResult:
        if TELEGRAM_TOKEN.fullmatch(secret) is None:
            return DeliveryResult.permanent("secret_invalid")
        endpoint = f"https://api.telegram.org/bot{secret}/sendMessage"
        body = {
            "chat_id": channel.settings["chatId"],
            "text": _message_text(payload),
            "disable_notification": channel.settings["disableNotification"],
        }
        return self._post(
            endpoint, body, {"Idempotency-Key": task.delivery_key},
            channel.timeout_seconds,
        )


def _classify_smtp_recipient_refusals(
    refusals: Mapping[Any, Any],
) -> DeliveryResult:
    retryable_codes: list[int] = []
    permanent_codes: list[int] = []
    for value in refusals.values():
        if (
            not isinstance(value, tuple)
            or not value
            or isinstance(value[0], bool)
            or not isinstance(value[0], int)
        ):
            continue
        code = int(value[0])
        if 400 <= code < 500:
            retryable_codes.append(code)
        elif 500 <= code < 600:
            permanent_codes.append(code)
    if retryable_codes:
        return DeliveryResult.retryable("smtp_retryable", min(retryable_codes))
    return DeliveryResult.permanent(
        "smtp_permanent", max(permanent_codes) if permanent_codes else None,
    )


class SmtpAdapter:
    def __init__(
        self,
        smtp_factory: Callable[..., smtplib.SMTP] = smtplib.SMTP,
        smtp_ssl_factory: Callable[..., smtplib.SMTP_SSL] = smtplib.SMTP_SSL,
    ):
        self.smtp_factory = smtp_factory
        self.smtp_ssl_factory = smtp_ssl_factory

    def send(self, channel: ChannelConfig, task: DeliveryTask, payload: Mapping[str, Any], secret: str) -> DeliveryResult:
        settings = channel.settings
        message = email.message.EmailMessage()
        event = payload["event"]
        prefix = "[TEST]" if payload["test"] else "[ALERT]"
        message["Subject"] = f"{prefix} {event['severity']} {event['ruleId']} {event['transition']}"
        message["From"] = settings["from"]
        message["To"] = ", ".join(settings["to"])
        message["Message-ID"] = f"<monitor.{task.delivery_key}@localhost>"
        message["X-Monitor-Idempotency-Key"] = task.delivery_key
        message.set_content(_message_text(payload))
        client: smtplib.SMTP | smtplib.SMTP_SSL | None = None
        try:
            if settings["tlsMode"] == "implicit":
                client = self.smtp_ssl_factory(
                    settings["host"], settings["port"],
                    timeout=channel.timeout_seconds, context=ssl.create_default_context(),
                )
            else:
                client = self.smtp_factory(
                    settings["host"], settings["port"], timeout=channel.timeout_seconds,
                )
            client.ehlo()
            if settings["tlsMode"] == "starttls":
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            client.login(settings["username"], secret)
            refusals = client.send_message(message)
            return (
                _classify_smtp_recipient_refusals(refusals)
                if refusals
                else DeliveryResult.success(250)
            )
        except smtplib.SMTPRecipientsRefused as error:
            return _classify_smtp_recipient_refusals(error.recipients)
        except smtplib.SMTPResponseException as error:
            code = int(error.smtp_code)
            if 400 <= code < 500:
                return DeliveryResult.retryable("smtp_retryable", code)
            return DeliveryResult.permanent("smtp_permanent", code)
        except (TimeoutError, socket.timeout):
            return DeliveryResult.retryable("timeout")
        except ssl.SSLCertVerificationError:
            return DeliveryResult.permanent("tls_verification_failed")
        except (smtplib.SMTPException, OSError, ssl.SSLError):
            return DeliveryResult.retryable("smtp_transport_error")
        finally:
            if client is not None:
                # close() only closes local file/socket objects. Do not issue
                # QUIT after DATA was accepted: a slow/erroring QUIT must not
                # turn a successful delivery into an at-least-once duplicate.
                try:
                    client.close()
                except Exception:
                    pass


DEFAULT_ADAPTERS: Mapping[str, ChannelAdapter] = {
    "webhook": WebhookAdapter(),
    "slack": SlackAdapter(),
    "discord": DiscordAdapter(),
    "telegram": TelegramAdapter(),
    "smtp": SmtpAdapter(),
}


def _call_with_delivery_deadline(
    config: DeliveryConfig,
    channel: ChannelConfig,
    operation: Callable[[], DeliveryResult],
) -> DeliveryResult:
    """Run one claimed delivery inside a lease-safe absolute wall deadline."""
    deadline_seconds = _channel_delivery_deadline_seconds(channel)
    unavailable = DeliveryResult.retryable("deadline_unavailable")
    if (
        not math.isfinite(deadline_seconds)
        or deadline_seconds <= 0
        or deadline_seconds + DELIVERY_LEASE_MARGIN_SECONDS > config.queue.lease_seconds
    ):
        return unavailable
    if (
        not sys.platform.startswith("linux")
        or threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "SIGALRM")
        or not hasattr(signal, "ITIMER_REAL")
        or not hasattr(signal, "getitimer")
        or not hasattr(signal, "setitimer")
        or not hasattr(signal, "pthread_sigmask")
        or not hasattr(signal, "SIG_BLOCK")
    ):
        return unavailable

    try:
        # Query the calling thread's mask without changing it. A blocked
        # SIGALRM would leave a blocking transport free to outlive its lease;
        # fail closed before resolving credentials or starting network I/O.
        current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if signal.SIGALRM in current_mask:
            return unavailable
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return unavailable
    # Replacing another component's alarm would either disable its safety
    # boundary or make restoration imprecise.  This worker therefore owns
    # SIGALRM only when both the handler and timer retain process defaults.
    if (
        previous_handler != signal.SIG_DFL
        or previous_timer[0] > 0
        or previous_timer[1] > 0
    ):
        return unavailable

    started_at = time.monotonic()
    result: DeliveryResult | None = None
    operation_error: BaseException | None = None
    expired = False
    setup_failed = False
    cleanup_failed = False
    handler_installed = False
    try:
        try:
            signal.signal(signal.SIGALRM, _raise_delivery_deadline)
            handler_installed = True
            # The arm itself and every subsequent instruction are inside this
            # outer protected region. A deschedule immediately after the
            # syscall therefore cannot bypass cleanup or leak our handler.
            signal.setitimer(signal.ITIMER_REAL, deadline_seconds, 0.0)
            try:
                result = operation()
            except _DeliveryDeadlineExpired:
                expired = True
            except BaseException as error:
                operation_error = error
        except _DeliveryDeadlineExpired:
            expired = True
        except (AttributeError, OSError, RuntimeError, ValueError):
            setup_failed = True
    finally:
        if handler_installed:
            # Ignore a pending alarm before disarming it, then restore the
            # exact default handler. If it arrives while changing the handler,
            # record the expiry and retry after the one-shot signal is spent.
            while True:
                try:
                    signal.signal(signal.SIGALRM, signal.SIG_IGN)
                    break
                except _DeliveryDeadlineExpired:
                    expired = True
                except (AttributeError, OSError, RuntimeError, ValueError):
                    cleanup_failed = True
                    break
            try:
                while True:
                    try:
                        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
                        break
                    except _DeliveryDeadlineExpired:
                        expired = True
            except (AttributeError, OSError, RuntimeError, ValueError):
                cleanup_failed = True
            finally:
                # Restore the caller's handler even if cancellation itself is
                # rejected. In the normal Linux worker, a successful arm and
                # rejected cancel cannot occur under the same seccomp policy;
                # this path primarily guarantees deterministic fail-closed
                # behavior for setup faults and embedded callers.
                try:
                    signal.signal(signal.SIGALRM, previous_handler)
                except (AttributeError, OSError, RuntimeError, ValueError):
                    cleanup_failed = True

    if setup_failed or cleanup_failed:
        return unavailable
    if expired or time.monotonic() - started_at >= deadline_seconds:
        return DeliveryResult.retryable("delivery_deadline_exceeded")
    if operation_error is not None:
        raise operation_error
    if result is None:
        return DeliveryResult.retryable("adapter_error")
    return result


def dispatch_task(
    config: DeliveryConfig,
    task: DeliveryTask,
    secret_resolver: Callable[[SecretRef], str] = resolve_secret,
    adapters: Mapping[str, ChannelAdapter] = DEFAULT_ADAPTERS,
) -> DeliveryResult:
    channel = config.channel(task.channel_id)
    if channel is None:
        return DeliveryResult.permanent("channel_missing")
    if not channel.enabled:
        return DeliveryResult.permanent("channel_disabled")
    adapter = adapters.get(channel.kind)
    if adapter is None:
        return DeliveryResult.permanent("adapter_missing")
    try:
        def deliver() -> DeliveryResult:
            payload = _validated_payload(task)
            secret = secret_resolver(channel.secret_ref)
            return adapter.send(channel, task, payload, secret)

        return _call_with_delivery_deadline(config, channel, deliver)
    except ValueError:
        return DeliveryResult.permanent("configuration_invalid")
    except Exception:
        # Never persist or print exception text: transport libraries can embed
        # endpoint URLs, usernames, response bodies, or credentials in it.
        return DeliveryResult.retryable("adapter_error")


def process_due(
    outbox: DeliveryOutbox,
    config: DeliveryConfig,
    now: dt.datetime,
    worker_id: str,
    max_items: int | None = None,
    sender: Callable[[DeliveryTask], DeliveryResult] | None = None,
    jitter: Callable[[], float] | None = None,
    clock: Callable[[], dt.datetime] | None = None,
    max_runtime_seconds: float | None = None,
    monotonic: Callable[[], float] | None = None,
) -> dict[str, int]:
    item_limit = config.queue.batch_size if max_items is None else _integer(max_items, "max items", 1, 100)
    deadline: float | None = None
    runtime_clock = monotonic or time.monotonic
    if max_runtime_seconds is not None:
        runtime_limit = _finite(
            max_runtime_seconds,
            "max runtime seconds",
            1.0,
            MAX_WORKER_RUNTIME_SECONDS,
        )
        started_at = runtime_clock()
        if (
            isinstance(started_at, bool)
            or not isinstance(started_at, (int, float))
            or not math.isfinite(float(started_at))
        ):
            raise ValueError("delivery monotonic time is invalid")
        deadline = float(started_at) + runtime_limit
    counts = {"processed": 0, "succeeded": 0, "retryScheduled": 0, "finalFailures": 0}
    for _index in range(item_limit):
        if deadline is not None:
            current_runtime = runtime_clock()
            if (
                isinstance(current_runtime, bool)
                or not isinstance(current_runtime, (int, float))
                or not math.isfinite(float(current_runtime))
            ):
                raise ValueError("delivery monotonic time is invalid")
            if float(current_runtime) >= deadline:
                break
        claim_time = clock() if clock is not None else now
        claimed = outbox.claim_due(claim_time, worker_id, 1)
        if not claimed:
            break
        task = claimed[0]
        result = sender(task) if sender is not None else dispatch_task(config, task)
        completed_at = clock() if clock is not None else now
        if not outbox.complete(task, result, completed_at, jitter):
            continue
        counts["processed"] += 1
        if result.outcome == "success":
            counts["succeeded"] += 1
        elif result.outcome == "retryable" and task.attempt < task.max_attempts:
            counts["retryScheduled"] += 1
        else:
            counts["finalFailures"] += 1
    return counts


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    drain = subparsers.add_parser("drain", help="deliver a bounded batch of due notifications")
    drain.add_argument("--worker-id", default=f"{socket.gethostname()}:{os.getpid()}")
    drain.add_argument("--max-items", type=int)
    drain.add_argument(
        "--max-runtime-seconds",
        type=float,
        default=DEFAULT_WORKER_RUNTIME_SECONDS,
        help=(
            "stop claiming new deliveries after this monotonic runtime budget "
            f"(1-{int(MAX_WORKER_RUNTIME_SECONDS)} seconds)"
        ),
    )
    test = subparsers.add_parser("test", help="enqueue a delivery-only test notification")
    test.add_argument("--channel", required=True)
    test.add_argument("--request-id", required=True)
    test.add_argument("--message", required=True)
    subparsers.add_parser("status", help="print bounded queue counters without payloads")
    return parser


def run_cli(arguments: Sequence[str] | None = None) -> int:
    values = _cli_parser().parse_args(arguments)
    try:
        config = load_delivery_config(values.config)
        outbox = DeliveryOutbox(values.db, config.queue)
        if values.command == "drain":
            result = process_due(
                outbox, config, dt.datetime.now(dt.timezone.utc),
                values.worker_id, values.max_items,
                clock=lambda: dt.datetime.now(dt.timezone.utc),
                max_runtime_seconds=values.max_runtime_seconds,
            )
        elif values.command == "test":
            disposition, event_key, delivery_key = enqueue_test_delivery(
                outbox, config, values.channel, values.request_id,
                values.message, dt.datetime.now(dt.timezone.utc),
            )
            result = {
                "disposition": disposition,
                "eventKey": event_key,
                "deliveryKey": delivery_key,
                "purpose": "test",
            }
        else:
            result = outbox.status()
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as error:
        print(f"monitor-alert-delivery: {type(error).__name__}", file=sys.stderr)
        return 1


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
