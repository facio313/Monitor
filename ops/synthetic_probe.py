#!/usr/bin/env python3
"""Bounded, SSRF-safe HTTP(S) synthetic probes.

The module intentionally uses a raw, pinned socket instead of a convenience
HTTP client.  A DNS answer is validated on *every* request (including every
redirect) and the selected validated address is the address passed to
``connect``.  This prevents a hostname from being resolved safely for policy
checks and then re-resolved to an internal address by a HTTP client.

Probe results are deliberately evidence-only: no response header values,
bodies, URL credentials, or proxy settings are retained or returned.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import errno
import fcntl
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit


SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 64 * 1024
MAX_PROBES = 32
MAX_CONCURRENCY = 4
MAX_URL_BYTES = 4 * 1024
MAX_TARGET_BYTES = 2 * 1024
MAX_REDIRECTS = 5
MAX_DNS_RESULTS = 16
MAX_RESPONSE_HEADER_BYTES = 16 * 1024
MAX_RESPONSE_BODY_BYTES = 0
MAX_OUTPUT_BYTES = 256 * 1024
_PROBE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_PROXY_ENVIRONMENT_KEYS = (
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
)
_STATUS = frozenset({"ok", "dns", "permission", "timeout", "tls", "http", "invalid", "unsupported"})
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


class SyntheticProbeError(ValueError):
    """A reduced public error category; detail is intentionally not exported."""

    def __init__(self, category: str):
        if category not in _STATUS - {"ok"}:
            raise ValueError("synthetic probe category is invalid")
        super().__init__(category)
        self.category = category


class SocketLike(Protocol):
    def settimeout(self, value: float) -> None: ...
    def connect(self, address: tuple[Any, ...]) -> None: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, size: int) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class Probe:
    probe_id: str
    url: str
    expected_status: int
    timeout_seconds: int
    max_redirects: int


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    target: str
    url: str
    host_header: str


Resolver = Callable[[str, int, int, int], Sequence[tuple[Any, ...]]]
SocketFactory = Callable[[int, int], SocketLike]


def _utc_now(now: Callable[[], float]) -> str:
    return dt.datetime.fromtimestamp(now(), tz=dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_read_config(path: Path, expected_uid: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_mode & 0o022
        or metadata.st_size > MAX_CONFIG_BYTES
    ):
        raise SyntheticProbeError("permission")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SyntheticProbeError("permission")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CONFIG_BYTES or os.read(descriptor, 1):
            raise SyntheticProbeError("invalid")
        return raw
    finally:
        os.close(descriptor)


def _json_exact(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise SyntheticProbeError("invalid")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SyntheticProbeError("invalid") from exc


def _canonical_host(host: str) -> tuple[str, bool]:
    if not host or len(host.encode("utf-8")) > 253:
        raise SyntheticProbeError("invalid")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            canonical = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise SyntheticProbeError("invalid") from exc
        if not canonical or len(canonical) > 253 or any(not label or len(label) > 63 for label in canonical.split(".")):
            raise SyntheticProbeError("invalid")
        return canonical, False
    return literal.compressed.lower(), True


def parse_target(url: str) -> Target:
    """Normalize one credential-free absolute HTTP(S) target."""

    if not isinstance(url, str) or not url or len(url.encode("utf-8")) > MAX_URL_BYTES:
        raise SyntheticProbeError("invalid")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise SyntheticProbeError("invalid") from exc
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc or parts.fragment:
        raise SyntheticProbeError("invalid")
    # ``urlsplit`` accepts escaped userinfo; reject any authority delimiter, not
    # merely parsed username/password, so a later client cannot reinterpret it.
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise SyntheticProbeError("invalid")
    host, is_literal = _canonical_host(parts.hostname or "")
    if is_literal and not _address_is_public(host):
        raise SyntheticProbeError("invalid")
    scheme = parts.scheme.lower()
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise SyntheticProbeError("invalid")
    path = parts.path or "/"
    target = path + (f"?{parts.query}" if parts.query else "")
    if not target.isascii() or len(target.encode("utf-8")) > MAX_TARGET_BYTES or "\r" in target or "\n" in target:
        raise SyntheticProbeError("invalid")
    display_host = f"[{host}]" if is_literal and ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = display_host if port == default_port else f"{display_host}:{port}"
    return Target(scheme, host, port, target, urlunsplit((scheme, authority, path, parts.query, "")), authority)


def _address_is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return bool(address.is_global) and not any((
        address.is_loopback, address.is_private, address.is_link_local,
        address.is_multicast, address.is_reserved, address.is_unspecified,
    ))


def resolve_public_addresses(target: Target, resolver: Resolver = socket.getaddrinfo) -> tuple[tuple[Any, ...], ...]:
    """Resolve and reject the complete answer if any answer is non-public.

    Rejecting mixed answers is deliberate: choosing a public answer now while
    retaining an internal rebinding candidate lets another resolver/client make
    the unsafe choice on a retry.
    """

    try:
        answers = resolver(target.host, target.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SyntheticProbeError("dns") from exc
    except OSError as exc:
        raise _classify_os_error(exc) from exc
    if not answers or len(answers) > MAX_DNS_RESULTS:
        raise SyntheticProbeError("dns")
    accepted: list[tuple[Any, ...]] = []
    seen: set[tuple[int, tuple[Any, ...]]] = set()
    for answer in answers:
        if not isinstance(answer, tuple) or len(answer) != 5:
            raise SyntheticProbeError("dns")
        family, socktype, _protocol, _canonical_name, sockaddr = answer
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
            raise SyntheticProbeError("dns")
        expected_shape = 2 if family == socket.AF_INET else 4
        if (
            not isinstance(sockaddr, tuple)
            or len(sockaddr) != expected_shape
            or not isinstance(sockaddr[0], str)
            or sockaddr[1] != target.port
        ):
            raise SyntheticProbeError("dns")
        if not _address_is_public(sockaddr[0]):
            raise SyntheticProbeError("invalid")
        key = (family, sockaddr)
        if key not in seen:
            accepted.append(answer)
            seen.add(key)
    if not accepted:
        raise SyntheticProbeError("dns")
    return tuple(accepted)


def _classify_os_error(exc: OSError) -> str:
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "permission"
    if exc.errno in {errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK}:
        return "timeout"
    return "http"


def _read_headers(connection: SocketLike) -> tuple[int, dict[str, str]]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        if len(received) >= MAX_RESPONSE_HEADER_BYTES:
            raise SyntheticProbeError("http")
        # A socket can return response body bytes together with the headers.
        # One-byte reads keep the zero-byte body retention policy literal.
        chunk = connection.recv(1)
        if not chunk:
            raise SyntheticProbeError("http")
        received.extend(chunk)
    header_block = bytes(received.split(b"\r\n\r\n", 1)[0])
    try:
        lines = header_block.decode("iso-8859-1").split("\r\n")
        version, raw_status, _reason = lines[0].split(" ", 2)
        status = int(raw_status)
    except (UnicodeError, ValueError, IndexError) as exc:
        raise SyntheticProbeError("http") from exc
    if not version.startswith("HTTP/") or not 100 <= status <= 599 or len(lines) > 128:
        raise SyntheticProbeError("http")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            raise SyntheticProbeError("http")
        key, value = line.split(":", 1)
        key = key.lower()
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}", key):
            raise SyntheticProbeError("http")
        if len(value) > 2048:
            raise SyntheticProbeError("http")
        if key == "location":
            if key in headers:
                raise SyntheticProbeError("http")
            headers[key] = value.strip()
    return status, headers


def _certificate_evidence(connection: SocketLike, now: Callable[[], float]) -> tuple[str | None, int | None]:
    getter = getattr(connection, "getpeercert", None)
    if getter is None:
        raise SyntheticProbeError("tls")
    try:
        certificate = getter()
        raw_expiry = certificate.get("notAfter") if isinstance(certificate, Mapping) else None
        expires_at = ssl.cert_time_to_seconds(raw_expiry) if isinstance(raw_expiry, str) else None
    except (ValueError, ssl.SSLError, OSError) as exc:
        raise SyntheticProbeError("tls") from exc
    if expires_at is None:
        raise SyntheticProbeError("tls")
    expiry = dt.datetime.fromtimestamp(expires_at, tz=dt.timezone.utc)
    return (
        expiry.isoformat(timespec="seconds").replace("+00:00", "Z"),
        int((expires_at - now()) // 86_400),
    )


def _proxies_present(environment: Mapping[str, str]) -> bool:
    return any(environment.get(key) for key in _PROXY_ENVIRONMENT_KEYS)


def _request_once(
    target: Target,
    timeout_seconds: int,
    *,
    resolver: Resolver,
    socket_factory: SocketFactory,
    ssl_context_factory: Callable[[], ssl.SSLContext],
    now: Callable[[], float],
) -> tuple[int, dict[str, str], str | None, int | None]:
    # There is exactly one TCP connect per request.  It is preceded by a fresh
    # complete DNS validation; a failed connect is not retried against a stale
    # answer, which keeps the rebinding invariant simple and auditable.
    family, socktype, _protocol, _canonical_name, sockaddr = resolve_public_addresses(target, resolver)[0]
    connection: SocketLike | None = None
    try:
        connection = socket_factory(family, socktype)
        connection.settimeout(timeout_seconds)
        # Pin the validated DNS sockaddr; do not pass target.host to connect.
        connection.connect(sockaddr)
        if target.scheme == "https":
            try:
                connection = ssl_context_factory().wrap_socket(connection, server_hostname=target.host)
                connection.settimeout(timeout_seconds)
            except ssl.SSLError as exc:
                raise SyntheticProbeError("tls") from exc
        request = (
            f"GET {target.target} HTTP/1.1\r\n"
            f"Host: {target.host_header}\r\n"
            "User-Agent: monitor-synthetic-probe/1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        connection.sendall(request)
        http_status, headers = _read_headers(connection)
        # Redirect responses still receive normal TLS hostname verification, but
        # only the final response has certificate-expiry evidence retained.
        expiry, expiry_days = (
            _certificate_evidence(connection, now)
            if target.scheme == "https" and http_status not in _REDIRECT_STATUS
            else (None, None)
        )
        # MAX_RESPONSE_BODY_BYTES is zero.  Closing after headers means body
        # bytes are neither consumed nor persisted.
        return http_status, headers, expiry, expiry_days
    except SyntheticProbeError:
        raise
    except socket.timeout as exc:
        raise SyntheticProbeError("timeout") from exc
    except OSError as exc:
        raise SyntheticProbeError(_classify_os_error(exc)) from exc
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def probe_once(
    probe: Probe,
    *,
    resolver: Resolver = socket.getaddrinfo,
    socket_factory: SocketFactory = socket.socket,
    ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    environment: Mapping[str, str] = os.environ,
    now: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run one probe and return only bounded operational evidence."""

    started = monotonic()
    checked_at = _utc_now(now)
    current_url = probe.url
    redirects = 0
    try:
        if _proxies_present(environment):
            raise SyntheticProbeError("unsupported")
        while True:
            target = parse_target(current_url)
            http_status, headers, expiry, expiry_days = _request_once(
                target, probe.timeout_seconds, resolver=resolver, socket_factory=socket_factory,
                ssl_context_factory=ssl_context_factory, now=now,
            )
            if http_status not in _REDIRECT_STATUS:
                category = "ok" if http_status == probe.expected_status else "http"
                return {
                    "schemaVersion": SCHEMA_VERSION, "id": probe.probe_id, "status": category,
                    "checkedAt": checked_at, "url": target.url, "httpStatus": http_status,
                    "redirectCount": redirects,
                    "latencyMilliseconds": max(0, int((monotonic() - started) * 1000)),
                    "certificateExpiresAt": expiry, "certificateDaysRemaining": expiry_days,
                }
            if redirects >= probe.max_redirects or not headers.get("location"):
                raise SyntheticProbeError("http")
            redirects += 1
            current_url = urljoin(target.url, headers["location"])
    except SyntheticProbeError as exc:
        return {
            "schemaVersion": SCHEMA_VERSION, "id": probe.probe_id, "status": exc.category,
            "checkedAt": checked_at, "url": None, "httpStatus": None,
            "redirectCount": redirects,
            "latencyMilliseconds": max(0, int((monotonic() - started) * 1000)),
            "certificateExpiresAt": None, "certificateDaysRemaining": None,
        }


def load_config(path: Path, *, expected_uid: int | None = None) -> tuple[Probe, ...]:
    """Read an owner-controlled exact-schema probe configuration."""

    owner = os.geteuid() if expected_uid is None else expected_uid
    document = _json_exact(_safe_read_config(path, owner))
    if not isinstance(document, Mapping) or set(document) != {"schemaVersion", "probes"} or document.get("schemaVersion") != SCHEMA_VERSION:
        raise SyntheticProbeError("invalid")
    values = document.get("probes")
    if not isinstance(values, list) or not values or len(values) > MAX_PROBES:
        raise SyntheticProbeError("invalid")
    probes: list[Probe] = []
    identifiers: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {"id", "url", "expectedStatus", "timeoutSeconds", "maxRedirects"}:
            raise SyntheticProbeError("invalid")
        probe_id = value.get("id")
        expected = value.get("expectedStatus")
        timeout = value.get("timeoutSeconds")
        redirect_limit = value.get("maxRedirects")
        if (
            not isinstance(probe_id, str) or _PROBE_ID.fullmatch(probe_id) is None or probe_id in identifiers
            or isinstance(expected, bool) or not isinstance(expected, int) or not 100 <= expected <= 599
            or isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30
            or isinstance(redirect_limit, bool) or not isinstance(redirect_limit, int) or not 0 <= redirect_limit <= MAX_REDIRECTS
        ):
            raise SyntheticProbeError("invalid")
        target = parse_target(value.get("url"))
        identifiers.add(probe_id)
        probes.append(Probe(probe_id, target.url, expected, timeout, redirect_limit))
    return tuple(probes)


def run_configured_probes(
    probes: Sequence[Probe],
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Run at most four probes concurrently and preserve reviewed config order."""

    if not probes or len(probes) > MAX_PROBES:
        raise SyntheticProbeError("invalid")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_CONCURRENCY, len(probes))) as executor:
        return list(executor.map(lambda item: probe_once(item, **kwargs), probes))


_PUBLIC_RESULT_FIELDS = frozenset({
    "schemaVersion", "id", "status", "checkedAt", "url", "httpStatus",
    "redirectCount", "latencyMilliseconds", "certificateExpiresAt",
    "certificateDaysRemaining",
})


def _is_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        return False
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00").tzinfo is not None
    except ValueError:
        return False


def _validate_public_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PUBLIC_RESULT_FIELDS:
        raise SyntheticProbeError("invalid")
    probe_id = value.get("id")
    status = value.get("status")
    url = value.get("url")
    http_status = value.get("httpStatus")
    redirects = value.get("redirectCount")
    latency = value.get("latencyMilliseconds")
    certificate_expiry = value.get("certificateExpiresAt")
    certificate_days = value.get("certificateDaysRemaining")
    if (
        value.get("schemaVersion") != SCHEMA_VERSION
        or not isinstance(probe_id, str) or _PROBE_ID.fullmatch(probe_id) is None
        or status not in _STATUS or not _is_utc_timestamp(value.get("checkedAt"))
        or (url is not None and (not isinstance(url, str) or len(url.encode("utf-8")) > MAX_URL_BYTES))
        or (http_status is not None and (isinstance(http_status, bool) or not isinstance(http_status, int) or not 100 <= http_status <= 599))
        or isinstance(redirects, bool) or not isinstance(redirects, int) or not 0 <= redirects <= MAX_REDIRECTS
        or isinstance(latency, bool) or not isinstance(latency, int) or not 0 <= latency <= 60_000
        or (certificate_expiry is not None and not _is_utc_timestamp(certificate_expiry))
        or (certificate_days is not None and (isinstance(certificate_days, bool) or not isinstance(certificate_days, int) or not -36_600 <= certificate_days <= 36_600))
    ):
        raise SyntheticProbeError("invalid")
    if status == "ok" and (url is None or http_status is None):
        raise SyntheticProbeError("invalid")
    if status == "http" and ((url is None) != (http_status is None) or (url is None and (certificate_expiry is not None or certificate_days is not None))):
        raise SyntheticProbeError("invalid")
    if status not in {"ok", "http"} and (url is not None or http_status is not None or certificate_expiry is not None or certificate_days is not None):
        raise SyntheticProbeError("invalid")
    return dict(value)


def build_public_document(results: Sequence[Mapping[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    """Return the exact bounded publication contract used by ``--output``."""

    if not isinstance(results, Sequence) or isinstance(results, (str, bytes, bytearray)) or not results or len(results) > MAX_PROBES:
        raise SyntheticProbeError("invalid")
    checked = _utc_now(time.time) if generated_at is None else generated_at
    if not _is_utc_timestamp(checked):
        raise SyntheticProbeError("invalid")
    normalized = [_validate_public_result(result) for result in results]
    if len({result["id"] for result in normalized}) != len(normalized):
        raise SyntheticProbeError("invalid")
    document = {"schemaVersion": SCHEMA_VERSION, "generatedAt": checked, "results": normalized}
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise SyntheticProbeError("invalid")
    return document


def _open_safe_output_directory(path: Path, expected_uid: int, expected_gid: int) -> tuple[int, str]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise SyntheticProbeError("permission")
    try:
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
        or parent_metadata.st_gid != expected_gid
        or parent_metadata.st_mode & 0o022
    ):
        raise SyntheticProbeError("permission")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.parent, flags)
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (parent_metadata.st_dev, parent_metadata.st_ino):
        os.close(descriptor)
        raise SyntheticProbeError("permission")
    return descriptor, path.name


def _assert_safe_existing_output(directory_fd: int, name: str, expected_uid: int, expected_gid: int) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o640
    ):
        raise SyntheticProbeError("permission")


def publish_output(path: Path, document: Mapping[str, Any], *, expected_uid: int | None = None, expected_gid: int | None = None) -> None:
    """Atomically publish a reduced mode-0640 result without link following.

    The output directory must be a private, non-group/world-writable directory
    owned by this service UID/GID.  An advisory directory lock serializes the
    one intended writer; temporary files are exclusive, single-link files and
    the final replacement plus directory fsync makes publication crash-safe.
    """

    if not isinstance(document, Mapping) or set(document) != {"schemaVersion", "generatedAt", "results"} or document.get("schemaVersion") != SCHEMA_VERSION:
        raise SyntheticProbeError("invalid")
    uid = os.geteuid() if expected_uid is None else expected_uid
    gid = os.getegid() if expected_gid is None else expected_gid
    canonical = build_public_document(document.get("results"), generated_at=document.get("generatedAt"))
    encoded = (json.dumps(canonical, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise SyntheticProbeError("invalid")
    directory_fd, name = _open_safe_output_directory(path, uid, gid)
    temporary_name = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(16)}"
    temporary_fd: int | None = None
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        _assert_safe_existing_output(directory_fd, name, uid, gid)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary_name, flags, 0o640, dir_fd=directory_fd)
        os.fchmod(temporary_fd, 0o640)
        metadata = os.fstat(temporary_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != uid or metadata.st_gid != gid:
            raise SyntheticProbeError("permission")
        written = 0
        while written < len(encoded):
            count = os.write(temporary_fd, encoded[written:])
            if count <= 0:
                raise SyntheticProbeError("permission")
            written += count
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        # Parent ownership/mode and the directory lock prevent a competing
        # writer; os.replace is the single atomic public visibility boundary.
        os.replace(temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        _assert_safe_existing_output(directory_fd, name, uid, gid)
        os.fsync(directory_fd)
    except OSError as exc:
        raise SyntheticProbeError("permission") from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        try:
            fcntl.flock(directory_fd, fcntl.LOCK_UN)
        finally:
            os.close(directory_fd)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a reviewed config and print one reduced JSON result per probe."""

    parser = argparse.ArgumentParser(description="Run SSRF-safe Monitor synthetic probes")
    parser.add_argument("--config", required=True, help="absolute owner-only v1 JSON config")
    parser.add_argument("--output", help="absolute atomic mode-0640 result document path")
    arguments = parser.parse_args(argv)
    try:
        results = run_configured_probes(load_config(Path(arguments.config)))
        document = build_public_document(results)
        if arguments.output:
            publish_output(Path(arguments.output), document)
    except SyntheticProbeError as exc:
        # Configuration failures are intentionally not expanded: paths and
        # malformed values may be sensitive operational information.
        print(json.dumps({"schemaVersion": SCHEMA_VERSION, "status": exc.category}, separators=(",", ":")))
        return 2
    if arguments.output:
        print(json.dumps(document, separators=(",", ":"), sort_keys=True))
    else:
        for result in results:
            print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if all(result["status"] == "ok" for result in results) else 1


if __name__ == "__main__":  # pragma: no cover - CLI composition is trivial.
    raise SystemExit(main())
