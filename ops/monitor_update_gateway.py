#!/usr/bin/python3
"""Unprivileged, fixed-protocol request gateway for Monitor host updates.

The gateway never invokes a package manager and never writes host status.  It
accepts one small JSON request from the rootless Monitor process, verifies the
Unix peer credential, and durably queues a reduced request for the root worker.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import struct
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 4096
MAX_QUEUE_DEPTH = 8
ALLOWED_ACTIONS = frozenset({"check", "apply-safe"})
ACTOR_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$", re.ASCII)
PLAN_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
REQUEST_ID_PATTERN = re.compile(
    r"^update-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
QUEUE_NAME_PATTERN = re.compile(
    r"^request-(update-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$",
    re.ASCII,
)
REJECTION_CODES = frozenset({
    "BUSY",
    "PEER_REJECTED",
    "INVALID_REQUEST",
    "INVALID_ACTION",
    "INVALID_ACTOR",
    "INVALID_PLAN",
    "QUEUE_FULL",
    "INTERNAL_ERROR",
})


class GatewayError(Exception):
    """Expected protocol or queue rejection with a fixed public code."""

    def __init__(self, code: str):
        if code not in REJECTION_CODES:
            raise ValueError("unknown gateway rejection code")
        super().__init__(code)
        self.code = code


def iso_timestamp(now: datetime | None = None) -> str:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode_request(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > MAX_REQUEST_BYTES:
        raise GatewayError("INVALID_REQUEST")
    if not payload.endswith(b"\n") or b"\n" in payload[:-1]:
        raise GatewayError("INVALID_REQUEST")
    try:
        decoded = payload[:-1].decode("utf-8", errors="strict")
        request = json.loads(decoded, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GatewayError("INVALID_REQUEST") from None
    if not isinstance(request, dict) or set(request) != {
        "schemaVersion", "action", "actor", "planId",
    }:
        raise GatewayError("INVALID_REQUEST")
    if type(request["schemaVersion"]) is not int or request["schemaVersion"] != SCHEMA_VERSION:
        raise GatewayError("INVALID_REQUEST")
    action = request["action"]
    actor = request["actor"]
    plan_id = request["planId"]
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise GatewayError("INVALID_ACTION")
    if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
        raise GatewayError("INVALID_ACTOR")
    if action == "check":
        if plan_id is not None:
            raise GatewayError("INVALID_PLAN")
    elif not isinstance(plan_id, str) or not PLAN_ID_PATTERN.fullmatch(plan_id):
        raise GatewayError("INVALID_PLAN")
    return request


def success_response(request_id: str) -> bytes:
    if not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ValueError("invalid request ID")
    return (json.dumps({
        "schemaVersion": SCHEMA_VERSION,
        "accepted": True,
        "requestId": request_id,
        "state": "queued",
    }, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def rejection_response(code: str) -> bytes:
    if code not in REJECTION_CODES:
        code = "INTERNAL_ERROR"
    return (json.dumps({
        "schemaVersion": SCHEMA_VERSION,
        "accepted": False,
        "code": code,
    }, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def socket_peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise GatewayError("PEER_REJECTED")
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def read_one_request(connection: socket.socket) -> bytes:
    connection.settimeout(2.0)
    payload = bytearray()
    while True:
        remaining = MAX_REQUEST_BYTES + 1 - len(payload)
        if remaining <= 0:
            raise GatewayError("INVALID_REQUEST")
        try:
            chunk = connection.recv(min(remaining, 1024))
        except TimeoutError:
            raise GatewayError("INVALID_REQUEST") from None
        if not chunk:
            break
        payload.extend(chunk)
        newline = payload.find(b"\n")
        if newline >= 0:
            if newline != len(payload) - 1:
                raise GatewayError("INVALID_REQUEST")
            break
        if len(payload) > MAX_REQUEST_BYTES:
            raise GatewayError("INVALID_REQUEST")
    if len(payload) > MAX_REQUEST_BYTES:
        raise GatewayError("INVALID_REQUEST")
    return bytes(payload)


class QueueWriter:
    def __init__(
        self,
        queue_dir: Path,
        *,
        expected_uid: int | None = None,
        maximum_depth: int = MAX_QUEUE_DEPTH,
        now: Callable[[], datetime] | None = None,
        request_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.queue_dir = queue_dir
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.maximum_depth = maximum_depth
        self.now = now or (lambda: datetime.now(UTC))
        self.request_id_factory = request_id_factory or (lambda: f"update-{uuid.uuid4()}")

    def _validate_directory(self) -> None:
        try:
            metadata = os.lstat(self.queue_dir)
        except OSError:
            raise GatewayError("INTERNAL_ERROR") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise GatewayError("INTERNAL_ERROR")

    def _queue_depth(self) -> int:
        try:
            names = os.listdir(self.queue_dir)
        except OSError:
            raise GatewayError("INTERNAL_ERROR") from None
        return sum(
            1 for name in names
            if QUEUE_NAME_PATTERN.fullmatch(name) or name.startswith(".request-")
        )

    def enqueue(self, request: dict[str, Any], peer_uid: int) -> str:
        self._validate_directory()
        if self._queue_depth() >= self.maximum_depth:
            raise GatewayError("QUEUE_FULL")
        request_id = self.request_id_factory()
        if not REQUEST_ID_PATTERN.fullmatch(request_id):
            raise GatewayError("INTERNAL_ERROR")
        record = {
            "schemaVersion": SCHEMA_VERSION,
            "requestId": request_id,
            "action": request["action"],
            "actor": request["actor"],
            "planId": request["planId"],
            "peerUid": peer_uid,
            "requestedAt": iso_timestamp(self.now()),
        }
        encoded = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if len(encoded) > MAX_REQUEST_BYTES:
            raise GatewayError("INTERNAL_ERROR")
        final_name = f"request-{request_id}.json"
        temporary_name = f".request-{request_id}.{os.getpid()}.tmp"
        final_path = self.queue_dir / final_name
        temporary_path = self.queue_dir / temporary_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(temporary_path, flags, 0o600)
            written = 0
            while written < len(encoded):
                written += os.write(descriptor, encoded[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary_path, final_path)
            directory_descriptor = os.open(
                self.queue_dir,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise GatewayError("INTERNAL_ERROR") from None
        return request_id


def handle_connection(
    connection: socket.socket,
    queue: QueueWriter,
    expected_peer_uid: int,
    *,
    peer_uid_reader: Callable[[socket.socket], int] = socket_peer_uid,
) -> None:
    response: bytes
    try:
        peer_uid = peer_uid_reader(connection)
        if peer_uid != expected_peer_uid:
            raise GatewayError("PEER_REJECTED")
        request = decode_request(read_one_request(connection))
        request_id = queue.enqueue(request, peer_uid)
        response = success_response(request_id)
    except GatewayError as error:
        response = rejection_response(error.code)
    except Exception:
        response = rejection_response("INTERNAL_ERROR")
    try:
        connection.sendall(response)
    except OSError:
        pass


def inherited_listener(file_descriptor: int) -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        raise RuntimeError("gateway must be activated by its systemd socket")
    try:
        descriptor_count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        descriptor_count = 0
    if descriptor_count != 1 or file_descriptor != 3:
        raise RuntimeError("gateway expected exactly one inherited descriptor")
    listener = socket.socket(fileno=file_descriptor)
    if (
        listener.family != socket.AF_UNIX
        or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
    ):
        raise RuntimeError("inherited descriptor is not a listening Unix stream socket")
    return listener


def serve(listener: socket.socket, queue: QueueWriter, expected_peer_uid: int) -> None:
    while True:
        connection, _address = listener.accept()
        try:
            handle_connection(connection, queue, expected_peer_uid)
        finally:
            connection.close()


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor update request gateway")
    parser.add_argument("--listen-fd", type=int, default=3)
    parser.add_argument("--queue-dir", type=Path, default=Path("/var/lib/monitor-update/incoming"))
    parser.add_argument("--peer-uid", type=int, default=1001)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    values = parse_arguments(arguments)
    if os.geteuid() == 0:
        raise PermissionError("monitor update gateway must not run as root")
    if values.peer_uid < 1:
        raise ValueError("peer UID must be unprivileged")
    listener = inherited_listener(values.listen_fd)
    queue = QueueWriter(values.queue_dir)
    serve(listener, queue, values.peer_uid)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PermissionError, RuntimeError, ValueError) as error:
        print(f"monitor update gateway: {error}", file=sys.stderr)
        raise SystemExit(1) from None
