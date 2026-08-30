import json
import os
import socket
import stat
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import sys

OPS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS))
import monitor_update_gateway as gateway  # noqa: E402


VALID_REQUEST_ID = "update-12345678-1234-4234-9234-123456789abc"


def wire(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("ascii")


class GatewayProtocolTests(unittest.TestCase):
    def check_request(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "action": "check",
            "actor": "operator@example.com",
            "planId": None,
        }

    def test_accepts_only_exact_check_and_apply_shapes(self) -> None:
        self.assertEqual(gateway.decode_request(wire(self.check_request())), self.check_request())
        apply_request = {
            **self.check_request(),
            "action": "apply-safe",
            "planId": "a" * 64,
        }
        self.assertEqual(gateway.decode_request(wire(apply_request)), apply_request)

        invalid_requests = [
            {**self.check_request(), "extra": True},
            {**self.check_request(), "schemaVersion": True},
            {**self.check_request(), "action": "full-upgrade"},
            {**self.check_request(), "actor": "operator command"},
            {**self.check_request(), "planId": "a" * 64},
            {**self.check_request(), "action": "apply-safe", "planId": None},
            {**self.check_request(), "action": "apply-safe", "planId": "A" * 64},
        ]
        for request in invalid_requests:
            with self.subTest(request=request), self.assertRaises(gateway.GatewayError):
                gateway.decode_request(wire(request))

    def test_rejects_duplicate_keys_trailing_requests_and_oversize(self) -> None:
        duplicate = (
            b'{"schemaVersion":1,"schemaVersion":1,"action":"check",'
            b'"actor":"alice","planId":null}\n'
        )
        for payload in (
            duplicate,
            wire(self.check_request()) + wire(self.check_request()),
            wire(self.check_request()).rstrip(b"\n"),
            b"x" * (gateway.MAX_REQUEST_BYTES + 1),
        ):
            with self.subTest(size=len(payload)), self.assertRaises(gateway.GatewayError):
                gateway.decode_request(payload)

    def test_response_contracts_have_exact_fields(self) -> None:
        accepted = json.loads(gateway.success_response(VALID_REQUEST_ID))
        self.assertEqual(set(accepted), {"schemaVersion", "accepted", "requestId", "state"})
        self.assertEqual(accepted, {
            "schemaVersion": 1,
            "accepted": True,
            "requestId": VALID_REQUEST_ID,
            "state": "queued",
        })
        rejected = json.loads(gateway.rejection_response("INVALID_PLAN"))
        self.assertEqual(rejected, {
            "schemaVersion": 1,
            "accepted": False,
            "code": "INVALID_PLAN",
        })
        self.assertEqual(set(gateway.REJECTION_CODES), {
            "BUSY", "QUEUE_FULL", "INVALID_REQUEST", "INVALID_ACTION", "INVALID_ACTOR",
            "INVALID_PLAN", "PEER_REJECTED", "INTERNAL_ERROR",
        })

    def test_inherited_listener_does_not_need_its_bound_path_after_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = str(Path(directory) / "gateway.sock")
            program = """
import os
import socket
import sys

sys.path.insert(0, sys.argv[1])
import monitor_update_gateway as gateway

listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(sys.argv[2])
listener.listen(1)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
else:
    listener.detach()
os.unlink(sys.argv[2])
os.environ["LISTEN_PID"] = str(os.getpid())
os.environ["LISTEN_FDS"] = "1"
inherited = gateway.inherited_listener(3)
assert inherited.family == socket.AF_UNIX
assert inherited.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
"""
            result = subprocess.run(
                [sys.executable, "-c", program, str(OPS), socket_path],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


class GatewayQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.queue_dir = Path(self.temporary.name) / "incoming"
        self.queue_dir.mkdir(mode=0o700)
        self.queue = gateway.QueueWriter(
            self.queue_dir,
            expected_uid=os.geteuid(),
            now=lambda: datetime(2026, 8, 27, 7, 0, tzinfo=UTC),
            request_id_factory=lambda: VALID_REQUEST_ID,
        )
        self.request = {
            "schemaVersion": 1,
            "action": "check",
            "actor": "alice",
            "planId": None,
        }

    def test_queue_record_is_private_bounded_and_exact(self) -> None:
        request_id = self.queue.enqueue(self.request, 1001)
        self.assertEqual(request_id, VALID_REQUEST_ID)
        path = self.queue_dir / f"request-{VALID_REQUEST_ID}.json"
        metadata = path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertLessEqual(metadata.st_size, gateway.MAX_REQUEST_BYTES)
        record = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(set(record), {
            "schemaVersion", "requestId", "action", "actor", "planId", "peerUid", "requestedAt",
        })
        self.assertEqual(record["peerUid"], 1001)
        self.assertEqual(record["requestedAt"], "2026-08-27T07:00:00Z")

    def test_handle_connection_checks_peer_and_returns_one_response(self) -> None:
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        client.sendall(wire(self.request))
        gateway.handle_connection(
            server,
            self.queue,
            1001,
            peer_uid_reader=lambda _connection: 1001,
        )
        response = json.loads(client.recv(4096))
        self.assertTrue(response["accepted"])
        self.assertEqual(response["requestId"], VALID_REQUEST_ID)

    def test_foreign_peer_is_rejected_without_queue_write(self) -> None:
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        client.sendall(wire(self.request))
        gateway.handle_connection(
            server,
            self.queue,
            1001,
            peer_uid_reader=lambda _connection: 2000,
        )
        self.assertEqual(json.loads(client.recv(4096))["code"], "PEER_REJECTED")
        self.assertEqual(list(self.queue_dir.iterdir()), [])

    def test_queue_depth_is_bounded(self) -> None:
        for index in range(gateway.MAX_QUEUE_DEPTH):
            (self.queue_dir / f"request-update-00000000-0000-4000-8000-{index:012d}.json").write_text(
                "{}\n", encoding="ascii"
            )
        with self.assertRaisesRegex(gateway.GatewayError, "QUEUE_FULL"):
            self.queue.enqueue(self.request, 1001)

    def test_unsafe_queue_directory_is_rejected(self) -> None:
        self.queue_dir.chmod(0o770)
        with self.assertRaisesRegex(gateway.GatewayError, "INTERNAL_ERROR"):
            self.queue.enqueue(self.request, 1001)


if __name__ == "__main__":
    unittest.main()
