#!/usr/bin/env python3
"""Focused regression tests for SSRF-safe synthetic probes; no real network."""

from __future__ import annotations

import json
import os
import socket
import ssl
import stat
import tempfile
import unittest
from pathlib import Path

from ops.synthetic_probe import (
    Probe,
    SyntheticProbeError,
    build_public_document,
    load_config,
    parse_target,
    publish_output,
    probe_once,
    resolve_public_addresses,
)


PUBLIC = "8.8.8.8"
NOW = 1_800_000_000.0


def answer(address: str = PUBLIC, family: int = socket.AF_INET):
    return (family, socket.SOCK_STREAM, 6, "", (address, 443) if family == socket.AF_INET else (address, 443, 0, 0))


class FakeSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.connected: list[tuple[object, ...]] = []
        self.sent = b""
        self.closed = False

    def settimeout(self, _value: float) -> None:
        return None

    def connect(self, address: tuple[object, ...]) -> None:
        self.connected.append(address)

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        response, self.response = self.response[:size], self.response[size:]
        return response

    def close(self) -> None:
        self.closed = True


class FakeTlsContext:
    def __init__(self):
        self.server_names: list[str] = []

    def wrap_socket(self, connection: FakeSocket, *, server_hostname: str) -> FakeSocket:
        self.server_names.append(server_hostname)
        connection.getpeercert = lambda: {"notAfter": "Jan 01 00:00:00 2030 GMT"}  # type: ignore[attr-defined]
        return connection


class FailingSocket(FakeSocket):
    def __init__(self, error: BaseException):
        super().__init__(b"")
        self.error = error

    def connect(self, address: tuple[object, ...]) -> None:
        self.connected.append(address)
        raise self.error


class SyntheticProbeTests(unittest.TestCase):
    def probe(self, url: str = "https://public.example/healthz", **values: object) -> Probe:
        return Probe("public", url, int(values.get("expected", 200)), int(values.get("timeout", 5)), int(values.get("redirects", 3)))

    def fake_run(self, probe: Probe, responses: list[bytes], resolver):
        sockets: list[FakeSocket] = []
        context = FakeTlsContext()

        def factory(_family: int, _type: int) -> FakeSocket:
            item = FakeSocket(responses.pop(0))
            sockets.append(item)
            return item

        ticks = iter((10.0, 10.025))
        result = probe_once(probe, resolver=resolver, socket_factory=factory,
                            ssl_context_factory=lambda: context, environment={}, now=lambda: NOW,
                            monotonic=lambda: next(ticks))
        return result, sockets, context

    def test_normal_public_https_success_pins_address_preserves_host_sni_and_drops_body(self):
        body = b"secret-response-body-must-not-be-read"
        result, sockets, context = self.fake_run(
            self.probe("https://B\u00dcCHER.example:443/healthz?q=1"),
            [b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" + body],
            lambda *_args: [answer()],
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["url"], "https://xn--bcher-kva.example/healthz?q=1")
        self.assertEqual(sockets[0].connected, [(PUBLIC, 443)])
        self.assertIn(b"Host: xn--bcher-kva.example\r\n", sockets[0].sent)
        self.assertEqual(context.server_names, ["xn--bcher-kva.example"])
        self.assertTrue(sockets[0].response.endswith(body))
        self.assertNotIn("secret-response-body", json.dumps(result))
        self.assertEqual(result["certificateExpiresAt"], "2030-01-01T00:00:00Z")

    def test_redirect_revalidates_dns_and_pins_each_new_connection(self):
        calls: list[str] = []
        answers = iter(([answer("8.8.8.8")], [answer("1.1.1.1")]))

        def resolver(host: str, *_args):
            calls.append(host)
            return next(answers)

        result, sockets, _context = self.fake_run(
            self.probe("https://public.example/a"),
            [b"HTTP/1.1 302 Found\r\nLocation: /b\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"], resolver,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["redirectCount"], 1)
        self.assertEqual(calls, ["public.example", "public.example"])
        self.assertEqual([item.connected[0][0] for item in sockets], ["8.8.8.8", "1.1.1.1"])

    def test_rebinding_to_private_address_after_redirect_is_rejected_before_connect(self):
        answers = iter(([answer()], [answer("169.254.169.254")]))
        result, sockets, _context = self.fake_run(
            self.probe(), [b"HTTP/1.1 302 Found\r\nLocation: /metadata\r\n\r\n"], lambda *_args: next(answers),
        )
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(len(sockets), 1)

    def test_private_v4_mapped_loopback_and_mixed_dns_answers_fail_closed(self):
        target = parse_target("https://public.example/")
        for addresses in (
            [answer("127.0.0.1")],
            [answer("10.0.0.1")],
            [answer("169.254.169.254")],
            [answer("::ffff:8.8.8.8", socket.AF_INET6)],
            [answer(), answer("10.0.0.1")],
        ):
            with self.assertRaises(SyntheticProbeError) as raised:
                resolve_public_addresses(target, lambda *_args, items=addresses: items)
            self.assertEqual(raised.exception.category, "invalid")
        with self.assertRaises(SyntheticProbeError) as raised:
            resolve_public_addresses(target, lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 1))])
        self.assertEqual(raised.exception.category, "dns")

    def test_proxy_environment_is_refused_and_invalid_redirect_is_not_requested(self):
        result = probe_once(self.probe(), environment={"HTTPS_PROXY": "http://proxy.invalid"})
        self.assertEqual(result["status"], "unsupported")
        result, sockets, _context = self.fake_run(
            self.probe(), [b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n"], lambda *_args: [answer()],
        )
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(len(sockets), 1)

    def test_config_is_exact_private_and_normalizes_idna_and_ports(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probes.json"
            path.write_text(json.dumps({"schemaVersion": 1, "probes": [{
                "id": "check", "url": "https://b\u00fccher.example:443/", "expectedStatus": 200,
                "timeoutSeconds": 10, "maxRedirects": 5,
            }]}), encoding="utf-8")
            path.chmod(0o600)
            probes = load_config(path, expected_uid=os.geteuid())
            self.assertEqual(probes[0].url, "https://xn--bcher-kva.example/")
            path.write_text('{"schemaVersion":1,"probes":[],"extra":true}', encoding="utf-8")
            with self.assertRaises(SyntheticProbeError):
                load_config(path, expected_uid=os.geteuid())

    def test_invalid_scheme_userinfo_fragment_and_redirect_limit_are_rejected(self):
        for value in (
            "file:///etc/passwd", "https://user:pass@public.example/", "https://public.example/#fragment",
        ):
            with self.assertRaises(SyntheticProbeError):
                parse_target(value)
        result, _sockets, _context = self.fake_run(
            self.probe(redirects=0), [b"HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n"], lambda *_args: [answer()],
        )
        self.assertEqual(result["status"], "http")

    def test_reduced_failure_categories_cover_dns_permission_timeout_tls_and_http(self):
        probe = self.probe()
        self.assertEqual(
            probe_once(probe, resolver=lambda *_args: (_ for _ in ()).throw(socket.gaierror())).get("status"),
            "dns",
        )
        for error, expected in ((OSError(1, "denied"), "permission"), (socket.timeout(), "timeout")):
            result = probe_once(
                probe, resolver=lambda *_args: [answer()],
                socket_factory=lambda *_args, failure=error: FailingSocket(failure), environment={}, now=lambda: NOW,
            )
            self.assertEqual(result["status"], expected)

        class BrokenTls:
            def wrap_socket(self, _connection, *, server_hostname):
                raise ssl.SSLError("certificate failure")

        result = probe_once(
            probe, resolver=lambda *_args: [answer()],
            socket_factory=lambda *_args: FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n"),
            ssl_context_factory=BrokenTls, environment={}, now=lambda: NOW,
        )
        self.assertEqual(result["status"], "tls")
        result, _sockets, _context = self.fake_run(
            self.probe(expected=204), [b"HTTP/1.1 200 OK\r\n\r\n"], lambda *_args: [answer()],
        )
        self.assertEqual(result["status"], "http")

    def test_atomic_output_is_exact_mode_0640_and_replaces_only_safe_prior_output(self):
        result = {
            "schemaVersion": 1, "id": "public", "status": "ok",
            "checkedAt": "2027-01-15T08:00:00.000Z", "url": "https://public.example/healthz",
            "httpStatus": 200, "redirectCount": 0, "latencyMilliseconds": 12,
            "certificateExpiresAt": "2030-01-01T00:00:00Z", "certificateDaysRemaining": 1000,
        }
        document = build_public_document([result], generated_at="2027-01-15T08:00:01.000Z")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            output = root / "synthetic-probes.json"
            publish_output(output, document)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), document)
            next_document = build_public_document([result], generated_at="2027-01-15T08:00:02.000Z")
            publish_output(output, next_document)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), next_document)
            self.assertFalse(list(root.glob(".synthetic-probes.json.tmp-*")))

    def test_output_rejects_links_unsafe_parent_and_extra_contract_fields(self):
        result = {
            "schemaVersion": 1, "id": "public", "status": "dns",
            "checkedAt": "2027-01-15T08:00:00.000Z", "url": None, "httpStatus": None,
            "redirectCount": 0, "latencyMilliseconds": 0,
            "certificateExpiresAt": None, "certificateDaysRemaining": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            output = root / "synthetic-probes.json"
            document = build_public_document([result], generated_at="2027-01-15T08:00:01.000Z")
            output.symlink_to(root / "outside")
            with self.assertRaises(SyntheticProbeError) as raised:
                publish_output(output, document)
            self.assertEqual(raised.exception.category, "permission")
            output.unlink()
            outside = root / "outside"
            outside.write_text("x", encoding="utf-8")
            outside.chmod(0o640)
            os.link(outside, output)
            with self.assertRaises(SyntheticProbeError):
                publish_output(output, document)
            output.unlink()
            root.chmod(0o770)
            with self.assertRaises(SyntheticProbeError):
                publish_output(output, document)
        invalid = dict(result)
        invalid["extra"] = True
        with self.assertRaises(SyntheticProbeError):
            build_public_document([invalid], generated_at="2027-01-15T08:00:01.000Z")

    def test_output_preserves_a_bounded_final_http_failure_without_headers_or_body(self):
        result = {
            "schemaVersion": 1, "id": "public", "status": "http",
            "checkedAt": "2027-01-15T08:00:00.000Z", "url": "https://public.example/healthz",
            "httpStatus": 503, "redirectCount": 1, "latencyMilliseconds": 12,
            "certificateExpiresAt": "2030-01-01T00:00:00Z", "certificateDaysRemaining": 1000,
        }
        document = build_public_document([result], generated_at="2027-01-15T08:00:01.000Z")
        self.assertEqual(document["results"][0]["httpStatus"], 503)
        self.assertNotIn("headers", json.dumps(document))

    def test_dedicated_systemd_contract_has_least_privilege_output_mode_and_timer(self):
        root = Path(__file__).resolve().parents[1]
        service = (root / "systemd" / "monitor-synthetic-probe.service").read_text(encoding="utf-8")
        timer = (root / "systemd" / "monitor-synthetic-probe.timer").read_text(encoding="utf-8")
        self.assertIn("User=cks", service)
        self.assertIn("Group=cks", service)
        self.assertIn("--output /var/lib/monitor-synthetic/results.json", service)
        self.assertIn("StateDirectory=monitor-synthetic", service)
        self.assertIn("ReadWritePaths=/var/lib/monitor-synthetic", service)
        self.assertNotIn("StateDirectory=monitor-export", service)
        self.assertNotIn("/var/lib/monitor-export", service)
        self.assertIn("CapabilityBoundingSet=", service)
        self.assertIn("AmbientCapabilities=", service)
        self.assertIn("Environment=HTTPS_PROXY=", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", service)
        self.assertIn("MemoryMax=80M", service)
        self.assertIn("TimeoutStartSec=40s", service)
        self.assertNotIn("User=root", service)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)


if __name__ == "__main__":
    unittest.main()
