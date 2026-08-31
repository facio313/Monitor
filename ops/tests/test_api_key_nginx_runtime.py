import http.client
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NGINX = shutil.which("nginx")
OPENSSL = shutil.which("openssl")


class _EchoServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address):
        super().__init__(server_address, _EchoHandler)
        self.requests = []
        self.requests_lock = threading.Lock()

    def record(self, request):
        with self.requests_lock:
            self.requests.append(request)

    def snapshot(self):
        with self.requests_lock:
            return list(self.requests)


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        request = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "bodyLength": len(body),
        }
        self.server.record(request)
        payload = json.dumps(request, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Set-Cookie", "upstream-session=must-not-escape")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, _format, *args):
        del args


def _reserve_tcp_port():
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    reservation.bind(("0.0.0.0", 0))
    return reservation, reservation.getsockname()[1]


def _non_loopback_ipv4():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return address if address and not address.startswith("127.") else None


@unittest.skipUnless(
    NGINX and OPENSSL,
    "runtime Nginx integration requires both nginx and openssl",
)
class ApiKeyNginxRuntimeTests(unittest.TestCase):
    FIXED_ROUTES = {
        "/monitor/api-key/v1/dashboard": ("GET", "/monitor/api/dashboard"),
        "/monitor/api-key/v1/generic-logs": ("GET", "/monitor/api/generic-logs"),
        "/monitor/api-key/v1/agents": ("GET", "/monitor/api/agents"),
        "/monitor/api-key/v1/agents/enrollment-tokens": (
            "POST",
            "/monitor/api/agents/enrollment-tokens",
        ),
        "/monitor/api-key/v1/infrastructure-ledger": (
            "GET",
            "/monitor/api/infrastructure-ledger",
        ),
        "/monitor/api-key/v1/system-updates": (
            "GET",
            "/monitor/api/system-updates",
        ),
        "/monitor/api-key/v1/system-updates/check": (
            "POST",
            "/monitor/api/system-updates/check",
        ),
        "/monitor/api-key/v1/system-updates/prepare": (
            "POST",
            "/monitor/api/system-updates/prepare",
        ),
        "/monitor/api-key/v1/system-updates/apply": (
            "POST",
            "/monitor/api/system-updates/apply",
        ),
        "/monitor/api-key/v1/operations/auth-inventory": (
            "GET",
            "/monitor/api/operations/auth-inventory",
        ),
    }

    @classmethod
    def setUpClass(cls):
        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="monitor-api-key-nginx-runtime-"
        )
        cls.directory = Path(cls._temporary_directory.name)
        cls.snippets = cls.directory / "snippets"
        cls.snippets.mkdir()
        # Nginx's -p flag does not relocate compile-time absolute temp paths.
        # A root integration run must never mutate the live worker directories.
        for name in ("client-body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (cls.directory / name).mkdir()

        cls.echo = _EchoServer(("127.0.0.1", 0))
        cls.echo_thread = threading.Thread(target=cls.echo.serve_forever, daemon=True)
        cls.echo_thread.start()
        cls.echo_port = cls.echo.server_address[1]

        cls.http_reservation, cls.http_port = _reserve_tcp_port()
        cls.https_reservation, cls.https_port = _reserve_tcp_port()
        cls._prepare_snippets()
        cls._create_certificate()
        cls.configuration = cls._write_configuration()

        syntax = subprocess.run(
            [NGINX, "-t", "-c", str(cls.configuration), "-p", str(cls.directory)],
            check=False,
            capture_output=True,
            text=True,
        )
        if syntax.returncode != 0:
            cls._cleanup_resources()
            raise AssertionError(syntax.stdout + syntax.stderr)

        cls.http_reservation.close()
        cls.https_reservation.close()
        cls.nginx = subprocess.Popen(
            [NGINX, "-c", str(cls.configuration), "-p", str(cls.directory)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls._wait_for_listener()

    @classmethod
    def tearDownClass(cls):
        cls._cleanup_resources()

    @classmethod
    def _prepare_snippets(cls):
        names = (
            "monitor-api-key-ingress.conf",
            "monitor-api-key-proxy.conf",
            "monitor-cloudflare-real-ip.conf",
            "monitor-api-key-peer-map.conf",
        )
        for name in names:
            source = (ROOT / "ops/nginx" / name).read_text(encoding="utf-8")
            source = source.replace("/etc/nginx/snippets/", f"{cls.snippets}/")
            if name == "monitor-api-key-proxy.conf":
                old_upstream = "proxy_pass         http://127.0.0.1:5181;"
                if source.count(old_upstream) != 1:
                    raise AssertionError("checked-in proxy_pass contract changed")
                source = source.replace(
                    old_upstream,
                    f"proxy_pass         http://127.0.0.1:{cls.echo_port};",
                )
            (cls.snippets / name).write_text(source, encoding="utf-8")

        (cls.snippets / "monitor-edge-secret.conf").write_text(
            'proxy_set_header X-Portfolio-Edge-Secret "test-only-edge-secret";\n',
            encoding="utf-8",
        )

    @classmethod
    def _create_certificate(cls):
        cls.certificate = cls.directory / "certificate.pem"
        cls.private_key = cls.directory / "private-key.pem"
        completed = subprocess.run(
            [
                OPENSSL,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(cls.private_key),
                "-out",
                str(cls.certificate),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stdout + completed.stderr)

    @classmethod
    def _write_configuration(cls):
        configuration = cls.directory / "nginx.conf"
        configuration.write_text(
            "worker_processes 1;\n"
            "daemon off;\n"
            "master_process off;\n"
            f"pid {cls.directory}/nginx.pid;\n"
            f"error_log {cls.directory}/error.log notice;\n"
            "events { worker_connections 64; }\n"
            "http {\n"
            "  access_log off;\n"
            f"  client_body_temp_path {cls.directory}/client-body;\n"
            f"  proxy_temp_path {cls.directory}/proxy;\n"
            f"  fastcgi_temp_path {cls.directory}/fastcgi;\n"
            f"  uwsgi_temp_path {cls.directory}/uwsgi;\n"
            f"  scgi_temp_path {cls.directory}/scgi;\n"
            f"  include {cls.snippets}/monitor-api-key-peer-map.conf;\n"
            "  server {\n"
            f"    listen 0.0.0.0:{cls.http_port};\n"
            f"    listen 0.0.0.0:{cls.https_port} ssl;\n"
            f"    ssl_certificate {cls.certificate};\n"
            f"    ssl_certificate_key {cls.private_key};\n"
            f"    include {cls.snippets}/monitor-api-key-ingress.conf;\n"
            "    location ^~ /monitor/ { return 418; }\n"
            "    location / { return 404; }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        return configuration

    @classmethod
    def _wait_for_listener(cls):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.nginx.poll() is not None:
                stdout, stderr = cls.nginx.communicate(timeout=1)
                cls._cleanup_resources()
                raise AssertionError(f"nginx exited early:\n{stdout}{stderr}")
            try:
                with socket.create_connection(("127.0.0.1", cls.https_port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.025)
        cls._cleanup_resources()
        raise AssertionError("nginx TLS listener did not become ready")

    def test_all_nginx_temp_paths_are_test_local(self):
        configured_temp_paths = {
            line.strip()
            for line in self.configuration.read_text(encoding="utf-8").splitlines()
            if line.strip().split(" ", 1)[0].endswith("_temp_path")
        }
        self.assertEqual(
            configured_temp_paths,
            {
                f"client_body_temp_path {self.directory}/client-body;",
                f"proxy_temp_path {self.directory}/proxy;",
                f"fastcgi_temp_path {self.directory}/fastcgi;",
                f"uwsgi_temp_path {self.directory}/uwsgi;",
                f"scgi_temp_path {self.directory}/scgi;",
            },
        )

    @classmethod
    def _cleanup_resources(cls):
        nginx = getattr(cls, "nginx", None)
        if nginx is not None and nginx.poll() is None:
            nginx.terminate()
            try:
                nginx.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                nginx.kill()
                nginx.communicate(timeout=3)
        echo = getattr(cls, "echo", None)
        if echo is not None:
            echo.shutdown()
            echo.server_close()
        echo_thread = getattr(cls, "echo_thread", None)
        if echo_thread is not None:
            echo_thread.join(timeout=2)
        for name in ("http_reservation", "https_reservation"):
            reservation = getattr(cls, name, None)
            if reservation is not None:
                try:
                    reservation.close()
                except OSError:
                    pass
        temporary_directory = getattr(cls, "_temporary_directory", None)
        if temporary_directory is not None:
            temporary_directory.cleanup()

    @classmethod
    def _request(cls, method, path, *, headers=None, body=None, tls=True, host="127.0.0.1"):
        if tls:
            connection = http.client.HTTPSConnection(
                host,
                cls.https_port,
                context=ssl._create_unverified_context(),
                timeout=5,
            )
        else:
            connection = http.client.HTTPConnection(host, cls.http_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            response_body = response.read()
            return response.status, response.getheaders(), response_body
        finally:
            connection.close()

    def _assert_not_proxied(self, method, path, expected_status):
        before = len(self.echo.snapshot())
        status, _headers, _body = self._request(method, path)
        self.assertEqual(status, expected_status)
        self.assertEqual(len(self.echo.snapshot()), before)

    @classmethod
    def _request_with_duplicate_authorization(cls, first, second):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            cls.https_port,
            context=ssl._create_unverified_context(),
            timeout=5,
        )
        try:
            connection.putrequest("GET", "/monitor/api-key/v1/dashboard")
            connection.putheader("Authorization", first)
            connection.putheader("Authorization", second)
            connection.endheaders()
            response = connection.getresponse()
            response_body = response.read()
            return response.status, response_body
        finally:
            connection.close()

    def test_rewrite_authorization_and_untrusted_headers(self):
        supplied_headers = {
            "Authorization": "Bearer integration-test-token",
            "Cookie": "session=attacker-controlled",
            "Remote-User": "forged-user",
            "Remote-Groups": "forged-admins",
            "Remote-Name": "Forged User",
            "Remote-Email": "forged@example.invalid",
            "X-Monitor-mTLS-Verified": "SUCCESS",
            "X-Monitor-Client-Cert-SHA256": "forged-fingerprint",
            "X-Monitor-Client-Cert-Not-After": "2099-01-01T00:00:00Z",
            "X-Forwarded-For": "198.51.100.10, 203.0.113.20",
            "CF-Connecting-IP": "192.0.2.55",
        }
        status, response_headers, response_body = self._request(
            "GET",
            "/monitor/api-key/v1/dashboard?window=5m",
            headers=supplied_headers,
        )
        self.assertEqual(status, 200)
        echoed = json.loads(response_body)
        self.assertEqual(echoed["method"], "GET")
        self.assertEqual(echoed["path"], "/monitor/api/dashboard?window=5m")
        self.assertEqual(
            echoed["headers"].get("authorization"),
            "Bearer integration-test-token",
        )
        self.assertEqual(echoed["headers"].get("x-forwarded-for"), "127.0.0.1")
        self.assertEqual(echoed["headers"].get("x-real-ip"), "127.0.0.1")
        self.assertEqual(echoed["headers"].get("x-forwarded-proto"), "https")
        self.assertEqual(echoed["headers"].get("x-forwarded-prefix"), "/monitor")
        self.assertEqual(
            echoed["headers"].get("x-portfolio-edge-secret"),
            "test-only-edge-secret",
        )
        for header in (
            "cookie",
            "remote-user",
            "remote-groups",
            "remote-name",
            "remote-email",
            "x-monitor-mtls-verified",
            "x-monitor-client-cert-sha256",
            "x-monitor-client-cert-not-after",
        ):
            self.assertNotIn(header, echoed["headers"])

        cache_control = [
            value.lower()
            for name, value in response_headers
            if name.lower() == "cache-control"
        ]
        self.assertEqual(cache_control, ["no-store"])
        self.assertFalse(
            any(name.lower() == "set-cookie" for name, _value in response_headers)
        )

    def test_duplicate_authorization_is_not_collapsed_to_one_valid_bearer(self):
        first = "Bearer mon_" + "A" * 43
        second = "Bearer mon_" + "B" * 43
        before = len(self.echo.snapshot())
        status, response_body = self._request_with_duplicate_authorization(
            first, second
        )
        self.assertEqual(status, 400, response_body.decode("utf-8", errors="replace"))
        self.assertEqual(len(self.echo.snapshot()), before)

    def test_every_fixed_alias_rewrites_to_its_exact_internal_uri(self):
        for public_path, (method, internal_path) in self.FIXED_ROUTES.items():
            with self.subTest(public_path=public_path):
                status, _headers, response_body = self._request(
                    method,
                    public_path,
                    headers={"Authorization": "Bearer route-contract"},
                    body=b"{}" if method == "POST" else None,
                )
                self.assertEqual(status, 200)
                echoed = json.loads(response_body)
                self.assertEqual(echoed["method"], method)
                self.assertEqual(echoed["path"], internal_path)

    def test_dynamic_agent_route_rewrites_to_the_exact_internal_uri(self):
        agent_id = "123e4567-e89b-42d3-a456-426614174000"
        for action in ("certificate-rotation-tokens", "revoke"):
            with self.subTest(action=action):
                status, _headers, response_body = self._request(
                    "POST",
                    f"/monitor/api-key/v1/agents/{agent_id}/{action}",
                    headers={"Authorization": "Bearer writer"},
                    body=b"{}",
                )
                self.assertEqual(status, 200)
                echoed = json.loads(response_body)
                self.assertEqual(
                    echoed["path"],
                    f"/monitor/api/agents/{agent_id}/{action}",
                )

    def test_method_trailing_slash_and_encoded_suffix_boundaries(self):
        self._assert_not_proxied(
            "POST", "/monitor/api-key/v1/dashboard", expected_status=405
        )
        self._assert_not_proxied(
            "GET", "/monitor/api-key/v1/system-updates/apply", expected_status=405
        )
        self._assert_not_proxied(
            "GET", "/monitor/api-key/v1/dashboard/", expected_status=418
        )
        self._assert_not_proxied(
            "GET", "/monitor/api-key/v1/dashboard%2Fextra", expected_status=418
        )
        agent_id = "123e4567-e89b-42d3-a456-426614174000"
        self._assert_not_proxied(
            "POST",
            f"/monitor/api-key/v1/agents/{agent_id}/revoke%2Fextra",
            expected_status=404,
        )

    def test_sixteen_kib_body_limit_is_inclusive(self):
        route = "/monitor/api-key/v1/agents/enrollment-tokens"
        status, _headers, response_body = self._request(
            "POST", route, body=b"a" * (16 * 1024)
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response_body)["bodyLength"], 16 * 1024)

        before = len(self.echo.snapshot())
        status, _headers, _body = self._request(
            "POST", route, body=b"a" * (16 * 1024 + 1)
        )
        self.assertEqual(status, 413)
        self.assertEqual(
            [
                value.lower()
                for name, value in _headers
                if name.lower() == "cache-control"
            ],
            ["no-store"],
        )
        self.assertEqual(len(self.echo.snapshot()), before)

    def test_plain_http_is_rejected_before_proxying(self):
        agent_id = "123e4567-e89b-42d3-a456-426614174000"
        for method, path in (
            ("GET", "/monitor/api-key/v1/dashboard"),
            ("POST", f"/monitor/api-key/v1/agents/{agent_id}/revoke"),
        ):
            with self.subTest(path=path):
                before = len(self.echo.snapshot())
                status, _headers, _body = self._request(
                    method, path, tls=False, body=b"{}" if method == "POST" else None
                )
                self.assertEqual(status, 426)
                self.assertEqual(len(self.echo.snapshot()), before)

    def test_non_loopback_tcp_peer_is_rejected(self):
        address = _non_loopback_ipv4()
        if address is None:
            self.skipTest("host has no routable non-loopback IPv4 address")
        agent_id = "123e4567-e89b-42d3-a456-426614174000"
        for method, path in (
            ("GET", "/monitor/api-key/v1/dashboard"),
            ("POST", f"/monitor/api-key/v1/agents/{agent_id}/revoke"),
        ):
            with self.subTest(path=path):
                before = len(self.echo.snapshot())
                try:
                    status, _headers, _body = self._request(
                        method,
                        path,
                        host=address,
                        body=b"{}" if method == "POST" else None,
                    )
                except OSError as error:
                    self.skipTest(f"host cannot loop back through {address}: {error}")
                self.assertEqual(status, 403)
                self.assertEqual(len(self.echo.snapshot()), before)


if __name__ == "__main__":
    unittest.main()
