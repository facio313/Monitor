import http.client
import json
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


NGINX = shutil.which("nginx")
PAYLOAD = json.dumps({"telemetry": "x" * (4 * 1024 * 1024)}).encode()


class _TelemetryHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        if self.path == "/streamed":
            self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(PAYLOAD)
        except (BrokenPipeError, ConnectionResetError):
            # The buffered control intentionally loses its upstream connection.
            pass

    def log_message(self, _format, *args):
        pass


@unittest.skipUnless(NGINX, "runtime response streaming requires nginx")
class NginxResponseStreamingTests(unittest.TestCase):
    def setUp(self):
        child_identity = {}
        if os.geteuid() == 0:
            try:
                unprivileged = pwd.getpwnam("nobody")
            except KeyError:
                self.skipTest("root runs need an unprivileged nobody account")
            child_identity = {
                "user": unprivileged.pw_uid,
                "group": unprivileged.pw_gid,
                "extra_groups": [],
            }

        temporary = tempfile.TemporaryDirectory(prefix="monitor-response-streaming-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o755)
        runtime = self.directory / "runtime"
        runtime.mkdir(mode=0o777)
        runtime.chmod(0o777)
        self.error_log = runtime / "error.log"

        # -p alone does not override Nginx's compiled absolute temp paths.
        # Explicitly isolate every path, including the unused protocols.
        for name in ("client-body", "proxy", "fastcgi", "uwsgi", "scgi"):
            path = self.directory / name
            path.mkdir()
            path.chmod(0o777)
        proxy_temp = self.directory / "proxy"
        proxy_temp.chmod(0)
        self.addCleanup(proxy_temp.chmod, 0o700)

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _TelemetryHandler)
        self.upstream.daemon_threads = True
        self.addCleanup(self.upstream.server_close)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.shutdown)

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]

        configuration = self.directory / "nginx.conf"
        configuration.write_text(
            "worker_processes 1;\n"
            "daemon off;\n"
            "master_process off;\n"
            f"pid {runtime}/nginx.pid;\n"
            f"error_log {self.error_log} notice;\n"
            "events { worker_connections 32; }\n"
            "http {\n"
            "  access_log off;\n"
            f"  client_body_temp_path {self.directory}/client-body;\n"
            f"  proxy_temp_path {proxy_temp};\n"
            f"  fastcgi_temp_path {self.directory}/fastcgi;\n"
            f"  uwsgi_temp_path {self.directory}/uwsgi;\n"
            f"  scgi_temp_path {self.directory}/scgi;\n"
            "  server {\n"
            f"    listen 127.0.0.1:{self.port} sndbuf=8192;\n"
            "    location / {\n"
            "      proxy_buffering on;\n"
            "      proxy_buffer_size 4k;\n"
            "      proxy_buffers 2 4k;\n"
            "      proxy_busy_buffers_size 4k;\n"
            "      proxy_temp_file_write_size 4k;\n"
            "      proxy_max_temp_file_size 16m;\n"
            f"      proxy_pass http://127.0.0.1:{self.upstream.server_port};\n"
            "    }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        self.nginx = subprocess.Popen(
            [NGINX, "-e", "stderr", "-c", str(configuration), "-p", str(self.directory)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **child_identity,
        )
        self.addCleanup(self._stop_nginx)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.nginx.poll() is not None:
                self.fail("isolated nginx failed: " + self.nginx.communicate()[1])
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        self.fail("isolated nginx did not start")

    def _stop_nginx(self):
        if self.nginx.poll() is None:
            self.nginx.terminate()
            try:
                self.nginx.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.nginx.kill()
                self.nginx.communicate(timeout=5)
        else:
            self.nginx.communicate()

    def _request(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(connection.close)
        connection.request("GET", path)
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(int(response.getheader("Content-Length")), len(PAYLOAD))
        # Backpressure makes a large buffered response spill to its temp path.
        time.sleep(0.15)
        return response

    def test_streaming_delivers_complete_json_when_proxy_temp_is_unwritable(self):
        buffered = self._request("/buffered")
        with self.assertRaises(http.client.IncompleteRead) as truncated:
            buffered.read()
        self.assertGreater(len(truncated.exception.partial), 0)
        self.assertLess(len(truncated.exception.partial), len(PAYLOAD))
        failure_log = self.error_log.read_text(encoding="utf-8")
        self.assertIn("Permission denied", failure_log)
        self.assertIn(str(self.directory / "proxy"), failure_log)

        streamed = self._request("/streamed")
        received = streamed.read()
        self.assertEqual(received, PAYLOAD)
        self.assertEqual(json.loads(received)["telemetry"], "x" * (4 * 1024 * 1024))
        self.assertEqual(self.error_log.read_text(encoding="utf-8"), failure_log)


if __name__ == "__main__":
    unittest.main()
