import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PublicReadinessNginxTests(unittest.TestCase):
    def test_only_the_exact_reduced_readiness_path_bypasses_sso(self):
        content = (ROOT / "ops/nginx/monitor-public-readiness.conf").read_text(
            encoding="utf-8"
        )
        directives = [
            line.strip() for line in content.splitlines()
            if line.lstrip().startswith("location ")
        ]
        self.assertEqual(directives, ["location = /monitor/readyz {"])
        self.assertIn("location = /monitor/readyz {", content)
        self.assertIn("proxy_pass         http://127.0.0.1:5181/readyz;", content)
        self.assertIn('add_header         Cache-Control "no-store" always;', content)
        self.assertIn("proxy_no_cache     1;", content)
        self.assertIn("proxy_cache_bypass 1;", content)
        self.assertNotIn("authrequest", content.lower())
        self.assertNotIn("edge-secret", content.lower())
        self.assertNotIn("/monitor/api", content)


class ApiKeyIngressNginxTests(unittest.TestCase):
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

    def test_public_aliases_match_the_application_bearer_allowlist(self):
        ingress = (ROOT / "ops/nginx/monitor-api-key-ingress.conf").read_text(
            encoding="utf-8"
        )
        application = (ROOT / "server/app.ts").read_text(encoding="utf-8")
        fixed_locations = [
            line.strip().split()[2]
            for line in ingress.splitlines()
            if line.strip().startswith("location = ")
        ]
        self.assertEqual(fixed_locations, list(self.FIXED_ROUTES))
        for public_path, (method, internal_path) in self.FIXED_ROUTES.items():
            expected_block_start = (
                f"location = {public_path} {{\n"
                f"    if ($request_method != {method}) {{ return 405; }}\n"
                "    include /etc/nginx/snippets/monitor-api-key-proxy.conf;\n"
                f"    rewrite ^ {internal_path} break;"
            )
            self.assertIn(expected_block_start, ingress)
            self.assertIn(f"['{method} {internal_path}',", application)

        self.assertEqual(
            ingress.count(
                "include /etc/nginx/snippets/monitor-api-key-proxy.conf;"
            ),
            len(self.FIXED_ROUTES) + 1,
        )
        self.assertIn("location ^~ /monitor/api-key/v1/agents/ {", ingress)
        self.assertIn("(?:certificate-rotation-tokens|revoke)$", ingress)
        self.assertIn("/monitor/api/agents/$1/$2 break;", ingress)
        dynamic_include = ingress.index(
            "include /etc/nginx/snippets/monitor-api-key-proxy.conf;",
            ingress.index("location ^~ /monitor/api-key/v1/agents/ {"),
        )
        dynamic_rewrite = ingress.index(
            "rewrite \"^/monitor/api-key/v1/agents/",
            dynamic_include,
        )
        self.assertLess(dynamic_include, dynamic_rewrite)
        self.assertIn("certificate-rotation-tokens|revoke", application)
        self.assertNotIn("/security/", ingress)
        self.assertNotIn("/monitor/api/agent/", ingress)
        self.assertNotIn("auth_request", ingress)

    def test_proxy_replaces_untrusted_authority_and_forwarding_headers(self):
        proxy = (ROOT / "ops/nginx/monitor-api-key-proxy.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("include /etc/nginx/snippets/monitor-edge-secret.conf;", proxy)
        self.assertIn("if ($monitor_api_key_peer_allowed = 0) { return 403; }", proxy)
        self.assertIn("if ($https != on) { return 426; }", proxy)
        self.assertNotIn("sso-authrequest", proxy)
        self.assertIn("X-Forwarded-For              $remote_addr;", proxy)
        self.assertNotIn("$proxy_add_x_forwarded_for", proxy)
        for header in (
            "Cookie",
            "Remote-User",
            "Remote-Groups",
            "Remote-Name",
            "Remote-Email",
            "X-Monitor-mTLS-Verified",
            "X-Monitor-Client-Cert-SHA256",
            "X-Monitor-Client-Cert-Not-After",
        ):
            self.assertIn(f"proxy_set_header   {header}", proxy)
        self.assertIn("proxy_hide_header     Set-Cookie;", proxy)
        self.assertIn('Cache-Control "no-store" always;', proxy)

    def test_cloudflare_real_ip_trust_is_explicit_and_bounded(self):
        content = (ROOT / "ops/nginx/monitor-cloudflare-real-ip.conf").read_text(
            encoding="utf-8"
        )
        ranges = [
            line.removeprefix("set_real_ip_from ").removesuffix(";")
            for line in content.splitlines()
            if line.startswith("set_real_ip_from ")
        ]
        self.assertEqual(len(ranges), 22)
        self.assertEqual(len(set(ranges)), len(ranges))
        self.assertIn("103.21.244.0/22", ranges)
        self.assertIn("198.41.128.0/17", ranges)
        self.assertIn("2405:b500::/32", ranges)
        self.assertIn("2c0f:f248::/32", ranges)
        self.assertIn("real_ip_header CF-Connecting-IP;", content)
        self.assertNotIn("set_real_ip_from 0.0.0.0/0", content)
        self.assertNotIn("set_real_ip_from ::/0", content)

        peer_map = (ROOT / "ops/nginx/monitor-api-key-peer-map.conf").read_text(
            encoding="utf-8"
        )
        allowed_ranges = [
            line.strip().split()[0]
            for line in peer_map.splitlines()
            if line.strip().endswith(" 1;")
        ]
        self.assertEqual(set(allowed_ranges), set(ranges) | {"127.0.0.1/32", "::1/128"})
        self.assertIn("geo $realip_remote_addr $monitor_api_key_peer_allowed {", peer_map)
        self.assertIn("default 0;", peer_map)

    @unittest.skipUnless(shutil.which("nginx"), "nginx is not installed")
    def test_composed_snippets_pass_nginx_syntax_validation(self):
        with tempfile.TemporaryDirectory(prefix="monitor-nginx-test-") as raw_directory:
            directory = Path(raw_directory)
            snippets = directory / "snippets"
            snippets.mkdir()
            for name in (
                "monitor-api-key-ingress.conf",
                "monitor-api-key-proxy.conf",
                "monitor-cloudflare-real-ip.conf",
                "monitor-api-key-peer-map.conf",
            ):
                source = (ROOT / "ops/nginx" / name).read_text(encoding="utf-8")
                source = source.replace("/etc/nginx/snippets/", f"{snippets}/")
                (snippets / name).write_text(source, encoding="utf-8")
            (snippets / "monitor-edge-secret.conf").write_text(
                'proxy_set_header X-Portfolio-Edge-Secret "test-only-edge-secret";\n',
                encoding="utf-8",
            )
            configuration = directory / "nginx.conf"
            configuration.write_text(
                f"pid {directory}/nginx.pid;\n"
                "error_log stderr;\n"
                "events {}\n"
                "http {\n"
                "  access_log off;\n"
                f"  include {snippets}/monitor-api-key-peer-map.conf;\n"
                "  server {\n"
                "    listen 127.0.0.1:8080;\n"
                f"    include {snippets}/monitor-api-key-ingress.conf;\n"
                "    location ^~ /monitor/ { return 418; }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                ["nginx", "-t", "-c", str(configuration), "-p", str(directory)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )


if __name__ == "__main__":
    unittest.main()
