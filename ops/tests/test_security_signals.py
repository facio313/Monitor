import datetime as dt
import unittest

from ops import security_signals as signals


NOW = dt.datetime(2026, 9, 13, 9, 0, tzinfo=dt.timezone.utc)


def ssh_row(message, seconds=0, **overrides):
    return {"timestamp": (NOW + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
            "sourceId": "journal:ssh", "redactionVersion": "monitor-log-redaction-v2",
            "message": message, **overrides}


def ssh_access_row(identifier="a", *, account="cks", fingerprint=None,
                   event="accepted", method="publickey", country="US"):
    return {"id": identifier * 64, "observedAt": NOW.isoformat().replace("+00:00", "Z"),
            "sourceId": "journal:ssh", "countryStatus": "estimated", "countryCode": country,
            "eventType": event, "authMethod": method, "targetAccount": account,
            "publicKeyFingerprint": fingerprint}


class SecuritySignalsTests(unittest.TestCase):
    def test_memory_mail_uses_cache_adjustment_but_oom_still_escalates(self):
        row = {"name": "database", "state": "running", "health": "healthy", "memoryBytes": 980,
               "memoryLimitBytes": 1000, "memoryWorkingSetBytes": 710, "memoryInactiveFileBytes": 270}
        current = {"latest": {}, "generatedAt": NOW.isoformat(),
                   "containerCollection": {"status": "fresh", "observedAt": NOW.isoformat()}, "containers": [row]}
        self.assertFalse(any(item["key"].endswith(":memory") for item in signals.operational_signals(current, NOW)))
        row["oomKilled"] = True
        self.assertTrue(any(item["key"].endswith(":oom") and item["severity"] == "critical"
                            for item in signals.operational_signals(current, NOW)))
        row["memoryWorkingSetBytes"] = None
        self.assertTrue(any(item["key"].endswith(":memory") and item["severity"] == "critical"
                            for item in signals.operational_signals(current, NOW)))

    def test_latency_is_left_to_rule_while_availability_and_tls_signals_remain(self):
        current = {"latest": {}, "generatedAt": NOW.isoformat(),
                   "syntheticProbeCollection": {"status": "fresh", "observedAt": NOW.isoformat()},
                   "syntheticProbes": [
                       {"id": "ready", "checkedAt": NOW.isoformat(), "status": "ok",
                        "latencyMilliseconds": 3209, "certificateDaysRemaining": 5},
                       {"id": "down", "checkedAt": NOW.isoformat(), "status": "timeout",
                        "latencyMilliseconds": 3209},
                   ]}
        result = signals.operational_signals(current, NOW)
        self.assertFalse(any(item["key"].endswith(":latency") for item in result))
        self.assertTrue(any(item["key"].endswith(":status") and item["severity"] == "critical"
                            for item in result))
        self.assertTrue(any(item["key"].endswith(":certificate") and item["severity"] == "critical"
                            for item in result))

    def test_denial_and_close_pair_is_one_conservative_attempt(self):
        denied = ssh_row("User root from [REDACTED_IP] not allowed because not listed in AllowUsers")
        closed = ssh_row("Connection closed by invalid user root [REDACTED_IP] port 5555 [preauth]")
        result = signals.ssh_signals([denied, closed, denied], NOW)
        self.assertEqual(result[0]["count"], 1)
        self.assertEqual(result[0]["severity"], "warning")
        self.assertNotIn("root", result[0]["evidence"])
        self.assertNotIn("REDACTED_IP", result[0]["evidence"])

    def test_failed_authentication_burst_warns_without_claiming_compromise(self):
        rows = [ssh_row("Failed password for invalid user account from [REDACTED_IP]", -index)
                for index in range(20)]
        self.assertEqual(signals.ssh_signals(rows, NOW)[0]["kind"], "ssh-auth-burst")
        result = signals.ssh_signals(rows, NOW)[0]
        self.assertEqual(result["severity"], "warning")
        self.assertEqual(result["count"], 20)
        self.assertIn("무단 접근 성공의 증거는 아닙니다", result["evidence"])
        self.assertEqual(signals.ssh_signals([
            ssh_row("Failed password for invalid user someone", redactionVersion=None),
            ssh_row("Failed password for invalid user someone", sourceId="journal:nginx"),
            ssh_row("Failed password for invalid user someone", -301),
            ssh_row("[UFW BLOCK] multicast packet"),
            ssh_row("Accepted publickey for admin"),
            ssh_row("wgang Failed password for invalid user someone"),
        ], NOW), [])

    def test_all_blocked_ssh_burst_is_attention_not_critical(self):
        rows = [ssh_row("User root from [REDACTED_IP] not allowed because not listed in AllowUsers", -index)
                for index in range(20)]
        result = signals.ssh_signals(rows, NOW)[0]
        self.assertEqual(result["kind"], "ssh-auth-burst")
        self.assertEqual(result["severity"], "warning")
        self.assertEqual(result["count"], 20)

    def test_only_exact_trusted_publickey_success_is_suppressed(self):
        trusted_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        trusted = frozenset({("cks", trusted_fingerprint)})
        approved = ssh_access_row(fingerprint=trusted_fingerprint)
        self.assertEqual(signals.ssh_signals([], NOW, [approved], trusted), [])

        unknown_key = ssh_access_row(
            "b", fingerprint="SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        result = signals.ssh_signals([], NOW, [approved, unknown_key], trusted)
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0]["key"], result[0]["count"]),
                         ("ssh-untrusted-accepted", 1))

        for row in (
            ssh_access_row("c", fingerprint=None),
            ssh_access_row("d", account="other", fingerprint=trusted_fingerprint),
            ssh_access_row("e", fingerprint=trusted_fingerprint, method="password"),
        ):
            with self.subTest(row=row):
                self.assertEqual(signals.ssh_signals([], NOW, [row], trusted)[0]["key"],
                                 "ssh-untrusted-accepted")

        failed = ssh_access_row("f", fingerprint=trusted_fingerprint, event="auth_failed")
        failure = signals.ssh_signals([], NOW, [failed], trusted)
        self.assertEqual(failure[0]["key"], "ssh-auth")
        serialized = str(result)
        self.assertNotIn("cks", serialized)
        self.assertNotIn(trusted_fingerprint, serialized)

    def test_generic_and_structured_failures_share_one_conservative_count(self):
        generic = [ssh_row(
            "Failed password for invalid user account from [REDACTED_IP]", seconds=-index,
        ) for index in range(5)]
        structured = [ssh_access_row(chr(97 + index), event="auth_failed", method="password")
                      for index in range(2)]
        result = signals.ssh_signals(generic, NOW, structured)
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0]["key"], result[0]["count"]), ("ssh-auth", 5))

    def test_http_counts_are_not_claimed_to_be_attacks(self):
        rows = {"currentTraffic": [
            {"app": "monitor", "requestCount": 100, "status4xx": 50, "status5xx": 0},
            {"app": "wgang", "requestCount": 1000, "status4xx": 1000},
        ]}
        result = signals.http_signals(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["kind"], "http-client-errors")
        self.assertIn("미확인", result[0]["evidence"])
        self.assertNotIn("wgang", str(result))

    def test_client_error_count_alone_never_implies_critical_outage(self):
        for total, errors in ((100, 100), (1000, 200), (10000, 10000)):
            with self.subTest(total=total, errors=errors):
                result = signals.http_signals({"currentTraffic": [{
                    "app": "monitor", "requestCount": total, "status4xx": errors,
                }]})
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["severity"], "warning")
                self.assertEqual(result[0]["count"], errors)

    def test_client_error_warning_still_requires_count_and_share(self):
        for total, errors in ((100, 19), (1000, 100)):
            with self.subTest(total=total, errors=errors):
                self.assertEqual(signals.http_signals({"currentTraffic": [{
                    "app": "monitor", "requestCount": total, "status4xx": errors,
                }]}), [])

    def test_operational_thresholds_and_nonfinite_values(self):
        current = {"latest": {"cpuPercent": 76, "memoryPercent": float("nan"),
                               "temperatureC": 86, "networkRxDroppedPerSecond": 0.1},
                   "disks": [{"mount": "/srv/wgang", "usedPercent": 99}]}
        result = signals.operational_signals(current)
        self.assertEqual([row["severity"] for row in result], ["critical"])

    def test_http_slow_share_requires_a_real_sample_but_absolute_delays_remain(self):
        for total, slow, maximum, severity in (
            (1, 1, 1200, None), (4, 3, 1200, None), (20, 2, 1200, None),
            (20, 3, 1200, "warning"), (20, 8, 1200, "critical"),
            (1, 1, 5000, "warning"), (1, 1, 15000, "critical"),
        ):
            with self.subTest(total=total, slow=slow, maximum=maximum):
                rows = signals.http_signals({"currentTraffic": [{
                    "app": "monitor", "requestCount": total, "slowCount": slow,
                    "maxResponseMs": maximum, "status4xx": 0, "status5xx": 0,
                }]})
                self.assertEqual([row["severity"] for row in rows], [severity] if severity else [])

    def test_http_server_critical_requires_count_and_share_at_any_traffic_volume(self):
        for total, errors, severity in (
            (1, 1, "warning"), (2, 2, "warning"), (3, 3, "critical"),
            (6, 3, "critical"), (7, 3, "warning"), (10, 5, "critical"),
            (19, 19, "critical"), (20, 4, "warning"), (20, 5, "critical"),
            (100, 5, "critical"), (101, 5, "warning"),
            (1000, 5, "warning"), (10000, 20, "warning"),
            (100000, 20, "warning"), (100000, 5000, "critical"),
        ):
            with self.subTest(total=total, errors=errors):
                rows = signals.http_signals({"currentTraffic": [{
                    "app": "monitor", "requestCount": total, "status5xx": errors,
                }]})
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["severity"], severity)
                self.assertEqual(rows[0]["count"], errors)

    def test_no_server_errors_do_not_generate_an_alert(self):
        self.assertEqual(signals.http_signals({"currentTraffic": [{
            "app": "monitor", "requestCount": 100, "status5xx": 0,
        }]}), [])


if __name__ == "__main__":
    unittest.main()
