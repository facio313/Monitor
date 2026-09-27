import json
from pathlib import Path
import unittest

from ops import alert_runtime
from ops import notification_policy as policy
from ops import notification_reports as reports
from ops import notification_visuals as visuals
from ops import security_signals as signals
from ops.alert_engine import load_rule_pack


OPS_ROOT = Path(__file__).resolve().parents[1]


class PersonalPiMailProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule_path = OPS_ROOT / "rules" / "default-rules.v1.json"
        cls.document = json.loads(cls.rule_path.read_text())
        cls.rules = {row["id"]: row for row in cls.document["rules"]}
        cls.pack = load_rule_pack(cls.rule_path)

    def test_rule_pack_uses_personal_pi_thresholds_and_warmup_version(self):
        self.assertEqual(self.document["version"], "2026.09.27.1")
        http = self.rules["HttpLatencyHigh"]
        self.assertEqual(
            (http["threshold"], http["forSamples"], http["forSeconds"]),
            (2000, 10, 540),
        )
        self.assertEqual(
            (http["recoveryThreshold"], http["recoverySamples"], http["recoverySeconds"]),
            (800, 10, 540),
        )
        tcp = self.rules["TcpRetransmissionHigh"]
        self.assertEqual(
            (tcp["threshold"], tcp["forSamples"], tcp["forSeconds"]),
            (5, 10, 540),
        )
        self.assertEqual((tcp["recoveryThreshold"], tcp["recoverySeconds"]), (1, 900))
        for rule_id in ("HttpLatencyHigh", "TcpRetransmissionHigh"):
            self.assertEqual(self.rules[rule_id]["labels"]["delivery_class"], "immediate-warning")

    def test_recovery_and_hardware_policy_are_deliberately_slow(self):
        self.assertEqual(
            (policy.RESOURCE_POLICIES["cpuPercent"].recovery_samples,
             policy.RESOURCE_POLICIES["cpuPercent"].recovery_seconds),
            (6, 300),
        )
        temperature = policy.RESOURCE_POLICIES["temperatureC"]
        self.assertEqual(
            (temperature.warning, temperature.warning_samples, temperature.warning_seconds),
            (80, 5, 240),
        )
        self.assertEqual(
            (temperature.critical, temperature.critical_samples, temperature.critical_seconds),
            (85, 2, 60),
        )
        for rule_id in ("ContainerDown", "ContainerUnhealthy", "HttpEndpointDown",
                        "RaspberryPiUnderVoltage"):
            rule = self.rules[rule_id]
            self.assertEqual((rule["recoverySamples"], rule["recoverySeconds"]), (6, 300))
        for rule_id in ("SmartHealthFailed", "RaspberryPiThrottling", "DiskIoErrors",
                        "UnexpectedReboot", "HttpErrorRateHigh", "OOMKillDetected"):
            self.assertFalse(self.rules[rule_id]["enabled"])

    def test_tcp_mail_value_requires_material_absolute_volume(self):
        base = {
            "identity": {"hostId": "11111111-1111-4111-8111-111111111111"},
            "host": {"hostname": "pi"},
            "linux": {"tcp": {"status": "supported", "assessment": {
                "status": "ok", "retransmissionPercent": 6,
                "retransmittedSegmentsDelta": 99,
            }}},
        }
        low = alert_runtime.observations_for_snapshot(self.pack, base)["TcpRetransmissionHigh"][0]
        self.assertEqual((low.status, low.value), ("ok", 0.0))
        base["linux"]["tcp"]["assessment"]["retransmittedSegmentsDelta"] = 100
        material = alert_runtime.observations_for_snapshot(self.pack, base)["TcpRetransmissionHigh"][0]
        self.assertEqual((material.status, material.value), ("ok", 6.0))

    def test_single_slow_request_or_maximum_does_not_create_mail_signal(self):
        def rows(total, slow, maximum):
            return signals.http_signals({"currentTraffic": [{
                "app": "personal-app", "requestCount": total,
                "status4xx": 0, "status5xx": 0,
                "slowCount": slow, "maxResponseMs": maximum,
            }]})

        self.assertEqual(rows(1, 1, 30000), [])
        self.assertEqual(rows(20, 2, 30000), [])
        result = rows(20, 3, 3000)
        self.assertEqual([(row["kind"], row["severity"]) for row in result],
                         [("operational-caution", "warning")])

    def test_http_visual_uses_the_same_recovery_and_entry_boundaries(self):
        self.assertEqual(visuals._card("HTTP", 799, "ms", 800, 2000, True)["tone"], "ok")
        self.assertEqual(visuals._card("HTTP", 800, "ms", 800, 2000, True)["tone"], "warning")
        self.assertEqual(visuals._card("HTTP", 2000, "ms", 800, 2000, True)["tone"], "critical")

    def test_delivery_classes_are_fixed_non_sensitive_labels(self):
        warning = {"key": "host:cpuPercent", "kind": "operational-caution", "severity": "warning"}
        digest = {"key": "host:ioPressure", "kind": "operational-caution", "severity": "warning"}
        critical = {"key": "kernel:oom", "kind": "kernel-event", "severity": "critical"}
        self.assertEqual(reports._signal_delivery_class(warning), "immediate-warning")
        self.assertEqual(reports._signal_delivery_class(digest), "digest-only")
        self.assertEqual(reports._signal_delivery_class(critical), "immediate-critical")
        event = reports._event(
            "OperationalCaution", "test", "warning", "2026-09-27T00:00:00Z",
            "2026-09-27T00:00:00Z", "bounded evidence",
            signal_kind="operational-caution", delivery_class="immediate-warning",
        )
        self.assertEqual(event["labels"]["delivery_class"], "immediate-warning")
        daily = reports._event(
            "HourlyReport", "daily", "info", "2026-09-27T00:00:00Z",
            "2026-09-27T00:00:00Z", "daily report",
        )
        self.assertEqual(daily["labels"]["delivery_class"], "daily-report")


if __name__ == "__main__":
    unittest.main()
