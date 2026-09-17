import hashlib
import json
from pathlib import Path
import unittest

from ops import notification_policy as policy
from ops import security_signals as signals


class NotificationPolicyTests(unittest.TestCase):
    def test_shared_policy_is_in_installer_preflight_backup_rollback_and_uninstall(self):
        ops = Path(__file__).resolve().parents[1]
        installer = (ops / "install.sh").read_text()
        uninstaller = (ops / "uninstall.sh").read_text()
        for required in (
            "notification_policy_target=/usr/local/lib/monitor-collector/notification_policy.py",
            '"$script_dir/notification_policy.py" \\\n',
            "had_notification_policy=false",
            'restore_file "$backup_dir/notification_policy.py" "$notification_policy_target" "$had_notification_policy"',
            '"$backup_dir/notification_policy.py" \\\n',
            '"$notification_policy_target" \\\n',
            'cp -p "$notification_policy_target" "$backup_dir/notification_policy.py"; had_notification_policy=true',
            'install -m 0644 "$script_dir/notification_policy.py" "$notification_policy_target"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, installer)
        self.assertIn("/usr/local/lib/monitor-collector/notification_policy.py", uninstaller)

    def test_default_rules_share_thresholds_recovery_and_durations(self):
        path = Path(__file__).resolve().parents[1] / "rules/default-rules.v1.json"
        rules = {row["id"]: row for row in json.loads(path.read_text())["rules"]}
        for rule_id, (field, severity, inverted) in policy.RESOURCE_RULE_POLICIES.items():
            with self.subTest(rule=rule_id):
                resource = policy.RESOURCE_POLICIES[field]
                rule = rules[rule_id]
                threshold = resource.critical if severity == "critical" else resource.warning
                recovery = resource.critical_recovery if severity == "critical" else resource.warning_recovery
                self.assertEqual(rule["threshold"], 100 - threshold if inverted else threshold)
                self.assertEqual(rule["recoveryThreshold"], 100 - recovery if inverted else recovery)
                self.assertEqual(rule["severity"], severity)
                self.assertEqual((rule["forSamples"], rule["forSeconds"]),
                                 policy.qualification(resource, severity))
                self.assertEqual((rule["recoverySamples"], rule["recoverySeconds"]),
                                 (resource.recovery_samples, resource.recovery_seconds))

    def test_cpu_is_sustained_warning_not_availability_critical(self):
        cpu = policy.RESOURCE_POLICIES["cpuPercent"]
        self.assertIsNone(policy.severity_for_value(cpu, 89.99))
        self.assertEqual(policy.severity_for_value(cpu, 90), "warning")
        self.assertEqual(policy.severity_for_value(cpu, 100), "warning")
        self.assertEqual(policy.qualification(cpu, "warning"), (5, 240))
        self.assertEqual(policy.severity_for_value(cpu, 85, "warning"), "warning")
        self.assertIsNone(policy.severity_for_value(cpu, 80, "warning"))
        # Old CPU critical incidents must be able to migrate to warning.
        self.assertEqual(policy.severity_for_value(cpu, 100, "critical"), "warning")

    def test_temperature_and_disk_entry_hysteresis_boundaries(self):
        for field, warning, critical, warning_recovery, critical_recovery in (
            ("temperatureC", 80, 85, 75, 80),
            ("usedPercent", 85, 95, 80, 90),
            ("inodeUsedPercent", 85, 90, 80, 85),
            ("memoryPercent", 80, 90, 75, 80),
        ):
            with self.subTest(field=field):
                resource = policy.RESOURCE_POLICIES[field]
                self.assertIsNone(policy.severity_for_value(resource, warning - 0.1))
                self.assertEqual(policy.severity_for_value(resource, warning), "warning")
                self.assertEqual(policy.severity_for_value(resource, critical), "critical")
                self.assertEqual(policy.severity_for_value(resource, critical_recovery + 0.1, "critical"), "critical")
                self.assertEqual(policy.severity_for_value(resource, critical_recovery, "critical"), "warning")
                self.assertEqual(policy.severity_for_value(resource, warning_recovery + 0.1, "warning"), "warning")
                self.assertIsNone(policy.severity_for_value(resource, warning_recovery, "warning"))

    def test_nonfinite_boolean_and_missing_values_are_not_observations(self):
        resource = policy.RESOURCE_POLICIES["cpuPercent"]
        for value in (None, float("nan"), float("inf"), -1, True, "99"):
            with self.subTest(value=value):
                self.assertIsNone(policy.resource_value("host:cpuPercent", {"latest": {"cpuPercent": value}}))
                self.assertIsNone(policy.severity_for_value(resource, value, "critical"))

    def test_load_requires_cpu_denominator_and_pressure_cannot_invent_host_cpu_full(self):
        for host in (None, {}, {"logicalCpuCount": 0}, {"logicalCpuCount": True}):
            current = {"latest": {"load1": 20, "cpuPressureFullAvg10": 100}, "host": host}
            self.assertIsNone(policy.resource_value("host:load", current))
            self.assertFalse(signals.observable("host:load", current))
            self.assertFalse(signals.observable("host:cpuPressureFullAvg10", current))
            self.assertEqual(signals.operational_signals(current), [])
        current = {"latest": {"load1": 6, "ioPressureFullAvg10": 99}, "host": {"logicalCpuCount": 4}}
        self.assertEqual(policy.resource_value("host:load", current), 1.5)
        self.assertEqual([row["severity"] for row in signals.operational_signals(current)], ["warning", "warning"])

    def test_disk_identity_and_exclusion_are_preserved(self):
        root_id = hashlib.sha256(b"/").hexdigest()[:12]
        excluded_id = hashlib.sha256(b"/srv/wgang").hexdigest()[:12]
        current = {"latest": {}, "disks": [
            {"mount": "/", "usedPercent": 96},
            {"mount": "/srv/wgang", "usedPercent": 99},
        ]}
        self.assertEqual(policy.resource_value(f"disk:{root_id}:usedPercent", current), 96)
        self.assertIsNone(policy.resource_value(f"disk:{excluded_id}:usedPercent", current))
        rows = signals.operational_signals(current)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["key"], f"disk:{root_id}:usedPercent")
        self.assertEqual(rows[0]["severity"], "critical")

    def test_hysteresis_evidence_does_not_claim_entry_threshold_still_exceeded(self):
        resource = policy.RESOURCE_POLICIES["temperatureC"]
        text = policy.evidence_for_value(resource, 82, "critical")
        self.assertIn("해제 기준", text)
        self.assertIn("80°C", text)
        self.assertNotIn("진입 기준", text)

    def test_power_loss_evidence_and_performance_limiting_are_distinct(self):
        for flags, severity in ((1, "critical"), (3, "critical"), (15, "critical"),
                                (2, "warning"), (4, "warning"), (8, "warning"), (14, "warning")):
            with self.subTest(flags=flags):
                rows = signals.operational_signals({"latest": {"throttledFlags": flags}})
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["severity"], severity)
        for flags in (None, "0", False):
            current = {"latest": {"throttledFlags": flags}}
            self.assertEqual(signals.operational_signals(current), [])
            self.assertFalse(signals.observable("host:power", current))
        self.assertTrue(signals.observable("host:power", {"latest": {"throttledFlags": 0}}))
        self.assertEqual(signals.operational_signals({"latest": {"throttledFlags": 1 << 16}}), [])
        path = Path(__file__).resolve().parents[1] / "rules/default-rules.v1.json"
        rules = {row["id"]: row for row in json.loads(path.read_text())["rules"]}
        self.assertEqual(rules["RaspberryPiThrottling"]["severity"], "warning")
        self.assertEqual((rules["RaspberryPiThrottling"]["forSamples"],
                          rules["RaspberryPiThrottling"]["forSeconds"]), (3, 120))
        self.assertEqual(rules["RaspberryPiUnderVoltage"]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
