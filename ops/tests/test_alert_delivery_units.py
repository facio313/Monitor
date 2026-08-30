import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]


class AlertDeliveryUnitTests(unittest.TestCase):
    def test_worker_unit_is_bounded_and_is_the_only_network_capable_alert_path(self):
        worker = (OPS / "systemd/monitor-alert-delivery.service").read_text(encoding="utf-8")
        collector = (OPS / "systemd/monitor-collector.service").read_text(encoding="utf-8")

        self.assertIn("Type=oneshot", worker)
        self.assertIn("User=root", worker)
        self.assertIn("CapabilityBoundingSet=\n", worker)
        self.assertIn("NoNewPrivileges=true", worker)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", worker)
        self.assertIn("TimeoutStartSec=5min", worker)
        self.assertIn("--max-items=10 --max-runtime-seconds=45", worker)
        self.assertIn(" drain --worker-id=monitor-alert-delivery ", worker)

        self.assertIn("RestrictAddressFamilies=AF_UNIX", collector)
        self.assertNotIn("AF_INET", collector)
        self.assertNotIn("alert_delivery.py", collector)

    def test_worker_mount_namespace_exposes_only_delivery_state_and_secret_references(self):
        worker = (OPS / "systemd/monitor-alert-delivery.service").read_text(encoding="utf-8")

        self.assertIn("ConditionPathExists=/etc/monitor/alert-delivery.json", worker)
        self.assertIn(
            "ConditionPathExists=/var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite",
            worker,
        )
        self.assertIn("EnvironmentFile=-/etc/monitor/alert-delivery.env", worker)
        self.assertIn("TemporaryFileSystem=/etc:ro /run:ro /var/lib:ro", worker)
        self.assertIn(
            "BindReadOnlyPaths=-/etc/monitor/alert-delivery.json -/etc/monitor/secrets",
            worker,
        )
        self.assertIn(
            "BindPaths=/var/lib/monitor-export/.state/alert-delivery\n", worker
        )
        self.assertIn(
            "ReadWritePaths=/var/lib/monitor-export/.state/alert-delivery\n", worker
        )
        self.assertNotIn("BindPaths=/var/lib/monitor-export/.state\n", worker)
        self.assertNotIn("ReadWritePaths=/var/lib/monitor-export/.state\n", worker)
        self.assertNotIn("ReadWritePaths=/var/lib/monitor-export\n", worker)
        self.assertNotIn("MONITOR_SLACK_WEBHOOK_URL=", worker)
        self.assertNotIn("MONITOR_TELEGRAM_BOT_TOKEN=", worker)

    def test_timer_waits_for_completion_and_does_not_overlap_workers(self):
        timer = (OPS / "systemd/monitor-alert-delivery.timer").read_text(encoding="utf-8")

        self.assertIn("OnBootSec=2min", timer)
        self.assertIn("OnUnitInactiveSec=15s", timer)
        self.assertNotIn("OnUnitActiveSec", timer)
        self.assertIn("Unit=monitor-alert-delivery.service", timer)
        self.assertIn("WantedBy=timers.target", timer)


if __name__ == "__main__":
    unittest.main()
