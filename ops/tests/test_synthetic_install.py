"""Operational install/uninstall contracts for the opt-in synthetic worker."""

from __future__ import annotations

import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]


class SyntheticInstallContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = (OPS / "install.sh").read_text(encoding="utf-8")
        cls.uninstaller = (OPS / "uninstall.sh").read_text(encoding="utf-8")
        cls.service = (OPS / "systemd" / "monitor-synthetic-probe.service").read_text(
            encoding="utf-8"
        )
        cls.collector_service = (OPS / "systemd" / "monitor-collector.service").read_text(
            encoding="utf-8"
        )

    def test_assets_participate_in_the_existing_file_transaction(self) -> None:
        contracts = (
            (
                "synthetic_probe.py",
                'install -m 0755 "$script_dir/synthetic_probe.py" "$synthetic_probe_target"',
            ),
            (
                "synthetic-probes.md",
                'install -m 0644 "$script_dir/../docs/synthetic-probes.md" "$synthetic_doc_target"',
            ),
            (
                "synthetic-probes.example.json",
                'install -m 0644 "$script_dir/synthetic-probes.example.json" "$synthetic_example_target"',
            ),
            (
                "monitor-synthetic-probe.service",
                'install -m 0644 "$script_dir/systemd/monitor-synthetic-probe.service" "$synthetic_service_target"',
            ),
            (
                "monitor-synthetic-probe.timer",
                'install -m 0644 "$script_dir/systemd/monitor-synthetic-probe.timer" "$synthetic_timer_target"',
            ),
        )
        transaction = self.installer.index("\ntransaction_started=true\n")
        for backup_name, install_command in contracts:
            backup = self.installer.index(f'"$backup_dir/{backup_name}"; had_')
            restore = self.installer.index(f'restore_file "$backup_dir/{backup_name}"')
            install = self.installer.index(install_command)
            self.assertLess(restore, transaction)
            self.assertLess(backup, transaction)
            self.assertGreater(install, transaction)

    def test_state_directory_ownership_and_rollback_metadata_are_explicit(self) -> None:
        snapshot = self.installer.index(
            "capture_directory_metadata /var/lib/monitor-synthetic"
        )
        transaction = self.installer.index("\ntransaction_started=true\n")
        mkdir = self.installer.index("mkdir -- /var/lib/monitor-synthetic")
        marker = self.installer.index("created_synthetic_output_directory=true", mkdir)
        ownership = self.installer.index(
            "install -d -o cks -g cks -m 0750 /var/lib/monitor-synthetic", marker
        )
        restore = self.installer.index("restore_directory /var/lib/monitor-synthetic")
        self.assertLess(restore, transaction)
        self.assertLess(snapshot, transaction)
        self.assertLess(transaction, mkdir)
        self.assertLess(mkdir, marker)
        self.assertLess(marker, ownership)

    def test_first_install_does_not_provision_targets_or_enable_probing(self) -> None:
        live_config = "/etc/monitor-synthetic-probe/probes.json"
        transaction_body = self.installer.split("transaction_started=true", 1)[1]
        # The sole live-config reference is an operator-facing completion note;
        # no mkdir, copy, or install operation targets the private config path.
        self.assertEqual(self.installer.count(live_config), 1)
        self.assertNotIn("enable --now monitor-synthetic-probe", self.installer)
        self.assertIn(
            'if [ "$was_synthetic_timer_enabled" = true ]; then\n'
            "    systemctl enable monitor-synthetic-probe.timer\n"
            "else\n"
            "    systemctl disable monitor-synthetic-probe.timer",
            transaction_body,
        )
        self.assertIn(
            'if [ "$was_synthetic_timer_active" = true ]; then\n'
            "    systemctl start monitor-synthetic-probe.timer",
            transaction_body,
        )

    def test_rollback_restores_prior_timer_state(self) -> None:
        transaction = self.installer.index("\ntransaction_started=true\n")
        enabled_snapshot = self.installer.index(
            "systemctl is-enabled --quiet monitor-synthetic-probe.timer"
        )
        active_snapshot = self.installer.index(
            "systemctl is-active --quiet monitor-synthetic-probe.timer"
        )
        rollback = self.installer.split("finish() {", 1)[1].split("trap finish EXIT", 1)[0]
        self.assertLess(enabled_snapshot, transaction)
        self.assertLess(active_snapshot, transaction)
        self.assertIn("systemctl stop monitor-synthetic-probe.timer", rollback)
        self.assertIn("systemctl enable monitor-synthetic-probe.timer", rollback)
        self.assertIn("systemctl disable monitor-synthetic-probe.timer", rollback)
        self.assertIn("systemctl start monitor-synthetic-probe.timer", rollback)

    def test_service_and_collector_have_a_one_way_ownership_handoff(self) -> None:
        self.assertIn("User=cks", self.service)
        self.assertIn("Group=cks", self.service)
        self.assertIn("StateDirectory=monitor-synthetic", self.service)
        self.assertIn("UMask=0027", self.service)
        self.assertIn(
            "--output /var/lib/monitor-synthetic/results.json", self.service
        )
        self.assertIn(
            "BindReadOnlyPaths=-/var/lib/monitor-synthetic/results.json",
            self.collector_service,
        )
        self.assertNotIn("BindPaths=/var/lib/monitor-synthetic", self.collector_service)

    def test_uninstall_removes_assets_but_preserves_operator_state(self) -> None:
        removals = self.uninstaller.split('echo "Collector removed', 1)[0]
        for installed_path in (
            "/etc/systemd/system/monitor-synthetic-probe.service",
            "/etc/systemd/system/monitor-synthetic-probe.timer",
            "/usr/local/lib/monitor-collector/synthetic_probe.py",
            "/usr/local/share/doc/monitor-collector/synthetic-probes.md",
            "/usr/local/share/doc/monitor-collector/synthetic-probes.example.json",
        ):
            self.assertIn(installed_path, removals)
        for retained_path in (
            "/etc/monitor-synthetic-probe/probes.json",
            "/var/lib/monitor-synthetic/results.json",
        ):
            self.assertNotIn(retained_path, removals)
            self.assertIn(retained_path, self.uninstaller)
        self.assertNotIn("rmdir /var/lib/monitor-synthetic", self.uninstaller)


if __name__ == "__main__":
    unittest.main()
