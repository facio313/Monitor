"""SSH observation helpers stay in the existing collector transaction."""

import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]


class SshInstallContractTests(unittest.TestCase):
    def test_helpers_are_preflighted_backed_up_installed_and_restored(self):
        install = (OPS / "install.sh").read_text()
        uninstall = (OPS / "uninstall.sh").read_text()
        transaction = install.index("\ntransaction_started=true\n")
        for name in ("ssh_access", "ip_country"):
            with self.subTest(module=name):
                target = f"/usr/local/lib/monitor-collector/{name}.py"
                self.assertIn(f"{name}_target={target}", install)
                self.assertIn(f'"$script_dir/{name}.py" \\\n', install)
                self.assertIn(f"had_{name}=false", install)
                self.assertIn(f'"${name}_target" \\\n', install)
                snapshot = f'if [ -e "${name}_target" ]; then cp -p "${name}_target" "$backup_dir/{name}.py"; had_{name}=true; fi'
                self.assertLess(install.index(snapshot), transaction)
                self.assertIn(f'restore_file "$backup_dir/{name}.py" "${name}_target" "$had_{name}" || rollback_failed=true', install)
                self.assertIn(f'install -m 0644 "$script_dir/{name}.py" "${name}_target"', install)
                self.assertIn(f'"$backup_dir/{name}.py" \\\n', install)
                self.assertIn(target, uninstall)

    def test_country_data_is_not_downloaded_or_deleted_by_service_install(self):
        install = (OPS / "install.sh").read_text()
        uninstall = (OPS / "uninstall.sh").read_text()
        self.assertNotIn("download.db-ip.com", install)
        self.assertNotIn("ip-country.sqlite", install)
        self.assertIn('echo "  /usr/local/share/monitor-collector/ip-country.sqlite', uninstall)
        self.assertNotIn("    /usr/local/share/monitor-collector/ip-country.sqlite \\", uninstall)


if __name__ == "__main__":
    unittest.main()
