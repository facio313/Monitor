"""SSH observation helpers stay in the existing collector transaction."""

import configparser
import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]


class SshInstallContractTests(unittest.TestCase):
    def test_geo_dropins_gate_the_correct_ssh_unit_types(self):
        for filename, section in (("ssh-service-geo.conf", "Service"), ("ssh-socket-geo.conf", "Socket")):
            with self.subTest(dropin=filename):
                config = configparser.ConfigParser(interpolation=None, strict=True)
                config.read_string((OPS / "systemd" / filename).read_text())
                self.assertEqual(set(config.sections()), {"Unit", section})
                self.assertEqual(dict(config["Unit"]), {
                    "wants": "monitor-ssh-geo.service",
                    "after": "monitor-ssh-geo.service",
                })
                self.assertEqual(dict(config[section]), {
                    "execstartpre": "/usr/local/sbin/monitor-ssh-geo-apply",
                })

    def test_ci_checks_standalone_units_without_passing_dropins_as_unit_files(self):
        workflow = (OPS.parent / ".github" / "workflows" / "deploy.yml").read_text()
        self.assertIn("'ops/systemd/*.service' 'ops/systemd/*.timer'", workflow)
        self.assertNotIn("git ls-files -z 'ops/systemd/*'", workflow)
        self.assertIn("sudo install -m 0755 ops/ssh_geo_apply.py /usr/local/sbin/monitor-ssh-geo-apply", workflow)

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
