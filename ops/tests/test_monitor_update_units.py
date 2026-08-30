import os
import subprocess
import unittest
from pathlib import Path


OPS = Path(__file__).resolve().parents[1]


class UpdateUnitContractTests(unittest.TestCase):
    @staticmethod
    def worker_guard(script_name: str) -> str:
        script = (OPS / script_name).read_text(encoding="utf-8")
        start = script.index("worker_is_quiescent() {")
        end = script.index("\n}\n", start) + 3
        return script[start:end]

    def run_worker_guard(
        self,
        script_name: str,
        *,
        load_state: str,
        active_state: str,
        job: str = "",
        failed_property: str = "",
    ) -> int:
        fake_systemctl = r'''
systemctl() {
    case "$*" in
        *--property=LoadState*) property=LoadState; value=$TEST_LOAD_STATE ;;
        *--property=ActiveState*) property=ActiveState; value=$TEST_ACTIVE_STATE ;;
        *--property=Job*) property=Job; value=$TEST_JOB ;;
        *) return 97 ;;
    esac
    if [ "$property" = "$TEST_FAILED_PROPERTY" ]; then
        return 1
    fi
    printf '%s\n' "$value"
}
'''
        result = subprocess.run(
            ["sh", "-c", f"{fake_systemctl}\n{self.worker_guard(script_name)}\nworker_is_quiescent"],
            check=False,
            env={
                **os.environ,
                "TEST_LOAD_STATE": load_state,
                "TEST_ACTIVE_STATE": active_state,
                "TEST_JOB": job,
                "TEST_FAILED_PROPERTY": failed_property,
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode

    def test_socket_uses_stable_narrow_runtime_directory(self) -> None:
        socket_unit = (OPS / "systemd/monitor-update-gateway.socket").read_text(encoding="utf-8")
        tmpfiles = (OPS / "tmpfiles/monitor-update.conf").read_text(encoding="utf-8")
        compose = (OPS.parent / "docker-compose.yml").read_text(encoding="utf-8")
        server_config = (OPS.parent / "server/config.ts").read_text(encoding="utf-8")
        host_directory = "/var/lib/monitor-update-socket"
        self.assertIn(f"ListenStream={host_directory}/gateway.sock", socket_unit)
        self.assertIn("RequiresMountsFor=/var/lib", socket_unit)
        self.assertIn("DirectoryMode=0750", socket_unit)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("SocketGroup=cks", socket_unit)
        self.assertEqual(tmpfiles, f"d {host_directory} 0750 root cks -\n")
        self.assertNotIn("monitor-update-gateway.sock", socket_unit)
        self.assertIn(f"source: {host_directory}", compose)
        self.assertNotIn("MONITOR_UPDATE_SOCKET_DIR", compose)
        self.assertIn("target: /run/monitor-update", compose)
        self.assertIn("create_host_path: false", compose)
        self.assertIn("'/run/monitor-update/gateway.sock'", server_config)

    def test_protected_gateway_consumes_only_the_systemd_inherited_socket(self) -> None:
        socket_unit = (OPS / "systemd/monitor-update-gateway.socket").read_text(encoding="utf-8")
        gateway_unit = (OPS / "systemd/monitor-update-gateway.service").read_text(encoding="utf-8")
        gateway_source = (OPS / "monitor_update_gateway.py").read_text(encoding="utf-8")
        self.assertIn("ListenStream=/var/lib/monitor-update-socket/", socket_unit)
        self.assertIn("ProtectHome=true", gateway_unit)
        self.assertIn("InaccessiblePaths=/home /root", gateway_unit)
        self.assertIn("--listen-fd=3", gateway_unit)
        self.assertIn('os.environ.get("LISTEN_PID")', gateway_source)
        self.assertIn('os.environ.get("LISTEN_FDS", "0")', gateway_source)
        self.assertIn("socket.socket(fileno=file_descriptor)", gateway_source)
        self.assertNotIn("monitor-update-socket", gateway_source)

    def test_socket_directory_lifecycle_is_transactional_and_legacy_path_is_only_cleaned(self) -> None:
        installer = (OPS / "install-updater.sh").read_text(encoding="utf-8")
        uninstaller = (OPS / "uninstall-updater.sh").read_text(encoding="utf-8")
        rollback = installer.split("finish() {", 1)[1].split("trap finish EXIT", 1)[0]
        host_directory = "/var/lib/monitor-update-socket"
        self.assertIn(f"socket_dir={host_directory}", installer)
        self.assertIn("for directory in /var \"$socket_parent\"", installer)
        self.assertIn('[ "$directory_uid" -ne 0 ]', installer)
        self.assertIn('if [ "$socket_dir_created" = true ]; then rmdir "$socket_dir"', rollback)
        self.assertIn('stat -c %u:%g:%a -- "$socket_dir"', installer)
        self.assertIn('rmdir "$legacy_socket_dir"', installer)
        install_commit = installer.rsplit("systemctl enable --now", 1)[1]
        self.assertLess(
            install_commit.index("committed=true"),
            install_commit.index('rmdir "$legacy_socket_dir"'),
        )
        self.assertIn(f"socket_dir={host_directory}", uninstaller)
        self.assertIn('stat -c %u:%g:%a -- "$socket_dir"', uninstaller)
        self.assertIn('rmdir "$socket_dir"', uninstaller)
        uninstall_commit = uninstaller.rsplit("systemctl daemon-reload", 1)[1]
        self.assertLess(
            uninstall_commit.index("committed=true"),
            uninstall_commit.index('rmdir "$socket_dir"'),
        )
        self.assertNotIn("d /run/monitor-update", (OPS / "tmpfiles/monitor-update.conf").read_text())

    def test_gateway_is_unprivileged_and_worker_is_path_triggered(self) -> None:
        gateway = (OPS / "systemd/monitor-update-gateway.service").read_text(encoding="utf-8")
        path = (OPS / "systemd/monitor-update-worker.path").read_text(encoding="utf-8")
        worker = (OPS / "systemd/monitor-update-worker.service").read_text(encoding="utf-8")
        self.assertIn("User=monitor-updater", gateway)
        self.assertIn("NoNewPrivileges=true", gateway)
        self.assertIn("ReadWritePaths=/var/lib/monitor-update/incoming", gateway)
        self.assertNotIn("apt-get", gateway)
        self.assertIn("PathExistsGlob=/var/lib/monitor-update/incoming/request-*.json", path)
        self.assertIn("PathExistsGlob=/var/lib/monitor-update/processing/request-*.json", path)
        self.assertIn("User=root", worker)
        self.assertNotIn("ConditionPathIsDirectory=/var/lib/monitor-update/incoming", worker)
        self.assertIn("monitor_update_worker.py", worker)
        self.assertIn("KillMode=process", worker)
        self.assertIn("TimeoutStartSec=infinity", worker)
        self.assertIn("SendSIGKILL=no", worker)
        self.assertNotIn("/run/systemd", gateway)
        self.assertNotIn("docker.sock", gateway)

    def test_exact_apt_config_makes_validator_the_first_pre_dpkg_hook(self) -> None:
        config = (OPS / "monitor-update-apt.conf").read_text(encoding="utf-8")
        installer = (OPS / "install-updater.sh").read_text(encoding="utf-8")
        uninstaller = (OPS / "uninstall-updater.sh").read_text(encoding="utf-8")
        self.assertIn("#clear DPkg::Pre-Invoke;", config)
        self.assertIn("#clear DPkg::Pre-Install-Pkgs;", config)
        self.assertIn("monitor_update_worker.py --verify-apt-transaction", config)
        self.assertIn("::Version \"3\";", config)
        self.assertIn("::InfoFD \"0\";", config)
        self.assertIn("apt-exact.conf", installer)
        self.assertIn("apt-exact.conf", uninstaller)

    def test_installer_rollback_removes_new_enable_links(self) -> None:
        installer = (OPS / "install-updater.sh").read_text(encoding="utf-8")
        rollback = installer.split("finish() {", 1)[1].split("trap finish EXIT", 1)[0]
        socket_disable = "systemctl disable monitor-update-gateway.socket"
        path_disable = "systemctl disable monitor-update-worker.path"
        self.assertIn('if [ "$socket_was_enabled" != true ]', rollback)
        self.assertIn('if [ "$path_was_enabled" != true ]', rollback)
        self.assertIn(socket_disable, rollback)
        self.assertIn(path_disable, rollback)
        self.assertLess(rollback.index(socket_disable), rollback.index('restore_target "$backup_dir/gateway.py"'))
        self.assertLess(rollback.index(path_disable), rollback.index('restore_target "$backup_dir/gateway.py"'))

    def test_installer_and_uninstaller_fail_closed_for_oneshot_worker_states(self) -> None:
        for script_name in ("install-updater.sh", "uninstall-updater.sh"):
            with self.subTest(script=script_name, state="loaded-inactive"):
                self.assertEqual(
                    self.run_worker_guard(script_name, load_state="loaded", active_state="inactive"),
                    0,
                )
            with self.subTest(script=script_name, state="not-found"):
                self.assertEqual(
                    self.run_worker_guard(script_name, load_state="not-found", active_state="inactive"),
                    0,
                )
            for active_state in (
                "activating",
                "active",
                "deactivating",
                "reloading",
                "failed",
                "unknown",
            ):
                with self.subTest(script=script_name, state=active_state):
                    self.assertNotEqual(
                        self.run_worker_guard(
                            script_name,
                            load_state="loaded",
                            active_state=active_state,
                        ),
                        0,
                    )
            with self.subTest(script=script_name, state="pending-job"):
                self.assertNotEqual(
                    self.run_worker_guard(
                        script_name,
                        load_state="loaded",
                        active_state="inactive",
                        job="123 start",
                    ),
                    0,
                )
            with self.subTest(script=script_name, state="unknown-load-state"):
                self.assertNotEqual(
                    self.run_worker_guard(script_name, load_state="error", active_state="inactive"),
                    0,
                )
            for failed_property in ("LoadState", "Job", "ActiveState"):
                with self.subTest(script=script_name, failed_property=failed_property):
                    self.assertNotEqual(
                        self.run_worker_guard(
                            script_name,
                            load_state="loaded",
                            active_state="inactive",
                            failed_property=failed_property,
                        ),
                        0,
                    )

    def test_uninstaller_restores_unit_state_if_the_worker_races(self) -> None:
        uninstaller = (OPS / "uninstall-updater.sh").read_text(encoding="utf-8")
        transaction = uninstaller.split("transaction_started=true", 1)[1]
        before_remove = transaction.split("rm -f --", 1)[0]
        rollback = uninstaller.split("finish() {", 1)[1].split("trap finish EXIT", 1)[0]
        self.assertIn("worker_is_quiescent", before_remove)
        self.assertIn("unit_is_stopped monitor-update-worker.path", before_remove)
        self.assertIn("unit_is_disabled monitor-update-gateway.socket", before_remove)
        self.assertIn('restore_target "$backup_dir/worker.py"', rollback)
        self.assertIn('case "$socket_enable_state"', rollback)
        self.assertIn('case "$path_enable_state"', rollback)
        self.assertIn('if [ "$socket_active_state" = active ]', rollback)
        self.assertIn('if [ "$path_active_state" = active ]', rollback)
        self.assertIn('if [ "$gateway_active_state" = active ]', rollback)
        self.assertNotIn("systemctl is-active", uninstaller)

    def test_installer_verifies_every_trigger_is_stopped_before_replacement(self) -> None:
        installer = (OPS / "install-updater.sh").read_text(encoding="utf-8")
        after_stop = installer.rsplit(
            "systemctl stop monitor-update-worker.path monitor-update-gateway.service "
            "monitor-update-gateway.socket",
            1,
        )[1]
        before_replace = after_stop.split('install -d -o root -g root -m 0755', 1)[0]
        self.assertIn("worker_is_quiescent", before_replace)
        self.assertIn("unit_is_stopped monitor-update-worker.path", before_replace)
        self.assertIn("unit_is_stopped monitor-update-gateway.service", before_replace)
        self.assertIn("unit_is_stopped monitor-update-gateway.socket", before_replace)


if __name__ == "__main__":
    unittest.main()
