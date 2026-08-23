from __future__ import annotations

import re
import stat
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NGINX_CONFIG = ROOT / "ops" / "nginx" / "monitor-traffic.conf"
LOGROTATE_CONFIG = ROOT / "ops" / "logrotate" / "monitor-traffic"
PRUNE_SCRIPT = ROOT / "ops" / "prune-traffic-logs.sh"
REOPEN_SCRIPT = ROOT / "ops" / "reopen-traffic-log.sh"
INSTALL_SCRIPT = ROOT / "ops" / "install-traffic-logging.sh"
UNINSTALL_SCRIPT = ROOT / "ops" / "uninstall-traffic-logging.sh"
SYSTEMD_DIR = ROOT / "ops" / "systemd"
ROTATE_SERVICE = SYSTEMD_DIR / "monitor-traffic-logrotate.service"
ROTATE_TIMER = SYSTEMD_DIR / "monitor-traffic-logrotate.timer"
RETENTION_SERVICE = SYSTEMD_DIR / "monitor-traffic-retention.service"
RETENTION_TIMER = SYSTEMD_DIR / "monitor-traffic-retention.timer"


class NginxTrafficConfigTests(unittest.TestCase):
    def test_only_fixed_allowlisted_application_labels_are_emitted(self) -> None:
        content = NGINX_CONFIG.read_text(encoding="utf-8")
        self.assertIn('default "";', content)
        self.assertIn("bonifacio.work  portfolio;", content)
        labels = re.findall(r"~\^portfolio:/[^\s]+\s+([a-z][a-z0-9-]+);", content)
        self.assertEqual(
            labels,
            [
                "monitor",
                "blog",
                "feelmyrythm",
                "multtara",
                "pilgrimage",
                "ddit-finalproject",
                "dukkeobi",
                "react",
                "vue",
            ],
        )
        self.assertIn(r"~^portfolio:/blog(?:/|$)               blog;", content)

    def test_persistent_log_has_no_request_or_user_identifiers(self) -> None:
        content = NGINX_CONFIG.read_text(encoding="utf-8")
        log_format = content.split("log_format monitor_privacy_aggregate", 1)[1].split("access_log", 1)[0]
        self.assertEqual(
            set(re.findall(r"\$[A-Za-z0-9_]+", log_format)),
            {"$time_iso8601", "$monitor_traffic_app", "$status", "$request_time"},
        )
        for sensitive_key in (
            "remote_addr",
            "remote_user",
            "request_uri",
            "http_user_agent",
            "http_referer",
            "cookie",
        ):
            self.assertNotIn(sensitive_key, log_format)

    def test_rotation_is_checked_minutely_with_accurate_logrotate_semantics(self) -> None:
        content = LOGROTATE_CONFIG.read_text(encoding="utf-8")
        service = ROTATE_SERVICE.read_text(encoding="utf-8")
        timer = ROTATE_TIMER.read_text(encoding="utf-8")

        self.assertRegex(content, r"(?m)^\s*daily$")
        self.assertRegex(content, r"(?m)^\s*maxsize 5M$")
        self.assertRegex(content, r"(?m)^\s*rotate 2$")
        self.assertRegex(content, r"(?m)^\s*maxage 2$")
        self.assertRegex(content, r"(?m)^\s*create 0640 www-data adm$")
        self.assertRegex(content, r"(?m)^\s*nocompress$")
        self.assertNotRegex(content, r"(?m)^\s*(?:delay)?compress$")
        mark_reopen = content.index("/usr/local/lib/monitor-traffic/reopen-log.sh mark")
        retry_reopen = content.index("/usr/local/lib/monitor-traffic/reopen-log.sh retry")
        self.assertLess(mark_reopen, retry_reopen)
        self.assertIn(
            "--state /var/lib/monitor-traffic-logrotate/status /etc/monitor-traffic/logrotate.conf",
            service,
        )
        self.assertIn("/run/monitor-traffic-maintenance/maintenance.lock", service)
        self.assertIn("ExecStartPre=/usr/bin/flock", service)
        self.assertIn("/usr/local/lib/monitor-traffic/reopen-log.sh retry", service)
        self.assertRegex(service, r"(?m)^Restart=on-failure$")
        self.assertRegex(service, r"(?m)^RestartSec=2s$")
        self.assertRegex(service, r"(?m)^StartLimitIntervalSec=60s$")
        self.assertRegex(service, r"(?m)^StartLimitBurst=5$")
        self.assertRegex(service, r"(?m)^MemoryMax=64M$")
        self.assertRegex(service, r"(?m)^TasksMax=32$")
        self.assertNotIn("/etc/logrotate.d/monitor-traffic", service)
        self.assertRegex(timer, r"(?m)^OnUnitActiveSec=60s$")
        self.assertRegex(timer, r"(?m)^AccuracySec=5s$")

    def test_reopen_marker_is_durable_strict_and_cleared_only_after_success(self) -> None:
        content = REOPEN_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("marker=\"$state_dir/reopen-required\"", content)
        self.assertIn('mktemp "$state_dir/.reopen-required.XXXXXX"', content)
        self.assertIn('mv -f -- "$temporary" "$marker"', content)
        self.assertGreaterEqual(content.count('fsync_path "$state_dir"'), 2)
        for check in (
            'stat -c %u -- "$state_dir"',
            'stat -c %g -- "$state_dir"',
            'stat -c %a -- "$state_dir"',
            'stat -c %u -- "$marker"',
            'stat -c %g -- "$marker"',
            'stat -c %h -- "$marker"',
            'stat -c %a -- "$marker"',
        ):
            self.assertIn(check, content)
        reopen = content.index("/usr/sbin/invoke-rc.d nginx rotate")
        remove = content.index('rm -f -- "$marker"', reopen)
        directory_sync = content.index('fsync_path "$state_dir"', remove)
        self.assertLess(reopen, remove)
        self.assertLess(remove, directory_sync)
        self.assertNotIn("rm -f -- \"$marker\"", content[:reopen])

    def test_retention_prunes_only_exact_safe_files_after_48_hours(self) -> None:
        script = PRUNE_SCRIPT.read_text(encoding="utf-8")
        service = RETENTION_SERVICE.read_text(encoding="utf-8")
        timer = RETENTION_TIMER.read_text(encoding="utf-8")

        self.assertEqual(script.count("/usr/bin/find -P \"$log_dir\" -xdev -maxdepth 1"), 2)
        self.assertEqual(script.count("-type f -links 1"), 3)
        self.assertEqual(script.count("-mmin +2880 -delete"), 2)
        self.assertIn(r"monitor-traffic\.jsonl\.[0-9]+(\.gz)?", script)
        self.assertIn(r"monitor-traffic\.jsonl'", script)
        self.assertIn("retired_marker=/usr/local/lib/monitor-traffic/logging-disabled", script)
        self.assertIn('if [ -f "$retired_marker" ] &&', script)
        self.assertIn('-P "$retired_marker" -xdev -maxdepth 0 -type f -links 1 -mmin +2880', script)
        self.assertNotIn("nginx_config=", script)
        self.assertNotIn("monitor-traffic.jsonl*", script)
        self.assertIn('stat -c %g -- "$retired_marker"', script)
        self.assertIn('stat -c %a -- "$retired_marker"', script)
        self.assertIn("/bin/sh /usr/local/lib/monitor-traffic/prune-logs.sh", service)
        self.assertIn("ReadWritePaths=-/var/log/nginx", service)
        self.assertIn("/run/monitor-traffic-maintenance/maintenance.lock", service)
        self.assertRegex(service, r"(?m)^MemoryMax=32M$")
        self.assertRegex(service, r"(?m)^TasksMax=8$")
        self.assertRegex(timer, r"(?m)^OnUnitActiveSec=60s$")

    def test_install_is_transactional_and_uses_dedicated_timers(self) -> None:
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("transaction_started=false", content)
        self.assertIn("rollback()", content)
        self.assertIn("logrotate_dir=/etc/monitor-traffic", content)
        self.assertIn('logrotate_target="$logrotate_dir/logrotate.conf"', content)
        self.assertIn('rm -f -- "$legacy_logrotate_target"', content)
        self.assertIn('rm -f -- "$retired_marker"', content)
        self.assertIn('backup_target "$reopen_target" reopen-log.sh', content)
        self.assertIn('install -o root -g root -m 0755 "$reopen_source" "$reopen_target"', content)
        self.assertIn('"reopen-log.sh:$reopen_target"', content)
        self.assertIn("quiesce_traffic_units", content)
        self.assertIn("/usr/bin/flock --exclusive --timeout 30 9", content)
        self.assertIn("rollback was incomplete", content)
        self.assertIn('systemctl is-enabled --quiet "$timer"', content)
        self.assertIn("systemd-analyze verify", content)
        self.assertIn(
            "systemctl enable --now monitor-traffic-logrotate.timer monitor-traffic-retention.timer",
            content,
        )

    def test_uninstall_arms_retention_before_removing_request_logging(self) -> None:
        content = UNINSTALL_SCRIPT.read_text(encoding="utf-8")

        enable_retention = content.index("systemctl enable --now monitor-traffic-retention.timer")
        remove_logging = content.index('rm -f -- "$nginx_target"')
        reload_nginx = content.index("systemctl reload nginx", remove_logging)
        retire_log = content.index('install -o root -g root -m 0600 /dev/null "$retired_marker"')
        retry_reopen = content.index('"$reopen_target" retry')
        self.assertLess(enable_retention, remove_logging)
        self.assertLess(reload_nginx, retire_log)
        self.assertLess(retry_reopen, remove_logging)
        self.assertIn('install -o root -g root -m 0755 "$reopen_source" "$reopen_target"', content)
        self.assertIn('"reopen-log.sh:$reopen_target"', content)
        self.assertIn("quiesce_traffic_units", content)
        self.assertIn("/usr/bin/flock --exclusive --timeout 30 9", content)
        self.assertIn("rollback was incomplete", content)
        self.assertIn("systemctl is-enabled --quiet monitor-traffic-retention.timer", content)
        self.assertIn(
            '"$logrotate_target" "$legacy_logrotate_target" "$reopen_target"',
            content,
        )
        self.assertNotIn(
            'rm -f -- "$retention_service_target" "$retention_timer_target"',
            content,
        )
        self.assertIn("Existing exact-name logs will be pruned after 48 hours", content)

    def test_traffic_maintenance_scripts_are_executable(self) -> None:
        for path in (INSTALL_SCRIPT, UNINSTALL_SCRIPT, PRUNE_SCRIPT, REOPEN_SCRIPT):
            with self.subTest(path=path.name):
                self.assertTrue(path.stat().st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
