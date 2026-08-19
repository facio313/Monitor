import datetime as dt
import json
import os
import stat
import sys
import tempfile
import threading
import time as wall_time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector  # noqa: E402


class ParsingTests(unittest.TestCase):
    def test_proc_parsers_and_rates(self):
        self.assertEqual(collector.parse_proc_stat("cpu  100 2 30 400 5 0 0 0\n"), (537, 405))
        self.assertAlmostEqual(collector.calculate_cpu((600, 440), [500, 400]), 60.0)
        total, available = collector.parse_meminfo(
            "MemTotal:       1000 kB\nMemAvailable:    250 kB\n"
        )
        self.assertEqual((total, available), (1_024_000, 256_000))
        net = collector.parse_net_dev(
            "Inter-| Receive | Transmit\n lo: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n"
            "eth0: 100 0 0 0 0 0 0 0 250 0 0 0 0 0 0 0\n"
        )
        self.assertEqual(net, (100, 250))
        self.assertEqual(collector.rate_pair((300, 650), [100, 250], 2), (100.0, 200.0))

    def test_diskstats_ignores_partitions_and_malformed(self):
        text = (
            "8 0 sda 1 0 10 0 1 0 20 0 0 0 0 0 0 0\n"
            "8 1 sda1 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "7 0 loop0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "broken data\n"
        )
        self.assertEqual(collector.parse_diskstats(text), (5120, 10240))

    def test_mountinfo_and_vcgencmd_parsers(self):
        mounts = collector.parse_mountinfo(
            "36 25 8:1 / / rw - ext4 /dev/sda1 rw\n"
            "37 25 0:4 / /proc rw - proc proc rw\n"
            "38 malformed\n"
        )
        self.assertEqual(mounts, [("/", "/dev/sda1", "ext4")])
        self.assertEqual(collector.parse_vcgencmd("get_throttled", "throttled=0x50005"), ("throttledFlags", 0x50005))
        self.assertEqual(collector.parse_vcgencmd("measure_temp", "temp=48.7'C"), ("temperatureC", 48.7))
        self.assertEqual(collector.parse_vcgencmd("get_mem gpu", "gpu=4M"), ("gpuMemoryBytes", 4 * 1024 ** 2))
        self.assertEqual(collector.parse_vcgencmd("measure_clock core", "frequency(48)=500000000"), ("gpuClockHz", 500_000_000))
        self.assertEqual(
            collector.parse_vcgencmd(
                "pmic_read_adc EXT5V_V",
                "     EXT5V_V volt(24)=4.86956000V\n",
            ),
            ("supplyVoltageVolts", 4.87),
        )
        self.assertEqual(collector.parse_loadavg("1.25 2.50 3.75 1/100 1"), (1.25, 2.5, 3.75))

    def test_vcgencmd_voltage_parser_rejects_malformed_nonfinite_and_out_of_range(self):
        command = "pmic_read_adc EXT5V_V"
        for output in (
            "EXT5V_V volt(24)=nanV",
            "EXT5V_V volt(24)=infV",
            "EXT5V_V volt(24)=-0.1V",
            "EXT5V_V volt(24)=10.0001V",
            "EXT5V_V volt(24)=4.9V trailing-data",
            "HDMI_V volt(23)=4.9V",
            "not vcgencmd output",
        ):
            with self.subTest(output=output):
                self.assertIsNone(collector.parse_vcgencmd(command, output))
        self.assertEqual(
            collector.parse_vcgencmd(command, "EXT5V_V volt(24)=0V"),
            ("supplyVoltageVolts", 0.0),
        )
        self.assertEqual(
            collector.parse_vcgencmd(command, "EXT5V_V volt(24)=10V"),
            ("supplyVoltageVolts", 10.0),
        )
        self.assertIsNone(collector.supply_voltage_volts(float("nan")))
        self.assertIsNone(collector.supply_voltage_volts(True))
        self.assertIsNone(collector.supply_voltage_volts("4.9"))
        self.assertIsNone(collector.parse_vcgencmd("get_throttled", "junk throttled=0x1"))
        self.assertIsNone(collector.parse_vcgencmd("get_throttled", "throttled=0x100000000"))

    def test_collect_gpu_bounds_commands_and_ignores_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "vcgencmd"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            calls = []

            def fake_run(arguments, **kwargs):
                calls.append((arguments, kwargs))
                invocation = tuple(arguments[1:])
                if invocation == ("get_throttled",):
                    return collector.subprocess.CompletedProcess(
                        arguments, 0, stdout="throttled=0x50000\n", stderr=""
                    )
                if invocation == ("pmic_read_adc", "EXT5V_V"):
                    return collector.subprocess.CompletedProcess(
                        arguments, 0, stdout="EXT5V_V volt(24)=4.87654000V\n", stderr=""
                    )
                if invocation == ("measure_temp",):
                    raise collector.subprocess.TimeoutExpired(arguments, kwargs["timeout"])
                return collector.subprocess.CompletedProcess(
                    arguments, 1, stdout="frequency(48)=999999999\n", stderr=""
                )

            with mock.patch.object(collector.subprocess, "run", side_effect=fake_run):
                result = collector.collect_gpu(str(executable), 1.25)
            self.assertEqual(result, {"throttledFlags": 0x50000, "supplyVoltageVolts": 4.877})
            self.assertEqual(len(calls), 6)
            self.assertTrue(all(call[1]["timeout"] == 1.25 for call in calls))
            self.assertTrue(all(call[1]["capture_output"] and call[1]["text"] for call in calls))

            def failed_pmic(arguments, **_kwargs):
                return collector.subprocess.CompletedProcess(
                    arguments, 1, stdout="EXT5V_V volt(24)=4.90000000V\n", stderr=""
                )

            with mock.patch.object(collector.subprocess, "run", side_effect=failed_pmic):
                self.assertEqual(collector.collect_gpu(str(executable), 1.25), {})

    def test_existing_history_rows_migrate_to_exact_finite_contract(self):
        legacy = {field: None for field in collector.LEGACY_SAMPLE_FIELDS}
        legacy.update({
            "timestamp": "2026-08-20T03:00:00.999Z",
            "cpuPercent": float("nan"),
            "powerState": "normal",
        })
        normalized = collector.existing_sample_record(legacy)
        self.assertEqual(tuple(normalized), collector.SAMPLE_FIELDS)
        self.assertEqual(normalized["timestamp"], "2026-08-20T03:00:00Z")
        self.assertIsNone(normalized["cpuPercent"])
        self.assertIsNone(normalized["supplyVoltageVolts"])
        self.assertIsNone(normalized["throttledFlags"])

        current = dict(normalized, supplyVoltageVolts=True, throttledFlags=True)
        current_normalized = collector.existing_sample_record(current)
        self.assertIsNone(current_normalized["supplyVoltageVolts"])
        self.assertIsNone(current_normalized["throttledFlags"])
        self.assertIsNone(collector.existing_sample_record({**legacy, "unexpected": "secret"}))

    def test_docker_reduction_has_exact_safe_fields(self):
        raw = {
            "Id": "a" * 64,
            "Names": ["/web"],
            "State": "running",
            "Status": "Up 2 hours (healthy)",
            "Image": "private/image",
            "Command": "secret --token=x",
            "Mounts": [{"Source": "/secret"}],
        }
        stats = {
            "cpu_stats": {"cpu_usage": {"total_usage": 200}, "system_cpu_usage": 2000, "online_cpus": 2},
            "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
            "memory_stats": {"usage": 25, "limit": 100},
        }
        prior = {"cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2}
        reduced = collector.container_from_api(raw, "cks", stats, prior)
        self.assertEqual(set(reduced), {
            "name", "owner", "state", "health", "cpuPercent", "memoryBytes", "memoryPercent"
        })
        self.assertEqual(reduced["name"], "web")
        self.assertEqual(reduced["health"], "healthy")
        self.assertEqual(reduced["cpuPercent"], 20.0)
        idle_stats = {
            **stats,
            "cpu_stats": {
                "cpu_usage": {"total_usage": 100},
                "system_cpu_usage": 2000,
                "online_cpus": 2,
            },
        }
        self.assertEqual(collector.container_from_api(raw, "cks", idle_stats, prior)["cpuPercent"], 0.0)
        self.assertNotIn("secret", json.dumps(reduced))
        unavailable = collector.container_from_api(raw, "cks", None)
        self.assertIsNone(unavailable["cpuPercent"])
        self.assertIsNone(unavailable["memoryBytes"])
        unnamed = collector.container_from_api({**raw, "Names": []}, "cks", None)
        self.assertEqual(unnamed["name"], "unnamed")
        self.assertNotIn(raw["Id"][:12], json.dumps(unnamed))

    def test_docker_stats_use_six_bounded_workers_and_redact_metadata(self):
        cks_raw = [{
            "Id": f"{value:064x}", "Names": [f"/cks-{value}"], "State": "running",
            "Image": "private/secret-image", "Command": "run --token=secret", "Env": ["TOKEN=secret"],
        } for value in range(12)]
        wgang_raw = [{
            "Id": f"{value + 100:064x}", "Names": [f"/wgang-{value}"], "State": "running",
            "Mounts": [{"Source": "/private/secret"}],
        } for value in range(2)]
        lock = threading.Lock()
        active = peak = stats_calls = 0
        sample = [0]
        stats_paths = []

        def fake_get(socket_path, path, _curl, request_timeout):
            nonlocal active, peak, stats_calls
            self.assertEqual(request_timeout, 2)
            if "containers/json" in path:
                return cks_raw if socket_path == Path("/cks.sock") else wgang_raw
            with lock:
                active += 1
                stats_calls += 1
                peak = max(peak, active)
                stats_paths.append(path)
            wall_time.sleep(0.02)
            with lock:
                active -= 1
            return {
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 200 + sample[0] * 100},
                    "system_cpu_usage": 2000 + sample[0] * 1000,
                    "online_cpus": 2,
                },
                "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
                "memory_stats": {"usage": 25, "limit": 100},
            }

        with mock.patch.object(collector, "docker_get", side_effect=fake_get):
            first, cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "wgang": Path("/wgang.sock")}, "/curl", 2
            )
            sample[0] = 1
            second, next_cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "wgang": Path("/wgang.sock")}, "/curl", 2, cpu_state
            )
        self.assertEqual(len(first), 14)
        self.assertEqual(len(second), 14)
        self.assertEqual(stats_calls, 28)
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 6)
        self.assertTrue(all(item["cpuPercent"] is None for item in first))
        self.assertTrue(all(item["memoryBytes"] == 25 for item in first))
        self.assertTrue(all(item["cpuPercent"] == 20.0 for item in second))
        self.assertEqual(len(cpu_state), 14)
        self.assertEqual(len(next_cpu_state), 14)
        self.assertTrue(all("stream=false&one-shot=true" in path for path in stats_paths))
        serialized = json.dumps([first, second]).lower()
        self.assertNotIn("secret", serialized)
        self.assertNotIn("token", serialized)
        self.assertNotIn("mount", serialized)
        self.assertNotIn(cks_raw[0]["Id"], serialized)

    def test_docker_deadline_keeps_all_lists_and_skips_stats(self):
        raw = [{"Id": f"{value:064x}", "Names": [f"/c{value}"], "State": "running"} for value in range(2)]
        calls = []

        def fake_get(_socket, path, _curl, _timeout):
            calls.append(path)
            return raw if "containers/json" in path else {}

        with mock.patch.object(collector, "_monotonic", side_effect=[0.0, 21.0]), \
             mock.patch.object(collector, "docker_get", side_effect=fake_get):
            result, cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "wgang": Path("/wgang.sock")}, "/curl", 2
            )
        self.assertEqual(len(result), 4)
        self.assertEqual(len([path for path in calls if "containers/json" in path]), 2)
        self.assertEqual(len([path for path in calls if "/stats?" in path]), 0)
        self.assertTrue(all(item["cpuPercent"] is None for item in result))
        self.assertEqual(cpu_state, {})

    def test_docker_cpu_state_is_capped_and_pruned_to_listed_containers(self):
        sockets = {owner: Path(f"/{owner}.sock") for owner in ("cks", "psy", "wgang")}
        raw_by_owner = {
            owner: [{
                "Id": f"{owner_index * 200 + value:064x}",
                "Names": [f"/{owner}-{value}"],
                "State": "running",
            } for value in range(200)]
            for owner_index, owner in enumerate(sockets)
        }
        prior = {
            f"{owner}:{raw['Id']}": {"cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2}
            for owner, records in raw_by_owner.items() for raw in records
        }
        prior["cks:" + "f" * 64] = {"cpuTotal": 1, "systemTotal": 1, "onlineCpus": 1}
        stats_calls = 0

        def fake_get(socket_path, path, _curl, _timeout):
            nonlocal stats_calls
            if "containers/json" in path:
                return raw_by_owner[socket_path.stem]
            stats_calls += 1
            return {
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 200}, "system_cpu_usage": 2000, "online_cpus": 2,
                },
                "memory_stats": {"usage": 1, "limit": 2},
            }

        with mock.patch.object(collector, "docker_get", side_effect=fake_get):
            containers, next_state = collector.collect_containers(sockets, "/curl", 2, prior)
        self.assertEqual(len(containers), 600)
        self.assertEqual(stats_calls, 30)
        self.assertEqual(len(next_state), 600)
        self.assertNotIn("cks:" + "f" * 64, next_state)

        with mock.patch.object(collector, "docker_get", return_value=[]):
            empty, pruned_state = collector.collect_containers(sockets, "/curl", 2, next_state)
        self.assertEqual(empty, [])
        self.assertEqual(pruned_state, {})


class RedactionTests(unittest.TestCase):
    def test_alerts_are_semantic_and_unknown_lines_are_dropped(self):
        snapshot = collector.sanitize_alert_line(
            "2026-08-19T01:02:03Z === SNAPSHOT reason=power-throttle === command=do-not-copy", "fallback"
        )
        metrics = collector.sanitize_alert_line(
            "2026-08-19T01:02:04Z metrics cpu=91.2% cpu_streak=1 "
            "memory_available=73% (6000000KiB/8127688KiB) temperature=82.5C raw=secret",
            "fallback",
        )
        recovered = collector.sanitize_alert_line(
            "2026-08-19T01:02:05Z RECOVERED reason=power-throttle arbitrary secret", "fallback"
        )
        contract = {"timestamp", "severity", "kind", "status", "message"}
        self.assertEqual(set(snapshot), contract)
        self.assertEqual(set(metrics), contract)
        self.assertEqual(set(recovered), contract)
        self.assertEqual(snapshot["status"], "active")
        self.assertEqual(metrics["severity"], "warning")
        self.assertEqual(metrics["message"], "CPU 91.2%; memory available 73%; temperature 82.5 C.")
        self.assertNotIn("bytes", metrics["message"])
        self.assertEqual(collector.existing_alert_record(metrics)["message"], metrics["message"])
        legacy_metrics = dict(metrics, message="CPU 2__ memory available 73 bytes_ temperature 63.9 C.")
        self.assertEqual(
            collector.existing_alert_record(legacy_metrics)["message"],
            "CPU 2%; memory available 73%; temperature 63.9 C.",
        )
        self.assertEqual(recovered["status"], "recovered")
        self.assertIsNone(collector.sanitize_alert_line("totally unrelated token=secret", "fallback"))
        self.assertNotIn("secret", json.dumps([snapshot, metrics, recovered]))

    def test_privilege_output_has_exact_fields_timestamp_and_no_command(self):
        line = (
            "Aug 19 10:10:10 host sudo: cks : TTY=pts/0 ; PWD=/home/cks ; "
            "USER=root ; COMMAND=/bin/cat /root/top-secret"
        )
        record = collector.sanitize_privilege_line(line, "2026-08-19T02:00:00Z")
        self.assertEqual(set(record), {"timestamp", "actor", "target", "action", "result"})
        self.assertEqual(record["actor"], "cks")
        self.assertEqual(record["target"], "root")
        self.assertEqual(record["action"], "sudo")
        self.assertEqual(record["result"], "success")
        self.assertTrue(record["timestamp"].endswith("Z"))
        self.assertNotIn("COMMAND", json.dumps(record))
        denied = collector.sanitize_privilege_line(
            "2026-08-19T01:20:00+09:00 host su: FAILED SU (to root) cks on pts/0",
            "2026-08-19T02:00:00Z",
        )
        self.assertEqual(denied["timestamp"], "2026-08-18T16:20:00Z")
        self.assertEqual(denied["result"], "failure")

    def test_structured_privilege_line_is_reduced_to_contract(self):
        line = json.dumps({
            "timestamp": "2026-08-19T01:02:03Z", "actor": "cks", "target": "root",
            "action": "sudo command", "result": "allowed", "command": "cat /root/secret",
        })
        record = collector.sanitize_privilege_line(line, "fallback")
        self.assertEqual(record, {
            "timestamp": "2026-08-19T01:02:03Z", "actor": "cks", "target": "root",
            "action": "sudo", "result": "success",
        })

    def test_kernel_power_lines_are_exact_semantic_records(self):
        fallback = "2026-08-20T04:00:00Z"
        cases = (
            (
                "2026-08-20T03:54:17+00:00 host kernel: hwmon: Undervoltage detected! raw=secret",
                {
                    "timestamp": "2026-08-20T03:54:17Z", "severity": "warning",
                    "kind": "under-voltage", "status": "active",
                    "message": "Kernel reported an under-voltage condition.",
                },
            ),
            (
                "2026-08-20T03:54:19+00:00 host kernel: hwmon: Voltage normalised raw=secret",
                {
                    "timestamp": "2026-08-20T03:54:19Z", "severity": "info",
                    "kind": "under-voltage", "status": "recovered",
                    "message": "Kernel reported voltage recovery.",
                },
            ),
            (
                "2026-08-20T03:54:30Z host kernel: nvme nvme0: controller is down; will reset: raw=secret",
                {
                    "timestamp": "2026-08-20T03:54:30Z", "severity": "critical",
                    "kind": "nvme-reset", "status": "active",
                    "message": "Kernel reported an NVMe controller reset.",
                },
            ),
            (
                "2026-08-20T03:55:00Z host kernel: blk_update_request: I/O error, dev nvme0n1, raw=secret",
                {
                    "timestamp": "2026-08-20T03:55:00Z", "severity": "critical",
                    "kind": "nvme-io", "status": "active",
                    "message": "Kernel reported an NVMe I/O error.",
                },
            ),
        )
        for line, expected in cases:
            with self.subTest(kind=expected["kind"], status=expected["status"]):
                record = collector.sanitize_kernel_power_line(line, fallback)
                self.assertEqual(record, expected)
                self.assertNotIn("secret", json.dumps(record))
                self.assertEqual(collector.existing_power_record(record), expected)

        self.assertIsNone(collector.sanitize_kernel_power_line(
            "2026-08-20T03:56:00Z unrelated password=secret", fallback
        ))
        valid = cases[0][1]
        self.assertIsNone(collector.existing_power_record({**valid, "raw": "secret"}))
        self.assertIsNone(collector.existing_power_record({**valid, "message": "raw secret"}))
        self.assertIsNone(collector.existing_power_record({**valid, "severity": "critical"}))


class FilesystemTests(unittest.TestCase):
    def test_atomic_write_leaves_complete_file_and_no_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "current.json"
            collector.atomic_write_json(path, {"ok": True})
            self.assertEqual(json.loads(path.read_text()), {"ok": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o750)
            self.assertEqual(list(path.parent.glob(".current.json.*")), [])

    def test_retention_removes_only_expired_dated_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("2026-07-20.jsonl", "2026-07-21.jsonl", "2026-08-19.jsonl", "notes.txt"):
                (root / name).write_text("x")
            collector.prune_history(root, dt.date(2026, 8, 19), 30)
            self.assertFalse((root / "2026-07-20.jsonl").exists())
            self.assertTrue((root / "2026-07-21.jsonl").exists())
            self.assertTrue((root / "2026-08-19.jsonl").exists())
            self.assertTrue((root / "notes.txt").exists())

    def test_malformed_inputs_produce_valid_schema_and_cursors_prevent_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            etc = root / "etc"
            output = root / "output"
            runtime = root / "run"
            mount_root = root / "fixture-root"
            for directory in (proc / "net", proc / "self", sys_root, etc, mount_root):
                directory.mkdir(parents=True, exist_ok=True)
            (proc / "stat").write_text("bad cpu values\n")
            (proc / "meminfo").write_text("MemTotal: nope\n")
            (proc / "net" / "dev").write_text("malformed\n")
            (proc / "diskstats").write_text("malformed\n")
            (proc / "loadavg").write_text("not-a-number\n")
            (proc / "uptime").write_text("also-bad\n")
            (proc / "self" / "mountinfo").write_text("36 25 8:1 / / rw - ext4 /dev/test rw\n")
            (etc / "os-release").write_text('PRETTY_NAME="Fixture OS"\n')
            events = root / "events.log"
            auth = root / "auth.log"
            events.write_text("2026-08-19T00:00:00Z SNAPSHOT reason=cpu-high secret=drop\nmalformed\n")
            auth.write_text("Aug 19 host sudo: cks : USER=root ; COMMAND=/bin/secret --password=x\n")
            history_dir = output / "history"
            history_dir.mkdir(parents=True)
            legacy_sample = {field: None for field in collector.LEGACY_SAMPLE_FIELDS}
            legacy_sample.update({
                "timestamp": "2026-08-19T00:00:00Z",
                "powerState": "normal",
            })
            (history_dir / "2026-08-19.jsonl").write_text(json.dumps(legacy_sample) + "\n")
            container_id = "b" * 64
            docker_sample = [0]

            def fake_docker(_socket, path, _curl, _timeout):
                if "containers/json" in path:
                    return [{
                        "Id": container_id, "Names": ["/fixture"], "State": "running",
                        "Image": "private/secret", "Command": "run --token=secret",
                    }]
                return {
                    "cpu_stats": {
                        "cpu_usage": {"total_usage": 100 + docker_sample[0] * 100},
                        "system_cpu_usage": 1000 + docker_sample[0] * 1000,
                        "online_cpus": 2,
                    },
                    "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
                    "memory_stats": {"usage": 40, "limit": 100},
                }

            config = collector.Config(
                output_dir=output, runtime_dir=runtime, proc_root=proc, sys_root=sys_root,
                etc_root=etc, mount_root=mount_root, events_log=events,
                kernel_log=root / "missing-kern.log", privilege_logs=[auth],
                docker_sockets={"cks": Path("/fake.sock")},
                vcgencmd="", max_log_records=10,
            )
            now = dt.datetime(2026, 8, 19, 0, 1, tzinfo=dt.timezone.utc)
            gpu = {
                "throttledFlags": 0x50000,
                "supplyVoltageVolts": 4.86956,
                "gpuMemoryBytes": 4 * 1024 ** 2,
                "gpuClockHz": 500_000_000,
            }
            with mock.patch.object(collector, "collect_gpu", return_value=gpu), \
                 mock.patch.object(collector, "docker_get", side_effect=fake_docker):
                current = collector.run(config, now)
                first_delta_state = json.loads((runtime / "delta-state.json").read_text())
                docker_sample[0] = 1
                second = collector.run(config, now + dt.timedelta(minutes=1))

            self.assertEqual(set(current), {"generatedAt", "host", "latest", "disks", "containers"})
            self.assertEqual(set(current["host"]), {"hostname", "os", "architecture", "uptimeSeconds"})
            self.assertEqual(tuple(current["latest"]), collector.SAMPLE_FIELDS)
            self.assertEqual(current["latest"]["powerState"], "degraded-history")
            self.assertEqual(current["latest"]["supplyVoltageVolts"], 4.87)
            self.assertEqual(current["latest"]["throttledFlags"], 0x50000)
            self.assertEqual(current["latest"]["gpuMemoryBytes"], 4 * 1024 ** 2)
            self.assertEqual(current["latest"]["gpuClockHz"], 500_000_000)
            self.assertEqual(set(current["disks"][0]), {"mount", "totalBytes", "usedBytes", "usedPercent"})
            self.assertIsNone(current["containers"][0]["cpuPercent"])
            self.assertEqual(current["containers"][0]["memoryBytes"], 40)
            self.assertEqual(second["containers"][0]["cpuPercent"], 20.0)
            self.assertIn(f"cks:{container_id}", first_delta_state["containers"])
            self.assertEqual(stat.S_IMODE((runtime / "delta-state.json").stat().st_mode), 0o600)
            self.assertNotIn(container_id, (output / "current.json").read_text())
            self.assertNotIn("secret", (output / "current.json").read_text())
            self.assertEqual(len((output / "alerts.jsonl").read_text().splitlines()), 1)
            alert = json.loads((output / "alerts.jsonl").read_text().splitlines()[0])
            self.assertEqual(set(alert), {"timestamp", "severity", "kind", "status", "message"})
            privilege_lines = (output / "privilege.jsonl").read_text().splitlines()
            self.assertEqual(len(privilege_lines), 1)
            privilege = json.loads(privilege_lines[0])
            self.assertEqual(set(privilege), {"timestamp", "actor", "target", "action", "result"})
            self.assertNotIn("secret", json.dumps(privilege))
            history = [
                json.loads(line)
                for line in (output / "history" / "2026-08-19.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(history), 3)
            self.assertTrue(all(tuple(sample) == collector.SAMPLE_FIELDS for sample in history))
            self.assertEqual([sample["supplyVoltageVolts"] for sample in history], [None, 4.87, 4.87])
            self.assertEqual([sample["throttledFlags"] for sample in history], [None, 0x50000, 0x50000])
            self.assertTrue((runtime / "delta-state.json").is_file())

    def test_bounded_exports_keep_newest_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "alerts.jsonl"
            collector.rewrite_json_lines(path, [{"n": value} for value in range(30)], 10)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["n"] for record in records], list(range(20, 30)))

    def test_power_alert_is_emitted_only_on_transitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                events_log=root / "missing-events", kernel_log=root / "missing-kern.log",
                privilege_logs=[], docker_sockets={},
            )
            collector.export_sanitized_logs(config, "2026-08-19T00:00:00Z", {
                "throttledFlags": 0x50005, "supplyVoltageVolts": 4.8119,
            })
            collector.export_sanitized_logs(config, "2026-08-19T00:01:00Z", {
                "throttledFlags": 0x50005, "supplyVoltageVolts": 4.1,
            })
            collector.export_sanitized_logs(config, "2026-08-19T00:02:00Z", {
                "throttledFlags": 0x50000, "supplyVoltageVolts": 4.9238,
            })
            collector.export_sanitized_logs(config, "2026-08-19T00:03:00Z", {
                "throttledFlags": 0x50000, "supplyVoltageVolts": 1.0,
            })
            records = [json.loads(line) for line in (config.output_dir / "alerts.jsonl").read_text().splitlines()]
            self.assertEqual([record["status"] for record in records], ["active", "recovered"])
            self.assertTrue(all(set(record) == {"timestamp", "severity", "kind", "status", "message"} for record in records))
            self.assertEqual(
                records[0]["message"],
                "Current vcgencmd throttle flags are 0x5. Full flags are 0x00050005. "
                "Supply voltage is 4.812 V.",
            )
            self.assertEqual(
                records[1]["message"],
                "Current vcgencmd throttle condition recovered. Full flags are 0x00050000. "
                "Supply voltage is 4.924 V.",
            )

    def test_kernel_power_tail_rotation_deduplication_and_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel_log = root / "kern.log"
            old_event = (
                "2026-08-20T03:00:00Z host kernel: hwmon: Undervoltage detected!\n"
            )
            filler = "".join(f"filler-{index:03d} " + "x" * 70 + "\n" for index in range(100))
            recent_event = (
                "2026-08-20T03:54:30Z host kernel: nvme nvme0: controller is down; will reset\n"
            )
            kernel_log.write_text(old_event + filler + recent_event)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                events_log=root / "missing-events", kernel_log=kernel_log,
                kernel_max_input_bytes=512, privilege_logs=[], docker_sockets={},
                max_log_records=10,
            )

            collector.export_sanitized_logs(config, "2026-08-20T04:00:00Z")
            power_path = config.output_dir / "power.jsonl"
            records = [json.loads(line) for line in power_path.read_text().splitlines()]
            self.assertEqual([(record["kind"], record["status"]) for record in records], [
                ("nvme-reset", "active"),
            ])
            self.assertEqual(stat.S_IMODE(power_path.stat().st_mode), 0o640)

            with kernel_log.open("a") as handle:
                handle.write(
                    "2026-08-20T03:54:31.100Z host kernel: Undervoltage detected! first detail\n"
                    "2026-08-20T03:54:31.900Z host kernel: Undervoltage detected! duplicate detail\n"
                    "2026-08-20T03:54:31.950Z host kernel: Voltage normalised detail\n"
                )
            collector.export_sanitized_logs(config, "2026-08-20T04:01:00Z")
            records = [json.loads(line) for line in power_path.read_text().splitlines()]
            self.assertEqual([(record["kind"], record["status"]) for record in records], [
                ("nvme-reset", "active"),
                ("under-voltage", "active"),
                ("under-voltage", "recovered"),
            ])

            rotated = root / "kern.log.1"
            kernel_log.rename(rotated)
            kernel_log.write_text(
                "2026-08-20T03:54:31.999Z host kernel: Voltage normalised duplicate after rotation\n"
                "2026-08-20T03:54:33.100Z host kernel: nvme0n1: I/O Error secret=drop\n"
                "2026-08-20T03:54:33.900Z host kernel: I/O error, dev nvme0n1 duplicate\n"
                "2026-08-20T03:54:34Z host kernel: I/O Error, dev sda ignored\n"
            )
            collector.export_sanitized_logs(config, "2026-08-20T04:02:00Z")
            records = [json.loads(line) for line in power_path.read_text().splitlines()]
            self.assertEqual([(record["kind"], record["status"]) for record in records], [
                ("nvme-reset", "active"),
                ("under-voltage", "active"),
                ("under-voltage", "recovered"),
                ("nvme-io", "active"),
            ])
            cursor_state = json.loads((config.output_dir / ".state" / "log-cursors.json").read_text())
            self.assertEqual(cursor_state["kernelPower"]["inode"], kernel_log.stat().st_ino)
            self.assertTrue(all(set(record) == {
                "timestamp", "severity", "kind", "status", "message",
            } for record in records))
            self.assertNotIn("secret", power_path.read_text())

            config.kernel_max_input_bytes = 4096
            with kernel_log.open("a") as handle:
                for second in range(10, 22):
                    handle.write(
                        f"2026-08-20T03:55:{second:02d}Z host kernel: "
                        "nvme nvme0: controller is down; will reset\n"
                    )
            collector.export_sanitized_logs(config, "2026-08-20T04:03:00Z")
            records = [json.loads(line) for line in power_path.read_text().splitlines()]
            self.assertEqual(len(records), 10)
            self.assertTrue(all(record["kind"] == "nvme-reset" for record in records))
            self.assertEqual(records[0]["timestamp"], "2026-08-20T03:55:12Z")
            self.assertEqual(records[-1]["timestamp"], "2026-08-20T03:55:21Z")

    def test_default_paths_timeout_and_systemd_access_contract(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            config = collector.config_from_environment([])
        self.assertEqual(config.privilege_logs, [Path("/var/log/privilege-events.log")])
        self.assertEqual(config.kernel_log, Path("/var/log/kern.log"))
        self.assertEqual(config.kernel_max_input_bytes, 8_388_608)
        self.assertEqual(config.command_timeout, 2.0)
        ops_root = Path(__file__).resolve().parents[1]
        unit = (ops_root / "systemd" / "monitor-collector.service").read_text()
        defaults = (ops_root / "monitor-collector.default").read_text()
        installer = (ops_root / "install.sh").read_text()
        self.assertIn("Group=cks", unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)
        self.assertIn("BindPaths=-/dev/vcio", unit)
        self.assertIn("DeviceAllow=/dev/vcio rw", unit)
        self.assertIn("ReadOnlyPaths=/proc /sys /var/log /run/user", unit)
        self.assertIn("MemoryHigh=160M", unit)
        self.assertIn("MemoryMax=192M", unit)
        self.assertIn("TasksMax=64", unit)
        self.assertIn("MONITOR_KERNEL_LOG=/var/log/kern.log", defaults)
        self.assertIn("MONITOR_KERNEL_MAX_INPUT_BYTES=8388608", defaults)
        self.assertIn("-o root -g cks -m 0750 /var/lib/monitor-export", installer)

    def test_power_state_is_normal_only_without_active_or_historical_flags(self):
        def fixture(flags):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                proc = root / "proc"
                for directory in (proc / "net", proc / "self", root / "sys", root / "etc", root / "mount"):
                    directory.mkdir(parents=True, exist_ok=True)
                (proc / "stat").write_text("cpu 1 0 1 10 0 0 0 0\n")
                (proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 50 kB\n")
                (proc / "net" / "dev").write_text("")
                (proc / "diskstats").write_text("")
                (proc / "loadavg").write_text("0 0 0 1/1 1\n")
                (proc / "uptime").write_text("1 1\n")
                (proc / "self" / "mountinfo").write_text("")
                config = collector.Config(
                    output_dir=root / "out", runtime_dir=root / "run", proc_root=proc,
                    sys_root=root / "sys", etc_root=root / "etc", mount_root=root / "mount",
                    events_log=root / "events", kernel_log=root / "kern.log",
                    privilege_logs=[], docker_sockets={}, vcgencmd="",
                )
                with mock.patch.object(collector, "collect_gpu", return_value={"throttledFlags": flags}):
                    return collector.run(config)["latest"]

        normal = fixture(0)
        self.assertEqual(normal["powerState"], "normal")
        self.assertEqual(normal["throttledFlags"], 0)
        self.assertIsNone(normal["supplyVoltageVolts"])
        self.assertEqual(fixture(0x50000)["powerState"], "degraded-history")
        self.assertEqual(fixture(0x50005)["powerState"], "throttled")
        unavailable = fixture(None)
        self.assertIsNone(unavailable["powerState"])
        self.assertIsNone(unavailable["throttledFlags"])


if __name__ == "__main__":
    unittest.main()
