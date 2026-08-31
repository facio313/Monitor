import datetime as dt
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time as wall_time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector  # noqa: E402


def docker_list_project(path: str) -> str | None:
    if not path.startswith("/v1.41/containers/json?"):
        return None
    query = parse_qs(urlsplit(path).query, strict_parsing=True)
    if query.get("all") != ["1"] or len(query.get("filters", [])) != 1:
        return None
    filters = json.loads(query["filters"][0])
    labels = filters.get("label") if isinstance(filters, dict) else None
    if not isinstance(labels, list) or len(labels) != 1:
        return None
    prefix = "com.docker.compose.project="
    return (
        labels[0][len(prefix):]
        if isinstance(labels[0], str) and labels[0].startswith(prefix)
        else None
    )


def incident_metrics(timestamp="2026-08-23T00:00:00Z", **changes):
    sample = {field: None for field in collector.SAMPLE_FIELDS}
    sample.update({
        "timestamp": timestamp,
        "cpuPercent": 10.0,
        "memoryPercent": 50.0,
        "memoryUsedBytes": 50,
        "memoryTotalBytes": 100,
        "temperatureC": 50.0,
        "load1": 0.5,
        "load5": 0.5,
        "load15": 0.5,
        "powerState": "normal",
        "supplyVoltageVolts": 5.0,
        "throttledFlags": 0,
        "gpuMemoryBytes": 0,
        "gpuClockHz": 500_000_000,
        "networkRxBytesPerSecond": 0.0,
        "networkTxBytesPerSecond": 0.0,
        "diskReadBytesPerSecond": 0.0,
        "diskWriteBytesPerSecond": 0.0,
    })
    sample.update(changes)
    return sample


def empty_pressure():
    return {
        kind: {"someAvg10": None, "fullAvg10": None}
        for kind in ("cpu", "memory", "io")
    }


class ParsingTests(unittest.TestCase):
    def test_proc_parsers_and_rates(self):
        proc_stat = (
            "cpu  100 2 30 400 5 0 0 0\n"
            "cpu0 50 1 15 200 2 0 0 0\n"
            "cpu1 50 1 15 200 3 0 0 0\n"
        )
        self.assertEqual(collector.parse_proc_stat(proc_stat), (537, 405))
        self.assertEqual(collector.parse_logical_cpu_count(proc_stat), 2)
        self.assertIsNone(collector.parse_logical_cpu_count("cpu 1 2 3 4\n"))
        self.assertAlmostEqual(collector.calculate_cpu((600, 440), [500, 400]), 60.0)
        self.assertIsNone(collector.calculate_cpu((600, 440), None))
        self.assertIsNone(collector.calculate_cpu(None, [500, 400]))
        total, available = collector.parse_meminfo(
            "MemTotal:       1000 kB\nMemAvailable:    250 kB\n"
        )
        self.assertEqual((total, available), (1_024_000, 256_000))
        self.assertEqual(collector.parse_meminfo("MemTotal: 1000 kB\n"), (1_024_000, None))
        self.assertEqual(collector.parse_meminfo("malformed\n"), (None, None))
        self.assertEqual(
            collector.parse_swapinfo("SwapTotal: 1000 kB\nSwapFree: 250 kB\n"),
            (1_024_000, 768_000, 75.0),
        )
        self.assertEqual(
            collector.parse_swapinfo("SwapTotal: 0 kB\nSwapFree: 0 kB\n"),
            (0, 0, 0.0),
        )
        self.assertEqual(
            collector.parse_swapinfo("SwapTotal: 1000 kB\n"),
            (1_024_000, None, None),
        )
        self.assertEqual(collector.parse_swapinfo("malformed\n"), (None, None, None))
        net = collector.parse_net_dev(
            "Inter-| Receive | Transmit\n lo: 9 0 9 9 0 0 0 0 9 0 9 9 0 0 0 0\n"
            "eth0: 100 0 3 4 0 0 0 0 250 0 5 6 0 0 0 0\n"
            "wlan0: 50 0 1 2 0 0 0 0 75 0 2 3 0 0 0 0\n"
        )
        self.assertEqual(net, (150, 325, 4, 7, 6, 9))
        self.assertEqual(collector.rate_pair((300, 650), [100, 250], 2), (100.0, 200.0))
        self.assertEqual(collector.rate_pair((300, 650), None, 2), (None, None))
        self.assertIsNone(collector.parse_net_dev("malformed\n"))
        self.assertIsNone(collector.parse_net_dev(
            "lo: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n"
        ))
        self.assertEqual(
            collector.network_rate_values(
                (300, 650, 7, 11, 13, 17), [100, 250, 3, 5, 4, 6], 2,
            ),
            (100.0, 200.0, 2.0, 3.0, 4.5, 5.5),
        )
        self.assertEqual(
            collector.network_rate_values(
                (300, 650, 7, 11, 13, 17), [100, 250], 2,
            ),
            (100.0, 200.0, None, None, None, None),
        )
        self.assertEqual(
            collector.network_rate_values(
                (90, 650, 7, 11, 13, 17), [100, 250, 3, 5, 4, 6], 2,
            ),
            (None, 200.0, 2.0, 3.0, 4.5, 5.5),
        )

    def test_diskstats_ignores_partitions_and_malformed(self):
        text = (
            "8 0 sda 1 0 10 0 1 0 20 0 0 0 0 0 0 0\n"
            "8 1 sda1 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "179 0 mmcblk0 1 0 30 0 1 0 40 0 0 0 0 0 0 0\n"
            "179 1 mmcblk0p1 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "179 8 mmcblk0boot0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "259 0 nvme0n1 1 0 50 0 1 0 60 0 0 0 0 0 0 0\n"
            "259 1 nvme0n1p1 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "7 0 loop0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "253 0 dm-0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "252 0 zram0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "1 0 ram0 1 0 999 0 1 0 999 0 0 0 0 0 0 0\n"
            "broken data\n"
        )
        self.assertEqual(collector.parse_diskstats(text), (46_080, 61_440))
        self.assertIsNone(collector.parse_diskstats("broken data\n"))

    def test_mountinfo_and_vcgencmd_parsers(self):
        mounts = collector.parse_mountinfo(
            "36 25 8:1 / / rw - ext4 /dev/sda1 rw\n"
            "37 25 8:2 / /archive ro - ext4 /dev/sda2 ro\n"
            "37 25 0:4 / /proc rw - proc proc rw\n"
            "38 malformed\n"
        )
        self.assertEqual(mounts, [
            ("/", "/dev/sda1", "ext4", False),
            ("/archive", "/dev/sda2", "ext4", True),
        ])
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
        self.assertEqual(collector.parse_loadavg("not-a-number"), (None, None, None))

    def test_filesystem_export_adds_available_inode_and_read_only_signals(self):
        mountinfo = (
            "36 25 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
            "37 25 8:2 / /archive ro,relatime - ext4 /dev/sda2 ro\n"
        )
        usage = mock.Mock(total=1_000, used=600, free=300)
        inode_stats = mock.Mock(f_files=100, f_ffree=25)
        with mock.patch.object(collector.shutil, "disk_usage", return_value=usage), \
             mock.patch.object(collector.os, "statvfs", return_value=inode_stats):
            disks = collector.collect_filesystems(mountinfo, Path("/fixture"))
        self.assertEqual(disks, [
            {
                "mount": "/",
                "totalBytes": 1_000,
                "usedBytes": 600,
                "availableBytes": 300,
                "usedPercent": 60.0,
                "inodeUsedPercent": 75.0,
                "readOnly": False,
            },
            {
                "mount": "/archive",
                "totalBytes": 1_000,
                "usedBytes": 600,
                "availableBytes": 300,
                "usedPercent": 60.0,
                "inodeUsedPercent": 75.0,
                "readOnly": True,
            },
        ])

        with mock.patch.object(collector.shutil, "disk_usage", return_value=usage), \
             mock.patch.object(collector.os, "statvfs", side_effect=OSError):
            [disk] = collector.collect_filesystems(mountinfo.splitlines()[0], Path("/fixture"))
        self.assertIsNone(disk["inodeUsedPercent"])

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

    def test_rpi_undervoltage_alarm_discovers_named_hwmon_sensor(self):
        with tempfile.TemporaryDirectory() as temporary:
            sys_root = Path(temporary)
            unrelated = sys_root / "class" / "hwmon" / "hwmon0"
            sensor = sys_root / "class" / "hwmon" / "hwmon7"
            unrelated.mkdir(parents=True)
            sensor.mkdir(parents=True)
            (unrelated / "name").write_text("nvme\n")
            (unrelated / "in0_lcrit_alarm").write_text("1\n")
            (sensor / "name").write_text("rpi_volt\n")
            (sensor / "in0_lcrit_alarm").write_text("0\n")
            self.assertEqual(collector.read_rpi_undervoltage_alarm(sys_root), 0)
            (sensor / "in0_lcrit_alarm").write_text("1\n")
            self.assertEqual(collector.read_rpi_undervoltage_alarm(sys_root), 1)
            (sensor / "in0_lcrit_alarm").write_text("invalid\n")
            self.assertIsNone(collector.read_rpi_undervoltage_alarm(sys_root))

    def test_collect_gpu_bounds_commands_and_ignores_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "vcgencmd"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            sys_root = Path(temporary) / "sys"
            sensor = sys_root / "class" / "hwmon" / "hwmon4"
            sensor.mkdir(parents=True)
            (sensor / "name").write_text("rpi_volt\n")
            (sensor / "in0_lcrit_alarm").write_text("1\n")
            calls = []

            def fake_run(arguments, **kwargs):
                calls.append((arguments, kwargs))
                invocation = tuple(arguments[1:])
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
                result = collector.collect_gpu(str(executable), 1.25, sys_root)
            self.assertEqual(result, {"supplyVoltageVolts": 4.877, "throttledFlags": 1})
            self.assertEqual(len(calls), 5)
            self.assertNotIn(("get_throttled",), [tuple(call[0][1:]) for call in calls])
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
        for field_name in (
            "swapTotalBytes", "swapUsedBytes", "swapPercent",
            "cpuPressureSomeAvg10", "cpuPressureFullAvg10",
            "memoryPressureSomeAvg10", "memoryPressureFullAvg10",
            "ioPressureSomeAvg10", "ioPressureFullAvg10",
            "networkRxErrorsPerSecond", "networkTxErrorsPerSecond",
            "networkRxDroppedPerSecond", "networkTxDroppedPerSecond",
        ):
            self.assertIsNone(normalized[field_name], field_name)

        power = {field: None for field in collector.POWER_SAMPLE_FIELDS}
        power.update({"timestamp": "2026-08-20T03:00:30Z", "powerState": "normal"})
        power_normalized = collector.existing_sample_record(power)
        self.assertEqual(tuple(power_normalized), collector.SAMPLE_FIELDS)
        self.assertIsNone(power_normalized["swapTotalBytes"])
        self.assertIsNone(power_normalized["networkRxErrorsPerSecond"])

        previous = {field: None for field in collector.PREVIOUS_SAMPLE_FIELDS}
        previous.update({"timestamp": "2026-08-20T03:01:00Z", "powerState": "normal"})
        previous_normalized = collector.existing_sample_record(previous)
        self.assertEqual(tuple(previous_normalized), collector.SAMPLE_FIELDS)
        self.assertIsNone(previous_normalized["swapTotalBytes"])
        self.assertIsNone(previous_normalized["ioPressureFullAvg10"])
        self.assertIsNone(previous_normalized["networkTxDroppedPerSecond"])

        current = dict(normalized, supplyVoltageVolts=True, throttledFlags=True)
        current_normalized = collector.existing_sample_record(current)
        self.assertIsNone(current_normalized["supplyVoltageVolts"])
        self.assertIsNone(current_normalized["throttledFlags"])
        invalid_signals = dict(
            normalized,
            swapTotalBytes=100,
            swapUsedBytes=101,
            swapPercent=101,
            cpuPressureSomeAvg10=-1,
            ioPressureFullAvg10=float("inf"),
            networkRxErrorsPerSecond=-1,
            networkTxDroppedPerSecond=1_000_000_000_001,
        )
        invalid_normalized = collector.existing_sample_record(invalid_signals)
        self.assertEqual(invalid_normalized["swapTotalBytes"], 100)
        self.assertIsNone(invalid_normalized["swapUsedBytes"])
        self.assertIsNone(invalid_normalized["swapPercent"])
        self.assertIsNone(invalid_normalized["cpuPressureSomeAvg10"])
        self.assertIsNone(invalid_normalized["ioPressureFullAvg10"])
        self.assertIsNone(invalid_normalized["networkRxErrorsPerSecond"])
        self.assertIsNone(invalid_normalized["networkTxDroppedPerSecond"])
        self.assertIsNone(collector.existing_sample_record({**legacy, "unexpected": "secret"}))

    def test_docker_reduction_has_exact_safe_fields(self):
        raw = {
            "Id": "a" * 64,
            "Names": ["/web"],
            "Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            },
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
        inspect = {
            "Id": raw["Id"],
            "Name": "/private-name",
            "Image": "sha256:secret-image-digest",
            "RestartCount": 5,
            "State": {
                "Status": "running",
                "OOMKilled": True,
                "StartedAt": "2026-08-23T01:02:03.123456789Z",
                "FinishedAt": "0001-01-01T00:00:00Z",
                "Health": {"Status": "unhealthy", "Log": [{"Output": "token=secret"}]},
            },
            "Config": {
                "Healthcheck": {"Test": ["CMD-SHELL", "curl -H 'token: secret' localhost"]},
                "Env": ["TOKEN=secret"],
            },
            "HostConfig": {
                "Memory": 0,
                "NanoCpus": 1_500_000_000,
                "CpuQuota": 0,
                "CpuPeriod": 0,
                "PidsLimit": None,
                "Binds": ["/private/secret:/data"],
            },
            "Mounts": [{"Source": "/private/secret"}],
        }
        prior = {
            "cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2,
            "restartCount": 2,
        }
        reduced = collector.container_from_api(raw, "cks", stats, prior, inspect=inspect)
        self.assertEqual(tuple(reduced), collector.CONTAINER_FIELDS)
        self.assertEqual(reduced["name"], "monitor")
        self.assertEqual(reduced["project"], "monitor")
        self.assertEqual(reduced["health"], "unhealthy")
        self.assertTrue(reduced["healthcheckConfigured"])
        self.assertEqual(reduced["cpuPercent"], 20.0)
        self.assertEqual(reduced["memoryPercent"], 25.0)
        self.assertEqual(reduced["restartCount"], 5)
        self.assertEqual(reduced["restartCountDelta"], 3)
        self.assertTrue(reduced["oomKilled"])
        self.assertEqual(reduced["startedAt"], "2026-08-23T01:02:03.123456Z")
        self.assertIsNone(reduced["finishedAt"])
        self.assertEqual(reduced["memoryLimitBytes"], 0)
        self.assertEqual(reduced["cpuLimitCores"], 1.5)
        self.assertEqual(reduced["pidLimit"], 0)
        future_inspect = {
            **inspect,
            "State": {
                **inspect["State"],
                "StartedAt": "2099-01-01T00:00:00Z",
                "FinishedAt": "2099-01-01T00:01:00Z",
            },
        }
        future_reduced = collector.container_from_api(
            raw, "cks", None, prior, inspect=future_inspect
        )
        self.assertIsNone(future_reduced["startedAt"])
        self.assertIsNone(future_reduced["finishedAt"])
        multi_core_stats = {
            **stats,
            "cpu_stats": {
                "cpu_usage": {"total_usage": 900},
                "system_cpu_usage": 2000,
                "online_cpus": 2,
            },
        }
        self.assertEqual(
            collector.container_from_api(
                raw, "cks", multi_core_stats, prior, inspect=inspect
            )["cpuPercent"],
            160.0,
        )
        self.assertEqual(
            collector.docker_cpu_percent(
                {"cpuTotal": 100_000, "systemTotal": 2000, "onlineCpus": 64}, prior
            ),
            collector.MAX_CONTAINER_CPU_PERCENT,
        )
        idle_stats = {
            **stats,
            "cpu_stats": {
                "cpu_usage": {"total_usage": 100},
                "system_cpu_usage": 2000,
                "online_cpus": 2,
            },
        }
        self.assertEqual(
            collector.container_from_api(raw, "cks", idle_stats, prior, inspect=inspect)["cpuPercent"],
            0.0,
        )
        self.assertNotIn("secret", json.dumps(reduced))
        unavailable = collector.container_from_api(raw, "cks", None)
        self.assertIsNone(unavailable["cpuPercent"])
        self.assertIsNone(unavailable["memoryBytes"])
        self.assertIsNone(unavailable["health"])
        self.assertIsNone(unavailable["healthcheckConfigured"])
        self.assertIsNone(unavailable["restartCount"])
        self.assertIsNone(unavailable["memoryLimitBytes"])
        self.assertEqual(unavailable["project"], "monitor")

        unlimited = collector.container_from_api(raw, "cks", None, inspect={
            "RestartCount": 0,
            "State": {
                "OOMKilled": False,
                "StartedAt": "2026-08-23T01:02:03Z",
                "FinishedAt": "2026-08-23T01:03:03Z",
            },
            "Config": {},
            "HostConfig": {
                "Memory": 0, "NanoCpus": 0, "CpuQuota": 0,
                "CpuPeriod": 100_000, "PidsLimit": -1,
            },
        })
        self.assertEqual(unlimited["health"], "none")
        self.assertFalse(unlimited["healthcheckConfigured"])
        self.assertFalse(unlimited["oomKilled"])
        self.assertEqual(unlimited["memoryLimitBytes"], 0)
        self.assertEqual(unlimited["cpuLimitCores"], 0.0)
        self.assertEqual(unlimited["pidLimit"], 0)
        self.assertEqual(unlimited["restartCount"], 0)
        self.assertIsNone(unlimited["restartCountDelta"])

        decreased = collector.container_from_api(raw, "cks", None, {"restartCount": 2}, inspect={
            "RestartCount": 1,
            "State": {
                "StartedAt": "2026-08-23T02:00:00Z",
                "FinishedAt": "2026-08-23T01:00:00Z",
            },
            "Config": {},
            "HostConfig": {},
        })
        self.assertEqual(decreased["restartCount"], 1)
        self.assertIsNone(decreased["restartCountDelta"])
        self.assertEqual(decreased["startedAt"], "2026-08-23T02:00:00Z")
        self.assertEqual(decreased["finishedAt"], "2026-08-23T01:00:00Z")
        with self.assertRaisesRegex(ValueError, "outside the Compose service allowlist"):
            collector.container_from_api({**raw, "Names": [], "Labels": {}}, "cks", None)

    def test_docker_response_and_detail_request_budgets_are_fixed(self):
        container_id = "a" * 64
        self.assertEqual(
            collector.docker_response_byte_limit(f"/v1.41/containers/{container_id}/json"),
            collector.MAX_DOCKER_DETAIL_RESPONSE_BYTES,
        )
        self.assertEqual(
            collector.docker_response_byte_limit(
                f"/v1.41/containers/{container_id}/stats?stream=false&one-shot=true"
            ),
            collector.MAX_DOCKER_DETAIL_RESPONSE_BYTES,
        )
        self.assertEqual(
            collector.docker_response_byte_limit(
                collector.compose_project_list_path("monitor")
            ),
            collector.MAX_DOCKER_LIST_RESPONSE_BYTES,
        )
        self.assertEqual(collector.MAX_DOCKER_INSPECT_REQUESTS, 30)
        self.assertEqual(collector.MAX_DOCKER_STATS_REQUESTS, 30)
        self.assertEqual(collector.MAX_DOCKER_DETAIL_WORKERS, 6)

    def test_inspect_identity_health_and_limit_contracts_fail_closed(self):
        container_id = "a" * 64
        base = {
            "Id": container_id,
            "Config": {"Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            }},
            "State": {},
            "HostConfig": {},
        }
        self.assertIs(collector.validated_container_inspect(base, container_id, "monitor"), base)
        self.assertIsNone(collector.validated_container_inspect(
            {**base, "Id": "b" * 64}, container_id, "monitor"
        ))
        self.assertIsNone(collector.validated_container_inspect({
            **base,
            "Config": {"Labels": {
                "com.docker.compose.project": "private-project",
                "com.docker.compose.service": "monitor",
            }},
        }, container_id, "monitor"))

        health_cases = (
            (None, (None, None)),
            ({"Config": {}}, ("none", False)),
            ({"Config": {"Healthcheck": {"Test": ["NONE"]}}}, ("none", False)),
            ({"Config": {"Healthcheck": {"Test": ["CMD", "true"]}}}, (None, True)),
            ({
                "Config": {"Healthcheck": {"Test": ["CMD-SHELL", "true"]}},
                "State": {"Health": {"Status": "healthy"}},
            }, ("healthy", True)),
            ({
                "Config": {},
                "State": {"Health": {"Status": "healthy"}},
            }, ("none", False)),
            ({
                "Config": {"Healthcheck": {"Test": ["NONE"]}},
                "State": {"Health": {"Status": "healthy"}},
            }, ("none", False)),
            ({
                "Config": {"Healthcheck": {"Test": ["BOGUS"]}},
                "State": {"Health": {"Status": "healthy"}},
            }, (None, None)),
            ({"Config": {"Healthcheck": {"Test": ["BOGUS", "secret"]}}}, (None, None)),
        )
        for inspect, expected in health_cases:
            with self.subTest(expected=expected):
                self.assertEqual(collector.docker_health_details(inspect), expected)

        for malformed_test in (
            ["CMD", {"secret": True}],
            ["CMD", "x" * 4097],
            ["CMD", *("x" for _ in range(32))],
            ["NONE", "unexpected"],
        ):
            reduced = collector.reduce_container_inspect({
                "Config": {"Healthcheck": {"Test": malformed_test}},
                "State": {"Health": {"Status": "healthy"}},
            })
            with self.subTest(malformed_test=malformed_test[:1]):
                self.assertEqual(collector.docker_health_details(reduced), (None, None))

        for raw_healthcheck in ({}, {"Test": []}, {"Test": ["NONE"]}):
            reduced = collector.reduce_container_inspect({
                "Config": {"Healthcheck": raw_healthcheck},
                "State": {"Health": {"Status": "healthy"}},
            })
            with self.subTest(raw_healthcheck=raw_healthcheck):
                self.assertEqual(collector.docker_health_details(reduced), ("none", False))

        self.assertEqual(
            collector.docker_resource_limits({"HostConfig": {
                "Memory": 0, "NanoCpus": 0, "CpuQuota": 50_000,
                "CpuPeriod": 100_000, "PidsLimit": None,
            }}),
            (0, 0.5, 0),
        )
        self.assertEqual(
            collector.docker_resource_limits({"HostConfig": {
                "Memory": True, "NanoCpus": 0, "CpuQuota": 50_000,
                "CpuPeriod": 0, "PidsLimit": "64",
            }}),
            (None, None, None),
        )
        self.assertEqual(
            collector.docker_resource_limits({"HostConfig": {
                "Memory": 0, "NanoCpus": 500_000_000,
                "CpuQuota": "malformed", "CpuPeriod": "malformed",
                "PidsLimit": -1,
            }}),
            (0, 0.5, 0),
        )

    def test_mismatched_inspect_is_redacted_and_does_not_rebase_restart_state(self):
        container_id = "a" * 64
        raw = {
            "Id": container_id,
            "Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            },
            "State": "running",
            "Status": "Up (healthy)",
        }
        prior = {f"cks:{container_id}": {
            "cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2,
            "restartCount": 9,
        }}

        def fake_get(_socket, path, _curl, _timeout):
            project = docker_list_project(path)
            if project is not None:
                return [raw] if project == "monitor" else []
            if path.endswith("/json"):
                return {
                    "Id": "b" * 64,
                    "RestartCount": 99,
                    "State": {"OOMKilled": True, "Health": {"Status": "unhealthy"}},
                    "Config": {
                        "Labels": raw["Labels"],
                        "Env": ["TOKEN=secret"],
                    },
                    "HostConfig": {"Memory": 123},
                }
            return {
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 200},
                    "system_cpu_usage": 2000,
                    "online_cpus": 2,
                },
                "memory_stats": {"usage": 25, "limit": 100},
            }

        with mock.patch.object(collector, "docker_get", side_effect=fake_get):
            containers, next_state = collector.collect_containers(
                {"cks": Path("/cks.sock")}, "/curl", 2, prior
            )
        self.assertEqual(len(containers), 1)
        self.assertIsNone(containers[0]["health"])
        self.assertIsNone(containers[0]["restartCount"])
        self.assertIsNone(containers[0]["oomKilled"])
        self.assertIsNone(containers[0]["memoryLimitBytes"])
        self.assertEqual(next_state[f"cks:{container_id}"]["restartCount"], 9)
        self.assertNotIn("secret", json.dumps([containers, next_state]))

    def test_docker_transport_rejects_oversize_and_invalid_utf8(self):
        container_id = "a" * 64
        request_path = f"/v1.41/containers/{container_id}/json"
        with tempfile.TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "docker.sock"
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.bind(str(socket_path))
            try:
                completed = mock.Mock(returncode=0, stdout=b"{}", stderr=b"")
                with mock.patch.object(collector.subprocess, "run", return_value=completed) as run:
                    self.assertEqual(
                        collector.docker_get(socket_path, request_path, "/curl", 2), {}
                    )
                arguments = run.call_args.args[0]
                self.assertIn("--max-filesize", arguments)
                self.assertIn(str(collector.MAX_DOCKER_DETAIL_RESPONSE_BYTES), arguments)

                completed.stdout = b"x" * (collector.MAX_DOCKER_DETAIL_RESPONSE_BYTES + 1)
                with mock.patch.object(collector.subprocess, "run", return_value=completed):
                    self.assertIsNone(
                        collector.docker_get(socket_path, request_path, "/curl", 2)
                    )
                completed.stdout = b"\xff"
                with mock.patch.object(collector.subprocess, "run", return_value=completed):
                    self.assertIsNone(
                        collector.docker_get(socket_path, request_path, "/curl", 2)
                    )
            finally:
                connection.close()

    def test_compose_pairs_have_distinct_fixed_names_and_filtered_list_paths(self):
        expected_pairs = {
            ("bonifacio", "bonifacio"): "bonifacio",
            ("bonifacio", "bonifacioSso"): "sso",
            ("bonifacio", "bonifacioSsoRedis"): "sso-redis",
            ("blog", "blogWeb"): "blog-frontend",
            ("blog", "blogServer"): "blog-backend",
            ("cks-database", "cksDB"): "cks-database",
            ("monitor", "monitor"): "monitor",
            ("feelmyrythm", "fmrWeb"): "feelmyrythm-frontend",
            ("feelmyrythm", "fmrServer"): "feelmyrythm-backend",
            ("feelmyrythm", "fmrRedis"): "feelmyrythm-redis",
            ("pilgrimage", "pilgrimageFrontend"): "pilgrimage-frontend",
            ("pilgrimage", "pilgrimageBackend"): "pilgrimage-backend",
            ("pilgrimage", "pilgrimageRedis"): "pilgrimage-redis",
            ("ddit-finalproject", "dditFinalProject"): "ddit-finalproject",
            ("dukkeobi", "dukkeobi"): "dukkeobi",
            ("react", "react"): "react",
            ("vue", "vue"): "vue",
            ("pongdang-multtara", "backend"): "multtara-backend",
            ("pongdang-multtara", "collector"): "multtara-collector",
            ("pongdang-multtara", "frontend"): "multtara-frontend",
        }
        self.assertEqual(collector.ALLOWED_COMPOSE_SERVICES, expected_pairs)
        self.assertNotIn(("pilgrimage", "pilgrimageDB"), collector.ALLOWED_COMPOSE_SERVICES)
        self.assertEqual(
            len(set(collector.ALLOWED_COMPOSE_SERVICES.values())),
            len(collector.ALLOWED_COMPOSE_SERVICES),
        )
        self.assertTrue(
            collector.LEGACY_CONTAINER_SERVICE_NAMES.isdisjoint(
                collector.CURRENT_CONTAINER_NAMES
            )
        )
        self.assertTrue(
            collector.LEGACY_CONTAINER_SERVICE_NAMES <= collector.SAFE_CONTAINER_NAMES
        )
        self.assertIn("multtara-database", collector.LEGACY_CONTAINER_SERVICE_NAMES)
        self.assertNotIn(
            ("pongdang-multtara", "db"), collector.ALLOWED_COMPOSE_SERVICES
        )
        paths = []
        inspect_paths = []
        stats_paths = []
        ids_by_pair = {
            pair: f"{index + 1:064x}"
            for index, pair in enumerate(collector.ALLOWED_COMPOSE_SERVICES)
        }

        def fake_get(_socket, path, _curl, _timeout):
            project = docker_list_project(path)
            if project is None:
                if path.endswith("/json"):
                    inspect_paths.append(path)
                else:
                    stats_paths.append(path)
                return {}
            self.assertIn(project, collector.ALLOWED_COMPOSE_PROJECTS)
            paths.append(path)
            records = []
            for pair, container_id in ids_by_pair.items():
                if pair[0] != project:
                    continue
                records.append({
                    "Id": container_id,
                    "Labels": {
                        "com.docker.compose.project": pair[0],
                        "com.docker.compose.service": pair[1],
                    },
                    "State": "exited",
                })
            if project == "monitor":
                records.extend([
                    {
                        "Id": "e" * 64,
                        "Labels": {
                            "com.docker.compose.project": "monitor",
                            "com.docker.compose.service": "unreviewed",
                        },
                        "State": "running",
                    },
                    {
                        "Id": "f" * 64,
                        "Labels": {
                            "com.docker.compose.project": "different-project",
                            "com.docker.compose.service": "monitor",
                        },
                        "State": "running",
                    },
                ])
            if project == "pongdang-multtara":
                records.append({
                    "Id": "d" * 64,
                    "Labels": {
                        "com.docker.compose.project": "pongdang-multtara",
                        "com.docker.compose.service": "db",
                    },
                    "State": "running",
                })
            return records

        with mock.patch.object(collector, "docker_get", side_effect=fake_get):
            containers, cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock")}, "/curl", 2
            )

        self.assertEqual(len(paths), len(collector.ALLOWED_COMPOSE_PROJECTS))
        encoded_filter = "filters=%7B%22label%22%3A%5B%22com.docker.compose.project%3D"
        self.assertTrue(all(encoded_filter in path for path in paths))
        self.assertNotIn("/v1.41/containers/json?all=1", paths)
        self.assertEqual(
            {docker_list_project(path) for path in paths},
            set(collector.ALLOWED_COMPOSE_PROJECTS),
        )
        self.assertEqual(
            {item["name"] for item in containers},
            set(collector.ALLOWED_COMPOSE_SERVICES.values()),
        )
        self.assertEqual(len(containers), len(collector.ALLOWED_COMPOSE_SERVICES))
        self.assertNotIn("cks-workload", {item["name"] for item in containers})
        self.assertEqual(cpu_state, {})
        self.assertEqual(len(inspect_paths), len(collector.ALLOWED_COMPOSE_SERVICES))
        self.assertTrue(all(path.endswith("/json") for path in inspect_paths))
        self.assertEqual(stats_paths, [])
        self.assertTrue(all(item["state"] == "exited" for item in containers))
        self.assertEqual(
            {item["project"] for item in containers},
            set(collector.ALLOWED_COMPOSE_PROJECTS),
        )

    def test_reduced_container_input_requires_fresh_cks_owned_fixed_schema(self):
        now = dt.datetime(2026, 8, 23, 3, 0, tzinfo=dt.timezone.utc)
        document = {
            "generatedAt": collector.iso_timestamp(now),
            "containerCollection": {
                "status": "fresh", "observedAt": collector.iso_timestamp(now),
            },
            "containers": [{
                "name": "monitor", "owner": "cks", "state": "running", "health": "healthy",
                "cpuPercent": 250.0, "memoryBytes": 123, "memoryPercent": 1.5,
            }],
        }
        normalized_container = {
            "name": "monitor", "project": None, "owner": "cks",
            "state": "running", "health": None, "healthcheckConfigured": None,
            "cpuPercent": 250.0, "memoryBytes": 123, "memoryPercent": 1.5,
            "memoryLimitBytes": None, "cpuLimitCores": None, "pidLimit": None,
            "restartCount": None, "restartCountDelta": None, "oomKilled": None,
            "startedAt": None, "finishedAt": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "containers.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            path.chmod(0o640)
            original_lstat = Path.lstat
            original_fstat = os.fstat

            def owned_by_cks(candidate):
                result = original_lstat(candidate)
                if candidate == path:
                    fields = list(result)
                    fields[4] = 1001
                    fields[5] = 1001
                    return os.stat_result(fields)
                return result

            def opened_by_cks(descriptor):
                result = original_fstat(descriptor)
                fields = list(result)
                fields[4] = 1001
                fields[5] = 1001
                return os.stat_result(fields)

            with mock.patch.object(Path, "lstat", owned_by_cks), \
                 mock.patch.object(collector.os, "fstat", opened_by_cks):
                self.assertEqual(collector.load_container_snapshot(path, now), [normalized_container])
                containers, collection = collector.load_container_snapshot_state(path, now)
                self.assertEqual(containers, [normalized_container])
                self.assertEqual(collection, document["containerCollection"])
                migrated_v2 = {
                    **document,
                    "containers": [normalized_container],
                }
                path.write_text(json.dumps(migrated_v2), encoding="utf-8")
                self.assertEqual(
                    collector.load_container_snapshot(path, now),
                    [normalized_container],
                )
                legacy_schema = {
                    "generatedAt": collector.iso_timestamp(now),
                    "containers": document["containers"],
                }
                path.write_text(json.dumps(legacy_schema), encoding="utf-8")
                self.assertEqual(
                    collector.load_container_snapshot_state(path, now)[1],
                    {"status": "fresh", "observedAt": collector.iso_timestamp(now)},
                )
                stale_observed = now - dt.timedelta(minutes=4)
                stale_legacy = {
                    "generatedAt": collector.iso_timestamp(stale_observed),
                    "containers": document["containers"],
                }
                path.write_text(json.dumps(stale_legacy), encoding="utf-8")
                self.assertEqual(
                    collector.load_container_snapshot_state(path, now)[1],
                    {"status": "last-known", "observedAt": collector.iso_timestamp(stale_observed)},
                )
                for legacy_name in sorted(collector.LEGACY_CONTAINER_NAMES):
                    legacy_document = {
                        **document,
                        "containers": [{
                            **document["containers"][0],
                            "name": legacy_name,
                        }],
                    }
                    path.write_text(json.dumps(legacy_document), encoding="utf-8")
                    loaded = collector.load_container_snapshot(path, now)
                    self.assertEqual(tuple(loaded[0]), collector.CONTAINER_V2_FIELDS)
                    self.assertEqual(loaded[0]["name"], legacy_name)
                    self.assertEqual(
                        loaded[0]["project"],
                        None,
                    )
                    self.assertIsNone(loaded[0]["health"])
                    self.assertIsNone(loaded[0]["restartCount"])
                path.write_text(json.dumps({
                    **document,
                    "containers": [{**document["containers"][0], "name": "alice@example.test"}],
                }), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "outside the allowlist"):
                    collector.load_container_snapshot(path, now)

                for invalid_row in (
                    {**normalized_container, "project": "private-project"},
                    {**normalized_container, "restartCount": True},
                    {**normalized_container, "restartCount": 2, "restartCountDelta": 3},
                    {**normalized_container, "oomKilled": "true"},
                    {**normalized_container, "memoryLimitBytes": -1},
                    {**normalized_container, "cpuLimitCores": float("inf")},
                    {**normalized_container, "pidLimit": "100"},
                    {**normalized_container, "startedAt": "not-a-date"},
                ):
                    path.write_text(json.dumps({
                        **document, "containers": [invalid_row],
                    }), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        collector.load_container_snapshot(path, now)

            path.chmod(0o660)
            with mock.patch.object(Path, "lstat", owned_by_cks), \
                 mock.patch.object(collector.os, "fstat", opened_by_cks):
                with self.assertRaisesRegex(ValueError, "file validation"):
                    collector.load_container_snapshot(path, now)

    def test_synthetic_probe_input_is_exact_bounded_and_drops_private_url_data(self):
        now = dt.datetime(2026, 8, 31, 6, 0, tzinfo=dt.timezone.utc)
        checked_at = collector.iso_timestamp(now - dt.timedelta(seconds=1))
        document = {
            "schemaVersion": 1,
            "generatedAt": collector.iso_timestamp(now),
            "results": [{
                "schemaVersion": 1,
                "id": "public-ready",
                "status": "ok",
                "checkedAt": checked_at,
                "url": "https://public.example/readyz?token=must-not-leak",
                "httpStatus": 200,
                "redirectCount": 1,
                "latencyMilliseconds": 17,
                "certificateExpiresAt": "2027-08-31T06:00:00Z",
                "certificateDaysRemaining": 365,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "results.json"
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            path.chmod(0o640)
            collection, rows = collector.load_synthetic_probe_document(
                path,
                now,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            self.assertEqual(collection, {
                "status": "fresh", "observedAt": collector.iso_timestamp(now),
            })
            self.assertEqual(rows, [{
                "id": "public-ready",
                "status": "ok",
                "checkedAt": checked_at,
                "httpStatus": 200,
                "redirectCount": 1,
                "latencyMilliseconds": 17,
                "certificateExpiresAt": "2027-08-31T06:00:00Z",
                "certificateDaysRemaining": 365,
            }])
            serialized = json.dumps(rows)
            self.assertNotIn("public.example", serialized)
            self.assertNotIn("token", serialized)

            stale_at = now - dt.timedelta(seconds=collector.MAX_SYNTHETIC_INPUT_AGE_SECONDS + 1)
            document["generatedAt"] = collector.iso_timestamp(stale_at)
            document["results"][0]["checkedAt"] = collector.iso_timestamp(stale_at)
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            stale, _rows = collector.load_synthetic_probe_document(
                path,
                now,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            self.assertEqual(stale, {
                "status": "stale", "observedAt": collector.iso_timestamp(stale_at),
            })

    def test_synthetic_probe_input_fails_closed_with_explicit_collection_statuses(self):
        now = dt.datetime(2026, 8, 31, 6, 0, tzinfo=dt.timezone.utc)
        missing = Path("/definitely/not/present/synthetic-results.json")
        self.assertEqual(collector.collect_synthetic_probes(missing, now), (
            {"status": "unsupported", "observedAt": None}, [],
        ))
        self.assertEqual(collector.collect_synthetic_probes(None, now), (
            {"status": "unsupported", "observedAt": None}, [],
        ))
        with mock.patch.object(
            collector, "load_synthetic_probe_document", side_effect=PermissionError,
        ):
            self.assertEqual(collector.collect_synthetic_probes(missing, now), (
                {"status": "permission-denied", "observedAt": None}, [],
            ))

        valid_row = (
            '{"schemaVersion":1,"id":"duplicate","status":"ok",'
            '"checkedAt":"2026-08-31T06:00:00Z",'
            '"url":"https://public.example/readyz","httpStatus":200,'
            '"redirectCount":0,"latencyMilliseconds":1,'
            '"certificateExpiresAt":null,"certificateDaysRemaining":null}'
        )
        invalid_documents = (
            # Duplicate root member must not be silently accepted by json.loads.
            '{"schemaVersion":1,"schemaVersion":1,'
            '"generatedAt":"2026-08-31T06:00:00Z","results":[' + valid_row + ']}',
            # Duplicate probe identifiers are ambiguous and therefore rejected.
            '{"schemaVersion":1,"generatedAt":"2026-08-31T06:00:00Z",'
            '"results":[' + valid_row + ',' + valid_row + ']}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "results.json"
            for raw in invalid_documents:
                path.write_text(raw, encoding="utf-8")
                path.chmod(0o640)
                with self.assertRaises(ValueError):
                    collector.load_synthetic_probe_document(
                        path,
                        now,
                        expected_uid=os.geteuid(),
                        expected_gid=os.getegid(),
                    )
            path.write_text(invalid_documents[-1], encoding="utf-8")
            path.chmod(0o660)
            with self.assertRaisesRegex(ValueError, "file validation"):
                collector.load_synthetic_probe_document(
                    path,
                    now,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_docker_stats_use_six_bounded_workers_and_redact_metadata(self):
        cks_raw = [{
            "Id": f"{value:064x}", "Names": [f"/cks-{value}"], "State": "running",
            "Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            },
            "Image": "private/secret-image", "Command": "run --token=secret", "Env": ["TOKEN=secret"],
        } for value in range(12)]
        secondary_raw = [{
            "Id": f"{value + 100:064x}", "Names": [f"/secondary-{value}"], "State": "running",
            "Mounts": [{"Source": "/private/secret"}],
        } for value in range(2)]
        lock = threading.Lock()
        active = peak = stats_calls = inspect_calls = 0
        sample = [0]
        stats_paths = []
        inspect_paths = []

        def fake_get(socket_path, path, _curl, request_timeout):
            nonlocal active, peak, stats_calls, inspect_calls
            self.assertEqual(request_timeout, 2)
            if "containers/json" in path:
                return cks_raw if socket_path == Path("/cks.sock") else secondary_raw
            with lock:
                active += 1
                peak = max(peak, active)
            wall_time.sleep(0.02)
            with lock:
                active -= 1
            if path.endswith("/json"):
                with lock:
                    inspect_calls += 1
                    inspect_paths.append(path)
                container_id = path.split("/")[3]
                return {
                    "Id": container_id,
                    "RestartCount": 5 + sample[0] * 2,
                    "State": {
                        "OOMKilled": False,
                        "StartedAt": "2026-08-23T01:00:00Z",
                        "FinishedAt": "0001-01-01T00:00:00Z",
                        "Health": {"Status": "healthy", "Log": [{"Output": "secret"}]},
                    },
                    "Config": {
                        "Healthcheck": {"Test": ["CMD", "secret-health-command"]},
                        "Env": ["TOKEN=secret"],
                        "Labels": {
                            "com.docker.compose.project": "monitor",
                            "com.docker.compose.service": "monitor",
                            "private.secret": "token",
                        },
                    },
                    "HostConfig": {
                        "Memory": 100, "NanoCpus": 500_000_000,
                        "CpuQuota": 0, "CpuPeriod": 0, "PidsLimit": 64,
                        "Binds": ["/private/secret:/data"],
                    },
                    "Mounts": [{"Source": "/private/secret"}],
                }
            with lock:
                stats_calls += 1
                stats_paths.append(path)
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
                {"cks": Path("/cks.sock"), "secondary": Path("/secondary.sock")}, "/curl", 2
            )
            sample[0] = 1
            second, next_cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "secondary": Path("/secondary.sock")}, "/curl", 2, cpu_state
            )
        self.assertEqual(len(first), 12)
        self.assertEqual(len(second), 12)
        self.assertEqual(stats_calls, 24)
        self.assertEqual(inspect_calls, 24)
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 6)
        self.assertTrue(all(item["cpuPercent"] is None for item in first))
        self.assertTrue(all(item["memoryBytes"] == 25 for item in first))
        self.assertTrue(all(item["cpuPercent"] == 20.0 for item in second))
        self.assertTrue(all(item["restartCount"] == 5 for item in first))
        self.assertTrue(all(item["restartCountDelta"] is None for item in first))
        self.assertTrue(all(item["restartCount"] == 7 for item in second))
        self.assertTrue(all(item["restartCountDelta"] == 2 for item in second))
        self.assertTrue(all(item["health"] == "healthy" for item in second))
        self.assertTrue(all(item["healthcheckConfigured"] is True for item in second))
        self.assertTrue(all(item["memoryLimitBytes"] == 100 for item in second))
        self.assertTrue(all(item["cpuLimitCores"] == 0.5 for item in second))
        self.assertTrue(all(item["pidLimit"] == 64 for item in second))
        self.assertEqual(len(cpu_state), 12)
        self.assertEqual(len(next_cpu_state), 12)
        self.assertTrue(all(value["restartCount"] == 7 for value in next_cpu_state.values()))
        self.assertTrue(all(item["owner"] == "cks" for item in first))
        self.assertTrue(all("stream=false&one-shot=true" in path for path in stats_paths))
        self.assertTrue(all(path.endswith("/json") for path in inspect_paths))
        serialized = json.dumps([first, second]).lower()
        self.assertNotIn("secret", serialized)
        self.assertNotIn("token", serialized)
        self.assertNotIn("/private/secret", serialized)
        self.assertNotIn('"binds"', serialized)
        self.assertNotIn(cks_raw[0]["Id"], serialized)

    def test_docker_deadline_keeps_all_lists_and_skips_stats(self):
        raw = [{
            "Id": f"{value:064x}", "Names": [f"/c{value}"], "State": "running",
            "Labels": {
                "com.docker.compose.project": "monitor",
                "com.docker.compose.service": "monitor",
            },
        } for value in range(2)]
        calls = []

        def fake_get(_socket, path, _curl, _timeout):
            calls.append(path)
            return raw if "containers/json" in path else {}

        with mock.patch.object(collector, "_monotonic", side_effect=[0.0, 0.0, 21.0]), \
             mock.patch.object(collector, "docker_get", side_effect=fake_get):
            result, cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "secondary": Path("/secondary.sock")}, "/curl", 2
            )
        self.assertEqual(len(result), 2)
        self.assertEqual(
            len([path for path in calls if "containers/json" in path]),
            len(collector.ALLOWED_COMPOSE_PROJECTS),
        )
        self.assertEqual(len([path for path in calls if "/stats?" in path]), 0)
        self.assertTrue(all(item["cpuPercent"] is None for item in result))
        self.assertEqual(cpu_state, {})

    def test_docker_list_queries_respect_global_deadline(self):
        calls = 0
        lock = threading.Lock()

        def slow_get(_socket, _path, _curl, _timeout):
            nonlocal calls
            with lock:
                calls += 1
            wall_time.sleep(0.03)
            return []

        started = wall_time.monotonic()
        with mock.patch.object(collector, "MAX_DOCKER_COLLECTION_SECONDS", 0.05), \
             mock.patch.object(collector, "docker_get", side_effect=slow_get):
            with self.assertRaisesRegex(collector.ContainerSourceUnavailable, "deadline"):
                collector.collect_containers({"cks": Path("/cks.sock")}, "/curl", 2)
        elapsed = wall_time.monotonic() - started

        self.assertLess(elapsed, 0.25)
        self.assertLessEqual(calls, len(collector.ALLOWED_COMPOSE_PROJECTS))

    def test_docker_cpu_state_is_capped_and_pruned_to_listed_containers(self):
        sockets = {owner: Path(f"/{owner}.sock") for owner in ("cks", "secondary", "tertiary")}
        raw_by_owner = {
            owner: [{
                "Id": f"{owner_index * 200 + value:064x}",
                "Names": [f"/{owner}-{value}"],
                "State": "running",
                "Labels": {
                    "com.docker.compose.project": "monitor",
                    "com.docker.compose.service": "monitor",
                },
            } for value in range(200)]
            for owner_index, owner in enumerate(sockets)
        }
        prior = {
            f"{owner}:{raw['Id']}": {"cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2}
            for owner, records in raw_by_owner.items() for raw in records
        }
        prior["cks:" + "f" * 64] = {"cpuTotal": 1, "systemTotal": 1, "onlineCpus": 1}
        stats_calls = 0
        inspect_calls = 0

        def fake_get(socket_path, path, _curl, _timeout):
            nonlocal stats_calls, inspect_calls
            if "containers/json" in path:
                return raw_by_owner[socket_path.stem]
            if path.endswith("/json"):
                inspect_calls += 1
                container_id = path.split("/")[3]
                return {
                    "Id": container_id,
                    "RestartCount": 1,
                    "State": {"OOMKilled": False},
                    "Config": {"Labels": {
                        "com.docker.compose.project": "monitor",
                        "com.docker.compose.service": "monitor",
                    }},
                    "HostConfig": {
                        "Memory": 0, "NanoCpus": 0, "CpuQuota": 0,
                        "CpuPeriod": 100_000, "PidsLimit": 0,
                    },
                }
            stats_calls += 1
            return {
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 200}, "system_cpu_usage": 2000, "online_cpus": 2,
                },
                "memory_stats": {"usage": 1, "limit": 2},
            }

        with mock.patch.object(collector, "docker_get", side_effect=fake_get):
            containers, next_state = collector.collect_containers(sockets, "/curl", 2, prior)
        self.assertEqual(len(containers), 200)
        self.assertEqual(stats_calls, 30)
        self.assertEqual(inspect_calls, 30)
        self.assertEqual(len(next_state), 200)
        self.assertEqual(
            sum("restartCount" in value for value in next_state.values()),
            collector.MAX_DOCKER_INSPECT_REQUESTS,
        )
        self.assertEqual(
            sum(item["restartCount"] is None for item in containers),
            200 - collector.MAX_DOCKER_INSPECT_REQUESTS,
        )
        self.assertNotIn("cks:" + "f" * 64, next_state)

        with mock.patch.object(collector, "docker_get", return_value=[]):
            empty, pruned_state = collector.collect_containers(sockets, "/curl", 2, next_state)
        self.assertEqual(empty, [])
        self.assertEqual(pruned_state, {})

    def test_system_inventory_uses_fixed_bounded_filesystem_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            etc = root / "etc"
            packages = root / "packages"
            controller = sys_root / "class" / "nvme" / "nvme0"
            device = controller / "device"
            bootloader = (
                sys_root / "firmware" / "devicetree" / "base" / "chosen" / "bootloader"
            )
            for directory in (
                proc,
                sys_root / "module" / "nvme_core" / "parameters",
                sys_root / "module" / "pcie_aspm" / "parameters",
                device / "of_node",
                bootloader,
                etc / "default",
                packages / "lib" / "modules" / "6.8.0-1061-raspi",
                packages / "lib" / "modules" / "6.8.0-1062-raspi",
                packages / "lib" / "firmware" / "raspberrypi" / "bootloader-2712" / "default",
            ):
                directory.mkdir(parents=True, exist_ok=True)

            (proc / "cmdline").write_text(
                "root=LABEL=writable nvme_core.default_ps_max_latency_us=0 "
                "pcie_aspm=off pcie_port_pm=off\n"
            )
            (sys_root / "module" / "nvme_core" / "parameters" / "default_ps_max_latency_us").write_text("0\n")
            (sys_root / "module" / "pcie_aspm" / "parameters" / "policy").write_text(
                "performance [default] powersave\n"
            )
            (sys_root / "firmware" / "devicetree" / "base" / "compatible").write_bytes(
                b"raspberrypi,5-model-b\0brcm,bcm2712\0"
            )
            current_bootloader = int(dt.datetime(
                2025, 12, 8, 19, 29, 54, tzinfo=dt.timezone.utc
            ).timestamp())
            (bootloader / "build-timestamp").write_bytes(current_bootloader.to_bytes(4, "big"))
            (etc / "default" / "rpi-eeprom-update").write_text(
                'FIRMWARE_RELEASE_STATUS="default"\n'
            )
            firmware = packages / "lib" / "firmware" / "raspberrypi" / "bootloader-2712" / "default"
            (firmware / "pieeprom-2025-11-05.bin").write_bytes(b"fixture")
            (firmware / "pieeprom-2025-12-08.bin").write_bytes(b"fixture")

            (controller / "model").write_text("NE-256 2242\n")
            (controller / "firmware_rev").write_text("SN25845\n")
            (device / "current_link_speed").write_text("2.5 GT/s PCIe\n")
            (device / "current_link_width").write_text("1\n")
            (device / "max_link_speed").write_text("8.0 GT/s PCIe\n")
            (device / "max_link_width").write_text("4\n")
            (device / "of_node" / "max-link-speed").write_bytes((1).to_bytes(4, "big"))
            (device / "aer_dev_correctable").write_text("RxErr 7\nTOTAL_ERR_COR 7\n")
            (device / "aer_dev_nonfatal").write_text("DLP 2\nTOTAL_ERR_NONFATAL 2\n")
            (device / "aer_dev_fatal").write_text("DLP 0\nTOTAL_ERR_FATAL 0\n")
            pci_config = bytearray(256)
            pci_config[0x34] = 0x40
            pci_config[0x40] = 0x10
            pci_config[0x4A:0x4C] = (0x3).to_bytes(2, "little")
            (device / "config").write_bytes(pci_config)

            now = dt.datetime(2026, 8, 27, 7, 0, tzinfo=dt.timezone.utc)
            summary = collector.update_kernel_event_summary(
                collector.empty_kernel_event_summary(),
                [
                    collector.reliability_event("2026-08-27T05:59:00Z", "kernel-warning", "active"),
                    collector.reliability_event("2026-08-27T06:00:30Z", "rcu-stall", "expedited"),
                    collector.reliability_event("2026-08-27T06:01:00Z", "rcu-stall", "active"),
                    collector.reliability_event("2026-08-27T06:02:00Z", "nvme-reset", "active"),
                    collector.reliability_event("2026-08-27T06:03:00Z", "pcie-aer", "fatal"),
                ],
                "2026-08-27T06:00:00Z",
                now,
            )
            config = collector.Config(
                proc_root=proc,
                sys_root=sys_root,
                etc_root=etc,
                package_root=packages,
            )
            with mock.patch.object(collector.platform, "release", return_value="6.8.0-1061-raspi"):
                system = collector.collect_system(config, summary)

            self.assertEqual(system["versions"], {
                "kernelRunning": "6.8.0-1061-raspi",
                "kernelLatestInstalled": "6.8.0-1062-raspi",
                "kernelRebootRequired": True,
                "bootloaderCurrent": "2025-12-08",
                "bootloaderLatest": "2025-12-08",
                "bootloaderChannel": "default",
                "nvmeModel": "NE-256 2242",
                "nvmeFirmware": "SN25845",
                "collector": collector.COLLECTOR_VERSION,
            })
            self.assertEqual(system["pcie"], {
                "configuredGeneration": 1,
                "negotiatedGeneration": 1,
                "negotiatedSpeedGtps": 2.5,
                "negotiatedWidth": 1,
                "endpointMaxGeneration": 3,
                "endpointMaxWidth": 4,
                "aspmDisabled": True,
                "nvmePowerSavingDisabled": True,
                "aerCorrectableCount": 7,
                "aerNonFatalCount": 2,
                "aerFatalCount": 0,
                "correctableStatusActive": True,
                "nonFatalStatusActive": True,
                "fatalStatusActive": False,
            })
            self.assertEqual(system["kernel"]["warning"], {
                "count": 0, "lastEventAt": None,
            })
            self.assertEqual(system["kernel"]["rcuStall"], {
                "count": 1, "lastEventAt": "2026-08-27T06:01:00Z",
            })
            self.assertEqual(system["kernel"]["rcuExpedited"], {
                "count": 1, "lastEventAt": "2026-08-27T06:00:30Z",
            })
            self.assertEqual(system["kernel"]["nvmeReset"]["count"], 1)
            self.assertEqual(system["kernel"]["pcieAerFatal"]["count"], 1)
            self.assertEqual(set(system["kernel"]), set(collector.KERNEL_EVENT_SUMMARY_KEYS))
            self.assertNotIn("serial", json.dumps(system).lower())

    def test_kernel_summary_contract_rejects_partial_or_inconsistent_values(self):
        summary = collector.empty_kernel_event_summary()
        self.assertEqual(collector.existing_kernel_event_summary(summary), summary)
        self.assertIsNone(collector.existing_kernel_event_summary({**summary, "raw": {}}))
        malformed = collector.empty_kernel_event_summary()
        malformed["oops"] = {"count": 1, "lastEventAt": None}
        self.assertIsNone(collector.existing_kernel_event_summary(malformed))

    def test_v2_kernel_summary_migration_only_uses_retained_current_boot_evidence(self):
        legacy = {
            key: {"count": 0, "lastEventAt": None}
            for key in collector.LEGACY_KERNEL_EVENT_SUMMARY_KEYS
        }
        legacy["warning"] = {
            "count": 5, "lastEventAt": "2026-08-27T06:05:00Z",
        }
        legacy["nvmeReset"] = {
            "count": 2, "lastEventAt": "2026-08-27T06:04:00Z",
        }
        expedited = collector.reliability_event(
            "2026-08-27T06:02:00Z", "rcu-stall", "expedited"
        )
        migrated = collector.migrate_v2_kernel_event_summary(
            legacy,
            [
                collector.reliability_event(
                    "2026-08-27T05:59:00Z", "kernel-warning", "active"
                ),
                collector.reliability_event(
                    "2026-08-27T06:01:00Z", "kernel-warning", "active"
                ),
                expedited,
                dict(expedited),
            ],
            "2026-08-27T06:00:00Z",
            dt.datetime(2026, 8, 27, 7, 0, tzinfo=dt.timezone.utc),
        )

        self.assertEqual(migrated["warning"], {
            "count": 1, "lastEventAt": "2026-08-27T06:01:00Z",
        })
        self.assertEqual(migrated["rcuExpedited"], {
            "count": 1, "lastEventAt": "2026-08-27T06:02:00Z",
        })
        self.assertEqual(migrated["nvmeReset"], {
            "count": 2, "lastEventAt": "2026-08-27T06:04:00Z",
        })

    def test_kernel_summary_deduplicates_exact_rows_but_counts_subsecond_events(self):
        now = dt.datetime(2026, 8, 27, 7, 0, tzinfo=dt.timezone.utc)
        first = collector.reliability_event(
            "2026-08-27T06:03:00.100000Z", "pcie-aer", "fatal"
        )
        second = collector.reliability_event(
            "2026-08-27T06:03:00.900000Z", "pcie-aer", "fatal"
        )
        summary = collector.update_kernel_event_summary(
            collector.empty_kernel_event_summary(),
            [first, dict(first), second],
            "2026-08-27T06:00:00Z",
            now,
        )
        self.assertEqual(summary["pcieAerFatal"], {
            "count": 2,
            "lastEventAt": "2026-08-27T06:03:00.900000Z",
        })
        merged = collector.merge_reliability_records(
            [], [first, dict(first), second], 10
        )
        self.assertEqual(
            [record["timestamp"] for record in merged],
            ["2026-08-27T06:03:00.100000Z", "2026-08-27T06:03:00.900000Z"],
        )

    def test_rcu_backfill_requires_boot_boundary_and_prior_event_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = root / "kern.log"
            config = collector.Config(kernel_log=kernel)
            now = dt.datetime(2026, 8, 27, 7, 0, tzinfo=dt.timezone.utc)
            kernel.write_text(
                "2026-08-27T06:10:00.100000Z kernel: rcu: INFO: "
                "rcu_preempt detected expedited stalls on CPUs/tasks raw=secret\n"
            )
            self.assertIsNone(collector.bounded_current_boot_rcu_backfill(
                config, "2026-08-27T06:00:00Z", now,
                "2026-08-27T06:10:00Z",
            ))
            kernel.write_text(
                "2026-08-27T06:00:00Z kernel: boot marker\n"
                "2026-08-27T06:10:00.100000Z kernel: rcu: INFO: "
                "rcu_preempt detected expedited stalls on CPUs/tasks raw=secret\n"
            )
            self.assertIsNone(collector.bounded_current_boot_rcu_backfill(
                config, "2026-08-27T06:00:00Z", now,
                "2026-08-27T06:11:00Z",
            ))
            records = collector.bounded_current_boot_rcu_backfill(
                config, "2026-08-27T06:00:00Z", now,
                "2026-08-27T06:10:00Z",
            )
            self.assertEqual(len(records or []), 1)
            self.assertNotIn("secret", json.dumps(records))

    def test_hardened_sysfs_config_read_leaves_pcie_status_bits_unknown(self):
        # Linux limits unprivileged PCI sysfs config reads to the 64-byte
        # conventional header. The collector deliberately has no CAP_SYS_ADMIN.
        self.assertEqual(collector.pcie_device_status(bytes(64)), (None, None, None))

    def test_latest_kernel_requires_a_configured_image_when_dpkg_state_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in ("6.8.0-1061-raspi", "6.8.0-1062-raspi"):
                (root / "lib" / "modules" / version).mkdir(parents=True)
            status = root / "var" / "lib" / "dpkg" / "status"
            status.parent.mkdir(parents=True)
            status.write_text(
                "Package: linux-image-raspi\n"
                "Status: install ok installed\n\n"
                "Package: linux-image-6.8.0-1061-raspi\n"
                "Status: install ok installed\n\n"
                "Package: linux-image-6.8.0-1062-raspi\n"
                "Status: install ok half-configured\n"
            )
            self.assertEqual(
                collector.latest_installed_kernel(root), "6.8.0-1061-raspi"
            )
            status.write_text(
                status.read_text().replace("install ok half-configured", "install ok installed")
            )
            self.assertEqual(
                collector.latest_installed_kernel(root), "6.8.0-1062-raspi"
            )

    def test_latest_kernel_uses_dpkg_when_modules_are_hidden(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "var" / "lib" / "dpkg" / "status"
            status.parent.mkdir(parents=True)
            status.write_text(
                "Package: linux-image-6.8.0-1061-raspi\n"
                "Status: install ok installed\n\n"
                "Package: linux-image-6.8.0-1062-raspi\n"
                "Status: hold ok installed\n"
            )
            self.assertFalse((root / "lib" / "modules").exists())
            self.assertEqual(
                collector.latest_installed_kernel(root), "6.8.0-1062-raspi"
            )


class IncidentTests(unittest.TestCase):
    @staticmethod
    def write_process_stat(root, pid, name, cpu_ticks, start_ticks, resident_pages):
        process = root / str(pid)
        process.mkdir(parents=True, exist_ok=True)
        fields = ["R", *(["0"] * 21)]
        fields[11] = str(cpu_ticks)
        fields[12] = "0"
        fields[19] = str(start_ticks)
        fields[21] = str(resident_pages)
        (process / "stat").write_text(f"{pid} ({name}) {' '.join(fields)}\n")

    def test_process_snapshot_groups_safe_names_without_identity_or_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            self.write_process_stat(proc, 101, "node", 100, 1001, 10)
            self.write_process_stat(proc, 102, "node", 200, 1002, 20)
            self.write_process_stat(proc, 103, "token=private", 300, 1003, 5)
            original_stat = Path.stat

            def allow_as_root(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path.parent == proc and path.name.isdigit():
                    result_values = list(result)
                    result_values[4] = 0
                    return os.stat_result(result_values)
                return result

            with mock.patch.object(Path, "stat", allow_as_root):
                first, prior = collector.collect_processes(proc, {}, 100, {0}, page_size=4096)
                self.write_process_stat(proc, 101, "node", 120, 1001, 11)
                self.write_process_stat(proc, 102, "node", 210, 1002, 21)
                second, state = collector.collect_processes(proc, prior, 100, {0}, page_size=4096)
                self.write_process_stat(proc, 104, "node", 50, 1004, 4)
                partial, partial_state = collector.collect_processes(
                    proc, state, 100, {0}, page_size=4096
                )
                self.write_process_stat(proc, 101, "node", 130, 1001, 11)
                self.write_process_stat(proc, 102, "node", 220, 1002, 21)
                self.write_process_stat(proc, 104, "node", 60, 1004, 4)
                complete, complete_state = collector.collect_processes(
                    proc, partial_state, 100, {0}, page_size=4096
                )
                blocked, blocked_state = collector.collect_processes(
                    proc, prior, 100, {9999}, page_size=4096
                )

            self.assertTrue(all(set(item) == {
                "name", "instances", "cpuPercent", "memoryBytes",
            } for item in first))
            node = next(item for item in second if item["name"] == "node")
            self.assertEqual(node, {
                "name": "node", "instances": 2, "cpuPercent": 30.0,
                "memoryBytes": 32 * 4096,
            })
            partial_node = next(item for item in partial if item["name"] == "node")
            self.assertEqual(partial_node, {
                "name": "node", "instances": 3, "cpuPercent": None,
                "memoryBytes": 36 * 4096,
            })
            complete_node = next(item for item in complete if item["name"] == "node")
            self.assertEqual(complete_node["cpuPercent"], 30.0)
            self.assertIn("redacted", {item["name"] for item in second})
            self.assertEqual(collector.safe_process_name("alice@example.test"), "other")
            self.assertLessEqual(len(second), collector.MAX_PROCESS_GROUPS)
            serialized = json.dumps(second).lower()
            for forbidden in ("private", "argv", "uid", "cwd", "open files"):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual(len(complete_state), 4)
            self.assertTrue(all(len(key) == 24 and ":" not in key for key in complete_state))
            self.assertEqual((blocked, blocked_state), ([], {}))

    def test_pressure_parser_is_exact_and_malformed_values_become_unknown(self):
        parsed = collector.parse_pressure(
            "some avg10=12.34 avg60=1.0 avg300=2.0 total=3\n"
            "full avg10=not-a-number avg60=0 total=0\n"
            "foreign avg10=99\n"
        )
        self.assertEqual(parsed, {"someAvg10": 12.34, "fullAvg10": None})

    def test_traffic_input_is_allowlisted_aggregated_and_cursor_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traffic_log = root / "traffic.jsonl"
            now = dt.datetime(2026, 8, 23, 0, 5, tzinfo=dt.timezone.utc)
            lines = [
                {"timestamp": "2026-08-23T00:04:30Z", "app": "monitor", "status": 200,
                 "requestTime": 0.1},
                {"timestamp": "2026-08-23T00:04:30Z", "app": "monitor", "status": 200,
                 "requestTime": 0.1, "remoteAddr": "must-not-export"},
                {"timestamp": "2026-08-23T00:04:31Z", "app": "monitor", "status": 503,
                 "requestTime": 1.5},
                {"timestamp": "2026-08-23T00:04:31Z", "app": "blog", "status": 200,
                 "requestTime": 0.4},
                {"timestamp": "2026-08-23T00:04:32Z", "app": "react", "status": 302,
                 "requestTime": 0.2},
                {"timestamp": "2026-08-23T00:04:33Z", "app": "unknown-safe-token", "status": 200,
                 "requestTime": 0.1},
                {"timestamp": "2026-08-23T00:04:34Z", "app": "monitor/private", "status": 200,
                 "requestTime": 0.1},
                {"timestamp": "2026-08-22T23:00:00Z", "app": "monitor", "status": 200,
                 "requestTime": 0.1},
                {"timestamp": "2026-08-23T00:04:35Z", "app": "monitor", "status": True,
                 "requestTime": 0.1},
                {"timestamp": "2026-08-23T00:04:36Z", "app": "monitor", "status": 200,
                 "requestTime": float("inf")},
            ]
            oversized = json.dumps({
                "timestamp": "2026-08-23T00:04:29Z", "app": "monitor", "status": 200,
                "requestTime": 0.1, "padding": "x" * collector.MAX_TRAFFIC_LINE_BYTES,
            })
            traffic_log.write_text(oversized + "\n" + "\n".join(json.dumps(line) for line in lines) + "\n")
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run", traffic_log=traffic_log,
                docker_sockets={}, traffic_slow_seconds=1.0,
            )
            result, cursor, available = collector.collect_traffic(config, now)
            self.assertTrue(available)
            self.assertEqual(result, [{
                "app": "blog", "requestCount": 1, "status2xx": 1, "status3xx": 0,
                "status4xx": 0, "status5xx": 0, "slowCount": 0,
                "avgResponseMs": 400.0, "maxResponseMs": 400.0,
            }, {
                "app": "monitor", "requestCount": 2, "status2xx": 1, "status3xx": 0,
                "status4xx": 0, "status5xx": 1, "slowCount": 1,
                "avgResponseMs": 800.0, "maxResponseMs": 1500.0,
            }, {
                "app": "react", "requestCount": 1, "status2xx": 0, "status3xx": 1,
                "status4xx": 0, "status5xx": 0, "slowCount": 0,
                "avgResponseMs": 200.0, "maxResponseMs": 200.0,
            }])
            self.assertNotIn("must-not-export", json.dumps(result))
            cursor_path = config.output_dir / ".state" / "traffic-cursor.json"
            self.assertFalse(cursor_path.exists())
            repeated, repeated_cursor, repeated_available = collector.collect_traffic(config, now)
            self.assertEqual((repeated, repeated_cursor, repeated_available), (result, cursor, True))
            collector.commit_traffic_cursor(config, cursor)
            self.assertEqual(stat.S_IMODE(cursor_path.stat().st_mode), 0o600)
            self.assertEqual(
                collector.collect_traffic(config, now + dt.timedelta(minutes=1)),
                ([], cursor, True),
            )

    def test_cpu_transition_supports_configurable_streak_follow_up_and_recovery(self):
        config = collector.Config(
            docker_sockets={}, traffic_log=None, cpu_warn_samples=2,
            incident_follow_up_samples=1,
        )
        start = dt.datetime(2026, 8, 23, 1, 0, tzinfo=dt.timezone.utc)
        first, state = collector.incident_transition(
            config, start, incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {}
        )
        self.assertIsNone(first)
        self.assertEqual(state["cpuStreak"], 1)
        missing, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=1), incident_metrics(cpuPercent=None),
            empty_pressure(), [], [], [], state,
        )
        self.assertIsNone(missing)
        self.assertEqual(state["cpuStreak"], 1)
        active, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=2), incident_metrics(cpuPercent=90),
            empty_pressure(), [], [], [], state,
        )
        self.assertEqual(active["phase"], "active")
        self.assertEqual(active["reasons"], ["cpu"])
        self.assertEqual(active["endedAt"], None)
        self.assertEqual(active["durationSeconds"], None)
        self.assertEqual(active["metrics"]["timestamp"], active["observedAt"])
        self.assertIsNotNone(collector.existing_incident_record(active))

        follow_up, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=3), incident_metrics(cpuPercent=80),
            empty_pressure(), [], [], [], state,
        )
        self.assertEqual(follow_up["phase"], "follow-up")
        suppressed, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=4), incident_metrics(cpuPercent=80),
            empty_pressure(), [], [], [], state,
        )
        self.assertIsNone(suppressed)
        recovered, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=5), incident_metrics(cpuPercent=74),
            empty_pressure(), [], [], [], state,
        )
        self.assertEqual(recovered["phase"], "recovered")
        self.assertEqual(recovered["durationSeconds"], 180)
        self.assertEqual(recovered["peaks"]["cpuPercent"], 90)
        self.assertEqual(state["activeReasons"], [])

    def test_memory_temperature_power_load_disk_and_traffic_hysteresis(self):
        config = collector.Config(docker_sockets={}, traffic_log=None)
        start = dt.datetime(2026, 8, 23, 2, 0, tzinfo=dt.timezone.utc)
        traffic = [{
            "app": "monitor", "requestCount": 300, "status2xx": 300, "status3xx": 0,
            "status4xx": 0, "status5xx": 0, "slowCount": 0,
            "avgResponseMs": 10.0, "maxResponseMs": 20.0,
        }]
        active, state = collector.incident_transition(
            config,
            start,
            incident_metrics(
                memoryPercent=80, temperatureC=75, throttledFlags=1, powerState="under-voltage",
                load1=4, diskReadBytesPerSecond=100 * 1024 * 1024,
            ),
            empty_pressure(), [], [], traffic, {},
        )
        self.assertEqual(active["reasons"], [
            "memory", "temperature", "power-throttle", "load", "disk-io", "traffic",
        ])

        traffic[0]["requestCount"] = 250
        traffic[0]["status2xx"] = 250
        follow_up, state = collector.incident_transition(
            config,
            start + dt.timedelta(minutes=1),
            incident_metrics(
                memoryPercent=77, temperatureC=73, throttledFlags=0, load1=3,
                diskReadBytesPerSecond=60 * 1024 * 1024,
            ),
            empty_pressure(), [], [], traffic, state,
        )
        self.assertEqual(follow_up["phase"], "follow-up")
        self.assertNotIn("power-throttle", state["activeReasons"])
        self.assertIn("power-throttle", follow_up["reasons"])

        traffic[0]["requestCount"] = 199
        traffic[0]["status2xx"] = 199
        recovered, state = collector.incident_transition(
            config,
            start + dt.timedelta(minutes=2),
            incident_metrics(
                memoryPercent=75, temperatureC=71.9, throttledFlags=0, load1=1.9,
                diskReadBytesPerSecond=(50 * 1024 * 1024) - 1,
            ),
            empty_pressure(), [], [], traffic, state,
        )
        self.assertEqual(recovered["phase"], "recovered")
        self.assertEqual(recovered["durationSeconds"], 120)
        self.assertEqual(state["activeReasons"], [])

    def test_unknown_metrics_preserve_active_reasons_without_opening_new_ones(self):
        config = collector.Config(docker_sockets={}, traffic_log=None, cpu_warn_samples=1)
        start = dt.datetime(2026, 8, 23, 2, 30, tzinfo=dt.timezone.utc)
        traffic = [{
            "app": "monitor", "requestCount": 300, "status2xx": 300, "status3xx": 0,
            "status4xx": 0, "status5xx": 0, "slowCount": 0,
            "avgResponseMs": 10.0, "maxResponseMs": 20.0,
        }]
        active, state = collector.incident_transition(
            config,
            start,
            incident_metrics(
                cpuPercent=90, memoryPercent=80, temperatureC=75,
                throttledFlags=1, powerState="under-voltage", load1=4,
                diskReadBytesPerSecond=100 * 1024 * 1024,
            ),
            empty_pressure(), [], [], traffic, {}, True,
        )
        self.assertEqual(active["reasons"], list(collector.INCIDENT_REASONS))

        unknown_metrics = incident_metrics(
            cpuPercent=None, memoryPercent=None, memoryUsedBytes=None,
            memoryTotalBytes=None, temperatureC=None, throttledFlags=None,
            powerState=None, load1=None, load5=None, load15=None,
            diskReadBytesPerSecond=None, diskWriteBytesPerSecond=None,
        )
        follow_up, state = collector.incident_transition(
            config,
            start + dt.timedelta(minutes=1),
            unknown_metrics,
            empty_pressure(), [], [], [], state, False,
        )
        self.assertEqual(follow_up["phase"], "follow-up")
        self.assertEqual(state["activeReasons"], list(collector.INCIDENT_REASONS))
        self.assertEqual(state["cpuStreak"], 1)

        absent, new_state = collector.incident_transition(
            config,
            start + dt.timedelta(minutes=2),
            unknown_metrics,
            empty_pressure(), [], [], [], {}, False,
        )
        self.assertIsNone(absent)
        self.assertEqual(new_state["activeReasons"], [])

    def test_incident_validation_rejects_foreign_owner_and_malformed_nested_data(self):
        config = collector.Config(docker_sockets={}, traffic_log=None, cpu_warn_samples=1)
        now = dt.datetime(2026, 8, 23, 3, 0, tzinfo=dt.timezone.utc)
        container = {
            "name": "web", "owner": "cks", "state": "running", "health": "healthy",
            "cpuPercent": 1.0, "memoryBytes": 1024, "memoryPercent": 1.0,
        }
        record, _state = collector.incident_transition(
            config, now, incident_metrics(cpuPercent=90), empty_pressure(),
            [{"name": "python", "instances": 1, "cpuPercent": 20.0, "memoryBytes": 4096}],
            [container], [], {},
        )
        self.assertIsNotNone(collector.existing_incident_record(record))
        foreign = json.loads(json.dumps(record))
        foreign["containers"][0]["owner"] = "foreign"
        self.assertIsNone(collector.existing_incident_record(foreign))
        malformed = json.loads(json.dumps(record))
        malformed["processes"][0]["argv"] = "must-not-pass"
        self.assertIsNone(collector.existing_incident_record(malformed))
        bad_metrics = json.loads(json.dumps(record))
        bad_metrics["metrics"]["memoryPercent"] = 101
        self.assertIsNone(collector.existing_incident_record(bad_metrics))
        bad_counts = json.loads(json.dumps(record))
        bad_counts["traffic"] = [{
            "app": "monitor", "requestCount": 1, "status2xx": 1, "status3xx": 0,
            "status4xx": 0, "status5xx": 1, "slowCount": 2,
            "avgResponseMs": 10.0, "maxResponseMs": 10.0,
        }]
        self.assertIsNone(collector.existing_incident_record(bad_counts))
        unexpected = dict(record, remoteAddress="must-not-pass")
        self.assertIsNone(collector.existing_incident_record(unexpected))

    def test_incident_container_snapshot_is_safe_prioritized_and_line_bounded(self):
        config = collector.Config(docker_sockets={}, traffic_log=None, cpu_warn_samples=1)
        now = dt.datetime(2026, 8, 23, 3, 30, tzinfo=dt.timezone.utc)
        containers = [{
            "name": f"service-{index}", "owner": "cks", "state": "running", "health": "healthy",
            "cpuPercent": 0.0, "memoryBytes": index, "memoryPercent": 0.0,
        } for index in range(80)]
        containers[-1].update({"name": "busy-service", "health": "unhealthy", "cpuPercent": 160.0})
        record, _state = collector.incident_transition(
            config, now, incident_metrics(cpuPercent=90), empty_pressure(), [], containers, [], {}
        )
        self.assertEqual(len(record["containers"]), collector.MAX_INCIDENT_CONTAINERS)
        self.assertEqual(record["containers"][0]["name"], "busy-service")
        self.assertLessEqual(
            len((json.dumps(record, separators=(",", ":")) + "\n").encode()),
            collector.MAX_INCIDENT_LINE_BYTES,
        )
        self.assertIsNotNone(collector.existing_incident_record(record))

    def test_incident_file_is_atomic_retained_record_and_byte_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run", docker_sockets={},
                traffic_log=None, max_incident_records=3, incident_retention_days=1,
                cpu_warn_samples=1,
            )
            start = dt.datetime(2026, 8, 23, 4, 0, tzinfo=dt.timezone.utc)
            records = []
            for offset in range(5):
                observed = start + dt.timedelta(minutes=offset)
                record, _state = collector.incident_transition(
                    config, observed, incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {}
                )
                records.append(record)
            path = config.output_dir / "incidents.jsonl"
            path.parent.mkdir(parents=True)
            old_time = start - dt.timedelta(days=2)
            old_record, _old_state = collector.incident_transition(
                config, old_time, incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {}
            )
            path.write_text(json.dumps(old_record) + '\n{"unexpected":"drop-me"}\n')
            for record in records:
                collector.persist_incidents(config, start + dt.timedelta(minutes=5), record)
            saved = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(saved), 3)
            self.assertEqual([record["observedAt"] for record in saved], [
                "2026-08-23T04:02:00Z", "2026-08-23T04:03:00Z", "2026-08-23T04:04:00Z",
            ])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertFalse(list(path.parent.glob(f".{path.name}.*")))
            fresh_time = (start + dt.timedelta(minutes=5)).timestamp()
            os.utime(path, (fresh_time, fresh_time))
            with mock.patch.object(collector, "rewrite_incident_lines") as rewrite:
                collector.persist_incidents(config, start + dt.timedelta(minutes=6), None)
                rewrite.assert_not_called()

            with mock.patch.object(collector, "MAX_INCIDENT_FILE_BYTES", 350), \
                 mock.patch.object(collector, "MAX_INCIDENT_LINE_BYTES", 300):
                collector.rewrite_incident_lines(path, [
                    {"sequence": 1, "padding": "a" * 120},
                    {"sequence": 2, "padding": "b" * 120},
                    {"sequence": 3, "padding": "c" * 400},
                ], 10)
            bounded = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([value["sequence"] for value in bounded], [1, 2])
            self.assertLessEqual(path.stat().st_size, 350)

    def test_pending_incident_commit_replays_all_fault_windows_idempotently(self):
        now = dt.datetime(2026, 8, 23, 4, 30, tzinfo=dt.timezone.utc)
        for fault_point in ("incident", "lifecycle", "cursor", "remove"):
            with self.subTest(fault_point=fault_point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = collector.Config(
                    output_dir=root / "out", runtime_dir=root / "run",
                    docker_sockets={}, traffic_log=None, cpu_warn_samples=1,
                )
                record, lifecycle = collector.incident_transition(
                    config, now, incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {}
                )
                cursor = {"inode": 123, "offset": 456, "discardUntilNewline": True}
                pending_path = collector.write_pending_incident_commit(
                    config, record, lifecycle, cursor
                )
                self.assertEqual(stat.S_IMODE(pending_path.stat().st_mode), 0o600)
                self.assertEqual(set(json.loads(pending_path.read_text())), {
                    "version", "record", "lifecycle", "trafficCursor",
                })

                stack = []
                if fault_point == "incident":
                    stack.append(mock.patch.object(
                        collector, "persist_incidents", side_effect=OSError("injected")
                    ))
                elif fault_point == "lifecycle":
                    original_atomic_write = collector.atomic_write_json

                    def fail_lifecycle(path, value, mode=0o640):
                        if Path(path).name == "incident-lifecycle.json":
                            raise OSError("injected")
                        return original_atomic_write(path, value, mode)

                    stack.append(mock.patch.object(
                        collector, "atomic_write_json", side_effect=fail_lifecycle
                    ))
                elif fault_point == "cursor":
                    stack.append(mock.patch.object(
                        collector, "commit_traffic_cursor", side_effect=OSError("injected")
                    ))
                else:
                    stack.append(mock.patch.object(
                        collector, "discard_pending_incident_commit", return_value=False
                    ))

                with stack[0]:
                    with self.assertRaises(OSError):
                        collector.replay_pending_incident_commit(config, now)
                self.assertTrue(pending_path.is_file())

                collector.replay_pending_incident_commit(config, now)
                incidents = [
                    json.loads(line)
                    for line in (config.output_dir / "incidents.jsonl").read_text().splitlines()
                ]
                self.assertEqual(len(incidents), 1)
                self.assertEqual(incidents[0], collector.existing_incident_record(record))
                self.assertEqual(
                    json.loads((config.output_dir / ".state" / "incident-lifecycle.json").read_text()),
                    lifecycle,
                )
                self.assertEqual(
                    json.loads((config.output_dir / ".state" / "traffic-cursor.json").read_text()),
                    {"cursor": cursor},
                )
                self.assertFalse(pending_path.exists())

                # Re-staging the same public capture is an upsert, not append.
                collector.write_pending_incident_commit(config, record, lifecycle, cursor)
                collector.replay_pending_incident_commit(config, now)
                self.assertEqual(
                    len((config.output_dir / "incidents.jsonl").read_text().splitlines()), 1
                )

    def test_pending_cursor_only_commit_survives_failure_and_advances(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                docker_sockets={}, traffic_log=None, cpu_warn_samples=1,
            )
            now = dt.datetime(2026, 8, 23, 4, 40, tzinfo=dt.timezone.utc)
            record, lifecycle = collector.incident_transition(
                config, now, incident_metrics(), empty_pressure(), [], [], [], {}
            )
            self.assertIsNone(record)
            cursor = {"inode": 987, "offset": 654}
            pending_path = collector.write_pending_incident_commit(
                config, record, lifecycle, cursor
            )
            with mock.patch.object(
                collector, "commit_traffic_cursor", side_effect=OSError("injected")
            ):
                with self.assertRaises(OSError):
                    collector.replay_pending_incident_commit(config, now)
            self.assertTrue(pending_path.exists())
            self.assertFalse((config.output_dir / "incidents.jsonl").exists())

            collector.replay_pending_incident_commit(config, now)
            self.assertEqual(
                json.loads((config.output_dir / ".state" / "traffic-cursor.json").read_text()),
                {"cursor": cursor},
            )
            self.assertFalse(pending_path.exists())

    def test_pending_publication_crash_recovers_exact_temp_link_and_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                docker_sockets={}, traffic_log=None, cpu_warn_samples=1,
            )
            now = dt.datetime(2026, 8, 23, 4, 45, tzinfo=dt.timezone.utc)
            record, lifecycle = collector.incident_transition(
                config, now, incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {}
            )
            cursor = {"inode": 222, "offset": 333}
            pending_path = collector.write_pending_incident_commit(
                config, record, lifecycle, cursor
            )
            publication_temp = pending_path.parent / f".{pending_path.name}.abcd1234"
            os.link(pending_path, publication_temp)
            self.assertEqual(pending_path.stat().st_nlink, 2)
            self.assertEqual(publication_temp.stat().st_ino, pending_path.stat().st_ino)

            self.assertTrue(collector.replay_pending_incident_commit(config, now))
            self.assertFalse(publication_temp.exists())
            self.assertFalse(pending_path.exists())
            incidents = [
                json.loads(line)
                for line in (config.output_dir / "incidents.jsonl").read_text().splitlines()
            ]
            self.assertEqual(incidents, [collector.existing_incident_record(record)])
            self.assertEqual(
                json.loads((config.output_dir / ".state" / "traffic-cursor.json").read_text()),
                {"cursor": cursor},
            )

    def test_pending_commit_fail_closed_preserves_every_unsafe_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                docker_sockets={}, traffic_log=None, cpu_warn_samples=1,
            )
            record, lifecycle = collector.incident_transition(
                config,
                dt.datetime(2026, 8, 23, 4, 50, tzinfo=dt.timezone.utc),
                incident_metrics(cpuPercent=90), empty_pressure(), [], [], [], {},
            )
            malformed_record = json.loads(json.dumps(record))
            malformed_record["reasons"] = [{}]
            state_dir = root / "out" / ".state"
            state_dir.mkdir(parents=True)
            path = state_dir / "pending-incident-commit.json"

            malformed_payloads = (
                b'{"record":{"remoteAddress":"private"}}\n',
                (json.dumps({
                    "version": 1, "record": malformed_record,
                    "lifecycle": lifecycle, "trafficCursor": None,
                }) + "\n").encode(),
                (json.dumps({
                    "version": True, "record": None,
                    "lifecycle": lifecycle, "trafficCursor": None,
                }) + "\n").encode(),
                b"x" * (collector.MAX_PENDING_INCIDENT_COMMIT_BYTES + 1),
            )
            for payload in malformed_payloads:
                with self.subTest(size=len(payload)):
                    path.write_bytes(payload)
                    path.chmod(0o600)
                    with self.assertRaises(collector.PendingJournalError):
                        collector.load_pending_incident_commit(path)
                    self.assertEqual(path.read_bytes(), payload)
                    with self.assertRaises(collector.PendingJournalError):
                        collector.write_pending_incident_commit(
                            config, record, lifecycle, None
                        )
                    self.assertEqual(path.read_bytes(), payload)
                    path.unlink()

            path.write_text("{}\n")
            path.chmod(0o640)
            with self.assertRaises(collector.PendingJournalError):
                collector.load_pending_incident_commit(path)
            self.assertTrue(path.is_file())

    def test_private_pending_loader_preserves_link_directory_and_io_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir = root / ".state"
            state_dir.mkdir()
            path = state_dir / "pending.json"
            target = root / "target"
            target.write_text("do-not-touch")
            path.symlink_to(target)
            with self.assertRaises(collector.PendingJournalError):
                collector.load_private_pending_json(path, 4096)
            self.assertTrue(path.is_symlink())
            self.assertEqual(target.read_text(), "do-not-touch")
            path.unlink()

            path.mkdir()
            with self.assertRaises(collector.PendingJournalError):
                collector.load_private_pending_json(path, 4096)
            self.assertTrue(path.is_dir())
            path.rmdir()

            path.write_text("{}\n")
            path.chmod(0o600)
            hardlink = state_dir / "pending-link.json"
            os.link(path, hardlink)
            with self.assertRaises(collector.PendingJournalError):
                collector.load_private_pending_json(path, 4096)
            self.assertTrue(path.exists())
            self.assertTrue(hardlink.exists())
            hardlink.unlink()

            with mock.patch.object(os, "open", side_effect=PermissionError("injected")):
                with self.assertRaises(collector.PendingJournalError):
                    collector.load_private_pending_json(path, 4096)
            self.assertEqual(path.read_text(), "{}\n")

            with mock.patch.object(Path, "lstat", side_effect=PermissionError("injected")):
                with self.assertRaises(collector.PendingJournalError):
                    collector.load_private_pending_json(path, 4096)
            self.assertEqual(path.read_text(), "{}\n")

            with mock.patch.object(os, "fdopen", side_effect=OSError("injected")):
                with self.assertRaises(collector.PendingJournalError):
                    collector.load_private_pending_json(path, 4096)
            self.assertEqual(path.read_text(), "{}\n")

    def test_run_writes_active_and_recovered_incidents_with_private_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            etc = root / "etc"
            mount = root / "mount"
            for directory in (proc / "net", proc / "self", sys_root, etc, mount):
                directory.mkdir(parents=True, exist_ok=True)
            (proc / "stat").write_text("cpu 100 0 0 900 0 0 0 0\n")
            (proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 20 kB\n")
            (proc / "net" / "dev").write_text("")
            (proc / "diskstats").write_text("")
            (proc / "loadavg").write_text("0.5 0.5 0.5 1/1 1\n")
            (proc / "uptime").write_text("60 0\n")
            (proc / "self" / "mountinfo").write_text("")
            (etc / "os-release").write_text('PRETTY_NAME="Fixture"\n')
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run", proc_root=proc,
                sys_root=sys_root, etc_root=etc, mount_root=mount,
                events_log=root / "events", kernel_log=root / "kernel",
                privilege_logs=[], traffic_log=None, docker_sockets={}, vcgencmd="",
            )
            start = dt.datetime(2026, 8, 23, 5, 0, tzinfo=dt.timezone.utc)
            collector.run(config, start)
            lifecycle_path = config.output_dir / ".state" / "incident-lifecycle.json"
            lifecycle = json.loads(lifecycle_path.read_text())
            self.assertEqual(stat.S_IMODE(lifecycle_path.stat().st_mode), 0o600)
            self.assertEqual(set(lifecycle), {
                "activeReasons", "allReasons", "cpuStreak", "id", "startedAt",
                "followUpCount", "peaks",
            })
            self.assertEqual(lifecycle["activeReasons"], ["memory"])
            first_incident_id = lifecycle["id"]
            durable_serialized = json.dumps(lifecycle).lower()
            for forbidden in ("processes", "containers", "pid", "network", "disk", "monotonic"):
                self.assertNotIn(forbidden, durable_serialized)

            # Simulate a reboot: volatile deltas disappear, but the open
            # incident must continue with the durable lifecycle state.
            (config.runtime_dir / "delta-state.json").unlink()
            (proc / "stat").write_text("cpu 110 0 0 990 0 0 0 0\n")
            collector.run(config, start + dt.timedelta(minutes=1))
            (proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 25 kB\n")
            (proc / "stat").write_text("cpu 120 0 0 1080 0 0 0 0\n")
            collector.run(config, start + dt.timedelta(minutes=2))

            incident_path = config.output_dir / "incidents.jsonl"
            incidents = [json.loads(line) for line in incident_path.read_text().splitlines()]
            self.assertEqual(
                [record["phase"] for record in incidents],
                ["active", "follow-up", "recovered"],
            )
            self.assertTrue(all(record["reasons"] == ["memory"] for record in incidents))
            self.assertTrue(all(record["id"] == first_incident_id for record in incidents))
            self.assertIsNone(incidents[1]["metrics"]["cpuPercent"])
            self.assertEqual(incidents[2]["durationSeconds"], 120)
            self.assertTrue(all(record["metrics"]["timestamp"] == record["observedAt"] for record in incidents))
            self.assertEqual(stat.S_IMODE(incident_path.stat().st_mode), 0o640)
            state_path = config.runtime_dir / "delta-state.json"
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            state = json.loads(state_path.read_text())
            self.assertEqual(state["incident"]["activeReasons"], [])

    def test_run_commits_traffic_cursor_only_after_incident_persistence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            for directory in (
                proc / "net", proc / "self", root / "sys", root / "etc", root / "mount",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            (proc / "stat").write_text("cpu 100 0 0 900 0 0 0 0\n")
            (proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 20 kB\n")
            (proc / "net" / "dev").write_text("")
            (proc / "diskstats").write_text("")
            (proc / "loadavg").write_text("0.5 0.5 0.5 1/1 1\n")
            (proc / "uptime").write_text("60 0\n")
            (proc / "self" / "mountinfo").write_text("")
            traffic_log = root / "traffic.jsonl"
            traffic_log.write_text(json.dumps({
                "timestamp": "2026-08-23T05:59:30Z", "app": "monitor",
                "status": 200, "requestTime": 0.1,
            }) + "\n")
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run", proc_root=proc,
                sys_root=root / "sys", etc_root=root / "etc", mount_root=root / "mount",
                events_log=root / "events", kernel_log=root / "kernel",
                privilege_logs=[], traffic_log=traffic_log, docker_sockets={}, vcgencmd="",
            )
            now = dt.datetime(2026, 8, 23, 6, 0, tzinfo=dt.timezone.utc)
            cursor_path = config.output_dir / ".state" / "traffic-cursor.json"
            lifecycle_path = config.output_dir / ".state" / "incident-lifecycle.json"
            with mock.patch.object(
                collector, "persist_incidents", side_effect=OSError("fixture failure")
            ):
                with self.assertRaises(OSError):
                    collector.run(config, now)
            self.assertFalse(cursor_path.exists())
            self.assertFalse(lifecycle_path.exists())
            pending_path = config.output_dir / ".state" / "pending-incident-commit.json"
            self.assertTrue(pending_path.is_file())
            self.assertEqual(stat.S_IMODE(pending_path.stat().st_mode), 0o600)

            collector.run(config, now + dt.timedelta(minutes=1))
            self.assertTrue(cursor_path.is_file())
            self.assertEqual(stat.S_IMODE(cursor_path.stat().st_mode), 0o600)
            self.assertFalse(pending_path.exists())
            incidents = [
                json.loads(line)
                for line in (config.output_dir / "incidents.jsonl").read_text().splitlines()
            ]
            self.assertEqual(incidents[0]["traffic"][0]["requestCount"], 1)
            self.assertEqual(
                len([
                    record for record in incidents
                    if (record["id"], record["observedAt"], record["phase"])
                    == (incidents[0]["id"], incidents[0]["observedAt"], incidents[0]["phase"])
                ]),
                1,
            )


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
        maintenance_started = collector.sanitize_alert_line(
            "2026-08-19T01:02:06Z MAINTENANCE "
            "event=multtara-cksdb-cutover status=started raw=secret",
            "fallback",
        )
        maintenance_completed = collector.sanitize_alert_line(
            "2026-08-19T01:02:07Z MAINTENANCE "
            "event=multtara-cksdb-cutover status=completed",
            "fallback",
        )
        maintenance_rollback = collector.sanitize_alert_line(
            "2026-08-19T01:02:08Z MAINTENANCE "
            "event=multtara-cksdb-cutover status=rolled-back",
            "fallback",
        )
        contract = {"timestamp", "severity", "kind", "status", "message"}
        self.assertEqual(set(snapshot), contract)
        self.assertEqual(set(metrics), contract)
        self.assertEqual(set(recovered), contract)
        self.assertEqual(set(maintenance_started), contract)
        self.assertEqual(set(maintenance_completed), contract)
        self.assertEqual(set(maintenance_rollback), contract)
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
        self.assertEqual(maintenance_started, {
            "timestamp": "2026-08-19T01:02:06Z",
            "severity": "info",
            "kind": "topology",
            "status": "started",
            "message": "Multtara database cutover maintenance started.",
        })
        self.assertEqual(maintenance_completed["status"], "completed")
        self.assertEqual(maintenance_rollback["severity"], "warning")
        self.assertIsNone(collector.sanitize_alert_line("totally unrelated token=secret", "fallback"))
        self.assertIsNone(collector.sanitize_alert_line(
            "MAINTENANCE event=arbitrary status=started token=secret", "fallback"
        ))
        self.assertNotIn("secret", json.dumps([
            snapshot, metrics, recovered, maintenance_started,
            maintenance_completed, maintenance_rollback,
        ]))

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

    def test_kernel_reliability_lines_are_fixed_and_drop_raw_details(self):
        fallback = "2026-08-26T00:00:00Z"
        cases = (
            (
                "2026-08-26T00:00:01Z kernel: nvme nvme0: controller is down; will reset token=secret",
                "nvme-reset", "active",
            ),
            (
                "2026-08-26T00:00:02Z kernel: blk_update_request: I/O error, dev nvme0n1 pid=123",
                "nvme-io", "active",
            ),
            (
                "2026-08-26T00:00:03.123456Z kernel: rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks",
                "rcu-stall", "expedited",
            ),
            (
                "2026-08-26T00:00:03Z kernel: rcu: INFO: rcu_preempt detected stalls on CPUs/tasks",
                "rcu-stall", "active",
            ),
            (
                "2026-08-26T00:00:04Z kernel: Out of memory: Killed process 123 (private-name)",
                "oom-kill", "active",
            ),
            (
                "2026-08-26T00:00:05Z kernel: EXT4-fs error (device nvme0n1p2): private path",
                "filesystem-error", "active",
            ),
            (
                "2026-08-26T00:00:06Z kernel: eth0: Link is Down client=192.0.2.1",
                "network-link", "unavailable",
            ),
            (
                "2026-08-26T00:00:07Z kernel: eth0: Link is Up 1000 Mbps",
                "network-link", "recovered",
            ),
            (
                "2026-08-26T00:00:08Z pcieport 0000:00:00.0: AER: Corrected error received: secret",
                "pcie-aer", "correctable",
            ),
            (
                "2026-08-26T00:00:09Z pcieport 0000:00:00.0: AER: Uncorrectable (Non-Fatal) error received",
                "pcie-aer", "nonfatal",
            ),
            (
                "2026-08-26T00:00:10Z PCIe Bus Error: severity=Uncorrected (Fatal), type=secret",
                "pcie-aer", "fatal",
            ),
            (
                "2026-08-26T00:00:11Z brcm-pcie 1000110000.pcie: link down token=secret",
                "pcie-link", "down",
            ),
            (
                "2026-08-26T00:00:12Z pcieport 0000:00:00.0: link training failed",
                "pcie-link", "degraded",
            ),
            (
                "2026-08-26T00:00:13Z brcm-pcie 1000110000.pcie: link up, 2.5 GT/s PCIe x1",
                "pcie-link", "recovered",
            ),
            (
                "2026-08-26T00:00:14Z kernel: WARNING: CPU: 2 PID: 123 at private.c:4",
                "kernel-warning", "active",
            ),
            (
                "2026-08-26T00:00:15Z kernel: Internal error: Oops: 00000000 private",
                "kernel-oops", "active",
            ),
            (
                "2026-08-26T00:00:16Z kernel: Kernel panic - not syncing: private",
                "kernel-panic", "active",
            ),
            (
                "2026-08-26T00:00:17Z kernel: INFO: task secret-app:123 blocked for more than 120 seconds",
                "hung-task", "active",
            ),
        )
        for line, kind, status in cases:
            with self.subTest(kind=kind, status=status):
                record = collector.sanitize_kernel_reliability_line(line, fallback)
                self.assertIsNotNone(record)
                self.assertEqual(record["kind"], kind)
                self.assertEqual(record["status"], status)
                if status == "expedited":
                    self.assertEqual(record["timestamp"], "2026-08-26T00:00:03.123456Z")
                self.assertEqual(set(record), set(collector.RELIABILITY_FIELDS))
                self.assertEqual(collector.existing_reliability_record(record), record)
                encoded = json.dumps(record).lower()
                for forbidden in ("secret", "192.0.2.1", "private-name", "pid=123"):
                    self.assertNotIn(forbidden, encoded)

        self.assertIsNone(collector.sanitize_kernel_reliability_line(
            "2026-08-26T00:00:08Z unrelated password=secret", fallback
        ))
        valid = collector.reliability_event(fallback, "host-boot", "observed")
        self.assertIsNone(collector.existing_reliability_record({**valid, "raw": "secret"}))
        self.assertIsNone(collector.existing_reliability_record({**valid, "message": "changed"}))

    def test_tcp_listener_network_and_nvme_mitigation_observers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            (proc / "net").mkdir(parents=True)
            (sys_root / "class" / "net" / "eth0").mkdir(parents=True)
            (sys_root / "module" / "nvme_core" / "parameters").mkdir(parents=True)
            (sys_root / "module" / "pcie_aspm" / "parameters").mkdir(parents=True)
            header = "sl local_address rem_address st\n"
            (proc / "net" / "tcp").write_text(
                header + "0: 00000000:0016 00000000:0000 0A\n"
            )
            (proc / "net" / "tcp6").write_text(
                header + "1: 00000000000000000000000000000000:5606 00000000000000000000000000000000:0000 0A\n"
            )
            (sys_root / "class" / "net" / "eth0" / "carrier").write_text("1\n")
            (sys_root / "class" / "net" / "eth0" / "operstate").write_text("up\n")
            (sys_root / "module" / "nvme_core" / "parameters" / "default_ps_max_latency_us").write_text("0\n")
            (sys_root / "module" / "pcie_aspm" / "parameters" / "policy").write_text(
                "[performance] default powersave\n"
            )
            self.assertEqual(collector.parse_listening_tcp_ports(proc), {22, 22022})
            self.assertTrue(collector.observed_ssh_listeners(proc, {22, 22022}))
            self.assertTrue(collector.observed_network_link(sys_root, "eth0"))
            self.assertTrue(collector.observed_nvme_mitigation(sys_root))

            (proc / "cmdline").write_text(
                "root=LABEL=writable nvme_core.default_ps_max_latency_us=0 "
                "pcie_aspm=off pcie_port_pm=off\n"
            )
            (sys_root / "module" / "nvme_core" / "parameters" / "default_ps_max_latency_us").write_text("100000\n")
            (sys_root / "module" / "pcie_aspm" / "parameters" / "policy").write_text(
                "performance [default] powersave\n"
            )
            self.assertTrue(collector.observed_nvme_mitigation(sys_root, proc))
            (proc / "cmdline").write_text(
                "nvme_core.default_ps_max_latency_us=0 pcie_aspm=off\n"
            )
            self.assertFalse(collector.observed_nvme_mitigation(sys_root, proc))

            (proc / "net" / "tcp6").write_text(header)
            (sys_root / "class" / "net" / "eth0" / "carrier").write_text("0\n")
            self.assertFalse(collector.observed_ssh_listeners(proc, {22, 22022}))
            self.assertFalse(collector.observed_network_link(sys_root, "eth0"))


class FilesystemTests(unittest.TestCase):
    def test_atomic_write_leaves_complete_file_and_no_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "current.json"
            collector.atomic_write_json(path, {"ok": True})
            self.assertEqual(json.loads(path.read_text()), {"ok": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o750)
            self.assertEqual(list(path.parent.glob(".current.json.*")), [])

    def test_enospc_before_atomic_replace_preserves_prior_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "current.json"
            collector.atomic_write_json(path, {"generation": 1})
            prior = path.read_bytes()
            with mock.patch.object(
                collector.os,
                "replace",
                side_effect=OSError(28, "No space left on device"),
            ):
                with self.assertRaises(OSError):
                    collector.atomic_write_json(path, {"generation": 2})
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(path.parent.glob(".current.json.*")), [])

    def test_inode_exhaustion_before_jsonl_temp_creation_preserves_prior_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.jsonl"
            collector.rewrite_json_lines(path, [{"generation": 1}], 10)
            prior = path.read_bytes()
            with mock.patch.object(
                collector.tempfile,
                "NamedTemporaryFile",
                side_effect=OSError(28, "No space left on device"),
            ):
                with self.assertRaises(OSError):
                    collector.rewrite_json_lines(path, [{"generation": 2}], 10)
            self.assertEqual(path.read_bytes(), prior)
            self.assertEqual(list(path.parent.glob(".history.jsonl.*")), [])

    def test_large_bounded_delta_state_round_trips_without_default_truncation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "delta-state.json"
            processes = {
                f"{index:024x}": {
                    "cpuTicks": index,
                    "readBytes": index,
                    "writeBytes": index,
                    "name": "p" * 64,
                    "allowlisted": False,
                }
                for index in range(collector.MAX_PROCESS_STATE_ENTRIES)
            }
            payload = {"linux": {"processes": processes}}
            self.assertGreater(
                len(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
                1_048_576,
            )

            collector.atomic_write_json(
                path, payload, 0o600, collector.MAX_DELTA_STATE_BYTES
            )

            self.assertEqual(collector.load_json(path), {})
            self.assertEqual(
                collector.load_json(path, collector.MAX_DELTA_STATE_BYTES), payload
            )
            with self.assertRaisesRegex(ValueError, "size limit"):
                collector.atomic_write_json(path, {"large": "x" * 2048}, 0o600, 1024)
            self.assertEqual(
                collector.load_json(path, collector.MAX_DELTA_STATE_BYTES), payload
            )

    def test_private_json_loader_rejects_pathological_valid_size_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "delta-state.json"
            path.write_text('{"nested":' * 10_000 + "0" + "}" * 10_000)
            self.assertEqual(
                len(collector.load_json(path, collector.MAX_DELTA_STATE_BYTES)), 0
            )
            path.write_text('{"integer":' + "9" * 5_000 + "}")
            self.assertEqual(
                len(collector.load_json(path, collector.MAX_DELTA_STATE_BYTES)), 0
            )

    def test_identity_is_stable_and_rekeys_a_copied_state_on_machine_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            etc = root / "etc"
            proc = root / "proc"
            (proc / "sys" / "kernel" / "random").mkdir(parents=True)
            etc.mkdir()
            machine_one = "1" * 32
            machine_two = "2" * 32
            boot_id = "11111111-1111-4111-8111-111111111111"
            (etc / "machine-id").write_text(machine_one + "\n")
            (proc / "sys" / "kernel" / "random" / "boot_id").write_text(boot_id + "\n")
            config = collector.Config(
                output_dir=root / "output",
                runtime_dir=root / "run",
                etc_root=etc,
                proc_root=proc,
            )
            now = dt.datetime(2026, 8, 30, 0, 0, tzinfo=dt.timezone.utc)
            first_identity, first_heartbeat = collector.prepare_identity(config, now)
            second_identity, second_heartbeat = collector.prepare_identity(
                config, now + dt.timedelta(minutes=1),
            )
            self.assertEqual(second_identity, first_identity)
            self.assertEqual(first_heartbeat["sequence"], 1)
            self.assertEqual(second_heartbeat["sequence"], 2)
            self.assertEqual(first_identity["machineIdentityStatus"], "bound")
            self.assertRegex(first_identity["bootId"], r"^[0-9a-f]{32}$")
            self.assertNotEqual(first_identity["bootId"], boot_id.replace("-", ""))

            (etc / "machine-id").write_text(machine_two + "\n")
            third_identity, third_heartbeat = collector.prepare_identity(
                config, now + dt.timedelta(minutes=2),
            )
            self.assertNotEqual(third_identity["hostId"], first_identity["hostId"])
            self.assertNotEqual(third_identity["agentId"], first_identity["agentId"])
            self.assertEqual(third_identity["identityGeneration"], 2)
            self.assertEqual(third_heartbeat["sequence"], 1)
            self.assertNotIn(machine_one, json.dumps(first_identity))
            self.assertNotIn(machine_two, json.dumps(third_identity))
            identity_path = config.output_dir / ".state" / "collector-identity.json"
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)

    def test_identity_state_permissions_and_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            etc = root / "etc"
            etc.mkdir()
            (etc / "machine-id").write_text("3" * 32 + "\n")
            config = collector.Config(
                output_dir=root / "output",
                runtime_dir=root / "run",
                etc_root=etc,
                proc_root=root / "proc",
            )
            now = dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc)
            collector.prepare_identity(config, now)
            identity_path = config.output_dir / ".state" / "collector-identity.json"
            identity_path.chmod(0o640)
            with self.assertRaisesRegex(collector.PendingJournalError, "file validation"):
                collector.prepare_identity(config, now + dt.timedelta(minutes=1))

            identity_path.unlink()
            collector.atomic_write_json(identity_path, {"schemaVersion": 999}, 0o600)
            with self.assertRaisesRegex(collector.PendingJournalError, "schema validation"):
                collector.prepare_identity(config, now + dt.timedelta(minutes=1))

            self.assertIsNone(collector.opaque_uuid("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"))

    def test_reliability_boot_gap_transitions_and_crash_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            output = root / "output"
            (proc / "net").mkdir(parents=True)
            (proc / "sys" / "kernel" / "random").mkdir(parents=True)
            (sys_root / "class" / "net" / "eth0").mkdir(parents=True)
            (sys_root / "module" / "nvme_core" / "parameters").mkdir(parents=True)
            (sys_root / "module" / "pcie_aspm" / "parameters").mkdir(parents=True)
            header = "sl local_address rem_address st\n"

            def set_listeners(available):
                rows = (
                    "0: 00000000:0016 00000000:0000 0A\n"
                    "1: 00000000000000000000000000000000:5606 "
                    "00000000000000000000000000000000:0000 0A\n"
                ) if available else ""
                (proc / "net" / "tcp").write_text(header + rows)
                (proc / "net" / "tcp6").write_text(header)

            set_listeners(True)
            (proc / "sys" / "kernel" / "random" / "boot_id").write_text(
                "11111111-1111-4111-8111-111111111111\n"
            )
            (sys_root / "class" / "net" / "eth0" / "carrier").write_text("1\n")
            (sys_root / "class" / "net" / "eth0" / "operstate").write_text("up\n")
            (sys_root / "module" / "nvme_core" / "parameters" / "default_ps_max_latency_us").write_text("0\n")
            (sys_root / "module" / "pcie_aspm" / "parameters" / "policy").write_text(
                "[performance] default powersave\n"
            )
            kernel = root / "kern.log"
            kernel.write_text(
                "2026-08-26T00:00:00Z kernel: boot marker\n"
                "2026-08-26T00:09:01Z kernel: nvme nvme0: controller is down; will reset token=secret\n"
                "2026-08-26T00:09:02.100000Z kernel: rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks token=secret-a\n"
                "2026-08-26T00:09:02.200000Z kernel: rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks token=secret-b\n"
                "2026-08-26T00:09:02.900000Z kernel: rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks token=secret-c\n"
            )
            config = collector.Config(
                output_dir=output,
                runtime_dir=root / "run",
                proc_root=proc,
                sys_root=sys_root,
                kernel_log=kernel,
                ssh_ports={22, 22022},
                primary_interface="eth0",
                max_log_records=50,
            )
            first_now = dt.datetime(2026, 8, 26, 0, 10, tzinfo=dt.timezone.utc)
            first = collector.collect_reliability(config, first_now, 600)
            self.assertEqual(first, {
                "bootStartedAt": "2026-08-26T00:00:00Z",
                "collectorGapSeconds": None,
                "sshListenersAvailable": True,
                "networkLinkAvailable": True,
                "nvmeMitigationActive": True,
            })
            first_rows = [
                json.loads(line)
                for line in (output / "reliability.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                {row["kind"] for row in first_rows},
                {"host-boot", "nvme-mitigation", "nvme-reset", "rcu-stall"},
            )
            self.assertNotIn("secret", (output / "reliability.jsonl").read_text())
            self.assertEqual(
                stat.S_IMODE((output / ".state" / "reliability-state.json").stat().st_mode),
                0o600,
            )
            first_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(first_state["version"], 5)
            self.assertEqual(first_state["kernelSummary"]["nvmeReset"]["count"], 1)
            self.assertEqual(first_state["kernelSummary"]["warning"]["count"], 0)
            self.assertEqual(first_state["kernelSummary"]["rcuExpedited"]["count"], 3)
            self.assertEqual(first_state["kernelSummary"]["rcuStall"]["count"], 0)

            legacy_v4_state = json.loads(json.dumps(first_state))
            legacy_v4_state["version"] = 4
            legacy_v4_state["kernelSummary"]["rcuExpedited"] = {
                "count": 1,
                "lastEventAt": "2026-08-26T00:09:02Z",
            }
            kernel.rename(root / "kern.log.1")
            kernel.write_text("")
            current_kernel_metadata = kernel.stat()
            legacy_v4_state["kernelCursor"] = {
                "inode": current_kernel_metadata.st_ino,
                "offset": current_kernel_metadata.st_size,
            }
            (output / ".state" / "reliability-state.json").write_text(
                json.dumps(legacy_v4_state) + "\n"
            )
            rows_before_backfill = (output / "reliability.jsonl").read_text()
            collector.collect_reliability(config, first_now, 600)
            backfilled_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(backfilled_state["version"], 5)
            self.assertEqual(
                backfilled_state["kernelSummary"]["rcuExpedited"],
                {"count": 3, "lastEventAt": "2026-08-26T00:09:02.900000Z"},
            )
            self.assertEqual(
                (output / "reliability.jsonl").read_text(), rows_before_backfill
            )
            collector.collect_reliability(config, first_now, 600)
            self.assertEqual(
                json.loads(
                    (output / ".state" / "reliability-state.json").read_text()
                )["kernelSummary"]["rcuExpedited"]["count"],
                3,
            )
            with kernel.open("a") as handle:
                handle.write(
                    "2026-08-26T00:09:03.100000Z kernel: rcu: INFO: "
                    "rcu_preempt detected expedited stalls on CPUs/tasks raw=secret-d\n"
                )
            collector.collect_reliability(config, first_now, 600)
            after_append_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(
                after_append_state["kernelSummary"]["rcuExpedited"]["count"], 4
            )

            legacy_v2_state = json.loads(json.dumps(after_append_state))
            legacy_v2_state["version"] = 2
            legacy_v2_state["kernelSummary"].pop("rcuExpedited")
            legacy_v2_state["kernelSummary"]["warning"] = {
                "count": 5, "lastEventAt": "2026-08-26T00:09:02Z",
            }
            self.assertEqual(
                collector.existing_reliability_state(legacy_v2_state)["version"], 2
            )
            (output / ".state" / "reliability-state.json").write_text(
                json.dumps(legacy_v2_state) + "\n"
            )
            collector.collect_reliability(config, first_now, 600)
            migrated_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(migrated_state["version"], 5)
            self.assertEqual(migrated_state["kernelSummary"]["nvmeReset"]["count"], 1)
            self.assertEqual(migrated_state["kernelSummary"]["warning"]["count"], 0)
            self.assertEqual(migrated_state["kernelSummary"]["rcuExpedited"]["count"], 4)
            self.assertEqual(migrated_state["kernelSummary"]["rcuStall"]["count"], 0)
            legacy_v1_state = {
                key: value
                for key, value in migrated_state.items()
                if key != "kernelSummary"
            }
            legacy_v1_state["version"] = 1
            (output / ".state" / "reliability-state.json").write_text(
                json.dumps(legacy_v1_state) + "\n"
            )
            collector.collect_reliability(config, first_now, 600)
            migrated_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(migrated_state["version"], 5)
            self.assertEqual(migrated_state["kernelSummary"]["nvmeReset"]["count"], 1)
            self.assertEqual(migrated_state["kernelSummary"]["warning"]["count"], 0)
            self.assertEqual(migrated_state["kernelSummary"]["rcuExpedited"]["count"], 4)
            self.assertEqual(migrated_state["kernelSummary"]["rcuStall"]["count"], 0)
            migrated_rows = [
                json.loads(line)
                for line in (output / "reliability.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                sum(row["kind"] == "rcu-stall" for row in migrated_rows), 4
            )
            first_rows = migrated_rows

            (proc / "sys" / "kernel" / "random" / "boot_id").write_text(
                "22222222-2222-4222-8222-222222222222\n"
            )
            set_listeners(False)
            (sys_root / "class" / "net" / "eth0" / "carrier").write_text("0\n")
            with kernel.open("a") as handle:
                handle.write(
                    "2026-08-26T00:14:30Z kernel: Out of memory: Killed process 999 secret-app\n"
                )
            second_now = dt.datetime(2026, 8, 26, 0, 15, tzinfo=dt.timezone.utc)
            second = collector.collect_reliability(config, second_now, 60)
            self.assertEqual(second["bootStartedAt"], "2026-08-26T00:14:00Z")
            self.assertEqual(second["collectorGapSeconds"], 300)
            self.assertFalse(second["sshListenersAvailable"])
            self.assertFalse(second["networkLinkAvailable"])
            rows = [
                json.loads(line)
                for line in (output / "reliability.jsonl").read_text().splitlines()
            ]
            latest_kinds = {row["kind"] for row in rows[len(first_rows):]}
            self.assertEqual(
                latest_kinds,
                {"host-boot", "collector-gap", "ssh-listener", "network-link", "oom-kill"},
            )
            gap = next(row for row in rows if row["kind"] == "collector-gap")
            self.assertEqual(gap["durationSeconds"], 300)
            second_state = json.loads(
                (output / ".state" / "reliability-state.json").read_text()
            )
            self.assertEqual(second_state["kernelSummary"]["nvmeReset"]["count"], 0)
            self.assertEqual(second_state["kernelSummary"]["rcuStall"]["count"], 0)
            self.assertEqual(second_state["kernelSummary"]["rcuExpedited"]["count"], 0)
            self.assertEqual(second_state["kernelSummary"]["oomKill"], {
                "count": 1, "lastEventAt": "2026-08-26T00:14:30Z",
            })

            # A crash after the event file but before private state publication
            # is replayed idempotently on the next run.
            set_listeners(True)
            (sys_root / "class" / "net" / "eth0" / "carrier").write_text("1\n")
            original_atomic = collector.atomic_write_json

            def fail_reliability_state(path, value, mode=0o640):
                if Path(path).name == "reliability-state.json":
                    raise OSError("injected reliability state failure")
                return original_atomic(path, value, mode)

            third_now = dt.datetime(2026, 8, 26, 0, 16, tzinfo=dt.timezone.utc)
            with mock.patch.object(
                collector, "atomic_write_json", side_effect=fail_reliability_state
            ):
                with self.assertRaises(OSError):
                    collector.collect_reliability(config, third_now, 120)
            pending = output / ".state" / "pending-reliability-commit.json"
            self.assertTrue(pending.is_file())
            collector.collect_reliability(
                config, third_now + dt.timedelta(minutes=1), 180
            )
            self.assertFalse(pending.exists())
            final_rows = [
                json.loads(line)
                for line in (output / "reliability.jsonl").read_text().splitlines()
            ]
            recovered = [
                row for row in final_rows
                if row["kind"] in {"ssh-listener", "network-link"}
                and row["status"] == "recovered"
            ]
            self.assertEqual(len(recovered), 2)

    def test_first_reliability_run_infers_existing_history_gap_around_boot(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            history = output / "history"
            history.mkdir(parents=True)
            samples = (
                incident_metrics("2026-08-26T00:03:00Z"),
                incident_metrics("2026-08-26T00:11:00Z"),
                incident_metrics("2026-08-26T00:12:00Z"),
            )
            (history / "2026-08-26.jsonl").write_text(
                "".join(json.dumps(sample) + "\n" for sample in samples)
            )
            config = collector.Config(output_dir=output)
            boot_started = dt.datetime(2026, 8, 26, 0, 10, tzinfo=dt.timezone.utc)
            self.assertEqual(
                collector.historical_collector_gap_at_boot(config, boot_started),
                8 * 60,
            )

    def test_line_cursor_preserves_appends_partial_tails_rotation_and_line_caps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "events.log"
            path.write_bytes(b"old\n")
            lines, cursor = collector.read_new_lines(path, {}, 1024, 64)
            self.assertEqual(lines, ["old"])

            with path.open("ab") as handle:
                handle.write(b"first\nsecond\npartial")
            lines, cursor = collector.read_new_lines(path, cursor, 1024, 64)
            self.assertEqual(lines, ["first", "second"])
            self.assertEqual(cursor["offset"], len(b"old\nfirst\nsecond\n"))

            with path.open("ab") as handle:
                handle.write(b"-done\nnext\nhalf")
            lines, cursor = collector.read_new_lines(path, cursor, 1024, 64)
            self.assertEqual(lines, ["partial-done", "next"])
            with path.open("ab") as handle:
                handle.write(b"-end\n")
            lines, cursor = collector.read_new_lines(path, cursor, 1024, 64)
            self.assertEqual(lines, ["half-end"])

            with path.open("ab") as handle:
                handle.write(b"late-on-old-inode\n")
            rotated = root / "events.log.1"
            path.rename(rotated)
            path.write_bytes(b"first-on-new-inode\n")
            lines, cursor = collector.read_new_lines(path, cursor, 1024, 64)
            self.assertEqual(lines, ["late-on-old-inode", "first-on-new-inode"])
            self.assertEqual(cursor["inode"], path.stat().st_ino)

            tail = root / "tail.log"
            tail.write_bytes(b"x" * 30 + b"\nkept\n")
            lines, _cursor = collector.read_new_lines(tail, {}, 16, 16)
            self.assertEqual(lines, ["kept"])

            boundary = root / "boundary.log"
            boundary.write_bytes(b"skip\nfirst\nsecond\n")
            lines, _cursor = collector.read_new_lines(boundary, {}, 13, 13)
            self.assertEqual(lines, ["first", "second"])

            oversized = root / "oversized.log"
            oversized.write_bytes(b"x" * 20)
            lines, oversized_cursor = collector.read_new_lines(oversized, {}, 64, 8)
            self.assertEqual(lines, [])
            self.assertTrue(oversized_cursor["discardUntilNewline"])
            with oversized.open("ab") as handle:
                handle.write(b"\nok\n")
            lines, oversized_cursor = collector.read_new_lines(
                oversized, oversized_cursor, 64, 8
            )
            self.assertEqual(lines, ["ok"])
            self.assertNotIn("discardUntilNewline", oversized_cursor)

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

    def test_sanitized_log_commit_replays_every_fault_and_freezes_synthetic_power_row(self):
        for fault_point in ("alerts", "power", "privilege", "cursor", "remove"):
            with self.subTest(fault_point=fault_point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                events = root / "events.log"
                kernel = root / "kern.log"
                privilege = root / "privilege.log"
                events.write_text(
                    "2026-08-23T05:00:01Z SNAPSHOT reason=cpu-high raw=secret\n"
                )
                kernel.write_text(
                    "2026-08-23T05:00:02Z host kernel: Undervoltage detected! raw=secret\n"
                )
                privilege.write_text(json.dumps({
                    "timestamp": "2026-08-23T05:00:03Z", "actor": "cks", "target": "root",
                    "action": "sudo", "result": "allowed", "command": "do-not-export",
                }) + "\n")
                config = collector.Config(
                    output_dir=root / "out", runtime_dir=root / "run",
                    events_log=events, kernel_log=kernel, privilege_logs=[privilege],
                    traffic_log=None, docker_sockets={},
                )
                patcher = None
                if fault_point in {"alerts", "power", "privilege"}:
                    original_rewrite = collector.rewrite_json_lines

                    def fail_output(path, records, limit, target=fault_point):
                        if Path(path).name == f"{target}.jsonl":
                            raise OSError("output write injected")
                        return original_rewrite(path, records, limit)

                    patcher = mock.patch.object(
                        collector, "rewrite_json_lines", side_effect=fail_output
                    )
                elif fault_point == "cursor":
                    original_atomic = collector.atomic_write_json

                    def fail_cursor(path, value, mode=0o640):
                        if Path(path).name == "log-cursors.json":
                            raise OSError("cursor write injected")
                        return original_atomic(path, value, mode)

                    patcher = mock.patch.object(
                        collector, "atomic_write_json", side_effect=fail_cursor
                    )
                else:
                    patcher = mock.patch.object(
                        collector, "discard_pending_sanitized_log_commit", return_value=False
                    )

                with patcher:
                    with self.assertRaises(OSError):
                        collector.export_sanitized_logs(config, "2026-08-23T05:01:00Z", {
                            "throttledFlags": 0x50005, "supplyVoltageVolts": 4.8119,
                        })
                pending_path = (
                    config.output_dir / ".state" / "pending-sanitized-log-commit.json"
                )
                self.assertTrue(pending_path.is_file())
                self.assertEqual(stat.S_IMODE(pending_path.stat().st_mode), 0o600)
                pending_text = pending_path.read_text()
                self.assertLessEqual(
                    len(pending_text.encode()),
                    collector.MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES,
                )
                self.assertNotIn("secret", pending_text.lower())
                self.assertNotIn("do-not-export", pending_text.lower())

                # Replay happens before this different sample can synthesize a
                # second transition with a new timestamp or voltage.
                collector.export_sanitized_logs(config, "2026-08-23T05:02:00Z", {
                    "throttledFlags": 0x50005, "supplyVoltageVolts": 4.1,
                })
                alerts = [
                    json.loads(line)
                    for line in (config.output_dir / "alerts.jsonl").read_text().splitlines()
                ]
                synthetic = [row for row in alerts if row["kind"] == "power"]
                self.assertEqual(len(alerts), 2)
                self.assertEqual(len(synthetic), 1)
                self.assertEqual(synthetic[0]["timestamp"], "2026-08-23T05:01:00Z")
                self.assertIn("4.812 V", synthetic[0]["message"])
                self.assertNotIn("4.100 V", synthetic[0]["message"])
                self.assertEqual(
                    len((config.output_dir / "power.jsonl").read_text().splitlines()), 1
                )
                self.assertEqual(
                    len((config.output_dir / "privilege.jsonl").read_text().splitlines()), 1
                )
                self.assertFalse(pending_path.exists())
                self.assertTrue(
                    (config.output_dir / ".state" / "log-cursors.json").is_file()
                )

    def test_identical_public_alert_and_privilege_rows_remain_distinct_source_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_line = "2026-08-23T05:10:01Z SNAPSHOT reason=cpu-high\n"
            privilege_line = json.dumps({
                "timestamp": "2026-08-23T05:10:02Z", "actor": "cks", "target": "root",
                "action": "sudo", "result": "allowed",
            }) + "\n"
            events = root / "events.log"
            privilege = root / "privilege.log"
            events.write_text(event_line * 2)
            privilege.write_text(privilege_line * 2)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                events_log=events, kernel_log=root / "missing-kernel",
                privilege_logs=[privilege], traffic_log=None, docker_sockets={},
            )
            collector.export_sanitized_logs(config, "2026-08-23T05:11:00Z")
            alerts = [
                json.loads(line)
                for line in (config.output_dir / "alerts.jsonl").read_text().splitlines()
            ]
            privileges = [
                json.loads(line)
                for line in (config.output_dir / "privilege.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(alerts), 2)
            self.assertEqual(alerts[0], alerts[1])
            self.assertEqual(len(privileges), 2)
            self.assertEqual(privileges[0], privileges[1])

            collector.export_sanitized_logs(config, "2026-08-23T05:12:00Z")
            self.assertEqual(
                len((config.output_dir / "alerts.jsonl").read_text().splitlines()), 2
            )
            self.assertEqual(
                len((config.output_dir / "privilege.jsonl").read_text().splitlines()), 2
            )

    def test_sanitized_pending_journal_and_output_divergence_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
                events_log=root / "events", kernel_log=root / "kernel",
                privilege_logs=[], traffic_log=None, docker_sockets={},
            )
            state_dir = config.output_dir / ".state"
            state_dir.mkdir(parents=True)
            pending_path = state_dir / "pending-sanitized-log-commit.json"
            unsafe = b'{"rawClient":"must-remain-for-recovery"}\n'
            pending_path.write_bytes(unsafe)
            pending_path.chmod(0o600)
            with self.assertRaises(collector.PendingJournalError):
                collector.load_pending_sanitized_log_commit(config, pending_path)
            self.assertEqual(pending_path.read_bytes(), unsafe)
            with self.assertRaises(collector.PendingJournalError):
                collector.write_pending_sanitized_log_commit(config, {
                    "alerts": [], "power": [], "privilege": [],
                }, {
                    "alerts": {}, "kernelPower": {}, "privilege": {}, "powerFlags": None,
                })
            self.assertEqual(pending_path.read_bytes(), unsafe)
            pending_path.unlink()

            alert = collector.sanitize_alert_line(
                "2026-08-23T05:20:01Z SNAPSHOT reason=cpu-high",
                "2026-08-23T05:21:00Z",
            )
            collector.write_pending_sanitized_log_commit(config, {
                "alerts": [alert], "power": [], "privilege": [],
            }, {
                "alerts": {}, "kernelPower": {}, "privilege": {}, "powerFlags": None,
            })
            divergent = collector.sanitize_alert_line(
                "2026-08-23T05:20:02Z SNAPSHOT reason=memory-low",
                "2026-08-23T05:21:00Z",
            )
            collector.rewrite_json_lines(
                config.output_dir / "alerts.jsonl", [divergent], config.max_log_records
            )
            with self.assertRaises(collector.PendingJournalError):
                collector.replay_pending_sanitized_log_commit(config)
            self.assertTrue(pending_path.is_file())
            self.assertFalse((state_dir / "log-cursors.json").exists())
            self.assertEqual(
                json.loads((config.output_dir / "alerts.jsonl").read_text()), divergent
            )

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
            (proc / "net" / "dev").write_text(
                "eth0: 100 0 1 3 0 0 0 0 200 0 2 4 0 0 0 0\n"
            )
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
            docker_available = [True]

            def fake_docker(_socket, path, _curl, _timeout):
                if "containers/json" in path:
                    if not docker_available[0]:
                        return None
                    return [{
                        "Id": container_id, "Names": ["/fixture"], "State": "running",
                        "Labels": {
                            "com.docker.compose.project": "monitor",
                            "com.docker.compose.service": "monitor",
                        },
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
                 mock.patch.object(collector, "docker_get", side_effect=fake_docker), \
                 mock.patch.object(collector, "_sample_monotonic", side_effect=[100.0, 160.0, 220.0]):
                current = collector.run(config, now)
                first_delta_state = json.loads((runtime / "delta-state.json").read_text())
                docker_sample[0] = 1
                (proc / "net" / "dev").write_text(
                    "eth0: 700 0 7 9 0 0 0 0 800 0 8 10 0 0 0 0\n"
                )
                second = collector.run(config, now + dt.timedelta(minutes=1))
                docker_available[0] = False
                third = collector.run(config, now + dt.timedelta(minutes=2))

            self.assertEqual(set(current), {
                "schemaVersion", "generatedAt", "identity", "heartbeat",
                "host", "latest", "disks", "containers",
                "containerCollection", "dockerEventCollection", "dockerEvents",
                "syntheticProbeCollection", "syntheticProbes",
                "currentTraffic", "reliability", "system", "linux",
            })
            self.assertEqual(current["schemaVersion"], collector.CURRENT_SCHEMA_VERSION)
            self.assertEqual(set(current["identity"]), {
                "hostId", "agentId", "installationEpoch", "identityGeneration",
                "machineIdentityStatus", "bootId",
            })
            self.assertIsNotNone(collector.opaque_uuid(current["identity"]["hostId"]))
            self.assertIsNotNone(collector.opaque_uuid(current["identity"]["agentId"]))
            self.assertEqual(current["identity"]["identityGeneration"], 1)
            self.assertEqual(current["identity"]["machineIdentityStatus"], "unavailable")
            self.assertIsNone(current["identity"]["bootId"])
            self.assertEqual(current["heartbeat"], {
                "sequence": 1,
                "observedAt": current["generatedAt"],
                "receivedAt": current["generatedAt"],
                "expectedIntervalSeconds": 60,
                "lifecycle": "active",
                "transport": "local-file",
            })
            self.assertEqual(second["identity"], current["identity"])
            self.assertEqual(third["identity"], current["identity"])
            self.assertEqual(second["heartbeat"]["sequence"], 2)
            self.assertEqual(third["heartbeat"]["sequence"], 3)
            identity_path = output / ".state" / "collector-identity.json"
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)
            self.assertEqual(current["containerCollection"], {
                "status": "fresh", "observedAt": current["generatedAt"],
            })
            self.assertEqual(second["containerCollection"], {
                "status": "fresh", "observedAt": second["generatedAt"],
            })
            self.assertEqual(third["containerCollection"], {
                "status": "last-known", "observedAt": second["generatedAt"],
            })
            self.assertEqual(third["containers"], second["containers"])
            self.assertEqual(third["latest"]["timestamp"], collector.iso_timestamp(
                now + dt.timedelta(minutes=2)
            ))
            self.assertEqual(current["currentTraffic"], [])
            self.assertEqual(set(current["host"]), {
                "hostname", "os", "architecture", "logicalCpuCount", "uptimeSeconds",
            })
            self.assertIsNone(current["host"]["logicalCpuCount"])
            self.assertEqual(set(current["reliability"]), {
                "bootStartedAt", "collectorGapSeconds", "sshListenersAvailable",
                "networkLinkAvailable", "nvmeMitigationActive",
            })
            self.assertEqual(set(current["system"]), {"versions", "pcie", "kernel"})
            self.assertEqual(current["linux"]["schemaVersion"], 1)
            self.assertEqual(current["linux"]["collectedAt"], current["generatedAt"])
            self.assertEqual(current["linux"]["privacy"], {
                "processCommandLinesCollected": False,
                "processEnvironmentsCollected": False,
                "rawKernelMessagesCollected": False,
            })
            self.assertEqual(current["linux"]["cpu"]["status"], "invalid")
            self.assertEqual(current["linux"]["memory"]["status"], "invalid")
            self.assertEqual(current["linux"]["blockDevices"]["status"], "invalid")
            self.assertEqual(current["linux"]["network"]["status"], "supported")
            self.assertEqual(
                second["linux"]["network"]["items"][0]["counterIdentityStatus"],
                "unsupported",
            )
            self.assertEqual(second["linux"]["network"]["items"][0]["rateStatus"], "warmup")
            self.assertIsNone(second["linux"]["network"]["items"][0]["rxBytesPerSecond"])
            self.assertEqual(tuple(current["latest"]), collector.SAMPLE_FIELDS)
            for field_name in (
                "cpuPercent", "memoryPercent", "memoryUsedBytes", "memoryTotalBytes",
                "swapTotalBytes", "swapUsedBytes", "swapPercent",
                "load1", "load5", "load15",
                "cpuPressureSomeAvg10", "cpuPressureFullAvg10",
                "memoryPressureSomeAvg10", "memoryPressureFullAvg10",
                "ioPressureSomeAvg10", "ioPressureFullAvg10",
                "networkRxBytesPerSecond",
                "networkTxBytesPerSecond",
                "networkRxErrorsPerSecond", "networkTxErrorsPerSecond",
                "networkRxDroppedPerSecond", "networkTxDroppedPerSecond",
                "diskReadBytesPerSecond",
                "diskWriteBytesPerSecond",
            ):
                self.assertIsNone(current["latest"][field_name], field_name)
            self.assertEqual(current["latest"]["powerState"], "degraded-history")
            self.assertEqual(current["latest"]["supplyVoltageVolts"], 4.87)
            self.assertEqual(current["latest"]["throttledFlags"], 0x50000)
            self.assertEqual(current["latest"]["gpuMemoryBytes"], 4 * 1024 ** 2)
            self.assertEqual(current["latest"]["gpuClockHz"], 500_000_000)
            self.assertEqual(set(current["disks"][0]), {
                "mount", "totalBytes", "usedBytes", "availableBytes", "usedPercent",
                "inodeUsedPercent", "readOnly",
            })
            self.assertIsNone(current["containers"][0]["cpuPercent"])
            self.assertEqual(current["containers"][0]["memoryBytes"], 40)
            self.assertEqual(second["containers"][0]["cpuPercent"], 20.0)
            self.assertEqual(second["latest"]["networkRxBytesPerSecond"], 10.0)
            self.assertEqual(second["latest"]["networkTxBytesPerSecond"], 10.0)
            self.assertEqual(second["latest"]["networkRxErrorsPerSecond"], 0.1)
            self.assertEqual(second["latest"]["networkTxErrorsPerSecond"], 0.1)
            self.assertEqual(second["latest"]["networkRxDroppedPerSecond"], 0.1)
            self.assertEqual(second["latest"]["networkTxDroppedPerSecond"], 0.1)
            self.assertIn(f"cks:{container_id}", first_delta_state["containers"])
            self.assertEqual(stat.S_IMODE((runtime / "delta-state.json").stat().st_mode), 0o600)
            self.assertNotIn(container_id, (output / "current.json").read_text())
            self.assertNotIn("secret", (output / "current.json").read_text())
            rule_evaluation = json.loads((output / "rule-evaluation.json").read_text())
            self.assertEqual(rule_evaluation["status"], "ok")
            self.assertEqual(rule_evaluation["rulePackVersion"], "2026.08.31.2")
            self.assertEqual(
                {state["ruleId"] for state in rule_evaluation["states"].values()},
                {rule["id"] for rule in json.loads(collector.DEFAULT_RULE_PACK_PATH.read_text())["rules"]},
            )
            self.assertEqual(stat.S_IMODE((output / ".state" / "rule-state.json").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((output / "rule-alerts.jsonl").stat().st_mode), 0o640)
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
            self.assertEqual(len(history), 4)
            self.assertTrue(all(tuple(sample) == collector.SAMPLE_FIELDS for sample in history))
            self.assertEqual(
                [sample["supplyVoltageVolts"] for sample in history],
                [None, 4.87, 4.87, 4.87],
            )
            self.assertEqual(
                [sample["throttledFlags"] for sample in history],
                [None, 0x50000, 0x50000, 0x50000],
            )
            self.assertEqual(
                [sample["networkRxErrorsPerSecond"] for sample in history],
                [None, None, 0.1, 0.0],
            )
            self.assertTrue((runtime / "delta-state.json").is_file())

    def test_bounded_exports_keep_newest_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "alerts.jsonl"
            collector.rewrite_json_lines(path, [{"n": value} for value in range(30)], 10)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["n"] for record in records], list(range(20, 30)))
            path.write_text('{"n":1}\n' + json.dumps({"padding": "x" * 200}) + '\n{"n":2}\n')
            self.assertEqual(
                collector.existing_json_lines(path, 10, 4096, 100),
                [{"n": 1}, {"n": 2}],
            )

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
                "Current hwmon power flags are 0x5. Full flags are 0x00050005. "
                "Supply voltage is 4.812 V.",
            )
            self.assertEqual(
                records[1]["message"],
                "Current hwmon power condition recovered. Full flags are 0x00050000. "
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
        self.assertEqual(config.package_root, Path("/"))
        self.assertEqual(config.kernel_max_input_bytes, 8_388_608)
        self.assertEqual(config.command_timeout, 2.0)
        self.assertEqual(config.expected_interval_seconds, 60)
        self.assertEqual(config.agent_lifecycle, "active")
        self.assertEqual(config.traffic_log, Path("/var/log/nginx/monitor-traffic.jsonl"))
        self.assertEqual(config.docker_sockets, {"cks": Path("/run/user/1001/docker.sock")})
        self.assertEqual(config.process_uids, {0, 1001})
        self.assertEqual(config.process_allowlist, set())
        self.assertEqual(config.systemd_units, set())
        self.assertEqual(config.systemctl, "/usr/bin/systemctl")
        self.assertEqual(config.timedatectl, "/usr/bin/timedatectl")
        self.assertEqual(config.systemd_state_dir, Path("/run/systemd/units"))
        self.assertEqual(config.docker_data_root, Path("/var/lib/docker"))
        self.assertEqual(config.ssh_ports, {22, 22022})
        self.assertEqual(config.primary_interface, "eth0")
        self.assertEqual(config.incident_retention_days, 30)
        self.assertEqual(config.max_incident_records, 1000)
        self.assertEqual(config.cpu_warn_samples, 2)
        self.assertEqual(config.rule_pack, collector.DEFAULT_RULE_PACK_PATH)
        self.assertEqual(
            config.log_sources_config, Path("/etc/monitor-collector/log-sources.json")
        )
        self.assertFalse(config.log_sources_required)
        self.assertEqual(config.generic_log_max_records, 20_000)
        self.assertEqual(config.generic_log_max_file_bytes, 16 * 1024 * 1024)
        bounded_logs = collector.config_from_environment([
            "--generic-log-max-records", "1000000",
            "--generic-log-max-file-bytes", str(1024 * 1024 * 1024),
        ])
        self.assertEqual(bounded_logs.generic_log_max_records, 20_000)
        self.assertEqual(bounded_logs.generic_log_max_file_bytes, 16 * 1024 * 1024)
        self.assertEqual(config.memory_available_warn_percent, 20)
        self.assertEqual(config.memory_available_recover_percent, 25)
        self.assertEqual(config.load_warn, 4)
        self.assertEqual(config.disk_io_warn_bytes_per_second, 100 * 1024 * 1024)
        restricted = collector.config_from_environment([
            "--docker-sockets", "foreign=/run/user/9999/docker.sock,cks=/tmp/not-allowed.sock",
            "--process-uids", "0,1001,9999",
        ])
        self.assertEqual(restricted.docker_sockets, {})
        self.assertEqual(restricted.process_uids, {0, 1001})
        configured = collector.config_from_environment([
            "--process-allowlist", "nginx,python3,bad value,api-token-worker",
            "--systemd-units", "nginx.service,ssh.service,bad;unit.service",
            "--docker-data-root", "/srv/docker",
        ])
        self.assertEqual(configured.process_allowlist, {"nginx", "python3"})
        self.assertEqual(configured.systemd_units, {"nginx.service", "ssh.service"})
        self.assertEqual(configured.docker_data_root, Path("/srv/docker"))
        self.assertEqual(
            collector.safe_absolute_path("../../unsafe", "/var/lib/docker"),
            Path("/var/lib/docker"),
        )
        self.assertEqual(collector.parse_uid_set(""), set())
        clamped = collector.config_from_environment([
            "--cpu-warn-percent", "80", "--cpu-recover-percent", "90",
            "--memory-available-warn-percent", "20",
            "--memory-available-recover-percent", "10",
            "--load-warn", "4", "--load-recover", "9",
            "--disk-io-warn-bytes-per-second", "100",
            "--disk-io-recover-bytes-per-second", "200",
            "--traffic-request-warn", "300", "--traffic-request-recover", "500",
            "--expected-interval-seconds", "1", "--agent-lifecycle", "maintenance",
        ])
        self.assertEqual(clamped.cpu_recover_percent, 80)
        self.assertEqual(clamped.memory_available_recover_percent, 20)
        self.assertEqual(clamped.load_recover, 4)
        self.assertEqual(clamped.disk_io_recover_bytes_per_second, 100)
        self.assertEqual(clamped.traffic_request_recover, 300)
        self.assertEqual(clamped.expected_interval_seconds, 10)
        self.assertEqual(clamped.agent_lifecycle, "maintenance")
        ops_root = Path(__file__).resolve().parents[1]
        unit = (ops_root / "systemd" / "monitor-collector.service").read_text()
        exporter_unit = (ops_root / "systemd" / "monitor-container-exporter.service").read_text()
        defaults = (ops_root / "monitor-collector.default").read_text()
        installer = (ops_root / "install.sh").read_text()
        self.assertIn("Group=cks", unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)
        self.assertIn("BindPaths=-/dev/vcio", unit)
        self.assertIn("DeviceAllow=/dev/vcio rw", unit)
        self.assertIn("InaccessiblePaths=/home /root", unit)
        self.assertIn("MONITOR_PACKAGE_ROOT=/", defaults)
        self.assertIn("TemporaryFileSystem=/run:ro", unit)
        self.assertIn("BindPaths=/run/monitor-collector", unit)
        self.assertIn("Wants=monitor-container-exporter.service", unit)
        self.assertNotIn("Requires=monitor-container-exporter.service", unit)
        self.assertIn("BindReadOnlyPaths=-/run/monitor-container-exporter/containers.json", unit)
        self.assertNotIn("/run/user/1001/docker.sock", unit)
        self.assertIn("User=cks", exporter_unit)
        self.assertNotIn("ProtectHome=", exporter_unit)
        self.assertIn("InaccessiblePaths=/home /root", exporter_unit)
        self.assertIn("TemporaryFileSystem=/run:ro", exporter_unit)
        self.assertIn("BindReadOnlyPaths=/run/user/1001/docker.sock", exporter_unit)
        self.assertIn("ReadOnlyPaths=/proc /sys /var/log", unit)
        self.assertIn("MemoryHigh=160M", unit)
        self.assertIn("MemoryMax=192M", unit)
        self.assertIn("TasksMax=64", unit)
        self.assertIn("MONITOR_KERNEL_LOG=/var/log/kern.log", defaults)
        self.assertIn("MONITOR_EXPECTED_INTERVAL_SECONDS=60", defaults)
        self.assertIn("MONITOR_AGENT_LIFECYCLE=active", defaults)
        self.assertIn("MONITOR_KERNEL_MAX_INPUT_BYTES=8388608", defaults)
        self.assertIn("MONITOR_RULE_PACK=/usr/local/lib/monitor-collector/rules/default-rules.v1.json", defaults)
        self.assertIn("MONITOR_LOG_SOURCES_CONFIG=/etc/monitor-collector/log-sources.json", defaults)
        self.assertIn("MONITOR_GENERIC_LOG_MAX_RECORDS=20000", defaults)
        self.assertIn("MONITOR_TRAFFIC_LOG=/var/log/nginx/monitor-traffic.jsonl", defaults)
        self.assertIn("MONITOR_DOCKER_SOCKETS=\n", defaults)
        self.assertIn("MONITOR_CONTAINER_INPUT=/run/monitor-container-exporter/containers.json", defaults)
        self.assertIn("MONITOR_PROCESS_UIDS=0,1001", defaults)
        self.assertIn("MONITOR_PROCESS_ALLOWLIST=", defaults)
        self.assertIn("MONITOR_SYSTEMD_UNITS=monitor-collector.service", defaults)
        self.assertIn("MONITOR_SYSTEMCTL=/usr/bin/systemctl", defaults)
        self.assertIn("MONITOR_TIMEDATECTL=/usr/bin/timedatectl", defaults)
        self.assertIn("MONITOR_SYSTEMD_STATE_DIR=/run/systemd/units", defaults)
        self.assertIn("MONITOR_DOCKER_DATA_ROOT=/var/lib/docker", defaults)
        self.assertIn("BindReadOnlyPaths=-/run/systemd/units -/run/systemd/timesync", unit)
        self.assertIn("MONITOR_SSH_PORTS=22,22022", defaults)
        self.assertIn("MONITOR_PRIMARY_INTERFACE=eth0", defaults)
        self.assertIn("MONITOR_CPU_WARN_SAMPLES=2", defaults)
        self.assertIn("-o root -g cks -m 0750 /var/lib/monitor-export", installer)
        self.assertIn('had_default=false', installer)
        self.assertIn('restore_file "$backup_dir/monitor-collector.default" "$default_target" "$had_default"', installer)
        self.assertIn('install -m 0640 "$script_dir/monitor-collector.default" "$default_target"', installer)
        self.assertIn('install -m 0644 "$script_dir/alert_store.py" "$alert_store_target"', installer)
        self.assertIn('install -m 0755 "$script_dir/alert_delivery.py" "$alert_delivery_target"', installer)
        self.assertIn('restore_file "$backup_dir/alert_delivery.py" "$alert_delivery_target" "$had_alert_delivery"', installer)
        self.assertNotIn('systemctl enable --now monitor-alert-delivery.timer', installer)
        self.assertIn('if [ "$was_delivery_timer_enabled" = true ]', installer)
        self.assertIn('systemctl enable monitor-alert-delivery.timer', installer)
        self.assertIn('if [ "$was_delivery_timer_active" = true ]', installer)
        self.assertIn('systemctl start monitor-alert-delivery.timer', installer)
        self.assertIn('install -m 0644 "$script_dir/linux_telemetry.py" "$linux_telemetry_target"', installer)
        self.assertIn('restore_file "$backup_dir/linux_telemetry.py" "$linux_telemetry_target" "$had_linux_telemetry"', installer)
        for module in ("log_pipeline", "log_sources", "log_store", "generic_log_collector"):
            self.assertIn(
                f'install -m 0644 "$script_dir/{module}.py" "${module}_target"',
                installer,
            )
            self.assertIn(
                f'restore_file "$backup_dir/{module}.py" "${module}_target" "$had_{module}"',
                installer,
            )
        self.assertIn('install -m 0644 "$script_dir/rules/default-rules.v1.json" "$rule_target"', installer)
        self.assertIn('restore_file "$backup_dir/default-rules.v1.json" "$rule_target" "$had_rule"', installer)
        self.assertIn('if [ "$transaction_started" = true ] && [ "$committed" != true ]', installer)
        self.assertIn("stat -c '%u %g %a'", installer)
        for directory in (
            "/var/lib/monitor-export",
            "/run/monitor-collector",
            "/run/monitor-container-exporter",
        ):
            self.assertIn(f"capture_directory_metadata {directory}", installer)
            self.assertLess(
                installer.index(f"capture_directory_metadata {directory}"),
                installer.index("transaction_started=true"),
            )
        self.assertIn('restore_directory /var/lib/monitor-export "$had_output_directory"', installer)
        self.assertIn('restore_directory /run/monitor-collector "$had_collector_runtime_directory"', installer)
        self.assertIn('restore_directory /run/monitor-container-exporter "$had_exporter_runtime_directory"', installer)
        self.assertIn('"$created_output_directory" "$output_directory_uid"', installer)
        self.assertIn('"$created_collector_runtime_directory" "$collector_runtime_directory_uid"', installer)
        self.assertIn('"$created_exporter_runtime_directory" "$exporter_runtime_directory_uid"', installer)
        self.assertIn('elif [ "$created" != true ]; then', installer)
        self.assertIn('chown "$owner:$group" "$target" && chmod "$mode" "$target"', installer)
        self.assertIn('rmdir "$target"', installer)
        self.assertLess(
            installer.index('cp -p "$default_target" "$backup_dir/monitor-collector.default"'),
            installer.index('transaction_started=true'),
        )
        self.assertLess(
            installer.index('transaction_started=true'),
            installer.index(
                'systemctl stop monitor-collector.timer',
                installer.index('transaction_started=true'),
            ),
        )
        self.assertIn('"$(id -u cks)" -ne 1001', installer)
        self.assertIn('"$(getent group cks | cut -d: -f3)" -ne 1001', installer)

    def test_notification_delivery_counter_becomes_a_restart_safe_delta(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "delivery.json"
            config.write_text("{}")
            fake_outbox = mock.Mock()
            fake_outbox.status.return_value = {
                "schemaVersion": 1,
                "states": {},
                "stats": {"operational_final_failure": 5},
            }
            with mock.patch.dict(
                os.environ, {"MONITOR_ALERT_DELIVERY_CONFIG": str(config)}
            ), mock.patch("alert_delivery.load_delivery_config", return_value=mock.Mock(queue=mock.Mock())), mock.patch(
                "alert_delivery.DeliveryOutbox", return_value=fake_outbox
            ):
                signal, counter = collector.notification_delivery_signal(
                    Path(temporary), 3
                )
            self.assertEqual(signal, {
                "notificationDeliveryStatus": "ok",
                "notificationFinalFailureDelta": 2,
                "notificationQueueActive": None,
                "notificationQueueUsedPercent": None,
            })
            self.assertEqual(counter, 5)

            with mock.patch.dict(
                os.environ, {"MONITOR_ALERT_DELIVERY_CONFIG": "relative.json"}
            ):
                failed, retained = collector.notification_delivery_signal(
                    Path(temporary), 5
                )
            self.assertEqual(failed["notificationDeliveryStatus"], "collection_error")
            self.assertIsNone(failed["notificationFinalFailureDelta"])
            self.assertEqual(retained, 5)

    def test_monitor_runtime_signal_reports_real_cadence_and_storage_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            now = dt.datetime(2026, 8, 30, 12, 2, 10, tzinfo=dt.timezone.utc)
            collector.atomic_write_json(output / "rule-evaluation.json", {
                "evaluatedAt": "2026-08-30T12:00:00Z",
            })
            usage = mock.Mock(total=1_000, used=850, free=150)
            with mock.patch.object(collector.shutil, "disk_usage", return_value=usage):
                signal = collector.monitor_runtime_signal(output, now, 75.0, 60)

            self.assertEqual(signal["alertEvaluationStatus"], "ok")
            self.assertEqual(signal["alertEvaluationDelaySeconds"], 70.0)
            self.assertEqual(signal["monitoringFilesystemStatus"], "ok")
            self.assertEqual(signal["monitoringFilesystemUsedPercent"], 85.0)
            self.assertEqual(signal["storageWriteFailureDelta"], 0)
            self.assertEqual(signal["ingestStatus"], "unsupported")
            self.assertIsNone(signal["ingestLagSeconds"])

            with mock.patch.object(
                collector.shutil, "disk_usage", side_effect=PermissionError
            ):
                denied = collector.monitor_runtime_signal(output, now, 0.0, 60)
            self.assertEqual(denied["monitoringFilesystemStatus"], "permission_denied")
            self.assertIsNone(denied["monitoringFilesystemUsedPercent"])
            self.assertEqual(denied["alertEvaluationStatus"], "ok")

    def test_delivery_checkpoint_waits_for_durable_rule_evaluation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = collector.Config(
                output_dir=root / "out", runtime_dir=root / "run",
            )
            delta_path = config.runtime_dir / "delta-state.json"
            delta_state = {
                "monotonic": 200.0,
                "cpu": [200, 150],
                "network": [20, 30],
                "notificationFinalFailures": 3,
            }
            collector.atomic_write_json(
                delta_path, delta_state, 0o600, collector.MAX_DELTA_STATE_BYTES,
            )
            failure = {
                "schemaVersion": 1,
                "status": "collection_error",
                "rulePackVersion": None,
                "evaluatedAt": "2026-08-30T12:00:00Z",
                "summary": {},
                "states": {},
            }
            success = {**failure, "status": "ok"}
            signal = {
                "notificationDeliveryStatus": "ok",
                "notificationFinalFailureDelta": 2,
            }
            now = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)

            with mock.patch.object(
                collector, "publish_rule_evaluation", return_value=failure,
            ):
                result = collector.publish_rules_and_commit_delivery_checkpoint(
                    config, {}, now, signal, delta_path, delta_state, 5,
                )
            self.assertEqual(result["status"], "collection_error")
            retained = json.loads(delta_path.read_text())
            self.assertEqual(retained["notificationFinalFailures"], 3)
            self.assertEqual(retained["cpu"], [200, 150])
            self.assertEqual(retained["network"], [20, 30])

            with mock.patch.object(
                collector, "publish_rule_evaluation", side_effect=OSError("injected"),
            ):
                with self.assertRaises(OSError):
                    collector.publish_rules_and_commit_delivery_checkpoint(
                        config, {}, now, signal, delta_path, delta_state, 5,
                    )
            self.assertEqual(
                json.loads(delta_path.read_text())["notificationFinalFailures"], 3,
            )

            with (
                mock.patch.object(
                    collector, "publish_rule_evaluation", return_value=success,
                ),
                mock.patch.object(
                    collector, "atomic_write_json", side_effect=OSError("crash window"),
                ),
            ):
                with self.assertRaises(OSError):
                    collector.publish_rules_and_commit_delivery_checkpoint(
                        config, {}, now, signal, delta_path, delta_state, 5,
                    )
            self.assertEqual(
                json.loads(delta_path.read_text())["notificationFinalFailures"], 3,
            )

            with mock.patch.object(
                collector, "publish_rule_evaluation", return_value=success,
            ):
                collector.publish_rules_and_commit_delivery_checkpoint(
                    config, {}, now, signal, delta_path, delta_state, 5,
                )
            committed = json.loads(delta_path.read_text())
            self.assertEqual(committed["notificationFinalFailures"], 5)
            self.assertEqual(committed["cpu"], [200, 150])
            self.assertEqual(committed["network"], [20, 30])

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
        self.assertIsNone(normal["cpuPercent"])
        self.assertEqual(normal["throttledFlags"], 0)
        self.assertIsNone(normal["supplyVoltageVolts"])
        self.assertEqual(fixture(0x50000)["powerState"], "degraded-history")
        self.assertEqual(fixture(0x50005)["powerState"], "throttled")
        unavailable = fixture(None)
        self.assertIsNone(unavailable["powerState"])
        self.assertIsNone(unavailable["throttledFlags"])


if __name__ == "__main__":
    unittest.main()
