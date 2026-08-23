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
        self.assertEqual(collector.parse_proc_stat("cpu  100 2 30 400 5 0 0 0\n"), (537, 405))
        self.assertAlmostEqual(collector.calculate_cpu((600, 440), [500, 400]), 60.0)
        self.assertIsNone(collector.calculate_cpu((600, 440), None))
        self.assertIsNone(collector.calculate_cpu(None, [500, 400]))
        total, available = collector.parse_meminfo(
            "MemTotal:       1000 kB\nMemAvailable:    250 kB\n"
        )
        self.assertEqual((total, available), (1_024_000, 256_000))
        self.assertEqual(collector.parse_meminfo("MemTotal: 1000 kB\n"), (1_024_000, None))
        self.assertEqual(collector.parse_meminfo("malformed\n"), (None, None))
        net = collector.parse_net_dev(
            "Inter-| Receive | Transmit\n lo: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n"
            "eth0: 100 0 0 0 0 0 0 0 250 0 0 0 0 0 0 0\n"
        )
        self.assertEqual(net, (100, 250))
        self.assertEqual(collector.rate_pair((300, 650), [100, 250], 2), (100.0, 200.0))
        self.assertEqual(collector.rate_pair((300, 650), None, 2), (None, None))
        self.assertIsNone(collector.parse_net_dev("malformed\n"))

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
        self.assertEqual(collector.parse_loadavg("not-a-number"), (None, None, None))

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
        prior = {"cpuTotal": 100, "systemTotal": 1000, "onlineCpus": 2}
        reduced = collector.container_from_api(raw, "cks", stats, prior)
        self.assertEqual(set(reduced), {
            "name", "owner", "state", "health", "cpuPercent", "memoryBytes", "memoryPercent"
        })
        self.assertEqual(reduced["name"], "monitor")
        self.assertEqual(reduced["health"], "healthy")
        self.assertEqual(reduced["cpuPercent"], 20.0)
        multi_core_stats = {
            **stats,
            "cpu_stats": {
                "cpu_usage": {"total_usage": 900},
                "system_cpu_usage": 2000,
                "online_cpus": 2,
            },
        }
        self.assertEqual(
            collector.container_from_api(raw, "cks", multi_core_stats, prior)["cpuPercent"],
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
        self.assertEqual(collector.container_from_api(raw, "cks", idle_stats, prior)["cpuPercent"], 0.0)
        self.assertNotIn("secret", json.dumps(reduced))
        unavailable = collector.container_from_api(raw, "cks", None)
        self.assertIsNone(unavailable["cpuPercent"])
        self.assertIsNone(unavailable["memoryBytes"])
        with self.assertRaisesRegex(ValueError, "outside the Compose service allowlist"):
            collector.container_from_api({**raw, "Names": [], "Labels": {}}, "cks", None)

    def test_compose_pairs_have_distinct_fixed_names_and_filtered_list_paths(self):
        expected_pairs = {
            ("bonifacio", "bonifacio"): "bonifacio",
            ("bonifacio", "bonifacioSso"): "sso",
            ("bonifacio", "bonifacioSsoRedis"): "sso-redis",
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
        stats_paths = []
        ids_by_pair = {
            pair: f"{index + 1:064x}"
            for index, pair in enumerate(collector.ALLOWED_COMPOSE_SERVICES)
        }

        def fake_get(_socket, path, _curl, _timeout):
            project = docker_list_project(path)
            if project is None:
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
        self.assertEqual(stats_paths, [])
        self.assertTrue(all(item["state"] == "exited" for item in containers))

    def test_reduced_container_input_requires_fresh_cks_owned_fixed_schema(self):
        now = dt.datetime(2026, 8, 23, 3, 0, tzinfo=dt.timezone.utc)
        document = {
            "generatedAt": collector.iso_timestamp(now),
            "containers": [{
                "name": "monitor", "owner": "cks", "state": "running", "health": "healthy",
                "cpuPercent": 250.0, "memoryBytes": 123, "memoryPercent": 1.5,
            }],
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
                self.assertEqual(collector.load_container_snapshot(path, now), document["containers"])
                for legacy_name in sorted(collector.LEGACY_CONTAINER_NAMES):
                    legacy_document = {
                        **document,
                        "containers": [{
                            **document["containers"][0],
                            "name": legacy_name,
                        }],
                    }
                    path.write_text(json.dumps(legacy_document), encoding="utf-8")
                    self.assertEqual(
                        collector.load_container_snapshot(path, now),
                        legacy_document["containers"],
                    )
                path.write_text(json.dumps({
                    **document,
                    "containers": [{**document["containers"][0], "name": "alice@example.test"}],
                }), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "outside the allowlist"):
                    collector.load_container_snapshot(path, now)

            path.chmod(0o660)
            with mock.patch.object(Path, "lstat", owned_by_cks), \
                 mock.patch.object(collector.os, "fstat", opened_by_cks):
                with self.assertRaisesRegex(ValueError, "file validation"):
                    collector.load_container_snapshot(path, now)

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
        active = peak = stats_calls = 0
        sample = [0]
        stats_paths = []

        def fake_get(socket_path, path, _curl, request_timeout):
            nonlocal active, peak, stats_calls
            self.assertEqual(request_timeout, 2)
            if "containers/json" in path:
                return cks_raw if socket_path == Path("/cks.sock") else secondary_raw
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
                {"cks": Path("/cks.sock"), "secondary": Path("/secondary.sock")}, "/curl", 2
            )
            sample[0] = 1
            second, next_cpu_state = collector.collect_containers(
                {"cks": Path("/cks.sock"), "secondary": Path("/secondary.sock")}, "/curl", 2, cpu_state
            )
        self.assertEqual(len(first), 12)
        self.assertEqual(len(second), 12)
        self.assertEqual(stats_calls, 24)
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 6)
        self.assertTrue(all(item["cpuPercent"] is None for item in first))
        self.assertTrue(all(item["memoryBytes"] == 25 for item in first))
        self.assertTrue(all(item["cpuPercent"] == 20.0 for item in second))
        self.assertEqual(len(cpu_state), 12)
        self.assertEqual(len(next_cpu_state), 12)
        self.assertTrue(all(item["owner"] == "cks" for item in first))
        self.assertTrue(all("stream=false&one-shot=true" in path for path in stats_paths))
        serialized = json.dumps([first, second]).lower()
        self.assertNotIn("secret", serialized)
        self.assertNotIn("token", serialized)
        self.assertNotIn("mount", serialized)
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

        with mock.patch.object(collector, "_monotonic", side_effect=[0.0, 21.0]), \
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
        self.assertEqual(len(containers), 200)
        self.assertEqual(stats_calls, 30)
        self.assertEqual(len(next_state), 200)
        self.assertNotIn("cks:" + "f" * 64, next_state)

        with mock.patch.object(collector, "docker_get", return_value=[]):
            empty, pruned_state = collector.collect_containers(sockets, "/curl", 2, next_state)
        self.assertEqual(empty, [])
        self.assertEqual(pruned_state, {})


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
        active, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=1), incident_metrics(cpuPercent=90),
            empty_pressure(), [], [], [], state,
        )
        self.assertEqual(active["phase"], "active")
        self.assertEqual(active["reasons"], ["cpu"])
        self.assertEqual(active["endedAt"], None)
        self.assertEqual(active["durationSeconds"], None)
        self.assertEqual(active["metrics"]["timestamp"], active["observedAt"])
        self.assertIsNotNone(collector.existing_incident_record(active))

        follow_up, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=2), incident_metrics(cpuPercent=80),
            empty_pressure(), [], [], [], state,
        )
        self.assertEqual(follow_up["phase"], "follow-up")
        suppressed, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=3), incident_metrics(cpuPercent=80),
            empty_pressure(), [], [], [], state,
        )
        self.assertIsNone(suppressed)
        recovered, state = collector.incident_transition(
            config, start + dt.timedelta(minutes=4), incident_metrics(cpuPercent=74),
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
        config = collector.Config(docker_sockets={}, traffic_log=None)
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
        config = collector.Config(docker_sockets={}, traffic_log=None)
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
        config = collector.Config(docker_sockets={}, traffic_log=None)
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
                    docker_sockets={}, traffic_log=None,
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
                docker_sockets={}, traffic_log=None,
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
                docker_sockets={}, traffic_log=None,
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
                docker_sockets={}, traffic_log=None,
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


class FilesystemTests(unittest.TestCase):
    def test_atomic_write_leaves_complete_file_and_no_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "current.json"
            collector.atomic_write_json(path, {"ok": True})
            self.assertEqual(json.loads(path.read_text()), {"ok": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o750)
            self.assertEqual(list(path.parent.glob(".current.json.*")), [])

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
                 mock.patch.object(collector, "docker_get", side_effect=fake_docker):
                current = collector.run(config, now)
                first_delta_state = json.loads((runtime / "delta-state.json").read_text())
                docker_sample[0] = 1
                second = collector.run(config, now + dt.timedelta(minutes=1))

            self.assertEqual(set(current), {"generatedAt", "host", "latest", "disks", "containers"})
            self.assertEqual(set(current["host"]), {"hostname", "os", "architecture", "uptimeSeconds"})
            self.assertEqual(tuple(current["latest"]), collector.SAMPLE_FIELDS)
            for field_name in (
                "cpuPercent", "memoryPercent", "memoryUsedBytes", "memoryTotalBytes",
                "load1", "load5", "load15", "networkRxBytesPerSecond",
                "networkTxBytesPerSecond", "diskReadBytesPerSecond",
                "diskWriteBytesPerSecond",
            ):
                self.assertIsNone(current["latest"][field_name], field_name)
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
        self.assertEqual(config.traffic_log, Path("/var/log/nginx/monitor-traffic.jsonl"))
        self.assertEqual(config.docker_sockets, {"cks": Path("/run/user/1001/docker.sock")})
        self.assertEqual(config.process_uids, {0, 1001})
        self.assertEqual(config.incident_retention_days, 30)
        self.assertEqual(config.max_incident_records, 1000)
        self.assertEqual(config.cpu_warn_samples, 1)
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
        self.assertEqual(collector.parse_uid_set(""), set())
        clamped = collector.config_from_environment([
            "--cpu-warn-percent", "80", "--cpu-recover-percent", "90",
            "--memory-available-warn-percent", "20",
            "--memory-available-recover-percent", "10",
            "--load-warn", "4", "--load-recover", "9",
            "--disk-io-warn-bytes-per-second", "100",
            "--disk-io-recover-bytes-per-second", "200",
            "--traffic-request-warn", "300", "--traffic-request-recover", "500",
        ])
        self.assertEqual(clamped.cpu_recover_percent, 80)
        self.assertEqual(clamped.memory_available_recover_percent, 20)
        self.assertEqual(clamped.load_recover, 4)
        self.assertEqual(clamped.disk_io_recover_bytes_per_second, 100)
        self.assertEqual(clamped.traffic_request_recover, 300)
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
        self.assertIn("TemporaryFileSystem=/run:ro", unit)
        self.assertIn("BindPaths=/run/monitor-collector", unit)
        self.assertIn("BindReadOnlyPaths=/run/monitor-container-exporter/containers.json", unit)
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
        self.assertIn("MONITOR_KERNEL_MAX_INPUT_BYTES=8388608", defaults)
        self.assertIn("MONITOR_TRAFFIC_LOG=/var/log/nginx/monitor-traffic.jsonl", defaults)
        self.assertIn("MONITOR_DOCKER_SOCKETS=\n", defaults)
        self.assertIn("MONITOR_CONTAINER_INPUT=/run/monitor-container-exporter/containers.json", defaults)
        self.assertIn("MONITOR_PROCESS_UIDS=0,1001", defaults)
        self.assertIn("MONITOR_CPU_WARN_SAMPLES=1", defaults)
        self.assertIn("-o root -g cks -m 0750 /var/lib/monitor-export", installer)
        self.assertIn('had_default=false', installer)
        self.assertIn('restore_file "$backup_dir/monitor-collector.default" "$default_target" "$had_default"', installer)
        self.assertIn('install -m 0640 "$script_dir/monitor-collector.default" "$default_target"', installer)
        self.assertIn('if [ "$transaction_started" = true ] && [ "$committed" != true ]', installer)
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
