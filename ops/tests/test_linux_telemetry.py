import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import linux_telemetry as telemetry  # noqa: E402


NOW = dt.datetime(2026, 8, 30, 12, 0, tzinfo=dt.timezone.utc)


def process_stat(cpu_ticks: int, resident_pages: int = 3, state: str = "R") -> str:
    tail = [
        state, "1", "1", "1", "0", "0", "0", "0", "0", "0", "0",
        str(cpu_ticks - 5), "5", "0", "0", "20", "0", "2", "0", "100",
        "4096", str(resident_pages),
    ]
    return f"123 (secret-worker) {' '.join(tail)}\n"


def diskstats(
    *, reads: int, sectors_read: int, read_ms: int, writes: int,
    sectors_written: int, write_ms: int, io_ms: int, weighted_ms: int,
    discards: int, sectors_discarded: int, flushes: int,
) -> str:
    counters = [
        reads, 0, sectors_read, read_ms,
        writes, 0, sectors_written, write_ms,
        2, io_ms, weighted_ms,
        discards, 0, sectors_discarded, 0,
        flushes, 0,
    ]
    return "8 0 sda " + " ".join(str(value) for value in counters) + "\n"


class LinuxTelemetryTests(unittest.TestCase):
    def create_fixture(self, root: Path) -> dict[str, Path]:
        proc = root / "proc"
        sys_root = root / "sys"
        mount_root = root / "mounted"
        for directory in (
            proc / "net", proc / "self", proc / "pressure", proc / "sys" / "fs",
            proc / "sys" / "net" / "ipv4", proc / "sys" / "net" / "netfilter",
            proc / "sys" / "kernel" / "random", proc / "123" / "fd",
            sys_root / "devices" / "system" / "cpu" / "cpu0" / "cpufreq",
            sys_root / "devices" / "system" / "cpu" / "cpu0" / "thermal_throttle",
            sys_root / "class" / "net" / "eth0" / "device",
            sys_root / "class" / "thermal" / "thermal_zone0",
            sys_root / "class" / "thermal" / "cooling_device0",
            sys_root / "class" / "hwmon" / "hwmon0",
            sys_root / "firmware" / "devicetree" / "base",
            sys_root / "fs" / "cgroup" / "fixture.slice",
            sys_root / "block" / "sda" / "queue",
            mount_root / "proc", mount_root / "var" / "lib" / "docker",
        ):
            directory.mkdir(parents=True, exist_ok=True)

        (proc / "stat").write_text(
            "cpu 100 10 20 800 10 5 5 0 0 0\n"
            "cpu0 100 10 20 800 10 5 5 0 0 0\n"
            "btime 1788060000\n"
        )
        (proc / "meminfo").write_text(
            "MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n"
            "Buffers: 1024 kB\nCached: 2048 kB\nSReclaimable: 512 kB\n"
            "SUnreclaim: 256 kB\nSlab: 768 kB\nShmem: 128 kB\n"
            "Dirty: 4 kB\nWriteback: 2 kB\nSwapTotal: 262144 kB\nSwapFree: 131072 kB\n"
        )
        (proc / "vmstat").write_text(
            "pswpin 100\npswpout 200\npgfault 1000\npgmajfault 10\noom_kill 1\n"
        )
        for kind in ("cpu", "memory", "io"):
            (proc / "pressure" / kind).write_text(
                "some avg10=1.00 avg60=2.00 avg300=3.00 total=1000\n"
                "full avg10=0.10 avg60=0.20 avg300=0.30 total=100\n"
            )
        (proc / "loadavg").write_text("1.0 2.0 3.0 1/10 123\n")
        (proc / "uptime").write_text("3600.00 0.00\n")
        (proc / "diskstats").write_text(diskstats(
            reads=100, sectors_read=1000, read_ms=500,
            writes=200, sectors_written=2000, write_ms=600,
            io_ms=700, weighted_ms=900, discards=10,
            sectors_discarded=100, flushes=5,
        ))
        (proc / "net" / "dev").write_text(
            "Inter-| Receive | Transmit\n"
            "eth0: 1000 100 1 2 0 0 0 3 2000 200 4 5 0 6 0 0\n"
        )
        tcp_header = (
            "Tcp: ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab "
            "InSegs OutSegs RetransSegs InErrs OutRsts\n"
        )
        (proc / "net" / "snmp").write_text(
            tcp_header + "Tcp: 100 50 2 1 1 2000 1000 10 0 3\n"
        )
        (proc / "net" / "netstat").write_text(
            "TcpExt: TCPSynRetrans TCPTimeouts\nTcpExt: 4 5\n"
        )
        socket_header = "  sl  local_address rem_address   st tx_queue rx_queue\n"
        (proc / "net" / "tcp").write_text(
            socket_header
            + "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n"
            + "   1: 0100007F:C350 0100007F:01BB 01 00000000:00000000\n"
            + "   2: 0100007F:C351 0100007F:01BB 08 00000000:00000000\n"
            + "   3: 0100007F:C352 0100007F:01BB 06 00000000:00000000\n"
        )
        (proc / "net" / "tcp6").write_text(socket_header)
        (proc / "sys" / "net" / "ipv4" / "ip_local_port_range").write_text(
            "32768 60999\n"
        )
        (proc / "sys" / "net" / "netfilter" / "nf_conntrack_count").write_text("25\n")
        (proc / "sys" / "net" / "netfilter" / "nf_conntrack_max").write_text("100\n")
        (proc / "self" / "mountinfo").write_text(
            "36 25 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
            "37 25 0:4 / /proc rw - proc proc rw\n"
            "38 25 0:55 / /var/lib/docker rw - overlay overlay rw\n"
        )
        (proc / "self" / "cgroup").write_text("0::/fixture.slice\n")
        (proc / "sys" / "fs" / "file-nr").write_text("100 10 1000\n")
        (proc / "sys" / "kernel" / "pid_max").write_text("4194304\n")
        (proc / "sys" / "kernel" / "random" / "boot_id").write_text(
            "01234567-89ab-4def-8123-456789abcdef\n"
        )
        (proc / "123" / "stat").write_text(process_stat(15))
        (proc / "123" / "io").write_text("read_bytes: 1000\nwrite_bytes: 2000\n")
        (proc / "123" / "fd" / "1").write_text("")
        (proc / "123" / "fd" / "2").write_text("")

        cpu_root = sys_root / "devices" / "system" / "cpu"
        (cpu_root / "offline").write_text("")
        cpufreq = cpu_root / "cpu0" / "cpufreq"
        (cpufreq / "scaling_cur_freq").write_text("1500000\n")
        (cpufreq / "scaling_min_freq").write_text("600000\n")
        (cpufreq / "scaling_max_freq").write_text("2400000\n")
        (cpufreq / "scaling_governor").write_text("schedutil\n")
        (cpu_root / "cpu0" / "thermal_throttle" / "core_throttle_count").write_text("2\n")
        interface = sys_root / "class" / "net" / "eth0"
        (interface / "ifindex").write_text("2\n")
        (interface / "iflink").write_text("2\n")
        (interface / "mtu").write_text("1500\n")
        (interface / "speed").write_text("1000\n")
        (interface / "duplex").write_text("full\n")
        (interface / "operstate").write_text("up\n")
        (interface / "carrier").write_text("1\n")
        (interface / "type").write_text("1\n")
        (sys_root / "block" / "sda" / "queue" / "rotational").write_text("0\n")
        thermal = sys_root / "class" / "thermal"
        (thermal / "thermal_zone0" / "type").write_text("cpu-thermal\n")
        (thermal / "thermal_zone0" / "temp").write_text("55000\n")
        (thermal / "cooling_device0" / "type").write_text("pwm-fan\n")
        (thermal / "cooling_device0" / "cur_state").write_text("2\n")
        (thermal / "cooling_device0" / "max_state").write_text("4\n")
        hwmon = sys_root / "class" / "hwmon" / "hwmon0"
        (hwmon / "name").write_text("pwmfan\n")
        (hwmon / "fan1_input").write_text("3200\n")
        (sys_root / "firmware" / "devicetree" / "base" / "model").write_bytes(
            b"Raspberry Pi 5 Model B Rev 1.0\x00"
        )
        (sys_root / "fs" / "cgroup" / "fixture.slice" / "pids.current").write_text("12\n")
        (sys_root / "fs" / "cgroup" / "fixture.slice" / "pids.max").write_text("100\n")
        kernel = root / "kern.log"
        kernel.write_text("fixture\n")
        return {"proc": proc, "sys": sys_root, "mount": mount_root, "kernel": kernel}

    def collect(self, paths, previous=None, when=NOW):
        return telemetry.collect_linux_telemetry(
            proc_root=paths["proc"],
            sys_root=paths["sys"],
            mountinfo_path=paths["proc"] / "self" / "mountinfo",
            mount_root=paths["mount"],
            docker_data_root=Path("/var/lib/docker"),
            kernel_log=paths["kernel"],
            kernel_summary={"oomKill": {"count": 1, "lastEventAt": "2026-08-30T11:59:00Z"}},
            previous=previous,
            elapsed_seconds=60,
            now=when,
            loadavg=(1.0, 2.0, 3.0),
            allowed_uids={os.getuid()},
            process_allowlist={"secret-worker"},
            process_name_sanitizer=lambda _name: "other",
            systemd_units={"monitor-collector.service"},
            systemd_state_dir=paths["sys"] / "fixture-systemd-units",
            systemctl="/usr/bin/systemctl",
            timedatectl="/usr/bin/timedatectl",
            command_timeout=0.5,
            rpi_data={
                "temperatureC": 55.0,
                "supplyVoltageVolts": 4.9,
                "throttledFlags": 0x50005,
                "_throttledFlagsSource": "vcgencmd",
            },
        )

    def test_two_samples_cover_linux_p0_p1_contract_and_rates(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.create_fixture(Path(temporary))
            first, state = self.collect(paths)
            self.assertEqual(first["schemaVersion"], 1)
            self.assertEqual(first["cpu"]["total"]["rateStatus"], "warmup")
            self.assertEqual(first["memory"]["rateStatus"], "warmup")
            self.assertEqual(first["blockDevices"]["items"][0]["rateStatus"], "warmup")
            self.assertEqual(first["network"]["items"][0]["rateStatus"], "warmup")

            (paths["proc"] / "stat").write_text(
                "cpu 160 10 50 850 20 10 10 0 0 0\n"
                "cpu0 160 10 50 850 20 10 10 0 0 0\n"
                "btime 1788060000\n"
            )
            (paths["proc"] / "vmstat").write_text(
                "pswpin 160\npswpout 320\npgfault 1600\npgmajfault 70\noom_kill 1\n"
            )
            (paths["proc"] / "diskstats").write_text(diskstats(
                reads=160, sectors_read=1120, read_ms=620,
                writes=230, sectors_written=2240, write_ms=690,
                io_ms=1000, weighted_ms=1500, discards=16,
                sectors_discarded=220, flushes=11,
            ))
            (paths["proc"] / "net" / "dev").write_text(
                "eth0: 7000 160 7 8 0 0 0 9 14000 260 10 11 0 12 0 0\n"
            )
            (paths["proc"] / "net" / "snmp").write_text(
                "Tcp: ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab "
                "InSegs OutSegs RetransSegs InErrs OutRsts\n"
                "Tcp: 110 55 2 1 1 2600 1600 16 0 4\n"
            )
            (paths["proc"] / "123" / "stat").write_text(process_stat(75))
            (paths["proc"] / "123" / "io").write_text(
                "read_bytes: 7000\nwrite_bytes: 14000\n"
            )
            second, next_state = self.collect(paths, state, NOW + dt.timedelta(minutes=1))

            total = second["cpu"]["total"]
            self.assertEqual(total["rateStatus"], "ok")
            self.assertEqual(total["busyPercent"], 62.5)
            self.assertEqual(total["userPercent"], 37.5)
            self.assertEqual(total["systemPercent"], 18.75)
            self.assertEqual(second["cpu"]["load"]["onePerOnlineCpu"], 1.0)
            self.assertEqual(second["cpu"]["cores"][0]["frequency"]["currentHz"], 1_500_000_000)
            self.assertEqual(second["memory"]["cachedBytes"], (2048 + 512 - 128) * 1024)
            self.assertEqual(second["memory"]["swapInPagesPerSecond"], 1.0)
            self.assertEqual(second["memory"]["swapInBytesPerSecond"], os.sysconf("SC_PAGE_SIZE"))
            self.assertEqual(second["memory"]["pageFaultsPerSecond"], 10.0)
            self.assertEqual(second["memory"]["majorPageFaultsPerSecond"], 1.0)
            self.assertEqual(second["memory"]["pressure"]["memory"]["some"]["avg60"], 2.0)

            filesystems = second["filesystems"]["items"]
            self.assertTrue(any(item["pseudo"] and item["filesystemType"] == "proc" for item in filesystems))
            docker_mount = next(item for item in filesystems if item["dockerDataRootFilesystem"])
            self.assertEqual(docker_mount["mount"], "/var/lib/docker")
            self.assertTrue(docker_mount["pseudo"])
            self.assertIn("inodeUsedPercent", docker_mount)

            block = second["blockDevices"]["items"][0]
            self.assertEqual(block["rateStatus"], "ok")
            self.assertEqual(block["readBytesPerSecond"], 1024.0)
            self.assertEqual(block["writeBytesPerSecond"], 2048.0)
            self.assertEqual(block["readIops"], 1.0)
            self.assertEqual(block["writeIops"], 0.5)
            self.assertEqual(block["readLatencyMilliseconds"], 2.0)
            self.assertEqual(block["utilizationPercent"], 0.5)
            self.assertEqual(block["averageQueueDepth"], 0.01)
            self.assertEqual(block["discardStatus"], "supported")
            self.assertEqual(block["discardRateStatus"], "ok")
            self.assertEqual(block["flushStatus"], "supported")
            self.assertEqual(block["flushRateStatus"], "ok")
            self.assertEqual(block["ioErrorCounterStatus"], "unsupported")

            interface = second["network"]["items"][0]
            self.assertEqual(interface["classification"], "physical")
            self.assertEqual(interface["rxBytesPerSecond"], 100.0)
            self.assertEqual(interface["txBytesPerSecond"], 200.0)
            self.assertEqual(interface["rxErrorsPerSecond"], 0.1)
            self.assertEqual(interface["txCollisionsPerSecond"], 0.1)

            self.assertEqual(interface["mtu"], 1500)
            self.assertEqual(interface["linkState"], "up")
            self.assertEqual(interface["speedMegabitsPerSecond"], 1000)
            self.assertEqual(interface["duplex"], "full")
            self.assertEqual(second["tcp"]["rateStatus"], "ok")
            self.assertEqual(second["tcp"]["outgoingSegmentsPerSecond"], 10.0)
            self.assertEqual(second["tcp"]["retransmittedSegmentsPerSecond"], 0.1)
            self.assertEqual(second["tcp"]["retransmissionPercent"], 1.0)
            self.assertEqual(second["tcp"]["states"]["established"], 1)
            self.assertEqual(second["tcp"]["states"]["closeWait"], 1)
            self.assertEqual(second["tcp"]["states"]["timeWait"], 1)
            self.assertEqual(second["tcp"]["states"]["listen"], 1)
            self.assertEqual(second["tcp"]["ephemeralPorts"]["used"], 3)
            self.assertEqual(second["tcp"]["conntrack"]["usedPercent"], 25.0)

            important = second["processes"]["important"][0]
            self.assertEqual(important["name"], "secret-worker")
            self.assertEqual(important["cpuPercent"], 37.5)
            self.assertEqual(important["readBytesPerSecond"], 100.0)
            self.assertEqual(important["writeBytesPerSecond"], 200.0)
            self.assertEqual(important["openFileDescriptors"], 2)
            self.assertEqual(second["processes"]["systemFileDescriptors"]["used"], 90)
            self.assertEqual(second["processes"]["cgroupPids"]["version"], 2)
            self.assertEqual(second["processes"]["cgroupPids"]["usedPercent"], 12.0)
            self.assertEqual(second["systemd"]["status"], "unsupported")
            self.assertEqual(second["thermal"]["sensors"][0]["temperatureCelsius"], 55.0)
            self.assertEqual(second["thermal"]["fans"][0]["rpm"], 3200)
            self.assertTrue(second["thermal"]["raspberryPi"]["currentThrottled"])
            self.assertTrue(second["thermal"]["raspberryPi"]["underVoltageOccurred"])
            self.assertEqual(second["clock"]["uptimeSeconds"], 3600)
            self.assertIsNone(second["clock"]["unexpectedReboot"])
            self.assertEqual(second["eventSources"]["kernelLogStatus"], "supported")
            self.assertFalse(second["privacy"]["processCommandLinesCollected"])
            self.assertFalse(second["privacy"]["processEnvironmentsCollected"])
            serialized = json.dumps(second)
            self.assertNotIn("--password", serialized)
            self.assertNotIn("/environ", serialized.lower())
            self.assertLess(len(serialized), 1_000_000)
            self.assertEqual(set(next_state), {
                "cpu", "vmstat", "filesystems", "blockDevices", "network", "tcp",
                "processes", "systemd", "bootId",
            })
            shutil.rmtree(paths["proc"] / "123")
            (paths["proc"] / "self" / "mountinfo").write_text(
                "36 25 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n"
                "37 25 0:4 / /proc rw - proc proc rw\n"
                "38 25 0:55 / /var/lib/docker rw - overlay overlay rw\n"
            )
            third, _third_state = self.collect(
                paths, next_state, NOW + dt.timedelta(minutes=2)
            )
            self.assertEqual(third["processes"]["terminatedSincePreviousSample"], [{
                "name": "secret-worker", "allowlisted": True, "instances": 1,
            }])
            root_filesystem = next(
                item for item in third["filesystems"]["items"] if item["mount"] == "/"
            )
            self.assertEqual(root_filesystem["readOnlyTransition"], "became_read_only")

    def test_hwmon_under_voltage_bit_does_not_claim_throttle_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.create_fixture(Path(temporary))
            thermal = telemetry.collect_thermal(paths["sys"], {
                "throttledFlags": 0x1,
                "_throttledFlagsSource": "hwmon-current-only",
            })
            raspberry_pi = thermal["raspberryPi"]
            self.assertEqual(raspberry_pi["flagSource"], "hwmon-current-only")
            self.assertTrue(raspberry_pi["currentUnderVoltage"])
            for field in (
                "currentFrequencyCapped", "currentThrottled",
                "currentSoftTemperatureLimit", "underVoltageOccurred",
                "frequencyCapOccurred", "throttlingOccurred",
                "softTemperatureLimitOccurred",
            ):
                self.assertIsNone(raspberry_pi[field])

    def test_file_descriptor_limit_above_json_safe_range_is_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.create_fixture(Path(temporary))
            (paths["proc"] / "sys" / "fs" / "file-nr").write_text(
                "100 10 9223372036854775807\n"
            )

            result, _state = self.collect(paths)
            descriptors = result["processes"]["systemFileDescriptors"]

            self.assertEqual(descriptors, {
                "status": "partial",
                "allocated": 100,
                "unusedAllocated": 10,
                "used": 90,
                "maximum": None,
                "usedPercent": None,
            })
            self.assertEqual(
                json.loads(json.dumps(descriptors)),
                descriptors,
            )

    def test_remote_and_triggerable_filesystems_are_never_synchronously_probed(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.create_fixture(Path(temporary))
            mountinfo = paths["proc"] / "self" / "mountinfo"
            with mountinfo.open("a") as handle:
                handle.write(
                    "39 25 0:56 / /mnt/remote rw - nfs4 server:/export rw\n"
                    "40 25 0:57 / /mnt/auto rw - autofs systemd-1 rw\n"
                    "41 25 0:58 / /mnt/fuse rw - fuse.custom remote rw\n"
                )
            original_disk_usage = telemetry.shutil.disk_usage
            original_statvfs = telemetry.os.statvfs
            probed: list[str] = []

            def bounded_disk_usage(path):
                probed.append(str(path))
                return original_disk_usage(path)

            def bounded_statvfs(path):
                probed.append(str(path))
                return original_statvfs(path)

            with mock.patch.object(
                telemetry.shutil, "disk_usage", side_effect=bounded_disk_usage
            ), mock.patch.object(
                telemetry.os, "statvfs", side_effect=bounded_statvfs
            ):
                result, _state = self.collect(paths)

            by_mount = {
                item["mount"]: item for item in result["filesystems"]["items"]
            }
            for mount in ("/mnt/remote", "/mnt/auto", "/mnt/fuse"):
                self.assertEqual(by_mount[mount]["availability"], "unsupported")
                self.assertIsNone(by_mount[mount]["totalBytes"])
                self.assertFalse(any(value.endswith(mount) for value in probed))

    def test_counter_decrease_or_identity_change_never_creates_rate_spike(self):
        previous_network = {
            "2:2:eth0": {field: 1000 for field in telemetry.NETWORK_COUNTER_FIELDS}
        }
        current = "eth0: " + " ".join("1" for _ in range(16)) + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            sys_root = root / "sys"
            (proc / "net").mkdir(parents=True)
            interface = sys_root / "class" / "net" / "eth0"
            interface.mkdir(parents=True)
            (proc / "net" / "dev").write_text(current)
            (interface / "ifindex").write_text("2\n")
            (interface / "iflink").write_text("2\n")
            result, _state = telemetry.collect_network(proc, sys_root, previous_network, 60)
            item = result["items"][0]
            self.assertEqual(item["rateStatus"], "counter_reset")
            self.assertTrue(all(
                item[f"{field}PerSecond"] is None
                for field in telemetry.NETWORK_COUNTER_FIELDS
            ))
            (interface / "ifindex").write_text("9\n")
            recreated, _state = telemetry.collect_network(proc, sys_root, previous_network, 60)
            self.assertEqual(recreated["items"][0]["rateStatus"], "warmup")

    def test_bounds_status_parsers_and_safe_systemd_allowlist(self):
        cpu_text = "cpu 1 1 1 1 1 1 1 1\n" + "".join(
            f"cpu{index} 1 1 1 1 1 1 1 1\n"
            for index in range(telemetry.MAX_CPU_COUNT + 20)
        )
        parsed = telemetry.parse_cpu_stat(cpu_text)
        self.assertLessEqual(len(parsed), telemetry.MAX_CPU_COUNT + 1)
        self.assertEqual(telemetry.parse_cpu_list("0-3,7"), {0, 1, 2, 3, 7})
        self.assertEqual(telemetry.parse_cpu_list("3-1"), set())
        legacy_disk = telemetry.parse_diskstats_detail(
            "8 0 sda 1 0 10 1 2 0 20 2 0 3 4\n"
        )["8:0:sda"]
        self.assertFalse(legacy_disk["discardSupported"])
        self.assertFalse(legacy_disk["flushSupported"])
        self.assertEqual(telemetry.parse_timedatectl_show(
            "NTPSynchronized=yes\nNTP=no\nCanNTP=yes\n"
        ), {"synchronized": True, "ntpEnabled": False, "ntpSupported": True})

        output = (
            "Id=monitor-collector.service\nLoadState=loaded\nActiveState=active\n"
            "SubState=running\nNRestarts=2\nResult=success\nExecMainStatus=0\n\n"
            "Id=foreign.service\nLoadState=loaded\nActiveState=active\n"
        )
        parsed_units = telemetry.parse_systemctl_show(
            output, {"monitor-collector.service"}
        )
        self.assertEqual(parsed_units, [{
            "unit": "monitor-collector.service", "loadState": "loaded",
            "activeState": "active", "subState": "running", "restartCount": 2,
            "restartCountStatus": "systemd_manager",
            "result": "success", "execMainStatus": 0,
        }])
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "systemctl"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            completed = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            with mock.patch.object(telemetry.subprocess, "run", return_value=completed) as run:
                result = telemetry.collect_systemd(
                    {"monitor-collector.service", "bad;touch.service"},
                    str(executable), 0.5, True,
                )
            self.assertEqual(result["status"], "supported")
            arguments = run.call_args.args[0]
            self.assertIn("monitor-collector.service", arguments)
            self.assertNotIn("bad;touch.service", arguments)
            self.assertNotIn("shell", run.call_args.kwargs)
            marker = Path(temporary) / "synchronized"
            marker.write_text("")
            sync = telemetry.collect_time_sync("/missing/timedatectl", 0.5, False, marker)
            self.assertEqual(sync["status"], "partial")
            self.assertTrue(sync["synchronized"])

        with mock.patch.object(Path, "open", side_effect=PermissionError):
            status, text = telemetry.read_limited(Path("/denied"), 10)
        self.assertEqual((status, text), ("permission_error", ""))

    def test_systemd_runtime_fallback_tracks_bounded_invocation_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "run" / "systemd" / "units"
            cgroup = root / "sys" / "fs" / "cgroup" / "system.slice" / "nginx.service"
            runtime.mkdir(parents=True)
            cgroup.mkdir(parents=True)
            invocation = runtime / "invocation:nginx.service"
            invocation.symlink_to("0" * 32)
            first, state = telemetry.collect_systemd_runtime(
                {"nginx.service"}, runtime, root / "sys", None,
            )
            self.assertEqual(first["status"], "supported")
            self.assertEqual(first["units"][0]["activeState"], "active")
            self.assertEqual(first["units"][0]["restartCount"], 0)
            self.assertEqual(
                first["units"][0]["restartCountStatus"],
                "observed_invocation_changes",
            )
            invocation.unlink()
            invocation.symlink_to("1" * 32)
            second, next_state = telemetry.collect_systemd_runtime(
                {"nginx.service"}, runtime, root / "sys", state,
            )
            self.assertEqual(second["units"][0]["restartCount"], 1)
            self.assertNotIn("1" * 32, json.dumps(second))
            self.assertRegex(next_state["nginx.service"]["invocationDigest"], r"^[0-9a-f]{32}$")


if __name__ == "__main__":
    unittest.main()
