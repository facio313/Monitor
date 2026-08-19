#!/usr/bin/env python3
"""Low-overhead, read-only host telemetry exporter.

Only the configured output and state directories are written.  Host inputs are
read from procfs/sysfs, selected logs, and explicitly configured Docker Unix
sockets.  No raw log line or Docker metadata is ever exported.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import fcntl
import json
import math
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


SAMPLE_FIELDS = (
    "timestamp",
    "cpuPercent",
    "memoryPercent",
    "memoryUsedBytes",
    "memoryTotalBytes",
    "temperatureC",
    "load1",
    "load5",
    "load15",
    "powerState",
    "supplyVoltageVolts",
    "throttledFlags",
    "gpuMemoryBytes",
    "gpuClockHz",
    "networkRxBytesPerSecond",
    "networkTxBytesPerSecond",
    "diskReadBytesPerSecond",
    "diskWriteBytesPerSecond",
)
LEGACY_SAMPLE_FIELDS = tuple(
    field for field in SAMPLE_FIELDS if field not in {"supplyVoltageVolts", "throttledFlags"}
)
MAX_UINT32 = (1 << 32) - 1
MAX_SUPPLY_VOLTAGE_VOLTS = 10.0
DEFAULT_KERNEL_MAX_INPUT_BYTES = 8_388_608
DEFAULT_SOCKETS = {
    "cks": "/run/user/1001/docker.sock",
    "psy": "/run/user/1002/docker.sock",
    "wgang": "/run/user/1003/docker.sock",
}
_monotonic = time.monotonic
VIRTUAL_FILESYSTEMS = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
    "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs",
    "overlay", "proc", "pstore", "ramfs", "securityfs", "sysfs", "tmpfs",
    "tracefs",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def finite_number(value: Any, default: float | None = None) -> float | None:
    try:
        parsed = float(value)
    except (OverflowError, TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def uint32(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= MAX_UINT32 else None


def supply_voltage_volts(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        parsed = float(value)
    except OverflowError:
        return None
    if not math.isfinite(parsed) or parsed < 0.0 or parsed > MAX_SUPPLY_VOLTAGE_VOLTS:
        return None
    return round(parsed, 3)


def bounded_text(value: Any, maximum: int = 96) -> str:
    text = str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.:@/+ -]", "_", text)
    return text[:maximum]


def bounded_message(value: Any, maximum: int = 300) -> str:
    """Keep safe sentence punctuation without allowing controls or raw log syntax."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value).strip())
    text = re.sub(r"[^A-Za-z0-9_.:@/+%(),; -]", "_", text)
    return re.sub(r"\s+", " ", text)[:maximum]


def read_text(path: Path, maximum: int = 1_048_576) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(maximum)
    except (OSError, ValueError):
        return ""


def ensure_directory(path: Path, mode: int = 0o750) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass


def atomic_write_json(path: Path, value: Any, mode: int = 0o640) -> None:
    ensure_directory(path.parent)
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def append_json_line(path: Path, value: Mapping[str, Any], mode: int = 0o640) -> None:
    ensure_directory(path.parent)
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rewrite_json_lines(path: Path, records: Sequence[Mapping[str, Any]], limit: int) -> None:
    ensure_directory(path.parent)
    kept = list(records[-limit:])
    payload = "".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
        for record in kept
    )
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), 0o640)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def parse_proc_stat(text: str) -> tuple[int, int] | None:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "cpu" and len(fields) >= 5:
            try:
                numbers = [int(item) for item in fields[1:]]
            except ValueError:
                return None
            idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
            return sum(numbers), idle
    return None


def calculate_cpu(current: tuple[int, int] | None, previous: Any) -> float:
    if current is None or not isinstance(previous, list) or len(previous) != 2:
        return 0.0
    try:
        total_delta = current[0] - int(previous[0])
        idle_delta = current[1] - int(previous[1])
    except (TypeError, ValueError):
        return 0.0
    if total_delta <= 0 or idle_delta < 0:
        return 0.0
    return round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 2)


def parse_meminfo(text: str) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s*(kB)?", line)
        if match:
            multiplier = 1024 if match.group(3) else 1
            values[match.group(1)] = int(match.group(2)) * multiplier
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable")
    if available is None:
        available = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    return total, min(total, max(0, available)) if total else 0


def parse_loadavg(text: str) -> tuple[float, float, float]:
    fields = text.split()
    values = [finite_number(fields[index] if len(fields) > index else None, 0.0) or 0.0 for index in range(3)]
    return tuple(round(value, 2) for value in values)  # type: ignore[return-value]


def parse_uptime(text: str) -> int:
    value = finite_number(text.split()[0] if text.split() else None, 0.0)
    return max(0, int(value or 0))


def parse_net_dev(text: str) -> tuple[int, int]:
    received = transmitted = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        interface, counters = line.split(":", 1)
        if interface.strip() == "lo":
            continue
        fields = counters.split()
        if len(fields) < 9:
            continue
        try:
            received += int(fields[0])
            transmitted += int(fields[8])
        except ValueError:
            continue
    return received, transmitted


def parse_diskstats(text: str) -> tuple[int, int]:
    read_bytes = write_bytes = 0
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        device = fields[2]
        if re.match(r"^(loop|ram|fd|sr|zram|dm-|md\d+)", device):
            continue
        # Avoid counting partitions as well as their parent disk.
        if re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+$", device) or re.match(r"^nvme\d+n\d+p\d+$", device):
            continue
        try:
            read_bytes += int(fields[5]) * 512
            write_bytes += int(fields[9]) * 512
        except ValueError:
            continue
    return read_bytes, write_bytes


def rate_pair(current: tuple[int, int], previous: Any, elapsed: float) -> tuple[float, float]:
    if not isinstance(previous, list) or len(previous) != 2 or elapsed <= 0:
        return 0.0, 0.0
    try:
        first = current[0] - int(previous[0])
        second = current[1] - int(previous[1])
    except (TypeError, ValueError):
        return 0.0, 0.0
    if first < 0 or second < 0:
        return 0.0, 0.0
    return round(first / elapsed, 2), round(second / elapsed, 2)


def read_temperature(sys_root: Path) -> float | None:
    values: list[float] = []
    thermal_root = sys_root / "class" / "thermal"
    try:
        paths = list(thermal_root.glob("thermal_zone*/temp"))
    except OSError:
        paths = []
    for path in paths:
        value = finite_number(read_text(path, 64))
        if value is None:
            continue
        if abs(value) > 1000:
            value /= 1000.0
        if -30 <= value <= 150:
            values.append(value)
    return round(max(values), 1) if values else None


def parse_mountinfo(text: str) -> list[tuple[str, str, str]]:
    mounts: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = fields[4].replace("\\040", " ").replace("\\134", "\\")
            filesystem = fields[separator + 1]
            device = fields[separator + 2]
        except (ValueError, IndexError):
            continue
        if filesystem in VIRTUAL_FILESYSTEMS or not mount_point.startswith("/"):
            continue
        mounts.append((mount_point, device, filesystem))
    return mounts


def collect_filesystems(mountinfo: str, mount_root: Path | None = None) -> list[dict[str, Any]]:
    disks: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_devices: set[str] = set()
    for mount_point, device, filesystem in parse_mountinfo(mountinfo):
        if mount_point in seen or device in seen_devices:
            continue
        seen.add(mount_point)
        actual_path = (mount_root / mount_point.lstrip("/")) if mount_root else Path(mount_point)
        try:
            usage = shutil.disk_usage(actual_path)
        except OSError:
            continue
        if usage.total <= 0:
            continue
        seen_devices.add(device)
        percent = round(100.0 * usage.used / usage.total, 2) if usage.total else 0.0
        disks.append({
            "mount": mount_point,
            "totalBytes": usage.total,
            "usedBytes": usage.used,
            "usedPercent": percent,
        })
    return sorted(disks, key=lambda item: item["mount"])


def parse_os_release(text: str) -> str:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return bounded_text(values.get("PRETTY_NAME") or values.get("NAME") or platform.system(), 128)


def parse_vcgencmd(command: str, output: str) -> tuple[str, Any] | None:
    if command == "get_throttled":
        match = re.fullmatch(r"\s*throttled=0x([0-9a-fA-F]{1,8})\s*", output)
        value = int(match.group(1), 16) if match else None
        return ("throttledFlags", value) if value is not None else None
    if command == "measure_temp":
        match = re.search(r"=(-?[0-9.]+)", output)
        value = finite_number(match.group(1) if match else None)
        return ("temperatureC", round(value, 1)) if value is not None else None
    if command == "measure_clock core":
        match = re.search(r"=(\d+)", output)
        return ("gpuClockHz", int(match.group(1))) if match else None
    if command == "get_mem gpu":
        match = re.search(r"=(\d+)\s*([KMGT])", output, re.IGNORECASE)
        if not match:
            return None
        multipliers = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
        return ("gpuMemoryBytes", int(match.group(1)) * multipliers[match.group(2).upper()])
    if command == "measure_volts core":
        match = re.search(r"=([0-9.]+)V", output)
        value = finite_number(match.group(1) if match else None)
        return ("coreVoltageV", value) if value is not None else None
    if command == "pmic_read_adc EXT5V_V":
        match = re.fullmatch(
            r"\s*EXT5V_V\s+volt\(\d+\)=([0-9]+(?:\.[0-9]+)?)V\s*",
            output,
        )
        parsed = finite_number(match.group(1) if match else None)
        value = supply_voltage_volts(parsed)
        return ("supplyVoltageVolts", value) if value is not None else None
    return None


def collect_gpu(vcgencmd: str, timeout: float) -> dict[str, Any]:
    if not vcgencmd or not (Path(vcgencmd).is_file() and os.access(vcgencmd, os.X_OK)):
        return {}
    result: dict[str, Any] = {}
    for invocation in (
        ("get_throttled",), ("measure_temp",), ("get_mem", "gpu"),
        ("measure_clock", "core"), ("measure_volts", "core"),
        ("pmic_read_adc", "EXT5V_V"),
    ):
        try:
            completed = subprocess.run(
                [vcgencmd, *invocation], capture_output=True, text=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode != 0:
            continue
        parsed = parse_vcgencmd(" ".join(invocation), completed.stdout[:256])
        if parsed:
            result[parsed[0]] = parsed[1]
    return result


def docker_get(socket_path: Path, request_path: str, curl: str, timeout: float) -> Any:
    if not socket_path.is_socket():
        return None
    try:
        completed = subprocess.run(
            [curl, "--silent", "--show-error", "--fail", "--max-time", str(timeout),
             "--unix-socket", str(socket_path), "http://localhost" + request_path],
            capture_output=True, text=True, timeout=timeout + 0.5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or len(completed.stdout) > 8_388_608:
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def docker_cpu_state(stats: Mapping[str, Any]) -> dict[str, int] | None:
    cpu = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), dict) else {}
    cpu_usage = cpu.get("cpu_usage") if isinstance(cpu.get("cpu_usage"), dict) else {}
    cpu_total = finite_number(cpu_usage.get("total_usage"))
    system_total = finite_number(cpu.get("system_cpu_usage"))
    if cpu_total is None or system_total is None or cpu_total < 0 or system_total < 0:
        return None
    online = int(finite_number(cpu.get("online_cpus"), 0) or len(cpu_usage.get("percpu_usage", [])) or 1)
    return {"cpuTotal": int(cpu_total), "systemTotal": int(system_total), "onlineCpus": max(1, online)}


def docker_cpu_percent(current: Mapping[str, Any] | None, previous: Any) -> float | None:
    if current is None or not isinstance(previous, Mapping):
        return None
    try:
        cpu_delta = int(current["cpuTotal"]) - int(previous["cpuTotal"])
        system_delta = int(current["systemTotal"]) - int(previous["systemTotal"])
        online = max(1, int(current["onlineCpus"]))
    except (KeyError, TypeError, ValueError):
        return None
    if cpu_delta < 0 or system_delta <= 0:
        return None
    return round(max(0.0, cpu_delta / system_delta * online * 100.0), 2)


def container_from_api(
    raw: Mapping[str, Any], owner: str, stats: Mapping[str, Any] | None, previous_cpu: Any = None
) -> dict[str, Any]:
    names = raw.get("Names") if isinstance(raw.get("Names"), list) else []
    name = str(names[0]).lstrip("/") if names else "unnamed"
    state = bounded_text(raw.get("State", "unknown"), 24).lower()
    status = str(raw.get("Status", ""))
    health_match = re.search(r"\((healthy|unhealthy|starting)\)", status, re.IGNORECASE)
    health = health_match.group(1).lower() if health_match else ("none" if state != "running" else "unknown")
    memory_bytes: int | None = None
    memory_percent: float | None = None
    cpu_percent: float | None = None
    if isinstance(stats, Mapping):
        memory = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
        memory_bytes = max(0, int(finite_number(memory.get("usage"), 0) or 0))
        memory_limit = max(0, int(finite_number(memory.get("limit"), 0) or 0))
        memory_percent = round(100.0 * memory_bytes / memory_limit, 2) if memory_limit else 0.0
        cpu_percent = docker_cpu_percent(docker_cpu_state(stats), previous_cpu)
    return {
        "name": bounded_text(name, 128),
        "owner": bounded_text(owner, 32),
        "state": state,
        "health": health,
        "cpuPercent": cpu_percent,
        "memoryBytes": memory_bytes,
        "memoryPercent": memory_percent,
    }


def collect_containers(
    sockets: Mapping[str, Path], curl: str, timeout: float, previous_cpu: Any = None
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    containers: list[dict[str, Any]] = []
    deadline = _monotonic() + 20.0
    entries: list[tuple[str, Path, Mapping[str, Any]]] = []
    # Fetch all three cheap list endpoints first. A slow stats endpoint for one
    # owner must not prevent containers belonging to later owners from appearing.
    for owner, socket_path in sockets.items():
        raw_list = docker_get(socket_path, "/v1.41/containers/json?all=1", curl, timeout)
        if not isinstance(raw_list, list):
            continue
        for raw in raw_list[:200]:
            if isinstance(raw, dict):
                entries.append((owner, socket_path, raw))

    previous_state = previous_cpu if isinstance(previous_cpu, Mapping) else {}
    listed_keys: list[str] = []
    stats_candidates: list[tuple[int, Path, str, str]] = []
    for index, (owner, socket_path, raw) in enumerate(entries):
        container_id = str(raw.get("Id", ""))
        state_key = f"{owner}:{container_id}"
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}:[a-fA-F0-9]{12,64}", state_key):
            listed_keys.append(state_key)
        if (
            raw.get("State") == "running"
            and re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id)
            and len(stats_candidates) < 30
        ):
            stats_candidates.append((index, socket_path, container_id, state_key))

    stats_by_index: dict[int, Mapping[str, Any]] = {}
    remaining = max(0.0, deadline - _monotonic())
    if stats_candidates and remaining > 0:
        worker_count = min(6, len(stats_candidates))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="docker-stats"
        ) as executor:
            futures = {
                executor.submit(
                    docker_get,
                    socket_path,
                    f"/v1.41/containers/{container_id}/stats?stream=false&one-shot=true",
                    curl,
                    timeout,
                ): index
                for index, socket_path, container_id, _state_key in stats_candidates
            }
            done, pending = concurrent.futures.wait(futures, timeout=remaining)
            for future in pending:
                future.cancel()
            for future in done:
                try:
                    stats = future.result()
                except Exception:
                    continue
                if isinstance(stats, dict):
                    stats_by_index[futures[future]] = stats

    next_cpu_state: dict[str, dict[str, int]] = {}
    # Retain prior counters only for containers still listed, and hard-cap the
    # protected internal state even if all three daemons return 200 entries.
    for state_key in listed_keys[:600]:
        prior_value = previous_state.get(state_key)
        if isinstance(prior_value, Mapping):
            try:
                next_cpu_state[state_key] = {
                    "cpuTotal": int(prior_value["cpuTotal"]),
                    "systemTotal": int(prior_value["systemTotal"]),
                    "onlineCpus": max(1, int(prior_value["onlineCpus"])),
                }
            except (KeyError, TypeError, ValueError):
                pass

    retained_keys = set(listed_keys[:600])
    for index, (owner, _socket_path, raw) in enumerate(entries):
        stats = stats_by_index.get(index)
        container_id = str(raw.get("Id", ""))
        state_key = f"{owner}:{container_id}"
        current_cpu = docker_cpu_state(stats) if isinstance(stats, Mapping) else None
        containers.append(container_from_api(
            raw, owner, stats if isinstance(stats, dict) else None, previous_state.get(state_key)
        ))
        if current_cpu is not None and state_key in retained_keys:
            next_cpu_state[state_key] = current_cpu
    return sorted(containers, key=lambda item: (item["owner"], item["name"])), next_cpu_state


TIMESTAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\d[T ][0-9:.+-]+(?:Z)?)")
SYSLOG_TIMESTAMP_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)")
POWER_EVENT_DETAILS = {
    ("under-voltage", "active"): (
        "warning",
        "Kernel reported an under-voltage condition.",
    ),
    ("under-voltage", "recovered"): (
        "info",
        "Kernel reported voltage recovery.",
    ),
    ("nvme-reset", "active"): (
        "critical",
        "Kernel reported an NVMe controller reset.",
    ),
    ("nvme-io", "active"): (
        "critical",
        "Kernel reported an NVMe I/O error.",
    ),
}


def event_timestamp(line: str, fallback: str) -> str:
    match = TIMESTAMP_RE.match(line)
    if match:
        try:
            parsed = dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return iso_timestamp(parsed)
        except ValueError:
            pass
    syslog = SYSLOG_TIMESTAMP_RE.match(line)
    if syslog:
        try:
            reference = dt.datetime.fromisoformat(fallback.replace("Z", "+00:00"))
            naive = dt.datetime.strptime(
                f"{reference.year} {syslog.group(1)} {syslog.group(2)} {syslog.group(3)}",
                "%Y %b %d %H:%M:%S",
            )
            epoch = time.mktime(naive.timetuple())
            candidate = dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
            if candidate > reference + dt.timedelta(days=2):
                naive = naive.replace(year=naive.year - 1)
                candidate = dt.datetime.fromtimestamp(time.mktime(naive.timetuple()), dt.timezone.utc)
            return iso_timestamp(candidate)
        except (OverflowError, ValueError):
            pass
    return fallback


def alert_message(reason: str, recovered: bool = False) -> str:
    state = "recovered" if recovered else "active"
    return f"Host condition {bounded_text(reason, 64)} is {state}."


def sanitize_alert_line(line: str, fallback_timestamp: str) -> dict[str, Any] | None:
    timestamp = event_timestamp(line, fallback_timestamp)
    match = re.search(r"\bSNAPSHOT\s+reason=([A-Za-z0-9_.:-]+)", line)
    if match:
        reason = bounded_text(match.group(1), 64)
        return {"timestamp": timestamp, "severity": "warning", "kind": "host", "status": "active", "message": alert_message(reason)}
    match = re.search(r"\bRECOVERED\s+reason=([A-Za-z0-9_.:-]+)", line)
    if match:
        reason = bounded_text(match.group(1), 64)
        return {"timestamp": timestamp, "severity": "info", "kind": "host", "status": "recovered", "message": alert_message(reason, True)}
    if re.search(r"\bmetrics\b", line, re.IGNORECASE):
        metrics: dict[str, float] = {}
        mappings = {
            "cpu": "cpuPercent", "memory_available": "memoryAvailablePercent", "temperature": "temperatureC"
        }
        for source, destination in mappings.items():
            match = re.search(rf"(?:^|\s){source}=(-?[0-9.]+)", line)
            value = finite_number(match.group(1) if match else None)
            if value is not None:
                metrics[destination] = value
        if metrics:
            parts = []
            if "cpuPercent" in metrics:
                parts.append(f"CPU {metrics['cpuPercent']:g}%")
            if "memoryAvailablePercent" in metrics:
                parts.append(f"memory available {metrics['memoryAvailablePercent']:g}%")
            if "temperatureC" in metrics:
                parts.append(f"temperature {metrics['temperatureC']:g} C")
            severity = "warning" if metrics.get("cpuPercent", 0) >= 90 or metrics.get("temperatureC", 0) >= 80 else "info"
            return {
                "timestamp": timestamp, "severity": severity, "kind": "metrics",
                "status": "observed", "message": "; ".join(parts) + ".",
            }
    return None


def existing_alert_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Retain only already-contract-safe records when rewriting the bounded file."""
    required = {"timestamp", "severity", "kind", "status", "message"}
    if set(record) != required:
        return None
    timestamp = str(record.get("timestamp", ""))
    normalized_timestamp = event_timestamp(timestamp, "")
    if not normalized_timestamp:
        return None
    severity = str(record.get("severity", "info")).lower()
    if severity not in {"info", "warning", "critical"}:
        severity = "info"
    message = bounded_message(record.get("message", ""), 300)
    legacy_metrics = re.fullmatch(
        r"CPU (-?[0-9.]+)__ memory available (-?[0-9.]+) bytes_ temperature (-?[0-9.]+) C\.",
        message,
    )
    if legacy_metrics:
        cpu, memory, temperature = legacy_metrics.groups()
        message = f"CPU {cpu}%; memory available {memory}%; temperature {temperature} C."
    if not message:
        return None
    # Our own messages contain no arbitrary raw data. Reject common secret or
    # command markers if a foreign writer has modified the export.
    if re.search(r"password|passwd|secret|token|api.?key|command|argv|sudo\s", message, re.IGNORECASE):
        message = "Sensitive alert details were redacted."
    return {
        "timestamp": normalized_timestamp,
        "severity": severity,
        "kind": bounded_text(record.get("kind", "host"), 64),
        "status": bounded_text(record.get("status", "unknown"), 32),
        "message": message,
    }


def sanitize_kernel_power_line(line: str, fallback_timestamp: str) -> dict[str, str] | None:
    event: tuple[str, str] | None = None
    if "Undervoltage detected!" in line:
        event = ("under-voltage", "active")
    elif "Voltage normalised" in line:
        event = ("under-voltage", "recovered")
    elif re.search(r"\bnvme\S*.*controller is down; will reset\b", line, re.IGNORECASE):
        event = ("nvme-reset", "active")
    elif re.search(r"\bnvme\S*", line, re.IGNORECASE) and (
        "I/O Error" in line or re.search(r"I/O error,\s*dev\s+nvme", line, re.IGNORECASE)
    ):
        event = ("nvme-io", "active")
    if event is None:
        return None
    severity, message = POWER_EVENT_DETAILS[event]
    return {
        "timestamp": event_timestamp(line, fallback_timestamp),
        "severity": severity,
        "kind": event[0],
        "status": event[1],
        "message": message,
    }


def existing_power_record(record: Mapping[str, Any]) -> dict[str, str] | None:
    required = {"timestamp", "severity", "kind", "status", "message"}
    if set(record) != required:
        return None
    normalized_timestamp = event_timestamp(str(record.get("timestamp", "")), "")
    if not normalized_timestamp:
        return None
    event = (str(record.get("kind", "")), str(record.get("status", "")))
    details = POWER_EVENT_DETAILS.get(event)
    if details is None:
        return None
    severity, message = details
    if record.get("severity") != severity or record.get("message") != message:
        return None
    return {
        "timestamp": normalized_timestamp,
        "severity": severity,
        "kind": event[0],
        "status": event[1],
        "message": message,
    }


def existing_sample_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    fields = frozenset(record)
    if fields not in {frozenset(SAMPLE_FIELDS), frozenset(LEGACY_SAMPLE_FIELDS)}:
        return None
    timestamp = event_timestamp(str(record.get("timestamp", "")), "")
    if not timestamp:
        return None
    normalized: dict[str, Any] = {}
    valid_power_states = {
        "normal", "degraded-history", "throttled", "thermal-limit",
        "frequency-capped", "under-voltage",
    }
    for field in SAMPLE_FIELDS:
        value = record.get(field)
        if field == "timestamp":
            normalized[field] = timestamp
        elif field == "powerState":
            normalized[field] = value if isinstance(value, str) and value in valid_power_states else None
        elif field == "supplyVoltageVolts":
            normalized[field] = supply_voltage_volts(value)
        elif field == "throttledFlags":
            normalized[field] = uint32(value)
        elif value is None:
            normalized[field] = None
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            normalized[field] = None
        else:
            normalized[field] = value if finite_number(value) is not None else None
    return normalized


def deduplicate_power_records(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    seen: set[tuple[str, Any, Any]] = set()
    for record in records:
        # event_timestamp deliberately truncates sub-second kernel timestamps.
        # Status remains part of the key so a rare active/recovered pair in one
        # second is not collapsed, while bursty duplicate kernel messages are.
        timestamp_second = event_timestamp(str(record.get("timestamp", "")), "")
        key = (timestamp_second, record.get("kind"), record.get("status"))
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result


def existing_privilege_record(record: Mapping[str, Any]) -> dict[str, str] | None:
    required = {"timestamp", "actor", "target", "action", "result"}
    if set(record) != required:
        return None
    normalized_timestamp = event_timestamp(str(record.get("timestamp", "")), "")
    if not normalized_timestamp:
        return None
    action = str(record.get("action", "unknown")).lower()
    if action not in {"sudo", "su", "authentication", "policy", "unknown"}:
        action = "unknown"
    result = str(record.get("result", "unknown")).lower()
    if result not in {"success", "failure", "unknown"}:
        result = "unknown"
    return {
        "timestamp": normalized_timestamp,
        "actor": safe_identity(record.get("actor", "unknown")),
        "target": safe_identity(record.get("target", "unknown")),
        "action": action,
        "result": result,
    }


def safe_identity(value: Any) -> str:
    match = re.search(r"[A-Za-z0-9_.@-]+", str(value))
    return match.group(0)[:64] if match else "unknown"


def sanitize_privilege_line(line: str, fallback_timestamp: str | None = None) -> dict[str, str] | None:
    timestamp = event_timestamp(line, fallback_timestamp or iso_timestamp(utc_now()))
    try:
        structured = json.loads(line)
    except json.JSONDecodeError:
        structured = None
    if isinstance(structured, dict):
        action_value = str(structured.get("action", "unknown")).lower()
        action = "sudo" if "sudo" in action_value else "su" if re.search(r"\bsu\b", action_value) else "authentication" if "auth" in action_value else "policy" if "policy" in action_value else "unknown"
        result_value = str(structured.get("result", structured.get("outcome", "unknown"))).lower()
        result = "failure" if re.search(r"fail|denied|reject|error", result_value) else "success" if re.search(r"success|allowed|accept|ok", result_value) else "unknown"
        return {
            "timestamp": event_timestamp(str(structured.get("timestamp", "")), timestamp),
            "actor": safe_identity(structured.get("actor", structured.get("user", "unknown"))),
            "target": safe_identity(structured.get("target", structured.get("targetUser", "unknown"))),
            "action": action,
            "result": result,
        }
    lowered = line.lower()
    if "sudo" not in lowered and re.search(r"\bsu(?:\[|:|\s)", lowered) is None:
        return None
    action = "sudo" if "sudo" in lowered else "su"
    result = "failure" if re.search(r"authentication failure|incorrect password|failed su|not in sudoers|command not allowed", lowered) else "success"
    actor = target = "unknown"
    match = re.search(r"session opened for user\s+([^\s(]+).*?\bby\s+([^\s(]+)", line, re.IGNORECASE)
    if match:
        target, actor = match.group(1), match.group(2)
    else:
        match = re.search(
            r"\bsudo(?:\[\d+\])?:\s*([A-Za-z0-9_.@-]+)\s*:\s*.*?\bUSER=([^\s;]+)",
            line,
            re.IGNORECASE,
        )
        if match:
            actor, target = match.group(1), match.group(2)
        else:
            match = re.search(r"FAILED SU \(to\s+([^\s)]+)\)\s+([^\s]+)", line, re.IGNORECASE)
            if match:
                target, actor = match.group(1), match.group(2)
    actor_match = re.search(r"\bactor=([A-Za-z0-9_.@-]+)", line)
    target_match = re.search(r"\btarget=([A-Za-z0-9_.@-]+)", line)
    if actor_match:
        actor = actor_match.group(1)
    if target_match:
        target = target_match.group(1)
    return {"timestamp": timestamp, "actor": safe_identity(actor), "target": safe_identity(target), "action": action, "result": result}


def read_new_lines(path: Path, cursor: Mapping[str, Any], max_bytes: int) -> tuple[list[str], dict[str, int]]:
    try:
        stat = path.stat()
        inode = int(stat.st_ino)
        old_inode = int(cursor.get("inode", -1))
        old_offset = int(cursor.get("offset", 0))
        if old_inode != inode or old_offset < 0 or old_offset > stat.st_size:
            old_offset = max(0, stat.st_size - max_bytes)
        start = max(old_offset, stat.st_size - max_bytes)
        with path.open("rb") as handle:
            handle.seek(start)
            if start:
                handle.readline(max_bytes)  # discard a bounded, possibly partial line
            content = handle.read(max_bytes)
            end = handle.tell()
        lines = content.decode("utf-8", errors="replace").splitlines()
        return lines, {"inode": inode, "offset": end}
    except (OSError, TypeError, ValueError):
        return [], dict(cursor) if isinstance(cursor, dict) else {}


def existing_json_lines(path: Path, limit: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        maximum = min(8_388_608, max(65_536, limit * 1024))
        size = path.stat().st_size
        start = max(0, size - maximum)
        with path.open("rb") as handle:
            handle.seek(start)
            if start:
                handle.readline(maximum)
            content = handle.read(maximum)
            for raw_line in content.splitlines():
                try:
                    record = json.loads(raw_line.decode("utf-8", errors="replace"))
                except (json.JSONDecodeError, UnicodeError):
                    continue
                if isinstance(record, dict):
                    records.append(record)
                    if len(records) > limit:
                        del records[: len(records) - limit]
    except OSError:
        pass
    return records


def export_sanitized_logs(config: "Config", now_text: str, gpu: Mapping[str, Any] | None = None) -> None:
    cursor_path = config.output_dir / ".state" / "log-cursors.json"
    cursors = load_json(cursor_path)
    next_cursors = dict(cursors)

    alert_records = [
        normalized for record in existing_json_lines(config.output_dir / "alerts.jsonl", config.max_log_records)
        if (normalized := existing_alert_record(record)) is not None
    ]
    lines, cursor = read_new_lines(config.events_log, cursors.get("alerts", {}), config.max_input_bytes)
    for line in lines:
        sanitized = sanitize_alert_line(line, now_text)
        if sanitized:
            alert_records.append(sanitized)
    next_cursors["alerts"] = cursor

    # vcgencmd low bits describe a currently active under-voltage, frequency
    # cap, throttle, or thermal limit. Export transitions, not one alert/minute.
    flags = uint32(gpu.get("throttledFlags")) if isinstance(gpu, Mapping) else None
    voltage = supply_voltage_volts(gpu.get("supplyVoltageVolts")) if isinstance(gpu, Mapping) else None
    if flags is not None:
        active_flags = flags & 0xF
        previous_flags = uint32(cursors.get("powerFlags"))
        detail = f" Full flags are 0x{flags:08x}."
        if voltage is not None:
            detail += f" Supply voltage is {voltage:.3f} V."
        if active_flags and active_flags != previous_flags:
            alert_records.append({
                "timestamp": now_text,
                "severity": "warning",
                "kind": "power",
                "status": "active",
                "message": f"Current vcgencmd throttle flags are 0x{active_flags:x}." + detail,
            })
        elif not active_flags and previous_flags not in {None, 0}:
            alert_records.append({
                "timestamp": now_text,
                "severity": "info",
                "kind": "power",
                "status": "recovered",
                "message": "Current vcgencmd throttle condition recovered." + detail,
            })
        next_cursors["powerFlags"] = active_flags

    power_records = [
        normalized for record in existing_json_lines(config.output_dir / "power.jsonl", config.max_log_records)
        if (normalized := existing_power_record(record)) is not None
    ]
    kernel_cursor = cursors.get("kernelPower", {})
    if not isinstance(kernel_cursor, Mapping):
        kernel_cursor = {}
    lines, cursor = read_new_lines(config.kernel_log, kernel_cursor, config.kernel_max_input_bytes)
    for line in lines:
        sanitized = sanitize_kernel_power_line(line, now_text)
        if sanitized:
            power_records.append(sanitized)
    next_cursors["kernelPower"] = cursor
    power_records = deduplicate_power_records(power_records)

    privilege_records = [
        normalized for record in existing_json_lines(config.output_dir / "privilege.jsonl", config.max_log_records)
        if (normalized := existing_privilege_record(record)) is not None
    ]
    privilege_cursors = cursors.get("privilege", {}) if isinstance(cursors.get("privilege"), dict) else {}
    next_privilege: dict[str, Any] = {}
    for path in config.privilege_logs:
        key = str(path)
        lines, cursor = read_new_lines(path, privilege_cursors.get(key, {}), config.max_input_bytes)
        for line in lines:
            sanitized = sanitize_privilege_line(line, now_text)
            if sanitized:
                privilege_records.append(sanitized)
        next_privilege[key] = cursor
    next_cursors["privilege"] = next_privilege

    rewrite_json_lines(config.output_dir / "alerts.jsonl", alert_records, config.max_log_records)
    rewrite_json_lines(config.output_dir / "power.jsonl", power_records, config.max_log_records)
    rewrite_json_lines(config.output_dir / "privilege.jsonl", privilege_records, config.max_log_records)
    atomic_write_json(cursor_path, next_cursors, 0o600)


def prune_history(history_dir: Path, today: dt.date, retention_days: int) -> None:
    cutoff = today - dt.timedelta(days=max(1, retention_days) - 1)
    try:
        paths = list(history_dir.iterdir())
    except OSError:
        return
    for path in paths:
        match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\.jsonl", path.name)
        if not match or not path.is_file():
            continue
        try:
            file_date = dt.date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if file_date < cutoff:
            try:
                path.unlink()
            except OSError:
                pass


def parse_socket_map(value: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for entry in value.split(","):
        if "=" not in entry:
            continue
        owner, path = entry.split("=", 1)
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", owner.strip()) and path.strip().startswith("/"):
            result[owner.strip()] = Path(path.strip())
    return result


@dataclass
class Config:
    output_dir: Path = Path("/var/lib/monitor-export")
    runtime_dir: Path = Path("/run/monitor-collector")
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")
    etc_root: Path = Path("/etc")
    mountinfo: Path | None = None
    mount_root: Path | None = None
    events_log: Path = Path("/var/log/server-watch/events.log")
    kernel_log: Path = Path("/var/log/kern.log")
    privilege_logs: list[Path] = field(default_factory=lambda: [Path("/var/log/privilege-events.log")])
    docker_sockets: dict[str, Path] = field(default_factory=lambda: {key: Path(value) for key, value in DEFAULT_SOCKETS.items()})
    curl: str = "/usr/bin/curl"
    vcgencmd: str = "/usr/bin/vcgencmd"
    command_timeout: float = 2.0
    retention_days: int = 30
    max_log_records: int = 5000
    max_input_bytes: int = 1_048_576
    kernel_max_input_bytes: int = DEFAULT_KERNEL_MAX_INPUT_BYTES

    @property
    def mountinfo_path(self) -> Path:
        return self.mountinfo or self.proc_root / "self" / "mountinfo"


def config_from_environment(arguments: Sequence[str] | None = None) -> Config:
    env = os.environ
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=env.get("MONITOR_OUTPUT_DIR", "/var/lib/monitor-export"))
    parser.add_argument("--runtime-dir", default=env.get("MONITOR_RUNTIME_DIR", "/run/monitor-collector"))
    parser.add_argument("--proc-root", default=env.get("MONITOR_PROC_ROOT", "/proc"))
    parser.add_argument("--sys-root", default=env.get("MONITOR_SYS_ROOT", "/sys"))
    parser.add_argument("--etc-root", default=env.get("MONITOR_ETC_ROOT", "/etc"))
    parser.add_argument("--mountinfo", default=env.get("MONITOR_MOUNTINFO"))
    parser.add_argument("--mount-root", default=env.get("MONITOR_MOUNT_ROOT"))
    parser.add_argument("--events-log", default=env.get("MONITOR_EVENTS_LOG", "/var/log/server-watch/events.log"))
    parser.add_argument("--kernel-log", default=env.get("MONITOR_KERNEL_LOG", "/var/log/kern.log"))
    parser.add_argument("--privilege-logs", default=env.get("MONITOR_PRIVILEGE_LOGS", "/var/log/privilege-events.log"))
    parser.add_argument("--docker-sockets", default=env.get(
        "MONITOR_DOCKER_SOCKETS", ",".join(f"{owner}={path}" for owner, path in DEFAULT_SOCKETS.items())
    ))
    parser.add_argument("--curl", default=env.get("MONITOR_CURL", "/usr/bin/curl"))
    parser.add_argument("--vcgencmd", default=env.get("MONITOR_VCGENCMD", "/usr/bin/vcgencmd"))
    parser.add_argument("--command-timeout", type=float, default=float(env.get("MONITOR_COMMAND_TIMEOUT", "2")))
    parser.add_argument("--retention-days", type=int, default=int(env.get("MONITOR_RETENTION_DAYS", "30")))
    parser.add_argument("--max-log-records", type=int, default=int(env.get("MONITOR_MAX_LOG_RECORDS", "5000")))
    parser.add_argument("--max-input-bytes", type=int, default=int(env.get("MONITOR_MAX_INPUT_BYTES", "1048576")))
    parser.add_argument(
        "--kernel-max-input-bytes",
        type=int,
        default=int(env.get("MONITOR_KERNEL_MAX_INPUT_BYTES", str(DEFAULT_KERNEL_MAX_INPUT_BYTES))),
    )
    values = parser.parse_args(arguments)
    return Config(
        output_dir=Path(values.output_dir), runtime_dir=Path(values.runtime_dir),
        proc_root=Path(values.proc_root), sys_root=Path(values.sys_root), etc_root=Path(values.etc_root),
        mountinfo=Path(values.mountinfo) if values.mountinfo else None,
        mount_root=Path(values.mount_root) if values.mount_root else None,
        events_log=Path(values.events_log), kernel_log=Path(values.kernel_log),
        privilege_logs=[Path(item) for item in values.privilege_logs.split(":") if item],
        docker_sockets=parse_socket_map(values.docker_sockets), curl=values.curl, vcgencmd=values.vcgencmd,
        command_timeout=max(0.1, min(10.0, values.command_timeout)),
        retention_days=max(1, min(366, values.retention_days)),
        max_log_records=max(10, min(100_000, values.max_log_records)),
        max_input_bytes=max(4096, min(16_777_216, values.max_input_bytes)),
        kernel_max_input_bytes=max(65_536, min(16_777_216, values.kernel_max_input_bytes)),
    )


def run(config: Config, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    now_text = iso_timestamp(now)
    ensure_directory(config.output_dir)
    ensure_directory(config.runtime_dir)
    lock_path = config.runtime_dir / "collector.lock"
    with lock_path.open("w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        delta_path = config.runtime_dir / "delta-state.json"
        prior = load_json(delta_path)
        monotonic = time.monotonic()
        elapsed = monotonic - (finite_number(prior.get("monotonic"), monotonic) or monotonic)

        cpu = parse_proc_stat(read_text(config.proc_root / "stat"))
        memory_total, memory_available = parse_meminfo(read_text(config.proc_root / "meminfo"))
        network = parse_net_dev(read_text(config.proc_root / "net" / "dev"))
        disk = parse_diskstats(read_text(config.proc_root / "diskstats"))
        network_rates = rate_pair(network, prior.get("network"), elapsed)
        disk_rates = rate_pair(disk, prior.get("disk"), elapsed)
        temperature = read_temperature(config.sys_root)
        gpu = collect_gpu(config.vcgencmd, config.command_timeout)
        if temperature is None and isinstance(gpu.get("temperatureC"), (int, float)):
            temperature = gpu["temperatureC"]

        load1, load5, load15 = parse_loadavg(read_text(config.proc_root / "loadavg", 128))
        power_flags = uint32(gpu.get("throttledFlags"))
        supply_voltage = supply_voltage_volts(gpu.get("supplyVoltageVolts"))
        power_state = None
        if power_flags is not None:
            active_flags = power_flags & 0xF
            historical_flags = (power_flags >> 16) & 0xF
            power_state = ("degraded-history" if historical_flags else "normal") if active_flags == 0 else (
                "throttled" if active_flags & 0x4 else
                "thermal-limit" if active_flags & 0x8 else
                "frequency-capped" if active_flags & 0x2 else
                "under-voltage"
            )
        latest = {
            "timestamp": now_text,
            "cpuPercent": calculate_cpu(cpu, prior.get("cpu")),
            "memoryPercent": round(100.0 * (memory_total - memory_available) / memory_total, 2) if memory_total else 0.0,
            "memoryUsedBytes": memory_total - memory_available if memory_total else 0,
            "memoryTotalBytes": memory_total,
            "temperatureC": temperature,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "powerState": power_state,
            "supplyVoltageVolts": supply_voltage,
            "throttledFlags": power_flags,
            "gpuMemoryBytes": gpu.get("gpuMemoryBytes") if isinstance(gpu.get("gpuMemoryBytes"), int) else None,
            "gpuClockHz": gpu.get("gpuClockHz") if isinstance(gpu.get("gpuClockHz"), int) else None,
            "networkRxBytesPerSecond": network_rates[0],
            "networkTxBytesPerSecond": network_rates[1],
            "diskReadBytesPerSecond": disk_rates[0],
            "diskWriteBytesPerSecond": disk_rates[1],
        }
        assert tuple(latest) == SAMPLE_FIELDS

        host = {
            "hostname": bounded_text(socket.gethostname(), 255),
            "os": parse_os_release(read_text(config.etc_root / "os-release", 8192)),
            "architecture": bounded_text(platform.machine() or "unknown", 64),
            "uptimeSeconds": parse_uptime(read_text(config.proc_root / "uptime", 128)),
        }
        containers, container_cpu_state = collect_containers(
            config.docker_sockets, config.curl, config.command_timeout, prior.get("containers")
        )
        current = {
            "generatedAt": now_text,
            "host": host,
            "latest": latest,
            "disks": collect_filesystems(read_text(config.mountinfo_path), config.mount_root),
            "containers": containers,
        }
        # The strict public snapshot schema has no GPU object. GPU temperature,
        # supply voltage, and throttle flags contribute only to the safe latest
        # sample; power transitions go to the bounded semantic event exports.
        atomic_write_json(config.output_dir / "current.json", current)
        history_dir = config.output_dir / "history"
        history_path = history_dir / f"{now.date().isoformat()}.jsonl"
        history_records = [
            normalized for record in existing_json_lines(history_path, 1999)
            if (normalized := existing_sample_record(record)) is not None
        ]
        history_records.append(latest)
        rewrite_json_lines(history_path, history_records, 2000)
        prune_history(history_dir, now.date(), config.retention_days)
        export_sanitized_logs(config, now_text, gpu)
        atomic_write_json(delta_path, {
            "monotonic": monotonic,
            "cpu": list(cpu) if cpu else None,
            "network": list(network),
            "disk": list(disk),
            "containers": container_cpu_state,
        }, 0o600)
        return current


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        run(config_from_environment(arguments))
        return 0
    except BlockingIOError:
        return 0
    except Exception as error:  # one concise message for journald; never include host data
        print(f"monitor-collector: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
