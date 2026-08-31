#!/usr/bin/env python3
"""Bounded Linux telemetry collected from procfs/sysfs without secrets.

The module deliberately never reads ``cmdline``, ``environ`` or process
environment files.  Monotonic kernel counters are exported together with
rates derived only when the previous counter identity and every required
counter are valid.  A missing previous sample or a counter decrease therefore
produces ``None`` rather than a fabricated spike.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA_VERSION = 1
MAX_CPU_COUNT = 512
MAX_BLOCK_DEVICES = 128
MAX_INTERFACES = 256
MAX_TCP_SOCKETS = 65_536
MAX_FILESYSTEMS = 256
MAX_PROCESSES = 8192
MAX_FDS_PER_PROCESS = 4096
MAX_PROCESS_GROUPS = 12
MAX_SYSTEMD_UNITS = 32
MAX_THERMAL_SENSORS = 64
MAX_FANS = 32
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_COUNTER = (1 << 63) - 1
MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
PROCESS_SCAN_SECONDS = 1.25
_monotonic = time.monotonic

PSEUDO_FILESYSTEMS = frozenset({
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs",
    "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs",
    "mqueue", "nsfs", "overlay", "proc", "pstore", "ramfs",
    "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
})
NETWORK_FILESYSTEMS = frozenset({
    "9p", "afs", "ceph", "cifs", "fuse.sshfs", "glusterfs", "nfs",
    "nfs4", "smb3",
})
CPU_MODES = (
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
)
DISK_COUNTER_FIELDS = (
    "reads", "readsMerged", "sectorsRead", "readMilliseconds",
    "writes", "writesMerged", "sectorsWritten", "writeMilliseconds",
    "inFlight", "ioMilliseconds", "weightedIoMilliseconds",
    "discards", "discardsMerged", "sectorsDiscarded", "discardMilliseconds",
    "flushes", "flushMilliseconds",
)
NETWORK_COUNTER_FIELDS = (
    "rxBytes", "rxPackets", "rxErrors", "rxDropped", "rxFifo",
    "rxFrame", "rxCompressed", "rxMulticast", "txBytes", "txPackets",
    "txErrors", "txDropped", "txFifo", "txCollisions", "txCarrier",
    "txCompressed",
)


def _finite(value: Any, minimum: float | None = None, maximum: float | None = None) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(parsed):
        return None
    if minimum is not None and parsed < minimum:
        return None
    if maximum is not None and parsed > maximum:
        return None
    return parsed


def _safe_integer(value: Any, maximum: int = MAX_COUNTER) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0 <= parsed <= maximum else None


def _safe_label(value: Any, maximum: int = 64) -> str:
    text = str(value).strip()
    text = re.sub(r"[^A-Za-z0-9_.:@/+ -]", "_", text)
    return text[:maximum] or "unknown"


def read_limited(path: Path, maximum: int = 65_536) -> tuple[str, str]:
    """Return ``(status, text)`` while retaining permission/missing state."""
    maximum = max(1, min(MAX_FILE_BYTES, maximum))
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            value = handle.read(maximum + 1)
    except FileNotFoundError:
        return "unsupported", ""
    except PermissionError:
        return "permission_error", ""
    except (OSError, ValueError):
        return "unavailable", ""
    if len(value) > maximum:
        return "too_large", ""
    return "supported", value


def _read_number(path: Path, minimum: float = 0, maximum: float = float(MAX_COUNTER)) -> tuple[str, float | None]:
    status, text = read_limited(path, 128)
    if status != "supported":
        return status, None
    value = _finite(text.strip(), minimum, maximum)
    return ("supported", value) if value is not None else ("invalid", None)


def _read_token(path: Path, allowed: set[str], maximum: int = 64) -> tuple[str, str | None]:
    status, text = read_limited(path, maximum)
    if status != "supported":
        return status, None
    token = text.strip().lower()
    return ("supported", token) if token in allowed else ("invalid", None)


def _counter_delta(current: int | None, previous: Any) -> int | None:
    prior = _safe_integer(previous)
    if current is None or prior is None or current < prior:
        return None
    return current - prior


def _rate(delta: int | None, elapsed: float, scale: float = 1.0) -> float | None:
    if delta is None or not math.isfinite(elapsed) or elapsed <= 0:
        return None
    return round(delta * scale / elapsed, 2)


def _counter_status(current: Mapping[str, int], previous: Any, fields: Sequence[str]) -> str:
    if not isinstance(previous, Mapping) or any(name not in previous for name in fields):
        return "warmup"
    for name in fields:
        if _counter_delta(current.get(name), previous.get(name)) is None:
            return "counter_reset"
    return "ok"


def parse_cpu_stat(text: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or re.fullmatch(r"cpu(?:\d+)?", fields[0]) is None:
            continue
        if fields[0] != "cpu" and int(fields[0][3:]) >= 4096:
            continue
        try:
            numbers = [int(value) for value in fields[1:11]]
        except ValueError:
            continue
        if len(numbers) < 4 or any(value < 0 or value > MAX_COUNTER for value in numbers):
            continue
        numbers.extend([0] * (10 - len(numbers)))
        # guest and guest_nice are already included in user/nice by Linux.
        result[fields[0]] = dict(zip(CPU_MODES, numbers[:8]))
        if len(result) >= MAX_CPU_COUNT + 1:
            break
    return result


def parse_cpu_list(text: str) -> set[int]:
    result: set[int] = set()
    for piece in text.strip().split(","):
        if not piece:
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", piece)
        if match is None:
            return set()
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start > end or end >= 4096 or end - start > 4096:
            return set()
        result.update(range(start, end + 1))
    return result


def _cpu_sample(current: Mapping[str, int], previous: Any) -> dict[str, Any]:
    status = _counter_status(current, previous, CPU_MODES)
    percentages = {f"{name}Percent": None for name in CPU_MODES}
    busy_percent: float | None = None
    if status == "ok" and isinstance(previous, Mapping):
        deltas = {name: current[name] - int(previous[name]) for name in CPU_MODES}
        total = sum(deltas.values())
        if total > 0:
            percentages = {
                f"{name}Percent": round(100.0 * deltas[name] / total, 2)
                for name in CPU_MODES
            }
            busy_percent = round(
                100.0 * (total - deltas["idle"] - deltas["iowait"]) / total, 2
            )
        else:
            status = "counter_reset"
    return {
        "rateStatus": status,
        "busyPercent": busy_percent,
        **percentages,
        "countersJiffies": dict(current),
    }


def _cpu_frequency(sys_root: Path, identifier: int) -> dict[str, Any]:
    root = sys_root / "devices" / "system" / "cpu" / f"cpu{identifier}" / "cpufreq"
    values: dict[str, int | None] = {}
    statuses: list[str] = []
    for public, filename in (
        ("currentHz", "scaling_cur_freq"),
        ("minimumHz", "scaling_min_freq"),
        ("maximumHz", "scaling_max_freq"),
    ):
        status, value = _read_number(root / filename, 0, 100_000_000)
        statuses.append(status)
        values[public] = int(value * 1000) if value is not None else None
    governor_status, governor_text = read_limited(root / "scaling_governor", 64)
    statuses.append(governor_status)
    governor = _safe_label(governor_text, 32) if governor_status == "supported" else None
    status = (
        "permission_error" if "permission_error" in statuses
        else "supported" if "supported" in statuses
        else "unsupported" if all(value == "unsupported" for value in statuses)
        else "unavailable"
    )
    return {"status": status, **values, "governor": governor}


def _cpu_throttle(sys_root: Path, identifier: int) -> dict[str, Any]:
    root = sys_root / "devices" / "system" / "cpu" / f"cpu{identifier}" / "thermal_throttle"
    status, value = _read_number(root / "core_throttle_count", 0, MAX_COUNTER)
    if status == "unsupported":
        status, value = _read_number(root / "package_throttle_count", 0, MAX_COUNTER)
    return {"status": status, "count": int(value) if value is not None else None}


def collect_cpu(proc_root: Path, sys_root: Path, previous: Any, loadavg: tuple[float | None, ...]) -> tuple[dict[str, Any], dict[str, Any]]:
    status, text = read_limited(proc_root / "stat", MAX_FILE_BYTES)
    parsed = parse_cpu_stat(text) if status == "supported" else {}
    effective_status = "invalid" if status == "supported" and "cpu" not in parsed else status
    prior = previous if isinstance(previous, Mapping) else {}
    total = _cpu_sample(parsed["cpu"], prior.get("cpu")) if "cpu" in parsed else None
    offline_status, offline_text = read_limited(
        sys_root / "devices" / "system" / "cpu" / "offline", 4096
    )
    offline = parse_cpu_list(offline_text) if offline_status == "supported" else set()
    cores: list[dict[str, Any]] = []
    state: dict[str, Any] = {}
    if "cpu" in parsed:
        state["cpu"] = parsed["cpu"]
    for name, counters in parsed.items():
        if name == "cpu":
            continue
        identifier = int(name[3:])
        state[name] = counters
        cores.append({
            "id": identifier,
            "online": identifier not in offline,
            **_cpu_sample(counters, prior.get(name)),
            "frequency": _cpu_frequency(sys_root, identifier),
            "throttling": _cpu_throttle(sys_root, identifier),
        })
    online_count = sum(1 for core in cores if core["online"])
    denominator = online_count or len(cores) or None
    load = {
        "one": loadavg[0], "five": loadavg[1], "fifteen": loadavg[2],
        "onePerOnlineCpu": round(loadavg[0] / denominator, 3)
        if loadavg[0] is not None and denominator else None,
        "fivePerOnlineCpu": round(loadavg[1] / denominator, 3)
        if loadavg[1] is not None and denominator else None,
        "fifteenPerOnlineCpu": round(loadavg[2] / denominator, 3)
        if loadavg[2] is not None and denominator else None,
    }
    return ({
        "status": "supported" if total is not None else effective_status,
        "total": total,
        "cores": cores,
        "coreCount": len(cores),
        "onlineCoreCount": online_count if cores else None,
        "offlineCoreIds": sorted(offline)[:MAX_CPU_COUNT],
        "truncated": len(parsed) >= MAX_CPU_COUNT + 1,
        "load": load,
    }, state)


def parse_meminfo_detail(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.splitlines()[:512]:
        match = re.fullmatch(r"([A-Za-z_()]+):\s+(\d+)\s*(kB)?\s*", line)
        if match is None:
            continue
        value = int(match.group(2)) * (1024 if match.group(3) else 1)
        if value <= MAX_COUNTER:
            result[match.group(1)] = value
    return result


def parse_vmstat(text: str) -> dict[str, int]:
    wanted = {"pswpin", "pswpout", "pgfault", "pgmajfault", "oom_kill"}
    result: dict[str, int] = {}
    for line in text.splitlines()[:4096]:
        fields = line.split()
        if len(fields) != 2 or fields[0] not in wanted:
            continue
        value = _safe_integer(fields[1])
        if value is not None:
            result[fields[0]] = value
    return result


def parse_psi(text: str) -> dict[str, dict[str, int | float | None]]:
    result: dict[str, dict[str, int | float | None]] = {}
    for line in text.splitlines()[:4]:
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        values: dict[str, int | float | None] = {
            "avg10": None, "avg60": None, "avg300": None, "totalMicroseconds": None,
        }
        for item in fields[1:]:
            if "=" not in item:
                continue
            key, raw = item.split("=", 1)
            if key in {"avg10", "avg60", "avg300"}:
                value = _finite(raw, 0, 100)
                values[key] = round(value, 2) if value is not None else None
            elif key == "total":
                values["totalMicroseconds"] = _safe_integer(raw)
        result[fields[0]] = values
    return result


def collect_memory(proc_root: Path, previous: Any, elapsed: float, page_size: int) -> tuple[dict[str, Any], dict[str, Any]]:
    mem_status, mem_text = read_limited(proc_root / "meminfo", 256 * 1024)
    values = parse_meminfo_detail(mem_text) if mem_status == "supported" else {}
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if available is None and total is not None:
        fallback = [values.get(name) for name in ("MemFree", "Buffers", "Cached")]
        available = sum(value or 0 for value in fallback) if any(value is not None for value in fallback) else None
    if total is not None and available is not None:
        available = max(0, min(total, available))
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    swap_used = (
        max(0, swap_total - min(swap_total, swap_free))
        if swap_total is not None and swap_free is not None else None
    )
    cache = sum(values.get(name, 0) for name in ("Cached", "SReclaimable")) - values.get("Shmem", 0)
    cache = max(0, cache)

    vm_status, vm_text = read_limited(proc_root / "vmstat", 512 * 1024)
    vm = parse_vmstat(vm_text) if vm_status == "supported" else {}
    prior_vm = previous if isinstance(previous, Mapping) else {}
    required = ("pswpin", "pswpout", "pgfault", "pgmajfault")
    counter_status = (
        _counter_status(vm, prior_vm, required)
        if all(name in vm for name in required)
        else "invalid" if vm_status == "supported" else vm_status
    )
    rates = {"swapInPagesPerSecond": None, "swapOutPagesPerSecond": None,
             "swapInBytesPerSecond": None, "swapOutBytesPerSecond": None,
             "pageFaultsPerSecond": None, "majorPageFaultsPerSecond": None}
    if counter_status == "ok":
        deltas = {name: vm[name] - int(prior_vm[name]) for name in required}
        rates = {
            "swapInPagesPerSecond": _rate(deltas["pswpin"], elapsed),
            "swapOutPagesPerSecond": _rate(deltas["pswpout"], elapsed),
            "swapInBytesPerSecond": _rate(deltas["pswpin"], elapsed, page_size),
            "swapOutBytesPerSecond": _rate(deltas["pswpout"], elapsed, page_size),
            "pageFaultsPerSecond": _rate(deltas["pgfault"], elapsed),
            "majorPageFaultsPerSecond": _rate(deltas["pgmajfault"], elapsed),
        }

    pressure: dict[str, Any] = {}
    pressure_statuses: list[str] = []
    for kind in ("cpu", "memory", "io"):
        psi_status, psi_text = read_limited(proc_root / "pressure" / kind, 4096)
        pressure_statuses.append(psi_status)
        parsed_psi = parse_psi(psi_text)
        pressure[kind] = {
            "status": "invalid" if psi_status == "supported" and not parsed_psi else psi_status,
            **parsed_psi,
        }
    return ({
        "status": ("invalid" if mem_status == "supported" else mem_status) if total is None else "supported",
        "totalBytes": total,
        "availableBytes": available,
        "usedBytes": total - available if total is not None and available is not None else None,
        "usedPercent": round(100 * (total - available) / total, 2)
        if total and available is not None else None,
        "cachedBytes": cache if values else None,
        "buffersBytes": values.get("Buffers"),
        "slabBytes": values.get("Slab"),
        "slabReclaimableBytes": values.get("SReclaimable"),
        "slabUnreclaimableBytes": values.get("SUnreclaim"),
        "dirtyBytes": values.get("Dirty"),
        "writebackBytes": values.get("Writeback"),
        "swapTotalBytes": swap_total,
        "swapUsedBytes": swap_used,
        "swapUsedPercent": round(100 * swap_used / swap_total, 2)
        if swap_total and swap_used is not None else (0.0 if swap_total == 0 else None),
        "vmCounters": vm,
        "rateStatus": counter_status,
        **rates,
        "pressure": pressure,
        "pressureStatus": (
            "permission_error" if "permission_error" in pressure_statuses
            else "supported" if "supported" in pressure_statuses
            else "unsupported"
        ),
    }, vm)


def _decode_mount(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def parse_mountinfo_all(text: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for line in text.splitlines()[:4096]:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount = _decode_mount(fields[4])
            options = set(fields[5].split(","))
            filesystem = fields[separator + 1]
            super_options = set(fields[separator + 3].split(","))
        except (ValueError, IndexError):
            continue
        if not mount.startswith("/") or any(ord(character) < 32 for character in mount):
            continue
        mounts.append({
            "mount": mount[:512],
            "filesystemType": _safe_label(filesystem, 64),
            "readOnly": "ro" in options or "ro" in super_options,
            "pseudo": filesystem in PSEUDO_FILESYSTEMS,
            "remote": filesystem in NETWORK_FILESYSTEMS,
        })
        if len(mounts) >= MAX_FILESYSTEMS:
            break
    return mounts


def _path_is_within(path: Path, mount: str) -> bool:
    normalized = os.path.normpath(str(path))
    normalized_mount = os.path.normpath(mount)
    return normalized == normalized_mount or normalized.startswith(normalized_mount.rstrip("/") + "/")


def _unsafe_filesystem_probe(mount: Mapping[str, Any]) -> bool:
    """Avoid synchronous statfs calls that can block on external responders."""

    filesystem = str(mount.get("filesystemType", "")).lower()
    return (
        mount.get("remote") is True
        or filesystem == "autofs"
        or filesystem == "fuse"
        or filesystem.startswith("fuse.")
    )


def collect_filesystems(
    mountinfo_path: Path, mount_root: Path | None, docker_data_root: Path,
    previous: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    status, text = read_limited(mountinfo_path, MAX_FILE_BYTES)
    mounts = parse_mountinfo_all(text) if status == "supported" else []
    docker_mount: str | None = None
    candidates = [item["mount"] for item in mounts if _path_is_within(docker_data_root, item["mount"])]
    if candidates:
        docker_mount = max(candidates, key=len)
    items: list[dict[str, Any]] = []
    prior = previous if isinstance(previous, Mapping) else {}
    state: dict[str, Any] = {}
    for mount in mounts:
        actual = mount_root / mount["mount"].lstrip("/") if mount_root else Path(mount["mount"])
        availability = "supported"
        total = used = available = inode_total = inode_used = inode_available = None
        used_percent = inode_percent = None
        if _unsafe_filesystem_probe(mount):
            availability = "unsupported"
        else:
            try:
                usage = shutil.disk_usage(actual)
                total, used, available = int(usage.total), int(usage.used), int(usage.free)
                used_percent = round(100.0 * used / total, 2) if total > 0 else None
                stats = os.statvfs(actual)
                inode_total = int(stats.f_files)
                inode_available = int(stats.f_favail)
                inode_free = int(stats.f_ffree)
                if inode_total > 0 and 0 <= inode_free <= inode_total:
                    inode_used = inode_total - inode_free
                    inode_percent = round(100.0 * inode_used / inode_total, 2)
            except PermissionError:
                availability = "permission_error"
            except (OSError, OverflowError, TypeError, ValueError):
                availability = "unavailable"
        prior_mount = prior.get(mount["mount"])
        transition: str | None = None
        if (
            isinstance(prior_mount, Mapping)
            and prior_mount.get("filesystemType") == mount["filesystemType"]
            and isinstance(prior_mount.get("readOnly"), bool)
            and prior_mount["readOnly"] != mount["readOnly"]
        ):
            transition = "became_read_only" if mount["readOnly"] else "became_read_write"
        state[mount["mount"]] = {
            "filesystemType": mount["filesystemType"],
            "readOnly": mount["readOnly"],
        }
        items.append({
            **mount,
            "readOnlyTransition": transition,
            "availability": availability,
            "mounted": True,
            "dockerDataRootFilesystem": mount["mount"] == docker_mount,
            "totalBytes": total,
            "usedBytes": used,
            "availableBytes": available,
            "usedPercent": used_percent,
            "inodeTotal": inode_total,
            "inodeUsed": inode_used,
            "inodeAvailable": inode_available,
            "inodeUsedPercent": inode_percent,
        })
    effective_status = "invalid" if status == "supported" and not items else status
    return ({
        "status": effective_status if not items else "supported",
        "truncated": len(mounts) >= MAX_FILESYSTEMS,
        "items": items,
    }, state)


def _partition_name(name: str) -> bool:
    return bool(
        re.fullmatch(r"(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+", name)
        or re.fullmatch(r"nvme\d+n\d+p\d+", name)
        or re.fullmatch(r"mmcblk\d+(?:p\d+|boot\d+|rpmb)", name)
    )


def parse_diskstats_detail(text: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for line in text.splitlines()[:4096]:
        fields = line.split()
        if len(fields) < 14:
            continue
        major = _safe_integer(fields[0], 1_048_575)
        minor = _safe_integer(fields[1], 1_048_575)
        name = fields[2]
        if major is None or minor is None or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is None:
            continue
        if _partition_name(name) or re.match(r"^(loop|ram|fd|sr|zram)", name):
            continue
        raw_indexes = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
        numbers: list[int] = []
        valid = True
        for index in raw_indexes:
            value = _safe_integer(fields[index]) if index < len(fields) else 0
            if value is None:
                valid = False
                break
            numbers.append(value)
        if not valid:
            continue
        identity = f"{major}:{minor}:{name}"
        result[identity] = {
            "major": major, "minor": minor, "name": name,
            "discardSupported": len(fields) >= 18,
            "flushSupported": len(fields) >= 20,
            **dict(zip(DISK_COUNTER_FIELDS, numbers)),
        }
        if len(result) >= MAX_BLOCK_DEVICES:
            break
    return result


def _block_type(name: str, sys_root: Path) -> tuple[str, bool | None]:
    if name.startswith("nvme"):
        kind = "nvme"
    elif name.startswith("mmcblk"):
        kind = "mmc"
    elif name.startswith("md"):
        kind = "raid"
    elif name.startswith("dm-"):
        kind = "device-mapper"
    elif name.startswith(("vd", "xvd")):
        kind = "virtual"
    else:
        transport_status, transport = read_limited(sys_root / "block" / name / "device" / "transport", 64)
        token = transport.strip().lower() if transport_status == "supported" else ""
        kind = token if token in {"ata", "sata", "sas", "usb", "scsi"} else "block"
    rotational_status, rotational_value = _read_number(sys_root / "block" / name / "queue" / "rotational", 0, 1)
    rotational = bool(rotational_value) if rotational_status == "supported" and rotational_value is not None else None
    return kind, rotational


def _block_health(name: str, sys_root: Path) -> dict[str, Any]:
    if name.startswith("md"):
        degraded_status, degraded = _read_number(sys_root / "block" / name / "md" / "degraded", 0, 4096)
        state_status, state_text = read_limited(sys_root / "block" / name / "md" / "array_state", 64)
        return {
            "smartStatus": "unsupported",
            "raidStatus": degraded_status,
            "raidDegradedDevices": int(degraded) if degraded is not None else None,
            "raidArrayState": _safe_label(state_text, 32) if state_status == "supported" else None,
        }
    return {
        "smartStatus": "unsupported",
        "raidStatus": "unsupported",
        "raidDegradedDevices": None,
        "raidArrayState": None,
    }


def collect_block_devices(proc_root: Path, sys_root: Path, previous: Any, elapsed: float) -> tuple[dict[str, Any], dict[str, Any]]:
    status, text = read_limited(proc_root / "diskstats", MAX_FILE_BYTES)
    parsed = parse_diskstats_detail(text) if status == "supported" else {}
    prior = previous if isinstance(previous, Mapping) else {}
    items: list[dict[str, Any]] = []
    state: dict[str, Any] = {}
    base_rate_fields = tuple(
        name for name in DISK_COUNTER_FIELDS[:11] if name != "inFlight"
    )
    for identity, raw in parsed.items():
        counters = {name: raw[name] for name in DISK_COUNTER_FIELDS}
        discard_supported = bool(raw["discardSupported"])
        flush_supported = bool(raw["flushSupported"])
        state[identity] = {
            **counters,
            "discardSupported": discard_supported,
            "flushSupported": flush_supported,
        }
        prior_counters = prior.get(identity)
        rate_status = _counter_status(counters, prior_counters, base_rate_fields)
        rates: dict[str, Any] = {
            "readBytesPerSecond": None, "writeBytesPerSecond": None,
            "readIops": None, "writeIops": None,
            "discardBytesPerSecond": None, "discardIops": None, "flushIops": None,
            "readLatencyMilliseconds": None, "writeLatencyMilliseconds": None,
            "averageLatencyMilliseconds": None, "utilizationPercent": None,
            "averageQueueDepth": None,
        }
        discard_rate_status = "unsupported" if not discard_supported else "warmup"
        flush_rate_status = "unsupported" if not flush_supported else "warmup"
        if rate_status == "ok" and isinstance(prior_counters, Mapping):
            delta = {name: counters[name] - int(prior_counters[name]) for name in base_rate_fields}
            read_ops = delta["reads"]
            write_ops = delta["writes"]
            total_ops = read_ops + write_ops
            rates = {
                "readBytesPerSecond": _rate(delta["sectorsRead"], elapsed, 512),
                "writeBytesPerSecond": _rate(delta["sectorsWritten"], elapsed, 512),
                "readIops": _rate(read_ops, elapsed),
                "writeIops": _rate(write_ops, elapsed),
                "discardBytesPerSecond": None,
                "discardIops": None,
                "flushIops": None,
                "readLatencyMilliseconds": round(delta["readMilliseconds"] / read_ops, 2) if read_ops else None,
                "writeLatencyMilliseconds": round(delta["writeMilliseconds"] / write_ops, 2) if write_ops else None,
                "averageLatencyMilliseconds": round((delta["readMilliseconds"] + delta["writeMilliseconds"]) / total_ops, 2) if total_ops else None,
                "utilizationPercent": round(min(100.0, 100.0 * delta["ioMilliseconds"] / (elapsed * 1000)), 2),
                "averageQueueDepth": round(delta["weightedIoMilliseconds"] / (elapsed * 1000), 3),
            }
            if discard_supported and prior_counters.get("discardSupported") is True:
                discard_delta = _counter_delta(counters["discards"], prior_counters.get("discards"))
                discard_sector_delta = _counter_delta(
                    counters["sectorsDiscarded"], prior_counters.get("sectorsDiscarded")
                )
                rates["discardIops"] = _rate(discard_delta, elapsed)
                rates["discardBytesPerSecond"] = _rate(discard_sector_delta, elapsed, 512)
                discard_rate_status = (
                    "ok" if discard_delta is not None and discard_sector_delta is not None
                    else "counter_reset"
                )
            if flush_supported and prior_counters.get("flushSupported") is True:
                flush_delta = _counter_delta(counters["flushes"], prior_counters.get("flushes"))
                rates["flushIops"] = _rate(flush_delta, elapsed)
                flush_rate_status = "ok" if flush_delta is not None else "counter_reset"
        kind, rotational = _block_type(raw["name"], sys_root)
        public_counters: dict[str, int | None] = dict(counters)
        if not discard_supported:
            for name in ("discards", "discardsMerged", "sectorsDiscarded", "discardMilliseconds"):
                public_counters[name] = None
        if not flush_supported:
            for name in ("flushes", "flushMilliseconds"):
                public_counters[name] = None
        items.append({
            "name": raw["name"], "major": raw["major"], "minor": raw["minor"],
            "counterIdentity": hashlib.blake2s(identity.encode("ascii"), digest_size=8).hexdigest(),
            "type": kind, "rotational": rotational,
            "queueDepth": counters["inFlight"], "rateStatus": rate_status,
            "counters": public_counters,
            "discardStatus": "supported" if discard_supported else "unsupported",
            "flushStatus": "supported" if flush_supported else "unsupported",
            "discardRateStatus": discard_rate_status,
            "flushRateStatus": flush_rate_status,
            **rates,
            "ioErrorCounterStatus": "unsupported",
            "ioErrorEvidenceSource": "bounded-kernel-events",
            "health": _block_health(raw["name"], sys_root),
        })
    effective_status = "invalid" if status == "supported" and not items else status
    return ({"status": effective_status if not items else "supported", "truncated": len(parsed) >= MAX_BLOCK_DEVICES, "items": items}, state)


def parse_net_dev_detail(text: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for line in text.splitlines()[:4096]:
        if ":" not in line:
            continue
        raw_name, raw_counters = line.split(":", 1)
        name = raw_name.strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) is None:
            continue
        fields = raw_counters.split()
        if len(fields) < 16:
            continue
        counters = [_safe_integer(value) for value in fields[:16]]
        if any(value is None for value in counters):
            continue
        result[name] = dict(zip(NETWORK_COUNTER_FIELDS, counters))  # type: ignore[arg-type]
        if len(result) >= MAX_INTERFACES:
            break
    return result


def _interface_type(name: str, sys_root: Path, iftype: int | None) -> str:
    if name == "lo" or iftype == 772:
        return "loopback"
    if name.startswith("veth"):
        return "veth"
    if name == "docker0" or name.startswith(("br-", "docker")):
        return "docker-bridge"
    if (sys_root / "class" / "net" / name / "wireless").exists() or name.startswith(("wl", "wlan")):
        return "wifi"
    if name.startswith(("tun", "tap", "wg", "tailscale", "zt")):
        return "vpn"
    if name.startswith(("gre", "gretap", "ip6tnl", "sit", "vxlan")):
        return "tunnel"
    if (sys_root / "class" / "net" / name / "device").exists():
        return "physical"
    if name.startswith(("bond", "team")):
        return "bond"
    return "virtual"


def collect_network(proc_root: Path, sys_root: Path, previous: Any, elapsed: float) -> tuple[dict[str, Any], dict[str, Any]]:
    status, text = read_limited(proc_root / "net" / "dev", MAX_FILE_BYTES)
    parsed = parse_net_dev_detail(text) if status == "supported" else {}
    prior = previous if isinstance(previous, Mapping) else {}
    items: list[dict[str, Any]] = []
    state: dict[str, Any] = {}
    for name, counters in parsed.items():
        sys_path = sys_root / "class" / "net" / name
        ifindex_status, ifindex_value = _read_number(sys_path / "ifindex", 1, 1_048_575)
        iflink_status, iflink_value = _read_number(sys_path / "iflink", 1, 1_048_575)
        ifindex = int(ifindex_value) if ifindex_value is not None else None
        iflink = int(iflink_value) if iflink_value is not None else None
        identity = f"{ifindex}:{iflink}:{name}" if ifindex is not None else f"unknown:{name}"
        state[identity] = counters
        identity_supported = ifindex_status == "supported" and iflink_status == "supported"
        prior_counters = prior.get(identity) if identity_supported else None
        rate_status = _counter_status(counters, prior_counters, NETWORK_COUNTER_FIELDS)
        rates = {f"{field}PerSecond": None for field in NETWORK_COUNTER_FIELDS}
        if rate_status == "ok" and isinstance(prior_counters, Mapping):
            rates = {
                f"{field}PerSecond": _rate(counters[field] - int(prior_counters[field]), elapsed)
                for field in NETWORK_COUNTER_FIELDS
            }
        mtu_status, mtu_value = _read_number(sys_path / "mtu", 68, 1_000_000)
        speed_status, speed_value = _read_number(sys_path / "speed", 0, 10_000_000)
        duplex_status, duplex = _read_token(sys_path / "duplex", {"full", "half", "unknown"})
        link_status, operstate = _read_token(
            sys_path / "operstate", {"unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up"}
        )
        carrier_status, carrier_value = _read_number(sys_path / "carrier", 0, 1)
        type_status, type_value = _read_number(sys_path / "type", 0, 65535)
        items.append({
            "name": name,
            "classification": _interface_type(name, sys_root, int(type_value) if type_value is not None else None),
            "counterIdentity": hashlib.blake2s(identity.encode("ascii"), digest_size=8).hexdigest(),
            "counterIdentityStatus": "supported" if identity_supported else (
                "permission_error" if "permission_error" in {ifindex_status, iflink_status}
                else "unsupported" if {ifindex_status, iflink_status} == {"unsupported"}
                else "unavailable"
            ),
            "linkStateStatus": link_status,
            "linkState": operstate,
            "carrier": bool(carrier_value) if carrier_status == "supported" and carrier_value is not None else None,
            "mtu": int(mtu_value) if mtu_status == "supported" and mtu_value is not None else None,
            "speedMegabitsPerSecond": int(speed_value) if speed_status == "supported" and speed_value is not None else None,
            "duplex": duplex if duplex_status == "supported" else None,
            "rateStatus": rate_status,
            "counters": counters,
            **rates,
        })
    effective_status = "invalid" if status == "supported" and not items else status
    return ({"status": effective_status if not items else "supported", "truncated": len(parsed) >= MAX_INTERFACES, "items": items}, state)


def parse_protocol_counters(text: str, protocol: str) -> dict[str, int]:
    header: list[str] | None = None
    for line in text.splitlines()[:2048]:
        fields = line.split()
        if not fields or fields[0] != f"{protocol}:":
            continue
        if header is None:
            header = fields[1:]
            continue
        if len(fields) - 1 != len(header):
            return {}
        result: dict[str, int] = {}
        for name, raw in zip(header, fields[1:]):
            value = _safe_integer(raw)
            if value is not None:
                result[name] = value
        return result
    return {}


TCP_STATES = {
    "01": "established", "02": "synSent", "03": "synRecv",
    "04": "finWait1", "05": "finWait2", "06": "timeWait",
    "07": "close", "08": "closeWait", "09": "lastAck",
    "0A": "listen", "0B": "closing", "0C": "newSynRecv",
}


def parse_tcp_sockets(
    text: str, ephemeral_start: int | None, ephemeral_end: int | None,
) -> tuple[dict[str, int], set[int], bool]:
    states = {name: 0 for name in TCP_STATES.values()}
    ephemeral_ports: set[int] = set()
    observed = 0
    truncated = False
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or ":" not in fields[1]:
            continue
        state = TCP_STATES.get(fields[3].upper())
        if state is None:
            continue
        observed += 1
        if observed > MAX_TCP_SOCKETS:
            truncated = True
            break
        states[state] += 1
        try:
            port = int(fields[1].rsplit(":", 1)[1], 16)
        except ValueError:
            continue
        if ephemeral_start is not None and ephemeral_end is not None and ephemeral_start <= port <= ephemeral_end:
            ephemeral_ports.add(port)
    return states, ephemeral_ports, truncated


def _ephemeral_range(proc_root: Path) -> tuple[str, int | None, int | None]:
    status, text = read_limited(
        proc_root / "sys" / "net" / "ipv4" / "ip_local_port_range", 128
    )
    fields = text.split()
    if status != "supported":
        return status, None, None
    if len(fields) != 2:
        return "invalid", None, None
    start = _safe_integer(fields[0], 65_535)
    end = _safe_integer(fields[1], 65_535)
    if start is None or end is None or start < 1024 or start > end:
        return "invalid", None, None
    return "supported", start, end


def collect_tcp(proc_root: Path, previous: Any, elapsed: float) -> tuple[dict[str, Any], dict[str, Any]]:
    snmp_status, snmp_text = read_limited(proc_root / "net" / "snmp", MAX_FILE_BYTES)
    netstat_status, netstat_text = read_limited(proc_root / "net" / "netstat", MAX_FILE_BYTES)
    tcp = parse_protocol_counters(snmp_text, "Tcp") if snmp_status == "supported" else {}
    tcp_ext = parse_protocol_counters(netstat_text, "TcpExt") if netstat_status == "supported" else {}
    counter_names = (
        "ActiveOpens", "PassiveOpens", "AttemptFails", "EstabResets",
        "InSegs", "OutSegs", "RetransSegs", "InErrs", "OutRsts",
    )
    counters = {name: tcp[name] for name in counter_names if name in tcp}
    if "TCPSynRetrans" in tcp_ext:
        counters["TCPSynRetrans"] = tcp_ext["TCPSynRetrans"]
    if "TCPTimeouts" in tcp_ext:
        counters["TCPTimeouts"] = tcp_ext["TCPTimeouts"]
    prior = previous if isinstance(previous, Mapping) else {}
    required = ("OutSegs", "RetransSegs")
    rate_status = (
        _counter_status(counters, prior, required)
        if all(name in counters for name in required)
        else "invalid" if snmp_status == "supported" else snmp_status
    )
    retrans_rate = out_rate = retrans_percent = None
    if rate_status == "ok":
        retrans_delta = counters["RetransSegs"] - int(prior["RetransSegs"])
        out_delta = counters["OutSegs"] - int(prior["OutSegs"])
        retrans_rate = _rate(retrans_delta, elapsed)
        out_rate = _rate(out_delta, elapsed)
        retrans_percent = round(100.0 * retrans_delta / out_delta, 3) if out_delta else None

    range_status, ephemeral_start, ephemeral_end = _ephemeral_range(proc_root)
    socket_statuses: list[str] = []
    combined_states = {name: 0 for name in TCP_STATES.values()}
    ephemeral_ports: set[int] = set()
    truncated = False
    for filename in ("tcp", "tcp6"):
        socket_status, socket_text = read_limited(proc_root / "net" / filename, MAX_FILE_BYTES)
        socket_statuses.append(socket_status)
        if socket_status != "supported":
            continue
        states, ports, current_truncated = parse_tcp_sockets(
            socket_text, ephemeral_start, ephemeral_end
        )
        for name, count in states.items():
            combined_states[name] += count
        ephemeral_ports.update(ports)
        truncated = truncated or current_truncated
    socket_status = (
        "permission_error" if "permission_error" in socket_statuses and "supported" not in socket_statuses
        else "supported" if "supported" in socket_statuses
        else "unsupported" if all(value == "unsupported" for value in socket_statuses)
        else "unavailable"
    )
    capacity = (
        ephemeral_end - ephemeral_start + 1
        if ephemeral_start is not None and ephemeral_end is not None else None
    )
    count_status, count_value = _read_number(
        proc_root / "sys" / "net" / "netfilter" / "nf_conntrack_count", 0, MAX_COUNTER
    )
    maximum_status, maximum_value = _read_number(
        proc_root / "sys" / "net" / "netfilter" / "nf_conntrack_max", 1, MAX_COUNTER
    )
    conntrack_statuses = {count_status, maximum_status}
    conntrack_status = (
        "supported" if conntrack_statuses == {"supported"}
        else "permission_error" if "permission_error" in conntrack_statuses
        else "partial" if "supported" in conntrack_statuses
        else "unsupported" if conntrack_statuses == {"unsupported"}
        else "unavailable"
    )
    status = (
        "supported" if counters or socket_status == "supported"
        else "permission_error" if "permission_error" in {snmp_status, socket_status}
        else "unsupported" if snmp_status == socket_status == "unsupported"
        else "unavailable"
    )
    return ({
        "status": status,
        "counters": counters,
        "rateStatus": rate_status,
        "outgoingSegmentsPerSecond": out_rate,
        "retransmittedSegmentsPerSecond": retrans_rate,
        "retransmissionPercent": retrans_percent,
        "states": combined_states,
        "socketScanStatus": socket_status,
        "socketScanTruncated": truncated,
        "ephemeralPorts": {
            "status": range_status if socket_status == "supported" else socket_status,
            "rangeStart": ephemeral_start,
            "rangeEnd": ephemeral_end,
            "capacity": capacity,
            "used": len(ephemeral_ports) if capacity is not None and socket_status == "supported" else None,
            "usedPercent": round(100.0 * len(ephemeral_ports) / capacity, 3)
            if capacity and socket_status == "supported" else None,
        },
        "conntrack": {
            "status": conntrack_status,
            "count": int(count_value) if count_value is not None else None,
            "maximum": int(maximum_value) if maximum_value is not None else None,
            "usedPercent": round(100.0 * count_value / maximum_value, 2)
            if count_value is not None and maximum_value else None,
        },
    }, counters)


def parse_process_stat(text: str) -> dict[str, Any] | None:
    opening = text.find("(")
    closing = text.rfind(")")
    if opening <= 0 or closing <= opening:
        return None
    tail = text[closing + 1:].split()
    if len(tail) < 22 or re.fullmatch(r"[A-Z]", tail[0]) is None:
        return None
    try:
        values = {
            "state": tail[0],
            "cpuTicks": int(tail[11]) + int(tail[12]),
            "threads": int(tail[17]),
            "startTicks": int(tail[19]),
            "virtualBytes": int(tail[20]),
            "residentPages": int(tail[21]),
            "rawName": text[opening + 1:closing],
        }
    except (TypeError, ValueError, OverflowError):
        return None
    numeric = (values["cpuTicks"], values["threads"], values["startTicks"], values["virtualBytes"], values["residentPages"])
    if any(value < 0 or value > MAX_COUNTER for value in numeric):
        return None
    return values


def parse_process_io(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.splitlines()[:32]:
        fields = line.split()
        if len(fields) != 2 or fields[0].rstrip(":") not in {"read_bytes", "write_bytes"}:
            continue
        value = _safe_integer(fields[1])
        if value is not None:
            result[fields[0].rstrip(":")] = value
    return result


def _count_directory(path: Path, maximum: int) -> tuple[str, int | None, bool]:
    count = 0
    try:
        with os.scandir(path) as entries:
            for _entry in entries:
                count += 1
                if count > maximum:
                    return "partial", maximum, True
    except FileNotFoundError:
        return "unavailable", None, False
    except PermissionError:
        return "permission_error", None, False
    except OSError:
        return "unavailable", None, False
    return "supported", count, False


def _process_candidates(proc_root: Path) -> tuple[list[Path], bool, str]:
    result: list[Path] = []
    try:
        with os.scandir(proc_root) as entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                result.append(proc_root / entry.name)
                if len(result) > MAX_PROCESSES:
                    return sorted(result[:MAX_PROCESSES], key=lambda item: int(item.name)), True, "partial"
    except PermissionError:
        return [], False, "permission_error"
    except OSError:
        return [], False, "unavailable"
    return sorted(result, key=lambda item: int(item.name)), False, "supported"


def _allowed_process_name(value: str, allowlist: set[str]) -> str | None:
    if value not in allowlist:
        return None
    if re.fullmatch(r"[A-Za-z0-9_.@+-]{1,64}", value) is None:
        return None
    return value


def _system_file_descriptors(proc_root: Path) -> dict[str, Any]:
    status, text = read_limited(proc_root / "sys" / "fs" / "file-nr", 256)
    fields = text.split()
    allocated = unused = maximum = None
    if status == "supported" and len(fields) >= 3:
        allocated = _safe_integer(fields[0], MAX_JSON_SAFE_INTEGER)
        unused = _safe_integer(fields[1], MAX_JSON_SAFE_INTEGER)
        raw_maximum = _safe_integer(fields[2])
        if allocated is None or unused is None or raw_maximum is None or unused > allocated:
            status = "invalid"
            allocated = unused = maximum = None
        elif raw_maximum > MAX_JSON_SAFE_INTEGER:
            # Keep the useful exact counters, but never serialize Linux's
            # LONG_MAX sentinel as an imprecise JavaScript number.
            status = "partial"
        else:
            maximum = raw_maximum
    used = allocated - unused if allocated is not None and unused is not None else None
    return {
        "status": status,
        "allocated": allocated,
        "unusedAllocated": unused,
        "used": used,
        "maximum": maximum,
        "usedPercent": round(100.0 * used / maximum, 2) if used is not None and maximum else None,
    }


def _cgroup_pids(proc_root: Path, sys_root: Path) -> dict[str, Any]:
    status, text = read_limited(proc_root / "self" / "cgroup", 65_536)
    if status != "supported":
        return {"status": status, "version": None, "current": None, "maximum": None}
    cgroup_path: str | None = None
    version: int | None = None
    base: Path | None = None
    for line in text.splitlines()[:256]:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        if fields[0] == "0" and fields[1] == "":
            version = 2
            cgroup_path = fields[2]
            base = sys_root / "fs" / "cgroup"
            break
        if "pids" in fields[1].split(","):
            version = 1
            cgroup_path = fields[2]
            base = sys_root / "fs" / "cgroup" / "pids"
    if version is None or base is None or cgroup_path is None:
        return {"status": "unsupported", "version": None, "current": None, "maximum": None}
    pieces = [piece for piece in cgroup_path.split("/") if piece]
    if any(piece in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}", piece) is None for piece in pieces):
        return {"status": "invalid", "version": version, "current": None, "maximum": None}
    root = base.joinpath(*pieces)
    current_status, current_value = _read_number(root / "pids.current", 0, MAX_COUNTER)
    maximum_status, maximum_text = read_limited(root / "pids.max", 128)
    maximum: int | None = None
    if maximum_status == "supported" and maximum_text.strip() != "max":
        maximum = _safe_integer(maximum_text.strip())
        if maximum is None:
            maximum_status = "invalid"
    statuses = {current_status, maximum_status}
    combined = (
        "permission_error" if "permission_error" in statuses
        else "supported" if current_status == maximum_status == "supported"
        else "partial" if "supported" in statuses
        else "unsupported" if statuses == {"unsupported"}
        else "unavailable"
    )
    return {
        "status": combined,
        "version": version,
        "current": int(current_value) if current_value is not None else None,
        "maximum": maximum,
        "usedPercent": round(100.0 * current_value / maximum, 2)
        if current_value is not None and maximum else None,
    }


def collect_processes(
    proc_root: Path,
    sys_root: Path,
    previous: Any,
    elapsed: float,
    host_cpu_delta: int,
    allowed_uids: set[int],
    process_allowlist: set[str],
    sanitizer: Callable[[Any], str],
    page_size: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidates, truncated, scan_status = _process_candidates(proc_root)
    prior = previous if isinstance(previous, Mapping) else {}
    groups: dict[str, dict[str, Any]] = {}
    next_state: dict[str, Any] = {}
    total_threads = zombies = observed = 0
    fd_observed = 0
    fd_partial = False
    deadline = _monotonic() + PROCESS_SCAN_SECONDS
    deadline_reached = False
    for process_dir in candidates:
        if _monotonic() > deadline:
            deadline_reached = True
            break
        try:
            metadata = process_dir.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        parsed = parse_process_stat(read_limited(process_dir / "stat", 8192)[1])
        if parsed is None:
            continue
        observed += 1
        total_threads += parsed["threads"]
        if parsed["state"] == "Z":
            zombies += 1
        if metadata.st_uid not in allowed_uids:
            continue
        allowlisted_name = _allowed_process_name(parsed["rawName"], process_allowlist)
        public_name = allowlisted_name or sanitizer(parsed["rawName"])
        public_name = _safe_label(public_name, 64)
        identity = hashlib.blake2s(
            f"{process_dir.name}:{parsed['startTicks']}".encode("ascii"), digest_size=12
        ).hexdigest()
        io_status, io_text = read_limited(process_dir / "io", 4096)
        io = parse_process_io(io_text) if io_status == "supported" else {}
        fd_status, fd_count, fd_truncated = _count_directory(process_dir / "fd", MAX_FDS_PER_PROCESS)
        if fd_count is not None:
            fd_observed += fd_count
        fd_partial = fd_partial or fd_truncated
        current_state = {
            "cpuTicks": parsed["cpuTicks"],
            "readBytes": io.get("read_bytes"),
            "writeBytes": io.get("write_bytes"),
            "name": public_name,
            "allowlisted": allowlisted_name is not None,
        }
        next_state[identity] = current_state
        prior_process = prior.get(identity) if isinstance(prior.get(identity), Mapping) else {}
        cpu_delta = _counter_delta(parsed["cpuTicks"], prior_process.get("cpuTicks"))
        read_delta = _counter_delta(io.get("read_bytes"), prior_process.get("readBytes"))
        write_delta = _counter_delta(io.get("write_bytes"), prior_process.get("writeBytes"))
        group = groups.setdefault(public_name, {
            "name": public_name,
            "allowlisted": allowlisted_name is not None,
            "instances": 0,
            "states": {},
            "threads": 0,
            "residentBytes": 0,
            "virtualBytes": 0,
            "openFileDescriptors": 0,
            "fileDescriptorStatus": "supported",
            "cpuDelta": 0,
            "cpuComplete": True,
            "readDelta": 0,
            "writeDelta": 0,
            "ioComplete": True,
        })
        group["instances"] += 1
        group["states"][parsed["state"]] = group["states"].get(parsed["state"], 0) + 1
        group["threads"] += parsed["threads"]
        group["residentBytes"] += parsed["residentPages"] * page_size
        group["virtualBytes"] += parsed["virtualBytes"]
        if fd_count is None:
            group["fileDescriptorStatus"] = fd_status
        else:
            group["openFileDescriptors"] += fd_count
        if cpu_delta is None:
            group["cpuComplete"] = False
        else:
            group["cpuDelta"] += cpu_delta
        if read_delta is None or write_delta is None:
            group["ioComplete"] = False
        else:
            group["readDelta"] += read_delta
            group["writeDelta"] += write_delta
    normalized: list[dict[str, Any]] = []
    for group in groups.values():
        cpu_percent = (
            round(100.0 * group["cpuDelta"] / host_cpu_delta, 2)
            if group["cpuComplete"] and host_cpu_delta > 0 else None
        )
        normalized.append({
            "name": group["name"],
            "allowlisted": group["allowlisted"],
            "instances": group["instances"],
            "states": group["states"],
            "threads": group["threads"],
            "cpuPercent": cpu_percent,
            "residentBytes": group["residentBytes"],
            "virtualBytes": group["virtualBytes"],
            "readBytesPerSecond": _rate(group["readDelta"], elapsed) if group["ioComplete"] else None,
            "writeBytesPerSecond": _rate(group["writeDelta"], elapsed) if group["ioComplete"] else None,
            "openFileDescriptors": group["openFileDescriptors"] if group["fileDescriptorStatus"] == "supported" else None,
            "fileDescriptorStatus": group["fileDescriptorStatus"],
        })
    top_cpu = sorted(normalized, key=lambda item: (
        -(item["cpuPercent"] if item["cpuPercent"] is not None else -1),
        -item["residentBytes"], item["name"],
    ))[:MAX_PROCESS_GROUPS]
    top_memory = sorted(normalized, key=lambda item: (-item["residentBytes"], item["name"]))[:MAX_PROCESS_GROUPS]
    top_io = sorted(
        normalized,
        key=lambda item: (-((item["readBytesPerSecond"] or 0) + (item["writeBytesPerSecond"] or 0)), item["name"]),
    )[:MAX_PROCESS_GROUPS]
    important = sorted((item for item in normalized if item["allowlisted"]), key=lambda item: item["name"])
    terminated: dict[tuple[str, bool], int] = {}
    if not truncated and not deadline_reached:
        for identity, prior_process in prior.items():
            if identity in next_state or not isinstance(prior_process, Mapping):
                continue
            prior_name = prior_process.get("name")
            allowlisted = prior_process.get("allowlisted")
            if (
                not isinstance(prior_name, str)
                or re.fullmatch(r"[A-Za-z0-9_.:@/+ -]{1,64}", prior_name) is None
                or not isinstance(allowlisted, bool)
            ):
                continue
            key = (prior_name, allowlisted)
            terminated[key] = terminated.get(key, 0) + 1
    pid_max_status, pid_max_value = _read_number(proc_root / "sys" / "kernel" / "pid_max", 1, MAX_COUNTER)
    pid_count = len(candidates)
    pid_max = int(pid_max_value) if pid_max_value is not None else None
    return ({
        "status": "partial" if truncated or deadline_reached else scan_status,
        "pidCount": pid_count,
        "pidCountLowerBound": truncated,
        "pidMaximumStatus": pid_max_status,
        "pidMaximum": pid_max,
        "pidUsedPercent": round(100.0 * pid_count / pid_max, 2) if pid_max else None,
        "zombieCount": zombies,
        "threadCount": total_threads,
        "observedProcessCount": observed,
        "scanTruncated": truncated,
        "deadlineReached": deadline_reached,
        "allowedUidCount": len(allowed_uids),
        "topCpu": top_cpu,
        "topMemory": top_memory,
        "topIo": top_io,
        "important": important,
        "terminatedSincePreviousSample": [
            {"name": name, "allowlisted": allowlisted, "instances": count}
            for (name, allowlisted), count in sorted(terminated.items())[:MAX_PROCESS_GROUPS]
        ],
        "systemFileDescriptors": _system_file_descriptors(proc_root),
        "allowlistedProcessOpenFileDescriptors": fd_observed,
        "fileDescriptorScanTruncated": fd_partial,
        "cgroupPids": _cgroup_pids(proc_root, sys_root),
    }, next_state)


def parse_systemctl_show(text: str, allowlist: set[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        values: dict[str, str] = {}
        for line in block.splitlines()[:64]:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"Id", "LoadState", "ActiveState", "SubState", "NRestarts", "Result", "ExecMainStatus"}:
                values[key] = value.strip()
        identifier = values.get("Id")
        if identifier not in allowlist:
            continue
        result.append({
            "unit": identifier,
            "loadState": _safe_label(values.get("LoadState", "unknown"), 32),
            "activeState": _safe_label(values.get("ActiveState", "unknown"), 32),
            "subState": _safe_label(values.get("SubState", "unknown"), 32),
            "restartCount": _safe_integer(values.get("NRestarts")),
            "restartCountStatus": "systemd_manager",
            "result": _safe_label(values.get("Result", "unknown"), 32),
            "execMainStatus": _safe_integer(values.get("ExecMainStatus"), (1 << 31) - 1),
        })
    return sorted(result, key=lambda item: item["unit"])


def collect_systemd(
    units: set[str], systemctl: str, timeout: float, execute_commands: bool,
) -> dict[str, Any]:
    safe_units = sorted({
        unit for unit in units
        if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}\.service", unit)
    })[:MAX_SYSTEMD_UNITS]
    if not safe_units:
        return {"status": "unsupported", "reason": "not_configured", "units": [], "truncated": len(units) > MAX_SYSTEMD_UNITS}
    executable = Path(systemctl)
    if not execute_commands or not executable.is_file() or not os.access(executable, os.X_OK):
        return {"status": "unsupported", "reason": "systemctl_unavailable", "units": [], "truncated": len(units) > MAX_SYSTEMD_UNITS}
    arguments = [
        systemctl, "show", *safe_units, "--no-pager",
        "--property=Id", "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=NRestarts", "--property=Result",
        "--property=ExecMainStatus",
    ]
    try:
        completed = subprocess.run(
            arguments, capture_output=True, text=True,
            timeout=max(0.1, min(5.0, timeout)), check=False,
        )
    except PermissionError:
        return {"status": "permission_error", "reason": "execution_denied", "units": [], "truncated": False}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "reason": "deadline", "units": [], "truncated": False}
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable", "reason": "execution_failed", "units": [], "truncated": False}
    output = completed.stdout[:256 * 1024]
    parsed = parse_systemctl_show(output, set(safe_units))
    if completed.returncode != 0 and not parsed:
        denied = "access denied" in completed.stderr[:1024].lower() or "permission denied" in completed.stderr[:1024].lower()
        return {"status": "permission_error" if denied else "unavailable", "reason": "query_failed", "units": [], "truncated": False}
    observed = {item["unit"] for item in parsed}
    for missing in sorted(set(safe_units) - observed):
        parsed.append({
            "unit": missing, "loadState": "not-found", "activeState": "inactive",
            "subState": "dead", "restartCount": None,
            "restartCountStatus": "systemd_manager", "result": "unknown", "execMainStatus": None,
        })
    return {"status": "supported" if completed.returncode == 0 else "partial", "reason": None, "units": sorted(parsed, key=lambda item: item["unit"]), "truncated": len(units) > MAX_SYSTEMD_UNITS}


def collect_systemd_runtime(
    units: set[str], runtime_units: Path, sys_root: Path, previous: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Observe allow-listed units without exposing systemd's control socket.

    systemd publishes an opaque invocation-id symlink for each invoked unit.
    The ID is retained only as a private digest and changes are counted across
    collector samples.  Active state is inferred from the system unit cgroup;
    fields that require the manager API remain explicitly unknown.
    """
    safe_units = sorted({
        unit for unit in units
        if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}\.service", unit)
    })[:MAX_SYSTEMD_UNITS]
    if not safe_units:
        return ({"status": "unsupported", "reason": "not_configured", "units": [], "truncated": len(units) > MAX_SYSTEMD_UNITS}, {})
    try:
        metadata = runtime_units.stat()
    except FileNotFoundError:
        return ({"status": "unsupported", "reason": "runtime_state_unavailable", "units": [], "truncated": False}, {})
    except PermissionError:
        return ({"status": "permission_error", "reason": "runtime_state_denied", "units": [], "truncated": False}, {})
    except OSError:
        return ({"status": "unavailable", "reason": "runtime_state_failed", "units": [], "truncated": False}, {})
    if not stat.S_ISDIR(metadata.st_mode):
        return ({"status": "invalid", "reason": "runtime_state_not_directory", "units": [], "truncated": False}, {})
    prior = previous if isinstance(previous, Mapping) else {}
    result: list[dict[str, Any]] = []
    state: dict[str, Any] = {}
    for unit in safe_units:
        invocation_path = runtime_units / f"invocation:{unit}"
        invocation_digest: str | None = None
        invocation_status = "unsupported"
        try:
            target = os.readlink(invocation_path)
            if re.fullmatch(r"[0-9a-f]{32}", target):
                invocation_digest = hashlib.blake2s(
                    b"monitor-systemd-invocation-v1\0" + target.encode("ascii"),
                    digest_size=16,
                ).hexdigest()
                invocation_status = "supported"
            else:
                invocation_status = "invalid"
        except FileNotFoundError:
            invocation_status = "supported"
        except PermissionError:
            invocation_status = "permission_error"
        except OSError:
            invocation_status = "unavailable"
        prior_unit = prior.get(unit) if isinstance(prior.get(unit), Mapping) else {}
        prior_digest = prior_unit.get("invocationDigest")
        prior_changes = _safe_integer(prior_unit.get("observedInvocationChanges")) or 0
        changes = prior_changes
        if (
            isinstance(prior_digest, str)
            and invocation_digest is not None
            and prior_digest != invocation_digest
        ):
            changes = min(MAX_COUNTER, changes + 1)
        state[unit] = {
            "invocationDigest": invocation_digest,
            "observedInvocationChanges": changes,
        }
        cgroup = sys_root / "fs" / "cgroup" / "system.slice" / unit
        try:
            active = cgroup.is_dir()
            active_status = "supported"
        except PermissionError:
            active = False
            active_status = "permission_error"
        except OSError:
            active = False
            active_status = "unavailable"
        result.append({
            "unit": unit,
            "loadState": "unknown",
            "activeState": "active" if active else "inactive" if active_status == "supported" else "unknown",
            "subState": "running" if active else "unknown",
            "restartCount": changes,
            "restartCountStatus": "observed_invocation_changes",
            "result": "unknown",
            "execMainStatus": None,
            "invocationStatus": invocation_status,
        })
    return ({
        "status": "supported",
        "reason": "bounded_runtime_observation",
        "units": result,
        "truncated": len(units) > MAX_SYSTEMD_UNITS,
    }, state)


def collect_systemd_observation(
    units: set[str], systemctl: str, timeout: float, execute_commands: bool,
    runtime_units: Path, sys_root: Path, previous: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manager = collect_systemd(units, systemctl, timeout, execute_commands)
    if manager["status"] in {"supported", "partial"}:
        return manager, {}
    runtime, state = collect_systemd_runtime(units, runtime_units, sys_root, previous)
    if runtime["status"] == "supported":
        return runtime, state
    return manager if manager["status"] != "unsupported" else runtime, state


def _bounded_named_directories(root: Path, pattern: str, maximum: int) -> tuple[str, list[Path], bool]:
    matcher = re.compile(pattern)
    result: list[Path] = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if not matcher.fullmatch(entry.name):
                    continue
                result.append(root / entry.name)
                if len(result) > maximum:
                    return "partial", sorted(result[:maximum]), True
    except FileNotFoundError:
        return "unsupported", [], False
    except PermissionError:
        return "permission_error", [], False
    except OSError:
        return "unavailable", [], False
    return "supported", sorted(result), False


def _temperature_celsius(value: float | None) -> float | None:
    if value is None:
        return None
    normalized = value / 1000.0 if abs(value) > 1000 else value
    return round(normalized, 2) if -50 <= normalized <= 200 else None


def _rpi_power_hwmon(sys_root: Path) -> tuple[str, int | None]:
    directory_status, devices, _truncated = _bounded_named_directories(
        sys_root / "class" / "hwmon", r"hwmon\d+", MAX_THERMAL_SENSORS
    )
    if directory_status not in {"supported", "partial"}:
        return directory_status, None
    saw_permission_error = False
    for device in devices:
        name_status, name = read_limited(device / "name", 64)
        if name_status == "permission_error":
            saw_permission_error = True
            continue
        if name_status != "supported" or name.strip() != "rpi_volt":
            continue
        alarm_status, alarm = _read_number(device / "in0_lcrit_alarm", 0, 1)
        return alarm_status, int(alarm) if alarm is not None else None
    return ("permission_error", None) if saw_permission_error else ("unsupported", None)


def collect_thermal(sys_root: Path, rpi_data: Mapping[str, Any]) -> dict[str, Any]:
    sensors: list[dict[str, Any]] = []
    fans: list[dict[str, Any]] = []
    cooling: list[dict[str, Any]] = []
    status_candidates: list[str] = []

    thermal_status, zones, thermal_truncated = _bounded_named_directories(
        sys_root / "class" / "thermal", r"thermal_zone\d+", MAX_THERMAL_SENSORS
    )
    status_candidates.append(thermal_status)
    for zone in zones:
        temp_status, raw_temp = _read_number(zone / "temp", 0, 500_000)
        type_status, raw_type = read_limited(zone / "type", 128)
        status_candidates.append(temp_status)
        sensors.append({
            "source": "thermal-zone",
            "name": _safe_label(raw_type, 64) if type_status == "supported" else zone.name,
            "status": temp_status,
            "temperatureCelsius": _temperature_celsius(raw_temp),
        })

    hwmon_status, hwmons, hwmon_truncated = _bounded_named_directories(
        sys_root / "class" / "hwmon", r"hwmon\d+", MAX_THERMAL_SENSORS
    )
    status_candidates.append(hwmon_status)
    for hwmon in hwmons:
        name_status, raw_name = read_limited(hwmon / "name", 128)
        device_name = _safe_label(raw_name, 64) if name_status == "supported" else hwmon.name
        try:
            children = sorted(hwmon.iterdir(), key=lambda item: item.name)[:512]
        except PermissionError:
            status_candidates.append("permission_error")
            continue
        except OSError:
            continue
        for child in children:
            temperature_match = re.fullmatch(r"temp(\d+)_input", child.name)
            fan_match = re.fullmatch(r"fan(\d+)_input", child.name)
            if temperature_match and len(sensors) < MAX_THERMAL_SENSORS:
                temp_status, raw_temp = _read_number(child, 0, 500_000)
                label_status, label = read_limited(hwmon / f"temp{temperature_match.group(1)}_label", 128)
                sensors.append({
                    "source": "hwmon",
                    "name": _safe_label(label, 64) if label_status == "supported" else device_name,
                    "status": temp_status,
                    "temperatureCelsius": _temperature_celsius(raw_temp),
                })
                status_candidates.append(temp_status)
            elif fan_match and len(fans) < MAX_FANS:
                fan_status, rpm = _read_number(child, 0, 1_000_000)
                label_status, label = read_limited(hwmon / f"fan{fan_match.group(1)}_label", 128)
                fans.append({
                    "name": _safe_label(label, 64) if label_status == "supported" else device_name,
                    "status": fan_status,
                    "rpm": int(rpm) if rpm is not None else None,
                })
                status_candidates.append(fan_status)

    cooling_status, cooling_devices, cooling_truncated = _bounded_named_directories(
        sys_root / "class" / "thermal", r"cooling_device\d+", MAX_FANS
    )
    status_candidates.append(cooling_status)
    for device in cooling_devices:
        type_status, raw_type = read_limited(device / "type", 128)
        current_status, current = _read_number(device / "cur_state", 0, MAX_COUNTER)
        maximum_status, maximum = _read_number(device / "max_state", 0, MAX_COUNTER)
        combined = (
            "permission_error" if "permission_error" in {current_status, maximum_status}
            else "supported" if current_status == maximum_status == "supported"
            else "partial"
        )
        cooling.append({
            "name": _safe_label(raw_type, 64) if type_status == "supported" else device.name,
            "status": combined,
            "currentState": int(current) if current is not None else None,
            "maximumState": int(maximum) if maximum is not None else None,
        })

    model_status, model_text = read_limited(
        sys_root / "firmware" / "devicetree" / "base" / "model", 256
    )
    model = model_text.replace("\x00", "").strip()
    is_raspberry_pi = model_status == "supported" and model.lower().startswith("raspberry pi")
    flags = _safe_integer(rpi_data.get("throttledFlags"), (1 << 32) - 1)
    rpi_temperature = _temperature_celsius(_finite(rpi_data.get("temperatureC"), -50, 200))
    voltage = _finite(rpi_data.get("supplyVoltageVolts"), 0, 10)
    power_sensor_status, power_alarm = _rpi_power_hwmon(sys_root)
    if flags is None and power_sensor_status == "supported" and power_alarm is not None:
        flags = power_alarm
    if rpi_temperature is None and is_raspberry_pi:
        available_temperatures = [
            item["temperatureCelsius"] for item in sensors
            if item["status"] == "supported" and item["temperatureCelsius"] is not None
        ]
        rpi_temperature = max(available_temperatures) if available_temperatures else None
    rpi_has_data = any(value is not None for value in (flags, rpi_temperature, voltage))
    rpi_status = (
        "supported" if rpi_has_data
        else "unsupported" if not is_raspberry_pi
        else "permission_error" if "permission_error" in {*status_candidates, power_sensor_status}
        else "unsupported"
    )
    flag_source = (
        rpi_data.get("_throttledFlagsSource")
        if rpi_data.get("_throttledFlagsSource") in {"vcgencmd", "hwmon-current-only"}
        else "hwmon-current-only" if power_sensor_status == "supported" and flags is not None
        else None
    )
    full_flag_history = flag_source == "vcgencmd"
    rpi = {
        "status": rpi_status,
        "detected": is_raspberry_pi,
        "temperatureCelsius": rpi_temperature,
        "supplyVoltageVolts": round(voltage, 3) if voltage is not None else None,
        "throttledFlags": flags,
        "currentUnderVoltage": bool(flags & 0x1) if flags is not None else None,
        # A hwmon alarm supplies only the current under-voltage bit. Treating
        # every other zero bit as an authoritative negative would create a
        # false-normal throttle history on hosts where get_throttled is not
        # available.
        "currentFrequencyCapped": bool(flags & 0x2) if flags is not None and full_flag_history else None,
        "currentThrottled": bool(flags & 0x4) if flags is not None and full_flag_history else None,
        "currentSoftTemperatureLimit": bool(flags & 0x8) if flags is not None and full_flag_history else None,
        "underVoltageOccurred": bool(flags & 0x10000) if flags is not None and full_flag_history else None,
        "frequencyCapOccurred": bool(flags & 0x20000) if flags is not None and full_flag_history else None,
        "throttlingOccurred": bool(flags & 0x40000) if flags is not None and full_flag_history else None,
        "softTemperatureLimitOccurred": bool(flags & 0x80000) if flags is not None and full_flag_history else None,
        "flagSource": flag_source,
    }
    overall = (
        "permission_error" if "permission_error" in status_candidates and not sensors and not fans
        else "supported" if sensors or fans or cooling or rpi_has_data
        else "unsupported" if all(value == "unsupported" for value in status_candidates)
        else "unavailable"
    )
    return {
        "status": overall,
        "sensors": sensors[:MAX_THERMAL_SENSORS],
        "fans": fans[:MAX_FANS],
        "coolingDevices": cooling[:MAX_FANS],
        "truncated": thermal_truncated or hwmon_truncated or cooling_truncated,
        "raspberryPi": rpi,
    }


def parse_timedatectl_show(text: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in text.splitlines()[:64]:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"NTPSynchronized", "NTP", "CanNTP"}:
            values[key] = value.strip().lower()
    def boolean(name: str) -> bool | None:
        if values.get(name) == "yes":
            return True
        if values.get(name) == "no":
            return False
        return None
    return {
        "synchronized": boolean("NTPSynchronized"),
        "ntpEnabled": boolean("NTP"),
        "ntpSupported": boolean("CanNTP"),
    }


def collect_time_sync(
    timedatectl: str, timeout: float, execute_commands: bool,
    synchronized_marker: Path | None = None,
) -> dict[str, Any]:
    executable = Path(timedatectl)
    base = {
        "synchronized": None,
        "ntpEnabled": None,
        "ntpSupported": None,
        "clockDriftMilliseconds": None,
        "clockDriftStatus": "unsupported",
    }
    def marker_result() -> dict[str, Any] | None:
        if synchronized_marker is None:
            return None
        try:
            marker = synchronized_marker.stat()
            if stat.S_ISREG(marker.st_mode):
                return {
                    "status": "partial", "reason": "systemd_timesync_marker",
                    **base, "synchronized": True,
                }
        except PermissionError:
            return {"status": "permission_error", "reason": "timesync_marker_denied", **base}
        except OSError:
            pass
        return None
    if not execute_commands or not executable.is_file() or not os.access(executable, os.X_OK):
        marker = marker_result()
        if marker is not None:
            return marker
        return {"status": "unsupported", "reason": "timedatectl_unavailable", **base}
    try:
        completed = subprocess.run(
            [timedatectl, "show", "--no-pager", "--property=NTPSynchronized", "--property=NTP", "--property=CanNTP"],
            capture_output=True, text=True, timeout=max(0.1, min(5.0, timeout)), check=False,
        )
    except PermissionError:
        return marker_result() or {"status": "permission_error", "reason": "execution_denied", **base}
    except subprocess.TimeoutExpired:
        return marker_result() or {"status": "timeout", "reason": "deadline", **base}
    except (OSError, subprocess.SubprocessError):
        return marker_result() or {"status": "unavailable", "reason": "execution_failed", **base}
    if completed.returncode != 0:
        denied = "access denied" in completed.stderr[:1024].lower() or "permission denied" in completed.stderr[:1024].lower()
        return marker_result() or {"status": "permission_error" if denied else "unavailable", "reason": "query_failed", **base}
    return {"status": "supported", "reason": None, **base, **parse_timedatectl_show(completed.stdout[:16_384])}


def _public_boot_id(proc_root: Path) -> str | None:
    status, text = read_limited(proc_root / "sys" / "kernel" / "random" / "boot_id", 128)
    if status != "supported":
        return None
    value = text.strip().lower()
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return None
    if str(parsed) != value:
        return None
    return hashlib.blake2s(b"monitor-boot-id-v1\0" + value.encode("ascii"), digest_size=16).hexdigest()


def _iso_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def collect_clock(
    proc_root: Path, now: dt.datetime, previous_boot_id: Any,
    timedatectl: str, timeout: float, execute_commands: bool,
    synchronized_marker: Path | None = None,
) -> tuple[dict[str, Any], str | None]:
    uptime_status, uptime_text = read_limited(proc_root / "uptime", 128)
    uptime_value = _finite(uptime_text.split()[0] if uptime_text.split() else None, 0, 10_000_000_000)
    uptime_seconds = int(uptime_value) if uptime_value is not None else None
    stat_status, stat_text = read_limited(proc_root / "stat", MAX_FILE_BYTES)
    boot_epoch: int | None = None
    if stat_status == "supported":
        for line in stat_text.splitlines():
            if line.startswith("btime "):
                boot_epoch = _safe_integer(line.split()[1], 32_503_680_000)
                break
    boot_time: str | None = None
    if boot_epoch is not None:
        boot_time = _iso_timestamp(dt.datetime.fromtimestamp(boot_epoch, tz=dt.timezone.utc))
    elif uptime_seconds is not None:
        boot_time = _iso_timestamp(now - dt.timedelta(seconds=uptime_seconds))
    boot_id = _public_boot_id(proc_root)
    prior = previous_boot_id if isinstance(previous_boot_id, str) and re.fullmatch(r"[0-9a-f]{32}", previous_boot_id) else None
    reboot_detected = bool(prior and boot_id and prior != boot_id) if prior is not None else None
    return ({
        "status": "supported" if uptime_seconds is not None else uptime_status,
        "uptimeSeconds": uptime_seconds,
        "bootTime": boot_time,
        "rebootDetectedSincePreviousSample": reboot_detected,
        "unexpectedReboot": None,
        "unexpectedRebootStatus": "not_inferable_from_local_counters",
        "timeSync": collect_time_sync(
            timedatectl, timeout, execute_commands, synchronized_marker
        ),
    }, boot_id)


def _probe_source(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            handle.read(1)
    except FileNotFoundError:
        return "unsupported"
    except PermissionError:
        return "permission_error"
    except OSError:
        return "unavailable"
    return "supported"


def collect_event_sources(kernel_log: Path, kernel_summary: Mapping[str, Any]) -> dict[str, Any]:
    safe_summary: dict[str, Any] = {}
    for key in (
        "warning", "oops", "panic", "hungTask", "rcuStall", "rcuExpedited",
        "oomKill", "filesystemError", "nvmeReset", "nvmeIo",
        "pcieAerCorrectable", "pcieAerNonFatal", "pcieAerFatal",
    ):
        value = kernel_summary.get(key)
        if not isinstance(value, Mapping):
            continue
        count = _safe_integer(value.get("count"), 1_000_000)
        last_event = value.get("lastEventAt")
        safe_summary[key] = {
            "count": count,
            "lastEventAt": last_event if isinstance(last_event, str) and len(last_event) <= 40 else None,
        }
    return {
        "kernelLogStatus": _probe_source(kernel_log),
        "summary": safe_summary,
        "rawMessagesExported": False,
    }


def _host_cpu_delta(current: Mapping[str, Any], previous: Any) -> int:
    total = current.get("cpu")
    prior = previous.get("cpu") if isinstance(previous, Mapping) else None
    if not isinstance(total, Mapping) or not isinstance(prior, Mapping):
        return 0
    deltas = [_counter_delta(total.get(name), prior.get(name)) for name in CPU_MODES]
    return sum(value for value in deltas if value is not None) if all(value is not None for value in deltas) else 0


def collect_linux_telemetry(
    *,
    proc_root: Path,
    sys_root: Path,
    mountinfo_path: Path,
    mount_root: Path | None,
    docker_data_root: Path,
    kernel_log: Path,
    kernel_summary: Mapping[str, Any],
    previous: Any,
    elapsed_seconds: float,
    now: dt.datetime,
    loadavg: tuple[float | None, float | None, float | None],
    allowed_uids: set[int],
    process_allowlist: set[str],
    process_name_sanitizer: Callable[[Any], str],
    systemd_units: set[str],
    systemd_state_dir: Path,
    systemctl: str,
    timedatectl: str,
    command_timeout: float,
    rpi_data: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Collect one additive, versioned Linux snapshot and private delta state."""
    prior = previous if isinstance(previous, Mapping) else {}
    elapsed = elapsed_seconds if math.isfinite(elapsed_seconds) and elapsed_seconds > 0 else 0.0
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, TypeError, ValueError):
        page_size = 4096
    page_size = max(1, min(1_048_576, page_size))
    execute_commands = proc_root == Path("/proc") and sys_root == Path("/sys")

    cpu, cpu_state = collect_cpu(proc_root, sys_root, prior.get("cpu"), loadavg)
    memory, memory_state = collect_memory(proc_root, prior.get("vmstat"), elapsed, page_size)
    filesystems, filesystem_state = collect_filesystems(
        mountinfo_path, mount_root, docker_data_root, prior.get("filesystems")
    )
    block_devices, block_state = collect_block_devices(proc_root, sys_root, prior.get("blockDevices"), elapsed)
    network, network_state = collect_network(proc_root, sys_root, prior.get("network"), elapsed)
    tcp, tcp_state = collect_tcp(proc_root, prior.get("tcp"), elapsed)
    processes, process_state = collect_processes(
        proc_root, sys_root, prior.get("processes"), elapsed,
        _host_cpu_delta(cpu_state, prior.get("cpu")), allowed_uids,
        process_allowlist, process_name_sanitizer, page_size,
    )
    clock, boot_id = collect_clock(
        proc_root, now, prior.get("bootId"), timedatectl, command_timeout,
        execute_commands, systemd_state_dir.parent / "timesync" / "synchronized",
    )
    systemd, systemd_state = collect_systemd_observation(
        systemd_units, systemctl, command_timeout, execute_commands,
        systemd_state_dir, sys_root, prior.get("systemd"),
    )
    public = {
        "schemaVersion": SCHEMA_VERSION,
        "collectedAt": _iso_timestamp(now),
        "cpu": cpu,
        "memory": memory,
        "filesystems": filesystems,
        "blockDevices": block_devices,
        "network": network,
        "tcp": tcp,
        "processes": processes,
        "systemd": systemd,
        "thermal": collect_thermal(sys_root, rpi_data),
        "clock": clock,
        "eventSources": collect_event_sources(kernel_log, kernel_summary),
        "collectionBounds": {
            "maximumCpuCount": MAX_CPU_COUNT,
            "maximumBlockDevices": MAX_BLOCK_DEVICES,
            "maximumInterfaces": MAX_INTERFACES,
            "maximumTcpSockets": MAX_TCP_SOCKETS,
            "maximumFilesystems": MAX_FILESYSTEMS,
            "maximumProcesses": MAX_PROCESSES,
            "processDeadlineMilliseconds": int(PROCESS_SCAN_SECONDS * 1000),
            "maximumSystemdUnits": MAX_SYSTEMD_UNITS,
            "maximumThermalSensors": MAX_THERMAL_SENSORS,
            "commandTimeoutMilliseconds": int(max(0.1, min(5.0, command_timeout)) * 1000),
        },
        "privacy": {
            "processCommandLinesCollected": False,
            "processEnvironmentsCollected": False,
            "rawKernelMessagesCollected": False,
        },
    }
    state = {
        "cpu": cpu_state,
        "vmstat": memory_state,
        "filesystems": filesystem_state,
        "blockDevices": block_state,
        "network": network_state,
        "tcp": tcp_state,
        "processes": process_state,
        "systemd": systemd_state,
        "bootId": boot_id,
    }
    return public, state
