#!/usr/bin/env python3
"""Low-overhead, read-only host telemetry exporter.

Only the configured output and state directories are written. Host inputs are
read from procfs/sysfs, selected logs, and a reduced unprivileged container
snapshot; direct Docker mode exists only for fixtures. No raw log line or
mutable Docker metadata is ever exported.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
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
}
INCIDENT_REASONS = (
    "cpu", "memory", "temperature", "power-throttle", "load", "disk-io", "traffic",
)
INCIDENT_PHASES = {"active", "follow-up", "recovered"}
MAX_PROCESS_STATE_ENTRIES = 8_192
MAX_PROCESS_GROUPS = 20
MAX_INCIDENT_CONTAINERS = 64
MAX_CONTAINER_CPU_PERCENT = 1024.0
ALLOWED_PROCESS_UIDS = frozenset({0, 1001})
MAX_TRAFFIC_APPS = 16
ALLOWED_TRAFFIC_APPS = frozenset({
    "monitor", "feelmyrythm", "multtara", "pilgrimage",
    "ddit-finalproject", "dukkeobi", "react", "vue",
})
MAX_TRAFFIC_REQUEST_SECONDS = 300.0
MAX_TRAFFIC_INPUT_AGE_SECONDS = 600
MAX_TRAFFIC_LINE_BYTES = 4096
MAX_INCIDENT_FILE_BYTES = 16 * 1024 * 1024
MAX_INCIDENT_LINE_BYTES = 64 * 1024
MAX_PENDING_INCIDENT_COMMIT_BYTES = 96 * 1024
MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES = 8 * 1024 * 1024
MAX_SANITIZED_LOG_RECORD_BYTES = 4096
MAX_CONTAINER_INPUT_BYTES = 1 * 1024 * 1024
MAX_CONTAINER_INPUT_AGE_SECONDS = 180
ALLOWED_COMPOSE_SERVICES = {
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
ALLOWED_COMPOSE_PROJECTS = tuple(sorted({
    project for project, _service in ALLOWED_COMPOSE_SERVICES
}))
CURRENT_CONTAINER_NAMES = frozenset(ALLOWED_COMPOSE_SERVICES.values())
LEGACY_CONTAINER_SERVICE_NAMES = frozenset({
    "bonifacio-web",
    "bonifacio-sso",
    "bonifacio-sso-admin",
    "bonifacio-sso-redis",
    "feelmyrythm-web",
    "feelmyrythm-server",
    # The standalone PostgreSQL service is forbidden in the live cksDB
    # topology, but retained snapshots/incidents must remain readable.
    "multtara-database",
})
# Previous exporters emitted app-level traffic labels, ``cks-workload``, or the
# superseded service labels above. Keep every prior value readable for retained
# snapshots/incidents, but never assign one to a new Docker observation.
LEGACY_CONTAINER_NAMES = (
    ALLOWED_TRAFFIC_APPS
    | LEGACY_CONTAINER_SERVICE_NAMES
    | frozenset({"cks-workload"})
)
SAFE_CONTAINER_NAMES = CURRENT_CONTAINER_NAMES | LEGACY_CONTAINER_NAMES
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


class PendingJournalError(RuntimeError):
    """A pending transaction exists but cannot be safely validated or completed."""


def require_pending_journal_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise PendingJournalError("pending journal absence could not be verified") from error
    raise PendingJournalError("pending journal already exists")


def atomic_create_json(
    path: Path,
    value: Any,
    maximum_bytes: int,
    mode: int = 0o600,
) -> None:
    """Publish a new journal atomically without replacing any existing object."""
    ensure_directory(path.parent)
    require_pending_journal_absent(path)

    payload = (json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ) + "\n").encode()
    if not 0 < len(payload) <= maximum_bytes:
        raise ValueError("pending journal exceeded its byte limit")

    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise PendingJournalError("pending journal appeared during creation") from error
        os.unlink(temporary)
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


def valid_private_pending_metadata(
    metadata: os.stat_result,
    maximum_bytes: int,
    link_count: int,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_nlink == link_count
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and 0 < metadata.st_size <= maximum_bytes
    )


def recover_linked_pending_publication(
    path: Path,
    metadata: os.stat_result,
    maximum_bytes: int,
) -> os.stat_result:
    """Finish only our exact hard-link publication crash window."""
    prefix = f".{path.name}."
    name_pattern = re.compile(rf"{re.escape(prefix)}[a-z0-9_]{{8}}")
    try:
        entries = list(path.parent.iterdir())
    except OSError as error:
        raise PendingJournalError("pending journal siblings could not be inspected") from error
    candidates = [entry for entry in entries if name_pattern.fullmatch(entry.name)]
    if len(candidates) != 1:
        raise PendingJournalError("pending journal has an ambiguous link count")
    sibling = candidates[0]
    try:
        sibling_metadata = sibling.lstat()
    except OSError as error:
        raise PendingJournalError("pending journal sibling could not be inspected") from error
    if (
        sibling.parent != path.parent
        or not name_pattern.fullmatch(sibling.name)
        or sibling_metadata.st_dev != metadata.st_dev
        or sibling_metadata.st_ino != metadata.st_ino
        or not stat.S_ISREG(sibling_metadata.st_mode)
        or sibling_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(sibling_metadata.st_mode) != 0o600
        or sibling_metadata.st_nlink != 2
        or not valid_private_pending_metadata(metadata, maximum_bytes, 2)
    ):
        raise PendingJournalError("pending journal sibling failed publication validation")
    try:
        sibling.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        recovered = path.lstat()
    except OSError as error:
        raise PendingJournalError("pending journal publication recovery failed") from error
    if (
        recovered.st_dev != metadata.st_dev
        or recovered.st_ino != metadata.st_ino
        or not valid_private_pending_metadata(recovered, maximum_bytes, 1)
    ):
        raise PendingJournalError("pending journal failed post-recovery validation")
    return recovered


def load_private_pending_json(path: Path, maximum_bytes: int) -> Any | None:
    """Load an exact private journal, preserving every unsafe object fail-closed."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise PendingJournalError("pending journal metadata could not be read") from error
    if metadata.st_nlink == 2:
        metadata = recover_linked_pending_publication(path, metadata, maximum_bytes)
    if not valid_private_pending_metadata(metadata, maximum_bytes, 1):
        raise PendingJournalError("pending journal failed file validation")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PendingJournalError("pending journal could not be opened") from error
    payload: bytes
    try:
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or not valid_private_pending_metadata(opened, maximum_bytes, 1)
            ):
                raise PendingJournalError("pending journal changed during validation")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read(maximum_bytes + 1)
        except OSError as error:
            raise PendingJournalError("pending journal could not be read") from error
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
        raise PendingJournalError("pending journal changed during reading")
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PendingJournalError("pending journal is not valid JSON") from error


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


def calculate_cpu(current: tuple[int, int] | None, previous: Any) -> float | None:
    if current is None or not isinstance(previous, list) or len(previous) != 2:
        return None
    try:
        total_delta = current[0] - int(previous[0])
        idle_delta = current[1] - int(previous[1])
    except (TypeError, ValueError):
        return None
    if total_delta <= 0 or idle_delta < 0:
        return None
    return round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 2)


def parse_meminfo(text: str) -> tuple[int | None, int | None]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s*(kB)?", line)
        if match:
            multiplier = 1024 if match.group(3) else 1
            values[match.group(1)] = int(match.group(2)) * multiplier
    total = values.get("MemTotal")
    if total is None or total <= 0:
        return None, None
    available = values.get("MemAvailable")
    if available is None:
        fallback_fields = ("MemFree", "Buffers", "Cached")
        if not any(field_name in values for field_name in fallback_fields):
            return total, None
        available = sum(values.get(field_name, 0) for field_name in fallback_fields)
    return total, min(total, max(0, available))


def parse_loadavg(text: str) -> tuple[float | None, float | None, float | None]:
    fields = text.split()
    values: list[float | None] = []
    for index in range(3):
        value = finite_number(fields[index] if len(fields) > index else None)
        values.append(round(value, 2) if value is not None and value >= 0 else None)
    return values[0], values[1], values[2]


def parse_uptime(text: str) -> int:
    value = finite_number(text.split()[0] if text.split() else None, 0.0)
    return max(0, int(value or 0))


def parse_net_dev(text: str) -> tuple[int, int] | None:
    received = transmitted = 0
    observed = False
    for line in text.splitlines():
        if ":" not in line:
            continue
        interface, counters = line.split(":", 1)
        fields = counters.split()
        if len(fields) < 9:
            continue
        try:
            current_received = int(fields[0])
            current_transmitted = int(fields[8])
        except ValueError:
            continue
        if current_received < 0 or current_transmitted < 0:
            continue
        observed = True
        if interface.strip() == "lo":
            continue
        received += current_received
        transmitted += current_transmitted
    return (received, transmitted) if observed else None


def parse_diskstats(text: str) -> tuple[int, int] | None:
    read_bytes = write_bytes = 0
    observed = False
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        device = fields[2]
        try:
            current_read = int(fields[5])
            current_write = int(fields[9])
        except ValueError:
            continue
        if current_read < 0 or current_write < 0:
            continue
        observed = True
        if re.match(r"^(loop|ram|fd|sr|zram|dm-|md\d+)", device):
            continue
        # Avoid counting partitions as well as their parent disk.
        if (
            re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+$", device)
            or re.match(r"^nvme\d+n\d+p\d+$", device)
            or re.match(r"^mmcblk\d+(?:p\d+|boot\d+|rpmb)$", device)
        ):
            continue
        read_bytes += current_read * 512
        write_bytes += current_write * 512
    return (read_bytes, write_bytes) if observed else None


def rate_pair(
    current: tuple[int, int] | None,
    previous: Any,
    elapsed: float,
) -> tuple[float | None, float | None]:
    if current is None or not isinstance(previous, list) or len(previous) != 2 or elapsed <= 0:
        return None, None
    try:
        first = current[0] - int(previous[0])
        second = current[1] - int(previous[1])
    except (TypeError, ValueError):
        return None, None
    if first < 0 or second < 0:
        return None, None
    return round(first / elapsed, 2), round(second / elapsed, 2)


def parse_pressure(text: str) -> dict[str, float | None]:
    result: dict[str, float | None] = {"someAvg10": None, "fullAvg10": None}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        match = next((field for field in fields[1:] if field.startswith("avg10=")), None)
        value = finite_number(match.split("=", 1)[1] if match else None)
        if value is not None and 0 <= value <= 100:
            result[f"{fields[0]}Avg10"] = round(value, 2)
    return result


def collect_pressure(proc_root: Path) -> dict[str, dict[str, float | None]]:
    return {
        kind: parse_pressure(read_text(proc_root / "pressure" / kind, 4096))
        for kind in ("cpu", "memory", "io")
    }


def safe_process_name(value: Any) -> str:
    name = bounded_text(value, 64).lower()
    if not name:
        return "unknown"
    if re.search(r"password|passwd|secret|token|api.?key", name, re.IGNORECASE):
        return "redacted"
    if re.fullmatch(r"node(?:js)?", name):
        return "node"
    if re.fullmatch(r"python(?:2|3)?(?:\.[0-9]+)?|pypy(?:3)?|gunicorn|uvicorn", name):
        return "python"
    if name in {"nginx", "caddy", "apache2", "httpd"}:
        return "web-server"
    if name in {"postgres", "postmaster", "mysqld", "mariadbd", "redis-server"}:
        return "database"
    if name in {
        "dockerd", "containerd", "containerd-shim", "rootlesskit", "rootlesskit-docker-proxy",
    }:
        return "container-runtime"
    if name in {
        "systemd", "systemd-journal", "systemd-logind", "dbus-daemon", "sshd", "cron", "crond",
    }:
        return "system-service"
    if re.match(r"^(?:kworker/|ksoftirqd/|migration/|rcu[_o]|watchdog/)", name):
        return "kernel-worker"
    return "other"


def parse_process_stat(text: str) -> tuple[str, int, int, int] | None:
    opening = text.find("(")
    closing = text.rfind(")")
    if opening <= 0 or closing <= opening:
        return None
    fields = text[closing + 1:].split()
    if len(fields) < 22:
        return None
    try:
        cpu_ticks = int(fields[11]) + int(fields[12])
        start_ticks = int(fields[19])
        resident_pages = int(fields[21])
    except (TypeError, ValueError):
        return None
    if min(cpu_ticks, start_ticks, resident_pages) < 0:
        return None
    return safe_process_name(text[opening + 1:closing]), cpu_ticks, start_ticks, resident_pages


def collect_processes(
    proc_root: Path,
    previous_cpu: Any,
    host_cpu_delta: int,
    allowed_uids: set[int],
    page_size: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Aggregate allow-listed host processes without exporting identities or argv."""
    allowed_uids = set(allowed_uids) & set(ALLOWED_PROCESS_UIDS)
    prior = previous_cpu if isinstance(previous_cpu, Mapping) else {}
    groups: dict[str, dict[str, Any]] = {}
    next_state: dict[str, int] = {}
    try:
        candidates = sorted(
            (path for path in proc_root.iterdir() if path.name.isdigit()),
            key=lambda path: int(path.name),
        )[:MAX_PROCESS_STATE_ENTRIES]
    except OSError:
        candidates = []
    if page_size is None:
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, TypeError, ValueError):
            page_size = 4096
    page_size = max(1, page_size)

    for process_dir in candidates:
        try:
            metadata = process_dir.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in allowed_uids:
            continue
        parsed = parse_process_stat(read_text(process_dir / "stat", 8192))
        if parsed is None:
            continue
        name, cpu_ticks, start_ticks, resident_pages = parsed
        state_key = hashlib.blake2s(
            f"{process_dir.name}:{start_ticks}".encode("ascii"), digest_size=12
        ).hexdigest()
        next_state[state_key] = cpu_ticks
        group = groups.setdefault(name, {
            "name": name,
            "instances": 0,
            "cpuTicks": 0,
            "cpuComplete": True,
            "memoryBytes": 0,
        })
        group["instances"] += 1
        group["memoryBytes"] += resident_pages * page_size
        previous_ticks = prior.get(state_key)
        if (
            host_cpu_delta > 0
            and isinstance(previous_ticks, int)
            and not isinstance(previous_ticks, bool)
            and 0 <= previous_ticks <= cpu_ticks
        ):
            group["cpuTicks"] += cpu_ticks - previous_ticks
        else:
            group["cpuComplete"] = False

    normalized: list[dict[str, Any]] = []
    for group in groups.values():
        cpu_percent = None
        if group["cpuComplete"] and host_cpu_delta > 0:
            cpu_percent = round(max(0.0, min(100.0, group["cpuTicks"] * 100.0 / host_cpu_delta)), 2)
        normalized.append({
            "name": group["name"],
            "instances": group["instances"],
            "cpuPercent": cpu_percent,
            "memoryBytes": group["memoryBytes"],
        })

    cpu_top = sorted(
        (item for item in normalized if item["cpuPercent"] is not None),
        key=lambda item: (-item["cpuPercent"], -item["memoryBytes"], item["name"]),
    )[: MAX_PROCESS_GROUPS // 2]
    memory_top = sorted(
        normalized,
        key=lambda item: (-item["memoryBytes"], -(item["cpuPercent"] or 0), item["name"]),
    )[: MAX_PROCESS_GROUPS // 2]
    selected = {item["name"] for item in [*cpu_top, *memory_top]}
    return sorted(
        (item for item in normalized if item["name"] in selected),
        key=lambda item: (-(item["cpuPercent"] or 0), -item["memoryBytes"], item["name"]),
    ), next_state


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
    return round(min(MAX_CONTAINER_CPU_PERCENT, max(0.0, cpu_delta / system_delta * online * 100.0)), 2)


def compose_project_list_path(project: str) -> str:
    """Build a Docker list request restricted to one reviewed Compose project."""
    if project not in ALLOWED_COMPOSE_PROJECTS:
        raise ValueError("Docker project is outside the allowlist")
    filters = json.dumps(
        {"label": [f"com.docker.compose.project={project}"]},
        separators=(",", ":"),
    )
    return "/v1.41/containers/json?" + urllib.parse.urlencode({"all": "1", "filters": filters})


def safe_container_name(raw: Mapping[str, Any], expected_project: str | None = None) -> str | None:
    """Map one exact Compose project/service pair to a fixed public label."""
    labels = raw.get("Labels") if isinstance(raw.get("Labels"), Mapping) else {}
    project = labels.get("com.docker.compose.project")
    service = labels.get("com.docker.compose.service")
    if not isinstance(project, str) or not isinstance(service, str):
        return None
    if expected_project is not None and project != expected_project:
        return None
    return ALLOWED_COMPOSE_SERVICES.get((project, service))


def container_from_api(
    raw: Mapping[str, Any], owner: str, stats: Mapping[str, Any] | None,
    previous_cpu: Any = None, public_name: str | None = None,
) -> dict[str, Any]:
    name = safe_container_name(raw)
    if name is None:
        raise ValueError("container is outside the Compose service allowlist")
    if public_name is not None and public_name != name:
        raise ValueError("container Compose labels changed after admission")
    state = bounded_text(raw.get("State", "unknown"), 24).lower()
    status = str(raw.get("Status", ""))
    health_match = re.search(r"\((healthy|unhealthy|starting)\)", status, re.IGNORECASE)
    health = health_match.group(1).lower() if health_match else ("none" if state != "running" else "unknown")
    memory_bytes: int | None = None
    memory_percent: float | None = None
    cpu_percent: float | None = None
    if isinstance(stats, Mapping):
        memory = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
        raw_memory_bytes = finite_number(memory.get("usage"))
        raw_memory_limit = finite_number(memory.get("limit"))
        memory_bytes = int(raw_memory_bytes) if raw_memory_bytes is not None and raw_memory_bytes >= 0 else None
        memory_limit = int(raw_memory_limit) if raw_memory_limit is not None and raw_memory_limit > 0 else None
        memory_percent = (
            round(min(100.0, 100.0 * memory_bytes / memory_limit), 2)
            if memory_bytes is not None and memory_limit is not None
            else None
        )
        cpu_percent = docker_cpu_percent(docker_cpu_state(stats), previous_cpu)
    return {
        "name": name,
        "owner": "cks" if owner == "cks" else "unknown",
        "state": state,
        "health": health,
        "cpuPercent": cpu_percent,
        "memoryBytes": memory_bytes,
        "memoryPercent": memory_percent,
    }


def collect_containers(
    sockets: Mapping[str, Path], curl: str, timeout: float, previous_cpu: Any = None
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    sockets = {"cks": sockets["cks"]} if isinstance(sockets.get("cks"), Path) else {}
    containers: list[dict[str, Any]] = []
    deadline = _monotonic() + 20.0
    entries: list[tuple[str, Path, Mapping[str, Any], str]] = []
    seen_container_ids: set[str] = set()
    # Every list request is constrained to one reviewed Compose project. An
    # unavailable query fails the whole export so callers retain the last
    # complete reduced snapshot instead of publishing a partial count.
    for owner, socket_path in sockets.items():
        for project in ALLOWED_COMPOSE_PROJECTS:
            raw_list = docker_get(socket_path, compose_project_list_path(project), curl, timeout)
            if not isinstance(raw_list, list):
                raise RuntimeError("cks container telemetry source unavailable")
            if len(raw_list) > 200:
                raise RuntimeError("cks container telemetry project response exceeded its limit")
            for raw in raw_list:
                if not isinstance(raw, dict):
                    raise RuntimeError("cks container telemetry project response is malformed")
                public_name = safe_container_name(raw, project)
                if public_name is None:
                    continue
                container_id = str(raw.get("Id", ""))
                if not re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id):
                    raise RuntimeError("cks container telemetry workload has an invalid ID")
                if container_id in seen_container_ids:
                    raise RuntimeError("cks container telemetry workload was listed more than once")
                seen_container_ids.add(container_id)
                entries.append((owner, socket_path, raw, public_name))
                if len(entries) > 200:
                    raise RuntimeError("cks container telemetry workload count exceeded its limit")

    previous_state = previous_cpu if isinstance(previous_cpu, Mapping) else {}
    listed_keys: list[str] = []
    stats_candidates: list[tuple[int, Path, str, str]] = []
    for index, (owner, socket_path, raw, _public_name) in enumerate(entries):
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
    for index, (owner, _socket_path, raw, public_name) in enumerate(entries):
        stats = stats_by_index.get(index)
        container_id = str(raw.get("Id", ""))
        state_key = f"{owner}:{container_id}"
        current_cpu = docker_cpu_state(stats) if isinstance(stats, Mapping) else None
        containers.append(container_from_api(
            raw, owner, stats if isinstance(stats, dict) else None,
            previous_state.get(state_key), public_name,
        ))
        if current_cpu is not None and state_key in retained_keys:
            next_cpu_state[state_key] = current_cpu
    return sorted(containers, key=lambda item: (item["owner"], item["name"])), next_cpu_state


def load_container_snapshot(path: Path, now: dt.datetime) -> list[dict[str, Any]]:
    """Validate the unprivileged export before admitting it to root-owned output."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimeError("container telemetry snapshot unavailable") from error
    def valid_metadata(value: os.stat_result) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and value.st_uid == 1001
            and value.st_gid == 1001
            and value.st_nlink == 1
            and stat.S_IMODE(value.st_mode) == 0o640
            and 0 < value.st_size <= MAX_CONTAINER_INPUT_BYTES
        )

    if not valid_metadata(metadata):
        raise ValueError("container telemetry snapshot failed file validation")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not valid_metadata(opened)
        ):
            raise ValueError("container telemetry snapshot changed during validation")
        payload = os.read(descriptor, MAX_CONTAINER_INPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_CONTAINER_INPUT_BYTES:
        raise ValueError("container telemetry snapshot exceeds the byte limit")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("container telemetry snapshot is invalid JSON") from error
    if not isinstance(raw, dict) or set(raw) != {"generatedAt", "containers"}:
        raise ValueError("container telemetry snapshot has unexpected fields")
    generated = parse_iso_timestamp(raw.get("generatedAt"))
    if generated is None or not -60 <= (now - generated).total_seconds() <= MAX_CONTAINER_INPUT_AGE_SECONDS:
        raise ValueError("container telemetry snapshot is stale")
    values = raw.get("containers")
    if not isinstance(values, list) or len(values) > 200:
        raise ValueError("container telemetry snapshot has an invalid workload list")

    result: list[dict[str, Any]] = []
    allowed_states = {"created", "running", "paused", "restarting", "removing", "exited", "dead", "unknown"}
    allowed_health = {"healthy", "unhealthy", "starting", "none", "unknown"}
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "name", "owner", "state", "health", "cpuPercent", "memoryBytes", "memoryPercent",
        }:
            raise ValueError("container telemetry workload has unexpected fields")
        name = value.get("name")
        state = value.get("state")
        health = value.get("health")
        if (
            name not in SAFE_CONTAINER_NAMES
            or value.get("owner") != "cks"
            or state not in allowed_states
            or health not in allowed_health
        ):
            raise ValueError("container telemetry workload is outside the allowlist")
        cpu_percent = normalized_bounded_number(value.get("cpuPercent"), 0, MAX_CONTAINER_CPU_PERCENT)
        memory_bytes = normalized_bounded_number(value.get("memoryBytes"), 0, 1 << 63)
        memory_percent = normalized_bounded_number(value.get("memoryPercent"), 0, 100)
        for source, normalized in (
            (value.get("cpuPercent"), cpu_percent),
            (value.get("memoryBytes"), memory_bytes),
            (value.get("memoryPercent"), memory_percent),
        ):
            if source is not None and normalized is None:
                raise ValueError("container telemetry workload has an invalid metric")
        if memory_bytes is not None and (
            isinstance(value.get("memoryBytes"), bool) or not isinstance(value.get("memoryBytes"), int)
        ):
            raise ValueError("container telemetry workload has an invalid memory byte count")
        result.append({
            "name": name,
            "owner": "cks",
            "state": state,
            "health": health,
            "cpuPercent": cpu_percent,
            "memoryBytes": memory_bytes,
            "memoryPercent": memory_percent,
        })
    return sorted(result, key=lambda item: item["name"])


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
MAINTENANCE_EVENT_DETAILS = {
    ("multtara-cksdb-cutover", "started"): (
        "info",
        "Multtara database cutover maintenance started.",
    ),
    ("multtara-cksdb-cutover", "completed"): (
        "info",
        "Multtara now uses the shared cksDB PostgreSQL service.",
    ),
    ("multtara-cksdb-cutover", "rolled-back"): (
        "warning",
        "Multtara database cutover rolled back to the retained standalone PostgreSQL service.",
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


def parse_iso_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def alert_message(reason: str, recovered: bool = False) -> str:
    state = "recovered" if recovered else "active"
    return f"Host condition {bounded_text(reason, 64)} is {state}."


def sanitize_alert_line(line: str, fallback_timestamp: str) -> dict[str, Any] | None:
    timestamp = event_timestamp(line, fallback_timestamp)
    match = re.search(
        r"\bMAINTENANCE\s+event=(multtara-cksdb-cutover)\s+"
        r"status=(started|completed|rolled-back)\b",
        line,
    )
    if match:
        event = (match.group(1), match.group(2))
        severity, message = MAINTENANCE_EVENT_DETAILS[event]
        return {
            "timestamp": timestamp,
            "severity": severity,
            "kind": "topology",
            "status": event[1],
            "message": message,
        }
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


def stable_deduplicate_records(
    records: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> list[Mapping[str, Any]]:
    """Keep the first occurrence of each complete fixed-schema public row."""
    result: list[Mapping[str, Any]] = []
    expected = set(fields)
    seen: set[tuple[Any, ...]] = set()
    for record in records:
        if set(record) != expected:
            continue
        key = tuple(record.get(field_name) for field_name in fields)
        if key in seen:
            continue
        seen.add(key)
        result.append(record)
    return result


def deduplicate_power_records(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    # Power records are canonicalized before this point, including timestamps
    # truncated to a second. Full-row equality therefore also collapses bursty
    # duplicate kernel messages without merging active/recovered transitions.
    return stable_deduplicate_records(
        records,
        ("timestamp", "severity", "kind", "status", "message"),
    )


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


def read_framed_segment(
    path: Path,
    start: int,
    max_bytes: int,
    max_line_bytes: int,
    discard_until_newline: bool,
) -> tuple[list[str], int, bool, bool]:
    """Read complete bounded lines and leave an incomplete tail for the next poll."""
    try:
        with path.open("rb") as handle:
            handle.seek(start)
            content = handle.read(max_bytes)
    except (OSError, ValueError):
        return [], start, discard_until_newline, False
    base = start
    if discard_until_newline:
        newline = content.find(b"\n")
        if newline < 0:
            return [], start + len(content), True, True
        consumed = newline + 1
        content = content[consumed:]
        base += consumed
    last_newline = content.rfind(b"\n")
    if last_newline < 0:
        if len(content) > max_line_bytes:
            return [], base + len(content), True, True
        return [], base, False, True
    complete = content[:last_newline + 1]
    trailing = content[last_newline + 1:]
    next_offset = base + last_newline + 1
    discard_next = False
    if len(trailing) > max_line_bytes:
        next_offset = base + len(content)
        discard_next = True
    lines = [
        raw.decode("utf-8", errors="replace")
        for raw in complete.splitlines()
        if len(raw) <= max_line_bytes
    ]
    return lines, next_offset, discard_next, True


def rotated_inode_path(path: Path, inode: int) -> Path | None:
    try:
        candidates = list(path.parent.iterdir())[:256]
    except OSError:
        return None
    for candidate in candidates:
        if candidate == path or not candidate.name.startswith(path.name):
            continue
        try:
            metadata = candidate.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and metadata.st_ino == inode:
            return candidate
    return None


def starts_mid_line(path: Path, offset: int) -> bool:
    if offset <= 0:
        return False
    try:
        with path.open("rb") as handle:
            handle.seek(offset - 1)
            return handle.read(1) != b"\n"
    except (OSError, ValueError):
        return True


def read_new_lines(
    path: Path,
    cursor: Mapping[str, Any],
    max_bytes: int,
    max_line_bytes: int = 128 * 1024,
) -> tuple[list[str], dict[str, Any]]:
    """Read each complete appended line once, including a rotated inode's residual tail."""
    max_bytes = max(1, max_bytes)
    max_line_bytes = max(1, min(max_bytes, max_line_bytes))
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            return [], dict(cursor) if isinstance(cursor, dict) else {}
        inode = int(metadata.st_ino)
        size = int(metadata.st_size)
        old_inode = int(cursor.get("inode", -1))
        old_offset = int(cursor.get("offset", 0))
    except (OSError, TypeError, ValueError):
        return [], dict(cursor) if isinstance(cursor, dict) else {}

    old_discard = cursor.get("discardUntilNewline") is True
    same_inode = old_inode == inode and 0 <= old_offset <= size
    if same_inode:
        start = old_offset
        discard = old_discard
        if size - start > max_bytes:
            start = size - max_bytes
            discard = old_discard or starts_mid_line(path, start)
        lines, next_offset, discard_next, success = read_framed_segment(
            path, start, max_bytes, max_line_bytes, discard
        )
        if not success:
            return [], dict(cursor) if isinstance(cursor, dict) else {}
        next_cursor: dict[str, Any] = {"inode": inode, "offset": next_offset}
        if discard_next:
            next_cursor["discardUntilNewline"] = True
        return lines, next_cursor

    lines: list[str] = []
    if old_inode >= 0 and old_offset >= 0:
        rotated = rotated_inode_path(path, old_inode)
        if rotated is not None:
            try:
                rotated_size = int(rotated.stat(follow_symlinks=False).st_size)
            except OSError:
                rotated_size = old_offset
            rotated_start = min(old_offset, rotated_size)
            rotated_discard = old_discard
            if rotated_size - rotated_start > max_bytes:
                rotated_start = rotated_size - max_bytes
                rotated_discard = old_discard or starts_mid_line(rotated, rotated_start)
            residual, _offset, _discard, _success = read_framed_segment(
                rotated, rotated_start, max_bytes, max_line_bytes, rotated_discard
            )
            lines.extend(residual)

    start = max(0, size - max_bytes)
    new_lines, next_offset, discard_next, success = read_framed_segment(
        path, start, max_bytes, max_line_bytes, starts_mid_line(path, start)
    )
    if not success:
        return lines, dict(cursor) if isinstance(cursor, dict) else {}
    lines.extend(new_lines)
    next_cursor = {"inode": inode, "offset": next_offset}
    if discard_next:
        next_cursor["discardUntilNewline"] = True
    return lines, next_cursor


def existing_json_lines(
    path: Path,
    limit: int,
    maximum_bytes: int = 8_388_608,
    estimated_record_bytes: int = 1024,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        maximum = min(maximum_bytes, max(65_536, limit * estimated_record_bytes))
        size = path.stat().st_size
        start = max(0, size - maximum)
        with path.open("rb") as handle:
            handle.seek(start)
            if start:
                handle.readline(maximum)
            content = handle.read(maximum)
            for raw_line in content.splitlines():
                if len(raw_line) > estimated_record_bytes:
                    continue
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


def rewrite_incident_lines(path: Path, records: Sequence[Mapping[str, Any]], limit: int) -> None:
    encoded: list[bytes] = []
    total = 0
    for record in reversed(records[-limit:]):
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(line) > MAX_INCIDENT_LINE_BYTES:
            continue
        if total + len(line) > MAX_INCIDENT_FILE_BYTES:
            break
        encoded.append(line)
        total += len(line)
    payload = b"".join(reversed(encoded))
    ensure_directory(path.parent)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), 0o640)
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


def parse_traffic_line(line: str, now: dt.datetime) -> tuple[str, int, float] | None:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(record, dict) or set(record) != {"timestamp", "app", "status", "requestTime"}:
        return None
    timestamp = parse_iso_timestamp(record.get("timestamp"))
    if timestamp is None:
        return None
    age = (now - timestamp).total_seconds()
    if age < -60 or age > MAX_TRAFFIC_INPUT_AGE_SECONDS:
        return None
    app = record.get("app")
    if (
        not isinstance(app, str)
        or app not in ALLOWED_TRAFFIC_APPS
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", app) is None
    ):
        return None
    status = record.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return None
    request_time = record.get("requestTime")
    if isinstance(request_time, bool) or not isinstance(request_time, (int, float)):
        return None
    parsed_time = finite_number(request_time)
    if parsed_time is None or not 0 <= parsed_time <= MAX_TRAFFIC_REQUEST_SECONDS:
        return None
    return app, status, parsed_time


def collect_traffic(
    config: "Config",
    now: dt.datetime,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
    """Aggregate a complete input interval without committing its cursor yet."""
    if config.traffic_log is None:
        return [], None, False
    cursor_path = config.output_dir / ".state" / "traffic-cursor.json"
    cursor_state = load_json(cursor_path)
    prior_cursor = cursor_state.get("cursor", {})
    if not isinstance(prior_cursor, Mapping):
        prior_cursor = {}
    try:
        metadata = config.traffic_log.stat()
        if not stat.S_ISREG(metadata.st_mode):
            return [], None, False
        # A separate open catches ordinary access failures so an unavailable
        # source cannot be mistaken for a known zero-request interval.
        with config.traffic_log.open("rb"):
            pass
    except OSError:
        return [], None, False
    lines, next_cursor = read_new_lines(
        config.traffic_log,
        prior_cursor,
        config.max_input_bytes,
        MAX_TRAFFIC_LINE_BYTES,
    )
    groups: dict[str, dict[str, Any]] = {}
    for line in lines:
        parsed = parse_traffic_line(line, now)
        if parsed is None:
            continue
        app, status, request_time = parsed
        if app not in groups and len(groups) >= MAX_TRAFFIC_APPS:
            continue
        group = groups.setdefault(app, {
            "app": app,
            "requestCount": 0,
            "status2xx": 0,
            "status3xx": 0,
            "status4xx": 0,
            "status5xx": 0,
            "slowCount": 0,
            "responseSeconds": 0.0,
            "maxResponseSeconds": 0.0,
        })
        group["requestCount"] += 1
        if 200 <= status <= 299:
            group["status2xx"] += 1
        elif 300 <= status <= 399:
            group["status3xx"] += 1
        elif 400 <= status <= 499:
            group["status4xx"] += 1
        elif 500 <= status <= 599:
            group["status5xx"] += 1
        if request_time >= config.traffic_slow_seconds:
            group["slowCount"] += 1
        group["responseSeconds"] += request_time
        group["maxResponseSeconds"] = max(group["maxResponseSeconds"], request_time)
    result = [{
        "app": group["app"],
        "requestCount": group["requestCount"],
        "status2xx": group["status2xx"],
        "status3xx": group["status3xx"],
        "status4xx": group["status4xx"],
        "status5xx": group["status5xx"],
        "slowCount": group["slowCount"],
        "avgResponseMs": round(group["responseSeconds"] * 1000.0 / group["requestCount"], 2),
        "maxResponseMs": round(group["maxResponseSeconds"] * 1000.0, 2),
    } for group in sorted(groups.values(), key=lambda item: item["app"])]
    return result, next_cursor, True


def commit_traffic_cursor(config: "Config", cursor: Mapping[str, Any] | None) -> None:
    if cursor is None:
        return
    normalized = existing_traffic_cursor(cursor)
    if normalized is None:
        raise ValueError("traffic cursor did not satisfy the private state contract")
    atomic_write_json(
        config.output_dir / ".state" / "traffic-cursor.json",
        {"cursor": normalized},
        0o600,
    )


def existing_traffic_cursor(value: Any) -> dict[str, Any] | None:
    """Validate the minimal offset-only state stored for the reduced access log."""
    if not isinstance(value, Mapping):
        return None
    fields = set(value)
    if not fields:
        return {}
    if fields not in ({"inode", "offset"}, {"inode", "offset", "discardUntilNewline"}):
        return None
    inode = value.get("inode")
    offset = value.get("offset")
    if (
        isinstance(inode, bool)
        or not isinstance(inode, int)
        or not 0 <= inode <= (1 << 64) - 1
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset <= (1 << 63) - 1
    ):
        return None
    normalized: dict[str, Any] = {"inode": inode, "offset": offset}
    if "discardUntilNewline" in value:
        if value.get("discardUntilNewline") is not True:
            return None
        normalized["discardUntilNewline"] = True
    return normalized


def normalized_bounded_number(value: Any, minimum: float, maximum: float) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = finite_number(value)
    if parsed is None or not minimum <= parsed <= maximum:
        return None
    return value


def existing_incident_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    required = {
        "id", "startedAt", "observedAt", "endedAt", "phase", "reasons", "metrics",
        "pressure", "processes", "containers", "traffic", "peaks", "durationSeconds",
    }
    if set(record) != required:
        return None
    incident_id = record.get("id")
    if not isinstance(incident_id, str) or re.fullmatch(r"incident-[0-9]{8}T[0-9]{6}Z", incident_id) is None:
        return None
    started = parse_iso_timestamp(record.get("startedAt"))
    observed = parse_iso_timestamp(record.get("observedAt"))
    ended = parse_iso_timestamp(record.get("endedAt")) if record.get("endedAt") is not None else None
    phase = record.get("phase")
    if started is None or observed is None or started > observed or phase not in INCIDENT_PHASES:
        return None
    if phase == "recovered":
        if ended is None or ended < started or ended != observed:
            return None
    elif ended is not None:
        return None
    raw_reasons = record.get("reasons")
    if (
        not isinstance(raw_reasons, list)
        or not raw_reasons
        or len(raw_reasons) > len(INCIDENT_REASONS)
        or not all(isinstance(reason, str) for reason in raw_reasons)
    ):
        return None
    reasons = [reason for reason in INCIDENT_REASONS if reason in raw_reasons]
    if len(reasons) != len(raw_reasons) or len(set(raw_reasons)) != len(raw_reasons):
        return None

    raw_metrics = record.get("metrics")
    if not isinstance(raw_metrics, Mapping):
        return None
    metrics = existing_sample_record(raw_metrics)
    observed_text = iso_timestamp(observed)
    if metrics is None or metrics["timestamp"] != observed_text:
        return None
    metric_bounds = {
        "cpuPercent": (0, 100), "memoryPercent": (0, 100),
        "memoryUsedBytes": (0, 1 << 60), "memoryTotalBytes": (0, 1 << 60),
        "temperatureC": (-100, 250), "load1": (0, 1_000_000),
        "load5": (0, 1_000_000), "load15": (0, 1_000_000),
        "gpuMemoryBytes": (0, 1 << 60), "gpuClockHz": (0, 1_000_000_000_000),
        "networkRxBytesPerSecond": (0, 1_000_000_000_000),
        "networkTxBytesPerSecond": (0, 1_000_000_000_000),
        "diskReadBytesPerSecond": (0, 1_000_000_000_000),
        "diskWriteBytesPerSecond": (0, 1_000_000_000_000),
    }
    for field_name, bounds in metric_bounds.items():
        value = metrics[field_name]
        if value is not None and normalized_bounded_number(value, *bounds) is None:
            return None
    if (
        metrics["memoryUsedBytes"] is not None
        and metrics["memoryTotalBytes"] is not None
        and metrics["memoryUsedBytes"] > metrics["memoryTotalBytes"]
    ):
        return None

    raw_pressure = record.get("pressure")
    if not isinstance(raw_pressure, Mapping) or set(raw_pressure) != {"cpu", "memory", "io"}:
        return None
    pressure: dict[str, dict[str, float | None]] = {}
    for kind in ("cpu", "memory", "io"):
        values = raw_pressure.get(kind)
        if not isinstance(values, Mapping) or set(values) != {"someAvg10", "fullAvg10"}:
            return None
        normalized_values: dict[str, float | None] = {}
        for field_name in ("someAvg10", "fullAvg10"):
            value = values.get(field_name)
            if value is None:
                normalized_values[field_name] = None
                continue
            parsed = normalized_bounded_number(value, 0, 100)
            if parsed is None:
                return None
            normalized_values[field_name] = float(parsed)
        pressure[kind] = normalized_values

    raw_processes = record.get("processes")
    if not isinstance(raw_processes, list) or len(raw_processes) > MAX_PROCESS_GROUPS:
        return None
    processes: list[dict[str, Any]] = []
    process_names: set[str] = set()
    for value in raw_processes:
        if not isinstance(value, Mapping) or set(value) != {"name", "instances", "cpuPercent", "memoryBytes"}:
            return None
        if not isinstance(value.get("name"), str):
            return None
        name = safe_process_name(value.get("name"))
        if name in process_names:
            return None
        instances = value.get("instances")
        memory_bytes = value.get("memoryBytes")
        cpu_percent = value.get("cpuPercent")
        if isinstance(instances, bool) or not isinstance(instances, int) or not 1 <= instances <= 1_000_000:
            return None
        if isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or not 0 <= memory_bytes <= 1 << 60:
            return None
        if cpu_percent is not None:
            cpu_percent = normalized_bounded_number(cpu_percent, 0, 100)
            if cpu_percent is None:
                return None
        process_names.add(name)
        processes.append({
            "name": name, "instances": instances, "cpuPercent": cpu_percent, "memoryBytes": memory_bytes,
        })

    raw_containers = record.get("containers")
    if not isinstance(raw_containers, list) or len(raw_containers) > MAX_INCIDENT_CONTAINERS:
        return None
    containers: list[dict[str, Any]] = []
    for value in raw_containers:
        fields = {"name", "owner", "state", "health", "cpuPercent", "memoryBytes", "memoryPercent"}
        if not isinstance(value, Mapping) or set(value) != fields:
            return None
        name = bounded_text(value.get("name"), 128)
        owner = bounded_text(value.get("owner"), 32)
        state_value = bounded_text(value.get("state"), 24).lower()
        health = bounded_text(value.get("health"), 24).lower()
        if name not in SAFE_CONTAINER_NAMES:
            name = "cks-workload"
        if (
            owner != "cks"
            or state_value not in {"created", "running", "paused", "restarting", "removing", "exited", "dead", "unknown"}
            or health not in {"healthy", "unhealthy", "starting", "none", "unknown"}
        ):
            return None
        cpu_percent = value.get("cpuPercent")
        memory_percent = value.get("memoryPercent")
        memory_bytes = value.get("memoryBytes")
        if cpu_percent is not None and normalized_bounded_number(
            cpu_percent, 0, MAX_CONTAINER_CPU_PERCENT
        ) is None:
            return None
        if memory_percent is not None and normalized_bounded_number(memory_percent, 0, 100) is None:
            return None
        if memory_bytes is not None and (
            isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or not 0 <= memory_bytes <= 1 << 60
        ):
            return None
        containers.append({
            "name": name, "owner": owner, "state": state_value, "health": health,
            "cpuPercent": cpu_percent, "memoryBytes": memory_bytes, "memoryPercent": memory_percent,
        })

    raw_traffic = record.get("traffic")
    if not isinstance(raw_traffic, list) or len(raw_traffic) > MAX_TRAFFIC_APPS:
        return None
    traffic: list[dict[str, Any]] = []
    traffic_apps: set[str] = set()
    traffic_fields = {
        "app", "requestCount", "status2xx", "status3xx", "status4xx", "status5xx",
        "slowCount", "avgResponseMs", "maxResponseMs",
    }
    for value in raw_traffic:
        if not isinstance(value, Mapping) or set(value) != traffic_fields:
            return None
        app = value.get("app")
        if (
            not isinstance(app, str)
            or app not in ALLOWED_TRAFFIC_APPS
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", app) is None
        ):
            return None
        if app in traffic_apps:
            return None
        counts: dict[str, int] = {}
        for field_name in ("requestCount", "status2xx", "status3xx", "status4xx", "status5xx", "slowCount"):
            count = value.get(field_name)
            if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 1_000_000_000:
                return None
            counts[field_name] = count
        if counts["slowCount"] > counts["requestCount"] or sum(
            counts[field_name] for field_name in ("status2xx", "status3xx", "status4xx", "status5xx")
        ) > counts["requestCount"]:
            return None
        average = normalized_bounded_number(value.get("avgResponseMs"), 0, MAX_TRAFFIC_REQUEST_SECONDS * 1000)
        maximum = normalized_bounded_number(value.get("maxResponseMs"), 0, MAX_TRAFFIC_REQUEST_SECONDS * 1000)
        if average is None or maximum is None or average > maximum:
            return None
        traffic_apps.add(app)
        traffic.append({"app": app, **counts, "avgResponseMs": average, "maxResponseMs": maximum})

    raw_peaks = record.get("peaks")
    peaks: dict[str, float | int | None] | None = None
    if raw_peaks is not None:
        if not isinstance(raw_peaks, Mapping) or set(raw_peaks) != {
            "cpuPercent", "memoryPercent", "temperatureC", "load1",
        }:
            return None
        peak_bounds = {
            "cpuPercent": (0, 100), "memoryPercent": (0, 100),
            "temperatureC": (-100, 250), "load1": (0, 1_000_000),
        }
        peaks = {}
        for field_name, bounds in peak_bounds.items():
            value = raw_peaks.get(field_name)
            if value is None:
                peaks[field_name] = None
                continue
            parsed = normalized_bounded_number(value, *bounds)
            if parsed is None:
                return None
            peaks[field_name] = parsed

    duration = record.get("durationSeconds")
    if duration is not None and (
        isinstance(duration, bool) or not isinstance(duration, int) or not 0 <= duration <= 366 * 86400
    ):
        return None
    if phase == "recovered" and duration is None:
        return None
    if phase != "recovered" and duration is not None:
        return None
    if phase == "recovered" and duration != int((ended - started).total_seconds()):
        return None
    return {
        "id": incident_id,
        "startedAt": iso_timestamp(started),
        "observedAt": observed_text,
        "endedAt": iso_timestamp(ended) if ended else None,
        "phase": phase,
        "reasons": reasons,
        "metrics": metrics,
        "pressure": pressure,
        "processes": processes,
        "containers": containers,
        "traffic": traffic,
        "peaks": peaks,
        "durationSeconds": duration,
    }


def update_peaks(previous: Any, metrics: Mapping[str, Any]) -> dict[str, float | int | None]:
    result: dict[str, float | int | None] = {}
    for field_name in ("cpuPercent", "memoryPercent", "temperatureC", "load1"):
        current = metrics.get(field_name)
        prior = previous.get(field_name) if isinstance(previous, Mapping) else None
        values = [
            value for value in (prior, current)
            if not isinstance(value, bool) and isinstance(value, (int, float)) and finite_number(value) is not None
        ]
        result[field_name] = max(values) if values else None
    return result


def incident_transition(
    config: "Config",
    now: dt.datetime,
    metrics: Mapping[str, Any],
    pressure: Mapping[str, Any],
    processes: Sequence[Mapping[str, Any]],
    containers: Sequence[Mapping[str, Any]],
    traffic: Sequence[Mapping[str, Any]],
    previous_state: Any,
    traffic_available: bool = True,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    prior = previous_state if isinstance(previous_state, Mapping) else {}
    previous_reasons = {
        reason for reason in prior.get("activeReasons", [])
        if isinstance(reason, str) and reason in INCIDENT_REASONS
    } if isinstance(prior.get("activeReasons", []), list) else set()
    previous_all_reasons = {
        reason for reason in prior.get("allReasons", [])
        if isinstance(reason, str) and reason in INCIDENT_REASONS
    } if isinstance(prior.get("allReasons", []), list) else set()
    previous_id = prior.get("id")
    previous_started = parse_iso_timestamp(prior.get("startedAt"))
    if previous_reasons and (
        not isinstance(previous_id, str)
        or re.fullmatch(r"incident-[0-9]{8}T[0-9]{6}Z", previous_id) is None
        or previous_started is None
    ):
        prior = {}
        previous_reasons = set()
        previous_all_reasons = set()
        previous_id = None
        previous_started = None
    if not previous_reasons:
        previous_all_reasons = set()
        previous_id = None
        previous_started = None
    cpu_value = finite_number(metrics.get("cpuPercent"))
    cpu_streak = prior.get("cpuStreak", 0)
    if isinstance(cpu_streak, bool) or not isinstance(cpu_streak, int) or not 0 <= cpu_streak <= config.cpu_warn_samples:
        cpu_streak = 0
    if cpu_value is not None:
        if cpu_value >= config.cpu_warn_percent:
            cpu_streak = min(config.cpu_warn_samples, cpu_streak + 1)
        else:
            cpu_streak = 0

    current_reasons: set[str] = set()
    if "cpu" in previous_reasons:
        if cpu_value is None or cpu_value >= config.cpu_recover_percent:
            current_reasons.add("cpu")
    elif cpu_streak >= config.cpu_warn_samples:
        current_reasons.add("cpu")

    memory_percent = finite_number(metrics.get("memoryPercent"))
    memory_available = 100.0 - memory_percent if memory_percent is not None else None
    if "memory" in previous_reasons:
        if memory_available is None or memory_available < config.memory_available_recover_percent:
            current_reasons.add("memory")
    elif memory_available is not None and memory_available <= config.memory_available_warn_percent:
        current_reasons.add("memory")

    temperature = finite_number(metrics.get("temperatureC"))
    if "temperature" in previous_reasons:
        if temperature is None or temperature >= config.temperature_recover_c:
            current_reasons.add("temperature")
    elif temperature is not None and temperature >= config.temperature_warn_c:
        current_reasons.add("temperature")

    flags = uint32(metrics.get("throttledFlags"))
    if flags is None:
        if "power-throttle" in previous_reasons:
            current_reasons.add("power-throttle")
    elif flags & 0xF:
        current_reasons.add("power-throttle")

    load = finite_number(metrics.get("load1"))
    if "load" in previous_reasons:
        if load is None or load >= config.load_recover:
            current_reasons.add("load")
    elif load is not None and load >= config.load_warn:
        current_reasons.add("load")

    disk_read = finite_number(metrics.get("diskReadBytesPerSecond"))
    disk_write = finite_number(metrics.get("diskWriteBytesPerSecond"))
    disk_io = (
        max(0.0, disk_read) + max(0.0, disk_write)
        if disk_read is not None and disk_write is not None
        else None
    )
    if "disk-io" in previous_reasons:
        if disk_io is None or disk_io >= config.disk_io_recover_bytes_per_second:
            current_reasons.add("disk-io")
    elif disk_io is not None and disk_io >= config.disk_io_warn_bytes_per_second:
        current_reasons.add("disk-io")

    request_count = sum(
        value.get("requestCount", 0)
        for value in traffic
        if isinstance(value, Mapping) and isinstance(value.get("requestCount"), int)
        and not isinstance(value.get("requestCount"), bool)
    )
    if "traffic" in previous_reasons:
        if not traffic_available or request_count >= config.traffic_request_recover:
            current_reasons.add("traffic")
    elif traffic_available and request_count >= config.traffic_request_warn:
        current_reasons.add("traffic")

    observed_text = iso_timestamp(now)
    phase: str | None = None
    incident_id: str | None = previous_id if isinstance(previous_id, str) else None
    started = previous_started
    all_reasons = previous_all_reasons | previous_reasons | current_reasons
    follow_up_count = prior.get("followUpCount", 0)
    if isinstance(follow_up_count, bool) or not isinstance(follow_up_count, int) or follow_up_count < 0:
        follow_up_count = 0
    if not previous_reasons and current_reasons:
        phase = "active"
        incident_id = f"incident-{now.astimezone(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        started = now.astimezone(dt.timezone.utc)
        all_reasons = set(current_reasons)
        follow_up_count = 0
    elif previous_reasons and current_reasons:
        if current_reasons - previous_reasons:
            phase = "active"
        elif follow_up_count < config.incident_follow_up_samples:
            phase = "follow-up"
            follow_up_count += 1
    elif previous_reasons and not current_reasons:
        phase = "recovered"

    peaks = update_peaks(
        prior.get("peaks") if previous_reasons else None, metrics
    ) if previous_reasons or current_reasons else None
    record: dict[str, Any] | None = None
    if phase is not None and incident_id is not None and started is not None:
        ended = observed_text if phase == "recovered" else None
        duration = max(0, int((now - started).total_seconds())) if phase == "recovered" else None
        normalized_metrics = dict(metrics)
        normalized_metrics["timestamp"] = observed_text
        record = {
            "id": incident_id,
            "startedAt": iso_timestamp(started),
            "observedAt": observed_text,
            "endedAt": ended,
            "phase": phase,
            "reasons": [reason for reason in INCIDENT_REASONS if reason in all_reasons],
            "metrics": normalized_metrics,
            "pressure": dict(pressure),
            "processes": [dict(value) for value in processes],
            "containers": [
                dict(value) for value in sorted(
                    containers,
                    key=lambda value: (
                        0 if str(value.get("health", "")).lower() not in {"healthy", "none"} else 1,
                        -float(finite_number(value.get("cpuPercent"), 0.0) or 0.0),
                        -int(finite_number(value.get("memoryBytes"), 0.0) or 0),
                        str(value.get("name", "")),
                    ),
                )[:MAX_INCIDENT_CONTAINERS]
            ],
            "traffic": [dict(value) for value in traffic],
            "peaks": peaks,
            "durationSeconds": duration,
        }

    next_state: dict[str, Any] = {
        "activeReasons": [reason for reason in INCIDENT_REASONS if reason in current_reasons],
        "allReasons": [reason for reason in INCIDENT_REASONS if reason in all_reasons] if current_reasons else [],
        "cpuStreak": cpu_streak,
        "id": incident_id if current_reasons else None,
        "startedAt": iso_timestamp(started) if current_reasons and started else None,
        "followUpCount": follow_up_count if current_reasons else 0,
        "peaks": peaks if current_reasons else None,
    }
    return record, next_state


def persist_incidents(config: "Config", now: dt.datetime, record: Mapping[str, Any] | None) -> None:
    path = config.output_dir / "incidents.jsonl"
    if record is None and not path.exists():
        return
    if record is None:
        try:
            age_seconds = now.timestamp() - path.stat(follow_symlinks=False).st_mtime
        except OSError:
            age_seconds = 86_400
        # With no new capture, compact at most daily. This still advances the
        # calendar retention boundary without rewriting up to 16 MiB per minute.
        if -86_400 <= age_seconds < 86_400:
            return
    cutoff = now - dt.timedelta(days=config.incident_retention_days)
    records_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for value in existing_json_lines(
        path,
        config.max_incident_records,
        MAX_INCIDENT_FILE_BYTES,
        MAX_INCIDENT_LINE_BYTES,
    ):
        normalized = existing_incident_record(value)
        if normalized is None:
            continue
        observed = parse_iso_timestamp(normalized["observedAt"])
        if observed is not None and cutoff <= observed <= now + dt.timedelta(seconds=60):
            key = (normalized["id"], normalized["observedAt"], normalized["phase"])
            records_by_key[key] = normalized
    if record is not None:
        normalized = existing_incident_record(record)
        if normalized is None:
            raise ValueError("generated incident did not satisfy the public contract")
        encoded = (
            json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode()
        if len(encoded) > MAX_INCIDENT_LINE_BYTES:
            raise ValueError("generated incident exceeded the public record byte limit")
        key = (normalized["id"], normalized["observedAt"], normalized["phase"])
        records_by_key[key] = normalized
    records = sorted(
        records_by_key.values(),
        key=lambda value: (value["observedAt"], value["id"], value["phase"]),
    )
    rewrite_incident_lines(path, records, config.max_incident_records)


def existing_incident_lifecycle_state(value: Any) -> dict[str, Any] | None:
    """Validate the bounded durable state used to continue an incident after reboot."""
    required = {
        "activeReasons", "allReasons", "cpuStreak", "id", "startedAt",
        "followUpCount", "peaks",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        return None

    def reasons(raw: Any) -> list[str] | None:
        if (
            not isinstance(raw, list)
            or len(raw) > len(INCIDENT_REASONS)
            or not all(isinstance(reason, str) for reason in raw)
        ):
            return None
        normalized = [reason for reason in INCIDENT_REASONS if reason in raw]
        if normalized != raw or len(set(raw)) != len(raw):
            return None
        return normalized

    active_reasons = reasons(value.get("activeReasons"))
    all_reasons = reasons(value.get("allReasons"))
    if active_reasons is None or all_reasons is None:
        return None
    cpu_streak = value.get("cpuStreak")
    follow_up_count = value.get("followUpCount")
    if (
        isinstance(cpu_streak, bool)
        or not isinstance(cpu_streak, int)
        or not 0 <= cpu_streak <= 60
        or isinstance(follow_up_count, bool)
        or not isinstance(follow_up_count, int)
        or not 0 <= follow_up_count <= 60
    ):
        return None

    incident_id = value.get("id")
    started = parse_iso_timestamp(value.get("startedAt")) if value.get("startedAt") is not None else None
    raw_peaks = value.get("peaks")
    peaks: dict[str, float | int | None] | None = None
    if raw_peaks is not None:
        if not isinstance(raw_peaks, Mapping) or set(raw_peaks) != {
            "cpuPercent", "memoryPercent", "temperatureC", "load1",
        }:
            return None
        peak_bounds = {
            "cpuPercent": (0, 100), "memoryPercent": (0, 100),
            "temperatureC": (-100, 250), "load1": (0, 1_000_000),
        }
        peaks = {}
        for field_name, bounds in peak_bounds.items():
            metric = raw_peaks.get(field_name)
            if metric is None:
                peaks[field_name] = None
                continue
            normalized_metric = normalized_bounded_number(metric, *bounds)
            if normalized_metric is None:
                return None
            peaks[field_name] = normalized_metric

    if active_reasons:
        if (
            not isinstance(incident_id, str)
            or re.fullmatch(r"incident-[0-9]{8}T[0-9]{6}Z", incident_id) is None
            or started is None
            or not all_reasons
            or not set(active_reasons).issubset(all_reasons)
            or peaks is None
        ):
            return None
    elif (
        incident_id is not None
        or started is not None
        or all_reasons
        or follow_up_count != 0
        or peaks is not None
    ):
        return None

    return {
        "activeReasons": active_reasons,
        "allReasons": all_reasons,
        "cpuStreak": cpu_streak,
        "id": incident_id,
        "startedAt": iso_timestamp(started) if started is not None else None,
        "followUpCount": follow_up_count,
        "peaks": peaks,
    }


def normalized_pending_incident_commit(value: Any) -> dict[str, Any] | None:
    """Admit only generated, already-redacted data to the private crash journal."""
    version = value.get("version") if isinstance(value, Mapping) else None
    if not isinstance(value, Mapping) or set(value) != {
        "version", "record", "lifecycle", "trafficCursor",
    } or isinstance(version, bool) or not isinstance(version, int) or version != 1:
        return None

    raw_record = value.get("record")
    record: dict[str, Any] | None = None
    if raw_record is not None:
        if not isinstance(raw_record, Mapping):
            return None
        record = existing_incident_record(raw_record)
        if record is None:
            return None
        record_size = len((
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode())
        if record_size > MAX_INCIDENT_LINE_BYTES:
            return None

    lifecycle = existing_incident_lifecycle_state(value.get("lifecycle"))
    if lifecycle is None:
        return None
    raw_cursor = value.get("trafficCursor")
    traffic_cursor: dict[str, Any] | None = None
    if raw_cursor is not None:
        traffic_cursor = existing_traffic_cursor(raw_cursor)
        if traffic_cursor is None:
            return None

    # Bind a capture to its resulting lifecycle. A cursor-only commit remains
    # valid when follow-up sampling is intentionally suppressed.
    if record is not None:
        if record["phase"] == "recovered":
            if lifecycle["activeReasons"]:
                return None
        elif (
            lifecycle["id"] != record["id"]
            or lifecycle["startedAt"] != record["startedAt"]
            or lifecycle["allReasons"] != record["reasons"]
            or not set(lifecycle["activeReasons"]).issubset(record["reasons"])
        ):
            return None

    normalized = {
        "version": 1,
        "record": record,
        "lifecycle": lifecycle,
        "trafficCursor": traffic_cursor,
    }
    encoded = (
        json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    return normalized if len(encoded) <= MAX_PENDING_INCIDENT_COMMIT_BYTES else None


def discard_pending_incident_commit(path: Path) -> bool:
    """Unlink one exact journal path and durably record the removal."""
    try:
        path.unlink()
    except FileNotFoundError:
        return True
    except IsADirectoryError:
        # Never recurse through an unexpected filesystem object.
        return False
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return True


def load_pending_incident_commit(path: Path) -> dict[str, Any] | None:
    """Read one private journal without following links or accepting partial data."""
    decoded = load_private_pending_json(path, MAX_PENDING_INCIDENT_COMMIT_BYTES)
    if decoded is None:
        return None
    normalized = normalized_pending_incident_commit(decoded)
    if normalized is None:
        raise PendingJournalError("pending incident journal failed schema validation")
    return normalized


def write_pending_incident_commit(
    config: "Config",
    record: Mapping[str, Any] | None,
    lifecycle: Mapping[str, Any],
    traffic_cursor: Mapping[str, Any] | None,
) -> Path:
    path = config.output_dir / ".state" / "pending-incident-commit.json"
    require_pending_journal_absent(path)
    normalized = normalized_pending_incident_commit({
        "version": 1,
        "record": dict(record) if record is not None else None,
        "lifecycle": dict(lifecycle),
        "trafficCursor": dict(traffic_cursor) if traffic_cursor is not None else None,
    })
    if normalized is None:
        raise ValueError("pending incident commit did not satisfy the private state contract")
    atomic_create_json(path, normalized, MAX_PENDING_INCIDENT_COMMIT_BYTES, 0o600)
    return path


def replay_pending_incident_commit(config: "Config", now: dt.datetime) -> bool:
    """Idempotently finish a staged incident/lifecycle/traffic transaction."""
    path = config.output_dir / ".state" / "pending-incident-commit.json"
    pending = load_pending_incident_commit(path)
    if pending is None:
        return False
    persist_incidents(config, now, pending["record"])
    atomic_write_json(
        config.output_dir / ".state" / "incident-lifecycle.json",
        pending["lifecycle"],
        0o600,
    )
    commit_traffic_cursor(config, pending["trafficCursor"])
    if not discard_pending_incident_commit(path):
        raise OSError("pending incident commit could not be removed")
    return True


SANITIZED_LOG_FIELDS: dict[str, tuple[str, ...]] = {
    "alerts": ("timestamp", "severity", "kind", "status", "message"),
    "power": ("timestamp", "severity", "kind", "status", "message"),
    "privilege": ("timestamp", "actor", "target", "action", "result"),
}


def canonical_sanitized_log_record(kind: str, value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or kind not in SANITIZED_LOG_FIELDS:
        return None
    if set(value) != set(SANITIZED_LOG_FIELDS[kind]):
        return None
    validator = {
        "alerts": existing_alert_record,
        "power": existing_power_record,
        "privilege": existing_privilege_record,
    }[kind]
    normalized = validator(value)
    if normalized is None or normalized != dict(value):
        return None
    encoded = (json.dumps(
        normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ) + "\n").encode()
    return normalized if len(encoded) <= MAX_SANITIZED_LOG_RECORD_BYTES else None


def load_sanitized_log_records(
    config: "Config", kind: str, limit: int
) -> list[dict[str, Any]]:
    path = config.output_dir / f"{kind}.jsonl"
    records: list[dict[str, Any]] = []
    for value in existing_json_lines(path, limit):
        normalized = canonical_sanitized_log_record(kind, value)
        if normalized is not None:
            records.append(normalized)
    return records[-limit:]


def merge_sanitized_log_records(
    kind: str,
    existing: Sequence[Mapping[str, Any]],
    new_records: Sequence[Mapping[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    merged = [dict(record) for record in (*existing, *new_records)]
    if kind == "power":
        # Kernel power rows are fixed semantic events whose timestamps are
        # normalized to one second; their established burst collapse remains.
        merged = [dict(record) for record in deduplicate_power_records(merged)]
    return merged[-limit:]


def sanitized_log_records_digest(records: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update((json.dumps(
            record, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ) + "\n").encode())
    return digest.hexdigest()


def normalized_sanitized_log_cursors(config: "Config", value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "alerts", "kernelPower", "privilege", "powerFlags",
    }:
        return None
    alerts = existing_traffic_cursor(value.get("alerts"))
    kernel_power = existing_traffic_cursor(value.get("kernelPower"))
    if alerts is None or kernel_power is None:
        return None
    raw_privilege = value.get("privilege")
    expected_privilege = {str(path) for path in config.privilege_logs}
    if (
        not isinstance(raw_privilege, Mapping)
        or len(expected_privilege) > 32
        or set(raw_privilege) != expected_privilege
    ):
        return None
    privilege: dict[str, dict[str, Any]] = {}
    for key in sorted(expected_privilege):
        if len(key) > 4096:
            return None
        cursor = existing_traffic_cursor(raw_privilege.get(key))
        if cursor is None:
            return None
        privilege[key] = cursor
    raw_flags = value.get("powerFlags")
    power_flags = None if raw_flags is None else uint32(raw_flags)
    if raw_flags is not None and power_flags is None:
        return None
    return {
        "alerts": alerts,
        "kernelPower": kernel_power,
        "privilege": privilege,
        "powerFlags": power_flags,
    }


def normalized_pending_sanitized_log_commit(
    config: "Config", value: Any
) -> dict[str, Any] | None:
    version = value.get("version") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, Mapping)
        or set(value) != {"version", "outputs", "cursors"}
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version != 1
    ):
        return None
    raw_outputs = value.get("outputs")
    if not isinstance(raw_outputs, Mapping) or set(raw_outputs) != set(SANITIZED_LOG_FIELDS):
        return None
    outputs: dict[str, dict[str, Any]] = {}
    for kind in SANITIZED_LOG_FIELDS:
        raw = raw_outputs.get(kind)
        if not isinstance(raw, Mapping) or set(raw) != {
            "baseDigest", "baseCount", "finalDigest", "finalCount", "limit", "rows",
        }:
            return None
        limit = raw.get("limit")
        base_count = raw.get("baseCount")
        final_count = raw.get("finalCount")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 10 <= limit <= 100_000
            or isinstance(base_count, bool)
            or not isinstance(base_count, int)
            or not 0 <= base_count <= limit
            or isinstance(final_count, bool)
            or not isinstance(final_count, int)
            or not 0 <= final_count <= limit
        ):
            return None
        base_digest = raw.get("baseDigest")
        final_digest = raw.get("finalDigest")
        if (
            not isinstance(base_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", base_digest) is None
            or not isinstance(final_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", final_digest) is None
        ):
            return None
        raw_rows = raw.get("rows")
        if not isinstance(raw_rows, list) or len(raw_rows) > limit:
            return None
        rows: list[dict[str, Any]] = []
        for row in raw_rows:
            normalized = canonical_sanitized_log_record(kind, row)
            if normalized is None:
                return None
            rows.append(normalized)
        outputs[kind] = {
            "baseDigest": base_digest,
            "baseCount": base_count,
            "finalDigest": final_digest,
            "finalCount": final_count,
            "limit": limit,
            "rows": rows,
        }
    cursors = normalized_sanitized_log_cursors(config, value.get("cursors"))
    if cursors is None:
        return None
    normalized = {"version": 1, "outputs": outputs, "cursors": cursors}
    encoded = (json.dumps(
        normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ) + "\n").encode()
    return normalized if len(encoded) <= MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES else None


def write_pending_sanitized_log_commit(
    config: "Config",
    new_records: Mapping[str, Sequence[Mapping[str, Any]]],
    cursors: Mapping[str, Any],
) -> Path:
    path = config.output_dir / ".state" / "pending-sanitized-log-commit.json"
    require_pending_journal_absent(path)
    outputs: dict[str, dict[str, Any]] = {}
    limit = config.max_log_records
    for kind in SANITIZED_LOG_FIELDS:
        base = load_sanitized_log_records(config, kind, limit)
        rows: list[dict[str, Any]] = []
        raw_rows = new_records.get(kind)
        if not isinstance(raw_rows, Sequence) or isinstance(raw_rows, (str, bytes, bytearray)):
            raise ValueError("sanitized log batch did not satisfy the private state contract")
        candidates = raw_rows if kind == "power" else raw_rows[-limit:]
        for raw in candidates:
            normalized = canonical_sanitized_log_record(kind, raw)
            if normalized is None:
                raise ValueError("sanitized log row did not satisfy the public contract")
            rows.append(normalized)
        if kind == "power":
            rows = [dict(row) for row in deduplicate_power_records(rows)][-limit:]
        final = merge_sanitized_log_records(kind, base, rows, limit)
        outputs[kind] = {
            "baseDigest": sanitized_log_records_digest(base),
            "baseCount": len(base),
            "finalDigest": sanitized_log_records_digest(final),
            "finalCount": len(final),
            "limit": limit,
            "rows": rows,
        }
    normalized = normalized_pending_sanitized_log_commit(config, {
        "version": 1, "outputs": outputs, "cursors": dict(cursors),
    })
    if normalized is None:
        raise ValueError("pending sanitized log commit did not satisfy the private state contract")
    atomic_create_json(path, normalized, MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES, 0o600)
    return path


def load_pending_sanitized_log_commit(
    config: "Config", path: Path
) -> dict[str, Any] | None:
    decoded = load_private_pending_json(path, MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES)
    if decoded is None:
        return None
    normalized = normalized_pending_sanitized_log_commit(config, decoded)
    if normalized is None:
        raise PendingJournalError("pending sanitized log journal failed schema validation")
    return normalized


def discard_pending_sanitized_log_commit(path: Path) -> bool:
    return discard_pending_incident_commit(path)


def replay_pending_sanitized_log_commit(config: "Config") -> bool:
    path = config.output_dir / ".state" / "pending-sanitized-log-commit.json"
    pending = load_pending_sanitized_log_commit(config, path)
    if pending is None:
        return False
    for kind in SANITIZED_LOG_FIELDS:
        output = pending["outputs"][kind]
        limit = output["limit"]
        output_path = config.output_dir / f"{kind}.jsonl"
        current = load_sanitized_log_records(config, kind, limit)
        current_digest = sanitized_log_records_digest(current)
        current_count = len(current)
        final_matches = (
            current_digest == output["finalDigest"]
            and current_count == output["finalCount"]
            and output_path.is_file()
        )
        if not final_matches:
            base_matches = (
                current_digest == output["baseDigest"]
                and current_count == output["baseCount"]
            )
            if not base_matches:
                raise PendingJournalError("sanitized log output diverged from pending transaction")
            final = merge_sanitized_log_records(kind, current, output["rows"], limit)
            if (
                sanitized_log_records_digest(final) != output["finalDigest"]
                or len(final) != output["finalCount"]
            ):
                raise PendingJournalError("sanitized log pending digest validation failed")
            rewrite_json_lines(output_path, final, limit)
            saved = load_sanitized_log_records(config, kind, limit)
            if (
                sanitized_log_records_digest(saved) != output["finalDigest"]
                or len(saved) != output["finalCount"]
            ):
                raise PendingJournalError("sanitized log output verification failed")
    atomic_write_json(
        config.output_dir / ".state" / "log-cursors.json",
        pending["cursors"],
        0o600,
    )
    if not discard_pending_sanitized_log_commit(path):
        raise OSError("pending sanitized log commit could not be removed")
    return True


def export_sanitized_logs(config: "Config", now_text: str, gpu: Mapping[str, Any] | None = None) -> None:
    # Direct callers receive the same ordering guarantee as run(): a staged
    # batch is completed before any raw source or current GPU state is sampled.
    replay_pending_sanitized_log_commit(config)
    cursor_path = config.output_dir / ".state" / "log-cursors.json"
    cursors = load_json(cursor_path)
    new_alert_records: list[dict[str, Any]] = []

    lines, cursor = read_new_lines(config.events_log, cursors.get("alerts", {}), config.max_input_bytes)
    for line in lines:
        sanitized = sanitize_alert_line(line, now_text)
        if sanitized:
            new_alert_records.append(sanitized)
    next_alert_cursor = cursor

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
            new_alert_records.append({
                "timestamp": now_text,
                "severity": "warning",
                "kind": "power",
                "status": "active",
                "message": f"Current vcgencmd throttle flags are 0x{active_flags:x}." + detail,
            })
        elif not active_flags and previous_flags not in {None, 0}:
            new_alert_records.append({
                "timestamp": now_text,
                "severity": "info",
                "kind": "power",
                "status": "recovered",
                "message": "Current vcgencmd throttle condition recovered." + detail,
            })
    next_power_flags = active_flags if flags is not None else uint32(cursors.get("powerFlags"))

    new_power_records: list[dict[str, Any]] = []
    kernel_cursor = cursors.get("kernelPower", {})
    if not isinstance(kernel_cursor, Mapping):
        kernel_cursor = {}
    lines, cursor = read_new_lines(config.kernel_log, kernel_cursor, config.kernel_max_input_bytes)
    for line in lines:
        sanitized = sanitize_kernel_power_line(line, now_text)
        if sanitized:
            new_power_records.append(sanitized)
    next_kernel_cursor = cursor

    new_privilege_records: list[dict[str, Any]] = []
    privilege_cursors = cursors.get("privilege", {}) if isinstance(cursors.get("privilege"), dict) else {}
    next_privilege: dict[str, Any] = {}
    for path in config.privilege_logs:
        key = str(path)
        lines, cursor = read_new_lines(path, privilege_cursors.get(key, {}), config.max_input_bytes)
        for line in lines:
            sanitized = sanitize_privilege_line(line, now_text)
            if sanitized:
                new_privilege_records.append(sanitized)
        next_privilege[key] = cursor
    next_cursors = {
        "alerts": next_alert_cursor,
        "kernelPower": next_kernel_cursor,
        "privilege": next_privilege,
        "powerFlags": next_power_flags,
    }
    write_pending_sanitized_log_commit(config, {
        "alerts": new_alert_records,
        "power": new_power_records,
        "privilege": new_privilege_records,
    }, next_cursors)
    replay_pending_sanitized_log_commit(config)


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
        if owner.strip() == "cks" and path.strip() == DEFAULT_SOCKETS["cks"]:
            result["cks"] = Path(DEFAULT_SOCKETS["cks"])
    return result


def parse_uid_set(value: str) -> set[int]:
    result: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if item.isdigit():
            parsed = int(item)
            if parsed in ALLOWED_PROCESS_UIDS:
                result.add(parsed)
        if len(result) >= 32:
            break
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
    traffic_log: Path | None = Path("/var/log/nginx/monitor-traffic.jsonl")
    container_input: Path | None = None
    docker_sockets: dict[str, Path] = field(
        default_factory=lambda: {key: Path(value) for key, value in DEFAULT_SOCKETS.items()}
    )
    process_uids: set[int] = field(default_factory=lambda: {0, 1001})
    curl: str = "/usr/bin/curl"
    vcgencmd: str = "/usr/bin/vcgencmd"
    command_timeout: float = 2.0
    retention_days: int = 30
    max_log_records: int = 5000
    incident_retention_days: int = 30
    max_incident_records: int = 1000
    incident_follow_up_samples: int = 5
    cpu_warn_percent: float = 85.0
    cpu_recover_percent: float = 75.0
    cpu_warn_samples: int = 1
    memory_available_warn_percent: float = 20.0
    memory_available_recover_percent: float = 25.0
    temperature_warn_c: float = 75.0
    temperature_recover_c: float = 72.0
    load_warn: float = 4.0
    load_recover: float = 2.0
    disk_io_warn_bytes_per_second: float = 100 * 1024 * 1024
    disk_io_recover_bytes_per_second: float = 50 * 1024 * 1024
    traffic_request_warn: int = 300
    traffic_request_recover: int = 200
    traffic_slow_seconds: float = 1.0
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
    parser.add_argument(
        "--traffic-log",
        default=env.get("MONITOR_TRAFFIC_LOG", "/var/log/nginx/monitor-traffic.jsonl"),
    )
    parser.add_argument("--container-input", default=env.get("MONITOR_CONTAINER_INPUT", ""))
    parser.add_argument("--docker-sockets", default=env.get(
        "MONITOR_DOCKER_SOCKETS", ",".join(f"{owner}={path}" for owner, path in DEFAULT_SOCKETS.items())
    ))
    parser.add_argument("--process-uids", default=env.get("MONITOR_PROCESS_UIDS", "0,1001"))
    parser.add_argument("--curl", default=env.get("MONITOR_CURL", "/usr/bin/curl"))
    parser.add_argument("--vcgencmd", default=env.get("MONITOR_VCGENCMD", "/usr/bin/vcgencmd"))
    parser.add_argument("--command-timeout", type=float, default=float(env.get("MONITOR_COMMAND_TIMEOUT", "2")))
    parser.add_argument("--retention-days", type=int, default=int(env.get("MONITOR_RETENTION_DAYS", "30")))
    parser.add_argument("--max-log-records", type=int, default=int(env.get("MONITOR_MAX_LOG_RECORDS", "5000")))
    parser.add_argument(
        "--incident-retention-days",
        type=int,
        default=int(env.get("MONITOR_INCIDENT_RETENTION_DAYS", "30")),
    )
    parser.add_argument(
        "--max-incident-records",
        type=int,
        default=int(env.get("MONITOR_MAX_INCIDENT_RECORDS", "1000")),
    )
    parser.add_argument(
        "--incident-follow-up-samples",
        type=int,
        default=int(env.get("MONITOR_INCIDENT_FOLLOW_UP_SAMPLES", "5")),
    )
    parser.add_argument("--cpu-warn-percent", type=float, default=float(env.get("MONITOR_CPU_WARN_PERCENT", "85")))
    parser.add_argument("--cpu-recover-percent", type=float, default=float(env.get("MONITOR_CPU_RECOVER_PERCENT", "75")))
    parser.add_argument("--cpu-warn-samples", type=int, default=int(env.get("MONITOR_CPU_WARN_SAMPLES", "1")))
    parser.add_argument(
        "--memory-available-warn-percent",
        type=float,
        default=float(env.get("MONITOR_MEMORY_AVAILABLE_WARN_PERCENT", "20")),
    )
    parser.add_argument(
        "--memory-available-recover-percent",
        type=float,
        default=float(env.get("MONITOR_MEMORY_AVAILABLE_RECOVER_PERCENT", "25")),
    )
    parser.add_argument("--temperature-warn-c", type=float, default=float(env.get("MONITOR_TEMPERATURE_WARN_C", "75")))
    parser.add_argument("--temperature-recover-c", type=float, default=float(env.get("MONITOR_TEMPERATURE_RECOVER_C", "72")))
    parser.add_argument("--load-warn", type=float, default=float(env.get("MONITOR_LOAD_WARN", "4")))
    parser.add_argument("--load-recover", type=float, default=float(env.get("MONITOR_LOAD_RECOVER", "2")))
    parser.add_argument(
        "--disk-io-warn-bytes-per-second",
        type=float,
        default=float(env.get("MONITOR_DISK_IO_WARN_BYTES_PER_SECOND", str(100 * 1024 * 1024))),
    )
    parser.add_argument(
        "--disk-io-recover-bytes-per-second",
        type=float,
        default=float(env.get("MONITOR_DISK_IO_RECOVER_BYTES_PER_SECOND", str(50 * 1024 * 1024))),
    )
    parser.add_argument("--traffic-request-warn", type=int, default=int(env.get("MONITOR_TRAFFIC_REQUEST_WARN", "300")))
    parser.add_argument("--traffic-request-recover", type=int, default=int(env.get("MONITOR_TRAFFIC_REQUEST_RECOVER", "200")))
    parser.add_argument("--traffic-slow-seconds", type=float, default=float(env.get("MONITOR_TRAFFIC_SLOW_SECONDS", "1")))
    parser.add_argument("--max-input-bytes", type=int, default=int(env.get("MONITOR_MAX_INPUT_BYTES", "1048576")))
    parser.add_argument(
        "--kernel-max-input-bytes",
        type=int,
        default=int(env.get("MONITOR_KERNEL_MAX_INPUT_BYTES", str(DEFAULT_KERNEL_MAX_INPUT_BYTES))),
    )
    values = parser.parse_args(arguments)
    cpu_warn = max(0.0, min(100.0, values.cpu_warn_percent))
    memory_warn = max(0.0, min(100.0, values.memory_available_warn_percent))
    temperature_warn = max(-30.0, min(150.0, values.temperature_warn_c))
    load_warn = max(0.0, min(1_000_000.0, values.load_warn))
    disk_io_warn = max(1.0, min(1_000_000_000_000.0, values.disk_io_warn_bytes_per_second))
    traffic_warn = max(1, min(1_000_000, values.traffic_request_warn))
    return Config(
        output_dir=Path(values.output_dir), runtime_dir=Path(values.runtime_dir),
        proc_root=Path(values.proc_root), sys_root=Path(values.sys_root), etc_root=Path(values.etc_root),
        mountinfo=Path(values.mountinfo) if values.mountinfo else None,
        mount_root=Path(values.mount_root) if values.mount_root else None,
        events_log=Path(values.events_log), kernel_log=Path(values.kernel_log),
        privilege_logs=[Path(item) for item in values.privilege_logs.split(":") if item],
        traffic_log=Path(values.traffic_log) if values.traffic_log else None,
        container_input=Path(values.container_input) if values.container_input else None,
        docker_sockets=parse_socket_map(values.docker_sockets),
        process_uids=parse_uid_set(values.process_uids),
        curl=values.curl, vcgencmd=values.vcgencmd,
        command_timeout=max(0.1, min(10.0, values.command_timeout)),
        retention_days=max(1, min(366, values.retention_days)),
        max_log_records=max(10, min(100_000, values.max_log_records)),
        incident_retention_days=max(1, min(366, values.incident_retention_days)),
        max_incident_records=max(10, min(100_000, values.max_incident_records)),
        incident_follow_up_samples=max(0, min(60, values.incident_follow_up_samples)),
        cpu_warn_percent=cpu_warn,
        cpu_recover_percent=max(0.0, min(cpu_warn, values.cpu_recover_percent)),
        cpu_warn_samples=max(1, min(60, values.cpu_warn_samples)),
        memory_available_warn_percent=memory_warn,
        memory_available_recover_percent=max(
            memory_warn, min(100.0, values.memory_available_recover_percent)
        ),
        temperature_warn_c=temperature_warn,
        temperature_recover_c=max(-30.0, min(temperature_warn, values.temperature_recover_c)),
        load_warn=load_warn,
        load_recover=max(0.0, min(load_warn, values.load_recover)),
        disk_io_warn_bytes_per_second=disk_io_warn,
        disk_io_recover_bytes_per_second=max(
            0.0, min(disk_io_warn, values.disk_io_recover_bytes_per_second)
        ),
        traffic_request_warn=traffic_warn,
        traffic_request_recover=max(1, min(traffic_warn, values.traffic_request_recover)),
        traffic_slow_seconds=max(0.001, min(MAX_TRAFFIC_REQUEST_SECONDS, values.traffic_slow_seconds)),
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
        # Finish a prior crash-safe commit before either durable/volatile
        # lifecycle state or the traffic cursor can influence this sample.
        replay_pending_incident_commit(config, now)
        replay_pending_sanitized_log_commit(config)
        delta_path = config.runtime_dir / "delta-state.json"
        prior = load_json(delta_path)
        incident_lifecycle_path = config.output_dir / ".state" / "incident-lifecycle.json"
        durable_incident_state = load_json(incident_lifecycle_path)
        previous_incident_state = durable_incident_state or prior.get("incident")
        monotonic = time.monotonic()
        elapsed = monotonic - (finite_number(prior.get("monotonic"), monotonic) or monotonic)

        cpu = parse_proc_stat(read_text(config.proc_root / "stat"))
        previous_cpu = prior.get("cpu")
        host_cpu_delta = 0
        if cpu is not None and isinstance(previous_cpu, list) and len(previous_cpu) == 2:
            try:
                host_cpu_delta = max(0, cpu[0] - int(previous_cpu[0]))
            except (TypeError, ValueError):
                host_cpu_delta = 0
        memory_total, memory_available = parse_meminfo(read_text(config.proc_root / "meminfo"))
        network = parse_net_dev(read_text(config.proc_root / "net" / "dev"))
        disk = parse_diskstats(read_text(config.proc_root / "diskstats"))
        network_rates = rate_pair(network, prior.get("network"), elapsed)
        disk_rates = rate_pair(disk, prior.get("disk"), elapsed)
        temperature = read_temperature(config.sys_root)
        pressure = collect_pressure(config.proc_root)
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
            "memoryPercent": round(
                100.0 * (memory_total - memory_available) / memory_total, 2
            ) if memory_total is not None and memory_available is not None else None,
            "memoryUsedBytes": (
                memory_total - memory_available
                if memory_total is not None and memory_available is not None
                else None
            ),
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
        if config.container_input is not None:
            containers = load_container_snapshot(config.container_input, now)
            container_cpu_state: dict[str, dict[str, int]] = {}
        else:
            containers, container_cpu_state = collect_containers(
                config.docker_sockets, config.curl, config.command_timeout, prior.get("containers")
            )
        processes, process_cpu_state = collect_processes(
            config.proc_root, prior.get("processes"), host_cpu_delta, config.process_uids
        )
        traffic, traffic_cursor, traffic_available = collect_traffic(config, now)
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
        incident, incident_state = incident_transition(
            config,
            now,
            latest,
            pressure,
            processes,
            containers,
            traffic,
            previous_incident_state,
            traffic_available,
        )
        write_pending_incident_commit(config, incident, incident_state, traffic_cursor)
        replay_pending_incident_commit(config, now)
        export_sanitized_logs(config, now_text, gpu)
        atomic_write_json(delta_path, {
            "monotonic": monotonic,
            "cpu": list(cpu) if cpu else None,
            "network": list(network) if network is not None else None,
            "disk": list(disk) if disk is not None else None,
            "containers": container_cpu_state,
            "processes": process_cpu_state,
            "incident": incident_state,
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
