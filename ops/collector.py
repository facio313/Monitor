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
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from generic_log_collector import collect_generic_logs
from linux_telemetry import collect_linux_telemetry


DEFAULT_RULE_PACK_PATH = Path(__file__).resolve().parent / "rules" / "default-rules.v1.json"


POWER_SAMPLE_FIELDS = (
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
    field
    for field in POWER_SAMPLE_FIELDS
    if field not in {"supplyVoltageVolts", "throttledFlags"}
)
PREVIOUS_SAMPLE_FIELDS = (
    "timestamp",
    "cpuPercent",
    "memoryPercent",
    "memoryUsedBytes",
    "memoryTotalBytes",
    "swapTotalBytes",
    "swapUsedBytes",
    "swapPercent",
    "temperatureC",
    "load1",
    "load5",
    "load15",
    "cpuPressureSomeAvg10",
    "cpuPressureFullAvg10",
    "memoryPressureSomeAvg10",
    "memoryPressureFullAvg10",
    "ioPressureSomeAvg10",
    "ioPressureFullAvg10",
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
NETWORK_QUALITY_SAMPLE_FIELDS = (
    "networkRxErrorsPerSecond",
    "networkTxErrorsPerSecond",
    "networkRxDroppedPerSecond",
    "networkTxDroppedPerSecond",
)
SAMPLE_FIELDS = (
    *PREVIOUS_SAMPLE_FIELDS[:-2],
    *NETWORK_QUALITY_SAMPLE_FIELDS,
    *PREVIOUS_SAMPLE_FIELDS[-2:],
)
SAMPLE_FIELD_SCHEMAS = frozenset({
    frozenset(LEGACY_SAMPLE_FIELDS),
    frozenset(POWER_SAMPLE_FIELDS),
    frozenset(PREVIOUS_SAMPLE_FIELDS),
    frozenset(SAMPLE_FIELDS),
})
MAX_UINT32 = (1 << 32) - 1
MAX_SAFE_COUNTER = (1 << 53) - 1
MAX_SUPPLY_VOLTAGE_VOLTS = 10.0
DEFAULT_KERNEL_MAX_INPUT_BYTES = 8_388_608
MAX_KERNEL_BACKFILL_BYTES = 16_777_216
COLLECTOR_VERSION = "1.0.0"
CURRENT_SCHEMA_VERSION = 2
IDENTITY_STATE_SCHEMA_VERSION = 1
MAX_IDENTITY_STATE_BYTES = 4096
MAX_DELTA_STATE_BYTES = 8 * 1024 * 1024
MAX_HEARTBEAT_INTERVAL_SECONDS = 86_400
AGENT_LIFECYCLES = frozenset({"active", "maintenance", "inactive"})
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
MAX_CONTAINER_CPU_LIMIT_CORES = 1024.0
MAX_CONTAINER_MEMORY_LIMIT_BYTES = MAX_SAFE_COUNTER
MAX_CONTAINER_PID_LIMIT = MAX_SAFE_COUNTER
MAX_CONTAINER_IO_BYTES = MAX_SAFE_COUNTER
MAX_CONTAINER_IO_RATE = 1_000_000_000_000_000.0
MAX_CONTAINER_MOUNT_COUNT = 4_096
MAX_CONTAINER_PORT_COUNT = 65_536
MAX_CONTAINER_CAPABILITY_COUNT = 64
MAX_DOCKER_LIST_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_DOCKER_DETAIL_RESPONSE_BYTES = 256 * 1024
MAX_DOCKER_EVENT_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_DOCKER_INSPECT_REQUESTS = 30
MAX_DOCKER_STATS_REQUESTS = 30
MAX_DOCKER_DETAIL_WORKERS = 6
MAX_DOCKER_COLLECTION_SECONDS = 20.0
MAX_DOCKER_EVENTS = 128
MAX_DOCKER_EVENT_LINES = 512
MAX_DOCKER_EVENT_LINE_BYTES = 16 * 1024
MAX_DOCKER_EVENT_REPLAY_SECONDS = 10 * 60
LEGACY_CONTAINER_FIELDS = (
    "name", "owner", "state", "health", "cpuPercent", "memoryBytes", "memoryPercent",
)
CONTAINER_V2_FIELDS = (
    "name", "project", "owner", "state", "health", "healthcheckConfigured",
    "cpuPercent", "memoryBytes", "memoryPercent", "memoryLimitBytes", "cpuLimitCores",
    "pidLimit", "restartCount", "restartCountDelta", "oomKilled", "startedAt", "finishedAt",
)
CONTAINER_FIELDS = CONTAINER_V2_FIELDS + (
    "instanceId", "pidCount", "cpuThrottledPercent", "cpuThrottledPeriods",
    "cpuThrottledSeconds", "blockReadBytes", "blockWriteBytes",
    "blockReadBytesPerSecond", "blockWriteBytesPerSecond", "networkRxBytes",
    "networkTxBytes", "networkRxBytesPerSecond", "networkTxBytesPerSecond",
    "networkErrors", "networkErrorsPerSecond", "writableLayerBytes", "volumeCount",
    "bindMountCount", "tmpfsMountCount", "networkAttachmentCount", "publishedPortCount",
    "privileged", "hostPid", "hostIpc", "hostNetwork", "dockerSocketMounted",
    "sensitiveBindMounted", "writableSensitiveBindMounted", "rootUser",
    "readOnlyRootFilesystem", "addedCapabilityCount",
    "dangerousCapabilityCount", "excessiveCapabilities", "imageName", "imageTag",
    "imageDigest", "imageDigestSource", "usesLatestTag", "imageDigestDrift",
    "imageDigestChanged",
)
CONTAINER_V3_LEGACY_FIELDS = tuple(
    field_name for field_name in CONTAINER_FIELDS
    if field_name != "writableSensitiveBindMounted"
)
CONTAINER_STATES = frozenset({
    "created", "running", "paused", "restarting", "removing", "exited", "dead", "unknown",
})
CONTAINER_HEALTH_STATES = frozenset({"healthy", "unhealthy", "starting", "none", "unknown"})
ALLOWED_PROCESS_UIDS = frozenset({0, 1001})
MAX_TRAFFIC_APPS = 16
ALLOWED_TRAFFIC_APPS = frozenset({
    "monitor", "blog", "feelmyrythm", "multtara", "pilgrimage",
    "ddit-finalproject", "dukkeobi", "react", "vue",
})
MAX_TRAFFIC_REQUEST_SECONDS = 300.0
MAX_TRAFFIC_INPUT_AGE_SECONDS = 600
MAX_TRAFFIC_LINE_BYTES = 4096
MAX_RELIABILITY_DURATION_SECONDS = 366 * 24 * 60 * 60
RELIABILITY_GAP_WARN_SECONDS = 180
MAX_INCIDENT_FILE_BYTES = 16 * 1024 * 1024
MAX_INCIDENT_LINE_BYTES = 64 * 1024
MAX_PENDING_INCIDENT_COMMIT_BYTES = 96 * 1024
MAX_PENDING_SANITIZED_LOG_COMMIT_BYTES = 8 * 1024 * 1024
MAX_PENDING_RELIABILITY_COMMIT_BYTES = 8 * 1024 * 1024
MAX_SANITIZED_LOG_RECORD_BYTES = 4096
MAX_CONTAINER_INPUT_BYTES = 1 * 1024 * 1024
MAX_CONTAINER_INPUT_AGE_SECONDS = 180
MAX_SYNTHETIC_INPUT_BYTES = 256 * 1024
MAX_SYNTHETIC_INPUT_AGE_SECONDS = 10 * 60
MAX_SYNTHETIC_PROBES = 32
SYNTHETIC_PROBE_STATUSES = frozenset({
    "ok", "dns", "permission", "timeout", "tls", "http", "invalid", "unsupported",
})
SYNTHETIC_PROBE_FIELDS = (
    "schemaVersion", "id", "status", "checkedAt", "url", "httpStatus",
    "redirectCount", "latencyMilliseconds", "certificateExpiresAt",
    "certificateDaysRemaining",
)
CONTAINER_COLLECTION_STATUSES = frozenset({
    "fresh", "last-known", "unavailable", "permission-denied",
})
DOCKER_EVENT_COLLECTION_STATUSES = frozenset({
    "fresh", "gap", "unavailable", "permission-denied",
})
DOCKER_EVENT_ACTIONS = frozenset({
    "create", "start", "stop", "die", "kill", "pause", "unpause", "restart",
    "oom", "health_status", "destroy",
})
DOCKER_EVENT_HEALTH_STATES = frozenset({"healthy", "unhealthy", "starting"})
DOCKER_EVENT_FIELDS = (
    "id", "occurredAt", "action", "containerName", "project", "instanceId",
    "exitCode", "healthStatus",
)
DOCKER_EVENT_COLLECTION_FIELDS = (
    "status", "observedAt", "cursorAt", "reconnectCount", "gapCount", "gapDetected",
    "logCollectionStatus",
)
ALLOWED_COMPOSE_SERVICES = {
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
ALLOWED_COMPOSE_PROJECTS = tuple(sorted({
    project for project, _service in ALLOWED_COMPOSE_SERVICES
}))
CURRENT_CONTAINER_NAMES = frozenset(ALLOWED_COMPOSE_SERVICES.values())
CURRENT_CONTAINER_PROJECTS = {
    public_name: project
    for (project, _service), public_name in ALLOWED_COMPOSE_SERVICES.items()
}
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
# Keep the interval clock independently patchable. Replacing
# ``time.monotonic`` on the shared stdlib module also changes subprocess and
# other imported modules, which can make deterministic collector fixtures
# consume the sample clock unexpectedly.
_sample_monotonic = time.monotonic
VIRTUAL_FILESYSTEMS = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
    "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs",
    "overlay", "proc", "pstore", "ramfs", "securityfs", "sysfs", "tmpfs",
    "tracefs",
}


class ContainerSourceUnavailable(RuntimeError):
    """The bounded Docker source could not provide a complete observation."""


LEGACY_KERNEL_EVENT_SUMMARY_KEYS = (
    "warning",
    "oops",
    "panic",
    "hungTask",
    "rcuStall",
    "oomKill",
    "filesystemError",
    "nvmeReset",
    "nvmeIo",
    "pcieAerCorrectable",
    "pcieAerNonFatal",
    "pcieAerFatal",
)
KERNEL_EVENT_SUMMARY_KEYS = (
    "warning",
    "oops",
    "panic",
    "hungTask",
    "rcuStall",
    "rcuExpedited",
    "oomKill",
    "filesystemError",
    "nvmeReset",
    "nvmeIo",
    "pcieAerCorrectable",
    "pcieAerNonFatal",
    "pcieAerFatal",
)
KERNEL_EVENT_SUMMARY_MAP = {
    ("kernel-warning", "active"): "warning",
    ("kernel-oops", "active"): "oops",
    ("kernel-panic", "active"): "panic",
    ("hung-task", "active"): "hungTask",
    ("rcu-stall", "expedited"): "rcuExpedited",
    ("rcu-stall", "active"): "rcuStall",
    ("oom-kill", "active"): "oomKill",
    ("filesystem-error", "active"): "filesystemError",
    ("nvme-reset", "active"): "nvmeReset",
    ("nvme-io", "active"): "nvmeIo",
    ("pcie-aer", "correctable"): "pcieAerCorrectable",
    ("pcie-aer", "nonfatal"): "pcieAerNonFatal",
    ("pcie-aer", "fatal"): "pcieAerFatal",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def iso_event_timestamp(value: dt.datetime) -> str:
    """Canonicalize an event time without merging distinct sub-second events."""
    normalized = value.astimezone(dt.timezone.utc)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def opaque_uuid(value: Any) -> str | None:
    """Return one canonical random UUID without accepting alternate spellings."""
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return None
    canonical = str(parsed)
    return canonical if canonical == value and parsed.version == 4 else None


def machine_identity_hash(etc_root: Path) -> str | None:
    """Bind private collector identity to machine-id without exporting it."""
    value = read_text(etc_root / "machine-id", 256).strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", value) is None or value == "0" * 32:
        return None
    return hashlib.sha256(b"monitor-machine-id-v1\0" + value.encode("ascii")).hexdigest()


def public_boot_id(proc_root: Path) -> str | None:
    """Expose only a namespace-bound digest of Linux's per-boot random UUID."""
    value = read_text(proc_root / "sys" / "kernel" / "random" / "boot_id", 128).strip().lower()
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return None
    if str(parsed) != value:
        return None
    return hashlib.blake2s(
        b"monitor-boot-id-v1\0" + value.encode("ascii"), digest_size=16,
    ).hexdigest()


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


def read_bytes(path: Path, maximum: int = 4096) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(maximum)
    except (OSError, ValueError):
        return b""


def ensure_directory(path: Path, mode: int = 0o750) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass


def atomic_write_json(
    path: Path,
    value: Any,
    mode: int = 0o640,
    maximum_bytes: int | None = None,
) -> None:
    ensure_directory(path.parent)
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    if maximum_bytes is not None and len(payload.encode("utf-8")) > maximum_bytes:
        raise ValueError("JSON payload exceeds its configured size limit")
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


def normalized_identity_state(value: Any) -> dict[str, Any] | None:
    """Validate the owner-only stable host/agent identity state."""
    fields = {
        "schemaVersion", "hostId", "agentId", "installationEpoch",
        "identityGeneration", "machineIdHash", "sequence", "lastObservedAt",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return None
    if value.get("schemaVersion") != IDENTITY_STATE_SCHEMA_VERSION:
        return None
    host_id = opaque_uuid(value.get("hostId"))
    agent_id = opaque_uuid(value.get("agentId"))
    installation = parse_iso_timestamp(value.get("installationEpoch"))
    last_observed = parse_iso_timestamp(value.get("lastObservedAt"))
    generation = value.get("identityGeneration")
    sequence = value.get("sequence")
    machine_hash = value.get("machineIdHash")
    if (
        host_id is None
        or agent_id is None
        or installation is None
        or last_observed is None
        or installation > last_observed
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= MAX_SAFE_COUNTER
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= MAX_SAFE_COUNTER
        or (
            machine_hash is not None
            and (
                not isinstance(machine_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", machine_hash) is None
            )
        )
    ):
        return None
    return {
        "schemaVersion": IDENTITY_STATE_SCHEMA_VERSION,
        "hostId": host_id,
        "agentId": agent_id,
        "installationEpoch": iso_timestamp(installation),
        "identityGeneration": generation,
        "machineIdHash": machine_hash,
        "sequence": sequence,
        "lastObservedAt": iso_timestamp(last_observed),
    }


def prepare_identity(
    config: "Config",
    now: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Advance a stable identity before publishing the matching heartbeat.

    The state is committed first. A later publication failure therefore leaves
    an observable sequence gap instead of reusing a sequence number.
    """
    path = config.output_dir / ".state" / "collector-identity.json"
    raw = load_private_pending_json(path, MAX_IDENTITY_STATE_BYTES)
    prior = normalized_identity_state(raw) if raw is not None else None
    if raw is not None and prior is None:
        raise PendingJournalError("collector identity failed schema validation")

    now_text = iso_timestamp(now)
    current_machine_hash = machine_identity_hash(config.etc_root)
    machine_changed = bool(
        prior
        and prior["machineIdHash"] is not None
        and current_machine_hash is not None
        and prior["machineIdHash"] != current_machine_hash
    )
    if prior is None or machine_changed:
        generation = 1 if prior is None else prior["identityGeneration"] + 1
        if generation > MAX_SAFE_COUNTER:
            raise OverflowError("collector identity generation exhausted")
        state = {
            "schemaVersion": IDENTITY_STATE_SCHEMA_VERSION,
            "hostId": str(uuid.uuid4()),
            "agentId": str(uuid.uuid4()),
            "installationEpoch": now_text,
            "identityGeneration": generation,
            "machineIdHash": current_machine_hash,
            "sequence": 1,
            "lastObservedAt": now_text,
        }
    else:
        if prior["sequence"] >= MAX_SAFE_COUNTER:
            raise OverflowError("collector heartbeat sequence exhausted")
        state = {
            **prior,
            "machineIdHash": prior["machineIdHash"] or current_machine_hash,
            "sequence": prior["sequence"] + 1,
            "lastObservedAt": now_text,
        }
    normalized = normalized_identity_state(state)
    if normalized is None:
        raise ValueError("collector identity did not satisfy the private contract")
    atomic_write_json(path, normalized, 0o600)

    identity = {
        "hostId": normalized["hostId"],
        "agentId": normalized["agentId"],
        "installationEpoch": normalized["installationEpoch"],
        "identityGeneration": normalized["identityGeneration"],
        "machineIdentityStatus": "bound" if normalized["machineIdHash"] else "unavailable",
        "bootId": public_boot_id(config.proc_root),
    }
    heartbeat = {
        "sequence": normalized["sequence"],
        "observedAt": now_text,
        "receivedAt": now_text,
        "expectedIntervalSeconds": config.expected_interval_seconds,
        "lifecycle": config.agent_lifecycle,
        "transport": "local-file",
    }
    return identity, heartbeat


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


def load_json(path: Path, maximum_bytes: int = 1_048_576) -> dict[str, Any]:
    if not 1 <= maximum_bytes <= 64 * 1024 * 1024:
        return {}
    try:
        with path.open("rb") as handle:
            encoded = handle.read(maximum_bytes + 1)
        if len(encoded) > maximum_bytes:
            return {}
        value = json.loads(encoded.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ):
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


def parse_logical_cpu_count(text: str) -> int | None:
    cpu_ids: set[int] = set()
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        match = re.fullmatch(r"cpu(\d+)", fields[0])
        if match is None:
            continue
        identifier = int(match.group(1))
        if identifier > 4095:
            return None
        cpu_ids.add(identifier)
    return len(cpu_ids) if cpu_ids else None


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


def parse_swapinfo(text: str) -> tuple[int | None, int | None, float | None]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s*(kB)?", line)
        if match:
            multiplier = 1024 if match.group(3) else 1
            values[match.group(1)] = int(match.group(2)) * multiplier
    total = values.get("SwapTotal")
    free = values.get("SwapFree")
    if total is None or total < 0:
        return None, None, None
    if free is None or free < 0:
        return total, None, None
    used = total - min(total, free)
    percent = round(100.0 * used / total, 2) if total > 0 else 0.0
    return total, used, percent


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


def parse_net_dev(text: str) -> tuple[int, int, int, int, int, int] | None:
    received = transmitted = 0
    receive_errors = transmit_errors = 0
    receive_dropped = transmit_dropped = 0
    observed = False
    for line in text.splitlines():
        if ":" not in line:
            continue
        interface, counters = line.split(":", 1)
        fields = counters.split()
        if len(fields) < 12:
            continue
        try:
            current_received = int(fields[0])
            current_transmitted = int(fields[8])
            current_receive_errors = int(fields[2])
            current_transmit_errors = int(fields[10])
            current_receive_dropped = int(fields[3])
            current_transmit_dropped = int(fields[11])
        except ValueError:
            continue
        if any(value < 0 for value in (
            current_received,
            current_transmitted,
            current_receive_errors,
            current_transmit_errors,
            current_receive_dropped,
            current_transmit_dropped,
        )):
            continue
        if interface.strip() == "lo":
            continue
        observed = True
        received += current_received
        transmitted += current_transmitted
        receive_errors += current_receive_errors
        transmit_errors += current_transmit_errors
        receive_dropped += current_receive_dropped
        transmit_dropped += current_transmit_dropped
    return (
        received,
        transmitted,
        receive_errors,
        transmit_errors,
        receive_dropped,
        transmit_dropped,
    ) if observed else None


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


def network_rate_values(
    current: tuple[int, int, int, int, int, int] | None,
    previous: Any,
    elapsed: float,
) -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
]:
    if (
        current is None
        or not isinstance(previous, list)
        or len(previous) not in {2, 6}
        or not math.isfinite(elapsed)
        or elapsed <= 0
    ):
        return None, None, None, None, None, None
    rates: list[float | None] = []
    for index, counter in enumerate(current):
        if index >= len(previous):
            rates.append(None)
            continue
        prior = previous[index]
        if (
            isinstance(prior, bool)
            or not isinstance(prior, int)
            or prior < 0
            or counter < prior
        ):
            rates.append(None)
            continue
        rates.append(round((counter - prior) / elapsed, 2))
    return rates[0], rates[1], rates[2], rates[3], rates[4], rates[5]


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


def read_rpi_undervoltage_alarm(sys_root: Path) -> int | None:
    """Read the standard Raspberry Pi hwmon under-voltage alarm.

    Recent Raspberry Pi kernels warn when the legacy firmware
    ``get_throttled`` attribute is queried. The hwmon driver polls that
    firmware state itself and exposes the current alarm as a safe boolean.
    Discover by sensor name because hwmon indices are not stable across boots.
    """
    hwmon_root = sys_root / "class" / "hwmon"
    try:
        devices = sorted(hwmon_root.glob("hwmon*"))[:256]
    except OSError:
        devices = []
    found_normal = False
    for device in devices:
        if read_text(device / "name", 64).strip() != "rpi_volt":
            continue
        alarm = read_text(device / "in0_lcrit_alarm", 16).strip()
        if alarm == "1":
            return 1
        if alarm == "0":
            found_normal = True
    return 0 if found_normal else None


def parse_mountinfo(text: str) -> list[tuple[str, str, str, bool]]:
    mounts: list[tuple[str, str, str, bool]] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = fields[4].replace("\\040", " ").replace("\\134", "\\")
            mount_options = fields[5].split(",")
            filesystem = fields[separator + 1]
            device = fields[separator + 2]
            super_options = fields[separator + 3].split(",")
        except (ValueError, IndexError):
            continue
        if filesystem in VIRTUAL_FILESYSTEMS or not mount_point.startswith("/"):
            continue
        if not ({"ro", "rw"} & set(mount_options)):
            continue
        mounts.append((
            mount_point,
            device,
            filesystem,
            "ro" in mount_options or "ro" in super_options,
        ))
    return mounts


def collect_filesystems(mountinfo: str, mount_root: Path | None = None) -> list[dict[str, Any]]:
    disks: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_devices: set[str] = set()
    for mount_point, device, filesystem, read_only in parse_mountinfo(mountinfo):
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
        inode_used_percent: float | None = None
        try:
            filesystem_stats = os.statvfs(actual_path)
            inode_total = int(filesystem_stats.f_files)
            inode_free = int(filesystem_stats.f_ffree)
            if inode_total > 0 and 0 <= inode_free <= inode_total:
                inode_used_percent = round(
                    100.0 * (inode_total - inode_free) / inode_total,
                    2,
                )
        except (OSError, OverflowError, TypeError, ValueError):
            pass
        seen_devices.add(device)
        percent = round(100.0 * usage.used / usage.total, 2) if usage.total else 0.0
        disks.append({
            "mount": mount_point,
            "totalBytes": usage.total,
            "usedBytes": usage.used,
            "availableBytes": max(0, min(usage.total, usage.free)),
            "usedPercent": percent,
            "inodeUsedPercent": inode_used_percent,
            "readOnly": read_only,
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


def safe_version(value: Any, maximum: int = 128) -> str | None:
    text = str(value).strip()
    if not text or len(text) > maximum:
        return None
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/ -]*", text) is None:
        return None
    return text


def empty_kernel_event_summary() -> dict[str, dict[str, Any]]:
    return {
        key: {"count": 0, "lastEventAt": None}
        for key in KERNEL_EVENT_SUMMARY_KEYS
    }


def _existing_kernel_event_summary_for_keys(
    value: Any,
    keys: Sequence[str],
) -> dict[str, dict[str, Any]] | None:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        return None
    result: dict[str, dict[str, Any]] = {}
    for key in keys:
        raw = value.get(key)
        if not isinstance(raw, Mapping) or set(raw) != {"count", "lastEventAt"}:
            return None
        count = raw.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_SAFE_COUNTER:
            return None
        raw_timestamp = raw.get("lastEventAt")
        if raw_timestamp is None:
            timestamp = None
        else:
            parsed = parse_iso_timestamp(raw_timestamp)
            if parsed is None:
                return None
            timestamp = iso_event_timestamp(parsed)
        if (count == 0) != (timestamp is None):
            return None
        result[key] = {"count": count, "lastEventAt": timestamp}
    return result


def existing_kernel_event_summary(value: Any) -> dict[str, dict[str, Any]] | None:
    return _existing_kernel_event_summary_for_keys(value, KERNEL_EVENT_SUMMARY_KEYS)


def existing_legacy_kernel_event_summary(
    value: Any,
) -> dict[str, dict[str, Any]] | None:
    return _existing_kernel_event_summary_for_keys(
        value, LEGACY_KERNEL_EVENT_SUMMARY_KEYS
    )


def migrate_v2_kernel_event_summary(
    legacy_summary: Mapping[str, Mapping[str, Any]],
    retained_records: Sequence[Mapping[str, Any]],
    boot_started_at: str | None,
    now: dt.datetime,
) -> dict[str, dict[str, Any]]:
    """Split the ambiguous v2 warning counter using retained boot evidence only."""
    normalized = existing_legacy_kernel_event_summary(legacy_summary)
    if normalized is None:
        return empty_kernel_event_summary()
    result = empty_kernel_event_summary()
    for key in LEGACY_KERNEL_EVENT_SUMMARY_KEYS:
        if key != "warning":
            result[key] = dict(normalized[key])
    retained = (
        update_kernel_event_summary(
            empty_kernel_event_summary(), retained_records, boot_started_at, now
        )
        if boot_started_at is not None
        else empty_kernel_event_summary()
    )
    result["warning"] = dict(retained["warning"])
    result["rcuExpedited"] = dict(retained["rcuExpedited"])
    return result


def update_kernel_event_summary(
    summary: Mapping[str, Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
    boot_started_at: str | None,
    now: dt.datetime,
) -> dict[str, dict[str, Any]]:
    normalized = existing_kernel_event_summary(summary)
    result = normalized if normalized is not None else empty_kernel_event_summary()
    boot_started = parse_iso_timestamp(boot_started_at) if boot_started_at else None
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        kind = str(record.get("kind", ""))
        status = str(record.get("status", ""))
        key = KERNEL_EVENT_SUMMARY_MAP.get((kind, status))
        timestamp_text = event_timestamp(
            str(record.get("timestamp", "")), "", preserve_subseconds=True
        )
        timestamp = parse_iso_timestamp(timestamp_text)
        if key is None or timestamp is None:
            continue
        if boot_started is not None and timestamp < boot_started:
            continue
        if timestamp > now + dt.timedelta(minutes=1):
            continue
        identity = (timestamp_text, kind, status)
        if identity in seen:
            continue
        seen.add(identity)
        current = result[key]
        current["count"] = min(MAX_SAFE_COUNTER, int(current["count"]) + 1)
        previous = parse_iso_timestamp(current.get("lastEventAt"))
        if previous is None or timestamp > previous:
            current["lastEventAt"] = timestamp_text
    return result


def read_device_tree_uint32(path: Path) -> int | None:
    payload = read_bytes(path, 5)
    return int.from_bytes(payload, "big") if len(payload) == 4 else None


def bootloader_date(sys_root: Path) -> str | None:
    timestamp = read_device_tree_uint32(
        sys_root / "firmware" / "devicetree" / "base" / "chosen" / "bootloader" / "build-timestamp"
    )
    if timestamp is None:
        return None
    try:
        value = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).date()
    except (OverflowError, OSError, ValueError):
        return None
    return value.isoformat() if dt.date(2012, 1, 1) <= value <= dt.date(2100, 1, 1) else None


def bootloader_channel(etc_root: Path) -> str | None:
    text = read_text(etc_root / "default" / "rpi-eeprom-update", 8192)
    match = re.search(
        r'^\s*FIRMWARE_RELEASE_STATUS\s*=\s*["\']?(default|latest)["\']?\s*(?:#.*)?$',
        text,
        re.MULTILINE,
    )
    return match.group(1) if match else None


def raspberry_pi_soc(sys_root: Path) -> str | None:
    compatible = read_bytes(
        sys_root / "firmware" / "devicetree" / "base" / "compatible",
        4096,
    ).split(b"\0")
    for value in compatible:
        match = re.fullmatch(rb"brcm,bcm(2711|2712)", value)
        if match:
            return match.group(1).decode("ascii")
    return None


def latest_bootloader_date(
    package_root: Path,
    sys_root: Path,
    channel: str | None,
) -> str | None:
    if channel not in {"default", "latest"}:
        return None
    soc = raspberry_pi_soc(sys_root)
    if soc is None:
        return None
    candidates: list[dt.date] = []
    relative = Path("firmware") / "raspberrypi" / f"bootloader-{soc}" / channel
    for library in ("lib", "usr/lib"):
        directory = package_root / library / relative
        try:
            paths = list(directory.glob("pieeprom-????-??-??.bin"))[:256]
        except OSError:
            continue
        for path in paths:
            match = re.fullmatch(r"pieeprom-(\d{4}-\d{2}-\d{2})\.bin", path.name)
            if not match:
                continue
            try:
                candidates.append(dt.date.fromisoformat(match.group(1)))
            except ValueError:
                continue
    return max(candidates).isoformat() if candidates else None


def natural_version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.split(r"(\d+)", value)
        if part
    )


def latest_installed_kernel(package_root: Path) -> str | None:
    status_path = package_root / "var" / "lib" / "dpkg" / "status"
    configured: set[str] = set()
    try:
        size = status_path.stat().st_size
    except OSError:
        size = 0
    if 0 < size <= 16_777_216:
        status = read_text(status_path, 16_777_217)
        if len(status.encode("utf-8", errors="replace")) <= 16_777_216:
            for paragraph in re.split(r"\n\s*\n", status):
                package_match = re.search(r"^Package:\s*(\S+)\s*$", paragraph, re.MULTILINE)
                state_match = re.search(r"^Status:\s*(.+?)\s*$", paragraph, re.MULTILINE)
                if not package_match or not state_match:
                    continue
                state_fields = state_match.group(1).split()
                if (
                    len(state_fields) != 3
                    or state_fields[0] not in {"install", "hold"}
                    or state_fields[1:] != ["ok", "installed"]
                ):
                    continue
                image_match = re.fullmatch(r"linux-image-(?!unsigned-)([0-9][A-Za-z0-9._+-]*)", package_match.group(1))
                if image_match and safe_version(image_match.group(1)) is not None:
                    configured.add(image_match.group(1))
    if configured:
        return max(configured, key=natural_version_key)

    # ProtectKernelModules intentionally hides /lib/modules from the hardened
    # production unit. Keep it only as a fallback for non-dpkg test hosts or
    # systems whose package database is unavailable.
    directory = package_root / "lib" / "modules"
    try:
        module_names = [
            path.name for path in directory.iterdir()
            if path.is_dir() and not path.is_symlink() and safe_version(path.name) is not None
        ][:512]
    except OSError:
        return None
    return max(module_names, key=natural_version_key) if module_names else None


def first_nvme_controller(sys_root: Path) -> Path | None:
    directory = sys_root / "class" / "nvme"
    try:
        paths = sorted(
            (path for path in directory.iterdir() if re.fullmatch(r"nvme\d+", path.name)),
            key=lambda path: int(path.name[4:]),
        )
    except OSError:
        return None
    return paths[0] if paths else None


def parse_link_speed_gtps(value: str) -> float | None:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s+GT/s(?:\s+PCIe)?\s*", value)
    speed = finite_number(match.group(1) if match else None)
    if speed is None or not 0 < speed <= 128:
        return None
    return round(speed, 3)


def generation_for_speed(speed: float | None) -> int | None:
    if speed is None:
        return None
    for generation, expected in enumerate((2.5, 5.0, 8.0, 16.0, 32.0, 64.0), start=1):
        if math.isclose(speed, expected, rel_tol=0.01, abs_tol=0.05):
            return generation
    return None


def parse_link_width(value: str) -> int | None:
    match = re.fullmatch(r"\s*(\d{1,2})\s*", value)
    width = int(match.group(1)) if match else None
    return width if width is not None and 1 <= width <= 32 else None


def configured_pcie_generation(sys_root: Path, controller: Path | None) -> int | None:
    if controller is None:
        return None
    try:
        sys_real = sys_root.resolve()
        endpoint = (controller / "device").resolve()
        endpoint.relative_to(sys_real)
    except (OSError, RuntimeError, ValueError):
        return None
    for candidate in (endpoint, *endpoint.parents):
        try:
            candidate.relative_to(sys_real)
        except ValueError:
            break
        generation = read_device_tree_uint32(candidate / "of_node" / "max-link-speed")
        if generation is not None:
            return generation if 1 <= generation <= 6 else None
        if candidate == sys_real:
            break
    return None


def aer_total(value: str, label: str) -> int | None:
    match = re.search(rf"^{re.escape(label)}\s+(\d+)\s*$", value, re.MULTILINE)
    if not match:
        return None
    result = int(match.group(1))
    return result if result <= MAX_SAFE_COUNTER else None


def pcie_device_status(config: bytes) -> tuple[bool | None, bool | None, bool | None]:
    if len(config) < 0x40:
        return None, None, None
    pointer = config[0x34] & 0xFC
    visited: set[int] = set()
    while pointer and pointer not in visited and len(visited) < 48:
        visited.add(pointer)
        if pointer + 2 > len(config):
            break
        capability = config[pointer]
        next_pointer = config[pointer + 1] & 0xFC
        if capability == 0x10:
            if pointer + 12 > len(config):
                break
            status = int.from_bytes(config[pointer + 10:pointer + 12], "little")
            return bool(status & 0x1), bool(status & 0x2), bool(status & 0x4)
        pointer = next_pointer
    return None, None, None


def cmdline_tokens(proc_root: Path) -> set[str]:
    return set(read_text(proc_root / "cmdline", 16_384).strip().split())


def pcie_power_settings(proc_root: Path, sys_root: Path) -> tuple[bool | None, bool | None]:
    tokens = cmdline_tokens(proc_root)
    aspm_policy = read_text(
        sys_root / "module" / "pcie_aspm" / "parameters" / "policy", 256
    ).strip().lower()
    latency = read_text(
        sys_root / "module" / "nvme_core" / "parameters" / "default_ps_max_latency_us", 64
    ).strip()
    aspm_off = "pcie_aspm=off" in tokens
    if aspm_off:
        aspm_disabled: bool | None = True
    elif aspm_policy:
        aspm_disabled = "[performance]" in aspm_policy or aspm_policy == "performance"
    else:
        aspm_disabled = None
    if "nvme_core.default_ps_max_latency_us=0" in tokens or latency == "0":
        nvme_power_disabled: bool | None = True
    elif latency:
        nvme_power_disabled = False
    else:
        nvme_power_disabled = None
    return aspm_disabled, nvme_power_disabled


def collect_system(
    config: "Config",
    kernel_summary: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    controller = first_nvme_controller(config.sys_root)
    device = controller / "device" if controller is not None else None
    kernel_running = safe_version(platform.release())
    kernel_latest = latest_installed_kernel(config.package_root)
    channel = bootloader_channel(config.etc_root)
    current_bootloader = bootloader_date(config.sys_root)
    latest_bootloader = latest_bootloader_date(
        config.package_root, config.sys_root, channel
    )
    negotiated_speed = parse_link_speed_gtps(
        read_text(device / "current_link_speed", 64) if device is not None else ""
    )
    endpoint_speed = parse_link_speed_gtps(
        read_text(device / "max_link_speed", 64) if device is not None else ""
    )
    aspm_disabled, nvme_power_disabled = pcie_power_settings(
        config.proc_root, config.sys_root
    )
    correctable_status, nonfatal_status, fatal_status = pcie_device_status(
        read_bytes(device / "config", 4096) if device is not None else b""
    )
    normalized_kernel = existing_kernel_event_summary(kernel_summary)
    if normalized_kernel is None:
        normalized_kernel = empty_kernel_event_summary()
    return {
        "versions": {
            "kernelRunning": kernel_running,
            "kernelLatestInstalled": kernel_latest,
            "kernelRebootRequired": (
                kernel_running != kernel_latest
                if kernel_running is not None and kernel_latest is not None
                else None
            ),
            "bootloaderCurrent": current_bootloader,
            "bootloaderLatest": latest_bootloader,
            "bootloaderChannel": channel,
            "nvmeModel": safe_version(
                read_text(controller / "model", 256), 128
            ) if controller is not None else None,
            "nvmeFirmware": safe_version(
                read_text(controller / "firmware_rev", 128), 64
            ) if controller is not None else None,
            "collector": COLLECTOR_VERSION,
        },
        "pcie": {
            "configuredGeneration": configured_pcie_generation(config.sys_root, controller),
            "negotiatedGeneration": generation_for_speed(negotiated_speed),
            "negotiatedSpeedGtps": negotiated_speed,
            "negotiatedWidth": parse_link_width(
                read_text(device / "current_link_width", 64) if device is not None else ""
            ),
            "endpointMaxGeneration": generation_for_speed(endpoint_speed),
            "endpointMaxWidth": parse_link_width(
                read_text(device / "max_link_width", 64) if device is not None else ""
            ),
            "aspmDisabled": aspm_disabled,
            "nvmePowerSavingDisabled": nvme_power_disabled,
            "aerCorrectableCount": aer_total(
                read_text(device / "aer_dev_correctable", 8192) if device is not None else "",
                "TOTAL_ERR_COR",
            ),
            "aerNonFatalCount": aer_total(
                read_text(device / "aer_dev_nonfatal", 8192) if device is not None else "",
                "TOTAL_ERR_NONFATAL",
            ),
            "aerFatalCount": aer_total(
                read_text(device / "aer_dev_fatal", 8192) if device is not None else "",
                "TOTAL_ERR_FATAL",
            ),
            "correctableStatusActive": correctable_status,
            "nonFatalStatusActive": nonfatal_status,
            "fatalStatusActive": fatal_status,
        },
        "kernel": normalized_kernel,
    }


def parse_vcgencmd(command: str, output: str) -> tuple[str, Any] | None:
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


def collect_gpu(vcgencmd: str, timeout: float, sys_root: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if vcgencmd and Path(vcgencmd).is_file() and os.access(vcgencmd, os.X_OK):
        for invocation in (
            ("measure_temp",), ("get_mem", "gpu"),
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
    if sys_root is not None:
        alarm = read_rpi_undervoltage_alarm(sys_root)
        if alarm is not None:
            # Preserve the public uint32 contract: bit 0 is the current
            # under-voltage condition. Legacy high-bit history remains
            # readable in retained samples but is no longer queried.
            result["throttledFlags"] = alarm
    return result


def docker_response_byte_limit(request_path: str) -> int:
    """Return the fixed response budget without trusting Docker-provided metadata."""
    if re.fullmatch(
        r"/v1\.41/containers/[a-fA-F0-9]{12,64}/"
        r"(?:json|stats\?stream=false&one-shot=true)",
        request_path,
    ):
        return MAX_DOCKER_DETAIL_RESPONSE_BYTES
    return MAX_DOCKER_LIST_RESPONSE_BYTES


def docker_get(socket_path: Path, request_path: str, curl: str, timeout: float) -> Any:
    try:
        socket_metadata = socket_path.stat()
    except PermissionError:
        raise
    except OSError:
        return None
    if not stat.S_ISSOCK(socket_metadata.st_mode):
        return None
    response_limit = docker_response_byte_limit(request_path)
    try:
        completed = subprocess.run(
            [curl, "--silent", "--show-error", "--fail", "--max-time", str(timeout),
             "--max-filesize", str(response_limit),
             "--unix-socket", str(socket_path), "http://localhost" + request_path],
            capture_output=True, timeout=timeout + 0.5, check=False,
        )
    except PermissionError:
        raise
    except (OSError, subprocess.SubprocessError):
        return None
    stdout = (
        completed.stdout
        if isinstance(completed.stdout, bytes)
        else str(completed.stdout).encode("utf-8", errors="replace")
    )
    stderr = (
        completed.stderr
        if isinstance(completed.stderr, bytes)
        else str(completed.stderr).encode("utf-8", errors="replace")
    )
    if completed.returncode != 0:
        bounded_error = stderr[:256].lower()
        if b"permission denied" in bounded_error or b"403" in bounded_error:
            raise PermissionError("container telemetry source denied access")
        return None
    if len(stdout) > response_limit:
        return None
    try:
        return json.loads(stdout)
    except (UnicodeError, json.JSONDecodeError):
        return None


def docker_cpu_state(stats: Mapping[str, Any]) -> dict[str, int] | None:
    cpu = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), dict) else {}
    cpu_usage = cpu.get("cpu_usage") if isinstance(cpu.get("cpu_usage"), dict) else {}
    cpu_total = bounded_integer(cpu_usage.get("total_usage"), 0, (1 << 63) - 1)
    system_total = bounded_integer(cpu.get("system_cpu_usage"), 0, (1 << 63) - 1)
    if cpu_total is None or system_total is None:
        return None
    online = bounded_integer(cpu.get("online_cpus"), 1, 4096)
    if online is None:
        per_cpu = cpu_usage.get("percpu_usage")
        online = len(per_cpu) if isinstance(per_cpu, list) and 1 <= len(per_cpu) <= 4096 else 1
    return {"cpuTotal": cpu_total, "systemTotal": system_total, "onlineCpus": online}


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
    return "/v1.41/containers/json?" + urllib.parse.urlencode({
        "all": "1", "size": "1", "filters": filters,
    })


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


def validated_container_inspect(
    value: Any,
    requested_id: str,
    public_name: str,
) -> Mapping[str, Any] | None:
    """Bind an inspect response to the admitted ID and exact Compose pair."""
    if not isinstance(value, Mapping):
        return None
    inspected_id = value.get("Id")
    if (
        not isinstance(inspected_id, str)
        or re.fullmatch(r"[a-fA-F0-9]{12,64}", inspected_id) is None
        or not (
            inspected_id.lower() == requested_id.lower()
            or (
                len(requested_id) >= 12
                and len(inspected_id) > len(requested_id)
                and inspected_id.lower().startswith(requested_id.lower())
            )
        )
    ):
        return None
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        return None
    project = labels.get("com.docker.compose.project")
    service = labels.get("com.docker.compose.service")
    if (
        not isinstance(project, str)
        or not isinstance(service, str)
        or ALLOWED_COMPOSE_SERVICES.get((project, service)) != public_name
        or CURRENT_CONTAINER_PROJECTS.get(public_name) != project
    ):
        return None
    return value


def reduce_container_inspect(value: Mapping[str, Any]) -> dict[str, Any]:
    """Discard inspect secrets immediately, retaining only fixed reduced inputs."""
    reduced: dict[str, Any] = {}
    restart_count = value.get("RestartCount")
    reduced["RestartCount"] = (
        restart_count if isinstance(restart_count, (int, bool)) else True
    )

    raw_state = value.get("State") if isinstance(value.get("State"), Mapping) else {}
    state: dict[str, Any] = {
        "OOMKilled": (
            raw_state.get("OOMKilled")
            if isinstance(raw_state.get("OOMKilled"), bool)
            else None
        ),
        "StartedAt": (
            raw_state.get("StartedAt")
            if isinstance(raw_state.get("StartedAt"), str) and len(raw_state["StartedAt"]) <= 64
            else None
        ),
        "FinishedAt": (
            raw_state.get("FinishedAt")
            if isinstance(raw_state.get("FinishedAt"), str) and len(raw_state["FinishedAt"]) <= 64
            else None
        ),
    }
    raw_health = raw_state.get("Health") if isinstance(raw_state.get("Health"), Mapping) else None
    if raw_health is not None:
        health_status = raw_health.get("Status")
        state["Health"] = {
            "Status": (
                health_status.lower()
                if isinstance(health_status, str)
                and health_status.lower() in {"healthy", "unhealthy", "starting"}
                else None
            )
        }
    reduced["State"] = state

    raw_config = value.get("Config") if isinstance(value.get("Config"), Mapping) else {}
    config: dict[str, Any] = {}
    if "Healthcheck" in raw_config:
        raw_healthcheck = raw_config.get("Healthcheck")
        if raw_healthcheck is None or raw_healthcheck == {}:
            config["Healthcheck"] = raw_healthcheck
        elif isinstance(raw_healthcheck, Mapping):
            raw_test = raw_healthcheck.get("Test")
            if isinstance(raw_test, list) and not raw_test:
                config["Healthcheck"] = {"Test": []}
            elif (
                isinstance(raw_test, list)
                and len(raw_test) <= 32
                and all(isinstance(item, str) and len(item) <= 4096 for item in raw_test)
                and raw_test[0].upper() in {"CMD", "CMD-SHELL", "NONE"}
                and (raw_test[0].upper() != "NONE" or len(raw_test) == 1)
            ):
                # The command body can contain secrets. Retain only the
                # validated schema marker needed by the public health contract.
                config["Healthcheck"] = {"Test": [raw_test[0].upper()]}
            else:
                config["Healthcheck"] = {"Test": ["INVALID"]}
        else:
            config["Healthcheck"] = "INVALID"
    raw_user = raw_config.get("User")
    if isinstance(raw_user, str) and len(raw_user) <= 128 and "\x00" not in raw_user:
        # Docker accepts user[:group]. The group does not change effective UID,
        # so root:staff and 0:1000 must both remain root-user evidence.
        config["RootUser"] = raw_user == "" or raw_user.split(":", 1)[0] in {"root", "0"}
    else:
        config["RootUser"] = None
    raw_image = raw_config.get("Image")
    config["Image"] = (
        raw_image
        if isinstance(raw_image, str)
        and 1 <= len(raw_image) <= 255
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", raw_image)
        and (
            "@" not in raw_image
            or (
                raw_image.count("@") == 1
                and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", raw_image.rsplit("@", 1)[1])
                is not None
            )
        )
        else None
    )
    reduced["Config"] = config

    raw_host = value.get("HostConfig") if isinstance(value.get("HostConfig"), Mapping) else None
    if raw_host is not None:
        host: dict[str, Any] = {}
        for field_name in (
            "Memory", "NanoCpus", "CpuQuota", "CpuPeriod", "PidsLimit", "Privileged",
            "PidMode", "IpcMode", "NetworkMode", "ReadonlyRootfs", "CapAdd",
        ):
            if field_name not in raw_host:
                continue
            candidate = raw_host.get(field_name)
            if field_name in {"PidMode", "IpcMode", "NetworkMode"}:
                host[field_name] = candidate if isinstance(candidate, str) and len(candidate) <= 64 else None
            elif field_name == "CapAdd":
                host[field_name] = (
                    candidate[:MAX_CONTAINER_CAPABILITY_COUNT + 1]
                    if isinstance(candidate, list)
                    and all(isinstance(item, str) and len(item) <= 64 for item in candidate[:MAX_CONTAINER_CAPABILITY_COUNT + 1])
                    else None
                )
            else:
                host[field_name] = (
                    candidate
                    if candidate is None or isinstance(candidate, (int, bool))
                    else None
                )
        reduced["HostConfig"] = host

    reduced["MountSummary"] = _reduce_mount_summary(value.get("Mounts"))

    raw_network = value.get("NetworkSettings") if isinstance(value.get("NetworkSettings"), Mapping) else {}
    networks = raw_network.get("Networks")
    ports = raw_network.get("Ports")
    reduced["NetworkSettings"] = {
        "NetworkCount": (
            min(len(networks), MAX_CONTAINER_MOUNT_COUNT)
            if isinstance(networks, Mapping) else None
        ),
        "PublishedPortCount": _published_port_count(ports),
    }
    raw_image_id = value.get("Image")
    reduced["Image"] = (
        raw_image_id.lower()
        if isinstance(raw_image_id, str)
        and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", raw_image_id)
        else None
    )
    return reduced


def reduce_container_stats(value: Mapping[str, Any]) -> dict[str, Any]:
    """Discard raw stats after reducing fixed aggregate counters."""
    reduced: dict[str, Any] = {}
    cpu_state = docker_cpu_state(value)
    if cpu_state is not None:
        reduced["cpu_stats"] = {
            "cpu_usage": {"total_usage": cpu_state["cpuTotal"]},
            "system_cpu_usage": cpu_state["systemTotal"],
            "online_cpus": cpu_state["onlineCpus"],
        }
        raw_cpu = value.get("cpu_stats") if isinstance(value.get("cpu_stats"), Mapping) else {}
        throttling = raw_cpu.get("throttling_data") if isinstance(raw_cpu.get("throttling_data"), Mapping) else {}
        periods = bounded_integer(throttling.get("periods"), 0, MAX_SAFE_COUNTER)
        throttled_periods = bounded_integer(throttling.get("throttled_periods"), 0, MAX_SAFE_COUNTER)
        throttled_time = bounded_integer(throttling.get("throttled_time"), 0, MAX_SAFE_COUNTER)
        reduced["cpu_stats"]["throttling_data"] = {
            "periods": periods,
            "throttled_periods": throttled_periods,
            "throttled_time": throttled_time,
        }
    raw_memory = value.get("memory_stats") if isinstance(value.get("memory_stats"), Mapping) else {}
    usage = bounded_integer(raw_memory.get("usage"), 0, MAX_CONTAINER_MEMORY_LIMIT_BYTES)
    limit = bounded_integer(raw_memory.get("limit"), 0, MAX_CONTAINER_MEMORY_LIMIT_BYTES)
    if usage is not None or limit is not None:
        reduced["memory_stats"] = {"usage": usage, "limit": limit}
    raw_pids = value.get("pids_stats") if isinstance(value.get("pids_stats"), Mapping) else {}
    reduced["pids_stats"] = {
        "current": bounded_integer(raw_pids.get("current"), 0, MAX_CONTAINER_PID_LIMIT),
    }
    raw_blkio = value.get("blkio_stats") if isinstance(value.get("blkio_stats"), Mapping) else {}
    raw_io = raw_blkio.get("io_service_bytes_recursive")
    if raw_io is None:
        raw_io = raw_blkio.get("io_service_bytes")
    read_bytes, write_bytes = _reduce_block_io_bytes(raw_io)
    reduced["blkio_stats"] = {"readBytes": read_bytes, "writeBytes": write_bytes}
    network_totals = _reduce_network_totals(value.get("networks"))
    reduced["networks"] = network_totals
    raw_read = value.get("read")
    reduced["read"] = raw_read if isinstance(raw_read, str) and len(raw_read) <= 64 else None
    return reduced


def _published_port_count(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    total = 0
    for bindings in list(value.values())[:MAX_CONTAINER_PORT_COUNT + 1]:
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            return None
        total += len(bindings)
        if total > MAX_CONTAINER_PORT_COUNT:
            return MAX_CONTAINER_PORT_COUNT
    return total


def _reduce_mount_summary(value: Any) -> dict[str, int | bool | None]:
    result: dict[str, int | bool | None] = {
        "volumeCount": None,
        "bindMountCount": None,
        "tmpfsMountCount": None,
        "dockerSocketMounted": None,
        "sensitiveBindMounted": None,
        "writableSensitiveBindMounted": None,
    }
    if not isinstance(value, list) or len(value) > MAX_CONTAINER_MOUNT_COUNT:
        return result
    counts = {"volume": 0, "bind": 0, "tmpfs": 0}
    docker_socket = False
    sensitive_bind = False
    writable_sensitive_bind: bool | None = False
    sensitive_roots = ("/", "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys")

    def normalized_path(candidate: Any) -> str | None:
        if (
            not isinstance(candidate, str)
            or not candidate.startswith("/")
            or len(candidate) > 4096
            or "\x00" in candidate
        ):
            return None
        return os.path.normpath(candidate)

    for raw_mount in value:
        if not isinstance(raw_mount, Mapping):
            return result
        mount_type = raw_mount.get("Type")
        if mount_type not in counts:
            continue
        counts[mount_type] += 1
        source = normalized_path(raw_mount.get("Source"))
        destination = normalized_path(raw_mount.get("Destination"))
        if any(
            path is not None and (path.endswith("/docker.sock") or path == "/var/run/docker.sock")
            for path in (source, destination)
        ):
            docker_socket = True
        if mount_type == "bind":
            # Only the host source represents host exposure. A conventional
            # in-container destination such as /etc/app is not itself a
            # sensitive host bind.
            mount_is_sensitive = source is not None and (
                source == "/"
                or any(
                    source == root or source.startswith(root + "/")
                    for root in sensitive_roots[1:]
                )
            )
            if mount_is_sensitive:
                sensitive_bind = True
                writable = raw_mount.get("RW")
                if writable is True:
                    writable_sensitive_bind = True
                elif writable is not False and writable_sensitive_bind is False:
                    writable_sensitive_bind = None
    return {
        "volumeCount": counts["volume"],
        "bindMountCount": counts["bind"],
        "tmpfsMountCount": counts["tmpfs"],
        "dockerSocketMounted": docker_socket,
        "sensitiveBindMounted": sensitive_bind,
        "writableSensitiveBindMounted": writable_sensitive_bind,
    }


def _reduce_block_io_bytes(value: Any) -> tuple[int | None, int | None]:
    if not isinstance(value, list) or len(value) > 4096:
        return None, None
    totals = {"read": 0, "write": 0}
    observed: set[str] = set()
    for row in value:
        if not isinstance(row, Mapping):
            return None, None
        operation = row.get("op")
        amount = bounded_integer(row.get("value"), 0, MAX_CONTAINER_IO_BYTES)
        if not isinstance(operation, str) or amount is None:
            continue
        normalized = operation.lower()
        if normalized not in totals:
            continue
        totals[normalized] += amount
        if totals[normalized] > MAX_CONTAINER_IO_BYTES:
            totals[normalized] = MAX_CONTAINER_IO_BYTES
        observed.add(normalized)
    return (
        totals["read"] if "read" in observed else None,
        totals["write"] if "write" in observed else None,
    )


def _reduce_network_totals(value: Any) -> dict[str, int | None]:
    fields = ("rx_bytes", "tx_bytes", "rx_errors", "tx_errors")
    totals = {field: 0 for field in fields}
    if not isinstance(value, Mapping) or len(value) > 256:
        return {field: None for field in fields}
    observed = False
    for row in value.values():
        if not isinstance(row, Mapping):
            return {field: None for field in fields}
        current: dict[str, int] = {}
        for field in fields:
            parsed = bounded_integer(row.get(field), 0, MAX_CONTAINER_IO_BYTES)
            if parsed is None:
                return {field: None for field in fields}
            current[field] = parsed
        observed = True
        for field in fields:
            totals[field] = min(MAX_CONTAINER_IO_BYTES, totals[field] + current[field])
    return totals if observed else {field: None for field in fields}


def bounded_integer(value: Any, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if minimum <= value <= maximum else None


def docker_container_timestamp(
    value: Any, not_after: dt.datetime | None = None,
) -> str | None:
    parsed = parse_iso_timestamp(value)
    maximum = not_after or (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60))
    if (
        parsed is None
        or parsed <= dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        or parsed > maximum
    ):
        return None
    return iso_event_timestamp(parsed)


def docker_health_details(inspect: Mapping[str, Any] | None) -> tuple[str | None, bool | None]:
    if not isinstance(inspect, Mapping):
        return None, None
    config = inspect.get("Config") if isinstance(inspect.get("Config"), Mapping) else None
    if config is None:
        return None, None
    healthcheck = config.get("Healthcheck")
    if healthcheck is None or healthcheck == {}:
        return "none", False
    if not isinstance(healthcheck, Mapping):
        return None, None
    test = healthcheck.get("Test")
    if not isinstance(test, list) or len(test) > 32 or not all(
        isinstance(item, str) and len(item) <= 4096 for item in test
    ):
        return None, None
    if not test or test[0].upper() == "NONE":
        return "none", False
    if test[0].upper() not in {"CMD", "CMD-SHELL"}:
        return None, None

    state = inspect.get("State") if isinstance(inspect.get("State"), Mapping) else None
    if state is not None and isinstance(state.get("Health"), Mapping):
        status = state["Health"].get("Status")
        if isinstance(status, str) and status.lower() in {"healthy", "unhealthy", "starting"}:
            return status.lower(), True
    return None, True


def docker_resource_limits(
    inspect: Mapping[str, Any] | None,
) -> tuple[int | None, float | None, int | None]:
    if not isinstance(inspect, Mapping) or not isinstance(inspect.get("HostConfig"), Mapping):
        return None, None, None
    host_config = inspect["HostConfig"]

    memory_limit: int | None = None
    if "Memory" in host_config:
        memory_limit = bounded_integer(
            host_config.get("Memory"), 0, MAX_CONTAINER_MEMORY_LIMIT_BYTES
        )

    cpu_limit: float | None = None
    nano_cpus_present = "NanoCpus" in host_config
    quota_present = "CpuQuota" in host_config
    nano_cpus = (
        bounded_integer(host_config.get("NanoCpus"), 0, MAX_SAFE_COUNTER)
        if nano_cpus_present else None
    )
    quota = (
        bounded_integer(host_config.get("CpuQuota"), -1, MAX_SAFE_COUNTER)
        if quota_present else None
    )
    period = (
        bounded_integer(host_config.get("CpuPeriod"), 0, MAX_SAFE_COUNTER)
        if "CpuPeriod" in host_config else None
    )
    candidate_cpu_limit: float | None = None
    if nano_cpus_present and nano_cpus is None:
        candidate_cpu_limit = None
    elif nano_cpus is not None and nano_cpus > 0:
        # NanoCpus is Docker's preferred effective CPU limit. Once it is a
        # valid positive value, stale or malformed quota fields are irrelevant.
        candidate_cpu_limit = nano_cpus / 1_000_000_000
    elif quota_present:
        if quota is None:
            candidate_cpu_limit = None
        elif quota > 0:
            candidate_cpu_limit = quota / period if period is not None and period > 0 else None
        elif quota in {-1, 0}:
            candidate_cpu_limit = 0.0
    elif nano_cpus == 0:
        candidate_cpu_limit = 0.0
    if (
        candidate_cpu_limit is not None
        and math.isfinite(candidate_cpu_limit)
        and 0 <= candidate_cpu_limit <= MAX_CONTAINER_CPU_LIMIT_CORES
    ):
        cpu_limit = round(candidate_cpu_limit, 6)

    pid_limit: int | None = None
    if "PidsLimit" in host_config:
        raw_pid_limit = host_config.get("PidsLimit")
        if raw_pid_limit is None:
            pid_limit = 0
        else:
            parsed_pid_limit = bounded_integer(raw_pid_limit, -1, MAX_CONTAINER_PID_LIMIT)
            if parsed_pid_limit is not None:
                pid_limit = max(0, parsed_pid_limit)
    return memory_limit, cpu_limit, pid_limit


def opaque_container_instance_id(container_id: Any) -> str | None:
    if not isinstance(container_id, str) or re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id) is None:
        return None
    return hashlib.sha256(
        b"monitor-container-instance-v1\x00" + container_id.lower().encode("ascii")
    ).hexdigest()[:32]


def docker_image_details(inspect: Mapping[str, Any] | None) -> tuple[
    str | None, str | None, str | None, str | None, bool | None, str | None,
]:
    if not isinstance(inspect, Mapping):
        return None, None, None, None, None, None
    config = inspect.get("Config") if isinstance(inspect.get("Config"), Mapping) else {}
    raw_reference = config.get("Image")
    raw_image_id = inspect.get("Image")
    image_id = (
        raw_image_id.lower()
        if isinstance(raw_image_id, str)
        and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", raw_image_id)
        else None
    )
    if (
        not isinstance(raw_reference, str)
        or not 1 <= len(raw_reference) <= 255
        or any(character.isspace() or ord(character) < 0x20 for character in raw_reference)
        or "://" in raw_reference
        or any(marker in raw_reference for marker in ("?", "#"))
    ):
        return None, None, image_id, "local-image-id" if image_id else None, None, None

    reference = raw_reference
    pinned_digest: str | None = None
    tag: str | None = None
    if "@" in reference:
        if reference.count("@") != 1:
            return None, None, image_id, "local-image-id" if image_id else None, None, None
        reference, candidate_digest = reference.rsplit("@", 1)
        if re.fullmatch(r"sha256:[a-fA-F0-9]{64}", candidate_digest) is None:
            return None, None, image_id, "local-image-id" if image_id else None, None, None
        pinned_digest = candidate_digest.lower()
    repository = reference
    final_slash = repository.rfind("/")
    final_colon = repository.rfind(":")
    if final_colon > final_slash:
        tag = repository[final_colon + 1:]
        repository = repository[:final_colon]
    elif pinned_digest is None:
        tag = "latest"
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}", repository)
        or repository.startswith("/")
        or repository.endswith("/")
        or "//" in repository
        or (tag is not None and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag) is None)
    ):
        return None, None, image_id, "local-image-id" if image_id else None, None, None
    digest = pinned_digest or image_id
    digest_source = "repo-digest" if pinned_digest is not None else "local-image-id" if image_id else None
    # Mutability is a property of the requested reference, not of whether the
    # daemon also resolved that reference to a local content digest.
    uses_latest = tag == "latest"
    # A pinned digest is part of the requested reference. Include it in the
    # fingerprint so an intentional pin update is not reported as a mutable
    # same-reference digest change. Mutable tag references deliberately omit
    # the resolved local image ID from this fingerprint.
    fingerprint_suffix = (
        f"tag:{tag}\x00digest:{pinned_digest}"
        if pinned_digest is not None
        else f"tag:{tag}"
    )
    reference_fingerprint = hashlib.sha256(
        (repository + "\x00" + fingerprint_suffix).encode("utf-8")
    ).hexdigest()
    return repository, tag, digest, digest_source, uses_latest, reference_fingerprint


def docker_security_details(inspect: Mapping[str, Any] | None) -> dict[str, int | bool | None]:
    result: dict[str, int | bool | None] = {
        "privileged": None,
        "hostPid": None,
        "hostIpc": None,
        "hostNetwork": None,
        "dockerSocketMounted": None,
        "sensitiveBindMounted": None,
        "writableSensitiveBindMounted": None,
        "rootUser": None,
        "readOnlyRootFilesystem": None,
        "addedCapabilityCount": None,
        "dangerousCapabilityCount": None,
        "excessiveCapabilities": None,
    }
    if not isinstance(inspect, Mapping):
        return result
    host = inspect.get("HostConfig") if isinstance(inspect.get("HostConfig"), Mapping) else {}
    config = inspect.get("Config") if isinstance(inspect.get("Config"), Mapping) else {}
    mounts = inspect.get("MountSummary") if isinstance(inspect.get("MountSummary"), Mapping) else {}
    privileged = host.get("Privileged") if isinstance(host.get("Privileged"), bool) else None
    read_only = host.get("ReadonlyRootfs") if isinstance(host.get("ReadonlyRootfs"), bool) else None
    pid_mode = host.get("PidMode")
    ipc_mode = host.get("IpcMode")
    network_mode = host.get("NetworkMode")
    root_user = config.get("RootUser") if isinstance(config.get("RootUser"), bool) else None
    sensitive_bind = (
        mounts.get("sensitiveBindMounted")
        if isinstance(mounts.get("sensitiveBindMounted"), bool) else None
    )
    writable_sensitive_bind = (
        mounts.get("writableSensitiveBindMounted")
        if isinstance(mounts.get("writableSensitiveBindMounted"), bool) else None
    )
    if writable_sensitive_bind is None and sensitive_bind is False:
        # A pre-field reduced MountSummary still proves that no sensitive bind
        # exists, so the derived "any writable" answer is definitively false.
        writable_sensitive_bind = False
    raw_capabilities = host.get("CapAdd")
    capability_count: int | None = None
    dangerous_count: int | None = None
    excessive: bool | None = None
    if raw_capabilities is None and "CapAdd" in host:
        capability_count = 0
        dangerous_count = 0
        excessive = False
    elif isinstance(raw_capabilities, list):
        normalized_capabilities = {
            candidate.upper().removeprefix("CAP_")
            for candidate in raw_capabilities[:MAX_CONTAINER_CAPABILITY_COUNT]
            if isinstance(candidate, str) and re.fullmatch(r"(?:CAP_)?[A-Za-z0-9_]{1,64}", candidate)
        }
        dangerous = {
            "ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN",
            "DAC_READ_SEARCH", "BPF", "PERFMON", "CHECKPOINT_RESTORE",
        }
        capability_count = min(len(raw_capabilities), MAX_CONTAINER_CAPABILITY_COUNT)
        dangerous_count = len(normalized_capabilities & dangerous)
        excessive = (
            len(raw_capabilities) > 12
            or len(raw_capabilities) > MAX_CONTAINER_CAPABILITY_COUNT
            or dangerous_count > 0
        )
    result.update({
        "privileged": privileged,
        "hostPid": pid_mode == "host" if isinstance(pid_mode, str) else None,
        "hostIpc": ipc_mode == "host" if isinstance(ipc_mode, str) else None,
        "hostNetwork": network_mode == "host" if isinstance(network_mode, str) else None,
        "dockerSocketMounted": mounts.get("dockerSocketMounted") if isinstance(mounts.get("dockerSocketMounted"), bool) else None,
        "sensitiveBindMounted": sensitive_bind,
        "writableSensitiveBindMounted": writable_sensitive_bind,
        "rootUser": root_user,
        "readOnlyRootFilesystem": read_only,
        "addedCapabilityCount": capability_count,
        "dangerousCapabilityCount": dangerous_count,
        "excessiveCapabilities": excessive,
    })
    return result


def _container_counter_rate(current: int | None, previous: Any, elapsed: float | None) -> float | None:
    prior = bounded_integer(previous, 0, MAX_CONTAINER_IO_BYTES)
    if current is None or prior is None or elapsed is None or elapsed <= 0 or current < prior:
        return None
    return round(min(MAX_CONTAINER_IO_RATE, (current - prior) / elapsed), 3)


def normalize_private_container_state(value: Any) -> dict[str, int | str]:
    """Admit only bounded counters and image fingerprints from owner-only state."""
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int | str] = {}
    cpu_total = bounded_integer(value.get("cpuTotal"), 0, (1 << 63) - 1)
    system_total = bounded_integer(value.get("systemTotal"), 0, (1 << 63) - 1)
    online_cpus = bounded_integer(value.get("onlineCpus"), 1, 4096)
    if cpu_total is not None and system_total is not None and online_cpus is not None:
        result.update({
            "cpuTotal": cpu_total,
            "systemTotal": system_total,
            "onlineCpus": online_cpus,
        })
    restart_count = bounded_integer(value.get("restartCount"), 0, MAX_SAFE_COUNTER)
    if restart_count is not None:
        result["restartCount"] = restart_count
    for field_name in (
        "sampleAtUnixMs", "cpuPeriods", "cpuThrottledPeriods",
        "cpuThrottledTimeNanoseconds", "blockReadBytes",
        "blockWriteBytes", "networkRxBytes", "networkTxBytes", "networkErrors",
    ):
        parsed = bounded_integer(value.get(field_name), 0, MAX_SAFE_COUNTER)
        if parsed is not None:
            result[field_name] = parsed
    image_digest = value.get("imageDigest")
    if isinstance(image_digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
        result["imageDigest"] = image_digest
    fingerprint = value.get("imageReferenceFingerprint")
    if isinstance(fingerprint, str) and re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        result["imageReferenceFingerprint"] = fingerprint
    return result


def normalize_private_container_state_map(value: Any) -> dict[str, dict[str, int | str]]:
    if not isinstance(value, Mapping) or len(value) > 400:
        return {}
    result: dict[str, dict[str, int | str]] = {}
    allowed_service_keys = {
        f"service:{project}:{public_name}"
        for (project, _service), public_name in ALLOWED_COMPOSE_SERVICES.items()
    }
    for key, candidate in value.items():
        if not isinstance(key, str) or (
            re.fullmatch(r"cks:[a-fA-F0-9]{12,64}", key) is None
            and key not in allowed_service_keys
        ):
            continue
        normalized = normalize_private_container_state(candidate)
        if normalized:
            result[key] = normalized
    return result


def private_container_counters(stats: Mapping[str, Any] | None) -> dict[str, int]:
    if not isinstance(stats, Mapping):
        return {}
    result: dict[str, int] = {}
    sample_time = parse_iso_timestamp(stats.get("read"))
    if sample_time is not None:
        sample_ms = int(sample_time.timestamp() * 1000)
        if 0 <= sample_ms <= MAX_SAFE_COUNTER:
            result["sampleAtUnixMs"] = sample_ms
    cpu = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), Mapping) else {}
    throttle = cpu.get("throttling_data") if isinstance(cpu.get("throttling_data"), Mapping) else {}
    sources = {
        "cpuPeriods": throttle.get("periods"),
        "cpuThrottledPeriods": throttle.get("throttled_periods"),
        "cpuThrottledTimeNanoseconds": throttle.get("throttled_time"),
    }
    block = stats.get("blkio_stats") if isinstance(stats.get("blkio_stats"), Mapping) else {}
    sources.update({
        "blockReadBytes": block.get("readBytes"),
        "blockWriteBytes": block.get("writeBytes"),
    })
    networks = stats.get("networks") if isinstance(stats.get("networks"), Mapping) else {}
    rx_errors = bounded_integer(networks.get("rx_errors"), 0, MAX_CONTAINER_IO_BYTES)
    tx_errors = bounded_integer(networks.get("tx_errors"), 0, MAX_CONTAINER_IO_BYTES)
    sources.update({
        "networkRxBytes": networks.get("rx_bytes"),
        "networkTxBytes": networks.get("tx_bytes"),
        "networkErrors": (
            min(MAX_CONTAINER_IO_BYTES, rx_errors + tx_errors)
            if rx_errors is not None and tx_errors is not None else None
        ),
    })
    for field_name, candidate in sources.items():
        parsed = bounded_integer(candidate, 0, MAX_SAFE_COUNTER)
        if parsed is not None:
            result[field_name] = parsed
    return result


def apply_container_image_drift(containers: Sequence[dict[str, Any]]) -> None:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in containers:
        project = row.get("project")
        name = row.get("name")
        if isinstance(project, str) and isinstance(name, str):
            grouped.setdefault((project, name), []).append(row)
    for rows in grouped.values():
        all_known = all(isinstance(row.get("imageDigest"), str) for row in rows)
        digests = {row["imageDigest"] for row in rows if isinstance(row.get("imageDigest"), str)}
        drift = len(digests) > 1 if all_known else None
        for row in rows:
            row["imageDigestDrift"] = drift


def container_from_api(
    raw: Mapping[str, Any], owner: str, stats: Mapping[str, Any] | None,
    previous_state: Any = None, public_name: str | None = None,
    inspect: Mapping[str, Any] | None = None,
    previous_service_state: Any = None,
) -> dict[str, Any]:
    name = safe_container_name(raw)
    if name is None:
        raise ValueError("container is outside the Compose service allowlist")
    if public_name is not None and public_name != name:
        raise ValueError("container Compose labels changed after admission")
    project = CURRENT_CONTAINER_PROJECTS[name]
    raw_state = raw.get("State")
    state = raw_state.lower() if isinstance(raw_state, str) and raw_state.lower() in CONTAINER_STATES else "unknown"
    health, healthcheck_configured = docker_health_details(inspect)

    memory_bytes: int | None = None
    memory_percent: float | None = None
    cpu_percent: float | None = None
    if isinstance(stats, Mapping):
        memory = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
        raw_memory_bytes = finite_number(memory.get("usage"))
        raw_memory_limit = finite_number(memory.get("limit"))
        memory_bytes = (
            int(raw_memory_bytes)
            if raw_memory_bytes is not None and 0 <= raw_memory_bytes <= MAX_CONTAINER_MEMORY_LIMIT_BYTES
            else None
        )
        effective_memory_limit = (
            int(raw_memory_limit)
            if raw_memory_limit is not None and 0 < raw_memory_limit <= MAX_CONTAINER_MEMORY_LIMIT_BYTES
            else None
        )
        memory_percent = (
            round(min(100.0, 100.0 * memory_bytes / effective_memory_limit), 2)
            if memory_bytes is not None and effective_memory_limit is not None
            else None
        )
        cpu_percent = docker_cpu_percent(docker_cpu_state(stats), previous_state)

    restart_count = (
        bounded_integer(inspect.get("RestartCount"), 0, MAX_SAFE_COUNTER)
        if isinstance(inspect, Mapping) else None
    )
    normalized_previous = normalize_private_container_state(previous_state)
    previous_restart_count = normalized_previous.get("restartCount")
    restart_delta = (
        restart_count - previous_restart_count
        if restart_count is not None
        and previous_restart_count is not None
        and restart_count >= previous_restart_count
        else None
    )
    inspect_state = (
        inspect.get("State")
        if isinstance(inspect, Mapping) and isinstance(inspect.get("State"), Mapping)
        else None
    )
    oom_killed = (
        inspect_state.get("OOMKilled")
        if inspect_state is not None and isinstance(inspect_state.get("OOMKilled"), bool)
        else None
    )
    started_at = docker_container_timestamp(inspect_state.get("StartedAt")) if inspect_state else None
    finished_at = docker_container_timestamp(inspect_state.get("FinishedAt")) if inspect_state else None
    memory_limit, cpu_limit, pid_limit = docker_resource_limits(inspect)

    pid_count: int | None = None
    cpu_throttled_percent: float | None = None
    cpu_throttled_periods: int | None = None
    cpu_throttled_seconds: float | None = None
    cpu_throttled_time_nanoseconds: int | None = None
    block_read_bytes: int | None = None
    block_write_bytes: int | None = None
    network_rx_bytes: int | None = None
    network_tx_bytes: int | None = None
    network_errors: int | None = None
    sample_at_unix_ms: int | None = None
    if isinstance(stats, Mapping):
        raw_pids = stats.get("pids_stats") if isinstance(stats.get("pids_stats"), Mapping) else {}
        pid_count = bounded_integer(raw_pids.get("current"), 0, MAX_CONTAINER_PID_LIMIT)
        raw_cpu = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), Mapping) else {}
        throttle = raw_cpu.get("throttling_data") if isinstance(raw_cpu.get("throttling_data"), Mapping) else {}
        throttled = bounded_integer(throttle.get("throttled_periods"), 0, MAX_SAFE_COUNTER)
        throttled_time = bounded_integer(throttle.get("throttled_time"), 0, MAX_SAFE_COUNTER)
        cpu_throttled_time_nanoseconds = throttled_time
        cpu_throttled_periods = throttled
        cpu_throttled_seconds = (
            round(throttled_time / 1_000_000_000, 6) if throttled_time is not None else None
        )
        raw_block = stats.get("blkio_stats") if isinstance(stats.get("blkio_stats"), Mapping) else {}
        block_read_bytes = bounded_integer(raw_block.get("readBytes"), 0, MAX_CONTAINER_IO_BYTES)
        block_write_bytes = bounded_integer(raw_block.get("writeBytes"), 0, MAX_CONTAINER_IO_BYTES)
        raw_networks = stats.get("networks") if isinstance(stats.get("networks"), Mapping) else {}
        network_rx_bytes = bounded_integer(raw_networks.get("rx_bytes"), 0, MAX_CONTAINER_IO_BYTES)
        network_tx_bytes = bounded_integer(raw_networks.get("tx_bytes"), 0, MAX_CONTAINER_IO_BYTES)
        network_rx_errors = bounded_integer(raw_networks.get("rx_errors"), 0, MAX_CONTAINER_IO_BYTES)
        network_tx_errors = bounded_integer(raw_networks.get("tx_errors"), 0, MAX_CONTAINER_IO_BYTES)
        if network_rx_errors is not None and network_tx_errors is not None:
            network_errors = min(MAX_CONTAINER_IO_BYTES, network_rx_errors + network_tx_errors)
        sample_time = parse_iso_timestamp(stats.get("read"))
        if sample_time is not None:
            sample_at_unix_ms = int(sample_time.timestamp() * 1000)
    previous_sample_ms = bounded_integer(normalized_previous.get("sampleAtUnixMs"), 0, MAX_SAFE_COUNTER)
    elapsed_seconds = (
        (sample_at_unix_ms - previous_sample_ms) / 1000
        if sample_at_unix_ms is not None
        and previous_sample_ms is not None
        and 0 < sample_at_unix_ms - previous_sample_ms <= 86_400_000
        else None
    )
    previous_throttled_time = bounded_integer(
        normalized_previous.get("cpuThrottledTimeNanoseconds"), 0, MAX_SAFE_COUNTER
    )
    if (
        cpu_throttled_time_nanoseconds is not None
        and previous_throttled_time is not None
        and cpu_throttled_time_nanoseconds >= previous_throttled_time
        and elapsed_seconds is not None
    ):
        throttled_delta_seconds = (
            cpu_throttled_time_nanoseconds - previous_throttled_time
        ) / 1_000_000_000
        cpu_throttled_percent = round(min(
            100.0,
            100.0 * throttled_delta_seconds / elapsed_seconds,
        ), 2)
    block_read_rate = _container_counter_rate(
        block_read_bytes, normalized_previous.get("blockReadBytes"), elapsed_seconds
    )
    block_write_rate = _container_counter_rate(
        block_write_bytes, normalized_previous.get("blockWriteBytes"), elapsed_seconds
    )
    network_rx_rate = _container_counter_rate(
        network_rx_bytes, normalized_previous.get("networkRxBytes"), elapsed_seconds
    )
    network_tx_rate = _container_counter_rate(
        network_tx_bytes, normalized_previous.get("networkTxBytes"), elapsed_seconds
    )
    network_error_rate = _container_counter_rate(
        network_errors, normalized_previous.get("networkErrors"), elapsed_seconds
    )

    mount_summary = (
        inspect.get("MountSummary")
        if isinstance(inspect, Mapping) and isinstance(inspect.get("MountSummary"), Mapping)
        else {}
    )
    network_summary = (
        inspect.get("NetworkSettings")
        if isinstance(inspect, Mapping) and isinstance(inspect.get("NetworkSettings"), Mapping)
        else {}
    )
    security = docker_security_details(inspect)
    image_name, image_tag, image_digest, digest_source, uses_latest, image_fingerprint = (
        docker_image_details(inspect)
    )
    normalized_service_previous = normalize_private_container_state(previous_service_state)
    previous_digest = normalized_service_previous.get("imageDigest")
    previous_fingerprint = normalized_service_previous.get("imageReferenceFingerprint")
    image_digest_changed = (
        image_digest != previous_digest
        if image_digest is not None
        and isinstance(previous_digest, str)
        and image_fingerprint is not None
        and previous_fingerprint == image_fingerprint
        else None
    )
    writable_layer_bytes = bounded_integer(raw.get("SizeRw"), 0, MAX_CONTAINER_IO_BYTES)

    return {
        "name": name,
        "project": project,
        "owner": "cks" if owner == "cks" else "unknown",
        "state": state,
        "health": health,
        "healthcheckConfigured": healthcheck_configured,
        "cpuPercent": cpu_percent,
        "memoryBytes": memory_bytes,
        "memoryPercent": memory_percent,
        "memoryLimitBytes": memory_limit,
        "cpuLimitCores": cpu_limit,
        "pidLimit": pid_limit,
        "restartCount": restart_count,
        "restartCountDelta": restart_delta,
        "oomKilled": oom_killed,
        "startedAt": started_at,
        "finishedAt": finished_at,
        "instanceId": opaque_container_instance_id(raw.get("Id")),
        "pidCount": pid_count,
        "cpuThrottledPercent": cpu_throttled_percent,
        "cpuThrottledPeriods": cpu_throttled_periods,
        "cpuThrottledSeconds": cpu_throttled_seconds,
        "blockReadBytes": block_read_bytes,
        "blockWriteBytes": block_write_bytes,
        "blockReadBytesPerSecond": block_read_rate,
        "blockWriteBytesPerSecond": block_write_rate,
        "networkRxBytes": network_rx_bytes,
        "networkTxBytes": network_tx_bytes,
        "networkRxBytesPerSecond": network_rx_rate,
        "networkTxBytesPerSecond": network_tx_rate,
        "networkErrors": network_errors,
        "networkErrorsPerSecond": network_error_rate,
        "writableLayerBytes": writable_layer_bytes,
        "volumeCount": bounded_integer(mount_summary.get("volumeCount"), 0, MAX_CONTAINER_MOUNT_COUNT),
        "bindMountCount": bounded_integer(mount_summary.get("bindMountCount"), 0, MAX_CONTAINER_MOUNT_COUNT),
        "tmpfsMountCount": bounded_integer(mount_summary.get("tmpfsMountCount"), 0, MAX_CONTAINER_MOUNT_COUNT),
        "networkAttachmentCount": bounded_integer(network_summary.get("NetworkCount"), 0, MAX_CONTAINER_MOUNT_COUNT),
        "publishedPortCount": bounded_integer(network_summary.get("PublishedPortCount"), 0, MAX_CONTAINER_PORT_COUNT),
        "privileged": security["privileged"],
        "hostPid": security["hostPid"],
        "hostIpc": security["hostIpc"],
        "hostNetwork": security["hostNetwork"],
        "dockerSocketMounted": security["dockerSocketMounted"],
        "sensitiveBindMounted": security["sensitiveBindMounted"],
        "writableSensitiveBindMounted": security["writableSensitiveBindMounted"],
        "rootUser": security["rootUser"],
        "readOnlyRootFilesystem": security["readOnlyRootFilesystem"],
        "addedCapabilityCount": security["addedCapabilityCount"],
        "dangerousCapabilityCount": security["dangerousCapabilityCount"],
        "excessiveCapabilities": security["excessiveCapabilities"],
        "imageName": image_name,
        "imageTag": image_tag,
        "imageDigest": image_digest,
        "imageDigestSource": digest_source,
        "usesLatestTag": uses_latest,
        "imageDigestDrift": False if image_digest is not None else None,
        "imageDigestChanged": image_digest_changed,
    }


def collect_containers(
    sockets: Mapping[str, Path], curl: str, timeout: float, previous_cpu: Any = None
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int | str]]]:
    sockets = {"cks": sockets["cks"]} if isinstance(sockets.get("cks"), Path) else {}
    if not sockets:
        raise ContainerSourceUnavailable("cks container telemetry source unavailable")
    containers: list[dict[str, Any]] = []
    deadline = _monotonic() + MAX_DOCKER_COLLECTION_SECONDS
    entries: list[tuple[str, Path, Mapping[str, Any], str]] = []
    seen_container_ids: set[str] = set()
    # Every list request is constrained to one reviewed Compose project. Run
    # those independent bounded queries concurrently so the 11-project allowlist
    # cannot multiply the per-request timeout past the exporter service budget.
    for owner, socket_path in sockets.items():
        list_remaining = max(0.0, deadline - _monotonic())
        if list_remaining < 0.25:
            raise ContainerSourceUnavailable("cks container telemetry source deadline exceeded")
        request_timeout = min(timeout, list_remaining)
        lists_by_project: dict[str, Any] = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(MAX_DOCKER_DETAIL_WORKERS, len(ALLOWED_COMPOSE_PROJECTS)),
            thread_name_prefix="docker-list",
        ) as executor:
            list_futures = {
                executor.submit(
                    docker_get,
                    socket_path,
                    compose_project_list_path(project),
                    curl,
                    request_timeout,
                ): project
                for project in ALLOWED_COMPOSE_PROJECTS
            }
            done, pending = concurrent.futures.wait(list_futures, timeout=list_remaining)
            for future in pending:
                future.cancel()
            if pending:
                raise ContainerSourceUnavailable("cks container telemetry source deadline exceeded")
            for future in done:
                project = list_futures[future]
                try:
                    response = future.result()
                except PermissionError:
                    raise
                except Exception:
                    response = None
                if not isinstance(response, list):
                    lists_by_project[project] = None
                    continue
                if len(response) > 200:
                    raise RuntimeError("cks container telemetry project response exceeded its limit")
                reduced_list: list[dict[str, Any]] = []
                for raw in response:
                    if not isinstance(raw, dict):
                        raise RuntimeError("cks container telemetry project response is malformed")
                    public_name = safe_container_name(raw, project)
                    if public_name is None:
                        continue
                    container_id = raw.get("Id")
                    if not isinstance(container_id, str) or re.fullmatch(
                        r"[a-fA-F0-9]{12,64}", container_id
                    ) is None:
                        raise RuntimeError("cks container telemetry workload has an invalid ID")
                    labels = raw.get("Labels")
                    service = labels.get("com.docker.compose.service") if isinstance(labels, Mapping) else None
                    reduced_list.append({
                        "Id": container_id,
                        "Labels": {
                            "com.docker.compose.project": project,
                            "com.docker.compose.service": service,
                        },
                        "State": raw.get("State") if isinstance(raw.get("State"), str) else "unknown",
                        "SizeRw": bounded_integer(raw.get("SizeRw"), 0, MAX_CONTAINER_IO_BYTES),
                    })
                lists_by_project[project] = reduced_list
            # Drop Future-held raw Docker responses (including labels, image,
            # command and mounts) before scheduling inspect/stats requests.
            done.clear()
            list_futures.clear()
            future = None
            response = None
            raw = None

        # An unavailable query fails the whole export so callers retain the last
        # complete reduced snapshot instead of publishing a partial count.
        for project in ALLOWED_COMPOSE_PROJECTS:
            raw_list = lists_by_project.get(project)
            if not isinstance(raw_list, list):
                raise ContainerSourceUnavailable("cks container telemetry source unavailable")
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
    inspect_candidates: list[tuple[int, Path, str, str]] = []
    for index, (owner, socket_path, raw, _public_name) in enumerate(entries):
        container_id = str(raw.get("Id", ""))
        state_key = f"{owner}:{container_id}"
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}:[a-fA-F0-9]{12,64}", state_key):
            listed_keys.append(state_key)
            if len(inspect_candidates) < MAX_DOCKER_INSPECT_REQUESTS:
                inspect_candidates.append((index, socket_path, container_id, state_key))
        if (
            raw.get("State") == "running"
            and re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id)
            and len(stats_candidates) < MAX_DOCKER_STATS_REQUESTS
        ):
            stats_candidates.append((index, socket_path, container_id, state_key))

    stats_by_index: dict[int, Mapping[str, Any]] = {}
    inspect_by_index: dict[int, Mapping[str, Any]] = {}
    remaining = max(0.0, deadline - _monotonic())
    detail_request_count = len(inspect_candidates) + len(stats_candidates)
    if detail_request_count and remaining >= 0.25:
        detail_timeout = min(timeout, remaining)
        worker_count = min(MAX_DOCKER_DETAIL_WORKERS, detail_request_count)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="docker-detail"
        ) as executor:
            futures: dict[concurrent.futures.Future[Any], tuple[str, int]] = {}
            # Submit inspect first: lifecycle/health/limit truth has priority over
            # optional point-in-time stats when the shared deadline is nearly spent.
            for index, socket_path, container_id, _state_key in inspect_candidates:
                future = executor.submit(
                    docker_get,
                    socket_path,
                    f"/v1.41/containers/{container_id}/json",
                    curl,
                    detail_timeout,
                )
                futures[future] = ("inspect", index)
            for index, socket_path, container_id, _state_key in stats_candidates:
                future = executor.submit(
                    docker_get,
                    socket_path,
                    f"/v1.41/containers/{container_id}/stats?stream=false&one-shot=true",
                    curl,
                    detail_timeout,
                )
                futures[future] = ("stats", index)
            done, pending = concurrent.futures.wait(futures, timeout=remaining)
            for future in pending:
                future.cancel()
            for future in done:
                try:
                    response = future.result()
                except Exception:
                    continue
                if not isinstance(response, dict):
                    continue
                kind, index = futures[future]
                if kind == "inspect":
                    _owner, _socket_path, raw, public_name = entries[index]
                    requested_id = str(raw.get("Id", ""))
                    validated = validated_container_inspect(
                        response, requested_id, public_name
                    )
                    if validated is not None:
                        inspect_by_index[index] = reduce_container_inspect(validated)
                else:
                    stats_by_index[index] = reduce_container_stats(response)
            done.clear()
            futures.clear()
            future = None
            response = None

    next_cpu_state: dict[str, dict[str, int | str]] = {}
    # Retain only validated private counters for containers still listed. This
    # lets a temporary inspect/stats miss bridge to the next observation without
    # admitting arbitrary state-file keys or exposing the raw-ID map publicly.
    for state_key in listed_keys[:200]:
        normalized_prior = normalize_private_container_state(previous_state.get(state_key))
        if normalized_prior:
            next_cpu_state[state_key] = normalized_prior

    retained_keys = set(listed_keys[:200])
    for index, (owner, _socket_path, raw, public_name) in enumerate(entries):
        stats = stats_by_index.get(index)
        container_id = str(raw.get("Id", ""))
        inspect = inspect_by_index.get(index)
        state_key = f"{owner}:{container_id}"
        service_key = f"service:{CURRENT_CONTAINER_PROJECTS[public_name]}:{public_name}"
        current_cpu = docker_cpu_state(stats) if isinstance(stats, Mapping) else None
        reduced = container_from_api(
            raw, owner, stats if isinstance(stats, dict) else None,
            previous_state.get(state_key), public_name, inspect,
            previous_state.get(service_key),
        )
        containers.append(reduced)
        if state_key in retained_keys:
            next_entry = dict(next_cpu_state.get(state_key, {}))
            if current_cpu is not None:
                next_entry.update(current_cpu)
            next_entry.update(private_container_counters(stats))
            if isinstance(reduced.get("restartCount"), int):
                next_entry["restartCount"] = reduced["restartCount"]
            if next_entry:
                next_cpu_state[state_key] = next_entry
    service_rows: dict[str, list[dict[str, Any]]] = {}
    for row in containers:
        service_key = f"service:{row['project']}:{row['name']}"
        service_rows.setdefault(service_key, []).append(row)
    apply_container_image_drift(containers)
    for service_key, rows in service_rows.items():
        digests = {
            row["imageDigest"] for row in rows if isinstance(row.get("imageDigest"), str)
        }
        all_digests_known = len(digests) > 0 and len(digests) == 1 and all(
            isinstance(row.get("imageDigest"), str) for row in rows
        )
        fingerprints: set[str] = set()
        for index, row in enumerate(rows):
            # Recompute only from already reduced inspect data; raw image refs
            # and container IDs are never persisted in the public snapshot.
            matching_index = next((
                candidate_index for candidate_index, (_owner, _socket, _raw, candidate_name)
                in enumerate(entries)
                if candidate_name == row["name"]
                and opaque_container_instance_id(_raw.get("Id")) == row["instanceId"]
            ), None)
            if matching_index is None:
                continue
            details = docker_image_details(inspect_by_index.get(matching_index))
            if isinstance(details[5], str):
                fingerprints.add(details[5])
        if all_digests_known and len(fingerprints) == 1:
            next_cpu_state[service_key] = {
                "imageDigest": next(iter(digests)),
                "imageReferenceFingerprint": next(iter(fingerprints)),
            }
    return sorted(containers, key=lambda item: (item["owner"], item["name"])), next_cpu_state


def docker_event_request_path(since: dt.datetime, until: dt.datetime) -> str:
    filters = json.dumps(
        {
            "type": ["container"],
            "label": [
                f"com.docker.compose.project={project}"
                for project in ALLOWED_COMPOSE_PROJECTS
            ],
        },
        separators=(",", ":"),
    )
    return "/v1.41/events?" + urllib.parse.urlencode({
        "since": max(0, int(since.timestamp())),
        "until": max(0, int(until.timestamp())),
        "filters": filters,
    })


def docker_get_events(socket_path: Path, request_path: str, curl: str, timeout: float) -> bytes | None:
    if not request_path.startswith("/v1.41/events?") or len(request_path) > 8192:
        raise ValueError("invalid Docker event request")
    try:
        metadata = socket_path.stat()
    except PermissionError:
        raise
    except OSError:
        return None
    if not stat.S_ISSOCK(metadata.st_mode):
        return None
    try:
        completed = subprocess.run(
            [
                curl, "--silent", "--show-error", "--fail", "--no-buffer",
                "--max-time", str(timeout), "--max-filesize", str(MAX_DOCKER_EVENT_RESPONSE_BYTES),
                "--unix-socket", str(socket_path), "http://localhost" + request_path,
            ],
            capture_output=True,
            timeout=timeout + 0.5,
            check=False,
        )
    except PermissionError:
        raise
    except (OSError, subprocess.SubprocessError):
        return None
    stdout = completed.stdout if isinstance(completed.stdout, bytes) else bytes(str(completed.stdout), "utf-8")
    stderr = completed.stderr if isinstance(completed.stderr, bytes) else bytes(str(completed.stderr), "utf-8")
    if completed.returncode != 0:
        bounded_error = stderr[:256].lower()
        if b"permission denied" in bounded_error or b"403" in bounded_error:
            raise PermissionError("container event source denied access")
        return None
    if len(stdout) > MAX_DOCKER_EVENT_RESPONSE_BYTES:
        return None
    return stdout


def normalize_docker_event(value: Any, not_after: dt.datetime) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    raw_type = value.get("Type")
    raw_action = value.get("Action")
    actor = value.get("Actor") if isinstance(value.get("Actor"), Mapping) else {}
    attributes = actor.get("Attributes") if isinstance(actor.get("Attributes"), Mapping) else {}
    container_id = actor.get("ID")
    if not isinstance(container_id, str):
        container_id = value.get("id")
    instance_id = opaque_container_instance_id(container_id)
    project = attributes.get("com.docker.compose.project")
    service = attributes.get("com.docker.compose.service")
    public_name = (
        ALLOWED_COMPOSE_SERVICES.get((project, service))
        if isinstance(project, str) and isinstance(service, str) else None
    )
    if raw_type != "container" or instance_id is None or public_name is None or not isinstance(raw_action, str):
        return None
    health_status: str | None = None
    action = raw_action.lower()
    if action.startswith("health_status:"):
        candidate = action.split(":", 1)[1].strip()
        if candidate not in DOCKER_EVENT_HEALTH_STATES:
            return None
        action = "health_status"
        health_status = candidate
    elif action == "health_status":
        candidate = attributes.get("healthStatus")
        if candidate not in DOCKER_EVENT_HEALTH_STATES:
            return None
        health_status = str(candidate)
    if action not in DOCKER_EVENT_ACTIONS:
        return None
    time_nano = bounded_integer(value.get("timeNano"), 1, (1 << 63) - 1)
    raw_time = bounded_integer(value.get("time"), 1, MAX_SAFE_COUNTER)
    try:
        occurred = (
            dt.datetime.fromtimestamp(time_nano / 1_000_000_000, tz=dt.timezone.utc)
            if time_nano is not None
            else dt.datetime.fromtimestamp(raw_time, tz=dt.timezone.utc)
            if raw_time is not None else None
        )
    except (OSError, OverflowError, ValueError):
        return None
    if occurred is None or occurred > not_after + dt.timedelta(seconds=60):
        return None
    exit_code: int | None = None
    raw_exit = attributes.get("exitCode")
    if isinstance(raw_exit, str) and re.fullmatch(r"[0-9]{1,10}", raw_exit):
        candidate_exit = int(raw_exit)
        exit_code = candidate_exit if candidate_exit <= 2_147_483_647 else None
    event_id = hashlib.sha256(
        b"monitor-docker-event-v1\x00"
        + str(time_nano if time_nano is not None else raw_time).encode("ascii")
        + b"\x00" + str(container_id).lower().encode("ascii")
        + b"\x00" + action.encode("ascii")
        + b"\x00" + (health_status or "").encode("ascii")
    ).hexdigest()[:32]
    return {
        "id": event_id,
        "occurredAt": iso_event_timestamp(occurred),
        "action": action,
        "containerName": public_name,
        "project": project,
        "instanceId": instance_id,
        "exitCode": exit_code,
        "healthStatus": health_status,
    }


def normalize_public_docker_event(value: Any, not_after: dt.datetime) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != set(DOCKER_EVENT_FIELDS):
        return None
    event_id = value.get("id")
    occurred = parse_iso_timestamp(value.get("occurredAt"))
    action = value.get("action")
    name = value.get("containerName")
    project = value.get("project")
    instance_id = value.get("instanceId")
    exit_code = value.get("exitCode")
    health = value.get("healthStatus")
    if (
        not isinstance(event_id, str) or re.fullmatch(r"[a-f0-9]{32}", event_id) is None
        or occurred is None or occurred > not_after + dt.timedelta(seconds=60)
        or action not in DOCKER_EVENT_ACTIONS
        or name not in CURRENT_CONTAINER_NAMES
        or project != CURRENT_CONTAINER_PROJECTS.get(str(name))
        or not isinstance(instance_id, str) or re.fullmatch(r"[a-f0-9]{32}", instance_id) is None
        or (exit_code is not None and bounded_integer(exit_code, 0, 2_147_483_647) is None)
        or (health is not None and health not in DOCKER_EVENT_HEALTH_STATES)
        or (action == "health_status") != (health is not None)
    ):
        return None
    return {
        "id": event_id,
        "occurredAt": iso_event_timestamp(occurred),
        "action": action,
        "containerName": name,
        "project": project,
        "instanceId": instance_id,
        "exitCode": exit_code,
        "healthStatus": health,
    }


def normalize_docker_event_state(value: Any, now: dt.datetime) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else {}
    status = source.get("status")
    cursor = parse_iso_timestamp(source.get("cursorAt"))
    observed = parse_iso_timestamp(source.get("observedAt"))
    reconnect_count = bounded_integer(source.get("reconnectCount"), 0, MAX_SAFE_COUNTER) or 0
    gap_count = bounded_integer(source.get("gapCount"), 0, MAX_SAFE_COUNTER) or 0
    raw_events = source.get("events") if isinstance(source.get("events"), list) else []
    events_by_id: dict[str, dict[str, Any]] = {}
    for candidate in raw_events[-MAX_DOCKER_EVENTS:]:
        normalized = normalize_public_docker_event(candidate, now)
        if normalized is not None:
            events_by_id[normalized["id"]] = normalized
    return {
        "status": status if status in DOCKER_EVENT_COLLECTION_STATUSES else "unavailable",
        "observedAt": iso_timestamp(observed) if observed is not None and observed <= now + dt.timedelta(seconds=60) else None,
        "cursorAt": iso_timestamp(cursor) if cursor is not None and cursor <= now + dt.timedelta(seconds=60) else None,
        "reconnectCount": reconnect_count,
        "gapCount": gap_count,
        "gapDetected": source.get("gapDetected") is True,
        "events": sorted(events_by_id.values(), key=lambda item: (item["occurredAt"], item["id"]))[-MAX_DOCKER_EVENTS:],
    }


def docker_event_failure_state(
    previous: Any,
    now: dt.datetime,
    status: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prior = normalize_docker_event_state(previous, now)
    cursor = parse_iso_timestamp(prior["cursorAt"])
    gap = cursor is None or (now - cursor).total_seconds() > MAX_DOCKER_EVENT_REPLAY_SECONDS
    gap_count = min(MAX_SAFE_COUNTER, prior["gapCount"] + (1 if gap and not prior["gapDetected"] else 0))
    public = {
        "status": status,
        "observedAt": prior["observedAt"],
        "cursorAt": prior["cursorAt"],
        "reconnectCount": prior["reconnectCount"],
        "gapCount": gap_count,
        "gapDetected": gap,
        "logCollectionStatus": "unsupported",
    }
    private = {**public, "events": prior["events"]}
    return public, private


def collect_docker_events(
    socket_path: Path,
    curl: str,
    timeout: float,
    previous: Any,
    now: dt.datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    prior = normalize_docker_event_state(previous, now)
    cursor = parse_iso_timestamp(prior["cursorAt"])
    reconnecting = prior["status"] in {"unavailable", "permission-denied"} and cursor is not None
    # Docker does not expose a daemon boot epoch. After a failed poll, replay
    # is attempted but continuity cannot be proved across a daemon restart, so
    # the recovery snapshot explicitly carries a possible gap.
    gap = (
        cursor is None
        or cursor > now
        or (now - cursor).total_seconds() > MAX_DOCKER_EVENT_REPLAY_SECONDS
        or reconnecting
    )
    since = max(
        now - dt.timedelta(seconds=MAX_DOCKER_EVENT_REPLAY_SECONDS),
        (cursor - dt.timedelta(seconds=1)) if cursor is not None and cursor <= now else now,
    )
    request_path = docker_event_request_path(since, now)
    try:
        payload = docker_get_events(socket_path, request_path, curl, timeout)
    except PermissionError:
        public, private = docker_event_failure_state(previous, now, "permission-denied")
        return public, private["events"], private
    if payload is None:
        public, private = docker_event_failure_state(previous, now, "unavailable")
        return public, private["events"], private

    lines = payload.splitlines()
    if len(lines) > MAX_DOCKER_EVENT_LINES or any(len(line) > MAX_DOCKER_EVENT_LINE_BYTES for line in lines):
        public, private = docker_event_failure_state(previous, now, "unavailable")
        return public, private["events"], private
    events_by_id = {event["id"]: event for event in prior["events"]}
    for line in lines:
        if not line.strip():
            continue
        try:
            decoded = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            public, private = docker_event_failure_state(previous, now, "unavailable")
            return public, private["events"], private
        normalized = normalize_docker_event(decoded, now)
        if normalized is not None:
            events_by_id[normalized["id"]] = normalized
    events = sorted(events_by_id.values(), key=lambda item: (item["occurredAt"], item["id"]))[-MAX_DOCKER_EVENTS:]
    reconnect_count = min(MAX_SAFE_COUNTER, prior["reconnectCount"] + (1 if reconnecting else 0))
    gap_count = min(MAX_SAFE_COUNTER, prior["gapCount"] + (1 if gap and not prior["gapDetected"] else 0))
    now_text = iso_timestamp(now)
    public = {
        "status": "gap" if gap else "fresh",
        "observedAt": now_text,
        "cursorAt": now_text,
        "reconnectCount": reconnect_count,
        "gapCount": gap_count,
        "gapDetected": gap,
        "logCollectionStatus": "unsupported",
    }
    private = {**public, "events": events}
    return public, events, private


def normalize_container_values(
    values: Any,
    not_after: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    """Reduce legacy or current rows to the exact bounded public contract."""
    if not isinstance(values, list) or len(values) > 200:
        raise ValueError("container telemetry snapshot has an invalid workload list")

    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("container telemetry workload has unexpected fields")
        fields = set(value)
        legacy = fields == set(LEGACY_CONTAINER_FIELDS)
        v2 = fields == set(CONTAINER_V2_FIELDS)
        v3_legacy = fields == set(CONTAINER_V3_LEGACY_FIELDS)
        v3 = fields == set(CONTAINER_FIELDS) or v3_legacy
        if not legacy and not v2 and not v3:
            raise ValueError("container telemetry workload has unexpected fields")
        name = value.get("name")
        state = value.get("state")
        source_health = value.get("health")
        if (
            name not in SAFE_CONTAINER_NAMES
            or value.get("owner") != "cks"
            or state not in CONTAINER_STATES
            or (source_health is not None and source_health not in CONTAINER_HEALTH_STATES)
        ):
            raise ValueError("container telemetry workload is outside the allowlist")
        # Legacy health was inferred from ``docker ps`` presentation text. Keep
        # the row as last-known evidence, but do not upgrade that inference into
        # the new authoritative inspect-backed health contract.
        health = None if legacy else source_health
        # A seven-field snapshot predates authoritative Compose provenance.
        # Overlapping app/service names make project inference ambiguous, so
        # migrate it as unknown and preserve that null in subsequent last-known
        # v2 snapshots. Fresh observations always carry the fixed allowlist value.
        project = None if legacy else value.get("project")
        expected_project = CURRENT_CONTAINER_PROJECTS.get(str(name))
        if (
            (project is not None and project != expected_project)
            or (project is not None and project not in ALLOWED_COMPOSE_PROJECTS)
        ):
            raise ValueError("container telemetry workload has an invalid Compose project")

        cpu_percent = normalized_bounded_number(value.get("cpuPercent"), 0, MAX_CONTAINER_CPU_PERCENT)
        memory_bytes = normalized_bounded_number(
            value.get("memoryBytes"), 0, MAX_CONTAINER_MEMORY_LIMIT_BYTES
        )
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

        healthcheck_configured = None if legacy else value.get("healthcheckConfigured")
        oom_killed = None if legacy else value.get("oomKilled")
        if healthcheck_configured is not None and not isinstance(healthcheck_configured, bool):
            raise ValueError("container telemetry workload has an invalid healthcheck state")
        if oom_killed is not None and not isinstance(oom_killed, bool):
            raise ValueError("container telemetry workload has an invalid OOM state")
        if healthcheck_configured is False and health != "none":
            raise ValueError("container telemetry workload has inconsistent health fields")
        if healthcheck_configured is True and health in {"none", "unknown"}:
            raise ValueError("container telemetry workload has inconsistent health fields")
        if healthcheck_configured is None and health is not None:
            raise ValueError("container telemetry workload has unverified health")

        restart_count = None if legacy else value.get("restartCount")
        restart_delta = None if legacy else value.get("restartCountDelta")
        memory_limit = None if legacy else value.get("memoryLimitBytes")
        pid_limit = None if legacy else value.get("pidLimit")
        for field_name, candidate, maximum in (
            ("restart count", restart_count, MAX_SAFE_COUNTER),
            ("restart delta", restart_delta, MAX_SAFE_COUNTER),
            ("memory limit", memory_limit, MAX_CONTAINER_MEMORY_LIMIT_BYTES),
            ("PID limit", pid_limit, MAX_CONTAINER_PID_LIMIT),
        ):
            if candidate is not None and bounded_integer(candidate, 0, maximum) is None:
                raise ValueError(f"container telemetry workload has an invalid {field_name}")
        if restart_delta is not None and (restart_count is None or restart_delta > restart_count):
            raise ValueError("container telemetry workload has an inconsistent restart delta")

        cpu_limit_source = None if legacy else value.get("cpuLimitCores")
        cpu_limit = normalized_bounded_number(
            cpu_limit_source, 0, MAX_CONTAINER_CPU_LIMIT_CORES
        )
        if cpu_limit_source is not None and cpu_limit is None:
            raise ValueError("container telemetry workload has an invalid CPU limit")
        if cpu_limit is not None:
            cpu_limit = round(float(cpu_limit), 6)

        normalized_times: dict[str, str | None] = {}
        for field_name in ("startedAt", "finishedAt"):
            source = None if legacy else value.get(field_name)
            parsed = parse_iso_timestamp(source) if source is not None else None
            if source is not None and (
                parsed is None
                or parsed <= dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
                or (not_after is not None and parsed > not_after)
            ):
                raise ValueError("container telemetry workload has an invalid lifecycle timestamp")
            normalized_times[field_name] = iso_event_timestamp(parsed) if parsed is not None else None
        normalized: dict[str, Any] = {
            "name": name,
            "project": project,
            "owner": "cks",
            "state": state,
            "health": health,
            "healthcheckConfigured": healthcheck_configured,
            "cpuPercent": cpu_percent,
            "memoryBytes": memory_bytes,
            "memoryPercent": memory_percent,
            "memoryLimitBytes": memory_limit,
            "cpuLimitCores": cpu_limit,
            "pidLimit": pid_limit,
            "restartCount": restart_count,
            "restartCountDelta": restart_delta,
            "oomKilled": oom_killed,
            "startedAt": normalized_times["startedAt"],
            "finishedAt": normalized_times["finishedAt"],
        }
        if v3:
            def optional_integer(field_name: str, maximum: int) -> int | None:
                source = value.get(field_name)
                parsed = bounded_integer(source, 0, maximum)
                if source is not None and parsed is None:
                    raise ValueError(f"container telemetry workload has an invalid {field_name}")
                return parsed

            def optional_number(field_name: str, maximum: float) -> float | None:
                source = value.get(field_name)
                parsed = normalized_bounded_number(source, 0, maximum)
                if source is not None and parsed is None:
                    raise ValueError(f"container telemetry workload has an invalid {field_name}")
                return parsed

            def optional_boolean(field_name: str) -> bool | None:
                source = value.get(field_name)
                if source is not None and not isinstance(source, bool):
                    raise ValueError(f"container telemetry workload has an invalid {field_name}")
                return source

            instance_id = value.get("instanceId")
            if not isinstance(instance_id, str) or re.fullmatch(r"[a-f0-9]{32}", instance_id) is None:
                raise ValueError("container telemetry workload has an invalid instance ID")
            integer_fields = {
                "pidCount": MAX_CONTAINER_PID_LIMIT,
                "cpuThrottledPeriods": MAX_SAFE_COUNTER,
                "blockReadBytes": MAX_CONTAINER_IO_BYTES,
                "blockWriteBytes": MAX_CONTAINER_IO_BYTES,
                "networkRxBytes": MAX_CONTAINER_IO_BYTES,
                "networkTxBytes": MAX_CONTAINER_IO_BYTES,
                "networkErrors": MAX_CONTAINER_IO_BYTES,
                "writableLayerBytes": MAX_CONTAINER_IO_BYTES,
                "volumeCount": MAX_CONTAINER_MOUNT_COUNT,
                "bindMountCount": MAX_CONTAINER_MOUNT_COUNT,
                "tmpfsMountCount": MAX_CONTAINER_MOUNT_COUNT,
                "networkAttachmentCount": MAX_CONTAINER_MOUNT_COUNT,
                "publishedPortCount": MAX_CONTAINER_PORT_COUNT,
                "addedCapabilityCount": MAX_CONTAINER_CAPABILITY_COUNT,
                "dangerousCapabilityCount": MAX_CONTAINER_CAPABILITY_COUNT,
            }
            number_fields = {
                "cpuThrottledPercent": 100.0,
                "cpuThrottledSeconds": float(MAX_SAFE_COUNTER),
                "blockReadBytesPerSecond": MAX_CONTAINER_IO_RATE,
                "blockWriteBytesPerSecond": MAX_CONTAINER_IO_RATE,
                "networkRxBytesPerSecond": MAX_CONTAINER_IO_RATE,
                "networkTxBytesPerSecond": MAX_CONTAINER_IO_RATE,
                "networkErrorsPerSecond": MAX_CONTAINER_IO_RATE,
            }
            boolean_fields = (
                "privileged", "hostPid", "hostIpc", "hostNetwork", "dockerSocketMounted",
                "sensitiveBindMounted", "writableSensitiveBindMounted", "rootUser", "readOnlyRootFilesystem",
                "excessiveCapabilities", "usesLatestTag", "imageDigestDrift", "imageDigestChanged",
            )
            normalized.update({"instanceId": instance_id})
            normalized.update({
                field_name: optional_integer(field_name, maximum)
                for field_name, maximum in integer_fields.items()
            })
            normalized.update({
                field_name: optional_number(field_name, maximum)
                for field_name, maximum in number_fields.items()
            })
            normalized.update({field_name: optional_boolean(field_name) for field_name in boolean_fields})
            if v3_legacy:
                normalized["writableSensitiveBindMounted"] = (
                    False if normalized["sensitiveBindMounted"] is False else None
                )
            sensitive_bind = normalized["sensitiveBindMounted"]
            writable_sensitive_bind = normalized["writableSensitiveBindMounted"]
            if (
                (sensitive_bind is None and writable_sensitive_bind is not None)
                or (sensitive_bind is False and writable_sensitive_bind is not False)
                or (writable_sensitive_bind is True and sensitive_bind is not True)
            ):
                raise ValueError("container telemetry workload has inconsistent sensitive bind state")
            image_name = value.get("imageName")
            image_tag = value.get("imageTag")
            image_digest = value.get("imageDigest")
            image_digest_source = value.get("imageDigestSource")
            if image_name is not None and (
                not isinstance(image_name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}", image_name) is None
                or image_name.startswith("/") or image_name.endswith("/") or "//" in image_name
            ):
                raise ValueError("container telemetry workload has an invalid image name")
            if image_tag is not None and (
                not isinstance(image_tag, str)
                or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", image_tag) is None
            ):
                raise ValueError("container telemetry workload has an invalid image tag")
            if image_digest is not None and (
                not isinstance(image_digest, str)
                or re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest) is None
            ):
                raise ValueError("container telemetry workload has an invalid image digest")
            if image_digest_source not in {None, "repo-digest", "local-image-id"}:
                raise ValueError("container telemetry workload has an invalid image digest source")
            if (image_digest is None) != (image_digest_source is None):
                raise ValueError("container telemetry workload has inconsistent image digest fields")
            uses_latest = normalized["usesLatestTag"]
            if image_name is None and uses_latest is not None:
                raise ValueError("container telemetry workload has inconsistent latest-tag state")
            if image_name is None and image_tag is not None:
                raise ValueError("container telemetry workload has an image tag without a name")
            if image_name is not None and uses_latest is not (image_tag == "latest"):
                raise ValueError("container telemetry workload has inconsistent latest-tag state")
            if image_digest_source == "repo-digest" and image_name is None:
                raise ValueError("container telemetry workload has an unbound repository digest")
            if image_digest is None and (
                normalized["imageDigestDrift"] is not None
                or normalized["imageDigestChanged"] is not None
            ):
                raise ValueError("container telemetry workload has digest state without a digest")
            if image_digest is not None and normalized["imageDigestDrift"] is None:
                raise ValueError("container telemetry workload is missing replica digest state")
            for total_field, rate_field in (
                ("blockReadBytes", "blockReadBytesPerSecond"),
                ("blockWriteBytes", "blockWriteBytesPerSecond"),
                ("networkRxBytes", "networkRxBytesPerSecond"),
                ("networkTxBytes", "networkTxBytesPerSecond"),
                ("networkErrors", "networkErrorsPerSecond"),
            ):
                if normalized[rate_field] is not None and normalized[total_field] is None:
                    raise ValueError("container telemetry workload has a rate without its counter")
            if (
                normalized["cpuThrottledPercent"] is not None
                and normalized["cpuThrottledPeriods"] is None
            ):
                raise ValueError("container telemetry workload has throttling rate without a counter")
            capability_state = (
                normalized["addedCapabilityCount"],
                normalized["dangerousCapabilityCount"],
                normalized["excessiveCapabilities"],
            )
            if any(candidate is None for candidate in capability_state) and not all(
                candidate is None for candidate in capability_state
            ):
                raise ValueError("container telemetry workload has partial capability state")
            if (
                normalized["dangerousCapabilityCount"] is not None
                and normalized["addedCapabilityCount"] is not None
                and normalized["dangerousCapabilityCount"] > normalized["addedCapabilityCount"]
            ):
                raise ValueError("container telemetry workload has inconsistent capability counts")
            if (
                normalized["addedCapabilityCount"] is not None
                and normalized["dangerousCapabilityCount"] is not None
                and normalized["excessiveCapabilities"]
                is not (
                    normalized["addedCapabilityCount"] > 12
                    or normalized["dangerousCapabilityCount"] > 0
                )
            ):
                raise ValueError("container telemetry workload has inconsistent capability state")
            normalized.update({
                "imageName": image_name,
                "imageTag": image_tag,
                "imageDigest": image_digest,
                "imageDigestSource": image_digest_source,
            })
            # Restore the declared field order after group-wise validation.
            normalized = {field_name: normalized[field_name] for field_name in CONTAINER_FIELDS}
            assert tuple(normalized) == CONTAINER_FIELDS
        else:
            assert tuple(normalized) == CONTAINER_V2_FIELDS
        result.append(normalized)
    return sorted(result, key=lambda item: item["name"])


def normalize_container_collection(
    value: Any,
    generated: dt.datetime,
    now: dt.datetime,
) -> dict[str, str | None]:
    if not isinstance(value, Mapping) or set(value) != {"status", "observedAt"}:
        raise ValueError("container telemetry snapshot has invalid collection status")
    status = value.get("status")
    if status not in CONTAINER_COLLECTION_STATUSES:
        raise ValueError("container telemetry snapshot has invalid collection status")
    observed = parse_iso_timestamp(value.get("observedAt"))
    if value.get("observedAt") is not None and observed is None:
        raise ValueError("container telemetry snapshot has invalid observation timestamp")
    if observed is not None and observed > now + dt.timedelta(seconds=60):
        raise ValueError("container telemetry snapshot has a future observation timestamp")
    if status in {"fresh", "last-known"} and observed is None:
        raise ValueError("container telemetry snapshot is missing its observation timestamp")
    if status == "unavailable" and observed is not None:
        raise ValueError("unavailable container telemetry cannot have an observation timestamp")
    if status == "fresh" and observed != generated:
        raise ValueError("fresh container telemetry timestamps do not match")
    if status == "fresh" and (now - generated).total_seconds() > MAX_CONTAINER_INPUT_AGE_SECONDS:
        status = "last-known"
    return {
        "status": str(status),
        "observedAt": iso_timestamp(observed) if observed is not None else None,
    }


def unavailable_docker_event_collection() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "observedAt": None,
        "cursorAt": None,
        "reconnectCount": 0,
        "gapCount": 0,
        "gapDetected": True,
        "logCollectionStatus": "unsupported",
    }


def normalize_docker_event_collection(
    value: Any,
    generated: dt.datetime,
    now: dt.datetime,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(DOCKER_EVENT_COLLECTION_FIELDS):
        raise ValueError("Docker event collection has unexpected fields")
    status = value.get("status")
    observed = parse_iso_timestamp(value.get("observedAt"))
    cursor = parse_iso_timestamp(value.get("cursorAt"))
    reconnect_count = bounded_integer(value.get("reconnectCount"), 0, MAX_SAFE_COUNTER)
    gap_count = bounded_integer(value.get("gapCount"), 0, MAX_SAFE_COUNTER)
    gap_detected = value.get("gapDetected")
    if (
        status not in DOCKER_EVENT_COLLECTION_STATUSES
        or (value.get("observedAt") is not None and observed is None)
        or (value.get("cursorAt") is not None and cursor is None)
        or reconnect_count is None
        or gap_count is None
        or not isinstance(gap_detected, bool)
        or value.get("logCollectionStatus") != "unsupported"
        or (observed is not None and observed > now + dt.timedelta(seconds=60))
        or (cursor is not None and cursor > now + dt.timedelta(seconds=60))
        or (status in {"fresh", "gap"} and (observed != generated or cursor != generated))
        or (status == "gap" and not gap_detected)
        or (status == "fresh" and gap_detected)
        or ((observed is None) != (cursor is None))
    ):
        raise ValueError("Docker event collection is invalid")
    return {
        "status": status,
        "observedAt": iso_timestamp(observed) if observed is not None else None,
        "cursorAt": iso_timestamp(cursor) if cursor is not None else None,
        "reconnectCount": reconnect_count,
        "gapCount": gap_count,
        "gapDetected": gap_detected,
        "logCollectionStatus": "unsupported",
    }


def load_container_snapshot_document(
    path: Path,
    now: dt.datetime,
    expected_uid: int | None = 1001,
    expected_gid: int | None = 1001,
) -> tuple[list[dict[str, Any]], dict[str, str | None], dict[str, Any], list[dict[str, Any]]]:
    """Validate the unprivileged export before admitting it to root-owned output."""
    try:
        metadata = path.lstat()
    except PermissionError:
        raise
    except OSError as error:
        raise RuntimeError("container telemetry snapshot unavailable") from error
    def valid_metadata(value: os.stat_result) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and (expected_uid is None or value.st_uid == expected_uid)
            and (expected_gid is None or value.st_gid == expected_gid)
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
    if not isinstance(raw, dict) or set(raw) not in (
        {"generatedAt", "containers"},
        {"generatedAt", "containerCollection", "containers"},
        {
            "generatedAt", "containerCollection", "containers",
            "dockerEventCollection", "dockerEvents",
        },
    ):
        raise ValueError("container telemetry snapshot has unexpected fields")
    generated = parse_iso_timestamp(raw.get("generatedAt"))
    if generated is None or generated > now + dt.timedelta(seconds=60):
        raise ValueError("container telemetry snapshot has an invalid generation timestamp")
    containers = normalize_container_values(
        raw.get("containers"), generated + dt.timedelta(seconds=60)
    )
    if "containerCollection" in raw:
        collection = normalize_container_collection(raw["containerCollection"], generated, now)
    else:
        collection = {
            "status": (
                "fresh"
                if (now - generated).total_seconds() <= MAX_CONTAINER_INPUT_AGE_SECONDS
                else "last-known"
            ),
            "observedAt": iso_timestamp(generated),
        }
    if collection["status"] == "unavailable" and containers:
        raise ValueError("unavailable container telemetry cannot contain workloads")
    if collection["observedAt"] is None and containers:
        raise ValueError("container telemetry workloads require an observation timestamp")
    if "dockerEventCollection" in raw:
        event_collection = normalize_docker_event_collection(
            raw["dockerEventCollection"], generated, now
        )
        raw_events = raw.get("dockerEvents")
        if not isinstance(raw_events, list) or len(raw_events) > MAX_DOCKER_EVENTS:
            raise ValueError("Docker event list is invalid")
        docker_events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for candidate in raw_events:
            event = normalize_public_docker_event(candidate, generated)
            if event is None or event["id"] in seen_ids:
                raise ValueError("Docker event list is invalid")
            seen_ids.add(event["id"])
            docker_events.append(event)
        docker_events.sort(key=lambda item: (item["occurredAt"], item["id"]))
        if event_collection["cursorAt"] is None and docker_events:
            raise ValueError("Docker events require a cursor")
    else:
        event_collection = unavailable_docker_event_collection()
        docker_events = []
    return containers, collection, event_collection, docker_events


def load_container_snapshot_state(
    path: Path,
    now: dt.datetime,
    expected_uid: int | None = 1001,
    expected_gid: int | None = 1001,
) -> tuple[list[dict[str, Any]], dict[str, str | None]]:
    containers, collection, _event_collection, _events = load_container_snapshot_document(
        path, now, expected_uid=expected_uid, expected_gid=expected_gid,
    )
    return containers, collection


def load_container_snapshot(path: Path, now: dt.datetime) -> list[dict[str, Any]]:
    """Backward-compatible list-only view of the reduced container snapshot."""
    return load_container_snapshot_state(path, now)[0]


def load_synthetic_probe_document(
    path: Path,
    now: dt.datetime,
    expected_uid: int | None = 1001,
    expected_gid: int | None = 1001,
) -> tuple[dict[str, str | None], list[dict[str, Any]]]:
    """Admit the unprivileged probe result while discarding reviewed URLs.

    The worker pins DNS and performs network I/O.  The root collector only
    validates its fixed evidence document and never receives a general URL
    fetch capability.  Query strings and endpoint paths remain in the private
    worker file and are not copied into the public collector snapshot.
    """

    metadata = path.lstat()

    def valid_metadata(value: os.stat_result) -> bool:
        return (
            stat.S_ISREG(value.st_mode)
            and (expected_uid is None or value.st_uid == expected_uid)
            and (expected_gid is None or value.st_gid == expected_gid)
            and value.st_nlink == 1
            and stat.S_IMODE(value.st_mode) == 0o640
            and 0 < value.st_size <= MAX_SYNTHETIC_INPUT_BYTES
        )

    if not valid_metadata(metadata):
        raise ValueError("synthetic probe result failed file validation")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or not valid_metadata(opened)
        ):
            raise ValueError("synthetic probe result changed during validation")
        chunks: list[bytes] = []
        remaining = MAX_SYNTHETIC_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_SYNTHETIC_INPUT_BYTES:
        raise ValueError("synthetic probe result exceeds the byte limit")
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("synthetic probe result is invalid JSON") from error
    if (
        not isinstance(raw, Mapping)
        or set(raw) != {"schemaVersion", "generatedAt", "results"}
        or raw.get("schemaVersion") != 1
        or not isinstance(raw.get("results"), list)
        or not 1 <= len(raw["results"]) <= MAX_SYNTHETIC_PROBES
    ):
        raise ValueError("synthetic probe result has an invalid exact schema")
    generated = parse_iso_timestamp(raw.get("generatedAt"))
    if generated is None or generated > now + dt.timedelta(seconds=60):
        raise ValueError("synthetic probe result has an invalid generation timestamp")
    reduced: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for value in raw["results"]:
        # The worker intentionally serializes with ``sort_keys=True``.  Exactness
        # is therefore a set property here; duplicate members were already
        # rejected by ``_reject_duplicate_json_pairs`` while decoding.
        if not isinstance(value, Mapping) or set(value) != set(SYNTHETIC_PROBE_FIELDS):
            raise ValueError("synthetic probe result row has unexpected fields")
        probe_id = value.get("id")
        status_value = value.get("status")
        checked = parse_iso_timestamp(value.get("checkedAt"))
        url = value.get("url")
        http_status = bounded_integer(value.get("httpStatus"), 100, 599)
        redirect_count = bounded_integer(value.get("redirectCount"), 0, 5)
        latency = bounded_integer(value.get("latencyMilliseconds"), 0, 60_000)
        expires = parse_iso_timestamp(value.get("certificateExpiresAt"))
        days_remaining = bounded_integer(
            value.get("certificateDaysRemaining"), -36_600, 36_600
        )
        if (
            value.get("schemaVersion") != 1
            or not isinstance(probe_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", probe_id) is None
            or probe_id in identifiers
            or status_value not in SYNTHETIC_PROBE_STATUSES
            or checked is None
            or checked > generated + dt.timedelta(seconds=60)
            or (url is not None and (
                not isinstance(url, str)
                or not 1 <= len(url.encode("utf-8")) <= 4096
                or "\r" in url or "\n" in url
            ))
            or (value.get("httpStatus") is not None and http_status is None)
            or redirect_count is None
            or latency is None
            or (value.get("certificateExpiresAt") is not None and expires is None)
            or (value.get("certificateDaysRemaining") is not None and days_remaining is None)
            or ((expires is None) != (days_remaining is None))
            or (status_value == "ok" and (url is None or http_status is None))
        ):
            raise ValueError("synthetic probe result row is invalid")
        identifiers.add(probe_id)
        reduced.append({
            "id": probe_id,
            "status": status_value,
            "checkedAt": iso_timestamp(checked),
            "httpStatus": http_status,
            "redirectCount": redirect_count,
            "latencyMilliseconds": latency,
            "certificateExpiresAt": iso_timestamp(expires) if expires is not None else None,
            "certificateDaysRemaining": days_remaining,
        })
    reduced.sort(key=lambda item: item["id"])
    age = (now - generated).total_seconds()
    return ({
        "status": "fresh" if age <= MAX_SYNTHETIC_INPUT_AGE_SECONDS else "stale",
        "observedAt": iso_timestamp(generated),
    }, reduced)


def _reject_duplicate_json_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def collect_synthetic_probes(
    path: Path | None,
    now: dt.datetime,
) -> tuple[dict[str, str | None], list[dict[str, Any]]]:
    if path is None:
        return {"status": "unsupported", "observedAt": None}, []
    try:
        return load_synthetic_probe_document(path, now)
    except FileNotFoundError:
        status_value = "unsupported"
    except PermissionError:
        status_value = "permission-denied"
    except OSError:
        status_value = "unavailable"
    except (TypeError, ValueError, OverflowError, RecursionError):
        status_value = "collection-error"
    return {"status": status_value, "observedAt": None}, []


def previous_container_observation(
    output_dir: Path,
    now: dt.datetime,
) -> tuple[list[dict[str, Any]], str | None]:
    """Recover only a previously admitted bounded observation from current.json."""
    current = load_json(output_dir / "current.json")
    try:
        containers = normalize_container_values(
            current.get("containers"), now + dt.timedelta(seconds=60)
        )
    except ValueError:
        return [], None

    raw_collection = current.get("containerCollection")
    if raw_collection is not None:
        if not isinstance(raw_collection, Mapping) or set(raw_collection) != {"status", "observedAt"}:
            return [], None
        status = raw_collection.get("status")
        observed = parse_iso_timestamp(raw_collection.get("observedAt"))
        if status not in CONTAINER_COLLECTION_STATUSES:
            return [], None
        if status in {"fresh", "last-known"} and observed is None:
            return [], None
        if status == "unavailable" and observed is not None:
            return [], None
        if observed is not None and observed <= now + dt.timedelta(seconds=60):
            return containers, iso_timestamp(observed)
        return [], None

    # Legacy current.json files had no collection status. Their collector
    # timestamp is the only bounded evidence that the list was observed.
    observed = parse_iso_timestamp(current.get("generatedAt"))
    if observed is None and isinstance(current.get("latest"), Mapping):
        observed = parse_iso_timestamp(current["latest"].get("timestamp"))
    if observed is None or observed > now + dt.timedelta(seconds=60):
        return [], None
    return containers, iso_timestamp(observed)


def collect_container_telemetry(
    config: "Config",
    prior: Mapping[str, Any],
    now: dt.datetime,
) -> tuple[
    list[dict[str, Any]], dict[str, str | None], dict[str, dict[str, int | str]],
    dict[str, Any], list[dict[str, Any]], dict[str, Any],
]:
    """Collect containers without allowing a Docker-side failure to block the host sample."""
    previous_containers, previous_observed_at = previous_container_observation(
        config.output_dir, now
    )
    try:
        if config.container_input is not None:
            containers, collection, event_collection, docker_events = (
                load_container_snapshot_document(config.container_input, now)
            )
            container_cpu_state: dict[str, dict[str, int | str]] = {}
            docker_event_state = {**event_collection, "events": docker_events}
        else:
            containers, container_cpu_state = collect_containers(
                config.docker_sockets,
                config.curl,
                config.command_timeout,
                prior.get("containers"),
            )
            collection = {"status": "fresh", "observedAt": iso_timestamp(now)}
            event_collection, docker_events, docker_event_state = collect_docker_events(
                config.docker_sockets["cks"], config.curl, config.command_timeout,
                prior.get("dockerEvents"), now,
            )
    except PermissionError:
        event_collection, docker_event_state = docker_event_failure_state(
            prior.get("dockerEvents"), now, "permission-denied"
        )
        return (
            previous_containers if previous_observed_at is not None else [],
            {"status": "permission-denied", "observedAt": previous_observed_at},
            {},
            event_collection,
            docker_event_state["events"],
            docker_event_state,
        )
    except (ContainerSourceUnavailable, RuntimeError, ValueError, OSError):
        event_collection, docker_event_state = docker_event_failure_state(
            prior.get("dockerEvents"), now, "unavailable"
        )
        return (
            previous_containers if previous_observed_at is not None else [],
            {
                "status": "last-known" if previous_observed_at is not None else "unavailable",
                "observedAt": previous_observed_at,
            },
            {},
            event_collection,
            docker_event_state["events"],
            docker_event_state,
        )

    # An exporter may have no retained state after a runtime-directory reset,
    # while current.json still contains a previously admitted observation.
    if collection["status"] in {"unavailable", "permission-denied"} and previous_observed_at is not None:
        if not containers:
            containers = previous_containers
        collection["observedAt"] = collection["observedAt"] or previous_observed_at
        if collection["status"] == "unavailable":
            collection["status"] = "last-known"
    return (
        containers, collection, container_cpu_state,
        event_collection, docker_events, docker_event_state,
    )


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
RELIABILITY_EVENT_DETAILS = {
    ("host-boot", "observed"): (
        "info",
        "Host boot was observed by the collector.",
    ),
    ("host-boot", "restarted"): (
        "warning",
        "Host boot followed a previous collector session.",
    ),
    ("collector-gap", "detected"): (
        "warning",
        "Collector heartbeat gap exceeded the expected interval.",
    ),
    ("ssh-listener", "unavailable"): (
        "critical",
        "One or more expected SSH listeners are unavailable.",
    ),
    ("ssh-listener", "recovered"): (
        "info",
        "All expected SSH listeners recovered.",
    ),
    ("network-link", "unavailable"): (
        "critical",
        "Primary network link became unavailable.",
    ),
    ("network-link", "recovered"): (
        "info",
        "Primary network link recovered.",
    ),
    ("nvme-reset", "active"): (
        "critical",
        "Kernel reported an NVMe controller reset.",
    ),
    ("nvme-io", "active"): (
        "critical",
        "Kernel reported an NVMe I/O error.",
    ),
    ("rcu-stall", "active"): (
        "critical",
        "Kernel reported an RCU stall.",
    ),
    ("rcu-stall", "expedited"): (
        "warning",
        "Kernel reported a short expedited RCU grace-period delay.",
    ),
    ("oom-kill", "active"): (
        "critical",
        "Kernel reported an out-of-memory kill.",
    ),
    ("filesystem-error", "active"): (
        "critical",
        "Kernel reported a filesystem or block I/O error.",
    ),
    ("pcie-aer", "correctable"): (
        "warning",
        "Kernel reported a correctable PCIe AER event.",
    ),
    ("pcie-aer", "nonfatal"): (
        "critical",
        "Kernel reported a non-fatal PCIe AER event.",
    ),
    ("pcie-aer", "fatal"): (
        "critical",
        "Kernel reported a fatal PCIe AER event.",
    ),
    ("pcie-link", "down"): (
        "critical",
        "Kernel reported that the PCIe link went down.",
    ),
    ("pcie-link", "degraded"): (
        "warning",
        "Kernel reported degraded PCIe link training.",
    ),
    ("pcie-link", "recovered"): (
        "info",
        "Kernel reported that the PCIe link recovered.",
    ),
    ("kernel-warning", "active"): (
        "warning",
        "Kernel reported an internal warning.",
    ),
    ("kernel-oops", "active"): (
        "critical",
        "Kernel reported an oops.",
    ),
    ("kernel-panic", "active"): (
        "critical",
        "Kernel reported a panic.",
    ),
    ("hung-task", "active"): (
        "critical",
        "Kernel reported a hung task.",
    ),
    ("nvme-mitigation", "active"): (
        "info",
        "Runtime NVMe power-management mitigation is active.",
    ),
    ("nvme-mitigation", "incomplete"): (
        "warning",
        "Runtime NVMe power-management mitigation is not fully active.",
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


def event_timestamp(line: str, fallback: str, preserve_subseconds: bool = False) -> str:
    formatter = iso_event_timestamp if preserve_subseconds else iso_timestamp
    match = TIMESTAMP_RE.match(line)
    if match:
        try:
            parsed = dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return formatter(parsed)
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
            return formatter(candidate)
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


def reliability_event(
    timestamp: str,
    kind: str,
    status: str,
    duration_seconds: int | None = None,
) -> dict[str, Any]:
    severity, message = RELIABILITY_EVENT_DETAILS[(kind, status)]
    return {
        "timestamp": event_timestamp(timestamp, "", preserve_subseconds=True),
        "severity": severity,
        "kind": kind,
        "status": status,
        "message": message,
        "durationSeconds": duration_seconds,
    }


def existing_reliability_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    required = {
        "timestamp", "severity", "kind", "status", "message", "durationSeconds",
    }
    if set(record) != required:
        return None
    timestamp = event_timestamp(
        str(record.get("timestamp", "")), "", preserve_subseconds=True
    )
    if not timestamp:
        return None
    event = (str(record.get("kind", "")), str(record.get("status", "")))
    details = RELIABILITY_EVENT_DETAILS.get(event)
    if details is None:
        return None
    severity, message = details
    if record.get("severity") != severity or record.get("message") != message:
        return None
    raw_duration = record.get("durationSeconds")
    if raw_duration is None:
        duration: int | None = None
    elif (
        isinstance(raw_duration, bool)
        or not isinstance(raw_duration, int)
        or not 0 <= raw_duration <= MAX_RELIABILITY_DURATION_SECONDS
    ):
        return None
    else:
        duration = raw_duration
    if event != ("collector-gap", "detected") and duration is not None:
        return None
    return {
        "timestamp": timestamp,
        "severity": severity,
        "kind": event[0],
        "status": event[1],
        "message": message,
        "durationSeconds": duration,
    }


def sanitize_kernel_reliability_line(
    line: str,
    fallback_timestamp: str,
    primary_interface: str = "eth0",
) -> dict[str, Any] | None:
    event: tuple[str, str] | None = None
    lowered = line.lower()
    if re.search(r"\bnvme\S*.*controller is down; will reset\b", line, re.IGNORECASE):
        event = ("nvme-reset", "active")
    elif re.search(r"\bnvme\S*", line, re.IGNORECASE) and (
        "I/O Error" in line or re.search(r"I/O error,\s*dev\s+nvme", line, re.IGNORECASE)
    ):
        event = ("nvme-io", "active")
    elif (
        "aer:" in lowered or "pcie bus error" in lowered
    ) and re.search(
        r"(?:uncorrectable\s*\(non[- ]fatal\)|severity\s*=\s*uncorrected\s*\(non[- ]fatal\)|non[- ]fatal error)",
        lowered,
    ):
        event = ("pcie-aer", "nonfatal")
    elif (
        "aer:" in lowered or "pcie bus error" in lowered
    ) and re.search(
        r"(?:uncorrectable\s*\(fatal\)|severity\s*=\s*uncorrected\s*\(fatal\)|fatal error)",
        lowered,
    ):
        event = ("pcie-aer", "fatal")
    elif (
        "aer:" in lowered or "pcie bus error" in lowered
    ) and re.search(
        r"(?:\bcorrected error\b|severity\s*=\s*corrected\b|\bcorrectable error\b)",
        lowered,
    ):
        event = ("pcie-aer", "correctable")
    elif re.search(r"\b(?:pcie|pcieport)\b", lowered) and re.search(
        r"\blink (?:is )?down\b|\bfailed to bring up (?:the )?link\b",
        lowered,
    ):
        event = ("pcie-link", "down")
    elif re.search(r"\b(?:pcie|pcieport)\b", lowered) and re.search(
        r"\b(?:link degraded|link training failed|failed to train (?:the )?link|link retrain(?:ing)? failed)\b",
        lowered,
    ):
        event = ("pcie-link", "degraded")
    elif re.search(r"\b(?:pcie|pcieport)\b", lowered) and re.search(
        r"\blink (?:is )?(?:up|recovered)\b",
        lowered,
    ):
        event = ("pcie-link", "recovered")
    elif re.search(r"\bkernel panic\b.*\bnot syncing\b|\bpanic:\s", lowered):
        event = ("kernel-panic", "active")
    elif re.search(
        r"\b(?:oops:|internal error:\s*oops|bug:\s+unable to handle kernel)",
        lowered,
    ):
        event = ("kernel-oops", "active")
    elif re.search(
        r"\b(?:info:\s+task\s+.+\s+blocked for more than\s+\d+\s+seconds|hung_task:)",
        lowered,
    ):
        event = ("hung-task", "active")
    elif re.search(
        r"\brcu(?:_preempt)?:?.*detected expedited stalls?",
        lowered,
    ):
        event = ("rcu-stall", "expedited")
    elif re.search(r"\brcu(?:_preempt)?:?.*(?:detected .*stalls?|stall detected|kthread starved)", lowered):
        event = ("rcu-stall", "active")
    elif re.search(r"\b(?:out of memory: killed process|oom-kill:)", lowered):
        event = ("oom-kill", "active")
    elif re.search(
        r"\b(?:ext[234]-fs error|xfs.*(?:corruption|metadata i/o error)|"
        r"buffer i/o error on dev|remounting filesystem read-only)\b",
        lowered,
    ):
        event = ("filesystem-error", "active")
    elif re.search(r"\bwarning:\s+(?:cpu:|at\s+)", lowered):
        event = ("kernel-warning", "active")
    elif re.search(
        rf"\b{re.escape(primary_interface)}\b.*\b(?:link is down|lost carrier|carrier lost)\b",
        lowered,
    ):
        event = ("network-link", "unavailable")
    elif re.search(
        rf"\b{re.escape(primary_interface)}\b.*\b(?:link is up|gained carrier|carrier acquired)\b",
        lowered,
    ):
        event = ("network-link", "recovered")
    if event is None:
        return None
    return reliability_event(
        event_timestamp(line, fallback_timestamp, preserve_subseconds=True), *event
    )


def bounded_current_boot_rcu_backfill(
    config: "Config",
    boot_started_at: str,
    now: dt.datetime,
    prior_last_event_at: str | None,
) -> list[dict[str, Any]] | None:
    """Reconstruct precise expedited-RCU rows from one bounded log rotation.

    This is private migration evidence only: callers must not append these
    replayed rows to the public reliability timeline. A complete, single-link
    current source (and optional immediate `.1` rotation) must span the boot
    start through the prior last event, otherwise the migration fails closed.
    """
    boot_started = parse_iso_timestamp(boot_started_at)
    prior_last = parse_iso_timestamp(prior_last_event_at) if prior_last_event_at else None
    if boot_started is None:
        return None
    sources = [config.kernel_log.with_name(config.kernel_log.name + ".1"), config.kernel_log]
    source_times: list[dt.datetime] = []
    records: list[dict[str, Any]] = []
    saw_source = False
    for source in sources:
        try:
            metadata = source.stat(follow_symlinks=False)
        except OSError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_KERNEL_BACKFILL_BYTES
        ):
            return None
        saw_source = True
        lines, _cursor = read_new_lines(
            source, {}, MAX_KERNEL_BACKFILL_BYTES
        )
        for line in lines:
            timestamp_text = event_timestamp(
                line, "", preserve_subseconds=True
            )
            timestamp = parse_iso_timestamp(timestamp_text)
            if timestamp is None:
                continue
            source_times.append(timestamp)
            if timestamp < boot_started or timestamp > now + dt.timedelta(minutes=1):
                continue
            record = sanitize_kernel_reliability_line(
                line, iso_timestamp(now), config.primary_interface
            )
            if (
                record is not None
                and record.get("kind") == "rcu-stall"
                and record.get("status") == "expedited"
            ):
                records.append(record)
    record_times = [
        timestamp
        for record in records
        if (timestamp := parse_iso_timestamp(record.get("timestamp"))) is not None
    ]
    if (
        not saw_source
        or not source_times
        or not any(
            abs((timestamp - boot_started).total_seconds()) <= 60
            for timestamp in source_times
        )
        or prior_last is not None
        and (not record_times or max(record_times) < prior_last)
    ):
        return None
    return [
        dict(record)
        for record in stable_deduplicate_records(records, RELIABILITY_FIELDS)
    ]


def parse_listening_tcp_ports(proc_root: Path) -> set[int]:
    ports: set[int] = set()
    for path in (proc_root / "net" / "tcp", proc_root / "net" / "tcp6"):
        for line in read_text(path, 2 * 1024 * 1024).splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3].upper() != "0A":
                continue
            try:
                port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if 0 < port <= 65535:
                ports.add(port)
    return ports


def observed_ssh_listeners(proc_root: Path, expected_ports: set[int]) -> bool | None:
    if not expected_ports:
        return None
    tcp = proc_root / "net" / "tcp"
    tcp6 = proc_root / "net" / "tcp6"
    if not tcp.is_file() and not tcp6.is_file():
        return None
    return expected_ports.issubset(parse_listening_tcp_ports(proc_root))


def observed_network_link(sys_root: Path, interface: str) -> bool | None:
    root = sys_root / "class" / "net" / interface
    operstate = read_text(root / "operstate", 64).strip().lower()
    carrier = read_text(root / "carrier", 64).strip()
    if not operstate and not carrier:
        return None
    if carrier in {"0", "1"}:
        return carrier == "1" and operstate not in {"down", "dormant", "notpresent", "lowerlayerdown"}
    if operstate:
        return operstate == "up"
    return None


def observed_nvme_mitigation(
    sys_root: Path,
    proc_root: Path = Path("/proc"),
) -> bool | None:
    aspm_disabled, nvme_power_disabled = pcie_power_settings(proc_root, sys_root)
    if aspm_disabled is None and nvme_power_disabled is None:
        return None
    tokens = cmdline_tokens(proc_root)
    aspm_mitigation_complete = aspm_disabled is True
    if "pcie_aspm=off" in tokens:
        # A cmdline-declared mitigation also disables PCIe port power
        # management. This is the exact deployed fallback when sysfs does not
        # expose a selectable performance policy.
        aspm_mitigation_complete = "pcie_port_pm=off" in tokens
    return aspm_mitigation_complete and nvme_power_disabled is True


def existing_sample_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    fields = frozenset(record)
    if fields not in SAMPLE_FIELD_SCHEMAS:
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
        elif field in {"swapTotalBytes", "swapUsedBytes"}:
            normalized[field] = (
                value
                if isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= MAX_SAFE_COUNTER
                else None
            )
        elif field in {
            "swapPercent",
            "cpuPressureSomeAvg10",
            "cpuPressureFullAvg10",
            "memoryPressureSomeAvg10",
            "memoryPressureFullAvg10",
            "ioPressureSomeAvg10",
            "ioPressureFullAvg10",
        }:
            parsed = finite_number(value)
            normalized[field] = (
                round(parsed, 2)
                if parsed is not None and 0 <= parsed <= 100
                else None
            )
        elif field in NETWORK_QUALITY_SAMPLE_FIELDS:
            parsed = finite_number(value)
            normalized[field] = (
                round(parsed, 2)
                if parsed is not None and 0 <= parsed <= 1_000_000_000_000
                else None
            )
        elif value is None:
            normalized[field] = None
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            normalized[field] = None
        else:
            normalized[field] = value if finite_number(value) is not None else None
    swap_total = normalized["swapTotalBytes"]
    swap_used = normalized["swapUsedBytes"]
    if swap_total is not None and swap_used is not None:
        if swap_used > swap_total:
            normalized["swapUsedBytes"] = None
            normalized["swapPercent"] = None
        else:
            expected_percent = round(
                100.0 * swap_used / swap_total,
                2,
            ) if swap_total > 0 else 0.0
            if normalized["swapPercent"] is not None and not math.isclose(
                normalized["swapPercent"], expected_percent, abs_tol=0.01
            ):
                normalized["swapPercent"] = None
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
        "networkRxErrorsPerSecond": (0, 1_000_000_000_000),
        "networkTxErrorsPerSecond": (0, 1_000_000_000_000),
        "networkRxDroppedPerSecond": (0, 1_000_000_000_000),
        "networkTxDroppedPerSecond": (0, 1_000_000_000_000),
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
                {
                    field_name: (
                        "unknown"
                        if field_name == "health" and value.get(field_name) is None
                        else value.get(field_name)
                    )
                    for field_name in LEGACY_CONTAINER_FIELDS
                }
                for value in sorted(
                    containers,
                    key=lambda value: (
                        0 if value.get("health") not in {"healthy", "none"} else 1,
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


RELIABILITY_FIELDS = (
    "timestamp", "severity", "kind", "status", "message", "durationSeconds",
)


def existing_reliability_state(value: Any) -> dict[str, Any] | None:
    legacy_required = {
        "version", "bootId", "lastSeenAt", "sshListenersAvailable",
        "networkLinkAvailable", "nvmeMitigationActive", "kernelCursor",
    }
    summary_required = legacy_required | {"kernelSummary"}
    fields = frozenset(value) if isinstance(value, Mapping) else frozenset()
    version = value.get("version") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, Mapping)
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version not in {1, 2, 3, 4, 5}
        or fields not in {frozenset(legacy_required), frozenset(summary_required)}
        or (version == 1 and fields != frozenset(legacy_required))
        or (version in {2, 3, 4, 5} and fields != frozenset(summary_required))
    ):
        return None
    boot_id = value.get("bootId")
    if boot_id is not None and (
        not isinstance(boot_id, str)
        or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot_id) is None
    ):
        return None
    last_seen = parse_iso_timestamp(value.get("lastSeenAt"))
    if last_seen is None:
        return None
    states: dict[str, bool | None] = {}
    for field_name in (
        "sshListenersAvailable", "networkLinkAvailable", "nvmeMitigationActive",
    ):
        raw = value.get(field_name)
        if raw is not None and not isinstance(raw, bool):
            return None
        states[field_name] = raw
    kernel_cursor = existing_traffic_cursor(value.get("kernelCursor"))
    if kernel_cursor is None:
        return None
    kernel_summary = None
    if version == 2:
        kernel_summary = existing_legacy_kernel_event_summary(value.get("kernelSummary"))
    elif version in {3, 4, 5}:
        kernel_summary = existing_kernel_event_summary(value.get("kernelSummary"))
    if version != 1 and kernel_summary is None:
        return None
    result = {
        "version": version,
        "bootId": boot_id,
        "lastSeenAt": iso_timestamp(last_seen),
        **states,
        "kernelCursor": kernel_cursor,
    }
    if kernel_summary is not None:
        result["kernelSummary"] = kernel_summary
    return result


def load_reliability_records(config: "Config", limit: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in existing_json_lines(config.output_dir / "reliability.jsonl", limit):
        normalized = existing_reliability_record(value)
        if normalized is not None:
            records.append(normalized)
    return records[-limit:]


def merge_reliability_records(
    existing: Sequence[Mapping[str, Any]],
    new_records: Sequence[Mapping[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for value in (*existing, *new_records):
        record = existing_reliability_record(value)
        if record is not None:
            normalized.append(record)
    return [
        dict(record) for record in stable_deduplicate_records(normalized, RELIABILITY_FIELDS)
    ][-limit:]


def reliability_records_digest(records: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update((json.dumps(
            record, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ) + "\n").encode())
    return digest.hexdigest()


def normalized_pending_reliability_commit(value: Any) -> dict[str, Any] | None:
    required = {
        "version", "baseDigest", "baseCount", "finalDigest", "finalCount",
        "limit", "rows", "state",
    }
    if not isinstance(value, Mapping) or set(value) != required or value.get("version") != 1:
        return None
    limit = value.get("limit")
    base_count = value.get("baseCount")
    final_count = value.get("finalCount")
    if (
        isinstance(limit, bool) or not isinstance(limit, int) or not 10 <= limit <= 100_000
        or isinstance(base_count, bool) or not isinstance(base_count, int) or not 0 <= base_count <= limit
        or isinstance(final_count, bool) or not isinstance(final_count, int) or not 0 <= final_count <= limit
    ):
        return None
    base_digest = value.get("baseDigest")
    final_digest = value.get("finalDigest")
    if (
        not isinstance(base_digest, str) or re.fullmatch(r"[0-9a-f]{64}", base_digest) is None
        or not isinstance(final_digest, str) or re.fullmatch(r"[0-9a-f]{64}", final_digest) is None
    ):
        return None
    raw_rows = value.get("rows")
    if not isinstance(raw_rows, list) or len(raw_rows) > limit:
        return None
    rows: list[dict[str, Any]] = []
    for value_row in raw_rows:
        if not isinstance(value_row, Mapping):
            return None
        record = existing_reliability_record(value_row)
        if record is None:
            return None
        rows.append(record)
    state = existing_reliability_state(value.get("state"))
    if state is None:
        return None
    normalized = {
        "version": 1,
        "baseDigest": base_digest,
        "baseCount": base_count,
        "finalDigest": final_digest,
        "finalCount": final_count,
        "limit": limit,
        "rows": rows,
        "state": state,
    }
    encoded = (json.dumps(
        normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ) + "\n").encode()
    return normalized if len(encoded) <= MAX_PENDING_RELIABILITY_COMMIT_BYTES else None


def load_pending_reliability_commit(path: Path) -> dict[str, Any] | None:
    decoded = load_private_pending_json(path, MAX_PENDING_RELIABILITY_COMMIT_BYTES)
    if decoded is None:
        return None
    normalized = normalized_pending_reliability_commit(decoded)
    if normalized is None:
        raise PendingJournalError("pending reliability journal failed schema validation")
    return normalized


def replay_pending_reliability_commit(config: "Config") -> bool:
    path = config.output_dir / ".state" / "pending-reliability-commit.json"
    pending = load_pending_reliability_commit(path)
    if pending is None:
        return False
    current = load_reliability_records(config, pending["limit"])
    current_digest = reliability_records_digest(current)
    current_count = len(current)
    final_matches = (
        current_digest == pending["finalDigest"]
        and current_count == pending["finalCount"]
        and (config.output_dir / "reliability.jsonl").is_file()
    )
    if not final_matches:
        if current_digest != pending["baseDigest"] or current_count != pending["baseCount"]:
            raise PendingJournalError("reliability output diverged from pending transaction")
        final = merge_reliability_records(current, pending["rows"], pending["limit"])
        if (
            reliability_records_digest(final) != pending["finalDigest"]
            or len(final) != pending["finalCount"]
        ):
            raise PendingJournalError("reliability pending digest validation failed")
        rewrite_json_lines(config.output_dir / "reliability.jsonl", final, pending["limit"])
        saved = load_reliability_records(config, pending["limit"])
        if (
            reliability_records_digest(saved) != pending["finalDigest"]
            or len(saved) != pending["finalCount"]
        ):
            raise PendingJournalError("reliability output verification failed")
    atomic_write_json(
        config.output_dir / ".state" / "reliability-state.json",
        pending["state"],
        0o600,
    )
    if not discard_pending_incident_commit(path):
        raise OSError("pending reliability journal could not be removed")
    return True


def write_pending_reliability_commit(
    config: "Config",
    rows: Sequence[Mapping[str, Any]],
    state: Mapping[str, Any],
) -> Path:
    path = config.output_dir / ".state" / "pending-reliability-commit.json"
    require_pending_journal_absent(path)
    limit = config.max_log_records
    base = load_reliability_records(config, limit)
    normalized_rows: list[dict[str, Any]] = []
    for value in rows:
        record = existing_reliability_record(value)
        if record is None:
            raise ValueError("reliability row did not satisfy the public contract")
        normalized_rows.append(record)
    bounded_rows = [
        dict(record)
        for record in stable_deduplicate_records(normalized_rows, RELIABILITY_FIELDS)
    ][-limit:]
    final = merge_reliability_records(base, bounded_rows, limit)
    normalized = normalized_pending_reliability_commit({
        "version": 1,
        "baseDigest": reliability_records_digest(base),
        "baseCount": len(base),
        "finalDigest": reliability_records_digest(final),
        "finalCount": len(final),
        "limit": limit,
        "rows": bounded_rows,
        "state": dict(state),
    })
    if normalized is None:
        raise ValueError("pending reliability commit did not satisfy the private state contract")
    atomic_create_json(path, normalized, MAX_PENDING_RELIABILITY_COMMIT_BYTES, 0o600)
    return path


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

    # The standard Raspberry Pi hwmon alarm maps to low bit 0. Retained legacy
    # samples can still contain the other firmware bits. Export transitions,
    # not one alert per minute.
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
                "message": f"Current hwmon power flags are 0x{active_flags:x}." + detail,
            })
        elif not active_flags and previous_flags not in {None, 0}:
            new_alert_records.append({
                "timestamp": now_text,
                "severity": "info",
                "kind": "power",
                "status": "recovered",
                "message": "Current hwmon power condition recovered." + detail,
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


def parse_port_set(value: str) -> set[int]:
    result: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if item.isdigit():
            port = int(item)
            if 0 < port <= 65535:
                result.add(port)
        if len(result) >= 16:
            break
    return result


def safe_interface_name(value: str) -> str:
    name = value.strip()
    return name if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) else "eth0"


def parse_process_allowlist(value: str) -> set[str]:
    """Parse explicit comm-name allowlisting without accepting argv fragments."""
    result: set[str] = set()
    for raw in value.split(",")[:128]:
        name = raw.strip()
        if (
            re.fullmatch(r"[A-Za-z0-9_.@+-]{1,64}", name)
            and re.search(r"password|passwd|secret|token|api.?key", name, re.IGNORECASE) is None
        ):
            result.add(name)
        if len(result) >= 64:
            break
    return result


def parse_systemd_allowlist(value: str) -> set[str]:
    result: set[str] = set()
    for raw in value.split(",")[:128]:
        unit = raw.strip()
        if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}\.service", unit):
            result.add(unit)
        if len(result) >= 32:
            break
    return result


def safe_absolute_path(value: str, default: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or len(str(path)) > 512:
        return Path(default)
    return path


@dataclass
class Config:
    output_dir: Path = Path("/var/lib/monitor-export")
    runtime_dir: Path = Path("/run/monitor-collector")
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")
    etc_root: Path = Path("/etc")
    package_root: Path = Path("/")
    mountinfo: Path | None = None
    mount_root: Path | None = None
    events_log: Path = Path("/var/log/server-watch/events.log")
    kernel_log: Path = Path("/var/log/kern.log")
    privilege_logs: list[Path] = field(default_factory=lambda: [Path("/var/log/privilege-events.log")])
    traffic_log: Path | None = Path("/var/log/nginx/monitor-traffic.jsonl")
    container_input: Path | None = None
    synthetic_input: Path | None = None
    docker_sockets: dict[str, Path] = field(
        default_factory=lambda: {key: Path(value) for key, value in DEFAULT_SOCKETS.items()}
    )
    process_uids: set[int] = field(default_factory=lambda: {0, 1001})
    process_allowlist: set[str] = field(default_factory=set)
    systemd_units: set[str] = field(default_factory=set)
    ssh_ports: set[int] = field(default_factory=lambda: {22, 22022})
    primary_interface: str = "eth0"
    curl: str = "/usr/bin/curl"
    vcgencmd: str = "/usr/bin/vcgencmd"
    systemctl: str = "/usr/bin/systemctl"
    timedatectl: str = "/usr/bin/timedatectl"
    systemd_state_dir: Path = Path("/run/systemd/units")
    docker_data_root: Path = Path("/var/lib/docker")
    command_timeout: float = 2.0
    expected_interval_seconds: int = 60
    agent_lifecycle: str = "active"
    retention_days: int = 30
    max_log_records: int = 5000
    incident_retention_days: int = 30
    max_incident_records: int = 1000
    incident_follow_up_samples: int = 5
    cpu_warn_percent: float = 85.0
    cpu_recover_percent: float = 75.0
    cpu_warn_samples: int = 2
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
    rule_pack: Path = DEFAULT_RULE_PACK_PATH
    log_sources_config: Path = Path("/etc/monitor-collector/log-sources.json")
    log_sources_required: bool = False
    journalctl: str = "/usr/bin/journalctl"
    generic_log_retention_days: int = 30
    generic_log_max_records: int = 20_000
    generic_log_max_file_bytes: int = 16 * 1024 * 1024
    generic_log_total_timeout: float = 15.0

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
    parser.add_argument("--package-root", default=env.get("MONITOR_PACKAGE_ROOT", "/"))
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
    parser.add_argument(
        "--synthetic-input",
        default=env.get("MONITOR_SYNTHETIC_INPUT", "/var/lib/monitor-synthetic/results.json"),
    )
    parser.add_argument("--docker-sockets", default=env.get(
        "MONITOR_DOCKER_SOCKETS", ",".join(f"{owner}={path}" for owner, path in DEFAULT_SOCKETS.items())
    ))
    parser.add_argument("--process-uids", default=env.get("MONITOR_PROCESS_UIDS", "0,1001"))
    parser.add_argument(
        "--process-allowlist", default=env.get("MONITOR_PROCESS_ALLOWLIST", "")
    )
    parser.add_argument(
        "--systemd-units", default=env.get("MONITOR_SYSTEMD_UNITS", "")
    )
    parser.add_argument("--ssh-ports", default=env.get("MONITOR_SSH_PORTS", "22,22022"))
    parser.add_argument(
        "--primary-interface", default=env.get("MONITOR_PRIMARY_INTERFACE", "eth0")
    )
    parser.add_argument("--curl", default=env.get("MONITOR_CURL", "/usr/bin/curl"))
    parser.add_argument("--vcgencmd", default=env.get("MONITOR_VCGENCMD", "/usr/bin/vcgencmd"))
    parser.add_argument("--systemctl", default=env.get("MONITOR_SYSTEMCTL", "/usr/bin/systemctl"))
    parser.add_argument("--timedatectl", default=env.get("MONITOR_TIMEDATECTL", "/usr/bin/timedatectl"))
    parser.add_argument(
        "--systemd-state-dir",
        default=env.get("MONITOR_SYSTEMD_STATE_DIR", "/run/systemd/units"),
    )
    parser.add_argument(
        "--docker-data-root", default=env.get("MONITOR_DOCKER_DATA_ROOT", "/var/lib/docker")
    )
    parser.add_argument("--command-timeout", type=float, default=float(env.get("MONITOR_COMMAND_TIMEOUT", "2")))
    parser.add_argument(
        "--expected-interval-seconds",
        type=int,
        default=int(env.get("MONITOR_EXPECTED_INTERVAL_SECONDS", "60")),
    )
    parser.add_argument(
        "--agent-lifecycle",
        choices=sorted(AGENT_LIFECYCLES),
        default=env.get("MONITOR_AGENT_LIFECYCLE", "active"),
    )
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
    parser.add_argument("--cpu-warn-samples", type=int, default=int(env.get("MONITOR_CPU_WARN_SAMPLES", "2")))
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
    parser.add_argument(
        "--rule-pack",
        default=env.get("MONITOR_RULE_PACK", str(DEFAULT_RULE_PACK_PATH)),
    )
    parser.add_argument(
        "--log-sources-config",
        default=env.get(
            "MONITOR_LOG_SOURCES_CONFIG", "/etc/monitor-collector/log-sources.json"
        ),
    )
    parser.add_argument(
        "--log-sources-required",
        choices=("true", "false"),
        default=env.get("MONITOR_LOG_SOURCES_REQUIRED", "false"),
    )
    parser.add_argument(
        "--journalctl", default=env.get("MONITOR_JOURNALCTL", "/usr/bin/journalctl")
    )
    parser.add_argument(
        "--generic-log-retention-days",
        type=int,
        default=int(env.get("MONITOR_GENERIC_LOG_RETENTION_DAYS", "30")),
    )
    parser.add_argument(
        "--generic-log-max-records",
        type=int,
        default=int(env.get("MONITOR_GENERIC_LOG_MAX_RECORDS", "20000")),
    )
    parser.add_argument(
        "--generic-log-max-file-bytes",
        type=int,
        default=int(env.get("MONITOR_GENERIC_LOG_MAX_FILE_BYTES", str(16 * 1024 * 1024))),
    )
    parser.add_argument(
        "--generic-log-total-timeout",
        type=float,
        default=float(env.get("MONITOR_GENERIC_LOG_TOTAL_TIMEOUT", "15")),
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
        package_root=Path(values.package_root),
        mountinfo=Path(values.mountinfo) if values.mountinfo else None,
        mount_root=Path(values.mount_root) if values.mount_root else None,
        events_log=Path(values.events_log), kernel_log=Path(values.kernel_log),
        privilege_logs=[Path(item) for item in values.privilege_logs.split(":") if item],
        traffic_log=Path(values.traffic_log) if values.traffic_log else None,
        container_input=Path(values.container_input) if values.container_input else None,
        synthetic_input=(
            safe_absolute_path(values.synthetic_input, "/var/lib/monitor-synthetic/results.json")
            if values.synthetic_input else None
        ),
        docker_sockets=parse_socket_map(values.docker_sockets),
        process_uids=parse_uid_set(values.process_uids),
        process_allowlist=parse_process_allowlist(values.process_allowlist),
        systemd_units=parse_systemd_allowlist(values.systemd_units),
        ssh_ports=parse_port_set(values.ssh_ports),
        primary_interface=safe_interface_name(values.primary_interface),
        curl=values.curl, vcgencmd=values.vcgencmd,
        systemctl=values.systemctl, timedatectl=values.timedatectl,
        systemd_state_dir=safe_absolute_path(values.systemd_state_dir, "/run/systemd/units"),
        docker_data_root=safe_absolute_path(values.docker_data_root, "/var/lib/docker"),
        command_timeout=max(0.1, min(10.0, values.command_timeout)),
        expected_interval_seconds=max(
            10, min(MAX_HEARTBEAT_INTERVAL_SECONDS, values.expected_interval_seconds)
        ),
        agent_lifecycle=values.agent_lifecycle,
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
        rule_pack=Path(values.rule_pack),
        log_sources_config=safe_absolute_path(
            values.log_sources_config, "/etc/monitor-collector/log-sources.json"
        ),
        log_sources_required=values.log_sources_required == "true",
        journalctl=str(safe_absolute_path(values.journalctl, "/usr/bin/journalctl")),
        generic_log_retention_days=max(1, min(3650, values.generic_log_retention_days)),
        generic_log_max_records=max(100, min(20_000, values.generic_log_max_records)),
        generic_log_max_file_bytes=max(
            1024 * 1024, min(16 * 1024 * 1024, values.generic_log_max_file_bytes)
        ),
        generic_log_total_timeout=max(1.0, min(30.0, values.generic_log_total_timeout)),
    )


def historical_collector_gap_at_boot(
    config: Config,
    boot_started: dt.datetime,
) -> int | None:
    """Infer one pre-existing reboot gap when reliability state is first introduced."""
    timestamps: list[dt.datetime] = []
    for file_date in (boot_started.date() - dt.timedelta(days=1), boot_started.date()):
        path = config.output_dir / "history" / f"{file_date.isoformat()}.jsonl"
        for value in existing_json_lines(path, 2000):
            sample = existing_sample_record(value)
            if sample is None:
                continue
            parsed = parse_iso_timestamp(sample.get("timestamp"))
            if parsed is not None:
                timestamps.append(parsed)
    before = [value for value in timestamps if value < boot_started]
    after = [value for value in timestamps if value >= boot_started]
    if not before or not after:
        return None
    duration = int((min(after) - max(before)).total_seconds())
    return max(0, min(MAX_RELIABILITY_DURATION_SECONDS, duration))


def collect_reliability(
    config: Config,
    now: dt.datetime,
    uptime_seconds: int | None,
    include_kernel_summary: bool = False,
) -> dict[str, Any] | tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Persist bounded host-availability evidence and return its public summary."""
    replay_pending_reliability_commit(config)
    now_text = iso_timestamp(now)
    state_path = config.output_dir / ".state" / "reliability-state.json"
    raw_previous = load_json(state_path)
    previous = existing_reliability_state(raw_previous)
    previous_version = previous.get("version") if previous is not None else None
    migrated_from_v1 = previous_version == 1
    migrated_from_v2 = previous_version == 2

    raw_boot_id = read_text(
        config.proc_root / "sys" / "kernel" / "random" / "boot_id", 128
    ).strip().lower()
    boot_id = raw_boot_id if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        raw_boot_id,
    ) else None
    boot_started_at: str | None = None
    if uptime_seconds is not None and 0 <= uptime_seconds <= MAX_RELIABILITY_DURATION_SECONDS:
        boot_started_at = iso_timestamp(now - dt.timedelta(seconds=uptime_seconds))

    ssh_available = observed_ssh_listeners(config.proc_root, config.ssh_ports)
    network_available = observed_network_link(config.sys_root, config.primary_interface)
    mitigation_active = observed_nvme_mitigation(config.sys_root, config.proc_root)
    events: list[dict[str, Any]] = []

    previous_seen = parse_iso_timestamp(previous.get("lastSeenAt")) if previous else None
    gap_seconds: int | None = None
    if previous_seen is not None:
        gap_seconds = max(0, min(
            MAX_RELIABILITY_DURATION_SECONDS,
            int((now - previous_seen).total_seconds()),
        ))
    elif previous is None and boot_started_at is not None:
        parsed_boot_started = parse_iso_timestamp(boot_started_at)
        if parsed_boot_started is not None:
            gap_seconds = historical_collector_gap_at_boot(config, parsed_boot_started)

    previous_boot = previous.get("bootId") if previous else None
    boot_changed = bool(previous_boot and boot_id and previous_boot != boot_id)
    if previous is None:
        events.append(reliability_event(
            boot_started_at or now_text, "host-boot", "observed",
        ))
    elif boot_changed:
        events.append(reliability_event(
            boot_started_at or now_text, "host-boot", "restarted",
        ))
    if gap_seconds is not None and gap_seconds > RELIABILITY_GAP_WARN_SECONDS:
        events.append(reliability_event(
            boot_started_at if (boot_changed or previous is None) and boot_started_at else now_text,
            "collector-gap",
            "detected",
            gap_seconds,
        ))

    prior_expedited = (
        previous.get("kernelSummary", {}).get("rcuExpedited", {})
        if previous is not None
        else {}
    )
    needs_precision_backfill = (
        previous_version in {3, 4}
        and not boot_changed
        and isinstance(prior_expedited, Mapping)
        and int(prior_expedited.get("count", 0)) > 0
        and boot_started_at is not None
    )
    precise_rcu_backfill = (
        bounded_current_boot_rcu_backfill(
            config,
            boot_started_at,
            now,
            prior_expedited.get("lastEventAt"),
        )
        if needs_precision_backfill
        else None
    )

    previous_ssh = previous.get("sshListenersAvailable") if previous else None
    if ssh_available is False and previous_ssh is not False:
        events.append(reliability_event(now_text, "ssh-listener", "unavailable"))
    elif ssh_available is True and previous_ssh is False:
        events.append(reliability_event(now_text, "ssh-listener", "recovered"))

    previous_network = previous.get("networkLinkAvailable") if previous else None
    if network_available is False and previous_network is not False:
        events.append(reliability_event(now_text, "network-link", "unavailable"))
    elif network_available is True and previous_network is False:
        events.append(reliability_event(now_text, "network-link", "recovered"))

    previous_mitigation = previous.get("nvmeMitigationActive") if previous else None
    if mitigation_active is not None and mitigation_active != previous_mitigation:
        events.append(reliability_event(
            now_text,
            "nvme-mitigation",
            "active" if mitigation_active else "incomplete",
        ))

    # Re-read the bounded kernel source once when upgrading the private v1
    # state. This reconstructs current-boot counts and discovers the supported
    # fixed event kinds; public event deduplication prevents replayed legacy
    # kinds from multiplying. The v2 cursor stays intact because only its
    # combined warning field needs a retained-evidence split.
    prior_cursor = previous.get("kernelCursor", {}) if previous and not migrated_from_v1 else {}
    if not isinstance(prior_cursor, Mapping):
        prior_cursor = {}
    lines, kernel_cursor = read_new_lines(
        config.kernel_log, prior_cursor, config.kernel_max_input_bytes
    )
    kernel_events: list[dict[str, Any]] = []
    for line in lines:
        record = sanitize_kernel_reliability_line(
            line, now_text, config.primary_interface
        )
        if record is not None:
            events.append(record)
            kernel_events.append(record)

    retained_records = load_reliability_records(config, config.max_log_records)
    if previous is None or boot_changed:
        kernel_summary = update_kernel_event_summary(
            empty_kernel_event_summary(), kernel_events, boot_started_at, now
        )
    elif migrated_from_v1:
        reconstructable = retained_records if boot_started_at is not None else []
        kernel_summary = update_kernel_event_summary(
            empty_kernel_event_summary(),
            [*reconstructable, *kernel_events],
            boot_started_at,
            now,
        )
    elif migrated_from_v2:
        prior_kernel_summary = migrate_v2_kernel_event_summary(
            previous.get("kernelSummary", {}),
            retained_records,
            boot_started_at,
            now,
        )
        kernel_summary = update_kernel_event_summary(
            prior_kernel_summary, kernel_events, boot_started_at, now
        )
    else:
        kernel_summary = update_kernel_event_summary(
            previous.get("kernelSummary", {}), kernel_events, boot_started_at, now
        )

    if precise_rcu_backfill is not None:
        reconstructed = update_kernel_event_summary(
            empty_kernel_event_summary(),
            [*precise_rcu_backfill, *kernel_events],
            boot_started_at,
            now,
        )["rcuExpedited"]
        current_expedited = kernel_summary["rcuExpedited"]
        if int(reconstructed["count"]) > int(current_expedited["count"]):
            kernel_summary["rcuExpedited"] = reconstructed

    state_version = (
        previous_version
        if needs_precision_backfill and precise_rcu_backfill is None
        else 5
    )

    state = {
        "version": state_version,
        "bootId": boot_id,
        "lastSeenAt": now_text,
        "sshListenersAvailable": ssh_available,
        "networkLinkAvailable": network_available,
        "nvmeMitigationActive": mitigation_active,
        "kernelCursor": kernel_cursor,
        "kernelSummary": kernel_summary,
    }
    if existing_reliability_state(state) is None:
        raise ValueError("reliability state did not satisfy the private contract")
    write_pending_reliability_commit(config, events, state)
    replay_pending_reliability_commit(config)
    summary = {
        "bootStartedAt": boot_started_at,
        "collectorGapSeconds": gap_seconds,
        "sshListenersAvailable": ssh_available,
        "networkLinkAvailable": network_available,
        "nvmeMitigationActive": mitigation_active,
    }
    return (summary, kernel_summary) if include_kernel_summary else summary


def publish_rule_evaluation(
    config: Config,
    snapshot: Mapping[str, Any],
    now: dt.datetime,
    monitor_internal: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate rules without allowing this optional subsystem to stop collection."""
    failure = {
        "schemaVersion": 1,
        "status": "collection_error",
        "rulePackVersion": None,
        "evaluatedAt": iso_timestamp(now),
        "summary": {},
        "states": {},
    }
    try:
        from alert_store import evaluate_and_persist

        evaluation_snapshot = dict(snapshot)
        if monitor_internal is not None:
            evaluation_snapshot["_monitor"] = dict(monitor_internal)
        return evaluate_and_persist(
            evaluation_snapshot,
            now,
            config.rule_pack,
            config.output_dir,
            config.max_log_records,
        )
    except Exception:
        # Missing/corrupt alert modules are an explicit rule-evaluation error,
        # not a reason to discard independently collected host telemetry.
        try:
            atomic_write_json(config.output_dir / "rule-evaluation.json", failure)
        except Exception:
            pass
        return failure


def publish_rules_and_commit_delivery_checkpoint(
    config: Config,
    snapshot: Mapping[str, Any],
    now: dt.datetime,
    monitor_internal: Mapping[str, Any],
    delta_path: Path,
    delta_state: Mapping[str, Any],
    notification_counter: int | None,
) -> dict[str, Any]:
    """Advance the delivery counter only after rule state is durable.

    The caller has already persisted the newest telemetry baselines with the
    prior delivery checkpoint.  If evaluation fails, the durable outbox delta
    is therefore retried without rolling back unrelated CPU/network state.  A
    crash after evaluation but before this second write also safely replays the
    deterministic transition on the next collection.
    """

    evaluation = publish_rule_evaluation(config, snapshot, now, monitor_internal)
    if evaluation.get("status") != "ok":
        return evaluation
    committed_delta = dict(delta_state)
    committed_delta["notificationFinalFailures"] = notification_counter
    atomic_write_json(delta_path, committed_delta, 0o600, MAX_DELTA_STATE_BYTES)
    return evaluation


def notification_delivery_signal(
    output_dir: Path,
    prior_counter: Any,
) -> tuple[dict[str, Any], int | None]:
    """Reduce outbox final-failure totals to one interval delta for rules."""

    retained = (
        prior_counter
        if isinstance(prior_counter, int) and not isinstance(prior_counter, bool)
        and prior_counter >= 0
        else None
    )
    configured = os.environ.get("MONITOR_ALERT_DELIVERY_CONFIG")
    if configured is not None:
        if not configured or len(configured) > 512 or "\x00" in configured:
            return {
                "notificationDeliveryStatus": "collection_error",
                "notificationFinalFailureDelta": None,
            }, retained
        config_path = Path(configured)
        if not config_path.is_absolute():
            return {
                "notificationDeliveryStatus": "collection_error",
                "notificationFinalFailureDelta": None,
            }, retained
    else:
        config_path = Path("/etc/monitor/alert-delivery.json")
        try:
            if not config_path.exists():
                return {
                    "notificationDeliveryStatus": "unsupported",
                    "notificationFinalFailureDelta": None,
                }, retained
        except OSError:
            return {
                "notificationDeliveryStatus": "permission_denied",
                "notificationFinalFailureDelta": None,
            }, retained
    try:
        from alert_delivery import DeliveryOutbox, load_delivery_config

        delivery_config = load_delivery_config(config_path)
        status = DeliveryOutbox(
            output_dir / ".state" / "alert-delivery" / "alert-delivery.sqlite",
            delivery_config.queue,
        ).status()
        states = status.get("states")
        max_pending = getattr(delivery_config.queue, "max_pending", None)
        active_count: int | None = None
        if isinstance(states, Mapping):
            active_values = [states.get(key) for key in ("pending", "retry", "leased")]
            if all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in active_values
            ):
                active_count = sum(active_values)
        queue_used_percent = (
            round(100.0 * active_count / max_pending, 2)
            if active_count is not None
            and isinstance(max_pending, int)
            and not isinstance(max_pending, bool)
            and max_pending > 0
            else None
        )
        stats = status.get("stats")
        counter = stats.get("operational_final_failure", 0) if isinstance(stats, Mapping) else None
        if isinstance(counter, bool) or not isinstance(counter, int) or counter < 0:
            raise ValueError("alert delivery counter is invalid")
        delta = counter - retained if retained is not None and counter >= retained else 0
        return {
            "notificationDeliveryStatus": "ok",
            "notificationFinalFailureDelta": delta,
            "notificationQueueActive": active_count,
            "notificationQueueUsedPercent": queue_used_percent,
        }, counter
    except PermissionError:
        status_value = "permission_denied"
    except Exception:
        status_value = "collection_error"
    return {
        "notificationDeliveryStatus": status_value,
        "notificationFinalFailureDelta": None,
        "notificationQueueActive": None,
        "notificationQueueUsedPercent": None,
    }, retained


def monitor_runtime_signal(
    output_dir: Path,
    now: dt.datetime,
    elapsed_seconds: float,
    expected_interval_seconds: int,
) -> dict[str, Any]:
    """Collect bounded health signals for Monitor's own local runtime.

    Unsupported central components remain explicit instead of being reported as
    healthy zeroes.  A completed local write interval is positive evidence for
    the write-failure delta; a collector crash is detected by the independent
    heartbeat/dead-man paths because no new evaluation can be published.
    """

    filesystem_status = "ok"
    filesystem_used_percent: float | None = None
    try:
        usage = shutil.disk_usage(output_dir)
        if usage.total <= 0 or usage.used < 0 or usage.used > usage.total:
            raise ValueError("invalid filesystem usage")
        filesystem_used_percent = round(100.0 * usage.used / usage.total, 2)
    except PermissionError:
        filesystem_status = "permission_denied"
    except (OSError, OverflowError, TypeError, ValueError):
        filesystem_status = "collection_error"

    cadence_status = "no_data"
    cadence_delay: float | None = None
    if math.isfinite(elapsed_seconds) and elapsed_seconds > 0:
        cadence_status = "ok"
        cadence_delay = round(
            max(0.0, elapsed_seconds - max(1, expected_interval_seconds)), 3
        )

    prior_evaluation = load_json(output_dir / "rule-evaluation.json")
    prior_evaluated_at = parse_iso_timestamp(prior_evaluation.get("evaluatedAt"))
    if prior_evaluated_at is not None:
        normalized_now = (
            now if now.tzinfo is not None else now.replace(tzinfo=dt.timezone.utc)
        ).astimezone(dt.timezone.utc)
        age = (normalized_now - prior_evaluated_at).total_seconds()
        if -60 <= age <= MAX_RELIABILITY_DURATION_SECONDS:
            evaluation_delay = max(0.0, age - max(1, expected_interval_seconds))
            cadence_delay = round(
                max(cadence_delay or 0.0, evaluation_delay), 3
            )
            cadence_status = "ok"

    return {
        "ingestStatus": "unsupported",
        "ingestLagSeconds": None,
        "metricsQueueStatus": "unsupported",
        "metricsQueueUsedPercent": None,
        "logsQueueStatus": "unsupported",
        "logsQueueUsedPercent": None,
        "storageWriteStatus": "ok",
        "storageWriteFailureDelta": 0,
        "alertEvaluationStatus": cadence_status,
        "alertEvaluationDelaySeconds": cadence_delay,
        "monitoringFilesystemStatus": filesystem_status,
        "monitoringFilesystemUsedPercent": filesystem_used_percent,
        "externalHeartbeatStatus": "unsupported",
        "externalHeartbeatAvailable": None,
    }


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
        replay_pending_reliability_commit(config)
        delta_path = config.runtime_dir / "delta-state.json"
        prior = load_json(delta_path, MAX_DELTA_STATE_BYTES)
        incident_lifecycle_path = config.output_dir / ".state" / "incident-lifecycle.json"
        durable_incident_state = load_json(incident_lifecycle_path)
        previous_incident_state = durable_incident_state or prior.get("incident")
        monotonic = _sample_monotonic()
        elapsed = monotonic - (finite_number(prior.get("monotonic"), monotonic) or monotonic)

        mountinfo = read_text(config.mountinfo_path)
        filesystems = collect_filesystems(mountinfo, config.mount_root)
        if config.mountinfo is not None and not filesystems:
            # A configured host-namespace mount source is a required production
            # observation surface. Preserve the previous complete snapshot if
            # its bind disappears instead of publishing a false empty inventory.
            raise RuntimeError("configured mountinfo has no collectable filesystems")

        proc_stat = read_text(config.proc_root / "stat")
        cpu = parse_proc_stat(proc_stat)
        previous_cpu = prior.get("cpu")
        host_cpu_delta = 0
        if cpu is not None and isinstance(previous_cpu, list) and len(previous_cpu) == 2:
            try:
                host_cpu_delta = max(0, cpu[0] - int(previous_cpu[0]))
            except (TypeError, ValueError):
                host_cpu_delta = 0
        meminfo = read_text(config.proc_root / "meminfo")
        memory_total, memory_available = parse_meminfo(meminfo)
        swap_total, swap_used, swap_percent = parse_swapinfo(meminfo)
        network = parse_net_dev(read_text(config.proc_root / "net" / "dev"))
        disk = parse_diskstats(read_text(config.proc_root / "diskstats"))
        network_rates = network_rate_values(network, prior.get("network"), elapsed)
        disk_rates = rate_pair(disk, prior.get("disk"), elapsed)
        temperature = read_temperature(config.sys_root)
        pressure = collect_pressure(config.proc_root)
        gpu = collect_gpu(config.vcgencmd, config.command_timeout, config.sys_root)
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
            "swapTotalBytes": swap_total,
            "swapUsedBytes": swap_used,
            "swapPercent": swap_percent,
            "temperatureC": temperature,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "cpuPressureSomeAvg10": pressure["cpu"]["someAvg10"],
            "cpuPressureFullAvg10": pressure["cpu"]["fullAvg10"],
            "memoryPressureSomeAvg10": pressure["memory"]["someAvg10"],
            "memoryPressureFullAvg10": pressure["memory"]["fullAvg10"],
            "ioPressureSomeAvg10": pressure["io"]["someAvg10"],
            "ioPressureFullAvg10": pressure["io"]["fullAvg10"],
            "powerState": power_state,
            "supplyVoltageVolts": supply_voltage,
            "throttledFlags": power_flags,
            "gpuMemoryBytes": gpu.get("gpuMemoryBytes") if isinstance(gpu.get("gpuMemoryBytes"), int) else None,
            "gpuClockHz": gpu.get("gpuClockHz") if isinstance(gpu.get("gpuClockHz"), int) else None,
            "networkRxBytesPerSecond": network_rates[0],
            "networkTxBytesPerSecond": network_rates[1],
            "networkRxErrorsPerSecond": network_rates[2],
            "networkTxErrorsPerSecond": network_rates[3],
            "networkRxDroppedPerSecond": network_rates[4],
            "networkTxDroppedPerSecond": network_rates[5],
            "diskReadBytesPerSecond": disk_rates[0],
            "diskWriteBytesPerSecond": disk_rates[1],
        }
        assert tuple(latest) == SAMPLE_FIELDS

        uptime_seconds = parse_uptime(read_text(config.proc_root / "uptime", 128))
        host = {
            "hostname": bounded_text(socket.gethostname(), 255),
            "os": parse_os_release(read_text(config.etc_root / "os-release", 8192)),
            "architecture": bounded_text(platform.machine() or "unknown", 64),
            "logicalCpuCount": parse_logical_cpu_count(proc_stat),
            "uptimeSeconds": uptime_seconds,
        }
        (
            containers, container_collection, container_cpu_state,
            docker_event_collection, docker_events, docker_event_state,
        ) = collect_container_telemetry(config, prior, now)
        processes, process_cpu_state = collect_processes(
            config.proc_root, prior.get("processes"), host_cpu_delta, config.process_uids
        )
        traffic, traffic_cursor, traffic_available = collect_traffic(config, now)
        reliability, kernel_summary = collect_reliability(
            config, now, uptime_seconds, include_kernel_summary=True
        )
        system = collect_system(config, kernel_summary)
        linux, linux_delta_state = collect_linux_telemetry(
            proc_root=config.proc_root,
            sys_root=config.sys_root,
            mountinfo_path=config.mountinfo_path,
            mount_root=config.mount_root,
            docker_data_root=config.docker_data_root,
            kernel_log=config.kernel_log,
            kernel_summary=kernel_summary,
            previous=prior.get("linux"),
            elapsed_seconds=elapsed,
            now=now,
            loadavg=(load1, load5, load15),
            allowed_uids=set(config.process_uids) & set(ALLOWED_PROCESS_UIDS),
            process_allowlist=config.process_allowlist,
            process_name_sanitizer=safe_process_name,
            systemd_units=config.systemd_units,
            systemd_state_dir=config.systemd_state_dir,
            systemctl=config.systemctl,
            timedatectl=config.timedatectl,
            command_timeout=config.command_timeout,
            rpi_data=gpu,
        )
        identity, heartbeat = prepare_identity(config, now)
        synthetic_probe_collection, synthetic_probes = collect_synthetic_probes(
            config.synthetic_input, now
        )
        current = {
            "schemaVersion": CURRENT_SCHEMA_VERSION,
            "generatedAt": now_text,
            "identity": identity,
            "heartbeat": heartbeat,
            "host": host,
            "latest": latest,
            "disks": filesystems,
            "containers": containers,
            "containerCollection": container_collection,
            "dockerEventCollection": docker_event_collection,
            "dockerEvents": docker_events,
            "syntheticProbeCollection": synthetic_probe_collection,
            "syntheticProbes": synthetic_probes,
            "currentTraffic": traffic,
            "reliability": reliability,
            "system": system,
            "linux": linux,
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
        collect_generic_logs(
            config.output_dir,
            config.log_sources_config,
            now,
            required=config.log_sources_required,
            journalctl=config.journalctl,
            command_timeout=config.command_timeout,
            retention_days=config.generic_log_retention_days,
            max_records=config.generic_log_max_records,
            max_file_bytes=config.generic_log_max_file_bytes,
            total_timeout=config.generic_log_total_timeout,
        )
        prior_notification_counter = prior.get("notificationFinalFailures")
        if (
            isinstance(prior_notification_counter, bool)
            or not isinstance(prior_notification_counter, int)
            or prior_notification_counter < 0
        ):
            prior_notification_counter = None
        notification_signal, notification_counter = notification_delivery_signal(
            config.output_dir, prior_notification_counter
        )
        monitor_signal = monitor_runtime_signal(
            config.output_dir,
            now,
            elapsed,
            config.expected_interval_seconds,
        )
        monitor_signal.update(notification_signal)
        delta_state = {
            "monotonic": monotonic,
            "cpu": list(cpu) if cpu else None,
            "network": list(network) if network is not None else None,
            "disk": list(disk) if disk is not None else None,
            "containers": container_cpu_state,
            "dockerEvents": docker_event_state,
            "processes": process_cpu_state,
            "linux": linux_delta_state,
            "notificationFinalFailures": prior_notification_counter,
            "incident": incident_state,
        }
        atomic_write_json(delta_path, delta_state, 0o600, MAX_DELTA_STATE_BYTES)
        publish_rules_and_commit_delivery_checkpoint(
            config,
            current,
            now,
            monitor_signal,
            delta_path,
            delta_state,
            notification_counter,
        )
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
