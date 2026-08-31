#!/usr/bin/env python3
"""Pure, exact-schema projection from local snapshots to central agent records.

This module deliberately has no filesystem or transport dependencies.  It is
the single allowlist between the much wider local collector snapshot and the
small central-ingest record contract.
"""

from __future__ import annotations

import datetime as dt
import math
import re
import uuid
from collections.abc import Mapping
from typing import Any


MAX_SAFE_INTEGER = 2**53 - 1
RFC3339_MILLISECONDS = re.compile(
    r"^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T"
    r"([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
HEX_32 = re.compile(r"^[a-f0-9]{32}$")

CURRENT_KEYS = {
    "schemaVersion",
    "generatedAt",
    "identity",
    "heartbeat",
    "host",
    "latest",
    "disks",
    "containers",
    "containerCollection",
    "dockerEventCollection",
    "dockerEvents",
    "currentTraffic",
    "reliability",
    "system",
    "linux",
}
IDENTITY_KEYS = {
    "hostId",
    "agentId",
    "installationEpoch",
    "identityGeneration",
    "machineIdentityStatus",
    "bootId",
}
HEARTBEAT_KEYS = {
    "sequence",
    "observedAt",
    "receivedAt",
    "expectedIntervalSeconds",
    "lifecycle",
    "transport",
}
LATEST_KEYS = {
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
    "networkRxErrorsPerSecond",
    "networkTxErrorsPerSecond",
    "networkRxDroppedPerSecond",
    "networkTxDroppedPerSecond",
    "diskReadBytesPerSecond",
    "diskWriteBytesPerSecond",
}

SELF_METRICS_KEYS = {
    "schemaVersion",
    "agentId",
    "observedAt",
    "runDurationSeconds",
    "userCpuSeconds",
    "systemCpuSeconds",
    "maxRssBytes",
    "ioReadBytes",
    "ioWriteBytes",
    "ioReadSyscalls",
    "ioWriteSyscalls",
    "resourceUsageStatus",
    "procIoStatus",
    "priorStateStatus",
    "outcomes",
    "retryStreaks",
    "lastHeartbeatAckAt",
    "heartbeatAckAgeSeconds",
    "spool",
    "quarantine",
}
SELF_OUTCOME_KEYS = {"enrollment", "heartbeat", "ingest"}
SELF_RETRY_KEYS = SELF_OUTCOME_KEYS
SELF_SPOOL_KEYS = {
    "entries",
    "bytes",
    "maxEntries",
    "maxBytes",
    "entriesUsedPercent",
    "bytesUsedPercent",
    "oldestAgeSeconds",
}
SELF_QUARANTINE_KEYS = {
    "entries",
    "bytes",
    "oldestAgeSeconds",
    "status",
    "batchTooOldEntries",
    "dataTooOldEntries",
}

SELF_INPUT_STATUSES = {
    "valid": 0,
    "missing": 1,
    "corrupt": 2,
    "unreadable": 3,
    "stale": 4,
}
SELF_METRICS_STALE_AFTER_SECONDS = 60
QUARANTINE_STATUS_CODES = {"empty": 0, "retained": 1}
RESOURCE_STATUSES = {"available", "unavailable"}
PROC_IO_STATUSES = {"available", "missing", "corrupt", "unreadable"}
PRIOR_STATE_STATUSES = {"valid", "missing", "corrupt", "unwritable"}
OUTCOME_CODES = {
    "not-enrolled": 0,
    "not-pending": 1,
    "not-due": 1,
    "empty": 1,
    "backoff": 2,
    "retry-scheduled": 3,
    "acknowledged": 4,
    "error": 5,
    "quarantined": 6,
}

LATEST_METRICS = {
    "cpuPercent": "host.cpu.percent",
    "memoryPercent": "host.memory.percent",
    "memoryUsedBytes": "host.memory.used_bytes",
    "memoryTotalBytes": "host.memory.total_bytes",
    "swapTotalBytes": "host.swap.total_bytes",
    "swapUsedBytes": "host.swap.used_bytes",
    "swapPercent": "host.swap.percent",
    "temperatureC": "host.temperature.celsius",
    "load1": "host.load.1",
    "load5": "host.load.5",
    "load15": "host.load.15",
    "cpuPressureSomeAvg10": "host.pressure.cpu.some_avg10",
    "cpuPressureFullAvg10": "host.pressure.cpu.full_avg10",
    "memoryPressureSomeAvg10": "host.pressure.memory.some_avg10",
    "memoryPressureFullAvg10": "host.pressure.memory.full_avg10",
    "ioPressureSomeAvg10": "host.pressure.io.some_avg10",
    "ioPressureFullAvg10": "host.pressure.io.full_avg10",
    "supplyVoltageVolts": "host.power.supply_volts",
    "throttledFlags": "host.power.throttled_flags",
    "gpuMemoryBytes": "host.gpu.memory_bytes",
    "gpuClockHz": "host.gpu.clock_hz",
    "networkRxBytesPerSecond": "host.network.rx_bytes_per_second",
    "networkTxBytesPerSecond": "host.network.tx_bytes_per_second",
    "networkRxErrorsPerSecond": "host.network.rx_errors_per_second",
    "networkTxErrorsPerSecond": "host.network.tx_errors_per_second",
    "networkRxDroppedPerSecond": "host.network.rx_dropped_per_second",
    "networkTxDroppedPerSecond": "host.network.tx_dropped_per_second",
    "diskReadBytesPerSecond": "host.disk.read_bytes_per_second",
    "diskWriteBytesPerSecond": "host.disk.write_bytes_per_second",
}

SELF_VALUE_METRICS = {
    "runDurationSeconds": "agent.self.run_duration_seconds",
    "userCpuSeconds": "agent.self.user_cpu_seconds",
    "systemCpuSeconds": "agent.self.system_cpu_seconds",
    "maxRssBytes": "agent.self.max_rss_bytes",
    "ioReadBytes": "agent.self.io_read_bytes",
    "ioWriteBytes": "agent.self.io_write_bytes",
    "ioReadSyscalls": "agent.self.io_read_syscalls",
    "ioWriteSyscalls": "agent.self.io_write_syscalls",
    "heartbeatAckAgeSeconds": "agent.self.heartbeat_ack_age_seconds",
}


class AgentRecordError(ValueError):
    """A collector/self-metrics value does not satisfy the exact allowlist."""


def _exact_mapping(value: object, keys: set[str], description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AgentRecordError(f"{description} has an invalid exact schema")
    return value


def _timestamp(value: object, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value.endswith("Z")
        or RFC3339_MILLISECONDS.fullmatch(value) is None
    ):
        raise AgentRecordError(f"{description} is not an RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AgentRecordError(f"{description} is not a real timestamp") from error
    if parsed.tzinfo is None or not 0 <= parsed.timestamp() * 1000 <= 253_402_300_799_999:
        raise AgentRecordError(f"{description} is outside the supported timestamp range")
    return value


def _timestamp_epoch_ms(value: object, description: str) -> int:
    normalized = _timestamp(value, description)
    parsed = dt.datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    return round(parsed.timestamp() * 1000)


def _uuid_v4(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise AgentRecordError(f"{description} is not a UUIDv4")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise AgentRecordError(f"{description} is not a UUIDv4") from error
    if str(parsed) != value or parsed.version != 4:
        raise AgentRecordError(f"{description} is not a canonical UUIDv4")
    return value


def _safe_integer(value: object, description: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        raise AgentRecordError(f"{description} is not a bounded integer")
    return value


def _finite_or_none(
    value: object,
    description: str,
    minimum: float = 0.0,
    maximum: float = 1_000_000_000_000_000.0,
) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgentRecordError(f"{description} is not a finite number or null")
    try:
        parsed = float(value)
    except OverflowError as error:
        raise AgentRecordError(f"{description} is not finite") from error
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise AgentRecordError(f"{description} is outside its fixed bound")
    return value


def validate_current(value: object) -> dict[str, Any]:
    """Validate the exact collector-v2 shell and every projected field."""

    current = _exact_mapping(value, CURRENT_KEYS, "collector current.json")
    if current["schemaVersion"] != 2:
        raise AgentRecordError("collector current.json schemaVersion must be 2")
    generated_at = _timestamp(current["generatedAt"], "collector generatedAt")
    identity = _exact_mapping(current["identity"], IDENTITY_KEYS, "collector identity")
    heartbeat = _exact_mapping(current["heartbeat"], HEARTBEAT_KEYS, "collector heartbeat")
    latest = _exact_mapping(current["latest"], LATEST_KEYS, "collector latest sample")

    host_id = _uuid_v4(identity["hostId"], "collector hostId")
    agent_id = _uuid_v4(identity["agentId"], "collector agentId")
    if host_id == agent_id:
        raise AgentRecordError("collector hostId and agentId must be distinct")
    installation_epoch = _timestamp(identity["installationEpoch"], "collector installationEpoch")
    identity_generation = _safe_integer(
        identity["identityGeneration"], "collector identityGeneration", 1
    )
    if identity["machineIdentityStatus"] not in {"bound", "unavailable"}:
        raise AgentRecordError("collector machineIdentityStatus is invalid")
    boot_id = identity["bootId"]
    if boot_id is not None and (not isinstance(boot_id, str) or HEX_32.fullmatch(boot_id) is None):
        raise AgentRecordError("collector bootId is invalid")

    source_sequence = _safe_integer(heartbeat["sequence"], "collector heartbeat sequence", 1)
    observed_at = _timestamp(heartbeat["observedAt"], "collector heartbeat observedAt")
    received_at = _timestamp(heartbeat["receivedAt"], "collector heartbeat receivedAt")
    interval = _safe_integer(
        heartbeat["expectedIntervalSeconds"], "collector heartbeat interval", 10
    )
    if interval > 86_400:
        raise AgentRecordError("collector heartbeat interval exceeds one day")
    if heartbeat["lifecycle"] not in {"active", "maintenance", "inactive"}:
        raise AgentRecordError("collector heartbeat lifecycle is invalid")
    if heartbeat["transport"] != "local-file":
        raise AgentRecordError("collector heartbeat transport must be local-file")
    latest_at = _timestamp(latest["timestamp"], "collector latest timestamp")
    if generated_at != observed_at or generated_at != received_at or generated_at != latest_at:
        raise AgentRecordError("collector timestamps do not describe one atomic snapshot")
    if _timestamp_epoch_ms(
        installation_epoch, "collector installationEpoch"
    ) > _timestamp_epoch_ms(generated_at, "collector generatedAt"):
        raise AgentRecordError("collector installationEpoch follows the snapshot")

    field_bounds = {
        "cpuPercent": (0.0, 100.0),
        "memoryPercent": (0.0, 100.0),
        "swapPercent": (0.0, 100.0),
        "temperatureC": (-273.15, 1000.0),
        "supplyVoltageVolts": (0.0, 10.0),
        "throttledFlags": (0.0, float(2**32 - 1)),
        "cpuPressureSomeAvg10": (0.0, 100.0),
        "cpuPressureFullAvg10": (0.0, 100.0),
        "memoryPressureSomeAvg10": (0.0, 100.0),
        "memoryPressureFullAvg10": (0.0, 100.0),
        "ioPressureSomeAvg10": (0.0, 100.0),
        "ioPressureFullAvg10": (0.0, 100.0),
    }
    byte_fields = {
        "memoryUsedBytes",
        "memoryTotalBytes",
        "swapTotalBytes",
        "swapUsedBytes",
        "gpuMemoryBytes",
        "gpuClockHz",
        "throttledFlags",
    }
    for field in LATEST_METRICS:
        minimum, maximum = field_bounds.get(field, (0.0, float(MAX_SAFE_INTEGER)))
        normalized = _finite_or_none(
            latest[field], f"collector latest {field}", minimum, maximum
        )
        if field in byte_fields and normalized is not None and (
            not isinstance(normalized, int) or isinstance(normalized, bool)
        ):
            raise AgentRecordError(f"collector latest {field} must be an integer or null")
    if (
        latest["memoryUsedBytes"] is not None
        and latest["memoryTotalBytes"] is not None
        and latest["memoryUsedBytes"] > latest["memoryTotalBytes"]
    ):
        raise AgentRecordError("collector memory used bytes exceeds total bytes")
    if (
        latest["swapUsedBytes"] is not None
        and latest["swapTotalBytes"] is not None
        and latest["swapUsedBytes"] > latest["swapTotalBytes"]
    ):
        raise AgentRecordError("collector swap used bytes exceeds total bytes")
    power_state = latest["powerState"]
    if power_state not in {
        None,
        "normal",
        "degraded-history",
        "throttled",
        "thermal-limit",
        "frequency-capped",
        "under-voltage",
    }:
        raise AgentRecordError("collector latest powerState is invalid")

    # Unprojected wide sections must at least retain their fixed container type;
    # no value from them crosses this module's explicit metric map.
    for name in {"host", "containerCollection", "dockerEventCollection", "reliability", "system", "linux"}:
        if not isinstance(current[name], Mapping):
            raise AgentRecordError(f"collector {name} must be an object")
    for name in {"disks", "containers", "dockerEvents", "currentTraffic"}:
        if not isinstance(current[name], list):
            raise AgentRecordError(f"collector {name} must be an array")

    return {
        "hostId": host_id,
        "agentId": agent_id,
        "installationEpoch": installation_epoch,
        "identityGeneration": identity_generation,
        "sourceSequence": source_sequence,
        "observedAt": observed_at,
        "latest": dict(latest),
    }


def validate_self_metrics(value: object, expected_agent_id: str) -> dict[str, Any]:
    metrics = _exact_mapping(value, SELF_METRICS_KEYS, "agent self-metrics")
    if metrics["schemaVersion"] != 1 or metrics["agentId"] != expected_agent_id:
        raise AgentRecordError("agent self-metrics identity or schema version is invalid")
    observed_at = _timestamp(metrics["observedAt"], "agent self-metrics observedAt")
    for field in SELF_VALUE_METRICS:
        _finite_or_none(metrics[field], f"agent self-metrics {field}")
    if metrics["resourceUsageStatus"] not in RESOURCE_STATUSES:
        raise AgentRecordError("agent self-metrics resourceUsageStatus is invalid")
    if metrics["procIoStatus"] not in PROC_IO_STATUSES:
        raise AgentRecordError("agent self-metrics procIoStatus is invalid")
    if metrics["priorStateStatus"] not in PRIOR_STATE_STATUSES:
        raise AgentRecordError("agent self-metrics priorStateStatus is invalid")
    resource_values = (
        metrics["userCpuSeconds"], metrics["systemCpuSeconds"], metrics["maxRssBytes"]
    )
    if metrics["resourceUsageStatus"] == "available":
        if any(item is None for item in resource_values):
            raise AgentRecordError("available resource usage is missing a measurement")
    elif any(item is not None for item in resource_values):
        raise AgentRecordError("unavailable resource usage contains a measurement")
    io_values = (
        metrics["ioReadBytes"],
        metrics["ioWriteBytes"],
        metrics["ioReadSyscalls"],
        metrics["ioWriteSyscalls"],
    )
    if metrics["procIoStatus"] == "available":
        if any(item is None for item in io_values):
            raise AgentRecordError("available proc I/O is missing a measurement")
    elif any(item is not None for item in io_values):
        raise AgentRecordError("unavailable proc I/O contains a measurement")
    outcomes = _exact_mapping(metrics["outcomes"], SELF_OUTCOME_KEYS, "agent outcomes")
    retries = _exact_mapping(metrics["retryStreaks"], SELF_RETRY_KEYS, "agent retry streaks")
    for name in SELF_OUTCOME_KEYS:
        if outcomes[name] not in OUTCOME_CODES:
            raise AgentRecordError(f"agent {name} outcome is invalid")
        _safe_integer(retries[name], f"agent {name} retry streak")
    last_ack = metrics["lastHeartbeatAckAt"]
    if last_ack is not None:
        _timestamp(last_ack, "agent lastHeartbeatAckAt")
    if (last_ack is None) != (metrics["heartbeatAckAgeSeconds"] is None):
        raise AgentRecordError("agent heartbeat acknowledgement fields disagree")

    spool = _exact_mapping(metrics["spool"], SELF_SPOOL_KEYS, "agent spool metrics")
    entries = _safe_integer(spool["entries"], "agent spool entries")
    size = _safe_integer(spool["bytes"], "agent spool bytes")
    max_entries = _safe_integer(spool["maxEntries"], "agent spool maxEntries", 1)
    max_bytes = _safe_integer(spool["maxBytes"], "agent spool maxBytes", 1)
    if entries > max_entries or size > max_bytes:
        raise AgentRecordError("agent spool usage exceeds its declared maximum")
    _finite_or_none(spool["entriesUsedPercent"], "agent spool entriesUsedPercent", 0, 100)
    _finite_or_none(spool["bytesUsedPercent"], "agent spool bytesUsedPercent", 0, 100)
    _finite_or_none(spool["oldestAgeSeconds"], "agent spool oldestAgeSeconds")
    if (entries == 0) != (spool["oldestAgeSeconds"] is None):
        raise AgentRecordError("agent spool oldest age does not match its entry count")

    quarantine = _exact_mapping(
        metrics["quarantine"], SELF_QUARANTINE_KEYS, "agent quarantine metrics"
    )
    quarantine_entries = _safe_integer(
        quarantine["entries"], "agent quarantine entries"
    )
    _safe_integer(quarantine["bytes"], "agent quarantine bytes")
    batch_too_old = _safe_integer(
        quarantine["batchTooOldEntries"], "agent quarantine batch-too-old entries"
    )
    data_too_old = _safe_integer(
        quarantine["dataTooOldEntries"], "agent quarantine data-too-old entries"
    )
    _finite_or_none(
        quarantine["oldestAgeSeconds"], "agent quarantine oldestAgeSeconds"
    )
    if (
        quarantine["status"] not in QUARANTINE_STATUS_CODES
        or (quarantine_entries == 0) != (quarantine["oldestAgeSeconds"] is None)
        or (quarantine_entries == 0) != (quarantine["status"] == "empty")
        or batch_too_old + data_too_old != quarantine_entries
    ):
        raise AgentRecordError("agent quarantine counters or status disagree")
    return {
        "observedAt": observed_at,
        "values": {field: metrics[field] for field in SELF_VALUE_METRICS},
        "resourceUsageStatus": metrics["resourceUsageStatus"],
        "procIoStatus": metrics["procIoStatus"],
        "priorStateStatus": metrics["priorStateStatus"],
        "outcomes": dict(outcomes),
        "retryStreaks": dict(retries),
        "spool": dict(spool),
        "quarantine": dict(quarantine),
    }


def _metric(metric: str, observed_at: str, value: int | float) -> dict[str, Any]:
    return {
        "kind": "metric",
        "metric": metric,
        "target": "host:primary",
        "observedAt": observed_at,
        "value": value,
        "severity": None,
    }


def project_records(
    current: object,
    self_metrics: object | None = None,
    *,
    self_metrics_status: str = "missing",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return validated source identity and only fixed, low-cardinality records."""

    source = validate_current(current)
    records: list[dict[str, Any]] = []
    observed_at = source["observedAt"]
    latest = source["latest"]
    for field, metric_name in LATEST_METRICS.items():
        value = latest[field]
        if value is not None:
            records.append(_metric(metric_name, observed_at, value))
    power_state = latest["powerState"]
    if power_state not in {None, "normal"}:
        severity = (
            "critical"
            if power_state in {"throttled", "thermal-limit", "under-voltage"}
            else "warning"
        )
        records.append({
            "kind": "event",
            "metric": "host.power.state",
            "target": "host:primary",
            "observedAt": observed_at,
            "value": None,
            "severity": severity,
        })

    if self_metrics_status not in SELF_INPUT_STATUSES:
        raise AgentRecordError("self-metrics reader status is invalid")
    if self_metrics_status in {"valid", "stale"}:
        if self_metrics is None:
            raise AgentRecordError("available self-metrics status requires a value")
        normalized_self = validate_self_metrics(self_metrics, source["agentId"])
        self_at = normalized_self["observedAt"]
        sample_age_seconds = round(max(
            0,
            _timestamp_epoch_ms(observed_at, "collector observedAt")
            - _timestamp_epoch_ms(self_at, "agent self-metrics observedAt"),
        ) / 1000, 3)
        effective_status = (
            "stale"
            if self_metrics_status == "stale"
            or sample_age_seconds > SELF_METRICS_STALE_AFTER_SECONDS
            else "valid"
        )
        # Self-metrics describe a prior transport run.  Every projection record
        # uses the fresh collector checkpoint time, while sample age preserves
        # the source time explicitly.  An old optional file can therefore never
        # make otherwise-fresh host telemetry fail the server backfill window.
        records.append(_metric(
            "agent.self.metrics_available", observed_at, int(effective_status == "valid")
        ))
        records.append(_metric(
            "agent.self.metrics_status_code",
            observed_at,
            SELF_INPUT_STATUSES[effective_status],
        ))
        records.append(_metric(
            "agent.self.sample_age_seconds", observed_at, sample_age_seconds
        ))
        if effective_status == "valid":
            for field, metric_name in SELF_VALUE_METRICS.items():
                value = normalized_self["values"][field]
                if value is not None:
                    records.append(_metric(metric_name, observed_at, value))
            records.extend([
                _metric(
                    "agent.self.resource_usage_available",
                    observed_at,
                    int(normalized_self["resourceUsageStatus"] == "available"),
                ),
                _metric(
                    "agent.self.proc_io_available",
                    observed_at,
                    int(normalized_self["procIoStatus"] == "available"),
                ),
                _metric(
                    "agent.self.prior_state_available",
                    observed_at,
                    int(normalized_self["priorStateStatus"] == "valid"),
                ),
            ])
            for name in sorted(SELF_OUTCOME_KEYS):
                records.append(_metric(
                    f"agent.self.{name}_outcome_code",
                    observed_at,
                    OUTCOME_CODES[normalized_self["outcomes"][name]],
                ))
                records.append(_metric(
                    f"agent.self.{name}_retry_streak",
                    observed_at,
                    normalized_self["retryStreaks"][name],
                ))
            spool = normalized_self["spool"]
            spool_fields = {
                "entries": "agent.spool.entries",
                "bytes": "agent.spool.bytes",
                "maxEntries": "agent.spool.max_entries",
                "maxBytes": "agent.spool.max_bytes",
                "entriesUsedPercent": "agent.spool.entries_used_percent",
                "bytesUsedPercent": "agent.spool.bytes_used_percent",
                "oldestAgeSeconds": "agent.spool.oldest_age_seconds",
            }
            for name, metric_name in spool_fields.items():
                if spool[name] is not None:
                    records.append(_metric(metric_name, observed_at, spool[name]))
            quarantine = normalized_self["quarantine"]
            quarantine_fields = {
                "entries": "agent.quarantine.entries",
                "bytes": "agent.quarantine.bytes",
                "oldestAgeSeconds": "agent.quarantine.oldest_age_seconds",
                "batchTooOldEntries": "agent.quarantine.batch_too_old_entries",
                "dataTooOldEntries": "agent.quarantine.data_too_old_entries",
            }
            for name, metric_name in quarantine_fields.items():
                if quarantine[name] is not None:
                    records.append(_metric(
                        metric_name, observed_at, quarantine[name]
                    ))
            records.append(_metric(
                "agent.quarantine.status_code",
                observed_at,
                QUARANTINE_STATUS_CODES[quarantine["status"]],
            ))
    else:
        if self_metrics is not None:
            raise AgentRecordError("unavailable self-metrics status must not include a value")
        records.append(_metric("agent.self.metrics_available", observed_at, 0))
        records.append(_metric(
            "agent.self.metrics_status_code",
            observed_at,
            SELF_INPUT_STATUSES[self_metrics_status],
        ))
    return source, records


__all__ = [
    "AgentRecordError",
    "CURRENT_KEYS",
    "HEARTBEAT_KEYS",
    "IDENTITY_KEYS",
    "LATEST_KEYS",
    "SELF_METRICS_KEYS",
    "project_records",
    "validate_current",
    "validate_self_metrics",
]
