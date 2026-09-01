"""Translate the reduced collector snapshot into bounded alert observations."""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import re
from typing import Any, Mapping, Sequence

try:  # Package imports for tests; direct imports for the installed scripts.
    from .alert_engine import Observation, RulePack, evaluate_rule_pack
except ImportError:  # pragma: no cover - exercised by collector integration
    from alert_engine import Observation, RulePack, evaluate_rule_pack


SAFE_TARGET = re.compile(r"[^a-zA-Z0-9_.:/-]+")
OPAQUE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SYNTHETIC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
CONTAINER_RULES = frozenset({
    "ContainerDown", "ContainerRestartLoop", "ContainerOOMKilled", "ContainerUnhealthy",
    "ContainerCpuHigh", "ContainerCpuThrottlingHigh", "ContainerMemoryNearLimit",
    "ContainerPidNearLimit", "ContainerNetworkErrors", "ContainerWritableLayerHigh",
    "ContainerNoMemoryLimit", "ContainerNoCpuLimit", "ContainerNoHealthcheck",
    "ContainerPrivileged", "ContainerDockerSocketMounted", "ContainerImageDigestDrift",
    "ContainerUsingLatestTag",
})
SYNTHETIC_RULES = frozenset({
    "HttpEndpointDown", "HttpLatencyHigh",
    "TlsCertificateExpiring", "TlsCertificateInvalid",
})
SWAP_PRESSURE_MEMORY_USED_PERCENT = 75.0
SWAP_PRESSURE_MEMORY_PSI_SOME_AVG10 = 1.0
SWAP_PRESSURE_MEMORY_PSI_FULL_AVG10 = 0.2


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def _pressure_gated_swap_percent(latest: Mapping[str, Any]) -> float | None:
    """Treat retained swap as healthy unless current memory pressure is proven.

    A non-pressure observation is a valid false compound condition even when
    the raw swap percentage is absent. If pressure is active, however, the raw
    swap value is still required so the rule cannot invent a breach or recovery.
    These thresholds match the operator-facing resource-pressure assessment.
    """

    memory_percent = _number(latest.get("memoryPercent"))
    memory_some = _number(latest.get("memoryPressureSomeAvg10"))
    memory_full = _number(latest.get("memoryPressureFullAvg10"))
    if memory_percent is None and memory_some is None and memory_full is None:
        return None
    pressure_active = (
        memory_percent is not None
        and memory_percent >= SWAP_PRESSURE_MEMORY_USED_PERCENT
    ) or (
        memory_some is not None
        and memory_some >= SWAP_PRESSURE_MEMORY_PSI_SOME_AVG10
    ) or (
        memory_full is not None
        and memory_full >= SWAP_PRESSURE_MEMORY_PSI_FULL_AVG10
    )
    return _number(latest.get("swapPercent")) if pressure_active else 0.0


def _timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _age_seconds(reference: dt.datetime | None, observed: Any) -> float | None:
    timestamp = _timestamp(observed)
    if reference is None or timestamp is None:
        return None
    age = (reference - timestamp).total_seconds()
    return age if 0 <= age <= 366 * 86400 else None


def _target(prefix: str, value: Any, fallback: str) -> str:
    text = value if isinstance(value, str) else fallback
    normalized = SAFE_TARGET.sub("-", text.strip())[:96].strip("-./:")
    return f"{prefix}/{normalized or fallback}"


def _filesystem_target(value: Any) -> str:
    mount = value if isinstance(value, str) else "unknown"
    digest = hashlib.sha256(mount.encode("utf-8", "replace")).hexdigest()[:16]
    return f"filesystem/{digest}"


def _observation(target: str, value: Any, status_when_missing: str = "no_data", **labels: str) -> Observation:
    number = _number(value)
    return Observation(
        target=target,
        value=number,
        status="ok" if number is not None else status_when_missing,
        labels=tuple(sorted(labels.items())),
    )


def _container_source_status(snapshot: Mapping[str, Any]) -> str:
    collection = _mapping(snapshot.get("containerCollection"))
    value = collection.get("status")
    return value if value in {"fresh", "last-known", "unavailable", "permission-denied", "unsupported"} else "unavailable"


def _observation_status_for_source(source_status: str) -> str:
    return {
        "fresh": "ok",
        "last-known": "stale",
        "unavailable": "collection_error",
        "permission-denied": "permission_denied",
        "unsupported": "unsupported",
    }[source_status]


def _linux_observation_status(section: Mapping[str, Any]) -> str:
    if "status" not in section:
        return "unsupported"
    return {
        "supported": "ok",
        "partial": "ok",
        "unsupported": "unsupported",
        "permission_error": "permission_denied",
        "unavailable": "collection_error",
        "invalid": "collection_error",
    }.get(section.get("status"), "collection_error")


def _source_observation(
    target: str,
    value: Any,
    section: Mapping[str, Any],
    **labels: str,
) -> Observation:
    status = _linux_observation_status(section)
    if status != "ok":
        return Observation(target, None, status, tuple(sorted(labels.items())))
    return _observation(target, value, **labels)


def observations_for_snapshot(pack: RulePack, snapshot: Mapping[str, Any]) -> dict[str, list[Observation]]:
    """Return observations for signals the current collector can prove.

    Every configured rule receives an explicit observation.  Rules whose input
    is not yet collected are ``unsupported`` rather than silently appearing
    healthy.  This is also the compatibility behavior for older snapshots.
    """

    identity = _mapping(snapshot.get("identity"))
    host = _mapping(snapshot.get("host"))
    latest = _mapping(snapshot.get("latest"))
    system = _mapping(snapshot.get("system"))
    monitor_internal = _mapping(snapshot.get("_monitor"))
    kernel = _mapping(system.get("kernel"))
    linux = _mapping(snapshot.get("linux"))
    linux_cpu = _mapping(linux.get("cpu"))
    linux_cpu_total = _mapping(linux_cpu.get("total"))
    linux_memory = _mapping(linux.get("memory"))
    host_id = identity.get("hostId")
    if not isinstance(host_id, str) or OPAQUE_UUID.fullmatch(host_id) is None:
        host_id = None
    host_target = _target(
        "host",
        host_id or host.get("hostname"),
        "local",
    )
    result: dict[str, list[Observation]] = {
        rule.rule_id: [Observation(host_target, None, "unsupported")]
        for rule in pack.rules
    }

    def host_metric(rule_id: str, value: Any, missing: str = "no_data") -> None:
        if rule_id in result:
            result[rule_id] = [_observation(host_target, value, missing)]

    snapshot_time = _timestamp(snapshot.get("generatedAt"))
    if snapshot_time is None:
        snapshot_time = _timestamp(latest.get("timestamp"))
    heartbeat = _mapping(snapshot.get("heartbeat"))
    lifecycle = heartbeat.get("lifecycle")
    heartbeat_enabled = lifecycle in {None, "active"}
    if "HostDown" in result:
        result["HostDown"] = [
            _observation(
                host_target,
                _age_seconds(snapshot_time, heartbeat.get("receivedAt"))
                if heartbeat_enabled else None,
                "unsupported" if not heartbeat_enabled else "no_data",
            )
        ]
    if "AgentHeartbeatMissing" in result:
        result["AgentHeartbeatMissing"] = [
            _observation(
                host_target,
                _age_seconds(snapshot_time, heartbeat.get("observedAt"))
                if heartbeat_enabled else None,
                "unsupported" if not heartbeat_enabled else "no_data",
            )
        ]
    if "AgentDataStale" in result:
        result["AgentDataStale"] = [
            _observation(
                host_target,
                _age_seconds(snapshot_time, latest.get("timestamp"))
                if heartbeat_enabled else None,
                "unsupported" if not heartbeat_enabled else "no_data",
            )
        ]

    host_metric("CpuUsageHigh", latest.get("cpuPercent"))
    if "CpuIowaitHigh" in result:
        result["CpuIowaitHigh"] = [
            _source_observation(host_target, linux_cpu_total.get("iowaitPercent"), linux_cpu)
        ]
    if "CpuStealHigh" in result:
        result["CpuStealHigh"] = [
            _source_observation(host_target, linux_cpu_total.get("stealPercent"), linux_cpu)
        ]
    cpu_count = _number(host.get("logicalCpuCount"))
    load = _number(latest.get("load1"))
    linux_load = _mapping(linux_cpu.get("load"))
    load_per_core = _number(linux_load.get("onePerOnlineCpu"))
    host_metric(
        "LoadPerCoreHigh",
        load_per_core if load_per_core is not None
        else load / cpu_count if load is not None and cpu_count and cpu_count > 0
        else None,
    )
    host_metric("CpuPressureHigh", latest.get("cpuPressureSomeAvg10"))
    memory_percent = _number(latest.get("memoryPercent"))
    host_metric("MemoryAvailableLow", 100.0 - memory_percent if memory_percent is not None else None)
    host_metric("MemoryPressureHigh", latest.get("memoryPressureSomeAvg10"))
    host_metric("SwapUsageHigh", _pressure_gated_swap_percent(latest))
    if "SwapThrashing" in result:
        swap_in = _number(linux_memory.get("swapInBytesPerSecond"))
        swap_out = _number(linux_memory.get("swapOutBytesPerSecond"))
        swap_io = swap_in + swap_out if swap_in is not None and swap_out is not None else None
        result["SwapThrashing"] = [
            _source_observation(host_target, swap_io, linux_memory)
        ]
    host_metric("NetworkErrorsHigh", (
        (_number(latest.get("networkRxErrorsPerSecond")) or 0.0)
        + (_number(latest.get("networkTxErrorsPerSecond")) or 0.0)
    ) if _number(latest.get("networkRxErrorsPerSecond")) is not None
       and _number(latest.get("networkTxErrorsPerSecond")) is not None else None)
    host_metric("NetworkDropsHigh", (
        (_number(latest.get("networkRxDroppedPerSecond")) or 0.0)
        + (_number(latest.get("networkTxDroppedPerSecond")) or 0.0)
    ) if _number(latest.get("networkRxDroppedPerSecond")) is not None
       and _number(latest.get("networkTxDroppedPerSecond")) is not None else None)
    host_metric("TemperatureHigh", latest.get("temperatureC"))
    if "NotificationDeliveryFailure" in result:
        delivery_status = monitor_internal.get("notificationDeliveryStatus")
        delivery_delta = monitor_internal.get("notificationFinalFailureDelta")
        if delivery_status == "ok":
            result["NotificationDeliveryFailure"] = [
                _observation(host_target, delivery_delta)
            ]
        elif delivery_status in {
            "no_data", "unsupported", "permission_denied", "collection_error"
        }:
            result["NotificationDeliveryFailure"] = [
                Observation(host_target, None, delivery_status)
            ]

    def monitor_metric(rule_id: str, status_key: str, value_key: str) -> None:
        if rule_id not in result:
            return
        raw_status = monitor_internal.get(status_key)
        status = (
            raw_status
            if raw_status in {
                "ok", "no_data", "stale", "unsupported",
                "permission_denied", "collection_error",
            }
            else "unsupported" if status_key not in monitor_internal else "collection_error"
        )
        result[rule_id] = [
            _observation(
                host_target, monitor_internal.get(value_key), "collection_error"
            )
            if status == "ok"
            else Observation(host_target, None, status)
        ]

    monitor_metric("IngestLagHigh", "ingestStatus", "ingestLagSeconds")
    monitor_metric("MetricsQueueHigh", "metricsQueueStatus", "metricsQueueUsedPercent")
    monitor_metric("LogsQueueHigh", "logsQueueStatus", "logsQueueUsedPercent")
    monitor_metric(
        "DatabaseWriteFailure", "storageWriteStatus", "storageWriteFailureDelta"
    )
    monitor_metric(
        "AlertEvaluationDelayed", "alertEvaluationStatus", "alertEvaluationDelaySeconds"
    )
    monitor_metric(
        "MonitoringDiskUsageHigh",
        "monitoringFilesystemStatus",
        "monitoringFilesystemUsedPercent",
    )
    monitor_metric(
        "MonitoringServiceUnavailable",
        "externalHeartbeatStatus",
        "externalHeartbeatAvailable",
    )

    # Same-host probes prove endpoint/DNS/TCP/TLS behavior but are deliberately
    # not treated as the independent external dead-man heartbeat above.
    synthetic_collection = _mapping(snapshot.get("syntheticProbeCollection"))
    synthetic_source = synthetic_collection.get("status")
    synthetic_source_status = {
        "fresh": "ok",
        "stale": "stale",
        "unsupported": "unsupported",
        "permission-denied": "permission_denied",
        "unavailable": "collection_error",
        "collection-error": "collection_error",
    }.get(synthetic_source, "unsupported" if not synthetic_collection else "collection_error")
    if SYNTHETIC_RULES & result.keys():
        if synthetic_source_status != "ok":
            for rule_id in SYNTHETIC_RULES & result.keys():
                result[rule_id] = [
                    Observation(host_target, None, synthetic_source_status)
                ]
        else:
            raw_probes = snapshot.get("syntheticProbes")
            probes = raw_probes if isinstance(raw_probes, list) else None
            valid = probes is not None and bool(probes)
            if probes is not None:
                identifiers: set[str] = set()
                for probe in probes:
                    probe_id = probe.get("id") if isinstance(probe, Mapping) else None
                    probe_status = probe.get("status") if isinstance(probe, Mapping) else None
                    if (
                        not isinstance(probe_id, str)
                        or SYNTHETIC_ID.fullmatch(probe_id) is None
                        or probe_id in identifiers
                        or probe_status not in {
                            "ok", "dns", "permission", "timeout", "tls",
                            "http", "invalid", "unsupported",
                        }
                    ):
                        valid = False
                        break
                    identifiers.add(probe_id)
            if not valid:
                status_value = "no_data" if probes == [] else "collection_error"
                for rule_id in SYNTHETIC_RULES & result.keys():
                    result[rule_id] = [Observation(host_target, None, status_value)]
            else:
                for rule_id in SYNTHETIC_RULES & result.keys():
                    result[rule_id] = []
                assert probes is not None
                for probe in probes:
                    assert isinstance(probe, Mapping)
                    probe_id = str(probe["id"])
                    probe_status = str(probe["status"])
                    target = _target("synthetic", probe_id, "probe")
                    labels = (("probe", probe_id),)
                    if probe_status == "unsupported":
                        for rule_id in SYNTHETIC_RULES & result.keys():
                            result[rule_id].append(
                                Observation(target, None, "unsupported", labels)
                            )
                        continue

                    availability = 1 if probe_status == "ok" else 0
                    if "HttpEndpointDown" in result:
                        result["HttpEndpointDown"].append(
                            Observation(target, float(availability), "ok", labels)
                        )
                    if "HttpLatencyHigh" in result:
                        latency = _number(probe.get("latencyMilliseconds"))
                        result["HttpLatencyHigh"].append(Observation(
                            target,
                            latency,
                            "ok" if latency is not None else "no_data",
                            labels,
                        ))

                    days_remaining = _number(probe.get("certificateDaysRemaining"))
                    if "TlsCertificateExpiring" in result:
                        result["TlsCertificateExpiring"].append(Observation(
                            target,
                            days_remaining,
                            "ok" if days_remaining is not None
                            else "no_data" if probe_status == "tls"
                            else "unsupported" if probe_status in {"ok", "http", "invalid"}
                            else "no_data",
                            labels,
                        ))
                    if "TlsCertificateInvalid" in result:
                        invalid_value = (
                            1.0 if probe_status == "tls"
                            else 0.0 if days_remaining is not None
                            else None
                        )
                        invalid_status = (
                            "ok" if invalid_value is not None
                            else "unsupported" if probe_status in {"ok", "http", "invalid"}
                            else "no_data"
                        )
                        result["TlsCertificateInvalid"].append(Observation(
                            target, invalid_value, invalid_status, labels,
                        ))
    linux_thermal = _mapping(linux.get("thermal"))
    raspberry_pi = _mapping(linux_thermal.get("raspberryPi"))
    raspberry_pi_status = _linux_observation_status(raspberry_pi)
    current_throttled = raspberry_pi.get("currentThrottled")
    current_under_voltage = raspberry_pi.get("currentUnderVoltage")
    if "RaspberryPiThrottling" in result:
        result["RaspberryPiThrottling"] = [
            _observation(
                host_target,
                1 if current_throttled is True else 0 if current_throttled is False else None,
                "unsupported" if raspberry_pi_status == "ok" else raspberry_pi_status,
            )
        ]
    if "RaspberryPiUnderVoltage" in result:
        result["RaspberryPiUnderVoltage"] = [
            _observation(
                host_target,
                1 if current_under_voltage is True else 0 if current_under_voltage is False else None,
                "unsupported" if raspberry_pi_status == "ok" else raspberry_pi_status,
            )
        ]

    oom = _mapping(kernel.get("oomKill"))
    # The collector currently exposes a cumulative/current-boot event summary,
    # not a per-interval delta.  Do not reinterpret it as a new OOM event.
    if "OOMKillDetected" in result and _number(oom.get("count")) is None:
        result["OOMKillDetected"] = [Observation(host_target, None, "no_data")]

    for disk in snapshot.get("disks", []) if isinstance(snapshot.get("disks"), list) else []:
        if not isinstance(disk, Mapping):
            continue
        target = _filesystem_target(disk.get("mount"))
        parent = (("parent_target", host_target),)
        if "DiskUsageHigh" in result:
            result.setdefault("DiskUsageHigh", []).append(_observation(target, disk.get("usedPercent"), parent_target=host_target))
        if "DiskUsageCritical" in result:
            result.setdefault("DiskUsageCritical", []).append(_observation(target, disk.get("usedPercent"), parent_target=host_target))
        if "InodeUsageHigh" in result:
            inode_total = _number(disk.get("inodeTotal"))
            result.setdefault("InodeUsageHigh", []).append(
                Observation(
                    target,
                    None,
                    "unsupported",
                    (("parent_target", host_target),),
                )
                if (
                    inode_total == 0
                    or (
                        "inodeTotal" not in disk
                        and disk.get("inodeUsedPercent") is None
                    )
                )
                else _observation(
                    target,
                    disk.get("inodeUsedPercent"),
                    parent_target=host_target,
                )
            )
        if "DiskReadOnly" in result:
            read_only = disk.get("readOnly")
            result.setdefault("DiskReadOnly", []).append(_observation(
                target, 1 if read_only is True else 0 if read_only is False else None,
                parent_target=host_target,
            ))
        del parent
    for rule_id in ("DiskUsageHigh", "DiskUsageCritical", "InodeUsageHigh", "DiskReadOnly"):
        if rule_id in result and len(result[rule_id]) > 1:
            result[rule_id] = result[rule_id][1:]

    linux_block = _mapping(linux.get("blockDevices"))
    block_items = linux_block.get("items") if isinstance(linux_block.get("items"), list) else []
    if "DiskLatencyHigh" in result:
        result["DiskLatencyHigh"] = []
        for item in block_items:
            if not isinstance(item, Mapping):
                continue
            target = _target("disk", item.get("name"), "unknown")
            result["DiskLatencyHigh"].append(_source_observation(
                target,
                item.get("averageLatencyMilliseconds"),
                linux_block,
                parent_target=host_target,
            ))
        if not result["DiskLatencyHigh"]:
            result["DiskLatencyHigh"] = [Observation(
                host_target, None, _linux_observation_status(linux_block),
            )]

    linux_tcp = _mapping(linux.get("tcp"))
    if "TcpRetransmissionHigh" in result:
        result["TcpRetransmissionHigh"] = [
            _source_observation(
                host_target, linux_tcp.get("retransmissionPercent"), linux_tcp,
            )
        ]
    if "ConntrackUsageHigh" in result:
        conntrack = _mapping(linux_tcp.get("conntrack"))
        result["ConntrackUsageHigh"] = [
            _source_observation(
                host_target, conntrack.get("usedPercent"),
                conntrack if "status" in conntrack else linux_tcp,
            )
        ]

    linux_processes = _mapping(linux.get("processes"))
    if "FileDescriptorUsageHigh" in result:
        file_descriptors = _mapping(linux_processes.get("systemFileDescriptors"))
        result["FileDescriptorUsageHigh"] = [
            Observation(host_target, None, "unsupported")
            if (
                file_descriptors.get("status") == "partial"
                and file_descriptors.get("maximum") is None
            )
            else _source_observation(
                host_target, file_descriptors.get("usedPercent"),
                file_descriptors if "status" in file_descriptors else linux_processes,
            )
        ]
    if "PidUsageHigh" in result:
        result["PidUsageHigh"] = [
            _source_observation(host_target, linux_processes.get("pidUsedPercent"), linux_processes)
        ]
    if "ZombieProcessesHigh" in result:
        result["ZombieProcessesHigh"] = [
            _source_observation(host_target, linux_processes.get("zombieCount"), linux_processes)
        ]

    linux_systemd = _mapping(linux.get("systemd"))
    units = linux_systemd.get("units") if isinstance(linux_systemd.get("units"), list) else []
    if "SystemdServiceFailed" in result:
        result["SystemdServiceFailed"] = []
        for item in units:
            if not isinstance(item, Mapping):
                continue
            active_state = item.get("activeState")
            unit_result = item.get("result")
            failed = (
                True if active_state == "failed" or unit_result == "failed"
                else False if active_state in {"active", "inactive", "activating", "deactivating"}
                else None
            )
            result["SystemdServiceFailed"].append(_source_observation(
                _target("systemd", item.get("unit"), "unknown"),
                1 if failed is True else 0 if failed is False else None,
                linux_systemd,
                parent_target=host_target,
            ))
        if not result["SystemdServiceFailed"]:
            result["SystemdServiceFailed"] = [Observation(
                host_target, None, _linux_observation_status(linux_systemd),
            )]

    linux_clock = _mapping(linux.get("clock"))
    time_sync = _mapping(linux_clock.get("timeSync"))
    if "ClockSkewHigh" in result:
        drift_ms = _number(time_sync.get("clockDriftMilliseconds"))
        drift_seconds = abs(drift_ms) / 1000 if drift_ms is not None else None
        result["ClockSkewHigh"] = [
            Observation(host_target, None, "unsupported")
            if time_sync.get("clockDriftStatus") == "unsupported"
            else _source_observation(
                host_target, drift_seconds,
                time_sync if "status" in time_sync else linux_clock,
            )
        ]
    if "UnexpectedReboot" in result:
        reboot = linux_clock.get("unexpectedReboot")
        result["UnexpectedReboot"] = [
            Observation(host_target, None, "unsupported")
            if linux_clock.get("unexpectedRebootStatus") == "not_inferable_from_local_counters"
            else _source_observation(
                host_target,
                1 if reboot is True else 0 if reboot is False else None,
                linux_clock,
            )
        ]

    source_status = _container_source_status(snapshot)
    source_observation_status = _observation_status_for_source(source_status)
    containers = snapshot.get("containers") if isinstance(snapshot.get("containers"), list) else []
    for rule_id in CONTAINER_RULES & result.keys():
        result[rule_id] = []
    for container in containers:
        if not isinstance(container, Mapping):
            continue
        target = _target("container", container.get("name"), "unknown")
        labels = {"parent_target": host_target}
        project = container.get("project")
        if isinstance(project, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,95}", project):
            labels["project"] = project

        def container_metric(rule_id: str, value: Any, missing: str = "no_data") -> None:
            if rule_id not in result:
                return
            if source_observation_status != "ok":
                result[rule_id].append(Observation(
                    target, None, source_observation_status, tuple(sorted(labels.items())),
                ))
            else:
                result[rule_id].append(_observation(target, value, missing, **labels))

        state = container.get("state")
        health = container.get("health")
        healthcheck_configured = container.get("healthcheckConfigured")
        running = 1 if state == "running" else 0 if isinstance(state, str) else None
        container_metric("ContainerDown", running)
        container_metric(
            "ContainerRestartLoop", container.get("restartCountDelta"),
        )
        oom_killed = container.get("oomKilled")
        container_metric(
            "ContainerOOMKilled",
            1 if oom_killed is True else 0 if oom_killed is False else None,
        )
        healthy = (
            1 if health == "healthy" and healthcheck_configured is True
            else 0 if health == "unhealthy" and healthcheck_configured is True
            else None
        )
        container_metric(
            "ContainerUnhealthy", healthy,
            "unsupported" if healthcheck_configured is False else "no_data",
        )

        cpu_percent = _number(container.get("cpuPercent"))
        cpu_limit = _number(container.get("cpuLimitCores"))
        cpu_of_limit = (
            cpu_percent / cpu_limit
            if cpu_percent is not None and cpu_limit is not None and cpu_limit > 0
            else None
        )
        container_metric("ContainerCpuHigh", cpu_of_limit)
        container_metric(
            "ContainerCpuThrottlingHigh", container.get("cpuThrottledPercent"), "unsupported"
        )

        memory_bytes = _number(container.get("memoryBytes"))
        memory_limit = _number(container.get("memoryLimitBytes"))
        memory_of_limit = (
            100.0 * memory_bytes / memory_limit
            if memory_bytes is not None and memory_limit is not None and memory_limit > 0
            else None
        )
        container_metric("ContainerMemoryNearLimit", memory_of_limit)
        pid_count = _number(container.get("pidCount"))
        pid_limit = _number(container.get("pidLimit"))
        pid_of_limit = (
            100.0 * pid_count / pid_limit
            if pid_count is not None and pid_limit is not None and pid_limit > 0
            else None
        )
        container_metric("ContainerPidNearLimit", pid_of_limit, "unsupported")
        container_metric(
            "ContainerNetworkErrors", container.get("networkErrorsPerSecond"), "unsupported"
        )
        container_metric(
            "ContainerWritableLayerHigh", container.get("writableLayerBytes"), "unsupported"
        )
        container_metric(
            "ContainerNoMemoryLimit",
            1 if memory_limit == 0 else 0 if memory_limit is not None and memory_limit > 0 else None,
        )
        container_metric(
            "ContainerNoCpuLimit",
            1 if cpu_limit == 0 else 0 if cpu_limit is not None and cpu_limit > 0 else None,
        )
        container_metric(
            "ContainerNoHealthcheck",
            1 if healthcheck_configured is False else 0 if healthcheck_configured is True else None,
        )
        privileged = container.get("privileged")
        container_metric(
            "ContainerPrivileged",
            1 if privileged is True else 0 if privileged is False else None,
            "unsupported",
        )
        docker_socket = container.get("dockerSocketMounted")
        container_metric(
            "ContainerDockerSocketMounted",
            1 if docker_socket is True else 0 if docker_socket is False else None,
            "unsupported",
        )
        digest_drift = container.get("imageDigestDrift")
        container_metric(
            "ContainerImageDigestDrift",
            1 if digest_drift is True else 0 if digest_drift is False else None,
            "unsupported",
        )
        latest_tag = container.get("usesLatestTag")
        container_metric(
            "ContainerUsingLatestTag",
            1 if latest_tag is True else 0 if latest_tag is False else None,
            "unsupported",
        )
    for rule_id in CONTAINER_RULES & result.keys():
        if not result[rule_id]:
            result[rule_id] = [Observation(
                host_target,
                None,
                source_observation_status if source_observation_status != "ok" else "unsupported",
            )]

    if "DockerDaemonUnavailable" in result:
        available = 1 if source_status == "fresh" else 0 if source_status == "unavailable" else None
        result["DockerDaemonUnavailable"] = [Observation(
            host_target,
            available,
            "ok" if available is not None else source_observation_status,
        )]
    if "DockerEventStreamDisconnected" in result:
        event_collection = _mapping(snapshot.get("dockerEventCollection"))
        event_status = event_collection.get("status")
        connected = (
            1 if event_status in {"fresh", "gap"}
            else 0 if event_status == "unavailable"
            else None
        )
        observation_status = (
            "permission_denied" if event_status == "permission-denied"
            else "unsupported" if not event_collection
            else "ok" if connected is not None
            else "collection_error"
        )
        result["DockerEventStreamDisconnected"] = [Observation(
            host_target, connected, observation_status,
        )]
    return result


def evaluate_snapshot(
    pack: RulePack,
    snapshot: Mapping[str, Any],
    previous_states: Mapping[str, Any],
    now: dt.datetime,
    silences: Sequence[Any] = (),
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    states, events = evaluate_rule_pack(
        pack, observations_for_snapshot(pack, snapshot), previous_states, now, silences,
    )
    counts: dict[str, int] = {}
    for state in states.values():
        phase = state["phase"]
        counts[phase] = counts.get(phase, 0) + 1
    rules = {rule.rule_id: rule for rule in pack.rules}
    public_states: dict[str, dict[str, Any]] = {}
    for state_key, state in states.items():
        rule_id, target = state_key.split(":", 1)
        rule = rules[rule_id]
        public_states[state_key] = {
            "ruleId": rule_id,
            "target": target,
            "metric": rule.metric,
            "severity": rule.severity,
            "description": rule.description,
            "runbook": rule.runbook,
            **state,
        }
    evaluated_at = now.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schemaVersion": 1,
        "status": "ok",
        "rulePackVersion": pack.version,
        "evaluatedAt": evaluated_at,
        "summary": dict(sorted(counts.items())),
        "states": public_states,
    }, events
