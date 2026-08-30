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
CONTAINER_RULES = frozenset({
    "ContainerDown", "ContainerRestartLoop", "ContainerOOMKilled", "ContainerUnhealthy",
    "ContainerCpuHigh", "ContainerCpuThrottlingHigh", "ContainerMemoryNearLimit",
    "ContainerPidNearLimit", "ContainerNetworkErrors", "ContainerWritableLayerHigh",
    "ContainerNoMemoryLimit", "ContainerNoCpuLimit", "ContainerNoHealthcheck",
    "ContainerPrivileged", "ContainerDockerSocketMounted", "ContainerImageDigestDrift",
    "ContainerUsingLatestTag",
})


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


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
    kernel = _mapping(system.get("kernel"))
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

    host_metric("CpuUsageHigh", latest.get("cpuPercent"))
    cpu_count = _number(host.get("logicalCpuCount"))
    load = _number(latest.get("load1"))
    host_metric("LoadPerCoreHigh", load / cpu_count if load is not None and cpu_count and cpu_count > 0 else None)
    host_metric("CpuPressureHigh", latest.get("cpuPressureSomeAvg10"))
    memory_percent = _number(latest.get("memoryPercent"))
    host_metric("MemoryAvailableLow", 100.0 - memory_percent if memory_percent is not None else None)
    host_metric("MemoryPressureHigh", latest.get("memoryPressureSomeAvg10"))
    host_metric("SwapUsageHigh", latest.get("swapPercent"))
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
    flags = latest.get("throttledFlags")
    if isinstance(flags, int) and not isinstance(flags, bool) and 0 <= flags <= 0xFFFF_FFFF:
        host_metric("RaspberryPiThrottling", 1 if flags & 0xC else 0)
        host_metric("RaspberryPiUnderVoltage", 1 if flags & 0x1 else 0)

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
            result.setdefault("InodeUsageHigh", []).append(_observation(target, disk.get("inodeUsedPercent"), parent_target=host_target))
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

        memory_bytes = _number(container.get("memoryBytes"))
        memory_limit = _number(container.get("memoryLimitBytes"))
        memory_of_limit = (
            100.0 * memory_bytes / memory_limit
            if memory_bytes is not None and memory_limit is not None and memory_limit > 0
            else None
        )
        container_metric("ContainerMemoryNearLimit", memory_of_limit)
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
