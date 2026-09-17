"""Shared, explicit policy for sustained host-resource notifications.

Thresholds are local operating policy, not universal service-level objectives.
CPU/load and I/O pressure alone demonstrate contention, not unavailability.
Capacity exhaustion and the Raspberry Pi's thermal limit retain critical tiers.
Sample qualification and recovery must use distinct source observations.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ResourcePolicy:
    label: str
    unit: str
    warning: float
    warning_recovery: float
    critical: float | None = None
    critical_recovery: float | None = None
    warning_samples: int = 5
    warning_seconds: int = 240
    critical_samples: int = 3
    critical_seconds: int = 120
    recovery_samples: int = 3
    recovery_seconds: int = 120


RESOURCE_POLICIES: Mapping[str, ResourcePolicy] = {
    "cpuPercent": ResourcePolicy("CPU 사용률", "%", 90, 80),
    "memoryPercent": ResourcePolicy("메모리 사용률", "%", 80, 75, 90, 80),
    "temperatureC": ResourcePolicy("온도", "°C", 80, 75, 85, 80,
                                   warning_samples=3, warning_seconds=120),
    "cpuPressureSomeAvg10": ResourcePolicy("CPU PSI some", "%", 20, 5),
    # System-wide CPU PSI full is undefined, unlike cgroup CPU PSI full.
    "memoryPressureSomeAvg10": ResourcePolicy("메모리 PSI some", "%", 2, 1, 10, 2),
    "memoryPressureFullAvg10": ResourcePolicy("메모리 PSI full", "%", 5, 1),
    "ioPressureSomeAvg10": ResourcePolicy("I/O PSI some", "%", 20, 5),
    "ioPressureFullAvg10": ResourcePolicy("I/O PSI full", "%", 8, 1),
    "load": ResourcePolicy("코어당 부하", "", 1.5, 1),
    "usedPercent": ResourcePolicy("저장 볼륨 사용률", "%", 85, 80, 95, 90),
    "inodeUsedPercent": ResourcePolicy("아이노드 사용률", "%", 85, 80, 90, 85),
}

HOST_RESOURCE_FIELDS = frozenset(RESOURCE_POLICIES) - {"usedPercent", "inodeUsedPercent"}
DISK_RESOURCE_FIELDS = frozenset({"usedPercent", "inodeUsedPercent"})

# These rule-pack paths remain evaluated for dashboard/history. The mail route
# may select the unified stateful signal instead, preventing duplicate mail.
RESOURCE_RULE_POLICIES: Mapping[str, tuple[str, str, bool]] = {
    "CpuUsageHigh": ("cpuPercent", "warning", False),
    "CpuPressureHigh": ("cpuPressureSomeAvg10", "warning", False),
    "LoadPerCoreHigh": ("load", "warning", False),
    "MemoryAvailableLow": ("memoryPercent", "critical", True),
    "MemoryPressureHigh": ("memoryPressureSomeAvg10", "critical", False),
    "TemperatureHigh": ("temperatureC", "critical", False),
    "DiskUsageHigh": ("usedPercent", "warning", False),
    "DiskUsageCritical": ("usedPercent", "critical", False),
    "InodeUsageHigh": ("inodeUsedPercent", "critical", False),
    "MonitoringDiskUsageHigh": ("usedPercent", "warning", False),
}


def policy_for_signal(key: str) -> ResourcePolicy | None:
    parts = key.split(":")
    if len(parts) == 2 and parts[0] == "host" and parts[1] in HOST_RESOURCE_FIELDS:
        return RESOURCE_POLICIES[parts[1]]
    if len(parts) == 3 and parts[0] == "disk" and parts[2] in DISK_RESOURCE_FIELDS:
        return RESOURCE_POLICIES[parts[2]]
    return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def resource_value(key: str, current: Mapping[str, Any]) -> float | None:
    """Read only the bounded public metric represented by a resource key."""
    if policy_for_signal(key) is None:
        return None
    parts = key.split(":")
    if parts[0] == "host":
        latest = current.get("latest")
        if not isinstance(latest, Mapping):
            return None
        if parts[1] != "load":
            return _number(latest.get(parts[1]))
        host = current.get("host")
        cores = _number(host.get("logicalCpuCount")) if isinstance(host, Mapping) else None
        load = _number(latest.get("load1"))
        # Without a denominator, load is not comparable to a per-core policy.
        return load / cores if load is not None and cores else None
    rows = current.get("disks")
    for index, row in enumerate(rows[:64] if isinstance(rows, list) else []):
        if not isinstance(row, Mapping) or "wgang" in json.dumps(row, ensure_ascii=False, default=str).casefold():
            continue
        disk_id = hashlib.sha256(str(row.get("mount", index)).encode()).hexdigest()[:12]
        if disk_id == parts[1]:
            return _number(row.get(parts[2]))
    return None


def severity_for_value(policy: ResourcePolicy, value: float | None,
                       previous_severity: str | None = None) -> str | None:
    """Classify a reading, preserving only already-confirmed hysteresis bands.

    None means no breach for a valid value, or no observation for None. Callers
    must distinguish those cases before accumulating recovery observations.
    A retired critical tier must not survive a policy migration indefinitely.
    """
    value = _number(value)
    if value is None:
        return None
    if policy.critical is not None:
        if value >= policy.critical:
            return "critical"
        if (previous_severity == "critical" and policy.critical_recovery is not None
                and value > policy.critical_recovery):
            return "critical"
    if value >= policy.warning:
        return "warning"
    if previous_severity in {"warning", "critical"} and value > policy.warning_recovery:
        return "warning"
    return None


def qualification(policy: ResourcePolicy, severity: str) -> tuple[int, int]:
    return ((policy.critical_samples, policy.critical_seconds) if severity == "critical"
            else (policy.warning_samples, policy.warning_seconds))


def evidence_for_value(policy: ResourcePolicy, value: float, severity: str) -> str:
    threshold = policy.critical if severity == "critical" else policy.warning
    recovery = policy.critical_recovery if severity == "critical" else policy.warning_recovery
    tier = "위험" if severity == "critical" else "주의"
    if threshold is not None and value < threshold:
        return (f"{policy.label} {value:g}{policy.unit}; 기존 {tier}의 해제 기준 "
                f"{recovery:g}{policy.unit} 이하가 아직 확인되지 않았습니다.")
    return (f"{policy.label} {value:g}{policy.unit}; {tier} 진입 기준 "
            f"{threshold:g}{policy.unit} 이상입니다. 지속 관측 후 알림을 확정합니다.")
