#!/usr/bin/env python3
"""Finite, evidence-based signals over reviewed and sanitized Monitor exports.

No log acquisition, network access, source addresses, usernames, or raw message
publication. Authentication messages are counted in categories using their
maximum, since a denied login can produce both denial and pre-auth close lines.
Counts therefore represent a conservative lower bound, not unique attackers.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Mapping, Sequence

try:
    from . import notification_policy as resource_policy
except ImportError:  # Installed scripts share one directory.
    import notification_policy as resource_policy


WINDOW_SECONDS = 300
BURST_THRESHOLD = 20
SOURCE_NAMES = frozenset({"snapshot", "rules", "ssh", "http"})
DETECTION_KINDS = frozenset({
    "ssh-auth-attempt", "ssh-auth-burst", "http-client-errors",
    "http-server-errors", "operational-caution", "source-unavailable", "rule-alert",
})
SSH_SOURCES = frozenset({"journal:ssh", "journal:sshd"})
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,159}$")
TCP_MAX_SAMPLES = 8
TCP_MIN_SAMPLES = 3
TCP_MIN_SPAN_SECONDS = 120
TCP_MAX_INTERVAL_SECONDS = 180
TCP_MIN_OUTBOUND_SEGMENTS = 1000
TCP_MIN_RETRANSMITTED_SEGMENTS = 20


def excluded(value: Any) -> bool:
    return "wgang" in json.dumps(value, ensure_ascii=False, default=str).casefold()


def timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(dt.timezone.utc) if result.tzinfo else None
    except ValueError:
        return None


def fresh(value: Any, now: dt.datetime, age: int = 180) -> bool:
    parsed = timestamp(value)
    return parsed is not None and -60 <= (now - parsed).total_seconds() <= age


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def safe_name(value: Any) -> str | None:
    return value if isinstance(value, str) and SAFE_NAME.fullmatch(value) and not excluded(value) else None


def sample_timestamp(key: str, current: Mapping[str, Any]) -> str | None:
    """Return the source observation identity, never the producer's run time.

    Freshness, future timestamps and strictly increasing observations are checked
    by the caller against its own clock and previously accepted sample.
    """
    raw = current.get("generatedAt")
    if key.startswith("host:") and resource_policy.policy_for_signal(key) is not None:
        latest = current.get("latest")
        raw = latest.get("timestamp", raw) if isinstance(latest, Mapping) else None
    elif key.startswith(("tcp:", "clock:", "kernel:")):
        linux = current.get("linux")
        raw = linux.get("collectedAt") if isinstance(linux, Mapping) else None
    elif key.startswith("synthetic:"):
        raw = None
        rows = current.get("syntheticProbes")
        for row in rows[:128] if isinstance(rows, list) else []:
            if not isinstance(row, Mapping) or excluded(row):
                continue
            name = safe_name(row.get("id"))
            if name and key.startswith(f"synthetic:{hashlib.sha256(name.encode()).hexdigest()[:12]}:"):
                raw = row.get("checkedAt")
                break
    elif key.startswith(("container:", "collection:")):
        collection_key = "syntheticProbeCollection" if key == "collection:synthetic" else "containerCollection"
        collection = current.get(collection_key)
        raw = collection.get("observedAt") if isinstance(collection, Mapping) else None
    parsed = timestamp(raw)
    return parsed.isoformat().replace("+00:00", "Z") if parsed is not None else None


def _tcp_counter(value: Any) -> int | None:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not 0 <= value <= (1 << 63) - 1 or int(value) != value):
        return None
    return int(value)


def _tcp_boot_identity(current: Mapping[str, Any], linux: Mapping[str, Any]) -> str | None:
    identity = current.get("identity")
    boot = identity.get("bootId") if isinstance(identity, Mapping) else None
    if isinstance(boot, str) and re.fullmatch(r"[0-9a-f-]{32,36}", boot):
        return boot
    clock = linux.get("clock")
    boot_time = timestamp(clock.get("bootTime")) if isinstance(clock, Mapping) else None
    return boot_time.isoformat() if boot_time is not None else None


def _project_tcp_window(tcp: dict[str, Any], samples: list[dict[str, Any]]) -> None:
    if len(samples) < TCP_MIN_SAMPLES:
        return
    span = (timestamp(samples[-1]["collectedAt"]) - timestamp(samples[0]["collectedAt"])).total_seconds()
    if span < TCP_MIN_SPAN_SECONDS:
        return
    total_out = sum(sample["outboundSegmentsDelta"] for sample in samples)
    total_retransmitted = sum(sample["retransmittedSegmentsDelta"] for sample in samples)
    if not total_out:
        return
    percent = total_retransmitted / total_out * 100
    # Sparse high ratios are unknown rather than evidence of recovery. A real
    # healthy ratio can clear after the same sustained observation requirement.
    if percent >= 1 and total_out < TCP_MIN_OUTBOUND_SEGMENTS and total_retransmitted < TCP_MIN_RETRANSMITTED_SEGMENTS:
        return
    tcp.update({"rateStatus": "ok", "retransmissionPercent": percent,
                "notificationWindow": {"outboundSegmentsDelta": total_out,
                                       "retransmittedSegmentsDelta": total_retransmitted,
                                       "windowSeconds": sum(sample["intervalSeconds"] for sample in samples),
                                       "sampleCount": len(samples)}})


def prepare_notification_current(
    current: Mapping[str, Any], now: dt.datetime, prior_tcp_window: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project a bounded TCP count window for mail without changing raw exports.

    A baseline plus three distinct intervals spanning at least two minutes is
    required. Exact cumulative counters provide the weighted numerator and
    denominator; rounded per-second rates are never converted back to counts.
    Missing/reset observations break the consecutive window and cannot recover
    an incident. The opaque returned state is JSON serializable and bounded.
    """
    projected = dict(current)
    linux = current.get("linux")
    linux = dict(linux) if isinstance(linux, Mapping) else {}
    tcp = linux.get("tcp")
    tcp = dict(tcp) if isinstance(tcp, Mapping) else {}
    linux["tcp"] = tcp
    projected["linux"] = linux
    raw_rate_status = tcp.get("rateStatus")
    tcp["rateStatus"] = "insufficient_samples"
    tcp["retransmissionPercent"] = None
    tcp.pop("notificationWindow", None)

    prior = prior_tcp_window if isinstance(prior_tcp_window, Mapping) else {}
    previous_time = timestamp(prior.get("lastCollectedAt"))
    if previous_time is not None and not 0 <= (now - previous_time).total_seconds() <= WINDOW_SECONDS:
        prior, previous_time = {}, None
    state: dict[str, Any] = {"lastCollectedAt": prior.get("lastCollectedAt") if previous_time else None,
                             "lastCounters": None, "bootIdentity": None, "samples": []}
    observed = timestamp(linux.get("collectedAt"))
    if observed is None or not 0 <= (now - observed).total_seconds() <= TCP_MAX_INTERVAL_SECONDS:
        return projected, state

    # A cached snapshot must neither add a sample nor replace a newer baseline.
    # Persist only validated, bounded window data even when it is repeated.
    samples: list[dict[str, Any]] = []
    prior_samples = prior.get("samples")
    for sample in prior_samples[-TCP_MAX_SAMPLES:] if isinstance(prior_samples, list) else []:
        if not isinstance(sample, Mapping):
            samples = []
            continue
        at = timestamp(sample.get("collectedAt"))
        interval = number(sample.get("intervalSeconds"))
        outbound = _tcp_counter(sample.get("outboundSegmentsDelta"))
        retransmitted = _tcp_counter(sample.get("retransmittedSegmentsDelta"))
        if (at is None or previous_time is None or at > previous_time
                or interval is None or not 0 < interval <= TCP_MAX_INTERVAL_SECONDS
                or outbound is None or retransmitted is None
                or not 0 <= (now - at).total_seconds() + interval <= WINDOW_SECONDS
                or (samples and (at - timestamp(samples[-1]["collectedAt"])).total_seconds() != interval)):
            samples = []
            continue
        samples.append({"collectedAt": at.isoformat().replace("+00:00", "Z"), "intervalSeconds": interval,
                        "outboundSegmentsDelta": outbound, "retransmittedSegmentsDelta": retransmitted})
    previous_counters = prior.get("lastCounters")
    previous_counters = previous_counters if isinstance(previous_counters, Mapping) else {}
    previous_out = _tcp_counter(previous_counters.get("OutSegs"))
    previous_retransmitted = _tcp_counter(previous_counters.get("RetransSegs"))
    if previous_time is not None and observed <= previous_time:
        state.update({"lastCounters": {"OutSegs": previous_out, "RetransSegs": previous_retransmitted}
                      if previous_out is not None and previous_retransmitted is not None else None,
                      "bootIdentity": prior.get("bootIdentity"), "samples": samples})
        counters = tcp.get("counters")
        if (observed == previous_time and tcp.get("status") == "supported" and raw_rate_status == "ok"
                and isinstance(counters, Mapping) and previous_out is not None and previous_retransmitted is not None
                and _tcp_counter(counters.get("OutSegs")) == previous_out
                and _tcp_counter(counters.get("RetransSegs")) == previous_retransmitted
                and _tcp_boot_identity(current, linux) == prior.get("bootIdentity")):
            _project_tcp_window(tcp, samples)
        return projected, state

    state["lastCollectedAt"] = observed.isoformat().replace("+00:00", "Z")
    counters = tcp.get("counters")
    counters = counters if isinstance(counters, Mapping) else {}
    outbound = _tcp_counter(counters.get("OutSegs"))
    retransmitted = _tcp_counter(counters.get("RetransSegs"))
    boot_identity = _tcp_boot_identity(current, linux)
    if (tcp.get("status") != "supported" or raw_rate_status != "ok"
            or outbound is None or retransmitted is None or boot_identity is None):
        return projected, state
    state.update({"lastCounters": {"OutSegs": outbound, "RetransSegs": retransmitted},
                  "bootIdentity": boot_identity})
    interval = (observed - previous_time).total_seconds() if previous_time else None
    clock = linux.get("clock")
    reboot = clock.get("rebootDetectedSincePreviousSample") if isinstance(clock, Mapping) else None
    if (interval is None or not 0 < interval <= TCP_MAX_INTERVAL_SECONDS
            or previous_out is None or previous_retransmitted is None
            or prior.get("bootIdentity") != boot_identity or reboot is True
            or outbound < previous_out or retransmitted < previous_retransmitted):
        return projected, state

    samples.append({"collectedAt": state["lastCollectedAt"], "intervalSeconds": interval,
                    "outboundSegmentsDelta": outbound - previous_out,
                    "retransmittedSegmentsDelta": retransmitted - previous_retransmitted})
    state["samples"] = samples[-TCP_MAX_SAMPLES:]
    _project_tcp_window(tcp, state["samples"])
    return projected, state


def _signal(key: str, kind: str, severity: str, source: str, count: int, evidence: str) -> dict[str, Any]:
    return {"key": key, "kind": kind, "severity": severity, "source": source,
            "count": min(max(count, 0), 1000000), "windowSeconds": WINDOW_SECONDS,
            "evidence": evidence}


def ssh_signals(records: Sequence[Mapping[str, Any]], now: dt.datetime) -> list[dict[str, Any]]:
    categories: Counter[str] = Counter()
    seen: set[str] = set()
    for row in records[-20000:]:
        if excluded(row) or row.get("sourceId") not in SSH_SOURCES:
            continue
        if row.get("redactionVersion") != "monitor-log-redaction-v2":
            continue
        if not fresh(row.get("timestamp"), now, WINDOW_SECONDS):
            continue
        message = row.get("message")
        if not isinstance(message, str) or len(message) > 32768:
            continue
        key = hashlib.sha256(json.dumps(
            [row.get("timestamp"), row.get("sourceId"), message], ensure_ascii=False,
        ).encode()).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        lowered = message.casefold()
        if "not allowed because not listed in allowusers" in lowered:
            categories["denied"] += 1
        elif re.search(r"\bfailed (?:password|publickey|keyboard-interactive)\b", lowered):
            categories["failed"] += 1
        elif re.search(r"\binvalid user\b", lowered):
            categories["invalid"] += 1
        elif "authentication failure" in lowered:
            categories["authentication"] += 1
    count = max(categories.values(), default=0)
    if not count:
        return []
    burst = count >= BURST_THRESHOLD
    return [_signal(
        "ssh-auth", "ssh-auth-burst" if burst else "ssh-auth-attempt",
        # These records prove rejected/failed authentication, not compromise or
        # service unavailability. Volume alone must not turn them into danger.
        "warning", "ssh", count,
        f"최근 5분 SSH 비허용 로그인/인증 실패 최소 {count}건. "
        + ("반복 공격 의심 패턴입니다. " if burst else "접근 시도 주의가 필요합니다. ")
        + "거부·종료 로그 중복을 보수적으로 묶었으며 침입 성공의 증거는 아닙니다.",
    )]


def http_signals(current: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Classify observed request outcomes, not inferred attacks.

    The local 5xx policy requires both an error count and a failure share:
    three errors affecting at least half the requests catch low-traffic
    outages; five errors affecting at least 5% catch broader degradation.
    These are conservative operational policy choices, not universal service
    SLOs. A single error still warrants attention but does not prove an outage.
    """
    rows = current.get("currentTraffic")
    result = []
    if not isinstance(rows, list):
        return result
    for row in rows[:64]:
        if not isinstance(row, Mapping) or excluded(row):
            continue
        app = safe_name(row.get("app"))
        total = number(row.get("requestCount"))
        if not app or total is None or total <= 0:
            continue
        for field, minimum, kind, wording in (
            ("status4xx", 20, "http-client-errors", "4xx 요청 이상; 공격 여부는 미확인"),
            ("status5xx", 1, "http-server-errors", "5xx 서버 오류 증가"),
        ):
            count = number(row.get(field))
            if count is None or count < minimum or (field == "status4xx" and count / total < 0.2):
                continue
            failure_share = count / total
            severe = field == "status5xx" and (
                (count >= 3 and failure_share >= 0.5)
                or (count >= 5 and failure_share >= 0.05)
            )
            result.append(_signal(
                f"{kind}:{app}", kind, "critical" if severe else "warning",
                "http", int(count),
                f"{app}: 최근 수집 구간 {wording}. {int(total)}건 중 {int(count)}건({count / total * 100:.1f}%).",
            ))
            result[-1]["windowSeconds"] = 60
        slow, maximum = number(row.get("slowCount")), number(row.get("maxResponseMs"))
        enough_slow = slow is not None and total >= 20 and slow >= 3
        if (enough_slow and slow / total >= 0.1) or (maximum is not None and maximum >= 5000):
            severe = (enough_slow and slow / total >= 0.4) or (maximum is not None and maximum >= 15000)
            result.append(_signal(f"http-slow:{app}", "operational-caution", "critical" if severe else "warning",
                                  "http", int(slow or 1), f"{app}: 느린 HTTP 요청 증가. "
                                  f"느린 요청 {int(slow) if slow is not None else '미관측'}건 / 전체 {int(total)}건, "
                                  f"최대 응답 {maximum if maximum is not None else '미관측'}ms."))
    return result


def _extended_observations(current: Mapping[str, Any], now: dt.datetime) -> list[dict[str, Any]]:
    """Normalized current observations; missing inputs are absent, never zero."""
    result: list[dict[str, Any]] = []

    def add(key: str, raw: Any, caution: float, danger: float, label: str,
            unit: str = "", *, low: bool = False) -> None:
        value = number(raw)
        if value is not None:
            result.append({"key": key, "value": value, "caution": caution, "danger": danger,
                           "label": label, "unit": unit, "low": low})

    linux = current.get("linux", {})
    if isinstance(linux, Mapping) and fresh(linux.get("collectedAt"), now):
        tcp = linux.get("tcp", {})
        if isinstance(tcp, Mapping) and tcp.get("status") == "supported" and tcp.get("rateStatus") == "ok":
            add("tcp:retransmission", tcp.get("retransmissionPercent"), 1, 5, "TCP 재전송률", "%")
        clock = linux.get("clock", {})
        sync = clock.get("timeSync", {}) if isinstance(clock, Mapping) else {}
        if (clock.get("status") == "supported" and sync.get("status") in {"supported", "partial"}
                and type(sync.get("synchronized")) is bool):
            add("clock:sync", 0 if sync["synchronized"] else 1, 1, 1, "시각 동기화 미완료")
        drift = sync.get("clockDriftMilliseconds")
        if isinstance(drift, (int, float)) and not isinstance(drift, bool) and math.isfinite(drift):
            add("clock:drift", abs(drift), 15000, 60000, "시계 차이", "ms")
        event_sources = linux.get("eventSources", {})
        if isinstance(event_sources, Mapping) and event_sources.get("kernelLogStatus") == "supported":
            kernel = current.get("system", {}).get("kernel", {})
            for field, label, critical in (
                ("warning", "커널 경고", False), ("oops", "커널 oops", True),
                ("panic", "커널 panic", True), ("hungTask", "작업 정체", True),
                ("rcuStall", "RCU 정체", True), ("rcuExpedited", "짧은 RCU 지연", False),
                ("oomKill", "OOM 종료", True), ("filesystemError", "파일시스템 오류", True),
                ("nvmeReset", "NVMe 재설정", False), ("nvmeIo", "NVMe I/O 오류", True),
                ("pcieAerCorrectable", "PCIe 보정 가능 오류", False),
                ("pcieAerNonFatal", "PCIe 비치명 오류", False), ("pcieAerFatal", "PCIe 치명 오류", True),
            ):
                entry = kernel.get(field, {})
                count = number(entry.get("count")) if isinstance(entry, Mapping) else None
                if count is None or (count and timestamp(entry.get("lastEventAt")) is None):
                    continue
                value = count if fresh(entry.get("lastEventAt"), now, WINDOW_SECONDS) else 0
                add(f"kernel:{field}", value, 1, 1 if critical else float("inf"),
                    f"최근 5분 {label} 기록(부팅 후 누적)", "건")
    for collection_key, rows_key, prefix, identity_key in (
        ("syntheticProbeCollection", "syntheticProbes", "synthetic", "id"),
        ("containerCollection", "containers", "container", "name"),
    ):
        collection = current.get(collection_key, {})
        if not isinstance(collection, Mapping):
            continue
        collection_age = 600 if prefix == "synthetic" else 180
        if collection.get("status") not in {None, "unsupported", "fresh"}:
            add(f"collection:{prefix}", 1, 1, 2, f"{prefix} 수집 상태 확인 필요")
        elif collection.get("status") == "fresh" and fresh(collection.get("observedAt"), now, collection_age):
            add(f"collection:{prefix}", 0, 1, 2, f"{prefix} 수집 상태 확인 필요")
        else:
            continue
        if collection.get("status") != "fresh" or not fresh(collection.get("observedAt"), now, collection_age):
            continue
        for row in current.get(rows_key, [])[:128]:
            if not isinstance(row, Mapping) or excluded(row):
                continue
            name = safe_name(row.get(identity_key))
            if not name:
                continue
            base = f"{prefix}:{hashlib.sha256(name.encode()).hexdigest()[:12]}"
            if prefix == "synthetic":
                if not fresh(row.get("checkedAt"), now, 600):
                    continue
                state = row.get("status")
                if state == "ok":
                    add(f"{base}:status", 0, 1, 1, f"{name} 합성 검사 실패")
                elif state in {"dns", "timeout", "tls", "http"}:
                    add(f"{base}:status", 1, 1, 1, f"{name} 합성 검사 실패")
                elif state in {"permission", "invalid"}:
                    add(f"{base}:status", 1, 1, 2, f"{name} 합성 검사 수집 주의")
                if state == "ok":
                    add(f"{base}:latency", row.get("latencyMilliseconds"), 1000, float("inf"), f"{name} 합성 검사 지연", "ms")
                days = row.get("certificateDaysRemaining")
                if isinstance(days, (int, float)) and not isinstance(days, bool) and math.isfinite(days):
                    add(f"{base}:certificate", max(0, days), 30, 7, f"{name} TLS 인증서 잔여", "일", low=True)
                continue
            state = row.get("state")
            state_values = {"running": 0, "exited": 2, "dead": 2, "failed": 2,
                            "starting": 1, "restarting": 1, "paused": 1, "created": 1,
                            "removing": 1, "unknown": 1}
            add(f"{base}:state", state_values.get(state), 1, 2, f"{name} 서비스 실행 상태 주의")
            health = row.get("health")
            add(f"{base}:health", {"healthy": 0, "starting": 1, "unhealthy": 2}.get(health),
                1, 2, f"{name} 서비스 healthcheck 주의")
            if type(row.get("oomKilled")) is bool:
                add(f"{base}:oom", 1 if row["oomKilled"] else 0, 1, 1, f"{name} OOM 종료 플래그")
            add(f"{base}:restarts", row.get("restartCountDelta"), 1, 3, f"{name} 재시작 증가", "회")
            add(f"{base}:cpu-throttle", row.get("cpuThrottledPercent"), 20, 50, f"{name} CPU 제한", "%")
            add(f"{base}:network-errors", row.get("networkErrorsPerSecond"), 0.1, 1, f"{name} 네트워크 오류", "/초")
            for key, numerator, denominator, label in (("memory", "memoryBytes", "memoryLimitBytes", "메모리"),
                                                        ("pids", "pidCount", "pidLimit", "PID")):
                value, limit = number(row.get(numerator)), number(row.get(denominator))
                if key == "memory" and number(row.get("memoryWorkingSetBytes")) is not None:
                    value = number(row["memoryWorkingSetBytes"])
                    label = "캐시 보정 메모리"
                if value is not None and limit:
                    add(f"{base}:{key}", value / limit * 100, 80, 90, f"{name} {label} 한도 사용률", "%")
    return result


def operational_signals(current: Mapping[str, Any], now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Apply notification policy; dashboard instantaneous gauges are separate."""
    latest = current.get("latest")
    if not isinstance(latest, Mapping):
        return []
    result = []
    now = now or timestamp(current.get("generatedAt"))
    if now is not None:
        for row in _extended_observations(current, now):
            breached = row["value"] <= row["caution"] if row["low"] else row["value"] >= row["caution"]
            danger = row["value"] <= row["danger"] if row["low"] else row["value"] >= row["danger"]
            if breached:
                evidence = f"{row['label']}: {row['value']:g}{row['unit']}. 최신 관측 기준입니다."
                window = current.get("linux", {}).get("tcp", {}).get("notificationWindow") if row["key"] == "tcp:retransmission" else None
                if isinstance(window, Mapping):
                    evidence = (f"TCP 재전송률: {row['value']:.2f}%. 최근 {window['windowSeconds']:g}초 "
                                f"서로 다른 관측 {window['sampleCount']}개에서 송신 "
                                f"{window['outboundSegmentsDelta']}개 중 재전송 "
                                f"{window['retransmittedSegmentsDelta']}개를 합산했습니다.")
                result.append(_signal(row["key"], "operational-caution", "critical" if danger else "warning",
                                      "snapshot", max(1, int(row["value"])),
                                      evidence))
    reboot = current.get("system", {}).get("reboot", {})
    if (isinstance(reboot, Mapping) and now is not None and reboot.get("status") == "ok"
            and fresh(reboot.get("observedAt"), now) and reboot.get("required") is True):
        result.append(_signal("host:reboot", "operational-caution", "warning", "snapshot", 1,
                              "운영체제가 재부팅 필요 상태입니다. 유지보수 시간을 정해 적용해야 합니다."))
    for field, policy in resource_policy.RESOURCE_POLICIES.items():
        if field not in resource_policy.HOST_RESOURCE_FIELDS:
            continue
        value = resource_policy.resource_value(f"host:{field}", current)
        severity = resource_policy.severity_for_value(policy, value)
        if severity is not None:
            result.append(_signal(f"host:{field}", "operational-caution", severity, "snapshot", 1,
                                  resource_policy.evidence_for_value(policy, value, severity)))
    for field, caution, danger, label, unit in (
        ("networkRxErrorsPerSecond", 0.1, 1, "수신 오류", "/초"),
        ("networkTxErrorsPerSecond", 0.1, 1, "송신 오류", "/초"),
        ("networkRxDroppedPerSecond", 1, 10, "수신 드롭", "/초"),
        ("networkTxDroppedPerSecond", 1, 10, "송신 드롭", "/초"),
    ):
        value = number(latest.get(field))
        if value is not None and value >= caution:
            result.append(_signal(
                f"host:{field}", "operational-caution", "critical" if value >= danger else "warning",
                "snapshot", 1, f"{label} {value:g}{unit}; 주의 {caution:g}, 위험 {danger:g} 기준 초과.",
            ))
    power = latest.get("throttledFlags")
    if type(power) is int and power & 15:
        undervoltage = bool(power & 1)
        result.append(_signal("host:power", "operational-caution", "critical" if undervoltage else "warning",
                              "snapshot", 1, "현재 저전압 플래그가 켜져 있습니다. 전원 공급 상태를 확인해야 합니다."
                              if undervoltage else "현재 성능·온도 제한 플래그가 켜져 있습니다. 부하와 냉각 상태를 확인하세요."))
    reliability = current.get("reliability", {})
    if isinstance(reliability, Mapping):
        for field, label in (("sshListenersAvailable", "SSH 리스너"), ("networkLinkAvailable", "네트워크 링크")):
            if reliability.get(field) is False:
                result.append(_signal(f"host:{field}", "operational-caution", "critical", "snapshot", 1,
                                      f"{label} 가용성 확인이 실패했습니다."))
    for index, row in enumerate(current.get("disks", [])[:64]):
        if not isinstance(row, Mapping) or excluded(row):
            continue
        # Export no mount paths; the stable hash distinguishes volumes.
        disk_id = hashlib.sha256(str(row.get("mount", index)).encode()).hexdigest()[:12]
        for field in ("usedPercent", "inodeUsedPercent"):
            value = number(row.get(field))
            policy = resource_policy.RESOURCE_POLICIES[field]
            severity = resource_policy.severity_for_value(policy, value)
            if severity is not None:
                result.append(_signal(f"disk:{disk_id}:{field}", "operational-caution",
                                      severity, "snapshot", 1,
                                      resource_policy.evidence_for_value(policy, value, severity)))
    return result


def observable(key: str, current: Mapping[str, Any]) -> bool:
    """Absence of a breach is a recovery sample only when its input exists."""
    if resource_policy.policy_for_signal(key) is not None:
        return resource_policy.resource_value(key, current) is not None
    if key == "host:cpuPressureFullAvg10":
        return False  # Undefined at host scope, never an observed healthy zero.
    if key.startswith("source:") or key == "ssh-auth":
        return True  # Caller separately requires the corresponding source healthy.
    if key.startswith(("tcp:", "clock:", "kernel:", "synthetic:", "container:", "collection:")):
        now = timestamp(current.get("generatedAt"))
        return now is not None and any(row["key"] == key for row in _extended_observations(current, now))
    latest = current.get("latest", {})
    if key.startswith("host:"):
        field = key.partition(":")[2]
        if field == "reboot":
            reboot = current.get("system", {}).get("reboot", {})
            now = timestamp(current.get("generatedAt"))
            return (isinstance(reboot, Mapping) and now is not None and reboot.get("status") == "ok"
                    and fresh(reboot.get("observedAt"), now) and type(reboot.get("required")) is bool)
        if field == "power":
            return type(latest.get("throttledFlags")) is int
        if field in {"sshListenersAvailable", "networkLinkAvailable"}:
            return type(current.get("reliability", {}).get(field)) is bool
        return number(latest.get("load1" if field == "load" else field)) is not None
    if key.startswith("disk:"):
        _, disk_id, field = key.split(":")
        for index, row in enumerate(current.get("disks", [])[:64]):
            if isinstance(row, Mapping) and not excluded(row) and hashlib.sha256(
                    str(row.get("mount", index)).encode()).hexdigest()[:12] == disk_id:
                return number(row.get(field)) is not None
        return False
    if key.startswith(("http-client-errors:", "http-server-errors:", "http-slow:")):
        kind, _, app = key.partition(":")
        rows = current.get("currentTraffic")
        if not isinstance(rows, list):
            return False
        matches = [row for row in rows[:64] if isinstance(row, Mapping) and not excluded(row) and row.get("app") == app]
        # A successful empty request interval is a healthy observed zero.
        fields = ("slowCount", "maxResponseMs") if kind == "http-slow" else (
            "status4xx" if kind == "http-client-errors" else "status5xx",)
        return not matches or all(number(row.get("requestCount")) is not None and all(
            number(row.get(field)) is not None for field in fields) for row in matches)
    return False
