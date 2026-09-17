"""Small, frozen visual data for notification mail; no rendering or delivery.

Trend readers visit only the one or two UTC dates intersecting the last hour.
Host peaks use 2-minute maxima, TCP percentages use segment-weighted buckets,
and missing/reset/zero-denominator observations remain gaps.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from . import security_signals as signals
    from . import notification_policy as policy
except ImportError:
    import security_signals as signals
    import notification_policy as policy


MAX_VISUAL_BYTES = 4096
MAX_DAY_BYTES = 8 * 1024 * 1024
MAX_TAIL_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = 32 * 1024
BUCKETS = 30
KST = dt.timezone(dt.timedelta(hours=9))
SOURCE_LABELS = {"snapshot": "서버", "rules": "규칙", "ssh": "SSH", "http": "HTTP"}
SOURCE_STATES = {"fresh", "stale", "unavailable", "partial"}
UNSAFE_TEXT = re.compile(
    r"https?://|www\.|<[^>]*>|\b[^\s@]+@[^\s@]+\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"(?:password|passwd|secret|token|api[-_]?key|authorization)\s*[:=]", re.I,
)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or signals.excluded(value) or UNSAFE_TEXT.search(value):
        return ""
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value):
        return ""
    return " ".join(value.split())[:limit]


def _value(raw: Any, maximum: float) -> float | None:
    value = signals.number(raw)
    return value if value is not None and value <= maximum else None


def _rows(path: Path) -> list[dict[str, Any]]:
    try:
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
            return []
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return []
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022
                or metadata.st_size > MAX_DAY_BYTES):
            return []
        offset = max(0, metadata.st_size - MAX_TAIL_BYTES)
        os.lseek(descriptor, offset, os.SEEK_SET)
        chunks = []
        remaining = MAX_TAIL_BYTES
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if offset:
            raw = raw.partition(b"\n")[2]
        result = []
        for line in raw.splitlines()[-10000:]:
            if not line or len(line) > MAX_ROW_BYTES or b"wgang" in line.lower():
                continue
            try:
                row = json.loads(line)
            except (UnicodeError, ValueError, RecursionError):
                continue
            if isinstance(row, dict) and not signals.excluded(row):
                result.append(row)
        return result
    except OSError:
        return []
    finally:
        os.close(descriptor)


def build_hour_trend(output_dir: Path | None, now: dt.datetime) -> dict[str, Any] | None:
    if output_dir is None:
        return None
    end = (now if now.tzinfo else now.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc).replace(microsecond=0)
    start = end - dt.timedelta(hours=1)
    dates = sorted({start.date(), end.date()})
    cpu: list[float | None] = [None] * BUCKETS
    memory: list[float | None] = [None] * BUCKETS
    numerator = [0] * BUCKETS
    denominator = [0] * BUCKETS

    def bucket(value: Any) -> int | None:
        parsed = signals.timestamp(value)
        if parsed is None or not start <= parsed <= end:
            return None
        return min(BUCKETS - 1, int((parsed - start).total_seconds()) // 120)

    seen_tcp: set[str] = set()
    for day in dates:
        for row in _rows(output_dir / "history" / f"{day.isoformat()}.jsonl"):
            index = bucket(row.get("timestamp"))
            if index is None:
                continue
            for field, destination in (("cpuPercent", cpu), ("memoryPercent", memory)):
                value = _value(row.get(field), 100)
                if value is not None:
                    destination[index] = max(destination[index], value) if destination[index] is not None else value
        for row in _rows(output_dir / "network-diagnostics" / f"{day.isoformat()}.jsonl"):
            index = bucket(row.get("observedAt"))
            observed_at = row.get("observedAt")
            if index is None or observed_at in seen_tcp:
                continue
            tcp = row.get("tcp")
            if not isinstance(tcp, Mapping) or tcp.get("status") != "fresh":
                continue
            retransmitted, outbound = tcp.get("retransmittedSegments"), tcp.get("outboundSegments")
            if (type(retransmitted) is not int or type(outbound) is not int
                    or not 0 <= retransmitted <= 10 ** 18 or not 0 <= outbound <= 10 ** 18):
                continue
            seen_tcp.add(observed_at)
            if not outbound:
                continue
            numerator[index] += retransmitted
            denominator[index] += outbound
    return {"from": _iso(start), "to": _iso(end),
            "cpu": [round(value, 2) if value is not None else None for value in cpu],
            "memory": [round(value, 2) if value is not None else None for value in memory],
            "tcp": [round(100 * top / bottom, 3) if bottom and 100 * top / bottom <= 1e6 else None
                    for top, bottom in zip(numerator, denominator)]}


def _card(label: str, raw: Any, unit: str, caution: float, critical: float,
          available: bool, maximum: float = 1e6, decimals: int = 1) -> dict[str, str]:
    value = _value(raw, maximum) if available else None
    displayed = "관측 없음" if value is None else f"{value:.{decimals}f}"
    if "." in displayed:
        displayed = displayed.rstrip("0").rstrip(".")
    return {"label": label, "value": displayed,
            "unit": unit if value is not None else "",
            "tone": "unknown" if value is None else "critical" if value >= critical else "warning" if value >= caution else "ok"}


def _bounded(value: dict[str, Any]) -> dict[str, Any]:
    while len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()) > MAX_VISUAL_BYTES:
        if value["highlights"]:
            value["highlights"].pop()
        elif value["trend"] is not None:
            value["trend"] = None
        elif value["cards"]:
            value["cards"].pop()
        else:
            raise ValueError("visual exceeds its limit")
    return value


def assess_hourly(current: Mapping[str, Any], evaluation: Mapping[str, Any],
                  source_health: Sequence[Mapping[str, Any]], active: Mapping[str, Any],
                  now: dt.datetime) -> dict[str, Any]:
    """One mail verdict, based on qualified unresolved incidents, not raw peaks.

    The producer supplies ``reportSeverity`` for additional signals and
    ``reportReady`` for rules after checking notification authority. Old/public
    rows without that authority are observations, not confirmed emergencies.
    Missing input is a separate coverage problem and cannot clear an incident.
    """
    now = (now if now.tzinfo else now.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)
    snapshot_fresh = signals.fresh(current.get("generatedAt"), now)
    rules_fresh = evaluation.get("status") == "ok" and signals.fresh(evaluation.get("evaluatedAt"), now)
    current_active = []
    unconfirmed_count = 0
    for key, row in active.items():
        if (not isinstance(row, Mapping) or row.get("status") != "active"
                or signals.excluded(key) or signals.excluded(row)):
            continue
        if row.get("reportSeverity") in {"warning", "critical"}:
            current_active.append({**row, "signalKey": row.get("signalKey", key)})
        else:
            unconfirmed_count += 1
    states = evaluation.get("states", {})
    states = states if isinstance(states, Mapping) else {}
    active_rules = []
    unconfirmed_rules = 0
    # An established ready incident remains unresolved while evaluation is lost.
    # An old public firing row, however, is not enough to establish authority.
    for key, row in states.items():
        if (not isinstance(row, Mapping) or row.get("phase") not in {"firing", "recovering"}
                or signals.excluded(key) or signals.excluded(row)):
            continue
        ready = (row.get("reportReady") is True if "reportReady" in row
                 else rules_fresh and row.get("notificationState") == "ready")
        if not ready:
            if "reportReady" not in row and "notificationState" not in row:
                unconfirmed_rules += 1
            continue
        severity = row.get("reportSeverity", row.get("severity"))
        if severity in {"warning", "critical"}:
            active_rules.append({**row, "reportSeverity": severity})

    def matched_severity(signal_match: Any, rule_ids: set[str]) -> str | None:
        levels = [row["reportSeverity"] for row in current_active if signal_match(row["signalKey"])]
        levels += [row["reportSeverity"] for row in active_rules if row.get("ruleId") in rule_ids]
        return "critical" if "critical" in levels else "warning" if "warning" in levels else None

    def observation(card: dict[str, str], severity: str | None) -> dict[str, str]:
        if card["tone"] != "unknown":
            # Color this measurement, not the last incident peak. A warning
            # observation can coexist with an unresolved critical incident while
            # its downgrade is being verified; neither can promote the other.
            card["tone"] = ("critical" if severity == card["tone"] == "critical" else "warning"
                            if severity and card["tone"] in {"warning", "critical"} else "neutral")
        card["label"] += " · 관측"
        return card

    latest = current.get("latest", {})
    latest = latest if isinstance(latest, Mapping) else {}
    latest_fresh = snapshot_fresh and signals.fresh(latest.get("timestamp", current.get("generatedAt")), now)
    cards = [observation(_card(label, latest.get(field), unit, policy.RESOURCE_POLICIES[field].warning,
                              policy.RESOURCE_POLICIES[field].critical or float("inf"), latest_fresh, maximum),
                         matched_severity(lambda key, field=field: key == f"host:{field}", {rule_id}))
             for label, field, unit, maximum, rule_id in (
                 ("CPU", "cpuPercent", "%", 100, "CpuUsageHigh"),
                 ("메모리", "memoryPercent", "%", 100, "MemoryAvailableLow"),
                 ("온도", "temperatureC", "°C", 200, "TemperatureHigh"))]
    disks = [_value(row.get("usedPercent"), 100) for row in current.get("disks", [])[:64]
             if isinstance(row, Mapping) and not signals.excluded(row)]
    disks = [value for value in disks if value is not None]
    disk_policy = policy.RESOURCE_POLICIES["usedPercent"]
    cards.append(observation(_card("디스크 최대", max(disks) if disks else None, "%", disk_policy.warning,
                                  disk_policy.critical, snapshot_fresh, 100),
                             matched_severity(lambda key: isinstance(key, str) and key.startswith("disk:") and key.endswith(":usedPercent"),
                                              {"DiskUsageHigh", "DiskUsageCritical"})))
    linux = current.get("linux", {})
    linux = linux if isinstance(linux, Mapping) else {}
    coverage_notes = []
    processes = linux.get("processes", {})
    if isinstance(processes, Mapping) and (processes.get("status") == "partial"
                                           or processes.get("pidCountLowerBound") is True):
        coverage_notes.append("프로세스는 일부만 관측됩니다. 관측된 좀비 0개를 호스트 전체 정상으로 판단하지 않습니다.")
    systemd = linux.get("systemd", {})
    if isinstance(systemd, Mapping) and systemd.get("status") == "partial":
        coverage_notes.append("systemd는 부분 관측입니다. 실행 결과·재시작 횟수가 미확인인 유닛은 정상이나 장애로 단정하지 않습니다.")
    tcp = linux.get("tcp", {})
    tcp = tcp if isinstance(tcp, Mapping) else {}
    tcp_fresh = snapshot_fresh and signals.fresh(linux.get("collectedAt"), now) and tcp.get("rateStatus") == "ok" and tcp.get("status") == "supported"
    window = tcp.get("notificationWindow")
    window = window if isinstance(window, Mapping) else {}
    outbound, retransmitted = window.get("outboundSegmentsDelta"), window.get("retransmittedSegmentsDelta")
    # Only the same qualified count window used by mail detection is displayable.
    # In particular, a preview must never fall back to an instantaneous ratio.
    tcp_ratio = (100 * retransmitted / outbound if type(outbound) is int and type(retransmitted) is int
                 and 0 < outbound <= 10 ** 18 and 0 <= retransmitted <= 10 ** 18
                 and type(window.get("sampleCount")) is int and window["sampleCount"] >= signals.TCP_MIN_SAMPLES
                 and (signals.number(window.get("windowSeconds")) or 0) >= signals.TCP_MIN_SPAN_SECONDS else None)
    if (tcp_ratio is not None and tcp_ratio >= 1 and outbound < signals.TCP_MIN_OUTBOUND_SEGMENTS
            and retransmitted < signals.TCP_MIN_RETRANSMITTED_SEGMENTS):
        tcp_ratio = None
    cards.append(observation(_card("TCP 합산 재전송", tcp_ratio, "%", 1, 5, tcp_fresh, decimals=3),
                             matched_severity(lambda key: key == "tcp:retransmission", {"TcpRetransmissionHigh"})))
    collection = current.get("syntheticProbeCollection", {})
    collection = collection if isinstance(collection, Mapping) else {}
    # Match the collector's 10-minute synthetic input freshness contract.
    probes_fresh = snapshot_fresh and collection.get("status") == "fresh" and signals.fresh(collection.get("observedAt"), now, 600)
    probes = [row for row in current.get("syntheticProbes", [])[:32] if isinstance(row, Mapping)
              and not signals.excluded(row) and signals.fresh(row.get("checkedAt"), now, 600)] if probes_fresh else []
    latencies = [_value(row.get("latencyMilliseconds"), 600000) for row in probes]
    latencies = [value for value in latencies if value is not None]
    http = _card("HTTP 응답 최대", max(latencies) if latencies else None, "ms", 1000, 3000, bool(probes), decimals=1)
    if any(row.get("status") in {"dns", "timeout", "tls", "http"} for row in probes):
        http.update(value="검사 실패", unit="", tone="critical")
    cards.append(observation(http, matched_severity(
        lambda key: isinstance(key, str) and key.startswith("synthetic:") and key.endswith((":latency", ":status")),
        {"HttpLatencyHigh", "HttpEndpointDown", "HttpProbeFailed"})))
    health_map = {row.get("source"): row for row in source_health if isinstance(row, Mapping) and not signals.excluded(row)}
    sources = []
    for key, label in SOURCE_LABELS.items():
        row = health_map.get(key, {})
        status = row.get("status") if row.get("status") in SOURCE_STATES else "unavailable"
        if status == "fresh" and not signals.fresh(row.get("observedAt"), now):
            status = "stale"
        sources.append({"label": label, "status": status})
    reboot = current.get("system", {}).get("reboot", {})
    reboot_needed = (snapshot_fresh and isinstance(reboot, Mapping) and reboot.get("status") == "ok"
                     and signals.fresh(reboot.get("observedAt"), now) and reboot.get("required") is True)
    highlights = []
    for row in sorted(current_active, key=lambda item: item.get("reportSeverity") != "critical"):
        evidence = _text(row.get("evidence"), 160)
        if row.get("reportRecoveryPending") is True and evidence:
            evidence = ("복구 확인 중 · 직전 확정 사건: " + evidence)[:160]
        elif row.get("reportDowngradePending") is True:
            evidence = ("위험 해제 확인 중 · 마지막 관측은 주의 범위" + (": " + evidence if evidence else ""))[:160]
        if evidence and not (reboot_needed and "재부팅 필요" in evidence):
            highlights.append(evidence)
        if len(highlights) == 3:
            break
    if reboot_needed:
        packages = [_text(value, 60) for value in reboot.get("packages", [])[:8]]
        packages = [value for value in packages if value]
        highlights = ["재부팅 필요" + (" · " + ", ".join(packages) if packages else "")][:1] + highlights[:2]
        highlights[0] = highlights[0][:160]
        highlights.append("작업을 저장하고 점검 시간을 정한 뒤 재부팅하세요. 이후 서비스 정상 여부를 확인하세요.")
    elif active_rules and len(highlights) < 4:
        highlights.append(f"활성 규칙 {len(active_rules)}건 · 해당 서비스 상태와 최근 변경 내역을 확인하세요.")
    elif not highlights:
        highlights.append("카드는 최신 관측, 그래프는 최근 1시간의 기록이며 순간 수치만으로 장애를 확정하지 않습니다.")
    levels = [row["reportSeverity"] for row in current_active + active_rules]
    missing_cards = any(card["tone"] == "unknown" for card in cards)
    missing_core = not snapshot_fresh or not rules_fresh
    missing_sources = any(row["status"] != "fresh" for row in sources)
    status = ("critical" if "critical" in levels else "warning" if "warning" in levels or reboot_needed
              else "unknown" if missing_core else "warning" if missing_cards or missing_sources or unconfirmed_rules or coverage_notes else "ok")
    if missing_core:
        highlights.insert(0, "수집 또는 평가가 지연됐습니다. 확인된 미해결 장애는 유지하며, 관측 손실을 복구로 처리하지 않습니다."
                          if levels else "수집이 지연됐거나 평가를 확인할 수 없습니다. 과거 수치를 현재 정상 상태로 해석하지 마세요.")
    elif missing_cards:
        highlights.insert(0, "일부 지표의 최신 관측이 없습니다. 관측 없음은 정상 상태를 뜻하지 않으므로 수집 상태를 확인하세요.")
    elif missing_sources:
        highlights.insert(0, "일부 탐지 입력을 확인할 수 없습니다. 주의 표시는 장애 확정이 아니라 관측 범위 확인 요청입니다.")
    elif unconfirmed_rules:
        highlights.insert(0, "일부 활성 규칙의 알림 확정 상태를 확인할 수 없습니다. 현재 위험으로 단정하지 않습니다.")
    if unconfirmed_count and len(highlights) < 4:
        highlights.append(f"확정 전 관측 {unconfirmed_count}건은 참고 정보이며 현재 위험 건수에 포함하지 않습니다.")
    if coverage_notes and len(highlights) < 4:
        highlights.append("일부 로컬 관측 범위가 제한됩니다. 주의 표시는 서버 장애 확정이 아닙니다.")
    return {"status": status, "active_rows": current_active, "rule_rows": active_rules,
            "sources": sources, "cards": cards, "highlights": highlights[:4],
            "snapshot_fresh": snapshot_fresh, "rules_fresh": rules_fresh,
            "unconfirmed_count": unconfirmed_count, "unconfirmed_rule_count": unconfirmed_rules,
            "reboot_needed": reboot_needed, "coverage_notes": coverage_notes}


def build_hourly_visual(output_dir: Path | None, current: Mapping[str, Any],
                        evaluation: Mapping[str, Any], source_health: Sequence[Mapping[str, Any]],
                        active: Mapping[str, Any], now: dt.datetime, *,
                        assessment: Mapping[str, Any] | None = None) -> dict[str, Any]:
    now = (now if now.tzinfo else now.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)
    assessment = assessment if assessment is not None else assess_hourly(current, evaluation, source_health, active, now)
    status = assessment["status"]
    generated = signals.timestamp(current.get("generatedAt"))
    subtitle = f"{now.astimezone(KST):%m/%d %H:%M} KST · 마지막 수집 " + (f"{generated.astimezone(KST):%H:%M:%S}" if generated else "관측 없음")
    subtitle += f" · 활성 규칙 {len(assessment['rule_rows'])} · 확정 신호 {len(assessment['active_rows'])}"
    return _bounded({"schemaVersion": 1, "kind": "hourly", "theme": "light", "status": status,
                     "title": "확인된 활성 경고가 없습니다" if status == "ok" else "확인된 위험이 아직 해소되지 않았습니다" if status == "critical"
                     else "확인할 사항이 있습니다" if status == "warning" else "새로운 관측을 확인해주세요",
                     "subtitle": subtitle, "cards": [dict(card) for card in assessment["cards"]],
                     "highlights": list(assessment["highlights"]), "sources": list(assessment["sources"]),
                     "trend": build_hour_trend(output_dir, now)})


def build_incident_visual(event: Mapping[str, Any], evidence: str) -> dict[str, Any]:
    if signals.excluded(event) or signals.excluded(evidence):
        raise ValueError("excluded notification visual")
    resolved = event.get("transition") == "resolved"
    status = "resolved" if resolved else "critical" if event.get("severity") == "critical" else "warning"
    reboot = "재부팅" in evidence
    ssh = event.get("ruleId") == "SecurityPattern" or "SSH" in evidence
    tcp = "TCP" in evidence or event.get("ruleId") == "TcpRetransmissionHigh"
    title = ("재부팅 필요 조건이 해제됐습니다" if resolved else "서버 재부팅이 필요합니다") if reboot else (
        "SSH 관측 조건이 해제됐습니다" if resolved else "SSH 접근 시도가 감지됐습니다") if ssh else (
        "TCP 재전송 경고가 해제됐습니다" if resolved else "네트워크 품질을 확인해주세요") if tcp else (
        "알림 조건이 해제됐습니다" if resolved else "서버에 확인할 사항이 있습니다")
    observed = signals.timestamp(event.get("observedAt"))
    opened = signals.timestamp(event.get("openedAt"))
    cards = [{"label": "알림 상태", "value": {"warning": "주의", "critical": "위험", "resolved": "조건 해제"}[status], "unit": "", "tone": status},
             {"label": "처음 관측", "value": f"{opened.astimezone(KST):%m/%d %H:%M}" if opened else "관측 없음", "unit": "KST" if opened else "", "tone": "neutral" if opened else "unknown"}]
    highlights = [_text(evidence, 160)]
    if resolved:
        highlights.append("복구 문구의 이전 이상값은 해소 전 기록입니다. 현재 정상값을 뜻하지 않습니다.")
    elif reboot:
        highlights.extend(["운영체제가 재부팅 필요 표식을 보고했습니다. 즉시 장애가 발생했다는 뜻은 아닙니다.",
                           "진행 중인 작업을 저장하고 서비스 점검 시간을 정하세요. 재부팅 후 서비스 상태를 확인하세요."])
    elif ssh:
        highlights.append("거부 또는 인증 실패의 관측입니다. 침입 성공 여부는 확인되지 않았습니다.")
    elif tcp:
        highlights.append("전체 송신량과 재전송 건수를 함께 보고, 외부 경로·장비·상대 서버 상태를 확인하세요.")
    else:
        highlights.append("해당 지표의 현재 값과 최근 변경·서비스 상태를 함께 확인하세요.")
    return _bounded({"schemaVersion": 1, "kind": "incident", "theme": "light", "status": status,
                     "title": title, "subtitle": f"{observed.astimezone(KST):%m/%d %H:%M:%S} KST · 즉시 알림" if observed else "관측 시각 확인 필요",
                     "cards": cards, "highlights": [value for value in highlights if value][:4], "sources": [], "trend": None})
