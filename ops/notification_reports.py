#!/usr/bin/env python3
"""Hourly Korean reports and immediate signals using the existing SMTP outbox.

The collector calls produce_notifications after committing its public exports.
Only the independent alert delivery worker opens network connections. Producer
checkpoints and queue inserts share one SQLite transaction, including the UTC
hour slot, so restarts cannot repeat an unchanged warning or hourly report.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any, Mapping

try:
    from . import alert_delivery as delivery
    from . import security_signals as signals
    from . import notification_visuals as visuals
    from . import notification_policy as policy
    from .alert_store import _atomic_write, _delivery_config_path, _json_payload, normalize_event
except ImportError:  # Installed scripts share one directory.
    import alert_delivery as delivery
    import security_signals as signals
    import notification_visuals as visuals
    import notification_policy as policy
    from alert_store import _atomic_write, _delivery_config_path, _json_payload, normalize_event


STATUS_FILENAME = "notification-reports.json"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_LOG_TAIL_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 256 * 1024
MAX_SIGNALS = 128
MAX_DETECTIONS = 32
WARNING_COOLDOWN_SECONDS = 900
KST = dt.timezone(dt.timedelta(hours=9))
RETIRED_SIGNALS = {"host:cpuPressureFullAvg10":
    "판정 정책 정정: 호스트 범위 CPU PSI full은 유효한 지표가 아니므로 현재 경고에서 제외했습니다. 실제 장애 복구를 의미하지 않습니다."}


def _iso(now: dt.datetime) -> str:
    return now.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _kst(value: Any) -> str:
    parsed = signals.timestamp(value)
    return parsed.astimezone(KST).strftime("%m/%d %H:%M:%S KST") if parsed else "관측 없음"


def _read(path: Path, *, tail: bool = False) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022
            or metadata.st_size > MAX_INPUT_BYTES):
        raise ValueError("notification input is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("notification input changed")
        offset = max(0, metadata.st_size - MAX_LOG_TAIL_BYTES) if tail else 0
        os.lseek(descriptor, offset, os.SEEK_SET)
        limit = MAX_LOG_TAIL_BYTES if tail else MAX_INPUT_BYTES
        result = b""
        while len(result) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result += chunk
        if len(result) > limit:
            raise ValueError("notification input exceeds its limit")
        return result.partition(b"\n")[2] if offset else result
    finally:
        os.close(descriptor)


def _object(path: Path) -> dict[str, Any]:
    raw = _read(path)
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise ValueError("notification input must be an object")
    return value


def _rows(path: Path) -> list[dict[str, Any]]:
    raw = _read(path, tail=True)
    rows = []
    for line in (raw or b"").splitlines()[-20000:]:
        # Excluded records never reach JSON parsing or signal evaluation.
        if b"wgang" in line.lower() or not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict) and not signals.excluded(value):
            rows.append(value)
    return rows


def _health(source: str, status: str, observed_at: Any, detail: str) -> dict[str, Any]:
    return {"source": source, "status": status,
            "observedAt": _iso(signals.timestamp(observed_at)) if signals.timestamp(observed_at) else None,
            "detail": detail}


def _source_health(current: Mapping[str, Any], evaluation: Mapping[str, Any],
                   log_sources: Mapping[str, Any], now: dt.datetime,
                   traffic_available: bool | None = None) -> list[dict[str, Any]]:
    snapshot_fresh = signals.fresh(current.get("generatedAt"), now)
    result = [_health("snapshot", "fresh" if snapshot_fresh else "stale", current.get("generatedAt"),
                      "호스트 최신 표본 확인" if snapshot_fresh else "호스트 표본이 없거나 180초 이상 지연됨")]
    rules_fresh = signals.fresh(evaluation.get("evaluatedAt"), now) and evaluation.get("status") == "ok"
    result.append(_health("rules", "fresh" if rules_fresh else "unavailable", evaluation.get("evaluatedAt"),
                          "지속 규칙 평가 확인" if rules_fresh else "규칙 평가 최신성 또는 수집 상태 확인 필요"))
    ssh_sources = [row for row in log_sources.get("sources", [])[:64]
                   if isinstance(row, Mapping) and not signals.excluded(row)
                   and row.get("sourceId") in signals.SSH_SOURCES]
    ssh_ok = bool(ssh_sources) and all(row.get("status") in {"fresh", "no_data"}
               and signals.fresh(row.get("observedAt"), now) for row in ssh_sources)
    ssh_partial = bool(ssh_sources) and any(row.get("status") == "truncated" for row in ssh_sources)
    result.append(_health("ssh", "fresh" if ssh_ok else "partial" if ssh_partial else "unavailable",
                          log_sources.get("generatedAt"),
                          "검토된 SSH 로그 수집 정상; 새 로그 없음도 정상" if ssh_ok else
                          "SSH 로그 수집 범위 또는 최신성 확인 필요; 무시도 상태로 판단하지 않음"))
    traffic = current.get("currentTraffic")
    # A fresh snapshot alone does not establish access-log acquisition health.
    traffic_known = snapshot_fresh and isinstance(traffic, list) and (
        traffic_available is True or (traffic_available is None and any(
            isinstance(row, Mapping) and not signals.excluded(row) for row in traffic)))
    result.append(_health("http", "fresh" if traffic_known else "unavailable", current.get("generatedAt"),
                          "검토된 서비스별 HTTP 응답 코드 집계; 경로·IP·공격 성공 여부는 수집하지 않음"
                          if traffic_known else "HTTP 요청 집계가 없어 요청 이상 탐지 범위 확인 필요"))
    return result


def _event(rule: str, key: str, severity: str, now_text: str, opened: str,
           evidence: str, transition: str = "firing", count: int | None = None) -> dict[str, Any]:
    return normalize_event({
        "schemaVersion": 1, "rulePackVersion": "notifications-v1",
        "idempotencyKey": hashlib.sha256(key.encode()).hexdigest(),
        "ruleId": rule, "target": "host/monitor", "transition": transition,
        "severity": severity, "notificationState": "ready", "observedAt": now_text,
        "openedAt": opened, "value": count, "status": "ok",
        "labels": {"scope": "notification", "purpose": "report" if rule == "HourlyReport" else "signal"},
        "description": evidence[:500],
        "runbook": "Monitor의 최신 표본과 해당 사건의 관측 시각을 확인하세요. 공격 의심은 침입 성공을 뜻하지 않습니다.",
    })


def _empty_counts() -> dict[str, int]:
    return {"enqueued": 0, "deduplicated": 0, "dropped": 0}


def _emit(outbox: delivery.DeliveryOutbox, connection: sqlite3.Connection,
          config: delivery.DeliveryConfig, event: Mapping[str, Any], now: dt.datetime,
          counts: dict[str, int], presentation: Mapping[str, Any] | None = None) -> bool:
    selected = delivery.route_channels(config, event)
    if not selected:
        return False
    admitted = True
    for channel in selected:
        item = outbox._prepare_enqueue(event, channel, "operational", now.timestamp(), presentation)
        disposition = outbox._enqueue_prepared(connection, item, retry_dropped=True)
        counts[disposition] += 1
        admitted = admitted and disposition != "dropped"
    return admitted


def _needs_readmission(connection: sqlite3.Connection, config: delivery.DeliveryConfig,
                      event: Mapping[str, Any]) -> bool:
    for channel in delivery.route_channels(config, event):
        key = delivery.delivery_identity(event["idempotencyKey"], channel.channel_id, "operational")
        row = connection.execute("SELECT state,attempts FROM outbox WHERE delivery_key=?", (key,)).fetchone()
        if row is not None and row["state"] == "dropped" and row["attempts"] == 0:
            return True
        if row is None:
            audit = connection.execute(
                "SELECT outcome,attempt FROM delivery_log WHERE delivery_key=? ORDER BY id DESC LIMIT 1", (key,),
            ).fetchone()
            if audit is not None and audit["attempt"] == 0 and audit["outcome"] in {"dropped", "evicted"}:
                return True
    return False


def _recovery_unfinished(connection: sqlite3.Connection, config: delivery.DeliveryConfig,
                         event: Mapping[str, Any]) -> bool:
    for channel in delivery.route_channels(config, event):
        key = delivery.delivery_identity(event["idempotencyKey"], channel.channel_id, "operational")
        row = connection.execute("SELECT state,attempts FROM outbox WHERE delivery_key=?", (key,)).fetchone()
        if row is not None and (row["state"] in {"pending", "retry", "leased"}
                                or (row["state"] == "dropped" and row["attempts"] == 0)):
            return True
    return _needs_readmission(connection, config, event)


def _display_evidence(evidence: str) -> str:
    # Threshold documentation must not claim both limits were exceeded when
    # the actual incident only reached the warning range.
    return re.sub(r"; 주의 ([0-9.]+), 위험 ([0-9.]+) 기준 초과\.",
                  r"; 판정 기준: 주의 \1 / 위험 \2.", evidence)


def _immediate_presentation(event: Mapping[str, Any], evidence: str) -> dict[str, Any]:
    if event["transition"] == "resolved":
        evidence = _project_legacy_recovery(evidence)
    evidence = _display_evidence(evidence)
    label = "복구" if event["transition"] == "resolved" else "위험" if event["severity"] == "critical" else "주의"
    presentation: dict[str, Any] = {"subject": f"[Monitor {label}] {event['ruleId']}", "body":
            f"Monitor 즉시 알림 · {label}\n관측: {_kst(event['observedAt'])}\n"
            f"시작: {_kst(event['openedAt'])}\n\n{evidence}\n\n"
            "현재 표본과 사건 전후 기록을 확인하세요.\n"
            "보안 신호는 관측된 접근 시도/요청 패턴이며 침입 성공을 뜻하지 않습니다."}
    try:
        presentation["visual"] = delivery.email_visuals.normalize_visual(visuals.build_incident_visual(event, evidence))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass  # Visual decoration cannot prevent the established text delivery.
    return presentation


def _recovery_evidence(previous: str) -> str:
    historical = re.sub(r"최신 관측 기준입니다\.\s*|현재\s+", "", previous).strip()
    prefix = "서로 다른 새 관측 2회에서 알림 조건 해제를 확인했습니다. 해소 전 마지막 이상 관측: "
    return prefix + historical[:500 - len(prefix)]


def _project_legacy_recovery(evidence: str) -> str:
    """Repair the known legacy presentation without rewriting stored records."""
    prefix, suffix = "복구: ", " 새 관측에서 조건이 해제되었습니다."
    if evidence.startswith(prefix) and evidence.endswith(suffix):
        return _recovery_evidence(evidence[len(prefix):-len(suffix)])
    return evidence


def _mail_requirements(signal: Mapping[str, Any]) -> tuple[int, int]:
    """Debounce measurements, while retaining immediate discrete failures."""
    key = signal["key"]
    if key in RETIRED_SIGNALS:
        return 1000001, 0
    resource = policy.policy_for_signal(key)
    if resource is not None:
        if signal["severity"] == "critical" and resource.critical is None:
            return 1000001, 0  # Retired tiers cannot emit cached critical mail.
        return policy.qualification(resource, signal["severity"])
    if key == "tcp:retransmission":
        return 1, 0  # The weighted TCP window already requires three intervals.
    if key.startswith("synthetic:") and key.endswith(":latency"):
        return 3, 120
    if key == "ssh-auth":
        return (1, 0) if signal["count"] >= 5 else (1000000, 0)
    if key == "host:reboot" or key.endswith(":certificate"):
        return 1, 0
    if signal["severity"] == "critical":
        discrete = (key.startswith("kernel:") or key in {
            "host:power", "host:sshListenersAvailable", "host:networkLinkAvailable",
        } or (key.startswith(("synthetic:", "container:"))
              and key.rsplit(":", 1)[-1] in {"status", "state", "health", "oom", "restarts"}))
        return (1, 0) if discrete else (2, 60)
    return 3, 120


def _source_sample(key: str, source: str, current: Mapping[str, Any],
                   evaluation: Mapping[str, Any], log_sources: Mapping[str, Any],
                   now: dt.datetime) -> dt.datetime | None:
    if key.startswith("source:"):
        return now  # A fresh producer invocation observes source unavailability.
    value = (log_sources.get("generatedAt") if source == "ssh" else
             evaluation.get("evaluatedAt") if source == "rules" else
             signals.sample_timestamp(key, current))
    sample = signals.timestamp(value)
    maximum_age = 600 if key.startswith("synthetic:") else 180
    return sample if sample is not None and 0 <= (now - sample).total_seconds() <= maximum_age else None


def _qualify_signal(signal: Mapping[str, Any], prior: Mapping[str, Any],
                    sample: dt.datetime, now_text: str) -> tuple[dict[str, Any], bool]:
    key = signal["key"]
    sample_text = sample.isoformat().replace("+00:00", "Z")
    previous_sample = signals.timestamp(prior.get("lastSourceSampleAt") or prior.get("observedAt"))
    if previous_sample is not None and sample <= previous_sample:
        return dict(prior), False
    opened = prior.get("openedAt", _iso(sample)) if prior.get("status") == "active" else _iso(sample)
    identifier = hashlib.sha256(f"{key}\0{opened}".encode()).hexdigest()
    last_breach = signals.timestamp(prior.get("lastBreachSampleAt"))
    gap = 660 if key.startswith("synthetic:") else 180
    continuous = last_breach is not None and 0 < (sample - last_breach).total_seconds() <= gap
    critical_continuous = continuous and prior.get("qualificationSeverity") == "critical"
    item = {**prior, "id": identifier, "kind": signal["kind"], "severity": signal["severity"],
            "status": "active", "openedAt": opened, "observedAt": now_text,
            "count": signal["count"], "windowSeconds": signal["windowSeconds"], "evidence": signal["evidence"],
            "source": signal["source"], "notifiedSeverity": prior.get("notifiedSeverity"),
            "clearSamples": 0, "lastSourceSampleAt": sample_text,
            "lastBreachSampleAt": sample_text, "qualificationSeverity": signal["severity"],
            "firstBreachAt": prior["firstBreachAt"] if continuous else sample_text,
            "breachSamples": min(1000000, prior.get("breachSamples", 0) + 1) if continuous else 1}
    if signal["severity"] == "critical":
        item["criticalSamples"] = prior.get("criticalSamples", 0) + 1 if critical_continuous else 1
        item["firstCriticalAt"] = prior["firstCriticalAt"] if critical_continuous else sample_text
        item["belowCriticalSamples"] = 0
        item.pop("firstBelowCriticalAt", None)
    else:
        item["criticalSamples"] = 0
        item.pop("firstCriticalAt", None)
        below_continuous = continuous and prior.get("qualificationSeverity") == "warning"
        item["belowCriticalSamples"] = prior.get("belowCriticalSamples", 0) + 1 if below_continuous else 1
        item["firstBelowCriticalAt"] = prior.get("firstBelowCriticalAt", sample_text) if below_continuous else sample_text
    return item, True


def _qualified(signal: Mapping[str, Any], item: Mapping[str, Any]) -> bool:
    """Observation qualification is independent of routing and resend cooldown."""
    samples, seconds = _mail_requirements(signal)
    critical = signal["severity"] == "critical"
    first = signals.timestamp(item.get("firstCriticalAt" if critical else "firstBreachAt"))
    last = signals.timestamp(item.get("lastBreachSampleAt"))
    count = item.get("criticalSamples" if critical else "breachSamples", 0)
    if first is None or last is None or count < samples or (last - first).total_seconds() < seconds:
        return False
    return True


def _qualified_severity(key: str, item: Mapping[str, Any]) -> str | None:
    if key in RETIRED_SIGNALS:
        return None
    # A confirmed incident remains open through recovery qualification or loss
    # of observation. A first raw critical sample cannot upgrade a warning.
    # Delivery severity is a legacy migration fallback, not a permanent floor:
    # a confirmed downgrade must not be undone by the last mail's old severity.
    confirmed = {item.get("qualifiedSeverity") if "qualifiedSeverity" in item else item.get("notifiedSeverity")}
    resource = policy.policy_for_signal(key)
    if resource is not None and resource.critical is None and "critical" in confirmed:
        # A retired critical tier is reclassified, not reported as recovered.
        confirmed.discard("critical")
        confirmed.add("warning")
    signal = {**item, "key": key}
    if (item.get("severity") == "critical" and (resource is None or resource.critical is not None)
            and _qualified(signal, item)):
        confirmed.add("critical")
    if item.get("severity") in {"warning", "critical"} and _qualified({**signal, "severity": "warning"}, item):
        confirmed.add("warning")
    below_started = signals.timestamp(item.get("firstBelowCriticalAt"))
    last = signals.timestamp(item.get("lastBreachSampleAt"))
    recovery_samples = resource.recovery_samples if resource else 2
    recovery_seconds = resource.recovery_seconds if resource else 60
    if (item.get("severity") == "warning" and "critical" in confirmed
            and item.get("belowCriticalSamples", 0) >= recovery_samples and below_started is not None and last is not None
            and (last - below_started).total_seconds() >= recovery_seconds):
        confirmed.discard("critical")
        confirmed.add("warning")
    return "critical" if "critical" in confirmed else "warning" if "warning" in confirmed else None


def _resource_hysteresis(observed: list[dict[str, Any]], active: Mapping[str, Any],
                         current: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Hold confirmed resource incidents until their separate recovery bands.

    Missing values are never inserted as healthy observations. Raw, unconfirmed
    peaks cannot establish a hysteresis band or an enduring incident.
    """
    result = {row["key"]: row for row in observed}
    for key, prior in active.items():
        resource = policy.policy_for_signal(key)
        if resource is None or not isinstance(prior, Mapping) or signals.excluded(key):
            continue
        value = policy.resource_value(key, current)
        confirmed = _qualified_severity(key, prior)
        severity = policy.severity_for_value(resource, value, confirmed)
        if value is None or severity is None:
            continue
        result[key] = {"key": key, "kind": "operational-caution", "severity": severity,
                       "source": "snapshot", "count": max(1, int(value)), "windowSeconds": 300,
                       "evidence": policy.evidence_for_value(resource, value, severity)}
    return list(result.values())


def _report_active(active: Mapping[str, Any]) -> dict[str, Any]:
    return {key: {**item, "evidence": _display_evidence(item.get("evidence", "")),
                  "signalKey": key, "reportSeverity": _qualified_severity(key, item),
                  "reportRecoveryPending": item.get("clearSamples", 0) > 0,
                  "reportDowngradePending": _qualified_severity(key, item) == "critical"
                      and item.get("severity") == "warning"}
            for key, item in active.items()
            if isinstance(item, Mapping) and item.get("status") == "active"
            and not signals.excluded(key) and not signals.excluded(item)}


def _mail_ready(signal: Mapping[str, Any], item: Mapping[str, Any],
                last_notice: Mapping[str, Any], now: dt.datetime) -> bool:
    if not _qualified(signal, item):
        return False
    previous = signals.timestamp(last_notice.get("at"))
    escalation = signal["severity"] == "critical" and last_notice.get("severity") != "critical"
    cooldown_applies = signal["severity"] == "warning" or signal["key"] == "tcp:retransmission"
    return not (cooldown_applies and not escalation and previous is not None
                and (now - previous).total_seconds() < WARNING_COOLDOWN_SECONDS)


def _report_rules(evaluation: Mapping[str, Any], outstanding: list[dict[str, Any]],
                  config: delivery.DeliveryConfig, previous: Mapping[str, Any],
                  now: dt.datetime) -> dict[str, Any]:
    """Project only SMTP-authorized rule episodes, preserving known source gaps."""
    if evaluation.get("status") != "ok" or not signals.fresh(evaluation.get("evaluatedAt"), now):
        retained = {key: {**row, "reportRetained": True} for key, row in previous.items()
                    if isinstance(row, Mapping) and row.get("reportReady") is True
                    and not signals.excluded(key) and not signals.excluded(row)}
        return {**evaluation, "states": retained}
    ready = {(row["ruleId"], row["target"], row["openedAt"]): row for row in outstanding
             if any(channel.kind == "smtp" for channel in delivery.route_channels(config, row))}
    rows = {}
    for key, row in evaluation.get("states", {}).items():
        if not isinstance(row, Mapping) or signals.excluded(key) or signals.excluded(row):
            continue
        authority = ready.get((row.get("ruleId"), row.get("target"), row.get("openedAt")))
        rows[key] = {**row, "reportReady": authority is not None,
                     "reportSeverity": authority["severity"] if authority is not None else None}
    return {**evaluation, "states": rows}


def _active_rule_events(evaluation: Mapping[str, Any], private: Mapping[str, Any],
                        events: list[dict[str, Any]], now: dt.datetime) -> list[dict[str, Any]]:
    """Current ready incidents survive the transition replay window on activation.

    Public firing state alone is not notification authority: retain ready events,
    or require a matching private ready checkpoint if their opening was pruned.
    """
    if evaluation.get("status") != "ok" or not signals.fresh(evaluation.get("evaluatedAt"), now):
        return []
    result = []
    for state_key, row in list(evaluation.get("states", {}).items())[:4096]:
        if (not isinstance(row, Mapping) or signals.excluded(row)
                or row.get("phase") not in {"firing", "recovering"}
                or row.get("severity") not in {"warning", "critical"}):
            continue
        matches = [event for event in events if event.get("ruleId") == row.get("ruleId")
                   and event.get("target") == row.get("target") and event.get("openedAt") == row.get("openedAt")
                   and event.get("transition") == "firing" and event.get("notificationState") == "ready"]
        if matches:
            result.append(matches[-1])
            continue
        authority = private.get("states", {}).get(state_key, {})
        if (not isinstance(authority, Mapping) or authority.get("notificationState") != "ready"
                or authority.get("openedAt") != row.get("openedAt")):
            continue
        version = evaluation.get("rulePackVersion")
        identity = f"{version}\0{row['ruleId']}\0{row['target']}\0{row['openedAt']}\0firing"
        try:
            result.append(normalize_event({
                "schemaVersion": 1, "rulePackVersion": version,
                "idempotencyKey": hashlib.sha256(identity.encode()).hexdigest(),
                "ruleId": row["ruleId"], "target": row["target"], "transition": "firing",
                "severity": row["severity"], "notificationState": "ready",
                "observedAt": row["lastEvaluatedAt"], "openedAt": row["openedAt"],
                "value": row.get("lastValue"), "status": row["observationStatus"],
                "labels": authority.get("notificationLabels", {}),
                "description": row["description"], "runbook": row["runbook"],
            }))
        except (KeyError, ValueError):
            continue
    return result


def _digest(current: Mapping[str, Any], evaluation: Mapping[str, Any],
            health: list[dict[str, Any]], active: Mapping[str, Any],
            events: list[dict[str, Any]], now: dt.datetime,
            output_dir: Path | None = None) -> dict[str, Any]:
    now_text = _iso(now)
    report_active = _report_active(active)
    assessment = visuals.assess_hourly(current, evaluation, health, report_active, now)
    rule_rows, active_rows = assessment["rule_rows"], assessment["active_rows"]
    summary = {"ok": "정상", "warning": "주의", "critical": "위험", "unknown": "관측 불가"}[assessment["status"]]
    lines = [f"Monitor 매시간 서버 보고 · {summary}", f"보고 시각: {_kst(now_text)}",
             f"최신 수집: {_kst(current.get('generatedAt'))}", "",
             "전체 등급은 확인된 미해소 사건과 관측 가능 여부를 기준으로 합니다.",
             "아래 수치는 관측값이며, 순간값만으로 서버 전체를 위험으로 판정하지 않습니다."]
    for card in assessment["cards"]:
        lines.append(f"{card['label']}: {card['value']}{card['unit']}")
    latest = current.get("latest", {})
    if (assessment["snapshot_fresh"] and isinstance(latest, Mapping)
            and signals.fresh(latest.get("timestamp", current.get("generatedAt")), now)):
        for key, label, unit in (("load1", "1분 부하", ""),
                                 ("memoryPressureSomeAvg10", "메모리 PSI", "%"),
                                 ("ioPressureSomeAvg10", "I/O PSI", "%")):
            value = signals.number(latest.get(key))
            lines.append(f"{label}: {value:g}{unit}" if value is not None else f"{label}: 수집 없음")
        system = current.get("system", {})
        reboot = system.get("reboot", {})
        if (isinstance(reboot, Mapping) and reboot.get("status") == "ok"
                and signals.fresh(reboot.get("observedAt"), now) and type(reboot.get("required")) is bool):
            lines.append(f"재부팅 필요: {'예' if reboot['required'] else '아니오'}")
            packages = [value for value in reboot.get("packages", [])[:64]
                        if isinstance(value, str) and len(value) <= 160 and not signals.excluded(value)
                        and re.fullmatch(r"[a-z0-9][a-z0-9+.:_-]*", value)]
            if packages:
                lines.append("재부팅 관련 패키지: " + ", ".join(packages[:8]) + (" 외 추가 항목" if len(packages) > 8 else ""))
        else:
            lines.append("재부팅 필요: 관측 없음 또는 최신성 확인 필요")
        kernel = system.get("kernel", {})
        history = kernel.get("rcuExpedited", {})
        count = signals.number(history.get("count"))
        if count:
            lines.append(f"부팅 후 짧은 RCU 지연 이력 {int(count)}건, 마지막 {_kst(history.get('lastEventAt'))} (과거 사건)")
    else:
        lines.append("최신 표본이 없어 자원 수치를 현재 정상으로 표시하지 않습니다.")
    lines.extend(["", f"확인된 활성 규칙 {len(rule_rows)}건 / 확인된 추가 경고 {len(active_rows)}건"])
    for row in rule_rows[:12]:
        rule, target = signals.safe_name(row.get("ruleId")), signals.safe_name(row.get("target"))
        if rule and target:
            lines.append(f"- {rule} ({target}), {row.get('phase')}")
    for row in active_rows[:8]:
        label = "위험" if row["reportSeverity"] == "critical" else "주의"
        state_label = "복구 확인 중" if row.get("reportRecoveryPending") else "미해소"
        lines.append(f"- [{label} · {state_label}] 마지막 이상 관측: {row['evidence']}")
    lines.extend(["", *assessment["highlights"]])
    recent = [row for row in events if signals.fresh(row.get("observedAt"), now, 3600)
              and row.get("ruleId") in {"TcpRetransmissionHigh", "HttpLatencyHigh", "HttpProbeFailed"}]
    lines.extend(["", f"최근 1시간 네트워크·HTTP 규칙 전이 {len(recent)}건"])
    for row in recent[-6:]:
        lines.append(f"- {_kst(row['observedAt'])}: {row['ruleId']} "
                     f"{'복구' if row['transition'] == 'resolved' else '발생'}, 관측값 {row['value']}")
    lines.extend(["", "탐지 입력 상태"])
    for row in health:
        lines.append(f"- {row['source']}: {row['status']} · {row['detail']}")
    lines.extend(assessment.get("coverage_notes", []))
    lines.extend(["", "외부 감시: 미구축. 별도 서버·서비스가 없어 서버 전체 정지·전원 단절 시 이 서버는 이메일을 보낼 수 없습니다.",
                  "이는 현재 장애가 아니라 감시 범위의 한계이며, 외부 감시 미구축만으로 위험 알림을 만들지 않습니다."])
    lines.extend(["", "SSH는 비허용 로그인·인증 실패 패턴, HTTP는 응답 코드 이상을 관찰합니다.",
                  "요청 주소·IP·사용자명·원문 로그는 메일에 포함하지 않습니다."])
    body = "\n".join(lines)
    # Leave enough room for the normalized event within the existing 16 KiB envelope.
    while len(body.encode()) > 9500:
        lines.pop(-6)
        body = "\n".join(lines)
    presentation: dict[str, Any] = {"subject": f"[Monitor 매시간 보고] {summary} · {now.astimezone(KST):%m/%d %H시}", "body": body}
    try:
        presentation["visual"] = delivery.email_visuals.normalize_visual(
            visuals.build_hourly_visual(output_dir, current, evaluation, health, report_active, now,
                                        assessment=assessment))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return presentation


def _readonly_producer_state(output_dir: Path) -> dict[str, Any] | None:
    """Read the existing qualification checkpoint without creating a DB or journal."""
    path = output_dir.absolute() / ".state" / "alert-delivery" / "alert-delivery.sqlite"
    try:
        for parent in (path.parent, path.parent.parent):
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                return None
        delivery._validate_db_file(path)
        before = path.lstat()
        with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2.0)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            row = connection.execute("SELECT value FROM notification_producer_state WHERE id=1").fetchone()
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or row is None:
            return None
        if not isinstance(row[0], str) or len(row[0].encode()) > MAX_STATE_BYTES:
            return None
        value = json.loads(row[0])
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, sqlite3.Error):
        return None


def build_hourly_presentation(output_dir: Path, now: dt.datetime) -> dict[str, Any]:
    """Read-only preview, including existing qualification; no writes or secrets."""
    now = (now if now.tzinfo else now.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)
    current = _object(output_dir / "current.json")
    evaluation = _object(output_dir / "rule-evaluation.json")
    report = _object(output_dir / STATUS_FILENAME)
    prior_health = report.get("sourceHealth", [])
    traffic_available = next((row.get("status") == "fresh" for row in prior_health
                              if isinstance(row, Mapping) and row.get("source") == "http"), None)
    if not signals.fresh(report.get("observedAt"), now):
        traffic_available = None
    health = _source_health(current, evaluation, _object(output_dir / "generic-log-sources.json"), now, traffic_available)
    state = _readonly_producer_state(output_dir)
    if state is None:
        state = {}
        health[1] = _health("rules", "unavailable", None,
                            "메일 판정 체크포인트를 확인할 수 없습니다. 공개 관측 목록만으로 위험·정상을 추정하지 않습니다.")
    notification_current, _ = signals.prepare_notification_current(current, now, state.get("tcpWindow"))
    saved_rules = state.get("reportRules", {})
    if evaluation.get("status") == "ok" and signals.fresh(evaluation.get("evaluatedAt"), now):
        projected = {}
        for key, row in evaluation.get("states", {}).items():
            if not isinstance(row, Mapping) or signals.excluded(key) or signals.excluded(row):
                continue
            saved = saved_rules.get(key, {})
            confirmed = (saved.get("reportReady") is True and saved.get("openedAt") == row.get("openedAt")
                         and row.get("phase") in {"firing", "recovering"})
            projected[key] = {**row, "reportReady": confirmed,
                              "reportSeverity": saved.get("reportSeverity") if confirmed else None}
        evaluation = {**evaluation, "states": projected}
    else:
        evaluation = {**evaluation, "states": saved_rules}
    return _digest(notification_current, evaluation, health, state.get("active", {}),
                   _rows(output_dir / "rule-alerts.jsonl"), now, output_dir)


def produce_notifications(
    output_dir: Path, now: dt.datetime, *, current: Mapping[str, Any] | None = None,
    evaluation: Mapping[str, Any] | None = None, delivery_config_path: Path | None = None,
    traffic_available: bool | None = None,
) -> dict[str, Any]:
    """Publish bounded status and enqueue reports; never send mail or read secrets."""
    now = (now if now.tzinfo else now.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)
    now_text = _iso(now)
    slot = now.strftime("%Y-%m-%dT%H:00:00Z")
    status: dict[str, Any] = {
        "schemaVersion": 1, "observedAt": now_text, "status": "error",
        "hourly": {"slot": slot, "lastQueuedAt": None, **_empty_counts()},
        "immediate": _empty_counts(), "sourceHealth": [], "detections": [],
        "delivery": {"pending": 0, "retrying": 0, "sent": 0, "failed": 0,
                     "lastAttemptAt": None, "lastOutcome": None},
    }
    try:
        current = current if current is not None else _object(output_dir / "current.json")
        evaluation = evaluation if evaluation is not None else _object(output_dir / "rule-evaluation.json")
        log_sources = _object(output_dir / "generic-log-sources.json")
        log_rows = _rows(output_dir / "generic-logs.jsonl")
        events = _rows(output_dir / "rule-alerts.jsonl")
        outstanding_events = _active_rule_events(
            evaluation, _object(output_dir / ".state" / "rule-state.json"), events, now)
        outstanding_ids = {event["idempotencyKey"] for event in outstanding_events}
        event_ids = {event.get("idempotencyKey") for event in events}
        events.extend(event for event in outstanding_events if event["idempotencyKey"] not in event_ids)
        health = _source_health(current, evaluation, log_sources, now, traffic_available)
        log_path = output_dir / "generic-logs.jsonl"
        if log_path.exists() and log_path.stat().st_size > MAX_LOG_TAIL_BYTES:
            times = [parsed for row in log_rows if (parsed := signals.timestamp(row.get("timestamp"))) is not None]
            if not times or min(times) > now - dt.timedelta(seconds=signals.WINDOW_SECONDS):
                health[2] = _health("ssh", "partial", log_sources.get("generatedAt"),
                                    "로그 읽기 상한으로 최근 5분 SSH 관측 범위가 일부 누락될 수 있음")
        status["sourceHealth"] = health
        health_by_source = {row["source"]: row["status"] for row in health}
        observed = signals.ssh_signals(log_rows, now) if health_by_source["ssh"] in {"fresh", "partial"} else []
        if health_by_source["http"] == "fresh":
            observed.extend(signals.http_signals(current))
        for row in health:
            if row["status"] != "fresh":
                observed.append({"key": f"source:{row['source']}", "kind": "source-unavailable",
                                 "severity": "warning", "source": row["source"], "count": 1,
                                 "windowSeconds": 180, "evidence": row["detail"]})
        configured_path = _delivery_config_path(delivery_config_path)
        config = delivery.load_delivery_config(configured_path) if configured_path else delivery.DeliveryConfig(
            (), (), delivery.QueueConfig(1000, 5000, 10000, 300, 10, 900))
        enabled = any(channel.enabled and channel.kind == "smtp" for channel in config.channels)
        # The user's mail preference does not implicitly enable other destinations.
        config = delivery.DeliveryConfig(tuple(channel for channel in config.channels if channel.kind == "smtp"),
                                         config.routes, config.queue)
        outbox = delivery.DeliveryOutbox(output_dir / ".state" / "alert-delivery" / "alert-delivery.sqlite", config.queue)
        with contextlib.closing(outbox._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS notification_producer_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL CHECK(length(value)<=262144))")
            prior_row = connection.execute("SELECT value FROM notification_producer_state WHERE id=1").fetchone()
            state = json.loads(prior_row[0]) if prior_row else {}
            notification_current, state["tcpWindow"] = signals.prepare_notification_current(
                current, now, state.get("tcpWindow"))
            if health_by_source["snapshot"] == "fresh":
                observed.extend(signals.operational_signals(notification_current, now))
            active = state.get("active", {})
            if health_by_source["snapshot"] == "fresh":
                observed = _resource_hysteresis(observed, active, notification_current)
            last_notices = {key: row for key, row in state.get("lastNotices", {}).items()
                            if not signals.excluded(key) and isinstance(row, Mapping)
                            and signals.fresh(row.get("at"), now, 86400)}
            pending_recoveries = []
            for event in state.get("pendingRecoveries", [])[:128]:
                if signals.excluded(event):
                    continue
                _emit(outbox, connection, config, event, now, status["immediate"],
                      _immediate_presentation(event, event["description"]))
                if _recovery_unfinished(connection, config, event):
                    pending_recoveries.append(event)
            recent = [row for row in state.get("recent", []) if not signals.excluded(row)
                      and (row.get("status") == "active" or signals.fresh(row.get("observedAt"), now, 86400))]
            for key, explanation in RETIRED_SIGNALS.items():
                retired = active.pop(key, None)
                if isinstance(retired, Mapping):
                    recent = [row for row in recent if row["id"] != retired["id"]] + [{
                        **retired, "status": "resolved", "severity": "warning", "observedAt": now_text,
                        "evidence": explanation}]
                    # Administrative retirement, no fabricated recovery email.
            observed.sort(key=lambda item: (item["severity"] != "critical", item["key"]))
            present = {signal["key"] for signal in observed}
            for signal in observed[:MAX_SIGNALS]:
                key = signal["key"]
                prior = active.get(key, {})
                sample = _source_sample(key, signal["source"], notification_current, evaluation, log_sources, now)
                if sample is None:
                    if prior:
                        prior["breachSamples"] = prior["clearSamples"] = 0
                        prior.pop("lastBreachSampleAt", None)
                    continue
                item, _ = _qualify_signal(signal, prior, sample, now_text)
                if not item:
                    continue
                item["qualifiedSeverity"] = _qualified_severity(key, item)
                identifier = item["id"]
                effective_signal = {**item, "key": key}
                ready = _mail_ready(effective_signal, item, last_notices.get(key, {}), now)
                if not ready and item["severity"] == "critical" and item["notifiedSeverity"] is None:
                    warning_signal = {**effective_signal, "severity": "warning"}
                    if _mail_ready(warning_signal, item, last_notices.get(key, {}), now):
                        effective_signal, ready = warning_signal, True
                mail_severity = effective_signal["severity"]
                escalation = mail_severity == "critical" and item["notifiedSeverity"] == "warning"
                event = _event("SecurityPattern" if item["kind"].startswith("ssh-") else "OperationalCaution",
                               f"signal\0{identifier}\0{mail_severity}", mail_severity,
                               now_text, item["openedAt"], item["evidence"], count=item["count"])
                readmission = _needs_readmission(connection, config, event)
                if readmission or ((item["notifiedSeverity"] is None or escalation)
                                   and ready):
                    if _emit(outbox, connection, config, event, now, status["immediate"],
                             _immediate_presentation(event, item["evidence"])):
                        item["notifiedSeverity"] = mail_severity
                        last_notices[key] = {"at": now_text, "severity": mail_severity}
                active[key] = item
                recent = [row for row in recent if row["id"] != identifier] + [item]
            for key, item in list(active.items()):
                if key in present:
                    continue
                sample = _source_sample(key, item["source"], notification_current, evaluation, log_sources, now)
                previous_sample = signals.timestamp(item.get("lastSourceSampleAt") or item.get("observedAt"))
                if sample is not None and previous_sample is not None and sample <= previous_sample:
                    continue  # Cached/backdated input cannot alter a streak, even if absent from signals.
                # Missing telemetry cannot prove a formerly active signal recovered.
                if not key.startswith("source:") and health_by_source.get(item["source"]) != "fresh":
                    item["clearSamples"] = item["breachSamples"] = 0
                    item.pop("lastBreachSampleAt", None)
                    continue
                if not signals.observable(key, notification_current):
                    item["clearSamples"] = item["breachSamples"] = 0
                    item.pop("lastBreachSampleAt", None)
                    continue
                if sample is None or (previous_sample is not None and sample <= previous_sample):
                    continue
                sample_time = sample.isoformat().replace("+00:00", "Z")
                gap = 660 if key.startswith("synthetic:") else 180
                if previous_sample is not None and (sample - previous_sample).total_seconds() > gap:
                    item["clearSamples"] = 0
                if not item.get("clearSamples"):
                    item["firstClearAt"] = sample_time
                item["lastSourceSampleAt"] = sample_time
                item["clearObservedAt"] = sample_time
                item["breachSamples"] = 0
                item.pop("lastBreachSampleAt", None)
                item["clearSamples"] = item.get("clearSamples", 0) + 1
                resource = policy.policy_for_signal(key)
                recovery_samples = resource.recovery_samples if resource else 2
                recovery_seconds = resource.recovery_seconds if resource else 0
                first_clear = signals.timestamp(item.get("firstClearAt"))
                if (item["clearSamples"] < recovery_samples or first_clear is None
                        or (sample - first_clear).total_seconds() < recovery_seconds):
                    continue
                evidence = _recovery_evidence(item["evidence"])
                event = _event("SecurityPattern" if item["kind"].startswith("ssh-") else "OperationalCaution",
                               f"signal\0{item['id']}\0resolved", item["notifiedSeverity"] or item["severity"],
                               now_text, item["openedAt"], evidence, "resolved", 0)
                if item["notifiedSeverity"]:
                    _emit(outbox, connection, config, event, now, status["immediate"], _immediate_presentation(event, evidence))
                    if _recovery_unfinished(connection, config, event):
                        pending_recoveries.append(event)
                item = {**item, "status": "resolved", "observedAt": now_text, "count": 0, "evidence": evidence}
                recent = [row for row in recent if row["id"] != item["id"]] + [item]
                del active[key]
            for raw in events[-4096:]:
                outstanding = raw.get("idempotencyKey") in outstanding_ids
                if not outstanding and not signals.fresh(raw.get("observedAt"), now, 86400):
                    continue
                event = normalize_event(raw)
                if event["notificationState"] != "ready" or event["ruleId"] in delivery.NON_DELIVERABLE_OPERATIONAL_RULES:
                    continue
                if event["severity"] not in {"warning", "critical"}:
                    continue
                evidence = f"{event['ruleId']} ({event['target']}): 관측값 {event['value']}; " + (
                    "규칙 조건 복구" if event["transition"] == "resolved" else "지속 규칙 조건 충족")
                if outstanding or signals.fresh(event["observedAt"], now, config.queue.replay_window_seconds):
                    _emit(outbox, connection, config, event, now, status["immediate"], _immediate_presentation(event, evidence))
                identifier = hashlib.sha256(
                    f"rule\0{event['ruleId']}\0{event['target']}\0{event['openedAt']}".encode()
                ).hexdigest()
                recent = [row for row in recent if row["id"] != identifier] + [{
                    "id": identifier, "kind": "rule-alert", "severity": event["severity"],
                    "status": "resolved" if event["transition"] == "resolved" else "active",
                    "openedAt": event["openedAt"], "observedAt": event["observedAt"],
                    "count": 0 if event["transition"] == "resolved" else 1, "windowSeconds": 0, "evidence": evidence,
                }]
            report_evaluation = _report_rules(evaluation, outstanding_events, config, state.get("reportRules", {}), now)
            report_rule_fields = {"ruleId", "target", "openedAt", "phase", "severity", "lastEvaluatedAt",
                                  "observationStatus", "reportReady", "reportSeverity", "reportRetained"}
            state["reportRules"] = {
                key: {field: value for field, value in row.items() if field in report_rule_fields}
                for key, row in report_evaluation.get("states", {}).items() if row.get("reportReady") is True}
            event = _event("HourlyReport", f"hourly\0{slot}", "info", now_text, slot, "서버 매시간 상태 보고")
            if enabled and (not state.get("lastHour") or slot > state["lastHour"] or (
                    slot == state["lastHour"] and _needs_readmission(connection, config, event))):
                if _emit(outbox, connection, config, event, now, status["hourly"],
                         _digest(notification_current, report_evaluation, health, active, events, now, output_dir)):
                    state["lastHour"], state["lastQueuedAt"] = slot, now_text
            recent.sort(key=lambda row: row["observedAt"], reverse=True)
            state.update({"active": active, "recent": recent[:MAX_DETECTIONS],
                          "pendingRecoveries": pending_recoveries,
                          "lastNotices": dict(sorted(last_notices.items(), key=lambda pair: pair[1]["at"],
                                                     reverse=True)[:MAX_SIGNALS])})
            serialized = json.dumps(state, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            if len(serialized.encode()) > MAX_STATE_BYTES:
                raise ValueError("notification state exceeds its bound")
            connection.execute("INSERT INTO notification_producer_state(id,value) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", (serialized,))
            outbox._prune(connection)
            connection.execute("COMMIT")
        status["hourly"]["lastQueuedAt"] = state.get("lastQueuedAt")
        public_fields = {"id", "kind", "severity", "status", "openedAt", "observedAt", "count", "windowSeconds", "evidence"}
        status["detections"] = [{key: value for key, value in row.items() if key in public_fields} for row in state["recent"]]
        for row in status["detections"]:
            if row["status"] == "resolved":
                row["evidence"] = _project_legacy_recovery(row["evidence"])
        delivery_status = outbox.status()
        totals, counters = delivery_status["states"], delivery_status["stats"]
        last = next(iter(outbox.delivery_log(1)), {})
        last_time = last.get("finished_at") or last.get("started_at")
        status["delivery"] = {
            "pending": totals["pending"] + totals["leased"], "retrying": totals["retry"],
            "sent": counters.get("operational_succeeded", 0),
            "failed": counters.get("operational_final_failure", 0) + counters.get("operational_dropped", 0),
            "lastAttemptAt": _iso(dt.datetime.fromtimestamp(last_time, dt.timezone.utc)) if last_time is not None else None,
            "lastOutcome": last.get("outcome"),
        }
        status["status"] = "ok" if enabled else "disabled"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error, RecursionError):
        # No exception text, input content, config, recipient or credentials cross
        # into the public status. Existing rules/collection remain independent.
        status["status"] = "error"
        status["hourly"].update(_empty_counts())
        status["immediate"].update(_empty_counts())
    try:
        _atomic_write(output_dir / STATUS_FILENAME, _json_payload(status, MAX_STATE_BYTES), 0o640)
    except (OSError, ValueError):
        status["status"] = "error"
    return status
