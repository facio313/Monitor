#!/usr/bin/env python3
"""Build Monitor's bounded public monitoring-catalog contract.

The catalog contains only reviewed labels, retention limits, and normalized
alert-rule metadata.  It deliberately never exports configured input paths,
credentials, private state, or raw observations.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Mapping

try:  # Installed scripts use flat imports; tests may import as a package.
    from alert_engine import AlertRule, load_rule_pack
except ModuleNotFoundError:  # pragma: no cover - package-style test import
    from .alert_engine import AlertRule, load_rule_pack


SCHEMA_VERSION = 1
MAX_CATALOG_BYTES = 2 * 1024 * 1024
RULE_EVALUATION_MAX_BYTES = 8 * 1024 * 1024
RULE_ALERT_MAX_BYTES = 32 * 1024 * 1024
RULE_ALERT_MAX_RECORDS = 5_000
GENERIC_STATUS_MAX_BYTES = 512 * 1024
SYSTEM_UPDATE_MAX_BYTES = 512 * 1024
INFRASTRUCTURE_LEDGER_MAX_BYTES = 16 * 1024 * 1024
INCIDENT_MAX_BYTES = 16 * 1024 * 1024
SYNTHETIC_PROBE_INTERVAL_SECONDS = 5 * 60
PUBLIC_RULE_SCOPES = frozenset({
    "agent", "certificate", "container", "database", "disk", "docker",
    "endpoint", "filesystem", "hardware", "host", "job", "monitor",
    "network", "process", "proxy", "security", "service", "storage",
})
FORBIDDEN_PUBLIC_TEXT = re.compile(
    r"(?:^|[^A-Za-z0-9/])/(?!/)[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*"
    r"|-----BEGIN [^-]+ PRIVATE KEY-----"
    r"|\b(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+"
    r"|(?:https?|ssh)://[^\s/@:]+:[^\s/@]+@"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    re.IGNORECASE,
)


def _localized(ko: str, en: str) -> dict[str, str]:
    return {"ko": ko, "en": en}


def _retention(
    policy: str,
    prune_cadence: str,
    *,
    max_age_days: int | None = None,
    max_records: int | None = None,
    record_scope: str | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    return {
        "policy": policy,
        "pruneCadence": prune_cadence,
        "maxAgeDays": max_age_days,
        "maxRecords": max_records,
        "recordScope": record_scope,
        "maxBytes": max_bytes,
    }


def _source(
    source_id: str,
    ko: str,
    en: str,
    description_ko: str,
    description_en: str,
    kind: str,
    evidence_mode: str,
    artifact_label: str,
    file_format: str,
    cadence_seconds: int | None,
    retention: Mapping[str, Any],
    detail_pages: list[str],
) -> dict[str, Any]:
    return {
        "id": source_id,
        "displayName": _localized(ko, en),
        "description": _localized(description_ko, description_en),
        "kind": kind,
        "evidenceMode": evidence_mode,
        "artifactLabel": artifact_label,
        "format": file_format,
        "cadenceSeconds": cadence_seconds,
        "retention": dict(retention),
        "detailPages": detail_pages,
    }


def evidence_sources(
    *,
    collection_interval_seconds: int,
    retention_days: int,
    max_log_records: int,
    incident_retention_days: int,
    max_incident_records: int,
    generic_log_retention_days: int,
    generic_log_max_records: int,
    generic_log_max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Return every reviewed public evidence surface and its runtime limits."""

    interval = collection_interval_seconds
    bounded_rule_events = min(RULE_ALERT_MAX_RECORDS, max_log_records)
    return [
        _source(
            "current-snapshot", "현재 상태 스냅샷", "Current state snapshot",
            "가장 최근에 정규화된 호스트·컨테이너·진단 상태입니다.",
            "The latest normalized host, container, and diagnostic state.",
            "snapshot", "current-state", "current.json", "json", interval,
            _retention("replace-on-collect", "replace-on-collection", max_records=1, record_scope="artifact"),
            ["resources", "network", "storage", "containers", "reliability", "power"],
        ),
        _source(
            "telemetry-history", "시계열 이력", "Telemetry history",
            "날짜별 CPU·메모리·부하·전력·네트워크·디스크 표본입니다.",
            "Daily CPU, memory, load, power, network, and disk samples.",
            "time-series", "accumulated-log", "history/YYYY-MM-DD.jsonl", "jsonl", interval,
            _retention(
                "daily-age-and-count", "every-collection", max_age_days=retention_days,
                max_records=2_000, record_scope="daily-partition",
            ),
            ["resources", "network", "storage", "power", "incidents"],
        ),
        _source(
            "semantic-alert-events", "수집기 경보 이벤트", "Collector alert events",
            "수집기가 정규화한 호스트 및 트래픽 경보 전환입니다.",
            "Normalized host and traffic alert transitions from the collector.",
            "event-log", "accumulated-log", "alerts.jsonl", "jsonl", interval,
            _retention("bounded-record-count", "every-collection", max_records=max_log_records, record_scope="artifact"),
            ["reliability", "incidents", "logs"],
        ),
        _source(
            "power-events", "전원 이벤트", "Power events",
            "전압 저하·스로틀·전원 관련 상태 전환의 정규화 기록입니다.",
            "Normalized under-voltage, throttling, and power-state transitions.",
            "event-log", "accumulated-log", "power.jsonl", "jsonl", interval,
            _retention("bounded-record-count", "every-collection", max_records=max_log_records, record_scope="artifact"),
            ["power", "reliability", "logs"],
        ),
        _source(
            "privilege-events", "권한 이벤트", "Privilege events",
            "민감 내용을 제거한 sudo·su·인증·정책 결과 기록입니다.",
            "Sanitized sudo, su, authentication, and policy outcomes.",
            "event-log", "accumulated-log", "privilege.jsonl", "jsonl", interval,
            _retention("bounded-record-count", "every-collection", max_records=max_log_records, record_scope="artifact"),
            ["maintenance", "infrastructure", "logs"],
        ),
        _source(
            "reliability-events", "신뢰성 이벤트", "Reliability events",
            "부팅·수집 공백·링크·커널·NVMe·PCIe 상태 전환입니다.",
            "Host boot, collection-gap, link, kernel, NVMe, and PCIe transitions.",
            "event-log", "accumulated-log", "reliability.jsonl", "jsonl", interval,
            _retention("bounded-record-count", "every-collection", max_records=max_log_records, record_scope="artifact"),
            ["reliability", "storage", "network", "power", "logs"],
        ),
        _source(
            "incident-events", "인시던트 이력", "Incident history",
            "자원·전력·스토리지·트래픽 이상 구간과 복구 후속 표본입니다.",
            "Resource, power, storage, and traffic incident windows and follow-up samples.",
            "event-log", "accumulated-log", "incidents.jsonl", "jsonl", interval,
            _retention(
                "bounded-age-count-and-bytes", "on-incident-write-or-daily", max_age_days=incident_retention_days,
                max_records=max_incident_records, record_scope="artifact",
                max_bytes=INCIDENT_MAX_BYTES,
            ),
            ["incidents", "resources", "network", "storage", "power"],
        ),
        _source(
            "rule-evaluation-state", "규칙 평가 상태", "Rule evaluation state",
            "로드된 경보 규칙의 대상별 최신 평가 상태입니다.",
            "The latest target-specific evaluation state for loaded alert rules.",
            "state", "current-state", "rule-evaluation.json", "json", interval,
            _retention(
                "replace-on-collect", "replace-on-collection", max_records=1, record_scope="artifact",
                max_bytes=RULE_EVALUATION_MAX_BYTES,
            ),
            ["reliability", "incidents", "logs"],
        ),
        _source(
            "rule-alert-events", "규칙 경보 전환", "Rule alert transitions",
            "규칙 경보의 발생·해제 및 알림 준비 상태 기록입니다.",
            "Rule firing, resolution, and notification-readiness transitions.",
            "event-log", "accumulated-log", "rule-alerts.jsonl", "jsonl", interval,
            _retention(
                "bounded-count-and-bytes", "every-rule-evaluation", max_records=bounded_rule_events,
                record_scope="artifact", max_bytes=RULE_ALERT_MAX_BYTES,
            ),
            ["reliability", "incidents", "logs"],
        ),
        _source(
            "generic-log-events", "통합 일반 로그", "Generic normalized logs",
            "허용된 소스에서 수집하고 비밀·개인정보를 제거한 통합 로그입니다.",
            "Allow-listed logs normalized with secret and personal-data redaction.",
            "event-log", "accumulated-log", "generic-logs.jsonl", "jsonl", interval,
            _retention(
                "bounded-age-count-and-bytes", "every-generic-collection", max_age_days=generic_log_retention_days,
                max_records=generic_log_max_records, record_scope="artifact",
                max_bytes=generic_log_max_file_bytes,
            ),
            ["logs", "containers", "reliability", "incidents"],
        ),
        _source(
            "generic-log-source-state", "로그 소스 수집 상태", "Log source collection state",
            "각 허용 로그 소스의 최신 수집 성공·실패·누락 상태입니다.",
            "The latest success, failure, and no-data state for each allow-listed log source.",
            "source-status", "current-state", "generic-log-sources.json", "json", interval,
            _retention(
                "replace-on-collect", "replace-on-generic-collection", max_records=1, record_scope="artifact",
                max_bytes=GENERIC_STATUS_MAX_BYTES,
            ),
            ["logs", "reliability"],
        ),
        _source(
            "system-update-state", "시스템 업데이트 상태", "System update state",
            "업데이트 확인·적용 작업의 최신 공개 상태입니다.",
            "The latest public state of system update checks and applications.",
            "external-state", "current-state", "system-update.json", "json", None,
            _retention(
                "replace-on-change", "replace-on-change", max_records=1, record_scope="artifact",
                max_bytes=SYSTEM_UPDATE_MAX_BYTES,
            ),
            ["maintenance"],
        ),
        _source(
            "infrastructure-ledger", "인프라 관리 원장", "Infrastructure ledger",
            "검증된 인프라 작업·결정·증거를 별도로 관리하는 공개 원장입니다.",
            "A separately managed public ledger of verified infrastructure work and evidence.",
            "external-state", "current-state", "infrastructure-ledger.json", "json", None,
            _retention(
                "externally-managed", "external-no-auto-prune", max_records=5_000, record_scope="artifact",
                max_bytes=INFRASTRUCTURE_LEDGER_MAX_BYTES,
            ),
            ["infrastructure"],
        ),
        _source(
            "agent-inventory", "에이전트 인벤토리", "Agent inventory",
            "등록된 원격 에이전트의 최신 수명주기·연결·인벤토리 상태입니다.",
            "The latest lifecycle, connectivity, and inventory state for registered remote agents.",
            "external-state", "current-state", "agents API", "api", None,
            _retention("externally-managed", "external-no-auto-prune"),
            ["infrastructure", "reliability"],
        ),
    ]


def _observation(
    observation_id: str,
    domain: str,
    ko: str,
    en: str,
    description_ko: str,
    description_en: str,
    evidence_mode: str,
    cadence_seconds: int | None,
    evidence_source_ids: list[str],
    detail_pages: list[str],
) -> dict[str, Any]:
    return {
        "id": observation_id,
        "domain": domain,
        "displayName": _localized(ko, en),
        "description": _localized(description_ko, description_en),
        "evidenceMode": evidence_mode,
        "cadenceSeconds": cadence_seconds,
        "evidenceSourceIds": evidence_source_ids,
        "detailPages": detail_pages,
    }


def observations(collection_interval_seconds: int) -> list[dict[str, Any]]:
    """Describe every public dashboard/current telemetry family."""

    cadence = collection_interval_seconds
    current = ["current-snapshot"]
    current_history = ["current-snapshot", "telemetry-history"]
    return [
        _observation("agent.identity-heartbeat", "agent", "에이전트 신원·하트비트", "Agent identity and heartbeat", "로컬 에이전트 신원, 수명주기, 시퀀스, 지연과 시계 편차를 확인합니다.", "Tracks local agent identity, lifecycle, sequence, delay, and clock skew.", "current-state", cadence, current, ["reliability", "infrastructure"]),
        _observation("agent.remote-inventory", "agent", "원격 에이전트 상태", "Remote agent state", "등록된 원격 에이전트의 연결, 인증서, 수명주기와 호스트 인벤토리를 확인합니다.", "Tracks registered remote-agent connectivity, certificates, lifecycle, and host inventory.", "current-state", None, ["agent-inventory"], ["infrastructure", "reliability"]),
        _observation("host.identity-capacity", "host", "호스트 정보·용량", "Host identity and capacity", "운영체제, 아키텍처, 논리 CPU 수와 가동 시간을 확인합니다.", "Tracks operating system, architecture, logical CPUs, and uptime.", "current-state", cadence, current, ["resources", "infrastructure"]),
        _observation("resources.cpu-load-pressure", "resources", "CPU·부하·PSI", "CPU, load, and PSI", "CPU 사용률, 코어별 부하, CPU 모드와 압력 지표를 확인합니다.", "Tracks CPU use, load per core, CPU modes, and pressure signals.", "current-and-history", cadence, current_history, ["resources"]),
        _observation("resources.memory-swap-pressure", "resources", "메모리·스왑·PSI", "Memory, swap, and PSI", "메모리 사용량, 스왑 사용·입출력과 메모리 압력을 확인합니다.", "Tracks memory use, swap use and I/O, and memory pressure.", "current-and-history", cadence, current_history, ["resources"]),
        _observation("resources.process-capacity", "resources", "프로세스·PID·파일 디스크립터", "Processes, PIDs, and file descriptors", "프로세스·스레드·좀비 수와 PID·파일 디스크립터 한도를 확인합니다.", "Tracks process, thread, and zombie counts plus PID and file-descriptor capacity.", "current-state", cadence, current, ["resources", "reliability"]),
        _observation("resources.process-usage", "resources", "사건 시 프로세스 사용 증거", "Incident process usage evidence", "이상 구간이 열릴 때 허용 목록 프로세스 범주의 CPU·메모리 사용을 사건 기록에 보존합니다.", "Retains CPU and memory use for allow-listed process groups in incident records when an abnormal window opens.", "accumulated-log", cadence, ["incident-events"], ["resources", "incidents"]),
        _observation("storage.filesystems-inodes", "storage", "파일시스템·아이노드", "Filesystems and inodes", "용량, 여유 공간, 아이노드 사용률과 읽기 전용 상태를 확인합니다.", "Tracks capacity, free space, inode use, and read-only state.", "current-state", cadence, current, ["storage"]),
        _observation("storage.block-io", "storage", "블록 장치 I/O", "Block-device I/O", "처리량, 지연, 큐 깊이, 사용률과 회전식 장치 여부를 확인합니다.", "Tracks throughput, latency, queue depth, utilization, and rotational media.", "current-and-history", cadence, current_history, ["storage"]),
        _observation("storage.device-health", "storage", "스토리지 장치 상태", "Storage device health", "SMART·RAID 상태와 성능 저하 장치 수를 확인합니다.", "Tracks SMART and RAID status and degraded-device counts.", "current-state", cadence, current, ["storage", "reliability"]),
        _observation("network.interfaces-quality", "network", "네트워크 처리량·품질", "Network throughput and quality", "송수신 속도, 오류와 드롭률, 기본 링크 가용성을 확인합니다.", "Tracks receive/transmit rates, errors, drops, and primary-link availability.", "current-and-history", cadence, current_history, ["network"]),
        _observation("network.tcp-sockets", "network", "TCP·소켓 상태", "TCP and socket state", "TCP 상태, 재전송, 임시 포트와 conntrack 사용률을 확인합니다.", "Tracks TCP states, retransmissions, ephemeral ports, and conntrack capacity.", "current-state", cadence, current, ["network", "reliability"]),
        _observation("network.application-traffic", "network", "애플리케이션 트래픽", "Application traffic", "앱별 요청량, 응답 등급과 느린 요청 지표를 확인합니다.", "Tracks per-application request volume, response classes, and slow requests.", "current-state", cadence, current, ["network", "incidents"]),
        _observation("reliability.systemd-units", "reliability", "systemd 서비스", "systemd services", "허용된 유닛의 상태, 결과, 종료 코드와 재시작 횟수를 확인합니다.", "Tracks allow-listed unit state, result, exit status, and restart counts.", "current-state", cadence, current, ["reliability", "maintenance"]),
        _observation("reliability.clock-time-sync", "reliability", "시계·시간 동기화", "Clock and time synchronization", "부팅 시각, 재부팅 감지, NTP 동기화와 시계 편차를 확인합니다.", "Tracks boot time, reboot detection, NTP synchronization, and clock drift.", "current-state", cadence, current, ["reliability"]),
        _observation("reliability.host-links", "reliability", "호스트·SSH·링크 가용성", "Host, SSH, and link availability", "수집 공백, SSH 리스너와 네트워크 링크 상태 전환을 확인합니다.", "Tracks collection gaps, SSH listeners, and network-link transitions.", "mixed", cadence, ["current-snapshot", "reliability-events"], ["reliability", "network"]),
        _observation("reliability.kernel-events", "reliability", "커널 장애 이벤트", "Kernel failure events", "경고, oops, panic, hung task, RCU stall, OOM과 파일시스템 오류를 확인합니다.", "Tracks warnings, oops, panic, hung tasks, RCU stalls, OOM, and filesystem errors.", "mixed", cadence, ["current-snapshot", "reliability-events"], ["reliability"]),
        _observation("reliability.pcie", "reliability", "PCIe 링크·AER", "PCIe link and AER", "협상 속도·폭, 전원 절약 설정과 AER 오류 상태를 확인합니다.", "Tracks negotiated speed and width, power-saving settings, and AER errors.", "mixed", cadence, ["current-snapshot", "reliability-events"], ["reliability", "storage"]),
        _observation("reliability.nvme", "reliability", "NVMe 펌웨어·오류", "NVMe firmware and errors", "모델·펌웨어·절전 완화 상태와 리셋·I/O 오류를 확인합니다.", "Tracks model, firmware, power mitigation, resets, and I/O errors.", "mixed", cadence, ["current-snapshot", "reliability-events"], ["reliability", "storage"]),
        _observation("power.thermal-cooling", "power", "온도·센서·팬", "Temperature, sensors, and fans", "호스트 온도, thermal/hwmon 센서와 팬 회전수를 확인합니다.", "Tracks host temperature, thermal and hwmon sensors, and fan speed.", "current-and-history", cadence, current_history, ["power", "resources"]),
        _observation("power.platform-state", "power", "전압·스로틀·플랫폼 전력", "Voltage, throttling, and platform power", "전압, 주파수 제한, 스로틀과 Raspberry Pi 전력 플래그를 확인합니다.", "Tracks voltage, frequency caps, throttling, and Raspberry Pi power flags.", "mixed", cadence, ["current-snapshot", "telemetry-history", "power-events"], ["power", "reliability"]),
        _observation("containers.inventory-lifecycle", "containers", "컨테이너 인벤토리·수명주기", "Container inventory and lifecycle", "고정 서비스 인벤토리, 실행·건강 상태, 시작·종료와 재시작을 확인합니다.", "Tracks fixed-service inventory, runtime and health state, starts, exits, and restarts.", "current-state", cadence, current, ["containers"]),
        _observation("containers.resources-limits", "containers", "컨테이너 자원·제한", "Container resources and limits", "CPU·메모리·PID 사용과 제한, 스로틀, OOM 상태를 확인합니다.", "Tracks CPU, memory, and PID use and limits, throttling, and OOM state.", "current-state", cadence, current, ["containers", "resources"]),
        _observation("containers.io-network", "containers", "컨테이너 I/O·네트워크", "Container I/O and network", "블록·네트워크 누적량과 속도, 오류, writable layer 크기를 확인합니다.", "Tracks block and network totals and rates, errors, and writable-layer size.", "current-state", cadence, current, ["containers", "network", "storage"]),
        _observation("containers.mount-network-surface", "containers", "컨테이너 마운트·노출면", "Container mounts and exposure", "볼륨·bind·tmpfs·네트워크·공개 포트 수와 마운트 정책 상태를 확인합니다.", "Tracks volumes, binds, tmpfs, networks, published ports, and mount-policy state.", "current-state", cadence, current, ["containers", "infrastructure"]),
        _observation("containers.security-posture", "containers", "컨테이너 보안 설정", "Container security posture", "privileged·host namespace·Docker 소켓·민감 bind·root·capability·읽기 전용 루트를 확인합니다.", "Tracks privileged mode, host namespaces, Docker socket, sensitive binds, root, capabilities, and read-only roots.", "current-state", cadence, current, ["containers", "reliability"]),
        _observation("containers.image-integrity", "containers", "컨테이너 이미지 무결성", "Container image integrity", "이미지 이름·태그·digest 출처, latest 사용과 digest 변경·드리프트를 확인합니다.", "Tracks image name, tag, digest source, latest-tag use, and digest change or drift.", "current-state", cadence, current, ["containers"]),
        _observation("containers.docker-events", "containers", "Docker 이벤트·수집 연속성", "Docker events and continuity", "생성·시작·종료·OOM·건강 이벤트와 커서 공백·재연결을 확인합니다.", "Tracks create, start, exit, OOM, and health events plus cursor gaps and reconnects.", "current-state", cadence, current, ["containers", "reliability"]),
        _observation("synthetic.http-tls", "synthetic", "외부 HTTP·TLS 합성 점검", "External HTTP and TLS probes", "DNS·권한·시간초과·TLS·HTTP 결과, 지연, 리다이렉트와 인증서 만료를 확인합니다.", "Tracks DNS, permission, timeout, TLS, HTTP, latency, redirects, and certificate expiry.", "current-state", SYNTHETIC_PROBE_INTERVAL_SECONDS, current, ["reliability", "network"]),
        _observation("incidents.resource-windows", "incidents", "자원 이상 구간", "Resource incident windows", "CPU·메모리·온도·부하·디스크·전력·트래픽 이상과 연관 표본을 누적합니다.", "Accumulates CPU, memory, temperature, load, disk, power, and traffic anomalies with correlated samples.", "accumulated-log", cadence, ["incident-events"], ["incidents"]),
        _observation("system.versions-firmware", "maintenance", "커널·부트로더·펌웨어 버전", "Kernel, bootloader, and firmware versions", "실행·설치 커널, 재부팅 필요 여부, 부트로더와 NVMe 펌웨어를 확인합니다.", "Tracks running and installed kernels, reboot need, bootloader, and NVMe firmware.", "current-state", cadence, current, ["maintenance", "reliability"]),
        _observation("maintenance.system-updates", "maintenance", "시스템 업데이트 작업", "System update operations", "업데이트 확인·적용 상태, 대상 패키지와 재부팅 필요 여부를 확인합니다.", "Tracks update check and apply state, affected packages, and reboot requirement.", "current-state", None, ["system-update-state"], ["maintenance"]),
        _observation("logs.semantic-events", "logs", "정규화 운영 이벤트", "Normalized operational events", "호스트·전력·신뢰성·권한 이벤트를 정해진 스키마로 누적합니다.", "Accumulates host, power, reliability, and privilege events under fixed schemas.", "accumulated-log", cadence, ["semantic-alert-events", "power-events", "reliability-events", "privilege-events"], ["logs", "reliability"]),
        _observation("logs.generic-events", "logs", "허용 소스 통합 로그", "Allow-listed generic logs", "허용된 journald·파일·컨테이너 로그를 정규화·제거 처리해 누적합니다.", "Accumulates normalized and redacted journald, file, and container logs from allow-listed sources.", "accumulated-log", cadence, ["generic-log-events"], ["logs"]),
        _observation("logs.source-health", "logs", "로그 소스 수집 건강", "Log-source collection health", "소스별 성공 시각, 실패 분류, 처리·탈락 건수를 확인합니다.", "Tracks source success time, failure class, admitted records, and drops.", "current-state", cadence, ["generic-log-source-state"], ["logs", "reliability"]),
        _observation("alerts.rule-evaluation", "alerts", "경보 규칙 평가", "Alert-rule evaluation", "모든 로드된 규칙의 최신 대상별 phase, 관찰 상태와 값을 확인합니다.", "Tracks the latest target phase, observation status, and value for every loaded rule.", "current-state", cadence, ["rule-evaluation-state"], ["reliability", "incidents"]),
        _observation("alerts.transitions-delivery", "alerts", "경보 전환·알림 전달", "Alert transitions and delivery", "경보 발생·해제, 억제·silence와 알림 전달 실패 신호를 확인합니다.", "Tracks firing, resolution, suppression, silence, and notification-delivery failure signals.", "mixed", cadence, ["rule-evaluation-state", "rule-alert-events"], ["reliability", "incidents", "logs"]),
        _observation("monitoring.self-health", "monitoring", "모니터링 자체 건강", "Monitoring self-health", "수집 지연, 큐, 저장 실패, 평가 지연, 저장소 사용률과 외부 하트비트 규칙을 확인합니다.", "Tracks ingestion lag, queues, write failures, evaluator delay, storage use, and external-heartbeat rules.", "mixed", cadence, ["rule-evaluation-state", "rule-alert-events", "generic-log-source-state"], ["reliability", "logs"]),
        _observation("infrastructure.change-ledger", "infrastructure", "인프라 작업·결정 이력", "Infrastructure work and decisions", "검증된 변경, 점검, 완화, 결정과 관련 증거를 현재 원장으로 확인합니다.", "Tracks verified changes, audits, mitigations, decisions, and related evidence in the current ledger.", "current-state", None, ["infrastructure-ledger"], ["infrastructure"]),
    ]


def _rule_domain_and_pages(rule: AlertRule) -> tuple[str, list[str]]:
    metric = rule.metric
    prefix = metric.split(".", 1)[0]
    if prefix in {"container", "docker"}:
        return "containers", ["containers"]
    if prefix in {"disk", "filesystem", "storage", "database"}:
        return "storage", ["storage", "reliability"]
    if prefix == "network":
        return "network", ["network", "reliability"]
    if prefix == "raspberry_pi" or "temperature" in metric or "power" in metric:
        return "power", ["power", "reliability"]
    if prefix in {"process"}:
        return "resources", ["resources", "reliability"]
    if prefix in {"synthetic", "proxy", "application", "service", "systemd"}:
        return "reliability", ["reliability"]
    if prefix == "monitor":
        return "monitoring", ["reliability", "logs"]
    if prefix == "agent" or prefix == "heartbeat":
        return "agent", ["reliability", "infrastructure"]
    if prefix == "host" and any(value in metric for value in ("cpu", "load", "memory", "swap")):
        return "resources", ["resources"]
    return "reliability", ["reliability"]


def _rule(
    rule: AlertRule,
    *,
    collection_interval_seconds: int,
    event_max_records: int,
) -> dict[str, Any]:
    domain, detail_pages = _rule_domain_and_pages(rule)
    labels = dict(rule.labels)
    public_labels = (
        {"scope": labels["scope"]}
        if labels.get("scope") in PUBLIC_RULE_SCOPES
        else {}
    )
    if FORBIDDEN_PUBLIC_TEXT.search(rule.description) or FORBIDDEN_PUBLIC_TEXT.search(rule.runbook):
        raise ValueError("monitoring catalog rule text contains forbidden material")
    return {
        "id": rule.rule_id,
        "domain": domain,
        "metric": rule.metric,
        "operator": rule.operator,
        "threshold": rule.threshold,
        "recoveryThreshold": rule.recovery_threshold,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "configuredEvaluationIntervalSeconds": rule.evaluation_interval_seconds,
        "effectiveEvaluationIntervalSeconds": collection_interval_seconds,
        "forSeconds": rule.for_seconds,
        "forSamples": rule.for_samples,
        "recoverySeconds": rule.recovery_seconds,
        "recoverySamples": rule.recovery_samples,
        "noDataPolicy": rule.no_data_policy,
        "noDataSeconds": rule.no_data_seconds,
        "noDataSamples": rule.no_data_samples,
        "parentRuleId": rule.parent_rule_id,
        "labels": public_labels,
        "description": rule.description,
        "runbook": rule.runbook,
        "stateEvidenceSourceId": "rule-evaluation-state",
        "eventEvidenceSourceId": "rule-alert-events",
        "eventRetention": {
            "maxRecords": event_max_records,
            "maxBytes": RULE_ALERT_MAX_BYTES,
        },
        "detailPages": detail_pages,
    }


def build_monitoring_catalog(
    *,
    now: dt.datetime,
    rule_pack_path: Path,
    collection_interval_seconds: int,
    retention_days: int,
    max_log_records: int,
    incident_retention_days: int,
    max_incident_records: int,
    generic_log_retention_days: int,
    generic_log_max_records: int,
    generic_log_max_file_bytes: int,
) -> dict[str, Any]:
    """Build one exact, serializable public catalog from resolved runtime config."""

    pack = load_rule_pack(rule_pack_path)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    generated_at = now.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    event_max_records = min(RULE_ALERT_MAX_RECORDS, max_log_records)
    sources = evidence_sources(
        collection_interval_seconds=collection_interval_seconds,
        retention_days=retention_days,
        max_log_records=max_log_records,
        incident_retention_days=incident_retention_days,
        max_incident_records=max_incident_records,
        generic_log_retention_days=generic_log_retention_days,
        generic_log_max_records=generic_log_max_records,
        generic_log_max_file_bytes=generic_log_max_file_bytes,
    )
    manifest = observations(collection_interval_seconds)
    source_ids = {source["id"] for source in sources}
    if len(source_ids) != len(sources):
        raise ValueError("monitoring catalog contains duplicate evidence source ids")
    if len({item["id"] for item in manifest}) != len(manifest):
        raise ValueError("monitoring catalog contains duplicate observation ids")
    for item in manifest:
        if not set(item["evidenceSourceIds"]).issubset(source_ids):
            raise ValueError("monitoring catalog observation references an unknown evidence source")
    rules = [
        _rule(
            rule,
            collection_interval_seconds=collection_interval_seconds,
            event_max_records=event_max_records,
        )
        for rule in pack.rules
    ]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": generated_at,
        "collectionIntervalSeconds": collection_interval_seconds,
        "rulePackVersion": pack.version,
        "evidenceSources": sources,
        "observations": manifest,
        "rules": rules,
    }
