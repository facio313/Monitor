import type { MonitoringEvidenceSource } from './api';
import type { DashboardPayload, MonitorLocale } from './types';

export interface EvidenceRecordSet {
  records: unknown[];
  limited: boolean;
  note: string;
}

const RECORD_LIMIT = 200;

function reducedIdentifier(value: string | null | undefined): string | null {
  if (!value) return null;
  return value.length > 12 ? `${value.slice(0, 12)}…` : value;
}

const PRIVATE_EVIDENCE_KEY = /(?:authorization|cookie|credential|password|passwd|secret|token|command|argv|environment|private|raw(?:path|line|value)|filePath|socketPath)/iu;
const REDUCED_IDENTIFIER_KEYS = new Set(['hostId', 'agentId', 'installationEpoch', 'bootId', 'instanceId']);
const PRIVATE_EVIDENCE_TEXT = /(?:^|[^A-Za-z0-9/])\/(?!\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*|-----BEGIN [^-]+ PRIVATE KEY-----|\b(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+|(?:https?|ssh):\/\/[^\s/@:]+:[^\s/@]+@|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/iu;

function logicalMountLabel(value: string): string {
  if (value === '/') return 'root-filesystem';
  const leaf = value.split('/').filter(Boolean).at(-1);
  return leaf && /^[A-Za-z0-9_.-]{1,64}$/u.test(leaf) ? `filesystem:${leaf}` : 'filesystem';
}

function safeEvidenceValue(value: unknown, key = '', depth = 0): unknown {
  if (PRIVATE_EVIDENCE_KEY.test(key) || depth > 12) return undefined;
  if (typeof value === 'string') {
    if (REDUCED_IDENTIFIER_KEYS.has(key)) return reducedIdentifier(value);
    if (key === 'mount') return logicalMountLabel(value);
    return PRIVATE_EVIDENCE_TEXT.test(value) ? '[redacted]' : value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, RECORD_LIMIT)
      .map((item) => safeEvidenceValue(item, '', depth + 1))
      .filter((item) => item !== undefined);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .slice(0, 256)
      .map(([itemKey, item]) => [itemKey, safeEvidenceValue(item, itemKey, depth + 1)] as const)
      .filter(([, item]) => item !== undefined));
  }
  return value;
}

function bounded(records: unknown[], note: string): EvidenceRecordSet {
  const safeRecords = records
    .map((record) => safeEvidenceValue(record))
    .filter((record) => record !== undefined);
  return {
    records: safeRecords.slice(0, RECORD_LIMIT),
    limited: safeRecords.length > RECORD_LIMIT,
    note,
  };
}

function newestFirst<T extends { timestamp?: string; observedAt?: string; occurredAt?: string }>(records: T[]): T[] {
  return [...records].sort((left, right) => {
    const leftAt = left.timestamp ?? left.observedAt ?? left.occurredAt ?? '';
    const rightAt = right.timestamp ?? right.observedAt ?? right.occurredAt ?? '';
    return rightAt.localeCompare(leftAt);
  });
}

function note(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

export function evidenceRecords(
  source: Pick<MonitoringEvidenceSource, 'id'>,
  data: DashboardPayload | null,
  locale: MonitorLocale,
): EvidenceRecordSet {
  if (!data) return bounded([], note(locale, '이 페이지에서 원격 측정 스냅샷을 불러오지 않았습니다.', 'This page has not loaded a telemetry snapshot.'));

  switch (source.id) {
    case 'current-snapshot':
      return bounded([{
        generatedAt: data.generatedAt,
        latestObservedAt: data.latestObservedAt,
        stale: data.stale,
        agent: data.agent,
        host: data.host,
        latest: data.latest,
        reliability: data.reliability,
        containerCollection: data.containerCollection,
        dockerEventCollection: data.dockerEventCollection ?? null,
        dockerEvents: data.dockerEvents ?? [],
        syntheticProbeCollection: data.syntheticProbeCollection ?? null,
        disks: data.disks,
        containers: data.containers,
        currentTraffic: data.currentTraffic,
        syntheticProbes: data.syntheticProbes ?? [],
        linux: data.linux,
        system: data.system,
      }], note(locale, 'current.json을 그대로 내려받는 기능이 아니라, API가 검증하고 식별자·민감 필드를 한 번 더 축약한 현재 상태입니다.', 'This is the API-validated reduced current state with a second reduction of identifiers and sensitive fields, not a raw current.json download.'));
    case 'telemetry-history':
      return bounded([...data.series].reverse(), note(locale, '선택한 기간에서 API가 검증하고 차트용으로 제한한 정규화 표본입니다.', 'Normalized samples validated and bounded by the API for the selected range.'));
    case 'semantic-alert-events':
      return bounded(newestFirst(data.alerts), note(locale, 'alerts.jsonl에서 선택 기간에 해당하는 검증된 의미 이벤트입니다.', 'Validated semantic events from alerts.jsonl for the selected range.'));
    case 'power-events':
      return bounded(newestFirst(data.powerEvents), note(locale, '원본 커널 메시지가 아닌 정규화된 전원 이벤트입니다.', 'Normalized power events, not raw kernel messages.'));
    case 'privilege-events':
      return bounded(newestFirst(data.privilegeEvents), note(locale, '명령 인자와 민감 내용을 제거한 권한 이벤트입니다.', 'Privilege events with command arguments and sensitive content removed.'));
    case 'reliability-events':
      return bounded(newestFirst(data.reliabilityEvents), note(locale, '부팅·링크·커널·NVMe 사건의 고정 스키마 기록입니다.', 'Fixed-schema boot, link, kernel, and NVMe records.'));
    case 'incident-events':
      return bounded(newestFirst(data.incidents), note(locale, '선택 기간의 정규화된 사건과 복구 후속 표본입니다.', 'Normalized incidents and recovery follow-up samples in the selected range.'));
    case 'rule-evaluation-state':
      return bounded(Object.values(data.ruleEvaluation.states).sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.target.localeCompare(right.target)), note(locale, '규칙별·대상별 최신 평가 상태입니다.', 'The latest evaluation state for each rule and target.'));
    case 'rule-alert-events':
      return bounded(newestFirst(data.ruleAlerts.events), note(locale, '발화·해제 전환만 저장한 정규화 규칙 이벤트입니다.', 'Normalized rule events containing only firing and resolution transitions.'));
    case 'generic-log-source-state':
      return bounded([], note(locale, '일반 로그 페이지에서 소스별 최신 상태와 처리·탈락 건수를 확인할 수 있습니다.', 'The Logs page shows each source status and admitted or dropped counts.'));
    case 'generic-log-events':
      return bounded([], note(locale, '일반 로그는 전용 검색 화면에서 sourceId로 안전하게 조회합니다.', 'Generic logs are queried safely by sourceId in the dedicated explorer.'));
    case 'system-update-state':
      return bounded([], note(locale, '버전·업데이트 상세에서 엄격히 검증된 최신 상태를 확인합니다.', 'The Versions & updates page shows the strictly validated latest state.'));
    case 'infrastructure-ledger':
      return bounded([], note(locale, '인프라 원장 상세에서 권한에 따라 검증된 공개 원장을 확인합니다.', 'The Infrastructure ledger page exposes the validated public ledger according to role.'));
    case 'agent-inventory':
      return bounded([], note(locale, '원격 에이전트 인벤토리는 관리 API의 축약 상태이며 원본 제어 상태는 공개하지 않습니다.', 'Remote-agent inventory is a reduced management API state; raw control state is never exposed.'));
    default:
      return bounded([], note(locale, '이 논리 기록은 전용 상세 화면에서 확인합니다.', 'This logical evidence stream is available from its dedicated detail view.'));
  }
}
