import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  ApiError,
  getGenericLogs,
  type GenericLogPage,
  type GenericLogSourceStatus,
  type MonitoringCatalog,
  type MonitoringEvidenceSource,
  type MonitoringObservation,
  type MonitoringRuleDefinition,
} from '../api';
import { localized, monitorPathForPage } from '../dashboard-model';
import { useMonitoringCatalog } from '../hooks/useMonitoringCatalog';
import type {
  DashboardPayload,
  MonitorDetailPage,
  MonitorLocale,
  RuleEvaluationPhase,
  RuleEvaluationState,
  TimeRange,
} from '../types';
import { formatBytes, formatDateTime, safeText } from '../utils';
import { EvidenceRecordDialog } from './EvidenceRecordDialog';
import { Icon } from './Icon';
import { Pagination, paginateItems, usePagination } from './Pagination';
import './monitoring-coverage.css';
import './monitoring-evidence.css';

type CoverageKind = 'observation' | 'check' | 'evidence';
type CoverageTone = 'ok' | 'caution' | 'danger' | 'neutral';

interface CoverageStatus {
  tone: CoverageTone;
  label: string;
  detail: string;
}

export interface CoverageRow {
  id: string;
  domain: string;
  kind: CoverageKind;
  label: string;
  description: string;
  evidenceMode: string;
  cadenceSeconds: number | null;
  sourceIds: string[];
  detailPages: string[];
  status: CoverageStatus;
  observation?: MonitoringObservation;
  rule?: MonitoringRuleDefinition;
  source?: MonitoringEvidenceSource;
  genericSource?: GenericLogSourceStatus;
  states?: RuleEvaluationState[];
}

const PHASE_ORDER: Record<RuleEvaluationPhase, number> = {
  collection_error: 10,
  permission_denied: 9,
  firing: 8,
  pending: 5,
  recovering: 4,
  no_data: 3,
  unsupported: 2,
  inactive: 1,
};

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function worstRulePhase(states: RuleEvaluationState[]): RuleEvaluationPhase | null {
  return states.reduce<RuleEvaluationPhase | null>((worst, state) => (
    worst === null || PHASE_ORDER[state.phase] > PHASE_ORDER[worst] ? state.phase : worst
  ), null);
}

function ruleStatus(
  rule: MonitoringRuleDefinition,
  states: RuleEvaluationState[],
  data: DashboardPayload,
  locale: MonitorLocale,
): CoverageStatus {
  if (!rule.enabled) return { tone: 'neutral', label: t(locale, '비활성', 'Disabled'), detail: t(locale, '규칙 팩에서 비활성화됨', 'Disabled in the loaded rule pack') };
  if (data.stale || data.ruleEvaluation.status !== 'ok') {
    return worstStatus([
      snapshotStatus(data, locale),
      collectionStatus(data.ruleEvaluation.status, locale),
    ]);
  }
  const phase = worstRulePhase(states);
  if (phase === null) return { tone: 'caution', label: t(locale, '평가 대상 없음', 'No target'), detail: t(locale, '현재 평가 상태에 이 규칙의 대상이 없습니다.', 'No current evaluation target exists for this rule.') };
  const count = states.filter((state) => state.phase === phase).length;
  const details = t(locale, `대상 ${states.length}개 · ${phase} ${count}개`, `${states.length} targets · ${count} ${phase}`);
  if (phase === 'firing') return { tone: rule.severity === 'critical' ? 'danger' : 'caution', label: t(locale, '발화 중', 'Firing'), detail: details };
  if (phase === 'collection_error' || phase === 'permission_denied') return { tone: 'danger', label: phase === 'collection_error' ? t(locale, '수집 오류', 'Collection error') : t(locale, '권한 거부', 'Permission denied'), detail: details };
  if (phase === 'pending') return { tone: 'caution', label: t(locale, '지속 확인 중', 'Pending'), detail: details };
  if (phase === 'recovering') return { tone: 'caution', label: t(locale, '복구 확인 중', 'Recovering'), detail: details };
  if (phase === 'no_data') return { tone: 'caution', label: t(locale, '데이터 없음', 'No data'), detail: details };
  if (phase === 'unsupported') return { tone: 'neutral', label: t(locale, '지원 안 됨', 'Unsupported'), detail: details };
  return { tone: 'ok', label: t(locale, '정상', 'Nominal'), detail: details };
}

function collectionStatus(status: string, locale: MonitorLocale): CoverageStatus {
  if (['fresh', 'healthy', 'ok', 'current', 'supported'].includes(status)) return { tone: 'ok', label: t(locale, '정상 수집', 'Collected'), detail: status };
  if (['unsupported', 'no_data'].includes(status)) return { tone: 'neutral', label: status === 'unsupported' ? t(locale, '지원 안 됨', 'Unsupported') : t(locale, '기록 없음', 'No records'), detail: status };
  if (['stale', 'last-known', 'delayed', 'truncated', 'degraded', 'partial', 'warmup', 'gap', 'unknown', 'inactive', 'maintenance'].includes(status)) return { tone: 'caution', label: t(locale, '확인 필요', 'Needs review'), detail: status };
  return { tone: 'danger', label: t(locale, '수집 오류', 'Collection failure'), detail: status };
}

const TONE_ORDER: Record<CoverageTone, number> = { danger: 4, caution: 3, neutral: 2, ok: 1 };

function worstStatus(statuses: CoverageStatus[]): CoverageStatus {
  return statuses.reduce((worst, status) => (
    TONE_ORDER[status.tone] > TONE_ORDER[worst.tone] ? status : worst
  ));
}

function snapshotStatus(data: DashboardPayload, locale: MonitorLocale, requireSample = false): CoverageStatus {
  if (data.stale) return { tone: 'caution', label: t(locale, '마지막 상태', 'Last known'), detail: data.latestObservedAt ?? data.generatedAt };
  if (requireSample && !data.latest) return collectionStatus('no_data', locale);
  return { tone: 'ok', label: t(locale, '정상 수집', 'Collected'), detail: data.latestObservedAt ?? data.generatedAt };
}

function currentSubsystemStatus(data: DashboardPayload, status: string, locale: MonitorLocale): CoverageStatus {
  return worstStatus([snapshotStatus(data, locale), collectionStatus(status, locale)]);
}

function eventReadStatus(data: DashboardPayload, locale: MonitorLocale): CoverageStatus {
  return data.stale
    ? snapshotStatus(data, locale)
    : {
        tone: 'neutral',
        label: t(locale, '독립 건강 신호 없음', 'No independent health signal'),
        detail: t(locale, '0건과 파일 읽기 실패를 현재 API가 구분해 보고하지 않습니다.', 'The current API does not distinguish an empty stream from a read failure.'),
      };
}

function observationStatus(observation: MonitoringObservation, data: DashboardPayload, genericPage: GenericLogPage | null, locale: MonitorLocale): CoverageStatus {
  if (observation.id === 'agent.identity-heartbeat') return currentSubsystemStatus(data, data.agent.status, locale);
  if (observation.id === 'agent.remote-inventory') return { tone: 'neutral', label: t(locale, '관리 API', 'Management API'), detail: t(locale, '관리자용 축약 상태', 'Reduced administrator state') };
  if (observation.id === 'containers.docker-events') return currentSubsystemStatus(data, data.dockerEventCollection?.status ?? 'unavailable', locale);
  if (observation.id.startsWith('containers.')) return currentSubsystemStatus(data, data.containerCollection.status, locale);
  if (observation.id === 'synthetic.http-tls') {
    const collection = data.syntheticProbeCollection?.status ?? 'unavailable';
    const failures = (data.syntheticProbes ?? []).filter((probe) => probe.status !== 'ok');
    if (collection === 'fresh' && failures.length) return worstStatus([snapshotStatus(data, locale), { tone: 'danger', label: t(locale, '검사 실패', 'Probe failed'), detail: t(locale, `${failures.length}개 결과 실패`, `${failures.length} failed results`) }]);
    return currentSubsystemStatus(data, collection, locale);
  }
  if (observation.id === 'logs.generic-events' || observation.id === 'logs.source-health') return collectionStatus(genericPage?.collection.status ?? 'unavailable', locale);
  if (observation.id === 'alerts.rule-evaluation') return currentSubsystemStatus(data, data.ruleEvaluation.status, locale);
  if (observation.id === 'alerts.transitions-delivery') return worstStatus([
    currentSubsystemStatus(data, data.ruleEvaluation.status, locale),
    collectionStatus(data.ruleAlerts.status, locale),
  ]);
  if (observation.id === 'monitoring.self-health') return worstStatus([
    currentSubsystemStatus(data, data.ruleEvaluation.status, locale),
    collectionStatus(data.ruleAlerts.status, locale),
    collectionStatus(genericPage?.collection.status ?? 'unavailable', locale),
  ]);
  if (observation.id === 'maintenance.system-updates' || observation.id === 'infrastructure.change-ledger') return { tone: 'neutral', label: t(locale, '전용 상태', 'Dedicated state'), detail: t(locale, '전용 상세 API에서 확인', 'Available from its dedicated detail API') };
  if (observation.id === 'resources.process-capacity') return currentSubsystemStatus(data, data.linux.resources.status, locale);
  if (observation.id === 'resources.process-usage') return data.stale
    ? snapshotStatus(data, locale)
    : eventReadStatus(data, locale);
  if (observation.id === 'incidents.resource-windows' || observation.id === 'logs.semantic-events') return eventReadStatus(data, locale);
  if (observation.id === 'storage.block-io' || observation.id === 'storage.device-health') return currentSubsystemStatus(data, data.linux.storage.status, locale);
  if (observation.id === 'network.tcp-sockets') return worstStatus([
        snapshotStatus(data, locale),
        collectionStatus(data.linux.network.status, locale),
        collectionStatus(data.linux.network.tcp.status, locale),
      ]);
  if (observation.id === 'reliability.systemd-units') return currentSubsystemStatus(data, data.linux.reliability.systemd.status, locale);
  if (observation.id === 'reliability.clock-time-sync') return worstStatus([
        snapshotStatus(data, locale),
        collectionStatus(data.linux.reliability.clock.status, locale),
        collectionStatus(data.linux.reliability.clock.timeSync.status, locale),
      ]);
  if (observation.id === 'power.thermal-cooling') return currentSubsystemStatus(data, data.linux.power.status, locale);
  if (observation.id === 'power.platform-state') return currentSubsystemStatus(data, data.linux.power.raspberryPi.detected ? data.linux.power.raspberryPi.status : data.linux.power.status, locale);
  if (observation.id === 'resources.cpu-load-pressure' || observation.id === 'resources.memory-swap-pressure' || observation.id === 'network.interfaces-quality') return snapshotStatus(data, locale, true);
  return snapshotStatus(data, locale);
}

function evidenceStatus(source: MonitoringEvidenceSource, data: DashboardPayload, genericPage: GenericLogPage | null, locale: MonitorLocale): CoverageStatus {
  if (source.id === 'generic-log-events' || source.id === 'generic-log-source-state') return collectionStatus(genericPage?.collection.status ?? 'unavailable', locale);
  if (source.id === 'rule-evaluation-state') return currentSubsystemStatus(data, data.ruleEvaluation.status, locale);
  if (source.id === 'rule-alert-events') return currentSubsystemStatus(data, data.ruleAlerts.status, locale);
  if (source.id === 'system-update-state' || source.id === 'infrastructure-ledger' || source.id === 'agent-inventory') return { tone: 'neutral', label: t(locale, '전용 API', 'Dedicated API'), detail: t(locale, '변경·작업 시 갱신', 'Updated on change or operation') };
  if (source.id === 'current-snapshot') return data.stale
    ? { tone: 'caution', label: t(locale, '마지막 상태', 'Last known'), detail: data.latestObservedAt ?? data.generatedAt }
    : { tone: 'ok', label: t(locale, '최신', 'Fresh'), detail: data.latestObservedAt ?? data.generatedAt };
  return eventReadStatus(data, locale);
}

function genericSourceStatus(source: GenericLogSourceStatus, locale: MonitorLocale): CoverageStatus {
  const status = collectionStatus(source.status, locale);
  return { ...status, detail: t(locale, `허용 ${source.admittedEvents} · 탈락 ${source.droppedLines}`, `${source.admittedEvents} admitted · ${source.droppedLines} dropped`) };
}

export function buildCoverageRows(
  catalog: MonitoringCatalog,
  data: DashboardPayload,
  genericPage: GenericLogPage | null,
  locale: MonitorLocale,
): CoverageRow[] {
  const statesByRule = new Map<string, RuleEvaluationState[]>();
  for (const state of Object.values(data.ruleEvaluation.states)) {
    const states = statesByRule.get(state.ruleId) ?? [];
    states.push(state);
    statesByRule.set(state.ruleId, states);
  }
  const observations = catalog.observations.map<CoverageRow>((observation) => ({
    id: `observation:${observation.id}`,
    domain: observation.domain,
    kind: 'observation',
    label: observation.displayName[locale],
    description: observation.description[locale],
    evidenceMode: observation.evidenceMode,
    cadenceSeconds: observation.cadenceSeconds,
    sourceIds: observation.evidenceSourceIds,
    detailPages: observation.detailPages,
    status: observationStatus(observation, data, genericPage, locale),
    observation,
  }));
  const rules = catalog.rules.map<CoverageRow>((rule) => {
    const states = statesByRule.get(rule.id) ?? [];
    return {
      id: `check:${rule.id}`,
      domain: rule.domain,
      kind: 'check',
      label: rule.id,
      description: rule.description,
      evidenceMode: 'current-and-event-log',
      cadenceSeconds: rule.effectiveEvaluationIntervalSeconds,
      sourceIds: [rule.stateEvidenceSourceId, rule.eventEvidenceSourceId],
      detailPages: rule.detailPages,
      status: ruleStatus(rule, states, data, locale),
      rule,
      states,
    };
  });
  const sources = catalog.evidenceSources.map<CoverageRow>((source) => ({
    id: `evidence:${source.id}`,
    domain: source.detailPages[0] ?? 'monitoring',
    kind: 'evidence',
    label: source.displayName[locale],
    description: source.description[locale],
    evidenceMode: source.evidenceMode,
    cadenceSeconds: source.cadenceSeconds,
    sourceIds: [source.id],
    detailPages: source.detailPages,
    status: evidenceStatus(source, data, genericPage, locale),
    source,
  }));
  const generic = (genericPage?.collection.sources ?? []).map<CoverageRow>((source) => {
    const evidence = catalog.evidenceSources.find((item) => item.id === 'generic-log-events');
    return {
      id: `generic-source:${source.sourceId}`,
      domain: 'logs',
      kind: 'evidence',
      label: source.sourceId,
      description: t(locale, `${source.sourceKind} 허용 소스의 정규화·민감정보 제거 기록`, `Normalized and redacted records from an allow-listed ${source.sourceKind} source`),
      evidenceMode: 'accumulated-log',
      cadenceSeconds: evidence?.cadenceSeconds ?? catalog.collectionIntervalSeconds,
      sourceIds: ['generic-log-events'],
      detailPages: ['logs'],
      status: genericSourceStatus(source, locale),
      source: evidence,
      genericSource: source,
    };
  });
  return [...observations, ...rules, ...sources, ...generic];
}

function domainLabel(domain: string, locale: MonitorLocale): string {
  const labels: Record<string, [string, string]> = {
    agent: ['에이전트', 'Agent'], host: ['호스트', 'Host'], resources: ['자원', 'Resources'], storage: ['저장장치', 'Storage'], network: ['네트워크', 'Network'], reliability: ['신뢰성', 'Reliability'], power: ['전원', 'Power'], containers: ['서비스', 'Services'], synthetic: ['합성 검사', 'Synthetic'], incidents: ['사건', 'Incidents'], maintenance: ['유지보수', 'Maintenance'], logs: ['로그', 'Logs'], alerts: ['경보', 'Alerts'], monitoring: ['Monitor', 'Monitor'], infrastructure: ['인프라', 'Infrastructure'],
  };
  const label = labels[domain];
  return label ? t(locale, ...label) : safeText(domain, t(locale, '기타', 'Other'), 32);
}

function kindLabel(kind: CoverageKind, locale: MonitorLocale): string {
  if (kind === 'observation') return t(locale, '관찰', 'Observation');
  if (kind === 'check') return t(locale, '규칙 검사', 'Rule check');
  return t(locale, '저장 기록', 'Evidence');
}

function evidenceLabel(mode: string, locale: MonitorLocale): string {
  if (mode === 'current-state') return t(locale, '현재 상태', 'Current state');
  if (mode === 'accumulated-log') return t(locale, '누적 로그', 'Accumulated log');
  if (mode === 'current-and-history') return t(locale, '현재 + 시계열', 'Current + history');
  if (mode.includes('event') || mode === 'mixed') return t(locale, '현재 + 이벤트', 'Current + events');
  return safeText(mode.replaceAll('-', ' '), t(locale, '혼합 근거', 'Mixed evidence'), 40);
}

function cadenceLabel(seconds: number | null, locale: MonitorLocale): string {
  if (seconds === null) return t(locale, '변경·작업 시', 'On change');
  if (seconds < 60) return t(locale, `${seconds}초`, `${seconds}s`);
  if (seconds % 3600 === 0) return t(locale, `${seconds / 3600}시간`, `${seconds / 3600}h`);
  return t(locale, `${seconds / 60}분`, `${seconds / 60}m`);
}

function retention(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  const limits: string[] = [];
  if (source.retention.maxAgeDays !== null) limits.push(t(locale, `${source.retention.maxAgeDays}일`, `${source.retention.maxAgeDays}d`));
  if (source.retention.maxRecords !== null) limits.push(`${source.retention.maxRecords.toLocaleString()} ${t(locale, '건', 'records')}`);
  if (source.retention.maxBytes !== null) limits.push(formatBytes(source.retention.maxBytes));
  return limits.length ? limits.join(' · ') : t(locale, '외부 정책', 'External policy');
}

function prune(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  const labels: Record<MonitoringEvidenceSource['retention']['pruneCadence'], [string, string]> = {
    'replace-on-collection': ['매 수집 때 교체', 'replace each collection'],
    'every-collection': ['매 수집 때 정리', 'prune each collection'],
    'on-incident-write-or-daily': ['사건 저장 시·하루 1회', 'on incident write or daily'],
    'every-rule-evaluation': ['매 규칙 평가 때', 'each rule evaluation'],
    'every-generic-collection': ['매 일반 로그 수집 때', 'each generic-log collection'],
    'replace-on-generic-collection': ['매 일반 로그 수집 때 교체', 'replace each generic-log collection'],
    'replace-on-change': ['변경 시 교체', 'replace on change'],
    'external-no-auto-prune': ['외부 관리·자동 삭제 없음', 'external; no auto-prune'],
  };
  return t(locale, ...labels[source.retention.pruneCadence]);
}

function monitorDetailPage(value: string): MonitorDetailPage | null {
  const values: MonitorDetailPage[] = ['coverage', 'resources', 'network', 'storage', 'containers', 'reliability', 'maintenance', 'infrastructure', 'power', 'incidents', 'logs'];
  return values.includes(value as MonitorDetailPage) ? value as MonitorDetailPage : null;
}

function sourceLogHref(range: TimeRange, sourceId?: string): string {
  const search = new URLSearchParams({ range });
  if (sourceId) search.set('sourceId', sourceId);
  return `${monitorPathForPage('logs')}?${search.toString()}`;
}

function RowDetail({ row, sourceMap, locale, range, onOpenSource }: {
  row: CoverageRow;
  sourceMap: Map<string, MonitoringEvidenceSource>;
  locale: MonitorLocale;
  range: TimeRange;
  onOpenSource: (source: MonitoringEvidenceSource) => void;
}) {
  return <div className="coverage-row-detail">
    <p>{row.description}</p>
    {row.rule && <div className="coverage-rule-contract"><dl><div><dt>{t(locale, '지표', 'Metric')}</dt><dd><code>{row.rule.metric}</code></dd></div><div><dt>{t(locale, '발화 조건', 'Firing')}</dt><dd>{row.rule.operator} {row.rule.threshold} · {row.rule.forSamples} samples / {row.rule.forSeconds}s</dd></div><div><dt>{t(locale, '복구 조건', 'Recovery')}</dt><dd>{row.rule.recoveryThreshold} · {row.rule.recoverySamples} samples / {row.rule.recoverySeconds}s</dd></div><div><dt>No data</dt><dd>{row.rule.noDataPolicy} · {row.rule.noDataSamples} samples / {row.rule.noDataSeconds}s</dd></div><div><dt>{t(locale, '상위 규칙', 'Parent')}</dt><dd>{row.rule.parentRuleId ?? '—'}</dd></div><div><dt>{t(locale, '규칙 팩 주기', 'Configured interval')}</dt><dd>{cadenceLabel(row.rule.configuredEvaluationIntervalSeconds, locale)}</dd></div></dl><p><strong>{t(locale, '조치 안내', 'Runbook')}</strong>{row.rule.runbook}</p></div>}
    {row.states?.length ? <details className="coverage-target-states"><summary>{t(locale, `대상별 최신 평가 ${row.states.length}개`, `${row.states.length} target evaluations`)}</summary><div className="coverage-state-table-wrap"><table><thead><tr><th>{t(locale, '대상', 'Target')}</th><th>Phase</th><th>{t(locale, '관측값', 'Value')}</th><th>{t(locale, '관측 상태', 'Observation')}</th><th>{t(locale, '평가 시각', 'Evaluated')}</th></tr></thead><tbody>{row.states.slice(0, 100).map((state) => <tr key={`${state.ruleId}:${state.target}`}><td><code>{safeText(state.target, '—', 128)}</code></td><td>{state.phase}</td><td>{state.lastValue ?? '—'}</td><td>{state.observationStatus}</td><td>{formatDateTime(state.lastEvaluatedAt, locale)}</td></tr>)}</tbody></table></div>{row.states.length > 100 && <p>{t(locale, '화면 안전 한도로 첫 100개 대상만 표시합니다.', 'Only the first 100 targets are shown in this bounded view.')}</p>}</details> : null}
    <div className="coverage-evidence-links"><strong>{t(locale, '판단 근거·저장 기록', 'Evidence and stored records')}</strong><div>{row.sourceIds.map((sourceId) => {
      const source = sourceMap.get(sourceId);
      if (!source) return <span key={sourceId}><code>{sourceId}</code></span>;
      const generic = source.id === 'generic-log-events' || source.id === 'generic-log-source-state';
      return generic ? <a key={sourceId} href={sourceLogHref(range, row.genericSource?.sourceId)}><code>{source.artifactLabel}</code><Icon name="chevron" size={13} /></a> : <button key={sourceId} type="button" onClick={() => onOpenSource(source)}><code>{source.artifactLabel}</code><Icon name="chevron" size={13} /></button>;
    })}</div></div>
  </div>;
}

export function MonitoringCoverage({ data, range, locale, onUnauthorized }: {
  data: DashboardPayload;
  range: TimeRange;
  locale: MonitorLocale;
  onUnauthorized: () => void;
}) {
  const telemetryRefreshKey = data.latestObservedAt ?? data.generatedAt;
  const { catalog, error, loading, refresh } = useMonitoringCatalog(onUnauthorized, telemetryRefreshKey);
  const [genericPage, setGenericPage] = useState<GenericLogPage | null>(null);
  const [genericError, setGenericError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [domain, setDomain] = useState('all');
  const [kind, setKind] = useState<'all' | CoverageKind>('all');
  const [basis, setBasis] = useState('all');
  const [tone, setTone] = useState<'all' | CoverageTone>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [selectedSource, setSelectedSource] = useState<MonitoringEvidenceSource | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getGenericLogs({ limit: 1 }, controller.signal)
      .then((result) => { setGenericPage(result); setGenericError(null); })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === 'AbortError') return;
        if (reason instanceof ApiError && reason.status === 401) { onUnauthorized(); return; }
        setGenericPage(null);
        setGenericError(reason instanceof Error ? reason.message : 'Generic log state is unavailable.');
      });
    return () => controller.abort();
  }, [onUnauthorized, telemetryRefreshKey]);

  const rows = useMemo(() => catalog ? buildCoverageRows(catalog, data, genericPage, locale) : [], [catalog, data, genericPage, locale]);
  const domains = useMemo(() => [...new Set(rows.map((row) => row.domain))].sort(), [rows]);
  const normalizedQuery = query.trim().toLocaleLowerCase(locale === 'ko' ? 'ko-KR' : 'en-US');
  const filtered = useMemo(() => rows.filter((row) => {
    if (domain !== 'all' && row.domain !== domain) return false;
    if (kind !== 'all' && row.kind !== kind) return false;
    if (tone !== 'all' && row.status.tone !== tone) return false;
    if (basis === 'current' && row.evidenceMode !== 'current-state') return false;
    if (basis === 'log' && row.evidenceMode !== 'accumulated-log') return false;
    if (basis === 'mixed' && (row.evidenceMode === 'current-state' || row.evidenceMode === 'accumulated-log')) return false;
    if (!normalizedQuery) return true;
    return [row.label, row.description, row.domain, row.rule?.metric ?? '', row.source?.artifactLabel ?? '', row.genericSource?.sourceId ?? ''].join(' ').toLocaleLowerCase(locale === 'ko' ? 'ko-KR' : 'en-US').includes(normalizedQuery);
  }), [basis, domain, kind, locale, normalizedQuery, rows, tone]);
  const resetKey = `${query}\u001f${domain}\u001f${kind}\u001f${basis}\u001f${tone}\u001f${filtered.length}`;
  const pagination = usePagination({ totalItems: filtered.length, pageSize: 20, resetKey });
  const visible = paginateItems(filtered, pagination);
  const sourceMap = useMemo(() => new Map(catalog?.evidenceSources.map((source) => [source.id, source]) ?? []), [catalog]);
  const counts = {
    observation: rows.filter((row) => row.kind === 'observation').length,
    check: rows.filter((row) => row.kind === 'check').length,
    evidence: rows.filter((row) => row.kind === 'evidence').length,
    danger: rows.filter((row) => row.status.tone === 'danger').length,
    caution: rows.filter((row) => row.status.tone === 'caution').length,
  };

  if (loading && !catalog) return <div className="coverage-state"><Icon name="refresh" size={24} className="spin" /><strong>{t(locale, '관찰·검사 계약을 불러오는 중', 'Loading the monitoring contract')}</strong></div>;
  if (error && !catalog) return <div className="coverage-state coverage-state-error"><Icon name="alert" size={24} /><strong>{t(locale, '관찰·검사 목록을 불러오지 못했습니다.', 'The monitoring catalog could not be loaded.')}</strong><span>{error}</span><button type="button" onClick={refresh}>{t(locale, '다시 시도', 'Retry')}</button></div>;
  if (!catalog) return null;
  const catalogGeneratedMs = Date.parse(catalog.generatedAt);
  const latestTelemetryMs = Date.parse(data.latestObservedAt ?? data.generatedAt);
  const catalogLagSeconds = (latestTelemetryMs - catalogGeneratedMs) / 1_000;
  const allowedLagSeconds = Math.max(30, catalog.collectionIntervalSeconds * 0.75);
  const catalogTimeMismatch = !Number.isFinite(catalogLagSeconds)
    || catalogLagSeconds > allowedLagSeconds
    || catalogLagSeconds < -Math.max(300, catalog.collectionIntervalSeconds * 2);
  const catalogRulePackMismatch = data.ruleEvaluation.rulePackVersion !== null
    && data.ruleEvaluation.rulePackVersion !== catalog.rulePackVersion;
  const catalogCurrent = !catalogTimeMismatch && !catalogRulePackMismatch;

  return (
    <div className="monitoring-coverage">
      <section className="coverage-intro">
        <div><span>{catalogCurrent ? t(locale, '현재 운영 설정에서 생성', 'GENERATED FROM CURRENT RUNTIME SETTINGS') : t(locale, '마지막 검증된 운영 계약', 'LAST VERIFIED RUNTIME CONTRACT')}</span><h2>{t(locale, 'Monitor가 무엇을 보고 어떻게 보관하는지', 'What Monitor observes and how it is retained')}</h2><p>{t(locale, '관찰 영역, 모든 로드된 규칙, 논리적 저장 파일, 허용 로그 소스를 한 표에서 확인합니다. 원본 경로·비밀·명령 인자는 공개하지 않습니다.', 'This table combines observation families, every loaded rule, logical evidence files, and allow-listed log sources. Raw paths, secrets, and command arguments are never exposed.')}</p></div>
        <dl><div><dt>{t(locale, '관찰', 'Observations')}</dt><dd>{counts.observation}</dd></div><div><dt>{t(locale, '규칙 검사', 'Rule checks')}</dt><dd>{counts.check}</dd></div><div><dt>{t(locale, '저장 기록', 'Evidence')}</dt><dd>{counts.evidence}</dd></div><div className="summary-danger"><dt>{t(locale, '위험', 'Danger')}</dt><dd>{counts.danger}</dd></div><div className="summary-caution"><dt>{t(locale, '주의', 'Caution')}</dt><dd>{counts.caution}</dd></div></dl>
      </section>
      {!catalogCurrent && <div className="coverage-notice coverage-catalog-warning" role="alert"><Icon name="alert" size={16} /><span>{t(locale, '카탈로그 시각 또는 규칙 팩이 최신 원격 측정과 일치하지 않습니다. 아래 목록은 마지막 검증본이며 현재 설정으로 단정하지 않습니다.', 'The catalog timestamp or rule pack does not match current telemetry. The table is the last verified contract and is not presented as current configuration.')}</span></div>}
      {genericError && <div className="coverage-notice"><Icon name="info" size={16} /><span>{t(locale, '일반 로그 소스 상태만 불러오지 못했습니다.', 'Only generic-log source status could not be loaded.')} {genericError}</span></div>}
      <section className="coverage-filters" aria-label={t(locale, '관찰·검사 필터', 'Monitoring catalog filters')}>
        <label className="coverage-search"><span>{t(locale, '검색', 'Search')}</span><input value={query} onChange={(event) => setQuery(event.target.value.slice(0, 128))} placeholder={t(locale, '항목, 지표, 파일명 검색', 'Search item, metric, or file label')} /></label>
        <label><span>{t(locale, '영역', 'Domain')}</span><select value={domain} onChange={(event) => setDomain(event.target.value)}><option value="all">{t(locale, '전체 영역', 'All domains')}</option>{domains.map((value) => <option key={value} value={value}>{domainLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '종류', 'Kind')}</span><select value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}><option value="all">{t(locale, '전체 종류', 'All kinds')}</option><option value="observation">{t(locale, '관찰', 'Observation')}</option><option value="check">{t(locale, '규칙 검사', 'Rule check')}</option><option value="evidence">{t(locale, '저장 기록', 'Evidence')}</option></select></label>
        <label><span>{t(locale, '판단 근거', 'Evidence basis')}</span><select value={basis} onChange={(event) => setBasis(event.target.value)}><option value="all">{t(locale, '전체 방식', 'All modes')}</option><option value="current">{t(locale, '현재 상태', 'Current state')}</option><option value="log">{t(locale, '누적 로그', 'Accumulated log')}</option><option value="mixed">{t(locale, '혼합', 'Mixed')}</option></select></label>
        <label><span>{t(locale, '현재 상태', 'Current status')}</span><select value={tone} onChange={(event) => setTone(event.target.value as typeof tone)}><option value="all">{t(locale, '전체 상태', 'All statuses')}</option><option value="danger">{t(locale, '위험', 'Danger')}</option><option value="caution">{t(locale, '주의', 'Caution')}</option><option value="ok">{t(locale, '정상', 'Nominal')}</option><option value="neutral">{t(locale, '지원 안 됨·전용', 'Unsupported / dedicated')}</option></select></label>
        <button type="button" onClick={() => { setQuery(''); setDomain('all'); setKind('all'); setBasis('all'); setTone('all'); }}>{t(locale, '필터 초기화', 'Clear filters')}</button>
      </section>
      <section className="coverage-table-panel" aria-labelledby="coverage-table-title">
        <header><div><h2 id="coverage-table-title">{t(locale, '전체 관찰·검사 목록', 'Complete observation and check catalog')}</h2><p>{t(locale, `${rows.length}개 중 ${filtered.length}개 표시`, `${filtered.length} of ${rows.length} items`)}</p></div><span>{t(locale, `규칙 팩 ${catalog.rulePackVersion}`, `Rule pack ${catalog.rulePackVersion}`)} · {formatDateTime(catalog.generatedAt, locale)}</span></header>
        <div className="coverage-table-wrap"><table className="coverage-table"><thead><tr><th>{t(locale, '영역', 'Domain')}</th><th>{t(locale, '항목', 'Item')}</th><th>{t(locale, '종류', 'Kind')}</th><th>{t(locale, '판단 근거', 'Evidence')}</th><th>{t(locale, '수집·평가', 'Cadence')}</th><th>{t(locale, '보존·삭제', 'Retention / pruning')}</th><th>{t(locale, '현재 상태', 'Current status')}</th><th>{t(locale, '열기', 'Open')}</th></tr></thead><tbody>{visible.map((row) => {
          const open = expanded === row.id;
          const source = row.source;
          const firstPage = row.detailPages.map(monitorDetailPage).find(Boolean) ?? null;
          return <Fragment key={row.id}>
            <tr className={`coverage-row row-${row.status.tone}`}>
              <td><span className="coverage-domain">{domainLabel(row.domain, locale)}</span></td>
              <td><button className="coverage-row-toggle" type="button" aria-expanded={open} onClick={() => setExpanded(open ? null : row.id)}><strong>{safeText(row.label, '—', 128)}</strong><small>{safeText(row.description, '—', 180)}</small></button></td>
              <td><span className={`coverage-kind kind-${row.kind}`}>{kindLabel(row.kind, locale)}</span></td>
              <td>{evidenceLabel(row.evidenceMode, locale)}</td>
              <td>{cadenceLabel(row.cadenceSeconds, locale)}</td>
              <td>{source ? <><strong>{retention(source, locale)}</strong><small>{prune(source, locale)}</small></> : <><strong>{row.kind === 'check' ? t(locale, '최신 상태 1개', 'Latest state') : '—'}</strong><small>{row.kind === 'check' ? t(locale, '전환은 별도 누적', 'Transitions retained separately') : ''}</small></>}</td>
              <td><span className={`coverage-status status-${row.status.tone}`}><b>{row.status.tone === 'danger' ? '▲' : row.status.tone === 'caution' ? '●' : row.status.tone === 'ok' ? '✓' : '—'}</b><span><strong>{row.status.label}</strong><small>{row.status.detail}</small></span></span></td>
              <td><div className="coverage-actions">{row.genericSource ? <a href={sourceLogHref(range, row.genericSource.sourceId)} aria-label={t(locale, `${row.label} 로그 열기`, `Open ${row.label} logs`)}><Icon name="clock" size={14} /></a> : source && source.id.startsWith('generic-log') ? <a href={sourceLogHref(range)} aria-label={t(locale, '일반 로그 열기', 'Open generic logs')}><Icon name="clock" size={14} /></a> : source && !['system-update-state', 'infrastructure-ledger', 'agent-inventory'].includes(source.id) ? <button type="button" onClick={() => setSelectedSource(source)} aria-label={t(locale, `${row.label} 저장 기록 보기`, `View ${row.label} records`)}><Icon name="clock" size={14} /></button> : firstPage ? <a href={`${monitorPathForPage(firstPage)}?range=${encodeURIComponent(range)}`} aria-label={t(locale, `${row.label} 상세 열기`, `Open ${row.label} detail`)}><Icon name="chevron" size={14} /></a> : null}<button type="button" onClick={() => setExpanded(open ? null : row.id)} aria-label={open ? t(locale, '설명 접기', 'Collapse details') : t(locale, '설명 펼치기', 'Expand details')}><span>{open ? '−' : '+'}</span></button></div></td>
            </tr>
            {open && <tr className="coverage-expanded-row"><td colSpan={8}><RowDetail row={row} sourceMap={sourceMap} locale={locale} range={range} onOpenSource={setSelectedSource} /></td></tr>}
          </Fragment>;
        })}</tbody></table></div>
        {!visible.length && <div className="coverage-empty"><Icon name="info" size={22} /><strong>{t(locale, '조건에 맞는 항목이 없습니다.', 'No item matches these filters.')}</strong></div>}
        <Pagination model={pagination} locale={locale} onPageChange={(page) => { pagination.setPage(page); setExpanded(null); }} ariaLabel={t(locale, '관찰·검사 목록 페이지', 'Monitoring catalog pages')} itemLabel={t(locale, '개 항목', 'items')} />
      </section>
      {selectedSource && <EvidenceRecordDialog source={selectedSource} data={data} locale={locale} onClose={() => setSelectedSource(null)} />}
    </div>
  );
}
