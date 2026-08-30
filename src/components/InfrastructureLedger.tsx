import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, getInfrastructureLedger } from '../api';
import {
  filterInfrastructureLedgerEntries,
  groupInfrastructureLedgerEntries,
  INFRASTRUCTURE_LEDGER_CATEGORIES,
  INFRASTRUCTURE_LEDGER_CSF_FUNCTIONS,
  INFRASTRUCTURE_LEDGER_PRIORITIES,
  INFRASTRUCTURE_LEDGER_SENSITIVITIES,
  INFRASTRUCTURE_LEDGER_STATUSES,
  INFRASTRUCTURE_LEDGER_VERIFICATIONS,
  INFRASTRUCTURE_LEDGER_WORK_TYPES,
  localizedLedgerText,
  currentInfrastructureLedgerEntries,
  summarizeInfrastructureLedger,
  type InfrastructureLedgerFilters,
  type InfrastructureLedgerGroup,
  type InfrastructureLedgerMode,
} from '../infrastructure-ledger';
import type {
  InfrastructureLedgerCategory,
  InfrastructureLedgerCsfFunction,
  InfrastructureLedgerEntry,
  InfrastructureLedgerPriority,
  InfrastructureLedgerReference,
  InfrastructureLedgerSensitivity,
  InfrastructureLedgerStatus,
  InfrastructureLedgerVerification,
  InfrastructureLedgerWorkType,
  MonitorLocale,
} from '../types';
import { formatBytes, formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';
import { Pagination, paginateItems, usePagination } from './Pagination';

const EMPTY_FILTERS: InfrastructureLedgerFilters = {
  query: '',
  category: 'all',
  status: 'all',
  workType: 'all',
  priority: 'all',
  verification: 'all',
  sensitivity: 'all',
  csfFunction: 'all',
  from: '',
  to: '',
};

function t(locale: MonitorLocale, ko: string, en: string): string {
  return locale === 'ko' ? ko : en;
}

function categoryLabel(value: InfrastructureLedgerCategory, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerCategory, [string, string]> = {
    security: ['보안', 'Security'],
    'identity-access': ['신원·접근', 'Identity & access'],
    network: ['네트워크', 'Network'],
    'dns-edge': ['DNS·엣지', 'DNS & edge'],
    reliability: ['신뢰성', 'Reliability'],
    'compute-kernel': ['컴퓨트·커널', 'Compute & kernel'],
    'storage-filesystem': ['저장장치·파일시스템', 'Storage & filesystem'],
    'backup-recovery': ['백업·복구', 'Backup & recovery'],
    'observability-logging': ['관측성·로그', 'Observability & logging'],
    'service-deployment': ['서비스·배포', 'Service & deployment'],
    containers: ['컨테이너', 'Containers'],
    'packages-firmware': ['패키지·펌웨어', 'Packages & firmware'],
    'governance-documentation': ['거버넌스·문서', 'Governance & documentation'],
    'hardware-physical': ['하드웨어·물리', 'Hardware & physical'],
  };
  return t(locale, ...labels[value]);
}

function statusLabel(value: InfrastructureLedgerStatus, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerStatus, [string, string]> = {
    completed: ['완료', 'Completed'],
    'in-progress': ['진행 중', 'In progress'],
    pending: ['미조치', 'Pending'],
    deferred: ['보류', 'Deferred'],
    recommended: ['권고·검토 필요', 'Recommended'],
    observed: ['관측 기록', 'Observed'],
    superseded: ['후속 기록으로 대체', 'Superseded'],
    'not-applicable': ['해당 없음', 'Not applicable'],
  };
  return t(locale, ...labels[value]);
}

function workTypeLabel(value: InfrastructureLedgerWorkType, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerWorkType, [string, string]> = {
    change: ['변경', 'Change'],
    configuration: ['설정', 'Configuration'],
    audit: ['감사', 'Audit'],
    hardening: ['보안 강화', 'Hardening'],
    mitigation: ['완화 조치', 'Mitigation'],
    update: ['업데이트', 'Update'],
    verification: ['검증', 'Verification'],
    incident: ['사건', 'Incident'],
    maintenance: ['유지보수', 'Maintenance'],
    recommendation: ['권고', 'Recommendation'],
    decision: ['운영 결정', 'Decision'],
    documentation: ['문서화', 'Documentation'],
  };
  return t(locale, ...labels[value]);
}

function priorityLabel(value: InfrastructureLedgerPriority, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerPriority, [string, string]> = {
    critical: ['긴급', 'Critical'],
    high: ['높음', 'High'],
    medium: ['보통', 'Medium'],
    low: ['낮음', 'Low'],
    informational: ['정보', 'Informational'],
  };
  return t(locale, ...labels[value]);
}

function verificationLabel(value: InfrastructureLedgerVerification, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerVerification, [string, string]> = {
    verified: ['검증 완료', 'Verified'],
    'partially-verified': ['부분 검증', 'Partially verified'],
    unverified: ['미검증', 'Unverified'],
    'not-applicable': ['검증 해당 없음', 'Not applicable'],
  };
  return t(locale, ...labels[value]);
}

function sensitivityLabel(value: InfrastructureLedgerSensitivity, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerSensitivity, [string, string]> = {
    public: ['공개 정보', 'Public'],
    internal: ['내부 운영', 'Internal'],
    restricted: ['관리자 제한', 'Restricted'],
  };
  return t(locale, ...labels[value]);
}

function csfFunctionLabel(value: InfrastructureLedgerCsfFunction, locale: MonitorLocale): string {
  const labels: Record<InfrastructureLedgerCsfFunction, [string, string]> = {
    govern: ['거버넌스', 'Govern'],
    identify: ['식별', 'Identify'],
    protect: ['보호', 'Protect'],
    detect: ['탐지', 'Detect'],
    respond: ['대응', 'Respond'],
    recover: ['복구', 'Recover'],
  };
  return t(locale, ...labels[value]);
}

function groupLabel(group: InfrastructureLedgerGroup, key: string, locale: MonitorLocale): string {
  if (group === 'category') return categoryLabel(key as InfrastructureLedgerCategory, locale);
  if (group === 'status') return statusLabel(key as InfrastructureLedgerStatus, locale);
  if (key === 'unknown') return t(locale, '날짜 미확인', 'Unknown date');
  const date = new Date(`${key}T00:00:00`);
  return Number.isFinite(date.getTime())
    ? new Intl.DateTimeFormat(locale === 'ko' ? 'ko-KR' : 'en-US', { dateStyle: 'full' }).format(date)
    : key;
}

function selectValue<T extends string>(value: string): T | 'all' {
  return value === 'all' ? 'all' : value as T;
}

interface InfrastructureLedgerProps {
  locale: MonitorLocale;
  onUnauthorized: () => void;
}

export function InfrastructureLedger({ locale, onUnauthorized }: InfrastructureLedgerProps) {
  const [data, setData] = useState<Awaited<ReturnType<typeof getInfrastructureLedger>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [mode, setMode] = useState<InfrastructureLedgerMode>('current');
  const [group, setGroup] = useState<InfrastructureLedgerGroup>('date');
  const [filters, setFilters] = useState<InfrastructureLedgerFilters>(EMPTY_FILTERS);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async (signal?: AbortSignal, refresh = false) => {
    if (refresh) setRefreshing(true);
    try {
      const result = await getInfrastructureLedger(signal);
      setData(result);
      setError(null);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === 'AbortError') return;
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized();
        return;
      }
      setError(caught instanceof Error ? caught.message : t(locale, '원장을 불러오지 못했습니다.', 'Could not load the ledger.'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [locale, onUnauthorized]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const sourceEntries = useMemo(() => {
    if (!data) return [];
    return mode === 'current' ? currentInfrastructureLedgerEntries(data.entries) : data.entries;
  }, [data, mode]);
  const filtered = useMemo(
    () => filterInfrastructureLedgerEntries(sourceEntries, filters, locale),
    [filters, locale, sourceEntries],
  );
  const entrySignature = useMemo(
    () => sourceEntries.map((entry) => `${entry.id}:${entry.revision}`).join('\u001f'),
    [sourceEntries],
  );
  const pagination = usePagination({
    totalItems: filtered.length,
    pageSize: 10,
    resetKey: `${mode}\u001e${group}\u001e${locale}\u001e${JSON.stringify(filters)}\u001e${entrySignature}`,
  });
  const visibleEntries = useMemo(
    () => paginateItems(filtered, pagination),
    [filtered, pagination.endIndex, pagination.startIndex],
  );
  const groupTotals = useMemo(
    () => new Map(groupInfrastructureLedgerEntries(filtered, group).map((bucket) => [bucket.key, bucket.entries.length])),
    [filtered, group],
  );
  const grouped = useMemo(() => groupInfrastructureLedgerEntries(visibleEntries, group), [group, visibleEntries]);
  const summary = useMemo(() => summarizeInfrastructureLedger(data?.entries ?? []), [data]);
  const references = useMemo(() => new Map((data?.references ?? []).map((reference) => [reference.id, reference])), [data]);
  const activeFilterCount = Object.entries(filters).filter(([key, value]) => key === 'query' ? Boolean(value.trim()) : value !== 'all' && value !== '').length;

  if (loading && !data) {
    return <div className="ledger-state" aria-busy="true"><Icon name="clock" size={28} /><strong>{t(locale, '인프라 작업 원장을 불러오는 중…', 'Loading infrastructure ledger…')}</strong></div>;
  }

  if (!data) {
    return <div className="ledger-state ledger-state-error" role="alert"><Icon name="alert" size={28} /><strong>{t(locale, '인프라 작업 원장을 사용할 수 없습니다', 'Infrastructure ledger is unavailable')}</strong><p>{safeText(error, t(locale, '원장 파일과 접근 권한을 확인하세요.', 'Check the ledger file and access permissions.'))}</p><button type="button" onClick={() => void load(undefined, true)}>{t(locale, '다시 확인', 'Try again')}</button></div>;
  }

  const capacityPercent = Math.max(
    data.entries.length / data.limits.maximumEntries,
    data.limits.usedBytes / data.limits.maximumBytes,
  ) * 100;

  return (
    <section className="infrastructure-ledger" aria-label={t(locale, '인프라 작업 원장', 'Infrastructure work ledger')}>
      <div className="ledger-summary-grid">
        <LedgerSummaryCard label={t(locale, '관리 항목', 'Work items')} value={summary.total} tone="neutral" />
        <LedgerSummaryCard label={t(locale, '완료', 'Completed')} value={summary.completed} tone="good" />
        <LedgerSummaryCard label={t(locale, '열린 항목', 'Open items')} value={summary.open} tone={summary.open ? 'caution' : 'good'} />
        <LedgerSummaryCard label={t(locale, '미조치·진행', 'Pending')} value={summary.pending} tone={summary.pending ? 'danger' : 'good'} />
        <LedgerSummaryCard label={t(locale, '권고·검토', 'Recommended')} value={summary.recommended} tone="caution" />
        <LedgerSummaryCard label={t(locale, '높은 우선순위', 'High-priority open')} value={summary.highPriorityOpen} tone={summary.highPriorityOpen ? 'danger' : 'good'} />
      </div>

      <div className="ledger-provenance">
        <div><Icon name="shield" size={20} /><div><strong>{t(locale, '증거 기반 장기 원장', 'Evidence-backed long-term ledger')}</strong><span>{t(locale, `${data.coverage.sources.length}개 증거원 · 최신 기록 ${formatDateTime(data.updatedAt, locale)}`, `${data.coverage.sources.length} evidence sources · updated ${formatDateTime(data.updatedAt, locale)}`)}</span><span className={capacityPercent >= 75 ? 'ledger-capacity-warning' : ''}>{t(locale, `저장 경계 ${capacityPercent.toFixed(1)}% · ${data.entries.length.toLocaleString()}/${data.limits.maximumEntries.toLocaleString()}건 · ${formatBytes(data.limits.usedBytes)}/${formatBytes(data.limits.maximumBytes)}`, `Storage boundary ${capacityPercent.toFixed(1)}% · ${data.entries.length.toLocaleString()}/${data.limits.maximumEntries.toLocaleString()} events · ${formatBytes(data.limits.usedBytes)}/${formatBytes(data.limits.maximumBytes)}`)}</span></div></div>
        <button type="button" onClick={() => void load(undefined, true)} disabled={refreshing}><Icon name="refresh" size={16} className={refreshing ? 'spin' : ''} />{refreshing ? t(locale, '갱신 중', 'Refreshing') : t(locale, '원장 갱신', 'Refresh ledger')}</button>
      </div>

      <details className="ledger-coverage">
        <summary>{t(locale, '수집 범위와 복원 한계', 'Evidence coverage and reconstruction limits')}</summary>
        <div className="ledger-coverage-grid">
          <div><strong>{t(locale, '확인한 증거원', 'Evidence sources')}</strong><ul>{data.coverage.sources.map((source) => <li key={source.id}>{localizedLedgerText(source.label, locale)}<small>{source.from ? `${formatDateTime(source.from, locale)} — ${source.through ? formatDateTime(source.through, locale) : t(locale, '현재', 'present')}` : t(locale, '보존 범위 미확인', 'retention window unknown')}</small></li>)}</ul></div>
          <div><strong>{t(locale, '한계', 'Limitations')}</strong><ul>{data.coverage.limitations.map((limitation, index) => <li key={`${index}-${limitation.ko.slice(0, 12)}`}>{localizedLedgerText(limitation, locale)}</li>)}</ul></div>
        </div>
      </details>

      {error && <div className="ledger-inline-error" role="alert"><Icon name="alert" size={16} />{safeText(error)} {t(locale, '마지막 정상 원장을 유지합니다.', 'The last good ledger remains visible.')}</div>}

      <div className="ledger-toolbar">
        <div className="ledger-mode-tabs" role="group" aria-label={t(locale, '원장 보기', 'Ledger view')}>
          <button type="button" className={mode === 'current' ? 'active' : ''} aria-pressed={mode === 'current'} onClick={() => setMode('current')}>{t(locale, '현재 항목', 'Current items')} <span>{summary.total}</span></button>
          <button type="button" className={mode === 'history' ? 'active' : ''} aria-pressed={mode === 'history'} onClick={() => setMode('history')}>{t(locale, '전체 변경 이력', 'Full history')} <span>{data.entries.length}</span></button>
        </div>
        <label><span>{t(locale, '묶어 보기', 'Group by')}</span><select value={group} onChange={(event) => setGroup(event.target.value as InfrastructureLedgerGroup)}><option value="date">{t(locale, '날짜', 'Date')}</option><option value="category">{t(locale, '분류', 'Category')}</option><option value="status">{t(locale, '상태', 'Status')}</option></select></label>
      </div>

      <div className="ledger-filters" aria-label={t(locale, '원장 필터', 'Ledger filters')}>
        <label className="ledger-search"><span>{t(locale, '검색', 'Search')}</span><input type="search" value={filters.query} onChange={(event) => setFilters((current) => ({ ...current, query: event.target.value }))} placeholder={t(locale, '작업, 이유, 결과, 근거 검색', 'Search work, rationale, outcome, evidence')} /></label>
        <label><span>{t(locale, '분류', 'Category')}</span><select value={filters.category} onChange={(event) => setFilters((current) => ({ ...current, category: selectValue<InfrastructureLedgerCategory>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_CATEGORIES.map((value) => <option key={value} value={value}>{categoryLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '상태', 'Status')}</span><select value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: selectValue<InfrastructureLedgerStatus>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_STATUSES.map((value) => <option key={value} value={value}>{statusLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '작업 구분', 'Work type')}</span><select value={filters.workType} onChange={(event) => setFilters((current) => ({ ...current, workType: selectValue<InfrastructureLedgerWorkType>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_WORK_TYPES.map((value) => <option key={value} value={value}>{workTypeLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '우선순위', 'Priority')}</span><select value={filters.priority} onChange={(event) => setFilters((current) => ({ ...current, priority: selectValue<InfrastructureLedgerPriority>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_PRIORITIES.map((value) => <option key={value} value={value}>{priorityLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '검증', 'Verification')}</span><select value={filters.verification} onChange={(event) => setFilters((current) => ({ ...current, verification: selectValue<InfrastructureLedgerVerification>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_VERIFICATIONS.map((value) => <option key={value} value={value}>{verificationLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '민감도', 'Sensitivity')}</span><select value={filters.sensitivity} onChange={(event) => setFilters((current) => ({ ...current, sensitivity: selectValue<InfrastructureLedgerSensitivity>(event.target.value) }))}><option value="all">{t(locale, '전체', 'All')}</option>{INFRASTRUCTURE_LEDGER_SENSITIVITIES.map((value) => <option key={value} value={value}>{sensitivityLabel(value, locale)}</option>)}</select></label>
        <label><span>NIST CSF</span><select value={filters.csfFunction} onChange={(event) => setFilters((current) => ({ ...current, csfFunction: selectValue<InfrastructureLedgerCsfFunction>(event.target.value) }))}><option value="all">{t(locale, '전체 기능', 'All functions')}</option>{INFRASTRUCTURE_LEDGER_CSF_FUNCTIONS.map((value) => <option key={value} value={value}>{csfFunctionLabel(value, locale)}</option>)}</select></label>
        <label><span>{t(locale, '시작일', 'From')}</span><input type="date" value={filters.from} onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))} /></label>
        <label><span>{t(locale, '종료일', 'To')}</span><input type="date" value={filters.to} onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))} /></label>
        <div className="ledger-filter-result"><strong>{filtered.length.toLocaleString()}</strong><span>{t(locale, mode === 'current' ? '개 항목' : '개 기록', mode === 'current' ? 'items' : 'events')}</span><button type="button" disabled={!activeFilterCount} onClick={() => setFilters(EMPTY_FILTERS)}>{t(locale, `초기화${activeFilterCount ? ` ${activeFilterCount}` : ''}`, `Reset${activeFilterCount ? ` ${activeFilterCount}` : ''}`)}</button></div>
      </div>

      <div className="ledger-groups">
        {grouped.map((bucket) => <section key={bucket.key} className="ledger-group"><header><div><span>{group === 'date' ? t(locale, '작업일', 'WORK DATE') : group === 'category' ? t(locale, '분류', 'CATEGORY') : t(locale, '상태', 'STATUS')}</span><h2>{groupLabel(group, bucket.key, locale)}</h2></div><strong>{groupTotals.get(bucket.key) ?? bucket.entries.length}</strong></header><ol>{bucket.entries.map((entry) => <LedgerEntryCard key={entry.id} entry={entry} references={references} expanded={expanded === entry.id} locale={locale} onToggle={() => setExpanded(expanded === entry.id ? null : entry.id)} />)}</ol></section>)}
        {!grouped.length && <div className="ledger-state"><Icon name="check" size={28} /><strong>{t(locale, '조건에 맞는 원장 항목이 없습니다', 'No ledger entries match these filters')}</strong><button type="button" onClick={() => setFilters(EMPTY_FILTERS)}>{t(locale, '필터 초기화', 'Reset filters')}</button></div>}
      </div>
      <Pagination
        model={pagination}
        locale={locale}
        onPageChange={pagination.setPage}
        ariaLabel={t(locale, '인프라 작업 원장 페이지', 'Infrastructure work ledger pages')}
        itemLabel={t(locale, mode === 'current' ? '개 항목' : '건', mode === 'current' ? 'items' : 'events')}
        className="ledger-pagination"
      />
    </section>
  );
}

function LedgerSummaryCard({ label, value, tone }: { label: string; value: number; tone: 'good' | 'caution' | 'danger' | 'neutral' }) {
  return <div className={`ledger-summary-card ledger-tone-${tone}`}><span>{label}</span><strong>{value.toLocaleString()}</strong></div>;
}

function LedgerEntryCard({ entry, references, expanded, locale, onToggle }: {
  entry: InfrastructureLedgerEntry;
  references: ReadonlyMap<string, InfrastructureLedgerReference>;
  expanded: boolean;
  locale: MonitorLocale;
  onToggle: () => void;
}) {
  const title = localizedLedgerText(entry.title, locale);
  const detailsId = `ledger-entry-${entry.id.replace(/[^a-z0-9_-]/giu, '-')}`;
  return (
    <li className={`ledger-entry ledger-status-${entry.status} ledger-priority-${entry.priority}`}>
      <button type="button" onClick={onToggle} aria-expanded={expanded} aria-controls={detailsId}>
        <span className="ledger-entry-mark" aria-hidden="true">{entry.status === 'completed' ? '✓' : entry.priority === 'critical' || entry.priority === 'high' ? '▲' : '●'}</span>
        <span className="ledger-entry-main"><span className="ledger-entry-badges"><b>{statusLabel(entry.status, locale)}</b><i>{categoryLabel(entry.category, locale)}</i><i>{workTypeLabel(entry.workType, locale)}</i><i>{priorityLabel(entry.priority, locale)}</i><i>{sensitivityLabel(entry.sensitivity, locale)}</i>{entry.csfFunctions.map((value) => <i key={value}>CSF {csfFunctionLabel(value, locale)}</i>)}</span><strong>{safeText(title)}</strong><small>{safeText(localizedLedgerText(entry.summary, locale))}</small></span>
        <span className="ledger-entry-time"><time dateTime={entry.occurredAt}>{formatDateTime(entry.occurredAt, locale)}</time><small>rev {entry.revision} · {verificationLabel(entry.verification, locale)}</small></span>
        <Icon name="chevron" size={16} className={expanded ? 'chevron-open' : ''} />
      </button>
      {expanded && <div id={detailsId} className="ledger-entry-detail">
        <dl className="ledger-entry-facts">
          <div><dt>{t(locale, '항목 키', 'Item key')}</dt><dd>{entry.itemKey}</dd></div>
          <div><dt>{t(locale, '행위자', 'Actor')}</dt><dd>{safeText(entry.actor)}</dd></div>
          <div><dt>{t(locale, '검증', 'Verification')}</dt><dd>{verificationLabel(entry.verification, locale)}</dd></div>
          <div><dt>{t(locale, '근거 신뢰도', 'Evidence confidence')}</dt><dd>{entry.confidence}</dd></div>
          <div><dt>{t(locale, '적용성', 'Applicability')}</dt><dd>{entry.applicability}</dd></div>
          <div><dt>{t(locale, '서비스 영향', 'Service impact')}</dt><dd>{entry.impact}</dd></div>
          <div><dt>{t(locale, '민감도', 'Sensitivity')}</dt><dd>{sensitivityLabel(entry.sensitivity, locale)}</dd></div>
          <div><dt>{t(locale, '기록 시각', 'Recorded')}</dt><dd>{formatDateTime(entry.recordedAt, locale)}</dd></div>
          <div><dt>{t(locale, '범위', 'Scope')}</dt><dd>{entry.scope.join(' · ') || '—'}</dd></div>
        </dl>
        <div className="ledger-narrative-grid">
          <LedgerNarrative title={t(locale, '왜 했는가', 'Rationale')} text={localizedLedgerText(entry.rationale, locale)} />
          <LedgerNarrative title={t(locale, '무엇을 확인·변경했는가', 'Work performed')} text={localizedLedgerText(entry.details, locale)} />
          <LedgerNarrative title={t(locale, '결과', 'Outcome')} text={localizedLedgerText(entry.outcome, locale)} />
          <LedgerNarrative title={t(locale, '다음 작업·완료 조건', 'Next action / completion criteria')} text={localizedLedgerText(entry.nextAction, locale)} />
        </div>
        {(entry.dueAt || entry.recurrence) && <div className="ledger-schedule"><Icon name="clock" size={16} /><div>{entry.dueAt && <span><b>{t(locale, '목표일', 'Due')}</b> {formatDateTime(entry.dueAt, locale)}</span>}{entry.recurrence && <span><b>{t(locale, '반복', 'Recurrence')}</b> {localizedLedgerText(entry.recurrence, locale)}</span>}</div></div>}
        <div className="ledger-evidence-grid">
          <section><h3>{t(locale, '검증 근거', 'Verification evidence')} <span>{entry.evidence.length}</span></h3>{entry.evidence.length ? <ul>{entry.evidence.map((evidence, index) => <li key={`${evidence.reference}-${index}`}><div><b>{evidence.kind}</b><code>{safeText(evidence.reference)}</code></div><p>{safeText(localizedLedgerText(evidence.note, locale))}</p><time dateTime={evidence.observedAt}>{formatDateTime(evidence.observedAt, locale)}</time></li>)}</ul> : <p>{t(locale, '직접 검증 근거가 없어 미검증으로 분류했습니다.', 'No direct verification evidence; this item remains unverified.')}</p>}</section>
          <section><h3>{t(locale, '공식 기준·문헌', 'Standards and references')} <span>{entry.referenceIds.length}</span></h3>{entry.referenceIds.length ? <ul>{entry.referenceIds.map((referenceId) => { const reference = references.get(referenceId); return reference ? <li key={reference.id}><a href={reference.url} target="_blank" rel="noreferrer noopener">{safeText(reference.title)}</a><small>{safeText(reference.publisher)} · {formatDateTime(reference.accessedAt, locale)}</small></li> : null; })}</ul> : <p>{t(locale, '이 항목에는 외부 기준이 연결되지 않았습니다.', 'No external reference is linked to this item.')}</p>}</section>
        </div>
        <footer>{entry.supersedes && <span>{t(locale, '대체한 기록', 'Supersedes')}: <code>{entry.supersedes}</code></span>}{entry.relatedIds.length > 0 && <span>{t(locale, '연관 기록', 'Related')}: <code>{entry.relatedIds.join(', ')}</code></span>}<span>{t(locale, '원문 명령·인자·자격 증명·개인정보는 원장에 저장하지 않습니다.', 'Raw commands, arguments, credentials, and personal data are not stored in this ledger.')}</span></footer>
      </div>}
    </li>
  );
}

function LedgerNarrative({ title, text }: { title: string; text: string }) {
  return <section><h3>{title}</h3><p>{safeText(text)}</p></section>;
}
