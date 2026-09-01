import { useMemo, useState } from 'react';
import type { MonitoringCatalog, MonitoringEvidenceSource } from '../api';
import { localized, monitorPathForPage } from '../dashboard-model';
import { useMonitoringCatalog } from '../hooks/useMonitoringCatalog';
import type { DashboardPayload, MonitorDetailPage, MonitorLocale, TimeRange } from '../types';
import { formatBytes } from '../utils';
import { EvidenceRecordDialog } from './EvidenceRecordDialog';
import { Icon } from './Icon';
import './monitoring-evidence.css';

const PAGE_EVIDENCE_EXTRAS: Record<MonitorDetailPage, string[]> = {
  coverage: [],
  resources: ['current-snapshot', 'telemetry-history', 'semantic-alert-events', 'reliability-events', 'rule-evaluation-state', 'rule-alert-events'],
  network: ['current-snapshot', 'telemetry-history', 'incident-events', 'semantic-alert-events', 'reliability-events', 'generic-log-events'],
  storage: ['current-snapshot', 'telemetry-history', 'reliability-events', 'incident-events', 'rule-evaluation-state'],
  containers: ['current-snapshot', 'semantic-alert-events', 'rule-evaluation-state', 'rule-alert-events', 'generic-log-events'],
  reliability: ['current-snapshot', 'reliability-events', 'power-events', 'privilege-events', 'rule-evaluation-state', 'rule-alert-events', 'generic-log-events'],
  maintenance: ['current-snapshot', 'system-update-state', 'privilege-events', 'generic-log-events'],
  infrastructure: ['infrastructure-ledger', 'privilege-events', 'generic-log-source-state', 'generic-log-events'],
  power: ['current-snapshot', 'telemetry-history', 'power-events', 'reliability-events'],
  incidents: ['incident-events', 'semantic-alert-events', 'rule-alert-events', 'generic-log-events'],
  logs: ['generic-log-events', 'generic-log-source-state'],
};

export function relatedEvidenceIds(
  page: MonitorDetailPage,
  catalog: Pick<MonitoringCatalog, 'evidenceSources' | 'observations' | 'rules'> | null,
): string[] {
  if (page === 'coverage') return [];
  const ids = new Set(PAGE_EVIDENCE_EXTRAS[page]);
  for (const source of catalog?.evidenceSources ?? []) {
    if (source.detailPages.includes(page)) ids.add(source.id);
  }
  for (const observation of catalog?.observations ?? []) {
    if (!observation.detailPages.includes(page)) continue;
    for (const sourceId of observation.evidenceSourceIds) ids.add(sourceId);
  }
  for (const rule of catalog?.rules ?? []) {
    if (!rule.detailPages.includes(page)) continue;
    ids.add(rule.stateEvidenceSourceId);
    ids.add(rule.eventEvidenceSourceId);
  }
  return [...ids];
}

const PAGE_GENERIC_SOURCES: Partial<Record<MonitorDetailPage, string[]>> = {
  resources: ['journal:monitor-collector'],
  network: ['journal:nginx'],
  storage: ['journal:monitor-collector'],
  containers: ['file:application'],
  reliability: ['journal:monitor-collector', 'journal:ssh'],
  maintenance: ['journal:monitor-collector'],
  infrastructure: ['journal:ssh', 'journal:monitor-collector'],
  power: ['journal:monitor-collector'],
  incidents: ['file:application', 'journal:monitor-collector'],
};

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function cadence(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  const seconds = source.cadenceSeconds;
  if (seconds === null) return t(locale, '변경·작업 시', 'On change or operation');
  if (seconds < 60) return t(locale, `${seconds}초마다`, `Every ${seconds}s`);
  if (seconds % 3600 === 0) return t(locale, `${seconds / 3600}시간마다`, `Every ${seconds / 3600}h`);
  return t(locale, `${seconds / 60}분마다`, `Every ${seconds / 60}m`);
}

function pruneCadence(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  const labels: Record<MonitoringEvidenceSource['retention']['pruneCadence'], [string, string]> = {
    'replace-on-collection': ['매 수집 때 교체', 'Replaced every collection'],
    'every-collection': ['매 수집 커밋 때 오래된 기록 정리', 'Pruned on every collection commit'],
    'on-incident-write-or-daily': ['새 사건 저장 시, 무사건이면 하루 1회 정리', 'Pruned on incident writes or once daily when quiet'],
    'every-rule-evaluation': ['매 규칙 평가 때 오래된 전환 정리', 'Pruned on every rule evaluation'],
    'every-generic-collection': ['매 일반 로그 수집 때 정리', 'Pruned on every generic-log collection'],
    'replace-on-generic-collection': ['매 일반 로그 수집 때 교체', 'Replaced on every generic-log collection'],
    'replace-on-change': ['상태 변경·작업 때 교체', 'Replaced when state changes'],
    'external-no-auto-prune': ['외부 정책 관리·자동 삭제 없음', 'Externally managed; no automatic pruning'],
  };
  return t(locale, ...labels[source.retention.pruneCadence]);
}

export function retentionLabel(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  const limits: string[] = [];
  if (source.retention.maxAgeDays !== null) limits.push(t(locale, `${source.retention.maxAgeDays}일`, `${source.retention.maxAgeDays} days`));
  if (source.retention.maxRecords !== null) {
    const scope = source.retention.recordScope === 'daily-partition' ? t(locale, '일', 'day') : t(locale, '파일', 'artifact');
    limits.push(t(locale, `${scope}당 ${source.retention.maxRecords.toLocaleString()}건`, `${source.retention.maxRecords.toLocaleString()} records/${scope}`));
  }
  if (source.retention.maxBytes !== null) limits.push(formatBytes(source.retention.maxBytes));
  return limits.length ? limits.join(' · ') : t(locale, '외부 정책', 'External policy');
}

function evidenceMode(source: MonitoringEvidenceSource, locale: MonitorLocale): string {
  return source.evidenceMode === 'current-state'
    ? t(locale, '현재 상태', 'Current state')
    : t(locale, '누적 기록', 'Accumulated records');
}

export function RelatedEvidencePanel({ page, data, range, locale, onUnauthorized }: {
  page: MonitorDetailPage;
  data: DashboardPayload | null;
  range: TimeRange;
  locale: MonitorLocale;
  onUnauthorized: () => void;
}) {
  const { catalog, error, loading, refresh } = useMonitoringCatalog(onUnauthorized, data?.latestObservedAt ?? data?.generatedAt ?? null);
  const [selected, setSelected] = useState<MonitoringEvidenceSource | null>(null);
  const ids = useMemo(() => relatedEvidenceIds(page, catalog), [catalog, page]);
  const sources = useMemo(() => {
    if (!catalog) return [];
    const byId = new Map(catalog.evidenceSources.map((source) => [source.id, source]));
    return ids.map((id) => byId.get(id)).filter((source): source is MonitoringEvidenceSource => Boolean(source));
  }, [catalog, ids]);
  const genericSourceIds = PAGE_GENERIC_SOURCES[page] ?? [];

  if (page === 'coverage') return null;
  return (
    <section id="related-evidence" className="related-evidence-panel" aria-labelledby={`related-evidence-${page}`}>
      <header>
        <span><Icon name="clock" size={18} /></span>
        <div><h2 id={`related-evidence-${page}`}>{t(locale, '관련 저장 기록·로그', 'Related stored records and logs')}</h2><p>{t(locale, '파일명은 논리적 증거 단위이며, 클릭하면 원본이 아닌 검증·축약·민감정보 제거 기록을 엽니다.', 'File labels identify logical evidence; opening them shows validated, reduced, redacted records rather than raw files.')}</p></div>
      </header>
      {error && catalog && <div className="related-evidence-state evidence-state-error" role="alert"><span>{t(locale, '최신 보존 정책을 갱신하지 못해 마지막 검증본을 표시합니다.', 'The latest retention policy could not be refreshed; the last verified catalog is shown.')} {error}</span><button type="button" onClick={refresh}>{t(locale, '다시 시도', 'Retry')}</button></div>}
      {loading && !catalog ? <div className="related-evidence-state">{t(locale, '보존 정책을 불러오는 중…', 'Loading retention policy…')}</div> : error && !catalog ? <div className="related-evidence-state evidence-state-error"><span>{error}</span><button type="button" onClick={refresh}>{t(locale, '다시 시도', 'Retry')}</button></div> : (
        <ul className="related-evidence-list">
          {sources.map((source) => {
            const generic = source.id === 'generic-log-events' || source.id === 'generic-log-source-state';
            const dedicated = source.id === 'system-update-state' ? 'maintenance' : source.id === 'infrastructure-ledger' || source.id === 'agent-inventory' ? 'infrastructure' : null;
            return <li key={source.id}>
              <div className="related-evidence-title"><span className={`evidence-mode mode-${source.evidenceMode}`}>{evidenceMode(source, locale)}</span><strong>{source.displayName[locale]}</strong><code>{source.artifactLabel}</code></div>
              <p>{source.description[locale]}</p>
              <dl><div><dt>{t(locale, '생성·수집', 'Collection')}</dt><dd>{cadence(source, locale)}</dd></div><div><dt>{t(locale, '보존 상한', 'Retention limit')}</dt><dd>{retentionLabel(source, locale)}</dd></div><div><dt>{t(locale, '정리 시점', 'Pruning')}</dt><dd>{pruneCadence(source, locale)}</dd></div></dl>
              <div className="related-evidence-actions">
                {generic ? (
                  <>
                    {(genericSourceIds.length ? genericSourceIds : [null]).map((sourceId) => {
                      const search = new URLSearchParams({ range });
                      if (sourceId) search.set('sourceId', sourceId);
                      const href = `${monitorPathForPage('logs')}?${search.toString()}`;
                      return <a key={sourceId ?? 'all'} href={href}>{sourceId ? safeSourceLabel(sourceId) : t(locale, '일반 로그 열기', 'Open generic logs')}<Icon name="chevron" size={14} /></a>;
                    })}
                  </>
                ) : dedicated ? <a href={`${monitorPathForPage(dedicated)}?range=${encodeURIComponent(range)}`}>{t(locale, '전용 상세 열기', 'Open dedicated detail')}<Icon name="chevron" size={14} /></a>
                  : <button type="button" onClick={() => setSelected(source)}>{t(locale, '저장 기록 보기', 'View stored records')}<Icon name="chevron" size={14} /></button>}
              </div>
            </li>;
          })}
        </ul>
      )}
      {selected && <EvidenceRecordDialog source={selected} data={data} locale={locale} onClose={() => setSelected(null)} />}
    </section>
  );
}

function safeSourceLabel(sourceId: string): string {
  const labels: Record<string, string> = {
    'journal:ssh': 'SSH',
    'journal:monitor-collector': 'Monitor collector',
    'journal:nginx': 'Nginx',
    'file:application': 'Application',
  };
  return labels[sourceId] ?? 'Logs';
}
