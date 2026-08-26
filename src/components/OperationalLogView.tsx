import { useMemo, useState } from 'react';
import type {
  OperationalLogCategory,
  OperationalLogEntry,
  OperationalLogSeverity,
} from '../dashboard-model';
import { localized } from '../dashboard-model';
import type { MonitorLocale } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';

const CATEGORIES: OperationalLogCategory[] = ['alert', 'reliability', 'power', 'privilege'];
const SEVERITIES: OperationalLogSeverity[] = ['critical', 'warning', 'info'];

function categoryLabel(category: OperationalLogCategory, locale: MonitorLocale): string {
  const labels: Record<OperationalLogCategory, [string, string]> = {
    alert: ['시스템 경고', 'System alert'],
    reliability: ['호스트 신뢰성', 'Host reliability'],
    power: ['전원', 'Power'],
    privilege: ['권한 감사', 'Privilege audit'],
  };
  return localized(locale, ...labels[category]);
}

function severityLabel(severity: OperationalLogSeverity, locale: MonitorLocale): string {
  const labels: Record<OperationalLogSeverity, [string, string]> = {
    critical: ['위험', 'Critical'],
    warning: ['주의', 'Caution'],
    info: ['정보', 'Advisory'],
  };
  return localized(locale, ...labels[severity]);
}

function localizedEventTitle(entry: OperationalLogEntry, locale: MonitorLocale): string {
  if (locale === 'en') return entry.title;
  const kindLabels: Record<string, string> = {
    'host-boot': '호스트 부팅',
    'collector-gap': '수집 공백',
    'ssh-listener': 'SSH 수신 상태',
    'network-link': '네트워크 연결',
    'nvme-reset': 'NVMe 컨트롤러 재설정',
    'nvme-io': 'NVMe 입출력 오류',
    'rcu-stall': '커널 RCU 지연',
    'oom-kill': '메모리 부족 종료',
    'filesystem-error': '파일시스템 오류',
    'nvme-mitigation': 'NVMe 완화 조치',
    topology: '서비스 구성 변경',
    host: '호스트 상태',
    metrics: '자원 임계치',
    power: '전원 상태',
    sudo: '관리자 명령',
    su: '사용자 전환',
    authentication: '권한 인증',
    policy: '권한 정책',
  };
  const statusLabels: Record<string, string> = {
    active: '발생 중',
    recovered: '복구됨',
    resolved: '해결됨',
    success: '성공',
    failure: '실패',
    allowed: '허용',
    denied: '거부',
    observed: '관측됨',
    available: '사용 가능',
    unavailable: '사용 불가',
    unknown: '상태 미확인',
  };
  const kind = kindLabels[entry.kind.toLowerCase()] ?? entry.kind.replace(/[-_]+/g, ' ');
  const status = statusLabels[entry.status.toLowerCase()] ?? entry.status.replace(/[-_]+/g, ' ');
  return `${kind} · ${status}`;
}

export interface OperationalLogViewProps {
  entries: OperationalLogEntry[];
  locale: MonitorLocale;
  compact?: boolean;
  category?: OperationalLogCategory | 'all';
}

export function OperationalLogView({ entries, locale, compact = false, category = 'all' }: OperationalLogViewProps) {
  const [query, setQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<OperationalLogCategory | 'all'>(category);
  const [selectedSeverity, setSelectedSeverity] = useState<OperationalLogSeverity | 'all'>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const filtered = useMemo(() => entries.filter((entry) => {
    if (selectedCategory !== 'all' && entry.category !== selectedCategory) return false;
    if (selectedSeverity !== 'all' && entry.severity !== selectedSeverity) return false;
    if (!normalizedQuery) return true;
    return [entry.title, entry.message, entry.kind, entry.status, entry.actor, entry.target]
      .some((value) => typeof value === 'string' && value.toLocaleLowerCase().includes(normalizedQuery));
  }), [entries, normalizedQuery, selectedCategory, selectedSeverity]);
  const shown = compact ? filtered.slice(0, 6) : filtered;

  return (
    <div className={`ops-log${compact ? ' ops-log-compact' : ''}`}>
      {!compact && (
        <div className="ops-log-controls" aria-label={localized(locale, '로그 필터', 'Log filters')}>
          <label className="ops-search">
            <span>{localized(locale, '로그 검색', 'Search logs')}</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={localized(locale, '상태, 메시지, 작업 검색', 'Search status, message, or action')}
            />
          </label>
          <label>
            <span>{localized(locale, '분류', 'Source')}</span>
            <select value={selectedCategory} onChange={(event) => setSelectedCategory(event.target.value as OperationalLogCategory | 'all')}>
              <option value="all">{localized(locale, '전체 분류', 'All sources')}</option>
              {CATEGORIES.map((value) => <option key={value} value={value}>{categoryLabel(value, locale)}</option>)}
            </select>
          </label>
          <label>
            <span>{localized(locale, '심각도', 'Severity')}</span>
            <select value={selectedSeverity} onChange={(event) => setSelectedSeverity(event.target.value as OperationalLogSeverity | 'all')}>
              <option value="all">{localized(locale, '전체 심각도', 'All severities')}</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{severityLabel(value, locale)}</option>)}
            </select>
          </label>
          <output>{localized(locale, `${filtered.length.toLocaleString()}건`, `${filtered.length.toLocaleString()} records`)}</output>
        </div>
      )}

      {shown.length ? (
        <ol className="ops-log-list">
          {shown.map((entry) => {
            const isExpanded = expanded === entry.id;
            const detailsId = `log-detail-${entry.id.replace(/[^a-zA-Z0-9_-]/g, '-')}`;
            return (
              <li key={entry.id} className={`ops-log-row severity-${entry.severity}`}>
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  aria-controls={detailsId}
                  onClick={() => setExpanded(isExpanded ? null : entry.id)}
                >
                  <span className="ops-log-symbol" aria-hidden="true">
                    {entry.severity === 'critical' ? '▲' : entry.severity === 'warning' ? '●' : 'i'}
                  </span>
                  <span className="ops-log-main">
                    <span className="ops-log-heading">
                      <strong>{localizedEventTitle(entry, locale)}</strong>
                      <span className={`severity-label severity-label-${entry.severity}`}>{severityLabel(entry.severity, locale)}</span>
                    </span>
                    <span className="ops-log-preview">{safeText(entry.message)}</span>
                  </span>
                  <time dateTime={entry.timestamp}>{formatDateTime(entry.timestamp, locale)}</time>
                  <Icon name="chevron" size={15} className={isExpanded ? 'chevron-open' : ''} />
                </button>
                {isExpanded && (
                  <div id={detailsId} className="ops-log-detail">
                    <dl>
                      <div><dt>{localized(locale, '분류', 'Source')}</dt><dd>{categoryLabel(entry.category, locale)}</dd></div>
                      <div><dt>{localized(locale, '종류', 'Kind')}</dt><dd>{entry.kind}</dd></div>
                      <div><dt>{localized(locale, '상태', 'Status')}</dt><dd>{entry.status}</dd></div>
                      <div><dt>{localized(locale, '시각', 'Timestamp')}</dt><dd>{entry.timestamp}</dd></div>
                      {entry.actor && <div><dt>{localized(locale, '행위자', 'Actor')}</dt><dd>{safeText(entry.actor)}</dd></div>}
                      {entry.target && <div><dt>{localized(locale, '대상', 'Target')}</dt><dd>{safeText(entry.target)}</dd></div>}
                    </dl>
                    <p>{safeText(entry.message)}</p>
                    <small>{localized(locale, '원문 명령·인자·자격 증명은 수집 단계에서 저장하지 않습니다.', 'Raw commands, arguments, and credentials are intentionally not collected.')}</small>
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <div className="ops-log-empty">
          <Icon name="check" size={22} />
          <strong>{localized(locale, '조건에 맞는 로그가 없습니다', 'No logs match these filters')}</strong>
          <span>{localized(locale, '기간이나 필터를 바꿔 확인하세요.', 'Change the time range or loosen the filters.')}</span>
        </div>
      )}
    </div>
  );
}
