import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  ApiError,
  getGenericLogs,
  type GenericLogCollectionStatus,
  type GenericLogPage,
  type GenericLogPriority,
  type GenericLogQuery,
  type GenericLogRecord,
  type GenericLogSeverity,
  type GenericLogSourceKind,
  type GenericLogSourceStatusValue,
} from '../api';
import { localized } from '../dashboard-model';
import type { MonitorLocale } from '../types';
import { formatDateTime } from '../utils';
import './generic-log-explorer.css';

const PAGE_SIZE = 50;
const EMPTY_QUERY: GenericLogQuery = { limit: PAGE_SIZE };

const SOURCE_KINDS: GenericLogSourceKind[] = ['docker', 'file', 'journald'];
const PRIORITIES: GenericLogPriority[] = ['debug', 'normal', 'incident', 'security'];
const SEVERITIES: GenericLogSeverity[] = [
  'trace', 'debug', 'info', 'notice', 'warning', 'error', 'critical',
];

export interface GenericLogFilterDraft {
  text: string;
  sourceId: string;
  sourceKind: GenericLogSourceKind | '';
  priority: GenericLogPriority | '';
  severity: GenericLogSeverity | '';
  from: string;
  to: string;
}

export const EMPTY_GENERIC_LOG_FILTERS: GenericLogFilterDraft = {
  text: '',
  sourceId: '',
  sourceKind: '',
  priority: '',
  severity: '',
  from: '',
  to: '',
};

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function localTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error('invalid_time');
  return parsed.toISOString();
}

export function genericLogQueryFromDraft(draft: GenericLogFilterDraft): GenericLogQuery {
  const text = draft.text.trim();
  if (new TextEncoder().encode(text).byteLength > 128) throw new Error('invalid_text');
  const from = localTimestamp(draft.from);
  const to = localTimestamp(draft.to);
  if (from && to && from > to) throw new Error('invalid_time_order');
  return {
    limit: PAGE_SIZE,
    ...(text ? { text } : {}),
    ...(draft.sourceId ? { sourceIds: [draft.sourceId] } : {}),
    ...(draft.sourceKind ? { sourceKinds: [draft.sourceKind] } : {}),
    ...(draft.priority ? { priorities: [draft.priority] } : {}),
    ...(draft.severity ? { severities: [draft.severity] } : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
  };
}

function withoutCursor(query: GenericLogQuery): GenericLogQuery {
  const { cursor: _cursor, ...rest } = query;
  return rest;
}

export interface GenericLogRequestQueries {
  applied: GenericLogQuery;
  lastAttempted: GenericLogQuery;
  lastAttemptedAppend: boolean;
}

export function beginGenericLogQueryRequest(
  current: GenericLogRequestQueries,
  requested: GenericLogQuery,
  append: boolean,
): GenericLogRequestQueries {
  if (append) {
    return { ...current, lastAttempted: requested, lastAttemptedAppend: true };
  }
  return {
    ...current,
    lastAttempted: withoutCursor(requested),
    lastAttemptedAppend: false,
  };
}

export function completeGenericLogQueryRequest(
  current: GenericLogRequestQueries,
  requested: GenericLogQuery,
  append: boolean,
): GenericLogRequestQueries {
  if (append) return current;
  const applied = withoutCursor(requested);
  return { applied, lastAttempted: applied, lastAttemptedAppend: false };
}

export function mergeGenericLogPages(
  current: GenericLogPage | null,
  incoming: GenericLogPage,
  append: boolean,
): GenericLogPage {
  if (!append || current === null) return incoming;
  if (incoming.page.cursorStatus === 'stale') {
    return {
      ...current,
      generatedAt: incoming.generatedAt,
      collection: incoming.collection,
      page: {
        ...current.page,
        nextCursor: null,
        cursorStatus: 'stale',
      },
    };
  }
  const items = [...current.items, ...incoming.items];
  return {
    ...incoming,
    items,
    page: {
      ...incoming.page,
      returned: items.length,
    },
  };
}

function sourceKindLabel(value: GenericLogSourceKind, locale: MonitorLocale): string {
  const labels: Record<GenericLogSourceKind, [string, string]> = {
    docker: ['Docker', 'Docker'],
    file: ['파일', 'File'],
    journald: ['Journald', 'Journald'],
  };
  return t(locale, ...labels[value]);
}

function priorityLabel(value: GenericLogPriority, locale: MonitorLocale): string {
  const labels: Record<GenericLogPriority, [string, string]> = {
    debug: ['디버그', 'Debug'],
    normal: ['일반', 'Normal'],
    incident: ['사건', 'Incident'],
    security: ['보안', 'Security'],
  };
  return t(locale, ...labels[value]);
}

function severityLabel(value: GenericLogSeverity, locale: MonitorLocale): string {
  const labels: Record<GenericLogSeverity, [string, string]> = {
    trace: ['추적', 'Trace'],
    debug: ['디버그', 'Debug'],
    info: ['정보', 'Info'],
    notice: ['알림', 'Notice'],
    warning: ['경고', 'Warning'],
    error: ['오류', 'Error'],
    critical: ['치명적', 'Critical'],
  };
  return t(locale, ...labels[value]);
}

function sourceStatusLabel(value: GenericLogSourceStatusValue, locale: MonitorLocale): string {
  const labels: Record<GenericLogSourceStatusValue, [string, string]> = {
    fresh: ['최신', 'Current'],
    no_data: ['데이터 없음', 'No data'],
    truncated: ['일부 생략', 'Truncated'],
    unsupported: ['미지원', 'Unsupported'],
    permission_denied: ['권한 거부', 'Permission denied'],
    failed: ['실패', 'Failed'],
  };
  return t(locale, ...labels[value]);
}

function collectionSummary(status: GenericLogCollectionStatus, locale: MonitorLocale): {
  title: string;
  detail: string;
  tone: 'good' | 'caution' | 'danger' | 'neutral';
} {
  const summaries: Record<GenericLogCollectionStatus, {
    ko: [string, string];
    en: [string, string];
    tone: 'good' | 'caution' | 'danger' | 'neutral';
  }> = {
    fresh: {
      ko: ['로그 수집 최신', '모든 구성된 원본이 현재 상태입니다.'],
      en: ['Log collection current', 'All configured sources are current.'],
      tone: 'good',
    },
    degraded: {
      ko: ['일부 로그 원본 확인 필요', '실패하거나 일부 생략된 입력을 원본 상태에서 확인하세요.'],
      en: ['Some log sources need attention', 'Check source status for failed or truncated inputs.'],
      tone: 'caution',
    },
    stale: {
      ko: ['로그 수집 지연', '최근 수집 시각이 허용 범위를 지났습니다.'],
      en: ['Log collection delayed', 'The most recent collection is outside the accepted age.'],
      tone: 'caution',
    },
    no_data: {
      ko: ['수집된 로그 없음', '아직 저장소에 승인된 로그가 없습니다.'],
      en: ['No collected logs', 'No records have been admitted to the store yet.'],
      tone: 'neutral',
    },
    unsupported: {
      ko: ['로그 수집 미지원', '이 호스트에서 구성된 로그 원본을 수집할 수 없습니다.'],
      en: ['Log collection unsupported', 'The configured log sources cannot be collected on this host.'],
      tone: 'neutral',
    },
    collection_error: {
      ko: ['로그 수집 오류', '수집기 출력과 공개 파일 권한을 확인하세요.'],
      en: ['Log collection error', 'Check collector output and public-file permissions.'],
      tone: 'danger',
    },
  };
  const summary = summaries[status];
  const [title, detail] = locale === 'ko' ? summary.ko : summary.en;
  return { title, detail, tone: summary.tone };
}

function validationMessage(code: string, locale: MonitorLocale): string {
  if (code === 'invalid_text') {
    return t(locale, '검색 문구는 UTF-8 기준 128바이트 이하여야 합니다.', 'Search text must be 128 UTF-8 bytes or fewer.');
  }
  if (code === 'invalid_time_order') {
    return t(locale, '시작 시각은 종료 시각보다 늦을 수 없습니다.', 'Start time cannot be later than end time.');
  }
  return t(locale, '유효한 날짜와 시각을 입력하세요.', 'Enter a valid date and time.');
}

function emptyResultCopy(status: GenericLogCollectionStatus, locale: MonitorLocale): [string, string] {
  if (status === 'collection_error') {
    return [
      t(locale, '수집 오류로 로그를 표시할 수 없습니다.', 'Logs are unavailable because collection failed.'),
      t(locale, '수집기 출력과 공개 파일 권한을 확인하세요.', 'Check collector output and public-file permissions.'),
    ];
  }
  if (status === 'unsupported') {
    return [
      t(locale, '이 호스트에서는 로그 수집을 지원하지 않습니다.', 'Log collection is not supported on this host.'),
      t(locale, '위의 원본 상태에서 미지원 입력을 확인하세요.', 'Review unsupported inputs in source status above.'),
    ];
  }
  if (status === 'no_data') {
    return [
      t(locale, '아직 수집된 로그가 없습니다.', 'No logs have been collected yet.'),
      t(locale, '수집 상태와 구성된 원본을 확인하세요.', 'Check collection status and configured sources.'),
    ];
  }
  return [
    t(locale, '조건에 맞는 로그가 없습니다.', 'No logs match the current filters.'),
    t(locale, '검색 문구, 기간 또는 필터를 조정하세요.', 'Adjust the search text, time range, or filters.'),
  ];
}

function requestErrorMessage(error: unknown, locale: MonitorLocale): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return t(locale, '로그를 불러오지 못했습니다.', 'Could not load logs.');
}

function recordDetailEntries(record: GenericLogRecord, locale: MonitorLocale): Array<[string, string]> {
  const entries: Array<[string, string | null]> = [
    [t(locale, '발생 시각', 'Event time'), record.timestamp],
    [t(locale, '관측 시각', 'Observed time'), record.observedAt],
    [t(locale, '시각 원본', 'Timestamp source'), record.timestampSource],
    [t(locale, '원본', 'Source'), record.sourceId],
    [t(locale, '원본 종류', 'Source kind'), record.sourceKind],
    [t(locale, '우선순위', 'Priority'), record.priority],
    [t(locale, '심각도', 'Severity'), record.severity],
    [t(locale, '파서', 'Parser'), record.parser],
    [t(locale, '호스트 ID', 'Host ID'), record.hostId],
    [t(locale, '컨테이너', 'Container'), record.containerName],
    [t(locale, 'Compose 프로젝트', 'Compose project'), record.composeProject],
    [t(locale, 'Compose 서비스', 'Compose service'), record.composeService],
    [t(locale, '프로세스', 'Process'), record.processName],
    [t(locale, 'Systemd 유닛', 'Systemd unit'), record.systemdUnit],
    [t(locale, '스트림', 'Stream'), record.stream],
    [t(locale, '줄 수', 'Line count'), String(record.multilineLineCount)],
  ];
  return entries.filter((entry): entry is [string, string] => entry[1] !== null);
}

export interface GenericLogExplorerProps {
  locale: MonitorLocale;
  onUnauthorized: () => void;
}

export function GenericLogExplorer({ locale, onUnauthorized }: GenericLogExplorerProps) {
  const [draft, setDraft] = useState<GenericLogFilterDraft>(EMPTY_GENERIC_LOG_FILTERS);
  const [requestQueries, setRequestQueries] = useState<GenericLogRequestQueries>({
    applied: EMPTY_QUERY,
    lastAttempted: EMPTY_QUERY,
    lastAttemptedAppend: false,
  });
  const [data, setData] = useState<GenericLogPage | null>(null);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [loadingMode, setLoadingMode] = useState<'replace' | 'append' | null>('replace');
  const requestController = useRef<AbortController | null>(null);
  const localeRef = useRef(locale);
  localeRef.current = locale;

  const requestPage = useCallback(async (query: GenericLogQuery, append = false) => {
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setLoadingMode(append ? 'append' : 'replace');
    setRequestError(null);
    if (!append) setExpandedIndex(null);
    setRequestQueries((current) => beginGenericLogQueryRequest(current, query, append));
    try {
      const result = await getGenericLogs(query, controller.signal);
      if (controller.signal.aborted) return;
      setData((current) => mergeGenericLogPages(current, result, append));
      setRequestQueries((current) => completeGenericLogQueryRequest(current, query, append));
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return;
      if (error instanceof ApiError && error.status === 401) {
        onUnauthorized();
        return;
      }
      setRequestError(requestErrorMessage(error, localeRef.current));
    } finally {
      if (requestController.current === controller) {
        requestController.current = null;
        setLoadingMode(null);
      }
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void requestPage(EMPTY_QUERY);
    return () => requestController.current?.abort();
  }, [requestPage]);

  const sourceIds = useMemo(() => {
    const values = new Set(data?.collection.sources.map((source) => source.sourceId) ?? []);
    if (draft.sourceId) values.add(draft.sourceId);
    return [...values].sort((left, right) => left.localeCompare(right));
  }, [data?.collection.sources, draft.sourceId]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const query = genericLogQueryFromDraft(draft);
      setValidationError(null);
      void requestPage(query);
    } catch (error) {
      setValidationError(validationMessage(error instanceof Error ? error.message : 'invalid_time', locale));
    }
  }

  function clearFilters() {
    setDraft(EMPTY_GENERIC_LOG_FILTERS);
    setValidationError(null);
    void requestPage(EMPTY_QUERY);
  }

  const collection = data ? collectionSummary(data.collection.status, locale) : null;
  const activeFilterCount = Object.values(draft).filter(Boolean).length;
  const {
    applied: appliedQuery,
    lastAttempted: lastAttemptedQuery,
    lastAttemptedAppend,
  } = requestQueries;
  const appliedFilterCount = [
    appliedQuery.text,
    appliedQuery.from,
    appliedQuery.to,
    ...(appliedQuery.sourceIds ?? []),
    ...(appliedQuery.sourceKinds ?? []),
    ...(appliedQuery.priorities ?? []),
    ...(appliedQuery.severities ?? []),
  ].filter(Boolean).length;
  const loading = loadingMode !== null;

  return (
    <section className="generic-log-explorer" aria-labelledby="generic-log-title" aria-busy={loading}>
      <header className="generic-log-heading">
        <div>
          <h2 id="generic-log-title">{t(locale, '일반 로그 검색', 'Search generic logs')}</h2>
          <p>{t(locale, '정규화되고 저장 전에 민감정보가 제거된 로그를 조회합니다.', 'Query normalized logs that are redacted before storage.')}</p>
        </div>
        <button
          className="generic-log-refresh"
          type="button"
          onClick={() => void requestPage(
            requestError ? lastAttemptedQuery : appliedQuery,
            requestError ? lastAttemptedAppend : false,
          )}
          disabled={loading}
        >
          {loadingMode === 'replace' && data
            ? t(locale, '새로 고치는 중…', 'Refreshing…')
            : t(locale, '새로 고침', 'Refresh')}
        </button>
      </header>

      <form className="generic-log-filters" role="search" aria-label={t(locale, '일반 로그 필터', 'Generic log filters')} onSubmit={applyFilters}>
        <div className="generic-log-primary-filter">
          <label htmlFor="generic-log-text">{t(locale, '메시지 또는 메타데이터 검색', 'Search message or metadata')}</label>
          <div>
            <input
              id="generic-log-text"
              type="search"
              value={draft.text}
              onChange={(event) => setDraft((current) => ({ ...current, text: event.target.value }))}
              placeholder={t(locale, '메시지, 서비스, 프로세스…', 'Message, service, process…')}
              autoComplete="off"
              maxLength={128}
            />
            <button type="submit" disabled={loading}>{t(locale, '검색', 'Search')}</button>
          </div>
        </div>

        <div className="generic-log-facet-grid">
          <label>
            <span>{t(locale, '원본', 'Source')}</span>
            <select value={draft.sourceId} onChange={(event) => setDraft((current) => ({ ...current, sourceId: event.target.value }))}>
              <option value="">{t(locale, '모든 원본', 'All sources')}</option>
              {sourceIds.map((sourceId) => <option key={sourceId} value={sourceId}>{sourceId}</option>)}
            </select>
          </label>
          <label>
            <span>{t(locale, '원본 종류', 'Source kind')}</span>
            <select value={draft.sourceKind} onChange={(event) => setDraft((current) => ({ ...current, sourceKind: event.target.value as GenericLogSourceKind | '' }))}>
              <option value="">{t(locale, '모든 종류', 'All kinds')}</option>
              {SOURCE_KINDS.map((value) => <option key={value} value={value}>{sourceKindLabel(value, locale)}</option>)}
            </select>
          </label>
          <label>
            <span>{t(locale, '우선순위', 'Priority')}</span>
            <select value={draft.priority} onChange={(event) => setDraft((current) => ({ ...current, priority: event.target.value as GenericLogPriority | '' }))}>
              <option value="">{t(locale, '모든 우선순위', 'All priorities')}</option>
              {PRIORITIES.map((value) => <option key={value} value={value}>{priorityLabel(value, locale)}</option>)}
            </select>
          </label>
          <label>
            <span>{t(locale, '심각도', 'Severity')}</span>
            <select value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value as GenericLogSeverity | '' }))}>
              <option value="">{t(locale, '모든 심각도', 'All severities')}</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{severityLabel(value, locale)}</option>)}
            </select>
          </label>
          <label>
            <span>{t(locale, '시작 시각', 'Start time')}</span>
            <input type="datetime-local" value={draft.from} onChange={(event) => setDraft((current) => ({ ...current, from: event.target.value }))} />
          </label>
          <label>
            <span>{t(locale, '종료 시각', 'End time')}</span>
            <input type="datetime-local" value={draft.to} onChange={(event) => setDraft((current) => ({ ...current, to: event.target.value }))} />
          </label>
        </div>

        <div className="generic-log-filter-actions">
          <span>{t(locale, '날짜·시각은 현재 브라우저 시간대를 사용합니다.', 'Dates and times use the current browser time zone.')}</span>
          <button type="button" onClick={clearFilters} disabled={loading || (activeFilterCount === 0 && appliedFilterCount === 0)}>
            {t(locale, '필터 초기화', 'Clear filters')}
          </button>
          <button type="submit" disabled={loading}>{t(locale, '필터 적용', 'Apply filters')}</button>
        </div>
      </form>

      {validationError && <div className="generic-log-notice generic-log-notice-danger" role="alert">{validationError}</div>}
      {requestError && (
        <div className="generic-log-notice generic-log-notice-danger" role="alert">
          <span>{requestError}</span>
          <button type="button" onClick={() => void requestPage(lastAttemptedQuery, lastAttemptedAppend)} disabled={loading}>{t(locale, '다시 시도', 'Try again')}</button>
        </div>
      )}

      {collection && data && (
        <div className={`generic-log-collection generic-log-tone-${collection.tone}`}>
          <div role="status">
            <strong>{collection.title}</strong>
            <span>{collection.detail}</span>
            {data.collection.observedAt && <time dateTime={data.collection.observedAt}>{formatDateTime(data.collection.observedAt, locale)}</time>}
          </div>
          <details>
            <summary>{t(locale, `원본 상태 ${data.collection.sources.length}개`, `${data.collection.sources.length} source statuses`)}</summary>
            {data.collection.sources.length ? (
              <ul>
                {data.collection.sources.map((source) => (
                  <li key={`${source.sourceKind}:${source.sourceId}`}>
                    <div><strong>{source.sourceId}</strong><span>{sourceKindLabel(source.sourceKind, locale)}</span></div>
                    <span className={`generic-log-source-status source-status-${source.status}`}>{sourceStatusLabel(source.status, locale)}</span>
                    <dl>
                      <div><dt>{t(locale, '승인', 'Admitted')}</dt><dd>{source.admittedEvents.toLocaleString()}</dd></div>
                      <div><dt>{t(locale, '누락', 'Dropped')}</dt><dd>{source.droppedLines.toLocaleString()}</dd></div>
                      {source.errorClass && <div><dt>{t(locale, '오류', 'Error')}</dt><dd>{source.errorClass}</dd></div>}
                    </dl>
                  </li>
                ))}
              </ul>
            ) : <p>{t(locale, '보고된 원본 상태가 없습니다.', 'No source status was reported.')}</p>}
          </details>
        </div>
      )}

      {loadingMode === 'replace' && !data ? (
        <div className="generic-log-state" role="status">{t(locale, '로그를 불러오는 중…', 'Loading logs…')}</div>
      ) : data ? (
        <div className="generic-log-results">
          <div className="generic-log-result-summary" role="status" aria-live="polite">
            <strong>{t(locale, '검색 결과', 'Results')}</strong>
            <span>{t(locale, `${data.items.length.toLocaleString()} / ${data.page.total.toLocaleString()}건 표시`, `${data.items.length.toLocaleString()} of ${data.page.total.toLocaleString()} records shown`)}</span>
          </div>

          {data.page.cursorStatus === 'stale' && (
            <div className="generic-log-notice generic-log-notice-caution" role="alert">
              <span>{t(locale, '새 로그가 추가되어 다음 페이지 기준이 만료되었습니다.', 'New logs changed the result set, so the next-page cursor expired.')}</span>
              <button type="button" onClick={() => void requestPage(appliedQuery)} disabled={loading}>{t(locale, '처음부터 새로 고침', 'Refresh from the start')}</button>
            </div>
          )}

          {data.items.length ? (
            <ol className="generic-log-list">
              {data.items.map((record, index) => {
                const expanded = expandedIndex === index;
                const detailId = `generic-log-detail-${index}`;
                const fields = Object.entries(record.fields);
                return (
                  <li key={`${record.timestamp}:${record.sourceId}:${index}`} className={`generic-log-record severity-${record.severity}`}>
                    <button type="button" aria-expanded={expanded} aria-controls={detailId} onClick={() => setExpandedIndex(expanded ? null : index)}>
                      <span className={`generic-log-severity severity-${record.severity}`}>{severityLabel(record.severity, locale)}</span>
                      <span className="generic-log-record-main">
                        <strong>{record.message}</strong>
                        <span>{record.sourceId} · {priorityLabel(record.priority, locale)}{record.truncated ? ` · ${t(locale, '일부 생략', 'truncated')}` : ''}</span>
                      </span>
                      <time dateTime={record.timestamp}>{formatDateTime(record.timestamp, locale)}</time>
                      <span aria-hidden="true">{expanded ? '−' : '+'}</span>
                    </button>
                    {expanded && (
                      <div id={detailId} className="generic-log-record-detail">
                        <p>{record.message}</p>
                        <dl className="generic-log-metadata">
                          {recordDetailEntries(record, locale).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
                        </dl>
                        {fields.length > 0 && (
                          <section aria-label={t(locale, '구조화 필드', 'Structured fields')}>
                            <h3>{t(locale, '구조화 필드', 'Structured fields')}</h3>
                            <dl>{fields.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value === null ? 'null' : String(value)}</dd></div>)}</dl>
                          </section>
                        )}
                        <small>{t(locale, '표시된 값은 저장 전에 민감정보가 제거되었습니다.', 'Displayed values were redacted before storage.')}</small>
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          ) : (
            <div className="generic-log-state">
              <strong>{emptyResultCopy(data.collection.status, locale)[0]}</strong>
              <span>{emptyResultCopy(data.collection.status, locale)[1]}</span>
            </div>
          )}

          {data.page.nextCursor && data.page.cursorStatus === 'current' && (
            <div className="generic-log-load-more">
              <button
                type="button"
                onClick={() => void requestPage({ ...appliedQuery, cursor: data.page.nextCursor ?? undefined }, true)}
                disabled={loading}
              >
                {loadingMode === 'append' ? t(locale, '더 불러오는 중…', 'Loading more…') : t(locale, '다음 로그 불러오기', 'Load more logs')}
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="generic-log-state generic-log-state-error">
          <strong>{t(locale, '로그를 표시할 수 없습니다.', 'Logs are unavailable.')}</strong>
          <button type="button" onClick={() => void requestPage(
            requestError ? lastAttemptedQuery : appliedQuery,
            requestError ? lastAttemptedAppend : false,
          )} disabled={loading}>{t(locale, '다시 시도', 'Try again')}</button>
        </div>
      )}
    </section>
  );
}
