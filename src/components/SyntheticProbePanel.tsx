import { useMemo } from 'react';
import { localized } from '../dashboard-model';
import type { DashboardPayload, MonitorLocale, SyntheticProbeResult } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';
import { Pagination, paginateItems, usePagination } from './Pagination';
import './monitoring-evidence.css';

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function statusLabel(status: SyntheticProbeResult['status'], locale: MonitorLocale): string {
  const labels: Record<SyntheticProbeResult['status'], [string, string]> = {
    ok: ['정상', 'OK'],
    dns: ['DNS 실패', 'DNS failure'],
    permission: ['권한 오류', 'Permission error'],
    timeout: ['시간 초과', 'Timeout'],
    tls: ['TLS 실패', 'TLS failure'],
    http: ['HTTP 실패', 'HTTP failure'],
    invalid: ['잘못된 결과', 'Invalid result'],
    unsupported: ['지원 안 됨', 'Unsupported'],
  };
  return t(locale, ...labels[status]);
}

function collectionLabel(
  status: NonNullable<DashboardPayload['syntheticProbeCollection']>['status'],
  locale: MonitorLocale,
): string {
  const labels: Record<NonNullable<DashboardPayload['syntheticProbeCollection']>['status'], [string, string]> = {
    fresh: ['최신', 'Fresh'],
    stale: ['지연', 'Stale'],
    unsupported: ['지원 안 됨', 'Unsupported'],
    'permission-denied': ['권한 거부', 'Permission denied'],
    unavailable: ['수집 불가', 'Unavailable'],
    'collection-error': ['수집 오류', 'Collection error'],
  };
  return t(locale, ...labels[status]);
}

function resultTone(status: SyntheticProbeResult['status']): 'ok' | 'caution' | 'danger' {
  if (status === 'ok') return 'ok';
  if (status === 'unsupported') return 'caution';
  return 'danger';
}

function number(value: number | null | undefined, suffix = ''): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toLocaleString()}${suffix}` : '—';
}

export function SyntheticProbePanel({ data, locale }: { data: DashboardPayload; locale: MonitorLocale }) {
  const collection = data.syntheticProbeCollection ?? { status: 'unavailable' as const, observedAt: null };
  const probes = useMemo(
    () => [...(data.syntheticProbes ?? [])].sort((left, right) => left.id.localeCompare(right.id)),
    [data.syntheticProbes],
  );
  const signature = useMemo(() => probes.map((probe) => `${probe.id}:${probe.checkedAt}`).join('\u001f'), [probes]);
  const pagination = usePagination({ totalItems: probes.length, pageSize: 10, resetKey: signature });
  const visible = paginateItems(probes, pagination);
  const failed = probes.filter((probe) => probe.status !== 'ok').length;

  return (
    <article id="synthetic-probes" tabIndex={-1} className="cockpit-panel synthetic-probe-panel">
      <header className="cockpit-panel-header">
        <span className="cockpit-panel-icon"><Icon name="network" size={19} /></span>
        <div>
          <h2>{t(locale, '외부 HTTP·TLS 합성 검사', 'External HTTP and TLS probes')}</h2>
          <p>{t(locale, '5분마다 외부 경로를 확인한 최신 결과 1개입니다. URL과 인증정보는 저장하지 않습니다.', 'The latest replace-only result checks the external path every five minutes; URLs and credentials are not retained.')}</p>
        </div>
        <span className={`cockpit-panel-badge ${failed ? 'probe-badge-danger' : ''}`}>{failed ? `${failed} ${t(locale, '실패', 'failed')}` : `${probes.length} OK`}</span>
      </header>
      <div className={`synthetic-collection-state collection-${collection.status}`} role={collection.status === 'fresh' ? 'status' : 'alert'}>
        <span>{t(locale, '수집 상태', 'Collection')}</span>
        <strong>{collectionLabel(collection.status, locale)}</strong>
        <time dateTime={collection.observedAt ?? undefined}>{collection.observedAt ? formatDateTime(collection.observedAt, locale) : '—'}</time>
      </div>
      {visible.length ? (
        <>
          <div className="cockpit-table-wrap synthetic-probe-table-wrap">
            <table className="cockpit-table synthetic-probe-table">
              <thead><tr><th>{t(locale, '검사', 'Probe')}</th><th>{t(locale, '상태', 'Status')}</th><th>HTTP</th><th>{t(locale, '지연', 'Latency')}</th><th>{t(locale, '리다이렉트', 'Redirects')}</th><th>{t(locale, '인증서 남은 날', 'Certificate left')}</th><th>{t(locale, '확인 시각', 'Checked')}</th></tr></thead>
              <tbody>{visible.map((probe) => (
                <tr key={probe.id}>
                  <td><strong>{safeText(probe.id, t(locale, '이름 없음', 'Unnamed probe'), 64)}</strong></td>
                  <td><span className={`status-token status-${resultTone(probe.status)}`}>{statusLabel(probe.status, locale)}</span></td>
                  <td>{number(probe.httpStatus)}</td>
                  <td>{number(probe.latencyMilliseconds, ' ms')}</td>
                  <td>{number(probe.redirectCount)}</td>
                  <td>{number(probe.certificateDaysRemaining, t(locale, '일', ' d'))}{probe.certificateExpiresAt ? <small>{formatDateTime(probe.certificateExpiresAt, locale)}</small> : null}</td>
                  <td><time dateTime={probe.checkedAt}>{formatDateTime(probe.checkedAt, locale)}</time></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <Pagination
            model={pagination}
            locale={locale}
            onPageChange={pagination.setPage}
            ariaLabel={t(locale, '합성 검사 결과 페이지', 'Synthetic probe result pages')}
            itemLabel={t(locale, '개 검사', 'probes')}
          />
        </>
      ) : <div className="detail-positive-empty">{collection.status === 'unsupported' ? t(locale, '이 환경에서는 합성 검사를 지원하지 않습니다.', 'Synthetic probes are not supported in this environment.') : t(locale, '저장된 합성 검사 결과가 없습니다.', 'No synthetic probe result is available.')}</div>}
    </article>
  );
}
