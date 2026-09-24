import { useEffect, useState } from 'react';
import type { NotificationReportStatus } from '../notification-report-types';
import type { MonitorLocale } from '../types';
import { formatDateTime } from '../utils';
import './notification-status.css';

type Detection = NotificationReportStatus['detections'][number];

export function deliveryOutcomeLabel(outcome: string | null, locale: MonitorLocale): string {
  const t = (ko: string, en: string) => locale === 'ko' ? ko : en;
  if (outcome === null) return t('최근 결과 기록 없음', 'No recent outcome recorded');
  return ({
    leased: t('전송 중', 'Sending'),
    success: t('SMTP 접수 성공', 'Accepted by SMTP'),
    retry: t('재시도 예정', 'Retry scheduled'),
    permanent_failure: t('최종 실패', 'Final failure'),
    exhausted: t('재시도 소진', 'Retries exhausted'),
    lease_expired: t('작업 만료 후 재검토', 'Lease expired; awaiting retry'),
    dropped: t('큐 용량으로 제외', 'Dropped by queue limit'),
    evicted: t('우선순위 큐에서 제외', 'Evicted by queue priority'),
  } as Record<string, string>)[outcome] ?? t('확인 필요', 'Review required');
}

function DetectionTable({ rows, locale }: { rows: Detection[]; locale: MonitorLocale }) {
  const t = (ko: string, en: string) => locale === 'ko' ? ko : en;
  return <div className="evidence-table-scroll"><table className="evidence-table"><thead><tr><th>{t('시각', 'Time')}</th><th>{t('수준', 'Severity')}</th><th>{t('상태', 'State')}</th><th>{t('근거', 'Evidence')}</th></tr></thead><tbody>{rows.map(d => <tr key={d.id}><td>{formatDateTime(d.observedAt, locale)}</td><td>{d.severity === 'critical' ? t('위험', 'Critical') : d.severity === 'warning' ? t('주의', 'Warning') : t('정보', 'Info')}</td><td>{d.status === 'active' ? t('진행 중', 'Active') : t('해소', 'Resolved')}</td><td>{d.evidence}</td></tr>)}</tbody></table></div>;
}

export function NotificationReportView({ data, locale }: { data: NotificationReportStatus; locale: MonitorLocale }) {
  const t = (ko: string, en: string) => locale === 'ko' ? ko : en;
  const active = data.detections.filter(detection => detection.status === 'active');
  const resolved = data.detections.filter(detection => detection.status === 'resolved');
  const detectionLimitReached = data.detections.length >= 32;
  const label = data.stale && data.observedAt ? t('알림 상태 정보 지연', 'Notification status is stale')
    : data.status === 'ok' ? t('일일 보고 · 이상 징후 알림', 'Daily reports and incident alerts')
    : data.status === 'disabled' ? t('메일 전송 미설정', 'Email delivery is not configured')
    : data.status === 'error' ? t('알림 처리 오류', 'Notification processing error') : t('알림 상태 수집 대기', 'Waiting for notification status');
  const names: Record<string, string> = { snapshot: t('서버 상태', 'Host'), rules: t('경보 규칙', 'Rules'), ssh: 'SSH', http: 'HTTP' };
  return <section className="notification-status-panel" aria-label={t('메일 알림과 이상 징후', 'Email notifications and detections')}>
    <div className="evidence-panel-heading"><div><h2>{t('메일 알림과 이상 징후', 'Email notifications and detections')}</h2><p>{label}</p></div></div>
    <p>{t('KST 09:00 이후 첫 알림 처리 주기에 하루 한 번 상태 보고서를 큐에 넣습니다. 수집이 불완전하면 보고서에 관측 한계로 표시합니다. 동일 조건은 한 규칙만 메일을 소유하며, SSH 실패·거부는 서로 다른 로그 행이 5분에 5건 이상일 때 즉시 알립니다. 계정과 키 지문은 신뢰 판정에만 사용하고 화면·메일에 표시하지 않습니다. 이 징후는 침입 성공을 뜻하지 않습니다.', 'One daily report is queued on the first notification processing cycle after 09:00 KST; incomplete collection is reported as a coverage limitation. One canonical rule owns mail for each condition, and SSH failures or denials alert after five distinct log rows within five minutes. Account and key fingerprints are used only for trust decisions and are not shown in the dashboard or email. Suspicious activity does not establish a successful intrusion.')}</p>
    {data.observedAt && <p>{t('마지막 관측', 'Last observed')}: {formatDateTime(data.observedAt, locale)}</p>}
    {(data.status === 'ok' || data.status === 'disabled') && <>
      <p>{t('현재 대기·전송 중', 'Pending or sending')}: {data.delivery.pending} · {t('현재 재시도', 'Currently retrying')}: {data.delivery.retrying} · {t('누적 SMTP 접수', 'Cumulative SMTP accepted')}: {data.delivery.sent} · {t('누적 미전송 종료(최종 실패·큐 제외)', 'Cumulative undelivered terminal outcomes (final failure or queue exclusion)')}: {data.delivery.failed}</p>
      <p>{t('최근 전송 결과', 'Latest delivery outcome')}: {deliveryOutcomeLabel(data.delivery.lastOutcome, locale)}{data.delivery.lastAttemptAt ? ` · ${formatDateTime(data.delivery.lastAttemptAt, locale)}` : ''}</p>
      <p>{t('마지막 일일 보고 예약', 'Last daily report queued')}: {data.hourly.lastQueuedAt ? formatDateTime(data.hourly.lastQueuedAt, locale) : '—'}</p>
      <p>{t('대기·전송 중·재시도는 현재 큐 상태이고, 접수·미전송 종료는 누적값입니다. 미전송 종료에는 최종 실패와 큐 제외가 포함됩니다. SMTP 접수는 받은편지함 도착을 보장하지 않습니다.', 'Pending, sending, and retrying are current queue states; accepted and undelivered terminal outcomes are cumulative totals. Terminal outcomes include final failures and queue exclusions. SMTP acceptance does not confirm inbox delivery.')}</p>
    </>}
    {data.sourceHealth.length > 0 && <div className="evidence-table-scroll"><table className="evidence-table"><thead><tr><th>{t('감지 자료', 'Detection source')}</th><th>{t('관측 상태', 'Observation status')}</th><th>{t('설명', 'Detail')}</th></tr></thead><tbody>{data.sourceHealth.map(source => <tr key={source.source}><td>{names[source.source] ?? source.source}</td><td>{({ fresh: t('최신', 'Fresh'), stale: t('지연', 'Stale'), unavailable: t('수집 불가', 'Unavailable'), partial: t('일부만 관측', 'Partial') })[source.status] ?? source.status}</td><td>{source.detail}</td></tr>)}</tbody></table></div>}
    <h3>{t(`표시 중인 진행 사건 ${active.length}건`, `${active.length} displayed active detections`)}</h3>
    {detectionLimitReached && <p>{t('공개 목록 상한 32건에 도달했습니다. 진행 사건을 먼저 표시하며 전체 이력은 더 많을 수 있습니다.', 'The public list reached its 32-item limit. Active detections are shown first, and more history may exist.')}</p>}
    {active.length === 0 ? <p>{t('현재 진행 중으로 확인된 이상 징후가 없습니다. 수집 상태가 불완전하면 정상으로 단정할 수 없습니다.', 'No active detections are currently confirmed. Incomplete source coverage cannot establish a healthy state.')}</p>
      : <DetectionTable rows={active} locale={locale} />}
    {resolved.length > 0 && <details className="notification-history"><summary>{t(`보관된 최근 해소 이력 ${resolved.length}건`, `${resolved.length} retained resolved detections`)}</summary><DetectionTable rows={resolved} locale={locale} /></details>}
  </section>;
}

export function NotificationStatusPanel({ locale, onUnauthorized }: { locale: MonitorLocale; onUnauthorized: () => void }) {
  const [data, setData] = useState<NotificationReportStatus | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    async function refresh() {
      try {
        const response = await fetch('/monitor/api/notification-reports', { credentials: 'same-origin', signal: controller.signal, headers: { Accept: 'application/json' } });
        if (response.status === 401) { onUnauthorized(); return; }
        if (!response.ok) throw new Error('request failed');
        const value = await response.json() as NotificationReportStatus;
        if (!controller.signal.aborted) { setData(value); setError(false); }
      } catch { if (!controller.signal.aborted) setError(true); }
    }
    void refresh();
    const timer = window.setInterval(() => { if (!document.hidden) void refresh(); }, 60_000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [onUnauthorized]);
  return <>{error && <p role="alert">{locale === 'ko' ? '알림 상태를 새로 불러오지 못했습니다. 아래 정보는 마지막 조회 결과입니다.' : 'Could not refresh notification status. Any information below is from the last successful request.'}</p>}{data ? <NotificationReportView data={data} locale={locale} /> : <p>{locale === 'ko' ? '알림 상태 조회 중…' : 'Loading notification status…'}</p>}</>;
}
