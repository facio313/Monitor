import { useEffect, useState } from 'react';
import type { NotificationReportStatus } from '../notification-report-types';
import type { MonitorLocale } from '../types';
import { formatDateTime } from '../utils';
import './notification-status.css';

export function NotificationReportView({ data, locale }: { data: NotificationReportStatus; locale: MonitorLocale }) {
  const t = (ko: string, en: string) => locale === 'ko' ? ko : en;
  const label = data.stale && data.observedAt ? t('알림 상태 정보 지연', 'Notification status is stale')
    : data.status === 'ok' ? t('시간별 보고 · 이상 징후 알림', 'Hourly reports and incident alerts')
    : data.status === 'disabled' ? t('메일 전송 미설정', 'Email delivery is not configured')
    : data.status === 'error' ? t('알림 처리 오류', 'Notification processing error') : t('알림 상태 수집 대기', 'Waiting for notification status');
  const names: Record<string, string> = { snapshot: t('서버 상태', 'Host'), rules: t('경보 규칙', 'Rules'), ssh: 'SSH', http: 'HTTP' };
  return <section className="notification-status-panel" aria-label={t('메일 알림과 이상 징후', 'Email notifications and detections')}>
    <div className="evidence-panel-heading"><div><h2>{t('메일 알림과 이상 징후', 'Email notifications and detections')}</h2><p>{label}</p></div></div>
    <p>{t('매시간 상태 보고서를 보내고, 새 주의·위험·의심 접근 또는 반복 패턴을 수집하면 다음 전송 주기에 알립니다. 의심 징후는 침입 성공을 뜻하지 않습니다.', 'Reports run hourly. New warnings, critical conditions, suspicious access and repeated patterns are queued for the next delivery cycle. Suspicious activity does not establish a successful intrusion.')}</p>
    {data.observedAt && <p>{t('마지막 관측', 'Last observed')}: {formatDateTime(data.observedAt, locale)}</p>}
    {data.status === 'ok' && <>
      <p>{t('SMTP 접수 완료', 'Accepted by SMTP')}: {data.delivery.sent} · {t('대기', 'Pending')}: {data.delivery.pending} · {t('재시도', 'Retrying')}: {data.delivery.retrying} · {t('실패', 'Failed')}: {data.delivery.failed}</p>
      <p>{t('마지막 시간별 보고 예약', 'Last hourly report queued')}: {data.hourly.lastQueuedAt ? formatDateTime(data.hourly.lastQueuedAt, locale) : '—'}{data.delivery.lastAttemptAt ? ` · ${t('최근 전송 시도', 'Last attempt')}: ${formatDateTime(data.delivery.lastAttemptAt, locale)}` : ''}</p>
      <p>{t('대기 건수는 발송 완료가 아니며, SMTP 접수 후에도 받은편지함 도착은 수신 메일 서비스에 따라 달라집니다.', 'Queued items have not yet been sent. SMTP acceptance does not confirm inbox delivery.')}</p>
    </>}
    {data.sourceHealth.length > 0 && <div className="evidence-table-scroll"><table className="evidence-table"><thead><tr><th>{t('감지 자료', 'Detection source')}</th><th>{t('관측 상태', 'Observation status')}</th><th>{t('설명', 'Detail')}</th></tr></thead><tbody>{data.sourceHealth.map(source => <tr key={source.source}><td>{names[source.source] ?? source.source}</td><td>{({ fresh: t('최신', 'Fresh'), stale: t('지연', 'Stale'), unavailable: t('수집 불가', 'Unavailable'), partial: t('일부만 관측', 'Partial') })[source.status] ?? source.status}</td><td>{source.detail}</td></tr>)}</tbody></table></div>}
    <h3>{t('최근 이상 징후', 'Recent detections')}</h3>
    {data.detections.length === 0 ? <p>{t('저장된 이상 징후가 없습니다. 위 자료의 관측 상태도 함께 확인하세요.', 'No stored detections. Also review source availability above.')}</p>
      : <div className="evidence-table-scroll"><table className="evidence-table"><thead><tr><th>{t('시각', 'Time')}</th><th>{t('수준', 'Severity')}</th><th>{t('상태', 'State')}</th><th>{t('근거', 'Evidence')}</th></tr></thead><tbody>{data.detections.map(d => <tr key={d.id}><td>{formatDateTime(d.observedAt, locale)}</td><td>{d.severity === 'critical' ? t('위험', 'Critical') : d.severity === 'warning' ? t('주의', 'Warning') : t('정보', 'Info')}</td><td>{d.status === 'active' ? t('진행 중', 'Active') : t('해소', 'Resolved')}</td><td>{d.evidence}</td></tr>)}</tbody></table></div>}
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
