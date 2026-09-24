import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { NotificationReportStatus } from '../notification-report-types';
import { deliveryOutcomeLabel, NotificationReportView } from './NotificationStatusPanel';

function fixture(): NotificationReportStatus {
  return { schemaVersion: 1, observedAt: '2026-09-13T08:00:00Z', stale: false, status: 'ok', hourly: { slot: null, lastQueuedAt: null, enqueued: 1, deduplicated: 0, dropped: 0 }, immediate: { enqueued: 1, deduplicated: 0, dropped: 0 }, delivery: { pending: 1, retrying: 0, sent: 0, failed: 0, lastAttemptAt: null, lastOutcome: null }, sourceHealth: [{ source: 'ssh', status: 'unavailable', observedAt: null, detail: 'SSH 자료 없음' }], detections: [] };
}
describe('notification status presentation', () => {
  it('shows delivery limits and missing detection coverage rather than claiming successful mail or safety', () => {
    const markup = renderToStaticMarkup(createElement(NotificationReportView, { data: fixture(), locale: 'en' }));
    expect(markup).toContain('Cumulative SMTP accepted');
    expect(markup).toContain('Pending or sending');
    expect(markup).toContain('Daily reports and incident alerts');
    expect(markup).toContain('first notification processing cycle after 09:00 KST');
    expect(markup).toContain('reported as a coverage limitation');
    expect(markup).toContain('Last daily report queued');
    expect(markup).toContain('current queue states');
    expect(markup).not.toContain('Reports run hourly');
    expect(markup).toContain('Unavailable');
    expect(markup).toContain('does not establish a successful intrusion');
  });
  it('prominently distinguishes disabled delivery and stale snapshots', () => {
    expect(renderToStaticMarkup(createElement(NotificationReportView, { data: { ...fixture(), status: 'disabled' }, locale: 'ko' }))).toContain('메일 전송 미설정');
    expect(renderToStaticMarkup(createElement(NotificationReportView, { data: { ...fixture(), stale: true }, locale: 'en' }))).toContain('Notification status is stale');
  });
  it('labels the compatible hourly field as a daily report in Korean', () => {
    const markup = renderToStaticMarkup(createElement(NotificationReportView, { data: fixture(), locale: 'ko' }));
    expect(markup).toContain('일일 보고 · 이상 징후 알림');
    expect(markup).toContain('마지막 일일 보고 예약');
    expect(markup).not.toContain('매시간');
  });
  it('separates active detections from collapsed resolved history', () => {
    const active = { id: 'a'.repeat(64), kind: 'ssh-auth-success', severity: 'warning', status: 'active' as const,
      openedAt: '2026-09-13T07:00:00Z', observedAt: '2026-09-13T08:00:00Z', count: 1, windowSeconds: 300,
      evidence: '신뢰 목록에 없는 SSH 인증 성공' };
    const resolved = Array.from({ length: 31 }, (_, index) => ({ ...active, id: index.toString(16).padStart(64, '0'),
      status: 'resolved' as const, evidence: `resolved-${index}` }));
    const markup = renderToStaticMarkup(createElement(NotificationReportView, {
      data: { ...fixture(), detections: [active, ...resolved] }, locale: 'ko',
    }));
    expect(markup).toContain('표시 중인 진행 사건 1건');
    expect(markup).toContain('신뢰 목록에 없는 SSH 인증 성공');
    expect(markup).toContain('공개 목록 상한 32건에 도달했습니다');
    expect(markup).toContain('<details class="notification-history"><summary>보관된 최근 해소 이력 31건</summary>');
    expect(markup).not.toContain('<details class="notification-history" open=""');
  });
  it('labels latest outcomes without treating cumulative totals as current failures', () => {
    expect(deliveryOutcomeLabel('success', 'ko')).toBe('SMTP 접수 성공');
    expect(deliveryOutcomeLabel('retry', 'en')).toBe('Retry scheduled');
    expect(deliveryOutcomeLabel('permanent_failure', 'ko')).toBe('최종 실패');
    const markup = renderToStaticMarkup(createElement(NotificationReportView, {
      data: { ...fixture(), delivery: { ...fixture().delivery, sent: 12, failed: 3, lastOutcome: 'success' } }, locale: 'ko',
    }));
    expect(markup).toContain('누적 SMTP 접수');
    expect(markup).toContain('누적 미전송 종료');
    expect(markup).toContain('최근 전송 결과');
  });
});
