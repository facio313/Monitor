import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { NotificationReportStatus } from '../notification-report-types';
import { NotificationReportView } from './NotificationStatusPanel';

function fixture(): NotificationReportStatus {
  return { schemaVersion: 1, observedAt: '2026-09-13T08:00:00Z', stale: false, status: 'ok', hourly: { slot: null, lastQueuedAt: null, enqueued: 1, deduplicated: 0, dropped: 0 }, immediate: { enqueued: 1, deduplicated: 0, dropped: 0 }, delivery: { pending: 1, retrying: 0, sent: 0, failed: 0, lastAttemptAt: null, lastOutcome: null }, sourceHealth: [{ source: 'ssh', status: 'unavailable', observedAt: null, detail: 'SSH 자료 없음' }], detections: [] };
}
describe('notification status presentation', () => {
  it('shows delivery limits and missing detection coverage rather than claiming successful mail or safety', () => {
    const markup = renderToStaticMarkup(createElement(NotificationReportView, { data: fixture(), locale: 'en' }));
    expect(markup).toContain('Accepted by SMTP');
    expect(markup).toContain('Queued items have not yet been sent');
    expect(markup).toContain('Unavailable');
    expect(markup).toContain('does not establish a successful intrusion');
  });
  it('prominently distinguishes disabled delivery and stale snapshots', () => {
    expect(renderToStaticMarkup(createElement(NotificationReportView, { data: { ...fixture(), status: 'disabled' }, locale: 'ko' }))).toContain('메일 전송 미설정');
    expect(renderToStaticMarkup(createElement(NotificationReportView, { data: { ...fixture(), stale: true }, locale: 'en' }))).toContain('Notification status is stale');
  });
});
