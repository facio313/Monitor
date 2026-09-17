import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readNotificationReports } from './notification-reports.js';

const NOW = Date.parse('2026-09-13T08:00:00Z');
function fixture(value?: unknown) {
  const dir = mkdtempSync(join(tmpdir(), 'monitor-notification-read-'));
  if (value !== undefined) writeFileSync(join(dir, 'notification-reports.json'), JSON.stringify(value), { mode: 0o640 });
  return dir;
}
function payload() {
  return { schemaVersion: 1, observedAt: new Date(NOW).toISOString(), status: 'ok',
    hourly: { slot: '2026-09-13T08:00:00Z', lastQueuedAt: new Date(NOW).toISOString(), enqueued: 1 },
    immediate: { enqueued: 2 }, delivery: { pending: 2, retrying: 1, sent: 3, failed: 0, lastOutcome: 'sent' },
    sourceHealth: [{ source: 'ssh', status: 'fresh', observedAt: new Date(NOW).toISOString(), detail: 'SSH 관측 정상' }],
    detections: [{ id: 'a'.repeat(64), kind: 'ssh-auth-attempt', severity: 'warning', status: 'active', openedAt: new Date(NOW).toISOString(), observedAt: new Date(NOW).toISOString(), count: 1, windowSeconds: 300, evidence: '허용되지 않은 SSH 접근 1건' }],
  };
}
describe('notification status public reader', () => {
  it('keeps queued and SMTP-accepted counts separate and retains reduced evidence', () => {
    const result = readNotificationReports(fixture(payload()), NOW);
    expect(result).toMatchObject({ status: 'ok', stale: false, delivery: { pending: 2, sent: 3 }, hourly: { enqueued: 1 } });
    expect(result.detections[0]?.evidence).toContain('SSH');
  });
  it('distinguishes disabled, unavailable, invalid and stale data', () => {
    expect(readNotificationReports(fixture(), NOW).status).toBe('unavailable');
    expect(readNotificationReports(fixture({ ...payload(), status: 'disabled' }), NOW).status).toBe('disabled');
    expect(readNotificationReports(fixture({ ...payload(), observedAt: 'invalid' }), NOW).status).toBe('error');
    expect(readNotificationReports(fixture(payload()), NOW + 301_000).stale).toBe(true);
    expect(readNotificationReports(fixture({ ...payload(), observedAt: new Date(NOW + 120_000).toISOString() }), NOW).stale).toBe(true);
  });
  it('does not expose extra secrets, excluded records, arbitrary sources or unsafe evidence', () => {
    const input = payload();
    const dir = fixture({ ...input, password: 'DO_NOT_EXPORT', sourceHealth: [...input.sourceHealth, { source: 'foreign', detail: 'DO_NOT_EXPORT' }], detections: [
      ...input.detections,
      { ...input.detections[0], evidence: 'wgang authentication event' },
      { ...input.detections[0], evidence: 'password=DO_NOT_EXPORT' },
      { ...input.detections[0], evidence: 'client 192.0.2.10' },
    ] });
    const result = readNotificationReports(dir, NOW);
    expect(result.detections).toHaveLength(1);
    expect(result.sourceHealth).toHaveLength(1);
    expect(JSON.stringify(result)).not.toMatch(/DO_NOT_EXPORT|wgang|192\.0\.2/);
  });
  it('rejects symlinks, writable exports and oversized artifacts', () => {
    const source = fixture(payload());
    const linked = fixture();
    symlinkSync(join(source, 'notification-reports.json'), join(linked, 'notification-reports.json'));
    expect(readNotificationReports(linked, NOW).status).toBe('error');
    chmodSync(join(source, 'notification-reports.json'), 0o666);
    expect(readNotificationReports(source, NOW).status).toBe('error');
    const oversized = fixture();
    writeFileSync(join(oversized, 'notification-reports.json'), ' '.repeat(256 * 1024 + 1), { mode: 0o640 });
    expect(readNotificationReports(oversized, NOW).status).toBe('error');
  });
});
