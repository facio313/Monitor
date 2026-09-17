import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';
import type { NotificationReportStatus } from '../src/notification-report-types.js';

const MAX_BYTES = 256 * 1024;
const KINDS = new Set(['ssh-auth-attempt', 'ssh-auth-burst', 'http-client-errors', 'http-server-errors', 'operational-caution', 'source-unavailable', 'rule-alert']);
const SOURCES = new Set(['snapshot', 'rules', 'ssh', 'http']);
type Obj = Record<string, unknown>;
function obj(value: unknown): Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Obj : {};
}
function integer(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}
function date(value: unknown): string | null {
  return typeof value === 'string' && value.length <= 32 && /Z$/.test(value) && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
}
function text(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length > max || /[\u0000-\u001f\u007f]|wgang|https?:\/\/|\b(?:password|token|secret|authorization|cookie)\s*[:=]|\b\d{1,3}(?:\.\d{1,3}){3}\b|\S+@\S+/i.test(value)) return '';
  return value;
}
function empty(status: NotificationReportStatus['status']): NotificationReportStatus {
  return { schemaVersion: 1, observedAt: null, stale: true, status,
    hourly: { slot: null, lastQueuedAt: null, enqueued: 0, deduplicated: 0, dropped: 0 },
    immediate: { enqueued: 0, deduplicated: 0, dropped: 0 },
    delivery: { pending: 0, retrying: 0, sent: 0, failed: 0, lastAttemptAt: null, lastOutcome: null }, sourceHealth: [], detections: [] };
}

export function readNotificationReports(dataDir: string, nowMs = Date.now()): NotificationReportStatus {
  let fd: number | undefined;
  try {
    const root = lstatSync(dataDir);
    if (!root.isDirectory() || root.isSymbolicLink()) return empty('error');
    fd = openSync(join(dataDir, 'notification-reports.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0 || stat.size > MAX_BYTES) return empty('error');
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    for (;;) {
      const read = readSync(fd, buffer, length, buffer.length - length, null);
      length += read;
      if (length > MAX_BYTES) return empty('error');
      if (read === 0) break;
    }
    const raw = obj(JSON.parse(buffer.subarray(0, length).toString('utf8')));
    if (raw.schemaVersion !== 1 || !['ok', 'disabled', 'error'].includes(String(raw.status))) return empty('error');
    const observedAt = date(raw.observedAt);
    if (!observedAt) return empty('error');
    const result = empty(raw.status as NotificationReportStatus['status']);
    result.observedAt = observedAt;
    result.stale = nowMs - Date.parse(observedAt) > 300_000 || Date.parse(observedAt) > nowMs + 60_000;
    const hourly = obj(raw.hourly), immediate = obj(raw.immediate), delivery = obj(raw.delivery);
    result.hourly = { slot: date(hourly.slot), lastQueuedAt: date(hourly.lastQueuedAt), enqueued: integer(hourly.enqueued), deduplicated: integer(hourly.deduplicated), dropped: integer(hourly.dropped) };
    result.immediate = { enqueued: integer(immediate.enqueued), deduplicated: integer(immediate.deduplicated), dropped: integer(immediate.dropped) };
    result.delivery = { pending: integer(delivery.pending), retrying: integer(delivery.retrying), sent: integer(delivery.sent), failed: integer(delivery.failed), lastAttemptAt: date(delivery.lastAttemptAt), lastOutcome: typeof delivery.lastOutcome === 'string' && /^[a-z_]{1,40}$/.test(delivery.lastOutcome) ? delivery.lastOutcome : null };
    result.sourceHealth = (Array.isArray(raw.sourceHealth) ? raw.sourceHealth : []).slice(0, 4).map(obj).filter(s => SOURCES.has(String(s.source))).map(s => ({
      source: String(s.source), status: ['fresh', 'stale', 'unavailable', 'partial'].includes(String(s.status)) ? String(s.status) : 'unavailable', observedAt: date(s.observedAt), detail: text(s.detail, 180),
    }));
    result.detections = (Array.isArray(raw.detections) ? raw.detections : []).slice(0, 32).map(obj).filter(d =>
      typeof d.id === 'string' && /^[a-f0-9]{64}$/.test(d.id) && KINDS.has(String(d.kind)) &&
      ['warning', 'critical', 'info'].includes(String(d.severity)) && ['active', 'resolved'].includes(String(d.status)) && date(d.openedAt) && date(d.observedAt) && text(d.evidence, 500),
    ).map(d => ({ id: String(d.id), kind: String(d.kind), severity: String(d.severity), status: d.status as 'active' | 'resolved', openedAt: date(d.openedAt)!, observedAt: date(d.observedAt)!, count: integer(d.count), windowSeconds: integer(d.windowSeconds), evidence: text(d.evidence, 500) }));
    return result;
  } catch (error) {
    return empty((error as NodeJS.ErrnoException).code === 'ENOENT' ? 'unavailable' : 'error');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
