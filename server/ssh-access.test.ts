import { createHash } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { SshAccessRecord } from '../src/ssh-access-types';
import { canonicalSshIp, parseSshAccessRecord, readSshAccess, SshAccessQueryError } from './ssh-access';

const NOW = Date.parse('2026-09-13T12:00:00Z');
const roots: string[] = [];
const id = (value: string) => createHash('sha256').update(value).digest('hex');
function record(index = 0, overrides: Partial<SshAccessRecord> = {}): SshAccessRecord {
  return { schemaVersion: 1, id: id(String(index)), observedAt: '2026-09-13T11:59:59.123456Z', sourceId: 'journal:ssh',
    sourceIp: '203.0.113.10', sourcePort: 52123, eventType: 'auth_failed', authMethod: 'password',
    countryCode: 'US', countryStatus: 'estimated', databaseDate: '2026-09-01', ...overrides };
}
function status(overrides: Record<string, unknown> = {}) {
  return { schemaVersion: 1, observedAt: '2026-09-13T12:00:00.000000Z', status: 'fresh', lastSuccessAt: '2026-09-13T12:00:00Z', errorClass: null,
    sources: [{ sourceId: 'journal:ssh', status: 'fresh', observedAt: '2026-09-13T12:00:00Z', lastSuccessAt: '2026-09-13T12:00:00Z', errorClass: null }],
    acceptedRecords: 1, deduplicatedRecords: 0, droppedRecords: 0, retentionDays: 30, ...overrides };
}
function fixture(rows: unknown[] = [record()]) {
  const root = mkdtempSync(join(tmpdir(), 'monitor-ssh-access-reader-'));
  roots.push(root);
  const directory = join(root, 'ssh-access');
  mkdirSync(directory, { mode: 0o750 });
  writeFileSync(join(root, 'ssh-access-status.json'), JSON.stringify(status()), { mode: 0o640 });
  writeFileSync(join(directory, '2026-09-13.jsonl'), rows.map(row => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''), { mode: 0o640 });
  return { root, directory };
}
afterEach(() => roots.splice(0).forEach(root => rmSync(root, { recursive: true, force: true })));

describe('SSH access strict read model', () => {
  it('keeps canonical IPs and microseconds with exact newest-first pagination and dedup', () => {
    const earlier = record(1, { observedAt: '2026-09-13T11:59:59.123455Z' });
    const newest = record(2, { observedAt: '2026-09-13T11:59:59.123457Z', sourceIp: '2001:db8::1' });
    const { root } = fixture([newest, earlier, record(), record()]);
    const first = readSshAccess(root, { limit: '1' }, NOW);
    expect(first).toMatchObject({ status: 'fresh', stale: false, partial: false, total: 3, deduplicatedRows: 1, scannedRows: 4 });
    expect(first.records[0]).toEqual(newest);
    expect(readSshAccess(root, { limit: '1', page: '2' }, NOW).records[0]).toEqual(record());
    expect(readSshAccess(root, { limit: '1', page: '3' }, NOW).records[0]).toEqual(earlier);
    expect(readSshAccess(root, { ip: '2001:db8::1' }, NOW).total).toBe(1);
  });

  it('separates successful authentication, failed/denied records and pre-auth closures', () => {
    const events = ['auth_failed', 'denied', 'invalid_user', 'accepted', 'preauth_closed'] as const;
    const { root } = fixture(events.map((eventType, index) => record(index, { eventType })));
    expect(readSshAccess(root, { event: 'all' }, NOW).total).toBe(5);
    expect(readSshAccess(root, { event: 'failed' }, NOW).records.map(row => row.eventType).sort()).toEqual(['auth_failed', 'denied', 'invalid_user']);
    expect(readSshAccess(root, { event: 'accepted' }, NOW).records.map(row => row.eventType)).toEqual(['accepted']);
    expect(readSshAccess(root, { event: 'preauth_closed' }, NOW).records.map(row => row.eventType)).toEqual(['preauth_closed']);
  });

  it('keeps a fresh successful empty acquisition distinct from unavailable/stale/partial', () => {
    const { root } = fixture([]);
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'fresh', stale: false, total: 0 });
    expect(readSshAccess(root, {}, NOW + 301_000)).toMatchObject({ status: 'stale', stale: true, total: 0 });
    writeFileSync(join(root, 'ssh-access-status.json'), JSON.stringify(status({ status: 'partial', errorClass: 'acquisition_partial', droppedRecords: 4 })));
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'partial', partial: true, droppedRecords: 4 });
    writeFileSync(join(root, 'ssh-access-status.json'), JSON.stringify(status({ observedAt: '2026-09-14T12:00:00Z' })));
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'stale', stale: true });
    expect(readSshAccess(join(root, 'missing'), {}, NOW)).toMatchObject({ status: 'unavailable', stale: true, records: [] });
  });

  it('retains valid history when the status pointer is malformed, missing or unsafe', () => {
    const { root } = fixture();
    writeFileSync(join(root, 'ssh-access-status.json'), 'bad json');
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'partial', partial: true, rejectedRows: 1, total: 1 });
    rmSync(join(root, 'ssh-access-status.json'));
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'unavailable', total: 1 });
    symlinkSync(join(root, 'ssh-access', '2026-09-13.jsonl'), join(root, 'ssh-access-status.json'));
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'partial', total: 1 });
  });

  it('rejects unknown fields, excluded data, malformed values and dates without echoing input', () => {
    const invalid = [
      { ...record(), rawMessage: 'password=secret never-export' }, { ...record(), sourceId: 'journal:wgang' },
      { ...record(), sourceIp: '203.0.113.10:22' }, { ...record(), id: 'bad' }, { ...record(), observedAt: '2026-02-31T12:00:00Z' },
      { ...record(), sourceIp: null },
      { ...record(), sourcePort: 0 }, { ...record(), sourcePort: 65536 }, { ...record(), eventType: 'unknown' },
      { ...record(), authMethod: 'token=secret' }, { ...record(), countryCode: 'USA' }, { ...record(), databaseDate: '2026-02-31' },
      { ...record(), sourceIp: '2001:0DB8::1' }, { ...record(), sourceIp: 'fe80::1%eth0' },
    ];
    invalid.forEach(row => expect(parseSshAccessRecord(row)).toBeNull());
    const { root } = fixture([...invalid, record()]);
    const result = readSshAccess(root, {}, NOW);
    expect(result).toMatchObject({ status: 'partial', total: 1, rejectedRows: invalid.length });
    expect(JSON.stringify(result)).not.toMatch(/wgang|password=|never-export|rawMessage|token=secret/);
  });

  it('allows stale unknown countries and preserves logs for unrecognized provider region codes', () => {
    expect(parseSshAccessRecord(record(1, { countryCode: null, countryStatus: 'stale' }))).toMatchObject({ countryCode: null, countryStatus: 'stale' });
    expect(parseSshAccessRecord(record(2, { countryCode: 'ZZ' }))).toMatchObject({ countryCode: null, countryStatus: 'not_found' });
    expect(parseSshAccessRecord(record(3, { countryCode: 'ZZ', countryStatus: 'stale' }))).toMatchObject({ countryCode: null, countryStatus: 'stale' });
    expect(parseSshAccessRecord(record(7, { countryCode: 'XK' }))).toMatchObject({ countryCode: 'XK', countryStatus: 'estimated' });
    expect(parseSshAccessRecord(record(4, { countryCode: null, countryStatus: 'private', sourceIp: '10.0.0.1' }))).not.toBeNull();
    expect(parseSshAccessRecord(record(5, { countryCode: null, countryStatus: 'estimated' }))).toBeNull();
    expect(parseSshAccessRecord(record(6, { countryStatus: 'private' }))).toBeNull();
  });

  it('normalizes mapped query IPs to IPv4 while refusing noncanonical mapped record identities', () => {
    expect(canonicalSshIp('::ffff:808:808')).toBe('8.8.8.8');
    expect(parseSshAccessRecord(record(1, { sourceIp: '::ffff:808:808' }))).toBeNull();
    const { root } = fixture([record(1, { sourceIp: '8.8.8.8' })]);
    expect(readSshAccess(root, { ip: '::ffff:808:808' }, NOW)).toMatchObject({ ip: '8.8.8.8', total: 1 });
  });

  it('rejects traversal, duplicate query values, ports, hostnames and unbounded pagination', () => {
    const { root } = fixture();
    for (const query of [{ page: '0' }, { page: ['1', '2'] }, { page: '300001' }, { limit: '101' }, { limit: 20 },
      { range: '365d' }, { range: '../' }, { event: 'unknown' }, { from: '2020-01-01' }, { path: '/etc/passwd' },
      { ip: 'example.invalid' }, { ip: 'https://8.8.8.8' }, { ip: '8.8.8.8:22' }, { ip: '008.8.8.8' },
      { ip: '2001:DB8::1' }, { ip: 'fe80::1%eth0' }, { ip: '' }, { ip: ['8.8.8.8'] }]) {
      expect(() => readSshAccess(root, query, NOW)).toThrow(SshAccessQueryError);
    }
  });

  it('rejects symlink/hardlink/writable day files, oversized days and wrong-day/future rows', () => {
    const { root, directory } = fixture([record(1, { observedAt: '2026-09-12T23:59:59Z' }), record(2, { observedAt: '2026-09-13T12:02:00Z' })]);
    const path = join(directory, '2026-09-13.jsonl');
    expect(readSshAccess(root, {}, NOW).rejectedRows).toBe(2);
    rmSync(path);
    symlinkSync(join(root, 'ssh-access-status.json'), path);
    expect(readSshAccess(root, {}, NOW)).toMatchObject({ status: 'partial', truncated: true, records: [] });
    rmSync(path);
    linkSync(join(root, 'ssh-access-status.json'), path);
    expect(readSshAccess(root, {}, NOW).truncated).toBe(true);
    rmSync(path);
    writeFileSync(path, JSON.stringify(record()), { mode: 0o666 });
    chmodSync(path, 0o666);
    expect(readSshAccess(root, {}, NOW).truncated).toBe(true);
    chmodSync(path, 0o640);
    writeFileSync(path, 'x'.repeat(4 * 1024 * 1024 + 1));
    expect(readSshAccess(root, {}, NOW).truncated).toBe(true);
    writeFileSync(path, '\n'.repeat(10_001) + JSON.stringify(record()));
    expect(readSshAccess(root, {}, NOW).truncated).toBe(true);
  });

  it('bounds a requested 30-day worst-case scan to 16MiB/40k rows and only keeps the page', () => {
    const { root, directory } = fixture([]);
    for (let daysAgo = 0; daysAgo < 6; daysAgo++) {
      const day = new Date(NOW - daysAgo * 86_400_000).toISOString().slice(0, 10);
      const rows = Array.from({ length: 9000 }, (_, index) => JSON.stringify(record(index + daysAgo * 9000, {
        observedAt: `${day}T01:00:00.${String(index).padStart(6, '0')}Z`,
      })));
      writeFileSync(join(directory, `${day}.jsonl`), rows.join('\n') + '\n', { mode: 0o640 });
    }
    const result = readSshAccess(root, { range: '30d', limit: '100' }, NOW);
    expect(result).toMatchObject({ status: 'partial', partial: true, truncated: true });
    expect(result.scannedRows).toBeLessThanOrEqual(40_000);
    expect(result.scannedBytes).toBeLessThanOrEqual(16 * 1024 * 1024);
    expect(result.records).toHaveLength(100);
    expect(result.total).toBeGreaterThan(10_000);
    expect(result.total).toBeLessThanOrEqual(result.scannedRows);
    expect(result.records[0].observedAt).toContain('2026-09-13');
  }, 15_000);
});
