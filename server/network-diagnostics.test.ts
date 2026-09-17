import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { NetworkDiagnosticRecord } from '../src/network-diagnostics-types';
import { NetworkDiagnosticsQueryError, parseNetworkDiagnosticRecord, readNetworkDiagnostics } from './network-diagnostics';

const NOW = Date.parse('2026-09-13T12:00:00Z');
const roots: string[] = [];
function record(time = '2026-09-13T12:00:00Z'): NetworkDiagnosticRecord {
  return { schemaVersion: 1, observedAt: time, probeStatus: 'fresh', probeObservedAt: time,
    probes: [{ id: 'public-monitor', checkedAt: time, status: 'timeout', httpStatus: null, redirectCount: 0,
      errorPhase: 'tcp', timings: { dnsMs: 12, tcpMs: null, tlsMs: null, ttfbMs: null, totalMs: 5000 } }],
    tcp: { status: 'fresh', elapsedSeconds: 10, retransmittedSegments: 2, outboundSegments: 100, retransmitPercent: 2, retransmittedPerSecond: .2, outboundPerSecond: 10 },
    interfaces: { rxErrorsPerSecond: 0, txErrorsPerSecond: 0, rxDroppedPerSecond: 0, txDroppedPerSecond: 0 },
    context: { cpuPercent: 25, memoryPercent: 35, cpuPressureSomeAvg10: 0, cpuPressureFullAvg10: 0,
      memoryPressureSomeAvg10: 0, memoryPressureFullAvg10: 0, ioPressureSomeAvg10: 0, ioPressureFullAvg10: 0 }, problems: ['http', 'tcp'] };
}
function fixture(rows: unknown[] = [record()]) {
  const root = mkdtempSync(join(tmpdir(), 'monitor-network-'));
  roots.push(root);
  const directory = join(root, 'network-diagnostics');
  mkdirSync(directory, { mode: 0o750 });
  writeFileSync(join(directory, 'latest.json'), JSON.stringify(record()), { mode: 0o640 });
  writeFileSync(join(directory, '2026-09-13.jsonl'), rows.map((row) => JSON.stringify(row)).join('\n') + '\n', { mode: 0o640 });
  return { root, directory };
}
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })));

describe('network diagnostics reader', () => {
  it('returns phase failures and correct outbound numerator/denominator with stable pagination', () => {
    const earlier = record('2026-09-13T11:59:50Z');
    earlier.problems = [];
    const { root } = fixture([earlier, record()]);
    const page1 = readNetworkDiagnostics(root, { limit: '1', to: '2026-09-13T12:00:00Z' }, NOW);
    expect(page1.status).toBe('fresh');
    expect(page1.total).toBe(2);
    expect(page1.records[0].probes[0].errorPhase).toBe('tcp');
    expect(page1.records[0].probes[0].timings.tcpMs).toBeNull();
    expect(page1.records[0].tcp.outboundSegments).toBe(100);
    expect(readNetworkDiagnostics(root, { limit: '1', page: '2', to: page1.to }, NOW).records[0].observedAt).toBe(earlier.observedAt);
    expect(readNetworkDiagnostics(root, { problem: 'tcp' }, NOW).total).toBe(1);
    expect(readNetworkDiagnostics(root, { problem: 'interface' }, NOW).total).toBe(0);
    expect(readNetworkDiagnostics(root, { from: '2026-09-13T11:59:55Z' }, NOW).total).toBe(1);
  });

  it('distinguishes no data, stale collection and damaged sources', () => {
    const { root, directory } = fixture();
    expect(readNetworkDiagnostics(root, {}, NOW + 180_000).status).toBe('stale');
    writeFileSync(join(directory, 'latest.json'), 'broken');
    const damaged = readNetworkDiagnostics(root, {}, NOW);
    expect(damaged.status).toBe('error');
    expect(damaged.rejectedRows).toBe(1);
    expect(damaged.total).toBe(1);
    expect(damaged.records).toHaveLength(1);
    expect(readNetworkDiagnostics(join(root, 'missing'), {}, NOW).status).toBe('no_data');
  });

  it('rejects unknown material without reflecting secrets or excluded services', () => {
    const secret = { ...record(), url: 'https://secret.example/?token=never-export' };
    const excluded = record();
    excluded.probes = [{ ...excluded.probes[0], id: 'wgang' }];
    const { root } = fixture([secret, excluded, record()]);
    const result = readNetworkDiagnostics(root, {}, NOW);
    expect(result.status).toBe('error');
    expect(result.rejectedRows).toBe(1);
    expect(result.total).toBe(2);
    expect(JSON.stringify(result)).not.toMatch(/wgang|secret\.example|never-export/);
    const badId = record();
    badId.probes[0].id = 'host-192.168.0.1';
    expect(parseNetworkDiagnosticRecord(badId)).toBeNull();
    const badTiming = record();
    badTiming.probes[0].timings.dnsMs = Number.POSITIVE_INFINITY;
    expect(parseNetworkDiagnosticRecord(badTiming)).toBeNull();
  });

  it('rejects symlinks, dates in wrong day files and oversized rows', () => {
    const { root, directory } = fixture([record('2026-09-12T23:59:59Z')]);
    expect(readNetworkDiagnostics(root, {}, NOW).rejectedRows).toBe(1);
    rmSync(join(directory, '2026-09-13.jsonl'));
    symlinkSync(join(directory, 'latest.json'), join(directory, '2026-09-13.jsonl'));
    const result = readNetworkDiagnostics(root, {}, NOW);
    expect(result.status).toBe('error');
    expect(result.truncated).toBe(true);
    expect(result.records).toHaveLength(0);
    rmSync(join(directory, '2026-09-13.jsonl'));
    writeFileSync(join(directory, '2026-09-13.jsonl'), 'x'.repeat(33 * 1024), { mode: 0o640 });
    expect(readNetworkDiagnostics(root, {}, NOW).rejectedRows).toBe(1);
  });

  it('bounds every query dimension and rejects traversal/array query shapes', () => {
    const { root } = fixture();
    for (const query of [{ page: '0' }, { page: ['1'] }, { limit: '101' }, { range: '../' }, { range: '365d' },
      { problem: 'secret' }, { unknown: 'x' }, { from: '2020-01-01T00:00:00Z' }, { to: '2027-01-01T00:00:00Z' }, { to: 'bad' }]) {
      expect(() => readNetworkDiagnostics(root, query, NOW)).toThrow(NetworkDiagnosticsQueryError);
    }
    expect(readNetworkDiagnostics(root, { range: '30d' }, NOW).records).toHaveLength(1);
  });
});
