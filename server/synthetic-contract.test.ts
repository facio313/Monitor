import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-31T06:01:00Z');
const directories: string[] = [];

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'monitor-synthetic-contract-'));
  directories.push(path);
  return path;
}

afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function probe() {
  return {
    id: 'public-ready', status: 'ok', checkedAt: '2026-08-31T06:00:00Z',
    httpStatus: 200, redirectCount: 1, latencyMilliseconds: 17,
    certificateExpiresAt: '2027-08-31T06:00:00Z', certificateDaysRemaining: 365,
  };
}

function snapshot() {
  return {
    generatedAt: '2026-08-31T06:01:00Z',
    latest: { timestamp: '2026-08-31T06:01:00Z' },
    syntheticProbeCollection: {
      status: 'fresh', observedAt: '2026-08-31T06:00:00Z',
    },
    syntheticProbes: [probe()],
  };
}

function read(current: Record<string, unknown>, now = NOW, staleAfterMs = 180_000) {
  const root = directory();
  writeFileSync(join(root, 'current.json'), `${JSON.stringify(current)}\n`);
  return readDashboard(root, '1h', now, staleAfterMs);
}

describe('synthetic probe collector contract', () => {
  it('preserves only the reduced exact evidence fields', () => {
    const result = read(snapshot());
    expect(result.syntheticProbeCollection).toEqual({
      status: 'fresh', observedAt: '2026-08-31T06:00:00.000Z',
    });
    expect(result.syntheticProbes).toEqual([{
      ...probe(),
      checkedAt: '2026-08-31T06:00:00.000Z',
      certificateExpiresAt: '2027-08-31T06:00:00.000Z',
    }]);
    expect(JSON.stringify(result.syntheticProbes)).not.toContain('url');
  });

  it('fails closed on extra URL data, duplicate ids, and inconsistent evidence', () => {
    const cases = [
      { ...snapshot(), syntheticProbes: [{ ...probe(), url: 'https://secret.example/?token=x' }] },
      { ...snapshot(), syntheticProbes: [probe(), probe()] },
      { ...snapshot(), syntheticProbes: [{ ...probe(), certificateDaysRemaining: null }] },
      { ...snapshot(), syntheticProbes: [{ ...probe(), status: 'ok', httpStatus: null }] },
    ];
    for (const current of cases) {
      const result = read(current);
      expect(result.syntheticProbeCollection).toEqual({
        status: 'collection-error', observedAt: null,
      });
      expect(result.syntheticProbes).toEqual([]);
    }
  });

  it('preserves explicit source states and ages fresh evidence to stale', () => {
    const aged = read(snapshot(), Date.parse('2026-08-31T06:10:00Z'));
    expect(aged.syntheticProbeCollection.status).toBe('stale');
    expect(aged.syntheticProbes).toHaveLength(1);

    for (const status of [
      'stale', 'unsupported', 'permission-denied', 'unavailable', 'collection-error',
    ] as const) {
      const current = snapshot();
      current.syntheticProbeCollection = {
        status,
        observedAt: status === 'stale' ? '2026-08-31T06:00:00Z' : null,
      };
      current.syntheticProbes = status === 'stale' ? [probe()] : [];
      expect(read(current).syntheticProbeCollection.status).toBe(status);
    }
  });

  it('treats legacy snapshots without probe fields as explicitly unsupported', () => {
    const result = read({
      generatedAt: '2026-08-31T06:01:00Z',
      latest: { timestamp: '2026-08-31T06:01:00Z' },
    });
    expect(result.syntheticProbeCollection).toEqual({
      status: 'unsupported', observedAt: null,
    });
    expect(result.syntheticProbes).toEqual([]);
  });
});
