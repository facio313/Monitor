import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-30T12:00:00Z');
const HOST_ID = '11111111-1111-4111-8111-111111111111';
const AGENT_ID = '22222222-2222-4222-8222-222222222222';
const temporaryDirectories: string[] = [];

function fixtureDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-agent-contract-'));
  temporaryDirectories.push(directory);
  mkdirSync(join(directory, 'history'), { recursive: true });
  return directory;
}

function heartbeatSnapshot(
  ageSeconds: number,
  lifecycle: 'active' | 'maintenance' | 'inactive' = 'active',
): Record<string, unknown> {
  const timestamp = new Date(NOW - ageSeconds * 1_000).toISOString();
  return {
    schemaVersion: 2,
    generatedAt: timestamp,
    identity: {
      hostId: HOST_ID,
      agentId: AGENT_ID,
      installationEpoch: '2026-08-01T00:00:00Z',
      identityGeneration: 1,
      machineIdentityStatus: 'bound',
      bootId: '0123456789abcdef0123456789abcdef',
    },
    heartbeat: {
      sequence: 42,
      observedAt: timestamp,
      receivedAt: timestamp,
      expectedIntervalSeconds: 60,
      lifecycle,
      transport: 'local-file',
    },
  };
}

function dashboardFor(snapshot: Record<string, unknown>) {
  const directory = fixtureDirectory();
  writeFileSync(join(directory, 'current.json'), `${JSON.stringify(snapshot)}\n`);
  return readDashboard(directory, '1h', NOW, 300_000);
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('agent identity and heartbeat contract', () => {
  it('distinguishes healthy, delayed, and disconnected active agents', () => {
    expect(dashboardFor(heartbeatSnapshot(90)).agent.status).toBe('healthy');
    expect(dashboardFor(heartbeatSnapshot(121)).agent.status).toBe('delayed');
    expect(dashboardFor(heartbeatSnapshot(301)).agent.status).toBe('disconnected');
  });

  it('honours explicit maintenance and inactive lifecycle states', () => {
    expect(dashboardFor(heartbeatSnapshot(3_600, 'maintenance')).agent.status).toBe('maintenance');
    expect(dashboardFor(heartbeatSnapshot(3_600, 'inactive')).agent.status).toBe('inactive');
  });

  it('keeps legacy snapshots available but fails malformed new contracts closed', () => {
    expect(dashboardFor({ host: { hostname: 'legacy' } }).agent).toMatchObject({
      status: 'unknown',
      hostId: null,
      sequence: null,
    });

    const incomplete = heartbeatSnapshot(0);
    delete incomplete.heartbeat;
    expect(dashboardFor(incomplete).agent.status).toBe('collection_error');

    const extraField = heartbeatSnapshot(0);
    (extraField.heartbeat as Record<string, unknown>).rawMachineId = 'must-not-pass';
    expect(dashboardFor(extraField).agent.status).toBe('collection_error');

    const wrongVersion = heartbeatSnapshot(0);
    wrongVersion.schemaVersion = 999;
    expect(dashboardFor(wrongVersion).agent.status).toBe('collection_error');

    const skewed = heartbeatSnapshot(0);
    (skewed.heartbeat as Record<string, unknown>).observedAt = '2026-08-30T11:58:00Z';
    expect(dashboardFor(skewed).agent.status).toBe('collection_error');

    const mismatchedSnapshot = heartbeatSnapshot(0);
    mismatchedSnapshot.generatedAt = '2026-08-30T11:59:59Z';
    expect(dashboardFor(mismatchedSnapshot).agent.status).toBe('collection_error');
  });

  it('returns only the reduced public identity and bounded timing values', () => {
    const agent = dashboardFor(heartbeatSnapshot(12.345)).agent;
    expect(agent).toEqual({
      hostId: HOST_ID,
      agentId: AGENT_ID,
      installationEpoch: '2026-08-01T00:00:00.000Z',
      identityGeneration: 1,
      machineIdentityStatus: 'bound',
      bootId: '0123456789abcdef0123456789abcdef',
      sequence: 42,
      observedAt: '2026-08-30T11:59:47.655Z',
      receivedAt: '2026-08-30T11:59:47.655Z',
      expectedIntervalSeconds: 60,
      lifecycle: 'active',
      transport: 'local-file',
      status: 'healthy',
      ageSeconds: 12.345,
      clockSkewSeconds: 0,
    });
  });
});
