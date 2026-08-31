import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-30T12:01:00Z');
const directories: string[] = [];

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'monitor-docker-contract-'));
  directories.push(path);
  return path;
}

afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function container() {
  return {
    name: 'monitor', project: 'monitor', owner: 'cks', state: 'running', health: 'healthy',
    healthcheckConfigured: true, cpuPercent: 95, memoryBytes: 900, memoryPercent: 90,
    memoryLimitBytes: 1000, cpuLimitCores: 1, pidLimit: 100, restartCount: 4,
    restartCountDelta: 3, oomKilled: false, startedAt: '2026-08-30T11:00:00Z', finishedAt: null,
    instanceId: 'a'.repeat(32), pidCount: 90, cpuThrottledPercent: 25,
    cpuThrottledPeriods: 50, cpuThrottledSeconds: 2.5, blockReadBytes: 1000,
    blockWriteBytes: 2000, blockReadBytesPerSecond: 10, blockWriteBytesPerSecond: 20,
    networkRxBytes: 3000, networkTxBytes: 4000, networkRxBytesPerSecond: 30,
    networkTxBytesPerSecond: 40, networkErrors: 5, networkErrorsPerSecond: 1.5,
    writableLayerBytes: 1_500_000_000, volumeCount: 1, bindMountCount: 2,
    tmpfsMountCount: 1, networkAttachmentCount: 1, publishedPortCount: 1,
    privileged: true, hostPid: true, hostIpc: false, hostNetwork: true,
    dockerSocketMounted: true, sensitiveBindMounted: true, writableSensitiveBindMounted: true,
    rootUser: true,
    readOnlyRootFilesystem: false, addedCapabilityCount: 2, dangerousCapabilityCount: 2,
    excessiveCapabilities: true, imageName: 'registry.example/ops/monitor', imageTag: 'latest',
    imageDigest: `sha256:${'1'.repeat(64)}`, imageDigestSource: 'repo-digest',
    usesLatestTag: true, imageDigestDrift: false, imageDigestChanged: true,
  };
}

function event() {
  return {
    id: 'b'.repeat(32), occurredAt: '2026-08-30T12:00:30Z', action: 'die',
    containerName: 'monitor', project: 'monitor', instanceId: 'a'.repeat(32),
    exitCode: 137, healthStatus: null,
  };
}

function snapshot() {
  return {
    generatedAt: '2026-08-30T12:01:00Z',
    latest: { timestamp: '2026-08-30T12:01:00Z' },
    containerCollection: { status: 'fresh', observedAt: '2026-08-30T12:01:00Z' },
    containers: [container()],
    dockerEventCollection: {
      status: 'fresh', observedAt: '2026-08-30T12:01:00Z', cursorAt: '2026-08-30T12:01:00Z',
      reconnectCount: 2, gapCount: 1, gapDetected: false, logCollectionStatus: 'unsupported',
    },
    dockerEvents: [event()],
  };
}

function read(current: ReturnType<typeof snapshot>, now = NOW) {
  const root = directory();
  writeFileSync(join(root, 'current.json'), `${JSON.stringify(current)}\n`);
  return readDashboard(root, '1h', now, 180_000);
}

describe('Docker v3 collector contract', () => {
  it('preserves every bounded resource, security, image, and event field', () => {
    const result = read(snapshot());
    expect(result.containers).toEqual([{
      ...container(),
      startedAt: '2026-08-30T11:00:00.000Z',
    }]);
    expect(result.dockerEventCollection).toEqual({
      status: 'fresh', observedAt: '2026-08-30T12:01:00.000Z',
      cursorAt: '2026-08-30T12:01:00.000Z', reconnectCount: 2, gapCount: 1,
      gapDetected: false, logCollectionStatus: 'unsupported',
    });
    expect(result.dockerEvents).toEqual([{
      ...event(), occurredAt: '2026-08-30T12:00:30.000Z',
    }]);
  });

  it('preserves read-only sensitive binds and migrates the prior exact v3 row as unknown', () => {
    const readOnly = snapshot();
    readOnly.containers = [{
      ...container(),
      writableSensitiveBindMounted: false,
    }];
    expect(read(readOnly).containers[0]).toMatchObject({
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: false,
    });

    const legacy = snapshot();
    const legacyContainer = { ...container() } as Record<string, unknown>;
    delete legacyContainer.writableSensitiveBindMounted;
    legacy.containers = [legacyContainer as ReturnType<typeof container>];
    expect(read(legacy).containers[0]).toMatchObject({
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: null,
    });
  });

  it('fails closed on row extras, inconsistent latest state, and event extras', () => {
    const rowExtra = snapshot();
    rowExtra.containers = [{ ...container(), environment: 'TOKEN=secret' } as ReturnType<typeof container>];
    expect(read(rowExtra).containers).toEqual([]);

    const inconsistent = snapshot();
    inconsistent.containers = [{ ...container(), usesLatestTag: false }];
    expect(read(inconsistent).containers).toEqual([]);

    const digestlessState = snapshot();
    digestlessState.containers = [{
      ...container(), imageDigest: null, imageDigestSource: null, imageDigestDrift: false,
    }];
    expect(read(digestlessState).containers).toEqual([]);

    const inconsistentCapabilities = snapshot();
    inconsistentCapabilities.containers = [{ ...container(), excessiveCapabilities: false }];
    expect(read(inconsistentCapabilities).containers).toEqual([]);

    const inconsistentSensitiveBind = snapshot();
    inconsistentSensitiveBind.containers = [{
      ...container(), sensitiveBindMounted: false, writableSensitiveBindMounted: true,
    }];
    expect(read(inconsistentSensitiveBind).containers).toEqual([]);

    const eventExtra = snapshot();
    eventExtra.dockerEvents = [{ ...event(), rawActor: 'secret' } as ReturnType<typeof event>];
    const rejected = read(eventExtra);
    expect(rejected.dockerEvents).toEqual([]);
    expect(rejected.dockerEventCollection.status).toBe('unavailable');
  });

  it('does not present a stale event poll as connected', () => {
    const stale = snapshot();
    stale.dockerEventCollection.observedAt = '2026-08-30T11:00:00Z';
    stale.dockerEventCollection.cursorAt = '2026-08-30T11:00:00Z';
    const result = read(stale);
    expect(result.dockerEventCollection.status).toBe('unavailable');
    expect(result.dockerEventCollection.gapDetected).toBe(true);
  });

  it('applies the selected dashboard range to Docker events', () => {
    const outsideRange = snapshot();
    outsideRange.dockerEvents = [{
      ...event(), occurredAt: '2026-08-30T10:00:00Z',
    }];
    expect(read(outsideRange).dockerEvents).toEqual([]);

    const exactlyAtCutoff = snapshot();
    exactlyAtCutoff.dockerEvents = [{
      ...event(), occurredAt: '2026-08-30T11:01:00Z',
    }];
    expect(read(exactlyAtCutoff).dockerEvents).toEqual([{
      ...event(), occurredAt: '2026-08-30T11:01:00.000Z',
    }]);
  });
});
