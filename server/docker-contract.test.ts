import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-30T12:01:00Z');
const directories: string[] = [];
type MountPolicyStatus = 'approved' | 'drift' | 'unknown' | 'unmanaged';

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'monitor-docker-contract-'));
  directories.push(path);
  return path;
}

afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function container(mountPolicyStatus: MountPolicyStatus = 'approved') {
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
    mountPolicyStatus,
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

describe('Docker v4 collector contract', () => {
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

  it('preserves only mount policy statuses valid for the service review scope', () => {
    for (const status of ['approved', 'drift', 'unknown'] as const) {
      const current = snapshot();
      current.containers = [container(status)];
      expect(read(current).containers[0]?.mountPolicyStatus).toBe(status);
    }
    const unmanaged = snapshot();
    unmanaged.containers = [{
      ...container('unmanaged'), name: 'blog-frontend', project: 'blog',
    }];
    expect(read(unmanaged).containers[0]?.mountPolicyStatus).toBe('unmanaged');
  });

  it('preserves read-only sensitive binds and migrates prior exact v3 rows by review scope', () => {
    const readOnly = snapshot();
    readOnly.containers = [{
      ...container(),
      writableSensitiveBindMounted: false,
    }];
    expect(read(readOnly).containers[0]).toMatchObject({
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: false,
      mountPolicyStatus: 'approved',
    });

    const v3 = snapshot();
    const v3Container = { ...container() } as Record<string, unknown>;
    delete v3Container.mountPolicyStatus;
    v3.containers = [v3Container as ReturnType<typeof container>];
    expect(read(v3).containers[0]).toMatchObject({
      mountPolicyStatus: 'unknown',
    });

    const legacyV3 = snapshot();
    const legacyV3Container = { ...container() } as Record<string, unknown>;
    delete legacyV3Container.mountPolicyStatus;
    delete legacyV3Container.writableSensitiveBindMounted;
    legacyV3.containers = [legacyV3Container as ReturnType<typeof container>];
    expect(read(legacyV3).containers[0]).toMatchObject({
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: null,
      mountPolicyStatus: 'unknown',
    });

    const unreviewedV3 = snapshot();
    const unreviewedV3Container = {
      ...container(), name: 'blog-frontend', project: 'blog',
    } as Record<string, unknown>;
    delete unreviewedV3Container.mountPolicyStatus;
    unreviewedV3.containers = [unreviewedV3Container as ReturnType<typeof container>];
    expect(read(unreviewedV3).containers[0]).toMatchObject({
      name: 'blog-frontend',
      mountPolicyStatus: 'unmanaged',
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

    for (const mountPolicyStatus of ['waived', null, true]) {
      const invalidMountPolicy = snapshot();
      invalidMountPolicy.containers = [{
        ...container(), mountPolicyStatus,
      } as unknown as ReturnType<typeof container>];
      expect(read(invalidMountPolicy).containers).toEqual([]);
    }
    const reviewedAsUnmanaged = snapshot();
    reviewedAsUnmanaged.containers = [container('unmanaged')];
    expect(read(reviewedAsUnmanaged).containers).toEqual([]);

    const unreviewedAsApproved = snapshot();
    unreviewedAsApproved.containers = [{
      ...container('approved'), name: 'blog-frontend', project: 'blog',
    }];
    expect(read(unreviewedAsApproved).containers).toEqual([]);

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
