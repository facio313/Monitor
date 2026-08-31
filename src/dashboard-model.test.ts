import { describe, expect, it } from 'vitest';
import {
  chooseInitialLocale,
  eventBuckets,
  monitorPageFromPath,
  monitorPathForPage,
  monitorRangeFromSearch,
  monitorSnapshotIsStale,
  operationalLogs,
  operationalAssessmentPresentation,
  relatedLogs,
  rangeStatistics,
} from './dashboard-model';
import type { OperationalLogEntry } from './dashboard-model';
import type { DashboardPayload, TelemetrySample } from './types';

function sample(timestamp: string, values: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp,
    cpuPercent: null,
    memoryPercent: null,
    memoryUsedBytes: null,
    memoryTotalBytes: null,
    swapTotalBytes: null,
    swapUsedBytes: null,
    swapPercent: null,
    temperatureC: null,
    load1: null,
    load5: null,
    load15: null,
    cpuPressureSomeAvg10: null,
    cpuPressureFullAvg10: null,
    memoryPressureSomeAvg10: null,
    memoryPressureFullAvg10: null,
    ioPressureSomeAvg10: null,
    ioPressureFullAvg10: null,
    powerState: null,
    supplyVoltageVolts: null,
    throttledFlags: null,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: null,
    networkTxBytesPerSecond: null,
    networkRxErrorsPerSecond: null,
    networkTxErrorsPerSecond: null,
    networkRxDroppedPerSecond: null,
    networkTxDroppedPerSecond: null,
    diskReadBytesPerSecond: null,
    diskWriteBytesPerSecond: null,
    ...values,
  };
}

describe('monitor navigation', () => {
  it('maps overview, compatibility details, and exact detail slugs', () => {
    expect(monitorPageFromPath('/monitor/')).toBe('overview');
    expect(monitorPageFromPath('/monitor/details')).toBe('resources');
    expect(monitorPageFromPath('/monitor/details/logs/')).toBe('logs');
    expect(monitorPageFromPath('/monitor/details/reliability')).toBe('reliability');
    expect(monitorPageFromPath('/monitor/details/maintenance')).toBe('maintenance');
    expect(monitorPageFromPath('/monitor/details/infrastructure')).toBe('infrastructure');
    expect(monitorPageFromPath('/monitor/details/not-real')).toBe('overview');
    expect(monitorPathForPage('overview')).toBe('/monitor/');
    expect(monitorPathForPage('containers')).toBe('/monitor/details/containers');
    expect(monitorPathForPage('reliability')).toBe('/monitor/details/reliability');
    expect(monitorPathForPage('maintenance')).toBe('/monitor/details/maintenance');
    expect(monitorPathForPage('infrastructure')).toBe('/monitor/details/infrastructure');
    expect(operationalAssessmentPresentation('overview')).toBe('overview');
    expect(operationalAssessmentPresentation('reliability')).toBe('details');
    expect(operationalAssessmentPresentation('resources')).toBe('hidden');
    expect(monitorRangeFromSearch('?range=7d')).toBe('7d');
    expect(monitorRangeFromSearch('?range=30d&extra=1')).toBe('30d');
    expect(monitorRangeFromSearch('?range=invalid')).toBe('24h');
    expect(monitorRangeFromSearch('')).toBe('24h');
    expect(monitorSnapshotIsStale(false, 1_000, 300_000)).toBe(false);
    expect(monitorSnapshotIsStale(false, 1_000, 301_001)).toBe(true);
    expect(monitorSnapshotIsStale(true, 300_000, 300_000)).toBe(true);
    expect(monitorSnapshotIsStale(false, Number.NaN, 300_000)).toBe(true);
  });

  it('uses explicit saved locales and defaults new viewers to Korean', () => {
    expect(chooseInitialLocale('en', ['ko-KR'])).toBe('en');
    expect(chooseInitialLocale('ko', ['en-US'])).toBe('ko');
    expect(chooseInitialLocale(null, ['en-US'])).toBe('ko');
    expect(chooseInitialLocale('invalid', [])).toBe('ko');
  });
});

describe('dashboard derived data', () => {
  it('calculates range summaries and bounds integration gaps', () => {
    const statistics = rangeStatistics([
      sample('2026-01-01T00:00:00.000Z', { cpuPercent: 10, memoryPercent: 40 }),
      sample('2026-01-01T00:01:00.000Z', {
        cpuPercent: 30,
        memoryPercent: 60,
        networkRxBytesPerSecond: 10,
        diskWriteBytesPerSecond: 5,
      }),
      sample('2026-01-01T01:01:00.000Z', {
        cpuPercent: 20,
        memoryPercent: 50,
        networkRxBytesPerSecond: 10,
        diskWriteBytesPerSecond: 5,
      }),
    ]);
    expect(statistics.cpuAverage).toBe(20);
    expect(statistics.cpuPeak).toBe(30);
    expect(statistics.memoryPeak).toBe(60);
    expect(statistics.networkReceivedBytes).toBe(3_600);
    expect(statistics.diskWrittenBytes).toBe(1_800);
  });

  it('buckets operational events by severity', () => {
    const entries: OperationalLogEntry[] = [
      { id: '1', timestamp: '2026-01-01T00:00:00Z', category: 'alert', severity: 'info', kind: 'a', status: 'ok', title: 'a', message: 'a', actor: null, target: null },
      { id: '2', timestamp: '2026-01-01T00:05:00Z', category: 'alert', severity: 'warning', kind: 'b', status: 'warn', title: 'b', message: 'b', actor: null, target: null },
      { id: '3', timestamp: '2026-01-01T00:10:00Z', category: 'alert', severity: 'critical', kind: 'c', status: 'fail', title: 'c', message: 'c', actor: null, target: null },
    ];
    const buckets = eventBuckets(entries, 2);
    expect(buckets).toHaveLength(2);
    expect(buckets.reduce((sum, bucket) => sum + bucket.info + bucket.warning + bucket.critical, 0)).toBe(3);
  });

  it('normalizes, deduplicates, bounds, and deterministically orders Docker and rule events', () => {
    const firing = {
      schemaVersion: 1 as const, rulePackVersion: 'test', idempotencyKey: 'f'.repeat(64),
      ruleId: 'ContainerOOMKilled', target: 'container/monitor', transition: 'firing' as const,
      severity: 'critical' as const, notificationState: 'ready' as const,
      observedAt: '2026-08-30T12:00:00Z', openedAt: '2026-08-30T11:59:00Z', value: 1,
      status: 'ok' as const, labels: {}, description: 'Container was OOM killed.', runbook: 'Inspect memory.',
    };
    const resolved = {
      ...firing, idempotencyKey: 'e'.repeat(64), transition: 'resolved' as const,
      observedAt: '2026-08-30T11:30:00Z', value: 0,
    };
    const oom = {
      id: 'd'.repeat(32), occurredAt: '2026-08-30T12:00:00Z', action: 'oom' as const,
      containerName: 'monitor', project: 'monitor', instanceId: 'a'.repeat(32),
      exitCode: null, healthStatus: null,
    };
    const payload = {
      generatedAt: '2026-08-30T12:00:00Z', range: '1h',
      alerts: [{ timestamp: '2026-08-30T11:00:00Z', severity: 'warning', kind: 'host', status: 'active', message: 'legacy' }],
      reliabilityEvents: [], powerEvents: [], privilegeEvents: [],
      ruleAlerts: { status: 'ok', events: [firing, firing, resolved] },
      dockerEvents: [
        oom, oom,
        { ...oom, id: 'c'.repeat(32), occurredAt: '2026-08-30T11:50:00Z', action: 'die', exitCode: 137 },
        { ...oom, id: 'b'.repeat(32), occurredAt: '2026-08-30T11:10:00Z', action: 'health_status', healthStatus: 'healthy' },
        { ...oom, id: 'old', occurredAt: '2026-08-30T10:59:59Z', action: 'restart' },
      ],
    } as unknown as DashboardPayload;

    const entries = operationalLogs(payload);
    expect(entries.map((entry) => entry.id)).toEqual([
      `docker:${oom.id}`,
      `rule:${firing.idempotencyKey}`,
      `docker:${'c'.repeat(32)}`,
      `rule:${resolved.idempotencyKey}`,
      `docker:${'b'.repeat(32)}`,
      'alert:2026-08-30T11:00:00Z:0',
    ]);
    expect(entries.find((entry) => entry.id === `rule:${resolved.idempotencyKey}`)).toMatchObject({ severity: 'info', category: 'rule' });
    expect(entries.find((entry) => entry.id === `docker:${oom.id}`)).toMatchObject({ severity: 'critical', status: 'oom', target: 'monitor' });
    expect(entries.find((entry) => entry.id === `docker:${'c'.repeat(32)}`)).toMatchObject({ severity: 'critical', status: 'exit-137' });
    expect(entries.find((entry) => entry.id === `docker:${'b'.repeat(32)}`)).toMatchObject({ severity: 'info', status: 'healthy' });
    expect(entries.filter((entry) => entry.category === 'docker')).toHaveLength(3);
    expect(entries.filter((entry) => entry.category === 'rule')).toHaveLength(2);
    expect(entries.map(({ id: _id, ...entry }) => JSON.stringify(entry)).join(' ')).not.toContain('a'.repeat(32));
  });

  it('keeps optional Docker history backward compatible and sorts invalid legacy timestamps last', () => {
    const payload = {
      generatedAt: '2026-08-30T12:00:00Z', range: '24h',
      alerts: [
        { timestamp: 'invalid', severity: 'critical', kind: 'bad', status: 'active', message: 'bad' },
        { timestamp: '2026-08-30T12:00:00Z', severity: 'info', kind: 'good', status: 'ok', message: 'good' },
      ],
      reliabilityEvents: [], powerEvents: [], privilegeEvents: [],
      ruleAlerts: { status: 'unavailable', events: [] },
    } as unknown as DashboardPayload;
    expect(operationalLogs(payload).map((entry) => entry.kind)).toEqual(['good', 'bad']);
  });

  it('routes the reliability timeline to all operational categories and container details to Docker and rule evidence', () => {
    const entries: OperationalLogEntry[] = [
      { id: 'a', timestamp: '2026-01-01T00:00:00Z', category: 'alert', severity: 'warning', kind: 'host', status: 'active', title: 'a', message: 'a', actor: null, target: null },
      { id: 'd', timestamp: '2026-01-01T00:00:00Z', category: 'docker', severity: 'info', kind: 'start', status: 'start', title: 'd', message: 'd', actor: null, target: 'monitor' },
      { id: 'r', timestamp: '2026-01-01T00:00:00Z', category: 'rule', severity: 'critical', kind: 'ContainerDown', status: 'firing', title: 'r', message: 'r', actor: null, target: 'container/monitor' },
      { id: 'p', timestamp: '2026-01-01T00:00:00Z', category: 'power', severity: 'info', kind: 'power', status: 'ok', title: 'p', message: 'p', actor: null, target: null },
      { id: 'v', timestamp: '2026-01-01T00:00:00Z', category: 'privilege', severity: 'info', kind: 'sudo', status: 'ok', title: 'v', message: 'v', actor: null, target: null },
      { id: 'h', timestamp: '2026-01-01T00:00:00Z', category: 'reliability', severity: 'info', kind: 'boot', status: 'ok', title: 'h', message: 'h', actor: null, target: null },
    ];
    expect(relatedLogs(entries, 'reliability').map((entry) => entry.id)).toEqual(['a', 'd', 'r', 'p', 'v', 'h']);
    expect(relatedLogs(entries, 'containers').map((entry) => entry.id)).toEqual(['a', 'd', 'r']);
  });
});
