import { describe, expect, it } from 'vitest';
import {
  chooseInitialLocale,
  eventBuckets,
  monitorPageFromPath,
  monitorPathForPage,
  rangeStatistics,
} from './dashboard-model';
import type { OperationalLogEntry } from './dashboard-model';
import type { TelemetrySample } from './types';

function sample(timestamp: string, values: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp,
    cpuPercent: null,
    memoryPercent: null,
    memoryUsedBytes: null,
    memoryTotalBytes: null,
    temperatureC: null,
    load1: null,
    load5: null,
    load15: null,
    powerState: null,
    supplyVoltageVolts: null,
    throttledFlags: null,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: null,
    networkTxBytesPerSecond: null,
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
    expect(monitorPageFromPath('/monitor/details/not-real')).toBe('overview');
    expect(monitorPathForPage('overview')).toBe('/monitor/');
    expect(monitorPathForPage('containers')).toBe('/monitor/details/containers');
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
});
