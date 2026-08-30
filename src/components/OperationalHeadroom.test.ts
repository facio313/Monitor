import { describe, expect, it } from 'vitest';
import type { DashboardPayload } from '../types';
import { operationalHeadroomReadings } from './OperationalHeadroom';

function payload(): DashboardPayload {
  return {
    host: { logicalCpuCount: 4 },
    latest: {
      load1: 1,
      cpuPressureSomeAvg10: 0,
      cpuPressureFullAvg10: 0,
      memoryPressureSomeAvg10: 0,
      memoryPressureFullAvg10: 0,
      ioPressureSomeAvg10: 0,
      ioPressureFullAvg10: 0,
      swapPercent: 0,
      swapTotalBytes: 0,
    },
    disks: [],
  } as unknown as DashboardPayload;
}

describe('operational headroom readings', () => {
  it('selects the fullest filesystem instead of the smallest absolute filesystem', () => {
    const data = payload();
    data.disks = [
      { mount: '/boot', totalBytes: 100, usedBytes: 40, availableBytes: 60, usedPercent: 40, inodeUsedPercent: 10, readOnly: false },
      { mount: '/', totalBytes: 10_000, usedBytes: 9_500, availableBytes: 500, usedPercent: 95, inodeUsedPercent: 20, readOnly: false },
    ];
    const reading = operationalHeadroomReadings(data, 'en').find((item) => item.key === 'free-space');
    expect(reading).toMatchObject({ value: '95.0%', tone: 'danger' });
    expect(reading?.detail).toContain('/');
    expect(reading?.detail).toContain('available');
  });

  it('keeps partially observed mount modes unknown unless a read-only mount is seen', () => {
    const data = payload();
    data.disks = [
      { mount: '/', totalBytes: 100, usedBytes: 40, availableBytes: 60, usedPercent: 40, inodeUsedPercent: 10, readOnly: false },
      { mount: '/data', totalBytes: 100, usedBytes: 40, availableBytes: 60, usedPercent: 40, inodeUsedPercent: 10, readOnly: null },
    ];
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'read-only')).toMatchObject({
      value: '—',
      tone: 'unknown',
    });
  });

  it('classifies PSI some and full values against the same thresholds as findings', () => {
    const data = payload();
    data.latest!.memoryPressureSomeAvg10 = 0;
    data.latest!.memoryPressureFullAvg10 = 3;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'memory-psi')?.tone).toBe('caution');
    data.latest!.memoryPressureFullAvg10 = 5;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'memory-psi')?.tone).toBe('danger');
  });
});
