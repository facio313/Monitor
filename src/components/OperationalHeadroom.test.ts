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
    data.latest!.memoryPressureFullAvg10 = 4.9;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'memory-psi')?.tone).toBe('ok');
    data.latest!.memoryPressureFullAvg10 = 5;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'memory-psi')?.tone).toBe('caution');
    data.latest!.memoryPressureSomeAvg10 = 10;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'memory-psi')?.tone).toBe('danger');
  });

  it('ignores host CPU full and bounds warning-only PSI without an infinite scale', () => {
    const data = payload();
    data.latest!.cpuPressureFullAvg10 = 100;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'cpu-psi')).toMatchObject({ tone: 'ok', level: 0 });
    data.latest!.cpuPressureSomeAvg10 = 20;
    const cpu = operationalHeadroomReadings(data, 'en').find((item) => item.key === 'cpu-psi');
    expect(cpu).toMatchObject({ tone: 'caution', level: 1 });
    expect(cpu?.detail).toContain('not applicable');
    data.latest!.cpuPressureSomeAvg10 = null;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'cpu-psi')).toMatchObject({ tone: 'unknown', level: null });
    data.latest!.ioPressureFullAvg10 = 8;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'io-psi')).toMatchObject({ tone: 'caution', level: 1 });
    data.latest!.ioPressureSomeAvg10 = 100;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'io-psi')?.tone).toBe('caution');
  });

  it('uses canonical load, disk and inode boundaries', () => {
    const data = payload();
    data.latest!.load1 = 6;
    data.disks = [{ mount: '/', totalBytes: 100, usedBytes: 90, availableBytes: 10, usedPercent: 90, inodeUsedPercent: 85, readOnly: false }];
    const readings = operationalHeadroomReadings(data, 'en');
    expect(readings.find((item) => item.key === 'load-per-cpu')).toMatchObject({ value: '1.50×', tone: 'caution' });
    expect(readings.find((item) => item.key === 'free-space')?.tone).toBe('caution');
    expect(readings.find((item) => item.key === 'inodes')?.tone).toBe('caution');
    data.host.logicalCpuCount = null;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'load-per-cpu')?.tone).toBe('unknown');
  });

  it('does not treat retained swap as pressure without an active memory signal', () => {
    const data = payload();
    data.latest!.swapPercent = 90;
    data.latest!.memoryPercent = 40;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'swap')?.tone).toBe('ok');
    data.latest!.memoryPressureFullAvg10 = 0.2;
    expect(operationalHeadroomReadings(data, 'en').find((item) => item.key === 'swap')?.tone).toBe('danger');
  });
});
