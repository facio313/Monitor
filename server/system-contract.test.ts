import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-27T12:00:00.000Z');
const temporaryDirectories: string[] = [];

function dataDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-system-contract-'));
  temporaryDirectories.push(directory);
  mkdirSync(join(directory, 'history'));
  return directory;
}

function writeCurrent(directory: string, extra: Record<string, unknown> = {}): void {
  writeFileSync(join(directory, 'current.json'), JSON.stringify({
    generatedAt: '2026-08-27T11:59:30Z',
    latest: {
      timestamp: '2026-08-27T11:59:30Z',
      cpuPercent: 10,
      memoryPercent: 20,
      memoryUsedBytes: 20,
      memoryTotalBytes: 100,
      temperatureC: 45,
      load1: 0.1,
      load5: 0.2,
      load15: 0.3,
      powerState: 'normal',
      supplyVoltageVolts: 5.02,
      throttledFlags: 0,
      gpuMemoryBytes: null,
      gpuClockHz: null,
      networkRxBytesPerSecond: 0,
      networkTxBytesPerSecond: 0,
      diskReadBytesPerSecond: 0,
      diskWriteBytesPerSecond: 0,
    },
    ...extra,
  }));
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('system snapshot contract', () => {
  it('keeps legacy snapshots readable with explicit unknown and zero defaults', () => {
    const directory = dataDirectory();
    writeCurrent(directory);
    const dashboard = readDashboard(directory, '1h', NOW, 300_000);
    const system = dashboard.system;

    expect(dashboard.containerCollection).toEqual({
      status: 'last-known',
      observedAt: '2026-08-27T11:59:30.000Z',
    });

    expect(system.versions).toEqual({
      kernelRunning: null,
      kernelLatestInstalled: null,
      kernelRebootRequired: null,
      bootloaderCurrent: null,
      bootloaderLatest: null,
      bootloaderChannel: null,
      nvmeModel: null,
      nvmeFirmware: null,
      collector: null,
    });
    expect(system.pcie).toEqual({
      configuredGeneration: null,
      negotiatedGeneration: null,
      negotiatedSpeedGtps: null,
      negotiatedWidth: null,
      endpointMaxGeneration: null,
      endpointMaxWidth: null,
      aspmDisabled: null,
      nvmePowerSavingDisabled: null,
      aerCorrectableCount: null,
      aerNonFatalCount: null,
      aerFatalCount: null,
      correctableStatusActive: null,
      nonFatalStatusActive: null,
      fatalStatusActive: null,
    });
    expect(Object.values(system.kernel)).toHaveLength(13);
    expect(Object.values(system.kernel).every(
      (value) => value.count === 0 && value.lastEventAt === null,
    )).toBe(true);
  });

  it('bounds every field and accepts only internally consistent kernel counters', () => {
    const directory = dataDirectory();
    writeCurrent(directory, {
      system: {
        versions: {
          kernelRunning: '6.8.0-1062-raspi',
          kernelLatestInstalled: 'bad\ntoken=secret',
          kernelRebootRequired: false,
          bootloaderCurrent: '2025-12-08',
          bootloaderLatest: '2025-13-99',
          bootloaderChannel: 'unstable',
          nvmeModel: 'Fixture NVMe 256GB',
          nvmeFirmware: 'FW100',
          collector: '1.0.0',
          serial: 'must-not-appear',
        },
        pcie: {
          configuredGeneration: 9,
          negotiatedGeneration: 1,
          negotiatedSpeedGtps: 2.5,
          negotiatedWidth: 1,
          endpointMaxGeneration: 3,
          endpointMaxWidth: 4,
          aspmDisabled: true,
          nvmePowerSavingDisabled: 'yes',
          aerCorrectableCount: 7,
          aerNonFatalCount: -1,
          aerFatalCount: 0,
          correctableStatusActive: true,
          nonFatalStatusActive: false,
          fatalStatusActive: false,
          rawConfig: 'secret',
        },
        kernel: {
          warning: { count: 2, lastEventAt: '2026-08-27T11:58:00Z' },
          oops: { count: 1, lastEventAt: null },
          panic: { count: 0, lastEventAt: '2026-08-27T11:57:00Z' },
          hungTask: { count: 0, lastEventAt: null },
          rcuStall: { count: 4, lastEventAt: '2026-08-27T11:59:00Z' },
          rcuExpedited: { count: 3, lastEventAt: '2026-08-27T11:58:30Z' },
          oomKill: { count: 0, lastEventAt: null },
          filesystemError: { count: 0, lastEventAt: null },
          nvmeReset: { count: 0, lastEventAt: null },
          nvmeIo: { count: 0, lastEventAt: null },
          pcieAerCorrectable: { count: 7, lastEventAt: '2026-08-27T11:59:01Z' },
          pcieAerNonFatal: { count: 0, lastEventAt: null },
          pcieAerFatal: { count: 1, lastEventAt: '2026-08-27T12:02:00Z' },
          raw: 'secret',
        },
      },
    });

    const system = readDashboard(directory, '1h', NOW, 300_000).system;
    expect(system.versions).toMatchObject({
      kernelRunning: '6.8.0-1062-raspi',
      kernelLatestInstalled: null,
      kernelRebootRequired: false,
      bootloaderCurrent: '2025-12-08',
      bootloaderLatest: null,
      bootloaderChannel: null,
      nvmeModel: 'Fixture NVMe 256GB',
    });
    expect(system.pcie).toMatchObject({
      configuredGeneration: null,
      negotiatedGeneration: 1,
      nvmePowerSavingDisabled: null,
      aerCorrectableCount: 7,
      aerNonFatalCount: null,
    });
    expect(system.kernel.warning).toEqual({
      count: 2,
      lastEventAt: '2026-08-27T11:58:00.000Z',
    });
    expect(system.kernel.rcuExpedited).toEqual({
      count: 3,
      lastEventAt: '2026-08-27T11:58:30.000Z',
    });
    expect(system.kernel.oops).toEqual({ count: 0, lastEventAt: null });
    expect(system.kernel.panic).toEqual({ count: 0, lastEventAt: null });
    expect(system.kernel.pcieAerFatal).toEqual({ count: 0, lastEventAt: null });
    expect(JSON.stringify(system)).not.toContain('must-not-appear');
    expect(JSON.stringify(system)).not.toContain('rawConfig');
  });

  it('admits only fixed new kernel and PCIe reliability contracts', () => {
    const directory = dataDirectory();
    writeCurrent(directory);
    const contracts = [
      ['pcie-aer', 'correctable', 'warning', 'Kernel reported a correctable PCIe AER event.'],
      ['pcie-aer', 'nonfatal', 'critical', 'Kernel reported a non-fatal PCIe AER event.'],
      ['pcie-aer', 'fatal', 'critical', 'Kernel reported a fatal PCIe AER event.'],
      ['pcie-link', 'down', 'critical', 'Kernel reported that the PCIe link went down.'],
      ['pcie-link', 'degraded', 'warning', 'Kernel reported degraded PCIe link training.'],
      ['pcie-link', 'recovered', 'info', 'Kernel reported that the PCIe link recovered.'],
      ['rcu-stall', 'expedited', 'warning', 'Kernel reported a short expedited RCU grace-period delay.'],
      ['kernel-warning', 'active', 'warning', 'Kernel reported an internal warning.'],
      ['kernel-oops', 'active', 'critical', 'Kernel reported an oops.'],
      ['kernel-panic', 'active', 'critical', 'Kernel reported a panic.'],
      ['hung-task', 'active', 'critical', 'Kernel reported a hung task.'],
    ] as const;
    const valid = contracts.map(([kind, status, severity, message], index) => ({
      timestamp: `2026-08-27T11:59:${String(50 - index).padStart(2, '0')}Z`,
      severity,
      kind,
      status,
      message,
      durationSeconds: null,
    }));
    writeFileSync(join(directory, 'reliability.jsonl'), [
      ...valid,
      {
        timestamp: '2026-08-27T11:57:00Z', severity: 'critical', kind: 'pcie-link',
        status: 'down', message: 'raw endpoint and token=secret', durationSeconds: null,
      },
    ].map((value) => JSON.stringify(value)).join('\n'));

    const events = readDashboard(directory, '1h', NOW, 300_000).reliabilityEvents;
    expect(events.map(({ kind, status }) => ({ kind, status }))).toEqual(
      contracts.map(([kind, status]) => ({ kind, status })),
    );
    expect(JSON.stringify(events)).not.toContain('secret');
  });
});
