import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { ContainerStatus, DashboardPayload, DiskUsage, SystemEventCount, SystemKernelStatus, SystemPcieStatus } from '../types';
import {
  containerUtilizationChartRows,
  ContainerStatusTable,
  CurrentTrafficWidget,
  currentBootReliabilitySignals,
  highestObservedDiskUsage,
  PcieStatusPanel,
  pcieLinkTone,
  ReliabilitySignalGrid,
  ReliabilityWidget,
  storageCapacityChartRows,
} from './CockpitVisuals';

function event(count = 0, lastEventAt: string | null = null): SystemEventCount {
  return { count, lastEventAt };
}

function kernel(overrides: Partial<SystemKernelStatus> = {}): SystemKernelStatus {
  return {
    warning: event(),
    oops: event(),
    panic: event(),
    hungTask: event(),
    rcuStall: event(),
    rcuExpedited: event(),
    oomKill: event(),
    filesystemError: event(),
    nvmeReset: event(),
    nvmeIo: event(),
    pcieAerCorrectable: event(),
    pcieAerNonFatal: event(),
    pcieAerFatal: event(),
    ...overrides,
  };
}

function pcie(overrides: Partial<SystemPcieStatus> = {}): SystemPcieStatus {
  return {
    configuredGeneration: 1,
    negotiatedGeneration: 1,
    negotiatedSpeedGtps: 2.5,
    negotiatedWidth: 1,
    endpointMaxGeneration: 4,
    endpointMaxWidth: 4,
    aspmDisabled: true,
    nvmePowerSavingDisabled: true,
    aerCorrectableCount: 0,
    aerNonFatalCount: 0,
    aerFatalCount: 0,
    correctableStatusActive: false,
    nonFatalStatusActive: false,
    fatalStatusActive: false,
    ...overrides,
  };
}

function reliabilityPayload(): DashboardPayload {
  return {
    reliability: {
      sshListenersAvailable: true,
      networkLinkAvailable: true,
      nvmeMitigationActive: true,
      collectorGapSeconds: 15,
      bootStartedAt: '2026-08-27T06:26:41Z',
    },
    reliabilityEvents: [],
    system: {
      kernel: kernel({ rcuExpedited: event(3, '2026-08-30T00:02:00Z') }),
      pcie: pcie(),
    },
    containers: [{
      name: 'monitor',
      owner: 'cks',
      state: 'running',
      health: 'healthy',
      cpuPercent: 1.5,
      memoryBytes: 128_000_000,
      memoryPercent: 2.5,
    }],
  } as unknown as DashboardPayload;
}

describe('current-boot reliability presentation', () => {
  it('keeps the overview widget compact and reserves boot-event signals for details', () => {
    const data = reliabilityPayload();
    const compact = renderToStaticMarkup(createElement(ReliabilityWidget, {
      data,
      locale: 'ko',
      onOpen: () => undefined,
    }));
    const detailed = renderToStaticMarkup(createElement(ReliabilityWidget, {
      data,
      locale: 'ko',
      onOpen: () => undefined,
      detailed: true,
    }));

    expect(compact).toContain('SSH 접속 경로');
    expect(compact).toContain('주 네트워크');
    expect(compact).not.toContain('현재 부팅의 커널·장치 사건');
    expect(compact).not.toContain('reliability-signal-grid');
    expect(detailed).toContain('현재 부팅의 커널·장치 사건');
    expect(detailed).toContain('reliability-signal-grid');
    expect(detailed).toContain('3건');
  });

  it('renders the restored service status table for the overview', () => {
    const markup = renderToStaticMarkup(createElement(ContainerStatusTable, {
      data: reliabilityPayload(),
      locale: 'ko',
      onOpen: () => undefined,
      grouped: true,
    }));

    expect(markup).toContain('전체 서비스 상태표');
    expect(markup).toContain('class="table-wrap"');
    expect(markup).toContain('Service / container');
    expect(markup).toContain('Sort services and containers by');
    expect(markup).toContain('monitor');
    expect(markup).toContain('running');
    expect(markup).toContain('상세');
  });

  it('treats configured and negotiated Gen1 x1 as nominal even when the endpoint advertises more', () => {
    const status = pcie();
    expect(pcieLinkTone(status)).toBe('ok');

    const markup = renderToStaticMarkup(createElement(PcieStatusPanel, { pcie: status, locale: 'en' }));
    expect(markup).toContain('Gen1 · 2.5 GT/s · x1');
    expect(markup).toContain('Gen4 · x4');
    expect(markup).toContain('NOMINAL');
    expect(markup).toContain('a higher value is not a fault');
  });

  it('distinguishes a negotiated downgrade, correctable AER, and non-fatal AER', () => {
    expect(pcieLinkTone(pcie({ configuredGeneration: 2, negotiatedGeneration: 1 }))).toBe('caution');
    expect(pcieLinkTone(pcie({ aerCorrectableCount: 1 }))).toBe('caution');
    expect(pcieLinkTone(pcie({ aerNonFatalCount: 1 }))).toBe('danger');
  });

  it('groups kernel, NVMe, PCIe, and filesystem evidence with the newest timestamp', () => {
    const currentKernel = kernel({
      warning: event(2, '2026-08-27T01:00:00Z'),
      rcuStall: event(3, '2026-08-27T02:00:00Z'),
      rcuExpedited: event(2, '2026-08-27T02:30:00Z'),
      nvmeReset: event(1, '2026-08-27T03:00:00Z'),
      pcieAerCorrectable: event(4, '2026-08-27T04:00:00Z'),
      filesystemError: event(1, '2026-08-27T05:00:00Z'),
    });
    const currentPcie = pcie({ aerCorrectableCount: 4 });
    const signals = currentBootReliabilitySignals(currentKernel, currentPcie);

    expect(signals).toEqual([
      { key: 'kernel', count: 7, lastEventAt: '2026-08-27T02:30:00Z', tone: 'danger' },
      { key: 'nvme', count: 1, lastEventAt: '2026-08-27T03:00:00Z', tone: 'danger' },
      { key: 'pcie', count: 4, lastEventAt: '2026-08-27T04:00:00Z', tone: 'caution' },
      { key: 'filesystem', count: 1, lastEventAt: '2026-08-27T05:00:00Z', tone: 'danger' },
    ]);

    const markup = renderToStaticMarkup(createElement(ReliabilitySignalGrid, { kernel: currentKernel, pcie: currentPcie, locale: 'ko' }));
    expect(markup).toContain('커널');
    expect(markup).toContain('NVMe');
    expect(markup).toContain('PCIe');
    expect(markup).toContain('파일시스템');
    expect(markup).toContain('7건');
  });

  it('counts expedited RCU delays as caution without treating them as active stalls', () => {
    expect(currentBootReliabilitySignals(
      kernel({ rcuExpedited: event(2, '2026-08-27T02:30:00Z') }),
      pcie(),
    )[0]).toEqual({
      key: 'kernel',
      count: 2,
      lastEventAt: '2026-08-27T02:30:00Z',
      tone: 'caution',
    });
  });

  it('prioritizes critical log evidence when live PCI status is nominal or unavailable', () => {
    const fatal = currentBootReliabilitySignals(
      kernel({ pcieAerFatal: event(1, '2026-08-27T06:00:00Z') }),
      pcie({
        aerCorrectableCount: 0,
        aerNonFatalCount: 0,
        aerFatalCount: 0,
        correctableStatusActive: null,
        nonFatalStatusActive: null,
        fatalStatusActive: null,
      }),
    );
    expect(fatal.find((signal) => signal.key === 'pcie')?.tone).toBe('danger');

    const hung = currentBootReliabilitySignals(
      kernel({ hungTask: event(1, '2026-08-27T06:01:00Z') }),
      pcie(),
    );
    expect(hung.find((signal) => signal.key === 'kernel')?.tone).toBe('danger');
  });

  it('counts live AER counters and active status without double-counting matching kernel evidence', () => {
    const signals = currentBootReliabilitySignals(
      kernel({
        pcieAerCorrectable: event(2, '2026-08-27T06:02:00Z'),
        pcieAerNonFatal: event(1, '2026-08-27T06:03:00Z'),
      }),
      pcie({
        aerCorrectableCount: 5,
        aerNonFatalCount: 1,
        aerFatalCount: 0,
        fatalStatusActive: true,
      }),
    );

    expect(signals.find((signal) => signal.key === 'pcie')).toEqual({
      key: 'pcie',
      count: 7,
      lastEventAt: '2026-08-27T06:03:00Z',
      tone: 'danger',
    });

    const mirrored = currentBootReliabilitySignals(
      kernel({ pcieAerCorrectable: event(5, '2026-08-27T06:04:00Z') }),
      pcie({ aerCorrectableCount: 5 }),
    );
    expect(mirrored.find((signal) => signal.key === 'pcie')?.count).toBe(5);
  });
});

describe('current traffic presentation', () => {
  it('bounds the latest sanitized app aggregates to eight rows per page', () => {
    const data = {
      currentTraffic: Array.from({ length: 10 }, (_, index) => ({
        app: `app-${String(index + 1).padStart(2, '0')}`,
        requestCount: index + 1,
        status2xx: index + 1,
        status3xx: 0,
        status4xx: 0,
        status5xx: index === 9 ? 1 : 0,
        slowCount: index === 8 ? 1 : 0,
        avgResponseMs: 12.5,
        maxResponseMs: 40,
      })),
    } as unknown as DashboardPayload;
    const markup = renderToStaticMarkup(createElement(CurrentTrafficWidget, { data, locale: 'en' }));
    expect(markup).toContain('Latest request interval');
    expect(markup).toContain('app-10');
    expect(markup).toContain('app-03');
    expect(markup).not.toContain('app-02');
    expect(markup).toContain('1–8 of 10 apps');
    expect(markup).toContain('Client addresses, paths, queries, and headers are not collected');
  });
});

describe('missing telemetry presentation', () => {
  it('does not turn unreported disk usage into a zero-percent vital or capacity bar', () => {
    const disks: DiskUsage[] = [
      { mount: '/unknown', totalBytes: null, usedBytes: null, availableBytes: null, usedPercent: null, inodeUsedPercent: null, readOnly: null },
      { mount: '/empty', totalBytes: 100, usedBytes: 0, availableBytes: 100, usedPercent: 0, inodeUsedPercent: 0, readOnly: false },
      { mount: '/busy', totalBytes: 100, usedBytes: 82, availableBytes: 18, usedPercent: 82, inodeUsedPercent: 20, readOnly: false },
    ];

    expect(highestObservedDiskUsage([disks[0]])).toBeNull();
    expect(highestObservedDiskUsage(disks)).toBe(82);
    expect(storageCapacityChartRows(disks)).toEqual([
      { name: '/empty', used: 0 },
      { name: '/busy', used: 82 },
    ]);
  });

  it('omits containers with no utilization readings and preserves partial readings as gaps', () => {
    const containers: ContainerStatus[] = [
      { name: 'unreported', owner: null, state: 'running', health: 'healthy', cpuPercent: null, memoryBytes: null, memoryPercent: null },
      { name: 'cpu-only', owner: null, state: 'running', health: 'healthy', cpuPercent: 4, memoryBytes: null, memoryPercent: null },
      { name: 'memory-only', owner: null, state: 'running', health: 'healthy', cpuPercent: null, memoryBytes: 700, memoryPercent: 70 },
    ];

    expect(containerUtilizationChartRows(containers)).toEqual([
      { name: 'cpu-only', cpu: 4, memory: null },
      { name: 'memory-only', cpu: null, memory: 70 },
    ]);
  });
});
