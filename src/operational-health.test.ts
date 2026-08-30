import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { operationalLogs } from './dashboard-model';
import {
  operationalFindingHref,
  operationalFindings,
} from './operational-health';
import { OperationalGuidance, OperationalHealthOverview, OperationalHealthSummary } from './components/OperationalHealth';
import { OperationalLogView } from './components/OperationalLogView';
import type {
  DashboardPayload,
  PeakIncident,
  SystemEventCount,
  TelemetrySample,
} from './types';

function count(value = 0, lastEventAt: string | null = null): SystemEventCount {
  return { count: value, lastEventAt };
}

function latest(values: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp: '2026-08-30T00:00:00Z',
    cpuPercent: 15,
    memoryPercent: 30,
    memoryUsedBytes: 3_000,
    memoryTotalBytes: 10_000,
    swapTotalBytes: 0,
    swapUsedBytes: 0,
    swapPercent: 0,
    temperatureC: 45,
    load1: 0.4,
    load5: 0.3,
    load15: 0.2,
    cpuPressureSomeAvg10: 0,
    cpuPressureFullAvg10: 0,
    memoryPressureSomeAvg10: 0,
    memoryPressureFullAvg10: 0,
    ioPressureSomeAvg10: 0,
    ioPressureFullAvg10: 0,
    powerState: 'normal',
    supplyVoltageVolts: 5.1,
    throttledFlags: 0,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: 0,
    networkTxBytesPerSecond: 0,
    networkRxErrorsPerSecond: 0,
    networkTxErrorsPerSecond: 0,
    networkRxDroppedPerSecond: 0,
    networkTxDroppedPerSecond: 0,
    diskReadBytesPerSecond: 0,
    diskWriteBytesPerSecond: 0,
    ...values,
  };
}

function payload(): DashboardPayload {
  return {
    generatedAt: '2026-08-30T00:00:05Z',
    range: '24h',
    stale: false,
    latestObservedAt: '2026-08-30T00:00:00Z',
    host: { hostname: 'host', os: 'Linux', architecture: 'arm64', logicalCpuCount: 4, uptimeSeconds: 3_600 },
    reliability: {
      bootStartedAt: '2026-08-29T00:00:00Z',
      collectorGapSeconds: 60,
      sshListenersAvailable: true,
      networkLinkAvailable: true,
      nvmeMitigationActive: true,
    },
    latest: latest(),
    series: [],
    telemetrySummary: {
      sampleCount: 1,
      cpuAveragePercent: 15,
      cpuPeakPercent: 15,
      memoryAveragePercent: 30,
      memoryPeakPercent: 30,
      temperatureAverageC: 45,
      temperaturePeakC: 45,
      load1Average: 0.4,
      load1Peak: 0.4,
      networkReceivedBytes: 0,
      networkTransmittedBytes: 0,
      diskReadBytes: 0,
      diskWrittenBytes: 0,
    },
    incidents: [],
    disks: [{ mount: '/', totalBytes: 100, usedBytes: 40, availableBytes: 60, usedPercent: 40, inodeUsedPercent: 10, readOnly: false }],
    containers: [],
    currentTraffic: [],
    alerts: [],
    privilegeEvents: [],
    powerEvents: [],
    reliabilityEvents: [],
    powerSummary: {
      sampleCount: 1,
      voltageSampleCount: 1,
      minSupplyVoltageVolts: 5.1,
      averageSupplyVoltageVolts: 5.1,
      maxSupplyVoltageVolts: 5.1,
      underVoltageSampleCount: 0,
      throttledSampleCount: 0,
    },
    system: {
      versions: {
        kernelRunning: '6.8.0-1063-raspi',
        kernelLatestInstalled: '6.8.0-1063-raspi',
        kernelRebootRequired: false,
        bootloaderCurrent: '2026-01-01',
        bootloaderLatest: '2026-01-01',
        bootloaderChannel: 'default',
        nvmeModel: 'NVMe',
        nvmeFirmware: '1.0',
        collector: '1',
      },
      pcie: {
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
      },
      kernel: {
        warning: count(),
        oops: count(),
        panic: count(),
        hungTask: count(),
        rcuStall: count(),
        rcuExpedited: count(),
        oomKill: count(),
        filesystemError: count(),
        nvmeReset: count(),
        nvmeIo: count(),
        pcieAerCorrectable: count(),
        pcieAerNonFatal: count(),
        pcieAerFatal: count(),
      },
    },
  };
}

function incident(observedAt: string): PeakIncident {
  return {
    id: `incident-${observedAt}`,
    startedAt: observedAt,
    observedAt,
    endedAt: null,
    phase: 'active',
    reasons: ['load'],
    metrics: latest({ timestamp: observedAt, load1: 9 }),
    pressure: {
      cpu: { someAvg10: 1, fullAvg10: 0 },
      memory: { someAvg10: 0, fullAvg10: 0 },
      io: { someAvg10: 0, fullAvg10: 0 },
    },
    processes: [],
    containers: [],
    traffic: [],
    peaks: null,
    durationSeconds: null,
  };
}

describe('operational health assessment', () => {
  it('stays quiet for a nominal current state and current boot', () => {
    expect(operationalFindings(payload())).toEqual([]);
  });

  it('separates currently stale telemetry from a recovered historical collection gap', () => {
    const recovered = payload();
    recovered.reliability.collectorGapSeconds = 600;
    expect(operationalFindings(recovered)).toEqual([
      expect.objectContaining({ id: 'collection-gap', level: 'caution', scope: 'range' }),
    ]);

    const stale = payload();
    stale.stale = true;
    stale.reliability.collectorGapSeconds = 60;
    stale.telemetrySummary.sampleCount = 0;
    expect(operationalFindings(stale)).toEqual([
      expect.objectContaining({ id: 'collection-stale', level: 'danger', scope: 'current' }),
    ]);
    expect(operationalFindings(stale)[0].evidence[0]).toContain(stale.latestObservedAt!);

    stale.latestObservedAt = null;
    const noSample = operationalFindings(stale)[0];
    expect(noSample.evidence[0]).toContain('유효 표본 없음');
    expect(noSample.evidence[0]).toContain(stale.generatedAt);
    expect(noSample.lastObservedAt).toBe(stale.generatedAt);
  });

  it('classifies and deduplicates short expedited RCU delays without calling them active stalls', () => {
    const data = payload();
    const expedited = {
      timestamp: '2026-08-29T08:34:41.021809Z',
      severity: 'warning' as const,
      kind: 'rcu-stall' as const,
      status: 'expedited',
      message: 'Kernel reported a short expedited RCU grace-period delay.',
      durationSeconds: null,
    };
    data.reliabilityEvents = [expedited, { ...expedited }];
    data.system.kernel.rcuExpedited = count(635, expedited.timestamp);

    const findings = operationalFindings(data);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: 'rcu-expedited',
      level: 'caution',
      scope: 'boot',
      page: 'reliability',
      count: 635,
    });
    expect(operationalFindingHref(findings[0], '7d')).toBe('/monitor/details/reliability?range=7d#issue-rcu-expedited');
  });

  it('falls back to retained range evidence when the current-boot expedited counter is empty', () => {
    const data = payload();
    data.reliabilityEvents = [{
      timestamp: '2026-08-28T08:34:41Z',
      severity: 'warning',
      kind: 'rcu-stall',
      status: 'expedited',
      message: 'retained short delay',
      durationSeconds: null,
    }];

    expect(operationalFindings(data).find((finding) => finding.id === 'rcu-expedited')).toMatchObject({
      level: 'caution',
      scope: 'range',
      count: 1,
    });
  });

  it('shows a real RCU stall as current-boot danger while retaining separate short-delay history', () => {
    const data = payload();
    data.system.kernel.rcuStall = count(1, '2026-08-30T00:01:00Z');
    data.system.kernel.hungTask = count(2, '2026-08-30T00:02:00Z');
    data.system.kernel.rcuExpedited = count(1, '2026-08-29T08:34:41Z');
    data.reliabilityEvents = [{
      timestamp: '2026-08-29T08:34:41Z',
      severity: 'warning',
      kind: 'rcu-stall',
      status: 'expedited',
      message: 'short delay',
      durationSeconds: null,
    }];

    const findings = operationalFindings(data);
    expect(findings.find((finding) => finding.id === 'kernel-stall')).toMatchObject({
      level: 'danger',
      scope: 'boot',
      count: 3,
    });
    expect(findings.find((finding) => finding.id === 'rcu-expedited')).toMatchObject({
      level: 'caution',
      scope: 'boot',
      count: 1,
    });
  });

  it('keeps expedited RCU and generic kernel warnings as separate findings', () => {
    const data = payload();
    data.reliabilityEvents = [
      {
        timestamp: '2026-08-29T08:34:41Z',
        severity: 'warning',
        kind: 'rcu-stall',
        status: 'expedited',
        message: 'short delay',
        durationSeconds: null,
      },
      {
        timestamp: '2026-08-29T08:35:41Z',
        severity: 'warning',
        kind: 'kernel-warning',
        status: 'active',
        message: 'separate warning',
        durationSeconds: null,
      },
    ];
    data.system.kernel.rcuExpedited = count(1, '2026-08-29T08:34:41Z');
    data.system.kernel.warning = count(1, '2026-08-29T08:35:41Z');

    const findings = operationalFindings(data);
    expect(findings.find((finding) => finding.id === 'rcu-expedited')).toMatchObject({ level: 'caution', count: 1 });
    expect(findings.find((finding) => finding.id === 'kernel-warning')).toMatchObject({ level: 'caution', count: 1 });
  });

  it('classifies transitional and uncertain services as caution, not nominal or danger', () => {
    const data = payload();
    data.containers = [
      { name: 'healthy', owner: null, state: 'running', health: 'healthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 },
      { name: 'transitioning', owner: null, state: 'restarting', health: 'none', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 },
      { name: 'unknown', owner: null, state: 'unknown', health: null, cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 },
    ];

    expect(operationalFindings(data).find((finding) => finding.id === 'service-fault')).toMatchObject({
      level: 'caution',
      scope: 'current',
      count: 2,
      evidence: ['위험 0개 · 주의 2개', '0 danger · 2 caution'],
    });
  });

  it('uses logical CPU count, PSI full stalls, swap, and inode headroom in resource decisions', () => {
    const normalizedLoad = payload();
    normalizedLoad.host.logicalCpuCount = 8;
    normalizedLoad.latest = latest({ load1: 6 });
    expect(operationalFindings(normalizedLoad).find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'caution' });

    const fullStall = payload();
    fullStall.latest = latest({ memoryPressureFullAvg10: 5 });
    expect(operationalFindings(fullStall).find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'danger' });

    const swapping = payload();
    swapping.latest = latest({ swapTotalBytes: 1_000, swapUsedBytes: 600, swapPercent: 60 });
    expect(operationalFindings(swapping).find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'caution' });

    const inodePressure = payload();
    inodePressure.disks[0].inodeUsedPercent = 92;
    expect(operationalFindings(inodePressure).find((entry) => entry.id === 'storage-capacity')).toMatchObject({ level: 'danger' });

    const readOnly = payload();
    readOnly.disks[0].readOnly = true;
    expect(operationalFindings(readOnly).find((entry) => entry.id === 'storage-integrity')).toMatchObject({ level: 'danger', scope: 'current' });
  });

  it('reports live network counter faults and sanitized request failures', () => {
    const interfaceFault = payload();
    interfaceFault.latest = latest({ networkRxErrorsPerSecond: 0.02 });
    expect(operationalFindings(interfaceFault).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'caution', page: 'network' });
    interfaceFault.latest.networkRxErrorsPerSecond = 1.2;
    expect(operationalFindings(interfaceFault).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'danger' });

    const traffic = payload();
    traffic.currentTraffic = [{
      app: 'monitor',
      requestCount: 100,
      status2xx: 99,
      status3xx: 0,
      status4xx: 0,
      status5xx: 1,
      slowCount: 0,
      avgResponseMs: 20,
      maxResponseMs: 100,
    }];
    expect(operationalFindings(traffic).find((entry) => entry.id === 'application-traffic')).toMatchObject({ level: 'caution', page: 'network' });
    traffic.currentTraffic[0].status2xx = 90;
    traffic.currentTraffic[0].status5xx = 10;
    expect(operationalFindings(traffic).find((entry) => entry.id === 'application-traffic')).toMatchObject({ level: 'danger' });
  });

  it('marks snapshot-dependent evidence as last-known when collection is stale', () => {
    const data = payload();
    data.stale = true;
    data.latestObservedAt = '2026-08-29T21:00:00Z';
    data.latest = latest({ timestamp: data.latestObservedAt, cpuPercent: 95, supplyVoltageVolts: 4.5, throttledFlags: 1 });
    data.containers = [{ name: 'service', owner: null, state: 'running', health: 'unhealthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 }];
    data.disks = [{ mount: '/', totalBytes: 100, usedBytes: 95, availableBytes: 5, usedPercent: 95, inodeUsedPercent: 20, readOnly: false }];
    data.reliability.networkLinkAvailable = false;
    data.reliability.nvmeMitigationActive = false;
    data.system.pcie.configuredGeneration = 3;
    data.system.pcie.negotiatedGeneration = 1;
    data.system.kernel.rcuExpedited = count(2, '2026-08-29T20:55:00Z');
    data.system.versions.kernelLatestInstalled = '6.8.0-1064-raspi';
    data.system.versions.kernelRebootRequired = true;
    data.incidents = [incident('2026-08-29T23:58:00Z')];

    const findings = operationalFindings(data);
    for (const id of ['service-fault', 'resource-pressure', 'storage-capacity', 'power-quality', 'connectivity', 'pcie-integrity', 'rcu-expedited', 'nvme-mitigation', 'reboot-required'] as const) {
      expect(findings.find((finding) => finding.id === id), id).toMatchObject({ scope: 'last-known' });
    }
    expect(findings.find((finding) => finding.id === 'power-quality')?.evidence[0]).toContain('마지막 표본 4.500V');
    expect(findings.find((finding) => finding.id === 'power-quality')?.evidence[0]).not.toContain('현재 4.500V');
    expect(findings.find((finding) => finding.id === 'active-incident')).toMatchObject({ level: 'caution', scope: 'range' });
  });

  it('raises caution when connectivity or NVMe mitigation state cannot be confirmed', () => {
    const data = payload();
    data.reliability.networkLinkAvailable = null;
    data.reliability.sshListenersAvailable = null;
    data.reliability.nvmeMitigationActive = null;

    expect(operationalFindings(data).find((finding) => finding.id === 'connectivity')).toMatchObject({
      level: 'caution',
      scope: 'current',
      count: 2,
    });
    expect(operationalFindings(data).find((finding) => finding.id === 'nvme-mitigation')).toMatchObject({
      level: 'caution',
      scope: 'current',
      evidence: ['보호 설정 확인 불가', 'mitigation state unknown'],
    });
  });

  it('ranks current danger before boot and range observations and maps each finding to its system page', () => {
    const data = payload();
    data.containers = [{ name: 'service', owner: null, state: 'running', health: 'unhealthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 }];
    data.latest = latest({ supplyVoltageVolts: 4.5, throttledFlags: 1 });
    data.disks = [{ mount: '/', totalBytes: 100, usedBytes: 95, availableBytes: 5, usedPercent: 95, inodeUsedPercent: 20, readOnly: false }];
    data.system.kernel.filesystemError = count(1, '2026-08-29T23:50:00Z');
    data.system.versions.kernelLatestInstalled = '6.8.0-1064-raspi';
    data.system.versions.kernelRebootRequired = true;

    const findings = operationalFindings(data);
    expect(findings.slice(0, 3).every((finding) => finding.level === 'danger' && finding.scope === 'current')).toBe(true);
    expect(findings.find((finding) => finding.id === 'service-fault')?.page).toBe('containers');
    expect(findings.find((finding) => finding.id === 'power-quality')?.page).toBe('power');
    expect(findings.find((finding) => finding.id === 'power-quality')?.evidence[0]).toContain('현재 제한 포함');
    expect(findings.find((finding) => finding.id === 'storage-capacity')?.page).toBe('storage');
    expect(findings.find((finding) => finding.id === 'storage-integrity')?.scope).toBe('boot');
    expect(findings.find((finding) => finding.id === 'reboot-required')?.page).toBe('maintenance');
  });

  it('downgrades an old unresolved incident record to selected-range caution instead of claiming a current danger', () => {
    const old = payload();
    old.incidents = [incident('2026-08-29T20:00:00Z')];
    expect(operationalFindings(old).find((finding) => finding.id === 'active-incident')).toMatchObject({
      level: 'caution',
      scope: 'range',
    });

    const fresh = payload();
    fresh.incidents = [incident('2026-08-29T23:58:00Z')];
    expect(operationalFindings(fresh).find((finding) => finding.id === 'active-incident')).toMatchObject({
      level: 'danger',
      scope: 'current',
    });
  });

  it('labels a latched throttle-history bit as current-boot evidence rather than a current fault', () => {
    const data = payload();
    data.latest = latest({ throttledFlags: 0x80000 });
    expect(operationalFindings(data).find((finding) => finding.id === 'power-quality')).toMatchObject({
      level: 'caution',
      scope: 'boot',
      count: 1,
      lastObservedAt: null,
    });
  });

  it('uses the actual selected-range power anomaly time without presenting the latest normal voltage as faulty', () => {
    const data = payload();
    data.series = [
      latest({ timestamp: '2026-08-29T22:00:00Z', supplyVoltageVolts: 4.7 }),
      latest({ timestamp: '2026-08-30T00:00:00Z', supplyVoltageVolts: 5.1 }),
    ];
    data.powerSummary.underVoltageSampleCount = 1;

    const finding = operationalFindings(data).find((entry) => entry.id === 'power-quality');
    expect(finding).toMatchObject({ scope: 'range', lastObservedAt: '2026-08-29T22:00:00Z' });
    expect(finding?.evidence[0]).toContain('저전압 표본 1건');
    expect(finding?.evidence[0]).not.toContain('현재 5.100V');
  });

  it('treats PCIe status bits as current-boot evidence unless the negotiated link is currently downgraded', () => {
    const historic = payload();
    historic.system.pcie.correctableStatusActive = true;
    expect(operationalFindings(historic).find((finding) => finding.id === 'pcie-integrity')).toMatchObject({
      level: 'caution',
      scope: 'boot',
      count: 1,
    });

    const downgraded = payload();
    downgraded.system.pcie.configuredGeneration = 3;
    downgraded.system.pcie.negotiatedGeneration = 1;
    expect(operationalFindings(downgraded).find((finding) => finding.id === 'pcie-integrity')).toMatchObject({
      level: 'caution',
      scope: 'current',
    });
  });

  it('preserves canonical info severity instead of promoting an active status to warning', () => {
    const data = payload();
    data.reliabilityEvents = [{
      timestamp: '2026-08-30T00:00:00Z',
      severity: 'info',
      kind: 'nvme-mitigation',
      status: 'active',
      message: 'Mitigation active.',
      durationSeconds: null,
    }];
    expect(operationalLogs(data)[0].severity).toBe('info');
  });
});

describe('operational health presentation', () => {
  it('keeps every dangerous finding visible instead of hiding danger behind the more-items disclosure', () => {
    const data = payload();
    data.containers = [{ name: 'service', owner: null, state: 'running', health: 'unhealthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 }];
    data.latest = latest({ cpuPercent: 95, supplyVoltageVolts: 4.5, throttledFlags: 1 });
    data.disks = [{ mount: '/', totalBytes: 100, usedBytes: 95, availableBytes: 5, usedPercent: 95, inodeUsedPercent: 20, readOnly: false }];
    data.reliability.networkLinkAvailable = false;
    data.system.kernel.panic = count(1, '2026-08-29T23:55:00Z');
    const findings = operationalFindings(data);
    expect(findings.filter((finding) => finding.level === 'danger').length).toBeGreaterThan(4);

    const markup = renderToStaticMarkup(createElement(OperationalHealthSummary, {
      findings,
      locale: 'ko',
      range: '24h',
      onNavigate: vi.fn(),
    }));
    expect(markup).not.toContain('health-more-findings');
    expect(markup).toContain('커널 Oops 또는 패닉');
  });

  it('renders named, reload-safe summary links instead of severity counts alone', () => {
    const data = payload();
    data.reliabilityEvents = [{
      timestamp: '2026-08-29T08:34:41Z',
      severity: 'warning',
      kind: 'rcu-stall',
      status: 'expedited',
      message: 'short delay',
      durationSeconds: null,
    }];
    const findings = operationalFindings(data);
    const markup = renderToStaticMarkup(createElement(OperationalHealthSummary, {
      findings,
      locale: 'ko',
      range: '7d',
      onNavigate: vi.fn(),
    }));

    expect(markup).toContain('지금 확인할 항목');
    expect(markup).toContain('짧은 RCU expedited 지연');
    expect(markup).toContain('선택 기간 관측');
    expect(markup).toContain('href="/monitor/details/reliability?range=7d#issue-rcu-expedited"');
    expect(markup).toContain('원인·증상·해결');
    expect(markup).toContain('aria-live="polite"');
    expect(markup).not.toContain('상세와 해결 방법 보기');
  });

  it('keeps the home assessment compact and routes the full list to reliability details', () => {
    const data = payload();
    data.reliabilityEvents = [{
      timestamp: '2026-08-29T08:34:41Z',
      severity: 'warning',
      kind: 'rcu-stall',
      status: 'expedited',
      message: 'short delay',
      durationSeconds: null,
    }];
    const findings = operationalFindings(data);
    const markup = renderToStaticMarkup(createElement(OperationalHealthOverview, {
      findings,
      locale: 'ko',
      range: '7d',
      onNavigate: vi.fn(),
    }));

    expect(markup).toContain('운영 판단 개요');
    expect(markup).toContain('홈에서는 핵심 상태만 요약');
    expect(markup).toContain('href="/monitor/details/reliability?range=7d"');
    expect(markup).toContain('전체 진단 보기');
    expect(markup).not.toContain('health-finding-grid');
    expect(markup).not.toContain('health-more-findings');
    expect(markup).not.toContain('짧은 RCU expedited 지연');
  });

  it('renders a linked detail guide with problem, symptoms, and resolution sections in Korean and English', () => {
    const data = payload();
    data.system.kernel.rcuStall = count(1, '2026-08-30T00:01:00Z');
    const findings = operationalFindings(data);
    const korean = renderToStaticMarkup(createElement(OperationalGuidance, { findings, locale: 'ko', page: 'reliability', range: '30d' }));
    const english = renderToStaticMarkup(createElement(OperationalGuidance, { findings, locale: 'en', page: 'reliability', range: '30d' }));

    expect(korean).toContain('id="issue-kernel-stall"');
    expect(korean).toContain('aria-labelledby="issue-kernel-stall-title"');
    expect(korean).toContain('문제점');
    expect(korean).toContain('나타나는 증상');
    expect(korean).toContain('해결·확인 방법');
    expect(korean).toContain('href="/monitor/details/reliability?range=30d#system-reliability"');
    expect(english).toContain('Problem');
    expect(english).toContain('Likely symptoms');
    expect(english).toContain('Resolution and checks');
    expect(english).toContain('Recorded kernel stall');
    expect(english).toContain('does not prove it is still active');
    expect(english).not.toContain('active RCU stalls');
  });

  it('renders a quiet positive summary when nothing requires attention', () => {
    const markup = renderToStaticMarkup(createElement(OperationalHealthSummary, {
      findings: [],
      locale: 'ko',
      range: '24h',
      onNavigate: vi.fn(),
    }));
    expect(markup).toContain('즉시 대응할 항목 없음');
    expect(markup).toContain('aria-label="위험 0개, 주의 0개"');
    expect(markup).not.toContain('health-finding-card');
  });

  it('localizes expedited and recorded kernel statuses without claiming old events are still occurring', () => {
    const common = {
      timestamp: '2026-08-30T00:00:00Z',
      category: 'reliability' as const,
      severity: 'warning' as const,
      message: 'sanitized event',
      actor: null,
      target: null,
    };
    const entries = [
      { ...common, id: 'expedited', kind: 'rcu-stall', status: 'expedited', title: 'rcu-stall · expedited' },
      { ...common, id: 'active', kind: 'hung-task', status: 'active', title: 'hung-task · active' },
      { ...common, id: 'mitigation', kind: 'nvme-mitigation', status: 'active', title: 'nvme-mitigation · active' },
    ];
    const korean = renderToStaticMarkup(createElement(OperationalLogView, { locale: 'ko', entries }));
    const english = renderToStaticMarkup(createElement(OperationalLogView, { locale: 'en', entries }));
    expect(korean).toContain('커널 RCU 지연 · 짧은 지연');
    expect(korean).toContain('커널 작업 정지 · 발생 기록');
    expect(korean).toContain('NVMe 완화 조치 · 적용됨');
    expect(english).toContain('hung task · recorded');
    expect(english).toContain('nvme mitigation · enabled');
    expect(english).not.toContain('hung-task · active');
  });
});
