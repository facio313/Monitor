import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from './system-emotion';
import type { DashboardPayload, PeakIncident } from './types';

function payload(): DashboardPayload {
  return {
    generatedAt: '2026-08-30T08:00:05Z',
    latestObservedAt: '2026-08-30T08:00:00Z',
    range: '24h',
    stale: false,
    agent: {
      hostId: 'bonifacio',
      agentId: 'monitor-collector',
      installationEpoch: 'install-1',
      identityGeneration: 1,
      machineIdentityStatus: 'bound',
      bootId: 'boot-1',
      sequence: 1,
      observedAt: '2026-08-30T08:00:00Z',
      receivedAt: '2026-08-30T08:00:01Z',
      expectedIntervalSeconds: 60,
      lifecycle: 'active',
      transport: 'local-file',
      status: 'healthy',
      ageSeconds: 1,
      clockSkewSeconds: 0,
    },
    host: { hostname: 'bonifacio', os: 'Linux', architecture: 'arm64', uptimeSeconds: 4_000, logicalCpuCount: 4 },
    reliability: {
      bootStartedAt: '2026-08-30T06:00:00Z',
      collectorGapSeconds: 60,
      sshListenersAvailable: true,
      networkLinkAvailable: true,
      nvmeMitigationActive: true,
    },
    linux: { status: 'unsupported' } as DashboardPayload['linux'],
    latest: {
      timestamp: '2026-08-30T08:00:00Z',
      cpuPercent: 14,
      memoryPercent: 31,
      memoryUsedBytes: 3_100,
      memoryTotalBytes: 10_000,
      swapTotalBytes: 2_000,
      swapUsedBytes: 0,
      swapPercent: 0,
      cpuPressureSomeAvg10: 0,
      cpuPressureFullAvg10: 0,
      memoryPressureSomeAvg10: 0,
      memoryPressureFullAvg10: 0,
      ioPressureSomeAvg10: 0,
      ioPressureFullAvg10: 0,
      temperatureC: 43,
      load1: 0.4,
      load5: 0.35,
      load15: 0.3,
      powerState: 'normal',
      supplyVoltageVolts: 5.1,
      throttledFlags: 0,
      gpuMemoryBytes: null,
      gpuClockHz: null,
      networkRxBytesPerSecond: 120_000,
      networkTxBytesPerSecond: 80_000,
      networkRxErrorsPerSecond: 0,
      networkTxErrorsPerSecond: 0,
      networkRxDroppedPerSecond: 0,
      networkTxDroppedPerSecond: 0,
      diskReadBytesPerSecond: 10_000,
      diskWriteBytesPerSecond: 15_000,
    },
    series: [],
    telemetrySummary: {
      sampleCount: 1,
      cpuAveragePercent: 14,
      cpuPeakPercent: 14,
      memoryAveragePercent: 31,
      memoryPeakPercent: 31,
      temperatureAverageC: 43,
      temperaturePeakC: 43,
      load1Average: 0.4,
      load1Peak: 0.4,
      networkReceivedBytes: 0,
      networkTransmittedBytes: 0,
      diskReadBytes: 0,
      diskWrittenBytes: 0,
    },
    disks: [{ mount: '/', totalBytes: 100, usedBytes: 34, availableBytes: 62, usedPercent: 34, inodeUsedPercent: 12, readOnly: false }],
    containerCollection: { status: 'fresh', observedAt: '2026-08-30T08:00:00Z' },
    containers: [{ name: 'monitor', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1, memoryBytes: 1_000, memoryPercent: 1 }],
    currentTraffic: [],
    alerts: [],
    ruleEvaluation: {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'test-v1',
      evaluatedAt: '2026-08-30T08:00:00Z',
      summary: {},
      states: {},
    },
    ruleAlerts: { status: 'ok', events: [] },
    privilegeEvents: [],
    powerEvents: [],
    reliabilityEvents: [],
    incidents: [],
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
        kernelRunning: null,
        kernelLatestInstalled: null,
        kernelRebootRequired: false,
        bootloaderCurrent: null,
        bootloaderLatest: null,
        bootloaderChannel: null,
        nvmeModel: null,
        nvmeFirmware: null,
        collector: null,
      },
      pcie: {
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
      },
      kernel: {
        warning: { count: 0, lastEventAt: null },
        oops: { count: 0, lastEventAt: null },
        panic: { count: 0, lastEventAt: null },
        hungTask: { count: 0, lastEventAt: null },
        rcuStall: { count: 0, lastEventAt: null },
        rcuExpedited: { count: 0, lastEventAt: null },
        oomKill: { count: 0, lastEventAt: null },
        filesystemError: { count: 0, lastEventAt: null },
        nvmeReset: { count: 0, lastEventAt: null },
        nvmeIo: { count: 0, lastEventAt: null },
        pcieAerCorrectable: { count: 0, lastEventAt: null },
        pcieAerNonFatal: { count: 0, lastEventAt: null },
        pcieAerFatal: { count: 0, lastEventAt: null },
      },
    },
  };
}

function incidentRecord(
  source: DashboardPayload,
  observedAt: string,
  phase: PeakIncident['phase'],
): PeakIncident {
  return {
    id: 'incident-shared',
    startedAt: '2026-08-30T07:55:00Z',
    observedAt,
    endedAt: phase === 'recovered' ? observedAt : null,
    phase,
    reasons: ['load'],
    metrics: { ...source.latest!, timestamp: observedAt },
    pressure: {
      cpu: { someAvg10: 0, fullAvg10: 0 },
      memory: { someAvg10: 0, fullAvg10: 0 },
      io: { someAvg10: 0, fullAvg10: 0 },
    },
    processes: [],
    containers: [],
    traffic: [],
    peaks: null,
    durationSeconds: phase === 'recovered' ? 300 : null,
  };
}

describe('system affect synthesis', () => {
  it('treats missing observations as dormant rather than nominal', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.mood).toBe('dormant');
    expect(model.score).toBe(0);
    expect(model.dominantPage).toBe('reliability');
  });

  it('keeps a fully observed quiet host serene', () => {
    const model = deriveSystemEmotion({ data: payload(), stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.mood).toBe('serene');
    expect(model.score).toBeGreaterThan(85);
    expect(model.turbulence).toBeLessThan(0.2);
    expect(model.dominantAxis).toBeNull();
    expect(model.dominantPage).toBeNull();
  });

  it('does not let a recovered incident\'s historical active row disturb the field', () => {
    const baseline = deriveSystemEmotion({ data: payload(), stale: false, dangerCount: 0, cautionCount: 0 });
    const data = payload();
    data.incidents = [
      incidentRecord(data, '2026-08-30T07:56:00Z', 'active'),
      incidentRecord(data, '2026-08-30T08:00:00Z', 'recovered'),
    ];

    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.score).toBe(baseline.score);
    expect(model.turbulence).toBe(baseline.turbulence);
    expect(model.mood).toBe('serene');
  });

  it('lets an extreme subsystem reshape the field and route to its evidence', () => {
    const data = payload();
    data.disks[0].usedPercent = 98;
    data.disks[0].inodeUsedPercent = 99;
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.mood).toBe('critical');
    expect(model.dominantAxis).toBe('storage');
    expect(model.dominantPage).toBe('storage');
    expect(model.waveAmplitude).toBeGreaterThan(0.45);
  });

  it('uses an explicit signal-loss state and keeps every visual control bounded', () => {
    const model = deriveSystemEmotion({ data: payload(), stale: true, dangerCount: 1, cautionCount: 9 });
    expect(model.mood).toBe('dormant');
    expect(model.score).toBeGreaterThanOrEqual(0);
    expect(model.score).toBeLessThanOrEqual(100);
    for (const value of [model.energy, model.turbulence, model.coherence, model.volatility, model.waveAmplitude]) {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThanOrEqual(1);
    }
  });

  it('does not invent a CPU count when normalizing load', () => {
    const data = payload();
    data.host.logicalCpuCount = null;
    data.latest!.load1 = 8;
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.axes.find((axis) => axis.key === 'compute')?.intensity).toBe(0);
    expect(model.mood).toBe('serene');
  });

  it.each([90, 100])('does not turn CPU %s or warning-only CPU pressure into a critical field', (cpuPercent) => {
    const data = payload();
    data.latest!.cpuPercent = cpuPercent;
    data.latest!.cpuPressureSomeAvg10 = 100;
    data.latest!.cpuPressureFullAvg10 = 100;
    data.latest!.load1 = 100;
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 1 });
    expect(model.mood).toBe('watchful');
    expect(model.axes.find((axis) => axis.key === 'compute')?.intensity).toBe(0.46);
  });

  it('does not treat host CPU full as either pressure or an observed compute signal', () => {
    const data = payload();
    data.latest!.cpuPercent = null;
    data.latest!.cpuPressureSomeAvg10 = null;
    data.latest!.cpuPressureFullAvg10 = 100;
    data.latest!.load1 = null;
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.axes.find((axis) => axis.key === 'compute')).toMatchObject({ observed: false, intensity: 0 });
    expect(model.mood).not.toBe('critical');
  });

  it('keeps memory-full and I/O PSI warning-only while memory-some supports danger', () => {
    const data = payload();
    data.latest!.memoryPressureFullAvg10 = 100;
    data.latest!.ioPressureFullAvg10 = 100;
    data.latest!.ioPressureSomeAvg10 = 100;
    const warning = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(warning.mood).not.toBe('critical');
    expect(warning.axes.find((axis) => axis.key === 'memory')?.intensity).toBe(0.46);
    expect(warning.axes.find((axis) => axis.key === 'storage')?.intensity).toBe(0.46);
    data.latest!.memoryPressureSomeAvg10 = 10;
    expect(deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 }).mood).toBe('critical');
  });

  it('uses canonical temperature boundaries and preserves the existing active swap gate', () => {
    const data = payload();
    data.latest!.temperatureC = 80;
    data.latest!.swapPercent = 85;
    const quietSwap = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(quietSwap.axes.find((axis) => axis.key === 'thermal')?.intensity).toBe(0.46);
    expect(quietSwap.axes.find((axis) => axis.key === 'memory')?.intensity).toBe(0);
    data.latest!.memoryPressureFullAvg10 = 0.2;
    expect(deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 }).axes.find((axis) => axis.key === 'memory')?.intensity).toBe(1);
    data.latest!.temperatureC = 85;
    expect(deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 }).axes.find((axis) => axis.key === 'thermal')?.intensity).toBe(1);
  });

  it.each([
    [1, 1, 0, false],
    [2, 2, 0, false],
    [100_000, 20, 0, false],
    [100, 4, 0, false],
    [1, 0, 1, false],
    [6, 3, 0, true],
    [19, 19, 0, true],
    [100, 5, 0, true],
  ])('requires both error count and share for HTTP danger (%s requests, %s 5xx, %s 4xx)', (requestCount, status5xx, status4xx, critical) => {
    const data = payload();
    data.currentTraffic = [{
      app: 'fixture', requestCount, status5xx, status4xx,
      status2xx: requestCount - status5xx - status4xx, status3xx: 0,
      slowCount: 0, avgResponseMs: 20, maxResponseMs: 50,
    }];
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.mood === 'critical').toBe(critical);
    expect(model.axes.find((axis) => axis.key === 'network')?.intensity).toBe(critical ? 1 : 0.46);
  });

  it('keeps wholly unobserved disk fields unknown', () => {
    const data = payload();
    data.latest!.ioPressureSomeAvg10 = null;
    data.latest!.ioPressureFullAvg10 = null;
    data.disks = [{
      mount: '/',
      totalBytes: null,
      usedBytes: null,
      availableBytes: null,
      usedPercent: null,
      inodeUsedPercent: null,
      readOnly: null,
    }];
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.axes.find((axis) => axis.key === 'storage')?.observed).toBe(false);
  });

  it('makes a non-metric finding drive both the field and its evidence link', () => {
    const model = deriveSystemEmotion({
      data: payload(),
      stale: false,
      dangerCount: 1,
      cautionCount: 0,
      primaryFinding: { id: 'reboot-required', level: 'danger', scope: 'boot', page: 'maintenance' },
    });
    expect(model.mood).toBe('critical');
    expect(model.dominantAxis).toBe('reliability');
    expect(model.dominantPage).toBe('maintenance');
    expect(model.score).toBeLessThan(25);
    expect(model.turbulence).toBeGreaterThan(0.6);
  });

  it('uses the canonical service classifier for transitional health states', () => {
    const data = payload();
    data.containers[0].health = 'starting';
    const model = deriveSystemEmotion({ data, stale: false, dangerCount: 0, cautionCount: 0 });
    expect(model.axes.find((axis) => axis.key === 'services')?.intensity).toBeGreaterThan(0);
    expect(model.dominantAxis).toBe('services');
  });

  it('keeps the dominant label and destination aligned when a metric outranks a finding', () => {
    const data = payload();
    data.disks[0].usedPercent = 98;
    const model = deriveSystemEmotion({
      data,
      stale: false,
      dangerCount: 0,
      cautionCount: 1,
      primaryFinding: { id: 'reboot-required', level: 'caution', scope: 'current', page: 'maintenance' },
    });
    expect(model.dominantAxis).toBe('storage');
    expect(model.dominantPage).toBe('storage');
  });

  it('routes a recovered boot OOM through the memory axis instead of compute', () => {
    const model = deriveSystemEmotion({
      data: payload(),
      stale: false,
      dangerCount: 1,
      cautionCount: 0,
      primaryFinding: { id: 'memory-oom', level: 'danger', scope: 'boot', page: 'resources' },
    });
    expect(model.dominantAxis).toBe('memory');
    expect(model.dominantPage).toBe('resources');
  });
});
