import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { operationalLogs } from './dashboard-model';
import {
  operationalFindingHref,
  operationalFindings,
  operationalServiceStates,
} from './operational-health';
import { OperationalGuidance, OperationalHealthOverview, OperationalHealthSummary } from './components/OperationalHealth';
import { OperationalLogView } from './components/OperationalLogView';
import type {
  DashboardPayload,
  LinuxDiagnostics,
  PeakIncident,
  SystemEventCount,
  TelemetrySample,
} from './types';

function linuxDiagnostics(): LinuxDiagnostics {
  const capacity = () => ({ status: 'supported' as const, current: 1, maximum: 100, usedPercent: 1 });
  return {
    schemaVersion: 1,
    collectedAt: '2026-08-30T00:00:00Z',
    status: 'supported',
    resources: {
      status: 'supported', processCount: 10, processCountIsLowerBound: false,
      observedProcessCount: 10, zombieCount: 0, threadCount: 20,
      scanTruncated: false, deadlineReached: false,
      pid: capacity(), systemFileDescriptors: capacity(), cgroupPids: { ...capacity(), version: 2 },
    },
    storage: { status: 'supported', truncated: false, devices: [] },
    network: {
      status: 'supported',
      tcp: {
        status: 'supported', rateStatus: 'ok', outgoingSegmentsPerSecond: 1,
        retransmittedSegmentsPerSecond: 0, retransmissionPercent: 0,
        states: {
          established: 1, synSent: 0, synRecv: 0, finWait1: 0, finWait2: 0,
          timeWait: 0, close: 0, closeWait: 0, lastAck: 0, listen: 1,
          closing: 0, newSynRecv: 0,
        },
        socketScanStatus: 'supported', socketScanTruncated: false,
        ephemeralPorts: { ...capacity(), rangeStart: 32_768, rangeEnd: 60_999 },
        conntrack: capacity(),
      },
    },
    reliability: {
      status: 'supported',
      clock: {
        status: 'supported', uptimeSeconds: 3_600, bootTime: '2026-08-29T23:00:00Z',
        rebootDetectedSincePreviousSample: false, unexpectedReboot: false,
        unexpectedRebootStatus: 'not-detected',
        timeSync: {
          status: 'supported', reason: null, synchronized: true, ntpEnabled: true,
          ntpSupported: true, clockDriftMilliseconds: 0, clockDriftStatus: 'supported',
        },
      },
      systemd: { status: 'supported', reason: null, truncated: false, units: [] },
    },
    power: {
      status: 'supported', truncated: false, maximumTemperatureCelsius: 45,
      sensors: [], fans: [],
      raspberryPi: {
        status: 'supported', detected: true, temperatureCelsius: 45,
        supplyVoltageVolts: 5.1, throttledFlags: 0, currentUnderVoltage: false,
        currentFrequencyCapped: false, currentThrottled: false,
        currentSoftTemperatureLimit: false, underVoltageOccurred: false,
        frequencyCapOccurred: false, throttlingOccurred: false,
        softTemperatureLimitOccurred: false, flagSource: 'vcgencmd',
      },
    },
  };
}

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
    agent: {
      hostId: '11111111-1111-4111-8111-111111111111',
      agentId: '22222222-2222-4222-8222-222222222222',
      installationEpoch: '2026-08-29T00:00:00Z',
      identityGeneration: 1,
      machineIdentityStatus: 'bound',
      bootId: '0123456789abcdef0123456789abcdef',
      sequence: 10,
      observedAt: '2026-08-30T00:00:00Z',
      receivedAt: '2026-08-30T00:00:00Z',
      expectedIntervalSeconds: 60,
      lifecycle: 'active',
      transport: 'local-file',
      status: 'healthy',
      ageSeconds: 5,
      clockSkewSeconds: 0,
    },
    host: { hostname: 'host', os: 'Linux', architecture: 'arm64', logicalCpuCount: 4, uptimeSeconds: 3_600 },
    reliability: {
      bootStartedAt: '2026-08-29T00:00:00Z',
      collectorGapSeconds: 60,
      sshListenersAvailable: true,
      networkLinkAvailable: true,
      nvmeMitigationActive: true,
    },
    linux: { status: 'unsupported' } as DashboardPayload['linux'],
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
    containerCollection: { status: 'fresh', observedAt: '2026-08-30T00:00:00Z' },
    containers: [],
    currentTraffic: [],
    alerts: [],
    ruleEvaluation: {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'test',
      evaluatedAt: '2026-08-30T00:00:00Z',
      summary: {},
      states: {},
    },
    ruleAlerts: { status: 'ok', events: [] },
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

  it('surfaces projected Linux resource, network, storage, reliability, and power evidence on its owning pages', () => {
    const data = payload();
    data.linux = linuxDiagnostics();
    data.linux.resources.pid.usedPercent = 92;
    data.linux.network.tcp.retransmissionPercent = 6;
    data.linux.storage.devices = [{
      name: 'nvme0n1', type: 'disk', rotational: false, rateStatus: 'ok',
      queueDepth: 1, readLatencyMilliseconds: 10, writeLatencyMilliseconds: 20,
      averageLatencyMilliseconds: 25, utilizationPercent: 82, averageQueueDepth: 1,
      smartStatus: 'supported', raidStatus: 'supported', raidDegradedDevices: 1,
      raidArrayState: 'degraded',
    }];
    data.linux.reliability.clock.timeSync.synchronized = false;
    data.linux.reliability.systemd.units = [{
      unit: 'monitor.service', loadState: 'loaded', activeState: 'failed', subState: 'failed',
      restartCount: 2, restartCountStatus: 'systemd_manager', result: 'exit-code',
      execMainStatus: 1, invocationStatus: 'supported',
    }];
    data.linux.power.raspberryPi.currentFrequencyCapped = true;

    const findings = operationalFindings(data);
    expect(findings.find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'danger', scope: 'current', page: 'resources' });
    expect(findings.find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'danger', scope: 'current', page: 'network' });
    expect(findings.find((entry) => entry.id === 'storage-integrity')).toMatchObject({ level: 'danger', scope: 'current', page: 'storage' });
    expect(findings.find((entry) => entry.id === 'linux-reliability')).toMatchObject({ level: 'danger', scope: 'current', page: 'reliability', count: 2 });
    expect(findings.find((entry) => entry.id === 'power-quality')).toMatchObject({ level: 'danger', scope: 'current', page: 'power' });
    expect(operationalFindingHref(findings.find((entry) => entry.id === 'linux-reliability')!, '7d'))
      .toBe('/monitor/details/reliability?range=7d#issue-linux-reliability');
  });

  it('keeps unsupported Linux and an explicitly unconfigured healthcheck neutral', () => {
    const data = payload();
    data.containers = [{
      name: 'worker', owner: null, state: 'running', health: 'none', healthcheckConfigured: false,
      cpuPercent: 1, memoryBytes: 1, memoryPercent: 1,
    }];
    expect(operationalFindings(data)).toEqual([]);

    data.linux = linuxDiagnostics();
    data.linux.network.tcp.rateStatus = 'warmup';
    data.linux.network.tcp.socketScanStatus = 'unsupported';
    expect(operationalFindings(data)).toEqual([]);
  });

  it('keeps synchronized fallback telemetry and successful oneshot invocations neutral', () => {
    const data = payload();
    data.linux = linuxDiagnostics();
    data.linux.reliability.clock.timeSync.status = 'partial';
    data.linux.reliability.clock.timeSync.synchronized = true;
    data.linux.reliability.systemd.reason = 'bounded_runtime_observation';
    data.linux.reliability.systemd.units = [
      {
        unit: 'monitor-collector.service', loadState: 'unknown', activeState: 'active', subState: 'running',
        restartCount: 1_324, restartCountStatus: 'observed_invocation_changes', result: 'unknown',
        execMainStatus: null, invocationStatus: 'supported',
      },
      {
        unit: 'monitor-container-exporter.service', loadState: 'unknown', activeState: 'inactive', subState: 'unknown',
        restartCount: 1_324, restartCountStatus: 'observed_invocation_changes', result: 'unknown',
        execMainStatus: null, invocationStatus: 'supported',
      },
      {
        unit: 'monitor-container-exporter.service', loadState: 'loaded', activeState: 'inactive', subState: 'dead',
        restartCount: 0, restartCountStatus: 'systemd_manager', result: 'success',
        execMainStatus: 0, invocationStatus: null,
      },
    ];

    expect(operationalFindings(data).find((entry) => entry.id === 'linux-reliability')).toBeUndefined();

    data.linux.reliability.clock.timeSync.status = 'collection_error';
    expect(operationalFindings(data).find((entry) => entry.id === 'linux-reliability')).toMatchObject({
      level: 'danger', count: 1,
    });

    data.linux.reliability.clock.timeSync.status = 'partial';
    data.linux.reliability.systemd.units = [{
      unit: 'nginx.service', loadState: 'unknown', activeState: 'inactive', subState: 'unknown',
      restartCount: 18, restartCountStatus: 'observed_invocation_changes', result: 'unknown',
      execMainStatus: null, invocationStatus: 'supported',
    }];
    expect(operationalFindings(data).find((entry) => entry.id === 'linux-reliability')).toMatchObject({
      level: 'danger', count: 1,
      evidence: [expect.stringContaining('nginx.service inactive'), expect.stringContaining('nginx.service inactive')],
    });
  });

  it('surfaces a top-level Linux collection failure even when diagnostics have no schema version', () => {
    const data = payload();
    data.linux = linuxDiagnostics();
    data.linux.schemaVersion = null;
    data.linux.status = 'collection_error';

    expect(operationalFindings(data)).toEqual([
      expect.objectContaining({
        id: 'linux-reliability', level: 'danger', scope: 'current', count: 1,
        evidence: [expect.stringContaining('Linux 진단 collection_error'), expect.stringContaining('Linux diagnostics collection_error')],
      }),
    ]);
  });

  it('aggregates Docker runtime and security risks by container and distinguishes event gaps from access failure', () => {
    const data = payload();
    data.containers = [{
      name: 'monitor', project: 'monitor', owner: null, state: 'running', health: 'healthy',
      healthcheckConfigured: true, cpuPercent: 1, memoryBytes: 950, memoryPercent: 1,
      memoryLimitBytes: 1_000, restartCountDelta: 3, oomKilled: true,
      pidCount: 95, pidLimit: 100, cpuThrottledPercent: 25,
      networkErrorsPerSecond: 1.2, instanceId: 'a'.repeat(32), privileged: true,
      dockerSocketMounted: true, sensitiveBindMounted: true,
      writableSensitiveBindMounted: true, dangerousCapabilityCount: 2,
    }];
    data.dockerEventCollection = {
      status: 'gap', observedAt: '2026-08-30T00:00:01Z', cursorAt: '2026-08-30T00:00:00Z',
      reconnectCount: 2, gapCount: 1, gapDetected: true, logCollectionStatus: 'unsupported',
    };

    const findings = operationalFindings(data);
    expect(operationalServiceStates(data)).toEqual(['danger']);
    expect(findings.find((entry) => entry.id === 'service-fault')).toMatchObject({ level: 'danger', scope: 'current', count: 1 });
    expect(findings.find((entry) => entry.id === 'container-security')).toMatchObject({ level: 'danger', scope: 'current', count: 1 });
    expect(findings.find((entry) => entry.id === 'docker-event-coverage')).toMatchObject({ level: 'caution', scope: 'range', count: 1 });
    expect(operationalFindingHref(findings.find((entry) => entry.id === 'container-security')!, '24h'))
      .toBe('/monitor/details/containers?range=24h#issue-container-security');

    data.dockerEventCollection.status = 'permission-denied';
    expect(operationalFindings(data).find((entry) => entry.id === 'docker-event-coverage')).toMatchObject({ level: 'danger', scope: 'current' });
    data.stale = true;
    expect(operationalFindings(data).find((entry) => entry.id === 'docker-event-coverage')).toMatchObject({ level: 'danger', scope: 'last-known' });
  });

  it('downgrades a known read-only sensitive bind but flags writable or unknown access', () => {
    const data = payload();
    data.containers = [{
      name: 'monitor', project: 'monitor', owner: 'cks', state: 'running', health: 'healthy',
      healthcheckConfigured: true, cpuPercent: 1, memoryBytes: 100, memoryPercent: 1,
      sensitiveBindMounted: true, writableSensitiveBindMounted: false,
    }];

    expect(operationalFindings(data).find((entry) => entry.id === 'container-security')).toMatchObject({
      level: 'caution', count: 1,
      evidence: [expect.stringContaining('읽기 전용 민감 bind'), expect.stringContaining('read-only sensitive bind')],
    });

    data.containers[0].writableSensitiveBindMounted = true;
    expect(operationalFindings(data).find((entry) => entry.id === 'container-security')).toMatchObject({
      level: 'danger', count: 1,
      evidence: [expect.stringContaining('쓰기 가능한 민감 bind'), expect.stringContaining('writable sensitive bind')],
    });

    data.containers[0].writableSensitiveBindMounted = null;
    expect(operationalFindings(data).find((entry) => entry.id === 'container-security')).toMatchObject({
      level: 'danger', count: 1,
      evidence: [expect.stringContaining('쓰기 권한 미확인'), expect.stringContaining('writability unverified')],
    });
  });

  it('surfaces reduced synthetic failures, latency, and certificate risk without requiring endpoint URLs', () => {
    const data = payload();
    data.syntheticProbeCollection = {
      status: 'fresh', observedAt: '2026-08-30T00:00:00Z',
    };
    data.syntheticProbes = [{
      id: 'public-ready', status: 'tls', checkedAt: '2026-08-30T00:00:00Z',
      httpStatus: null, redirectCount: 0, latencyMilliseconds: 3_500,
      certificateExpiresAt: null, certificateDaysRemaining: null,
    }, {
      id: 'certificate-watch', status: 'ok', checkedAt: '2026-08-30T00:00:01Z',
      httpStatus: 200, redirectCount: 0, latencyMilliseconds: 25,
      certificateExpiresAt: '2026-09-05T00:00:00Z', certificateDaysRemaining: 6,
    }];

    expect(operationalFindings(data).find((entry) => entry.id === 'synthetic-availability')).toMatchObject({
      level: 'danger', scope: 'current', page: 'network', count: 2,
      evidence: [
        expect.stringContaining('public-ready 상태 tls'),
        expect.stringContaining('public-ready status tls'),
      ],
    });
    expect(JSON.stringify(operationalFindings(data))).not.toContain('token=');
    expect(JSON.stringify(operationalFindings(data))).not.toContain('://');

    data.syntheticProbeCollection = { status: 'permission-denied', observedAt: null };
    data.syntheticProbes = [];
    expect(operationalFindings(data).find((entry) => entry.id === 'synthetic-availability')).toMatchObject({
      level: 'danger', scope: 'current', count: null,
    });

    data.syntheticProbeCollection = { status: 'unsupported', observedAt: null };
    expect(operationalFindings(data).find((entry) => entry.id === 'synthetic-availability')).toBeUndefined();
  });

  it('includes evaluator rules in the authoritative overall assessment', () => {
    const data = payload();
    data.ruleEvaluation = {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'test',
      evaluatedAt: '2026-08-30T00:00:00Z',
      summary: { firing: 1 },
      states: {
        'CpuUsageHigh:host/node-a': {
          ruleId: 'CpuUsageHigh',
          target: 'host/node-a',
          metric: 'host.cpu.percent',
          severity: 'warning',
          description: 'Evaluator-owned rule.',
          runbook: 'Inspect evaluator evidence.',
          phase: 'firing',
          breachSamples: 5,
          recoverySamples: 0,
          missingSamples: 0,
          openedAt: '2026-08-29T23:55:00Z',
          conditionStartedAt: '2026-08-29T23:55:00Z',
          recoveryStartedAt: null,
          missingStartedAt: null,
          evaluationIntervalSeconds: 60,
          changedAt: '2026-08-30T00:00:00Z',
          lastEvaluatedAt: '2026-08-30T00:00:00Z',
          lastValue: 95,
          observationStatus: 'ok',
        },
      },
    };

    expect(operationalFindings(data)).toEqual([
      expect.objectContaining({
        id: 'rule-evaluation',
        level: 'caution',
        scope: 'current',
        count: 1,
        evidence: [expect.stringContaining('CpuUsageHigh (host/node-a=95)'), expect.stringContaining('CpuUsageHigh (host/node-a=95)')],
      }),
    ]);

    data.ruleEvaluation.states['CpuUsageHigh:host/node-a']!.severity = 'critical';
    expect(operationalFindings(data)).toEqual([
      expect.objectContaining({ id: 'rule-evaluation', level: 'danger' }),
    ]);
  });

  it('reports rule-transition collection coverage independently from evaluator health', () => {
    const data = payload();
    data.ruleAlerts = { status: 'collection_error', events: [] };
    expect(operationalFindings(data)).toEqual([
      expect.objectContaining({
        id: 'rule-evaluation', level: 'caution', scope: 'current', count: 1,
        evidence: [expect.stringContaining('전환 기록 collection_error'), expect.stringContaining('transition log collection_error')],
      }),
    ]);
  });

  it('distinguishes collector and service inventory failures from an empty nominal host', () => {
    const disconnected = payload();
    disconnected.agent.status = 'disconnected';
    disconnected.agent.ageSeconds = 301;
    expect(operationalFindings(disconnected)).toEqual([
      expect.objectContaining({ id: 'agent-heartbeat', level: 'danger' }),
    ]);

    const denied = payload();
    denied.containerCollection = { status: 'permission-denied', observedAt: null };
    denied.containers = [];
    expect(operationalFindings(denied)).toEqual([
      expect.objectContaining({ id: 'service-collection', level: 'danger' }),
    ]);

    const lastKnown = payload();
    lastKnown.containerCollection = {
      status: 'last-known',
      observedAt: '2026-08-29T23:59:00Z',
    };
    expect(operationalFindings(lastKnown)).toEqual([
      expect.objectContaining({
        id: 'service-collection',
        level: 'caution',
        scope: 'last-known',
      }),
    ]);
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

  it('never promotes a last-known failed service to a current danger signal', () => {
    const data = payload();
    data.containerCollection = {
      status: 'last-known',
      observedAt: '2026-08-29T23:58:00Z',
    };
    data.containers = [
      { name: 'old-failure', owner: null, state: 'exited', health: 'unhealthy', cpuPercent: 0, memoryBytes: 0, memoryPercent: 0 },
    ];

    const findings = operationalFindings(data);
    expect(findings.find((finding) => finding.id === 'service-collection')).toMatchObject({
      level: 'caution',
      scope: 'last-known',
    });
    expect(findings.find((finding) => finding.id === 'service-fault')).toMatchObject({
      level: 'caution',
      scope: 'last-known',
      lastObservedAt: '2026-08-29T23:58:00Z',
    });
  });

  it('uses logical CPU count, PSI full stalls, active swap pressure, and inode headroom in resource decisions', () => {
    const normalizedLoad = payload();
    normalizedLoad.host.logicalCpuCount = 8;
    normalizedLoad.latest = latest({ load1: 6 });
    expect(operationalFindings(normalizedLoad).find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'caution' });

    const fullStall = payload();
    fullStall.latest = latest({ memoryPressureFullAvg10: 5 });
    expect(operationalFindings(fullStall).find((entry) => entry.id === 'resource-pressure')).toMatchObject({ level: 'danger' });

    const retainedSwap = payload();
    retainedSwap.latest = latest({ swapTotalBytes: 1_000, swapUsedBytes: 600, swapPercent: 60 });
    expect(operationalFindings(retainedSwap).find((entry) => entry.id === 'resource-pressure')).toBeUndefined();

    const activeSwapPressure = payload();
    activeSwapPressure.latest = latest({
      memoryPercent: 80, swapTotalBytes: 1_000, swapUsedBytes: 600, swapPercent: 60,
    });
    expect(operationalFindings(activeSwapPressure).find((entry) => entry.id === 'resource-pressure')).toMatchObject({
      level: 'caution', evidence: [expect.stringContaining('스왑 60%'), expect.stringContaining('swap 60%')],
    });

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
    expect(operationalFindings(interfaceFault).find((entry) => entry.id === 'network-quality')).toBeUndefined();
    interfaceFault.latest.networkRxErrorsPerSecond = 0.2;
    expect(operationalFindings(interfaceFault).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'caution', page: 'network' });
    interfaceFault.latest.networkRxErrorsPerSecond = 1.2;
    expect(operationalFindings(interfaceFault).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'danger' });

    const interfaceDrops = payload();
    interfaceDrops.latest = latest({ networkRxDroppedPerSecond: 0.11 });
    expect(operationalFindings(interfaceDrops).find((entry) => entry.id === 'network-quality')).toBeUndefined();
    interfaceDrops.latest.networkRxDroppedPerSecond = 1.2;
    expect(operationalFindings(interfaceDrops).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'caution' });
    interfaceDrops.latest.networkRxDroppedPerSecond = 10.2;
    expect(operationalFindings(interfaceDrops).find((entry) => entry.id === 'network-quality')).toMatchObject({ level: 'danger' });

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

  it('does not report an incident as unresolved after a newer recovered transition', () => {
    const data = payload();
    const active = { ...incident('2026-08-29T23:56:00Z'), id: 'incident-shared' };
    const recovered = {
      ...incident('2026-08-29T23:58:00Z'),
      id: active.id,
      startedAt: active.startedAt,
      phase: 'recovered' as const,
      endedAt: '2026-08-29T23:58:00Z',
      durationSeconds: 120,
    };
    data.incidents = [active, recovered];

    expect(operationalFindings(data).find((finding) => finding.id === 'active-incident')).toBeUndefined();
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

  it('does not classify a voltage reading without an authoritative flag or event', () => {
    const data = payload();
    data.latest = latest({ supplyVoltageVolts: 4.4, throttledFlags: 0 });
    data.series = [latest({ timestamp: '2026-08-29T22:00:00Z', supplyVoltageVolts: 4.3, throttledFlags: 0 })];
    data.powerSummary.minSupplyVoltageVolts = 4.3;
    data.powerSummary.averageSupplyVoltageVolts = 4.4;

    expect(operationalFindings(data).find((finding) => finding.id === 'power-quality')).toBeUndefined();
  });

  it('uses authoritative power events for severity even when no throttle flag is available', () => {
    const data = payload();
    data.powerEvents = [{
      timestamp: '2026-08-29T22:00:00Z',
      severity: 'critical',
      kind: 'power',
      status: 'active',
      message: 'authoritative power fault',
      supplyVoltageVolts: 4.5,
      throttledFlags: null,
    }];

    expect(operationalFindings(data).find((finding) => finding.id === 'power-quality')).toMatchObject({
      level: 'danger',
      scope: 'range',
      count: 1,
      lastObservedAt: '2026-08-29T22:00:00Z',
      evidence: [expect.stringContaining('전원 이벤트 1건'), expect.stringContaining('1 power event')],
    });
  });

  it('uses the actual selected-range power-flag time without presenting the latest normal voltage as faulty', () => {
    const data = payload();
    data.series = [
      latest({ timestamp: '2026-08-29T22:00:00Z', supplyVoltageVolts: 4.7, throttledFlags: 1 }),
      latest({ timestamp: '2026-08-30T00:00:00Z', supplyVoltageVolts: 5.1, throttledFlags: 0 }),
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
    expect(markup).toContain('health-overview-findings');
    expect(markup).toContain('짧은 RCU expedited 지연');
    expect(markup).toContain('href="/monitor/details/reliability?range=7d#issue-rcu-expedited"');
  });

  it('shows exactly the first three ordered findings while retaining full counts and the complete-assessment link', () => {
    const data = payload();
    data.containers = [{ name: 'service', owner: null, state: 'exited', health: 'unhealthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 }];
    data.latest = latest({ cpuPercent: 95, throttledFlags: 1 });
    data.disks[0].usedPercent = 95;
    data.reliability.networkLinkAvailable = false;
    data.system.kernel.panic = count(1, '2026-08-29T23:55:00Z');
    const findings = operationalFindings(data);
    expect(findings.length).toBeGreaterThan(3);

    const markup = renderToStaticMarkup(createElement(OperationalHealthOverview, {
      findings, locale: 'en', range: '24h', onNavigate: vi.fn(),
    }));
    expect(markup.match(/class="health-more-link/g)).toHaveLength(3);
    for (const finding of findings.slice(0, 3)) expect(markup).toContain(`issue-${finding.id}`);
    expect(markup).not.toContain(`issue-${findings[3].id}`);
    expect(markup).toContain(`${findings.filter((finding) => finding.level === 'danger').length} danger`);
    expect(markup).toContain('href="/monitor/details/reliability?range=24h"');
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

  it('offers Docker and rule-transition sources without rewriting their bounded titles', () => {
    const entries = [
      { id: 'docker:1', timestamp: '2026-08-30T00:00:00Z', category: 'docker' as const, severity: 'critical' as const, kind: 'oom', status: 'oom', title: 'monitor · oom', message: 'project monitor', actor: null, target: 'monitor' },
      { id: 'rule:1', timestamp: '2026-08-30T00:01:00Z', category: 'rule' as const, severity: 'warning' as const, kind: 'ContainerDown', status: 'firing · ready · ok', title: 'ContainerDown · firing', message: 'value 0', actor: null, target: 'container/monitor' },
    ];
    const korean = renderToStaticMarkup(createElement(OperationalLogView, { locale: 'ko', entries }));
    const english = renderToStaticMarkup(createElement(OperationalLogView, { locale: 'en', entries }));
    expect(korean).toContain('Docker 이벤트');
    expect(korean).toContain('규칙 전환');
    expect(english).toContain('Docker event');
    expect(english).toContain('Rule transition');
    expect(english).toContain('monitor · oom');
    expect(english).toContain('ContainerDown · firing');
  });
});
