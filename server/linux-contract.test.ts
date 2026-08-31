import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW = Date.parse('2026-08-30T12:01:00Z');
const directories: string[] = [];

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'monitor-linux-contract-'));
  directories.push(path);
  return path;
}

function cpuSample() {
  return {
    rateStatus: 'warmup',
    busyPercent: null,
    userPercent: null,
    nicePercent: null,
    systemPercent: null,
    idlePercent: null,
    iowaitPercent: null,
    irqPercent: null,
    softirqPercent: null,
    stealPercent: null,
    countersJiffies: {
      user: 1,
      nice: 0,
      system: 1,
      idle: 8,
      iowait: 0,
      irq: 0,
      softirq: 0,
      steal: 0,
    },
  };
}

function blockDevice(index = 0) {
  return {
    name: `sd${String.fromCharCode(97 + (index % 26))}`,
    major: 8,
    minor: index,
    counterIdentity: index.toString(16).padStart(16, '0'),
    type: 'sata',
    rotational: false,
    queueDepth: 2,
    rateStatus: 'ok',
    counters: {
      reads: 1,
      readsMerged: 0,
      sectorsRead: 2,
      readMilliseconds: 3,
      writes: 4,
      writesMerged: 0,
      sectorsWritten: 5,
      writeMilliseconds: 6,
      inFlight: 2,
      ioMilliseconds: 7,
      weightedIoMilliseconds: 8,
      discards: 0,
      discardsMerged: 0,
      sectorsDiscarded: 0,
      discardMilliseconds: 0,
      flushes: 0,
      flushMilliseconds: 0,
    },
    discardStatus: 'supported',
    flushStatus: 'supported',
    discardRateStatus: 'ok',
    flushRateStatus: 'ok',
    readBytesPerSecond: 1024,
    writeBytesPerSecond: 2048,
    readIops: 2,
    writeIops: 3,
    discardBytesPerSecond: 0,
    discardIops: 0,
    flushIops: 0,
    readLatencyMilliseconds: 2.5,
    writeLatencyMilliseconds: 4,
    averageLatencyMilliseconds: 3.25,
    utilizationPercent: 62.5,
    averageQueueDepth: 0.75,
    ioErrorCounterStatus: 'unsupported',
    ioErrorEvidenceSource: 'bounded-kernel-events',
    health: {
      smartStatus: 'unsupported',
      raidStatus: 'unsupported',
      raidDegradedDevices: null,
      raidArrayState: null,
    },
  };
}

function processGroup() {
  return {
    name: 'secret-worker',
    allowlisted: true,
    instances: 1,
    states: { R: 1 },
    threads: 2,
    cpuPercent: 1.5,
    residentBytes: 4096,
    virtualBytes: 8192,
    readBytesPerSecond: 10,
    writeBytesPerSecond: 20,
    openFileDescriptors: 3,
    fileDescriptorStatus: 'supported',
  };
}

function linuxFixture() {
  return {
    schemaVersion: 1,
    collectedAt: '2026-08-30T12:00:00Z',
    cpu: {
      status: 'supported',
      total: cpuSample(),
      cores: [],
      coreCount: 0,
      onlineCoreCount: null,
      offlineCoreIds: [],
      truncated: false,
      load: {
        one: 1,
        five: 0.5,
        fifteen: 0.25,
        onePerOnlineCpu: null,
        fivePerOnlineCpu: null,
        fifteenPerOnlineCpu: null,
      },
    },
    memory: {
      status: 'unsupported',
      totalBytes: null,
      availableBytes: null,
      usedBytes: null,
      usedPercent: null,
      cachedBytes: null,
      buffersBytes: null,
      slabBytes: null,
      slabReclaimableBytes: null,
      slabUnreclaimableBytes: null,
      dirtyBytes: null,
      writebackBytes: null,
      swapTotalBytes: null,
      swapUsedBytes: null,
      swapUsedPercent: null,
      vmCounters: {},
      rateStatus: 'unsupported',
      swapInPagesPerSecond: null,
      swapOutPagesPerSecond: null,
      swapInBytesPerSecond: null,
      swapOutBytesPerSecond: null,
      pageFaultsPerSecond: null,
      majorPageFaultsPerSecond: null,
      pressure: {
        cpu: { status: 'unsupported' },
        memory: { status: 'unsupported' },
        io: { status: 'unsupported' },
      },
      pressureStatus: 'unsupported',
    },
    filesystems: { status: 'unsupported', truncated: false, items: [] },
    blockDevices: { status: 'supported', truncated: false, items: [blockDevice()] },
    network: { status: 'unsupported', truncated: false, items: [] },
    tcp: {
      status: 'supported',
      counters: { OutSegs: 1000, RetransSegs: 10 },
      rateStatus: 'ok',
      outgoingSegmentsPerSecond: 100,
      retransmittedSegmentsPerSecond: 1,
      retransmissionPercent: 1,
      states: {
        established: 20,
        synSent: 1,
        synRecv: 2,
        finWait1: 3,
        finWait2: 4,
        timeWait: 5,
        close: 6,
        closeWait: 7,
        lastAck: 8,
        listen: 9,
        closing: 10,
        newSynRecv: 11,
      },
      socketScanStatus: 'supported',
      socketScanTruncated: false,
      ephemeralPorts: {
        status: 'supported',
        rangeStart: 32768,
        rangeEnd: 60999,
        capacity: 28232,
        used: 120,
        usedPercent: 0.425,
      },
      conntrack: { status: 'supported', count: 250, maximum: 1000, usedPercent: 25 },
    },
    processes: {
      status: 'supported',
      pidCount: 120,
      pidCountLowerBound: false,
      pidMaximumStatus: 'supported',
      pidMaximum: 4194304,
      pidUsedPercent: 0,
      zombieCount: 2,
      threadCount: 450,
      observedProcessCount: 120,
      scanTruncated: false,
      deadlineReached: false,
      allowedUidCount: 2,
      topCpu: [processGroup()],
      topMemory: [processGroup()],
      topIo: [processGroup()],
      important: [processGroup()],
      terminatedSincePreviousSample: [],
      systemFileDescriptors: {
        status: 'supported',
        allocated: 1000,
        unusedAllocated: 100,
        used: 900,
        maximum: 10000,
        usedPercent: 9,
      },
      allowlistedProcessOpenFileDescriptors: 3,
      fileDescriptorScanTruncated: false,
      cgroupPids: {
        status: 'supported',
        version: 2,
        current: 120,
        maximum: 1000,
        usedPercent: 12,
      },
    },
    systemd: {
      status: 'supported',
      reason: null,
      units: [{
        unit: 'monitor-collector.service',
        loadState: 'loaded',
        activeState: 'active',
        subState: 'running',
        restartCount: 2,
        restartCountStatus: 'systemd_manager',
        result: 'success',
        execMainStatus: 0,
      }],
      truncated: false,
    },
    thermal: {
      status: 'supported',
      sensors: [{
        source: 'thermal-zone',
        name: 'cpu-thermal',
        status: 'supported',
        temperatureCelsius: 55,
      }],
      fans: [{ name: 'case-fan', status: 'supported', rpm: 3200 }],
      coolingDevices: [{ name: 'fan', status: 'supported', currentState: 1, maximumState: 4 }],
      truncated: false,
      raspberryPi: {
        status: 'supported',
        detected: true,
        temperatureCelsius: 55,
        supplyVoltageVolts: 4.9,
        throttledFlags: 327685,
        currentUnderVoltage: true,
        currentFrequencyCapped: false,
        currentThrottled: true,
        currentSoftTemperatureLimit: false,
        underVoltageOccurred: true,
        frequencyCapOccurred: false,
        throttlingOccurred: true,
        softTemperatureLimitOccurred: false,
        flagSource: 'vcgencmd',
      },
    },
    clock: {
      status: 'supported',
      uptimeSeconds: 3600,
      bootTime: '2026-08-30T11:00:00Z',
      rebootDetectedSincePreviousSample: false,
      unexpectedReboot: null,
      unexpectedRebootStatus: 'not_inferable_from_local_counters',
      timeSync: {
        status: 'supported',
        reason: null,
        synchronized: true,
        ntpEnabled: true,
        ntpSupported: true,
        clockDriftMilliseconds: null,
        clockDriftStatus: 'unsupported',
      },
    },
    eventSources: { kernelLogStatus: 'unsupported', summary: {}, rawMessagesExported: false },
    collectionBounds: {
      maximumCpuCount: 512,
      maximumBlockDevices: 128,
      maximumInterfaces: 256,
      maximumTcpSockets: 65536,
      maximumFilesystems: 256,
      maximumProcesses: 8192,
      processDeadlineMilliseconds: 1250,
      maximumSystemdUnits: 32,
      maximumThermalSensors: 64,
      commandTimeoutMilliseconds: 500,
    },
    privacy: {
      processCommandLinesCollected: false,
      processEnvironmentsCollected: false,
      rawKernelMessagesCollected: false,
    },
  };
}

function dashboard(linux: unknown) {
  const root = directory();
  writeFileSync(join(root, 'current.json'), `${JSON.stringify({ linux })}\n`, 'utf8');
  return readDashboard(root, '1h', NOW, 120_000);
}

afterEach(() => {
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('Linux collector v1 API boundary', () => {
  it('exposes only bounded operational evidence and does not leak process labels', () => {
    const result = dashboard(linuxFixture()).linux;

    expect(result.schemaVersion).toBe(1);
    expect(result.resources).toMatchObject({ processCount: 120, zombieCount: 2 });
    expect(result.resources.systemFileDescriptors).toMatchObject({ current: 900, maximum: 10000 });
    expect(result.resources.cgroupPids).toMatchObject({ version: 2, current: 120, maximum: 1000 });
    expect(result.storage.devices[0]).toMatchObject({
      name: 'sda',
      averageLatencyMilliseconds: 3.25,
      utilizationPercent: 62.5,
      averageQueueDepth: 0.75,
    });
    expect(result.network.tcp).toMatchObject({
      retransmissionPercent: 1,
      states: { established: 20, closeWait: 7, timeWait: 5 },
      conntrack: { current: 250, maximum: 1000, usedPercent: 25 },
    });
    expect(result.reliability.systemd.units[0]).toMatchObject({
      unit: 'monitor-collector.service', restartCount: 2, result: 'success',
    });
    expect(result.reliability.clock.timeSync.synchronized).toBe(true);
    expect(result.power).toMatchObject({ maximumTemperatureCelsius: 55 });
    expect(result.power.raspberryPi).toMatchObject({
      detected: true, currentThrottled: true, flagSource: 'vcgencmd',
    });
    expect(JSON.stringify(result)).not.toContain('secret-worker');
  });

  it('keeps supported, partial, unsupported, permission, unavailable, and invalid distinct', () => {
    for (const status of [
      'supported', 'partial', 'unsupported', 'permission_error', 'unavailable', 'invalid',
    ] as const) {
      const fixture = linuxFixture();
      fixture.processes.status = status;
      expect(dashboard(fixture).linux.resources.status).toBe(status);
    }
  });

  it('accepts microsecond event times and safely reduces a legacy 64-bit file limit', () => {
    const fixture = linuxFixture();
    fixture.eventSources.summary = {
      rcuExpedited: { count: 1, lastEventAt: '2026-08-30T11:59:20.945946Z' },
    };
    fixture.processes.systemFileDescriptors.maximum = 9_223_372_036_854_775_807;
    fixture.processes.systemFileDescriptors.usedPercent = 0;

    const result = dashboard(fixture).linux;

    expect(result.schemaVersion).toBe(1);
    expect(result.status).not.toBe('collection_error');
    expect(result.resources.systemFileDescriptors).toMatchObject({
      status: 'partial',
      current: 900,
      maximum: null,
      usedPercent: null,
    });
  });

  it('bounds the reduced response and rejects collector arrays beyond the v1 cap', () => {
    const reduced = linuxFixture();
    reduced.blockDevices.items = Array.from({ length: 20 }, (_, index) => blockDevice(index));
    const reducedResult = dashboard(reduced).linux.storage;
    expect(reducedResult.devices).toHaveLength(16);
    expect(reducedResult.truncated).toBe(true);

    const excessive = linuxFixture();
    excessive.blockDevices.items = Array.from({ length: 129 }, (_, index) => blockDevice(index));
    expect(dashboard(excessive).linux.status).toBe('collection_error');
  });

  it.each([
    ['unknown top-level key', (fixture: ReturnType<typeof linuxFixture>) => Object.assign(fixture, { surprise: true })],
    ['unknown nested key', (fixture: ReturnType<typeof linuxFixture>) => Object.assign(fixture.tcp, { surprise: true })],
    ['malformed counter', (fixture: ReturnType<typeof linuxFixture>) => { fixture.tcp.states.established = -1; }],
    ['oversized text', (fixture: ReturnType<typeof linuxFixture>) => { fixture.systemd.units[0]!.unit = `${'x'.repeat(129)}.service`; }],
    ['invalid timestamp', (fixture: ReturnType<typeof linuxFixture>) => { fixture.collectedAt = 'tomorrow'; }],
    ['unknown schema', (fixture: ReturnType<typeof linuxFixture>) => { fixture.schemaVersion = 2; }],
    ['privacy contract violation', (fixture: ReturnType<typeof linuxFixture>) => { fixture.privacy.processCommandLinesCollected = true; }],
  ])('returns collection_error for %s instead of silently normalizing it', (_label, mutate) => {
    const fixture = linuxFixture();
    mutate(fixture);
    const result = dashboard(fixture).linux;
    expect(result.status).toBe('collection_error');
    expect(result.schemaVersion).toBeNull();
    expect(result.storage.devices).toEqual([]);
    expect(result.reliability.systemd.units).toEqual([]);
  });

  it('reports legacy snapshots without Linux telemetry as unsupported, not healthy', () => {
    const root = directory();
    writeFileSync(join(root, 'current.json'), '{}\n', 'utf8');
    const result = readDashboard(root, '1h', NOW, 120_000).linux;
    expect(result.status).toBe('unsupported');
    expect(result.resources.status).toBe('unsupported');
    expect(result.network.tcp.status).toBe('unsupported');
  });
});
