import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { release, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { dataLimits, readDashboard } from './data.js';

const LATEST_FIELDS = [
  'timestamp',
  'cpuPercent',
  'memoryPercent',
  'memoryUsedBytes',
  'memoryTotalBytes',
  'swapTotalBytes',
  'swapUsedBytes',
  'swapPercent',
  'temperatureC',
  'load1',
  'load5',
  'load15',
  'cpuPressureSomeAvg10',
  'cpuPressureFullAvg10',
  'memoryPressureSomeAvg10',
  'memoryPressureFullAvg10',
  'ioPressureSomeAvg10',
  'ioPressureFullAvg10',
  'powerState',
  'supplyVoltageVolts',
  'throttledFlags',
  'gpuMemoryBytes',
  'gpuClockHz',
  'networkRxBytesPerSecond',
  'networkTxBytesPerSecond',
  'networkRxErrorsPerSecond',
  'networkTxErrorsPerSecond',
  'networkRxDroppedPerSecond',
  'networkTxDroppedPerSecond',
  'diskReadBytesPerSecond',
  'diskWriteBytesPerSecond',
] as const;

const temporaryDirectories: string[] = [];

function fixtureDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-contract-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('collector to server contract', () => {
  it('preserves every safe telemetry, disk, alert, and privilege field', () => {
    const fixture = fixtureDirectory();
    const procRoot = join(fixture, 'proc');
    const sysRoot = join(fixture, 'sys');
    const etcRoot = join(fixture, 'etc');
    const packageRoot = join(fixture, 'packages');
    const mountRoot = join(fixture, 'mounted-root');
    const outputRoot = join(fixture, 'output');
    const runtimeRoot = join(fixture, 'runtime');
    const eventsLog = join(fixture, 'events.log');
    const kernelLog = join(fixture, 'kern.log');
    const privilegeLog = join(fixture, 'privilege.log');
    const trafficLog = join(fixture, 'traffic.jsonl');
    const vcgencmd = join(fixture, 'vcgencmd');

    for (const directory of [
      join(procRoot, 'net'),
      join(procRoot, 'pressure'),
      join(procRoot, 'self'),
      join(procRoot, 'sys', 'kernel', 'random'),
      join(sysRoot, 'class', 'thermal', 'thermal_zone0'),
      join(sysRoot, 'class', 'hwmon', 'hwmon4'),
      join(sysRoot, 'class', 'nvme', 'nvme0', 'device', 'of_node'),
      join(sysRoot, 'module', 'nvme_core', 'parameters'),
      join(sysRoot, 'module', 'pcie_aspm', 'parameters'),
      join(sysRoot, 'firmware', 'devicetree', 'base', 'chosen', 'bootloader'),
      etcRoot,
      join(etcRoot, 'default'),
      join(packageRoot, 'lib', 'modules', release()),
      join(packageRoot, 'lib', 'firmware', 'raspberrypi', 'bootloader-2712', 'default'),
      mountRoot,
    ]) mkdirSync(directory, { recursive: true });

    writeFileSync(join(procRoot, 'stat'), [
      'cpu  100 0 50 850 0 0 0 0 0 0',
      'cpu0 50 0 25 425 0 0 0 0 0 0',
      'cpu1 50 0 25 425 0 0 0 0 0 0',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'meminfo'), [
      'MemTotal:       2048 kB',
      'MemAvailable:    512 kB',
      'SwapTotal:       1024 kB',
      'SwapFree:         256 kB',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'pressure', 'cpu'), [
      'some avg10=1.25 avg60=0.50 avg300=0.25 total=10',
      'full avg10=0.10 avg60=0.05 avg300=0.01 total=2',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'pressure', 'memory'), [
      'some avg10=2.50 avg60=1.00 avg300=0.50 total=20',
      'full avg10=0.20 avg60=0.10 avg300=0.05 total=4',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'pressure', 'io'), [
      'some avg10=3.75 avg60=1.50 avg300=0.75 total=30',
      'full avg10=0.30 avg60=0.15 avg300=0.07 total=6',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'loadavg'), '1.25 2.50 3.75 1/100 123\n');
    writeFileSync(join(procRoot, 'uptime'), '86400.50 12345.00\n');
    writeFileSync(join(procRoot, 'cmdline'), [
      'root=LABEL=writable',
      'nvme_core.default_ps_max_latency_us=0',
      'pcie_aspm=off',
      'pcie_port_pm=off',
      '',
    ].join(' '));
    writeFileSync(
      join(procRoot, 'sys', 'kernel', 'random', 'boot_id'),
      '11111111-1111-4111-8111-111111111111\n',
    );
    writeFileSync(join(procRoot, 'net', 'dev'), [
      'Inter-| Receive                                                | Transmit',
      ' face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed',
      '  eth0: 4096 1 0 0 0 0 0 0 8192 1 0 0 0 0 0 0',
      '',
    ].join('\n'));
    writeFileSync(
      join(procRoot, 'diskstats'),
      '8 0 sda 10 0 100 0 20 0 200 0 0 0 0 0 0 0\n',
    );
    writeFileSync(
      join(procRoot, 'self', 'mountinfo'),
      '36 25 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n',
    );
    writeFileSync(join(sysRoot, 'class', 'thermal', 'thermal_zone0', 'temp'), '45500\n');
    writeFileSync(join(sysRoot, 'class', 'hwmon', 'hwmon4', 'name'), 'rpi_volt\n');
    writeFileSync(join(sysRoot, 'class', 'hwmon', 'hwmon4', 'in0_lcrit_alarm'), '0\n');
    writeFileSync(join(etcRoot, 'machine-id'), '0123456789abcdef0123456789abcdef\n');
    writeFileSync(join(etcRoot, 'os-release'), 'PRETTY_NAME="Contract Fixture Linux"\n');
    writeFileSync(join(etcRoot, 'default', 'rpi-eeprom-update'), 'FIRMWARE_RELEASE_STATUS="default"\n');

    const controller = join(sysRoot, 'class', 'nvme', 'nvme0');
    const device = join(controller, 'device');
    writeFileSync(join(controller, 'model'), 'Fixture NVMe 256GB\n');
    writeFileSync(join(controller, 'firmware_rev'), 'FW100\n');
    writeFileSync(join(device, 'current_link_speed'), '2.5 GT/s PCIe\n');
    writeFileSync(join(device, 'current_link_width'), '1\n');
    writeFileSync(join(device, 'max_link_speed'), '8.0 GT/s PCIe\n');
    writeFileSync(join(device, 'max_link_width'), '4\n');
    writeFileSync(join(device, 'of_node', 'max-link-speed'), Buffer.from([0, 0, 0, 1]));
    writeFileSync(join(device, 'aer_dev_correctable'), 'RxErr 3\nTOTAL_ERR_COR 3\n');
    writeFileSync(join(device, 'aer_dev_nonfatal'), 'DLP 0\nTOTAL_ERR_NONFATAL 0\n');
    writeFileSync(join(device, 'aer_dev_fatal'), 'DLP 0\nTOTAL_ERR_FATAL 0\n');
    const pciConfig = Buffer.alloc(256);
    pciConfig[0x34] = 0x40;
    pciConfig[0x40] = 0x10;
    pciConfig.writeUInt16LE(0x1, 0x4a);
    writeFileSync(join(device, 'config'), pciConfig);
    writeFileSync(join(sysRoot, 'module', 'nvme_core', 'parameters', 'default_ps_max_latency_us'), '0\n');
    writeFileSync(join(sysRoot, 'module', 'pcie_aspm', 'parameters', 'policy'), 'performance [default]\n');
    writeFileSync(
      join(sysRoot, 'firmware', 'devicetree', 'base', 'compatible'),
      Buffer.from('raspberrypi,5-model-b\0brcm,bcm2712\0'),
    );
    writeFileSync(
      join(sysRoot, 'firmware', 'devicetree', 'base', 'chosen', 'bootloader', 'build-timestamp'),
      Buffer.from([0x69, 0x37, 0x27, 0x32]),
    );
    writeFileSync(
      join(packageRoot, 'lib', 'firmware', 'raspberrypi', 'bootloader-2712', 'default', 'pieeprom-2025-12-08.bin'),
      'fixture',
    );

    writeFileSync(
      eventsLog,
      'SNAPSHOT reason=cpu-high token=RAW_ALERT_SECRET command=never-export-this\n',
    );
    writeFileSync(kernelLog, [
      'kernel: hwmon hwmon4: Undervoltage detected! RAW_KERNEL_SECRET',
      'kernel: hwmon hwmon4: Voltage normalised RAW_KERNEL_SECRET',
      'kernel: rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks RAW_RCU_SECRET',
      'pcieport 0000:00:00.0: AER: Corrected error received: RAW_PCIE_SECRET',
      '',
    ].join('\n'));
    writeFileSync(privilegeLog, `${JSON.stringify({
      actor: 'fixture-user',
      target: 'root',
      action: 'sudo command',
      result: 'allowed',
      command: 'cat /root/RAW_COMMAND_SECRET',
      password: 'RAW_PASSWORD_SECRET',
    })}\n`);
    const trafficObservedAt = new Date().toISOString();
    writeFileSync(trafficLog, [
      {
        timestamp: trafficObservedAt, app: 'monitor', status: 200, requestTime: 0.1,
      },
      {
        timestamp: trafficObservedAt, app: 'monitor', status: 503, requestTime: 1.2,
      },
      {
        timestamp: trafficObservedAt, app: 'blog', status: 200, requestTime: 0.4,
      },
      {
        timestamp: trafficObservedAt, app: 'monitor', status: 200, requestTime: 0.1,
        remoteAddr: 'RAW_TRAFFIC_SECRET',
      },
    ].map((record) => JSON.stringify(record)).join('\n') + '\n');
    writeFileSync(vcgencmd, [
      '#!/bin/sh',
      'case "$*" in',
      '  get_throttled) exit 97 ;;',
      '  "pmic_read_adc EXT5V_V") printf "%s\\n" "EXT5V_V volt(24)=4.87654000V" ;;',
      '  *) exit 1 ;;',
      'esac',
      '',
    ].join('\n'));
    chmodSync(vcgencmd, 0o755);

    execFileSync('python3', [
      resolve('ops/collector.py'),
      '--output-dir', outputRoot,
      '--runtime-dir', runtimeRoot,
      '--proc-root', procRoot,
      '--sys-root', sysRoot,
      '--etc-root', etcRoot,
      '--package-root', packageRoot,
      '--mount-root', mountRoot,
      '--events-log', eventsLog,
      '--kernel-log', kernelLog,
      '--privilege-logs', privilegeLog,
      '--traffic-log', trafficLog,
      '--docker-sockets', '',
      '--vcgencmd', vcgencmd,
      '--temperature-warn-c', '40',
      '--temperature-recover-c', '35',
    ], {
      cwd: resolve('.'),
      encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000,
    });

    const currentPath = join(outputRoot, 'current.json');
    const incidentPath = join(outputRoot, 'incidents.jsonl');
    const current = JSON.parse(readFileSync(currentPath, 'utf8')) as {
      generatedAt: string;
      identity: {
        hostId: string;
        agentId: string;
        installationEpoch: string;
        identityGeneration: number;
        machineIdentityStatus: 'bound' | 'unavailable';
        bootId: string | null;
      };
      heartbeat: {
        sequence: number;
        observedAt: string;
        receivedAt: string;
        expectedIntervalSeconds: number;
        lifecycle: 'active' | 'maintenance' | 'inactive';
        transport: 'local-file';
      };
      containerCollection: {
        status: 'fresh' | 'last-known' | 'unavailable' | 'permission-denied';
        observedAt: string | null;
      };
      syntheticProbeCollection: {
        status: 'fresh' | 'stale' | 'unsupported' | 'permission-denied' | 'unavailable' | 'collection-error';
        observedAt: string | null;
      };
      syntheticProbes: unknown[];
      containers: unknown[];
      currentTraffic: unknown[];
      latest: Record<string, unknown>;
    };
    expect(current.containerCollection).toEqual({ status: 'unavailable', observedAt: null });
    expect(current.syntheticProbeCollection).toEqual({ status: 'unsupported', observedAt: null });
    expect(current.syntheticProbes).toEqual([]);
    const expectedTraffic = [{
      app: 'blog', requestCount: 1, status2xx: 1, status3xx: 0, status4xx: 0,
      status5xx: 0, slowCount: 0, avgResponseMs: 400, maxResponseMs: 400,
    }, {
      app: 'monitor', requestCount: 2, status2xx: 1, status3xx: 0, status4xx: 0,
      status5xx: 1, slowCount: 1, avgResponseMs: 650, maxResponseMs: 1200,
    }];
    expect(current.currentTraffic).toEqual(expectedTraffic);
    Object.assign(current.latest, {
      networkRxErrorsPerSecond: 0.25,
      networkTxErrorsPerSecond: 0.5,
      networkRxDroppedPerSecond: 0.75,
      networkTxDroppedPerSecond: 1,
    });
    const multiCoreContainer = {
      name: 'monitor',
      owner: 'cks',
      state: 'running',
      health: 'healthy',
      cpuPercent: 250,
      memoryBytes: 262_144,
      memoryPercent: 12.5,
    };
    const currentContainer = {
      ...multiCoreContainer,
      project: 'monitor',
      healthcheckConfigured: true,
      memoryLimitBytes: 2_097_152,
      cpuLimitCores: 4,
      pidLimit: 128,
      restartCount: 2,
      restartCountDelta: 0,
      oomKilled: false,
      startedAt: '2026-08-30T11:00:00Z',
      finishedAt: null,
    };
    current.containers = [currentContainer];
    current.containerCollection = { status: 'fresh', observedAt: current.generatedAt };
    writeFileSync(currentPath, `${JSON.stringify(current)}\n`);
    const incident = JSON.parse(readFileSync(incidentPath, 'utf8').trim()) as {
      containers: unknown[];
    };
    incident.containers = [multiCoreContainer];
    writeFileSync(incidentPath, `${JSON.stringify(incident)}\n`);
    const now = Date.parse(current.generatedAt);
    expect(Number.isFinite(now)).toBe(true);

    const dashboard = readDashboard(outputRoot, '1h', now, 120_000);

    expect(dashboard.latestObservedAt).toBe(new Date(current.generatedAt).toISOString());
    expect(dashboard.agent).toEqual({
      ...current.identity,
      ...current.heartbeat,
      installationEpoch: new Date(current.identity.installationEpoch).toISOString(),
      observedAt: new Date(current.heartbeat.observedAt).toISOString(),
      receivedAt: new Date(current.heartbeat.receivedAt).toISOString(),
      status: 'healthy',
      ageSeconds: 0,
      clockSkewSeconds: 0,
    });
    expect(dashboard.agent.hostId).toMatch(/^[0-9a-f-]{36}$/);
    expect(dashboard.agent.agentId).toMatch(/^[0-9a-f-]{36}$/);
    expect(dashboard.agent.machineIdentityStatus).toBe('bound');
    expect(dashboard.agent.bootId).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(dashboard.agent)).not.toContain('0123456789abcdef0123456789abcdef');
    expect(Object.keys(dashboard.latest)).toEqual(LATEST_FIELDS);
    expect(dashboard.latest).toMatchObject({
      memoryPercent: 75,
      memoryUsedBytes: 1_572_864,
      memoryTotalBytes: 2_097_152,
      swapTotalBytes: 1_048_576,
      swapUsedBytes: 786_432,
      swapPercent: 75,
      temperatureC: 45.5,
      load1: 1.25,
      load5: 2.5,
      load15: 3.75,
      cpuPressureSomeAvg10: 1.25,
      cpuPressureFullAvg10: 0.1,
      memoryPressureSomeAvg10: 2.5,
      memoryPressureFullAvg10: 0.2,
      ioPressureSomeAvg10: 3.75,
      ioPressureFullAvg10: 0.3,
      networkRxErrorsPerSecond: 0.25,
      networkTxErrorsPerSecond: 0.5,
      networkRxDroppedPerSecond: 0.75,
      networkTxDroppedPerSecond: 1,
      powerState: 'normal',
      supplyVoltageVolts: 4.877,
      throttledFlags: 0,
    });
    expect(dashboard.series).toHaveLength(1);
    expect(Object.keys(dashboard.series[0]!)).toEqual(LATEST_FIELDS);
    expect(dashboard.host.logicalCpuCount).toBe(2);
    expect(dashboard.linux.schemaVersion).toBe(1);
    expect(dashboard.linux.status).not.toBe('collection_error');
    expect(dashboard.linux.resources.processCount).not.toBeNull();
    expect(dashboard.linux.network.tcp.status).not.toBe('collection_error');
    expect(dashboard.system.versions).toEqual({
      kernelRunning: release(),
      kernelLatestInstalled: release(),
      kernelRebootRequired: false,
      bootloaderCurrent: '2025-12-08',
      bootloaderLatest: '2025-12-08',
      bootloaderChannel: 'default',
      nvmeModel: 'Fixture NVMe 256GB',
      nvmeFirmware: 'FW100',
      collector: '1.0.0',
    });
    expect(dashboard.system.pcie).toEqual({
      configuredGeneration: 1,
      negotiatedGeneration: 1,
      negotiatedSpeedGtps: 2.5,
      negotiatedWidth: 1,
      endpointMaxGeneration: 3,
      endpointMaxWidth: 4,
      aspmDisabled: true,
      nvmePowerSavingDisabled: true,
      aerCorrectableCount: 3,
      aerNonFatalCount: 0,
      aerFatalCount: 0,
      correctableStatusActive: true,
      nonFatalStatusActive: false,
      fatalStatusActive: false,
    });
    expect(dashboard.system.kernel.warning).toEqual({
      count: 0,
      lastEventAt: null,
    });
    expect(dashboard.system.kernel.rcuExpedited).toEqual({
      count: 1,
      lastEventAt: new Date(current.generatedAt).toISOString(),
    });
    expect(dashboard.system.kernel.rcuStall).toEqual({ count: 0, lastEventAt: null });
    expect(dashboard.system.kernel.pcieAerCorrectable).toEqual({
      count: 1,
      lastEventAt: new Date(current.generatedAt).toISOString(),
    });
    expect(dashboard.system.kernel.nvmeReset).toEqual({ count: 0, lastEventAt: null });
    expect(dashboard.reliabilityEvents).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'rcu-stall', status: 'expedited', severity: 'warning' }),
      expect.objectContaining({ kind: 'pcie-aer', status: 'correctable' }),
    ]));
    expect(dashboard.containers).toEqual([{
      ...currentContainer,
      startedAt: '2026-08-30T11:00:00.000Z',
    }]);
    expect(dashboard.containerCollection).toEqual({
      status: 'fresh',
      observedAt: new Date(current.generatedAt).toISOString(),
    });
    expect(dashboard.syntheticProbeCollection).toEqual({
      status: 'unsupported', observedAt: null,
    });
    expect(dashboard.syntheticProbes).toEqual([]);
    expect(dashboard.ruleEvaluation.status).toBe('ok');
    expect(dashboard.ruleEvaluation.rulePackVersion).toBe('2026.08.31.2');
    expect(Object.keys(dashboard.ruleEvaluation.states).length).toBeGreaterThanOrEqual(82);
    expect(Object.values(dashboard.ruleEvaluation.states).some(
      (state) => state.ruleId === 'CpuUsageHigh' && state.metric === 'host.cpu.percent',
    )).toBe(true);
    expect(Object.values(dashboard.ruleEvaluation.summary).reduce(
      (total, count) => total + (count ?? 0),
      0,
    )).toBe(Object.keys(dashboard.ruleEvaluation.states).length);
    expect(dashboard.ruleAlerts).toEqual({ status: 'ok', events: [] });
    expect(dashboard.currentTraffic).toEqual(expectedTraffic);
    expect(dashboard.powerSummary).toEqual({
      sampleCount: 1,
      voltageSampleCount: 1,
      minSupplyVoltageVolts: 4.877,
      averageSupplyVoltageVolts: 4.877,
      maxSupplyVoltageVolts: 4.877,
      underVoltageSampleCount: 0,
      throttledSampleCount: 0,
    });
    expect(dashboard.powerEvents).toEqual([
      {
        timestamp: new Date(now).toISOString(),
        severity: 'warning',
        kind: 'under-voltage',
        status: 'active',
        message: 'Kernel reported an under-voltage condition.',
        supplyVoltageVolts: 4.877,
        throttledFlags: 0,
      },
      {
        timestamp: new Date(now).toISOString(),
        severity: 'info',
        kind: 'under-voltage',
        status: 'recovered',
        message: 'Kernel reported voltage recovery.',
        supplyVoltageVolts: 4.877,
        throttledFlags: 0,
      },
    ]);
    expect(dataLimits.fixedFiles).toContain('power.jsonl');
    expect(dataLimits.fixedFiles).toContain('reliability.jsonl');
    expect(dataLimits.fixedFiles).toContain('incidents.jsonl');

    expect(dashboard.incidents).toHaveLength(1);
    expect(dashboard.incidents[0]).toMatchObject({
      phase: 'active',
      reasons: ['temperature'],
      endedAt: null,
      durationSeconds: null,
      metrics: {
        timestamp: new Date(now).toISOString(),
        temperatureC: 45.5,
        swapTotalBytes: 1_048_576,
        swapUsedBytes: 786_432,
        swapPercent: 75,
        cpuPressureSomeAvg10: 1.25,
        memoryPressureSomeAvg10: 2.5,
        ioPressureSomeAvg10: 3.75,
      },
      pressure: {
        cpu: { someAvg10: 1.25, fullAvg10: 0.1 },
        memory: { someAvg10: 2.5, fullAvg10: 0.2 },
        io: { someAvg10: 3.75, fullAvg10: 0.3 },
      },
      processes: [],
      containers: [multiCoreContainer],
      traffic: expectedTraffic,
      peaks: {
        cpuPercent: null,
        memoryPercent: 75,
        temperatureC: 45.5,
        load1: 1.25,
      },
    });
    expect(dashboard.incidents[0]!.id).toMatch(/^incident-\d{8}T\d{6}Z$/);
    expect(Object.keys(dashboard.incidents[0]!)).toEqual([
      'id',
      'startedAt',
      'observedAt',
      'endedAt',
      'phase',
      'reasons',
      'metrics',
      'pressure',
      'processes',
      'containers',
      'traffic',
      'peaks',
      'durationSeconds',
    ]);

    expect(dashboard.disks).toHaveLength(1);
    expect(Object.keys(dashboard.disks[0]!)).toEqual([
      'mount', 'totalBytes', 'usedBytes', 'availableBytes', 'usedPercent',
      'inodeUsedPercent', 'readOnly',
    ]);
    expect(dashboard.disks[0]).toMatchObject({ mount: '/' });
    expect(dashboard.disks[0]!.totalBytes).toBeGreaterThan(0);
    expect(dashboard.disks[0]!.usedBytes).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.availableBytes).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.usedPercent).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.usedPercent).toBeLessThanOrEqual(100);
    expect(dashboard.disks[0]!.inodeUsedPercent).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.inodeUsedPercent).toBeLessThanOrEqual(100);
    expect(dashboard.disks[0]!.readOnly).toBe(false);

    expect(dashboard.alerts).toEqual([{
      timestamp: new Date(now).toISOString(),
      severity: 'warning',
      kind: 'host',
      status: 'active',
      message: 'Host condition cpu-high is active.',
    }]);
    expect(dashboard.privilegeEvents).toEqual([{
      timestamp: new Date(now).toISOString(),
      actor: 'fixture-user',
      target: 'root',
      action: 'sudo',
      result: 'success',
    }]);

    const publicExport = [
      readFileSync(join(outputRoot, 'current.json'), 'utf8'),
      readFileSync(join(outputRoot, 'history', `${current.generatedAt.slice(0, 10)}.jsonl`), 'utf8'),
      readFileSync(join(outputRoot, 'alerts.jsonl'), 'utf8'),
      readFileSync(join(outputRoot, 'power.jsonl'), 'utf8'),
      readFileSync(join(outputRoot, 'reliability.jsonl'), 'utf8'),
      readFileSync(join(outputRoot, 'privilege.jsonl'), 'utf8'),
      readFileSync(join(outputRoot, 'incidents.jsonl'), 'utf8'),
      JSON.stringify(dashboard),
    ].join('\n');
    expect(publicExport).not.toContain('RAW_ALERT_SECRET');
    expect(publicExport).not.toContain('RAW_COMMAND_SECRET');
    expect(publicExport).not.toContain('RAW_PASSWORD_SECRET');
    expect(publicExport).not.toContain('RAW_KERNEL_SECRET');
    expect(publicExport).not.toContain('RAW_RCU_SECRET');
    expect(publicExport).not.toContain('RAW_PCIE_SECRET');
    expect(publicExport).not.toContain('RAW_TRAFFIC_SECRET');
    expect(publicExport).not.toContain('never-export-this');
  });
});
