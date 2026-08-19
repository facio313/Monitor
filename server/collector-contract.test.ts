import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const LATEST_FIELDS = [
  'timestamp',
  'cpuPercent',
  'memoryPercent',
  'memoryUsedBytes',
  'memoryTotalBytes',
  'temperatureC',
  'load1',
  'load5',
  'load15',
  'powerState',
  'gpuMemoryBytes',
  'gpuClockHz',
  'networkRxBytesPerSecond',
  'networkTxBytesPerSecond',
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
    const mountRoot = join(fixture, 'mounted-root');
    const outputRoot = join(fixture, 'output');
    const runtimeRoot = join(fixture, 'runtime');
    const eventsLog = join(fixture, 'events.log');
    const privilegeLog = join(fixture, 'privilege.log');

    for (const directory of [
      join(procRoot, 'net'),
      join(procRoot, 'self'),
      join(sysRoot, 'class', 'thermal', 'thermal_zone0'),
      etcRoot,
      mountRoot,
    ]) mkdirSync(directory, { recursive: true });

    writeFileSync(join(procRoot, 'stat'), 'cpu  100 0 50 850 0 0 0 0 0 0\n');
    writeFileSync(join(procRoot, 'meminfo'), [
      'MemTotal:       2048 kB',
      'MemAvailable:    512 kB',
      '',
    ].join('\n'));
    writeFileSync(join(procRoot, 'loadavg'), '1.25 2.50 3.75 1/100 123\n');
    writeFileSync(join(procRoot, 'uptime'), '86400.50 12345.00\n');
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
    writeFileSync(join(etcRoot, 'os-release'), 'PRETTY_NAME="Contract Fixture Linux"\n');

    writeFileSync(
      eventsLog,
      'SNAPSHOT reason=cpu-high token=RAW_ALERT_SECRET command=never-export-this\n',
    );
    writeFileSync(privilegeLog, `${JSON.stringify({
      actor: 'fixture-user',
      target: 'root',
      action: 'sudo command',
      result: 'allowed',
      command: 'cat /root/RAW_COMMAND_SECRET',
      password: 'RAW_PASSWORD_SECRET',
    })}\n`);

    execFileSync('python3', [
      resolve('ops/collector.py'),
      '--output-dir', outputRoot,
      '--runtime-dir', runtimeRoot,
      '--proc-root', procRoot,
      '--sys-root', sysRoot,
      '--etc-root', etcRoot,
      '--mount-root', mountRoot,
      '--events-log', eventsLog,
      '--privilege-logs', privilegeLog,
      '--docker-sockets', '',
      '--vcgencmd', '',
    ], {
      cwd: resolve('.'),
      encoding: 'utf8',
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000,
    });

    const current = JSON.parse(readFileSync(join(outputRoot, 'current.json'), 'utf8')) as {
      generatedAt: string;
    };
    const now = Date.parse(current.generatedAt);
    expect(Number.isFinite(now)).toBe(true);

    const dashboard = readDashboard(outputRoot, '1h', now, 120_000);

    expect(Object.keys(dashboard.latest)).toEqual(LATEST_FIELDS);
    expect(dashboard.latest).toMatchObject({
      memoryPercent: 75,
      memoryUsedBytes: 1_572_864,
      memoryTotalBytes: 2_097_152,
      temperatureC: 45.5,
      load1: 1.25,
      load5: 2.5,
      load15: 3.75,
    });
    expect(dashboard.series).toHaveLength(1);
    expect(Object.keys(dashboard.series[0]!)).toEqual(LATEST_FIELDS);

    expect(dashboard.disks).toHaveLength(1);
    expect(Object.keys(dashboard.disks[0]!)).toEqual([
      'mount', 'totalBytes', 'usedBytes', 'usedPercent',
    ]);
    expect(dashboard.disks[0]).toMatchObject({ mount: '/' });
    expect(dashboard.disks[0]!.totalBytes).toBeGreaterThan(0);
    expect(dashboard.disks[0]!.usedBytes).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.usedPercent).toBeGreaterThanOrEqual(0);
    expect(dashboard.disks[0]!.usedPercent).toBeLessThanOrEqual(100);

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
      readFileSync(join(outputRoot, 'privilege.jsonl'), 'utf8'),
      JSON.stringify(dashboard),
    ].join('\n');
    expect(publicExport).not.toContain('RAW_ALERT_SECRET');
    expect(publicExport).not.toContain('RAW_COMMAND_SECRET');
    expect(publicExport).not.toContain('RAW_PASSWORD_SECRET');
    expect(publicExport).not.toContain('never-export-this');
  });
});
