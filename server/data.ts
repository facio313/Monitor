import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { basename, join, relative, resolve, sep } from 'node:path';
import type {
  DashboardRange,
  DashboardResponse,
  IncidentReason,
  RuleAlertEvent,
  RuleEvaluationPhase,
  RuleEvaluationState,
  RuleObservationStatus,
  TelemetrySample,
} from './types.js';

const MAX_CURRENT_BYTES = 1024 * 1024;
const MAX_EVENT_FILE_BYTES = 4 * 1024 * 1024;
const MAX_RULE_EVALUATION_BYTES = 8 * 1024 * 1024;
const MAX_RULE_ALERT_FILE_BYTES = 32 * 1024 * 1024;
const MAX_RULE_ALERT_LINE_BYTES = 8192;
const MAX_RULE_STATES = 8192;
const MAX_RULE_ALERT_RECORDS = 5000;
const MAX_RULE_ALERTS = 500;
const MAX_INCIDENT_FILE_BYTES = 16 * 1024 * 1024;
const MAX_HISTORY_FILE_BYTES = 8 * 1024 * 1024;
const MAX_JSONL_LINES = 50_000;
const MAX_LINE_BYTES = 128 * 1024;
const MAX_SERIES_POINTS = 360;
const MAX_EVENTS = 500;
const MAX_INCIDENTS = 500;
const MAX_INCIDENT_REASONS = 16;
const MAX_INCIDENT_PROCESSES = 32;
const MAX_INCIDENT_CONTAINERS = 256;
const MAX_INCIDENT_TRAFFIC = 64;
const MAX_CURRENT_TRAFFIC = 16;
const MAX_POWER_CORRELATION_MS = 2 * 60 * 1_000;
const MAX_UINT32 = 0xffff_ffff;
const MAX_INCIDENT_DURATION_SECONDS = 366 * 24 * 60 * 60;
const MAX_RESPONSE_TIME_MS = 300_000;
const MAX_INCIDENT_COUNT = 1_000_000_000;
const MAX_RELIABILITY_DURATION_SECONDS = 366 * 24 * 60 * 60;
const MAX_CONTAINER_CPU_PERCENT = 1024;
const MAX_TELEMETRY_RATE = 1_000_000_000_000;
const RULE_PHASES = new Set<RuleEvaluationPhase>([
  'inactive', 'pending', 'firing', 'recovering', 'no_data', 'unsupported',
  'permission_denied', 'collection_error',
]);
const RULE_OBSERVATION_STATUSES = new Set<RuleObservationStatus>([
  'ok', 'no_data', 'stale', 'collection_error', 'permission_denied', 'unsupported',
]);
const RULE_SEVERITIES = new Set<RuleEvaluationState['severity']>([
  'info', 'warning', 'critical',
]);
const RULE_ID_PATTERN = /^[A-Z][A-Za-z0-9]{2,63}$/;
const RULE_PACK_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const RULE_METRIC_PATTERN = /^[a-z][a-z0-9_.]{2,127}$/;
const RULE_TARGET_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,191}$/;
const RULE_LABEL_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
const RULE_LABEL_VALUE_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,95}$/;
const OPAQUE_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPAQUE_BOOT_ID_PATTERN = /^[0-9a-f]{32}$/;
const CURRENT_SNAPSHOT_SCHEMA_VERSION = 2;
const TRAFFIC_AGGREGATE_FIELDS = new Set([
  'app',
  'requestCount',
  'status2xx',
  'status3xx',
  'status4xx',
  'status5xx',
  'slowCount',
  'avgResponseMs',
  'maxResponseMs',
]);
const INCIDENT_REASON_ORDER: IncidentReason[] = [
  'cpu',
  'memory',
  'temperature',
  'power-throttle',
  'load',
  'disk-io',
  'traffic',
];
const INCIDENT_REASONS = new Set<IncidentReason>(INCIDENT_REASON_ORDER);
const INCIDENT_TRAFFIC_APPS = new Set([
  'monitor',
  'blog',
  'feelmyrythm',
  'multtara',
  'pilgrimage',
  'ddit-finalproject',
  'dukkeobi',
  'react',
  'vue',
]);
const FIXED_CONTAINER_SERVICE_NAMES = [
  'bonifacio',
  'sso',
  'sso-redis',
  'blog-frontend',
  'blog-backend',
  'cks-database',
  'monitor',
  'feelmyrythm-frontend',
  'feelmyrythm-backend',
  'feelmyrythm-redis',
  'multtara-backend',
  'multtara-collector',
  'multtara-database',
  'multtara-frontend',
  'pilgrimage-frontend',
  'pilgrimage-backend',
  'pilgrimage-redis',
  'ddit-finalproject',
  'dukkeobi',
  'react',
  'vue',
] as const;
const CURRENT_CONTAINER_PROJECTS: Readonly<Record<string, string>> = {
  bonifacio: 'bonifacio',
  sso: 'bonifacio',
  'sso-redis': 'bonifacio',
  'blog-frontend': 'blog',
  'blog-backend': 'blog',
  'cks-database': 'cks-database',
  monitor: 'monitor',
  'feelmyrythm-frontend': 'feelmyrythm',
  'feelmyrythm-backend': 'feelmyrythm',
  'feelmyrythm-redis': 'feelmyrythm',
  'multtara-backend': 'pongdang-multtara',
  'multtara-collector': 'pongdang-multtara',
  'multtara-frontend': 'pongdang-multtara',
  'pilgrimage-frontend': 'pilgrimage',
  'pilgrimage-backend': 'pilgrimage',
  'pilgrimage-redis': 'pilgrimage',
  'ddit-finalproject': 'ddit-finalproject',
  dukkeobi: 'dukkeobi',
  react: 'react',
  vue: 'vue',
};
const LEGACY_CONTAINER_SERVICE_NAMES = [
  'bonifacio-web',
  'bonifacio-sso',
  'bonifacio-sso-admin',
  'bonifacio-sso-redis',
  'feelmyrythm-web',
  'feelmyrythm-server',
] as const;
// Older collectors emitted app-level traffic labels, `cks-workload`, or the
// superseded service labels above. Keep every prior value readable in current
// snapshots and incident history; the exporter emits only the fixed names.
const SAFE_CONTAINER_NAMES = new Set([
  ...INCIDENT_TRAFFIC_APPS,
  ...FIXED_CONTAINER_SERVICE_NAMES,
  ...LEGACY_CONTAINER_SERVICE_NAMES,
  'cks-workload',
]);
const SAFE_CONTAINER_STATES = new Set([
  'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead', 'unknown',
]);
const SAFE_CONTAINER_HEALTH = new Set(['healthy', 'unhealthy', 'starting', 'none', 'unknown']);
const RELIABILITY_KINDS = new Set<DashboardResponse['reliabilityEvents'][number]['kind']>([
  'host-boot',
  'collector-gap',
  'ssh-listener',
  'network-link',
  'nvme-reset',
  'nvme-io',
  'rcu-stall',
  'oom-kill',
  'filesystem-error',
  'pcie-aer',
  'pcie-link',
  'kernel-warning',
  'kernel-oops',
  'kernel-panic',
  'hung-task',
  'nvme-mitigation',
]);
const RELIABILITY_EVENT_CONTRACT = {
  'host-boot:observed': { severity: 'info', message: 'Host boot was observed by the collector.' },
  'host-boot:restarted': { severity: 'warning', message: 'Host boot followed a previous collector session.' },
  'collector-gap:detected': { severity: 'warning', message: 'Collector heartbeat gap exceeded the expected interval.' },
  'ssh-listener:unavailable': { severity: 'critical', message: 'One or more expected SSH listeners are unavailable.' },
  'ssh-listener:recovered': { severity: 'info', message: 'All expected SSH listeners recovered.' },
  'network-link:unavailable': { severity: 'critical', message: 'Primary network link became unavailable.' },
  'network-link:recovered': { severity: 'info', message: 'Primary network link recovered.' },
  'nvme-reset:active': { severity: 'critical', message: 'Kernel reported an NVMe controller reset.' },
  'nvme-io:active': { severity: 'critical', message: 'Kernel reported an NVMe I/O error.' },
  'rcu-stall:active': { severity: 'critical', message: 'Kernel reported an RCU stall.' },
  'rcu-stall:expedited': { severity: 'warning', message: 'Kernel reported a short expedited RCU grace-period delay.' },
  'oom-kill:active': { severity: 'critical', message: 'Kernel reported an out-of-memory kill.' },
  'filesystem-error:active': { severity: 'critical', message: 'Kernel reported a filesystem or block I/O error.' },
  'pcie-aer:correctable': { severity: 'warning', message: 'Kernel reported a correctable PCIe AER event.' },
  'pcie-aer:nonfatal': { severity: 'critical', message: 'Kernel reported a non-fatal PCIe AER event.' },
  'pcie-aer:fatal': { severity: 'critical', message: 'Kernel reported a fatal PCIe AER event.' },
  'pcie-link:down': { severity: 'critical', message: 'Kernel reported that the PCIe link went down.' },
  'pcie-link:degraded': { severity: 'warning', message: 'Kernel reported degraded PCIe link training.' },
  'pcie-link:recovered': { severity: 'info', message: 'Kernel reported that the PCIe link recovered.' },
  'kernel-warning:active': { severity: 'warning', message: 'Kernel reported an internal warning.' },
  'kernel-oops:active': { severity: 'critical', message: 'Kernel reported an oops.' },
  'kernel-panic:active': { severity: 'critical', message: 'Kernel reported a panic.' },
  'hung-task:active': { severity: 'critical', message: 'Kernel reported a hung task.' },
  'nvme-mitigation:active': { severity: 'info', message: 'Runtime NVMe power-management mitigation is active.' },
  'nvme-mitigation:incomplete': { severity: 'warning', message: 'Runtime NVMe power-management mitigation is not fully active.' },
} as const;

type JsonRecord = Record<string, unknown>;

const rangeDuration: Record<DashboardRange, number> = {
  '1h': 60 * 60 * 1_000,
  '24h': 24 * 60 * 60 * 1_000,
  '7d': 7 * 24 * 60 * 60 * 1_000,
  '30d': 30 * 24 * 60 * 60 * 1_000,
};

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function own(record: JsonRecord | undefined, key: string): unknown {
  return record && Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

function exactKeys(record: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function recordAt(record: JsonRecord | undefined, ...keys: string[]): JsonRecord | undefined {
  let value: unknown = record;
  for (const key of keys) {
    if (!isRecord(value)) return undefined;
    value = own(value, key);
  }
  return isRecord(value) ? value : undefined;
}

function first(record: JsonRecord | undefined, keys: string[]): unknown {
  for (const key of keys) {
    const value = own(record, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

function finite(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number | null {
  const number = typeof value === 'number' ? value : Number.NaN;
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function percent(value: unknown): number | null {
  return finite(value, 0, 100);
}

function containerCpuPercent(value: unknown): number | null {
  return finite(value, 0, MAX_CONTAINER_CPU_PERCENT);
}

function integer(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number | null {
  const number = finite(value, minimum, maximum);
  return number !== null && Number.isInteger(number) ? number : null;
}

function uint32(value: unknown): number | null {
  return typeof value === 'number'
    && Number.isInteger(value)
    && value >= 0
    && value <= MAX_UINT32
    ? (value === 0 ? 0 : value)
    : null;
}

function cleanText(value: unknown, maximumLength: number): string | null {
  if (typeof value !== 'string') return null;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maximumLength);
  return cleaned || null;
}

function cleanIdentity(value: unknown): string | null {
  const cleaned = cleanText(value, 64);
  return cleaned && /^[a-z0-9_.@-]+$/i.test(cleaned) ? cleaned : null;
}

function incidentToken(value: unknown, maximumLength: number): string | null {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximumLength) return null;
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value) ? value : null;
}

function incidentId(value: unknown): string | null {
  return typeof value === 'string' && /^incident-\d{8}T\d{6}Z$/.test(value) ? value : null;
}

function safeProcessName(value: unknown): string {
  if (typeof value !== 'string') return 'unknown';
  const name = value
    .trim()
    .replace(/[^A-Za-z0-9_.:@/+ -]/g, '_')
    .slice(0, 64)
    .toLowerCase();
  if (!name) return 'unknown';
  if (/password|passwd|secret|token|api.?key/i.test(name)) return 'redacted';
  if (/^node(?:js)?$/.test(name)) return 'node';
  if (/^(?:python(?:2|3)?(?:\.[0-9]+)?|pypy3?|gunicorn|uvicorn)$/.test(name)) return 'python';
  if (['nginx', 'caddy', 'apache2', 'httpd'].includes(name)) return 'web-server';
  if (['postgres', 'postmaster', 'mysqld', 'mariadbd', 'redis-server'].includes(name)) return 'database';
  if (['dockerd', 'containerd', 'containerd-shim', 'rootlesskit', 'rootlesskit-docker-proxy'].includes(name)) {
    return 'container-runtime';
  }
  if (['systemd', 'systemd-journal', 'systemd-logind', 'dbus-daemon', 'sshd', 'cron', 'crond'].includes(name)) {
    return 'system-service';
  }
  if (/^(?:kworker\/|ksoftirqd\/|migration\/|rcu[_o]|watchdog\/)/.test(name)) return 'kernel-worker';
  return 'other';
}

function safeContainerName(value: unknown): string {
  const name = cleanText(value, 128)?.toLowerCase();
  return name && SAFE_CONTAINER_NAMES.has(name) ? name : 'cks-workload';
}

function safeContainerState(value: unknown): string | null {
  const state = cleanText(value, 32)?.toLowerCase() ?? 'unknown';
  return SAFE_CONTAINER_STATES.has(state) ? state : 'unknown';
}

function safeContainerHealth(value: unknown): string | null {
  const health = cleanText(value, 32)?.toLowerCase() ?? 'unknown';
  return SAFE_CONTAINER_HEALTH.has(health) ? health : 'unknown';
}

function safeMessage(value: unknown): string | null {
  const cleaned = cleanText(value, 300);
  if (!cleaned) return null;
  return cleaned
    .replace(/\b(bearer)\s+[a-z0-9._~+\/-]+=*/gi, '$1 [redacted]')
    .replace(/\b(password|passwd|secret|token|api[_ -]?key)\s*[:=]\s*\S+/gi, '$1=[redacted]')
    .replace(/\b(command|cmd|argv)\s*[:=]\s*.+$/gi, '$1=[redacted]')
    .replace(/\bsudo\s+.+$/gi, 'sudo [details redacted]')
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, '[redacted access key]')
    .replace(/\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]{20,}\b/g, '[redacted token]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----.*/gi, '[redacted private key]');
}

function isoTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const time = typeof value === 'number' && value < 10_000_000_000
    ? value * 1_000
    : new Date(value).getTime();
  if (!Number.isFinite(time) || time < 0) return null;
  return new Date(time).toISOString();
}

function timestampOf(record: JsonRecord): string | null {
  return isoTimestamp(first(record, ['timestamp', 'collectedAt', 'generatedAt', 'time', 'ts']));
}

function normalizeSwap(
  totalValue: unknown,
  usedValue: unknown,
  percentValue: unknown,
): Pick<TelemetrySample, 'swapTotalBytes' | 'swapUsedBytes' | 'swapPercent'> {
  const swapTotalBytes = integer(totalValue);
  let swapUsedBytes = integer(usedValue);
  let swapPercent = percent(percentValue);
  if (swapTotalBytes !== null && swapUsedBytes !== null) {
    if (swapUsedBytes > swapTotalBytes) {
      swapUsedBytes = null;
      swapPercent = null;
    } else {
      const expectedPercent = swapTotalBytes > 0
        ? Math.round((100 * swapUsedBytes / swapTotalBytes) * 100) / 100
        : 0;
      if (swapPercent === null) {
        swapPercent = expectedPercent;
      } else if (Math.abs(swapPercent - expectedPercent) > 0.01) {
        swapPercent = null;
      }
    }
  }
  return { swapTotalBytes, swapUsedBytes, swapPercent };
}

function normalizeSample(value: unknown): TelemetrySample | null {
  if (!isRecord(value)) return null;
  const timestamp = timestampOf(value);
  if (!timestamp) return null;
  const cpu = recordAt(value, 'cpu');
  const memory = recordAt(value, 'memory') ?? recordAt(value, 'mem');
  const network = recordAt(value, 'network');
  const disk = recordAt(value, 'disk') ?? recordAt(value, 'diskIo') ?? recordAt(value, 'io');
  const gpu = recordAt(value, 'gpu');
  const thermal = recordAt(value, 'thermal');
  const power = recordAt(value, 'power');
  const swap = recordAt(value, 'swap');
  const pressure = recordAt(value, 'pressure');
  const cpuPressure = recordAt(pressure, 'cpu');
  const memoryPressure = recordAt(pressure, 'memory');
  const ioPressure = recordAt(pressure, 'io');
  const load = first(cpu, ['loadAverage', 'load']) ?? first(value, ['loadAverage', 'load']);
  const loadValues = Array.isArray(load) ? load : [];

  const memoryUsedBytes = finite(
    first(memory, ['usedBytes', 'used', 'usageBytes']) ?? first(value, ['memoryUsedBytes']),
  );
  const memoryTotalBytes = finite(
    first(memory, ['totalBytes', 'total']) ?? first(value, ['memoryTotalBytes']),
  );
  let memoryPercent = percent(
    first(memory, ['percent', 'usagePercent', 'usedPercent']) ?? first(value, ['memoryPercent']),
  );
  if (memoryPercent === null && memoryUsedBytes !== null && memoryTotalBytes && memoryTotalBytes > 0) {
    memoryPercent = Math.min(100, (memoryUsedBytes / memoryTotalBytes) * 100);
  }
  const normalizedSwap = normalizeSwap(
    first(value, ['swapTotalBytes']) ?? first(swap, ['totalBytes', 'total']),
    first(value, ['swapUsedBytes']) ?? first(swap, ['usedBytes', 'used']),
    first(value, ['swapPercent']) ?? first(swap, ['percent', 'usedPercent']),
  );

  return {
    timestamp,
    cpuPercent: percent(first(cpu, ['percent', 'usagePercent', 'usage']) ?? first(value, ['cpuPercent'])),
    memoryPercent,
    memoryUsedBytes,
    memoryTotalBytes,
    ...normalizedSwap,
    temperatureC: finite(
      first(value, ['temperatureC', 'temperature'])
        ?? first(thermal, ['temperatureC', 'temperature', 'cpuTemperatureC'])
        ?? first(cpu, ['temperatureC', 'temperature']),
      -100,
      250,
    ),
    load1: finite(loadValues[0] ?? first(cpu, ['load1']) ?? first(value, ['load1'])),
    load5: finite(loadValues[1] ?? first(cpu, ['load5']) ?? first(value, ['load5'])),
    load15: finite(loadValues[2] ?? first(cpu, ['load15']) ?? first(value, ['load15'])),
    cpuPressureSomeAvg10: percent(
      first(value, ['cpuPressureSomeAvg10']) ?? first(cpuPressure, ['someAvg10']),
    ),
    cpuPressureFullAvg10: percent(
      first(value, ['cpuPressureFullAvg10']) ?? first(cpuPressure, ['fullAvg10']),
    ),
    memoryPressureSomeAvg10: percent(
      first(value, ['memoryPressureSomeAvg10']) ?? first(memoryPressure, ['someAvg10']),
    ),
    memoryPressureFullAvg10: percent(
      first(value, ['memoryPressureFullAvg10']) ?? first(memoryPressure, ['fullAvg10']),
    ),
    ioPressureSomeAvg10: percent(
      first(value, ['ioPressureSomeAvg10']) ?? first(ioPressure, ['someAvg10']),
    ),
    ioPressureFullAvg10: percent(
      first(value, ['ioPressureFullAvg10']) ?? first(ioPressure, ['fullAvg10']),
    ),
    powerState: cleanText(
      first(value, ['powerState'])
        ?? first(power, ['state', 'status'])
        ?? first(recordAt(value, 'host'), ['powerState']),
      32,
    ),
    supplyVoltageVolts: finite(
      first(value, ['supplyVoltageVolts']) ?? first(power, ['supplyVoltageVolts']),
      0,
      10,
    ),
    throttledFlags: uint32(
      first(value, ['throttledFlags'])
        ?? first(power, ['throttledFlags'])
        ?? first(gpu, ['throttledFlags']),
    ),
    gpuMemoryBytes: finite(first(gpu, ['memoryBytes', 'memoryUsedBytes', 'usedMemoryBytes']) ?? first(value, ['gpuMemoryBytes'])),
    gpuClockHz: finite(first(gpu, ['clockHz', 'gpuClockHz']) ?? first(value, ['gpuClockHz'])),
    networkRxBytesPerSecond: finite(first(network, [
      'rxBytesPerSecond', 'receiveBytesPerSecond', 'rxBps',
    ]) ?? first(value, ['networkRxBytesPerSecond'])),
    networkTxBytesPerSecond: finite(first(network, [
      'txBytesPerSecond', 'transmitBytesPerSecond', 'txBps',
    ]) ?? first(value, ['networkTxBytesPerSecond'])),
    networkRxErrorsPerSecond: finite(
      first(value, ['networkRxErrorsPerSecond']), 0, MAX_TELEMETRY_RATE,
    ),
    networkTxErrorsPerSecond: finite(
      first(value, ['networkTxErrorsPerSecond']), 0, MAX_TELEMETRY_RATE,
    ),
    networkRxDroppedPerSecond: finite(
      first(value, ['networkRxDroppedPerSecond']), 0, MAX_TELEMETRY_RATE,
    ),
    networkTxDroppedPerSecond: finite(
      first(value, ['networkTxDroppedPerSecond']), 0, MAX_TELEMETRY_RATE,
    ),
    diskReadBytesPerSecond: finite(first(disk, [
      'readBytesPerSecond', 'readBps', 'diskReadBytesPerSecond',
    ]) ?? first(value, ['diskReadBytesPerSecond'])),
    diskWriteBytesPerSecond: finite(first(disk, [
      'writeBytesPerSecond', 'writeBps', 'diskWriteBytesPerSecond',
    ]) ?? first(value, ['diskWriteBytesPerSecond'])),
  };
}

function emptySample(timestamp: string): TelemetrySample {
  return {
    timestamp,
    cpuPercent: null,
    memoryPercent: null,
    memoryUsedBytes: null,
    memoryTotalBytes: null,
    swapTotalBytes: null,
    swapUsedBytes: null,
    swapPercent: null,
    temperatureC: null,
    load1: null,
    load5: null,
    load15: null,
    cpuPressureSomeAvg10: null,
    cpuPressureFullAvg10: null,
    memoryPressureSomeAvg10: null,
    memoryPressureFullAvg10: null,
    ioPressureSomeAvg10: null,
    ioPressureFullAvg10: null,
    powerState: null,
    supplyVoltageVolts: null,
    throttledFlags: null,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: null,
    networkTxBytesPerSecond: null,
    networkRxErrorsPerSecond: null,
    networkTxErrorsPerSecond: null,
    networkRxDroppedPerSecond: null,
    networkTxDroppedPerSecond: null,
    diskReadBytesPerSecond: null,
    diskWriteBytesPerSecond: null,
  };
}

function mergeSamples(history: TelemetrySample, current: TelemetrySample): TelemetrySample {
  const merged = { ...history };
  for (const key of Object.keys(current) as Array<keyof TelemetrySample>) {
    const value = current[key];
    if (key === 'timestamp' || value !== null) {
      Object.assign(merged, { [key]: value });
    }
  }
  return merged;
}

function isInside(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === '' || (!child.startsWith(`..${sep}`) && child !== '..' && !child.startsWith(sep));
}

function readBounded(root: string, path: string, maximumBytes: number): string | null {
  let realRoot: string;
  let realPath: string;
  try {
    realRoot = realpathSync(root);
    realPath = realpathSync(path);
  } catch {
    return null;
  }
  if (!isInside(realRoot, realPath)) return null;

  let descriptor: number | undefined;
  try {
    descriptor = openSync(realPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximumBytes) return null;
    return readFileSync(descriptor, 'utf8');
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

type StrictFileRead =
  | { status: 'ok'; content: string }
  | { status: 'unavailable' | 'collection_error'; content: null };

function strictFileFailure(error: unknown): StrictFileRead {
  return (error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT'
    ? { status: 'unavailable', content: null }
    : { status: 'collection_error', content: null };
}

function readStrictBounded(root: string, path: string, maximumBytes: number): StrictFileRead {
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch (error) {
    return strictFileFailure(error);
  }

  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    return strictFileFailure(error);
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || metadata.size > maximumBytes
  ) {
    return { status: 'collection_error', content: null };
  }

  let realPath: string;
  try {
    realPath = realpathSync(path);
  } catch (error) {
    return strictFileFailure(error);
  }
  if (!isInside(realRoot, realPath)) {
    return { status: 'collection_error', content: null };
  }

  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile()
      || opened.nlink !== 1
      || opened.dev !== metadata.dev
      || opened.ino !== metadata.ino
      || opened.size !== metadata.size
      || opened.size > maximumBytes
    ) {
      return { status: 'collection_error', content: null };
    }
    const payload = readFileSync(descriptor);
    if (payload.length !== opened.size || payload.length > maximumBytes) {
      return { status: 'collection_error', content: null };
    }
    try {
      return {
        status: 'ok',
        content: new TextDecoder('utf-8', { fatal: true }).decode(payload),
      };
    } catch {
      return { status: 'collection_error', content: null };
    }
  } catch {
    return { status: 'collection_error', content: null };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function parseObjectFile(root: string, path: string, maximumBytes: number): JsonRecord | null {
  const content = readBounded(root, path, maximumBytes);
  if (content === null) return null;
  try {
    const parsed: unknown = JSON.parse(content);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function telemetryIsReady(
  dataDirectory: string,
  nowMs = Date.now(),
  staleAfterMs = 5 * 60 * 1_000,
): boolean {
  const root = resolve(dataDirectory);
  const current = parseObjectFile(root, join(root, 'current.json'), MAX_CURRENT_BYTES);
  const currentPayload = recordAt(current ?? undefined, 'latest') ?? current;
  const sample = normalizeSample(currentPayload);
  if (!sample) return false;
  const observedAt = new Date(sample.timestamp).getTime();
  return observedAt <= nowMs + 60_000 && nowMs - observedAt <= staleAfterMs;
}

function parseJsonLines(root: string, path: string, maximumBytes: number): JsonRecord[] {
  const content = readBounded(root, path, maximumBytes);
  if (content === null) return [];
  const records: JsonRecord[] = [];
  const allLines = content.split('\n');
  const lines = allLines.length > MAX_JSONL_LINES
    ? allLines.slice(-MAX_JSONL_LINES)
    : allLines;
  for (const line of lines) {
    if (!line.trim() || Buffer.byteLength(line) > MAX_LINE_BYTES) continue;
    try {
      const parsed: unknown = JSON.parse(line);
      if (isRecord(parsed)) records.push(parsed);
    } catch {
      // A malformed collector line must not make the rest of the dashboard unavailable.
    }
  }
  return records;
}

function dateNames(fromMs: number, toMs: number): string[] {
  const names: string[] = [];
  const cursor = new Date(fromMs);
  cursor.setUTCHours(0, 0, 0, 0);
  while (cursor.getTime() <= toMs && names.length < 32) {
    names.push(cursor.toISOString().slice(0, 10));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return names;
}

function evenlySelect(values: number[], maximum: number): number[] {
  if (maximum <= 0) return [];
  if (values.length <= maximum) return values;
  if (maximum === 1) return [values[Math.floor((values.length - 1) / 2)]!];
  return Array.from({ length: maximum }, (_, index) => (
    values[Math.round((index * (values.length - 1)) / (maximum - 1))]!
  ));
}

function downsampleTelemetry(values: TelemetrySample[], maximum: number): TelemetrySample[] {
  if (values.length <= maximum) return values;

  const required = new Set<number>([0, values.length - 1]);
  const extremaFields: Array<keyof TelemetrySample> = [
    'cpuPercent',
    'memoryPercent',
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
    'supplyVoltageVolts',
    'networkRxBytesPerSecond',
    'networkTxBytesPerSecond',
    'networkRxErrorsPerSecond',
    'networkTxErrorsPerSecond',
    'networkRxDroppedPerSecond',
    'networkTxDroppedPerSecond',
    'diskReadBytesPerSecond',
    'diskWriteBytesPerSecond',
  ];
  const extrema = new Map<keyof TelemetrySample, { minimum: number; minimumIndex: number; maximum: number; maximumIndex: number }>();
  const transitions: number[] = [];
  for (let index = 0; index < values.length; index += 1) {
    const sample = values[index]!;
    for (const field of extremaFields) {
      const value = sample[field];
      if (typeof value !== 'number' || !Number.isFinite(value)) continue;
      const current = extrema.get(field);
      if (!current) {
        extrema.set(field, { minimum: value, minimumIndex: index, maximum: value, maximumIndex: index });
        continue;
      }
      if (value < current.minimum) {
        current.minimum = value;
        current.minimumIndex = index;
      }
      if (value > current.maximum) {
        current.maximum = value;
        current.maximumIndex = index;
      }
    }
    if (index > 0) {
      const previous = values[index - 1]!;
      if (
        sample.powerState !== previous.powerState
        || sample.throttledFlags !== previous.throttledFlags
      ) transitions.push(index);
    }
  }
  for (const value of extrema.values()) {
    required.add(value.minimumIndex);
    required.add(value.maximumIndex);
  }

  const transitionCapacity = Math.max(0, maximum - required.size);
  for (const index of evenlySelect(transitions, transitionCapacity)) required.add(index);

  const remainingCapacity = maximum - required.size;
  if (remainingCapacity > 0) {
    const candidates = Array.from(
      { length: values.length },
      (_, index) => index,
    ).filter((index) => !required.has(index));
    for (const index of evenlySelect(candidates, remainingCapacity)) required.add(index);
  }

  return [...required]
    .sort((left, right) => left - right)
    .slice(0, maximum)
    .map((index) => values[index]!);
}

function normalizeHost(current: JsonRecord | null): DashboardResponse['host'] {
  const host = recordAt(current ?? undefined, 'host') ?? current ?? undefined;
  return {
    hostname: cleanText(first(host, ['hostname', 'name']), 128),
    os: cleanText(first(host, ['os', 'platform', 'release', 'kernel']), 128),
    architecture: cleanText(first(host, ['architecture', 'arch']), 32),
    logicalCpuCount: integer(first(host, ['logicalCpuCount']), 1, 4096),
    uptimeSeconds: finite(first(host, ['uptimeSeconds', 'uptime']), 0),
  };
}

function unavailableAgent(
  status: DashboardResponse['agent']['status'] = 'unknown',
): DashboardResponse['agent'] {
  return {
    hostId: null,
    agentId: null,
    installationEpoch: null,
    identityGeneration: null,
    machineIdentityStatus: null,
    bootId: null,
    sequence: null,
    observedAt: null,
    receivedAt: null,
    expectedIntervalSeconds: null,
    lifecycle: null,
    transport: null,
    status,
    ageSeconds: null,
    clockSkewSeconds: null,
  };
}

function normalizeAgent(
  current: JsonRecord | null,
  nowMs: number,
  staleAfterMs: number,
): DashboardResponse['agent'] {
  if (!current) return unavailableAgent();
  const hasIdentity = Object.prototype.hasOwnProperty.call(current, 'identity');
  const hasHeartbeat = Object.prototype.hasOwnProperty.call(current, 'heartbeat');
  if (!hasIdentity && !hasHeartbeat) return unavailableAgent();
  if (own(current, 'schemaVersion') !== CURRENT_SNAPSHOT_SCHEMA_VERSION) {
    return unavailableAgent('collection_error');
  }
  const identity = recordAt(current, 'identity');
  const heartbeat = recordAt(current, 'heartbeat');
  const identityFields = [
    'hostId', 'agentId', 'installationEpoch', 'identityGeneration',
    'machineIdentityStatus', 'bootId',
  ] as const;
  const heartbeatFields = [
    'sequence', 'observedAt', 'receivedAt', 'expectedIntervalSeconds',
    'lifecycle', 'transport',
  ] as const;
  if (
    !identity
    || !heartbeat
    || !exactKeys(identity, identityFields)
    || !exactKeys(heartbeat, heartbeatFields)
  ) return unavailableAgent('collection_error');

  const hostId = contractText(own(identity, 'hostId'), 36);
  const agentId = contractText(own(identity, 'agentId'), 36);
  const installationEpoch = contractTimestamp(own(identity, 'installationEpoch'), nowMs);
  const identityGeneration = integer(own(identity, 'identityGeneration'), 1);
  const machineIdentityStatus = own(identity, 'machineIdentityStatus');
  const rawBootId = own(identity, 'bootId');
  const bootId = rawBootId === null ? null : contractText(rawBootId, 32);
  const sequence = integer(own(heartbeat, 'sequence'), 1);
  const observedAt = contractTimestamp(own(heartbeat, 'observedAt'), nowMs);
  const receivedAt = contractTimestamp(own(heartbeat, 'receivedAt'), nowMs);
  const expectedIntervalSeconds = integer(own(heartbeat, 'expectedIntervalSeconds'), 10, 86_400);
  const lifecycle = own(heartbeat, 'lifecycle');
  const transport = own(heartbeat, 'transport');
  const generatedAt = contractTimestamp(own(current, 'generatedAt'), nowMs);
  if (
    hostId === null
    || !OPAQUE_UUID_PATTERN.test(hostId)
    || agentId === null
    || !OPAQUE_UUID_PATTERN.test(agentId)
    || installationEpoch === null
    || identityGeneration === null
    || (machineIdentityStatus !== 'bound' && machineIdentityStatus !== 'unavailable')
    || (bootId !== null && !OPAQUE_BOOT_ID_PATTERN.test(bootId))
    || sequence === null
    || observedAt === null
    || receivedAt === null
    || expectedIntervalSeconds === null
    || generatedAt === null
    || (lifecycle !== 'active' && lifecycle !== 'maintenance' && lifecycle !== 'inactive')
    || transport !== 'local-file'
  ) return unavailableAgent('collection_error');

  const installationMs = new Date(installationEpoch).getTime();
  const observedMs = new Date(observedAt).getTime();
  const receivedMs = new Date(receivedAt).getTime();
  const generatedMs = new Date(generatedAt).getTime();
  if (
    installationMs > observedMs
    || receivedMs !== observedMs
    || generatedMs !== observedMs
  ) {
    return unavailableAgent('collection_error');
  }
  const ageSeconds = Math.max(0, (nowMs - receivedMs) / 1_000);
  const clockSkewSeconds = (receivedMs - observedMs) / 1_000;
  const delayedAfterSeconds = Math.max(90, expectedIntervalSeconds * 2);
  const disconnectedAfterSeconds = Math.max(
    staleAfterMs / 1_000,
    expectedIntervalSeconds * 5,
  );
  const status: DashboardResponse['agent']['status'] = lifecycle === 'maintenance'
    ? 'maintenance'
    : lifecycle === 'inactive'
      ? 'inactive'
      : ageSeconds > disconnectedAfterSeconds
        ? 'disconnected'
        : ageSeconds > delayedAfterSeconds
          ? 'delayed'
          : 'healthy';
  return {
    hostId,
    agentId,
    installationEpoch,
    identityGeneration,
    machineIdentityStatus,
    bootId,
    sequence,
    observedAt,
    receivedAt,
    expectedIntervalSeconds,
    lifecycle,
    transport,
    status,
    ageSeconds: Math.round(ageSeconds * 1000) / 1000,
    clockSkewSeconds,
  };
}

function optionalBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function normalizeReliability(current: JsonRecord | null): DashboardResponse['reliability'] {
  const reliability = recordAt(current ?? undefined, 'reliability');
  return {
    bootStartedAt: isoTimestamp(own(reliability, 'bootStartedAt')),
    collectorGapSeconds: finite(
      own(reliability, 'collectorGapSeconds'),
      0,
      MAX_RELIABILITY_DURATION_SECONDS,
    ),
    sshListenersAvailable: optionalBoolean(own(reliability, 'sshListenersAvailable')),
    networkLinkAvailable: optionalBoolean(own(reliability, 'networkLinkAvailable')),
    nvmeMitigationActive: optionalBoolean(own(reliability, 'nvmeMitigationActive')),
  };
}

const SYSTEM_KERNEL_KEYS = [
  'warning',
  'oops',
  'panic',
  'hungTask',
  'rcuStall',
  'rcuExpedited',
  'oomKill',
  'filesystemError',
  'nvmeReset',
  'nvmeIo',
  'pcieAerCorrectable',
  'pcieAerNonFatal',
  'pcieAerFatal',
] as const;

function systemText(value: unknown, maximumLength: number): string | null {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > maximumLength
    || !/^[A-Za-z0-9][A-Za-z0-9._+:/ -]*$/.test(value)
  ) return null;
  return value.trim() || null;
}

function calendarDate(value: unknown): string | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value
    ? value
    : null;
}

function normalizeSystemKernel(
  value: JsonRecord | undefined,
  nowMs: number,
  bootStartedMs: number | null,
): DashboardResponse['system']['kernel'] {
  return Object.fromEntries(SYSTEM_KERNEL_KEYS.map((key) => {
    const raw = recordAt(value, key);
    const count = integer(own(raw, 'count'), 0);
    const timestamp = isoTimestamp(own(raw, 'lastEventAt'));
    const time = timestamp ? new Date(timestamp).getTime() : Number.NaN;
    if (
      count === null
      || !timestamp && count !== 0
      || timestamp && (
        count === 0
        || time > nowMs + 60_000
        || bootStartedMs !== null && time < bootStartedMs
      )
    ) return [key, { count: 0, lastEventAt: null }];
    return [key, { count, lastEventAt: timestamp }];
  })) as DashboardResponse['system']['kernel'];
}

function normalizeSystem(
  current: JsonRecord | null,
  nowMs: number,
): DashboardResponse['system'] {
  const system = recordAt(current ?? undefined, 'system');
  const versions = recordAt(system, 'versions');
  const pcie = recordAt(system, 'pcie');
  const channel = own(versions, 'bootloaderChannel');
  const bootStartedAt = isoTimestamp(own(
    recordAt(current ?? undefined, 'reliability'),
    'bootStartedAt',
  ));
  const bootStartedMs = bootStartedAt ? new Date(bootStartedAt).getTime() : null;
  return {
    versions: {
      kernelRunning: systemText(own(versions, 'kernelRunning'), 128),
      kernelLatestInstalled: systemText(own(versions, 'kernelLatestInstalled'), 128),
      kernelRebootRequired: optionalBoolean(own(versions, 'kernelRebootRequired')),
      bootloaderCurrent: calendarDate(own(versions, 'bootloaderCurrent')),
      bootloaderLatest: calendarDate(own(versions, 'bootloaderLatest')),
      bootloaderChannel: channel === 'default' || channel === 'latest' ? channel : null,
      nvmeModel: systemText(own(versions, 'nvmeModel'), 128),
      nvmeFirmware: systemText(own(versions, 'nvmeFirmware'), 64),
      collector: systemText(own(versions, 'collector'), 64),
    },
    pcie: {
      configuredGeneration: integer(own(pcie, 'configuredGeneration'), 1, 6),
      negotiatedGeneration: integer(own(pcie, 'negotiatedGeneration'), 1, 6),
      negotiatedSpeedGtps: finite(own(pcie, 'negotiatedSpeedGtps'), 0.1, 128),
      negotiatedWidth: integer(own(pcie, 'negotiatedWidth'), 1, 32),
      endpointMaxGeneration: integer(own(pcie, 'endpointMaxGeneration'), 1, 6),
      endpointMaxWidth: integer(own(pcie, 'endpointMaxWidth'), 1, 32),
      aspmDisabled: optionalBoolean(own(pcie, 'aspmDisabled')),
      nvmePowerSavingDisabled: optionalBoolean(own(pcie, 'nvmePowerSavingDisabled')),
      aerCorrectableCount: integer(own(pcie, 'aerCorrectableCount'), 0),
      aerNonFatalCount: integer(own(pcie, 'aerNonFatalCount'), 0),
      aerFatalCount: integer(own(pcie, 'aerFatalCount'), 0),
      correctableStatusActive: optionalBoolean(own(pcie, 'correctableStatusActive')),
      nonFatalStatusActive: optionalBoolean(own(pcie, 'nonFatalStatusActive')),
      fatalStatusActive: optionalBoolean(own(pcie, 'fatalStatusActive')),
    },
    kernel: normalizeSystemKernel(recordAt(system, 'kernel'), nowMs, bootStartedMs),
  };
}

function normalizeDisks(current: JsonRecord | null): DashboardResponse['disks'] {
  const input = current ? first(current, ['disks', 'filesystems']) : undefined;
  if (!Array.isArray(input)) return [];
  return input.slice(0, 128).flatMap((value) => {
    if (!isRecord(value)) return [];
    const mount = cleanText(first(value, ['mount', 'mountpoint']), 256);
    if (!mount || !mount.startsWith('/')) return [];
    const usedBytes = finite(first(value, ['usedBytes', 'used']));
    const totalBytes = finite(first(value, ['totalBytes', 'total', 'sizeBytes']));
    let availableBytes = integer(first(value, ['availableBytes']));
    if (availableBytes !== null && totalBytes !== null && availableBytes > totalBytes) {
      availableBytes = null;
    }
    let usagePercent = percent(first(value, ['percent', 'usagePercent', 'usedPercent']));
    if (usagePercent === null && usedBytes !== null && totalBytes && totalBytes > 0) {
      usagePercent = Math.min(100, (usedBytes / totalBytes) * 100);
    }
    return [{
      mount,
      totalBytes,
      usedBytes,
      availableBytes,
      usedPercent: usagePercent,
      inodeUsedPercent: percent(first(value, ['inodeUsedPercent'])),
      readOnly: optionalBoolean(first(value, ['readOnly'])),
    }];
  });
}

const CONTAINER_V2_FIELDS = [
  'name', 'project', 'owner', 'state', 'health', 'healthcheckConfigured',
  'cpuPercent', 'memoryBytes', 'memoryPercent', 'memoryLimitBytes', 'cpuLimitCores',
  'pidLimit', 'restartCount', 'restartCountDelta', 'oomKilled', 'startedAt', 'finishedAt',
] as const;
const CONTAINER_V2_ONLY_FIELDS = [
  'project', 'healthcheckConfigured', 'memoryLimitBytes', 'cpuLimitCores', 'pidLimit',
  'restartCount', 'restartCountDelta', 'oomKilled', 'startedAt', 'finishedAt',
] as const;

function containerLifecycleTimestamp(value: unknown, nowMs: number): string | null | undefined {
  if (value === null) return null;
  if (typeof value !== 'string') return undefined;
  const normalized = isoTimestamp(value);
  if (normalized === null) return undefined;
  const time = new Date(normalized).getTime();
  return time > 0 && time <= nowMs + 60_000 ? normalized : undefined;
}

function normalizeContainerList(
  input: unknown,
  nowMs: number,
  allowMigratedLegacy: boolean,
  maximum = 256,
): DashboardResponse['containers'] {
  if (!Array.isArray(input)) return [];
  return input.slice(0, maximum).flatMap((value) => {
    if (!isRecord(value)) return [];
    if (own(value, 'owner') !== 'cks') return [];
    const v2 = CONTAINER_V2_ONLY_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(value, field));
    if (v2 && !CONTAINER_V2_FIELDS.every((field) => Object.prototype.hasOwnProperty.call(value, field))) {
      return [];
    }
    const rawName = cleanText(own(value, 'name'), 128)?.toLowerCase() ?? null;
    const name = safeContainerName(first(value, ['name']));
    const expectedProject = rawName === null ? undefined : CURRENT_CONTAINER_PROJECTS[rawName];
    const project = v2 ? own(value, 'project') : null;
    const migratedV2 = v2
      && project === null
      && own(value, 'health') === null
      && CONTAINER_V2_ONLY_FIELDS
        .filter((field) => field !== 'project')
        .every((field) => own(value, field) === null);
    if (
      (!v2 && !allowMigratedLegacy)
      || (v2 && (
        name !== rawName
        || expectedProject === undefined
        || (project !== expectedProject && !(allowMigratedLegacy && migratedV2))
      ))
    ) {
      return [];
    }
    const rawHealth = own(value, 'health');
    const rawState = own(value, 'state');
    const health = !v2 || rawHealth === null
      ? null
      : safeContainerHealth(first(value, ['health', 'healthStatus']));
    const healthcheckConfigured = v2 ? own(value, 'healthcheckConfigured') : null;
    const oomKilled = v2 ? own(value, 'oomKilled') : null;
    const memoryBytes = v2
      ? (own(value, 'memoryBytes') === null ? null : integer(own(value, 'memoryBytes')))
      : finite(first(value, ['memoryBytes', 'memoryUsageBytes']));
    const memoryLimitBytes = v2
      ? (own(value, 'memoryLimitBytes') === null ? null : integer(own(value, 'memoryLimitBytes')))
      : null;
    const cpuLimitCores = v2
      ? (own(value, 'cpuLimitCores') === null ? null : finite(own(value, 'cpuLimitCores'), 0, 1024))
      : null;
    const pidLimit = v2
      ? (own(value, 'pidLimit') === null ? null : integer(own(value, 'pidLimit')))
      : null;
    const restartCount = v2
      ? (own(value, 'restartCount') === null ? null : integer(own(value, 'restartCount')))
      : null;
    const restartCountDelta = v2
      ? (own(value, 'restartCountDelta') === null ? null : integer(own(value, 'restartCountDelta')))
      : null;
    const startedAt = v2 ? containerLifecycleTimestamp(own(value, 'startedAt'), nowMs) : null;
    const finishedAt = v2 ? containerLifecycleTimestamp(own(value, 'finishedAt'), nowMs) : null;
    const cpuPercent = containerCpuPercent(first(value, ['cpuPercent', 'cpu']));
    const memoryPercent = percent(first(value, ['memoryPercent']));
    if (v2 && (
      (healthcheckConfigured !== null && typeof healthcheckConfigured !== 'boolean')
      || (oomKilled !== null && typeof oomKilled !== 'boolean')
      || (own(value, 'memoryBytes') !== null && memoryBytes === null)
      || (own(value, 'memoryLimitBytes') !== null && memoryLimitBytes === null)
      || (own(value, 'cpuLimitCores') !== null && cpuLimitCores === null)
      || (own(value, 'pidLimit') !== null && pidLimit === null)
      || (own(value, 'restartCount') !== null && restartCount === null)
      || (own(value, 'restartCountDelta') !== null && restartCountDelta === null)
      || (restartCountDelta !== null && (restartCount === null || restartCountDelta > restartCount))
      || startedAt === undefined
      || finishedAt === undefined
      || typeof rawState !== 'string'
      || safeContainerState(rawState) !== rawState
      || (rawHealth !== null && (typeof rawHealth !== 'string' || health !== rawHealth))
      || (own(value, 'cpuPercent') !== null && cpuPercent === null)
      || (own(value, 'memoryPercent') !== null && memoryPercent === null)
      || (healthcheckConfigured === false && health !== 'none')
      || (healthcheckConfigured === true && !['healthy', 'unhealthy', 'starting'].includes(health ?? ''))
      || (healthcheckConfigured === null && health !== null)
    )) return [];
    return [{
      name,
      project: typeof project === 'string' ? project : null,
      owner: 'cks',
      state: safeContainerState(first(value, ['state', 'status'])),
      health,
      healthcheckConfigured: typeof healthcheckConfigured === 'boolean' ? healthcheckConfigured : null,
      cpuPercent,
      memoryBytes,
      memoryPercent,
      memoryLimitBytes,
      cpuLimitCores,
      pidLimit,
      restartCount,
      restartCountDelta,
      oomKilled: typeof oomKilled === 'boolean' ? oomKilled : null,
      startedAt: startedAt ?? null,
      finishedAt: finishedAt ?? null,
    }];
  });
}

function normalizeContainers(
  current: JsonRecord,
  nowMs: number,
  allowMigratedLegacy: boolean,
): DashboardResponse['containers'] {
  return normalizeContainerList(
    first(current, ['containers']),
    nowMs,
    allowMigratedLegacy,
  );
}

const CONTAINER_COLLECTION_STATUSES = new Set<DashboardResponse['containerCollection']['status']>([
  'fresh',
  'last-known',
  'unavailable',
  'permission-denied',
]);

function unavailableContainerCollection(): DashboardResponse['containerCollection'] {
  return { status: 'unavailable', observedAt: null };
}

function normalizeContainerTelemetry(
  current: JsonRecord | null,
  nowMs: number,
  staleAfterMs: number,
): Pick<DashboardResponse, 'containerCollection' | 'containers'> {
  if (!current) {
    return { containerCollection: unavailableContainerCollection(), containers: [] };
  }

  const rawCollection = own(current, 'containerCollection');
  if (rawCollection === undefined) {
    const containers = normalizeContainers(current, nowMs, true);
    const latest = recordAt(current, 'latest');
    const observedAt = isoTimestamp(
      first(latest, ['timestamp']) ?? first(current, ['generatedAt']),
    );
    if (!observedAt) {
      // Pre-status snapshots sometimes contained only the reduced list. Never
      // claim current or last-known evidence without an observation time.
      return { containerCollection: unavailableContainerCollection(), containers: [] };
    }
    const observedMs = new Date(observedAt).getTime();
    if (observedMs > nowMs + 60_000) {
      return { containerCollection: unavailableContainerCollection(), containers: [] };
    }
    return {
      containerCollection: {
        status: 'last-known',
        observedAt,
      },
      containers,
    };
  }

  if (!isRecord(rawCollection)) {
    return { containerCollection: unavailableContainerCollection(), containers: [] };
  }
  const keys = Object.keys(rawCollection);
  const rawStatus = own(rawCollection, 'status');
  const rawObservedAt = own(rawCollection, 'observedAt');
  const observedAt = rawObservedAt === null ? null : isoTimestamp(rawObservedAt);
  if (
    keys.length !== 2
    || !keys.includes('status')
    || !keys.includes('observedAt')
    || typeof rawStatus !== 'string'
    || !CONTAINER_COLLECTION_STATUSES.has(rawStatus as DashboardResponse['containerCollection']['status'])
    || (rawObservedAt !== null && observedAt === null)
  ) {
    return { containerCollection: unavailableContainerCollection(), containers: [] };
  }
  let status = rawStatus as DashboardResponse['containerCollection']['status'];
  if (
    status === 'fresh'
    && observedAt !== null
    && nowMs - new Date(observedAt).getTime() > staleAfterMs
  ) {
    status = 'last-known';
  }
  const containers = normalizeContainers(current, nowMs, status !== 'fresh');
  if (
    ((status === 'fresh' || status === 'last-known') && observedAt === null)
    || (status === 'unavailable' && observedAt !== null)
    || (observedAt !== null && new Date(observedAt).getTime() > nowMs + 60_000)
    || (observedAt === null && containers.length > 0)
  ) {
    return { containerCollection: unavailableContainerCollection(), containers: [] };
  }
  return { containerCollection: { status, observedAt }, containers };
}

function contractText(value: unknown, maximumLength: number): string | null {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximumLength) return null;
  const normalized = value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return normalized === value ? value : null;
}

function contractTimestamp(value: unknown, nowMs: number): string | null {
  if (typeof value !== 'string') return null;
  const timestamp = isoTimestamp(value);
  return timestamp !== null && new Date(timestamp).getTime() <= nowMs + 60_000
    ? timestamp
    : null;
}

function signedRuleValue(value: unknown): number | null {
  return typeof value === 'number'
    && Number.isFinite(value)
    ? value
    : null;
}

function unavailableRuleEvaluation(
  status: 'unavailable' | 'collection_error',
): DashboardResponse['ruleEvaluation'] {
  return {
    schemaVersion: 1,
    status,
    rulePackVersion: null,
    evaluatedAt: null,
    summary: {},
    states: {},
  };
}

const RULE_STATE_FIELDS = [
  'ruleId',
  'target',
  'metric',
  'severity',
  'description',
  'runbook',
  'phase',
  'breachSamples',
  'recoverySamples',
  'missingSamples',
  'openedAt',
  'changedAt',
  'lastEvaluatedAt',
  'lastValue',
  'observationStatus',
] as const;

function normalizeRuleState(
  key: string,
  value: unknown,
  evaluatedAt: string,
  nowMs: number,
): RuleEvaluationState | null {
  if (!isRecord(value) || !exactKeys(value, RULE_STATE_FIELDS)) return null;
  const ruleId = own(value, 'ruleId');
  const target = own(value, 'target');
  const metric = own(value, 'metric');
  const severity = own(value, 'severity');
  const description = contractText(own(value, 'description'), 500);
  const runbook = contractText(own(value, 'runbook'), 500);
  const phase = own(value, 'phase');
  const observationStatus = own(value, 'observationStatus');
  if (
    typeof ruleId !== 'string'
    || !RULE_ID_PATTERN.test(ruleId)
    || typeof target !== 'string'
    || !RULE_TARGET_PATTERN.test(target)
    || key !== `${ruleId}:${target}`
    || typeof metric !== 'string'
    || !RULE_METRIC_PATTERN.test(metric)
    || typeof severity !== 'string'
    || !RULE_SEVERITIES.has(severity as RuleEvaluationState['severity'])
    || description === null
    || runbook === null
    || typeof phase !== 'string'
    || !RULE_PHASES.has(phase as RuleEvaluationPhase)
    || typeof observationStatus !== 'string'
    || !RULE_OBSERVATION_STATUSES.has(observationStatus as RuleObservationStatus)
  ) return null;

  const breachSamples = integer(own(value, 'breachSamples'), 0, 10_000);
  const recoverySamples = integer(own(value, 'recoverySamples'), 0, 10_000);
  const missingSamples = integer(own(value, 'missingSamples'), 0, 10_000);
  const openedAtValue = own(value, 'openedAt');
  const openedAt = openedAtValue === null ? null : contractTimestamp(openedAtValue, nowMs);
  const changedAt = contractTimestamp(own(value, 'changedAt'), nowMs);
  const lastEvaluatedAt = contractTimestamp(own(value, 'lastEvaluatedAt'), nowMs);
  const rawLastValue = own(value, 'lastValue');
  const lastValue = rawLastValue === null ? null : signedRuleValue(rawLastValue);
  const evaluatedMs = new Date(evaluatedAt).getTime();
  if (
    breachSamples === null
    || recoverySamples === null
    || missingSamples === null
    || (openedAtValue !== null && openedAt === null)
    || changedAt === null
    || lastEvaluatedAt !== evaluatedAt
    || new Date(changedAt).getTime() > evaluatedMs
    || (openedAt !== null && new Date(openedAt).getTime() > evaluatedMs)
    || ((phase === 'firing' || phase === 'recovering') && openedAt === null)
    || ((phase !== 'firing' && phase !== 'recovering') && openedAt !== null)
    || (rawLastValue !== null && lastValue === null)
    || (observationStatus !== 'ok' && lastValue !== null)
  ) return null;

  return {
    ruleId,
    target,
    metric,
    severity: severity as RuleEvaluationState['severity'],
    description,
    runbook,
    phase: phase as RuleEvaluationPhase,
    breachSamples,
    recoverySamples,
    missingSamples,
    openedAt,
    changedAt,
    lastEvaluatedAt,
    lastValue,
    observationStatus: observationStatus as RuleObservationStatus,
  };
}

function readRuleEvaluation(
  root: string,
  nowMs: number,
  staleAfterMs: number,
): DashboardResponse['ruleEvaluation'] {
  const file = readStrictBounded(
    root,
    join(root, 'rule-evaluation.json'),
    MAX_RULE_EVALUATION_BYTES,
  );
  if (file.status !== 'ok') return unavailableRuleEvaluation(file.status);

  let parsed: unknown;
  try {
    parsed = JSON.parse(file.content);
  } catch {
    return unavailableRuleEvaluation('collection_error');
  }
  const topFields = [
    'schemaVersion', 'status', 'rulePackVersion', 'evaluatedAt', 'summary', 'states',
  ] as const;
  if (!isRecord(parsed) || !exactKeys(parsed, topFields) || own(parsed, 'schemaVersion') !== 1) {
    return unavailableRuleEvaluation('collection_error');
  }
  const status = own(parsed, 'status');
  const evaluatedAt = contractTimestamp(own(parsed, 'evaluatedAt'), nowMs);
  const rawSummary = own(parsed, 'summary');
  const rawStates = own(parsed, 'states');
  if (
    (status !== 'ok' && status !== 'collection_error')
    || evaluatedAt === null
    || !isRecord(rawSummary)
    || !isRecord(rawStates)
  ) return unavailableRuleEvaluation('collection_error');

  if (status === 'collection_error') {
    if (
      own(parsed, 'rulePackVersion') !== null
      || Object.keys(rawSummary).length !== 0
      || Object.keys(rawStates).length !== 0
    ) return unavailableRuleEvaluation('collection_error');
    return {
      schemaVersion: 1,
      status,
      rulePackVersion: null,
      evaluatedAt,
      summary: {},
      states: {},
    };
  }

  const rawVersion = own(parsed, 'rulePackVersion');
  const rulePackVersion = contractText(rawVersion, 64);
  if (
    rulePackVersion === null
    || !RULE_PACK_VERSION_PATTERN.test(rulePackVersion)
    || Object.keys(rawStates).length === 0
  ) return unavailableRuleEvaluation('collection_error');

  const stateEntries = Object.entries(rawStates);
  if (stateEntries.length > MAX_RULE_STATES) {
    return unavailableRuleEvaluation('collection_error');
  }
  const states: Record<string, RuleEvaluationState> = {};
  const phaseCounts: Partial<Record<RuleEvaluationPhase, number>> = {};
  for (const [key, rawState] of stateEntries) {
    const state = normalizeRuleState(key, rawState, evaluatedAt, nowMs);
    if (!state) return unavailableRuleEvaluation('collection_error');
    states[key] = state;
    phaseCounts[state.phase] = (phaseCounts[state.phase] ?? 0) + 1;
  }

  const summary: Partial<Record<RuleEvaluationPhase, number>> = {};
  for (const [phase, rawCount] of Object.entries(rawSummary)) {
    if (!RULE_PHASES.has(phase as RuleEvaluationPhase)) {
      return unavailableRuleEvaluation('collection_error');
    }
    const count = integer(rawCount, 1, MAX_RULE_STATES);
    if (count === null) return unavailableRuleEvaluation('collection_error');
    summary[phase as RuleEvaluationPhase] = count;
  }
  const countedPhases = Object.keys(phaseCounts) as RuleEvaluationPhase[];
  if (
    Object.keys(summary).length !== countedPhases.length
    || countedPhases.some((phase) => summary[phase] !== phaseCounts[phase])
  ) return unavailableRuleEvaluation('collection_error');

  return {
    schemaVersion: 1,
    status: nowMs - new Date(evaluatedAt).getTime() > staleAfterMs ? 'last-known' : status,
    rulePackVersion,
    evaluatedAt,
    summary,
    states,
  };
}

const RULE_ALERT_FIELDS = [
  'schemaVersion',
  'rulePackVersion',
  'idempotencyKey',
  'ruleId',
  'target',
  'transition',
  'severity',
  'notificationState',
  'observedAt',
  'openedAt',
  'value',
  'status',
  'labels',
  'description',
  'runbook',
] as const;

function normalizeRuleAlert(value: unknown, nowMs: number): RuleAlertEvent | null {
  if (!isRecord(value) || !exactKeys(value, RULE_ALERT_FIELDS) || own(value, 'schemaVersion') !== 1) {
    return null;
  }
  const rulePackVersion = own(value, 'rulePackVersion');
  const idempotencyKey = own(value, 'idempotencyKey');
  const ruleId = own(value, 'ruleId');
  const target = own(value, 'target');
  const transition = own(value, 'transition');
  const severity = own(value, 'severity');
  const notificationState = own(value, 'notificationState');
  const observedAt = contractTimestamp(own(value, 'observedAt'), nowMs);
  const openedAt = contractTimestamp(own(value, 'openedAt'), nowMs);
  const rawValue = own(value, 'value');
  const normalizedValue = rawValue === null ? null : signedRuleValue(rawValue);
  const status = own(value, 'status');
  const rawLabels = own(value, 'labels');
  const description = contractText(own(value, 'description'), 500);
  const runbook = contractText(own(value, 'runbook'), 500);
  if (
    typeof rulePackVersion !== 'string'
    || !RULE_PACK_VERSION_PATTERN.test(rulePackVersion)
    || typeof idempotencyKey !== 'string'
    || !/^[a-f0-9]{64}$/.test(idempotencyKey)
    || typeof ruleId !== 'string'
    || !RULE_ID_PATTERN.test(ruleId)
    || typeof target !== 'string'
    || !RULE_TARGET_PATTERN.test(target)
    || (transition !== 'firing' && transition !== 'resolved')
    || typeof severity !== 'string'
    || !RULE_SEVERITIES.has(severity as RuleAlertEvent['severity'])
    || (notificationState !== 'ready' && notificationState !== 'suppressed' && notificationState !== 'silenced')
    || observedAt === null
    || openedAt === null
    || new Date(openedAt).getTime() > new Date(observedAt).getTime()
    || (rawValue !== null && normalizedValue === null)
    || typeof status !== 'string'
    || !RULE_OBSERVATION_STATUSES.has(status as RuleObservationStatus)
    || (status !== 'ok' && normalizedValue !== null)
    || !isRecord(rawLabels)
    || Object.keys(rawLabels).length > 16
    || description === null
    || runbook === null
  ) return null;

  const labels: Record<string, string> = {};
  for (const [key, labelValue] of Object.entries(rawLabels)) {
    if (
      !RULE_LABEL_NAME_PATTERN.test(key)
      || typeof labelValue !== 'string'
      || !RULE_LABEL_VALUE_PATTERN.test(labelValue)
    ) return null;
    labels[key] = labelValue;
  }
  return {
    schemaVersion: 1,
    rulePackVersion,
    idempotencyKey,
    ruleId,
    target,
    transition,
    severity: severity as RuleAlertEvent['severity'],
    notificationState,
    observedAt,
    openedAt,
    value: normalizedValue,
    status: status as RuleObservationStatus,
    labels,
    description,
    runbook,
  };
}

function readRuleAlerts(
  root: string,
  cutoff: number,
  nowMs: number,
): DashboardResponse['ruleAlerts'] {
  const file = readStrictBounded(root, join(root, 'rule-alerts.jsonl'), MAX_RULE_ALERT_FILE_BYTES);
  if (file.status !== 'ok') return { status: file.status, events: [] };
  if (file.content.length === 0) return { status: 'ok', events: [] };

  const lines = file.content.split('\n');
  if (lines.at(-1) === '') lines.pop();
  if (lines.length > MAX_RULE_ALERT_RECORDS || lines.some((line) => line.length === 0)) {
    return { status: 'collection_error', events: [] };
  }
  const events: RuleAlertEvent[] = [];
  const identities = new Set<string>();
  for (const line of lines) {
    if (Buffer.byteLength(line) > MAX_RULE_ALERT_LINE_BYTES) {
      return { status: 'collection_error', events: [] };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return { status: 'collection_error', events: [] };
    }
    const event = normalizeRuleAlert(parsed, nowMs);
    if (!event || identities.has(event.idempotencyKey)) {
      return { status: 'collection_error', events: [] };
    }
    identities.add(event.idempotencyKey);
    const observedMs = new Date(event.observedAt).getTime();
    if (observedMs >= cutoff) events.push(event);
  }
  events.sort((left, right) => right.observedAt.localeCompare(left.observedAt));
  return { status: 'ok', events: events.slice(0, MAX_RULE_ALERTS) };
}

function normalizeAlert(
  record: JsonRecord,
  cutoff: number,
  nowMs: number,
): DashboardResponse['alerts'][number] | null {
  const timestamp = timestampOf(record);
  const time = timestamp ? new Date(timestamp).getTime() : Number.NaN;
  if (!timestamp || time < cutoff || time > nowMs + 60_000) return null;
  const message = safeMessage(first(record, ['message', 'summary', 'title']));
  if (!message) return null;
  const rawSeverity = cleanText(first(record, ['severity', 'level']), 16)?.toLowerCase();
  const severity: DashboardResponse['alerts'][number]['severity'] = rawSeverity === 'critical' || rawSeverity === 'error'
    ? 'critical'
    : rawSeverity === 'warning' || rawSeverity === 'warn'
      ? 'warning'
      : 'info';
  return {
    timestamp,
    severity,
    kind: cleanText(first(record, ['kind', 'type', 'category']), 64),
    status: cleanText(first(record, ['status', 'state']), 32),
    message,
  };
}

function normalizeAlerts(records: JsonRecord[], cutoff: number, nowMs: number): DashboardResponse['alerts'] {
  return records
    .map((record) => normalizeAlert(record, cutoff, nowMs))
    .filter((alert): alert is DashboardResponse['alerts'][number] => alert !== null)
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
    .slice(0, MAX_EVENTS);
}

const POWER_ALERT_PATTERN = /\b(?:power-throttle|under-voltage|undervoltage|vcgencmd|throttl(?:e|ed|ing)|voltage)\b/i;

function alertRecordIsPowerRelated(
  record: JsonRecord,
  alert: DashboardResponse['alerts'][number],
): boolean {
  const kind = alert.kind?.toLowerCase();
  if (kind === 'power') return true;
  if (kind !== 'host') return false;
  const discriminator = cleanText(first(record, ['alert', 'reason', 'name']), 128);
  return POWER_ALERT_PATTERN.test(`${discriminator ?? ''} ${alert.message}`);
}

function nearestSample(
  samples: TelemetrySample[],
  eventTime: number,
): TelemetrySample | null {
  let low = 0;
  let high = samples.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (new Date(samples[middle]!.timestamp).getTime() < eventTime) low = middle + 1;
    else high = middle;
  }

  let nearest: TelemetrySample | null = null;
  let nearestDistance = MAX_POWER_CORRELATION_MS + 1;
  for (const index of [low - 1, low]) {
    const sample = samples[index];
    if (!sample) continue;
    const distance = Math.abs(new Date(sample.timestamp).getTime() - eventTime);
    if (distance < nearestDistance) {
      nearest = sample;
      nearestDistance = distance;
    }
  }
  return nearestDistance <= MAX_POWER_CORRELATION_MS ? nearest : null;
}

function powerEventDedupeKey(event: DashboardResponse['powerEvents'][number]): string {
  const sameSecond = event.timestamp.slice(0, 19);
  return [
    sameSecond,
    event.severity,
    event.status?.toLowerCase() ?? '',
    event.message.toLowerCase(),
  ].join('\u0000');
}

function normalizePowerEvents(
  dedicatedRecords: JsonRecord[],
  alertRecords: JsonRecord[],
  samples: TelemetrySample[],
  cutoff: number,
  nowMs: number,
): DashboardResponse['powerEvents'] {
  const dedicatedCandidates: DashboardResponse['powerEvents'] = [];
  const alertCandidates: DashboardResponse['powerEvents'] = [];
  const append = (
    target: DashboardResponse['powerEvents'],
    record: JsonRecord,
    requirePowerSemantics: boolean,
  ): void => {
    const alert = normalizeAlert(record, cutoff, nowMs);
    if (!alert || requirePowerSemantics && !alertRecordIsPowerRelated(record, alert)) return;
    const eventTime = new Date(alert.timestamp).getTime();
    const sample = nearestSample(samples, eventTime);
    target.push({
      timestamp: alert.timestamp,
      severity: alert.severity,
      kind: alert.kind,
      status: alert.status,
      message: alert.message,
      supplyVoltageVolts: sample?.supplyVoltageVolts ?? null,
      throttledFlags: sample?.throttledFlags ?? null,
    });
  };

  // Dedicated power records win semantic duplicates from the legacy alert feed.
  for (const record of dedicatedRecords) append(dedicatedCandidates, record, false);
  for (const record of alertRecords) append(alertCandidates, record, true);
  dedicatedCandidates.sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  alertCandidates.sort((left, right) => right.timestamp.localeCompare(left.timestamp));

  const seen = new Set<string>();
  return [...dedicatedCandidates, ...alertCandidates]
    .filter((event) => {
      const key = powerEventDedupeKey(event);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
    .slice(0, MAX_EVENTS);
}

function normalizeReliabilitySeverity(
  value: unknown,
): DashboardResponse['reliabilityEvents'][number]['severity'] | null {
  const severity = cleanText(value, 16)?.toLowerCase();
  return severity === 'info' || severity === 'warning' || severity === 'critical'
    ? severity
    : null;
}

function reliabilityEventDedupeKey(
  event: DashboardResponse['reliabilityEvents'][number],
  preserveSubseconds = true,
): string {
  return [
    preserveSubseconds ? event.timestamp : event.timestamp.slice(0, 19),
    event.kind,
    event.status.toLowerCase(),
    event.message.toLowerCase(),
  ].join('\u0000');
}

function normalizeReliabilityRecord(
  record: JsonRecord,
  cutoff: number,
  nowMs: number,
  legacyPowerRecord = false,
): DashboardResponse['reliabilityEvents'][number] | null {
  const timestamp = timestampOf(record);
  const time = timestamp ? new Date(timestamp).getTime() : Number.NaN;
  if (!timestamp || time < cutoff || time > nowMs + 60_000) return null;

  const rawKind = cleanText(first(record, ['kind']), 32)?.toLowerCase();
  if (!rawKind || !RELIABILITY_KINDS.has(rawKind as DashboardResponse['reliabilityEvents'][number]['kind'])) {
    return null;
  }
  if (legacyPowerRecord && rawKind !== 'nvme-reset' && rawKind !== 'nvme-io') return null;

  const status = incidentToken(first(record, ['status']), 32)?.toLowerCase();
  if (!status) return null;
  const contractKey = `${rawKind}:${status}` as keyof typeof RELIABILITY_EVENT_CONTRACT;
  const contract = RELIABILITY_EVENT_CONTRACT[contractKey];
  const severity = normalizeReliabilitySeverity(first(record, ['severity']));
  const message = safeMessage(first(record, ['message']));
  if (!contract || severity !== contract.severity || message !== contract.message) return null;

  const rawDuration = own(record, 'durationSeconds');
  const durationSeconds = rawKind === 'collector-gap'
    ? integer(rawDuration, 0, MAX_RELIABILITY_DURATION_SECONDS)
    : null;
  if (rawKind === 'collector-gap' && durationSeconds === null) return null;
  if (!legacyPowerRecord && rawKind !== 'collector-gap' && rawDuration !== null) return null;

  return {
    timestamp,
    severity,
    kind: rawKind as DashboardResponse['reliabilityEvents'][number]['kind'],
    status,
    message: contract.message,
    durationSeconds,
  };
}

function normalizeReliabilityEvents(
  dedicatedRecords: JsonRecord[],
  legacyPowerRecords: JsonRecord[],
  cutoff: number,
  nowMs: number,
): DashboardResponse['reliabilityEvents'] {
  const dedicated = dedicatedRecords.flatMap((record) => {
    const event = normalizeReliabilityRecord(record, cutoff, nowMs);
    return event ? [event] : [];
  });
  const legacy = legacyPowerRecords.flatMap((record) => {
    const event = normalizeReliabilityRecord(record, cutoff, nowMs, true);
    return event ? [event] : [];
  });
  dedicated.sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  legacy.sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  const dedicatedExact = new Set<string>();
  const dedicatedSeconds = new Set<string>();
  const uniqueDedicated = dedicated.filter((event) => {
    const exactKey = reliabilityEventDedupeKey(event);
    if (dedicatedExact.has(exactKey)) return false;
    dedicatedExact.add(exactKey);
    dedicatedSeconds.add(reliabilityEventDedupeKey(event, false));
    return true;
  });
  const legacySeconds = new Set<string>();
  const uniqueLegacy = legacy.filter((event) => {
    const secondKey = reliabilityEventDedupeKey(event, false);
    if (dedicatedSeconds.has(secondKey) || legacySeconds.has(secondKey)) return false;
    legacySeconds.add(secondKey);
    return true;
  });
  return [...uniqueDedicated, ...uniqueLegacy]
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
    .slice(0, MAX_EVENTS);
}

function summarizePower(samples: TelemetrySample[]): DashboardResponse['powerSummary'] {
  let voltageSampleCount = 0;
  let voltageSum = 0;
  let minimumVoltage: number | null = null;
  let maximumVoltage: number | null = null;
  let underVoltageSampleCount = 0;
  let throttledSampleCount = 0;
  for (const sample of samples) {
    if (sample.supplyVoltageVolts !== null) {
      voltageSampleCount += 1;
      voltageSum += sample.supplyVoltageVolts;
      minimumVoltage = minimumVoltage === null
        ? sample.supplyVoltageVolts
        : Math.min(minimumVoltage, sample.supplyVoltageVolts);
      maximumVoltage = maximumVoltage === null
        ? sample.supplyVoltageVolts
        : Math.max(maximumVoltage, sample.supplyVoltageVolts);
    }
    if (sample.throttledFlags !== null && (sample.throttledFlags & 0x1) !== 0) {
      underVoltageSampleCount += 1;
    }
    if (sample.throttledFlags !== null && (sample.throttledFlags & 0x4) !== 0) {
      throttledSampleCount += 1;
    }
  }
  return {
    sampleCount: samples.length,
    voltageSampleCount,
    minSupplyVoltageVolts: minimumVoltage,
    averageSupplyVoltageVolts: voltageSampleCount
      ? Math.round((voltageSum / voltageSampleCount) * 1_000) / 1_000
      : null,
    maxSupplyVoltageVolts: maximumVoltage,
    underVoltageSampleCount,
    throttledSampleCount,
  };
}

function telemetryValues(samples: TelemetrySample[], field: keyof TelemetrySample): number[] {
  return samples
    .map((sample) => sample[field])
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
}

function telemetryAverage(values: number[]): number | null {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
}

function telemetryPeak(values: number[]): number | null {
  if (!values.length) return null;
  let maximum = values[0]!;
  for (let index = 1; index < values.length; index += 1) {
    if (values[index]! > maximum) maximum = values[index]!;
  }
  return maximum;
}

function integrateTelemetryRate(samples: TelemetrySample[], field: keyof TelemetrySample): number {
  let total = 0;
  for (let index = 1; index < samples.length; index += 1) {
    const previous = samples[index - 1]!;
    const current = samples[index]!;
    const rate = current[field];
    if (typeof rate !== 'number' || !Number.isFinite(rate) || rate < 0) continue;
    const before = new Date(previous.timestamp).getTime();
    const after = new Date(current.timestamp).getTime();
    if (!Number.isFinite(before) || !Number.isFinite(after) || after <= before) continue;
    const contribution = rate * Math.min((after - before) / 1_000, 300);
    total = Math.min(Number.MAX_SAFE_INTEGER, total + contribution);
  }
  return total;
}

function summarizeTelemetry(samples: TelemetrySample[]): DashboardResponse['telemetrySummary'] {
  const cpu = telemetryValues(samples, 'cpuPercent');
  const memory = telemetryValues(samples, 'memoryPercent');
  const temperature = telemetryValues(samples, 'temperatureC');
  const load1 = telemetryValues(samples, 'load1');
  return {
    sampleCount: samples.length,
    cpuAveragePercent: telemetryAverage(cpu),
    cpuPeakPercent: telemetryPeak(cpu),
    memoryAveragePercent: telemetryAverage(memory),
    memoryPeakPercent: telemetryPeak(memory),
    temperatureAverageC: telemetryAverage(temperature),
    temperaturePeakC: telemetryPeak(temperature),
    load1Average: telemetryAverage(load1),
    load1Peak: telemetryPeak(load1),
    networkReceivedBytes: integrateTelemetryRate(samples, 'networkRxBytesPerSecond'),
    networkTransmittedBytes: integrateTelemetryRate(samples, 'networkTxBytesPerSecond'),
    diskReadBytes: integrateTelemetryRate(samples, 'diskReadBytesPerSecond'),
    diskWrittenBytes: integrateTelemetryRate(samples, 'diskWriteBytesPerSecond'),
  };
}

function privilegeAction(record: JsonRecord): DashboardResponse['privilegeEvents'][number]['action'] {
  const value = cleanText(first(record, ['action', 'type', 'event']), 64)?.toLowerCase() ?? '';
  if (value.includes('sudo')) return 'sudo';
  if (/\bsu\b/.test(value)) return 'su';
  if (value.includes('auth') || value.includes('login')) return 'authentication';
  if (value.includes('policy') || value.includes('polkit')) return 'policy';
  return 'unknown';
}

function normalizePrivilege(records: JsonRecord[], cutoff: number, nowMs: number): DashboardResponse['privilegeEvents'] {
  return records.flatMap((record) => {
    const timestamp = timestampOf(record);
    const time = timestamp ? new Date(timestamp).getTime() : Number.NaN;
    if (!timestamp || time < cutoff || time > nowMs + 60_000) return [];
    const rawOutcome = cleanText(first(record, ['result', 'outcome', 'status']), 32)?.toLowerCase() ?? '';
    const result: DashboardResponse['privilegeEvents'][number]['result'] = /success|allowed|accepted|ok/.test(rawOutcome)
      ? 'success'
      : /fail|denied|rejected|error/.test(rawOutcome)
        ? 'failure'
        : 'unknown';
    return [{
      timestamp,
      actor: cleanIdentity(first(record, ['actor', 'user', 'username'])),
      target: cleanIdentity(first(record, ['target', 'targetUser'])),
      action: privilegeAction(record),
      result,
    }];
  }).sort((left, right) => right.timestamp.localeCompare(left.timestamp)).slice(0, MAX_EVENTS);
}

function normalizePressureWindow(value: unknown): DashboardResponse['incidents'][number]['pressure']['cpu'] | null {
  if (!isRecord(value)) return null;
  return {
    someAvg10: percent(own(value, 'someAvg10')),
    fullAvg10: percent(own(value, 'fullAvg10')),
  };
}

function normalizeIncidentProcesses(value: unknown): DashboardResponse['incidents'][number]['processes'] | null {
  if (!Array.isArray(value)) return null;
  return value.slice(0, MAX_INCIDENT_PROCESSES).flatMap((candidate) => {
    if (!isRecord(candidate)) return [];
    const name = safeProcessName(own(candidate, 'name'));
    const instances = integer(own(candidate, 'instances'), 1, 1_000_000);
    if (instances === null) return [];
    return [{
      name,
      instances,
      cpuPercent: percent(own(candidate, 'cpuPercent')),
      memoryBytes: integer(own(candidate, 'memoryBytes')),
    }];
  });
}

function normalizeIncidentMetrics(
  value: JsonRecord,
  observedAt: string,
): TelemetrySample | null {
  const memoryUsedBytes = finite(own(value, 'memoryUsedBytes'));
  const memoryTotalBytes = finite(own(value, 'memoryTotalBytes'));
  if (
    memoryUsedBytes !== null
    && memoryTotalBytes !== null
    && memoryUsedBytes > memoryTotalBytes
  ) return null;
  const normalizedSwap = normalizeSwap(
    own(value, 'swapTotalBytes'),
    own(value, 'swapUsedBytes'),
    own(value, 'swapPercent'),
  );
  return {
    timestamp: observedAt,
    cpuPercent: percent(own(value, 'cpuPercent')),
    memoryPercent: percent(own(value, 'memoryPercent')),
    memoryUsedBytes,
    memoryTotalBytes,
    ...normalizedSwap,
    temperatureC: finite(own(value, 'temperatureC'), -100, 250),
    load1: finite(own(value, 'load1')),
    load5: finite(own(value, 'load5')),
    load15: finite(own(value, 'load15')),
    cpuPressureSomeAvg10: percent(own(value, 'cpuPressureSomeAvg10')),
    cpuPressureFullAvg10: percent(own(value, 'cpuPressureFullAvg10')),
    memoryPressureSomeAvg10: percent(own(value, 'memoryPressureSomeAvg10')),
    memoryPressureFullAvg10: percent(own(value, 'memoryPressureFullAvg10')),
    ioPressureSomeAvg10: percent(own(value, 'ioPressureSomeAvg10')),
    ioPressureFullAvg10: percent(own(value, 'ioPressureFullAvg10')),
    powerState: cleanText(own(value, 'powerState'), 32),
    supplyVoltageVolts: finite(own(value, 'supplyVoltageVolts'), 0, 10),
    throttledFlags: uint32(own(value, 'throttledFlags')),
    gpuMemoryBytes: finite(own(value, 'gpuMemoryBytes')),
    gpuClockHz: finite(own(value, 'gpuClockHz')),
    networkRxBytesPerSecond: finite(own(value, 'networkRxBytesPerSecond')),
    networkTxBytesPerSecond: finite(own(value, 'networkTxBytesPerSecond')),
    networkRxErrorsPerSecond: finite(
      own(value, 'networkRxErrorsPerSecond'), 0, MAX_TELEMETRY_RATE,
    ),
    networkTxErrorsPerSecond: finite(
      own(value, 'networkTxErrorsPerSecond'), 0, MAX_TELEMETRY_RATE,
    ),
    networkRxDroppedPerSecond: finite(
      own(value, 'networkRxDroppedPerSecond'), 0, MAX_TELEMETRY_RATE,
    ),
    networkTxDroppedPerSecond: finite(
      own(value, 'networkTxDroppedPerSecond'), 0, MAX_TELEMETRY_RATE,
    ),
    diskReadBytesPerSecond: finite(own(value, 'diskReadBytesPerSecond')),
    diskWriteBytesPerSecond: finite(own(value, 'diskWriteBytesPerSecond')),
  };
}

function normalizeIncidentContainers(value: unknown): DashboardResponse['incidents'][number]['containers'] | null {
  if (!Array.isArray(value)) return null;
  return value.slice(0, MAX_INCIDENT_CONTAINERS).flatMap((candidate) => {
    if (!isRecord(candidate)) return [];
    if (own(candidate, 'owner') !== 'cks') return [];
    const name = safeContainerName(own(candidate, 'name'));
    return [{
      name,
      owner: 'cks',
      state: safeContainerState(own(candidate, 'state')),
      health: safeContainerHealth(own(candidate, 'health')),
      cpuPercent: containerCpuPercent(own(candidate, 'cpuPercent')),
      memoryBytes: finite(own(candidate, 'memoryBytes')),
      memoryPercent: percent(own(candidate, 'memoryPercent')),
    }];
  });
}

function normalizeIncidentTraffic(value: unknown): DashboardResponse['incidents'][number]['traffic'] | null {
  if (!Array.isArray(value)) return null;
  return value.slice(0, MAX_INCIDENT_TRAFFIC).flatMap((candidate) => {
    if (!isRecord(candidate)) return [];
    const app = incidentToken(own(candidate, 'app'), 64);
    const requestCount = integer(own(candidate, 'requestCount'), 0, MAX_INCIDENT_COUNT);
    const status2xx = integer(own(candidate, 'status2xx'), 0, MAX_INCIDENT_COUNT);
    const status3xx = integer(own(candidate, 'status3xx'), 0, MAX_INCIDENT_COUNT);
    const status4xx = integer(own(candidate, 'status4xx'), 0, MAX_INCIDENT_COUNT);
    const status5xx = integer(own(candidate, 'status5xx'), 0, MAX_INCIDENT_COUNT);
    const slowCount = integer(own(candidate, 'slowCount'), 0, MAX_INCIDENT_COUNT);
    if (
      !app
      || !INCIDENT_TRAFFIC_APPS.has(app)
      || requestCount === null
      || status2xx === null
      || status3xx === null
      || status4xx === null
      || status5xx === null
      || slowCount === null
      || slowCount > requestCount
      || status2xx + status3xx + status4xx + status5xx > requestCount
    ) return [];
    const avgResponseMs = finite(own(candidate, 'avgResponseMs'), 0, MAX_RESPONSE_TIME_MS);
    const maxResponseMs = finite(own(candidate, 'maxResponseMs'), 0, MAX_RESPONSE_TIME_MS);
    if (avgResponseMs !== null && maxResponseMs !== null && avgResponseMs > maxResponseMs) return [];
    return [{
      app,
      requestCount,
      status2xx,
      status3xx,
      status4xx,
      status5xx,
      slowCount,
      avgResponseMs,
      maxResponseMs,
    }];
  });
}

function normalizeCurrentTraffic(current: JsonRecord | null): DashboardResponse['currentTraffic'] {
  const input = own(current ?? undefined, 'currentTraffic');
  if (input === undefined) return [];
  if (!Array.isArray(input) || input.length > MAX_CURRENT_TRAFFIC) return [];
  for (const candidate of input) {
    if (!isRecord(candidate)) return [];
    const fields = Object.keys(candidate);
    if (
      fields.length !== TRAFFIC_AGGREGATE_FIELDS.size
      || fields.some((field) => !TRAFFIC_AGGREGATE_FIELDS.has(field))
    ) return [];
  }
  const normalized = normalizeIncidentTraffic(input);
  if (
    normalized === null
    || normalized.length !== input.length
    || normalized.some((item) => item.avgResponseMs === null || item.maxResponseMs === null)
    || new Set(normalized.map((item) => item.app)).size !== normalized.length
  ) return [];
  return normalized;
}

function normalizeIncident(
  record: JsonRecord,
  cutoff: number,
  nowMs: number,
): DashboardResponse['incidents'][number] | null {
  const id = incidentId(own(record, 'id'));
  const startedAt = typeof own(record, 'startedAt') === 'string'
    ? isoTimestamp(own(record, 'startedAt'))
    : null;
  const observedAt = typeof own(record, 'observedAt') === 'string'
    ? isoTimestamp(own(record, 'observedAt'))
    : null;
  const rawEndedAt = own(record, 'endedAt');
  const endedAt = rawEndedAt === null || rawEndedAt === undefined
    ? null
    : typeof rawEndedAt === 'string'
      ? isoTimestamp(rawEndedAt)
      : null;
  if (!id || !startedAt || !observedAt || rawEndedAt !== null && rawEndedAt !== undefined && !endedAt) return null;

  const startedMs = new Date(startedAt).getTime();
  const observedMs = new Date(observedAt).getTime();
  const endedMs = endedAt ? new Date(endedAt).getTime() : null;
  if (
    startedMs > observedMs
    || observedMs < cutoff
    || observedMs > nowMs + 60_000
    || endedMs !== null && (endedMs < startedMs || endedMs > observedMs)
  ) return null;

  const phase = own(record, 'phase');
  if (phase !== 'active' && phase !== 'follow-up' && phase !== 'recovered') return null;
  if (phase === 'recovered' ? endedAt === null || endedMs !== observedMs : endedAt !== null) return null;

  const rawReasons = own(record, 'reasons');
  if (!Array.isArray(rawReasons)) return null;
  if (rawReasons.length === 0 || rawReasons.length > MAX_INCIDENT_REASONS) return null;
  const reasonSet = new Set<IncidentReason>();
  for (const reason of rawReasons) {
    if (typeof reason !== 'string' || !INCIDENT_REASONS.has(reason as IncidentReason)) return null;
    if (reasonSet.has(reason as IncidentReason)) return null;
    reasonSet.add(reason as IncidentReason);
  }
  const reasons = INCIDENT_REASON_ORDER.filter((reason) => reasonSet.has(reason));

  const rawMetrics = own(record, 'metrics');
  const rawPressure = own(record, 'pressure');
  const rawProcesses = own(record, 'processes');
  const rawContainers = own(record, 'containers');
  const rawTraffic = own(record, 'traffic');
  if (!isRecord(rawMetrics) || !isRecord(rawPressure) || !Array.isArray(rawContainers)) return null;
  const metrics = normalizeIncidentMetrics(rawMetrics, observedAt);
  const cpuPressure = normalizePressureWindow(own(rawPressure, 'cpu'));
  const memoryPressure = normalizePressureWindow(own(rawPressure, 'memory'));
  const ioPressure = normalizePressureWindow(own(rawPressure, 'io'));
  const processes = normalizeIncidentProcesses(rawProcesses);
  const containers = normalizeIncidentContainers(rawContainers);
  const traffic = normalizeIncidentTraffic(rawTraffic);
  if (!metrics || !cpuPressure || !memoryPressure || !ioPressure || !processes || !containers || !traffic) return null;

  const rawPeaks = own(record, 'peaks');
  const peaks = rawPeaks === null || rawPeaks === undefined
    ? null
    : isRecord(rawPeaks)
      ? {
          cpuPercent: percent(own(rawPeaks, 'cpuPercent')),
          memoryPercent: percent(own(rawPeaks, 'memoryPercent')),
          temperatureC: finite(own(rawPeaks, 'temperatureC'), -100, 250),
          load1: finite(own(rawPeaks, 'load1')),
        }
      : null;
  if (rawPeaks !== null && rawPeaks !== undefined && !isRecord(rawPeaks)) return null;

  const rawDurationSeconds = own(record, 'durationSeconds');
  const durationSeconds = rawDurationSeconds === null || rawDurationSeconds === undefined
    ? null
    : integer(rawDurationSeconds, 0, MAX_INCIDENT_DURATION_SECONDS);
  if (rawDurationSeconds !== null && rawDurationSeconds !== undefined && durationSeconds === null) return null;
  if (phase === 'recovered' ? durationSeconds === null : durationSeconds !== null) return null;

  return {
    id,
    startedAt,
    observedAt,
    endedAt,
    phase,
    reasons,
    metrics,
    pressure: {
      cpu: cpuPressure,
      memory: memoryPressure,
      io: ioPressure,
    },
    processes,
    containers,
    traffic,
    peaks,
    durationSeconds,
  };
}

function normalizeIncidents(
  records: JsonRecord[],
  cutoff: number,
  nowMs: number,
): DashboardResponse['incidents'] {
  return records
    .map((record) => normalizeIncident(record, cutoff, nowMs))
    .filter((incident): incident is DashboardResponse['incidents'][number] => incident !== null)
    .sort((left, right) => right.observedAt.localeCompare(left.observedAt))
    .slice(0, MAX_INCIDENTS);
}

export function readDashboard(
  dataDirectory: string,
  range: DashboardRange,
  nowMs: number,
  staleAfterMs: number,
): DashboardResponse {
  const root = resolve(dataDirectory);
  const cutoff = nowMs - rangeDuration[range];
  const current = parseObjectFile(root, join(root, 'current.json'), MAX_CURRENT_BYTES);
  const history = dateNames(cutoff, nowMs).flatMap((date) => parseJsonLines(
    root,
    join(root, 'history', `${date}.jsonl`),
    MAX_HISTORY_FILE_BYTES,
  ));
  const samples = history
    .map(normalizeSample)
    .filter((sample): sample is TelemetrySample => sample !== null)
    .filter((sample) => {
      const time = new Date(sample.timestamp).getTime();
      return time >= cutoff && time <= nowMs + 60_000;
    });
  const currentPayload = recordAt(current ?? undefined, 'latest') ?? current;
  const currentSampleCandidate = normalizeSample(currentPayload);
  const currentSample = currentSampleCandidate
    && new Date(currentSampleCandidate.timestamp).getTime() <= nowMs + 60_000
    ? currentSampleCandidate
    : null;
  if (
    currentSample
    && new Date(currentSample.timestamp).getTime() >= cutoff
  ) {
    const matchingHistoryIndex = samples.findIndex((sample) => sample.timestamp === currentSample.timestamp);
    if (matchingHistoryIndex === -1) {
      samples.push(currentSample);
    } else {
      samples[matchingHistoryIndex] = mergeSamples(samples[matchingHistoryIndex]!, currentSample);
    }
  }
  samples.sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  const observedLatest = currentSample ?? samples.at(-1) ?? null;
  const latestTime = observedLatest ? new Date(observedLatest.timestamp).getTime() : Number.NaN;
  const latest = observedLatest ?? emptySample(new Date(nowMs).toISOString());
  const containerTelemetry = normalizeContainerTelemetry(current, nowMs, staleAfterMs);
  const alerts = parseJsonLines(root, join(root, 'alerts.jsonl'), MAX_EVENT_FILE_BYTES);
  const ruleEvaluation = readRuleEvaluation(root, nowMs, staleAfterMs);
  const ruleAlerts = readRuleAlerts(root, cutoff, nowMs);
  const power = parseJsonLines(root, join(root, 'power.jsonl'), MAX_EVENT_FILE_BYTES);
  const reliability = parseJsonLines(root, join(root, 'reliability.jsonl'), MAX_EVENT_FILE_BYTES);
  const privilege = parseJsonLines(root, join(root, 'privilege.jsonl'), MAX_EVENT_FILE_BYTES);
  const incidents = parseJsonLines(root, join(root, 'incidents.jsonl'), MAX_INCIDENT_FILE_BYTES);

  return {
    generatedAt: new Date(nowMs).toISOString(),
    range,
    stale: !Number.isFinite(latestTime) || nowMs - latestTime > staleAfterMs,
    latestObservedAt: observedLatest?.timestamp ?? null,
    agent: normalizeAgent(current, nowMs, staleAfterMs),
    host: normalizeHost(current),
    reliability: normalizeReliability(current),
    system: normalizeSystem(current, nowMs),
    latest,
    series: downsampleTelemetry(samples, MAX_SERIES_POINTS),
    telemetrySummary: summarizeTelemetry(samples),
    powerSummary: summarizePower(samples),
    disks: normalizeDisks(current),
    containerCollection: containerTelemetry.containerCollection,
    containers: containerTelemetry.containers,
    currentTraffic: normalizeCurrentTraffic(current),
    alerts: normalizeAlerts(alerts, cutoff, nowMs),
    ruleEvaluation,
    ruleAlerts,
    powerEvents: normalizePowerEvents(power, alerts, samples, cutoff, nowMs),
    reliabilityEvents: normalizeReliabilityEvents(reliability, power, cutoff, nowMs),
    privilegeEvents: normalizePrivilege(privilege, cutoff, nowMs),
    incidents: normalizeIncidents(incidents, cutoff, nowMs),
  };
}

export const dataLimits = {
  maximumSeriesPoints: MAX_SERIES_POINTS,
  maximumEvents: MAX_EVENTS,
  maximumRuleStates: MAX_RULE_STATES,
  maximumRuleAlerts: MAX_RULE_ALERTS,
  maximumRuleEvaluationBytes: MAX_RULE_EVALUATION_BYTES,
  maximumRuleAlertFileBytes: MAX_RULE_ALERT_FILE_BYTES,
  maximumIncidents: MAX_INCIDENTS,
  maximumIncidentFileBytes: MAX_INCIDENT_FILE_BYTES,
  acceptedHistoryFilePattern: /^\d{4}-\d{2}-\d{2}\.jsonl$/,
  fixedFiles: [
    'current.json',
    'alerts.jsonl',
    'rule-evaluation.json',
    'rule-alerts.jsonl',
    'power.jsonl',
    'reliability.jsonl',
    'privilege.jsonl',
    'incidents.jsonl',
  ].map((path) => basename(path)),
} as const;
