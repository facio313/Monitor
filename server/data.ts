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
const MAX_SYNTHETIC_PROBES = 32;
const MAX_POWER_CORRELATION_MS = 2 * 60 * 1_000;
const MAX_UINT32 = 0xffff_ffff;
const MAX_INCIDENT_DURATION_SECONDS = 366 * 24 * 60 * 60;
const MAX_RESPONSE_TIME_MS = 300_000;
const MAX_INCIDENT_COUNT = 1_000_000_000;
const MAX_RELIABILITY_DURATION_SECONDS = 366 * 24 * 60 * 60;
const MAX_CONTAINER_CPU_PERCENT = 1024;
const MAX_TELEMETRY_RATE = 1_000_000_000_000;
const MAX_LINUX_COUNTER = Number.MAX_SAFE_INTEGER;
// Legacy Linux v1 producers allowed signed 64-bit counters.  Their upper
// bound rounds to 2^63 when JSON is parsed as a JavaScript number.
const MAX_LINUX_V1_RAW_COUNTER = 2 ** 63;
const MAX_LINUX_RATE = 1_000_000_000_000_000;
const MAX_LINUX_REDUCED_DEVICES = 16;
const MAX_LINUX_REDUCED_THERMAL_ITEMS = 8;
const LINUX_RAW_STATUSES = new Set([
  'supported', 'partial', 'unsupported', 'permission_error', 'unavailable',
  'invalid', 'too_large', 'timeout',
]);
const LINUX_RATE_STATUSES = new Set([
  'ok', 'warmup', 'counter_reset', ...LINUX_RAW_STATUSES,
]);
const LINUX_CPU_MODES = [
  'user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal',
] as const;
const LINUX_DISK_COUNTER_FIELDS = [
  'reads', 'readsMerged', 'sectorsRead', 'readMilliseconds',
  'writes', 'writesMerged', 'sectorsWritten', 'writeMilliseconds',
  'inFlight', 'ioMilliseconds', 'weightedIoMilliseconds',
  'discards', 'discardsMerged', 'sectorsDiscarded', 'discardMilliseconds',
  'flushes', 'flushMilliseconds',
] as const;
const LINUX_NETWORK_COUNTER_FIELDS = [
  'rxBytes', 'rxPackets', 'rxErrors', 'rxDropped', 'rxFifo',
  'rxFrame', 'rxCompressed', 'rxMulticast', 'txBytes', 'txPackets',
  'txErrors', 'txDropped', 'txFifo', 'txCollisions', 'txCarrier',
  'txCompressed',
] as const;
const LINUX_TCP_STATE_FIELDS = [
  'established', 'synSent', 'synRecv', 'finWait1', 'finWait2', 'timeWait',
  'close', 'closeWait', 'lastAck', 'listen', 'closing', 'newSynRecv',
] as const;
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

function exactKnownKeys(
  record: JsonRecord,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.prototype.hasOwnProperty.call(record, key))
    && Object.keys(record).every((key) => allowed.has(key));
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
const CONTAINER_V3_ONLY_FIELDS = [
  'instanceId', 'pidCount', 'cpuThrottledPercent', 'cpuThrottledPeriods',
  'cpuThrottledSeconds', 'blockReadBytes', 'blockWriteBytes',
  'blockReadBytesPerSecond', 'blockWriteBytesPerSecond', 'networkRxBytes',
  'networkTxBytes', 'networkRxBytesPerSecond', 'networkTxBytesPerSecond',
  'networkErrors', 'networkErrorsPerSecond', 'writableLayerBytes', 'volumeCount',
  'bindMountCount', 'tmpfsMountCount', 'networkAttachmentCount', 'publishedPortCount',
  'privileged', 'hostPid', 'hostIpc', 'hostNetwork', 'dockerSocketMounted',
  'sensitiveBindMounted', 'rootUser', 'readOnlyRootFilesystem', 'addedCapabilityCount',
  'dangerousCapabilityCount', 'excessiveCapabilities', 'imageName', 'imageTag',
  'imageDigest', 'imageDigestSource', 'usesLatestTag', 'imageDigestDrift',
  'imageDigestChanged',
] as const;
const CONTAINER_V3_FIELDS = [...CONTAINER_V2_FIELDS, ...CONTAINER_V3_ONLY_FIELDS] as const;
type ContainerRow = DashboardResponse['containers'][number];
type ContainerV3Extras = Pick<ContainerRow, (typeof CONTAINER_V3_ONLY_FIELDS)[number]>;
const EMPTY_CONTAINER_V3_EXTRAS: ContainerV3Extras = {};

function nullableContainerInteger(record: JsonRecord, field: string, maximum: number): number | null | undefined {
  const value = own(record, field);
  if (value === null) return null;
  return integer(value, 0, maximum) ?? undefined;
}

function nullableContainerNumber(record: JsonRecord, field: string, maximum: number): number | null | undefined {
  const value = own(record, field);
  if (value === null) return null;
  return finite(value, 0, maximum) ?? undefined;
}

function nullableContainerBoolean(record: JsonRecord, field: string): boolean | null | undefined {
  const value = own(record, field);
  return value === null ? null : typeof value === 'boolean' ? value : undefined;
}

function normalizeContainerV3Extras(record: JsonRecord): ContainerV3Extras | null {
  const instanceId = own(record, 'instanceId');
  if (typeof instanceId !== 'string' || !/^[a-f0-9]{32}$/.test(instanceId)) return null;
  const integers = {
    pidCount: nullableContainerInteger(record, 'pidCount', Number.MAX_SAFE_INTEGER),
    cpuThrottledPeriods: nullableContainerInteger(record, 'cpuThrottledPeriods', Number.MAX_SAFE_INTEGER),
    blockReadBytes: nullableContainerInteger(record, 'blockReadBytes', Number.MAX_SAFE_INTEGER),
    blockWriteBytes: nullableContainerInteger(record, 'blockWriteBytes', Number.MAX_SAFE_INTEGER),
    networkRxBytes: nullableContainerInteger(record, 'networkRxBytes', Number.MAX_SAFE_INTEGER),
    networkTxBytes: nullableContainerInteger(record, 'networkTxBytes', Number.MAX_SAFE_INTEGER),
    networkErrors: nullableContainerInteger(record, 'networkErrors', Number.MAX_SAFE_INTEGER),
    writableLayerBytes: nullableContainerInteger(record, 'writableLayerBytes', Number.MAX_SAFE_INTEGER),
    volumeCount: nullableContainerInteger(record, 'volumeCount', 4096),
    bindMountCount: nullableContainerInteger(record, 'bindMountCount', 4096),
    tmpfsMountCount: nullableContainerInteger(record, 'tmpfsMountCount', 4096),
    networkAttachmentCount: nullableContainerInteger(record, 'networkAttachmentCount', 4096),
    publishedPortCount: nullableContainerInteger(record, 'publishedPortCount', 65_536),
    addedCapabilityCount: nullableContainerInteger(record, 'addedCapabilityCount', 64),
    dangerousCapabilityCount: nullableContainerInteger(record, 'dangerousCapabilityCount', 64),
  };
  const numbers = {
    cpuThrottledPercent: nullableContainerNumber(record, 'cpuThrottledPercent', 100),
    cpuThrottledSeconds: nullableContainerNumber(record, 'cpuThrottledSeconds', Number.MAX_SAFE_INTEGER),
    blockReadBytesPerSecond: nullableContainerNumber(record, 'blockReadBytesPerSecond', 1e15),
    blockWriteBytesPerSecond: nullableContainerNumber(record, 'blockWriteBytesPerSecond', 1e15),
    networkRxBytesPerSecond: nullableContainerNumber(record, 'networkRxBytesPerSecond', 1e15),
    networkTxBytesPerSecond: nullableContainerNumber(record, 'networkTxBytesPerSecond', 1e15),
    networkErrorsPerSecond: nullableContainerNumber(record, 'networkErrorsPerSecond', 1e15),
  };
  const booleans = {
    privileged: nullableContainerBoolean(record, 'privileged'),
    hostPid: nullableContainerBoolean(record, 'hostPid'),
    hostIpc: nullableContainerBoolean(record, 'hostIpc'),
    hostNetwork: nullableContainerBoolean(record, 'hostNetwork'),
    dockerSocketMounted: nullableContainerBoolean(record, 'dockerSocketMounted'),
    sensitiveBindMounted: nullableContainerBoolean(record, 'sensitiveBindMounted'),
    rootUser: nullableContainerBoolean(record, 'rootUser'),
    readOnlyRootFilesystem: nullableContainerBoolean(record, 'readOnlyRootFilesystem'),
    excessiveCapabilities: nullableContainerBoolean(record, 'excessiveCapabilities'),
    usesLatestTag: nullableContainerBoolean(record, 'usesLatestTag'),
    imageDigestDrift: nullableContainerBoolean(record, 'imageDigestDrift'),
    imageDigestChanged: nullableContainerBoolean(record, 'imageDigestChanged'),
  };
  if (
    Object.values(integers).some((value) => value === undefined)
    || Object.values(numbers).some((value) => value === undefined)
    || Object.values(booleans).some((value) => value === undefined)
  ) return null;
  const imageName = own(record, 'imageName');
  const imageTag = own(record, 'imageTag');
  const imageDigest = own(record, 'imageDigest');
  const imageDigestSource = own(record, 'imageDigestSource');
  if (
    (imageName !== null && (typeof imageName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$/.test(imageName) || imageName.startsWith('/') || imageName.endsWith('/') || imageName.includes('//')))
    || (imageTag !== null && (typeof imageTag !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(imageTag)))
    || (imageDigest !== null && (typeof imageDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(imageDigest)))
    || ![null, 'repo-digest', 'local-image-id'].includes(imageDigestSource as null | string)
    || ((imageDigest === null) !== (imageDigestSource === null))
    || (imageName === null && imageTag !== null)
    || (imageName === null && booleans.usesLatestTag !== null)
    || (imageName !== null && booleans.usesLatestTag !== (imageTag === 'latest'))
    || (imageDigestSource === 'repo-digest' && imageName === null)
    || (imageDigest === null && (booleans.imageDigestDrift !== null || booleans.imageDigestChanged !== null))
    || (imageDigest !== null && booleans.imageDigestDrift === null)
    || (numbers.blockReadBytesPerSecond !== null && integers.blockReadBytes === null)
    || (numbers.blockWriteBytesPerSecond !== null && integers.blockWriteBytes === null)
    || (numbers.networkRxBytesPerSecond !== null && integers.networkRxBytes === null)
    || (numbers.networkTxBytesPerSecond !== null && integers.networkTxBytes === null)
    || (numbers.networkErrorsPerSecond !== null && integers.networkErrors === null)
    || (numbers.cpuThrottledPercent !== null && integers.cpuThrottledPeriods === null)
    || (
      [integers.addedCapabilityCount, integers.dangerousCapabilityCount, booleans.excessiveCapabilities]
        .some((value) => value === null)
      && ![integers.addedCapabilityCount, integers.dangerousCapabilityCount, booleans.excessiveCapabilities]
        .every((value) => value === null)
    )
    || (
      integers.addedCapabilityCount !== null
      && integers.dangerousCapabilityCount !== null
      && integers.dangerousCapabilityCount! > integers.addedCapabilityCount!
    )
    || (
      integers.addedCapabilityCount !== null
      && integers.dangerousCapabilityCount !== null
      && booleans.excessiveCapabilities !== (
        integers.addedCapabilityCount! > 12 || integers.dangerousCapabilityCount! > 0
      )
    )
  ) return null;
  return {
    instanceId,
    ...integers,
    ...numbers,
    ...booleans,
    imageName: imageName as string | null,
    imageTag: imageTag as string | null,
    imageDigest: imageDigest as string | null,
    imageDigestSource: imageDigestSource as ContainerRow['imageDigestSource'],
  } as ContainerV3Extras;
}

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
    const v3 = CONTAINER_V3_ONLY_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(value, field));
    const v2 = !v3 && CONTAINER_V2_ONLY_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(value, field));
    const modern = v2 || v3;
    if (
      (v3 && !exactKeys(value, CONTAINER_V3_FIELDS))
      || (v2 && !exactKeys(value, CONTAINER_V2_FIELDS))
    ) {
      return [];
    }
    const rawName = cleanText(own(value, 'name'), 128)?.toLowerCase() ?? null;
    const name = safeContainerName(first(value, ['name']));
    const expectedProject = rawName === null ? undefined : CURRENT_CONTAINER_PROJECTS[rawName];
    const project = modern ? own(value, 'project') : null;
    const migratedV2 = modern
      && project === null
      && own(value, 'health') === null
      && CONTAINER_V2_ONLY_FIELDS
        .filter((field) => field !== 'project')
        .every((field) => own(value, field) === null);
    if (
      (!modern && !allowMigratedLegacy)
      || (modern && (
        name !== rawName
        || expectedProject === undefined
        || (project !== expectedProject && !(allowMigratedLegacy && migratedV2))
      ))
    ) {
      return [];
    }
    const rawHealth = own(value, 'health');
    const rawState = own(value, 'state');
    const health = !modern || rawHealth === null
      ? null
      : safeContainerHealth(first(value, ['health', 'healthStatus']));
    const healthcheckConfigured = modern ? own(value, 'healthcheckConfigured') : null;
    const oomKilled = modern ? own(value, 'oomKilled') : null;
    const memoryBytes = modern
      ? (own(value, 'memoryBytes') === null ? null : integer(own(value, 'memoryBytes')))
      : finite(first(value, ['memoryBytes', 'memoryUsageBytes']));
    const memoryLimitBytes = modern
      ? (own(value, 'memoryLimitBytes') === null ? null : integer(own(value, 'memoryLimitBytes')))
      : null;
    const cpuLimitCores = modern
      ? (own(value, 'cpuLimitCores') === null ? null : finite(own(value, 'cpuLimitCores'), 0, 1024))
      : null;
    const pidLimit = modern
      ? (own(value, 'pidLimit') === null ? null : integer(own(value, 'pidLimit')))
      : null;
    const restartCount = modern
      ? (own(value, 'restartCount') === null ? null : integer(own(value, 'restartCount')))
      : null;
    const restartCountDelta = modern
      ? (own(value, 'restartCountDelta') === null ? null : integer(own(value, 'restartCountDelta')))
      : null;
    const startedAt = modern ? containerLifecycleTimestamp(own(value, 'startedAt'), nowMs) : null;
    const finishedAt = modern ? containerLifecycleTimestamp(own(value, 'finishedAt'), nowMs) : null;
    const cpuPercent = containerCpuPercent(first(value, ['cpuPercent', 'cpu']));
    const memoryPercent = percent(first(value, ['memoryPercent']));
    if (modern && (
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
    const v3Extras = v3 ? normalizeContainerV3Extras(value) : EMPTY_CONTAINER_V3_EXTRAS;
    if (v3Extras === null) return [];
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
      ...v3Extras,
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

const DOCKER_EVENT_STATUSES = new Set<DashboardResponse['dockerEventCollection']['status']>([
  'fresh', 'gap', 'unavailable', 'permission-denied',
]);
const DOCKER_EVENT_ACTIONS = new Set<DashboardResponse['dockerEvents'][number]['action']>([
  'create', 'start', 'stop', 'die', 'kill', 'pause', 'unpause', 'restart', 'oom',
  'health_status', 'destroy',
]);
const DOCKER_EVENT_COLLECTION_FIELDS = [
  'status', 'observedAt', 'cursorAt', 'reconnectCount', 'gapCount', 'gapDetected',
  'logCollectionStatus',
] as const;
const DOCKER_EVENT_FIELDS = [
  'id', 'occurredAt', 'action', 'containerName', 'project', 'instanceId', 'exitCode',
  'healthStatus',
] as const;

function unavailableDockerEvents(): Pick<DashboardResponse, 'dockerEventCollection' | 'dockerEvents'> {
  return {
    dockerEventCollection: {
      status: 'unavailable',
      observedAt: null,
      cursorAt: null,
      reconnectCount: 0,
      gapCount: 0,
      gapDetected: true,
      logCollectionStatus: 'unsupported',
    },
    dockerEvents: [],
  };
}

function normalizeDockerEventTelemetry(
  current: JsonRecord | null,
  nowMs: number,
  staleAfterMs: number,
  cutoff: number,
): Pick<DashboardResponse, 'dockerEventCollection' | 'dockerEvents'> {
  if (!current) return unavailableDockerEvents();
  const rawCollection = own(current, 'dockerEventCollection');
  const rawEvents = own(current, 'dockerEvents');
  if (!isRecord(rawCollection) || !Array.isArray(rawEvents) || rawEvents.length > 128) {
    return unavailableDockerEvents();
  }
  if (!exactKeys(rawCollection, DOCKER_EVENT_COLLECTION_FIELDS)) return unavailableDockerEvents();
  const rawStatus = own(rawCollection, 'status');
  const rawObservedAt = own(rawCollection, 'observedAt');
  const rawCursorAt = own(rawCollection, 'cursorAt');
  const observedAt = rawObservedAt === null ? null : isoTimestamp(rawObservedAt);
  const cursorAt = rawCursorAt === null ? null : isoTimestamp(rawCursorAt);
  const reconnectCount = integer(own(rawCollection, 'reconnectCount'), 0, Number.MAX_SAFE_INTEGER);
  const gapCount = integer(own(rawCollection, 'gapCount'), 0, Number.MAX_SAFE_INTEGER);
  const gapDetected = own(rawCollection, 'gapDetected');
  if (
    typeof rawStatus !== 'string'
    || !DOCKER_EVENT_STATUSES.has(rawStatus as DashboardResponse['dockerEventCollection']['status'])
    || (rawObservedAt !== null && observedAt === null)
    || (rawCursorAt !== null && cursorAt === null)
    || reconnectCount === null
    || gapCount === null
    || typeof gapDetected !== 'boolean'
    || own(rawCollection, 'logCollectionStatus') !== 'unsupported'
    || ((observedAt === null) !== (cursorAt === null))
    || (observedAt !== null && new Date(observedAt).getTime() > nowMs + 60_000)
    || (cursorAt !== null && new Date(cursorAt).getTime() > nowMs + 60_000)
    || (rawStatus === 'fresh' && gapDetected)
    || (rawStatus === 'gap' && !gapDetected)
    || (['fresh', 'gap'].includes(rawStatus) && (observedAt === null || cursorAt === null))
  ) return unavailableDockerEvents();

  let status = rawStatus as DashboardResponse['dockerEventCollection']['status'];
  let effectiveGap = gapDetected;
  if (
    (status === 'fresh' || status === 'gap')
    && observedAt !== null
    && nowMs - new Date(observedAt).getTime() > staleAfterMs
  ) {
    status = 'unavailable';
    effectiveGap = true;
  }
  const events: DashboardResponse['dockerEvents'] = [];
  const seen = new Set<string>();
  for (const candidate of rawEvents) {
    if (!isRecord(candidate) || !exactKeys(candidate, DOCKER_EVENT_FIELDS)) return unavailableDockerEvents();
    const id = own(candidate, 'id');
    const occurredAt = isoTimestamp(own(candidate, 'occurredAt'));
    const action = own(candidate, 'action');
    const containerName = own(candidate, 'containerName');
    const project = own(candidate, 'project');
    const instanceId = own(candidate, 'instanceId');
    const rawExitCode = own(candidate, 'exitCode');
    const exitCode = rawExitCode === null ? null : integer(rawExitCode, 0, 2_147_483_647);
    const healthStatus = own(candidate, 'healthStatus');
    if (
      typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id) || seen.has(id)
      || occurredAt === null || new Date(occurredAt).getTime() > nowMs + 60_000
      || typeof action !== 'string'
      || !DOCKER_EVENT_ACTIONS.has(action as DashboardResponse['dockerEvents'][number]['action'])
      || typeof containerName !== 'string' || safeContainerName(containerName) !== containerName
      || typeof project !== 'string' || CURRENT_CONTAINER_PROJECTS[containerName] !== project
      || typeof instanceId !== 'string' || !/^[a-f0-9]{32}$/.test(instanceId)
      || (rawExitCode !== null && exitCode === null)
      || ![null, 'healthy', 'unhealthy', 'starting'].includes(healthStatus as null | string)
      || ((action === 'health_status') !== (healthStatus !== null))
    ) return unavailableDockerEvents();
    seen.add(id);
    if (new Date(occurredAt).getTime() >= cutoff) {
      events.push({
        id,
        occurredAt,
        action: action as DashboardResponse['dockerEvents'][number]['action'],
        containerName,
        project,
        instanceId,
        exitCode,
        healthStatus: healthStatus as DashboardResponse['dockerEvents'][number]['healthStatus'],
      });
    }
  }
  events.sort((left, right) => left.occurredAt.localeCompare(right.occurredAt) || left.id.localeCompare(right.id));
  return {
    dockerEventCollection: {
      status,
      observedAt,
      cursorAt,
      reconnectCount,
      gapCount,
      gapDetected: effectiveGap,
      logCollectionStatus: 'unsupported',
    },
    dockerEvents: events,
  };
}

const SYNTHETIC_COLLECTION_STATUSES = new Set<DashboardResponse['syntheticProbeCollection']['status']>([
  'fresh', 'stale', 'unsupported', 'permission-denied', 'unavailable', 'collection-error',
]);
const SYNTHETIC_PROBE_STATUSES = new Set<DashboardResponse['syntheticProbes'][number]['status']>([
  'ok', 'dns', 'permission', 'timeout', 'tls', 'http', 'invalid', 'unsupported',
]);
const SYNTHETIC_COLLECTION_FIELDS = ['status', 'observedAt'] as const;
const SYNTHETIC_PROBE_FIELDS = [
  'id', 'status', 'checkedAt', 'httpStatus', 'redirectCount',
  'latencyMilliseconds', 'certificateExpiresAt', 'certificateDaysRemaining',
] as const;

function syntheticFallback(
  status: DashboardResponse['syntheticProbeCollection']['status'],
): Pick<DashboardResponse, 'syntheticProbeCollection' | 'syntheticProbes'> {
  return { syntheticProbeCollection: { status, observedAt: null }, syntheticProbes: [] };
}

function normalizeSyntheticProbeTelemetry(
  current: JsonRecord | null,
  nowMs: number,
  staleAfterMs: number,
): Pick<DashboardResponse, 'syntheticProbeCollection' | 'syntheticProbes'> {
  if (!current) return syntheticFallback('unsupported');
  const rawCollection = own(current, 'syntheticProbeCollection');
  const rawProbes = own(current, 'syntheticProbes');
  if (rawCollection === undefined && rawProbes === undefined) return syntheticFallback('unsupported');
  if (
    !isRecord(rawCollection)
    || !exactKeys(rawCollection, SYNTHETIC_COLLECTION_FIELDS)
    || !Array.isArray(rawProbes)
    || rawProbes.length > MAX_SYNTHETIC_PROBES
  ) return syntheticFallback('collection-error');
  const rawStatus = own(rawCollection, 'status');
  const rawObservedAt = own(rawCollection, 'observedAt');
  const observedAt = rawObservedAt === null ? null : contractTimestamp(rawObservedAt, nowMs);
  if (
    typeof rawStatus !== 'string'
    || !SYNTHETIC_COLLECTION_STATUSES.has(rawStatus as DashboardResponse['syntheticProbeCollection']['status'])
    || (rawObservedAt !== null && observedAt === null)
    || ((rawStatus === 'fresh' || rawStatus === 'stale') !== (observedAt !== null))
    || (!(rawStatus === 'fresh' || rawStatus === 'stale') && rawProbes.length !== 0)
    || (rawStatus === 'fresh' && rawProbes.length === 0)
  ) return syntheticFallback('collection-error');

  let status = rawStatus as DashboardResponse['syntheticProbeCollection']['status'];
  if (
    status === 'fresh'
    && observedAt !== null
    && nowMs - new Date(observedAt).getTime() > staleAfterMs
  ) status = 'stale';

  const probes: DashboardResponse['syntheticProbes'] = [];
  const identifiers = new Set<string>();
  for (const candidate of rawProbes) {
    if (!isRecord(candidate) || !exactKeys(candidate, SYNTHETIC_PROBE_FIELDS)) {
      return syntheticFallback('collection-error');
    }
    const id = own(candidate, 'id');
    const probeStatus = own(candidate, 'status');
    const checkedAt = contractTimestamp(own(candidate, 'checkedAt'), nowMs);
    const rawHttpStatus = own(candidate, 'httpStatus');
    const httpStatus = rawHttpStatus === null ? null : integer(rawHttpStatus, 100, 599);
    const redirectCount = integer(own(candidate, 'redirectCount'), 0, 5);
    const latencyMilliseconds = integer(own(candidate, 'latencyMilliseconds'), 0, 60_000);
    const rawCertificateExpiresAt = own(candidate, 'certificateExpiresAt');
    const certificateExpiresAt = rawCertificateExpiresAt === null
      ? null
      : contractTimestamp(rawCertificateExpiresAt, nowMs + 36600 * 86400 * 1000);
    const rawDaysRemaining = own(candidate, 'certificateDaysRemaining');
    const certificateDaysRemaining = rawDaysRemaining === null
      ? null
      : integer(rawDaysRemaining, -36_600, 36_600);
    if (
      typeof id !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(id)
      || identifiers.has(id)
      || typeof probeStatus !== 'string'
      || !SYNTHETIC_PROBE_STATUSES.has(probeStatus as DashboardResponse['syntheticProbes'][number]['status'])
      || checkedAt === null
      || (observedAt !== null && new Date(checkedAt).getTime() > new Date(observedAt).getTime() + 60_000)
      || (rawHttpStatus !== null && httpStatus === null)
      || redirectCount === null
      || latencyMilliseconds === null
      || (rawCertificateExpiresAt !== null && certificateExpiresAt === null)
      || (rawDaysRemaining !== null && certificateDaysRemaining === null)
      || ((certificateExpiresAt === null) !== (certificateDaysRemaining === null))
      || (probeStatus === 'ok' && httpStatus === null)
    ) return syntheticFallback('collection-error');
    identifiers.add(id);
    probes.push({
      id,
      status: probeStatus as DashboardResponse['syntheticProbes'][number]['status'],
      checkedAt,
      httpStatus,
      redirectCount,
      latencyMilliseconds,
      certificateExpiresAt,
      certificateDaysRemaining,
    });
  }
  probes.sort((left, right) => left.id.localeCompare(right.id));
  return { syntheticProbeCollection: { status, observedAt }, syntheticProbes: probes };
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
  'conditionStartedAt',
  'recoveryStartedAt',
  'missingStartedAt',
  'evaluationIntervalSeconds',
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
  const conditionStartedAtValue = own(value, 'conditionStartedAt');
  const conditionStartedAt = conditionStartedAtValue === null
    ? null
    : contractTimestamp(conditionStartedAtValue, nowMs);
  const recoveryStartedAtValue = own(value, 'recoveryStartedAt');
  const recoveryStartedAt = recoveryStartedAtValue === null
    ? null
    : contractTimestamp(recoveryStartedAtValue, nowMs);
  const missingStartedAtValue = own(value, 'missingStartedAt');
  const missingStartedAt = missingStartedAtValue === null
    ? null
    : contractTimestamp(missingStartedAtValue, nowMs);
  const evaluationIntervalSeconds = integer(own(value, 'evaluationIntervalSeconds'), 1, 86_400);
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
    || (conditionStartedAtValue !== null && conditionStartedAt === null)
    || (recoveryStartedAtValue !== null && recoveryStartedAt === null)
    || (missingStartedAtValue !== null && missingStartedAt === null)
    || evaluationIntervalSeconds === null
    || changedAt === null
    || lastEvaluatedAt !== evaluatedAt
    || new Date(changedAt).getTime() > evaluatedMs
    || (openedAt !== null && new Date(openedAt).getTime() > evaluatedMs)
    || (conditionStartedAt !== null && new Date(conditionStartedAt).getTime() > evaluatedMs)
    || (recoveryStartedAt !== null && new Date(recoveryStartedAt).getTime() > evaluatedMs)
    || (missingStartedAt !== null && new Date(missingStartedAt).getTime() > evaluatedMs)
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
    conditionStartedAt,
    recoveryStartedAt,
    missingStartedAt,
    evaluationIntervalSeconds,
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

function linuxRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): JsonRecord | null {
  return isRecord(value) && exactKnownKeys(value, required, optional) ? value : null;
}

function linuxArray(
  value: unknown,
  maximum: number,
  validate: (entry: unknown) => boolean,
): value is unknown[] {
  return Array.isArray(value) && value.length <= maximum && value.every(validate);
}

function linuxNullableNumber(
  value: unknown,
  minimum = 0,
  maximum = MAX_LINUX_RATE,
): boolean {
  return value === null || finite(value, minimum, maximum) !== null;
}

function linuxNullableInteger(
  value: unknown,
  minimum = 0,
  maximum = MAX_LINUX_COUNTER,
): boolean {
  return value === null || integer(value, minimum, maximum) !== null;
}

function linuxNullableV1RawCounter(value: unknown, minimum = 0): boolean {
  return value === null || (
    typeof value === 'number'
    && Number.isFinite(value)
    && Number.isInteger(value)
    && value >= minimum
    && value <= MAX_LINUX_V1_RAW_COUNTER
  );
}

function linuxBooleanOrNull(value: unknown): boolean {
  return value === null || typeof value === 'boolean';
}

function linuxLabel(value: unknown, maximum: number): boolean {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= maximum
    && /^[A-Za-z0-9_.:@/+ -]+$/.test(value);
}

function linuxPrintableText(value: unknown, maximum: number): boolean {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function linuxTimestamp(value: unknown, nowMs: number): string | null {
  if (
    typeof value !== 'string'
    || value.length > 40
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)
  ) {
    return null;
  }
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) && timestamp >= 0 && timestamp <= nowMs + 60_000
    ? new Date(timestamp).toISOString()
    : null;
}

function linuxRawStatus(value: unknown): boolean {
  return typeof value === 'string' && LINUX_RAW_STATUSES.has(value);
}

function linuxRateStatusIsValid(value: unknown): boolean {
  return typeof value === 'string' && LINUX_RATE_STATUSES.has(value);
}

function validateLinuxCpuSample(value: unknown): boolean {
  const percentageFields = [
    'busyPercent', 'userPercent', 'nicePercent', 'systemPercent', 'idlePercent',
    'iowaitPercent', 'irqPercent', 'softirqPercent', 'stealPercent',
  ] as const;
  const record = linuxRecord(value, ['rateStatus', ...percentageFields, 'countersJiffies']);
  const counters = record && linuxRecord(own(record, 'countersJiffies'), LINUX_CPU_MODES);
  return Boolean(
    record
    && linuxRateStatusIsValid(own(record, 'rateStatus'))
    && percentageFields.every((field) => linuxNullableNumber(own(record, field), 0, 100))
    && counters
    && LINUX_CPU_MODES.every((field) => integer(own(counters, field), 0, MAX_LINUX_COUNTER) !== null),
  );
}

function validateLinuxCpu(value: unknown): boolean {
  const record = linuxRecord(value, [
    'status', 'total', 'cores', 'coreCount', 'onlineCoreCount',
    'offlineCoreIds', 'truncated', 'load',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status'))) return false;
  const total = own(record, 'total');
  if (total !== null && !validateLinuxCpuSample(total)) return false;
  const cores = own(record, 'cores');
  if (!linuxArray(cores, 512, (entry) => {
    const core = linuxRecord(entry, [
      'id', 'online', 'rateStatus', 'busyPercent', 'userPercent', 'nicePercent',
      'systemPercent', 'idlePercent', 'iowaitPercent', 'irqPercent',
      'softirqPercent', 'stealPercent', 'countersJiffies', 'frequency', 'throttling',
    ]);
    if (!core || integer(own(core, 'id'), 0, 4095) === null || typeof own(core, 'online') !== 'boolean') return false;
    const sample = {
      rateStatus: own(core, 'rateStatus'),
      busyPercent: own(core, 'busyPercent'),
      userPercent: own(core, 'userPercent'),
      nicePercent: own(core, 'nicePercent'),
      systemPercent: own(core, 'systemPercent'),
      idlePercent: own(core, 'idlePercent'),
      iowaitPercent: own(core, 'iowaitPercent'),
      irqPercent: own(core, 'irqPercent'),
      softirqPercent: own(core, 'softirqPercent'),
      stealPercent: own(core, 'stealPercent'),
      countersJiffies: own(core, 'countersJiffies'),
    };
    const frequency = linuxRecord(own(core, 'frequency'), [
      'status', 'currentHz', 'minimumHz', 'maximumHz', 'governor',
    ]);
    const throttling = linuxRecord(own(core, 'throttling'), ['status', 'count']);
    return validateLinuxCpuSample(sample)
      && Boolean(frequency)
      && linuxRawStatus(own(frequency ?? undefined, 'status'))
      && ['currentHz', 'minimumHz', 'maximumHz'].every((field) => (
        linuxNullableInteger(own(frequency ?? undefined, field), 0, 100_000_000_000)
      ))
      && (own(frequency ?? undefined, 'governor') === null || linuxLabel(own(frequency ?? undefined, 'governor'), 32))
      && Boolean(throttling)
      && linuxRawStatus(own(throttling ?? undefined, 'status'))
      && linuxNullableInteger(own(throttling ?? undefined, 'count'));
  })) return false;
  const coreCount = integer(own(record, 'coreCount'), 0, 512);
  const onlineCoreCount = own(record, 'onlineCoreCount');
  if (coreCount === null || coreCount !== cores.length) return false;
  if (onlineCoreCount !== null && integer(onlineCoreCount, 0, coreCount) === null) return false;
  const offline = own(record, 'offlineCoreIds');
  if (!linuxArray(offline, 512, (entry) => integer(entry, 0, 4095) !== null)) return false;
  if (new Set(offline).size !== offline.length || typeof own(record, 'truncated') !== 'boolean') return false;
  const load = linuxRecord(own(record, 'load'), [
    'one', 'five', 'fifteen', 'onePerOnlineCpu', 'fivePerOnlineCpu', 'fifteenPerOnlineCpu',
  ]);
  return Boolean(load) && Object.keys(load ?? {}).every((field) => (
    linuxNullableNumber(own(load ?? undefined, field), 0, 1_000_000)
  ));
}

function validateLinuxPressureWindow(value: unknown): boolean {
  const record = linuxRecord(value, ['avg10', 'avg60', 'avg300', 'totalMicroseconds']);
  return Boolean(record)
    && ['avg10', 'avg60', 'avg300'].every((field) => linuxNullableNumber(own(record ?? undefined, field), 0, 100))
    && linuxNullableInteger(own(record ?? undefined, 'totalMicroseconds'));
}

function validateLinuxMemory(value: unknown): boolean {
  const byteFields = [
    'totalBytes', 'availableBytes', 'usedBytes', 'cachedBytes', 'buffersBytes',
    'slabBytes', 'slabReclaimableBytes', 'slabUnreclaimableBytes', 'dirtyBytes',
    'writebackBytes', 'swapTotalBytes', 'swapUsedBytes',
  ] as const;
  const rateFields = [
    'swapInPagesPerSecond', 'swapOutPagesPerSecond', 'swapInBytesPerSecond',
    'swapOutBytesPerSecond', 'pageFaultsPerSecond', 'majorPageFaultsPerSecond',
  ] as const;
  const record = linuxRecord(value, [
    'status', ...byteFields, 'usedPercent', 'swapUsedPercent', 'vmCounters',
    'rateStatus', ...rateFields, 'pressure', 'pressureStatus',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status')) || !linuxRawStatus(own(record, 'pressureStatus'))) return false;
  if (!byteFields.every((field) => linuxNullableInteger(own(record, field)))) return false;
  if (!linuxNullableNumber(own(record, 'usedPercent'), 0, 100)
    || !linuxNullableNumber(own(record, 'swapUsedPercent'), 0, 100)
    || !linuxRateStatusIsValid(own(record, 'rateStatus'))
    || !rateFields.every((field) => linuxNullableNumber(own(record, field)))) return false;
  const vmCounters = linuxRecord(own(record, 'vmCounters'), [], [
    'pswpin', 'pswpout', 'pgfault', 'pgmajfault', 'oom_kill',
  ]);
  if (!vmCounters || !Object.keys(vmCounters).every((field) => integer(own(vmCounters, field), 0, MAX_LINUX_COUNTER) !== null)) return false;
  const pressure = linuxRecord(own(record, 'pressure'), ['cpu', 'memory', 'io']);
  return Boolean(pressure) && ['cpu', 'memory', 'io'].every((kind) => {
    const item = linuxRecord(own(pressure ?? undefined, kind), ['status'], ['some', 'full']);
    return Boolean(item)
      && linuxRawStatus(own(item ?? undefined, 'status'))
      && ['some', 'full'].every((window) => (
        own(item ?? undefined, window) === undefined || validateLinuxPressureWindow(own(item ?? undefined, window))
      ));
  });
}

function validateLinuxFilesystems(value: unknown): boolean {
  const record = linuxRecord(value, ['status', 'truncated', 'items']);
  return Boolean(record)
    && linuxRawStatus(own(record ?? undefined, 'status'))
    && typeof own(record ?? undefined, 'truncated') === 'boolean'
    && linuxArray(own(record ?? undefined, 'items'), 256, (entry) => {
      const item = linuxRecord(entry, [
        'mount', 'filesystemType', 'readOnly', 'pseudo', 'remote',
        'readOnlyTransition', 'availability', 'mounted', 'dockerDataRootFilesystem',
        'totalBytes', 'usedBytes', 'availableBytes', 'usedPercent',
        'inodeTotal', 'inodeUsed', 'inodeAvailable', 'inodeUsedPercent',
      ]);
      const transition = own(item ?? undefined, 'readOnlyTransition');
      return Boolean(item)
        && linuxPrintableText(own(item ?? undefined, 'mount'), 512)
        && linuxLabel(own(item ?? undefined, 'filesystemType'), 64)
        && ['readOnly', 'pseudo', 'remote', 'mounted', 'dockerDataRootFilesystem'].every((field) => typeof own(item ?? undefined, field) === 'boolean')
        && (transition === null || transition === 'became_read_only' || transition === 'became_read_write')
        && linuxRawStatus(own(item ?? undefined, 'availability'))
        && ['totalBytes', 'usedBytes', 'availableBytes', 'inodeTotal', 'inodeUsed', 'inodeAvailable'].every((field) => linuxNullableInteger(own(item ?? undefined, field)))
        && ['usedPercent', 'inodeUsedPercent'].every((field) => linuxNullableNumber(own(item ?? undefined, field), 0, 100));
    });
}

function validateLinuxBlockDevices(value: unknown): boolean {
  const rateFields = [
    'readBytesPerSecond', 'writeBytesPerSecond', 'readIops', 'writeIops',
    'discardBytesPerSecond', 'discardIops', 'flushIops',
    'readLatencyMilliseconds', 'writeLatencyMilliseconds',
    'averageLatencyMilliseconds', 'averageQueueDepth',
  ] as const;
  const record = linuxRecord(value, ['status', 'truncated', 'items']);
  return Boolean(record)
    && linuxRawStatus(own(record ?? undefined, 'status'))
    && typeof own(record ?? undefined, 'truncated') === 'boolean'
    && linuxArray(own(record ?? undefined, 'items'), 128, (entry) => {
      const item = linuxRecord(entry, [
        'name', 'major', 'minor', 'counterIdentity', 'type', 'rotational',
        'queueDepth', 'rateStatus', 'counters', 'discardStatus', 'flushStatus',
        'discardRateStatus', 'flushRateStatus', ...rateFields, 'utilizationPercent',
        'ioErrorCounterStatus', 'ioErrorEvidenceSource', 'health',
      ]);
      const counters = item && linuxRecord(own(item, 'counters'), LINUX_DISK_COUNTER_FIELDS);
      const health = item && linuxRecord(own(item, 'health'), [
        'smartStatus', 'raidStatus', 'raidDegradedDevices', 'raidArrayState',
      ]);
      return Boolean(item)
        && /^[A-Za-z0-9_.-]{1,64}$/.test(String(own(item ?? undefined, 'name')))
        && integer(own(item ?? undefined, 'major'), 0, 1_048_575) !== null
        && integer(own(item ?? undefined, 'minor'), 0, 1_048_575) !== null
        && typeof own(item ?? undefined, 'counterIdentity') === 'string'
        && /^[0-9a-f]{16}$/.test(own(item ?? undefined, 'counterIdentity') as string)
        && linuxLabel(own(item ?? undefined, 'type'), 64)
        && linuxBooleanOrNull(own(item ?? undefined, 'rotational'))
        && linuxNullableInteger(own(item ?? undefined, 'queueDepth'))
        && linuxRateStatusIsValid(own(item ?? undefined, 'rateStatus'))
        && Boolean(counters)
        && LINUX_DISK_COUNTER_FIELDS.every((field) => linuxNullableInteger(own(counters ?? undefined, field)))
        && ['discardStatus', 'flushStatus', 'ioErrorCounterStatus'].every((field) => linuxRawStatus(own(item ?? undefined, field)))
        && ['discardRateStatus', 'flushRateStatus'].every((field) => linuxRateStatusIsValid(own(item ?? undefined, field)))
        && rateFields.every((field) => linuxNullableNumber(own(item ?? undefined, field)))
        && linuxNullableNumber(own(item ?? undefined, 'utilizationPercent'), 0, 100)
        && own(item ?? undefined, 'ioErrorEvidenceSource') === 'bounded-kernel-events'
        && Boolean(health)
        && linuxRawStatus(own(health ?? undefined, 'smartStatus'))
        && linuxRawStatus(own(health ?? undefined, 'raidStatus'))
        && linuxNullableInteger(own(health ?? undefined, 'raidDegradedDevices'), 0, 4096)
        && (own(health ?? undefined, 'raidArrayState') === null || linuxLabel(own(health ?? undefined, 'raidArrayState'), 32));
    });
}

function validateLinuxNetwork(value: unknown): boolean {
  const record = linuxRecord(value, ['status', 'truncated', 'items']);
  const classifications = new Set([
    'loopback', 'veth', 'docker-bridge', 'wifi', 'vpn', 'tunnel',
    'physical', 'bond', 'virtual',
  ]);
  const linkStates = new Set([
    'unknown', 'notpresent', 'down', 'lowerlayerdown', 'testing', 'dormant', 'up',
  ]);
  return Boolean(record)
    && linuxRawStatus(own(record ?? undefined, 'status'))
    && typeof own(record ?? undefined, 'truncated') === 'boolean'
    && linuxArray(own(record ?? undefined, 'items'), 256, (entry) => {
      const rateFields = LINUX_NETWORK_COUNTER_FIELDS.map((field) => `${field}PerSecond`);
      const item = linuxRecord(entry, [
        'name', 'classification', 'counterIdentity', 'counterIdentityStatus',
        'linkStateStatus', 'linkState', 'carrier', 'mtu',
        'speedMegabitsPerSecond', 'duplex', 'rateStatus', 'counters', ...rateFields,
      ]);
      const counters = item && linuxRecord(own(item, 'counters'), LINUX_NETWORK_COUNTER_FIELDS);
      const name = own(item ?? undefined, 'name');
      const classification = own(item ?? undefined, 'classification');
      const linkState = own(item ?? undefined, 'linkState');
      const duplex = own(item ?? undefined, 'duplex');
      return Boolean(item)
        && typeof name === 'string' && /^[A-Za-z0-9_.-]{1,15}$/.test(name)
        && typeof classification === 'string' && classifications.has(classification)
        && typeof own(item ?? undefined, 'counterIdentity') === 'string'
        && /^[0-9a-f]{16}$/.test(own(item ?? undefined, 'counterIdentity') as string)
        && linuxRawStatus(own(item ?? undefined, 'counterIdentityStatus'))
        && linuxRawStatus(own(item ?? undefined, 'linkStateStatus'))
        && (linkState === null || (typeof linkState === 'string' && linkStates.has(linkState)))
        && linuxBooleanOrNull(own(item ?? undefined, 'carrier'))
        && linuxNullableInteger(own(item ?? undefined, 'mtu'), 68, 1_000_000)
        && linuxNullableInteger(own(item ?? undefined, 'speedMegabitsPerSecond'), 0, 10_000_000)
        && (duplex === null || duplex === 'full' || duplex === 'half' || duplex === 'unknown')
        && linuxRateStatusIsValid(own(item ?? undefined, 'rateStatus'))
        && Boolean(counters)
        && LINUX_NETWORK_COUNTER_FIELDS.every((field) => integer(own(counters ?? undefined, field), 0, MAX_LINUX_COUNTER) !== null)
        && rateFields.every((field) => linuxNullableNumber(own(item ?? undefined, field)));
    });
}

function validateLinuxTcp(value: unknown): boolean {
  const record = linuxRecord(value, [
    'status', 'counters', 'rateStatus', 'outgoingSegmentsPerSecond',
    'retransmittedSegmentsPerSecond', 'retransmissionPercent', 'states',
    'socketScanStatus', 'socketScanTruncated', 'ephemeralPorts', 'conntrack',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status')) || !linuxRateStatusIsValid(own(record, 'rateStatus'))) return false;
  if (!linuxNullableNumber(own(record, 'outgoingSegmentsPerSecond'))
    || !linuxNullableNumber(own(record, 'retransmittedSegmentsPerSecond'))
    || !linuxNullableNumber(own(record, 'retransmissionPercent'), 0, 100)) return false;
  const counters = linuxRecord(own(record, 'counters'), [], [
    'ActiveOpens', 'PassiveOpens', 'AttemptFails', 'EstabResets', 'InSegs',
    'OutSegs', 'RetransSegs', 'InErrs', 'OutRsts', 'TCPSynRetrans', 'TCPTimeouts',
  ]);
  if (!counters || !Object.keys(counters).every((field) => integer(own(counters, field), 0, MAX_LINUX_COUNTER) !== null)) return false;
  const states = linuxRecord(own(record, 'states'), LINUX_TCP_STATE_FIELDS);
  if (!states || !LINUX_TCP_STATE_FIELDS.every((field) => integer(own(states, field), 0, 65_536) !== null)) return false;
  if (!linuxRawStatus(own(record, 'socketScanStatus')) || typeof own(record, 'socketScanTruncated') !== 'boolean') return false;
  const ports = linuxRecord(own(record, 'ephemeralPorts'), [
    'status', 'rangeStart', 'rangeEnd', 'capacity', 'used', 'usedPercent',
  ]);
  const conntrack = linuxRecord(own(record, 'conntrack'), ['status', 'count', 'maximum', 'usedPercent']);
  return Boolean(ports)
    && linuxRawStatus(own(ports ?? undefined, 'status'))
    && linuxNullableInteger(own(ports ?? undefined, 'rangeStart'), 1024, 65_535)
    && linuxNullableInteger(own(ports ?? undefined, 'rangeEnd'), 1024, 65_535)
    && linuxNullableInteger(own(ports ?? undefined, 'capacity'), 1, 64_512)
    && linuxNullableInteger(own(ports ?? undefined, 'used'), 0, 64_512)
    && linuxNullableNumber(own(ports ?? undefined, 'usedPercent'), 0, 100)
    && Boolean(conntrack)
    && linuxRawStatus(own(conntrack ?? undefined, 'status'))
    && linuxNullableInteger(own(conntrack ?? undefined, 'count'))
    && linuxNullableInteger(own(conntrack ?? undefined, 'maximum'), 1)
    && linuxNullableNumber(own(conntrack ?? undefined, 'usedPercent'), 0, 100);
}

function validateLinuxProcessGroup(value: unknown): boolean {
  const record = linuxRecord(value, [
    'name', 'allowlisted', 'instances', 'states', 'threads', 'cpuPercent',
    'residentBytes', 'virtualBytes', 'readBytesPerSecond', 'writeBytesPerSecond',
    'openFileDescriptors', 'fileDescriptorStatus',
  ]);
  const rawStates = record ? own(record, 'states') : undefined;
  const states = isRecord(rawStates) ? rawStates : null;
  return Boolean(record)
    && linuxLabel(own(record ?? undefined, 'name'), 64)
    && typeof own(record ?? undefined, 'allowlisted') === 'boolean'
    && integer(own(record ?? undefined, 'instances'), 1, 8192) !== null
    && Boolean(states)
    && Object.keys(states ?? {}).length <= 26
    && Object.keys(states ?? {}).every((state) => /^[A-Z]$/.test(state) && integer(own(states ?? undefined, state), 0, 8192) !== null)
    && integer(own(record ?? undefined, 'threads'), 0, MAX_LINUX_COUNTER) !== null
    && linuxNullableNumber(own(record ?? undefined, 'cpuPercent'), 0, 10_000)
    && integer(own(record ?? undefined, 'residentBytes'), 0, MAX_LINUX_COUNTER) !== null
    && integer(own(record ?? undefined, 'virtualBytes'), 0, MAX_LINUX_COUNTER) !== null
    && linuxNullableNumber(own(record ?? undefined, 'readBytesPerSecond'))
    && linuxNullableNumber(own(record ?? undefined, 'writeBytesPerSecond'))
    && linuxNullableInteger(own(record ?? undefined, 'openFileDescriptors'))
    && linuxRawStatus(own(record ?? undefined, 'fileDescriptorStatus'));
}

function validateLinuxProcesses(value: unknown): boolean {
  const record = linuxRecord(value, [
    'status', 'pidCount', 'pidCountLowerBound', 'pidMaximumStatus', 'pidMaximum',
    'pidUsedPercent', 'zombieCount', 'threadCount', 'observedProcessCount',
    'scanTruncated', 'deadlineReached', 'allowedUidCount', 'topCpu', 'topMemory',
    'topIo', 'important', 'terminatedSincePreviousSample', 'systemFileDescriptors',
    'allowlistedProcessOpenFileDescriptors', 'fileDescriptorScanTruncated', 'cgroupPids',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status')) || !linuxRawStatus(own(record, 'pidMaximumStatus'))) return false;
  if (integer(own(record, 'pidCount'), 0, 8192) === null
    || typeof own(record, 'pidCountLowerBound') !== 'boolean'
    || !linuxNullableInteger(own(record, 'pidMaximum'), 1)
    || !linuxNullableNumber(own(record, 'pidUsedPercent'), 0, 100)
    || integer(own(record, 'zombieCount'), 0, 8192) === null
    || integer(own(record, 'threadCount'), 0, MAX_LINUX_COUNTER) === null
    || integer(own(record, 'observedProcessCount'), 0, 8192) === null
    || typeof own(record, 'scanTruncated') !== 'boolean'
    || typeof own(record, 'deadlineReached') !== 'boolean'
    || integer(own(record, 'allowedUidCount'), 0, 4096) === null
    || integer(own(record, 'allowlistedProcessOpenFileDescriptors'), 0, MAX_LINUX_COUNTER) === null
    || typeof own(record, 'fileDescriptorScanTruncated') !== 'boolean') return false;
  for (const field of ['topCpu', 'topMemory', 'topIo'] as const) {
    if (!linuxArray(own(record, field), 12, validateLinuxProcessGroup)) return false;
  }
  if (!linuxArray(own(record, 'important'), 64, validateLinuxProcessGroup)) return false;
  if (!linuxArray(own(record, 'terminatedSincePreviousSample'), 12, (entry) => {
    const terminated = linuxRecord(entry, ['name', 'allowlisted', 'instances']);
    return Boolean(terminated)
      && linuxLabel(own(terminated ?? undefined, 'name'), 64)
      && typeof own(terminated ?? undefined, 'allowlisted') === 'boolean'
      && integer(own(terminated ?? undefined, 'instances'), 1, 8192) !== null;
  })) return false;
  const descriptors = linuxRecord(own(record, 'systemFileDescriptors'), [
    'status', 'allocated', 'unusedAllocated', 'used', 'maximum', 'usedPercent',
  ]);
  if (!descriptors || !linuxRawStatus(own(descriptors, 'status'))
    || !['allocated', 'unusedAllocated', 'used'].every((field) => linuxNullableInteger(own(descriptors, field)))
    // Accept the old signed-64-bit producer value at ingress so a rolling
    // deployment does not poison the whole snapshot. Normalization below
    // deliberately maps an unsafe maximum to null rather than exposing an
    // imprecise capacity.
    || !linuxNullableV1RawCounter(own(descriptors, 'maximum'))
    || !linuxNullableNumber(own(descriptors, 'usedPercent'), 0, 100)) return false;
  const cgroup = linuxRecord(own(record, 'cgroupPids'), ['status', 'version', 'current', 'maximum'], ['usedPercent']);
  const version = own(cgroup ?? undefined, 'version');
  return Boolean(cgroup)
    && linuxRawStatus(own(cgroup ?? undefined, 'status'))
    && (version === null || version === 1 || version === 2)
    && linuxNullableInteger(own(cgroup ?? undefined, 'current'))
    && linuxNullableInteger(own(cgroup ?? undefined, 'maximum'), 1)
    && (own(cgroup ?? undefined, 'usedPercent') === undefined || linuxNullableNumber(own(cgroup ?? undefined, 'usedPercent'), 0, 100));
}

function validateLinuxSystemd(value: unknown): boolean {
  const reasons = new Set([
    'not_configured', 'systemctl_unavailable', 'execution_denied', 'deadline',
    'execution_failed', 'query_failed', 'runtime_state_unavailable',
    'runtime_state_denied', 'runtime_state_failed', 'runtime_state_not_directory',
    'bounded_runtime_observation',
  ]);
  const record = linuxRecord(value, ['status', 'reason', 'units', 'truncated']);
  const reason = own(record ?? undefined, 'reason');
  return Boolean(record)
    && linuxRawStatus(own(record ?? undefined, 'status'))
    && (reason === null || (typeof reason === 'string' && reasons.has(reason)))
    && typeof own(record ?? undefined, 'truncated') === 'boolean'
    && linuxArray(own(record ?? undefined, 'units'), 32, (entry) => {
      const unit = linuxRecord(entry, [
        'unit', 'loadState', 'activeState', 'subState', 'restartCount',
        'restartCountStatus', 'result', 'execMainStatus',
      ], ['invocationStatus']);
      const identifier = own(unit ?? undefined, 'unit');
      const restartStatus = own(unit ?? undefined, 'restartCountStatus');
      return Boolean(unit)
        && typeof identifier === 'string'
        && identifier.length <= 128
        && /^[A-Za-z0-9_.@:-]+\.service$/.test(identifier)
        && ['loadState', 'activeState', 'subState', 'result'].every((field) => linuxLabel(own(unit ?? undefined, field), 32))
        && linuxNullableInteger(own(unit ?? undefined, 'restartCount'))
        && (restartStatus === 'systemd_manager' || restartStatus === 'observed_invocation_changes')
        && linuxNullableInteger(own(unit ?? undefined, 'execMainStatus'), 0, 2_147_483_647)
        && (own(unit ?? undefined, 'invocationStatus') === undefined || linuxRawStatus(own(unit ?? undefined, 'invocationStatus')));
    });
}

function validateLinuxThermal(value: unknown): boolean {
  const record = linuxRecord(value, [
    'status', 'sensors', 'fans', 'coolingDevices', 'truncated', 'raspberryPi',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status')) || typeof own(record, 'truncated') !== 'boolean') return false;
  if (!linuxArray(own(record, 'sensors'), 64, (entry) => {
    const sensor = linuxRecord(entry, ['source', 'name', 'status', 'temperatureCelsius']);
    const source = own(sensor ?? undefined, 'source');
    return Boolean(sensor)
      && (source === 'thermal-zone' || source === 'hwmon')
      && linuxLabel(own(sensor ?? undefined, 'name'), 64)
      && linuxRawStatus(own(sensor ?? undefined, 'status'))
      && linuxNullableNumber(own(sensor ?? undefined, 'temperatureCelsius'), -50, 200);
  })) return false;
  if (!linuxArray(own(record, 'fans'), 32, (entry) => {
    const fan = linuxRecord(entry, ['name', 'status', 'rpm']);
    return Boolean(fan)
      && linuxLabel(own(fan ?? undefined, 'name'), 64)
      && linuxRawStatus(own(fan ?? undefined, 'status'))
      && linuxNullableInteger(own(fan ?? undefined, 'rpm'), 0, 1_000_000);
  })) return false;
  if (!linuxArray(own(record, 'coolingDevices'), 32, (entry) => {
    const cooling = linuxRecord(entry, ['name', 'status', 'currentState', 'maximumState']);
    return Boolean(cooling)
      && linuxLabel(own(cooling ?? undefined, 'name'), 64)
      && linuxRawStatus(own(cooling ?? undefined, 'status'))
      && linuxNullableInteger(own(cooling ?? undefined, 'currentState'))
      && linuxNullableInteger(own(cooling ?? undefined, 'maximumState'));
  })) return false;
  const rpi = linuxRecord(own(record, 'raspberryPi'), [
    'status', 'detected', 'temperatureCelsius', 'supplyVoltageVolts',
    'throttledFlags', 'currentUnderVoltage', 'currentFrequencyCapped',
    'currentThrottled', 'currentSoftTemperatureLimit', 'underVoltageOccurred',
    'frequencyCapOccurred', 'throttlingOccurred', 'softTemperatureLimitOccurred',
    'flagSource',
  ]);
  const source = own(rpi ?? undefined, 'flagSource');
  return Boolean(rpi)
    && linuxRawStatus(own(rpi ?? undefined, 'status'))
    && typeof own(rpi ?? undefined, 'detected') === 'boolean'
    && linuxNullableNumber(own(rpi ?? undefined, 'temperatureCelsius'), -50, 200)
    && linuxNullableNumber(own(rpi ?? undefined, 'supplyVoltageVolts'), 0, 10)
    && linuxNullableInteger(own(rpi ?? undefined, 'throttledFlags'), 0, MAX_UINT32)
    && [
      'currentUnderVoltage', 'currentFrequencyCapped', 'currentThrottled',
      'currentSoftTemperatureLimit', 'underVoltageOccurred', 'frequencyCapOccurred',
      'throttlingOccurred', 'softTemperatureLimitOccurred',
    ].every((field) => linuxBooleanOrNull(own(rpi ?? undefined, field)))
    && (source === null || source === 'vcgencmd' || source === 'hwmon-current-only');
}

function validateLinuxClock(value: unknown, nowMs: number): boolean {
  const record = linuxRecord(value, [
    'status', 'uptimeSeconds', 'bootTime', 'rebootDetectedSincePreviousSample',
    'unexpectedReboot', 'unexpectedRebootStatus', 'timeSync',
  ]);
  if (!record || !linuxRawStatus(own(record, 'status'))
    || !linuxNullableInteger(own(record, 'uptimeSeconds'), 0, 10_000_000_000)
    || (own(record, 'bootTime') !== null && linuxTimestamp(own(record, 'bootTime'), nowMs) === null)
    || !linuxBooleanOrNull(own(record, 'rebootDetectedSincePreviousSample'))
    || !linuxBooleanOrNull(own(record, 'unexpectedReboot'))
    || !linuxLabel(own(record, 'unexpectedRebootStatus'), 64)) return false;
  const sync = linuxRecord(own(record, 'timeSync'), [
    'status', 'reason', 'synchronized', 'ntpEnabled', 'ntpSupported',
    'clockDriftMilliseconds', 'clockDriftStatus',
  ]);
  const reason = own(sync ?? undefined, 'reason');
  const reasons = new Set([
    'systemd_timesync_marker', 'timesync_marker_denied', 'timedatectl_unavailable',
    'execution_denied', 'deadline', 'execution_failed', 'query_failed',
  ]);
  return Boolean(sync)
    && linuxRawStatus(own(sync ?? undefined, 'status'))
    && (reason === null || (typeof reason === 'string' && reasons.has(reason)))
    && ['synchronized', 'ntpEnabled', 'ntpSupported'].every((field) => linuxBooleanOrNull(own(sync ?? undefined, field)))
    && linuxNullableNumber(own(sync ?? undefined, 'clockDriftMilliseconds'), -86_400_000, 86_400_000)
    && linuxRawStatus(own(sync ?? undefined, 'clockDriftStatus'));
}

function validateLinuxEventSources(value: unknown, nowMs: number): boolean {
  const record = linuxRecord(value, ['kernelLogStatus', 'summary', 'rawMessagesExported']);
  if (!record || !linuxRawStatus(own(record, 'kernelLogStatus')) || own(record, 'rawMessagesExported') !== false) return false;
  const summary = linuxRecord(own(record, 'summary'), [], [
    'warning', 'oops', 'panic', 'hungTask', 'rcuStall', 'rcuExpedited', 'oomKill',
    'filesystemError', 'nvmeReset', 'nvmeIo', 'pcieAerCorrectable',
    'pcieAerNonFatal', 'pcieAerFatal',
  ]);
  return Boolean(summary) && Object.values(summary ?? {}).every((entry) => {
    const event = linuxRecord(entry, ['count', 'lastEventAt']);
    return Boolean(event)
      && linuxNullableInteger(own(event ?? undefined, 'count'), 0, 1_000_000)
      && (own(event ?? undefined, 'lastEventAt') === null || linuxTimestamp(own(event ?? undefined, 'lastEventAt'), nowMs) !== null);
  });
}

function validateLinuxBoundsAndPrivacy(boundsValue: unknown, privacyValue: unknown): boolean {
  const bounds = linuxRecord(boundsValue, [
    'maximumCpuCount', 'maximumBlockDevices', 'maximumInterfaces',
    'maximumTcpSockets', 'maximumFilesystems', 'maximumProcesses',
    'processDeadlineMilliseconds', 'maximumSystemdUnits',
    'maximumThermalSensors', 'commandTimeoutMilliseconds',
  ]);
  const privacy = linuxRecord(privacyValue, [
    'processCommandLinesCollected', 'processEnvironmentsCollected',
    'rawKernelMessagesCollected',
  ]);
  return Boolean(bounds)
    && own(bounds ?? undefined, 'maximumCpuCount') === 512
    && own(bounds ?? undefined, 'maximumBlockDevices') === 128
    && own(bounds ?? undefined, 'maximumInterfaces') === 256
    && own(bounds ?? undefined, 'maximumTcpSockets') === 65_536
    && own(bounds ?? undefined, 'maximumFilesystems') === 256
    && own(bounds ?? undefined, 'maximumProcesses') === 8192
    && own(bounds ?? undefined, 'processDeadlineMilliseconds') === 1250
    && own(bounds ?? undefined, 'maximumSystemdUnits') === 32
    && own(bounds ?? undefined, 'maximumThermalSensors') === 64
    && integer(own(bounds ?? undefined, 'commandTimeoutMilliseconds'), 100, 5000) !== null
    && Boolean(privacy)
    && own(privacy ?? undefined, 'processCommandLinesCollected') === false
    && own(privacy ?? undefined, 'processEnvironmentsCollected') === false
    && own(privacy ?? undefined, 'rawKernelMessagesCollected') === false;
}

function validateLinuxV1(value: unknown, nowMs: number): value is JsonRecord {
  const record = linuxRecord(value, [
    'schemaVersion', 'collectedAt', 'cpu', 'memory', 'filesystems', 'blockDevices',
    'network', 'tcp', 'processes', 'systemd', 'thermal', 'clock', 'eventSources',
    'collectionBounds', 'privacy',
  ]);
  return Boolean(record)
    && own(record ?? undefined, 'schemaVersion') === 1
    && linuxTimestamp(own(record ?? undefined, 'collectedAt'), nowMs) !== null
    && validateLinuxCpu(own(record ?? undefined, 'cpu'))
    && validateLinuxMemory(own(record ?? undefined, 'memory'))
    && validateLinuxFilesystems(own(record ?? undefined, 'filesystems'))
    && validateLinuxBlockDevices(own(record ?? undefined, 'blockDevices'))
    && validateLinuxNetwork(own(record ?? undefined, 'network'))
    && validateLinuxTcp(own(record ?? undefined, 'tcp'))
    && validateLinuxProcesses(own(record ?? undefined, 'processes'))
    && validateLinuxSystemd(own(record ?? undefined, 'systemd'))
    && validateLinuxThermal(own(record ?? undefined, 'thermal'))
    && validateLinuxClock(own(record ?? undefined, 'clock'), nowMs)
    && validateLinuxEventSources(own(record ?? undefined, 'eventSources'), nowMs)
    && validateLinuxBoundsAndPrivacy(
      own(record ?? undefined, 'collectionBounds'),
      own(record ?? undefined, 'privacy'),
    );
}

function normalizeLinuxStatus(value: unknown): DashboardResponse['linux']['status'] {
  switch (value) {
    case 'supported':
    case 'partial':
    case 'unsupported':
    case 'permission_error':
    case 'unavailable':
    case 'invalid':
      return value;
    case 'timeout':
      return 'unavailable';
    case 'too_large':
      return 'invalid';
    default:
      return 'collection_error';
  }
}

function normalizeLinuxRateStatus(
  value: unknown,
): DashboardResponse['linux']['storage']['devices'][number]['rateStatus'] {
  if (value === 'ok' || value === 'warmup' || value === 'counter_reset') return value;
  return normalizeLinuxStatus(value);
}

function combinedLinuxStatus(
  statuses: DashboardResponse['linux']['status'][],
): DashboardResponse['linux']['status'] {
  if (statuses.includes('collection_error')) return 'collection_error';
  if (statuses.includes('invalid')) return 'invalid';
  const hasObserved = statuses.some((status) => status === 'supported' || status === 'partial');
  if (hasObserved && statuses.some((status) => status !== 'supported' && status !== 'partial')) return 'partial';
  if (statuses.includes('partial')) return 'partial';
  if (statuses.includes('permission_error')) return 'permission_error';
  if (statuses.includes('unavailable')) return 'unavailable';
  if (statuses.every((status) => status === 'unsupported')) return 'unsupported';
  return 'supported';
}

function emptyLinuxDiagnostics(
  status: DashboardResponse['linux']['status'],
): DashboardResponse['linux'] {
  const capacity = () => ({ status, current: null, maximum: null, usedPercent: null });
  return {
    schemaVersion: null,
    collectedAt: null,
    status,
    resources: {
      status,
      processCount: null,
      processCountIsLowerBound: false,
      observedProcessCount: null,
      zombieCount: null,
      threadCount: null,
      scanTruncated: false,
      deadlineReached: false,
      pid: capacity(),
      systemFileDescriptors: capacity(),
      cgroupPids: { ...capacity(), version: null },
    },
    storage: { status, truncated: false, devices: [] },
    network: {
      status,
      tcp: {
        status,
        rateStatus: status,
        outgoingSegmentsPerSecond: null,
        retransmittedSegmentsPerSecond: null,
        retransmissionPercent: null,
        states: {
          established: 0,
          synSent: 0,
          synRecv: 0,
          finWait1: 0,
          finWait2: 0,
          timeWait: 0,
          close: 0,
          closeWait: 0,
          lastAck: 0,
          listen: 0,
          closing: 0,
          newSynRecv: 0,
        },
        socketScanStatus: status,
        socketScanTruncated: false,
        ephemeralPorts: { ...capacity(), rangeStart: null, rangeEnd: null },
        conntrack: capacity(),
      },
    },
    reliability: {
      status,
      clock: {
        status,
        uptimeSeconds: null,
        bootTime: null,
        rebootDetectedSincePreviousSample: null,
        unexpectedReboot: null,
        unexpectedRebootStatus: 'unavailable',
        timeSync: {
          status,
          reason: null,
          synchronized: null,
          ntpEnabled: null,
          ntpSupported: null,
          clockDriftMilliseconds: null,
          clockDriftStatus: status,
        },
      },
      systemd: { status, reason: null, truncated: false, units: [] },
    },
    power: {
      status,
      truncated: false,
      maximumTemperatureCelsius: null,
      sensors: [],
      fans: [],
      raspberryPi: {
        status,
        detected: false,
        temperatureCelsius: null,
        supplyVoltageVolts: null,
        throttledFlags: null,
        currentUnderVoltage: null,
        currentFrequencyCapped: null,
        currentThrottled: null,
        currentSoftTemperatureLimit: null,
        underVoltageOccurred: null,
        frequencyCapOccurred: null,
        throttlingOccurred: null,
        softTemperatureLimitOccurred: null,
        flagSource: null,
      },
    },
  };
}

function normalizeLinuxDiagnostics(
  current: JsonRecord | null,
  nowMs: number,
): DashboardResponse['linux'] {
  const raw = own(current ?? undefined, 'linux');
  if (raw === undefined) return emptyLinuxDiagnostics('unsupported');
  if (!validateLinuxV1(raw, nowMs)) return emptyLinuxDiagnostics('collection_error');

  const processes = own(raw, 'processes') as JsonRecord;
  const descriptors = own(processes, 'systemFileDescriptors') as JsonRecord;
  const cgroup = own(processes, 'cgroupPids') as JsonRecord;
  const pidCount = integer(own(processes, 'pidCount'), 0, 8192);
  const resourceStatus = normalizeLinuxStatus(own(processes, 'status'));
  const descriptorMaximum = integer(own(descriptors, 'maximum'), 1, MAX_LINUX_COUNTER);
  const descriptorStatus = descriptorMaximum === null && typeof own(descriptors, 'maximum') === 'number'
    ? 'partial'
    : normalizeLinuxStatus(own(descriptors, 'status'));
  const resources: DashboardResponse['linux']['resources'] = {
    status: resourceStatus,
    processCount: pidCount,
    processCountIsLowerBound: own(processes, 'pidCountLowerBound') as boolean,
    observedProcessCount: integer(own(processes, 'observedProcessCount'), 0, 8192),
    zombieCount: integer(own(processes, 'zombieCount'), 0, 8192),
    threadCount: integer(own(processes, 'threadCount'), 0, MAX_LINUX_COUNTER),
    scanTruncated: own(processes, 'scanTruncated') as boolean,
    deadlineReached: own(processes, 'deadlineReached') as boolean,
    pid: {
      status: normalizeLinuxStatus(own(processes, 'pidMaximumStatus')),
      current: pidCount,
      maximum: integer(own(processes, 'pidMaximum'), 1, MAX_LINUX_COUNTER),
      usedPercent: percent(own(processes, 'pidUsedPercent')),
    },
    systemFileDescriptors: {
      status: descriptorStatus,
      current: integer(own(descriptors, 'used'), 0, MAX_LINUX_COUNTER),
      maximum: descriptorMaximum,
      usedPercent: descriptorMaximum === null ? null : percent(own(descriptors, 'usedPercent')),
    },
    cgroupPids: {
      status: normalizeLinuxStatus(own(cgroup, 'status')),
      version: own(cgroup, 'version') as 1 | 2 | null,
      current: integer(own(cgroup, 'current'), 0, MAX_LINUX_COUNTER),
      maximum: integer(own(cgroup, 'maximum'), 1, MAX_LINUX_COUNTER),
      usedPercent: percent(own(cgroup, 'usedPercent')),
    },
  };

  const blockDevices = own(raw, 'blockDevices') as JsonRecord;
  const reducedDevices = (own(blockDevices, 'items') as JsonRecord[]).map((item) => {
    const health = own(item, 'health') as JsonRecord;
    return {
      name: own(item, 'name') as string,
      type: own(item, 'type') as string,
      rotational: own(item, 'rotational') as boolean | null,
      rateStatus: normalizeLinuxRateStatus(own(item, 'rateStatus')),
      queueDepth: integer(own(item, 'queueDepth'), 0, MAX_LINUX_COUNTER),
      readLatencyMilliseconds: finite(own(item, 'readLatencyMilliseconds'), 0, MAX_LINUX_RATE),
      writeLatencyMilliseconds: finite(own(item, 'writeLatencyMilliseconds'), 0, MAX_LINUX_RATE),
      averageLatencyMilliseconds: finite(own(item, 'averageLatencyMilliseconds'), 0, MAX_LINUX_RATE),
      utilizationPercent: percent(own(item, 'utilizationPercent')),
      averageQueueDepth: finite(own(item, 'averageQueueDepth'), 0, MAX_LINUX_RATE),
      smartStatus: normalizeLinuxStatus(own(health, 'smartStatus')),
      raidStatus: normalizeLinuxStatus(own(health, 'raidStatus')),
      raidDegradedDevices: integer(own(health, 'raidDegradedDevices'), 0, 4096),
      raidArrayState: own(health, 'raidArrayState') as string | null,
    };
  }).sort((left, right) => {
    const leftRisk = (left.raidDegradedDevices ?? 0) * 1000
      + (left.utilizationPercent ?? 0) * 10
      + (left.averageLatencyMilliseconds ?? 0);
    const rightRisk = (right.raidDegradedDevices ?? 0) * 1000
      + (right.utilizationPercent ?? 0) * 10
      + (right.averageLatencyMilliseconds ?? 0);
    return rightRisk - leftRisk || left.name.localeCompare(right.name);
  });
  const storage: DashboardResponse['linux']['storage'] = {
    status: normalizeLinuxStatus(own(blockDevices, 'status')),
    truncated: (own(blockDevices, 'truncated') as boolean) || reducedDevices.length > MAX_LINUX_REDUCED_DEVICES,
    devices: reducedDevices.slice(0, MAX_LINUX_REDUCED_DEVICES),
  };

  const tcp = own(raw, 'tcp') as JsonRecord;
  const tcpStates = own(tcp, 'states') as JsonRecord;
  const ports = own(tcp, 'ephemeralPorts') as JsonRecord;
  const conntrack = own(tcp, 'conntrack') as JsonRecord;
  const tcpStatus = normalizeLinuxStatus(own(tcp, 'status'));
  const network: DashboardResponse['linux']['network'] = {
    status: tcpStatus,
    tcp: {
      status: tcpStatus,
      rateStatus: normalizeLinuxRateStatus(own(tcp, 'rateStatus')),
      outgoingSegmentsPerSecond: finite(own(tcp, 'outgoingSegmentsPerSecond'), 0, MAX_LINUX_RATE),
      retransmittedSegmentsPerSecond: finite(own(tcp, 'retransmittedSegmentsPerSecond'), 0, MAX_LINUX_RATE),
      retransmissionPercent: percent(own(tcp, 'retransmissionPercent')),
      states: {
        established: integer(own(tcpStates, 'established'), 0, 65_536) ?? 0,
        synSent: integer(own(tcpStates, 'synSent'), 0, 65_536) ?? 0,
        synRecv: integer(own(tcpStates, 'synRecv'), 0, 65_536) ?? 0,
        finWait1: integer(own(tcpStates, 'finWait1'), 0, 65_536) ?? 0,
        finWait2: integer(own(tcpStates, 'finWait2'), 0, 65_536) ?? 0,
        timeWait: integer(own(tcpStates, 'timeWait'), 0, 65_536) ?? 0,
        close: integer(own(tcpStates, 'close'), 0, 65_536) ?? 0,
        closeWait: integer(own(tcpStates, 'closeWait'), 0, 65_536) ?? 0,
        lastAck: integer(own(tcpStates, 'lastAck'), 0, 65_536) ?? 0,
        listen: integer(own(tcpStates, 'listen'), 0, 65_536) ?? 0,
        closing: integer(own(tcpStates, 'closing'), 0, 65_536) ?? 0,
        newSynRecv: integer(own(tcpStates, 'newSynRecv'), 0, 65_536) ?? 0,
      },
      socketScanStatus: normalizeLinuxStatus(own(tcp, 'socketScanStatus')),
      socketScanTruncated: own(tcp, 'socketScanTruncated') as boolean,
      ephemeralPorts: {
        status: normalizeLinuxStatus(own(ports, 'status')),
        current: integer(own(ports, 'used'), 0, 64_512),
        maximum: integer(own(ports, 'capacity'), 1, 64_512),
        usedPercent: percent(own(ports, 'usedPercent')),
        rangeStart: integer(own(ports, 'rangeStart'), 1024, 65_535),
        rangeEnd: integer(own(ports, 'rangeEnd'), 1024, 65_535),
      },
      conntrack: {
        status: normalizeLinuxStatus(own(conntrack, 'status')),
        current: integer(own(conntrack, 'count'), 0, MAX_LINUX_COUNTER),
        maximum: integer(own(conntrack, 'maximum'), 1, MAX_LINUX_COUNTER),
        usedPercent: percent(own(conntrack, 'usedPercent')),
      },
    },
  };

  const clock = own(raw, 'clock') as JsonRecord;
  const timeSync = own(clock, 'timeSync') as JsonRecord;
  const systemd = own(raw, 'systemd') as JsonRecord;
  const clockStatus = normalizeLinuxStatus(own(clock, 'status'));
  const systemdStatus = normalizeLinuxStatus(own(systemd, 'status'));
  const reliability: DashboardResponse['linux']['reliability'] = {
    status: combinedLinuxStatus([clockStatus, systemdStatus]),
    clock: {
      status: clockStatus,
      uptimeSeconds: integer(own(clock, 'uptimeSeconds'), 0, 10_000_000_000),
      bootTime: own(clock, 'bootTime') === null ? null : linuxTimestamp(own(clock, 'bootTime'), nowMs),
      rebootDetectedSincePreviousSample: own(clock, 'rebootDetectedSincePreviousSample') as boolean | null,
      unexpectedReboot: own(clock, 'unexpectedReboot') as boolean | null,
      unexpectedRebootStatus: own(clock, 'unexpectedRebootStatus') as string,
      timeSync: {
        status: normalizeLinuxStatus(own(timeSync, 'status')),
        reason: own(timeSync, 'reason') as string | null,
        synchronized: own(timeSync, 'synchronized') as boolean | null,
        ntpEnabled: own(timeSync, 'ntpEnabled') as boolean | null,
        ntpSupported: own(timeSync, 'ntpSupported') as boolean | null,
        clockDriftMilliseconds: finite(own(timeSync, 'clockDriftMilliseconds'), -86_400_000, 86_400_000),
        clockDriftStatus: normalizeLinuxStatus(own(timeSync, 'clockDriftStatus')),
      },
    },
    systemd: {
      status: systemdStatus,
      reason: own(systemd, 'reason') as string | null,
      truncated: own(systemd, 'truncated') as boolean,
      units: (own(systemd, 'units') as JsonRecord[]).map((unit) => ({
        unit: own(unit, 'unit') as string,
        loadState: own(unit, 'loadState') as string,
        activeState: own(unit, 'activeState') as string,
        subState: own(unit, 'subState') as string,
        restartCount: integer(own(unit, 'restartCount'), 0, MAX_LINUX_COUNTER),
        restartCountStatus: own(unit, 'restartCountStatus') as 'systemd_manager' | 'observed_invocation_changes',
        result: own(unit, 'result') as string,
        execMainStatus: integer(own(unit, 'execMainStatus'), 0, 2_147_483_647),
        invocationStatus: own(unit, 'invocationStatus') === undefined
          ? null
          : normalizeLinuxStatus(own(unit, 'invocationStatus')),
      })),
    },
  };

  const thermal = own(raw, 'thermal') as JsonRecord;
  const rawSensors = own(thermal, 'sensors') as JsonRecord[];
  const rawFans = own(thermal, 'fans') as JsonRecord[];
  const rpi = own(thermal, 'raspberryPi') as JsonRecord;
  const temperatures = rawSensors
    .map((sensor) => finite(own(sensor, 'temperatureCelsius'), -50, 200))
    .filter((value): value is number => value !== null);
  const powerStatus = normalizeLinuxStatus(own(thermal, 'status'));
  const power: DashboardResponse['linux']['power'] = {
    status: powerStatus,
    truncated: (own(thermal, 'truncated') as boolean)
      || rawSensors.length > MAX_LINUX_REDUCED_THERMAL_ITEMS
      || rawFans.length > MAX_LINUX_REDUCED_THERMAL_ITEMS,
    maximumTemperatureCelsius: temperatures.length ? Math.max(...temperatures) : null,
    sensors: rawSensors.slice(0, MAX_LINUX_REDUCED_THERMAL_ITEMS).map((sensor) => ({
      source: own(sensor, 'source') as 'thermal-zone' | 'hwmon',
      name: own(sensor, 'name') as string,
      status: normalizeLinuxStatus(own(sensor, 'status')),
      temperatureCelsius: finite(own(sensor, 'temperatureCelsius'), -50, 200),
    })),
    fans: rawFans.slice(0, MAX_LINUX_REDUCED_THERMAL_ITEMS).map((fan) => ({
      name: own(fan, 'name') as string,
      status: normalizeLinuxStatus(own(fan, 'status')),
      rpm: integer(own(fan, 'rpm'), 0, 1_000_000),
    })),
    raspberryPi: {
      status: normalizeLinuxStatus(own(rpi, 'status')),
      detected: own(rpi, 'detected') as boolean,
      temperatureCelsius: finite(own(rpi, 'temperatureCelsius'), -50, 200),
      supplyVoltageVolts: finite(own(rpi, 'supplyVoltageVolts'), 0, 10),
      throttledFlags: integer(own(rpi, 'throttledFlags'), 0, MAX_UINT32),
      currentUnderVoltage: own(rpi, 'currentUnderVoltage') as boolean | null,
      currentFrequencyCapped: own(rpi, 'currentFrequencyCapped') as boolean | null,
      currentThrottled: own(rpi, 'currentThrottled') as boolean | null,
      currentSoftTemperatureLimit: own(rpi, 'currentSoftTemperatureLimit') as boolean | null,
      underVoltageOccurred: own(rpi, 'underVoltageOccurred') as boolean | null,
      frequencyCapOccurred: own(rpi, 'frequencyCapOccurred') as boolean | null,
      throttlingOccurred: own(rpi, 'throttlingOccurred') as boolean | null,
      softTemperatureLimitOccurred: own(rpi, 'softTemperatureLimitOccurred') as boolean | null,
      flagSource: own(rpi, 'flagSource') as 'vcgencmd' | 'hwmon-current-only' | null,
    },
  };

  const statuses = [resourceStatus, storage.status, network.status, reliability.status, powerStatus];
  return {
    schemaVersion: 1,
    collectedAt: linuxTimestamp(own(raw, 'collectedAt'), nowMs),
    status: combinedLinuxStatus(statuses),
    resources,
    storage,
    network,
    reliability,
    power,
  };
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
  const dockerEventTelemetry = normalizeDockerEventTelemetry(current, nowMs, staleAfterMs, cutoff);
  const syntheticProbeTelemetry = normalizeSyntheticProbeTelemetry(current, nowMs, staleAfterMs);
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
    linux: normalizeLinuxDiagnostics(current, nowMs),
    system: normalizeSystem(current, nowMs),
    latest,
    series: downsampleTelemetry(samples, MAX_SERIES_POINTS),
    telemetrySummary: summarizeTelemetry(samples),
    powerSummary: summarizePower(samples),
    disks: normalizeDisks(current),
    containerCollection: containerTelemetry.containerCollection,
    containers: containerTelemetry.containers,
    dockerEventCollection: dockerEventTelemetry.dockerEventCollection,
    dockerEvents: dockerEventTelemetry.dockerEvents,
    syntheticProbeCollection: syntheticProbeTelemetry.syntheticProbeCollection,
    syntheticProbes: syntheticProbeTelemetry.syntheticProbes,
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
