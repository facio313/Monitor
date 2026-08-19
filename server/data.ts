import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { basename, join, relative, resolve, sep } from 'node:path';
import type { DashboardRange, DashboardResponse, TelemetrySample } from './types.js';

const MAX_CURRENT_BYTES = 1024 * 1024;
const MAX_EVENT_FILE_BYTES = 4 * 1024 * 1024;
const MAX_HISTORY_FILE_BYTES = 8 * 1024 * 1024;
const MAX_JSONL_LINES = 50_000;
const MAX_LINE_BYTES = 128 * 1024;
const MAX_SERIES_POINTS = 360;
const MAX_EVENTS = 500;
const MAX_POWER_CORRELATION_MS = 2 * 60 * 1_000;
const MAX_UINT32 = 0xffff_ffff;

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

  return {
    timestamp,
    cpuPercent: percent(first(cpu, ['percent', 'usagePercent', 'usage']) ?? first(value, ['cpuPercent'])),
    memoryPercent,
    memoryUsedBytes,
    memoryTotalBytes,
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
    temperatureC: null,
    load1: null,
    load5: null,
    load15: null,
    powerState: null,
    supplyVoltageVolts: null,
    throttledFlags: null,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: null,
    networkTxBytesPerSecond: null,
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

export function telemetryIsReady(dataDirectory: string): boolean {
  const root = resolve(dataDirectory);
  const current = parseObjectFile(root, join(root, 'current.json'), MAX_CURRENT_BYTES);
  const currentPayload = recordAt(current ?? undefined, 'latest') ?? current;
  return normalizeSample(currentPayload) !== null;
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
  let minimumVoltageIndex: number | null = null;
  let maximumVoltageIndex: number | null = null;
  const transitions: number[] = [];
  for (let index = 0; index < values.length; index += 1) {
    const sample = values[index]!;
    if (sample.supplyVoltageVolts !== null) {
      if (
        minimumVoltageIndex === null
        || sample.supplyVoltageVolts < values[minimumVoltageIndex]!.supplyVoltageVolts!
      ) minimumVoltageIndex = index;
      if (
        maximumVoltageIndex === null
        || sample.supplyVoltageVolts > values[maximumVoltageIndex]!.supplyVoltageVolts!
      ) maximumVoltageIndex = index;
    }
    if (index > 0) {
      const previous = values[index - 1]!;
      if (
        sample.powerState !== previous.powerState
        || sample.throttledFlags !== previous.throttledFlags
      ) transitions.push(index);
    }
  }
  if (minimumVoltageIndex !== null) required.add(minimumVoltageIndex);
  if (maximumVoltageIndex !== null) required.add(maximumVoltageIndex);

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
    uptimeSeconds: finite(first(host, ['uptimeSeconds', 'uptime']), 0),
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
    let usagePercent = percent(first(value, ['percent', 'usagePercent', 'usedPercent']));
    if (usagePercent === null && usedBytes !== null && totalBytes && totalBytes > 0) {
      usagePercent = Math.min(100, (usedBytes / totalBytes) * 100);
    }
    return [{
      mount,
      totalBytes,
      usedBytes,
      usedPercent: usagePercent,
    }];
  });
}

function normalizeContainers(current: JsonRecord | null): DashboardResponse['containers'] {
  const input = current ? first(current, ['containers']) : undefined;
  if (!Array.isArray(input)) return [];
  return input.slice(0, 256).flatMap((value) => {
    if (!isRecord(value)) return [];
    const name = cleanText(first(value, ['name']), 128);
    if (!name) return [];
    return [{
      name,
      owner: cleanText(first(value, ['owner', 'user']), 64),
      state: cleanText(first(value, ['state', 'status']), 64),
      health: cleanText(first(value, ['health', 'healthStatus']), 64),
      cpuPercent: percent(first(value, ['cpuPercent', 'cpu'])),
      memoryBytes: finite(first(value, ['memoryBytes', 'memoryUsageBytes'])),
      memoryPercent: percent(first(value, ['memoryPercent'])),
    }];
  });
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
  const alerts = parseJsonLines(root, join(root, 'alerts.jsonl'), MAX_EVENT_FILE_BYTES);
  const power = parseJsonLines(root, join(root, 'power.jsonl'), MAX_EVENT_FILE_BYTES);
  const privilege = parseJsonLines(root, join(root, 'privilege.jsonl'), MAX_EVENT_FILE_BYTES);

  return {
    generatedAt: new Date(nowMs).toISOString(),
    range,
    stale: !Number.isFinite(latestTime) || nowMs - latestTime > staleAfterMs,
    host: normalizeHost(current),
    latest,
    series: downsampleTelemetry(samples, MAX_SERIES_POINTS),
    powerSummary: summarizePower(samples),
    disks: normalizeDisks(current),
    containers: normalizeContainers(current),
    alerts: normalizeAlerts(alerts, cutoff, nowMs),
    powerEvents: normalizePowerEvents(power, alerts, samples, cutoff, nowMs),
    privilegeEvents: normalizePrivilege(privilege, cutoff, nowMs),
  };
}

export const dataLimits = {
  maximumSeriesPoints: MAX_SERIES_POINTS,
  maximumEvents: MAX_EVENTS,
  acceptedHistoryFilePattern: /^\d{4}-\d{2}-\d{2}\.jsonl$/,
  fixedFiles: ['current.json', 'alerts.jsonl', 'power.jsonl', 'privilege.jsonl'].map((path) => basename(path)),
} as const;
