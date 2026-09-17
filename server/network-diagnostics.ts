import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { NetworkDiagnosticRecord, NetworkDiagnosticRange, NetworkDiagnosticProblem, NetworkDiagnosticsResponse } from '../src/network-diagnostics-types.js';

const DAY = 86_400_000;
const MAX_DAY_BYTES = 8 * 1024 * 1024;
const MAX_ROW_BYTES = 32 * 1024;
const RANGES = { '1h': 3_600_000, '6h': 21_600_000, '24h': DAY, '7d': 7 * DAY, '30d': 30 * DAY };
const PROBLEMS = ['all', 'http', 'tcp', 'interface'];
const STATES = ['fresh', 'stale', 'no_data', 'error'];
const PHASES = ['validation', 'dns', 'tcp', 'tls', 'request', 'ttfb', 'headers', 'certificate', 'redirect', 'http'];

export class NetworkDiagnosticsQueryError extends Error {
  constructor() { super('Invalid network diagnostics query.'); this.name = 'NetworkDiagnosticsQueryError'; }
}

type JsonRecord = Record<string, unknown>;
function exact(value: unknown, fields: string[]): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}
function numeric(value: unknown, max: number, nullable = true): boolean {
  return (nullable && value === null) || (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= max);
}
function timestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) && Number.isFinite(Date.parse(value));
}
function safeId(value: unknown): boolean {
  return typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(value)
    && !/wgang|\b(?:\d{1,3}\.){3}\d{1,3}\b|gh[opsu]_|github_pat_|eyJ/i.test(value);
}

export function parseNetworkDiagnosticRecord(raw: unknown): NetworkDiagnosticRecord | null {
  if (!exact(raw, ['schemaVersion', 'observedAt', 'probeStatus', 'probeObservedAt', 'probes', 'tcp', 'interfaces', 'context', 'problems'])
    || raw.schemaVersion !== 1 || !timestamp(raw.observedAt)
    || !STATES.includes(raw.probeStatus as string)
    || !(raw.probeObservedAt === null || timestamp(raw.probeObservedAt))
    || !Array.isArray(raw.probes) || raw.probes.length > 32
    || !Array.isArray(raw.problems) || raw.problems.length > 3
    || raw.problems.some((item) => !['http', 'tcp', 'interface'].includes(item))) return null;
  const probes = raw.probes.filter((probe) => !(probe && typeof probe === 'object' && typeof probe.id === 'string' && /wgang/i.test(probe.id)));
  if (probes.some((probe) => {
    if (!exact(probe, ['id', 'checkedAt', 'status', 'httpStatus', 'redirectCount', 'errorPhase', 'timings'])
      || !safeId(probe.id) || !timestamp(probe.checkedAt)
      || !['ok', 'dns', 'permission', 'timeout', 'tls', 'http', 'invalid', 'unsupported'].includes(probe.status as string)
      || !(probe.errorPhase === null || PHASES.includes(probe.errorPhase as string))
      || (probe.status === 'ok') !== (probe.errorPhase === null)
      || !numeric(probe.redirectCount, 5, false) || !Number.isInteger(probe.redirectCount)
      || !(probe.httpStatus === null || (numeric(probe.httpStatus, 599, false) && Number(probe.httpStatus) >= 100 && Number.isInteger(probe.httpStatus)))
      || (probe.status === 'ok' && probe.httpStatus === null)
      || !exact(probe.timings, ['dnsMs', 'tcpMs', 'tlsMs', 'ttfbMs', 'totalMs'])
      || !numeric(probe.timings.totalMs, 600_000, false)
      || Object.values(probe.timings).some((value) => !numeric(value, 600_000))) return true;
    return Date.parse(probe.checkedAt) > Date.parse(raw.observedAt as string) + 60_000;
  }) || new Set(probes.map((probe) => probe.id)).size !== probes.length) return null;
  if (!exact(raw.tcp, ['status', 'elapsedSeconds', 'retransmittedSegments', 'outboundSegments', 'retransmitPercent', 'retransmittedPerSecond', 'outboundPerSecond'])
    || !['fresh', 'no_data', 'error'].includes(raw.tcp.status as string)
    || Object.entries(raw.tcp).some(([key, value]) => key !== 'status' && !numeric(value, 1e18))
    || !numeric(raw.tcp.elapsedSeconds, 600)
    || !exact(raw.interfaces, ['rxErrorsPerSecond', 'txErrorsPerSecond', 'rxDroppedPerSecond', 'txDroppedPerSecond'])
    || Object.values(raw.interfaces).some((value) => !numeric(value, 1e12))
    || !exact(raw.context, ['cpuPercent', 'memoryPercent', 'cpuPressureSomeAvg10', 'cpuPressureFullAvg10', 'memoryPressureSomeAvg10', 'memoryPressureFullAvg10', 'ioPressureSomeAvg10', 'ioPressureFullAvg10'])
    || Object.values(raw.context).some((value) => !numeric(value, 100))) return null;
  // Only reviewed fixed fields reach the API, even if the private exporter is malformed.
  return { ...raw, probes } as unknown as NetworkDiagnosticRecord;
}

function readBounded(path: string, max: number): string | null {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.mode & 0o022 || metadata.size > max) throw new Error('Invalid diagnostic file');
    const buffer = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (!count) break;
      offset += count;
    }
    return buffer.subarray(0, offset).toString('utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

/** Auth belongs to the route. All input dates and work are bounded to retained UTC days. */
export function readNetworkDiagnostics(dataDir: string, query: Record<string, unknown> = {}, nowMs = Date.now()): NetworkDiagnosticsResponse {
  if (Object.keys(query).some((key) => !['range', 'problem', 'page', 'limit', 'from', 'to'].includes(key))) throw new NetworkDiagnosticsQueryError();
  const range = query.range ?? '24h';
  const problem = query.problem ?? 'all';
  const integer = (value: unknown, fallback: number, maximum: number): number => {
    if (value === undefined) return fallback;
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,6}$/.test(value) || Number(value) > maximum) throw new NetworkDiagnosticsQueryError();
    return Number(value);
  };
  if (typeof range !== 'string' || !Object.hasOwn(RANGES, range) || typeof problem !== 'string' || !PROBLEMS.includes(problem)) throw new NetworkDiagnosticsQueryError();
  const page = integer(query.page, 1, 300_000);
  const limit = integer(query.limit, 20, 100);
  if (query.to !== undefined && !timestamp(query.to) || query.from !== undefined && !timestamp(query.from)) throw new NetworkDiagnosticsQueryError();
  const toMs = query.to === undefined ? nowMs : Date.parse(query.to as string);
  const fromMs = query.from === undefined ? Math.max(toMs - RANGES[range as NetworkDiagnosticRange], Math.floor(nowMs / DAY) * DAY - 29 * DAY) : Date.parse(query.from as string);
  if (toMs > nowMs + 60_000 || fromMs < Math.floor(nowMs / DAY) * DAY - 29 * DAY || fromMs >= toMs || toMs - fromMs > 30 * DAY) throw new NetworkDiagnosticsQueryError();
  const result: NetworkDiagnosticsResponse = { schemaVersion: 1, status: 'no_data', observedAt: null, range: range as NetworkDiagnosticRange,
    from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString(), problem: problem as NetworkDiagnosticProblem,
    page, limit, total: 0, records: [], rejectedRows: 0, truncated: false, retentionDays: 30 };
  const root = join(resolve(dataDir), 'network-diagnostics');
  try {
    const info = lstatSync(root);
    if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o022) throw new Error('Invalid diagnostic directory');
    try {
      const latestText = readBounded(join(root, 'latest.json'), MAX_ROW_BYTES);
      const latest = latestText ? parseNetworkDiagnosticRecord(JSON.parse(latestText)) : null;
      if (latestText && (!latest || Date.parse(latest.observedAt) > nowMs + 60_000)) result.rejectedRows++;
      if (latest && Date.parse(latest.observedAt) <= nowMs + 60_000) {
        result.observedAt = latest.observedAt;
        result.status = nowMs - Date.parse(latest.observedAt) > 120_000 ? 'stale' : 'fresh';
      }
    } catch { result.rejectedRows++; } // A damaged latest pointer must not hide valid retained history.
    // At most 30 files × 8 MiB; parse one bounded day at a time and retain only
    // the requested page. Total and paging remain exact for a 30-day query.
    for (let day = Math.floor(toMs / DAY) * DAY; day >= Math.floor(fromMs / DAY) * DAY; day -= DAY) {
      let content: string | null;
      try { content = readBounded(join(root, `${new Date(day).toISOString().slice(0, 10)}.jsonl`), MAX_DAY_BYTES); }
      catch { result.rejectedRows++; result.truncated = true; continue; }
      if (!content) continue;
      const lines = content.trimEnd().split('\n');
      if (lines.length > 10_000) { result.rejectedRows++; result.truncated = true; continue; }
      for (let index = lines.length - 1; index >= 0; index--) {
        let record: NetworkDiagnosticRecord | null = null;
        try { if (Buffer.byteLength(lines[index]) <= MAX_ROW_BYTES) record = parseNetworkDiagnosticRecord(JSON.parse(lines[index])); } catch { /* Count malformed rows without returning their content. */ }
        if (!record) { result.rejectedRows++; continue; }
        const observed = Date.parse(record.observedAt);
        if (observed < day || observed >= day + DAY) { result.rejectedRows++; continue; }
        if (observed < fromMs || observed > toMs || problem !== 'all' && !record.problems.includes(problem as Exclude<NetworkDiagnosticProblem, 'all'>)) continue;
        if (result.total >= (page - 1) * limit && result.records.length < limit) result.records.push(record);
        result.total++;
      }
    }
    if (result.rejectedRows || result.truncated) result.status = 'error';
    return result;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') result.status = 'error';
    return result;
  }
}
