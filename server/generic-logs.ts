import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { join, relative, resolve, sep } from 'node:path';

const MAX_LOG_BYTES = 16 * 1024 * 1024;
const MAX_STATUS_BYTES = 512 * 1024;
const MAX_FAILURE_MARKER_BYTES = 4 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_RECORDS = 20_000;
const MAX_QUERY_BYTES = 128;
const MAX_PAGE_SIZE = 200;
const MAX_FILTER_VALUES = 32;
const FUTURE_SKEW_MS = 5 * 60 * 1_000;
const SOURCE_STALE_MS = 5 * 60 * 1_000;

const recordFields = [
  'schemaVersion', 'timestamp', 'observedAt', 'timestampSource', 'sourceKind',
  'sourceId', 'priority', 'severity', 'parser', 'message', 'truncated',
  'multilineLineCount', 'hostId', 'containerName', 'composeProject',
  'composeService', 'processName', 'systemdUnit', 'stream', 'fields',
  'redactionVersion',
] as const;
const dropFields = [
  'inputLineLimit', 'inputByteLimit', 'oversizedLine', 'multilineLineLimit',
  'oversizedEvent', 'sourceQuota', 'globalQuota', 'acquisition',
] as const;
const sourceStatusFields = [
  'schemaVersion', 'sourceId', 'sourceKind', 'status', 'observedAt',
  'lastSuccessAt', 'errorClass', 'seenLines', 'seenBytes', 'parsedEvents',
  'admittedEvents', 'droppedLines', 'dropped',
] as const;

const sourceKinds = new Set<GenericLogSourceKind>(['docker', 'file', 'journald']);
const priorities = new Set<GenericLogPriority>(['debug', 'normal', 'incident', 'security']);
const severities = new Set<GenericLogSeverity>([
  'trace', 'debug', 'info', 'notice', 'warning', 'error', 'critical',
]);
const parsers = new Set<GenericLogParser>(['json', 'logfmt', 'syslog', 'plain']);
const sourceStatuses = new Set<GenericLogSourceStatusValue>([
  'fresh', 'no_data', 'truncated', 'unsupported', 'permission_denied', 'failed',
]);
const errorClasses = new Set([
  'unsupported', 'permission_denied', 'timeout', 'command_failed',
  'output_limit', 'read_failed', 'unsafe_source',
]);
const successStatuses = new Set<GenericLogSourceStatusValue>(['fresh', 'no_data', 'truncated']);

const safeIdPattern = /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$/;
const rawContainerIdPattern = /^[0-9a-f]{32,64}$/i;
const safeFieldPattern = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const secretKeyPattern = /(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|pwd|secret|token|access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|apikey|client[-_]?secret|session[-_]?(?:id)?|private[-_]?key|access[-_]?key(?:[-_]?id)?)/i;
const obviousSecretPattern = /(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|SECRET)|(?:authorization|password|passwd|pwd|secret|token|api[-_]?key|client[-_]?secret|session(?:id)?)\s*[:=]\s*(?!\[REDACTED(?:_[A-Z]+)?\])\S+|\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b)/i;
const secretAssignmentPrefixPattern = /(?:^|[^A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,127}(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|pwd|secret|token|access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|apikey|client[-_]?secret|session[-_]?(?:id)?|private[-_]?key|access[-_]?key(?:[-_]?id)?)[A-Za-z0-9_.-]{0,127}\s*[:=]\s*/gimu;
const obviousPersonalDataPattern = /(?:\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}\b|(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])|(?<![0-9])(?:\+82[- ]?|0)10[- ]?[0-9]{3,4}[- ]?[0-9]{4}(?![0-9]))/;
const ipv6CandidatePattern = /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])/gu;
const cardCandidatePattern = /(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])/gu;

export type GenericLogSourceKind = 'docker' | 'file' | 'journald';
export type GenericLogPriority = 'debug' | 'normal' | 'incident' | 'security';
export type GenericLogSeverity = 'trace' | 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical';
export type GenericLogParser = 'json' | 'logfmt' | 'syslog' | 'plain';
export type GenericLogSourceStatusValue =
  | 'fresh'
  | 'no_data'
  | 'truncated'
  | 'unsupported'
  | 'permission_denied'
  | 'failed';
export type GenericLogCollectionStatus =
  | 'fresh'
  | 'degraded'
  | 'stale'
  | 'no_data'
  | 'unsupported'
  | 'collection_error';

export interface GenericLogRecord {
  schemaVersion: 1;
  timestamp: string;
  observedAt: string;
  timestampSource: 'event' | 'observed';
  sourceKind: GenericLogSourceKind;
  sourceId: string;
  priority: GenericLogPriority;
  severity: GenericLogSeverity;
  parser: GenericLogParser;
  message: string;
  truncated: boolean;
  multilineLineCount: number;
  hostId: string | null;
  containerName: string | null;
  composeProject: string | null;
  composeService: string | null;
  processName: string | null;
  systemdUnit: string | null;
  stream: 'stdout' | 'stderr' | null;
  fields: Record<string, string | number | boolean | null>;
  redactionVersion: 'monitor-log-redaction-v2';
}

export interface GenericLogSourceStatus {
  schemaVersion: 1;
  sourceId: string;
  sourceKind: GenericLogSourceKind;
  status: GenericLogSourceStatusValue;
  observedAt: string;
  lastSuccessAt: string | null;
  errorClass: string | null;
  seenLines: number;
  seenBytes: number;
  parsedEvents: number;
  admittedEvents: number;
  droppedLines: number;
  dropped: Record<(typeof dropFields)[number], number>;
}

export interface GenericLogQuery {
  limit?: number;
  cursor?: string;
  text?: string;
  sourceIds?: string[];
  sourceKinds?: GenericLogSourceKind[];
  priorities?: GenericLogPriority[];
  severities?: GenericLogSeverity[];
  from?: string;
  to?: string;
}

interface NormalizedQuery {
  limit: number;
  cursor: string | null;
  text: string | null;
  sourceIds: string[];
  sourceKinds: GenericLogSourceKind[];
  priorities: GenericLogPriority[];
  severities: GenericLogSeverity[];
  from: string | null;
  to: string | null;
}

type CursorBoundQuery = Omit<NormalizedQuery, 'limit' | 'cursor'>;

export interface GenericLogPage {
  schemaVersion: 1;
  generatedAt: string;
  collection: {
    status: GenericLogCollectionStatus;
    observedAt: string | null;
    sources: GenericLogSourceStatus[];
  };
  query: Omit<NormalizedQuery, 'cursor'>;
  items: GenericLogRecord[];
  page: {
    limit: number;
    returned: number;
    total: number;
    nextCursor: string | null;
    cursorStatus: 'current' | 'stale';
  };
}

interface StrictRead {
  status: 'ok' | 'unavailable' | 'collection_error';
  content: string | null;
  digest: string | null;
}

interface StrictOpenedFile {
  descriptor: number;
  cacheKey: string;
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  uid: number;
  mode: number;
  nlink: number;
}

interface StrictOpen {
  status: StrictRead['status'];
  file: StrictOpenedFile | null;
}

type CachedGenericLogRecord = GenericLogRecord & {
  _index: number;
  _searchText: string;
  _timestampMs: number;
};

interface RecordSnapshotCacheEntry {
  status: 'ok' | 'collection_error';
  digest: string;
  records: CachedGenericLogRecord[];
}

const MAX_RECORD_SNAPSHOT_CACHE_ENTRIES = 1;
const recordSnapshotCache = new Map<string, RecordSnapshotCacheEntry>();
let recordSnapshotParseCount = 0;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function canonicalTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) return null;
  return value;
}

function boundedCounter(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function safeIdentifier(value: unknown, allowRawHex = false): value is string {
  return typeof value === 'string'
    && safeIdPattern.test(value)
    && (allowRawHex || !rawContainerIdPattern.test(value))
    && !secretKeyPattern.test(value);
}

function safeOptionalIdentifier(value: unknown): value is string | null {
  return value === null || safeIdentifier(value);
}

function scalar(value: unknown): value is string | number | boolean | null {
  return value === null
    || typeof value === 'string'
    || typeof value === 'boolean'
    || (typeof value === 'number' && Number.isFinite(value));
}

function luhnValid(value: string): boolean {
  const digits = [...value].filter((character) => /[0-9]/u.test(character)).map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  const parity = digits.length % 2;
  const total = digits.reduce((sum, rawDigit, index) => {
    let digit = rawDigit;
    if (index % 2 === parity) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    return sum + digit;
  }, 0);
  return total % 10 === 0;
}

function containsObviousPersonalData(value: string): boolean {
  if (obviousPersonalDataPattern.test(value)) return true;
  ipv6CandidatePattern.lastIndex = 0;
  for (const match of value.matchAll(ipv6CandidatePattern)) {
    if (isIP(match[0]) === 6) return true;
  }
  cardCandidatePattern.lastIndex = 0;
  return [...value.matchAll(cardCandidatePattern)].some((match) => luhnValid(match[0]));
}

function containsUnsafeSecretAssignment(value: string): boolean {
  secretAssignmentPrefixPattern.lastIndex = 0;
  for (const match of value.matchAll(secretAssignmentPrefixPattern)) {
    const start = (match.index ?? 0) + match[0].length;
    const lineEnd = value.indexOf('\n', start);
    const remainder = value.slice(start, lineEnd < 0 ? value.length : lineEnd);
    if (!/^\[REDACTED(?:_[A-Z]+)?\]\s*$/u.test(remainder)) return true;
  }
  return false;
}

export function normalizeGenericLogRecord(value: unknown): GenericLogRecord | null {
  if (!isRecord(value) || !hasExactKeys(value, recordFields)) return null;
  if (
    value.schemaVersion !== 1
    || canonicalTimestamp(value.timestamp) === null
    || canonicalTimestamp(value.observedAt) === null
    || (value.timestampSource !== 'event' && value.timestampSource !== 'observed')
    || !sourceKinds.has(value.sourceKind as GenericLogSourceKind)
    || !safeIdentifier(value.sourceId)
    || !priorities.has(value.priority as GenericLogPriority)
    || !severities.has(value.severity as GenericLogSeverity)
    || !parsers.has(value.parser as GenericLogParser)
    || typeof value.message !== 'string'
    || Buffer.byteLength(value.message) > MAX_LINE_BYTES
    || obviousSecretPattern.test(value.message)
    || containsUnsafeSecretAssignment(value.message)
    || containsObviousPersonalData(value.message)
    || typeof value.truncated !== 'boolean'
    || !Number.isInteger(value.multilineLineCount)
    || (value.multilineLineCount as number) < 1
    || (value.multilineLineCount as number) > 1024
    || !safeOptionalIdentifier(value.containerName)
    || !safeOptionalIdentifier(value.composeProject)
    || !safeOptionalIdentifier(value.composeService)
    || !safeOptionalIdentifier(value.processName)
    || !safeOptionalIdentifier(value.systemdUnit)
    || (value.stream !== null && value.stream !== 'stdout' && value.stream !== 'stderr')
    || value.redactionVersion !== 'monitor-log-redaction-v2'
  ) return null;
  if (value.hostId !== null) {
    if (typeof value.hostId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.hostId)) {
      return null;
    }
  }
  if (!isRecord(value.fields) || Object.keys(value.fields).length > 16) return null;
  const fields: Record<string, string | number | boolean | null> = {};
  for (const [key, fieldValue] of Object.entries(value.fields)) {
    if (!safeFieldPattern.test(key) || secretKeyPattern.test(key) || !scalar(fieldValue)) return null;
    if (typeof fieldValue === 'string' && (
      obviousSecretPattern.test(fieldValue)
      || containsUnsafeSecretAssignment(fieldValue)
      || containsObviousPersonalData(fieldValue)
    )) return null;
    fields[key] = fieldValue;
  }
  return {
    schemaVersion: 1,
    timestamp: value.timestamp as string,
    observedAt: value.observedAt as string,
    timestampSource: value.timestampSource as 'event' | 'observed',
    sourceKind: value.sourceKind as GenericLogSourceKind,
    sourceId: value.sourceId as string,
    priority: value.priority as GenericLogPriority,
    severity: value.severity as GenericLogSeverity,
    parser: value.parser as GenericLogParser,
    message: value.message,
    truncated: value.truncated,
    multilineLineCount: value.multilineLineCount as number,
    hostId: value.hostId as string | null,
    containerName: value.containerName as string | null,
    composeProject: value.composeProject as string | null,
    composeService: value.composeService as string | null,
    processName: value.processName as string | null,
    systemdUnit: value.systemdUnit as string | null,
    stream: value.stream as 'stdout' | 'stderr' | null,
    fields,
    redactionVersion: 'monitor-log-redaction-v2',
  };
}

function normalizeSourceStatus(value: unknown): GenericLogSourceStatus | null {
  if (!isRecord(value) || !hasExactKeys(value, sourceStatusFields)) return null;
  if (
    value.schemaVersion !== 1
    || !safeIdentifier(value.sourceId)
    || !sourceKinds.has(value.sourceKind as GenericLogSourceKind)
    || !sourceStatuses.has(value.status as GenericLogSourceStatusValue)
    || canonicalTimestamp(value.observedAt) === null
    || (value.lastSuccessAt !== null && canonicalTimestamp(value.lastSuccessAt) === null)
    || (value.errorClass !== null && (typeof value.errorClass !== 'string' || !errorClasses.has(value.errorClass)))
  ) return null;
  const status = value.status as GenericLogSourceStatusValue;
  if (successStatuses.has(status)) {
    if (value.lastSuccessAt === null || (value.errorClass !== null && value.errorClass !== 'output_limit')) return null;
  } else if (value.errorClass === null) return null;
  for (const field of ['seenLines', 'seenBytes', 'parsedEvents', 'admittedEvents', 'droppedLines']) {
    if (!boundedCounter(value[field])) return null;
  }
  if (!isRecord(value.dropped) || !hasExactKeys(value.dropped, dropFields)) return null;
  const dropped = {} as Record<(typeof dropFields)[number], number>;
  let droppedTotal = 0;
  for (const key of dropFields) {
    const count = value.dropped[key];
    if (!boundedCounter(count)) return null;
    dropped[key] = count;
    droppedTotal += count;
  }
  if (droppedTotal !== value.droppedLines) return null;
  return {
    schemaVersion: 1,
    sourceId: value.sourceId as string,
    sourceKind: value.sourceKind as GenericLogSourceKind,
    status,
    observedAt: value.observedAt as string,
    lastSuccessAt: value.lastSuccessAt as string | null,
    errorClass: value.errorClass as string | null,
    seenLines: value.seenLines as number,
    seenBytes: value.seenBytes as number,
    parsedEvents: value.parsedEvents as number,
    admittedEvents: value.admittedEvents as number,
    droppedLines: value.droppedLines as number,
    dropped,
  };
}

function isInside(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === '' || (!child.startsWith(`..${sep}`) && child !== '..' && !child.startsWith(sep));
}

function trustedDataRootOwnerUid(root: string): number | null {
  try {
    const before = lstatSync(root);
    if (
      !before.isDirectory()
      || before.isSymbolicLink()
      || before.nlink < 1
      || (before.mode & 0o022) !== 0
      || !Number.isSafeInteger(before.uid)
      || before.uid < 0
    ) return null;
    const realRoot = realpathSync(root);
    if (realRoot !== root) return null;
    const after = lstatSync(root);
    if (
      !after.isDirectory()
      || after.isSymbolicLink()
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.uid !== before.uid
      || after.gid !== before.gid
      || after.mode !== before.mode
      || after.nlink !== before.nlink
    ) return null;
    return before.uid;
  } catch {
    return null;
  }
}

function openStrictFile(
  root: string,
  fileName: string,
  maximumBytes: number,
  expectedOwnerUid: number,
): StrictOpen {
  const path = join(root, fileName);
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return { status: 'unavailable', file: null };
  }
  let before: ReturnType<typeof lstatSync>;
  try {
    before = lstatSync(path);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT'
      ? { status: 'unavailable', file: null }
      : { status: 'collection_error', file: null };
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || before.uid !== expectedOwnerUid
    || (before.mode & 0o027) !== 0
    || before.size > maximumBytes
  ) return { status: 'collection_error', file: null };
  let descriptor: number | undefined;
  try {
    const realPath = realpathSync(path);
    if (!isInside(realRoot, realPath)) return { status: 'collection_error', file: null };
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile()
      || opened.nlink !== 1
      || opened.uid !== expectedOwnerUid
      || (opened.mode & 0o027) !== 0
      || opened.dev !== before.dev
      || opened.ino !== before.ino
      || opened.size !== before.size
      || opened.uid !== before.uid
      || opened.mode !== before.mode
      || opened.nlink !== before.nlink
      || opened.mtimeMs !== before.mtimeMs
      || opened.ctimeMs !== before.ctimeMs
      || opened.size > maximumBytes
    ) return { status: 'collection_error', file: null };
    const transferredDescriptor = descriptor;
    descriptor = undefined;
    return {
      status: 'ok',
      file: {
        descriptor: transferredDescriptor,
        cacheKey: JSON.stringify([
          realRoot,
          realPath,
          expectedOwnerUid,
          opened.dev,
          opened.ino,
          opened.size,
          opened.mtimeMs,
          opened.ctimeMs,
          opened.uid,
          opened.mode,
          opened.nlink,
        ]),
        dev: opened.dev,
        ino: opened.ino,
        size: opened.size,
        mtimeMs: opened.mtimeMs,
        ctimeMs: opened.ctimeMs,
        uid: opened.uid,
        mode: opened.mode,
        nlink: opened.nlink,
      },
    };
  } catch {
    return { status: 'collection_error', file: null };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function openedFileIsUnchanged(file: StrictOpenedFile): boolean {
  try {
    const after = fstatSync(file.descriptor);
    return after.isFile()
      && after.dev === file.dev
      && after.ino === file.ino
      && after.size === file.size
      && after.mtimeMs === file.mtimeMs
      && after.ctimeMs === file.ctimeMs
      && after.uid === file.uid
      && after.mode === file.mode
      && after.nlink === file.nlink;
  } catch {
    return false;
  }
}

function readOpenedStrictFile(file: StrictOpenedFile, maximumBytes: number): StrictRead {
  try {
    const payload = readFileSync(file.descriptor);
    if (
      payload.length !== file.size
      || payload.length > maximumBytes
      || !openedFileIsUnchanged(file)
    ) return { status: 'collection_error', content: null, digest: null };
    let content: string;
    try {
      content = new TextDecoder('utf-8', { fatal: true }).decode(payload);
    } catch {
      return { status: 'collection_error', content: null, digest: null };
    }
    return {
      status: 'ok',
      content,
      digest: createHash('sha256').update(payload).digest('hex'),
    };
  } catch {
    return { status: 'collection_error', content: null, digest: null };
  } finally {
    closeSync(file.descriptor);
  }
}

function readStrictFile(
  root: string,
  fileName: string,
  maximumBytes: number,
  expectedOwnerUid: number,
): StrictRead {
  const opened = openStrictFile(root, fileName, maximumBytes, expectedOwnerUid);
  if (opened.status !== 'ok' || opened.file === null) {
    return { status: opened.status, content: null, digest: null };
  }
  return readOpenedStrictFile(opened.file, maximumBytes);
}

function cachedRecordSnapshot(cacheKey: string): RecordSnapshotCacheEntry | null {
  const cached = recordSnapshotCache.get(cacheKey);
  if (!cached) return null;
  recordSnapshotCache.delete(cacheKey);
  recordSnapshotCache.set(cacheKey, cached);
  return cached;
}

function storeRecordSnapshot(cacheKey: string, entry: RecordSnapshotCacheEntry): void {
  recordSnapshotCache.delete(cacheKey);
  recordSnapshotCache.set(cacheKey, entry);
  while (recordSnapshotCache.size > MAX_RECORD_SNAPSHOT_CACHE_ENTRIES) {
    const oldest = recordSnapshotCache.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    recordSnapshotCache.delete(oldest);
  }
}

export function clearGenericLogSnapshotCacheForTests(): void {
  recordSnapshotCache.clear();
  recordSnapshotParseCount = 0;
}

export function genericLogSnapshotCacheStatsForTests(): {
  entries: number;
  parsedSnapshots: number;
} {
  return {
    entries: recordSnapshotCache.size,
    parsedSnapshots: recordSnapshotParseCount,
  };
}

function readRecords(root: string, expectedOwnerUid: number): {
  status: StrictRead['status']; records: CachedGenericLogRecord[]; digest: string | null;
} {
  const opened = openStrictFile(root, 'generic-logs.jsonl', MAX_LOG_BYTES, expectedOwnerUid);
  if (opened.status !== 'ok' || opened.file === null) {
    recordSnapshotCache.clear();
    return { status: opened.status, records: [], digest: null };
  }
  const cached = cachedRecordSnapshot(opened.file.cacheKey);
  if (cached !== null) {
    closeSync(opened.file.descriptor);
    return { status: cached.status, records: cached.records, digest: cached.digest };
  }
  recordSnapshotCache.clear();
  const cacheKey = opened.file.cacheKey;
  const file = readOpenedStrictFile(opened.file, MAX_LOG_BYTES);
  if (file.status !== 'ok' || file.content === null || file.digest === null) {
    return { status: file.status, records: [], digest: file.digest };
  }
  recordSnapshotParseCount += 1;
  const records: CachedGenericLogRecord[] = [];
  const lines = file.content.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (!line) continue;
    if (Buffer.byteLength(line) > MAX_LINE_BYTES || records.length >= MAX_RECORDS) {
      storeRecordSnapshot(cacheKey, { status: 'collection_error', digest: file.digest, records: [] });
      return { status: 'collection_error', records: [], digest: file.digest };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      storeRecordSnapshot(cacheKey, { status: 'collection_error', digest: file.digest, records: [] });
      return { status: 'collection_error', records: [], digest: file.digest };
    }
    const normalized = normalizeGenericLogRecord(parsed);
    if (normalized === null) {
      storeRecordSnapshot(cacheKey, { status: 'collection_error', digest: file.digest, records: [] });
      return { status: 'collection_error', records: [], digest: file.digest };
    }
    records.push({
      ...normalized,
      _index: index,
      _searchText: searchable(normalized),
      _timestampMs: new Date(normalized.timestamp).getTime(),
    });
  }
  records.sort((left, right) => (
    right.timestamp.localeCompare(left.timestamp) || right._index - left._index
  ));
  storeRecordSnapshot(cacheKey, { status: 'ok', digest: file.digest, records });
  return { status: 'ok', records, digest: file.digest };
}

function readStatuses(root: string, expectedOwnerUid: number): {
  status: StrictRead['status']; generatedAt: string | null; sources: GenericLogSourceStatus[];
} {
  const file = readStrictFile(root, 'generic-log-sources.json', MAX_STATUS_BYTES, expectedOwnerUid);
  if (file.status !== 'ok' || file.content === null) {
    return { status: file.status, generatedAt: null, sources: [] };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(file.content);
  } catch {
    return { status: 'collection_error', generatedAt: null, sources: [] };
  }
  if (
    !isRecord(parsed)
    || !hasExactKeys(parsed, ['schemaVersion', 'generatedAt', 'sources'])
    || parsed.schemaVersion !== 1
    || canonicalTimestamp(parsed.generatedAt) === null
    || !Array.isArray(parsed.sources)
    || parsed.sources.length > 64
  ) return { status: 'collection_error', generatedAt: null, sources: [] };
  const sources: GenericLogSourceStatus[] = [];
  const identifiers = new Set<string>();
  for (const value of parsed.sources) {
    const normalized = normalizeSourceStatus(value);
    if (normalized === null || identifiers.has(normalized.sourceId)) {
      return { status: 'collection_error', generatedAt: null, sources: [] };
    }
    identifiers.add(normalized.sourceId);
    sources.push(normalized);
  }
  return { status: 'ok', generatedAt: parsed.generatedAt as string, sources };
}

function readFailureMarker(root: string, expectedOwnerUid: number): {
  status: 'none' | 'present' | 'collection_error'; observedAt: string | null;
} {
  const file = readStrictFile(
    root,
    'generic-log-collection-error.json',
    MAX_FAILURE_MARKER_BYTES,
    expectedOwnerUid,
  );
  if (file.status === 'unavailable') return { status: 'none', observedAt: null };
  if (file.status !== 'ok' || file.content === null) {
    return { status: 'collection_error', observedAt: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(file.content);
  } catch {
    return { status: 'collection_error', observedAt: null };
  }
  if (
    !isRecord(parsed)
    || !hasExactKeys(parsed, ['schemaVersion', 'observedAt', 'errorClass'])
    || parsed.schemaVersion !== 1
    || canonicalTimestamp(parsed.observedAt) === null
    || !['unsafe_config', 'collection_failed', 'persistence_failed'].includes(
      parsed.errorClass as string,
    )
  ) return { status: 'collection_error', observedAt: null };
  return { status: 'present', observedAt: parsed.observedAt as string };
}

function normalizeStringArray<T extends string>(
  value: unknown,
  allowed: Set<T> | null,
  validator?: (item: unknown) => item is T,
): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_FILTER_VALUES) throw new GenericLogQueryError('invalid_filter');
  const output: T[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || (allowed && !allowed.has(item as T)) || (validator && !validator(item))) {
      throw new GenericLogQueryError('invalid_filter');
    }
    if (!output.includes(item as T)) output.push(item as T);
  }
  return output;
}

function normalizeQuery(value: GenericLogQuery): NormalizedQuery {
  const limit = value.limit ?? 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) throw new GenericLogQueryError('invalid_limit');
  let text: string | null = null;
  if (value.text !== undefined) {
    if (typeof value.text !== 'string' || Buffer.byteLength(value.text) > MAX_QUERY_BYTES || /[\u0000-\u001f\u007f]/.test(value.text)) {
      throw new GenericLogQueryError('invalid_text');
    }
    const normalized = value.text.normalize('NFKC').trim().toLocaleLowerCase('en-US');
    text = normalized || null;
  }
  const from = value.from === undefined ? null : canonicalTimestamp(value.from);
  const to = value.to === undefined ? null : canonicalTimestamp(value.to);
  if ((value.from !== undefined && from === null) || (value.to !== undefined && to === null)) {
    throw new GenericLogQueryError('invalid_time');
  }
  if (from && to && from > to) throw new GenericLogQueryError('invalid_time');
  if (value.cursor !== undefined && (typeof value.cursor !== 'string' || value.cursor.length > 512)) {
    throw new GenericLogQueryError('invalid_cursor');
  }
  return {
    limit,
    cursor: value.cursor ?? null,
    text,
    sourceIds: normalizeStringArray(value.sourceIds, null, safeIdentifier),
    sourceKinds: normalizeStringArray(value.sourceKinds, sourceKinds),
    priorities: normalizeStringArray(value.priorities, priorities),
    severities: normalizeStringArray(value.severities, severities),
    from,
    to,
  };
}

function cursorQueryFingerprint(query: NormalizedQuery): string {
  const canonicalQuery = {
    text: query.text,
    sourceIds: [...query.sourceIds].sort(),
    sourceKinds: [...query.sourceKinds].sort(),
    priorities: [...query.priorities].sort(),
    severities: [...query.severities].sort(),
    from: query.from,
    to: query.to,
  } satisfies CursorBoundQuery;
  return createHash('sha256').update(JSON.stringify({
    v: 1,
    query: canonicalQuery,
    sort: ['timestamp:desc', 'record-index:desc'],
  })).digest('hex');
}

function encodeCursor(digest: string, queryFingerprint: string, offset: number): string {
  return Buffer.from(JSON.stringify({ v: 2, d: digest, q: queryFingerprint, o: offset }), 'utf8').toString('base64url');
}

function decodeCursor(
  value: string | null,
  digest: string,
  queryFingerprint: string,
): { offset: number; status: 'current' | 'stale' } {
  if (value === null) return { offset: 0, status: 'current' };
  let parsed: unknown;
  try {
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value) throw new Error('non-canonical base64url');
    parsed = JSON.parse(decoded.toString('utf8'));
  } catch {
    throw new GenericLogQueryError('invalid_cursor');
  }
  if (
    !isRecord(parsed)
    || !hasExactKeys(parsed, ['v', 'd', 'q', 'o'])
    || parsed.v !== 2
    || typeof parsed.d !== 'string'
    || !/^[0-9a-f]{64}$/.test(parsed.d)
    || typeof parsed.q !== 'string'
    || !/^[0-9a-f]{64}$/.test(parsed.q)
    || !Number.isSafeInteger(parsed.o)
    || (parsed.o as number) < 0
  ) throw new GenericLogQueryError('invalid_cursor');
  if (parsed.q !== queryFingerprint) throw new GenericLogQueryError('invalid_cursor');
  return parsed.d === digest
    ? { offset: parsed.o as number, status: 'current' }
    : { offset: 0, status: 'stale' };
}

function searchable(record: GenericLogRecord): string {
  return [
    record.message,
    record.sourceId,
    record.containerName,
    record.composeProject,
    record.composeService,
    record.processName,
    record.systemdUnit,
    ...Object.entries(record.fields).flatMap(([key, value]) => [key, String(value)]),
  ].filter((value): value is string => typeof value === 'string')
    .join('\n')
    .normalize('NFKC')
    .toLocaleLowerCase('en-US');
}

function overallCollectionStatus(
  recordsStatus: StrictRead['status'],
  statusRead: ReturnType<typeof readStatuses>,
  failureMarker: ReturnType<typeof readFailureMarker>,
  nowMs: number,
): GenericLogCollectionStatus {
  if (failureMarker.status !== 'none') return 'collection_error';
  if (recordsStatus === 'collection_error' || statusRead.status === 'collection_error') return 'collection_error';
  if (recordsStatus === 'unavailable' && statusRead.status === 'unavailable') return 'no_data';
  if (recordsStatus !== 'ok' || statusRead.status !== 'ok' || statusRead.generatedAt === null) return 'collection_error';
  const generatedMs = new Date(statusRead.generatedAt).getTime();
  if (generatedMs > nowMs + FUTURE_SKEW_MS || nowMs - generatedMs > SOURCE_STALE_MS) return 'stale';
  if (statusRead.sources.length === 0) return 'no_data';
  if (statusRead.sources.every((source) => source.status === 'unsupported')) return 'unsupported';
  if (statusRead.sources.some((source) => !successStatuses.has(source.status))) return 'degraded';
  if (statusRead.sources.some((source) => source.status === 'truncated')) return 'degraded';
  if (statusRead.sources.every((source) => source.status === 'no_data')) return 'no_data';
  return 'fresh';
}

export class GenericLogQueryError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'GenericLogQueryError';
  }
}

export function readGenericLogPage(
  dataDirectory: string,
  query: GenericLogQuery = {},
  nowMs = Date.now(),
  expectedOwnerUid?: number,
): GenericLogPage {
  const normalizedQuery = normalizeQuery(query);
  const root = resolve(dataDirectory);
  const ownerUid = expectedOwnerUid ?? trustedDataRootOwnerUid(root) ?? -1;
  const recordRead = readRecords(root, ownerUid);
  const statusRead = readStatuses(root, ownerUid);
  const failureMarker = readFailureMarker(root, ownerUid);
  const collectionStatus = overallCollectionStatus(
    recordRead.status,
    statusRead,
    failureMarker,
    nowMs,
  );
  const digest = recordRead.digest ?? createHash('sha256').update('').digest('hex');
  const queryFingerprint = cursorQueryFingerprint(normalizedQuery);
  const cursor = decodeCursor(normalizedQuery.cursor, digest, queryFingerprint);
  const { cursor: _privateCursor, ...publicQuery } = normalizedQuery;
  if (cursor.status === 'stale') {
    return {
      schemaVersion: 1,
      generatedAt: new Date(nowMs).toISOString(),
      collection: {
        status: collectionStatus,
        observedAt: failureMarker.observedAt ?? statusRead.generatedAt,
        sources: statusRead.sources,
      },
      query: publicQuery,
      items: [],
      page: { limit: normalizedQuery.limit, returned: 0, total: 0, nextCursor: null, cursorStatus: 'stale' },
    };
  }
  let records = collectionStatus === 'collection_error' ? [] : recordRead.records;
  const sourceFilter = new Set(normalizedQuery.sourceIds);
  const kindFilter = new Set(normalizedQuery.sourceKinds);
  const priorityFilter = new Set(normalizedQuery.priorities);
  const severityFilter = new Set(normalizedQuery.severities);
  const fromMs = normalizedQuery.from ? new Date(normalizedQuery.from).getTime() : Number.NEGATIVE_INFINITY;
  const toMs = normalizedQuery.to ? new Date(normalizedQuery.to).getTime() : Number.POSITIVE_INFINITY;
  records = records.filter((record) => {
    return record._timestampMs >= fromMs
      && record._timestampMs <= toMs
      && record._timestampMs <= nowMs + FUTURE_SKEW_MS
      && (!sourceFilter.size || sourceFilter.has(record.sourceId))
      && (!kindFilter.size || kindFilter.has(record.sourceKind))
      && (!priorityFilter.size || priorityFilter.has(record.priority))
      && (!severityFilter.size || severityFilter.has(record.severity))
      && (!normalizedQuery.text || record._searchText.includes(normalizedQuery.text));
  });
  const total = records.length;
  const start = Math.min(cursor.offset, total);
  const selected = records.slice(start, start + normalizedQuery.limit).map(({
    _index: _ignoredIndex,
    _searchText: _ignoredSearchText,
    _timestampMs: _ignoredTimestamp,
    ...record
  }) => ({ ...record, fields: { ...record.fields } }));
  const nextOffset = start + selected.length;
  const nextCursor = nextOffset < total
    ? encodeCursor(digest, queryFingerprint, nextOffset)
    : null;
  return {
    schemaVersion: 1,
    generatedAt: new Date(nowMs).toISOString(),
    collection: {
      status: collectionStatus,
      observedAt: failureMarker.observedAt ?? statusRead.generatedAt,
      sources: statusRead.sources,
    },
    query: publicQuery,
    items: selected,
    page: {
      limit: normalizedQuery.limit,
      returned: selected.length,
      total,
      nextCursor,
      cursorStatus: 'current',
    },
  };
}

export const genericLogLimits = {
  maximumLogBytes: MAX_LOG_BYTES,
  maximumStatusBytes: MAX_STATUS_BYTES,
  maximumLineBytes: MAX_LINE_BYTES,
  maximumRecords: MAX_RECORDS,
  maximumPageSize: MAX_PAGE_SIZE,
};
