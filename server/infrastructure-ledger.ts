import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import type {
  InfrastructureLedgerCategory,
  InfrastructureLedgerApplicability,
  InfrastructureLedgerConfidence,
  InfrastructureLedgerCsfFunction,
  InfrastructureLedgerEntry,
  InfrastructureLedgerEvidence,
  InfrastructureLedgerImpact,
  InfrastructureLedgerPriority,
  InfrastructureLedgerReference,
  InfrastructureLedgerResponse,
  InfrastructureLedgerSensitivity,
  InfrastructureLedgerStatus,
  InfrastructureLedgerText,
  InfrastructureLedgerVerification,
  InfrastructureLedgerWorkType,
} from './types.js';

const LEDGER_FILE = 'infrastructure-ledger.json';
const MAX_LEDGER_BYTES = 16 * 1024 * 1024;
const MAX_ENTRIES = 5_000;
const MAX_REFERENCES = 256;
const MAX_EVIDENCE_PER_ENTRY = 24;
const MAX_RELATED_IDS = 32;
const MAX_SCOPE_VALUES = 24;
const MAX_COVERAGE_SOURCES = 64;
const MAX_LIMITATIONS = 32;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;

const CATEGORIES = new Set<InfrastructureLedgerCategory>([
  'network',
  'security',
  'identity-access',
  'dns-edge',
  'reliability',
  'compute-kernel',
  'storage-filesystem',
  'backup-recovery',
  'observability-logging',
  'service-deployment',
  'containers',
  'packages-firmware',
  'governance-documentation',
  'hardware-physical',
]);
const STATUSES = new Set<InfrastructureLedgerStatus>([
  'completed',
  'in-progress',
  'pending',
  'deferred',
  'recommended',
  'observed',
  'superseded',
  'not-applicable',
]);
const WORK_TYPES = new Set<InfrastructureLedgerWorkType>([
  'change',
  'configuration',
  'audit',
  'hardening',
  'mitigation',
  'update',
  'verification',
  'incident',
  'maintenance',
  'recommendation',
  'decision',
  'documentation',
]);
const PRIORITIES = new Set<InfrastructureLedgerPriority>([
  'critical', 'high', 'medium', 'low', 'informational',
]);
const CONFIDENCE = new Set<InfrastructureLedgerConfidence>([
  'current-state', 'documented', 'inferred', 'recommendation',
]);
const VERIFICATION = new Set<InfrastructureLedgerVerification>([
  'verified', 'partially-verified', 'unverified', 'not-applicable',
]);
const APPLICABILITY = new Set<InfrastructureLedgerApplicability>([
  'applicable', 'needs-assessment', 'not-applicable',
]);
const IMPACTS = new Set<InfrastructureLedgerImpact>([
  'none', 'observed-none', 'low', 'brief', 'maintenance-window-required', 'unknown',
]);
const SENSITIVITY = new Set<InfrastructureLedgerSensitivity>([
  'public', 'internal', 'restricted',
]);
const CSF_FUNCTIONS = new Set<InfrastructureLedgerCsfFunction>([
  'govern', 'identify', 'protect', 'detect', 'respond', 'recover',
]);
const EVIDENCE_KINDS = new Set<InfrastructureLedgerEvidence['kind']>([
  'runtime', 'file', 'journal', 'package-log', 'repository', 'session', 'standard', 'operator',
]);

type JsonRecord = Record<string, unknown>;

const ROOT_FIELDS = ['schemaVersion', 'updatedAt', 'coverage', 'references', 'entries'] as const;
const COVERAGE_FIELDS = ['from', 'through', 'sources', 'limitations'] as const;
const COVERAGE_SOURCE_FIELDS = ['id', 'label', 'from', 'through'] as const;
const REFERENCE_FIELDS = ['id', 'title', 'publisher', 'url', 'publishedAt', 'accessedAt'] as const;
const EVIDENCE_FIELDS = ['kind', 'reference', 'observedAt', 'note'] as const;
const ENTRY_FIELDS = [
  'id', 'itemKey', 'revision', 'occurredAt', 'recordedAt', 'category', 'workType',
  'status', 'priority', 'confidence', 'verification', 'applicability', 'impact',
  'sensitivity', 'csfFunctions', 'title', 'summary', 'rationale', 'details',
  'outcome', 'nextAction', 'actor', 'scope', 'evidence', 'referenceIds',
  'relatedIds', 'supersedes', 'dueAt', 'recurrence',
] as const;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(value: JsonRecord, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length
    && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
}

function readBoundedFile(root: string, fileName: string): string | null {
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return null;
  }
  const path = join(realRoot, fileName);

  let descriptor: number | undefined;
  try {
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) return null;
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(descriptor);
    if (
      !stat.isFile()
      || stat.dev !== before.dev
      || stat.ino !== before.ino
      || stat.nlink !== 1
      || (stat.mode & 0o022) !== 0
      || stat.size <= 0
      || stat.size > MAX_LEDGER_BYTES
    ) return null;
    return readFileSync(descriptor, 'utf8');
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function containsForbiddenMaterial(value: string): boolean {
  return /\bwgang\b/iu.test(value)
    || /-----BEGIN [^-]+ PRIVATE KEY-----/iu.test(value)
    || /\b(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+/iu.test(value)
    || /\b(?:gh[opsu]_|github_pat_)[A-Za-z0-9_]{20,}\b/u.test(value)
    || /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u.test(value)
    || /(?:https?|ssh):\/\/[^\s/@:]+:[^\s/@]+@/iu.test(value)
    || /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu.test(value)
    || /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/u.test(value);
}

function text(value: unknown, maximum: number): string | null {
  if (typeof value !== 'string' || containsForbiddenMaterial(value)) return null;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
  return cleaned && cleaned.length <= maximum ? cleaned : null;
}

function id(value: unknown): string | null {
  const cleaned = text(value, 128);
  return cleaned && /^[a-z0-9][a-z0-9._:-]{1,127}$/u.test(cleaned) ? cleaned : null;
}

function scopeValue(value: unknown): string | null {
  const cleaned = text(value, 64);
  return cleaned && /^[a-z0-9][a-z0-9._/-]{0,63}$/u.test(cleaned) ? cleaned : null;
}

function isoTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/u.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[7]!;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year < 1
    || month < 1
    || month > 12
    || day < 1
    || day > monthDays[month - 1]!
    || hour > 23
    || minute > 59
    || second > 59
  ) return null;
  if (zone !== 'Z') {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return null;
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || time < 0) return null;
  return new Date(time).toISOString();
}

function optionalTimestamp(value: unknown): string | null | undefined {
  if (value === null || value === undefined) return null;
  return isoTimestamp(value) ?? undefined;
}

function localizedText(value: unknown, maximum: number): InfrastructureLedgerText | null {
  if (!isRecord(value) || !hasExactFields(value, ['ko', 'en'])) return null;
  const ko = text(value.ko, maximum);
  const en = text(value.en, maximum);
  return ko && en ? { ko, en } : null;
}

function uniqueIds(value: unknown, maximum: number): string[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const values = value.map(id);
  if (values.some((candidate) => candidate === null)) return null;
  const unique = [...new Set(values as string[])];
  return unique.length === values.length ? unique : null;
}

function scopes(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_SCOPE_VALUES) return null;
  const values = value.map(scopeValue);
  if (values.some((candidate) => candidate === null)) return null;
  const unique = [...new Set(values as string[])];
  return unique.length === values.length ? unique : null;
}

function csfFunctions(value: unknown): InfrastructureLedgerCsfFunction[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > CSF_FUNCTIONS.size) return null;
  const values = value.map((candidate) => enumValue(candidate, CSF_FUNCTIONS));
  if (values.some((candidate) => candidate === null)) return null;
  const unique = [...new Set(values as InfrastructureLedgerCsfFunction[])];
  return unique.length === values.length ? unique : null;
}

function enumValue<T extends string>(value: unknown, accepted: Set<T>): T | null {
  return typeof value === 'string' && accepted.has(value as T) ? value as T : null;
}

function positiveInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function normalizeEvidence(value: unknown): InfrastructureLedgerEvidence | null {
  if (!isRecord(value) || !hasExactFields(value, EVIDENCE_FIELDS)) return null;
  const kind = enumValue(value.kind, EVIDENCE_KINDS);
  const reference = text(value.reference, 320);
  const observedAt = isoTimestamp(value.observedAt);
  const note = localizedText(value.note, 600);
  return kind && reference && observedAt && note
    ? { kind, reference, observedAt, note }
    : null;
}

function normalizeEntry(value: unknown): InfrastructureLedgerEntry | null {
  if (!isRecord(value) || !hasExactFields(value, ENTRY_FIELDS)) return null;
  const entryId = id(value.id);
  const itemKey = id(value.itemKey);
  const revision = positiveInteger(value.revision);
  const occurredAt = isoTimestamp(value.occurredAt);
  const recordedAt = isoTimestamp(value.recordedAt);
  const category = enumValue(value.category, CATEGORIES);
  const workType = enumValue(value.workType, WORK_TYPES);
  const status = enumValue(value.status, STATUSES);
  const priority = enumValue(value.priority, PRIORITIES);
  const confidence = enumValue(value.confidence, CONFIDENCE);
  const verification = enumValue(value.verification, VERIFICATION);
  const applicability = enumValue(value.applicability, APPLICABILITY);
  const impact = enumValue(value.impact, IMPACTS);
  const sensitivity = enumValue(value.sensitivity, SENSITIVITY);
  const entryCsfFunctions = csfFunctions(value.csfFunctions);
  const title = localizedText(value.title, 180);
  const summary = localizedText(value.summary, 800);
  const rationale = localizedText(value.rationale, 1_600);
  const details = localizedText(value.details, 4_000);
  const outcome = localizedText(value.outcome, 1_600);
  const nextAction = localizedText(value.nextAction, 1_600);
  const actor = text(value.actor, 96);
  const entryScopes = scopes(value.scope);
  const referenceIds = uniqueIds(value.referenceIds, MAX_REFERENCES);
  const relatedIds = uniqueIds(value.relatedIds, MAX_RELATED_IDS);
  const rawEvidence = Array.isArray(value.evidence) && value.evidence.length <= MAX_EVIDENCE_PER_ENTRY
    ? value.evidence
    : null;
  const evidence = rawEvidence?.map(normalizeEvidence) ?? null;
  const supersedes = value.supersedes === null || value.supersedes === undefined ? null : id(value.supersedes);
  const dueAt = optionalTimestamp(value.dueAt);
  const recurrence = value.recurrence === null || value.recurrence === undefined
    ? null
    : localizedText(value.recurrence, 300);

  if (
    !entryId || !itemKey || !revision || !occurredAt || !recordedAt || !category || !workType || !status
    || !priority || !confidence || !verification || !applicability || !impact || !sensitivity || !entryCsfFunctions
    || !title || !summary || !rationale || !details || !outcome || !nextAction || !actor
    || !entryScopes || !referenceIds || !relatedIds || !evidence
    || evidence.some((candidate) => candidate === null)
    || supersedes === null && value.supersedes !== null && value.supersedes !== undefined
    || dueAt === undefined
    || recurrence === null && value.recurrence !== null && value.recurrence !== undefined
  ) return null;
  if (occurredAt > recordedAt) return null;
  if (
    status === 'completed'
    && (verification !== 'verified' && verification !== 'partially-verified' || evidence.length === 0)
  ) return null;
  if (status === 'not-applicable' && applicability !== 'not-applicable') return null;

  return {
    id: entryId,
    itemKey,
    revision,
    occurredAt,
    recordedAt,
    category,
    workType,
    status,
    priority,
    confidence,
    verification,
    applicability,
    impact,
    sensitivity,
    csfFunctions: entryCsfFunctions,
    title,
    summary,
    rationale,
    details,
    outcome,
    nextAction,
    actor,
    scope: entryScopes,
    evidence: evidence as InfrastructureLedgerEvidence[],
    referenceIds,
    relatedIds,
    supersedes,
    dueAt: dueAt ?? null,
    recurrence,
  };
}

function normalizeReference(value: unknown): InfrastructureLedgerReference | null {
  if (!isRecord(value) || !hasExactFields(value, REFERENCE_FIELDS)) return null;
  const referenceId = id(value.id);
  const title = text(value.title, 240);
  const publisher = text(value.publisher, 160);
  const accessedAt = isoTimestamp(value.accessedAt);
  const publishedAt = optionalTimestamp(value.publishedAt);
  const rawUrl = text(value.url, 600);
  if (!referenceId || !title || !publisher || !accessedAt || publishedAt === undefined || !rawUrl) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href.length > 600) return null;
    return {
      id: referenceId,
      title,
      publisher,
      url: url.href,
      publishedAt: publishedAt ?? null,
      accessedAt,
    };
  } catch {
    return null;
  }
}

function normalizeCoverage(value: unknown): InfrastructureLedgerResponse['coverage'] | null {
  if (!isRecord(value) || !hasExactFields(value, COVERAGE_FIELDS)) return null;
  const from = optionalTimestamp(value.from);
  const through = isoTimestamp(value.through);
  const rawSources = Array.isArray(value.sources) && value.sources.length <= MAX_COVERAGE_SOURCES
    ? value.sources
    : null;
  const rawLimitations = Array.isArray(value.limitations) && value.limitations.length <= MAX_LIMITATIONS
    ? value.limitations
    : null;
  if (from === undefined || !through || !rawSources || !rawLimitations) return null;
  const sources = rawSources.map((candidate) => {
    if (!isRecord(candidate) || !hasExactFields(candidate, COVERAGE_SOURCE_FIELDS)) return null;
    const sourceId = id(candidate.id);
    const label = localizedText(candidate.label, 240);
    const sourceFrom = optionalTimestamp(candidate.from);
    const sourceThrough = optionalTimestamp(candidate.through);
    return sourceId && label && sourceFrom !== undefined && sourceThrough !== undefined
      ? { id: sourceId, label, from: sourceFrom ?? null, through: sourceThrough ?? null }
      : null;
  });
  const limitations = rawLimitations.map((candidate) => localizedText(candidate, 800));
  if (sources.some((candidate) => candidate === null) || limitations.some((candidate) => candidate === null)) return null;
  return {
    from: from ?? null,
    through,
    sources: sources as InfrastructureLedgerResponse['coverage']['sources'],
    limitations: limitations as InfrastructureLedgerText[],
  };
}

export function readInfrastructureLedger(
  dataDirectory: string,
  nowMs = Date.now(),
): InfrastructureLedgerResponse | null {
  const root = resolve(dataDirectory);
  const content = readBoundedFile(root, LEDGER_FILE);
  if (content === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!isRecord(parsed) || !hasExactFields(parsed, ROOT_FIELDS) || parsed.schemaVersion !== 1) return null;

  const updatedAt = isoTimestamp(parsed.updatedAt);
  const coverage = normalizeCoverage(parsed.coverage);
  const rawReferences = Array.isArray(parsed.references) && parsed.references.length <= MAX_REFERENCES
    ? parsed.references
    : null;
  const rawEntries = Array.isArray(parsed.entries) && parsed.entries.length <= MAX_ENTRIES
    ? parsed.entries
    : null;
  if (!updatedAt || !coverage || !rawReferences || !rawEntries) return null;

  const references = rawReferences.map(normalizeReference);
  const entries = rawEntries.map(normalizeEntry);
  if (references.some((candidate) => candidate === null) || entries.some((candidate) => candidate === null)) return null;

  const normalizedReferences = references as InfrastructureLedgerReference[];
  const normalizedEntries = entries as InfrastructureLedgerEntry[];
  const referenceIds = new Set(normalizedReferences.map((reference) => reference.id));
  const entryIds = new Set(normalizedEntries.map((entry) => entry.id));
  if (referenceIds.size !== normalizedReferences.length || entryIds.size !== normalizedEntries.length) return null;
  if (coverage.sources.length !== new Set(coverage.sources.map((source) => source.id)).size) return null;
  if (coverage.from !== null && coverage.from > coverage.through) return null;
  if (coverage.sources.some((source) => (
    source.from !== null && source.through !== null && source.from > source.through
  ))) return null;
  const futureBoundary = nowMs + MAX_FUTURE_SKEW_MS;
  const timestampIsFuture = (value: string | null): boolean => (
    value !== null && Date.parse(value) > futureBoundary
  );
  if (
    timestampIsFuture(updatedAt)
    || timestampIsFuture(coverage.from)
    || timestampIsFuture(coverage.through)
    || coverage.sources.some((source) => timestampIsFuture(source.from) || timestampIsFuture(source.through))
    || normalizedReferences.some((reference) => (
      timestampIsFuture(reference.publishedAt) || timestampIsFuture(reference.accessedAt)
    ))
    || normalizedEntries.some((entry) => (
      timestampIsFuture(entry.occurredAt)
      || timestampIsFuture(entry.recordedAt)
      || entry.evidence.some((evidence) => timestampIsFuture(evidence.observedAt))
    ))
  ) return null;
  if (
    normalizedEntries.length > 0
    && updatedAt < normalizedEntries.reduce((latest, entry) => (
      entry.recordedAt > latest ? entry.recordedAt : latest
    ), normalizedEntries[0]!.recordedAt)
  ) return null;
  if (
    normalizedEntries.length > 0
    && coverage.through < normalizedEntries.reduce((latest, entry) => (
      entry.recordedAt > latest ? entry.recordedAt : latest
    ), normalizedEntries[0]!.recordedAt)
  ) return null;

  const byId = new Map(normalizedEntries.map((entry) => [entry.id, entry]));
  const revisions = new Set<string>();
  for (const entry of normalizedEntries) {
    const revisionKey = `${entry.itemKey}\u0000${entry.revision}`;
    if (revisions.has(revisionKey)) return null;
    revisions.add(revisionKey);
    if (entry.referenceIds.some((referenceId) => !referenceIds.has(referenceId))) return null;
    if (entry.relatedIds.some((relatedId) => !entryIds.has(relatedId) || relatedId === entry.id)) return null;
    if (entry.supersedes) {
      const previous = byId.get(entry.supersedes);
      if (!previous || previous.id === entry.id || previous.itemKey !== entry.itemKey) return null;
      if (previous.revision + 1 !== entry.revision) return null;
      if (previous.occurredAt >= entry.occurredAt) return null;
    } else if (entry.revision !== 1) {
      return null;
    }
  }

  normalizedEntries.sort((left, right) => (
    right.occurredAt.localeCompare(left.occurredAt) || right.id.localeCompare(left.id)
  ));
  normalizedReferences.sort((left, right) => left.id.localeCompare(right.id));

  return {
    schemaVersion: 1,
    generatedAt: new Date(nowMs).toISOString(),
    updatedAt,
    limits: {
      usedBytes: Buffer.byteLength(content, 'utf8'),
      maximumBytes: MAX_LEDGER_BYTES,
      maximumEntries: MAX_ENTRIES,
      maximumReferences: MAX_REFERENCES,
    },
    coverage,
    references: normalizedReferences,
    entries: normalizedEntries,
  };
}

export const infrastructureLedgerLimits = {
  fileName: LEDGER_FILE,
  maximumBytes: MAX_LEDGER_BYTES,
  maximumEntries: MAX_ENTRIES,
  maximumReferences: MAX_REFERENCES,
} as const;
