import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const CATALOG_FILE = 'monitoring-catalog.json';
const MAX_CATALOG_BYTES = 2 * 1024 * 1024;
const MAX_EVIDENCE_SOURCES = 32;
const MAX_OBSERVATIONS = 128;
const MAX_RULES = 256;
const MAX_RULE_ALERT_BYTES = 32 * 1024 * 1024;

const DETAIL_PAGES = new Set<MonitoringCatalogDetailPage>([
  'resources', 'network', 'storage', 'containers', 'reliability',
  'maintenance', 'infrastructure', 'power', 'incidents', 'logs',
]);
const SOURCE_KINDS = new Set<MonitoringEvidenceKind>([
  'snapshot', 'time-series', 'event-log', 'state', 'source-status', 'external-state',
]);
const SOURCE_MODES = new Set<MonitoringSourceEvidenceMode>([
  'current-state', 'accumulated-log',
]);
const OBSERVATION_MODES = new Set<MonitoringObservationEvidenceMode>([
  'current-state', 'current-and-history', 'accumulated-log', 'mixed',
]);
const RETENTION_POLICIES = new Set<MonitoringRetentionPolicy>([
  'replace-on-collect', 'daily-age-and-count', 'bounded-record-count',
  'bounded-age-count-and-bytes', 'bounded-count-and-bytes',
  'replace-on-change', 'externally-managed',
]);
const PRUNE_CADENCES = new Set<MonitoringPruneCadence>([
  'replace-on-collection', 'every-collection', 'on-incident-write-or-daily',
  'every-rule-evaluation', 'every-generic-collection',
  'replace-on-generic-collection', 'replace-on-change', 'external-no-auto-prune',
]);
const RECORD_SCOPES = new Set<MonitoringRecordScope>(['artifact', 'daily-partition']);
const FORMATS = new Set<MonitoringEvidenceFormat>(['json', 'jsonl', 'api']);
const DOMAINS = new Set<MonitoringDomain>([
  'agent', 'host', 'resources', 'storage', 'network', 'reliability', 'power',
  'containers', 'synthetic', 'incidents', 'maintenance', 'logs', 'alerts',
  'monitoring', 'infrastructure',
]);
const OPERATORS = new Set<MonitoringRuleOperator>(['gt', 'gte', 'lt', 'lte', 'eq', 'neq']);
const SEVERITIES = new Set<MonitoringRuleSeverity>(['info', 'warning', 'critical']);
const NO_DATA_POLICIES = new Set<MonitoringRuleNoDataPolicy>(['ignore', 'alert']);
const SYNTHETIC_PROBE_INTERVAL_SECONDS = 5 * 60;
const PUBLIC_RULE_SCOPES = new Set([
  'agent', 'certificate', 'container', 'database', 'disk', 'docker',
  'endpoint', 'filesystem', 'hardware', 'host', 'job', 'monitor', 'network',
  'process', 'proxy', 'security', 'service', 'storage',
]);

const SOURCE_ARTIFACTS = new Map<string, {
  label: string;
  format: MonitoringEvidenceFormat;
  kind: MonitoringEvidenceKind;
  evidenceMode: MonitoringSourceEvidenceMode;
  retentionPolicy: MonitoringRetentionPolicy;
  pruneCadence: MonitoringPruneCadence;
  recordScope: MonitoringRecordScope | null;
}>([
  ['current-snapshot', { label: 'current.json', format: 'json', kind: 'snapshot', evidenceMode: 'current-state', retentionPolicy: 'replace-on-collect', pruneCadence: 'replace-on-collection', recordScope: 'artifact' }],
  ['telemetry-history', { label: 'history/YYYY-MM-DD.jsonl', format: 'jsonl', kind: 'time-series', evidenceMode: 'accumulated-log', retentionPolicy: 'daily-age-and-count', pruneCadence: 'every-collection', recordScope: 'daily-partition' }],
  ['semantic-alert-events', { label: 'alerts.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-record-count', pruneCadence: 'every-collection', recordScope: 'artifact' }],
  ['power-events', { label: 'power.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-record-count', pruneCadence: 'every-collection', recordScope: 'artifact' }],
  ['privilege-events', { label: 'privilege.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-record-count', pruneCadence: 'every-collection', recordScope: 'artifact' }],
  ['reliability-events', { label: 'reliability.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-record-count', pruneCadence: 'every-collection', recordScope: 'artifact' }],
  ['incident-events', { label: 'incidents.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-age-count-and-bytes', pruneCadence: 'on-incident-write-or-daily', recordScope: 'artifact' }],
  ['rule-evaluation-state', { label: 'rule-evaluation.json', format: 'json', kind: 'state', evidenceMode: 'current-state', retentionPolicy: 'replace-on-collect', pruneCadence: 'replace-on-collection', recordScope: 'artifact' }],
  ['rule-alert-events', { label: 'rule-alerts.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-count-and-bytes', pruneCadence: 'every-rule-evaluation', recordScope: 'artifact' }],
  ['generic-log-events', { label: 'generic-logs.jsonl', format: 'jsonl', kind: 'event-log', evidenceMode: 'accumulated-log', retentionPolicy: 'bounded-age-count-and-bytes', pruneCadence: 'every-generic-collection', recordScope: 'artifact' }],
  ['generic-log-source-state', { label: 'generic-log-sources.json', format: 'json', kind: 'source-status', evidenceMode: 'current-state', retentionPolicy: 'replace-on-collect', pruneCadence: 'replace-on-generic-collection', recordScope: 'artifact' }],
  ['system-update-state', { label: 'system-update.json', format: 'json', kind: 'external-state', evidenceMode: 'current-state', retentionPolicy: 'replace-on-change', pruneCadence: 'replace-on-change', recordScope: 'artifact' }],
  ['infrastructure-ledger', { label: 'infrastructure-ledger.json', format: 'json', kind: 'external-state', evidenceMode: 'current-state', retentionPolicy: 'externally-managed', pruneCadence: 'external-no-auto-prune', recordScope: 'artifact' }],
  ['agent-inventory', { label: 'agents API', format: 'api', kind: 'external-state', evidenceMode: 'current-state', retentionPolicy: 'externally-managed', pruneCadence: 'external-no-auto-prune', recordScope: null }],
]);

export const REQUIRED_MONITORING_OBSERVATION_IDS = [
  'agent.identity-heartbeat',
  'agent.remote-inventory',
  'host.identity-capacity',
  'resources.cpu-load-pressure',
  'resources.memory-swap-pressure',
  'resources.process-capacity',
  'resources.process-usage',
  'storage.filesystems-inodes',
  'storage.block-io',
  'storage.device-health',
  'network.interfaces-quality',
  'network.tcp-sockets',
  'network.application-traffic',
  'reliability.systemd-units',
  'reliability.clock-time-sync',
  'reliability.host-links',
  'reliability.kernel-events',
  'reliability.pcie',
  'reliability.nvme',
  'power.thermal-cooling',
  'power.platform-state',
  'containers.inventory-lifecycle',
  'containers.resources-limits',
  'containers.io-network',
  'containers.mount-network-surface',
  'containers.security-posture',
  'containers.image-integrity',
  'containers.docker-events',
  'synthetic.http-tls',
  'incidents.resource-windows',
  'system.versions-firmware',
  'maintenance.system-updates',
  'logs.semantic-events',
  'logs.generic-events',
  'logs.source-health',
  'alerts.rule-evaluation',
  'alerts.transitions-delivery',
  'monitoring.self-health',
  'infrastructure.change-ledger',
] as const;

export type MonitoringCatalogDetailPage =
  | 'resources' | 'network' | 'storage' | 'containers' | 'reliability'
  | 'maintenance' | 'infrastructure' | 'power' | 'incidents' | 'logs';
export type MonitoringEvidenceKind =
  | 'snapshot' | 'time-series' | 'event-log' | 'state' | 'source-status' | 'external-state';
export type MonitoringSourceEvidenceMode = 'current-state' | 'accumulated-log';
export type MonitoringObservationEvidenceMode =
  | 'current-state' | 'current-and-history' | 'accumulated-log' | 'mixed';
export type MonitoringRetentionPolicy =
  | 'replace-on-collect' | 'daily-age-and-count' | 'bounded-record-count'
  | 'bounded-age-count-and-bytes' | 'bounded-count-and-bytes'
  | 'replace-on-change' | 'externally-managed';
export type MonitoringPruneCadence =
  | 'replace-on-collection' | 'every-collection' | 'on-incident-write-or-daily'
  | 'every-rule-evaluation' | 'every-generic-collection'
  | 'replace-on-generic-collection' | 'replace-on-change' | 'external-no-auto-prune';
export type MonitoringRecordScope = 'artifact' | 'daily-partition';
export type MonitoringEvidenceFormat = 'json' | 'jsonl' | 'api';
export type MonitoringDomain =
  | 'agent' | 'host' | 'resources' | 'storage' | 'network' | 'reliability'
  | 'power' | 'containers' | 'synthetic' | 'incidents' | 'maintenance'
  | 'logs' | 'alerts' | 'monitoring' | 'infrastructure';
export type MonitoringRuleOperator = 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq';
export type MonitoringRuleSeverity = 'info' | 'warning' | 'critical';
export type MonitoringRuleNoDataPolicy = 'ignore' | 'alert';

export interface MonitoringLocalizedText {
  ko: string;
  en: string;
}

export interface MonitoringRetention {
  policy: MonitoringRetentionPolicy;
  pruneCadence: MonitoringPruneCadence;
  maxAgeDays: number | null;
  maxRecords: number | null;
  recordScope: MonitoringRecordScope | null;
  maxBytes: number | null;
}

export interface MonitoringEvidenceSource {
  id: string;
  displayName: MonitoringLocalizedText;
  description: MonitoringLocalizedText;
  kind: MonitoringEvidenceKind;
  evidenceMode: MonitoringSourceEvidenceMode;
  artifactLabel: string;
  format: MonitoringEvidenceFormat;
  cadenceSeconds: number | null;
  retention: MonitoringRetention;
  detailPages: MonitoringCatalogDetailPage[];
}

export interface MonitoringObservation {
  id: string;
  domain: MonitoringDomain;
  displayName: MonitoringLocalizedText;
  description: MonitoringLocalizedText;
  evidenceMode: MonitoringObservationEvidenceMode;
  cadenceSeconds: number | null;
  evidenceSourceIds: string[];
  detailPages: MonitoringCatalogDetailPage[];
}

export interface MonitoringCatalogRule {
  id: string;
  domain: MonitoringDomain;
  metric: string;
  operator: MonitoringRuleOperator;
  threshold: number;
  recoveryThreshold: number;
  severity: MonitoringRuleSeverity;
  enabled: boolean;
  configuredEvaluationIntervalSeconds: number;
  effectiveEvaluationIntervalSeconds: number;
  forSeconds: number;
  forSamples: number;
  recoverySeconds: number;
  recoverySamples: number;
  noDataPolicy: MonitoringRuleNoDataPolicy;
  noDataSeconds: number;
  noDataSamples: number;
  parentRuleId: string | null;
  labels: Record<string, string>;
  description: string;
  runbook: string;
  stateEvidenceSourceId: 'rule-evaluation-state';
  eventEvidenceSourceId: 'rule-alert-events';
  eventRetention: { maxRecords: number; maxBytes: number };
  detailPages: MonitoringCatalogDetailPage[];
}

export interface MonitoringCatalog {
  schemaVersion: 1;
  generatedAt: string;
  collectionIntervalSeconds: number;
  rulePackVersion: string;
  evidenceSources: MonitoringEvidenceSource[];
  observations: MonitoringObservation[];
  rules: MonitoringCatalogRule[];
}

type JsonRecord = Record<string, unknown>;

const ROOT_FIELDS = [
  'schemaVersion', 'generatedAt', 'collectionIntervalSeconds', 'rulePackVersion',
  'evidenceSources', 'observations', 'rules',
] as const;
const SOURCE_FIELDS = [
  'id', 'displayName', 'description', 'kind', 'evidenceMode', 'artifactLabel',
  'format', 'cadenceSeconds', 'retention', 'detailPages',
] as const;
const RETENTION_FIELDS = [
  'policy', 'pruneCadence', 'maxAgeDays', 'maxRecords', 'recordScope', 'maxBytes',
] as const;
const OBSERVATION_FIELDS = [
  'id', 'domain', 'displayName', 'description', 'evidenceMode', 'cadenceSeconds',
  'evidenceSourceIds', 'detailPages',
] as const;
const RULE_FIELDS = [
  'id', 'domain', 'metric', 'operator', 'threshold', 'recoveryThreshold',
  'severity', 'enabled', 'configuredEvaluationIntervalSeconds',
  'effectiveEvaluationIntervalSeconds', 'forSeconds', 'forSamples',
  'recoverySeconds', 'recoverySamples', 'noDataPolicy', 'noDataSeconds',
  'noDataSamples', 'parentRuleId', 'labels', 'description', 'runbook',
  'stateEvidenceSourceId', 'eventEvidenceSourceId', 'eventRetention', 'detailPages',
] as const;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactFields(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length
    && actual.every((key) => expected.includes(key));
}

function containsForbiddenMaterial(value: string): boolean {
  return /(?:^|[^A-Za-z0-9/])\/(?!\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*/u.test(value)
    || /-----BEGIN [^-]+ PRIVATE KEY-----/iu.test(value)
    || /\b(?:authorization|cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+/iu.test(value)
    || /(?:https?|ssh):\/\/[^\s/@:]+:[^\s/@]+@/iu.test(value)
    || /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u.test(value)
    || /\bAKIA[0-9A-Z]{16}\b/u.test(value)
    || /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u.test(value);
}

function safeText(value: unknown, maximum: number): string | null {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)
    || containsForbiddenMaterial(value)
  ) return null;
  return value;
}

function localized(value: unknown, maximum: number): MonitoringLocalizedText | null {
  if (!isRecord(value) || !exactFields(value, ['ko', 'en'])) return null;
  const ko = safeText(value.ko, maximum);
  const en = safeText(value.en, maximum);
  return ko && en ? { ko, en } : null;
}

function integer(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= minimum
    && value <= maximum
    ? value
    : null;
}

function nullableInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null | undefined {
  if (value === null) return null;
  return integer(value, minimum, maximum) ?? undefined;
}

function finite(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function canonicalTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value ? value : null;
}

function enumValue<T extends string>(value: unknown, allowed: Set<T>): T | null {
  return typeof value === 'string' && allowed.has(value as T) ? value as T : null;
}

function uniqueEnumArray<T extends string>(
  value: unknown,
  allowed: Set<T>,
  maximum: number,
): T[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > maximum) return null;
  const values = value.map((item) => enumValue(item, allowed));
  if (values.some((item) => item === null)) return null;
  const unique = [...new Set(values as T[])];
  return unique.length === values.length ? unique : null;
}

function safeId(value: unknown): string | null {
  return typeof value === 'string' && /^[a-z][a-z0-9.-]{2,127}$/u.test(value)
    ? value
    : null;
}

function normalizeRetention(value: unknown): MonitoringRetention | null {
  if (!isRecord(value) || !exactFields(value, RETENTION_FIELDS)) return null;
  const policy = enumValue(value.policy, RETENTION_POLICIES);
  const pruneCadence = enumValue(value.pruneCadence, PRUNE_CADENCES);
  const maxAgeDays = nullableInteger(value.maxAgeDays, 1, 3_650);
  const maxRecords = nullableInteger(value.maxRecords, 1, 100_000);
  const maxBytes = nullableInteger(value.maxBytes, 1, MAX_RULE_ALERT_BYTES);
  const recordScope = value.recordScope === null
    ? null
    : enumValue(value.recordScope, RECORD_SCOPES);
  if (
    !policy
    || !pruneCadence
    || maxAgeDays === undefined
    || maxRecords === undefined
    || maxBytes === undefined
    || (value.recordScope !== null && recordScope === null)
  ) return null;
  return { policy, pruneCadence, maxAgeDays, maxRecords, recordScope, maxBytes };
}

function normalizeEvidenceSource(value: unknown): MonitoringEvidenceSource | null {
  if (!isRecord(value) || !exactFields(value, SOURCE_FIELDS)) return null;
  const id = safeId(value.id);
  if (!id) return null;
  const expected = SOURCE_ARTIFACTS.get(id);
  const displayName = localized(value.displayName, 160);
  const description = localized(value.description, 600);
  const kind = enumValue(value.kind, SOURCE_KINDS);
  const evidenceMode = enumValue(value.evidenceMode, SOURCE_MODES);
  const format = enumValue(value.format, FORMATS);
  const cadenceSeconds = value.cadenceSeconds === null
    ? null
    : integer(value.cadenceSeconds, 10, 86_400);
  const retention = normalizeRetention(value.retention);
  const detailPages = uniqueEnumArray(value.detailPages, DETAIL_PAGES, DETAIL_PAGES.size);
  if (
    !expected
    || !displayName
    || !description
    || !kind
    || !evidenceMode
    || !format
    || cadenceSeconds === null && value.cadenceSeconds !== null
    || !retention
    || !detailPages
    || value.artifactLabel !== expected.label
    || format !== expected.format
    || kind !== expected.kind
    || evidenceMode !== expected.evidenceMode
    || retention.policy !== expected.retentionPolicy
    || retention.pruneCadence !== expected.pruneCadence
    || retention.recordScope !== expected.recordScope
  ) return null;
  return {
    id,
    displayName,
    description,
    kind,
    evidenceMode,
    artifactLabel: expected.label,
    format,
    cadenceSeconds,
    retention,
    detailPages,
  };
}

function normalizeObservation(
  value: unknown,
  knownSourceIds: ReadonlySet<string>,
): MonitoringObservation | null {
  if (!isRecord(value) || !exactFields(value, OBSERVATION_FIELDS)) return null;
  const id = safeId(value.id);
  const domain = enumValue(value.domain, DOMAINS);
  const displayName = localized(value.displayName, 160);
  const description = localized(value.description, 600);
  const evidenceMode = enumValue(value.evidenceMode, OBSERVATION_MODES);
  const cadenceSeconds = value.cadenceSeconds === null
    ? null
    : integer(value.cadenceSeconds, 10, 86_400);
  const detailPages = uniqueEnumArray(value.detailPages, DETAIL_PAGES, DETAIL_PAGES.size);
  if (
    !id || !domain || !displayName || !description || !evidenceMode
    || cadenceSeconds === null && value.cadenceSeconds !== null || !detailPages
    || !Array.isArray(value.evidenceSourceIds)
    || value.evidenceSourceIds.length < 1
    || value.evidenceSourceIds.length > SOURCE_ARTIFACTS.size
  ) return null;
  const evidenceSourceIds: string[] = [];
  for (const sourceId of value.evidenceSourceIds) {
    if (typeof sourceId !== 'string' || !knownSourceIds.has(sourceId)) return null;
    evidenceSourceIds.push(sourceId);
  }
  if (new Set(evidenceSourceIds).size !== evidenceSourceIds.length) return null;
  return {
    id, domain, displayName, description, evidenceMode, cadenceSeconds,
    evidenceSourceIds, detailPages,
  };
}

function normalizeLabels(value: unknown): Record<string, string> | null {
  if (!isRecord(value)) return null;
  if (exactFields(value, [])) return {};
  if (!exactFields(value, ['scope'])) return null;
  return typeof value.scope === 'string' && PUBLIC_RULE_SCOPES.has(value.scope)
    ? { scope: value.scope }
    : null;
}

function normalizeRule(value: unknown): MonitoringCatalogRule | null {
  if (!isRecord(value) || !exactFields(value, RULE_FIELDS)) return null;
  const id = typeof value.id === 'string' && /^[A-Z][A-Za-z0-9]{2,63}$/u.test(value.id)
    ? value.id
    : null;
  const domain = enumValue(value.domain, DOMAINS);
  const metric = typeof value.metric === 'string' && /^[a-z][a-z0-9_.]{2,127}$/u.test(value.metric)
    ? value.metric
    : null;
  const operator = enumValue(value.operator, OPERATORS);
  const threshold = finite(value.threshold);
  const recoveryThreshold = finite(value.recoveryThreshold);
  const severity = enumValue(value.severity, SEVERITIES);
  const configuredEvaluationIntervalSeconds = integer(
    value.configuredEvaluationIntervalSeconds, 1, 86_400,
  );
  const effectiveEvaluationIntervalSeconds = integer(
    value.effectiveEvaluationIntervalSeconds, 10, 86_400,
  );
  const forSeconds = integer(value.forSeconds, 0, 31_622_400);
  const forSamples = integer(value.forSamples, 1, 10_000);
  const recoverySeconds = integer(value.recoverySeconds, 0, 31_622_400);
  const recoverySamples = integer(value.recoverySamples, 1, 10_000);
  const noDataPolicy = enumValue(value.noDataPolicy, NO_DATA_POLICIES);
  const noDataSeconds = integer(value.noDataSeconds, 0, 31_622_400);
  const noDataSamples = integer(value.noDataSamples, 1, 10_000);
  const parentRuleId = value.parentRuleId === null
    ? null
    : typeof value.parentRuleId === 'string' && /^[A-Z][A-Za-z0-9]{2,63}$/u.test(value.parentRuleId)
      ? value.parentRuleId
      : undefined;
  const labels = normalizeLabels(value.labels);
  const description = safeText(value.description, 500);
  const runbook = safeText(value.runbook, 500);
  const detailPages = uniqueEnumArray(value.detailPages, DETAIL_PAGES, DETAIL_PAGES.size);
  const eventRetention = isRecord(value.eventRetention)
    && exactFields(value.eventRetention, ['maxRecords', 'maxBytes'])
    && integer(value.eventRetention.maxRecords, 10, 5_000) !== null
    && value.eventRetention.maxBytes === MAX_RULE_ALERT_BYTES
    ? {
        maxRecords: value.eventRetention.maxRecords as number,
        maxBytes: MAX_RULE_ALERT_BYTES,
      }
    : null;
  const thresholdsAreConsistent = threshold !== null && recoveryThreshold !== null && operator !== null
    && (
      operator === 'gte' ? recoveryThreshold < threshold
        : operator === 'gt' ? recoveryThreshold <= threshold
          : operator === 'lte' ? recoveryThreshold > threshold
            : operator === 'lt' ? recoveryThreshold >= threshold
              : true
    );
  if (
    !id || !domain || !metric || !operator || threshold === null || recoveryThreshold === null
    || !thresholdsAreConsistent
    || !severity || typeof value.enabled !== 'boolean'
    || configuredEvaluationIntervalSeconds === null
    || effectiveEvaluationIntervalSeconds === null
    || forSeconds === null || forSamples === null
    || recoverySeconds === null || recoverySamples === null
    || !noDataPolicy || noDataSeconds === null || noDataSamples === null
    || parentRuleId === undefined || !labels || !description || !runbook || !detailPages
    || value.stateEvidenceSourceId !== 'rule-evaluation-state'
    || value.eventEvidenceSourceId !== 'rule-alert-events'
    || !eventRetention
  ) return null;
  return {
    id, domain, metric, operator, threshold, recoveryThreshold, severity,
    enabled: value.enabled,
    configuredEvaluationIntervalSeconds,
    effectiveEvaluationIntervalSeconds,
    forSeconds, forSamples, recoverySeconds, recoverySamples, noDataPolicy,
    noDataSeconds, noDataSamples, parentRuleId, labels, description, runbook,
    stateEvidenceSourceId: 'rule-evaluation-state',
    eventEvidenceSourceId: 'rule-alert-events',
    eventRetention,
    detailPages,
  };
}

export function normalizeMonitoringCatalog(value: unknown): MonitoringCatalog | null {
  if (!isRecord(value) || !exactFields(value, ROOT_FIELDS)) return null;
  const generatedAt = canonicalTimestamp(value.generatedAt);
  const collectionIntervalSeconds = integer(value.collectionIntervalSeconds, 10, 86_400);
  const rulePackVersion = typeof value.rulePackVersion === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u.test(value.rulePackVersion)
    ? value.rulePackVersion
    : null;
  if (
    value.schemaVersion !== 1
    || !generatedAt
    || collectionIntervalSeconds === null
    || !rulePackVersion
    || !Array.isArray(value.evidenceSources)
    || value.evidenceSources.length !== SOURCE_ARTIFACTS.size
    || value.evidenceSources.length > MAX_EVIDENCE_SOURCES
  ) return null;
  const evidenceSources = value.evidenceSources.map(normalizeEvidenceSource);
  if (evidenceSources.some((source) => source === null)) return null;
  const normalizedSources = evidenceSources as MonitoringEvidenceSource[];
  const sourceIds = new Set(normalizedSources.map((source) => source.id));
  if (
    sourceIds.size !== normalizedSources.length
    || [...SOURCE_ARTIFACTS.keys()].some((sourceId) => !sourceIds.has(sourceId))
    || !Array.isArray(value.observations)
    || value.observations.length > MAX_OBSERVATIONS
  ) return null;
  const observations = value.observations.map((item) => normalizeObservation(item, sourceIds));
  if (observations.some((item) => item === null)) return null;
  const normalizedObservations = observations as MonitoringObservation[];
  const observationIds = new Set(normalizedObservations.map((item) => item.id));
  if (
    observationIds.size !== normalizedObservations.length
    || observationIds.size !== REQUIRED_MONITORING_OBSERVATION_IDS.length
    || REQUIRED_MONITORING_OBSERVATION_IDS.some((id) => !observationIds.has(id))
    || !Array.isArray(value.rules)
    || value.rules.length < 1
    || value.rules.length > MAX_RULES
  ) return null;
  const rules = value.rules.map(normalizeRule);
  if (rules.some((rule) => rule === null)) return null;
  const normalizedRules = rules as MonitoringCatalogRule[];
  const ruleIds = new Set(normalizedRules.map((rule) => rule.id));
  const ruleEventSource = normalizedSources.find((source) => source.id === 'rule-alert-events');
  if (
    ruleIds.size !== normalizedRules.length
    || normalizedSources.some((source) => (
      source.cadenceSeconds !== null && source.cadenceSeconds !== collectionIntervalSeconds
    ))
    || normalizedObservations.some((item) => {
      if (item.cadenceSeconds === null) return false;
      const expectedCadence = item.id === 'synthetic.http-tls'
        ? SYNTHETIC_PROBE_INTERVAL_SECONDS
        : collectionIntervalSeconds;
      return item.cadenceSeconds !== expectedCadence;
    })
    || !ruleEventSource
    || ruleEventSource.retention.maxRecords === null
    || ruleEventSource.retention.maxBytes !== MAX_RULE_ALERT_BYTES
  ) return null;
  for (const rule of normalizedRules) {
    if (
      rule.effectiveEvaluationIntervalSeconds !== collectionIntervalSeconds
      || rule.eventRetention.maxRecords !== ruleEventSource.retention.maxRecords
      || rule.eventRetention.maxBytes !== ruleEventSource.retention.maxBytes
      || rule.parentRuleId !== null && !ruleIds.has(rule.parentRuleId)
    ) return null;
    const visited = new Set<string>();
    let current: MonitoringCatalogRule | undefined = rule;
    while (current?.parentRuleId !== null) {
      if (visited.has(current.id)) return null;
      visited.add(current.id);
      current = normalizedRules.find((candidate) => candidate.id === current?.parentRuleId);
      if (!current) return null;
    }
  }
  return {
    schemaVersion: 1,
    generatedAt,
    collectionIntervalSeconds,
    rulePackVersion,
    evidenceSources: normalizedSources,
    observations: normalizedObservations,
    rules: normalizedRules,
  };
}

function isInside(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === '' || (!child.startsWith(`..${sep}`) && child !== '..' && !child.startsWith(sep));
}

function trustedRootOwnerUid(root: string): number | null {
  try {
    const before = lstatSync(root);
    if (
      !before.isDirectory() || before.isSymbolicLink() || before.nlink < 1
      || (before.mode & 0o022) !== 0 || !Number.isSafeInteger(before.uid) || before.uid < 0
      || realpathSync(root) !== root
    ) return null;
    const after = lstatSync(root);
    return after.isDirectory() && !after.isSymbolicLink()
      && after.dev === before.dev && after.ino === before.ino
      && after.uid === before.uid && after.gid === before.gid
      && after.mode === before.mode && after.nlink === before.nlink
      ? before.uid
      : null;
  } catch {
    return null;
  }
}

export function readMonitoringCatalog(
  dataDirectory: string,
  expectedOwnerUid?: number,
): MonitoringCatalog | null {
  const root = resolve(dataDirectory);
  const ownerUid = trustedRootOwnerUid(root);
  if (ownerUid === null || expectedOwnerUid !== undefined && expectedOwnerUid !== ownerUid) return null;
  const path = join(root, CATALOG_FILE);
  let descriptor: number | undefined;
  try {
    const before = lstatSync(path);
    if (
      !before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== ownerUid || (before.mode & 0o027) !== 0
      || before.size < 2 || before.size > MAX_CATALOG_BYTES
    ) return null;
    const realRoot = realpathSync(root);
    const realPath = realpathSync(path);
    if (!isInside(realRoot, realPath)) return null;
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile() || opened.nlink !== 1 || opened.uid !== ownerUid
      || (opened.mode & 0o027) !== 0 || opened.size !== before.size
      || opened.size > MAX_CATALOG_BYTES || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.mode !== before.mode || opened.mtimeMs !== before.mtimeMs
      || opened.ctimeMs !== before.ctimeMs
    ) return null;
    const payload = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      payload.length !== opened.size || after.dev !== opened.dev || after.ino !== opened.ino
      || after.size !== opened.size || after.mode !== opened.mode || after.uid !== opened.uid
      || after.nlink !== opened.nlink || after.mtimeMs !== opened.mtimeMs
      || after.ctimeMs !== opened.ctimeMs
    ) return null;
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(payload);
    } catch {
      return null;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }
    return normalizeMonitoringCatalog(parsed);
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export const monitoringCatalogLimits = {
  fileName: CATALOG_FILE,
  maximumBytes: MAX_CATALOG_BYTES,
  maximumEvidenceSources: MAX_EVIDENCE_SOURCES,
  maximumObservations: MAX_OBSERVATIONS,
  maximumRules: MAX_RULES,
} as const;
