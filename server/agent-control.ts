import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import {
  closeSync,
  constants as fileConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { isIP } from 'node:net';
import { basename, dirname, join } from 'node:path';
import type { Request } from 'express';
import type { AgentControlRuntimeConfig, AgentStorageKeyring } from './config.js';
import type { CentralAgentInventory } from './types.js';

const UUID_V4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const HEX_SHA256 = /^[a-f0-9]{64}$/u;
const TOKEN_ID = /^[a-f0-9]{32}$/u;
const ENROLLMENT_TOKEN = /^menr_([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const RFC3339_MILLISECONDS = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u;
export const MAX_CONTROL_STATE_PLAINTEXT_BYTES = 4 * 1024 * 1024;
export const MAX_CONTROL_STATE_ENVELOPE_BYTES = 6 * 1024 * 1024;
const MAX_TOKENS = 2_048;
const TOKEN_AUDIT_RETENTION_MS = 24 * 60 * 60 * 1_000;

type AgentLifecycle = 'active' | 'maintenance' | 'inactive';
type AgentStatus = 'healthy' | 'delayed' | 'disconnected' | 'maintenance' | 'inactive' | 'revoked';
type QueuePriority = 'priority' | 'normal';
type TokenPurpose = 'enrollment' | 'certificate-rotation';

export class AgentControlError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'AgentControlError';
  }
}

export interface TrustedAgentCertificate {
  fingerprintSha256: string;
  notAfter: number;
}

export type AgentInventory = CentralAgentInventory;

interface EnrollmentTokenRecord {
  tokenId: string;
  tokenHash: string;
  purpose: TokenPurpose;
  boundAgentId: string | null;
  issuedAt: number;
  expiresAt: number;
  maxUses: 1;
  uses: 0 | 1;
  consumedAt: number | null;
  consumedAgentId: string | null;
  requestDigest: string | null;
}

interface AgentRecord {
  agentId: string;
  hostId: string;
  machineIdentityKey: string;
  installationEpoch: number;
  registeredAt: number;
  lastSeenAt: number;
  lastObservedAt: number;
  expectedHeartbeatIntervalSeconds: number;
  lifecycle: AgentLifecycle;
  inventory: AgentInventory;
  certificateFingerprintSha256: string;
  certificateNotAfter: number;
  lastHeartbeatSequence: number;
  lastHeartbeatObservedAt: number;
  maxSequence: number;
  rejectedClockSkewCount: number;
  lastRejectedAt: number | null;
  revokedAt: number | null;
  revokedReason: 'compromised' | 'decommissioned' | 'operator' | 'reinstalled' | null;
}

interface BatchReceipt {
  agentId: string;
  batchId: string;
  digest: string;
  receivedAt: number;
  recordKeys: string[];
  recordDigests: string[];
  priority: QueuePriority;
  queueFile: string | null;
  acceptedRecordCount: number;
  duplicateRecordCount: number;
}

interface ControlState {
  schemaVersion: 1;
  tokens: EnrollmentTokenRecord[];
  agents: AgentRecord[];
  receipts: BatchReceipt[];
  counters: {
    rejectedBatches: number;
    rejectedRecords: number;
    duplicateBatches: number;
    duplicateRecords: number;
    outOfOrderRecords: number;
    expiredQueueBatches: number;
  };
}

interface EncryptedEnvelope {
  schemaVersion: 1;
  algorithm: 'aes-256-gcm';
  keyId: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

function base64UrlEncodedLength(bytes: number): number {
  const remainder = bytes % 3;
  return Math.floor(bytes / 3) * 4 + (remainder === 0 ? 0 : remainder + 1);
}

function base64UrlDecodedLength(value: string): number | null {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) return null;
  const remainder = value.length % 4;
  return Math.floor(value.length / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
}

export function preflightAgentControlState(
  serialized: string,
  keyId: string,
): { plaintextBytes: number; envelopeBytes: number } {
  const plaintextBytes = Buffer.byteLength(serialized, 'utf8');
  const emptyEnvelope: EncryptedEnvelope = {
    schemaVersion: 1,
    algorithm: 'aes-256-gcm',
    keyId,
    iv: '',
    ciphertext: '',
    tag: '',
  };
  const envelopeBytes = Buffer.byteLength(JSON.stringify(emptyEnvelope), 'utf8')
    + base64UrlEncodedLength(12)
    + base64UrlEncodedLength(plaintextBytes)
    + base64UrlEncodedLength(16)
    + 1;
  if (
    plaintextBytes > MAX_CONTROL_STATE_PLAINTEXT_BYTES
    || envelopeBytes > MAX_CONTROL_STATE_ENVELOPE_BYTES
  ) {
    throw new AgentControlError(
      429,
      'CONTROL_STATE_BACKPRESSURE',
      'Agent control state capacity is exhausted',
      60,
    );
  }
  return { plaintextBytes, envelopeBytes };
}

interface NormalizedRegistration {
  schemaVersion: 1;
  enrollmentToken: string;
  hostId: string;
  agentId: string;
  machineIdentityDigest: string;
  installationEpoch: number;
  heartbeatIntervalSeconds: number;
  inventory: AgentInventory;
}

interface NormalizedHeartbeat {
  schemaVersion: 1;
  agentId: string;
  sequence: number;
  observedAt: number;
  expectedIntervalSeconds: number;
  lifecycle: AgentLifecycle;
  inventory: AgentInventory;
}

interface NormalizedIngestRecord {
  kind: 'metric' | 'event';
  metric: string;
  target: string;
  observedAt: number;
  sequence: number;
  value: number | null;
  severity: 'info' | 'warning' | 'critical' | null;
}

interface NormalizedBatch {
  schemaVersion: 1;
  agentId: string;
  batchId: string;
  sentAt: number;
  firstSequence: number;
  lastSequence: number;
  records: NormalizedIngestRecord[];
}

interface QueuedBatch {
  schemaVersion: 1;
  agentId: string;
  batchId: string;
  receivedAt: number;
  sentAt: number;
  firstSequence: number;
  lastSequence: number;
  priority: QueuePriority;
  digest: string;
  records: Array<{
    kind: 'metric' | 'event';
    metric: string;
    target: string;
    observedAt: string;
    sequence: number;
    value: number | null;
    severity: 'info' | 'warning' | 'critical' | null;
  }>;
}

interface ValidatedQueuedBatch {
  schemaVersion: 1;
  agentId: string;
  batchId: string;
  receivedAt: number;
  sentAt: number;
  firstSequence: number;
  lastSequence: number;
  priority: QueuePriority;
  digest: string;
  records: NormalizedIngestRecord[];
}

interface QueueUsage {
  entries: number;
  bytes: number;
  priorityEntries: number;
  priorityBytes: number;
  normalEntries: number;
  normalBytes: number;
  selectedAgentEntries: number;
  selectedAgentBytes: number;
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index])
    ? record
    : null;
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function validSafeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
}

function parseTimestamp(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const match = RFC3339_MILLISECONDS.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day > daysInMonth[month - 1]!) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function safeText(value: unknown, maximumLength: number, allowNull = false): string | null {
  if (allowNull && value === null) return null;
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > maximumLength
    || /[\u0000-\u001f\u007f]/u.test(normalized)
  ) return null;
  return normalized;
}

function parseInventory(value: unknown): AgentInventory | null {
  const record = exactRecord(value, [
    'agentVersion',
    'hostname',
    'ipAddresses',
    'operatingSystem',
    'ubuntuVersion',
    'kernelVersion',
    'architecture',
    'cpuModel',
    'memoryBytes',
  ]);
  if (!record || !Array.isArray(record.ipAddresses) || record.ipAddresses.length > 16) return null;
  const agentVersion = safeText(record.agentVersion, 64);
  const hostname = safeText(record.hostname, 253);
  const operatingSystem = safeText(record.operatingSystem, 128);
  const ubuntuVersion = record.ubuntuVersion === null ? null : safeText(record.ubuntuVersion, 64);
  const kernelVersion = safeText(record.kernelVersion, 128);
  const architecture = safeText(record.architecture, 32);
  const cpuModel = safeText(record.cpuModel, 256);
  const ipAddresses = record.ipAddresses.filter((entry): entry is string => (
    typeof entry === 'string' && isIP(entry) !== 0
  ));
  if (
    !agentVersion
    || !hostname
    || !operatingSystem
    || (record.ubuntuVersion !== null && !ubuntuVersion)
    || !kernelVersion
    || !architecture
    || !cpuModel
    || ipAddresses.length !== record.ipAddresses.length
    || new Set(ipAddresses).size !== ipAddresses.length
    || !validSafeInteger(record.memoryBytes, 1)
  ) return null;
  return {
    agentVersion,
    hostname,
    ipAddresses,
    operatingSystem,
    ubuntuVersion,
    kernelVersion,
    architecture,
    cpuModel,
    memoryBytes: record.memoryBytes,
  };
}

function parseRegistration(value: unknown): NormalizedRegistration | null {
  const record = exactRecord(value, [
    'schemaVersion',
    'enrollmentToken',
    'hostId',
    'agentId',
    'machineIdentityDigest',
    'installationEpoch',
    'heartbeatIntervalSeconds',
    'inventory',
  ]);
  if (!record || record.schemaVersion !== 1) return null;
  const installationEpoch = parseTimestamp(record.installationEpoch);
  const inventory = parseInventory(record.inventory);
  if (
    typeof record.enrollmentToken !== 'string'
    || !ENROLLMENT_TOKEN.test(record.enrollmentToken)
    || typeof record.hostId !== 'string'
    || !UUID_V4.test(record.hostId)
    || typeof record.agentId !== 'string'
    || !UUID_V4.test(record.agentId)
    || record.hostId === record.agentId
    || typeof record.machineIdentityDigest !== 'string'
    || !HEX_SHA256.test(record.machineIdentityDigest)
    || installationEpoch === null
    || installationEpoch < 0
    || !validSafeInteger(record.heartbeatIntervalSeconds, 10)
    || record.heartbeatIntervalSeconds > 86_400
    || !inventory
  ) return null;
  return {
    schemaVersion: 1,
    enrollmentToken: record.enrollmentToken,
    hostId: record.hostId,
    agentId: record.agentId,
    machineIdentityDigest: record.machineIdentityDigest,
    installationEpoch,
    heartbeatIntervalSeconds: record.heartbeatIntervalSeconds,
    inventory,
  };
}

function parseHeartbeat(value: unknown): NormalizedHeartbeat | null {
  const record = exactRecord(value, [
    'schemaVersion',
    'agentId',
    'sequence',
    'observedAt',
    'expectedIntervalSeconds',
    'lifecycle',
    'inventory',
  ]);
  if (!record || record.schemaVersion !== 1) return null;
  const observedAt = parseTimestamp(record.observedAt);
  const inventory = parseInventory(record.inventory);
  if (
    typeof record.agentId !== 'string'
    || !UUID_V4.test(record.agentId)
    || !validSafeInteger(record.sequence, 1)
    || observedAt === null
    || !validSafeInteger(record.expectedIntervalSeconds, 10)
    || record.expectedIntervalSeconds > 86_400
    || !['active', 'maintenance', 'inactive'].includes(String(record.lifecycle))
    || !inventory
  ) return null;
  return {
    schemaVersion: 1,
    agentId: record.agentId,
    sequence: record.sequence,
    observedAt,
    expectedIntervalSeconds: record.expectedIntervalSeconds,
    lifecycle: record.lifecycle as AgentLifecycle,
    inventory,
  };
}

function parseIngestRecord(value: unknown): NormalizedIngestRecord | null {
  const record = exactRecord(value, [
    'kind',
    'metric',
    'target',
    'observedAt',
    'sequence',
    'value',
    'severity',
  ]);
  if (!record || (record.kind !== 'metric' && record.kind !== 'event')) return null;
  const metric = safeText(record.metric, 128);
  const target = safeText(record.target, 128);
  const observedAt = parseTimestamp(record.observedAt);
  if (
    !metric
    || !SAFE_NAME.test(metric)
    || !target
    || !SAFE_NAME.test(target)
    || observedAt === null
    || !validSafeInteger(record.sequence, 1)
  ) return null;
  if (record.kind === 'metric') {
    if (
      typeof record.value !== 'number'
      || !Number.isFinite(record.value)
      || record.severity !== null
    ) return null;
  } else if (
    record.value !== null
    || !['info', 'warning', 'critical'].includes(String(record.severity))
  ) return null;
  return {
    kind: record.kind,
    metric,
    target,
    observedAt,
    sequence: record.sequence,
    value: record.value as number | null,
    severity: record.severity as NormalizedIngestRecord['severity'],
  };
}

function parseBatch(
  value: unknown,
  maxRecords: number,
  allowLegacyMixed = false,
): NormalizedBatch | null {
  const record = exactRecord(value, [
    'schemaVersion',
    'agentId',
    'batchId',
    'sentAt',
    'firstSequence',
    'lastSequence',
    'records',
  ]);
  if (!record || record.schemaVersion !== 1 || !Array.isArray(record.records)) return null;
  const sentAt = parseTimestamp(record.sentAt);
  const records = record.records.map(parseIngestRecord);
  if (
    typeof record.agentId !== 'string'
    || !UUID_V4.test(record.agentId)
    || typeof record.batchId !== 'string'
    || !UUID_V4.test(record.batchId)
    || sentAt === null
    || !validSafeInteger(record.firstSequence, 1)
    || !validSafeInteger(record.lastSequence, record.firstSequence)
    || records.length < 1
    || records.length > maxRecords
    || records.some((entry) => entry === null)
  ) return null;
  const normalizedRecords = records as NormalizedIngestRecord[];
  const sequences = normalizedRecords.map((entry) => entry.sequence);
  if (
    Math.min(...sequences) !== record.firstSequence
    || Math.max(...sequences) !== record.lastSequence
    || sequences.some((sequence, index) => index > 0 && sequence < sequences[index - 1]!)
    || (
      !allowLegacyMixed
      && new Set(normalizedRecords.map((entry) => entry.kind)).size !== 1
    )
  ) return null;
  return {
    schemaVersion: 1,
    agentId: record.agentId,
    batchId: record.batchId,
    sentAt,
    firstSequence: record.firstSequence,
    lastSequence: record.lastSequence,
    records: normalizedRecords,
  };
}

function parseQueuedBatch(
  value: unknown,
  maxRecords: number,
  allowLegacyMixed = false,
): ValidatedQueuedBatch | null {
  const record = exactRecord(value, [
    'schemaVersion',
    'agentId',
    'batchId',
    'receivedAt',
    'sentAt',
    'firstSequence',
    'lastSequence',
    'priority',
    'digest',
    'records',
  ]);
  if (!record || record.schemaVersion !== 1 || !Array.isArray(record.records)) return null;
  const records = record.records.map(parseIngestRecord);
  if (
    typeof record.agentId !== 'string'
    || !UUID_V4.test(record.agentId)
    || typeof record.batchId !== 'string'
    || !UUID_V4.test(record.batchId)
    || !validSafeInteger(record.receivedAt)
    || !validSafeInteger(record.sentAt)
    || !validSafeInteger(record.firstSequence, 1)
    || !validSafeInteger(record.lastSequence, record.firstSequence)
    || (record.priority !== 'priority' && record.priority !== 'normal')
    || typeof record.digest !== 'string'
    || !HEX_SHA256.test(record.digest)
    || records.length < 1
    || records.length > maxRecords
    || records.some((entry) => entry === null)
  ) return null;
  const normalizedRecords = records as NormalizedIngestRecord[];
  const sequences = normalizedRecords.map((entry) => entry.sequence);
  const kinds = new Set(normalizedRecords.map((entry) => entry.kind));
  const expectedPriority: QueuePriority = kinds.has('event') ? 'priority' : 'normal';
  if (
    Math.min(...sequences) !== record.firstSequence
    || Math.max(...sequences) !== record.lastSequence
    || sequences.some((sequence, index) => index > 0 && sequence < sequences[index - 1]!)
    || (!allowLegacyMixed && kinds.size !== 1)
    || record.priority !== expectedPriority
  ) return null;
  return {
    schemaVersion: 1,
    agentId: record.agentId,
    batchId: record.batchId,
    receivedAt: record.receivedAt,
    sentAt: record.sentAt,
    firstSequence: record.firstSequence,
    lastSequence: record.lastSequence,
    priority: record.priority,
    digest: record.digest,
    records: normalizedRecords,
  };
}

function inventoryIsValid(value: AgentInventory): boolean {
  return parseInventory(value) !== null;
}

function stateIsValid(value: unknown): value is ControlState {
  const state = exactRecord(value, ['schemaVersion', 'tokens', 'agents', 'receipts', 'counters']);
  if (
    !state
    || state.schemaVersion !== 1
    || !Array.isArray(state.tokens)
    || !Array.isArray(state.agents)
    || !Array.isArray(state.receipts)
  ) return false;
  const counters = exactRecord(state.counters, [
    'rejectedBatches',
    'rejectedRecords',
    'duplicateBatches',
    'duplicateRecords',
    'outOfOrderRecords',
    'expiredQueueBatches',
  ]);
  if (!counters || Object.values(counters).some((entry) => !validSafeInteger(entry))) return false;

  const tokensValid = state.tokens.every((entry) => {
    const token = exactRecord(entry, [
      'tokenId', 'tokenHash', 'purpose', 'boundAgentId', 'issuedAt', 'expiresAt',
      'maxUses', 'uses', 'consumedAt', 'consumedAgentId', 'requestDigest',
    ]);
    return Boolean(
      token
      && typeof token.tokenId === 'string' && TOKEN_ID.test(token.tokenId)
      && typeof token.tokenHash === 'string' && HEX_SHA256.test(token.tokenHash)
      && (token.purpose === 'enrollment' || token.purpose === 'certificate-rotation')
      && (token.boundAgentId === null || typeof token.boundAgentId === 'string' && UUID_V4.test(token.boundAgentId))
      && validSafeInteger(token.issuedAt)
      && validSafeInteger(token.expiresAt, token.issuedAt)
      && token.maxUses === 1
      && (token.uses === 0 || token.uses === 1)
      && (token.consumedAt === null || validSafeInteger(token.consumedAt, token.issuedAt))
      && (token.consumedAgentId === null || typeof token.consumedAgentId === 'string' && UUID_V4.test(token.consumedAgentId))
      && (token.requestDigest === null || typeof token.requestDigest === 'string' && HEX_SHA256.test(token.requestDigest)),
    );
  });

  const agentsValid = state.agents.every((entry) => {
    const agent = exactRecord(entry, [
      'agentId', 'hostId', 'machineIdentityKey', 'installationEpoch', 'registeredAt',
      'lastSeenAt', 'lastObservedAt', 'expectedHeartbeatIntervalSeconds', 'lifecycle',
      'inventory', 'certificateFingerprintSha256', 'certificateNotAfter',
      'lastHeartbeatSequence', 'lastHeartbeatObservedAt', 'maxSequence',
      'rejectedClockSkewCount', 'lastRejectedAt', 'revokedAt', 'revokedReason',
    ]);
    return Boolean(
      agent
      && typeof agent.agentId === 'string' && UUID_V4.test(agent.agentId)
      && typeof agent.hostId === 'string' && UUID_V4.test(agent.hostId)
      && typeof agent.machineIdentityKey === 'string' && HEX_SHA256.test(agent.machineIdentityKey)
      && validSafeInteger(agent.installationEpoch)
      && validSafeInteger(agent.registeredAt)
      && validSafeInteger(agent.lastSeenAt)
      && validSafeInteger(agent.lastObservedAt)
      && validSafeInteger(agent.expectedHeartbeatIntervalSeconds, 10)
      && ['active', 'maintenance', 'inactive'].includes(String(agent.lifecycle))
      && inventoryIsValid(agent.inventory as AgentInventory)
      && typeof agent.certificateFingerprintSha256 === 'string' && HEX_SHA256.test(agent.certificateFingerprintSha256)
      && validSafeInteger(agent.certificateNotAfter)
      && validSafeInteger(agent.lastHeartbeatSequence)
      && validSafeInteger(agent.lastHeartbeatObservedAt)
      && validSafeInteger(agent.maxSequence)
      && validSafeInteger(agent.rejectedClockSkewCount)
      && (agent.lastRejectedAt === null || validSafeInteger(agent.lastRejectedAt))
      && (agent.revokedAt === null || validSafeInteger(agent.revokedAt))
      && (agent.revokedReason === null || ['compromised', 'decommissioned', 'operator', 'reinstalled'].includes(String(agent.revokedReason))),
    );
  });

  const receiptsValid = state.receipts.every((entry) => {
    const receipt = exactRecord(entry, [
      'agentId', 'batchId', 'digest', 'receivedAt', 'recordKeys', 'recordDigests', 'priority',
      'queueFile', 'acceptedRecordCount', 'duplicateRecordCount',
    ]);
    return Boolean(
      receipt
      && typeof receipt.agentId === 'string' && UUID_V4.test(receipt.agentId)
      && typeof receipt.batchId === 'string' && UUID_V4.test(receipt.batchId)
      && typeof receipt.digest === 'string' && HEX_SHA256.test(receipt.digest)
      && validSafeInteger(receipt.receivedAt)
      && Array.isArray(receipt.recordKeys)
      && receipt.recordKeys.every((key) => typeof key === 'string' && HEX_SHA256.test(key))
      && Array.isArray(receipt.recordDigests)
      && receipt.recordDigests.length === receipt.recordKeys.length
      && receipt.recordDigests.every((digest) => typeof digest === 'string' && HEX_SHA256.test(digest))
      && (receipt.priority === 'priority' || receipt.priority === 'normal')
      && (receipt.queueFile === null || typeof receipt.queueFile === 'string' && /^[a-f0-9_-]+\.json\.enc$/u.test(receipt.queueFile))
      && validSafeInteger(receipt.acceptedRecordCount)
      && validSafeInteger(receipt.duplicateRecordCount),
    );
  });
  const tokens = state.tokens as EnrollmentTokenRecord[];
  const agents = state.agents as AgentRecord[];
  const receipts = state.receipts as BatchReceipt[];
  const uniqueTokens = new Set(tokens.map((token) => token.tokenId)).size === tokens.length;
  const uniqueAgents = new Set(agents.map((agent) => agent.agentId)).size === agents.length
    && new Set(agents.map((agent) => agent.hostId)).size === agents.length
    && new Set(agents.map((agent) => agent.machineIdentityKey)).size === agents.length
    && new Set(agents.map((agent) => agent.certificateFingerprintSha256)).size === agents.length;
  const uniqueReceipts = new Set(
    receipts.map((receipt) => `${receipt.agentId}\0${receipt.batchId}`),
  ).size === receipts.length;
  return tokensValid && agentsValid && receiptsValid && uniqueTokens && uniqueAgents && uniqueReceipts;
}

function initialState(): ControlState {
  return {
    schemaVersion: 1,
    tokens: [],
    agents: [],
    receipts: [],
    counters: {
      rejectedBatches: 0,
      rejectedRecords: 0,
      duplicateBatches: 0,
      duplicateRecords: 0,
      outOfOrderRecords: 0,
      expiredQueueBatches: 0,
    },
  };
}

function ensurePrivateDirectory(path: string): void {
  if (!existsSync(path)) mkdirSync(path, { recursive: true, mode: 0o700 });
  if (typeof process.geteuid !== 'function') {
    throw new Error(`Agent control path ownership cannot be validated: ${path}`);
  }
  const status = lstatSync(path);
  if (
    !status.isDirectory()
    || status.isSymbolicLink()
    || status.uid !== process.geteuid()
    || (status.mode & 0o077) !== 0
  ) {
    throw new Error(`Agent control path must be a private directory: ${path}`);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fileConstants.O_RDONLY | fileConstants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function atomicPrivateWrite(path: string, data: Buffer): void {
  const directory = dirname(path);
  const temporary = join(
    directory,
    `.${basename(path)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`,
  );
  let descriptor: number | null = null;
  try {
    descriptor = openSync(
      temporary,
      fileConstants.O_WRONLY
        | fileConstants.O_CREAT
        | fileConstants.O_EXCL
        | fileConstants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, data);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    renameSync(temporary, path);
    fsyncDirectory(directory);
  } catch (error) {
    if (descriptor !== null) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created or may already have been renamed.
    }
    throw error;
  }
}

function secureRead(path: string, maximumBytes: number): Buffer {
  if (typeof process.geteuid !== 'function') {
    throw new Error(`Agent control file ownership cannot be validated: ${path}`);
  }
  const expectedUid = process.geteuid();
  const before = lstatSync(path);
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.uid !== expectedUid
    || before.nlink !== 1
    || (before.mode & 0o077) !== 0
    || before.size > maximumBytes
  ) throw new Error(`Agent control file is unsafe: ${path}`);
  const descriptor = openSync(path, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== before.dev
      || opened.ino !== before.ino
      || !opened.isFile()
      || opened.uid !== expectedUid
      || opened.nlink !== 1
      || (opened.mode & 0o077) !== 0
      || opened.size > maximumBytes
    ) {
      throw new Error(`Agent control file changed while opening: ${path}`);
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

class EncryptedStore {
  constructor(private readonly keyring: AgentStorageKeyring) {}

  encode(purpose: string, value: unknown): Buffer {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) throw new Error('Agent control value cannot be serialized');
    return this.encodeSerialized(purpose, serialized);
  }

  encodeSerialized(purpose: string, plaintext: string): Buffer {
    const key = this.keyring.keys[this.keyring.activeKeyId];
    if (!key) throw new Error('Active agent storage key is unavailable');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(`monitor-agent:${purpose}:v1`, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      schemaVersion: 1,
      algorithm: 'aes-256-gcm',
      keyId: this.keyring.activeKeyId,
      iv: iv.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
    };
    return Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
  }

  decode(
    path: string,
    purpose: string,
    maximumBytes: number,
    maximumPlaintextBytes?: number,
  ): unknown {
    let parsed: unknown;
    try {
      parsed = JSON.parse(secureRead(path, maximumBytes).toString('utf8'));
    } catch (error) {
      throw new Error(`Agent control encrypted file cannot be read: ${path}`, { cause: error });
    }
    const envelope = exactRecord(parsed, [
      'schemaVersion', 'algorithm', 'keyId', 'iv', 'ciphertext', 'tag',
    ]);
    if (
      !envelope
      || envelope.schemaVersion !== 1
      || envelope.algorithm !== 'aes-256-gcm'
      || typeof envelope.keyId !== 'string'
      || typeof envelope.iv !== 'string'
      || typeof envelope.ciphertext !== 'string'
      || typeof envelope.tag !== 'string'
    ) throw new Error(`Agent control encrypted file has an invalid envelope: ${path}`);
    const key = this.keyring.keys[envelope.keyId];
    if (!key) throw new Error(`Agent control storage key is unavailable for ${path}`);
    try {
      const iv = Buffer.from(envelope.iv, 'base64url');
      const tag = Buffer.from(envelope.tag, 'base64url');
      if (iv.length !== 12 || tag.length !== 16) throw new Error('invalid IV or tag');
      const ciphertextBytes = maximumPlaintextBytes === undefined
        ? null
        : base64UrlDecodedLength(envelope.ciphertext);
      if (
        maximumPlaintextBytes !== undefined
        && (ciphertextBytes === null || ciphertextBytes > maximumPlaintextBytes)
      ) throw new Error('encrypted plaintext exceeds its purpose limit');
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
      if (ciphertextBytes !== null && ciphertext.length !== ciphertextBytes) {
        throw new Error('ciphertext is not canonical base64url');
      }
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(`monitor-agent:${purpose}:v1`, 'utf8'));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
      if (maximumPlaintextBytes !== undefined && plaintext.length > maximumPlaintextBytes) {
        throw new Error('decrypted plaintext exceeds its purpose limit');
      }
      return JSON.parse(plaintext.toString('utf8'));
    } catch (error) {
      throw new Error(`Agent control encrypted file authentication failed: ${path}`, { cause: error });
    }
  }
}

export function trustedAgentCertificate(
  request: Request,
  expectedEdgeSecret: string,
  now: number,
): TrustedAgentCertificate {
  const edgeSecret = request.get('x-portfolio-edge-secret');
  const verified = request.get('x-monitor-mtls-verified');
  const fingerprint = request.get('x-monitor-client-cert-sha256');
  const notAfterHeader = request.get('x-monitor-client-cert-not-after');
  if (!edgeSecret || !safeEqual(edgeSecret, expectedEdgeSecret) || verified !== 'SUCCESS') {
    throw new AgentControlError(
      401,
      'MTLS_PROXY_AUTH_REQUIRED',
      'A trusted proxy-verified client certificate is required',
    );
  }
  if (!fingerprint || !HEX_SHA256.test(fingerprint)) {
    throw new AgentControlError(401, 'CERTIFICATE_INVALID', 'Client certificate fingerprint is invalid');
  }
  const notAfter = parseTimestamp(notAfterHeader);
  if (notAfter === null) {
    throw new AgentControlError(401, 'CERTIFICATE_INVALID', 'Client certificate expiry is invalid');
  }
  if (notAfter <= now) {
    throw new AgentControlError(401, 'CERTIFICATE_EXPIRED', 'Client certificate has expired');
  }
  return { fingerprintSha256: fingerprint, notAfter };
}

export class AgentControlPlane {
  private readonly encrypted: EncryptedStore;
  private readonly statePath: string;
  private readonly queueRoot: string;
  private readonly priorityQueue: string;
  private readonly normalQueue: string;
  private state: ControlState;

  constructor(
    private readonly config: AgentControlRuntimeConfig,
    private readonly now: () => number = Date.now,
  ) {
    ensurePrivateDirectory(config.stateDir);
    this.queueRoot = join(config.stateDir, 'ingest-queue');
    this.priorityQueue = join(this.queueRoot, 'priority');
    this.normalQueue = join(this.queueRoot, 'normal');
    for (const path of [this.queueRoot, this.priorityQueue, this.normalQueue]) {
      ensurePrivateDirectory(path);
    }
    this.encrypted = new EncryptedStore(config.storageKeyring);
    this.statePath = join(config.stateDir, 'control-state.json.enc');
    if (existsSync(this.statePath)) {
      const decoded = this.encrypted.decode(
        this.statePath,
        'control-state',
        MAX_CONTROL_STATE_ENVELOPE_BYTES,
        MAX_CONTROL_STATE_PLAINTEXT_BYTES,
      );
      if (!stateIsValid(decoded)) throw new Error('Agent control state has an invalid contract');
      this.state = decoded;
    } else {
      this.state = initialState();
      this.persist(this.state);
    }
    this.pruneExpired(this.now());
    this.validateReceiptQueues();
  }

  private persist(next: ControlState): void {
    const encoded = this.encodeControlState(next);
    this.persistEncoded(next, encoded);
  }

  private encodeControlState(next: ControlState): Buffer {
    const serialized = JSON.stringify(next);
    const capacity = preflightAgentControlState(
      serialized,
      this.config.storageKeyring.activeKeyId,
    );
    const encoded = this.encrypted.encodeSerialized('control-state', serialized);
    if (encoded.length !== capacity.envelopeBytes) {
      throw new Error('Agent control encrypted envelope size invariant failed');
    }
    return encoded;
  }

  private persistEncoded(next: ControlState, encoded: Buffer): void {
    atomicPrivateWrite(this.statePath, encoded);
    this.state = next;
  }

  private copyState(): ControlState {
    return structuredClone(this.state);
  }

  private machineIdentityKey(machineIdentityDigest: string): string {
    return createHmac('sha256', this.config.proxyEdgeSecret)
      .update('monitor-machine-identity-v1\0', 'utf8')
      .update(machineIdentityDigest, 'utf8')
      .digest('hex');
  }

  private queuePath(priority: QueuePriority, file: string): string {
    return join(priority === 'priority' ? this.priorityQueue : this.normalQueue, file);
  }

  private validateReceiptQueue(receipt: BatchReceipt): void {
    if (receipt.queueFile === null) {
      if (receipt.acceptedRecordCount !== 0 || receipt.recordKeys.length !== 0) {
        throw new Error('Agent ingest receipt is missing its durable queue entry');
      }
      return;
    }
    const path = this.queuePath(receipt.priority, receipt.queueFile);
    if (!existsSync(path)) {
      throw new Error('Agent ingest receipt references a missing durable queue entry');
    }
    const decoded = this.encrypted.decode(
      path,
      'ingest-batch',
      this.config.maxBatchBytes * 4,
    );
    // Releases before homogeneous admission stored mixed accepted records as
    // one priority entry.  Keep those authenticated, receipt-bound files
    // readable until retention/downstream drain removes them; new requests and
    // all newly written queue entries still use the strict parser.
    const queued = parseQueuedBatch(decoded, this.config.maxRecordsPerBatch, true);
    if (
      !queued
      || queued.agentId !== receipt.agentId
      || queued.batchId !== receipt.batchId
      || queued.receivedAt !== receipt.receivedAt
      || queued.priority !== receipt.priority
      || !safeEqual(queued.digest, receipt.digest)
      || queued.records.length !== receipt.acceptedRecordCount
      || receipt.recordKeys.length !== receipt.acceptedRecordCount
      || receipt.recordDigests.length !== receipt.acceptedRecordCount
    ) {
      throw new Error('Agent ingest receipt does not match its durable queue entry');
    }
    queued.records.forEach((record, index) => {
      if (
        !safeEqual(this.recordKey(receipt.agentId, record), receipt.recordKeys[index]!)
        || !safeEqual(sha256(JSON.stringify(record)), receipt.recordDigests[index]!)
      ) {
        throw new Error('Agent ingest receipt record does not match its durable queue entry');
      }
    });
  }

  private validateReceiptQueues(): void {
    for (const receipt of this.state.receipts) this.validateReceiptQueue(receipt);
  }

  private pruneExpired(at: number): void {
    const next = this.copyState();
    let changed = false;
    const expiredQueuePaths: string[] = [];
    const tokenCutoff = at - TOKEN_AUDIT_RETENTION_MS;
    const filteredTokens = next.tokens.filter((token) => token.expiresAt >= tokenCutoff);
    if (filteredTokens.length !== next.tokens.length) {
      next.tokens = filteredTokens;
      changed = true;
    }
    const receiptCutoff = at - this.config.queueRetentionMs;
    const retainedReceipts: BatchReceipt[] = [];
    for (const receipt of next.receipts) {
      if (receipt.receivedAt >= receiptCutoff) {
        retainedReceipts.push(receipt);
        continue;
      }
      if (receipt.queueFile) {
        expiredQueuePaths.push(this.queuePath(receipt.priority, receipt.queueFile));
      }
      next.counters.expiredQueueBatches += 1;
      changed = true;
    }
    next.receipts = retainedReceipts;
    if (changed) this.persist(next);

    const knownFiles = new Set(
      this.state.receipts.flatMap((receipt) => (
        receipt.queueFile ? [`${receipt.priority}/${receipt.queueFile}`] : []
      )),
    );
    const expiredPaths = new Set(expiredQueuePaths);
    let priorityDirectoryChanged = false;
    let normalDirectoryChanged = false;
    for (const [priority, directory] of [
      ['priority', this.priorityQueue],
      ['normal', this.normalQueue],
    ] as const) {
      for (const file of readdirSync(directory)) {
        const path = join(directory, file);
        const status = lstatSync(path);
        if (
          !status.isFile()
          || status.isSymbolicLink()
          || typeof process.geteuid !== 'function'
          || status.uid !== process.geteuid()
          || status.nlink !== 1
          || (status.mode & 0o077) !== 0
        ) {
          throw new Error(`Agent ingest queue entry is unsafe: ${path}`);
        }
        if (
          expiredPaths.has(path)
          || !knownFiles.has(`${priority}/${file}`) && status.mtimeMs < receiptCutoff
        ) {
          unlinkSync(path);
          if (priority === 'priority') priorityDirectoryChanged = true;
          else normalDirectoryChanged = true;
        }
      }
    }
    if (priorityDirectoryChanged) fsyncDirectory(this.priorityQueue);
    if (normalDirectoryChanged) fsyncDirectory(this.normalQueue);
  }

  private consumeToken(
    next: ControlState,
    supplied: string,
    purpose: TokenPurpose,
    agentId: string,
    requestDigest: string,
    at: number,
  ): { token: EnrollmentTokenRecord; replay: boolean } {
    const match = ENROLLMENT_TOKEN.exec(supplied);
    if (!match) throw new AgentControlError(400, 'ENROLLMENT_TOKEN_INVALID', 'Enrollment token is invalid');
    const token = next.tokens.find((candidate) => candidate.tokenId === match[1]);
    const suppliedHash = sha256(supplied);
    if (!token || !safeEqual(token.tokenHash, suppliedHash) || token.purpose !== purpose) {
      throw new AgentControlError(401, 'ENROLLMENT_TOKEN_INVALID', 'Enrollment token is invalid');
    }
    if (token.boundAgentId !== null && token.boundAgentId !== agentId) {
      throw new AgentControlError(403, 'ENROLLMENT_TOKEN_SCOPE', 'Enrollment token is bound to another agent');
    }
    if (token.uses === 1) {
      if (token.consumedAgentId === agentId && token.requestDigest === requestDigest) {
        return { token, replay: true };
      }
      throw new AgentControlError(409, 'ENROLLMENT_TOKEN_CONSUMED', 'Enrollment token has already been used');
    }
    if (token.expiresAt <= at) {
      throw new AgentControlError(410, 'ENROLLMENT_TOKEN_EXPIRED', 'Enrollment token has expired');
    }
    token.uses = 1;
    token.consumedAt = at;
    token.consumedAgentId = agentId;
    token.requestDigest = requestDigest;
    return { token, replay: false };
  }

  issueEnrollmentToken(ttlSeconds: unknown, boundAgentId: string | null = null) {
    if (!validSafeInteger(ttlSeconds, 30) || ttlSeconds * 1_000 > this.config.maxEnrollmentTtlMs) {
      throw new AgentControlError(
        400,
        'INVALID_TOKEN_TTL',
        `Enrollment token TTL must be 30 through ${this.config.maxEnrollmentTtlMs / 1_000} seconds`,
      );
    }
    if (boundAgentId !== null && !UUID_V4.test(boundAgentId)) {
      throw new AgentControlError(400, 'INVALID_AGENT_ID', 'Agent ID is invalid');
    }
    const at = this.now();
    this.pruneExpired(at);
    if (this.state.tokens.length >= MAX_TOKENS) {
      throw new AgentControlError(503, 'TOKEN_STORE_FULL', 'Enrollment token store is full', 60);
    }
    const tokenId = randomBytes(16).toString('hex');
    const secret = randomBytes(32).toString('base64url');
    const plaintext = `menr_${tokenId}.${secret}`;
    const next = this.copyState();
    next.tokens.push({
      tokenId,
      tokenHash: sha256(plaintext),
      purpose: boundAgentId === null ? 'enrollment' : 'certificate-rotation',
      boundAgentId,
      issuedAt: at,
      expiresAt: at + ttlSeconds * 1_000,
      maxUses: 1,
      uses: 0,
      consumedAt: null,
      consumedAgentId: null,
      requestDigest: null,
    });
    this.persist(next);
    return {
      token: plaintext,
      tokenId,
      purpose: boundAgentId === null ? 'enrollment' as const : 'certificate-rotation' as const,
      boundAgentId,
      expiresAt: new Date(at + ttlSeconds * 1_000).toISOString(),
      maxUses: 1 as const,
    };
  }

  issueCertificateRotationToken(agentId: string, ttlSeconds: unknown) {
    if (!UUID_V4.test(agentId)) {
      throw new AgentControlError(400, 'INVALID_AGENT_ID', 'Agent ID is invalid');
    }
    const agent = this.state.agents.find((candidate) => candidate.agentId === agentId);
    if (!agent) throw new AgentControlError(404, 'AGENT_NOT_FOUND', 'Agent was not found');
    if (agent.revokedAt !== null) throw new AgentControlError(409, 'AGENT_REVOKED', 'Agent is revoked');
    return this.issueEnrollmentToken(ttlSeconds, agentId);
  }

  register(value: unknown, certificate: TrustedAgentCertificate, sourceAddress: string | null) {
    const registration = parseRegistration(value);
    if (!registration) {
      throw new AgentControlError(400, 'INVALID_REGISTRATION', 'Registration contract is invalid');
    }
    const at = this.now();
    if (registration.installationEpoch > at + this.config.maxClockSkewMs) {
      throw new AgentControlError(422, 'CLOCK_SKEW', 'Installation time is ahead of server time');
    }
    const machineIdentityKey = this.machineIdentityKey(registration.machineIdentityDigest);
    const requestDigest = sha256(JSON.stringify({
      ...registration,
      enrollmentToken: undefined,
      machineIdentityDigest: machineIdentityKey,
      certificateFingerprintSha256: certificate.fingerprintSha256,
      certificateNotAfter: certificate.notAfter,
    }));
    const next = this.copyState();
    const consumed = this.consumeToken(
      next,
      registration.enrollmentToken,
      'enrollment',
      registration.agentId,
      requestDigest,
      at,
    );
    const existingAgent = next.agents.find((agent) => agent.agentId === registration.agentId);
    if (consumed.replay) {
      if (!existingAgent) {
        throw new AgentControlError(409, 'REGISTRATION_INCOMPLETE', 'Registration replay cannot be recovered');
      }
      return this.publicAgent(existingAgent, at, true);
    }
    if (existingAgent) {
      throw new AgentControlError(409, 'AGENT_ID_CONFLICT', 'Agent ID is already registered');
    }
    if (next.agents.some((agent) => agent.hostId === registration.hostId)) {
      throw new AgentControlError(409, 'HOST_ID_CONFLICT', 'Host ID is already registered');
    }
    if (next.agents.some((agent) => agent.machineIdentityKey === machineIdentityKey)) {
      throw new AgentControlError(
        409,
        'MACHINE_IDENTITY_CONFLICT',
        'Machine identity requires operator reconciliation',
      );
    }
    if (next.agents.some((agent) => (
      agent.certificateFingerprintSha256 === certificate.fingerprintSha256
    ))) {
      throw new AgentControlError(409, 'CERTIFICATE_CONFLICT', 'Certificate is already bound');
    }
    const sourceIp = sourceAddress && isIP(sourceAddress) !== 0 ? sourceAddress : null;
    const inventory = sourceIp && !registration.inventory.ipAddresses.includes(sourceIp)
      ? { ...registration.inventory, ipAddresses: [...registration.inventory.ipAddresses, sourceIp].slice(0, 16) }
      : registration.inventory;
    const agent: AgentRecord = {
      agentId: registration.agentId,
      hostId: registration.hostId,
      machineIdentityKey,
      installationEpoch: registration.installationEpoch,
      registeredAt: at,
      lastSeenAt: at,
      lastObservedAt: at,
      expectedHeartbeatIntervalSeconds: registration.heartbeatIntervalSeconds,
      lifecycle: 'active',
      inventory,
      certificateFingerprintSha256: certificate.fingerprintSha256,
      certificateNotAfter: certificate.notAfter,
      lastHeartbeatSequence: 0,
      lastHeartbeatObservedAt: at,
      maxSequence: 0,
      rejectedClockSkewCount: 0,
      lastRejectedAt: null,
      revokedAt: null,
      revokedReason: null,
    };
    next.agents.push(agent);
    this.persist(next);
    return this.publicAgent(agent, at, false);
  }

  private authenticatedAgent(
    next: ControlState,
    agentId: string,
    certificate: TrustedAgentCertificate,
  ): AgentRecord {
    const agent = next.agents.find((candidate) => candidate.agentId === agentId);
    if (!agent) throw new AgentControlError(401, 'AGENT_UNREGISTERED', 'Agent is not registered');
    if (agent.revokedAt !== null) throw new AgentControlError(403, 'AGENT_REVOKED', 'Agent is revoked');
    if (!safeEqual(agent.certificateFingerprintSha256, certificate.fingerprintSha256)) {
      throw new AgentControlError(401, 'CERTIFICATE_UNBOUND', 'Certificate is not bound to this agent');
    }
    if (agent.certificateNotAfter !== certificate.notAfter) {
      throw new AgentControlError(401, 'CERTIFICATE_CONTRACT_MISMATCH', 'Certificate metadata does not match registration');
    }
    return agent;
  }

  heartbeat(value: unknown, certificate: TrustedAgentCertificate) {
    const heartbeat = parseHeartbeat(value);
    if (!heartbeat) throw new AgentControlError(400, 'INVALID_HEARTBEAT', 'Heartbeat contract is invalid');
    const at = this.now();
    const next = this.copyState();
    const agent = this.authenticatedAgent(next, heartbeat.agentId, certificate);
    const skew = heartbeat.observedAt - at;
    if (Math.abs(skew) > this.config.maxClockSkewMs) {
      agent.rejectedClockSkewCount += 1;
      agent.lastRejectedAt = at;
      this.persist(next);
      throw new AgentControlError(422, 'CLOCK_SKEW', 'Agent clock differs from server clock');
    }
    if (heartbeat.sequence < agent.lastHeartbeatSequence) {
      throw new AgentControlError(409, 'SEQUENCE_REWIND', 'Heartbeat sequence moved backwards');
    }
    if (heartbeat.sequence === agent.lastHeartbeatSequence) {
      if (
        heartbeat.observedAt !== agent.lastHeartbeatObservedAt
        || heartbeat.expectedIntervalSeconds !== agent.expectedHeartbeatIntervalSeconds
        || heartbeat.lifecycle !== agent.lifecycle
        || JSON.stringify(heartbeat.inventory) !== JSON.stringify(agent.inventory)
      ) {
        throw new AgentControlError(
          409,
          'SEQUENCE_CONFLICT',
          'Heartbeat sequence was reused with different content',
        );
      }
      return {
        accepted: true,
        duplicate: true,
        serverTime: new Date(at).toISOString(),
        status: this.status(agent, at),
        certificate: this.publicCertificate(agent, at),
      };
    }
    agent.lastHeartbeatSequence = heartbeat.sequence;
    agent.lastHeartbeatObservedAt = heartbeat.observedAt;
    agent.maxSequence = Math.max(agent.maxSequence, heartbeat.sequence);
    agent.lastSeenAt = at;
    agent.lastObservedAt = heartbeat.observedAt;
    agent.expectedHeartbeatIntervalSeconds = heartbeat.expectedIntervalSeconds;
    agent.lifecycle = heartbeat.lifecycle;
    agent.inventory = heartbeat.inventory;
    this.persist(next);
    return {
      accepted: true,
      duplicate: false,
      serverTime: new Date(at).toISOString(),
      clockSkewSeconds: skew / 1_000,
      status: this.status(agent, at),
      certificate: this.publicCertificate(agent, at),
    };
  }

  rotateCertificate(value: unknown, certificate: TrustedAgentCertificate) {
    const body = exactRecord(value, ['schemaVersion', 'agentId', 'rotationToken']);
    if (
      !body
      || body.schemaVersion !== 1
      || typeof body.agentId !== 'string'
      || !UUID_V4.test(body.agentId)
      || typeof body.rotationToken !== 'string'
      || !ENROLLMENT_TOKEN.test(body.rotationToken)
    ) throw new AgentControlError(400, 'INVALID_CERTIFICATE_ROTATION', 'Certificate rotation contract is invalid');
    const at = this.now();
    const requestDigest = sha256(JSON.stringify({
      agentId: body.agentId,
      fingerprint: certificate.fingerprintSha256,
      notAfter: certificate.notAfter,
    }));
    const next = this.copyState();
    const agent = next.agents.find((candidate) => candidate.agentId === body.agentId);
    if (!agent) throw new AgentControlError(401, 'AGENT_UNREGISTERED', 'Agent is not registered');
    if (agent.revokedAt !== null) throw new AgentControlError(403, 'AGENT_REVOKED', 'Agent is revoked');
    const consumed = this.consumeToken(
      next,
      body.rotationToken,
      'certificate-rotation',
      body.agentId,
      requestDigest,
      at,
    );
    if (consumed.replay) {
      if (
        agent.certificateFingerprintSha256 !== certificate.fingerprintSha256
        || agent.certificateNotAfter !== certificate.notAfter
      ) throw new AgentControlError(409, 'CERTIFICATE_ROTATION_CONFLICT', 'Certificate rotation replay conflicts');
      return { rotated: true, duplicate: true, certificate: this.publicCertificate(agent, at) };
    }
    if (next.agents.some((candidate) => (
      candidate.agentId !== agent.agentId
      && candidate.certificateFingerprintSha256 === certificate.fingerprintSha256
    ))) throw new AgentControlError(409, 'CERTIFICATE_CONFLICT', 'Certificate is already bound');
    agent.certificateFingerprintSha256 = certificate.fingerprintSha256;
    agent.certificateNotAfter = certificate.notAfter;
    agent.lastSeenAt = at;
    this.persist(next);
    return { rotated: true, duplicate: false, certificate: this.publicCertificate(agent, at) };
  }

  revoke(agentId: string, reason: unknown) {
    if (!UUID_V4.test(agentId)) throw new AgentControlError(400, 'INVALID_AGENT_ID', 'Agent ID is invalid');
    if (!['compromised', 'decommissioned', 'operator', 'reinstalled'].includes(String(reason))) {
      throw new AgentControlError(400, 'INVALID_REVOCATION_REASON', 'Revocation reason is invalid');
    }
    const at = this.now();
    const next = this.copyState();
    const agent = next.agents.find((candidate) => candidate.agentId === agentId);
    if (!agent) throw new AgentControlError(404, 'AGENT_NOT_FOUND', 'Agent was not found');
    const duplicate = agent.revokedAt !== null;
    if (duplicate && agent.revokedReason !== reason) {
      throw new AgentControlError(409, 'REVOCATION_CONFLICT', 'Agent is already revoked for another reason');
    }
    if (agent.revokedAt === null) {
      agent.revokedAt = at;
      agent.revokedReason = reason as AgentRecord['revokedReason'];
      agent.lifecycle = 'inactive';
      this.persist(next);
    }
    return this.publicAgent(agent, at, duplicate);
  }

  private recordKey(agentId: string, record: NormalizedIngestRecord): string {
    return sha256([
      agentId,
      record.metric,
      record.target,
      new Date(record.observedAt).toISOString(),
      String(record.sequence),
    ].join('\0'));
  }

  private queueUsage(selectedAgentId?: string): QueueUsage {
    const usage: QueueUsage = {
      entries: 0,
      bytes: 0,
      priorityEntries: 0,
      priorityBytes: 0,
      normalEntries: 0,
      normalBytes: 0,
      selectedAgentEntries: 0,
      selectedAgentBytes: 0,
    };
    for (const [priority, directory] of [
      ['priority', this.priorityQueue],
      ['normal', this.normalQueue],
    ] as const) {
      for (const file of readdirSync(directory)) {
        const path = join(directory, file);
        const status = lstatSync(path);
        if (
          !status.isFile()
          || status.isSymbolicLink()
          || typeof process.geteuid !== 'function'
          || status.uid !== process.geteuid()
          || status.nlink !== 1
          || (status.mode & 0o077) !== 0
        ) {
          throw new Error(`Agent ingest queue entry is unsafe: ${path}`);
        }
        usage.entries += 1;
        usage.bytes += status.size;
        if (selectedAgentId && file.startsWith(`${selectedAgentId}_`)) {
          usage.selectedAgentEntries += 1;
          usage.selectedAgentBytes += status.size;
        }
        if (priority === 'priority') {
          usage.priorityEntries += 1;
          usage.priorityBytes += status.size;
        } else {
          usage.normalEntries += 1;
          usage.normalBytes += status.size;
        }
      }
    }
    return usage;
  }

  ingest(value: unknown, certificate: TrustedAgentCertificate) {
    const batch = parseBatch(value, this.config.maxRecordsPerBatch, true);
    if (!batch) throw new AgentControlError(400, 'INVALID_INGEST_BATCH', 'Ingest batch contract is invalid');
    const homogeneous = new Set(batch.records.map((record) => record.kind)).size === 1;
    if (!homogeneous) {
      const legacyDigest = sha256(JSON.stringify(batch));
      const legacyReceipt = this.state.receipts.find((receipt) => (
        receipt.agentId === batch.agentId && receipt.batchId === batch.batchId
      ));
      // Mixed input can cross the parser only when it is byte-equivalent after
      // normalization to a receipt created by the pre-homogeneous release.
      // Unknown or changed mixed batches are rejected before authentication or
      // any queue/state mutation and can never consume priority reserve.
      if (!legacyReceipt || !safeEqual(legacyReceipt.digest, legacyDigest)) {
        throw new AgentControlError(400, 'INVALID_INGEST_BATCH', 'Ingest batch contract is invalid');
      }
    }
    const at = this.now();
    this.pruneExpired(at);
    const next = this.copyState();
    const agent = this.authenticatedAgent(next, batch.agentId, certificate);
    const normalizedDigest = sha256(JSON.stringify(batch));
    const existingReceipt = next.receipts.find((receipt) => (
      receipt.agentId === batch.agentId && receipt.batchId === batch.batchId
    ));
    if (existingReceipt) {
      if (!safeEqual(existingReceipt.digest, normalizedDigest)) {
        throw new AgentControlError(409, 'BATCH_ID_CONFLICT', 'Batch ID was reused with different content');
      }
      this.validateReceiptQueue(existingReceipt);
      next.counters.duplicateBatches += 1;
      this.persist(next);
      return {
        accepted: true,
        duplicate: true,
        batchId: batch.batchId,
        acceptedRecords: existingReceipt.acceptedRecordCount,
        duplicateRecords: existingReceipt.duplicateRecordCount,
        serverTime: new Date(at).toISOString(),
      };
    }
    if (!homogeneous) {
      throw new AgentControlError(400, 'INVALID_INGEST_BATCH', 'Ingest batch contract is invalid');
    }
    if (batch.sentAt > at + this.config.maxClockSkewMs) {
      agent.rejectedClockSkewCount += 1;
      agent.lastRejectedAt = at;
      this.persist(next);
      throw new AgentControlError(422, 'CLOCK_SKEW', 'Batch send time is ahead of server time');
    }
    if (batch.sentAt < at - this.config.maxBackfillAgeMs) {
      throw new AgentControlError(422, 'BATCH_TOO_OLD', 'Batch exceeds the offline replay window');
    }
    for (const record of batch.records) {
      if (record.observedAt > at + this.config.maxClockSkewMs) {
        agent.rejectedClockSkewCount += 1;
        agent.lastRejectedAt = at;
        this.persist(next);
        throw new AgentControlError(422, 'CLOCK_SKEW', 'Record time is ahead of server time');
      }
      if (record.observedAt < at - this.config.maxBackfillAgeMs) {
        throw new AgentControlError(422, 'DATA_TOO_OLD', 'Record exceeds the offline replay window');
      }
    }
    if (next.receipts.length >= this.config.maxBatchReceipts) {
      next.counters.rejectedBatches += 1;
      next.counters.rejectedRecords += batch.records.length;
      this.persist(next);
      throw new AgentControlError(429, 'RECEIPT_BACKPRESSURE', 'Batch receipt window is full', 30);
    }
    const agentReceiptCount = next.receipts.filter((receipt) => receipt.agentId === batch.agentId).length;
    if (agentReceiptCount >= this.config.maxBatchReceiptsPerAgent) {
      next.counters.rejectedBatches += 1;
      next.counters.rejectedRecords += batch.records.length;
      this.persist(next);
      throw new AgentControlError(429, 'AGENT_QUOTA_BACKPRESSURE', 'Agent receipt quota is full', 30);
    }

    const existingRecords = new Map<string, string>();
    for (const receipt of next.receipts) {
      receipt.recordKeys.forEach((key, index) => {
        existingRecords.set(key, receipt.recordDigests[index]!);
      });
    }
    const batchKeys = new Set<string>();
    const accepted: NormalizedIngestRecord[] = [];
    const acceptedKeys: string[] = [];
    const acceptedDigests: string[] = [];
    let duplicateRecords = 0;
    let outOfOrderRecords = 0;
    for (const record of batch.records) {
      const key = this.recordKey(batch.agentId, record);
      if (batchKeys.has(key)) {
        throw new AgentControlError(400, 'DUPLICATE_RECORD_IN_BATCH', 'Batch repeats an idempotency key');
      }
      batchKeys.add(key);
      const recordDigest = sha256(JSON.stringify(record));
      const existingRecordDigest = existingRecords.get(key);
      if (existingRecordDigest !== undefined) {
        if (!safeEqual(existingRecordDigest, recordDigest)) {
          throw new AgentControlError(
            409,
            'RECORD_IDEMPOTENCY_CONFLICT',
            'Record idempotency key was reused with different content',
          );
        }
        duplicateRecords += 1;
        continue;
      }
      if (record.sequence < agent.maxSequence) outOfOrderRecords += 1;
      accepted.push(record);
      acceptedKeys.push(key);
      acceptedDigests.push(recordDigest);
    }
    const currentIdempotencyRecords = next.receipts.reduce(
      (total, receipt) => total + receipt.recordKeys.length,
      0,
    );
    const agentIdempotencyRecords = next.receipts
      .filter((receipt) => receipt.agentId === batch.agentId)
      .reduce((total, receipt) => total + receipt.recordKeys.length, 0);
    if (
      agentIdempotencyRecords + acceptedKeys.length
      > this.config.maxIdempotencyRecordsPerAgent
    ) {
      next.counters.rejectedBatches += 1;
      next.counters.rejectedRecords += batch.records.length;
      this.persist(next);
      throw new AgentControlError(429, 'AGENT_QUOTA_BACKPRESSURE', 'Agent idempotency quota is full', 30);
    }
    if (currentIdempotencyRecords + acceptedKeys.length > this.config.maxIdempotencyRecords) {
      next.counters.rejectedBatches += 1;
      next.counters.rejectedRecords += batch.records.length;
      this.persist(next);
      throw new AgentControlError(429, 'IDEMPOTENCY_BACKPRESSURE', 'Idempotency window is full', 30);
    }

    const priority: QueuePriority = batch.records[0]!.kind === 'event'
      ? 'priority'
      : 'normal';
    let queueFile: string | null = null;
    let queueWrite: { target: string; encoded: Buffer } | null = null;
    let receiptReceivedAt = at;
    if (accepted.length > 0) {
      const queued: QueuedBatch = {
        schemaVersion: 1,
        agentId: batch.agentId,
        batchId: batch.batchId,
        receivedAt: at,
        sentAt: batch.sentAt,
        firstSequence: Math.min(...accepted.map((record) => record.sequence)),
        lastSequence: Math.max(...accepted.map((record) => record.sequence)),
        priority,
        digest: normalizedDigest,
        records: accepted.map((record) => ({
          ...record,
          observedAt: new Date(record.observedAt).toISOString(),
        })),
      };
      const encoded = this.encrypted.encode('ingest-batch', queued);
      queueFile = `${batch.agentId}_${batch.batchId}.json.enc`;
      const target = this.queuePath(priority, queueFile);
      if (existsSync(target)) {
        const existing = parseQueuedBatch(
          this.encrypted.decode(target, 'ingest-batch', this.config.maxBatchBytes * 4),
          this.config.maxRecordsPerBatch,
        );
        if (
          !existing
          || existing.agentId !== batch.agentId
          || existing.batchId !== batch.batchId
          || existing.sentAt !== batch.sentAt
          || existing.priority !== priority
          || !safeEqual(existing.digest, normalizedDigest)
          || existing.records.length !== accepted.length
          || existing.records.some((record, index) => (
            JSON.stringify(record) !== JSON.stringify(accepted[index])
          ))
        ) {
          throw new AgentControlError(409, 'BATCH_ID_CONFLICT', 'Queued batch conflicts with retry');
        }
        receiptReceivedAt = existing.receivedAt;
      } else {
        const usage = this.queueUsage(batch.agentId);
        const reservedEntries = Math.max(
          1,
          Math.ceil(this.config.maxQueueEntries * this.config.priorityReservePercent / 100),
        );
        const reservedBytes = Math.ceil(
          this.config.maxQueueBytes * this.config.priorityReservePercent / 100,
        );
        const entryLimit = priority === 'normal'
          ? this.config.maxQueueEntries - reservedEntries
          : this.config.maxQueueEntries;
        const byteLimit = priority === 'normal'
          ? this.config.maxQueueBytes - reservedBytes
          : this.config.maxQueueBytes;
        if (
          usage.selectedAgentEntries + 1 > this.config.maxQueueEntriesPerAgent
          || usage.selectedAgentBytes + encoded.length > this.config.maxQueueBytesPerAgent
        ) {
          next.counters.rejectedBatches += 1;
          next.counters.rejectedRecords += batch.records.length;
          this.persist(next);
          throw new AgentControlError(429, 'AGENT_QUOTA_BACKPRESSURE', 'Agent queue quota is full', 30);
        }
        if (usage.entries + 1 > entryLimit || usage.bytes + encoded.length > byteLimit) {
          next.counters.rejectedBatches += 1;
          next.counters.rejectedRecords += batch.records.length;
          this.persist(next);
          throw new AgentControlError(429, 'INGEST_BACKPRESSURE', 'Durable ingest queue is full', 30);
        }
        queueWrite = { target, encoded };
      }
    }

    next.receipts.push({
      agentId: batch.agentId,
      batchId: batch.batchId,
      digest: normalizedDigest,
      receivedAt: receiptReceivedAt,
      recordKeys: acceptedKeys,
      recordDigests: acceptedDigests,
      priority,
      queueFile,
      acceptedRecordCount: accepted.length,
      duplicateRecordCount: duplicateRecords,
    });
    next.counters.duplicateRecords += duplicateRecords;
    next.counters.outOfOrderRecords += outOfOrderRecords;
    agent.maxSequence = Math.max(agent.maxSequence, batch.lastSequence);
    agent.lastSeenAt = at;
    agent.lastObservedAt = Math.max(agent.lastObservedAt, ...batch.records.map((record) => record.observedAt));
    const encodedState = this.encodeControlState(next);
    if (queueWrite) atomicPrivateWrite(queueWrite.target, queueWrite.encoded);
    this.persistEncoded(next, encodedState);
    return {
      accepted: true,
      duplicate: false,
      batchId: batch.batchId,
      acceptedRecords: accepted.length,
      duplicateRecords,
      outOfOrderRecords,
      priority,
      serverTime: new Date(at).toISOString(),
    };
  }

  private status(agent: AgentRecord, at: number): AgentStatus {
    if (agent.revokedAt !== null) return 'revoked';
    if (agent.lifecycle === 'maintenance') return 'maintenance';
    if (agent.lifecycle === 'inactive') return 'inactive';
    const age = Math.max(0, at - agent.lastSeenAt);
    const interval = agent.expectedHeartbeatIntervalSeconds * 1_000;
    if (age > Math.max(24 * 60 * 60 * 1_000, interval * 60)) return 'inactive';
    if (age > Math.max(5 * 60 * 1_000, interval * 5)) return 'disconnected';
    if (age > Math.max(90 * 1_000, interval * 2)) return 'delayed';
    return 'healthy';
  }

  private publicCertificate(agent: AgentRecord, at: number) {
    return {
      expiresAt: new Date(agent.certificateNotAfter).toISOString(),
      renewalRequired: agent.certificateNotAfter - at <= this.config.certificateExpiryWarningMs,
    };
  }

  private publicAgent(agent: AgentRecord, at: number, duplicate: boolean) {
    return {
      registered: true,
      duplicate,
      agentId: agent.agentId,
      hostId: agent.hostId,
      installationEpoch: new Date(agent.installationEpoch).toISOString(),
      registeredAt: new Date(agent.registeredAt).toISOString(),
      lastSeenAt: new Date(agent.lastSeenAt).toISOString(),
      lastObservedAt: new Date(agent.lastObservedAt).toISOString(),
      lifecycle: agent.lifecycle,
      status: this.status(agent, at),
      expectedHeartbeatIntervalSeconds: agent.expectedHeartbeatIntervalSeconds,
      maxSequence: agent.maxSequence,
      inventory: agent.inventory,
      certificate: this.publicCertificate(agent, at),
      clockRejections: {
        count: agent.rejectedClockSkewCount,
        lastRejectedAt: agent.lastRejectedAt === null
          ? null
          : new Date(agent.lastRejectedAt).toISOString(),
      },
      revokedAt: agent.revokedAt === null ? null : new Date(agent.revokedAt).toISOString(),
      revokedReason: agent.revokedReason,
      serverTime: new Date(at).toISOString(),
    };
  }

  listAgents() {
    const at = this.now();
    this.pruneExpired(at);
    this.validateReceiptQueues();
    const {
      selectedAgentEntries: _selectedAgentEntries,
      selectedAgentBytes: _selectedAgentBytes,
      ...usage
    } = this.queueUsage();
    return {
      serverTime: new Date(at).toISOString(),
      transport: {
        tlsTermination: 'trusted-reverse-proxy' as const,
        applicationVerifies: ['edge-secret', 'mtls-verified-marker', 'certificate-sha256-binding'],
      },
      queue: {
        ...usage,
        maxEntries: this.config.maxQueueEntries,
        maxBytes: this.config.maxQueueBytes,
        maxBatchReceipts: this.config.maxBatchReceipts,
        maxQueueEntriesPerAgent: this.config.maxQueueEntriesPerAgent,
        maxQueueBytesPerAgent: this.config.maxQueueBytesPerAgent,
        maxBatchReceiptsPerAgent: this.config.maxBatchReceiptsPerAgent,
        maxIdempotencyRecordsPerAgent: this.config.maxIdempotencyRecordsPerAgent,
        priorityReservePercent: this.config.priorityReservePercent,
        rejectedBatches: this.state.counters.rejectedBatches,
        rejectedRecords: this.state.counters.rejectedRecords,
        duplicateBatches: this.state.counters.duplicateBatches,
        duplicateRecords: this.state.counters.duplicateRecords,
        outOfOrderRecords: this.state.counters.outOfOrderRecords,
        expiredQueueBatches: this.state.counters.expiredQueueBatches,
      },
      agents: this.state.agents.map((agent) => this.publicAgent(agent, at, false)),
    };
  }
}
