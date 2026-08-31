import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import type { Stats } from 'node:fs';
import {
  createHash,
  randomBytes as systemRandomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { isIP } from 'node:net';
import { basename, join, resolve } from 'node:path';

const STATE_SCHEMA_VERSION = 2 as const;
const LEGACY_STATE_SCHEMA_VERSION = 1 as const;
const AUDIT_SCHEMA_VERSION = 1 as const;
const API_KEY_FILE_NAME = 'api-keys.json';
const AUDIT_FILE_NAME = 'application-audit.jsonl';
const MAX_STATE_BYTES = 128 * 1024;
const MAX_API_KEYS = 128;
const DEFAULT_MAX_API_KEYS = 64;
const MAX_SOURCE_IP_ALLOWLIST_ENTRIES = 32;
const API_KEY_BYTES = 32;
const API_KEY_ID_BYTES = 16;
const MAX_KEY_LIFETIME_MS = 366 * 24 * 60 * 60 * 1_000;
const MIN_LAST_USED_WRITE_INTERVAL_MS = 1_000;
const MAX_LAST_USED_WRITE_INTERVAL_MS = 60 * 60 * 1_000;
const DEFAULT_LAST_USED_WRITE_INTERVAL_MS = 60 * 1_000;
const TOMBSTONE_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_RETAINED_TOMBSTONES = 16;
const MAX_AUDIT_RECORD_BYTES = 2 * 1024;
const MIN_AUDIT_FILE_BYTES = 512;
const MAX_AUDIT_FILE_BYTES = 16 * 1024 * 1024;
const DEFAULT_AUDIT_FILE_BYTES = 1024 * 1024;
const MIN_AUDIT_RETENTION_FILES = 2;
const MAX_AUDIT_RETENTION_FILES = 10;
const DEFAULT_AUDIT_RETENTION_FILES = 4;
const API_KEY_DIGEST_DOMAIN = Buffer.from(
  'monitor.application-security.api-key.v1\0',
  'utf8',
);
const SOURCE_IP_DIGEST_DOMAIN = Buffer.from(
  'monitor.application-security.source-ip.v1\0',
  'utf8',
);

export const APPLICATION_API_KEY_SCOPES = [
  'dashboard:read',
  'logs:read',
  'agents:read',
  'agents:write',
  'infrastructure-ledger:read',
  'system-updates:read',
  'system-updates:check',
  'system-updates:apply',
  'auth-inventory:read',
] as const;

export const APPLICATION_AUDIT_ROLES = [
  'user',
  'admin',
  'chief-admin',
  'local-owner',
  'api-key',
  'agent',
  'system',
] as const;

export const APPLICATION_AUDIT_OUTCOMES = [
  'intent',
  'success',
  'denied',
  'failure',
] as const;

export type ApplicationApiKeyScope = typeof APPLICATION_API_KEY_SCOPES[number];
export type ApplicationAuditRole = typeof APPLICATION_AUDIT_ROLES[number];
export type ApplicationAuditOutcome = typeof APPLICATION_AUDIT_OUTCOMES[number];

export interface ApplicationAuditInput {
  requestId: string;
  actor: {
    subject: string;
    role: ApplicationAuditRole;
  };
  action: string;
  target: string;
  outcome: ApplicationAuditOutcome;
  sourceIp: string | null;
}

export interface ApplicationAuditRecord {
  schemaVersion: 1;
  timestamp: string;
  requestId: string;
  actor: {
    subject: string;
    role: ApplicationAuditRole;
  };
  action: string;
  target: string;
  outcome: ApplicationAuditOutcome;
  sourceIpHash: string | null;
}

export interface IssueApiKeyInput {
  name: string;
  scopes: readonly ApplicationApiKeyScope[];
  expiresAt: string;
  sourceIpAllowlist?: readonly string[];
}

export interface RotateApiKeyInput {
  id: string;
  expiresAt: string;
}

export interface ApplicationApiKeyMetadata {
  id: string;
  name: string;
  scopes: ApplicationApiKeyScope[];
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  sourceIpAllowlist: string[];
}

export interface IssuedApplicationApiKey extends ApplicationApiKeyMetadata {
  token: string;
}

export interface AuthenticatedApplicationApiKey {
  id: string;
  name: string;
  scopes: ApplicationApiKeyScope[];
}

export interface ApplicationApiKeyAuthentication {
  principal: AuthenticatedApplicationApiKey;
  requiredScopesSatisfied: boolean;
}

export interface ApplicationSecurityStateOptions {
  now?: () => number;
  randomBytes?: (size: number) => Buffer;
  ownerUid?: number;
  maxApiKeys?: number;
  auditMaxBytes?: number;
  auditRetentionFiles?: number;
  lastUsedWriteIntervalMs?: number;
  syncDirectory?: (directory: string) => void;
  onDurabilityWarning?: (message: string) => void;
}

interface StoredApiKey extends ApplicationApiKeyMetadata {
  digest: string;
}

interface ApiKeyState {
  schemaVersion: 2;
  keys: StoredApiKey[];
}

interface ParsedApiKeyState {
  state: ApiKeyState;
  needsMigration: boolean;
}

type JsonRecord = Record<string, unknown>;

const SCOPE_ORDER = new Map<ApplicationApiKeyScope, number>(
  APPLICATION_API_KEY_SCOPES.map((scope, index) => [scope, index]),
);
const API_KEY_SCOPES = new Set<string>(APPLICATION_API_KEY_SCOPES);
const AUDIT_ROLES = new Set<string>(APPLICATION_AUDIT_ROLES);
const AUDIT_OUTCOMES = new Set<string>(APPLICATION_AUDIT_OUTCOMES);
const STATE_FIELDS = ['schemaVersion', 'keys'] as const;
const LEGACY_KEY_FIELDS = [
  'id',
  'name',
  'scopes',
  'digest',
  'createdAt',
  'expiresAt',
  'lastUsedAt',
  'revokedAt',
] as const;
const KEY_FIELDS = [
  ...LEGACY_KEY_FIELDS,
  'sourceIpAllowlist',
] as const;
const AUDIT_FIELDS = [
  'schemaVersion',
  'timestamp',
  'requestId',
  'actor',
  'action',
  'target',
  'outcome',
  'sourceIpHash',
] as const;
const AUDIT_ACTOR_FIELDS = ['subject', 'role'] as const;
const ISSUE_FIELDS = ['name', 'scopes', 'expiresAt'] as const;
const ISSUE_FIELDS_WITH_SOURCE_IPS = [
  ...ISSUE_FIELDS,
  'sourceIpAllowlist',
] as const;
const ROTATE_FIELDS = ['id', 'expiresAt'] as const;

export const applicationSecurityStateLimits = Object.freeze({
  apiKeyFileName: API_KEY_FILE_NAME,
  auditFileName: AUDIT_FILE_NAME,
  maximumStateBytes: MAX_STATE_BYTES,
  maximumApiKeys: MAX_API_KEYS,
  maximumSourceIpAllowlistEntries: MAX_SOURCE_IP_ALLOWLIST_ENTRIES,
  maximumKeyLifetimeMs: MAX_KEY_LIFETIME_MS,
  defaultLastUsedWriteIntervalMs: DEFAULT_LAST_USED_WRITE_INTERVAL_MS,
  tombstoneRetentionMs: TOMBSTONE_RETENTION_MS,
  maximumRetainedTombstones: MAX_RETAINED_TOMBSTONES,
  maximumAuditRecordBytes: MAX_AUDIT_RECORD_BYTES,
  maximumAuditFileBytes: MAX_AUDIT_FILE_BYTES,
  maximumAuditRetentionFiles: MAX_AUDIT_RETENTION_FILES,
});

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(value: JsonRecord, fields: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length
    && actual.every((field, index) => field === expected[index]);
}

function canonicalTimestamp(value: unknown): string | null {
  if (
    typeof value !== 'string'
    || value.length !== 24
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  ) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  return new Date(milliseconds).toISOString() === value ? value : null;
}

function timestampAt(milliseconds: number): string {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
    throw new Error('Application security clock returned an invalid timestamp');
  }
  try {
    return new Date(milliseconds).toISOString();
  } catch {
    throw new Error('Application security clock returned an invalid timestamp');
  }
}

function normalizeName(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().replace(/\s+/gu, ' ');
  if (
    normalized.length < 1
    || normalized.length > 64
    || !/^[\p{L}\p{N}][\p{L}\p{N} ._-]*$/u.test(normalized)
  ) return null;
  return normalized;
}

function validKeyId(value: unknown): value is string {
  return typeof value === 'string'
    && /^key_[A-Za-z0-9_-]{22}$/u.test(value);
}

function validDigest(value: unknown): value is string {
  return typeof value === 'string'
    && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function normalizeScopes(value: unknown): ApplicationApiKeyScope[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > APPLICATION_API_KEY_SCOPES.length) {
    return null;
  }
  const scopes: ApplicationApiKeyScope[] = [];
  const seen = new Set<string>();
  for (const candidate of value) {
    if (typeof candidate !== 'string' || !API_KEY_SCOPES.has(candidate) || seen.has(candidate)) {
      return null;
    }
    seen.add(candidate);
    scopes.push(candidate as ApplicationApiKeyScope);
  }
  scopes.sort((left, right) => SCOPE_ORDER.get(left)! - SCOPE_ORDER.get(right)!);
  return scopes;
}

function scopesAreCanonical(value: unknown): value is ApplicationApiKeyScope[] {
  const normalized = normalizeScopes(value);
  return normalized !== null
    && Array.isArray(value)
    && normalized.every((scope, index) => scope === value[index]);
}

function canonicalIpAddress(value: unknown): string | null {
  if (typeof value !== 'string' || value.length < 2 || value.length > 45 || value.includes('%')) {
    return null;
  }
  const family = isIP(value);
  if (family === 4) return value;
  if (family !== 6) return null;
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    const normalized = hostname.slice(1, -1).toLowerCase();
    const mappedIpv4 = /^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/u.exec(normalized);
    if (mappedIpv4) {
      const high = Number.parseInt(mappedIpv4[1]!, 16);
      const low = Number.parseInt(mappedIpv4[2]!, 16);
      return [high >>> 8, high & 0xff, low >>> 8, low & 0xff].join('.');
    }
    return normalized;
  } catch {
    return null;
  }
}

function normalizeSourceIpAllowlist(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_SOURCE_IP_ALLOWLIST_ENTRIES) return null;
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const candidate of value) {
    const address = canonicalIpAddress(candidate);
    if (address === null || seen.has(address)) return null;
    seen.add(address);
    normalized.push(address);
  }
  normalized.sort();
  return normalized;
}

function sourceIpAllowlistIsCanonical(value: unknown): value is string[] {
  const normalized = normalizeSourceIpAllowlist(value);
  return normalized !== null
    && Array.isArray(value)
    && normalized.every((address, index) => address === value[index]);
}

function nullableTimestamp(value: unknown): string | null | undefined {
  if (value === null) return null;
  return canonicalTimestamp(value) ?? undefined;
}

function parseStoredKey(value: unknown, legacy: boolean): StoredApiKey | null {
  if (!isRecord(value) || !hasExactFields(value, legacy ? LEGACY_KEY_FIELDS : KEY_FIELDS)) return null;
  const name = normalizeName(value.name);
  const createdAt = canonicalTimestamp(value.createdAt);
  const expiresAt = canonicalTimestamp(value.expiresAt);
  const lastUsedAt = nullableTimestamp(value.lastUsedAt);
  const revokedAt = nullableTimestamp(value.revokedAt);
  if (
    !validKeyId(value.id)
    || name === null
    || name !== value.name
    || !scopesAreCanonical(value.scopes)
    || !validDigest(value.digest)
    || createdAt === null
    || expiresAt === null
    || lastUsedAt === undefined
    || revokedAt === undefined
    || (!legacy && !sourceIpAllowlistIsCanonical(value.sourceIpAllowlist))
  ) return null;

  const created = Date.parse(createdAt);
  const expires = Date.parse(expiresAt);
  const lastUsed = lastUsedAt === null ? null : Date.parse(lastUsedAt);
  const revoked = revokedAt === null ? null : Date.parse(revokedAt);
  if (
    expires <= created
    || expires - created > MAX_KEY_LIFETIME_MS
    || (lastUsed !== null && (lastUsed < created || lastUsed >= expires))
    || (revoked !== null && revoked < created)
    || (lastUsed !== null && revoked !== null && lastUsed > revoked)
  ) return null;

  return {
    id: value.id,
    name,
    scopes: [...value.scopes],
    digest: value.digest,
    createdAt,
    expiresAt,
    lastUsedAt,
    revokedAt,
    sourceIpAllowlist: legacy ? [] : [...(value.sourceIpAllowlist as string[])],
  };
}

function parseState(serialized: string, maximumKeys: number): ParsedApiKeyState {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error('Application API key state is not valid JSON');
  }
  if (!isRecord(value) || !hasExactFields(value, STATE_FIELDS)) {
    throw new Error('Application API key state has an invalid schema');
  }
  const legacy = value.schemaVersion === LEGACY_STATE_SCHEMA_VERSION;
  if (
    (!legacy && value.schemaVersion !== STATE_SCHEMA_VERSION)
    || !Array.isArray(value.keys)
    || value.keys.length > maximumKeys
  ) {
    throw new Error('Application API key state is invalid or unsupported');
  }
  const keys: StoredApiKey[] = [];
  const ids = new Set<string>();
  const digests = new Set<string>();
  for (const candidate of value.keys) {
    const key = parseStoredKey(candidate, legacy);
    if (!key || ids.has(key.id) || digests.has(key.digest)) {
      throw new Error('Application API key state contains an invalid key');
    }
    ids.add(key.id);
    digests.add(key.digest);
    keys.push(key);
  }
  return {
    state: { schemaVersion: STATE_SCHEMA_VERSION, keys },
    needsMigration: legacy,
  };
}

function opaqueRequestId(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 16
    && value.length <= 128
    && /^[A-Za-z0-9_-]+$/u.test(value)
    && !value.startsWith('mon_')
    && !value.startsWith('eyJ');
}

function actorSubject(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 255
    && value === value.trim()
    && !/[\u0000-\u001f\u007f]/u.test(value)
    && !value.startsWith('mon_')
    && !/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u.test(value);
}

function auditAction(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 3
    && value.length <= 64
    && /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/u.test(value);
}

function auditTarget(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 160
    && /^\/?[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(value)
    && !value.includes('//')
    && !value.startsWith('mon_')
    && isIP(value) === 0;
}

function normalizeIp(value: unknown): string | null | undefined {
  if (value === null) return null;
  return canonicalIpAddress(value) ?? undefined;
}

function sourceIpDigest(value: string | null): string | null {
  if (value === null) return null;
  const digest = createHash('sha256')
    .update(SOURCE_IP_DIGEST_DOMAIN)
    .update(value, 'utf8')
    .digest('hex');
  return `sha256:${digest}`;
}

function normalizeAuditInput(value: unknown): Omit<ApplicationAuditRecord, 'schemaVersion' | 'timestamp'> {
  if (!isRecord(value) || !hasExactFields(value, [
    'requestId',
    'actor',
    'action',
    'target',
    'outcome',
    'sourceIp',
  ])) {
    throw new Error('Application audit input has an invalid schema');
  }
  if (!isRecord(value.actor) || !hasExactFields(value.actor, AUDIT_ACTOR_FIELDS)) {
    throw new Error('Application audit actor has an invalid schema');
  }
  const role = typeof value.actor.role === 'string' && AUDIT_ROLES.has(value.actor.role)
    ? value.actor.role as ApplicationAuditRole
    : null;
  const outcome = typeof value.outcome === 'string' && AUDIT_OUTCOMES.has(value.outcome)
    ? value.outcome as ApplicationAuditOutcome
    : null;
  const sourceIp = normalizeIp(value.sourceIp);
  if (
    !opaqueRequestId(value.requestId)
    || !actorSubject(value.actor.subject)
    || role === null
    || !auditAction(value.action)
    || !auditTarget(value.target)
    || outcome === null
    || sourceIp === undefined
  ) {
    throw new Error('Application audit input contains an invalid value');
  }
  return {
    requestId: value.requestId,
    actor: { subject: value.actor.subject, role },
    action: value.action,
    target: value.target,
    outcome,
    sourceIpHash: sourceIpDigest(sourceIp),
  };
}

export function parseApplicationAuditRecord(value: unknown): ApplicationAuditRecord | null {
  if (!isRecord(value) || !hasExactFields(value, AUDIT_FIELDS)) return null;
  if (!isRecord(value.actor) || !hasExactFields(value.actor, AUDIT_ACTOR_FIELDS)) return null;
  const role = typeof value.actor.role === 'string' && AUDIT_ROLES.has(value.actor.role)
    ? value.actor.role as ApplicationAuditRole
    : null;
  const outcome = typeof value.outcome === 'string' && AUDIT_OUTCOMES.has(value.outcome)
    ? value.outcome as ApplicationAuditOutcome
    : null;
  const timestamp = canonicalTimestamp(value.timestamp);
  if (
    value.schemaVersion !== AUDIT_SCHEMA_VERSION
    || timestamp === null
    || !opaqueRequestId(value.requestId)
    || !actorSubject(value.actor.subject)
    || role === null
    || !auditAction(value.action)
    || !auditTarget(value.target)
    || outcome === null
    || !(
      value.sourceIpHash === null
      || (typeof value.sourceIpHash === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value.sourceIpHash))
    )
  ) return null;
  return {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    timestamp,
    requestId: value.requestId,
    actor: { subject: value.actor.subject, role },
    action: value.action,
    target: value.target,
    outcome,
    sourceIpHash: value.sourceIpHash,
  };
}

function fileExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function expectedEffectiveUid(): number {
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : undefined;
  if (uid === undefined) {
    throw new Error('Application security state requires an effective owner identity');
  }
  return uid;
}

function validateDirectory(directory: string, ownerUid: number): void {
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('Application security state directory must be a real directory');
  }
  if (stat.uid !== ownerUid) {
    throw new Error('Application security state directory has a foreign owner');
  }
  if ((stat.mode & 0o777) !== 0o700) {
    throw new Error('Application security state directory permissions must be 0700');
  }
  if (realpathSync.native(directory) !== directory) {
    throw new Error('Application security state directory must not contain symlinks');
  }
}

function validateFileStat(
  stat: Stats,
  ownerUid: number,
  maximumBytes: number,
  allowEmpty: boolean,
  label: string,
): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`${label} must be an unlinked regular file`);
  }
  if (stat.uid !== ownerUid) throw new Error(`${label} has a foreign owner`);
  if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(`${label} permissions must be 0600`);
  }
  if (stat.size > maximumBytes || (!allowEmpty && stat.size < 1)) {
    throw new Error(`${label} exceeds its size bounds`);
  }
}

function openValidatedFile(
  path: string,
  flags: number,
  ownerUid: number,
  maximumBytes: number,
  allowEmpty: boolean,
  label: string,
): number {
  const before = lstatSync(path);
  validateFileStat(before, ownerUid, maximumBytes, allowEmpty, label);
  const descriptor = openSync(path, flags | constants.O_NOFOLLOW);
  try {
    const after = fstatSync(descriptor);
    validateFileStat(after, ownerUid, maximumBytes, allowEmpty, label);
    if (after.dev !== before.dev || after.ino !== before.ino) {
      throw new Error(`${label} changed while it was being opened`);
    }
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function defaultSyncDirectory(directory: string): void {
  const descriptor = openSync(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function cloneMetadata(key: StoredApiKey): ApplicationApiKeyMetadata {
  return {
    id: key.id,
    name: key.name,
    scopes: [...key.scopes],
    createdAt: key.createdAt,
    expiresAt: key.expiresAt,
    lastUsedAt: key.lastUsedAt,
    revokedAt: key.revokedAt,
    sourceIpAllowlist: [...key.sourceIpAllowlist],
  };
}

function digestToken(token: string): Buffer {
  return createHash('sha256')
    .update(API_KEY_DIGEST_DOMAIN)
    .update(token, 'utf8')
    .digest();
}

function encodedDigest(token: string): string {
  return `sha256:${digestToken(token).toString('hex')}`;
}

function inactiveKeyTime(key: StoredApiKey, now: number): number | null {
  if (key.revokedAt !== null) return Date.parse(key.revokedAt);
  const expiresAt = Date.parse(key.expiresAt);
  return expiresAt <= now ? expiresAt : null;
}

function compactKeysForMutation(
  keys: readonly StoredApiKey[],
  now: number,
  maximumKeys: number,
  reserveActiveSlots = 0,
): StoredApiKey[] | null {
  const active: StoredApiKey[] = [];
  const tombstones: Array<{ key: StoredApiKey; inactiveAt: number }> = [];
  for (const key of keys) {
    const inactiveAt = inactiveKeyTime(key, now);
    if (inactiveAt === null) active.push(key);
    else tombstones.push({ key, inactiveAt });
  }
  if (active.length + reserveActiveSlots > maximumKeys) return null;

  const configuredTombstoneLimit = Math.max(
    1,
    Math.min(MAX_RETAINED_TOMBSTONES, Math.floor(maximumKeys / 4)),
  );
  const availableTombstoneSlots = Math.max(
    0,
    maximumKeys - reserveActiveSlots - active.length,
  );
  const retainedIds = new Set(
    tombstones
      .filter(({ inactiveAt }) => now - inactiveAt <= TOMBSTONE_RETENTION_MS)
      .sort((left, right) => (
        right.inactiveAt - left.inactiveAt
        || left.key.id.localeCompare(right.key.id)
      ))
      .slice(0, Math.min(configuredTombstoneLimit, availableTombstoneSlots))
      .map(({ key }) => key.id),
  );
  return keys.filter((key) => inactiveKeyTime(key, now) === null || retainedIds.has(key.id));
}

export class ApplicationSecurityState {
  readonly #directory: string;
  readonly #statePath: string;
  readonly #ownerUid: number;
  readonly #maximumKeys: number;
  readonly #auditMaximumBytes: number;
  readonly #auditRetentionFiles: number;
  readonly #lastUsedWriteIntervalMs: number;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Buffer;
  readonly #syncDirectory: (directory: string) => void;
  readonly #onDurabilityWarning: (message: string) => void;
  #state: ApiKeyState;
  #tail: Promise<void> = Promise.resolve();

  constructor(directory: string, options: ApplicationSecurityStateOptions = {}) {
    this.#directory = resolve(directory);
    this.#statePath = join(this.#directory, API_KEY_FILE_NAME);
    this.#ownerUid = options.ownerUid ?? expectedEffectiveUid();
    this.#maximumKeys = options.maxApiKeys ?? DEFAULT_MAX_API_KEYS;
    this.#auditMaximumBytes = options.auditMaxBytes ?? DEFAULT_AUDIT_FILE_BYTES;
    this.#auditRetentionFiles = options.auditRetentionFiles ?? DEFAULT_AUDIT_RETENTION_FILES;
    this.#lastUsedWriteIntervalMs = options.lastUsedWriteIntervalMs
      ?? DEFAULT_LAST_USED_WRITE_INTERVAL_MS;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? systemRandomBytes;
    this.#syncDirectory = options.syncDirectory ?? defaultSyncDirectory;
    this.#onDurabilityWarning = options.onDurabilityWarning ?? ((message) => {
      process.stderr.write(`${message}\n`);
    });

    if (!Number.isSafeInteger(this.#ownerUid) || this.#ownerUid < 0) {
      throw new Error('Application security state owner UID is invalid');
    }
    if (
      !Number.isSafeInteger(this.#maximumKeys)
      || this.#maximumKeys < 1
      || this.#maximumKeys > MAX_API_KEYS
    ) throw new Error('Application API key limit is invalid');
    if (
      !Number.isSafeInteger(this.#auditMaximumBytes)
      || this.#auditMaximumBytes < MIN_AUDIT_FILE_BYTES
      || this.#auditMaximumBytes > MAX_AUDIT_FILE_BYTES
    ) throw new Error('Application audit file size limit is invalid');
    if (
      !Number.isSafeInteger(this.#auditRetentionFiles)
      || this.#auditRetentionFiles < MIN_AUDIT_RETENTION_FILES
      || this.#auditRetentionFiles > MAX_AUDIT_RETENTION_FILES
    ) throw new Error('Application audit retention limit is invalid');
    if (
      !Number.isSafeInteger(this.#lastUsedWriteIntervalMs)
      || this.#lastUsedWriteIntervalMs < MIN_LAST_USED_WRITE_INTERVAL_MS
      || this.#lastUsedWriteIntervalMs > MAX_LAST_USED_WRITE_INTERVAL_MS
    ) throw new Error('Application API key last-used write interval is invalid');

    this.#validateDirectory();
    this.#cleanupTemporaryStateFiles();
    this.#cleanupAndValidateAuditFiles();
    if (fileExists(this.#statePath)) {
      const loaded = this.#readState();
      if (loaded.needsMigration) this.#atomicWriteState(loaded.state);
      this.#state = loaded.state;
    } else {
      const initialState: ApiKeyState = { schemaVersion: STATE_SCHEMA_VERSION, keys: [] };
      this.#atomicWriteState(initialState);
      this.#state = initialState;
    }
  }

  #validateDirectory(): void {
    validateDirectory(this.#directory, this.#ownerUid);
  }

  #warnAboutDurability(message: string): void {
    try {
      this.#onDurabilityWarning(message);
    } catch {
      // A reporting callback must never make committed state appear uncommitted.
    }
  }

  #syncCommittedDirectory(message: string): void {
    try {
      this.#syncDirectory(this.#directory);
    } catch (error) {
      this.#warnAboutDurability(message);
      throw new Error(message, { cause: error });
    }
  }

  #random(size: number): Buffer {
    const value = this.#randomBytes(size);
    if (!Buffer.isBuffer(value) || value.length !== size) {
      throw new Error('Application security random source returned an invalid value');
    }
    return Buffer.from(value);
  }

  #enqueue<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = this.#tail.then(operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #cleanupTemporaryStateFiles(): void {
    let changed = false;
    for (const name of readdirSync(this.#directory)) {
      if (!/^\.api-keys\.json\.\d+\.[a-f0-9]{24}\.tmp$/u.test(name)) continue;
      const path = join(this.#directory, name);
      const stat = lstatSync(path);
      validateFileStat(stat, this.#ownerUid, MAX_STATE_BYTES, true, 'Application API key temporary state');
      unlinkSync(path);
      changed = true;
    }
    if (changed) this.#syncDirectory(this.#directory);
  }

  #readState(): ParsedApiKeyState {
    this.#validateDirectory();
    const descriptor = openValidatedFile(
      this.#statePath,
      constants.O_RDONLY,
      this.#ownerUid,
      MAX_STATE_BYTES,
      false,
      'Application API key state',
    );
    try {
      return parseState(readFileSync(descriptor, 'utf8'), this.#maximumKeys);
    } finally {
      closeSync(descriptor);
    }
  }

  #temporaryStatePath(): string {
    const suffix = this.#random(12).toString('hex');
    return join(
      this.#directory,
      `.${basename(this.#statePath)}.${process.pid}.${suffix}.tmp`,
    );
  }

  #atomicWriteState(state: ApiKeyState): void {
    this.#validateDirectory();
    const serialized = `${JSON.stringify(state)}\n`;
    if (Buffer.byteLength(serialized, 'utf8') > MAX_STATE_BYTES) {
      throw new Error('Application API key state exceeds its size limit');
    }
    if (fileExists(this.#statePath)) {
      const descriptor = openValidatedFile(
        this.#statePath,
        constants.O_RDONLY,
        this.#ownerUid,
        MAX_STATE_BYTES,
        false,
        'Application API key state',
      );
      closeSync(descriptor);
    }

    const temporaryPath = this.#temporaryStatePath();
    let descriptor: number | undefined;
    let renamed = false;
    try {
      descriptor = openSync(
        temporaryPath,
        constants.O_WRONLY
          | constants.O_CREAT
          | constants.O_EXCL
          | constants.O_NOFOLLOW,
        0o600,
      );
      fchmodSync(descriptor, 0o600);
      writeFileSync(descriptor, serialized, { encoding: 'utf8' });
      fsyncSync(descriptor);
      validateFileStat(
        fstatSync(descriptor),
        this.#ownerUid,
        MAX_STATE_BYTES,
        false,
        'Application API key temporary state',
      );
      closeSync(descriptor);
      descriptor = undefined;
      renameSync(temporaryPath, this.#statePath);
      renamed = true;
      try {
        this.#syncDirectory(this.#directory);
      } catch (error) {
        this.#warnAboutDurability('Application API key state directory sync failed');
        throw new Error('Application API key state directory sync failed', { cause: error });
      }
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      if (!renamed) {
        try {
          unlinkSync(temporaryPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      }
    }
  }

  #commitState(next: ApiKeyState): void {
    try {
      this.#atomicWriteState(next);
      this.#state = next;
    } catch (error) {
      // A directory fsync can fail after rename has atomically published the
      // new inode. Reload the exact validated file so this process never keeps
      // authorizing against stale pre-rename state, while still rejecting the
      // operation because crash durability was not proven.
      if (fileExists(this.#statePath)) {
        try {
          this.#state = this.#readState().state;
        } catch {
          // Preserve the original durability error. Subsequent operations will
          // continue to fail at their filesystem boundary rather than treating
          // the requested mutation as successful.
        }
      }
      throw error;
    }
  }

  #newCredential(state: ApiKeyState): { id: string; token: string; digest: string } {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const tokenBytes = this.#random(API_KEY_BYTES);
      const token = `mon_${tokenBytes.toString('base64url')}`;
      tokenBytes.fill(0);
      const idBytes = this.#random(API_KEY_ID_BYTES);
      const id = `key_${idBytes.toString('base64url')}`;
      idBytes.fill(0);
      const digest = encodedDigest(token);
      if (!state.keys.some((key) => key.id === id || key.digest === digest)) {
        return { id, token, digest };
      }
    }
    throw new Error('Application API key random source produced repeated credentials');
  }

  #validateExpiry(value: unknown, now: number): string {
    const expiresAt = canonicalTimestamp(value);
    if (expiresAt === null) throw new Error('Application API key expiry must be a canonical UTC timestamp');
    const expires = Date.parse(expiresAt);
    if (expires <= now || expires - now > MAX_KEY_LIFETIME_MS) {
      throw new Error('Application API key expiry is outside the allowed lifetime');
    }
    return expiresAt;
  }

  #monotonicKeyTime(key: StoredApiKey, observedNow: number): number {
    timestampAt(observedNow);
    return Math.max(
      observedNow,
      Date.parse(key.createdAt),
      key.lastUsedAt === null ? 0 : Date.parse(key.lastUsedAt),
    );
  }

  issueApiKey(input: IssueApiKeyInput): Promise<IssuedApplicationApiKey> {
    return this.#enqueue(() => {
      if (
        !isRecord(input)
        || !(
          hasExactFields(input, ISSUE_FIELDS)
          || hasExactFields(input, ISSUE_FIELDS_WITH_SOURCE_IPS)
        )
      ) {
        throw new Error('Application API key issue request has an invalid schema');
      }
      const name = normalizeName(input.name);
      const scopes = normalizeScopes(input.scopes);
      const sourceIpAllowlist = normalizeSourceIpAllowlist(input.sourceIpAllowlist ?? []);
      const now = this.#now();
      const createdAt = timestampAt(now);
      const expiresAt = this.#validateExpiry(input.expiresAt, now);
      if (name === null || scopes === null || sourceIpAllowlist === null) {
        throw new Error('Application API key request contains an invalid name, scope, or source IP allowlist');
      }
      const compactedKeys = compactKeysForMutation(
        this.#state.keys,
        now,
        this.#maximumKeys,
        1,
      );
      if (compactedKeys === null) throw new Error('Application API key limit reached');
      const credential = this.#newCredential(this.#state);
      const key: StoredApiKey = {
        id: credential.id,
        name,
        scopes,
        digest: credential.digest,
        createdAt,
        expiresAt,
        lastUsedAt: null,
        revokedAt: null,
        sourceIpAllowlist,
      };
      const next: ApiKeyState = {
        schemaVersion: STATE_SCHEMA_VERSION,
        keys: [...compactedKeys, key],
      };
      this.#commitState(next);
      return { ...cloneMetadata(key), token: credential.token };
    });
  }

  authenticateApiKey(
    token: unknown,
    requiredScopes: readonly ApplicationApiKeyScope[] = [],
    sourceIp: string | null = null,
  ): Promise<ApplicationApiKeyAuthentication | null> {
    return this.#enqueue(() => {
      const requestedScopes = requiredScopes.length === 0 ? [] : normalizeScopes(requiredScopes);
      if (requestedScopes === null) {
        throw new Error('Application API key authentication requested an invalid scope');
      }
      const syntacticallyValid = typeof token === 'string'
        && /^mon_[A-Za-z0-9_-]{43}$/u.test(token)
        && Buffer.from(token.slice(4), 'base64url').length === API_KEY_BYTES;
      const candidate = digestToken(syntacticallyValid ? token : '');
      let matchedIndex = -1;
      for (let index = 0; index < this.#state.keys.length; index += 1) {
        const stored = Buffer.from(this.#state.keys[index]!.digest.slice(7), 'hex');
        const matched = timingSafeEqual(candidate, stored);
        if (matched) matchedIndex = index;
      }
      candidate.fill(0);
      if (!syntacticallyValid || matchedIndex < 0) return null;

      const key = this.#state.keys[matchedIndex]!;
      const now = this.#monotonicKeyTime(key, this.#now());
      const normalizedSourceIp = canonicalIpAddress(sourceIp);
      const requiredScopesSatisfied = requestedScopes.every((scope) => key.scopes.includes(scope));
      if (
        key.revokedAt !== null
        || now >= Date.parse(key.expiresAt)
        || (
          key.sourceIpAllowlist.length > 0
          && (normalizedSourceIp === null || !key.sourceIpAllowlist.includes(normalizedSourceIp))
        )
      ) return null;

      const authentication = (): ApplicationApiKeyAuthentication => ({
        principal: { id: key.id, name: key.name, scopes: [...key.scopes] },
        requiredScopesSatisfied,
      });
      if (!requiredScopesSatisfied) return authentication();

      const previousLastUsed = key.lastUsedAt === null ? null : Date.parse(key.lastUsedAt);
      if (
        previousLastUsed !== null
        && now - previousLastUsed < this.#lastUsedWriteIntervalMs
      ) {
        return authentication();
      }
      const updated: StoredApiKey = {
        ...key,
        scopes: [...key.scopes],
        sourceIpAllowlist: [...key.sourceIpAllowlist],
        lastUsedAt: timestampAt(now),
      };
      const keys = this.#state.keys.map((candidateKey, index) => (
        index === matchedIndex ? updated : candidateKey
      ));
      this.#commitState({ schemaVersion: STATE_SCHEMA_VERSION, keys });
      return {
        principal: { id: updated.id, name: updated.name, scopes: [...updated.scopes] },
        requiredScopesSatisfied: true,
      };
    });
  }

  revokeApiKey(id: string): Promise<ApplicationApiKeyMetadata | null> {
    return this.#enqueue(() => {
      if (!validKeyId(id)) throw new Error('Application API key identifier is invalid');
      const index = this.#state.keys.findIndex((key) => key.id === id);
      if (index < 0) return null;
      const existing = this.#state.keys[index]!;
      if (existing.revokedAt !== null) return cloneMetadata(existing);
      const now = this.#monotonicKeyTime(existing, this.#now());
      const revoked: StoredApiKey = {
        ...existing,
        scopes: [...existing.scopes],
        sourceIpAllowlist: [...existing.sourceIpAllowlist],
        revokedAt: timestampAt(now),
      };
      const keys = this.#state.keys.map((key, candidateIndex) => (
        candidateIndex === index ? revoked : key
      ));
      this.#commitState({ schemaVersion: STATE_SCHEMA_VERSION, keys });
      return cloneMetadata(revoked);
    });
  }

  rotateApiKey(input: RotateApiKeyInput): Promise<IssuedApplicationApiKey> {
    return this.#enqueue(() => {
      if (!isRecord(input) || !hasExactFields(input, ROTATE_FIELDS) || !validKeyId(input.id)) {
        throw new Error('Application API key rotation request has an invalid schema');
      }
      const index = this.#state.keys.findIndex((key) => key.id === input.id);
      if (index < 0) throw new Error('Application API key was not found');
      const previous = this.#state.keys[index]!;
      const now = this.#monotonicKeyTime(previous, this.#now());
      if (previous.revokedAt !== null || now >= Date.parse(previous.expiresAt)) {
        throw new Error('Application API key is not active');
      }
      const createdAt = timestampAt(now);
      const expiresAt = this.#validateExpiry(input.expiresAt, now);
      const credential = this.#newCredential(this.#state);
      const revoked: StoredApiKey = {
        ...previous,
        scopes: [...previous.scopes],
        sourceIpAllowlist: [...previous.sourceIpAllowlist],
        revokedAt: createdAt,
      };
      const replacement: StoredApiKey = {
        id: credential.id,
        name: previous.name,
        scopes: [...previous.scopes],
        sourceIpAllowlist: [...previous.sourceIpAllowlist],
        digest: credential.digest,
        createdAt,
        expiresAt,
        lastUsedAt: null,
        revokedAt: null,
      };
      const keys = this.#state.keys.map((key, candidateIndex) => (
        candidateIndex === index ? revoked : key
      ));
      keys.push(replacement);
      const compactedKeys = compactKeysForMutation(keys, now, this.#maximumKeys);
      if (compactedKeys === null) throw new Error('Application API key limit reached');
      this.#commitState({ schemaVersion: STATE_SCHEMA_VERSION, keys: compactedKeys });
      return { ...cloneMetadata(replacement), token: credential.token };
    });
  }

  listApiKeys(): Promise<ApplicationApiKeyMetadata[]> {
    return this.#enqueue(() => this.#state.keys.map(cloneMetadata));
  }

  #auditPath(rotation: number): string {
    if (rotation === 0) return join(this.#directory, AUDIT_FILE_NAME);
    return join(this.#directory, `application-audit.${rotation}.jsonl`);
  }

  #parseAuditLines(serialized: string, allowPartialTail: boolean): {
    records: ApplicationAuditRecord[];
    completeBytes: number;
    validPartialRecord: ApplicationAuditRecord | null;
  } {
    const endsWithNewline = serialized.endsWith('\n');
    const lines = serialized.split('\n');
    if (endsWithNewline) lines.pop();
    let partial: string | null = null;
    if (!endsWithNewline && lines.length > 0) partial = lines.pop()!;
    const records: ApplicationAuditRecord[] = [];
    for (const line of lines) {
      if (line.length === 0 || Buffer.byteLength(`${line}\n`, 'utf8') > MAX_AUDIT_RECORD_BYTES) {
        throw new Error('Application audit log contains an invalid record');
      }
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        throw new Error('Application audit log contains invalid JSON');
      }
      const record = parseApplicationAuditRecord(value);
      if (!record) throw new Error('Application audit log contains an invalid record');
      records.push(record);
    }
    const complete = lines.length === 0 ? '' : `${lines.join('\n')}\n`;
    if (partial === null) {
      return {
        records,
        completeBytes: Buffer.byteLength(serialized, 'utf8'),
        validPartialRecord: null,
      };
    }
    if (!allowPartialTail) throw new Error('Rotated application audit log has an incomplete record');
    let validPartialRecord: ApplicationAuditRecord | null = null;
    if (Buffer.byteLength(`${partial}\n`, 'utf8') <= MAX_AUDIT_RECORD_BYTES) {
      try {
        validPartialRecord = parseApplicationAuditRecord(JSON.parse(partial));
      } catch {
        validPartialRecord = null;
      }
    }
    return {
      records,
      completeBytes: Buffer.byteLength(complete, 'utf8'),
      validPartialRecord,
    };
  }

  #readAuditFile(rotation: number, recoverTail: boolean): ApplicationAuditRecord[] {
    const path = this.#auditPath(rotation);
    if (!fileExists(path)) return [];
    const descriptor = openValidatedFile(
      path,
      recoverTail ? constants.O_RDWR : constants.O_RDONLY,
      this.#ownerUid,
      this.#auditMaximumBytes,
      true,
      'Application audit log',
    );
    try {
      const serialized = readFileSync(descriptor, 'utf8');
      if (serialized.length === 0) return [];
      const parsed = this.#parseAuditLines(serialized, recoverTail);
      if (!serialized.endsWith('\n')) {
        if (
          parsed.validPartialRecord
          && Buffer.byteLength(serialized, 'utf8') + 1 <= this.#auditMaximumBytes
        ) {
          const written = writeSync(descriptor, '\n', null, 'utf8');
          if (written !== 1) throw new Error('Application audit tail recovery was incomplete');
          fsyncSync(descriptor);
          parsed.records.push(parsed.validPartialRecord);
        } else {
          ftruncateSync(descriptor, parsed.completeBytes);
          fsyncSync(descriptor);
        }
      }
      return parsed.records;
    } finally {
      closeSync(descriptor);
    }
  }

  #cleanupAndValidateAuditFiles(): void {
    this.#validateDirectory();
    let changed = false;
    const rotatedPattern = /^application-audit\.(\d+)\.jsonl$/u;
    for (const name of readdirSync(this.#directory)) {
      const match = rotatedPattern.exec(name);
      if (!match) continue;
      const rotation = Number(match[1]);
      if (!Number.isSafeInteger(rotation) || rotation < 1 || String(rotation) !== match[1]) {
        throw new Error('Application audit rotation filename is invalid');
      }
      if (rotation >= this.#auditRetentionFiles) {
        const path = join(this.#directory, name);
        const descriptor = openValidatedFile(
          path,
          constants.O_RDONLY,
          this.#ownerUid,
          this.#auditMaximumBytes,
          true,
          'Application audit log',
        );
        closeSync(descriptor);
        unlinkSync(path);
        changed = true;
      }
    }
    if (changed) this.#syncDirectory(this.#directory);
    for (let rotation = this.#auditRetentionFiles - 1; rotation >= 1; rotation -= 1) {
      this.#readAuditFile(rotation, false);
    }
    this.#readAuditFile(0, true);
  }

  #rotateAudit(): void {
    this.#validateDirectory();
    for (let rotation = this.#auditRetentionFiles - 1; rotation >= 1; rotation -= 1) {
      const source = this.#auditPath(rotation - 1);
      const destination = this.#auditPath(rotation);
      if (!fileExists(source)) continue;
      const sourceDescriptor = openValidatedFile(
        source,
        constants.O_RDONLY,
        this.#ownerUid,
        this.#auditMaximumBytes,
        true,
        'Application audit log',
      );
      closeSync(sourceDescriptor);
      if (fileExists(destination)) {
        const destinationDescriptor = openValidatedFile(
          destination,
          constants.O_RDONLY,
          this.#ownerUid,
          this.#auditMaximumBytes,
          true,
          'Application audit log',
        );
        closeSync(destinationDescriptor);
      }
      renameSync(source, destination);
    }
    this.#syncCommittedDirectory('Application audit rotation directory sync failed');
  }

  #appendAudit(record: ApplicationAuditRecord): void {
    this.#validateDirectory();
    const serialized = `${JSON.stringify(record)}\n`;
    const bytes = Buffer.byteLength(serialized, 'utf8');
    if (bytes > MAX_AUDIT_RECORD_BYTES || bytes > this.#auditMaximumBytes) {
      throw new Error('Application audit record exceeds its size limit');
    }
    const currentPath = this.#auditPath(0);
    this.#readAuditFile(0, true);
    if (fileExists(currentPath)) {
      const current = lstatSync(currentPath);
      validateFileStat(
        current,
        this.#ownerUid,
        this.#auditMaximumBytes,
        true,
        'Application audit log',
      );
      if (current.size > 0 && current.size + bytes > this.#auditMaximumBytes) {
        this.#rotateAudit();
      }
    }

    const created = !fileExists(currentPath);
    let descriptor: number;
    if (created) {
      descriptor = openSync(
        currentPath,
        constants.O_WRONLY
          | constants.O_APPEND
          | constants.O_CREAT
          | constants.O_EXCL
          | constants.O_NOFOLLOW,
        0o600,
      );
      fchmodSync(descriptor, 0o600);
      validateFileStat(
        fstatSync(descriptor),
        this.#ownerUid,
        this.#auditMaximumBytes,
        true,
        'Application audit log',
      );
    } else {
      descriptor = openValidatedFile(
        currentPath,
        constants.O_WRONLY | constants.O_APPEND,
        this.#ownerUid,
        this.#auditMaximumBytes,
        true,
        'Application audit log',
      );
    }
    try {
      const initialSize = fstatSync(descriptor).size;
      const written = writeSync(descriptor, serialized, null, 'utf8');
      if (written !== bytes) {
        ftruncateSync(descriptor, initialSize);
        fsyncSync(descriptor);
        throw new Error('Application audit append was incomplete');
      }
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    // Sync on every append, not only creation. Besides being conservative for
    // the current record, this retries a prior create-directory fsync that may
    // have failed after the file became visible. No later intent may be
    // acknowledged against an entry whose directory durability is unproven.
    this.#syncCommittedDirectory('Application audit file directory sync failed');
  }

  audit(input: ApplicationAuditInput): Promise<ApplicationAuditRecord> {
    let normalized: Omit<ApplicationAuditRecord, 'schemaVersion' | 'timestamp'>;
    try {
      normalized = normalizeAuditInput(input);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.#enqueue(() => {
      const record: ApplicationAuditRecord = {
        schemaVersion: AUDIT_SCHEMA_VERSION,
        timestamp: timestampAt(this.#now()),
        requestId: normalized.requestId,
        actor: { ...normalized.actor },
        action: normalized.action,
        target: normalized.target,
        outcome: normalized.outcome,
        sourceIpHash: normalized.sourceIpHash,
      };
      this.#appendAudit(record);
      return record;
    });
  }

  readAuditRecords(): Promise<ApplicationAuditRecord[]> {
    return this.#enqueue(() => {
      this.#validateDirectory();
      const records: ApplicationAuditRecord[] = [];
      for (let rotation = this.#auditRetentionFiles - 1; rotation >= 1; rotation -= 1) {
        records.push(...this.#readAuditFile(rotation, false));
      }
      records.push(...this.#readAuditFile(0, true));
      return records.map((record) => ({ ...record, actor: { ...record.actor } }));
    });
  }
}
