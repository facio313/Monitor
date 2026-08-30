import {
  closeSync,
  constants as fileConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

const MAX_SECRET_FILE_BYTES = 64 * 1024;
const BUILD_AUTH_CONTRACT_FILE = '/etc/portfolio-auth-build';

interface CommonRuntimeConfig {
  dataDir: string;
  staleAfterMs: number;
  allowedOrigins: string[];
  legacyAuthStateFile: string;
  updateSocketPath: string;
  agentControl: AgentControlRuntimeConfig | null;
}

export interface AgentStorageKeyring {
  activeKeyId: string;
  keys: Readonly<Record<string, Buffer>>;
}

export interface AgentStorageKeyringInput {
  schemaVersion: 1;
  activeKeyId: string;
  keys: Record<string, string>;
}

export interface AgentControlRuntimeConfig {
  stateDir: string;
  proxyEdgeSecret: string;
  storageKeyring: AgentStorageKeyring;
  maxBatchBytes: number;
  maxRecordsPerBatch: number;
  maxQueueBytes: number;
  maxQueueEntries: number;
  maxQueueBytesPerAgent: number;
  maxQueueEntriesPerAgent: number;
  maxBatchReceipts: number;
  maxBatchReceiptsPerAgent: number;
  maxIdempotencyRecords: number;
  maxIdempotencyRecordsPerAgent: number;
  priorityReservePercent: number;
  maxClockSkewMs: number;
  maxBackfillAgeMs: number;
  queueRetentionMs: number;
  maxEnrollmentTtlMs: number;
  certificateExpiryWarningMs: number;
}

export interface SsoRuntimeConfig extends CommonRuntimeConfig {
  ssoEnabled: true;
  edgeSecret: string;
}

export interface LocalRuntimeConfig extends CommonRuntimeConfig {
  ssoEnabled: false;
  edgeSecret: null;
  getBootstrapPassword: () => string;
  authStateFile: string;
  sessionSecret: string;
  sessionTtlMs: number;
}

export type RuntimeConfig = SsoRuntimeConfig | LocalRuntimeConfig;

export interface ConfigOverrides {
  password?: string;
  authStateFile?: string;
  sessionSecret?: string;
  dataDir?: string;
  sessionTtlMs?: number;
  staleAfterMs?: number;
  allowedOrigins?: string[];
  ssoEnabled?: boolean;
  edgeSecret?: string;
  updateSocketPath?: string;
  agentIngestEnabled?: boolean;
  agentIngestTestFixture?: boolean;
  agentEdgeSecret?: string;
  agentStateDir?: string;
  agentStorageKeyring?: AgentStorageKeyringInput;
  agentMaxBatchBytes?: number;
  agentMaxRecordsPerBatch?: number;
  agentMaxQueueBytes?: number;
  agentMaxQueueEntries?: number;
  agentMaxQueueBytesPerAgent?: number;
  agentMaxQueueEntriesPerAgent?: number;
  agentMaxBatchReceipts?: number;
  agentMaxBatchReceiptsPerAgent?: number;
  agentMaxIdempotencyRecords?: number;
  agentMaxIdempotencyRecordsPerAgent?: number;
  agentPriorityReservePercent?: number;
  agentMaxClockSkewSeconds?: number;
  agentMaxBackfillAgeSeconds?: number;
  agentQueueRetentionSeconds?: number;
  agentMaxEnrollmentTtlSeconds?: number;
  agentCertificateExpiryWarningSeconds?: number;
}

function ssoEnabledFromPortfolioContract(): boolean {
  const branch = process.env.PORTFOLIO_BRANCH;
  const authMode = process.env.PORTFOLIO_AUTH_MODE;

  if (!branch || !/^[A-Za-z0-9._/-]+$/u.test(branch)) {
    throw new Error('PORTFOLIO_BRANCH must be provided by scripts/portfolio-auth-mode.sh');
  }
  if (authMode !== 'sso' && authMode !== 'local') {
    throw new Error('PORTFOLIO_AUTH_MODE must be sso or local');
  }

  const expectedMode = branch === 'main' || branch === 'dev' ? 'sso' : 'local';
  if (authMode !== expectedMode) {
    throw new Error(`Portfolio branch ${branch} requires ${expectedMode} authentication`);
  }

  if (existsSync(BUILD_AUTH_CONTRACT_FILE)) {
    const contract = readFileSync(BUILD_AUTH_CONTRACT_FILE, 'utf8');
    const expectedContract = `${branch}\n${authMode}\n`;
    if (contract !== expectedContract) {
      throw new Error('Runtime authentication contract does not match the image build contract');
    }
  }

  const legacyMode = process.env.MONITOR_SSO_ENABLED;
  if (legacyMode !== undefined) {
    const normalized = legacyMode.trim().toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
      throw new Error('MONITOR_SSO_ENABLED must be true or false when provided');
    }
    if ((normalized === 'true') !== (authMode === 'sso')) {
      throw new Error('MONITOR_SSO_ENABLED conflicts with PORTFOLIO_AUTH_MODE');
    }
  }

  return authMode === 'sso';
}

function secretFromEnvironment(fileName: string, valueName?: string): string | undefined {
  const file = process.env[fileName];
  if (file) {
    if (typeof process.geteuid !== 'function') {
      throw new Error(`${fileName} ownership cannot be validated on this platform`);
    }
    const expectedUid = process.geteuid();
    const before = lstatSync(file);
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.uid !== expectedUid
      || before.nlink !== 1
      || before.size > MAX_SECRET_FILE_BYTES
      || (before.mode & 0o077) !== 0
    ) {
      throw new Error(`${fileName} must reference a private small regular file`);
    }
    const descriptor = openSync(file, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
    let value: string;
    try {
      const opened = fstatSync(descriptor);
      if (
        before.dev !== opened.dev
        || before.ino !== opened.ino
        || !opened.isFile()
        || opened.uid !== expectedUid
        || opened.nlink !== 1
        || (opened.mode & 0o077) !== 0
        || opened.size > MAX_SECRET_FILE_BYTES
      ) {
        throw new Error(`${fileName} changed while it was opened`);
      }
      value = readFileSync(descriptor, 'utf8').replace(/[\r\n]+$/, '');
    } finally {
      closeSync(descriptor);
    }
    if (!value) throw new Error(`${fileName} is empty`);
    return value;
  }
  return valueName === undefined ? undefined : process.env[valueName];
}

function positiveInteger(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function strictBooleanEnvironment(name: string, fallback = false): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

function boundedIntegerEnvironment(
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function boundedOverride(
  value: number | undefined,
  environmentName: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined) {
    return boundedIntegerEnvironment(environmentName, fallback, minimum, maximum);
  }
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${environmentName} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function parseStorageKeyring(input: unknown): AgentStorageKeyring {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Monitor agent storage keyring must be a JSON object');
  }
  const record = input as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'activeKeyId,keys,schemaVersion'
    || record.schemaVersion !== 1
    || typeof record.activeKeyId !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(record.activeKeyId)
    || record.keys === null
    || typeof record.keys !== 'object'
    || Array.isArray(record.keys)
  ) {
    throw new Error('Monitor agent storage keyring has an invalid contract');
  }
  const encodedKeys = record.keys as Record<string, unknown>;
  const entries = Object.entries(encodedKeys);
  if (entries.length < 1 || entries.length > 8) {
    throw new Error('Monitor agent storage keyring must contain 1 through 8 keys');
  }
  const keys: Record<string, Buffer> = {};
  for (const [keyId, encoded] of entries) {
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(keyId)
      || typeof encoded !== 'string'
      || !/^[A-Za-z0-9+/]{43}=$/u.test(encoded)
    ) {
      throw new Error('Monitor agent storage keyring contains an invalid key');
    }
    const decoded = Buffer.from(encoded, 'base64');
    if (decoded.length !== 32 || decoded.toString('base64') !== encoded) {
      throw new Error('Monitor agent storage keys must be canonical base64-encoded 32-byte values');
    }
    keys[keyId] = decoded;
  }
  if (!(record.activeKeyId in keys)) {
    throw new Error('Monitor agent storage active key is not present in the keyring');
  }
  return { activeKeyId: record.activeKeyId, keys };
}

function agentControlConfig(
  overrides: ConfigOverrides,
  ssoEnabled: boolean,
  ssoEdgeSecret: string | null,
): AgentControlRuntimeConfig | null {
  const enabled = overrides.agentIngestEnabled
    ?? strictBooleanEnvironment('MONITOR_AGENT_INGEST_ENABLED');
  if (!enabled) return null;

  const explicitTestFixture = overrides.agentIngestTestFixture === true
    && process.env.NODE_ENV === 'test';
  if (!ssoEnabled && !explicitTestFixture) {
    throw new Error('Monitor agent ingest requires SSO or an explicit test fixture');
  }
  const agentEdgeSecret = overrides.agentEdgeSecret
    ?? secretFromEnvironment('MONITOR_AGENT_EDGE_SECRET_FILE', 'MONITOR_AGENT_EDGE_SECRET');
  if (!agentEdgeSecret || Buffer.byteLength(agentEdgeSecret) < 32) {
    throw new Error('MONITOR_AGENT_EDGE_SECRET must contain at least 32 bytes when agent ingest is enabled');
  }
  if (ssoEdgeSecret !== null && agentEdgeSecret === ssoEdgeSecret) {
    throw new Error('MONITOR_AGENT_EDGE_SECRET must differ from the Monitor SSO edge secret');
  }

  const configuredStateDir = overrides.agentStateDir ?? process.env.MONITOR_AGENT_STATE_DIR;
  if (!configuredStateDir) {
    throw new Error('MONITOR_AGENT_STATE_DIR is required when agent ingest is enabled');
  }
  const stateDir = resolve(configuredStateDir);
  if (stateDir === '/') {
    throw new Error('MONITOR_AGENT_STATE_DIR must not be the filesystem root');
  }

  let keyringInput: unknown = overrides.agentStorageKeyring;
  if (keyringInput === undefined) {
    const serialized = secretFromEnvironment('MONITOR_AGENT_STORAGE_KEYRING_FILE');
    if (!serialized) {
      throw new Error('Monitor agent storage keyring is required when agent ingest is enabled');
    }
    try {
      keyringInput = JSON.parse(serialized);
    } catch {
      throw new Error('Monitor agent storage keyring must be valid JSON');
    }
  }

  const maxBackfillAgeMs = boundedOverride(
    overrides.agentMaxBackfillAgeSeconds,
    'MONITOR_AGENT_MAX_BACKFILL_AGE_SECONDS',
    7 * 24 * 60 * 60,
    60,
    90 * 24 * 60 * 60,
  ) * 1_000;
  const queueRetentionMs = boundedOverride(
    overrides.agentQueueRetentionSeconds,
    'MONITOR_AGENT_QUEUE_RETENTION_SECONDS',
    7 * 24 * 60 * 60,
    60,
    90 * 24 * 60 * 60,
  ) * 1_000;
  if (queueRetentionMs < maxBackfillAgeMs) {
    throw new Error('MONITOR_AGENT_QUEUE_RETENTION_SECONDS must cover the backfill age');
  }
  const maxQueueBytes = boundedOverride(
    overrides.agentMaxQueueBytes,
    'MONITOR_AGENT_MAX_QUEUE_BYTES',
    32 * 1024 * 1024,
    64 * 1024,
    4 * 1024 * 1024 * 1024,
  );
  const maxQueueEntries = boundedOverride(
    overrides.agentMaxQueueEntries,
    'MONITOR_AGENT_MAX_QUEUE_ENTRIES',
    256,
    2,
    100_000,
  );
  const maxBatchReceipts = boundedOverride(
    overrides.agentMaxBatchReceipts,
    'MONITOR_AGENT_MAX_BATCH_RECEIPTS',
    4_096,
    100,
    100_000,
  );
  const maxIdempotencyRecords = boundedOverride(
    overrides.agentMaxIdempotencyRecords,
    'MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS',
    100_000,
    100,
    200_000,
  );
  const maxQueueBytesPerAgent = boundedOverride(
    overrides.agentMaxQueueBytesPerAgent,
    'MONITOR_AGENT_MAX_QUEUE_BYTES_PER_AGENT',
    Math.min(8 * 1024 * 1024, maxQueueBytes),
    32 * 1024,
    maxQueueBytes,
  );
  const maxQueueEntriesPerAgent = boundedOverride(
    overrides.agentMaxQueueEntriesPerAgent,
    'MONITOR_AGENT_MAX_QUEUE_ENTRIES_PER_AGENT',
    Math.min(64, maxQueueEntries),
    1,
    maxQueueEntries,
  );
  const maxBatchReceiptsPerAgent = boundedOverride(
    overrides.agentMaxBatchReceiptsPerAgent,
    'MONITOR_AGENT_MAX_BATCH_RECEIPTS_PER_AGENT',
    Math.min(1_024, maxBatchReceipts),
    25,
    maxBatchReceipts,
  );
  const maxIdempotencyRecordsPerAgent = boundedOverride(
    overrides.agentMaxIdempotencyRecordsPerAgent,
    'MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS_PER_AGENT',
    Math.min(25_000, maxIdempotencyRecords),
    25,
    maxIdempotencyRecords,
  );

  return {
    stateDir,
    proxyEdgeSecret: agentEdgeSecret,
    storageKeyring: parseStorageKeyring(keyringInput),
    maxBatchBytes: boundedOverride(
      overrides.agentMaxBatchBytes,
      'MONITOR_AGENT_MAX_BATCH_BYTES',
      256 * 1024,
      8 * 1024,
      4 * 1024 * 1024,
    ),
    maxRecordsPerBatch: boundedOverride(
      overrides.agentMaxRecordsPerBatch,
      'MONITOR_AGENT_MAX_RECORDS_PER_BATCH',
      500,
      1,
      5_000,
    ),
    maxQueueBytes,
    maxQueueEntries,
    maxQueueBytesPerAgent,
    maxQueueEntriesPerAgent,
    maxBatchReceipts,
    maxBatchReceiptsPerAgent,
    maxIdempotencyRecords,
    maxIdempotencyRecordsPerAgent,
    priorityReservePercent: boundedOverride(
      overrides.agentPriorityReservePercent,
      'MONITOR_AGENT_PRIORITY_RESERVE_PERCENT',
      20,
      5,
      80,
    ),
    maxClockSkewMs: boundedOverride(
      overrides.agentMaxClockSkewSeconds,
      'MONITOR_AGENT_MAX_CLOCK_SKEW_SECONDS',
      300,
      30,
      3_600,
    ) * 1_000,
    maxBackfillAgeMs,
    queueRetentionMs,
    maxEnrollmentTtlMs: boundedOverride(
      overrides.agentMaxEnrollmentTtlSeconds,
      'MONITOR_AGENT_MAX_ENROLLMENT_TTL_SECONDS',
      15 * 60,
      30,
      60 * 60,
    ) * 1_000,
    certificateExpiryWarningMs: boundedOverride(
      overrides.agentCertificateExpiryWarningSeconds,
      'MONITOR_AGENT_CERTIFICATE_EXPIRY_WARNING_SECONDS',
      14 * 24 * 60 * 60,
      60 * 60,
      90 * 24 * 60 * 60,
    ) * 1_000,
  };
}

export function loadConfig(overrides: ConfigOverrides = {}): RuntimeConfig {
  // ssoEnabled remains an explicit dependency-injection seam for unit tests.
  // Real process startup must use the repository-wide branch contract.
  const ssoEnabled = overrides.ssoEnabled ?? ssoEnabledFromPortfolioContract();
  const commonWithoutAgentControl = {
    dataDir: resolve(overrides.dataDir ?? process.env.MONITOR_DATA_DIR ?? '/data'),
    staleAfterMs: overrides.staleAfterMs
      ?? positiveInteger(process.env.MONITOR_STALE_AFTER_SECONDS, 5 * 60) * 1_000,
    allowedOrigins: overrides.allowedOrigins
      ?? (process.env.MONITOR_ALLOWED_ORIGINS ?? '')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
    legacyAuthStateFile: resolve(
      overrides.authStateFile
        ?? process.env.MONITOR_AUTH_STATE_FILE
        ?? '/var/lib/monitor-auth/password.json',
    ),
    updateSocketPath: resolve(
      overrides.updateSocketPath
        ?? process.env.MONITOR_UPDATE_SOCKET
        ?? '/run/monitor-update/gateway.sock',
    ),
  };

  if (ssoEnabled) {
    const edgeSecret = overrides.edgeSecret
      ?? secretFromEnvironment('MONITOR_EDGE_SECRET_FILE', 'MONITOR_EDGE_SECRET');
    if (!edgeSecret || Buffer.byteLength(edgeSecret) < 32) {
      throw new Error('Monitor edge secret must contain at least 32 bytes when SSO is enabled');
    }
    return {
      ...commonWithoutAgentControl,
      agentControl: agentControlConfig(overrides, true, edgeSecret),
      ssoEnabled: true,
      edgeSecret,
    };
  }

  const sessionSecret = overrides.sessionSecret
    ?? secretFromEnvironment('MONITOR_SESSION_SECRET_FILE', 'MONITOR_SESSION_SECRET');
  if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
    throw new Error('Monitor session secret must contain at least 32 bytes');
  }

  return {
    ...commonWithoutAgentControl,
    agentControl: agentControlConfig(overrides, false, null),
    ssoEnabled: false,
    edgeSecret: null,
    getBootstrapPassword: () => {
      const password = overrides.password
        ?? secretFromEnvironment('MONITOR_PASSWORD_FILE', 'MONITOR_PASSWORD');
      if (!password) throw new Error('Monitor bootstrap password is not configured');
      return password;
    },
    authStateFile: commonWithoutAgentControl.legacyAuthStateFile,
    sessionSecret,
    sessionTtlMs: Math.max(1_000, Math.min(
      overrides.sessionTtlMs
        ?? positiveInteger(process.env.MONITOR_SESSION_TTL_SECONDS, 60 * 60) * 1_000,
      24 * 60 * 60 * 1_000,
    )),
  };
}
