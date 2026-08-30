import { randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants as fileConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';
import { createConnection } from 'node:net';
import { join, resolve, sep } from 'node:path';

const STATUS_FILE_NAME = 'system-update.json';
const MAX_STATUS_BYTES = 512 * 1024;
const MAX_GATEWAY_MESSAGE_BYTES = 4 * 1024;
const GATEWAY_TIMEOUT_MS = 2_000;
const MAX_PUBLIC_PACKAGES = 512;
const MAX_PRIVATE_PLAN_PACKAGES = 2_048;

const UPDATE_STATES = [
  'idle',
  'checking',
  'available',
  'up-to-date',
  'applying',
  'succeeded',
  'failed',
  'interrupted',
] as const;
const UPDATE_ACTIONS = ['check', 'apply-safe'] as const;
const UPDATE_CATEGORIES = [
  'kernel',
  'firmware',
  'container-runtime',
  'network',
  'core-system',
  'other',
] as const;
const UPDATE_CODES = [
  'READY',
  'CHECKING',
  'UPDATES_AVAILABLE',
  'UP_TO_DATE',
  'UPDATES_KEPT_BACK',
  'APPLYING',
  'APPLY_SUCCEEDED',
  'REBOOT_REQUIRED',
  'PACKAGE_MANAGER_BUSY',
  'DPKG_AUDIT_FAILED',
  'PLAN_NOT_FOUND',
  'PLAN_STALE',
  'PLAN_CHANGED',
  'ROOT_READ_ONLY',
  'DISK_SPACE_LOW',
  'PLAN_TOO_LARGE',
  'COMMAND_FAILED',
  'INTERRUPTED',
  'INTERNAL_ERROR',
] as const;
const GATEWAY_REJECTION_CODES = [
  'BUSY',
  'QUEUE_FULL',
  'INVALID_REQUEST',
  'INVALID_ACTION',
  'INVALID_ACTOR',
  'INVALID_PLAN',
  'PEER_REJECTED',
  'INTERNAL_ERROR',
] as const;

export type SystemUpdateState = typeof UPDATE_STATES[number];
export type SystemUpdateAction = typeof UPDATE_ACTIONS[number];
export type SystemUpdateCategory = typeof UPDATE_CATEGORIES[number];
export type SystemUpdateCode = typeof UPDATE_CODES[number];

export interface SystemUpdateSummary {
  upgradeCount: number;
  installCount: number;
  removeCount: number;
  keptBackCount: number;
  packageCount: number;
  packagesTruncated: boolean;
}

export interface SystemUpdatePackage {
  name: string;
  installedVersion: string | null;
  candidateVersion: string;
  action: 'upgrade' | 'install';
  category: SystemUpdateCategory;
}

export interface SystemUpdateStatus {
  schemaVersion: 1;
  generatedAt: string;
  state: SystemUpdateState;
  requestId: string | null;
  action: SystemUpdateAction | null;
  startedAt: string | null;
  completedAt: string | null;
  checkedAt: string | null;
  planId: string | null;
  planExpiresAt: string | null;
  summary: SystemUpdateSummary | null;
  packages: SystemUpdatePackage[];
  rebootRequired: boolean;
  code: SystemUpdateCode;
}

export interface UpdateGatewayRequest {
  schemaVersion: 1;
  action: SystemUpdateAction;
  actor: string;
  planId: string | null;
}

export type UpdateGatewayResponse = {
  schemaVersion: 1;
  accepted: true;
  requestId: string;
  state: 'queued';
} | {
  schemaVersion: 1;
  accepted: false;
  code: string;
};

type JsonRecord = Record<string, unknown>;

function record(value: unknown): JsonRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : null;
}

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function member<T extends readonly string[]>(value: unknown, choices: T): T[number] | null {
  return typeof value === 'string' && (choices as readonly string[]).includes(value)
    ? value as T[number]
    : null;
}

function boundedInteger(value: unknown, maximum = MAX_PRIVATE_PLAN_PACKAGES): number | null {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum
    ? value as number
    : null;
}

function isoTimestamp(value: unknown): string | null {
  if (
    typeof value !== 'string'
    || value.length < 20
    || value.length > 32
    || !value.endsWith('Z')
    || !Number.isFinite(Date.parse(value))
  ) return null;
  return value;
}

function nullableTimestamp(value: unknown): string | null | undefined {
  if (value === null) return null;
  return isoTimestamp(value) ?? undefined;
}

function planId(value: unknown): string | null | undefined {
  if (value === null) return null;
  return typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value) ? value : undefined;
}

function requestId(value: unknown): string | null | undefined {
  if (value === null) return null;
  return typeof value === 'string'
    && /^update-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)
    ? value
    : undefined;
}

function safeVersion(value: unknown, nullable: boolean): string | null | undefined {
  if (nullable && value === null) return null;
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 256
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) return undefined;
  return value;
}

function normalizeSummary(value: unknown): SystemUpdateSummary | null | undefined {
  if (value === null) return null;
  const input = record(value);
  if (!input || !exactKeys(input, [
    'upgradeCount',
    'installCount',
    'removeCount',
    'keptBackCount',
    'packageCount',
    'packagesTruncated',
  ])) return undefined;
  const upgradeCount = boundedInteger(input.upgradeCount);
  const installCount = boundedInteger(input.installCount);
  const removeCount = boundedInteger(input.removeCount);
  const keptBackCount = boundedInteger(input.keptBackCount);
  const packageCount = boundedInteger(input.packageCount);
  if (
    upgradeCount === null
    || installCount === null
    || removeCount === null
    || keptBackCount === null
    || packageCount === null
    || typeof input.packagesTruncated !== 'boolean'
    || packageCount < upgradeCount + installCount
  ) return undefined;
  return {
    upgradeCount,
    installCount,
    removeCount,
    keptBackCount,
    packageCount,
    packagesTruncated: input.packagesTruncated,
  };
}

function normalizePackage(value: unknown): SystemUpdatePackage | null {
  const input = record(value);
  if (!input || !exactKeys(input, [
    'name',
    'installedVersion',
    'candidateVersion',
    'action',
    'category',
  ])) return null;
  const installedVersion = safeVersion(input.installedVersion, true);
  const candidateVersion = safeVersion(input.candidateVersion, false);
  const action = member(input.action, ['upgrade', 'install'] as const);
  const category = member(input.category, UPDATE_CATEGORIES);
  if (
    typeof input.name !== 'string'
    || input.name.length > 160
    || !/^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$/u.test(input.name)
    || installedVersion === undefined
    || typeof candidateVersion !== 'string'
    || action === null
    || category === null
  ) return null;
  return { name: input.name, installedVersion, candidateVersion, action, category };
}

export function normalizeSystemUpdateStatus(value: unknown): SystemUpdateStatus | null {
  const input = record(value);
  if (!input || !exactKeys(input, [
    'schemaVersion',
    'generatedAt',
    'state',
    'requestId',
    'action',
    'startedAt',
    'completedAt',
    'checkedAt',
    'planId',
    'planExpiresAt',
    'summary',
    'packages',
    'rebootRequired',
    'code',
  ])) return null;
  const generatedAt = isoTimestamp(input.generatedAt);
  const state = member(input.state, UPDATE_STATES);
  const normalizedRequestId = requestId(input.requestId);
  const action = input.action === null ? null : member(input.action, UPDATE_ACTIONS);
  const startedAt = nullableTimestamp(input.startedAt);
  const completedAt = nullableTimestamp(input.completedAt);
  const checkedAt = nullableTimestamp(input.checkedAt);
  const normalizedPlanId = planId(input.planId);
  const planExpiresAt = nullableTimestamp(input.planExpiresAt);
  const summary = normalizeSummary(input.summary);
  const code = member(input.code, UPDATE_CODES);
  if (
    input.schemaVersion !== 1
    || generatedAt === null
    || state === null
    || normalizedRequestId === undefined
    || action === undefined
    || startedAt === undefined
    || completedAt === undefined
    || checkedAt === undefined
    || normalizedPlanId === undefined
    || planExpiresAt === undefined
    || summary === undefined
    || !Array.isArray(input.packages)
    || input.packages.length > MAX_PUBLIC_PACKAGES
    || typeof input.rebootRequired !== 'boolean'
    || code === null
  ) return null;
  const packages = input.packages.map(normalizePackage);
  if (packages.some((item) => item === null)) return null;
  if (summary === null && packages.length !== 0) return null;
  if (summary && (
    packages.length > summary.packageCount
    || summary.packagesTruncated !== (packages.length < summary.packageCount)
  )) return null;
  return {
    schemaVersion: 1,
    generatedAt,
    state,
    requestId: normalizedRequestId,
    action,
    startedAt,
    completedAt,
    checkedAt,
    planId: normalizedPlanId,
    planExpiresAt,
    summary,
    packages: packages as SystemUpdatePackage[],
    rebootRequired: input.rebootRequired,
    code,
  };
}

export function readSystemUpdateStatus(dataDirectory: string): SystemUpdateStatus | null {
  const root = resolve(dataDirectory);
  const path = resolve(join(root, STATUS_FILE_NAME));
  if (!path.startsWith(`${root}${sep}`)) return null;
  let before;
  try {
    before = lstatSync(path);
  } catch {
    return null;
  }
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || before.size < 2
    || before.size > MAX_STATUS_BYTES
    || (before.mode & 0o022) !== 0
  ) return null;
  let descriptor: number;
  try {
    descriptor = openSync(path, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== before.dev
      || opened.ino !== before.ino
      || opened.nlink !== 1
      || opened.size !== before.size
      || opened.size > MAX_STATUS_BYTES
    ) return null;
    const raw = readFileSync(descriptor, 'utf8');
    return normalizeSystemUpdateStatus(JSON.parse(raw) as unknown);
  } catch {
    return null;
  } finally {
    closeSync(descriptor);
  }
}

export function safeUpdateActor(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$/u.test(value);
}

export function updateGatewayIsAvailable(socketPath: string): boolean {
  try {
    const status = lstatSync(socketPath);
    return status.isSocket() && !status.isSymbolicLink();
  } catch {
    return false;
  }
}

function normalizeGatewayResponse(value: unknown): UpdateGatewayResponse | null {
  const input = record(value);
  if (!input || input.schemaVersion !== 1 || typeof input.accepted !== 'boolean') return null;
  if (input.accepted) {
    if (!exactKeys(input, ['schemaVersion', 'accepted', 'requestId', 'state'])) return null;
    const id = requestId(input.requestId);
    if (id === null || id === undefined || input.state !== 'queued') return null;
    return { schemaVersion: 1, accepted: true, requestId: id, state: 'queued' };
  }
  if (
    !exactKeys(input, ['schemaVersion', 'accepted', 'code'])
    || member(input.code, GATEWAY_REJECTION_CODES) === null
  ) return null;
  return { schemaVersion: 1, accepted: false, code: input.code as string };
}

export class UpdateGatewayError extends Error {
  constructor() {
    super('Update gateway unavailable');
    this.name = 'UpdateGatewayError';
  }
}

export function sendUpdateGatewayRequest(
  socketPath: string,
  request: UpdateGatewayRequest,
): Promise<UpdateGatewayResponse> {
  if (
    request.schemaVersion !== 1
    || !member(request.action, UPDATE_ACTIONS)
    || !safeUpdateActor(request.actor)
    || (request.action === 'check' && request.planId !== null)
    || (request.action === 'apply-safe' && typeof planId(request.planId) !== 'string')
  ) return Promise.reject(new UpdateGatewayError());
  const outbound = `${JSON.stringify(request)}\n`;
  if (Buffer.byteLength(outbound) > MAX_GATEWAY_MESSAGE_BYTES) {
    return Promise.reject(new UpdateGatewayError());
  }

  return new Promise((resolvePromise, rejectPromise) => {
    const socket = createConnection({ path: socketPath });
    let settled = false;
    let received = Buffer.alloc(0);
    const fail = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      rejectPromise(new UpdateGatewayError());
    };
    socket.setTimeout(GATEWAY_TIMEOUT_MS, fail);
    socket.once('error', fail);
    socket.once('connect', () => socket.write(outbound));
    socket.on('data', (chunk: Buffer) => {
      if (settled) return;
      received = Buffer.concat([received, chunk]);
      if (received.length > MAX_GATEWAY_MESSAGE_BYTES) {
        fail();
        return;
      }
      const newline = received.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== received.length - 1) {
        fail();
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(received.subarray(0, newline).toString('utf8')) as unknown;
      } catch {
        fail();
        return;
      }
      const normalized = normalizeGatewayResponse(parsed);
      if (!normalized) {
        fail();
        return;
      }
      settled = true;
      socket.end();
      resolvePromise(normalized);
    });
    socket.once('end', () => {
      if (!settled) fail();
    });
  });
}

interface NonceEntry {
  subject: string;
  planId: string;
  expiresAtMs: number;
}

function equalText(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export class UpdateNonceStore {
  private readonly entries = new Map<string, NonceEntry>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly ttlMs = 5 * 60 * 1_000,
    private readonly maximumEntries = 64,
  ) {}

  private prune(): void {
    const current = this.now();
    for (const [nonce, entry] of this.entries) {
      if (entry.expiresAtMs <= current) this.entries.delete(nonce);
    }
    while (this.entries.size >= this.maximumEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (!oldest) break;
      this.entries.delete(oldest);
    }
  }

  issue(subject: string, selectedPlanId: string): { nonce: string; expiresAt: string } {
    if (!safeUpdateActor(subject) || planId(selectedPlanId) === undefined) {
      throw new TypeError('Invalid update authorization context');
    }
    this.prune();
    const nonce = randomBytes(32).toString('hex');
    const expiresAtMs = this.now() + this.ttlMs;
    this.entries.set(nonce, { subject, planId: selectedPlanId, expiresAtMs });
    return { nonce, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  consume(nonce: unknown, subject: string, selectedPlanId: string): boolean {
    if (typeof nonce !== 'string' || !/^[a-f0-9]{64}$/u.test(nonce)) return false;
    const entry = this.entries.get(nonce);
    if (!entry) return false;
    this.entries.delete(nonce);
    return entry.expiresAtMs > this.now()
      && equalText(entry.subject, subject)
      && equalText(entry.planId, selectedPlanId);
  }
}
