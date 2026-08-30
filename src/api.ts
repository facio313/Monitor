import type { DashboardPayload, InfrastructureLedgerResponse, TimeRange } from './types';

const API_ROOT = '/monitor/api';

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code = 'REQUEST_FAILED') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  });

  if (!response.ok) {
    let message = response.status === 401 ? 'Your session has expired.' : 'The request could not be completed.';
    let code = 'REQUEST_FAILED';
    try {
      const body = (await response.json()) as {
        code?: string;
        error?: string | { code?: string; message?: string };
        message?: string;
      };
      message = body.message || (typeof body.error === 'string' ? body.error : body.error?.message) || message;
      const suppliedCode = body.code || (typeof body.error === 'object' ? body.error?.code : undefined);
      if (typeof suppliedCode === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(suppliedCode)) code = suppliedCode;
    } catch {
      // The response may intentionally contain no body.
    }
    throw new ApiError(message, response.status, code);
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export interface SessionInfo {
  authenticated: boolean;
  mode: 'local' | 'sso';
  user: string | null;
  role: 'user' | 'admin' | 'chief-admin' | null;
  permissions: string[];
}

export async function getSession(signal?: AbortSignal): Promise<SessionInfo> {
  try {
    const session = await apiFetch<{
      authenticated?: boolean;
      mode?: string;
      user?: unknown;
      role?: unknown;
      permissions?: unknown;
    }>('/auth/session', { signal });
    const role = session.role === 'user' || session.role === 'admin' || session.role === 'chief-admin'
      ? session.role
      : null;
    return {
      authenticated: session.authenticated === true,
      mode: session.mode === 'sso' ? 'sso' : 'local',
      user: typeof session.user === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(session.user) ? session.user : null,
      role,
      permissions: Array.isArray(session.permissions)
        ? session.permissions.filter((value): value is string => typeof value === 'string' && /^[a-z][a-z:-]{0,63}$/.test(value)).slice(0, 32)
        : [],
    };
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return { authenticated: false, mode: 'local', user: null, role: null, permissions: [] };
    }
    throw error;
  }
}

export function login(password: string): Promise<unknown> {
  return apiFetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
}

export function logout(): Promise<void> {
  return apiFetch<void>('/auth/session', { method: 'DELETE' });
}

export function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  return apiFetch<void>('/auth/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
}

export function getDashboard(range: TimeRange, signal?: AbortSignal): Promise<DashboardPayload> {
  return apiFetch<DashboardPayload>(`/dashboard?range=${encodeURIComponent(range)}`, { signal });
}

export function getInfrastructureLedger(signal?: AbortSignal): Promise<InfrastructureLedgerResponse> {
  return apiFetch<InfrastructureLedgerResponse>('/infrastructure-ledger', { signal });
}

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
  dropped: {
    inputLineLimit: number;
    inputByteLimit: number;
    oversizedLine: number;
    multilineLineLimit: number;
    oversizedEvent: number;
    sourceQuota: number;
    globalQuota: number;
    acquisition: number;
  };
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

export interface GenericLogPage {
  schemaVersion: 1;
  generatedAt: string;
  collection: {
    status: GenericLogCollectionStatus;
    observedAt: string | null;
    sources: GenericLogSourceStatus[];
  };
  query: {
    limit: number;
    text: string | null;
    sourceIds: string[];
    sourceKinds: GenericLogSourceKind[];
    priorities: GenericLogPriority[];
    severities: GenericLogSeverity[];
    from: string | null;
    to: string | null;
  };
  items: GenericLogRecord[];
  page: {
    limit: number;
    returned: number;
    total: number;
    nextCursor: string | null;
    cursorStatus: 'current' | 'stale';
  };
}

export function getGenericLogs(query: GenericLogQuery = {}, signal?: AbortSignal): Promise<GenericLogPage> {
  const parameters = new URLSearchParams();
  if (query.limit !== undefined) parameters.set('limit', String(query.limit));
  if (query.cursor !== undefined) parameters.set('cursor', query.cursor);
  if (query.text !== undefined) parameters.set('text', query.text);
  if (query.from !== undefined) parameters.set('from', query.from);
  if (query.to !== undefined) parameters.set('to', query.to);
  query.sourceIds?.forEach((value) => parameters.append('sourceId', value));
  query.sourceKinds?.forEach((value) => parameters.append('sourceKind', value));
  query.priorities?.forEach((value) => parameters.append('priority', value));
  query.severities?.forEach((value) => parameters.append('severity', value));
  const search = parameters.size ? `?${parameters.toString()}` : '';
  return apiFetch<GenericLogPage>(`/generic-logs${search}`, { signal });
}

export type SystemUpdateState =
  | 'idle'
  | 'checking'
  | 'available'
  | 'up-to-date'
  | 'applying'
  | 'succeeded'
  | 'failed'
  | 'interrupted';

export type SystemUpdateCategory =
  | 'kernel'
  | 'firmware'
  | 'container-runtime'
  | 'network'
  | 'core-system'
  | 'other';

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
  action: 'check' | 'apply-safe' | null;
  startedAt: string | null;
  completedAt: string | null;
  checkedAt: string | null;
  planId: string | null;
  planExpiresAt: string | null;
  summary: {
    upgradeCount: number;
    installCount: number;
    removeCount: number;
    keptBackCount: number;
    packageCount: number;
    packagesTruncated: boolean;
  } | null;
  packages: SystemUpdatePackage[];
  rebootRequired: boolean;
  code: string;
}

export interface SystemUpdatesResponse {
  status: SystemUpdateStatus | null;
  capabilities: {
    gatewayAvailable: boolean;
    canCheck: boolean;
    canApply: boolean;
  };
}

interface QueuedUpdateResponse {
  schemaVersion: 1;
  accepted: true;
  requestId: string;
  state: 'queued';
}

export function getSystemUpdates(signal?: AbortSignal): Promise<SystemUpdatesResponse> {
  return apiFetch<SystemUpdatesResponse>('/system-updates', { signal });
}

export function checkSystemUpdates(): Promise<QueuedUpdateResponse> {
  return apiFetch<QueuedUpdateResponse>('/system-updates/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
}

export function prepareSystemUpdate(planId: string): Promise<{
  planId: string;
  nonce: string;
  expiresAt: string;
}> {
  return apiFetch('/system-updates/prepare', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ planId }),
  });
}

export function applySystemUpdate(planId: string, nonce: string): Promise<QueuedUpdateResponse> {
  return apiFetch<QueuedUpdateResponse>('/system-updates/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ planId, nonce }),
  });
}
