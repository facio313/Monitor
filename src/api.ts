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
