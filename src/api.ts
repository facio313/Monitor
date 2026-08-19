import type { DashboardPayload, TimeRange } from './types';

const API_ROOT = '/monitor/api';

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
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
    try {
      const body = (await response.json()) as { error?: string | { code?: string; message?: string }; message?: string };
      message = body.message || (typeof body.error === 'string' ? body.error : body.error?.message) || message;
    } catch {
      // The response may intentionally contain no body.
    }
    throw new ApiError(message, response.status);
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function getSession(signal?: AbortSignal): Promise<boolean> {
  try {
    const session = await apiFetch<{ authenticated?: boolean }>('/auth/session', { signal });
    return session.authenticated === true;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return false;
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
