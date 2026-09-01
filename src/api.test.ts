import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  getGenericLogs,
  getMonitoringCatalog,
  getRemoteAgents,
  type GenericLogPage,
  type MonitoringCatalog,
} from './api';
import type { RemoteAgentInventoryResponse } from './types';

const EMPTY_PAGE: GenericLogPage = {
  schemaVersion: 1,
  generatedAt: '2026-08-31T00:00:00.000Z',
  collection: { status: 'no_data', observedAt: null, sources: [] },
  query: {
    limit: 25,
    text: null,
    sourceIds: [],
    sourceKinds: [],
    priorities: [],
    severities: [],
    from: null,
    to: null,
  },
  items: [],
  page: { limit: 25, returned: 0, total: 0, nextCursor: null, cursorStatus: 'current' },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('generic log API client', () => {
  it('uses the generic-log endpoint and repeated singular facet parameters', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => EMPTY_PAGE,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    await expect(getGenericLogs({
      limit: 25,
      cursor: 'next cursor',
      text: 'database error',
      sourceIds: ['file:application', 'journal:worker'],
      sourceKinds: ['file', 'journald'],
      priorities: ['incident', 'security'],
      severities: ['warning', 'critical'],
      from: '2026-08-30T00:00:00.000Z',
      to: '2026-08-31T00:00:00.000Z',
    }, controller.signal)).resolves.toBe(EMPTY_PAGE);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [requestPath, init] = fetchMock.mock.calls[0]!;
    const url = new URL(String(requestPath), 'https://monitor.test');
    expect(url.pathname).toBe('/monitor/api/generic-logs');
    expect(url.searchParams.get('limit')).toBe('25');
    expect(url.searchParams.get('cursor')).toBe('next cursor');
    expect(url.searchParams.get('text')).toBe('database error');
    expect(url.searchParams.getAll('sourceId')).toEqual(['file:application', 'journal:worker']);
    expect(url.searchParams.getAll('sourceKind')).toEqual(['file', 'journald']);
    expect(url.searchParams.getAll('priority')).toEqual(['incident', 'security']);
    expect(url.searchParams.getAll('severity')).toEqual(['warning', 'critical']);
    expect([...url.searchParams.keys()]).not.toContain('sourceIds');
    expect(init).toMatchObject({ credentials: 'same-origin', signal: controller.signal });
  });
});

describe('monitoring catalog API client', () => {
  it('uses the authenticated monitoring-catalog endpoint and forwards cancellation', async () => {
    const catalog: MonitoringCatalog = {
      schemaVersion: 1,
      generatedAt: '2026-09-01T00:00:00.000Z',
      collectionIntervalSeconds: 60,
      rulePackVersion: 'test-v1',
      evidenceSources: [],
      observations: [],
      rules: [],
    };
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => catalog,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    await expect(getMonitoringCatalog(controller.signal)).resolves.toBe(catalog);

    expect(fetchMock).toHaveBeenCalledWith('/monitor/api/monitoring-catalog', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
  });
});

describe('remote agent API client', () => {
  it('uses the authenticated management endpoint and forwards cancellation', async () => {
    const inventory = {
      serverTime: '2026-09-01T00:00:00.000Z',
      transport: { tlsTermination: 'trusted-reverse-proxy', applicationVerifies: [] },
      queue: {},
      agents: [],
    } as unknown as RemoteAgentInventoryResponse;
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => inventory,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    await expect(getRemoteAgents(controller.signal)).resolves.toBe(inventory);

    expect(fetchMock).toHaveBeenCalledWith('/monitor/api/agents', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
  });
});
