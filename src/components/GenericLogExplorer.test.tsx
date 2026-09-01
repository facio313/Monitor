import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { GenericLogPage, GenericLogRecord } from '../api';
import {
  beginGenericLogQueryRequest,
  completeGenericLogQueryRequest,
  EMPTY_GENERIC_LOG_FILTERS,
  GenericLogExplorer,
  genericLogFiltersFromSearch,
  genericLogLocationFromQuery,
  genericLogQueryFromDraft,
  mergeGenericLogPages,
} from './GenericLogExplorer';

function record(message: string, timestamp: string): GenericLogRecord {
  return {
    schemaVersion: 1,
    timestamp,
    observedAt: timestamp,
    timestampSource: 'event',
    sourceKind: 'file',
    sourceId: 'file:application',
    priority: 'normal',
    severity: 'info',
    parser: 'plain',
    message,
    truncated: false,
    multilineLineCount: 1,
    hostId: null,
    containerName: null,
    composeProject: null,
    composeService: null,
    processName: 'application',
    systemdUnit: null,
    stream: null,
    fields: {},
    redactionVersion: 'monitor-log-redaction-v2',
  };
}

function page(items: GenericLogRecord[], overrides: Partial<GenericLogPage['page']> = {}): GenericLogPage {
  return {
    schemaVersion: 1,
    generatedAt: '2026-08-31T00:00:00.000Z',
    collection: { status: 'fresh', observedAt: '2026-08-31T00:00:00.000Z', sources: [] },
    query: {
      limit: 50,
      text: null,
      sourceIds: [],
      sourceKinds: [],
      priorities: [],
      severities: [],
      from: null,
      to: null,
    },
    items,
    page: {
      limit: 50,
      returned: items.length,
      total: items.length,
      nextCursor: null,
      cursorStatus: 'current',
      ...overrides,
    },
  };
}

describe('generic log explorer model', () => {
  it('builds a bounded server query from the action filters', () => {
    const from = '2026-08-30T09:30';
    const to = '2026-08-30T10:45';
    expect(genericLogQueryFromDraft({
      ...EMPTY_GENERIC_LOG_FILTERS,
      text: '  database error  ',
      sourceId: 'file:application',
      sourceKind: 'file',
      priority: 'incident',
      severity: 'error',
      from,
      to,
    })).toEqual({
      limit: 50,
      text: 'database error',
      sourceIds: ['file:application'],
      sourceKinds: ['file'],
      priorities: ['incident'],
      severities: ['error'],
      from: new Date(from).toISOString(),
      to: new Date(to).toISOString(),
    });
  });

  it('rejects oversized search text and reversed time bounds before requesting', () => {
    expect(() => genericLogQueryFromDraft({
      ...EMPTY_GENERIC_LOG_FILTERS,
      text: '가'.repeat(43),
    })).toThrow('invalid_text');
    expect(() => genericLogQueryFromDraft({
      ...EMPTY_GENERIC_LOG_FILTERS,
      from: '2026-08-31T10:00',
      to: '2026-08-31T09:00',
    })).toThrow('invalid_time_order');
  });

  it('initializes all supported filters from a bounded, canonical deep link', () => {
    const from = '2026-08-30T00:30:00.000Z';
    const to = '2026-08-30T01:45:00.000Z';
    const filters = genericLogFiltersFromSearch(
      `?range=7d&sourceId=journal%3Anginx&kind=journald&priority=security&severity=warning&text=${encodeURIComponent('  denied request  ')}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    );

    expect(filters).toMatchObject({
      sourceId: 'journal:nginx',
      sourceKind: 'journald',
      priority: 'security',
      severity: 'warning',
      text: 'denied request',
    });
    expect(new Date(filters.from).toISOString()).toBe(from);
    expect(new Date(filters.to).toISOString()).toBe(to);
    expect(genericLogQueryFromDraft(filters)).toEqual({
      limit: 50,
      sourceIds: ['journal:nginx'],
      sourceKinds: ['journald'],
      priorities: ['security'],
      severities: ['warning'],
      text: 'denied request',
      from,
      to,
    });
  });

  it('ignores URL filter values outside the generic-log API contract', () => {
    const filters = genericLogFiltersFromSearch(
      `?sourceId=${'a'.repeat(129)}&kind=socket&priority=urgent&severity=fatal&text=${encodeURIComponent('x\ny')}`
      + '&from=2026-08-30T00%3A30%3A00Z&to=not-a-date',
    );
    expect(filters).toEqual(EMPTY_GENERIC_LOG_FILTERS);

    const reversed = genericLogFiltersFromSearch(
      '?from=2026-08-30T02%3A00%3A00.000Z&to=2026-08-30T01%3A00%3A00.000Z',
    );
    expect(reversed.from).toBe('');
    expect(reversed.to).toBe('');
  });

  it('synchronizes owned filters without losing the monitor route or unrelated params', () => {
    const target = genericLogLocationFromQuery({
      pathname: '/monitor/details/logs',
      search: '?range=30d&future=keep&sourceId=old&kind=file&text=old',
      hash: '#latest',
    }, {
      limit: 50,
      sourceIds: ['journal:ssh'],
      sourceKinds: ['journald'],
      priorities: ['security'],
      severities: ['critical'],
      text: 'authentication failure',
      from: '2026-08-30T00:30:00.000Z',
      to: '2026-08-30T01:45:00.000Z',
    });
    const url = new URL(target, 'https://monitor.test');

    expect(url.pathname).toBe('/monitor/details/logs');
    expect(url.hash).toBe('#latest');
    expect(url.searchParams.get('range')).toBe('30d');
    expect(url.searchParams.get('future')).toBe('keep');
    expect(url.searchParams.get('sourceId')).toBe('journal:ssh');
    expect(url.searchParams.get('kind')).toBe('journald');
    expect(url.searchParams.get('priority')).toBe('security');
    expect(url.searchParams.get('severity')).toBe('critical');
    expect(url.searchParams.get('text')).toBe('authentication failure');
    expect(url.searchParams.get('from')).toBe('2026-08-30T00:30:00.000Z');
    expect(url.searchParams.get('to')).toBe('2026-08-30T01:45:00.000Z');
  });

  it('clears only generic-log URL filters and keeps unrelated navigation state', () => {
    const target = genericLogLocationFromQuery({
      pathname: '/monitor/details/logs',
      search: '?range=24h&sourceId=journal%3Assh&kind=journald&priority=security&severity=error&text=denied&from=2026-08-30T00%3A00%3A00.000Z&to=2026-08-31T00%3A00%3A00.000Z',
      hash: '',
    }, { limit: 50 });

    expect(target).toBe('/monitor/details/logs?range=24h');
  });

  it('appends current cursor pages and preserves loaded records when a cursor becomes stale', () => {
    const first = page([record('one', '2026-08-31T00:00:00.000Z')], {
      total: 2,
      nextCursor: 'cursor-one',
    });
    const second = page([record('two', '2026-08-30T23:59:00.000Z')], { total: 2 });
    const combined = mergeGenericLogPages(first, second, true);
    expect(combined.items.map(({ message }) => message)).toEqual(['one', 'two']);
    expect(combined.page).toMatchObject({ returned: 2, total: 2, cursorStatus: 'current' });

    const stale = page([], { total: 0, cursorStatus: 'stale' });
    const preserved = mergeGenericLogPages(first, stale, true);
    expect(preserved.items.map(({ message }) => message)).toEqual(['one']);
    expect(preserved.page).toMatchObject({ nextCursor: null, cursorStatus: 'stale' });
  });

  it('retries the last failed replacement query and keeps append cursors out of the base query', () => {
    const oldQuery = { limit: 50, text: 'old' };
    const replacement = { limit: 50, text: 'new', cursor: 'must-not-survive' };
    const initial = {
      applied: oldQuery,
      lastAttempted: oldQuery,
      lastAttemptedAppend: false,
    };

    const failed = beginGenericLogQueryRequest(initial, replacement, false);
    expect(failed).toEqual({
      applied: oldQuery,
      lastAttempted: { limit: 50, text: 'new' },
      lastAttemptedAppend: false,
    });

    const retrying = beginGenericLogQueryRequest(failed, failed.lastAttempted, false);
    const recovered = completeGenericLogQueryRequest(retrying, failed.lastAttempted, false);
    expect(recovered.applied).toEqual({ limit: 50, text: 'new' });

    const append = { ...recovered.applied, cursor: 'next-page' };
    const failedAppend = beginGenericLogQueryRequest(recovered, append, true);
    expect(failedAppend).toEqual({
      ...recovered,
      lastAttempted: append,
      lastAttemptedAppend: true,
    });
    expect(completeGenericLogQueryRequest(failedAppend, append, true)).toBe(failedAppend);
  });

  it('renders an explicitly labelled search form and named actions before data arrives', () => {
    const markup = renderToStaticMarkup(createElement(GenericLogExplorer, {
      locale: 'en',
      onUnauthorized: () => undefined,
    }));

    expect(markup).toContain('aria-labelledby="generic-log-title"');
    expect(markup).toContain('role="search"');
    expect(markup).toContain('aria-label="Generic log filters"');
    expect(markup).toContain('Search message or metadata');
    expect(markup).toContain('>Apply filters<');
    expect(markup).toContain('>Refresh<');
    expect(markup).toContain('role="status"');
  });
});
