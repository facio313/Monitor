import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { MonitoringCatalog, MonitoringEvidenceSource } from '../api';
import { relatedEvidenceIds, RelatedEvidencePanel, retentionLabel } from './RelatedEvidencePanel';

let hookCatalog: MonitoringCatalog | null = null;
let hookError: string | null = null;

vi.mock('../hooks/useMonitoringCatalog', () => ({
  useMonitoringCatalog: () => ({
    catalog: hookCatalog,
    error: hookError,
    loading: hookCatalog === null,
    refresh: vi.fn(),
  }),
}));

function source(
  id: string,
  overrides: Partial<MonitoringEvidenceSource> = {},
): MonitoringEvidenceSource {
  return {
    id,
    displayName: { ko: `${id} 기록`, en: `${id} evidence` },
    description: { ko: `${id} 설명`, en: `${id} safe description` },
    kind: 'event-log',
    evidenceMode: 'accumulated-log',
    artifactLabel: `${id}.jsonl`,
    format: 'jsonl',
    cadenceSeconds: 60,
    retention: {
      policy: 'bounded-age-count-and-bytes',
      pruneCadence: 'every-collection',
      maxAgeDays: 30,
      maxRecords: 2_000,
      recordScope: 'artifact',
      maxBytes: 8_388_608,
    },
    detailPages: ['reliability'],
    ...overrides,
  };
}

function catalog(evidenceSources: MonitoringEvidenceSource[]): MonitoringCatalog {
  return {
    schemaVersion: 1,
    generatedAt: '2026-09-01T03:00:00.000Z',
    collectionIntervalSeconds: 60,
    rulePackVersion: 'test-v1',
    evidenceSources,
    observations: [],
    rules: [],
  };
}

afterEach(() => {
  hookCatalog = null;
  hookError = null;
});

describe('retentionLabel', () => {
  it('states age, record scope, and byte bounds without implying unlimited storage', () => {
    const value = source('semantic-alert-events');
    expect(retentionLabel(value, 'en')).toBe('30 days · 2,000 records/artifact · 8.0 MB');
    expect(retentionLabel(value, 'ko')).toBe('30일 · 파일당 2,000건 · 8.0 MB');

    const external = source('infrastructure-ledger', {
      retention: {
        policy: 'externally-managed',
        pruneCadence: 'external-no-auto-prune',
        maxAgeDays: null,
        maxRecords: null,
        recordScope: null,
        maxBytes: null,
      },
    });
    expect(retentionLabel(external, 'en')).toBe('External policy');
  });
});

describe('RelatedEvidencePanel', () => {
  it('labels a retained catalog as last verified when a refresh fails', () => {
    hookCatalog = catalog([source('current-snapshot', { detailPages: ['resources'] })]);
    hookError = 'Monitoring catalog is unavailable.';
    const markup = renderToStaticMarkup(createElement(RelatedEvidencePanel, {
      page: 'resources',
      data: null,
      range: '24h',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));
    expect(markup).toContain('last verified catalog is shown');
    expect(markup).toContain('current-snapshot.jsonl');
  });

  it('unions catalog-declared evidence with curated cross-page evidence without omissions', () => {
    const value = catalog([
      source('current-snapshot', { detailPages: ['resources'] }),
      source('incident-events', { detailPages: ['resources', 'incidents'] }),
      source('power-events', { detailPages: ['power'] }),
    ]);
    value.observations = [{
      id: 'network.application-traffic',
      domain: 'network',
      displayName: { ko: '요청', en: 'Traffic' },
      description: { ko: '요청 증거', en: 'Traffic evidence' },
      evidenceMode: 'current-state',
      cadenceSeconds: 60,
      evidenceSourceIds: ['current-snapshot'],
      detailPages: ['incidents'],
    }];
    expect(relatedEvidenceIds('resources', value)).toEqual(expect.arrayContaining([
      'current-snapshot',
      'incident-events',
    ]));
    expect(relatedEvidenceIds('resources', value)).not.toContain('power-events');
    expect(relatedEvidenceIds('incidents', value)).toContain('current-snapshot');
    expect(relatedEvidenceIds('coverage', value)).toEqual([]);
  });

  it('maps infrastructure evidence to dedicated and source-filtered safe viewers', () => {
    hookCatalog = catalog([
      source('infrastructure-ledger', {
        kind: 'external-state',
        evidenceMode: 'current-state',
        artifactLabel: 'infrastructure-ledger.json',
        format: 'json',
        cadenceSeconds: null,
        retention: {
          policy: 'externally-managed',
          pruneCadence: 'external-no-auto-prune',
          maxAgeDays: null,
          maxRecords: null,
          recordScope: null,
          maxBytes: null,
        },
        detailPages: ['infrastructure'],
      }),
      source('privilege-events', { artifactLabel: 'privilege.jsonl', detailPages: ['reliability', 'maintenance', 'infrastructure'] }),
      source('generic-log-source-state', {
        kind: 'source-status',
        evidenceMode: 'current-state',
        artifactLabel: 'generic-log-sources.json',
        format: 'json',
        detailPages: ['logs'],
      }),
      source('generic-log-events', {
        artifactLabel: 'generic-logs.jsonl',
        retention: {
          policy: 'bounded-age-count-and-bytes',
          pruneCadence: 'every-generic-collection',
          maxAgeDays: 14,
          maxRecords: 10_000,
          recordScope: 'artifact',
          maxBytes: 16_777_216,
        },
        detailPages: ['logs'],
      }),
    ]);

    const markup = renderToStaticMarkup(createElement(RelatedEvidencePanel, {
      page: 'infrastructure',
      data: null,
      range: '24h',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));

    expect(markup).toContain('Related stored records and logs');
    expect(markup).toContain('infrastructure-ledger.json');
    expect(markup).toContain('/monitor/details/infrastructure?range=24h');
    expect(markup).toContain('/monitor/details/logs?range=24h&amp;sourceId=journal%3Assh');
    expect(markup).toContain('/monitor/details/logs?range=24h&amp;sourceId=journal%3Amonitor-collector');
    expect(markup).toContain('Externally managed; no automatic pruning');
    expect(markup).toContain('Pruned on every generic-log collection');
    expect(markup).toContain('View stored records');
    expect(markup).not.toMatch(/\/(?:etc|home|root|run|var|proc|sys|usr)\//u);
  });

  it('lists only the evidence contract assigned to the selected detail page', () => {
    hookCatalog = catalog([
      source('current-snapshot', { evidenceMode: 'current-state', artifactLabel: 'current.json', format: 'json' }),
      source('telemetry-history', { artifactLabel: 'history/YYYY-MM-DD.jsonl' }),
      source('semantic-alert-events', { artifactLabel: 'alerts.jsonl' }),
      source('reliability-events', { artifactLabel: 'reliability.jsonl' }),
      source('rule-evaluation-state', { evidenceMode: 'current-state', artifactLabel: 'rule-evaluation.json', format: 'json' }),
      source('rule-alert-events', { artifactLabel: 'rule-alerts.jsonl' }),
      source('power-events', { artifactLabel: 'power.jsonl' }),
    ]);

    const markup = renderToStaticMarkup(createElement(RelatedEvidencePanel, {
      page: 'resources',
      data: null,
      range: '7d',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));

    for (const artifact of [
      'current.json',
      'history/YYYY-MM-DD.jsonl',
      'alerts.jsonl',
      'reliability.jsonl',
      'rule-evaluation.json',
      'rule-alerts.jsonl',
    ]) expect(markup).toContain(artifact);
    expect(markup).not.toContain('power.jsonl');
  });

  it('does not duplicate a related-evidence panel on the coverage catalog itself', () => {
    hookCatalog = catalog([source('current-snapshot')]);
    const markup = renderToStaticMarkup(createElement(RelatedEvidencePanel, {
      page: 'coverage',
      data: null,
      range: '24h',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));
    expect(markup).toBe('');
  });
});
