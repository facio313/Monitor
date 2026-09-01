import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  GenericLogPage,
  GenericLogSourceStatus,
  MonitoringCatalog,
  MonitoringEvidenceSource,
  MonitoringObservation,
  MonitoringRuleDefinition,
} from '../api';
import type { DashboardPayload, RuleEvaluationPhase, RuleEvaluationState } from '../types';
import { buildCoverageRows, CoverageRetentionDetails, MonitoringCoverage } from './MonitoringCoverage';

let hookCatalog: MonitoringCatalog | null = null;

vi.mock('../hooks/useMonitoringCatalog', () => ({
  useMonitoringCatalog: () => ({
    catalog: hookCatalog,
    error: null,
    loading: hookCatalog === null,
    refresh: vi.fn(),
  }),
}));

function evidenceSource(
  id: string,
  evidenceMode: 'current-state' | 'accumulated-log' = 'accumulated-log',
  overrides: Partial<MonitoringEvidenceSource> = {},
): MonitoringEvidenceSource {
  return {
    id,
    displayName: { ko: `${id} 기록`, en: `${id} evidence` },
    description: { ko: `${id} 설명`, en: `${id} description` },
    kind: evidenceMode === 'current-state' ? 'snapshot' : 'event-log',
    evidenceMode,
    artifactLabel: `${id}.jsonl`,
    format: evidenceMode === 'current-state' ? 'json' : 'jsonl',
    cadenceSeconds: 60,
    retention: {
      policy: 'bounded-record-count',
      pruneCadence: 'every-collection',
      maxAgeDays: 30,
      maxRecords: 2_000,
      recordScope: 'artifact',
      maxBytes: 1_048_576,
    },
    detailPages: ['reliability'],
    ...overrides,
  };
}

function observation(
  id: string,
  domain: string,
  evidenceSourceIds: string[],
  overrides: Partial<MonitoringObservation> = {},
): MonitoringObservation {
  return {
    id,
    domain,
    displayName: { ko: `${id} 관찰`, en: `${id} observation` },
    description: { ko: `${id} 설명`, en: `${id} description` },
    evidenceMode: 'current-state',
    cadenceSeconds: 60,
    evidenceSourceIds,
    detailPages: ['reliability'],
    ...overrides,
  };
}

function rule(id: string, overrides: Partial<MonitoringRuleDefinition> = {}): MonitoringRuleDefinition {
  return {
    id,
    domain: 'reliability',
    metric: 'linux.test.value',
    operator: 'gte',
    threshold: 1,
    recoveryThreshold: 0,
    severity: 'warning',
    enabled: true,
    configuredEvaluationIntervalSeconds: 60,
    effectiveEvaluationIntervalSeconds: 75,
    forSeconds: 120,
    forSamples: 2,
    recoverySeconds: 180,
    recoverySamples: 3,
    noDataPolicy: 'ignore',
    noDataSeconds: 120,
    noDataSamples: 2,
    parentRuleId: null,
    labels: {},
    description: `${id} description`,
    runbook: `${id} runbook`,
    stateEvidenceSourceId: 'rule-evaluation-state',
    eventEvidenceSourceId: 'rule-alert-events',
    eventRetention: { maxRecords: 2_000, maxBytes: 1_048_576 },
    detailPages: ['reliability'],
    ...overrides,
  };
}

function state(ruleId: string, phase: RuleEvaluationPhase, target = 'host'): RuleEvaluationState {
  return {
    ruleId,
    target,
    metric: 'linux.test.value',
    severity: 'warning',
    description: `${ruleId} description`,
    runbook: `${ruleId} runbook`,
    phase,
    breachSamples: 1,
    recoverySamples: 0,
    missingSamples: 0,
    openedAt: null,
    conditionStartedAt: null,
    recoveryStartedAt: null,
    missingStartedAt: null,
    evaluationIntervalSeconds: 75,
    changedAt: '2026-09-01T03:00:00.000Z',
    lastEvaluatedAt: '2026-09-01T03:00:00.000Z',
    lastValue: 2,
    observationStatus: phase === 'unsupported' ? 'unsupported' : phase === 'no_data' ? 'no_data' : 'ok',
  };
}

function genericSource(overrides: Partial<GenericLogSourceStatus> = {}): GenericLogSourceStatus {
  return {
    schemaVersion: 1,
    sourceId: 'journal:ssh',
    sourceKind: 'journald',
    status: 'fresh',
    observedAt: '2026-09-01T03:00:00.000Z',
    lastSuccessAt: '2026-09-01T03:00:00.000Z',
    errorClass: null,
    seenLines: 20,
    seenBytes: 2_000,
    parsedEvents: 10,
    admittedEvents: 8,
    droppedLines: 2,
    dropped: {
      inputLineLimit: 0,
      inputByteLimit: 0,
      oversizedLine: 0,
      multilineLineLimit: 0,
      oversizedEvent: 0,
      sourceQuota: 0,
      globalQuota: 0,
      acquisition: 2,
    },
    ...overrides,
  };
}

function genericPage(sources: GenericLogSourceStatus[] = [genericSource()]): GenericLogPage {
  return {
    schemaVersion: 1,
    generatedAt: '2026-09-01T03:00:00.000Z',
    collection: { status: 'fresh', observedAt: '2026-09-01T03:00:00.000Z', sources },
    query: {
      limit: 1,
      text: null,
      sourceIds: [],
      sourceKinds: [],
      priorities: [],
      severities: [],
      from: null,
      to: null,
    },
    items: [],
    page: { limit: 1, returned: 0, total: 0, nextCursor: null, cursorStatus: 'current' },
  };
}

function catalog(): MonitoringCatalog {
  return {
    schemaVersion: 1,
    generatedAt: '2026-09-01T03:00:00.000Z',
    collectionIntervalSeconds: 75,
    rulePackVersion: 'test-v1',
    evidenceSources: [
      evidenceSource('current-snapshot', 'current-state', { artifactLabel: 'current.json' }),
      evidenceSource('rule-evaluation-state', 'current-state', { artifactLabel: 'rule-evaluation.json' }),
      evidenceSource('rule-alert-events', 'accumulated-log', { artifactLabel: 'rule-alerts.jsonl' }),
      evidenceSource('generic-log-events', 'accumulated-log', {
        artifactLabel: 'generic-logs.jsonl',
        retention: {
          policy: 'bounded-age-count-and-bytes',
          pruneCadence: 'every-generic-collection',
          maxAgeDays: 14,
          maxRecords: 10_000,
          recordScope: 'artifact',
          maxBytes: 8_388_608,
        },
        detailPages: ['logs'],
      }),
    ],
    observations: [
      observation('agent.identity-heartbeat', 'agent', ['current-snapshot']),
      observation('synthetic.http-tls', 'synthetic', ['current-snapshot']),
      observation('containers.docker-events', 'containers', ['current-snapshot'], { detailPages: ['containers', 'reliability'] }),
      observation('alerts.transitions-delivery', 'alerts', ['rule-evaluation-state', 'rule-alert-events']),
      observation('logs.generic-events', 'logs', ['generic-log-events'], {
        evidenceMode: 'accumulated-log',
        detailPages: ['logs'],
      }),
    ],
    rules: [
      rule('CriticalFiring', { severity: 'critical' }),
      rule('UnsupportedRule'),
      rule('NoTargetRule'),
      rule('DisabledRule', { enabled: false }),
    ],
  };
}

function dashboard(states: RuleEvaluationState[] = []): DashboardPayload {
  return {
    generatedAt: '2026-09-01T03:00:00.000Z',
    range: '24h',
    stale: false,
    latestObservedAt: '2026-09-01T02:59:55.000Z',
    agent: { status: 'healthy' },
    containerCollection: { status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z' },
    syntheticProbeCollection: { status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z' },
    syntheticProbes: [{
      id: 'public-readiness',
      status: 'tls',
      checkedAt: '2026-09-01T02:59:55.000Z',
      httpStatus: null,
      redirectCount: 0,
      latencyMilliseconds: 50,
      certificateExpiresAt: null,
      certificateDaysRemaining: null,
    }],
    ruleEvaluation: {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'test-v1',
      evaluatedAt: '2026-09-01T03:00:00.000Z',
      summary: {},
      states: Object.fromEntries(states.map((item) => [`${item.ruleId}:${item.target}`, item])),
    },
    ruleAlerts: { status: 'ok', events: [] },
    series: [],
    alerts: [],
    powerEvents: [],
    privilegeEvents: [],
    reliabilityEvents: [],
    incidents: [],
  } as unknown as DashboardPayload;
}

afterEach(() => {
  hookCatalog = null;
});

describe('buildCoverageRows', () => {
  it('includes every catalog item plus each configured generic-log source', () => {
    const value = catalog();
    const page = genericPage([
      genericSource(),
      genericSource({ sourceId: 'file:application', sourceKind: 'file', admittedEvents: 3 }),
    ]);
    const rows = buildCoverageRows(value, dashboard(), page, 'en');

    expect(rows).toHaveLength(
      value.observations.length + value.rules.length + value.evidenceSources.length + page.collection.sources.length,
    );
    expect(rows.map(({ id }) => id)).toEqual(expect.arrayContaining([
      'observation:agent.identity-heartbeat',
      'check:CriticalFiring',
      'evidence:generic-log-events',
      'generic-source:journal:ssh',
      'generic-source:file:application',
    ]));
    expect(rows.find(({ id }) => id === 'generic-source:journal:ssh')).toMatchObject({
      domain: 'logs',
      kind: 'evidence',
      evidenceMode: 'accumulated-log',
      sourceIds: ['generic-log-events'],
      status: { tone: 'ok', label: 'Collected', detail: '8 admitted · 2 dropped' },
    });
  });

  it('keeps observation source policies separate and gives the rule event contract precedence', () => {
    const value = catalog();
    const stateSource = value.evidenceSources.find(({ id }) => id === 'rule-evaluation-state');
    const eventSource = value.evidenceSources.find(({ id }) => id === 'rule-alert-events');
    expect(stateSource).toBeDefined();
    expect(eventSource).toBeDefined();
    stateSource!.retention = {
      policy: 'replace-on-collect',
      pruneCadence: 'replace-on-collection',
      maxAgeDays: null,
      maxRecords: 1,
      recordScope: 'artifact',
      maxBytes: 4_194_304,
    };
    eventSource!.retention = {
      policy: 'bounded-age-count-and-bytes',
      pruneCadence: 'every-rule-evaluation',
      maxAgeDays: 14,
      maxRecords: 9_000,
      recordScope: 'artifact',
      maxBytes: 8_388_608,
    };
    value.rules = [rule('RetentionRule', {
      eventRetention: { maxRecords: 321, maxBytes: 524_288 },
    })];

    const rows = buildCoverageRows(value, dashboard(), genericPage(), 'en');
    const observationRow = rows.find(({ id }) => id === 'observation:alerts.transitions-delivery');
    const ruleRow = rows.find(({ id }) => id === 'check:RetentionRule');

    expect(observationRow?.retentionSources).toHaveLength(2);
    expect(observationRow?.retentionSources.map(({ sourceId, retention }) => ({
      sourceId,
      maxRecords: retention?.maxRecords,
      maxBytes: retention?.maxBytes,
      pruneCadence: retention?.pruneCadence,
    }))).toEqual([
      {
        sourceId: 'rule-evaluation-state',
        maxRecords: 1,
        maxBytes: 4_194_304,
        pruneCadence: 'replace-on-collection',
      },
      {
        sourceId: 'rule-alert-events',
        maxRecords: 9_000,
        maxBytes: 8_388_608,
        pruneCadence: 'every-rule-evaluation',
      },
    ]);
    expect(ruleRow?.retentionSources).toMatchObject([
      {
        sourceId: 'rule-evaluation-state',
        role: 'state',
        retention: { maxRecords: 1, maxBytes: 4_194_304, pruneCadence: 'replace-on-collection' },
      },
      {
        sourceId: 'rule-alert-events',
        role: 'events',
        retention: { maxAgeDays: 14, maxRecords: 321, maxBytes: 524_288, pruneCadence: 'every-rule-evaluation' },
      },
    ]);

    const observationDetails = renderToStaticMarkup(createElement(CoverageRetentionDetails, {
      row: observationRow!,
      locale: 'en',
    }));
    const ruleDetails = renderToStaticMarkup(createElement(CoverageRetentionDetails, {
      row: ruleRow!,
      locale: 'en',
    }));
    expect(observationDetails).toContain('rule-evaluation-state evidence');
    expect(observationDetails).toContain('Retention cap: 1 record/artifact · 4.0 MB');
    expect(observationDetails).toContain('rule-alert-events evidence');
    expect(observationDetails).toContain('Retention cap: 14d · 9,000 records/artifact · 8.0 MB');
    expect(ruleDetails).toContain('State · rule-evaluation-state evidence');
    expect(ruleDetails).toContain('Events · rule-alert-events evidence');
    expect(ruleDetails.match(/Cadence: 1m/g)).toHaveLength(2);
    expect(ruleDetails).toContain('Retention cap: 14d · 321 records/artifact · 512 KB');
    expect(ruleDetails).toContain('Pruning: each rule evaluation');
  });

  it('reports the worst live rule phase and distinguishes unsupported, disabled, and missing targets', () => {
    const rows = buildCoverageRows(catalog(), dashboard([
      state('CriticalFiring', 'unsupported', 'old-target'),
      state('CriticalFiring', 'firing', 'live-target'),
      state('UnsupportedRule', 'unsupported'),
    ]), genericPage(), 'en');

    expect(rows.find(({ id }) => id === 'check:CriticalFiring')?.status).toEqual({
      tone: 'danger',
      label: 'Firing',
      detail: '2 targets · 1 firing',
    });
    expect(rows.find(({ id }) => id === 'check:UnsupportedRule')?.status.tone).toBe('neutral');
    expect(rows.find(({ id }) => id === 'check:UnsupportedRule')?.status.label).toBe('Unsupported');
    expect(rows.find(({ id }) => id === 'check:NoTargetRule')?.status).toMatchObject({ tone: 'caution', label: 'No target' });
    expect(rows.find(({ id }) => id === 'check:DisabledRule')?.status).toMatchObject({ tone: 'neutral', label: 'Disabled' });
  });

  it('does not hide a collection failure behind a non-critical firing target', () => {
    const value = catalog();
    value.rules = [rule('MixedWarning')];
    const rows = buildCoverageRows(value, dashboard([
      state('MixedWarning', 'firing', 'breaching-target'),
      state('MixedWarning', 'collection_error', 'uncollected-target'),
    ]), genericPage(), 'en');
    expect(rows.find(({ id }) => id === 'check:MixedWarning')?.status)
      .toMatchObject({ tone: 'danger', label: 'Collection error' });
  });

  it('surfaces a failed synthetic probe as danger without treating healthy collection as sufficient', () => {
    const rows = buildCoverageRows(catalog(), dashboard(), genericPage(), 'en');
    expect(rows.find(({ id }) => id === 'observation:synthetic.http-tls')?.status).toMatchObject({
      tone: 'danger',
      label: 'Probe failed',
      detail: '1 failed results',
    });
  });

  it('treats intentionally inactive agents as caution rather than healthy or failed', () => {
    const data = dashboard();
    data.agent.status = 'inactive';
    expect(buildCoverageRows(catalog(), data, genericPage(), 'en')
      .find(({ id }) => id === 'observation:agent.identity-heartbeat')?.status)
      .toMatchObject({ tone: 'caution', detail: 'inactive' });
  });

  it('uses subsystem collection health instead of painting stale or failed checks green', () => {
    const data = dashboard([state('CriticalFiring', 'firing')]);
    data.dockerEventCollection = {
      status: 'gap',
      observedAt: '2026-09-01T02:59:55.000Z',
      cursorAt: '2026-09-01T02:59:50.000Z',
      reconnectCount: 1,
      gapCount: 1,
      gapDetected: true,
      logCollectionStatus: 'unsupported',
    };
    data.ruleAlerts = { status: 'collection_error', events: [] };
    data.ruleEvaluation.status = 'last-known';
    const rows = buildCoverageRows(catalog(), data, genericPage(), 'en');

    expect(rows.find(({ id }) => id === 'observation:containers.docker-events')?.status)
      .toMatchObject({ tone: 'caution', detail: 'gap' });
    expect(rows.find(({ id }) => id === 'observation:alerts.transitions-delivery')?.status)
      .toMatchObject({ tone: 'danger', detail: 'collection_error' });
    expect(rows.find(({ id }) => id === 'check:CriticalFiring')?.status)
      .toMatchObject({ tone: 'caution', detail: 'last-known' });
    expect(rows.find(({ id }) => id === 'evidence:rule-alert-events')?.status)
      .toMatchObject({ tone: 'danger', detail: 'collection_error' });
  });

  it('keeps known subsystem failures dangerous when the overall snapshot is also stale', () => {
    const data = dashboard([state('CriticalFiring', 'inactive')]);
    data.stale = true;
    data.ruleEvaluation.status = 'collection_error';
    data.ruleAlerts = { status: 'collection_error', events: [] };
    data.dockerEventCollection = {
      status: 'permission-denied',
      observedAt: null,
      cursorAt: null,
      reconnectCount: 0,
      gapCount: 0,
      gapDetected: false,
      logCollectionStatus: 'unsupported',
    };
    const rows = buildCoverageRows(catalog(), data, genericPage(), 'en');
    expect(rows.find(({ id }) => id === 'check:CriticalFiring')?.status.tone).toBe('danger');
    expect(rows.find(({ id }) => id === 'observation:containers.docker-events')?.status.tone).toBe('danger');
    expect(rows.find(({ id }) => id === 'observation:alerts.transitions-delivery')?.status.tone).toBe('danger');
    expect(rows.find(({ id }) => id === 'evidence:rule-alert-events')?.status.tone).toBe('danger');
  });

  it('does not claim nominal health for event files without an independent read signal', () => {
    const rows = buildCoverageRows(catalog(), dashboard(), genericPage(), 'en');
    expect(rows.find(({ id }) => id === 'evidence:generic-log-events')?.status.tone).toBe('ok');
    const value = catalog();
    value.evidenceSources.push(evidenceSource('incident-events'));
    value.observations.push(observation('incidents.resource-windows', 'incidents', ['incident-events'], { evidenceMode: 'accumulated-log' }));
    const uncertainRows = buildCoverageRows(value, dashboard(), genericPage(), 'en');
    expect(uncertainRows.find(({ id }) => id === 'evidence:incident-events')?.status)
      .toMatchObject({ tone: 'neutral', label: 'No independent health signal' });
    expect(uncertainRows.find(({ id }) => id === 'observation:incidents.resource-windows')?.status.tone)
      .toBe('neutral');
  });
});

describe('MonitoringCoverage', () => {
  it('renders generated counts, retention policy, and every loaded rule without raw host paths', () => {
    hookCatalog = catalog();
    const markup = renderToStaticMarkup(createElement(MonitoringCoverage, {
      data: dashboard([state('CriticalFiring', 'firing')]),
      range: '24h',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));

    expect(markup).toContain('GENERATED FROM CURRENT RUNTIME SETTINGS');
    expect(markup).toContain('Complete observation and check catalog');
    expect(markup).toContain('CriticalFiring');
    expect(markup).toContain('UnsupportedRule');
    expect(markup).toContain('NoTargetRule');
    expect(markup).toContain('DisabledRule');
    expect(markup).toContain('30d');
    expect(markup).toContain('2,000 records');
    expect(markup).toContain('prune each collection');
    expect(markup).not.toMatch(/\/(?:etc|home|root|run|var|proc|sys|usr)\//u);
  });

  it('renders unambiguous observation and rule retention summaries in their own rows', () => {
    const value = catalog();
    const stateSource = value.evidenceSources.find(({ id }) => id === 'rule-evaluation-state');
    const eventSource = value.evidenceSources.find(({ id }) => id === 'rule-alert-events');
    expect(stateSource).toBeDefined();
    expect(eventSource).toBeDefined();
    stateSource!.retention = {
      policy: 'replace-on-collect',
      pruneCadence: 'replace-on-collection',
      maxAgeDays: null,
      maxRecords: 1,
      recordScope: 'artifact',
      maxBytes: 4_194_304,
    };
    eventSource!.retention = {
      policy: 'bounded-age-count-and-bytes',
      pruneCadence: 'every-rule-evaluation',
      maxAgeDays: 14,
      maxRecords: 9_000,
      recordScope: 'artifact',
      maxBytes: 8_388_608,
    };
    value.rules = [rule('RetentionRule', {
      eventRetention: { maxRecords: 321, maxBytes: 524_288 },
    })];
    hookCatalog = value;

    const markup = renderToStaticMarkup(createElement(MonitoringCoverage, {
      data: dashboard(),
      range: '24h',
      locale: 'en',
      onUnauthorized: vi.fn(),
    }));
    const rowMarkup = (label: string) => {
      const labelAt = markup.indexOf(label);
      expect(labelAt).toBeGreaterThanOrEqual(0);
      return markup.slice(markup.lastIndexOf('<tr', labelAt), markup.indexOf('</tr>', labelAt));
    };
    const observationMarkup = rowMarkup('alerts.transitions-delivery observation');
    const ruleMarkup = rowMarkup('RetentionRule');

    expect(observationMarkup).toContain('2 sources · distinct per-source caps');
    expect(observationMarkup).toContain('1 record/artifact · 4.0 MB');
    expect(observationMarkup).toContain('14d · 9,000 records/artifact · 8.0 MB');
    expect(observationMarkup).toContain('Per-source pruning replace each collection / each rule evaluation');
    expect(ruleMarkup).toContain('2 sources · State: 1 record/artifact · 4.0 MB');
    expect(ruleMarkup).toContain('Events: 14d · 321 records/artifact · 512 KB');
    expect(ruleMarkup).toContain('State: replace each collection / Events: each rule evaluation');
    expect(ruleMarkup).not.toContain('9,000 records/artifact');
  });
});
