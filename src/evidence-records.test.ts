import { describe, expect, it } from 'vitest';
import type { MonitoringEvidenceSource } from './api';
import { evidenceRecords } from './evidence-records';
import type { AlertEvent, DashboardPayload, RuleEvaluationState } from './types';

function source(id: string): Pick<MonitoringEvidenceSource, 'id'> {
  return { id };
}

function ruleState(ruleId: string, target: string): RuleEvaluationState {
  return {
    ruleId,
    target,
    metric: 'metric.test',
    severity: 'warning',
    description: 'description',
    runbook: 'runbook',
    phase: 'inactive',
    breachSamples: 0,
    recoverySamples: 0,
    missingSamples: 0,
    openedAt: null,
    conditionStartedAt: null,
    recoveryStartedAt: null,
    missingStartedAt: null,
    evaluationIntervalSeconds: 60,
    changedAt: '2026-09-01T03:00:00.000Z',
    lastEvaluatedAt: '2026-09-01T03:00:00.000Z',
    lastValue: 0,
    observationStatus: 'ok',
  };
}

function dashboard(overrides: Partial<DashboardPayload> = {}): DashboardPayload {
  return {
    generatedAt: '2026-09-01T03:00:00.000Z',
    range: '24h',
    stale: false,
    latestObservedAt: '2026-09-01T02:59:55.000Z',
    agent: { status: 'healthy' },
    host: { hostname: 'monitor-host', os: 'Linux', architecture: 'arm64', logicalCpuCount: 8, uptimeSeconds: 300 },
    reliability: {},
    linux: { status: 'supported' },
    latest: { timestamp: '2026-09-01T02:59:55.000Z', cpuPercent: 2 },
    series: [
      { timestamp: '2026-09-01T02:58:00.000Z', cpuPercent: 1 },
      { timestamp: '2026-09-01T02:59:00.000Z', cpuPercent: 2 },
    ],
    incidents: [],
    disks: [],
    containerCollection: { status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z' },
    containers: [],
    currentTraffic: [],
    alerts: [],
    ruleEvaluation: {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'test-v1',
      evaluatedAt: '2026-09-01T03:00:00.000Z',
      summary: { inactive: 2 },
      states: {
        second: ruleState('ZuluRule', 'b'),
        first: ruleState('AlphaRule', 'z'),
      },
    },
    ruleAlerts: { status: 'ok', events: [] },
    privilegeEvents: [],
    powerEvents: [],
    reliabilityEvents: [],
    powerSummary: {},
    system: {},
    ...overrides,
  } as unknown as DashboardPayload;
}

describe('evidenceRecords', () => {
  it('returns only the API-validated reduced snapshot instead of unrelated event collections', () => {
    const result = evidenceRecords(source('current-snapshot'), dashboard({
      alerts: [{ timestamp: '2026-09-01T02:00:00.000Z', severity: 'warning', kind: 'test', status: 'open', message: 'event' }],
      privilegeEvents: [{ timestamp: '2026-09-01T02:00:00.000Z', actor: 'admin', target: 'root', action: 'sudo', result: 'ok' }],
      dockerEvents: [{
        id: 'docker-event',
        occurredAt: '2026-09-01T02:00:00.000Z',
        action: 'start',
        containerName: 'application',
        project: 'portfolio',
        instanceId: '1234567890abcdef1234567890abcdef',
        exitCode: null,
        healthStatus: 'healthy',
      }],
      disks: [{ mount: '/var/lib/private-volume', totalBytes: 100, usedBytes: 10, availableBytes: 90, usedPercent: 10, inodeUsedPercent: 1, readOnly: false }],
      reliability: {
        bootStartedAt: 'token=raw-secret-value',
        collectorGapSeconds: 0,
        sshListenersAvailable: true,
        networkLinkAvailable: true,
        nvmeMitigationActive: true,
      },
    }), 'en');

    expect(result).toMatchObject({ limited: false });
    expect(result.note).toContain('API-validated reduced current state');
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      generatedAt: '2026-09-01T03:00:00.000Z',
      stale: false,
      host: { hostname: 'monitor-host' },
      containerCollection: { status: 'fresh' },
    });
    expect(result.records[0]).not.toHaveProperty('alerts');
    expect(result.records[0]).not.toHaveProperty('privilegeEvents');
    expect(result.records[0]).not.toHaveProperty('ruleAlerts');
    expect(result.records[0]).toHaveProperty('dockerEvents.0.instanceId', '1234567890ab…');
    expect(result.records[0]).toHaveProperty('disks.0.mount', 'filesystem:private-volume');
    expect(result.records[0]).toHaveProperty('reliability.bootStartedAt', '[redacted]');
  });

  it('orders accumulated records newest first and enforces the 200-record display bound', () => {
    const alerts: AlertEvent[] = Array.from({ length: 205 }, (_, index) => ({
      timestamp: new Date(Date.UTC(2026, 8, 1, 0, 0, index)).toISOString(),
      severity: 'info',
      kind: 'test',
      status: 'recorded',
      message: `event-${index}`,
    }));
    const result = evidenceRecords(source('semantic-alert-events'), dashboard({ alerts }), 'en');

    expect(result.records).toHaveLength(200);
    expect(result.limited).toBe(true);
    expect(result.records[0]).toMatchObject({ message: 'event-204' });
    expect(result.records.at(-1)).toMatchObject({ message: 'event-5' });
    expect(result.note).toContain('selected range');
  });

  it('uses newest-first history and stable rule/target ordering for current evaluation state', () => {
    const data = dashboard();
    const history = evidenceRecords(source('telemetry-history'), data, 'en');
    expect(history.records.map((record) => (record as { cpuPercent: number }).cpuPercent)).toEqual([2, 1]);

    const rules = evidenceRecords(source('rule-evaluation-state'), data, 'en');
    expect(rules.records.map((record) => (record as RuleEvaluationState).ruleId)).toEqual(['AlphaRule', 'ZuluRule']);
  });

  it('keeps dedicated raw-backed streams out of the generic record dialog', () => {
    const data = dashboard();
    const cases = [
      ['generic-log-events', 'queried safely by sourceId'],
      ['generic-log-source-state', 'Logs page shows each source status'],
      ['system-update-state', 'Versions & updates page'],
      ['infrastructure-ledger', 'Infrastructure ledger page'],
      ['agent-inventory', 'reduced management API state'],
    ] as const;

    for (const [id, expectedNote] of cases) {
      const result = evidenceRecords(source(id), data, 'en');
      expect(result.records, id).toEqual([]);
      expect(result.limited, id).toBe(false);
      expect(result.note, id).toContain(expectedNote);
    }
  });

  it('returns an explicit empty state when no dashboard snapshot was loaded', () => {
    expect(evidenceRecords(source('current-snapshot'), null, 'ko')).toEqual({
      records: [],
      limited: false,
      note: '이 페이지에서 원격 측정 스냅샷을 불러오지 않았습니다.',
    });
  });
});
