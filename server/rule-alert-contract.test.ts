import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { dataLimits, readDashboard } from './data.js';

const NOW = Date.parse('2026-08-30T12:00:00.000Z');
const temporaryDirectories: string[] = [];

function dataDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-rule-contract-'));
  temporaryDirectories.push(directory);
  mkdirSync(join(directory, 'history'));
  return directory;
}

function evaluationState() {
  return {
    ruleId: 'CpuUsageHigh',
    target: 'host/node-a',
    metric: 'host.cpu.percent',
    severity: 'warning',
    description: 'CPU usage remains high.',
    runbook: 'Inspect load and top processes.',
    phase: 'firing',
    breachSamples: 3,
    recoverySamples: 0,
    missingSamples: 0,
    openedAt: '2026-08-30T11:58:00Z',
    conditionStartedAt: '2026-08-30T11:58:00Z',
    recoveryStartedAt: null,
    missingStartedAt: null,
    evaluationIntervalSeconds: 60,
    changedAt: '2026-08-30T12:00:00Z',
    lastEvaluatedAt: '2026-08-30T12:00:00Z',
    lastValue: 95,
    observationStatus: 'ok',
  };
}

function evaluationDocument() {
  return {
    schemaVersion: 1,
    status: 'ok',
    rulePackVersion: '2026.08.1',
    evaluatedAt: '2026-08-30T12:00:00Z',
    summary: { firing: 1 },
    states: { 'CpuUsageHigh:host/node-a': evaluationState() },
  };
}

function alertEvent() {
  return {
    schemaVersion: 1,
    rulePackVersion: '2026.08.1',
    idempotencyKey: 'a'.repeat(64),
    ruleId: 'CpuUsageHigh',
    target: 'host/node-a',
    transition: 'firing',
    severity: 'warning',
    notificationState: 'ready',
    observedAt: '2026-08-30T12:00:00Z',
    openedAt: '2026-08-30T11:58:00Z',
    value: 95,
    status: 'ok',
    labels: { scope: 'host' },
    description: 'CPU usage remains high.',
    runbook: 'Inspect load and top processes.',
  };
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('rule evaluation and alert API contract', () => {
  it('reports missing outputs as unavailable without merging them into legacy alerts', () => {
    const directory = dataDirectory();
    const dashboard = readDashboard(directory, '1h', NOW, 300_000);

    expect(dashboard.ruleEvaluation).toEqual({
      schemaVersion: 1,
      status: 'unavailable',
      rulePackVersion: null,
      evaluatedAt: null,
      summary: {},
      states: {},
    });
    expect(dashboard.ruleAlerts).toEqual({ status: 'unavailable', events: [] });
    expect(dashboard.alerts).toEqual([]);
  });

  it('admits only the exact internally consistent evaluation and event schemas', () => {
    const directory = dataDirectory();
    writeFileSync(
      join(directory, 'rule-evaluation.json'),
      `${JSON.stringify(evaluationDocument())}\n`,
    );
    writeFileSync(join(directory, 'rule-alerts.jsonl'), `${JSON.stringify(alertEvent())}\n`);
    writeFileSync(join(directory, 'alerts.jsonl'), `${JSON.stringify({
      timestamp: '2026-08-30T11:59:00Z',
      severity: 'warning',
      message: 'Legacy alert remains separate.',
    })}\n`);

    const dashboard = readDashboard(directory, '1h', NOW, 300_000);
    expect(dashboard.ruleEvaluation).toEqual({
      ...evaluationDocument(),
      evaluatedAt: '2026-08-30T12:00:00.000Z',
      states: {
        'CpuUsageHigh:host/node-a': {
          ...evaluationState(),
          openedAt: '2026-08-30T11:58:00.000Z',
          conditionStartedAt: '2026-08-30T11:58:00.000Z',
          changedAt: '2026-08-30T12:00:00.000Z',
          lastEvaluatedAt: '2026-08-30T12:00:00.000Z',
        },
      },
    });
    expect(dashboard.ruleAlerts).toEqual({
      status: 'ok',
      events: [{
        ...alertEvent(),
        observedAt: '2026-08-30T12:00:00.000Z',
        openedAt: '2026-08-30T11:58:00.000Z',
      }],
    });
    expect(dashboard.alerts).toHaveLength(1);
    expect(JSON.stringify(dashboard.alerts)).not.toContain('CpuUsageHigh');
  });

  it('downgrades an old successful evaluation to last-known without dropping its state', () => {
    const directory = dataDirectory();
    const old = evaluationDocument();
    old.evaluatedAt = '2026-08-30T11:00:00Z';
    old.states['CpuUsageHigh:host/node-a'].changedAt = '2026-08-30T11:00:00Z';
    old.states['CpuUsageHigh:host/node-a'].lastEvaluatedAt = '2026-08-30T11:00:00Z';
    old.states['CpuUsageHigh:host/node-a'].openedAt = '2026-08-30T10:58:00Z';
    old.states['CpuUsageHigh:host/node-a'].conditionStartedAt = '2026-08-30T10:58:00Z';
    writeFileSync(join(directory, 'rule-evaluation.json'), `${JSON.stringify(old)}\n`);

    const dashboard = readDashboard(directory, '1h', NOW, 300_000);
    expect(dashboard.ruleEvaluation.status).toBe('last-known');
    expect(dashboard.ruleEvaluation.rulePackVersion).toBe('2026.08.1');
    expect(dashboard.ruleEvaluation.summary).toEqual({ firing: 1 });
    expect(dashboard.ruleEvaluation.states['CpuUsageHigh:host/node-a']).toMatchObject({
      phase: 'firing',
      openedAt: '2026-08-30T10:58:00.000Z',
      lastEvaluatedAt: '2026-08-30T11:00:00.000Z',
    });
  });

  it('preserves an explicit collection error but fails closed on contradictory content', () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'rule-evaluation.json'), JSON.stringify({
      schemaVersion: 1,
      status: 'collection_error',
      rulePackVersion: null,
      evaluatedAt: '2026-08-30T12:00:00Z',
      summary: {},
      states: {},
    }));
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleEvaluation).toEqual({
      schemaVersion: 1,
      status: 'collection_error',
      rulePackVersion: null,
      evaluatedAt: '2026-08-30T12:00:00.000Z',
      summary: {},
      states: {},
    });

    const contradictory = evaluationDocument();
    contradictory.summary = { firing: 2 };
    writeFileSync(join(directory, 'rule-evaluation.json'), JSON.stringify(contradictory));
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleEvaluation).toEqual({
      schemaVersion: 1,
      status: 'collection_error',
      rulePackVersion: null,
      evaluatedAt: null,
      summary: {},
      states: {},
    });
  });

  it('rejects partial malformed or oversized rule exports as collection errors', () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'rule-alerts.jsonl'), [
      JSON.stringify(alertEvent()),
      JSON.stringify({ ...alertEvent(), rawCommand: 'must-not-pass' }),
      '',
    ].join('\n'));
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleAlerts).toEqual({
      status: 'collection_error',
      events: [],
    });

    writeFileSync(
      join(directory, 'rule-evaluation.json'),
      'x'.repeat(dataLimits.maximumRuleEvaluationBytes + 1),
    );
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleEvaluation.status).toBe(
      'collection_error',
    );
  });

  it('fails closed on invalid duration-state timing and cadence metadata', () => {
    const directory = dataDirectory();
    const invalidCadence = evaluationDocument();
    invalidCadence.states['CpuUsageHigh:host/node-a'].evaluationIntervalSeconds = 0;
    writeFileSync(join(directory, 'rule-evaluation.json'), JSON.stringify(invalidCadence));
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleEvaluation.status).toBe(
      'collection_error',
    );

    const futureRecovery = evaluationDocument();
    futureRecovery.states['CpuUsageHigh:host/node-a'].recoveryStartedAt = '2026-08-30T12:01:00Z';
    writeFileSync(join(directory, 'rule-evaluation.json'), JSON.stringify(futureRecovery));
    expect(readDashboard(directory, '1h', NOW, 300_000).ruleEvaluation.status).toBe(
      'collection_error',
    );
  });
});
