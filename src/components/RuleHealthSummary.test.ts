import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type {
  RuleAlertCollection,
  RuleAlertEvent,
  RuleEvaluation,
  RuleEvaluationState,
} from '../types';
import {
  rulePhaseCounts,
  RuleHealthSummary,
  ruleSummaryNeedsAttention,
  selectActiveRules,
  selectFiringRules,
  selectRecentRuleTransitions,
} from './RuleHealthSummary';

function state(ruleId: string, overrides: Partial<RuleEvaluationState> = {}): RuleEvaluationState {
  return {
    ruleId,
    target: `host/${ruleId.toLowerCase()}`,
    metric: 'host.test.metric',
    severity: 'warning',
    description: `${ruleId} description`,
    runbook: `${ruleId} safe procedure`,
    phase: 'inactive',
    breachSamples: 0,
    recoverySamples: 0,
    missingSamples: 0,
    openedAt: null,
    conditionStartedAt: null,
    recoveryStartedAt: null,
    missingStartedAt: null,
    evaluationIntervalSeconds: 60,
    changedAt: '2026-08-30T11:59:00Z',
    lastEvaluatedAt: '2026-08-30T12:00:00Z',
    lastValue: null,
    observationStatus: 'ok',
    ...overrides,
  };
}

function evaluation(states: RuleEvaluationState[] = [], status: RuleEvaluation['status'] = 'ok'): RuleEvaluation {
  return {
    schemaVersion: 1,
    status,
    rulePackVersion: status === 'ok' || status === 'last-known' ? '2026.08.30.1' : null,
    evaluatedAt: status === 'unavailable' ? null : '2026-08-30T12:00:00Z',
    summary: {},
    states: Object.fromEntries(states.map((entry) => [`${entry.ruleId}:${entry.target}`, entry])),
  };
}

function transition(index: number, overrides: Partial<RuleAlertEvent> = {}): RuleAlertEvent {
  return {
    schemaVersion: 1,
    rulePackVersion: '2026.08.30.1',
    idempotencyKey: String(index).padStart(64, '0'),
    ruleId: `Transition${index}`,
    target: `host/node-${index}`,
    transition: index % 2 ? 'firing' : 'resolved',
    severity: 'warning',
    notificationState: 'ready',
    observedAt: `2026-08-30T${String(index).padStart(2, '0')}:00:00Z`,
    openedAt: '2026-08-30T00:00:00Z',
    value: index,
    status: 'ok',
    labels: { scope: 'host' },
    description: 'transition description',
    runbook: 'transition runbook',
    ...overrides,
  };
}

const noAlerts: RuleAlertCollection = { status: 'ok', events: [] };

describe('rule health overview', () => {
  it('collapses only a truly nominal overview while retaining attention states', () => {
    const nominal = evaluation([state('Inactive'), state('Unsupported', { phase: 'unsupported', observationStatus: 'unsupported' })]);
    expect(ruleSummaryNeedsAttention(nominal, noAlerts, false)).toBe(false);
    const compact = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: nominal, alerts: noAlerts, locale: 'en', stale: false, compactWhenNominal: true,
    }));
    expect(compact).toContain('rule-health-compact');
    expect(compact).toContain('2 rules evaluated · 1 unsupported');
    expect(compact).not.toContain('rule-lifecycle-summary');
    expect(compact).not.toContain('rule-coverage-details');

    const pending = evaluation([state('Pending', { phase: 'pending' })]);
    expect(ruleSummaryNeedsAttention(pending, noAlerts, false)).toBe(true);
    const expanded = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: pending, alerts: noAlerts, locale: 'en', stale: false, compactWhenNominal: true,
    }));
    expect(expanded).not.toContain('rule-health-compact');
    expect(expanded).toContain('rule-lifecycle-summary');

    const unavailableAlerts: RuleAlertCollection = { status: 'unavailable', events: [] };
    expect(ruleSummaryNeedsAttention(evaluation(), unavailableAlerts, false)).toBe(true);
    const unavailable = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation(), alerts: unavailableAlerts, locale: 'en', stale: false, compactWhenNominal: true,
    }));
    expect(unavailable).not.toContain('rule-health-compact');
    expect(unavailable).toContain('Recent transition log unavailable');
  });

  it('orders firing rules by severity, caps them at five, and renders safe operator context', () => {
    const rules = [
      state('InfoOld', { phase: 'firing', severity: 'info', openedAt: '2026-08-30T01:00:00Z' }),
      state('WarningNew', { phase: 'firing', severity: 'warning', openedAt: '2026-08-30T10:00:00Z' }),
      state('CriticalNew', { phase: 'firing', severity: 'critical', openedAt: '2026-08-30T09:00:00Z' }),
      state('InfoNew', { phase: 'firing', severity: 'info', openedAt: '2026-08-30T11:00:00Z' }),
      state('CriticalOld', { phase: 'firing', severity: 'critical', openedAt: '2026-08-30T02:00:00Z' }),
      state('WarningOld', {
        phase: 'firing',
        severity: 'warning',
        openedAt: null,
        description: 'Visible <script> text is escaped',
        runbook: 'Inspect token=secret before acting.',
      }),
      state('PendingOnly', { phase: 'pending' }),
    ];
    const model = evaluation(rules);

    expect(selectFiringRules(model).map((entry) => entry.ruleId)).toEqual([
      'CriticalOld',
      'CriticalNew',
      'WarningNew',
      'WarningOld',
      'InfoOld',
    ]);

    const markup = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: model,
      alerts: noAlerts,
      locale: 'en',
      stale: false,
    }));
    expect(markup).toContain('6 rules are firing');
    expect(markup).toContain('CriticalOld');
    expect(markup).toContain('InfoOld');
    expect(markup).not.toContain('InfoNew');
    expect(markup).toContain('1 lower-priority firing rule');
    expect(markup).toContain('Visible &lt;script&gt; text is escaped');
    expect(markup).toContain('token=[redacted]');
    expect(markup).toContain('Not recorded');
    expect(markup).toContain('Safe runbook');
  });

  it('distinguishes unavailable output, evaluator collection errors, and stale last-known state', () => {
    const unavailable = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation([], 'unavailable'), alerts: { status: 'unavailable', events: [] }, locale: 'en', stale: false,
    }));
    const failed = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation([], 'collection_error'), alerts: { status: 'collection_error', events: [] }, locale: 'en', stale: false,
    }));
    const stale = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation(
        [state('LastKnown', { phase: 'firing', severity: 'critical', openedAt: null })],
        'last-known',
      ),
      alerts: noAlerts,
      locale: 'en',
      stale: false,
    }));

    expect(unavailable).toContain('rule-health-unavailable');
    expect(unavailable).toContain('Rule evaluation is not available yet');
    expect(unavailable).not.toContain('Rule evaluation could not be collected');
    expect(failed).toContain('rule-health-error');
    expect(failed).toContain('Rule evaluation could not be collected');
    expect(stale).toContain('rule-health-stale');
    expect(stale).toContain('last evaluation');
    expect(stale).toContain('Observation stale');
    expect(stale).toContain('Not recorded');

    const recoveringStale = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation([state('RecoveringLastKnown', {
        phase: 'recovering',
        severity: 'warning',
        openedAt: '2026-08-30T11:00:00Z',
      })], 'last-known'),
      alerts: noAlerts,
      locale: 'en',
      stale: false,
    }));
    expect(recoveringStale).toContain('1 rule was awaiting recovery confirmation in the last evaluation');
    expect(recoveringStale).toContain('The rule evaluation is stale');
    expect(recoveringStale).not.toContain('No rules were firing in the last evaluation');
  });

  it('renders recovering incidents as active and orders them behind firing rules', () => {
    const model = evaluation([
      state('RecoveringCritical', { phase: 'recovering', severity: 'critical', openedAt: '2026-08-30T11:00:00Z' }),
      state('FiringWarning', { phase: 'firing', severity: 'warning', openedAt: '2026-08-30T11:30:00Z' }),
    ]);
    expect(selectActiveRules(model).map((entry) => entry.ruleId)).toEqual([
      'FiringWarning',
      'RecoveringCritical',
    ]);

    const markup = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: model, alerts: noAlerts, locale: 'en', stale: false,
    }));
    expect(markup).toContain('rule-health-firing');
    expect(markup).toContain('Firing and recovering rules');
    expect(markup).toContain('RecoveringCritical');

    const recoveringOnly = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation([state('RecoveringOnly', {
        phase: 'recovering',
        severity: 'critical',
        openedAt: '2026-08-30T11:00:00Z',
      })]),
      alerts: noAlerts,
      locale: 'en',
      stale: false,
    }));
    expect(recoveringOnly).toContain('rule-health-recovering');
    expect(recoveringOnly).toContain('1 rule is awaiting recovery confirmation');
    expect(recoveringOnly).toContain('RecoveringOnly');
    expect(recoveringOnly).not.toContain('rule-health-nominal');
    expect(recoveringOnly).not.toContain('No rules are firing');
  });

  it('separates pending, no-data, permission, error, and neutral unsupported coverage', () => {
    const model = evaluation([
      state('Inactive'),
      state('Pending', { phase: 'pending' }),
      state('NoData', { phase: 'no_data', observationStatus: 'no_data' }),
      state('Unsupported', { phase: 'unsupported', observationStatus: 'unsupported' }),
      state('Permission', { phase: 'permission_denied', observationStatus: 'permission_denied' }),
      state('Collection', { phase: 'collection_error', observationStatus: 'collection_error' }),
    ]);
    const counts = rulePhaseCounts(model);
    const markup = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: model, alerts: noAlerts, locale: 'en', stale: false,
    }));

    expect(counts).toMatchObject({ pending: 1, recovering: 0, no_data: 1, unsupported: 1, permission_denied: 1, collection_error: 1 });
    expect(markup).toContain('rule-health-coverage');
    expect(markup).toContain('Pending');
    expect(markup).toContain('Recovering');
    expect(markup).toContain('No data');
    expect(markup).toContain('Permission denied');
    expect(markup).toContain('Collection error');
    expect(markup).toContain('coverage-unsupported');
    expect(markup).toContain('Unsupported checks are not faults');
    expect(markup).toContain('<details class="rule-coverage-details">');

    const unsupportedOnly = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation([state('UnsupportedOnly', { phase: 'unsupported', observationStatus: 'unsupported' })]),
      alerts: noAlerts,
      locale: 'en',
      stale: false,
    }));
    expect(unsupportedOnly).toContain('rule-health-nominal');
    expect(unsupportedOnly).not.toContain('rule-health-coverage');
    expect(unsupportedOnly).toContain('Unsupported checks are not faults');
  });

  it('keeps rule transitions separate and limits the newest transition list to five', () => {
    const alerts: RuleAlertCollection = { status: 'ok', events: Array.from({ length: 7 }, (_, index) => transition(index)) };
    expect(selectRecentRuleTransitions(alerts).map((event) => event.ruleId)).toEqual([
      'Transition6', 'Transition5', 'Transition4', 'Transition3', 'Transition2',
    ]);

    const markup = renderToStaticMarkup(createElement(RuleHealthSummary, {
      evaluation: evaluation(), alerts, locale: 'en', stale: false,
    }));
    expect(markup).toContain('5 recent rule transitions');
    expect(markup).toContain('Transition6');
    expect(markup).toContain('Transition2');
    expect(markup).not.toContain('Transition1');
    expect(markup).toContain('<section class="rule-health-summary');
    expect(markup).toContain('aria-labelledby="rule-health-title"');
  });
});
