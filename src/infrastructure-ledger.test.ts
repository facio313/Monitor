import { describe, expect, it } from 'vitest';
import {
  currentInfrastructureLedgerEntries,
  filterInfrastructureLedgerEntries,
  groupInfrastructureLedgerEntries,
  summarizeInfrastructureLedger,
  type InfrastructureLedgerFilters,
} from './infrastructure-ledger';
import type { InfrastructureLedgerEntry } from './types';

function entry(overrides: Partial<InfrastructureLedgerEntry> = {}): InfrastructureLedgerEntry {
  return {
    id: 'event.alpha.1',
    itemKey: 'item.alpha',
    revision: 1,
    occurredAt: '2026-08-28T01:00:00.000Z',
    recordedAt: '2026-08-28T02:00:00.000Z',
    category: 'security',
    workType: 'audit',
    status: 'pending',
    priority: 'high',
    confidence: 'current-state',
    verification: 'verified',
    applicability: 'applicable',
    impact: 'none',
    sensitivity: 'internal',
    csfFunctions: ['identify'],
    title: { ko: '방화벽 감사', en: 'Firewall audit' },
    summary: { ko: '인바운드 정책을 확인함', en: 'Reviewed inbound policy' },
    rationale: { ko: '노출 범위 확인', en: 'Establish exposure' },
    details: { ko: '고정 스키마 증거', en: 'Fixed-schema evidence' },
    outcome: { ko: '검토 필요', en: 'Review required' },
    nextAction: { ko: '정책 승인', en: 'Approve policy' },
    actor: 'codex',
    scope: ['host'],
    evidence: [{
      kind: 'runtime',
      reference: 'runtime:firewall-summary',
      observedAt: '2026-08-28T01:00:00.000Z',
      note: { ko: '비밀 없는 요약', en: 'Secret-free summary' },
    }],
    referenceIds: [],
    relatedIds: [],
    supersedes: null,
    dueAt: null,
    recurrence: null,
    ...overrides,
  };
}

const EMPTY_FILTERS: InfrastructureLedgerFilters = {
  query: '',
  category: 'all',
  status: 'all',
  workType: 'all',
  priority: 'all',
  verification: 'all',
  sensitivity: 'all',
  csfFunction: 'all',
  from: '',
  to: '',
};

describe('infrastructure ledger model', () => {
  const records = [
    entry(),
    entry({
      id: 'event.alpha.2',
      revision: 2,
      occurredAt: '2026-08-29T01:00:00.000Z',
      status: 'completed',
      priority: 'medium',
      title: { ko: '방화벽 감사 완료', en: 'Firewall audit completed' },
      supersedes: 'event.alpha.1',
    }),
    entry({
      id: 'event.beta.1',
      itemKey: 'item.beta',
      occurredAt: '2026-08-30T01:00:00.000Z',
      category: 'backup-recovery',
      workType: 'recommendation',
      status: 'recommended',
      priority: 'critical',
      verification: 'unverified',
      applicability: 'needs-assessment',
      confidence: 'recommendation',
      title: { ko: '복구 시험', en: 'Recovery exercise' },
      summary: { ko: '격리 복원을 시험해야 함', en: 'Test isolated restore' },
    }),
  ];

  it('selects the latest immutable revision for each work item', () => {
    expect(currentInfrastructureLedgerEntries(records).map(({ id }) => id)).toEqual([
      'event.beta.1',
      'event.alpha.2',
    ]);
  });

  it('summarizes only current work-item states', () => {
    expect(summarizeInfrastructureLedger(records)).toEqual({
      total: 2,
      completed: 1,
      open: 1,
      pending: 0,
      recommended: 1,
      deferred: 0,
      highPriorityOpen: 1,
    });
  });

  it('filters localized narrative, exact facets, and date boundaries', () => {
    expect(filterInfrastructureLedgerEntries(records, {
      ...EMPTY_FILTERS,
      query: '격리 복원',
      category: 'backup-recovery',
      priority: 'critical',
      verification: 'unverified',
      from: '2026-08-30',
      to: '2026-08-30',
    }, 'ko').map(({ id }) => id)).toEqual(['event.beta.1']);
    expect(filterInfrastructureLedgerEntries(records, { ...EMPTY_FILTERS, query: 'missing' }, 'en')).toEqual([]);
  });

  it('groups deterministically by date, category, and status', () => {
    expect(groupInfrastructureLedgerEntries(records, 'date').map(({ key }) => key)).toEqual([
      '2026-08-30', '2026-08-29', '2026-08-28',
    ]);
    expect(groupInfrastructureLedgerEntries(records, 'category').map(({ key }) => key)).toEqual([
      'backup-recovery', 'security',
    ]);
    expect(groupInfrastructureLedgerEntries(records, 'status').map(({ key }) => key)).toEqual([
      'completed', 'pending', 'recommended',
    ]);
  });
});
