import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { infrastructureLedgerLimits, readInfrastructureLedger } from './infrastructure-ledger.js';

const NOW = Date.parse('2026-08-30T03:00:00Z');

function entry(overrides: Record<string, unknown> = {}) {
  return {
    id: 'event.alpha.1',
    itemKey: 'item.alpha',
    revision: 1,
    occurredAt: '2026-08-29T01:00:00Z',
    recordedAt: '2026-08-29T02:00:00Z',
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
    title: { ko: '방화벽 점검', en: 'Firewall review' },
    summary: { ko: '안전한 요약', en: 'Safe summary' },
    rationale: { ko: '노출 확인', en: 'Establish exposure' },
    details: { ko: '고정 스키마 확인', en: 'Checked fixed-schema evidence' },
    outcome: { ko: '후속 검토', en: 'Follow-up review' },
    nextAction: { ko: '승인 후 적용', en: 'Apply after approval' },
    actor: 'codex',
    scope: ['host'],
    evidence: [{
      kind: 'runtime',
      reference: 'runtime:firewall-summary',
      observedAt: '2026-08-29T01:00:00Z',
      note: { ko: '원문 명령 미저장', en: 'Raw command omitted' },
    }],
    referenceIds: ['nist-csf-2'],
    relatedIds: [],
    supersedes: null,
    dueAt: null,
    recurrence: null,
    ...overrides,
  };
}

function document(entries = [entry()]) {
  return {
    schemaVersion: 1,
    updatedAt: '2026-08-30T02:00:00Z',
    coverage: {
      from: null,
      through: '2026-08-30T02:00:00Z',
      sources: [{
        id: 'runtime-audit',
        label: { ko: '현재 상태 감사', en: 'Current-state audit' },
        from: '2026-08-29T01:00:00Z',
        through: '2026-08-30T02:00:00Z',
      }],
      limitations: [{ ko: '보존 전 기록은 복원할 수 없음', en: 'Pre-retention records cannot be reconstructed' }],
    },
    references: [{
      id: 'nist-csf-2',
      title: 'Cybersecurity Framework 2.0',
      publisher: 'NIST',
      url: 'https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20',
      publishedAt: null,
      accessedAt: '2026-08-30T01:00:00Z',
    }],
    entries,
  };
}

function directoryWith(value: unknown): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-ledger-'));
  const path = join(directory, infrastructureLedgerLimits.fileName);
  writeFileSync(path, JSON.stringify(value));
  chmodSync(path, 0o640);
  return directory;
}

describe('infrastructure ledger reader', () => {
  it('normalizes a bounded fixed-schema ledger and preserves revision history', () => {
    const second = entry({
      id: 'event.alpha.2',
      revision: 2,
      occurredAt: '2026-08-30T01:00:00Z',
      recordedAt: '2026-08-30T02:00:00Z',
      status: 'completed',
      supersedes: 'event.alpha.1',
    });
    const ledger = readInfrastructureLedger(
      directoryWith(document([entry(), second])),
      NOW,
    );
    expect(ledger).toMatchObject({
      schemaVersion: 1,
      generatedAt: '2026-08-30T03:00:00.000Z',
      updatedAt: '2026-08-30T02:00:00.000Z',
      limits: { maximumEntries: 5_000, maximumBytes: 16 * 1024 * 1024 },
    });
    expect(ledger?.entries.map(({ id }) => id)).toEqual(['event.alpha.2', 'event.alpha.1']);
    expect(ledger?.references[0].url).toBe('https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20');
  });

  it('fails closed for missing references, conflicting revisions, duplicates, or sensitive text', () => {
    expect(readInfrastructureLedger(directoryWith(document([entry({ referenceIds: ['missing'] })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([
      entry(),
      entry({ id: 'event.alpha.2', revision: 3, occurredAt: '2026-08-30T01:00:00Z', supersedes: 'event.alpha.1' }),
    ])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry(), entry()])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([
      entry(),
      entry({ id: 'event.beta.1', occurredAt: '2026-08-29T03:00:00Z' }),
    ])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({
      status: 'completed',
      verification: 'unverified',
      evidence: [],
    })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ details: {
      ko: 'token=definitely-not-safe',
      en: 'safe',
    } })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ details: {
      ko: 'client 203.0.113.7',
      en: 'unsafe',
    } })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ details: {
      ko: 'operator@example.test',
      en: 'unsafe',
    } })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ scope: ['wgang'] })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ scope: ['host', 'host'] })])), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({ unexpected: true })])), NOW)).toBeNull();

    const withFragment = document();
    withFragment.references[0]!.url = `${withFragment.references[0]!.url}#fragment`;
    expect(readInfrastructureLedger(directoryWith(withFragment), NOW)).toBeNull();
  });

  it('rejects future or internally stale publication timestamps', () => {
    expect(readInfrastructureLedger(directoryWith({
      ...document(),
      updatedAt: '2026-08-31T03:00:00Z',
    }), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith({
      ...document(),
      updatedAt: '2026-08-29T01:30:00Z',
    }), NOW)).toBeNull();
    expect(readInfrastructureLedger(directoryWith(document([entry({
      occurredAt: '2026-02-30T01:00:00Z',
    })])), NOW)).toBeNull();
  });

  it('rejects symlinks, hardlinks, and group-writable publication files', () => {
    const symlinkDirectory = mkdtempSync(join(tmpdir(), 'monitor-ledger-link-'));
    const external = join(symlinkDirectory, 'external.json');
    writeFileSync(external, JSON.stringify(document()));
    chmodSync(external, 0o640);
    mkdirSync(join(symlinkDirectory, 'data'));
    symlinkSync(external, join(symlinkDirectory, 'data', infrastructureLedgerLimits.fileName));
    expect(readInfrastructureLedger(join(symlinkDirectory, 'data'), NOW)).toBeNull();

    const internalSymlinkDirectory = mkdtempSync(join(tmpdir(), 'monitor-ledger-internal-link-'));
    const internalTarget = join(internalSymlinkDirectory, 'real.json');
    writeFileSync(internalTarget, JSON.stringify(document()));
    chmodSync(internalTarget, 0o640);
    symlinkSync(internalTarget, join(internalSymlinkDirectory, infrastructureLedgerLimits.fileName));
    expect(readInfrastructureLedger(internalSymlinkDirectory, NOW)).toBeNull();

    const hardlinkDirectory = directoryWith(document());
    linkSync(
      join(hardlinkDirectory, infrastructureLedgerLimits.fileName),
      join(hardlinkDirectory, 'second-link.json'),
    );
    expect(readInfrastructureLedger(hardlinkDirectory, NOW)).toBeNull();

    const writableDirectory = directoryWith(document());
    chmodSync(join(writableDirectory, infrastructureLedgerLimits.fileName), 0o660);
    expect(readInfrastructureLedger(writableDirectory, NOW)).toBeNull();
  });
});
