import {
  chmodSync,
  closeSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  symlinkSync,
  writeSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  clearGenericLogSnapshotCacheForTests,
  genericLogSnapshotCacheStatsForTests,
  GenericLogQueryError,
  normalizeGenericLogRecord,
  readGenericLogPage,
  type GenericLogQuery,
  type GenericLogRecord,
  type GenericLogSourceStatus,
} from './generic-logs.js';

const NOW = Date.parse('2026-08-30T12:00:00.000Z');
const OWNER = process.getuid?.() ?? 0;

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'monitor-generic-logs-'));
  chmodSync(path, 0o700);
  return path;
}

function record(
  timestamp: string,
  message: string,
  overrides: Partial<GenericLogRecord> = {},
): GenericLogRecord {
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
    ...overrides,
  };
}

function sourceStatus(
  generatedAt = '2026-08-30T12:00:00.000Z',
  overrides: Partial<GenericLogSourceStatus> = {},
): GenericLogSourceStatus {
  return {
    schemaVersion: 1,
    sourceId: 'file:application',
    sourceKind: 'file',
    status: 'fresh',
    observedAt: generatedAt,
    lastSuccessAt: generatedAt,
    errorClass: null,
    seenLines: 3,
    seenBytes: 300,
    parsedEvents: 3,
    admittedEvents: 3,
    droppedLines: 0,
    dropped: {
      inputLineLimit: 0,
      inputByteLimit: 0,
      oversizedLine: 0,
      multilineLineLimit: 0,
      oversizedEvent: 0,
      sourceQuota: 0,
      globalQuota: 0,
      acquisition: 0,
    },
    ...overrides,
  };
}

function writeRecords(root: string, records: GenericLogRecord[]): void {
  const path = join(root, 'generic-logs.jsonl');
  writeFileSync(path, records.map((value) => JSON.stringify(value)).join('\n') + (records.length ? '\n' : ''));
  chmodSync(path, 0o640);
}

function writeStatus(
  root: string,
  generatedAt = '2026-08-30T12:00:00.000Z',
  sources: GenericLogSourceStatus[] = [sourceStatus(generatedAt)],
): void {
  const path = join(root, 'generic-log-sources.json');
  writeFileSync(path, JSON.stringify({ schemaVersion: 1, generatedAt, sources }) + '\n');
  chmodSync(path, 0o640);
}

describe('generic log read model', () => {
  it('normalizes exact public records and rejects unredacted or expanded content', () => {
    const safe = record('2026-08-30T11:59:00.000Z', 'token=[REDACTED]');
    expect(normalizeGenericLogRecord(safe)).toEqual(safe);
    expect(normalizeGenericLogRecord({ ...safe, extra: true })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, message: 'token=raw-secret' })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, message: 'person@example.com' })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, message: 'peer 2001:db8::1' })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, message: 'card 4111 1111 1111 1111' })).toBeNull();
    expect(normalizeGenericLogRecord({
      ...safe,
      message: 'password=[REDACTED] secret phrase]',
    })).toBeNull();
    expect(normalizeGenericLogRecord({
      ...safe,
      message: 'Authorization: [REDACTED] Credential=example Signature=abcdef',
    })).toBeNull();
    expect(normalizeGenericLogRecord({
      ...safe,
      message: 'AWS_SECRET_ACCESS_KEY=supersecret123',
    })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, message: 'db_password=hunter2' })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, fields: { password: 'hidden' } })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, fields: { db_password: 'hidden' } })).toBeNull();
    expect(normalizeGenericLogRecord({ ...safe, timestamp: '2026-08-30T11:59:00Z' })).toBeNull();
  });

  it('filters by time, source, severity, priority and bounded literal text', () => {
    const root = directory();
    writeRecords(root, [
      record('2026-08-30T11:57:00.000Z', 'old informational'),
      record('2026-08-30T11:58:00.000Z', 'database connection failed', {
        severity: 'error', priority: 'incident', fields: { service: 'database' },
      }),
      record('2026-08-30T11:59:00.000Z', 'worker recovered', {
        sourceKind: 'journald', sourceId: 'journal:worker', systemdUnit: 'worker.service',
      }),
    ]);
    writeStatus(root, undefined, [
      sourceStatus(),
      sourceStatus(undefined, {
        sourceId: 'journal:worker', sourceKind: 'journald', seenLines: 1,
        seenBytes: 50, parsedEvents: 1, admittedEvents: 1,
      }),
    ]);
    const page = readGenericLogPage(root, {
      from: '2026-08-30T11:58:00.000Z',
      to: '2026-08-30T12:00:00.000Z',
      sourceIds: ['file:application'],
      severities: ['error'],
      priorities: ['incident'],
      text: 'DATABASE',
    }, NOW, OWNER);
    expect(page.collection.status).toBe('fresh');
    expect(page.items.map((item) => item.message)).toEqual(['database connection failed']);
    expect(page.page).toMatchObject({ returned: 1, total: 1, nextCursor: null, cursorStatus: 'current' });
    expect(page.query.text).toBe('database');
  });

  it('uses a snapshot-bound cursor and reports a stale cursor after append', () => {
    const root = directory();
    const records = [
      record('2026-08-30T11:57:00.000Z', 'one'),
      record('2026-08-30T11:58:00.000Z', 'two'),
      record('2026-08-30T11:59:00.000Z', 'three'),
    ];
    writeRecords(root, records);
    writeStatus(root);
    const first = readGenericLogPage(root, { limit: 2 }, NOW, OWNER);
    expect(first.items.map((item) => item.message)).toEqual(['three', 'two']);
    expect(first.page.nextCursor).toBeTypeOf('string');
    const second = readGenericLogPage(root, {
      limit: 2, cursor: first.page.nextCursor!,
    }, NOW, OWNER);
    expect(second.items.map((item) => item.message)).toEqual(['one']);
    expect(second.page.nextCursor).toBeNull();

    writeRecords(root, [
      ...records,
      record('2026-08-30T11:59:30.000Z', 'new append'),
    ]);
    const stale = readGenericLogPage(root, {
      limit: 2, cursor: first.page.nextCursor!,
    }, NOW, OWNER);
    expect(stale.page.cursorStatus).toBe('stale');
    expect(stale.items).toEqual([]);
  });

  it('parses and sorts one safe snapshot once, then invalidates on atomic replacement', () => {
    clearGenericLogSnapshotCacheForTests();
    const root = directory();
    const original = [
      record('2026-08-30T11:58:00.000Z', 'older'),
      record('2026-08-30T11:59:00.000Z', 'newer'),
    ];
    writeRecords(root, original);
    writeStatus(root);

    const first = readGenericLogPage(root, { limit: 1 }, NOW, OWNER);
    expect(first.items.map((item) => item.message)).toEqual(['newer']);
    expect(first.page.nextCursor).toBeTypeOf('string');
    expect(genericLogSnapshotCacheStatsForTests()).toEqual({
      entries: 1,
      parsedSnapshots: 1,
    });

    for (const text of ['new', 'old', undefined]) {
      readGenericLogPage(root, text ? { text } : {}, NOW, OWNER);
    }
    expect(genericLogSnapshotCacheStatsForTests()).toEqual({
      entries: 1,
      parsedSnapshots: 1,
    });

    const replacement = join(root, '.generic-logs.replacement');
    const replacedRecords = [
      ...original,
      record('2026-08-30T11:59:30.000Z', 'atomic replacement'),
    ];
    writeFileSync(
      replacement,
      `${replacedRecords.map((value) => JSON.stringify(value)).join('\n')}\n`,
    );
    chmodSync(replacement, 0o640);
    renameSync(replacement, join(root, 'generic-logs.jsonl'));

    const stale = readGenericLogPage(root, {
      limit: 1,
      cursor: first.page.nextCursor!,
    }, NOW, OWNER);
    expect(stale.page.cursorStatus).toBe('stale');
    expect(stale.items).toEqual([]);
    expect(genericLogSnapshotCacheStatsForTests()).toEqual({
      entries: 1,
      parsedSnapshots: 2,
    });

    const current = readGenericLogPage(root, {}, NOW, OWNER);
    expect(current.items[0]?.message).toBe('atomic replacement');
    expect(genericLogSnapshotCacheStatsForTests().parsedSnapshots).toBe(2);
  });

  it('binds cursors to canonical query semantics but not the page limit', () => {
    const root = directory();
    writeRecords(root, [
      record('2026-08-30T11:56:00.000Z', 'item one'),
      record('2026-08-30T11:57:00.000Z', 'item two'),
      record('2026-08-30T11:58:00.000Z', 'item three'),
      record('2026-08-30T11:59:00.000Z', 'item four'),
    ]);
    writeStatus(root);
    const query = {
      text: 'ITEM',
      sourceIds: ['journal:unused', 'file:application'],
      sourceKinds: ['journald', 'file'],
      priorities: ['incident', 'normal'],
      severities: ['error', 'info'],
      from: '2026-08-30T11:55:00.000Z',
      to: '2026-08-30T12:00:00.000Z',
    } satisfies GenericLogQuery;
    const first = readGenericLogPage(root, { ...query, limit: 1 }, NOW, OWNER);
    expect(first.items.map((item) => item.message)).toEqual(['item four']);

    const second = readGenericLogPage(root, {
      ...query,
      limit: 2,
      cursor: first.page.nextCursor!,
      text: ' item ',
      sourceIds: [...query.sourceIds].reverse(),
      sourceKinds: [...query.sourceKinds].reverse(),
      priorities: [...query.priorities].reverse(),
      severities: [...query.severities].reverse(),
    }, NOW, OWNER);
    expect(second.items.map((item) => item.message)).toEqual(['item three', 'item two']);

    const mismatchedQueries: GenericLogQuery[] = [
      { ...query, text: 'two' },
      { ...query, sourceIds: ['file:application'] },
      { ...query, sourceKinds: ['file'] },
      { ...query, priorities: ['normal'] },
      { ...query, severities: ['info'] },
      { ...query, from: '2026-08-30T11:56:00.000Z' },
      { ...query, to: '2026-08-30T11:59:00.000Z' },
    ];
    for (const mismatchedQuery of mismatchedQueries) {
      expect(() => readGenericLogPage(root, {
        ...mismatchedQuery,
        cursor: first.page.nextCursor!,
      }, NOW, OWNER)).toThrowError('invalid_cursor');
    }
  });

  it('derives fresh, degraded, stale, unsupported and no-data collection states', () => {
    const freshRoot = directory();
    writeRecords(freshRoot, [record('2026-08-30T11:59:00.000Z', 'ok')]);
    writeStatus(freshRoot);
    expect(readGenericLogPage(freshRoot, {}, NOW, OWNER).collection.status).toBe('fresh');

    const degradedRoot = directory();
    writeRecords(degradedRoot, []);
    writeStatus(degradedRoot, undefined, [sourceStatus(undefined, {
      status: 'permission_denied', lastSuccessAt: null, errorClass: 'permission_denied',
      seenLines: 0, seenBytes: 0, parsedEvents: 0, admittedEvents: 0,
    })]);
    expect(readGenericLogPage(degradedRoot, {}, NOW, OWNER).collection.status).toBe('degraded');

    const staleRoot = directory();
    writeRecords(staleRoot, []);
    writeStatus(staleRoot, '2026-08-30T11:50:00.000Z', [sourceStatus('2026-08-30T11:50:00.000Z')]);
    expect(readGenericLogPage(staleRoot, {}, NOW, OWNER).collection.status).toBe('stale');

    const unsupportedRoot = directory();
    writeRecords(unsupportedRoot, []);
    writeStatus(unsupportedRoot, undefined, [sourceStatus(undefined, {
      status: 'unsupported', lastSuccessAt: null, errorClass: 'unsupported',
      seenLines: 0, seenBytes: 0, parsedEvents: 0, admittedEvents: 0,
    })]);
    expect(readGenericLogPage(unsupportedRoot, {}, NOW, OWNER).collection.status).toBe('unsupported');

    const emptyRoot = directory();
    expect(readGenericLogPage(emptyRoot, {}, NOW, OWNER).collection.status).toBe('no_data');
  });

  it('fails closed on malformed, sensitive, linked, or writable public files', () => {
    const malformedRoot = directory();
    writeRecords(malformedRoot, [{
      ...record('2026-08-30T11:59:00.000Z', 'safe'), extra: true,
    } as unknown as GenericLogRecord]);
    writeStatus(malformedRoot);
    expect(readGenericLogPage(malformedRoot, {}, NOW, OWNER).collection.status).toBe('collection_error');

    const legacyRoot = directory();
    writeRecords(legacyRoot, [{
      ...record('2026-08-30T11:59:00.000Z', 'standalone v1 body row'),
      redactionVersion: 'monitor-log-redaction-v1',
    } as unknown as GenericLogRecord]);
    writeStatus(legacyRoot);
    const legacy = readGenericLogPage(legacyRoot, {}, NOW, OWNER);
    expect(legacy.collection.status).toBe('collection_error');
    expect(legacy.items).toEqual([]);

    const secretRoot = directory();
    writeRecords(secretRoot, [record('2026-08-30T11:59:00.000Z', 'password=raw-secret')]);
    writeStatus(secretRoot);
    expect(readGenericLogPage(secretRoot, {}, NOW, OWNER).collection.status).toBe('collection_error');

    const writableRoot = directory();
    writeRecords(writableRoot, [record('2026-08-30T11:59:00.000Z', 'cached safe')]);
    writeStatus(writableRoot);
    expect(readGenericLogPage(writableRoot, {}, NOW, OWNER).collection.status).toBe('fresh');
    chmodSync(join(writableRoot, 'generic-logs.jsonl'), 0o660);
    const writable = readGenericLogPage(writableRoot, {}, NOW, OWNER);
    expect(writable.collection.status).toBe('collection_error');
    expect(writable.items).toEqual([]);

    const linkedRoot = directory();
    writeRecords(linkedRoot, []);
    const external = join(linkedRoot, 'outside-status.json');
    writeFileSync(external, '{}');
    chmodSync(external, 0o640);
    symlinkSync(external, join(linkedRoot, 'generic-log-sources.json'));
    expect(readGenericLogPage(linkedRoot, {}, NOW, OWNER).collection.status).toBe('collection_error');
  });

  it('derives the mapped owner only from a stable non-writable export root', () => {
    const root = directory();
    writeRecords(root, [record('2026-08-30T11:59:00.000Z', 'mapped owner')]);
    writeStatus(root);

    expect(readGenericLogPage(root, {}, NOW).collection.status).toBe('fresh');
    expect(readGenericLogPage(root, {}, NOW, OWNER + 1).collection.status).toBe('collection_error');

    chmodSync(root, 0o770);
    expect(readGenericLogPage(root, {}, NOW).collection.status).toBe('collection_error');

    const realParent = directory();
    const nestedRoot = join(realParent, 'export');
    mkdirSync(nestedRoot, { mode: 0o700 });
    writeRecords(nestedRoot, [record('2026-08-30T11:59:00.000Z', 'aliased root')]);
    writeStatus(nestedRoot);
    const aliasParent = directory();
    symlinkSync(realParent, join(aliasParent, 'mapped-parent'));
    expect(readGenericLogPage(join(aliasParent, 'mapped-parent', 'export'), {}, NOW).collection.status)
      .toBe('collection_error');
  });

  it('surfaces a strict collector failure marker until a successful collection clears it', () => {
    const root = directory();
    writeRecords(root, [record('2026-08-30T11:59:00.000Z', 'cached before marker')]);
    writeStatus(root, undefined, [sourceStatus(undefined, {
      seenLines: 1, seenBytes: 20, parsedEvents: 1, admittedEvents: 1,
    })]);
    expect(readGenericLogPage(root, {}, NOW, OWNER).items).toHaveLength(1);
    const marker = join(root, 'generic-log-collection-error.json');
    writeFileSync(marker, `${JSON.stringify({
      schemaVersion: 1,
      observedAt: '2026-08-30T12:00:00.000Z',
      errorClass: 'unsafe_config',
    })}\n`);
    chmodSync(marker, 0o640);
    const page = readGenericLogPage(root, {}, NOW, OWNER);
    expect(page.collection).toMatchObject({
      status: 'collection_error', observedAt: '2026-08-30T12:00:00.000Z',
    });
    expect(page.items).toEqual([]);

    writeFileSync(marker, '{"expanded":true}\n');
    chmodSync(marker, 0o640);
    expect(readGenericLogPage(root, {}, NOW, OWNER).collection.status).toBe('collection_error');
  });

  it('rejects unbounded filters, malformed timestamps and non-canonical cursors', () => {
    const root = directory();
    writeRecords(root, []);
    writeStatus(root, undefined, [sourceStatus(undefined, {
      status: 'no_data', seenLines: 0, seenBytes: 0, parsedEvents: 0, admittedEvents: 0,
    })]);
    const invalid = [
      { limit: 201 },
      { text: 'x'.repeat(129) },
      { from: 'not-a-time' },
      { from: '2026-08-30T12:00:00.000Z', to: '2026-08-30T11:00:00.000Z' },
      { sourceKinds: ['socket'] },
      { cursor: 'not base64url!' },
    ];
    for (const query of invalid) {
      expect(() => readGenericLogPage(root, query as never, NOW, OWNER)).toThrow(GenericLogQueryError);
    }
  });

  it('holds a near-maximum 20k snapshot within the bounded cache memory budget', () => {
    clearGenericLogSnapshotCacheForTests();
    const root = directory();
    const path = join(root, 'generic-logs.jsonl');
    const descriptor = openSync(path, 'w', 0o640);
    try {
      for (let index = 0; index < 20_000; index += 1) {
        const value = record(
          '2026-08-30T11:59:00.000Z',
          `event-${String(index).padStart(5, '0')}-${'x'.repeat(300)}`,
        );
        writeSync(descriptor, `${JSON.stringify(value)}\n`);
      }
    } finally {
      closeSync(descriptor);
    }
    chmodSync(path, 0o640);
    const snapshotBytes = statSync(path).size;
    expect(snapshotBytes).toBeGreaterThan(15 * 1024 * 1024);
    expect(snapshotBytes).toBeLessThanOrEqual(16 * 1024 * 1024);
    writeStatus(root);

    const heapBefore = process.memoryUsage().heapUsed;
    const rssBefore = process.memoryUsage().rss;
    const maxRssBefore = process.resourceUsage().maxRSS;
    const page = readGenericLogPage(root, { limit: 1 }, NOW, OWNER);
    const heapGrowth = Math.max(0, process.memoryUsage().heapUsed - heapBefore);
    const rssGrowth = Math.max(0, process.memoryUsage().rss - rssBefore);
    const peakRssGrowth = Math.max(0, process.resourceUsage().maxRSS - maxRssBefore) * 1024;

    expect(page.page).toMatchObject({ total: 20_000, returned: 1 });
    expect(genericLogSnapshotCacheStatsForTests()).toEqual({
      entries: 1,
      parsedSnapshots: 1,
    });
    expect(heapGrowth).toBeLessThan(192 * 1024 * 1024);
    expect(rssGrowth).toBeLessThan(192 * 1024 * 1024);
    expect(peakRssGrowth).toBeLessThan(192 * 1024 * 1024);
    clearGenericLogSnapshotCacheForTests();
  }, 15_000);
});
