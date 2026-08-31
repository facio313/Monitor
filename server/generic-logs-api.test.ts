import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import type { GenericLogRecord, GenericLogSourceStatus } from './generic-logs.js';

const NOW = Date.parse('2026-08-30T12:00:00.000Z');
const SESSION_SECRET = 'generic-log-api-test-session-secret-32-bytes';
const PASSWORD = 'correct horse battery staple';
const OWNER = process.getuid?.() ?? 0;

function fixtureDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-generic-log-api-'));
  chmodSync(directory, 0o700);
  return directory;
}

function record(
  timestamp: string,
  sourceId: string,
  message: string,
  severity: GenericLogRecord['severity'],
): GenericLogRecord {
  return {
    schemaVersion: 1,
    timestamp,
    observedAt: timestamp,
    timestampSource: 'event',
    sourceKind: sourceId.startsWith('journal:') ? 'journald' : 'file',
    sourceId,
    priority: severity === 'error' ? 'incident' : 'normal',
    severity,
    parser: 'plain',
    message,
    truncated: false,
    multilineLineCount: 1,
    hostId: null,
    containerName: null,
    composeProject: null,
    composeService: null,
    processName: null,
    systemdUnit: sourceId.startsWith('journal:') ? 'worker.service' : null,
    stream: null,
    fields: {},
    redactionVersion: 'monitor-log-redaction-v2',
  };
}

function status(sourceId: string, sourceKind: 'file' | 'journald'): GenericLogSourceStatus {
  return {
    schemaVersion: 1,
    sourceId,
    sourceKind,
    status: 'fresh',
    observedAt: '2026-08-30T12:00:00.000Z',
    lastSuccessAt: '2026-08-30T12:00:00.000Z',
    errorClass: null,
    seenLines: 1,
    seenBytes: 32,
    parsedEvents: 1,
    admittedEvents: 1,
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
  };
}

function writeFixture(directory: string): void {
  const records = [
    record('2026-08-30T11:58:00.000Z', 'file:app', 'database failed', 'error'),
    record('2026-08-30T11:59:00.000Z', 'journal:worker', 'worker healthy', 'info'),
  ];
  const logsPath = join(directory, 'generic-logs.jsonl');
  const statusPath = join(directory, 'generic-log-sources.json');
  writeFileSync(logsPath, `${records.map((item) => JSON.stringify(item)).join('\n')}\n`);
  writeFileSync(statusPath, `${JSON.stringify({
    schemaVersion: 1,
    generatedAt: '2026-08-30T12:00:00.000Z',
    sources: [status('file:app', 'file'), status('journal:worker', 'journald')],
  })}\n`);
  chmodSync(logsPath, 0o640);
  chmodSync(statusPath, 0o640);
}

function appFor(directory: string) {
  return createApp({
    password: PASSWORD,
    authStateFile: join(directory, 'auth-state.json'),
    sessionSecret: SESSION_SECRET,
    dataDir: directory,
    securityStateDir: directory,
    now: () => NOW,
    ssoEnabled: false,
    genericLogOwnerUid: OWNER,
  });
}

async function loginCookie(app: ReturnType<typeof createApp>): Promise<string> {
  const response = await request(app)
    .post('/monitor/api/auth/login')
    .send({ password: PASSWORD })
    .expect(200);
  const raw = response.headers['set-cookie'];
  const cookie = Array.isArray(raw) ? raw[0] : raw;
  if (!cookie) throw new Error('login did not issue a cookie');
  return cookie.split(';')[0]!;
}

describe('generic log HTTP API', () => {
  it('requires authentication and maps repeated filter parameters to the strict read model', async () => {
    const directory = fixtureDirectory();
    writeFixture(directory);
    const app = appFor(directory);
    await request(app).get('/monitor/api/generic-logs').expect(401);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/generic-logs?limit=10&sourceId=file%3Aapp&sourceId=journal%3Aworker&severity=error&priority=incident&text=DATABASE')
      .set('Cookie', cookie)
      .expect(200)
      .expect('Cache-Control', 'no-store');
    expect(response.body.collection.status).toBe('fresh');
    expect(response.body.items).toHaveLength(1);
    expect(response.body.items[0]).toMatchObject({
      sourceId: 'file:app', severity: 'error', message: 'database failed',
    });
    expect(response.body.query).toMatchObject({
      limit: 10,
      sourceIds: ['file:app', 'journal:worker'],
      severities: ['error'],
      priorities: ['incident'],
      text: 'database',
    });
  });

  it('rejects unknown, nested, duplicate-single and out-of-range query shapes', async () => {
    const directory = fixtureDirectory();
    writeFixture(directory);
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    for (const query of [
      'unknown=value',
      'sourceId%5Bname%5D=file%3Aapp',
      'cursor=one&cursor=two',
      'limit=201',
      'limit=01',
    ]) {
      const response = await request(app)
        .get(`/monitor/api/generic-logs?${query}`)
        .set('Cookie', cookie)
        .expect(400);
      expect(response.body).toMatchObject({ code: 'INVALID_LOG_QUERY' });
    }
  });

  it('rejects a cursor reused with different query semantics', async () => {
    const directory = fixtureDirectory();
    writeFixture(directory);
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const first = await request(app)
      .get('/monitor/api/generic-logs?limit=1')
      .set('Cookie', cookie)
      .expect(200);
    expect(first.body.page.nextCursor).toBeTypeOf('string');

    const response = await request(app)
      .get(`/monitor/api/generic-logs?limit=1&severity=error&cursor=${encodeURIComponent(first.body.page.nextCursor)}`)
      .set('Cookie', cookie)
      .expect(400);
    expect(response.body).toMatchObject({ code: 'INVALID_LOG_QUERY' });
  });

  it('rate-limits authenticated log reads to the bounded per-IP budget', async () => {
    const directory = fixtureDirectory();
    writeFixture(directory);
    const app = appFor(directory);
    const cookie = await loginCookie(app);

    for (let requestIndex = 0; requestIndex < 25; requestIndex += 1) {
      await request(app).get('/monitor/api/generic-logs?limit=1').expect(401);
    }
    for (let requestIndex = 0; requestIndex < 20; requestIndex += 1) {
      await request(app)
        .get('/monitor/api/generic-logs?limit=1')
        .set('Cookie', cookie)
        .expect(200);
    }
    const rejected = await request(app)
      .get('/monitor/api/generic-logs?limit=1')
      .set('Cookie', cookie)
      .expect(429);
    expect(rejected.body).toMatchObject({ code: 'RATE_LIMITED' });
  });
});
