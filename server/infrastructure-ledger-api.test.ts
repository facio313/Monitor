import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';

const NOW = Date.parse('2026-08-30T03:00:00Z');
const SESSION_SECRET = 'test-session-secret-is-at-least-32-bytes-long';
const EDGE_SECRET = 'test-edge-secret-is-at-least-32-bytes-long';

function ledgerDocument() {
  return {
    schemaVersion: 1,
    updatedAt: '2026-08-30T02:00:00Z',
    coverage: {
      from: null,
      through: '2026-08-30T02:00:00Z',
      sources: [{ id: 'audit', label: { ko: '감사', en: 'Audit' }, from: null, through: '2026-08-30T02:00:00Z' }],
      limitations: [{ ko: '한계', en: 'Limitation' }],
    },
    references: [],
    entries: [{
      id: 'event.alpha.1', itemKey: 'item.alpha', revision: 1,
      occurredAt: '2026-08-30T01:00:00Z', recordedAt: '2026-08-30T02:00:00Z',
      category: 'security', workType: 'audit', status: 'pending', priority: 'high',
      confidence: 'current-state', verification: 'verified', applicability: 'applicable', impact: 'none', sensitivity: 'internal', csfFunctions: ['identify'],
      title: { ko: '점검', en: 'Audit' }, summary: { ko: '요약', en: 'Summary' },
      rationale: { ko: '이유', en: 'Rationale' }, details: { ko: '상세', en: 'Details' },
      outcome: { ko: '결과', en: 'Outcome' }, nextAction: { ko: '후속', en: 'Follow-up' },
      actor: 'codex', scope: ['host'], evidence: [], referenceIds: [], relatedIds: [],
      supersedes: null, dueAt: null, recurrence: null,
    }],
  };
}

function dataDirectory(withLedger = true): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-ledger-api-'));
  mkdirSync(join(directory, 'history'));
  if (withLedger) {
    const path = join(directory, 'infrastructure-ledger.json');
    writeFileSync(path, JSON.stringify(ledgerDocument()));
    chmodSync(path, 0o640);
  }
  return directory;
}

function localApp(directory: string) {
  return createApp({
    password: 'correct horse battery staple',
    authStateFile: join(directory, 'auth-state.json'),
    sessionSecret: SESSION_SECRET,
    dataDir: directory,
    now: () => NOW,
    ssoEnabled: false,
  });
}

async function loginCookie(app: ReturnType<typeof createApp>): Promise<string> {
  const response = await request(app).post('/monitor/api/auth/login').send({ password: 'correct horse battery staple' });
  const raw = response.headers['set-cookie'];
  const cookie = Array.isArray(raw) ? raw[0] : raw;
  if (!cookie) throw new Error('missing login cookie');
  return cookie.split(';')[0]!;
}

function ssoHeaders(groups: string): Record<string, string> {
  return {
    'Remote-User': 'portfolio-owner',
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': groups,
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

describe('infrastructure ledger API', () => {
  it('requires a local session and returns only the public snapshot', async () => {
    const app = localApp(dataDirectory());
    await request(app).get('/monitor/api/infrastructure-ledger').expect(401);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/infrastructure-ledger')
      .set('Cookie', cookie)
      .expect('Cache-Control', 'no-store')
      .expect(200);
    expect(response.body).toMatchObject({ schemaVersion: 1, generatedAt: '2026-08-30T03:00:00.000Z' });
    expect(response.body.entries).toHaveLength(1);
    expect(JSON.stringify(response.body)).not.toContain('correct horse battery staple');
  });

  it('distinguishes an unavailable ledger from a valid empty ledger', async () => {
    const directory = dataDirectory(false);
    const app = localApp(directory);
    const cookie = await loginCookie(app);
    await request(app)
      .get('/monitor/api/infrastructure-ledger')
      .set('Cookie', cookie)
      .expect(503, { error: 'Infrastructure ledger is unavailable', code: 'LEDGER_UNAVAILABLE' });

    const path = join(directory, 'infrastructure-ledger.json');
    writeFileSync(path, JSON.stringify({ ...ledgerDocument(), entries: [] }));
    chmodSync(path, 0o640);
    const response = await request(app).get('/monitor/api/infrastructure-ledger').set('Cookie', cookie).expect(200);
    expect(response.body.entries).toEqual([]);
  });

  it('restricts SSO access to admin and chief-admin roles', async () => {
    const app = createApp({ dataDir: dataDirectory(), now: () => NOW, ssoEnabled: true, edgeSecret: EDGE_SECRET });
    await request(app).get('/monitor/api/infrastructure-ledger').expect(401);
    await request(app)
      .get('/monitor/api/infrastructure-ledger')
      .set(ssoHeaders('user,portfolio-v2,access-monitor'))
      .expect(403, { error: 'Admin role required', code: 'ROLE_REQUIRED' });
    await request(app)
      .get('/monitor/api/infrastructure-ledger')
      .set(ssoHeaders('user,admin,portfolio-v2,access-monitor'))
      .expect(200);
    await request(app)
      .get('/monitor/api/infrastructure-ledger')
      .set(ssoHeaders('user,admin,chief-admin,portfolio-v2'))
      .expect(200);
  });
});
