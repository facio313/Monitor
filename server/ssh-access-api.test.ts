import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { ApplicationSecurityState } from './application-security-state.js';

const NOW = Date.parse('2026-09-13T12:00:00Z');
const EDGE_SECRET = 'ssh-access-fixture-edge-secret-at-least-32-bytes';
const roots: string[] = [];
function fixture(ssoEnabled = false) {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-ssh-access-api-'));
  roots.push(directory);
  mkdirSync(join(directory, 'ssh-access'), { mode: 0o750 });
  const records = ['accepted', 'auth_failed'].map((eventType, index) => ({ schemaVersion: 1, id: String(index + 1).repeat(64), observedAt: `2026-09-13T11:59:5${index}.123456Z`,
    sourceId: 'journal:ssh', sourceIp: '203.0.113.10', sourcePort: 51234, eventType, authMethod: 'publickey', countryCode: 'KR', countryStatus: 'estimated', databaseDate: '2026-09-01' }));
  writeFileSync(join(directory, 'ssh-access', '2026-09-13.jsonl'), records.map(record => JSON.stringify(record)).join('\n') + '\n', { mode: 0o640 });
  const security = new ApplicationSecurityState(directory, { now: () => NOW });
  const app = createApp({ password: 'correct horse battery staple', authStateFile: join(directory, 'auth-state.json'), sessionSecret: 'ssh-access-test-secret-at-least-32-bytes',
    dataDir: directory, securityStateDir: directory, applicationSecurityState: security, ssoEnabled, edgeSecret: EDGE_SECRET, now: () => NOW });
  return { directory, app, security };
}
afterEach(() => roots.splice(0).forEach(root => rmSync(root, { recursive: true, force: true })));

describe('SSH access authenticated API', () => {
  it('requires authentication even for invalid queries and never exposes IPs anonymously', async () => {
    const { app } = fixture();
    const response = await request(app).get('/monitor/api/ssh-access?range=bad').expect(401);
    expect(JSON.stringify(response.body)).not.toContain('203.0.113.10');
  });
  it('returns authorized paged evidence and maps invalid query shapes to 400', async () => {
    const { app } = fixture();
    const login = await request(app).post('/monitor/api/auth/login').send({ password: 'correct horse battery staple' }).expect(200);
    const cookie = login.headers['set-cookie'];
    const response = await request(app).get('/monitor/api/ssh-access?range=6h&limit=1&page=1').set('Cookie', cookie).expect('Cache-Control', 'no-store').expect(200);
    expect(response.body).toMatchObject({ total: 2, status: 'unavailable', page: 1 });
    expect(response.body.records[0]).toMatchObject({ sourceIp: '203.0.113.10', eventType: 'auth_failed' });
    expect((await request(app).get('/monitor/api/ssh-access?event=accepted').set('Cookie', cookie).expect(200)).body.total).toBe(1);
    for (const query of ['limit=101', 'page=0', 'ip=hostname.invalid', 'range=1h&range=24h', 'path=/etc/passwd']) {
      const invalid = await request(app).get(`/monitor/api/ssh-access?${query}`).set('Cookie', cookie).expect(400);
      expect(invalid.body.code).toBe('INVALID_SSH_ACCESS_QUERY');
    }
  });
  it('enforces logs:read independently of dashboard bearer permission', async () => {
    const { app, security } = fixture(true);
    const expiresAt = new Date(NOW + 3_600_000).toISOString();
    const dashboard = await security.issueApiKey({ name: 'Dashboard only', scopes: ['dashboard:read'], expiresAt });
    const logs = await security.issueApiKey({ name: 'Logs reader', scopes: ['logs:read'], expiresAt });
    const denied = await request(app).get('/monitor/api/ssh-access').set({ Authorization: `Bearer ${dashboard.token}`, 'X-Portfolio-Edge-Secret': EDGE_SECRET }).expect(403);
    expect(denied.body.code).toBe('API_KEY_SCOPE_REQUIRED');
    const response = await request(app).get('/monitor/api/ssh-access').set({ Authorization: `Bearer ${logs.token}`, 'X-Portfolio-Edge-Secret': EDGE_SECRET }).expect(200);
    expect(response.body.records).toHaveLength(2);
  });
});
