import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import {
  createApp,
  MAX_API_KEY_READ_REQUESTS_PER_MINUTE,
  MAX_FAILED_BEARER_ATTEMPTS_PER_15_MINUTES,
} from './app.js';
import { ApplicationSecurityState } from './application-security-state.js';
import { loadConfig } from './config.js';

const NOW = Date.parse('2026-08-31T03:00:00.000Z');
const EDGE_SECRET = 'test-edge-secret-is-at-least-32-bytes-long';
const SESSION_SECRET = 'test-session-secret-is-at-least-32-bytes-long';
const ORIGIN = 'https://monitor.example.test';

function privateDirectory(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(directory, 0o700);
  return directory;
}

function dataDirectory(): string {
  const directory = privateDirectory('monitor-security-app-data-');
  mkdirSync(join(directory, 'history'));
  return directory;
}

function ssoHeaders(
  groups = 'user,admin,chief-admin,portfolio-v2',
): Record<string, string> {
  return {
    'Remote-User': 'portfolio-owner',
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': groups,
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

function readHeaders(groups?: string): Record<string, string> {
  return {
    ...ssoHeaders(groups),
    Origin: ORIGIN,
    'Sec-Fetch-Site': 'same-origin',
  };
}

function mutationHeaders(groups?: string): Record<string, string> {
  return readHeaders(groups);
}

function apiKeyHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

function ssoApplication() {
  const directory = dataDirectory();
  const securityDirectory = privateDirectory('monitor-security-app-state-');
  const security = new ApplicationSecurityState(securityDirectory, { now: () => NOW });
  const app = createApp({
    dataDir: directory,
    securityStateDir: securityDirectory,
    applicationSecurityState: security,
    now: () => NOW,
    securityRequestId: (() => {
      let value = 0;
      return () => `security-request-${String(value += 1).padStart(8, '0')}`;
    })(),
    ssoEnabled: true,
    edgeSecret: EDGE_SECRET,
    allowedOrigins: [ORIGIN],
  });
  return { app, security, securityDirectory };
}

describe('application security configuration', () => {
  it('uses the private named-volume path by default and rejects non-normalized roots', () => {
    const previous = process.env.MONITOR_SECURITY_STATE_DIR;
    delete process.env.MONITOR_SECURITY_STATE_DIR;
    try {
      expect(loadConfig({ ssoEnabled: true, edgeSecret: EDGE_SECRET }).securityStateDir)
        .toBe('/var/lib/monitor-security');
      expect(loadConfig({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        securityStateDir: '/srv/monitor/security',
      }).securityStateDir).toBe('/srv/monitor/security');
      expect(() => loadConfig({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        securityStateDir: 'relative/security',
      })).toThrow(/normalized absolute non-root/u);
      expect(() => loadConfig({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        securityStateDir: '/',
      })).toThrow(/normalized absolute non-root/u);
    } finally {
      if (previous === undefined) delete process.env.MONITOR_SECURITY_STATE_DIR;
      else process.env.MONITOR_SECURITY_STATE_DIR = previous;
    }
  });
});

describe('API-key HTTP integration', () => {
  it('restricts lifecycle management and enforces the exact bearer route scope', async () => {
    const { app, security, securityDirectory } = ssoApplication();
    const expiry = new Date(NOW + 60 * 60 * 1_000).toISOString();

    await request(app)
      .post('/monitor/api/security/api-keys')
      .set(ssoHeaders())
      .send({ name: 'Missing origin', scopes: ['dashboard:read'], expiresAt: expiry })
      .expect(403, { error: 'Same-origin JSON request required', code: 'ORIGIN_REJECTED' });
    await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders('user,developer,admin'))
      .send({ name: 'Legacy chief', scopes: ['dashboard:read'], expiresAt: expiry })
      .expect(403, { error: 'Canonical chief admin role required', code: 'CANONICAL_ROLE_REQUIRED' });

    const issued = await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Dashboard automation',
        scopes: ['dashboard:read'],
        expiresAt: expiry,
      })
      .expect(201);
    expect(issued.body.token).toMatch(/^mon_[A-Za-z0-9_-]{43}$/u);
    expect(issued.body).not.toHaveProperty('digest');

    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Authorization', `Bearer ${issued.body.token}`)
      .expect(403, {
        error: 'API key requests require the trusted edge proxy',
        code: 'API_KEY_PROXY_REQUIRED',
      });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set({
        Authorization: `Bearer ${issued.body.token}`,
        'X-Portfolio-Edge-Secret': `${EDGE_SECRET}-wrong`,
      })
      .expect(403, {
        error: 'API key requests require the trusted edge proxy',
        code: 'API_KEY_PROXY_REQUIRED',
      });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .expect(200);
    await request(app)
      .get('/monitor/api/generic-logs')
      .set(apiKeyHeaders(issued.body.token))
      .expect(403, {
        error: 'API key scope logs:read required',
        code: 'API_KEY_SCOPE_REQUIRED',
      });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set({ ...ssoHeaders(), Authorization: 'Bearer mon_not-valid' })
      .expect(401, { error: 'API key authentication failed', code: 'INVALID_API_KEY' });
    await request(app)
      .get('/monitor/api/auth/session')
      .set(apiKeyHeaders(issued.body.token))
      .expect(403, { error: 'API keys are not accepted on this route', code: 'API_KEY_NOT_ALLOWED' });

    const listed = await request(app)
      .get('/monitor/api/security/api-keys')
      .set(readHeaders())
      .expect(200);
    expect(listed.body.keys).toHaveLength(1);
    expect(listed.body.keys[0]).not.toHaveProperty('token');
    expect(listed.body.keys[0]).not.toHaveProperty('digest');

    const rotated = await request(app)
      .post(`/monitor/api/security/api-keys/${issued.body.id}/rotate`)
      .set(mutationHeaders())
      .send({ expiresAt: expiry })
      .expect(201);
    expect(rotated.body.token).toMatch(/^mon_[A-Za-z0-9_-]{43}$/u);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .expect(401);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(rotated.body.token))
      .expect(200);

    await request(app)
      .post(`/monitor/api/security/api-keys/${rotated.body.id}/revoke`)
      .set(mutationHeaders())
      .send({})
      .expect(200);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(rotated.body.token))
      .expect(401);

    const audit = await request(app)
      .get('/monitor/api/security/audit?limit=2')
      .set(readHeaders())
      .expect(200);
    expect(audit.body.schemaVersion).toBe(1);
    expect(audit.body.records).toHaveLength(2);
    expect(audit.body.records[0]).toMatchObject({
      action: 'api-key.revoke',
      outcome: 'success',
      target: `/monitor/api/security/api-keys/${rotated.body.id}/revoke`,
    });
    await request(app)
      .get('/monitor/api/security/audit?limit=101')
      .set(readHeaders())
      .expect(400, { error: 'Audit query is invalid', code: 'INVALID_AUDIT_QUERY' });

    const lifecycle = await security.readAuditRecords();
    expect(lifecycle).toContainEqual(expect.objectContaining({
      action: 'api-key.issue',
      outcome: 'success',
      target: `/monitor/api/security/api-keys/${issued.body.id}`,
    }));
    expect(lifecycle).toContainEqual(expect.objectContaining({
      action: 'api-key.rotate',
      outcome: 'success',
      target: `/monitor/api/security/api-keys/${issued.body.id}/rotate/${rotated.body.id}`,
    }));

    const serializedState = readdirSync(securityDirectory)
      .map((name) => readFileSync(join(securityDirectory, name), 'utf8'))
      .join('\n');
    expect(serializedState).not.toContain(issued.body.token);
    expect(serializedState).not.toContain(rotated.body.token);
    expect(await security.listApiKeys()).toHaveLength(2);
  });

  it('fails privileged mutation before its side effect when intent auditing fails', async () => {
    const { app, security } = ssoApplication();
    vi.spyOn(security, 'audit').mockRejectedValue(new Error('simulated audit failure'));
    await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Must not issue',
        scopes: ['dashboard:read'],
        expiresAt: new Date(NOW + ONE_HOUR).toISOString(),
      })
      .expect(503, {
        error: 'Security audit storage is unavailable',
        code: 'SECURITY_AUDIT_UNAVAILABLE',
      });
    expect(await security.listApiKeys()).toEqual([]);
  });

  it('enforces canonical source-IP restrictions from the trusted proxy address', async () => {
    const { app } = ssoApplication();
    const expiry = new Date(NOW + ONE_HOUR).toISOString();
    const issued = await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Restricted dashboard',
        scopes: ['dashboard:read'],
        expiresAt: expiry,
        sourceIpAllowlist: ['2001:0db8:0:0:0:0:0:1', '203.0.113.7'],
      })
      .expect(201);
    expect(issued.body.sourceIpAllowlist).toEqual(['2001:db8::1', '203.0.113.7']);

    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Authorization', `Bearer ${issued.body.token}`)
      .set('X-Forwarded-For', '203.0.113.7')
      .expect(403, {
        error: 'API key requests require the trusted edge proxy',
        code: 'API_KEY_PROXY_REQUIRED',
      });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .set('X-Forwarded-For', '203.0.113.7')
      .expect(200);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .set('X-Forwarded-For', '198.51.100.8')
      .expect(401, { error: 'API key authentication failed', code: 'INVALID_API_KEY' });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .set('X-Forwarded-For', '198.51.100.8, 203.0.113.7')
      .expect(200);

    await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Invalid restriction',
        scopes: ['dashboard:read'],
        expiresAt: expiry,
        sourceIpAllowlist: ['not-an-address'],
      })
      .expect(400, { error: 'API key request is invalid', code: 'INVALID_REQUEST' });
  });

  it('bounds API-key reads per opaque key identifier', async () => {
    const { app } = ssoApplication();
    const issued = await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Bounded dashboard reader',
        scopes: ['dashboard:read'],
        expiresAt: new Date(NOW + ONE_HOUR).toISOString(),
      })
      .expect(201);

    for (let index = 0; index < MAX_API_KEY_READ_REQUESTS_PER_MINUTE; index += 1) {
      await request(app)
        .get('/monitor/api/dashboard?range=1h')
        .set(apiKeyHeaders(issued.body.token))
        .expect(200);
    }
    const limited = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(issued.body.token))
      .expect(429, { error: 'API key read rate exceeded', code: 'RATE_LIMITED' });
    expect(limited.headers['cache-control']).toBe('no-store');
    expect(JSON.stringify(limited.headers)).not.toContain(issued.body.token);
  });

  it('bounds invalid bearer attempts without charging authenticated downstream failures', async () => {
    const { app } = ssoApplication();
    const valid = await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Authenticated failure control',
        scopes: ['system-updates:check'],
        expiresAt: new Date(NOW + ONE_HOUR).toISOString(),
      })
      .expect(201);
    // The principal map is cleared by a finish listener before the limiter's
    // finish-promise callback runs. A separate weak authentication marker must
    // therefore keep each verified request out of the failure counter even
    // though the downstream gateway returns 503.
    for (let index = 0; index < 3; index += 1) {
      await request(app)
        .post('/monitor/api/system-updates/check')
        .set(apiKeyHeaders(valid.body.token))
        .set('X-Forwarded-For', '198.51.100.41')
        .send({})
        .expect(503, { error: 'Update service unavailable', code: 'UPDATE_UNAVAILABLE' });
    }
    const invalidToken = `mon_${'A'.repeat(43)}`;
    for (let index = 0; index < MAX_FAILED_BEARER_ATTEMPTS_PER_15_MINUTES; index += 1) {
      await request(app)
        .get('/monitor/api/dashboard?range=1h')
        .set(apiKeyHeaders(invalidToken))
        .set('X-Forwarded-For', '198.51.100.41')
        .expect(401, { error: 'API key authentication failed', code: 'INVALID_API_KEY' });
    }
    const limited = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(invalidToken))
      .set('X-Forwarded-For', '198.51.100.41')
      .expect(429, {
        error: 'Too many failed bearer authentication attempts',
        code: 'RATE_LIMITED',
      });
    expect(limited.headers['retry-after']).toBeTruthy();
    expect(limited.headers['cache-control']).toBe('no-store');
    expect(JSON.stringify(limited.headers)).not.toContain(invalidToken);

    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(apiKeyHeaders(invalidToken))
      .set('X-Forwarded-For', '198.51.100.42')
      .expect(401);
  });

  it('does not apply ambient-cookie CSRF checks to an authenticated scoped bearer mutation', async () => {
    const { app } = ssoApplication();
    const issued = await request(app)
      .post('/monitor/api/security/api-keys')
      .set(mutationHeaders())
      .send({
        name: 'Update checker',
        scopes: ['system-updates:check'],
        expiresAt: new Date(NOW + ONE_HOUR).toISOString(),
      })
      .expect(201);

    await request(app)
      .post('/monitor/api/system-updates/check')
      .set(apiKeyHeaders(issued.body.token))
      .set('Origin', 'https://cross-site.example.test')
      .set('Sec-Fetch-Site', 'cross-site')
      .send({})
      .expect(503, { error: 'Update service unavailable', code: 'UPDATE_UNAVAILABLE' });
  });
});

const ONE_HOUR = 60 * 60 * 1_000;

describe('local authentication audit integration', () => {
  it('records intent and outcome without persisting passwords', async () => {
    const data = dataDirectory();
    const securityDirectory = privateDirectory('monitor-local-security-state-');
    const security = new ApplicationSecurityState(securityDirectory, { now: () => NOW });
    const app = createApp({
      password: 'correct horse battery staple',
      authStateFile: join(data, 'password-state.json'),
      sessionSecret: SESSION_SECRET,
      dataDir: data,
      securityStateDir: securityDirectory,
      applicationSecurityState: security,
      now: () => NOW,
      securityRequestId: (() => {
        let value = 0;
        return () => `local-request-${String(value += 1).padStart(8, '0')}`;
      })(),
      ssoEnabled: false,
    });

    await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'definitely wrong password' })
      .expect(401, { error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
    const login = await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(200);
    const cookieHeader = login.headers['set-cookie'];
    const cookie = (Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader)?.split(';')[0];
    expect(cookie).toBeTruthy();
    await request(app)
      .delete('/monitor/api/auth/session')
      .set('Cookie', cookie!)
      .expect(204);

    const records = await security.readAuditRecords();
    expect(records.map(({ action, outcome }) => `${action}:${outcome}`)).toEqual([
      'auth.login:intent',
      'auth.login:denied',
      'auth.login:intent',
      'auth.login:success',
      'auth.logout:intent',
      'auth.logout:success',
    ]);
    const serialized = readdirSync(securityDirectory)
      .map((name) => readFileSync(join(securityDirectory, name), 'utf8'))
      .join('\n');
    expect(serialized).not.toContain('correct horse battery staple');
    expect(serialized).not.toContain('definitely wrong password');
  });

  it('uses the same invalid-credentials response when login audit persistence fails', async () => {
    const data = dataDirectory();
    const securityDirectory = privateDirectory('monitor-login-audit-failure-');
    const security = new ApplicationSecurityState(securityDirectory, { now: () => NOW });
    vi.spyOn(security, 'audit').mockRejectedValue(new Error('simulated audit failure'));
    const app = createApp({
      password: 'correct horse battery staple',
      authStateFile: join(data, 'password-state.json'),
      sessionSecret: SESSION_SECRET,
      dataDir: data,
      securityStateDir: securityDirectory,
      applicationSecurityState: security,
      now: () => NOW,
      ssoEnabled: false,
    });

    const wrong = await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'definitely wrong password' })
      .expect(401);
    const correct = await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(401);
    expect(correct.body).toEqual(wrong.body);
    expect(correct.headers['set-cookie']).toBeUndefined();
  });
});
