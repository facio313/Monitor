import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { ApplicationSecurityState } from './application-security-state.js';
import { monitoringCatalogLimits } from './monitoring-catalog.js';

const NOW = Date.parse('2026-09-01T03:05:00.000Z');
const SESSION_SECRET = 'test-session-secret-is-at-least-32-bytes-long';
const EDGE_SECRET = 'test-edge-secret-is-at-least-32-bytes-long';

function catalogDocument(): unknown {
  const script = `
import datetime as dt, json
from pathlib import Path
from monitoring_catalog import build_monitoring_catalog
print(json.dumps(build_monitoring_catalog(
    now=dt.datetime(2026, 9, 1, 3, 4, 5, tzinfo=dt.timezone.utc),
    rule_pack_path=Path("ops/rules/default-rules.v1.json"),
    collection_interval_seconds=60,
    retention_days=30,
    max_log_records=5000,
    incident_retention_days=30,
    max_incident_records=1000,
    generic_log_retention_days=30,
    generic_log_max_records=20000,
    generic_log_max_file_bytes=16777216,
), ensure_ascii=False, separators=(",", ":")))
`;
  return JSON.parse(execFileSync('python3', ['-c', script], {
    cwd: process.cwd(),
    env: { ...process.env, PYTHONPATH: join(process.cwd(), 'ops') },
    encoding: 'utf8',
    maxBuffer: monitoringCatalogLimits.maximumBytes,
  }));
}

function privateDirectory(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(root, 0o700);
  return root;
}

function dataDirectory(withCatalog = true): string {
  const root = privateDirectory('monitor-catalog-api-');
  mkdirSync(join(root, 'history'));
  if (withCatalog) {
    const path = join(root, monitoringCatalogLimits.fileName);
    writeFileSync(path, `${JSON.stringify(catalogDocument())}\n`);
    chmodSync(path, 0o640);
  }
  return root;
}

function localApp(root: string) {
  return createApp({
    password: 'correct horse battery staple',
    authStateFile: join(root, 'auth-state.json'),
    sessionSecret: SESSION_SECRET,
    dataDir: root,
    securityStateDir: root,
    now: () => NOW,
    ssoEnabled: false,
  });
}

async function loginCookie(app: ReturnType<typeof createApp>): Promise<string> {
  const response = await request(app)
    .post('/monitor/api/auth/login')
    .send({ password: 'correct horse battery staple' });
  const raw = response.headers['set-cookie'];
  const cookie = Array.isArray(raw) ? raw[0] : raw;
  if (!cookie) throw new Error('missing login cookie');
  return cookie.split(';')[0]!;
}

function ssoHeaders(groups = 'user,portfolio-v2,access-monitor'): Record<string, string> {
  return {
    'Remote-User': 'portfolio-owner',
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': groups,
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

describe('monitoring catalog API', () => {
  it('requires a local session and returns the normalized catalog', async () => {
    const app = localApp(dataDirectory());
    await request(app).get('/monitor/api/monitoring-catalog').expect(401, {
      error: 'Authentication required', code: 'AUTH_REQUIRED',
    });
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/monitoring-catalog')
      .set('Cookie', cookie)
      .expect('Cache-Control', 'no-store')
      .expect(200);
    expect(response.body).toMatchObject({
      schemaVersion: 1,
      collectionIntervalSeconds: 60,
    });
    expect(response.body.rules).toHaveLength(82);
    expect(JSON.stringify(response.body)).not.toContain('/var/lib/monitor-export');
  });

  it('returns a fixed unavailable error for missing or malformed catalog files', async () => {
    const missingRoot = dataDirectory(false);
    const missingApp = localApp(missingRoot);
    const missingCookie = await loginCookie(missingApp);
    await request(missingApp)
      .get('/monitor/api/monitoring-catalog')
      .set('Cookie', missingCookie)
      .expect(503, {
        error: 'Monitoring catalog is unavailable',
        code: 'MONITORING_CATALOG_UNAVAILABLE',
      });

    const malformedRoot = dataDirectory(false);
    const malformedPath = join(malformedRoot, monitoringCatalogLimits.fileName);
    writeFileSync(malformedPath, '{"schemaVersion":1,"extra":true}\n');
    chmodSync(malformedPath, 0o640);
    const malformedApp = localApp(malformedRoot);
    const malformedCookie = await loginCookie(malformedApp);
    await request(malformedApp)
      .get('/monitor/api/monitoring-catalog')
      .set('Cookie', malformedCookie)
      .expect(503, {
        error: 'Monitoring catalog is unavailable',
        code: 'MONITORING_CATALOG_UNAVAILABLE',
      });
  });

  it('accepts only a trusted SSO identity with Monitor access', async () => {
    const root = dataDirectory();
    const app = createApp({
      dataDir: root,
      securityStateDir: privateDirectory('monitor-catalog-sso-security-'),
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
    });
    await request(app).get('/monitor/api/monitoring-catalog').expect(401);
    await request(app)
      .get('/monitor/api/monitoring-catalog')
      .set(ssoHeaders('user'))
      .expect(401);
    await request(app)
      .get('/monitor/api/monitoring-catalog')
      .set(ssoHeaders())
      .expect(200);
  });

  it('maps bearer access to dashboard:read and rejects a logs-only key', async () => {
    const root = dataDirectory();
    const securityRoot = privateDirectory('monitor-catalog-key-security-');
    const security = new ApplicationSecurityState(securityRoot, { now: () => NOW });
    const app = createApp({
      dataDir: root,
      securityStateDir: securityRoot,
      applicationSecurityState: security,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
    });
    const expiresAt = new Date(NOW + 60 * 60 * 1_000).toISOString();
    const dashboardKey = await security.issueApiKey({
      name: 'Catalog reader', scopes: ['dashboard:read'], expiresAt,
    });
    const logsKey = await security.issueApiKey({
      name: 'Logs reader', scopes: ['logs:read'], expiresAt,
    });
    await request(app)
      .get('/monitor/api/monitoring-catalog')
      .set({
        Authorization: `Bearer ${dashboardKey.token}`,
        'X-Portfolio-Edge-Secret': EDGE_SECRET,
      })
      .expect(200);
    await request(app)
      .get('/monitor/api/monitoring-catalog')
      .set({
        Authorization: `Bearer ${logsKey.token}`,
        'X-Portfolio-Edge-Secret': EDGE_SECRET,
      })
      .expect(403, {
        error: 'API key scope dashboard:read required',
        code: 'API_KEY_SCOPE_REQUIRED',
      });
  });
});
