import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from './app.js';
import { loadConfig } from './config.js';

const NOW = Date.parse('2026-08-19T12:00:00.000Z');
const SECRET = 'test-session-secret-is-at-least-32-bytes-long';

function dataDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-test-'));
  mkdirSync(join(directory, 'history'));
  return directory;
}

function appFor(directory: string) {
  return createApp({
    password: 'correct horse battery staple',
    sessionSecret: SECRET,
    dataDir: directory,
    now: () => NOW,
  });
}

async function loginCookie(app: ReturnType<typeof createApp>): Promise<string> {
  const response = await request(app)
    .post('/monitor/api/auth/login')
    .send({ password: 'correct horse battery staple' });
  const header = response.headers['set-cookie'];
  const cookie = Array.isArray(header) ? header[0] : header;
  if (!cookie) throw new Error('login did not issue a cookie');
  return cookie.split(';')[0]!;
}

describe('authentication', () => {
  it('loads password and session secret files ahead of environment values', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-secrets-'));
    const passwordFile = join(directory, 'password');
    const sessionFile = join(directory, 'session');
    writeFileSync(passwordFile, 'password-from-file\n');
    writeFileSync(sessionFile, `${SECRET}\n`);
    vi.stubEnv('MONITOR_PASSWORD_FILE', passwordFile);
    vi.stubEnv('MONITOR_PASSWORD', 'password-from-environment');
    vi.stubEnv('MONITOR_SESSION_SECRET_FILE', sessionFile);
    vi.stubEnv('MONITOR_SESSION_SECRET', 'environment-session-secret-is-long-enough');
    try {
      const config = loadConfig();
      expect(config.password).toBe('password-from-file');
      expect(config.sessionSecret).toBe(SECRET);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('keeps health public and dashboard protected', async () => {
    const directory = dataDirectory();
    const app = appFor(directory);
    await request(app).get('/healthz').expect(200, { status: 'ok' });
    await request(app).get('/readyz').expect(503, { status: 'not_ready' });
    writeFileSync(join(directory, 'current.json'), JSON.stringify({
      latest: { timestamp: '2026-08-19T12:00:00Z', cpuPercent: 1 },
    }));
    await request(app).get('/readyz').expect(200, { status: 'ready' });
    await request(app).get('/monitor/api/dashboard?range=1h').expect(401);
  });

  it('rejects bad credentials and issues a hardened session cookie', async () => {
    const app = appFor(dataDirectory());
    await request(app).post('/monitor/api/auth/login').send({ password: 'wrong' }).expect(401);
    const response = await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(200);
    const cookie = String(response.headers['set-cookie']);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).toContain('Path=/monitor');
    expect(response.body.authenticated).toBe(true);
  });

  it('rejects tampered sessions and rate-limits repeated failed logins', async () => {
    const app = appFor(dataDirectory());
    const cookie = await loginCookie(app);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', `${cookie}tampered`)
      .expect(401);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(app).post('/monitor/api/auth/login').send({ password: 'wrong' }).expect(401);
    }
    const limited = await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'wrong' })
      .expect(429);
    expect(limited.body).toEqual({ error: 'Too many login attempts', code: 'RATE_LIMITED' });
  });

  it('rejects cross-site mutations and clears a session', async () => {
    const app = appFor(dataDirectory());
    await request(app)
      .post('/monitor/api/auth/login')
      .set('Origin', 'https://attacker.invalid')
      .set('Host', 'monitor.example')
      .send({ password: 'correct horse battery staple' })
      .expect(403);
    const cookie = await loginCookie(app);
    await request(app).get('/monitor/api/auth/session').set('Cookie', cookie).expect(200, {
      authenticated: true,
      expiresAt: '2026-08-19T13:00:00.000Z',
    });
    const deleted = await request(app).delete('/monitor/api/auth/session').set('Cookie', cookie).expect(204);
    expect(String(deleted.headers['set-cookie'])).toContain('Path=/monitor');
  });
});

describe('dashboard ingestion', () => {
  it('handles missing and malformed collector data gracefully', async () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'current.json'), '{invalid');
    writeFileSync(join(directory, 'alerts.jsonl'), 'not-json\n');
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.stale).toBe(true);
    expect(response.body.latest).toMatchObject({
      timestamp: '2026-08-19T12:00:00.000Z',
      cpuPercent: null,
      temperatureC: null,
      diskReadBytesPerSecond: null,
    });
    expect(response.body.series).toEqual([]);
    expect(response.body.alerts).toEqual([]);
  });

  it('whitelists fields, redacts secrets, and never returns raw privilege commands', async () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'current.json'), JSON.stringify({
      secret: 'do-not-return',
      host: { hostname: 'host\u0000name', os: 'Linux', architecture: 'arm64', password: 'hidden' },
      latest: {
        timestamp: '2026-08-19T11:59:00Z',
        cpu: { percent: 20 },
        memoryUsedBytes: 50,
        memoryTotalBytes: 100,
        memoryPercent: 50,
        temperatureC: 42,
        diskReadBytesPerSecond: 12,
      },
      disks: [{ mount: '/', usedBytes: 1, totalBytes: 2, command: 'df -h' }],
      containers: [{ name: 'web', owner: 'svc', state: 'running', health: 'healthy', command: 'private command' }],
    }));
    writeFileSync(join(directory, 'alerts.jsonl'), `${JSON.stringify({
      timestamp: '2026-08-19T11:58:00Z', severity: 'warn', message: 'token=abc123 is exposed', command: 'raw',
    })}\n`);
    writeFileSync(join(directory, 'privilege.jsonl'), `${JSON.stringify({
      timestamp: '2026-08-19T11:57:00Z', user: 'alice', targetUser: 'root', action: 'sudo command',
      outcome: 'success', command: 'sudo cat /etc/shadow', argv: ['secret'],
    })}\n`);
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    const serialized = JSON.stringify(response.body);
    expect(serialized).not.toContain('do-not-return');
    expect(serialized).not.toContain('private command');
    expect(serialized).not.toContain('/etc/shadow');
    expect(serialized).not.toContain('abc123');
    expect(response.body.host.hostname).toBe('host name');
    expect(response.body.host).toEqual({ hostname: 'host name', os: 'Linux', architecture: 'arm64', uptimeSeconds: null });
    expect(response.body.latest).toMatchObject({ temperatureC: 42, diskReadBytesPerSecond: 12 });
    expect(Object.keys(response.body.latest)).toEqual([
      'timestamp',
      'cpuPercent',
      'memoryPercent',
      'memoryUsedBytes',
      'memoryTotalBytes',
      'temperatureC',
      'load1',
      'load5',
      'load15',
      'powerState',
      'gpuMemoryBytes',
      'gpuClockHz',
      'networkRxBytesPerSecond',
      'networkTxBytesPerSecond',
      'diskReadBytesPerSecond',
      'diskWriteBytesPerSecond',
    ]);
    expect(response.body.disks[0].usedPercent).toBe(50);
    expect(response.body.containers[0]).toMatchObject({ owner: 'svc', state: 'running', health: 'healthy' });
    expect(response.body.alerts[0]).toMatchObject({ kind: null, status: null });
    expect(response.body.privilegeEvents[0].action).toBe('sudo');
    expect(response.body.privilegeEvents[0].result).toBe('success');
  });

  it('downsamples history to at most 360 points', async () => {
    const directory = dataDirectory();
    const lines = Array.from({ length: 1_000 }, (_, index) => JSON.stringify({
      timestamp: new Date(NOW - 3_600_000 + index * 3_000).toISOString(),
      cpu: { percent: index % 101 },
    })).join('\n');
    writeFileSync(join(directory, 'history', '2026-08-19.jsonl'), lines);
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.series).toHaveLength(360);
  });

  it('does not follow collector symlinks outside the configured data directory', async () => {
    const directory = dataDirectory();
    const outside = join(mkdtempSync(join(tmpdir(), 'monitor-outside-')), 'current.json');
    writeFileSync(outside, JSON.stringify({ timestamp: '2026-08-19T12:00:00Z', host: { hostname: 'leaked' } }));
    symlinkSync(outside, join(directory, 'current.json'));
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.host.hostname).toBeNull();
    expect(response.body.latest.cpuPercent).toBeNull();
  });

  it('serves the built SPA with no-store caching while APIs remain JSON 404s', async () => {
    const directory = dataDirectory();
    const publicDirectory = mkdtempSync(join(tmpdir(), 'monitor-public-'));
    mkdirSync(join(publicDirectory, 'assets'));
    writeFileSync(join(publicDirectory, 'index.html'), '<!doctype html><title>Monitor</title>');
    writeFileSync(join(publicDirectory, 'assets', 'app-ABC12345.js'), 'void 0;');
    const app = createApp({
      password: 'correct horse battery staple',
      sessionSecret: SECRET,
      dataDir: directory,
      publicDir: publicDirectory,
      now: () => NOW,
    });
    const index = await request(app).get('/monitor/').expect(200);
    expect(index.text).toContain('<title>Monitor</title>');
    expect(index.headers['cache-control']).toBe('no-store');
    expect(index.headers['content-security-policy']).toContain("default-src 'self'");
    const asset = await request(app).get('/monitor/assets/app-ABC12345.js').expect(200);
    expect(asset.headers['cache-control']).toContain('immutable');
    await request(app).get('/monitor/api/not-a-route').expect(404).expect('Content-Type', /json/);
  });
});
