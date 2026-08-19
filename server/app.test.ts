import {
  chmodSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { PasswordStore, PasswordStoreBusyError } from './password-store.js';

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
    authStateFile: join(directory, 'auth-state.json'),
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
      expect(config.getBootstrapPassword()).toBe('password-from-file');
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

  it('changes the password without persisting plaintext and revokes every session', async () => {
    const directory = dataDirectory();
    const app = appFor(directory);
    const firstCookie = await loginCookie(app);
    const secondCookie = await loginCookie(app);
    const nextPassword = 'a newer correct horse battery staple';

    const changed = await request(app)
      .post('/monitor/api/auth/password')
      .set('Cookie', firstCookie)
      .send({
        currentPassword: 'correct horse battery staple',
        newPassword: nextPassword,
      })
      .expect(204);
    expect(String(changed.headers['set-cookie'])).toContain('Path=/monitor');

    await request(app).get('/monitor/api/auth/session').set('Cookie', firstCookie).expect(200, {
      authenticated: false,
      expiresAt: null,
    });
    await request(app).get('/monitor/api/auth/session').set('Cookie', secondCookie).expect(200, {
      authenticated: false,
      expiresAt: null,
    });
    await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(401);
    await request(app)
      .post('/monitor/api/auth/login')
      .send({ password: nextPassword })
      .expect(200);

    const statePath = join(directory, 'auth-state.json');
    const serialized = readFileSync(statePath, 'utf8');
    expect(serialized).not.toContain('correct horse battery staple');
    expect(serialized).not.toContain(nextPassword);
    expect(JSON.parse(serialized)).toMatchObject({
      version: 1,
      password: { algorithm: 'scrypt', n: 65_536, r: 8, p: 1, keyLength: 32 },
    });
    expect(statSync(statePath).mode & 0o077).toBe(0);
  });

  it('keeps the changed password and session revocation across restarts', async () => {
    const directory = dataDirectory();
    const initialApp = appFor(directory);
    const oldCookie = await loginCookie(initialApp);
    const nextPassword = 'persistent monitor password';
    await request(initialApp)
      .post('/monitor/api/auth/password')
      .set('Cookie', oldCookie)
      .send({
        currentPassword: 'correct horse battery staple',
        newPassword: nextPassword,
      })
      .expect(204);

    const restartedApp = appFor(directory);
    await request(restartedApp).get('/monitor/api/auth/session').set('Cookie', oldCookie).expect(200, {
      authenticated: false,
      expiresAt: null,
    });
    await request(restartedApp)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(401);
    await request(restartedApp)
      .post('/monitor/api/auth/login')
      .send({ password: nextPassword })
      .expect(200);
  });

  it('starts from valid state without reading or requiring a bootstrap password', async () => {
    const directory = dataDirectory();
    appFor(directory);
    const missingBootstrapFile = join(directory, 'does-not-exist');
    vi.stubEnv('MONITOR_PASSWORD_FILE', missingBootstrapFile);
    vi.stubEnv('MONITOR_PASSWORD', '');
    try {
      const restartedApp = createApp({
        authStateFile: join(directory, 'auth-state.json'),
        sessionSecret: SECRET,
        dataDir: directory,
        now: () => NOW,
      });
      await request(restartedApp)
        .post('/monitor/api/auth/login')
        .send({ password: 'correct horse battery staple' })
        .expect(200);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('fails closed when state and a bootstrap password are both absent', () => {
    const directory = dataDirectory();
    vi.stubEnv('MONITOR_PASSWORD_FILE', '');
    vi.stubEnv('MONITOR_PASSWORD', '');
    try {
      expect(() => createApp({
        authStateFile: join(directory, 'auth-state.json'),
        sessionSecret: SECRET,
        dataDir: directory,
        now: () => NOW,
      })).toThrow(/bootstrap password is not configured/);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('does not fall back to bootstrap credentials when existing state is malformed', () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'auth-state.json'), '{}', { mode: 0o600 });
    expect(() => appFor(directory)).toThrow(/invalid or unsupported/);
  });

  it('uses explicit state removal as bootstrap recovery with a fresh session epoch', async () => {
    const directory = dataDirectory();
    const initialApp = appFor(directory);
    const oldCookie = await loginCookie(initialApp);
    await request(initialApp)
      .post('/monitor/api/auth/password')
      .set('Cookie', oldCookie)
      .send({
        currentPassword: 'correct horse battery staple',
        newPassword: 'password that will be recovered away',
      })
      .expect(204);

    unlinkSync(join(directory, 'auth-state.json'));
    const recoveredApp = appFor(directory);
    await request(recoveredApp).get('/monitor/api/auth/session').set('Cookie', oldCookie).expect(200, {
      authenticated: false,
      expiresAt: null,
    });
    await request(recoveredApp)
      .post('/monitor/api/auth/login')
      .send({ password: 'correct horse battery staple' })
      .expect(200);
    await request(recoveredApp)
      .post('/monitor/api/auth/login')
      .send({ password: 'password that will be recovered away' })
      .expect(401);
  });

  it('generalizes password-policy and current-password failures', async () => {
    const app = appFor(dataDirectory());
    const cookie = await loginCookie(app);
    const attempts = [
      { currentPassword: 'wrong password value', newPassword: 'a sufficiently long new password' },
      { currentPassword: 'correct horse battery staple', newPassword: 'short' },
      { currentPassword: 'correct horse battery staple', newPassword: 'correct horse battery staple' },
      { currentPassword: 'correct horse battery staple', newPassword: '한'.repeat(86) },
    ];
    for (const body of attempts) {
      const response = await request(app)
        .post('/monitor/api/auth/password')
        .set('Cookie', cookie)
        .send(body)
        .expect(400);
      expect(response.body).toEqual({
        error: 'Password change rejected',
        code: 'PASSWORD_CHANGE_REJECTED',
      });
    }
  });

  it('serializes concurrent changes so only one current password can win', async () => {
    const app = appFor(dataDirectory());
    const cookie = await loginCookie(app);
    const candidates = ['first concurrent password', 'second concurrent password'];
    const responses = await Promise.all(candidates.map((newPassword) => request(app)
      .post('/monitor/api/auth/password')
      .set('Cookie', cookie)
      .send({ currentPassword: 'correct horse battery staple', newPassword })));
    expect(responses.map((response) => response.status).sort()).toEqual([204, 400]);

    const logins = await Promise.all(candidates.map((password) => request(app)
      .post('/monitor/api/auth/login')
      .send({ password })));
    expect(logins.map((response) => response.status).sort()).toEqual([200, 401]);
  });

  it('rejects a queued password change after its authorizing session epoch is revoked', async () => {
    const app = appFor(dataDirectory());
    const cookie = await loginCookie(app);
    const firstPassword = 'first password in a chained change';
    const secondPassword = 'second password in a chained change';
    const [first, staleSecond] = await Promise.all([
      request(app)
        .post('/monitor/api/auth/password')
        .set('Cookie', cookie)
        .send({
          currentPassword: 'correct horse battery staple',
          newPassword: firstPassword,
        }),
      request(app)
        .post('/monitor/api/auth/password')
        .set('Cookie', cookie)
        .send({
          currentPassword: firstPassword,
          newPassword: secondPassword,
        }),
    ]);
    expect(first.status).toBe(204);
    expect(staleSecond.status).toBe(400);
    await request(app).post('/monitor/api/auth/login').send({ password: firstPassword }).expect(200);
    await request(app).post('/monitor/api/auth/login').send({ password: secondPassword }).expect(401);
  });

  it('bounds queued scrypt work across clients', async () => {
    const directory = dataDirectory();
    const store = new PasswordStore(
      join(directory, 'auth-state.json'),
      () => 'correct horse battery staple',
    );
    const attempts = await Promise.allSettled(
      Array.from({ length: 12 }, () => store.authenticate('a rejected password attempt')),
    );
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(8);
    const rejected = attempts.filter((attempt) => attempt.status === 'rejected');
    expect(rejected).toHaveLength(4);
    expect(rejected.every((attempt) => attempt.reason instanceof PasswordStoreBusyError)).toBe(true);
  });

  it('keeps disk and memory committed when directory durability sync fails after rename', async () => {
    const directory = dataDirectory();
    const statePath = join(directory, 'auth-state.json');
    const initialStore = new PasswordStore(
      statePath,
      () => 'correct horse battery staple',
    );
    const warning = vi.fn(() => {
      throw new Error('warning sink failed');
    });
    const store = new PasswordStore(
      statePath,
      () => {
        throw new Error('bootstrap must stay lazy');
      },
      {
        syncDirectory: () => {
          throw new Error('injected directory fsync failure');
        },
        onDurabilityWarning: warning,
      },
    );
    const previousEpoch = initialStore.sessionEpoch;
    const nextPassword = 'password committed before fsync warning';

    await expect(store.changePassword(
      'correct horse battery staple',
      nextPassword,
      previousEpoch,
    )).resolves.toBe('changed');
    expect(warning).toHaveBeenCalledOnce();
    expect(store.sessionEpoch).not.toBe(previousEpoch);
    await expect(store.authenticate('correct horse battery staple')).resolves.toBeNull();
    await expect(store.authenticate(nextPassword)).resolves.toBe(store.sessionEpoch);

    const restartedStore = new PasswordStore(statePath, () => {
      throw new Error('persisted state must not read bootstrap');
    });
    await expect(restartedStore.authenticate(nextPassword)).resolves.toBe(restartedStore.sessionEpoch);
  });

  it('requires a same-origin authenticated session and rate-limits rejected changes', async () => {
    const app = appFor(dataDirectory());
    const body = {
      currentPassword: 'wrong password value',
      newPassword: 'a sufficiently long new password',
    };
    await request(app).post('/monitor/api/auth/password').send(body).expect(401);
    const cookie = await loginCookie(app);
    await request(app)
      .post('/monitor/api/auth/password')
      .set('Cookie', cookie)
      .set('Origin', 'https://attacker.invalid')
      .set('Host', 'monitor.example')
      .send(body)
      .expect(403);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(app)
        .post('/monitor/api/auth/password')
        .set('Cookie', cookie)
        .send(body)
        .expect(400);
    }
    await request(app)
      .post('/monitor/api/auth/password')
      .set('Cookie', cookie)
      .send(body)
      .expect(429, { error: 'Too many password change attempts', code: 'RATE_LIMITED' });
  });

  it('refuses symlinked, oversized, or overexposed authentication state paths', () => {
    const symlinkDirectory = dataDirectory();
    const outside = join(mkdtempSync(join(tmpdir(), 'monitor-auth-outside-')), 'state.json');
    writeFileSync(outside, '{}', { mode: 0o600 });
    symlinkSync(outside, join(symlinkDirectory, 'auth-state.json'));
    expect(() => appFor(symlinkDirectory)).toThrow(/regular file/);

    const oversizedDirectory = dataDirectory();
    const oversized = join(oversizedDirectory, 'auth-state.json');
    writeFileSync(oversized, 'x'.repeat(4_097), { mode: 0o600 });
    expect(() => appFor(oversizedDirectory)).toThrow(/small/);

    const exposedDirectory = dataDirectory();
    const exposed = join(exposedDirectory, 'auth-state.json');
    writeFileSync(exposed, '{}', { mode: 0o644 });
    chmodSync(exposed, 0o644);
    expect(() => appFor(exposedDirectory)).toThrow(/permissions/);

    const exposedParent = dataDirectory();
    chmodSync(exposedParent, 0o750);
    expect(() => appFor(exposedParent)).toThrow(/0700/);

    const inaccessibleParent = dataDirectory();
    chmodSync(inaccessibleParent, 0o600);
    expect(() => appFor(inaccessibleParent)).toThrow(/0700/);

    const linkedParentRoot = mkdtempSync(join(tmpdir(), 'monitor-auth-parent-link-'));
    const realParent = dataDirectory();
    const linkedParent = join(linkedParentRoot, 'linked');
    symlinkSync(realParent, linkedParent);
    expect(() => createApp({
      password: 'correct horse battery staple',
      authStateFile: join(linkedParent, 'auth-state.json'),
      sessionSecret: SECRET,
      dataDir: realParent,
      now: () => NOW,
    })).toThrow(/real directory/);
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
      authStateFile: join(directory, 'auth-state.json'),
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
