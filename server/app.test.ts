import {
  chmodSync,
  existsSync,
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
import { parseSsoGroups } from './sso.js';

const NOW = Date.parse('2026-08-19T12:00:00.000Z');
const SECRET = 'test-session-secret-is-at-least-32-bytes-long';
const EDGE_SECRET = 'test-edge-secret-is-at-least-32-bytes-long';

function ssoHeaders(groups = 'user', edgeSecret = EDGE_SECRET): Record<string, string> {
  return {
    'Remote-User': 'portfolio-owner',
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': groups,
    'X-Portfolio-Edge-Secret': edgeSecret,
  };
}

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
    ssoEnabled: false,
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
  it('loads local password and session files ahead of environment values', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-secrets-'));
    const passwordFile = join(directory, 'password');
    const sessionFile = join(directory, 'session');
    writeFileSync(passwordFile, 'password-from-file\n');
    writeFileSync(sessionFile, `${SECRET}\n`);
    for (const path of [passwordFile, sessionFile]) chmodSync(path, 0o600);
    vi.stubEnv('MONITOR_PASSWORD_FILE', passwordFile);
    vi.stubEnv('MONITOR_PASSWORD', 'password-from-environment');
    vi.stubEnv('MONITOR_SESSION_SECRET_FILE', sessionFile);
    vi.stubEnv('MONITOR_SESSION_SECRET', 'environment-session-secret-is-long-enough');
    vi.stubEnv('PORTFOLIO_BRANCH', 'feature/local-monitor');
    vi.stubEnv('PORTFOLIO_AUTH_MODE', 'local');
    try {
      const config = loadConfig();
      expect(config.ssoEnabled).toBe(false);
      if (config.ssoEnabled) throw new Error('expected local configuration');
      expect(config.getBootstrapPassword()).toBe('password-from-file');
      expect(config.sessionSecret).toBe(SECRET);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('loads only the edge credential in SSO mode and ignores all local auth storage', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-sso-secrets-'));
    const edgeFile = join(directory, 'edge');
    const absentState = join(directory, 'auth', 'password.json');
    writeFileSync(edgeFile, `${EDGE_SECRET}\n`);
    chmodSync(edgeFile, 0o600);
    vi.stubEnv('PORTFOLIO_BRANCH', 'main');
    vi.stubEnv('PORTFOLIO_AUTH_MODE', 'sso');
    vi.stubEnv('MONITOR_SSO_ENABLED', 'true');
    vi.stubEnv('MONITOR_EDGE_SECRET_FILE', edgeFile);
    vi.stubEnv('MONITOR_EDGE_SECRET', 'environment-edge-secret-is-long-enough');
    vi.stubEnv('MONITOR_PASSWORD_FILE', join(directory, 'missing-password'));
    vi.stubEnv('MONITOR_SESSION_SECRET_FILE', join(directory, 'missing-session'));
    vi.stubEnv('MONITOR_AUTH_STATE_FILE', absentState);
    try {
      const config = loadConfig();
      expect(config.ssoEnabled).toBe(true);
      expect(config.edgeSecret).toBe(EDGE_SECRET);
      expect('sessionSecret' in config).toBe(false);
      expect('authStateFile' in config).toBe(false);
      expect(existsSync(absentState)).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('fails closed when SSO is enabled without a strong edge secret', () => {
    expect(() => loadConfig({ sessionSecret: SECRET, ssoEnabled: true })).toThrow(
      'Monitor edge secret must contain at least 32 bytes',
    );
    expect(() => loadConfig({ sessionSecret: SECRET, ssoEnabled: true, edgeSecret: 'short' })).toThrow(
      'Monitor edge secret must contain at least 32 bytes',
    );
  });

  it('derives authentication only from a matching branch contract', () => {
    vi.stubEnv('PORTFOLIO_BRANCH', 'feature/local-dashboard');
    vi.stubEnv('PORTFOLIO_AUTH_MODE', 'local');
    try {
      expect(loadConfig({ sessionSecret: SECRET }).ssoEnabled).toBe(false);

      vi.stubEnv('PORTFOLIO_BRANCH', 'dev');
      vi.stubEnv('PORTFOLIO_AUTH_MODE', 'sso');
      expect(loadConfig({ sessionSecret: SECRET, edgeSecret: EDGE_SECRET }).ssoEnabled).toBe(true);

      vi.stubEnv('PORTFOLIO_AUTH_MODE', 'local');
      expect(() => loadConfig({ sessionSecret: SECRET })).toThrow(
        'Portfolio branch dev requires sso authentication',
      );

      vi.stubEnv('PORTFOLIO_AUTH_MODE', 'sso');
      vi.stubEnv('MONITOR_SSO_ENABLED', 'false');
      expect(() => loadConfig({ sessionSecret: SECRET, edgeSecret: EDGE_SECRET })).toThrow(
        'MONITOR_SSO_ENABLED conflicts with PORTFOLIO_AUTH_MODE',
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('rejects broad or symlinked SSO edge secret files', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-edge-secret-'));
    const realFile = join(directory, 'real');
    const linkFile = join(directory, 'link');
    writeFileSync(realFile, `${EDGE_SECRET}\n`);
    chmodSync(realFile, 0o644);
    vi.stubEnv('PORTFOLIO_BRANCH', 'main');
    vi.stubEnv('PORTFOLIO_AUTH_MODE', 'sso');
    vi.stubEnv('MONITOR_SSO_ENABLED', 'true');
    vi.stubEnv('MONITOR_EDGE_SECRET_FILE', realFile);
    try {
      expect(() => loadConfig({ sessionSecret: SECRET })).toThrow(
        'must reference a private small regular file',
      );
      chmodSync(realFile, 0o600);
      symlinkSync(realFile, linkFile);
      vi.stubEnv('MONITOR_EDGE_SECRET_FILE', linkFile);
      expect(() => loadConfig({ sessionSecret: SECRET })).toThrow(
        'must reference a private small regular file',
      );
    } finally {
      vi.unstubAllEnvs();
      unlinkSync(linkFile);
      unlinkSync(realFile);
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

  it('uses trusted proxy identity in SSO mode and disables local credentials', async () => {
    const directory = dataDirectory();
    const absentState = join(directory, 'auth-state.json');
    const app = createApp({
      dataDir: directory,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
    });

    await request(app).get('/monitor/api/auth/session').expect(200, {
      authenticated: false,
      expiresAt: null,
      mode: 'sso',
      user: null,
      groups: [],
      role: null,
      permissions: [],
    });
    await request(app)
      .get('/monitor/api/auth/session')
      .set(ssoHeaders())
      .expect(200, {
        authenticated: true,
        expiresAt: null,
        mode: 'sso',
        user: 'portfolio-owner',
        groups: ['user'],
        role: 'user',
        permissions: [],
      });
    await request(app).post('/monitor/api/auth/login').send({ password: 'unused local password' }).expect(403);
    await request(app)
      .post('/monitor/api/auth/password')
      .set(ssoHeaders())
      .send({ currentPassword: 'old', newPassword: 'new password value' })
      .expect(403);
    await request(app).get('/monitor/api/dashboard?range=1h').expect(401);
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(ssoHeaders())
      .expect(403, { error: 'Developer role required', code: 'ROLE_REQUIRED' });
    await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set(ssoHeaders('user,developer'))
      .expect(200);

    await request(app)
      .get('/monitor/api/auth/session')
      .set(ssoHeaders('user', 'forged-secret-that-is-long-enough-to-look-real'))
      .expect(200, {
        authenticated: false,
        expiresAt: null,
        mode: 'sso',
        user: null,
        groups: [],
        role: null,
        permissions: [],
      });
    expect(existsSync(absentState)).toBe(false);
  });

  it('fails closed on non-canonical SSO groups and gates aggregate auth inventory', async () => {
    const directory = dataDirectory();
    const authStateFile = join(directory, 'legacy-auth-state.json');
    writeFileSync(authStateFile, '{"legacy":"credential-record"}\n', { mode: 0o600 });
    const app = createApp({
      authStateFile,
      dataDir: directory,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
    });

    for (const groups of [
      '',
      'developer',
      'admin',
      'user,admin',
      'developer,user',
      'user,user',
      'user,unknown',
      'user,',
      'user, developer',
    ]) {
      await request(app)
        .get('/monitor/api/dashboard?range=1h')
        .set(ssoHeaders(groups))
        .expect(401);
    }

    await request(app)
      .get('/monitor/api/operations/auth-inventory')
      .set(ssoHeaders())
      .expect(403, { error: 'Developer role required', code: 'ROLE_REQUIRED' });
    const developer = await request(app)
      .get('/monitor/api/operations/auth-inventory')
      .set('Cookie', 'monitor_session=legacy-local-cookie')
      .set(ssoHeaders('user,developer'))
      .expect(200);
    expect(developer.body).toEqual({
      localPasswordRecords: 1,
      unsafeLocalAuthArtifacts: 0,
      legacySessionCookies: 1,
    });
    await request(app)
      .get('/monitor/api/operations/auth-inventory')
      .set(ssoHeaders('user,developer,admin'))
      .expect(200, {
        localPasswordRecords: 1,
        unsafeLocalAuthArtifacts: 0,
        legacySessionCookies: 0,
      });

    const session = await request(app)
      .get('/monitor/api/auth/session')
      .set('Cookie', 'monitor_session=legacy-local-cookie')
      .set(ssoHeaders('user,developer,admin'))
      .expect(200);
    expect(session.body).toMatchObject({
      authenticated: true,
      groups: ['user', 'developer', 'admin'],
      role: 'admin',
      permissions: ['dashboard:read', 'auth-inventory:read'],
    });
    expect(String(session.headers['set-cookie'])).toContain('monitor_session=;');
    expect(existsSync(authStateFile)).toBe(true);
  });

  it('rejects whitespace before HTTP header normalization', () => {
    for (const groups of [' user', 'user ', 'user, developer', 'user,developer ']) {
      expect(parseSsoGroups(groups)).toBeNull();
    }
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
        ssoEnabled: false,
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
        ssoEnabled: false,
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
      ssoEnabled: false,
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
      supplyVoltageVolts: null,
      throttledFlags: null,
      diskReadBytesPerSecond: null,
    });
    expect(response.body.series).toEqual([]);
    expect(response.body.alerts).toEqual([]);
    expect(response.body.powerEvents).toEqual([]);
    expect(response.body.incidents).toEqual([]);
    expect(response.body.powerSummary).toEqual({
      sampleCount: 0,
      voltageSampleCount: 0,
      minSupplyVoltageVolts: null,
      averageSupplyVoltageVolts: null,
      maxSupplyVoltageVolts: null,
      underVoltageSampleCount: 0,
      throttledSampleCount: 0,
    });
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
      containers: [
        {
          name: 'web', owner: 'cks', state: 'running', health: 'healthy',
          cpuPercent: 250, command: 'private command',
        },
        { name: 'foreign-container-secret', owner: 'other', state: 'running', health: 'healthy' },
      ],
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
    expect(serialized).not.toContain('foreign-container-secret');
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
      'supplyVoltageVolts',
      'throttledFlags',
      'gpuMemoryBytes',
      'gpuClockHz',
      'networkRxBytesPerSecond',
      'networkTxBytesPerSecond',
      'diskReadBytesPerSecond',
      'diskWriteBytesPerSecond',
    ]);
    expect(response.body.disks[0].usedPercent).toBe(50);
    expect(response.body.containers).toHaveLength(1);
    expect(response.body.containers[0]).toMatchObject({
      name: 'cks-workload', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 250,
    });
    expect(response.body.alerts[0]).toMatchObject({ kind: null, status: null });
    expect(response.body.privilegeEvents[0].action).toBe('sudo');
    expect(response.body.privilegeEvents[0].result).toBe('success');
  });

  it('strictly reconstructs bounded incident snapshots and drops malformed or out-of-range records', async () => {
    const directory = dataDirectory();
    const validIncident = {
      id: 'incident-20260819T115500Z',
      startedAt: '2026-08-19T11:55:00Z',
      observedAt: '2026-08-19T11:59:00Z',
      endedAt: null,
      phase: 'active',
      reasons: ['cpu', 'disk-io'],
      reasonSecret: 'secret-token',
      metrics: {
        timestamp: '2026-08-19T00:00:00Z',
        cpuPercent: 97.5,
        memoryPercent: 61,
        memoryUsedBytes: 610,
        memoryTotalBytes: 1_000,
        temperatureC: 76.5,
        load1: 4.5,
        load5: 2.5,
        load15: 1.5,
        powerState: 'normal',
        supplyVoltageVolts: 5.04,
        throttledFlags: 0,
        gpuMemoryBytes: 4_194_304,
        gpuClockHz: 910_000_000,
        networkRxBytesPerSecond: 12_345,
        networkTxBytesPerSecond: 6_789,
        diskReadBytesPerSecond: 987_654,
        diskWriteBytesPerSecond: 456_789,
        cpu: { percent: 1 },
        secret: 'raw-metrics-secret',
      },
      pressure: {
        cpu: { someAvg10: 12.5, fullAvg10: null, secret: 'raw-pressure-secret' },
        memory: { someAvg10: 1.5, fullAvg10: 0.25 },
        io: { someAvg10: 8.75, fullAvg10: 3.5 },
      },
      processes: [
        {
          name: 'node', instances: 3, cpuPercent: 70.5, memoryBytes: 500_000_000,
          command: 'raw-process-secret --token abc',
        },
        {
          name: 'api-token-reader', instances: 1, cpuPercent: 10, memoryBytes: 1,
          pid: 1234, argv: ['raw-process-argv-secret'],
        },
        { name: 'task\nrunner♥', instances: 1, cpuPercent: null, memoryBytes: 2 },
      ],
      containers: [
        {
          name: 'web', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 250,
          memoryBytes: 123_456, memoryPercent: 12.5, command: 'raw-container-secret',
        },
        {
          name: 'out-of-scope-container-secret', owner: 'other', state: 'running', health: 'healthy',
          cpuPercent: 50, memoryBytes: 1, memoryPercent: 1,
        },
      ],
      traffic: [
        {
          app: 'monitor', requestCount: 20, status2xx: 17, status3xx: 1, status4xx: 1,
          status5xx: 1, slowCount: 2, avgResponseMs: 25.5, maxResponseMs: 250,
          rawClient: 'raw-traffic-secret',
        },
        {
          app: 'react', requestCount: 1, status2xx: 2, status3xx: 0, status4xx: 0,
          status5xx: 0, slowCount: 0, avgResponseMs: 1, maxResponseMs: 1,
        },
        {
          app: 'out-of-scope-app-secret', requestCount: 1, status2xx: 1, status3xx: 0, status4xx: 0,
          status5xx: 0, slowCount: 0, avgResponseMs: 1, maxResponseMs: 1,
        },
      ],
      peaks: { cpuPercent: 99, memoryPercent: 65, temperatureC: 78, load1: 5.5, secret: 'peak-secret' },
      durationSeconds: null,
      command: 'raw-incident-secret',
    };
    writeFileSync(join(directory, 'incidents.jsonl'), [
      '{malformed',
      JSON.stringify(validIncident),
      JSON.stringify({ ...validIncident, id: 'incident-20260819T115503Z', phase: 'paused' }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T120200Z',
        observedAt: '2026-08-19T12:02:00Z',
      }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T105959Z',
        observedAt: '2026-08-19T10:59:59Z',
      }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T115504Z',
        startedAt: '2026-08-19T11:59:30Z',
      }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T115505Z',
        phase: 'recovered',
      }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T115501Z',
        reasons: ['cpu', 'not-allowed'],
      }),
      JSON.stringify({
        ...validIncident,
        id: 'incident-20260819T115502Z',
        reasons: ['cpu', 'cpu'],
      }),
    ].join('\n'));

    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);

    expect(response.body.incidents).toHaveLength(1);
    expect(response.body.incidents[0]).toEqual({
      id: 'incident-20260819T115500Z',
      startedAt: '2026-08-19T11:55:00.000Z',
      observedAt: '2026-08-19T11:59:00.000Z',
      endedAt: null,
      phase: 'active',
      reasons: ['cpu', 'disk-io'],
      metrics: {
        timestamp: '2026-08-19T11:59:00.000Z',
        cpuPercent: 97.5,
        memoryPercent: 61,
        memoryUsedBytes: 610,
        memoryTotalBytes: 1_000,
        temperatureC: 76.5,
        load1: 4.5,
        load5: 2.5,
        load15: 1.5,
        powerState: 'normal',
        supplyVoltageVolts: 5.04,
        throttledFlags: 0,
        gpuMemoryBytes: 4_194_304,
        gpuClockHz: 910_000_000,
        networkRxBytesPerSecond: 12_345,
        networkTxBytesPerSecond: 6_789,
        diskReadBytesPerSecond: 987_654,
        diskWriteBytesPerSecond: 456_789,
      },
      pressure: {
        cpu: { someAvg10: 12.5, fullAvg10: null },
        memory: { someAvg10: 1.5, fullAvg10: 0.25 },
        io: { someAvg10: 8.75, fullAvg10: 3.5 },
      },
      processes: [
        { name: 'node', instances: 3, cpuPercent: 70.5, memoryBytes: 500_000_000 },
        { name: 'redacted', instances: 1, cpuPercent: 10, memoryBytes: 1 },
        { name: 'other', instances: 1, cpuPercent: null, memoryBytes: 2 },
      ],
      containers: [
        {
          name: 'cks-workload', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 250,
          memoryBytes: 123_456, memoryPercent: 12.5,
        },
      ],
      traffic: [{
        app: 'monitor', requestCount: 20, status2xx: 17, status3xx: 1, status4xx: 1,
        status5xx: 1, slowCount: 2, avgResponseMs: 25.5, maxResponseMs: 250,
      }],
      peaks: { cpuPercent: 99, memoryPercent: 65, temperatureC: 78, load1: 5.5 },
      durationSeconds: null,
    });
    const serialized = JSON.stringify(response.body.incidents);
    for (const secret of [
      'secret-token',
      'raw-metrics-secret',
      'raw-pressure-secret',
      'raw-process-secret',
      'api-token-reader',
      'raw-process-argv-secret',
      'raw-container-secret',
      'out-of-scope-container-secret',
      'secret-owner',
      'secret-state',
      'raw-traffic-secret',
      'out-of-scope-app-secret',
      'peak-secret',
      'raw-incident-secret',
    ]) expect(serialized).not.toContain(secret);
  });

  it('normalizes power telemetry, summarizes the full range, and correlates sanitized power events', async () => {
    const directory = dataDirectory();
    const history = [
      { timestamp: '2026-08-19T11:54:00Z', supplyVoltageVolts: 5.2, throttledFlags: 0 },
      { timestamp: '2026-08-19T11:55:00Z', supplyVoltageVolts: '5.0', throttledFlags: 1.5 },
      { timestamp: '2026-08-19T11:56:00Z', supplyVoltageVolts: -0.1, throttledFlags: -1 },
      { timestamp: '2026-08-19T11:57:30Z', supplyVoltageVolts: 4.7, throttledFlags: 1 },
      { timestamp: '2026-08-19T11:58:00Z', supplyVoltageVolts: 10, throttledFlags: 0xffff_ffff },
    ];
    writeFileSync(
      join(directory, 'history', '2026-08-19.jsonl'),
      history.map((sample) => JSON.stringify(sample)).join('\n'),
    );
    writeFileSync(join(directory, 'current.json'), JSON.stringify({
      latest: {
        timestamp: '2026-08-19T12:00:00Z',
        supplyVoltageVolts: 5.1,
        throttledFlags: 4,
      },
    }));

    const duplicateMessage = 'Supply voltage warning token=abc123';
    writeFileSync(join(directory, 'power.jsonl'), [
      {
        timestamp: '2026-08-19T11:57:20.100Z', severity: 'warning', kind: 'power', status: 'active',
        message: duplicateMessage,
      },
      {
        timestamp: '2026-08-19T11:57:20.900Z', severity: 'warning', kind: 'power', status: 'active',
        message: duplicateMessage,
      },
      {
        timestamp: '2026-08-19T11:51:00Z', severity: 'info', kind: 'nvme', status: 'recovered',
        message: 'NVMe power condition recovered.',
      },
      {
        timestamp: '2026-08-19T12:02:00Z', severity: 'critical', kind: 'power', status: 'active',
        message: 'Future power event must be excluded.',
      },
      {
        timestamp: '2026-08-19T10:59:59Z', severity: 'critical', kind: 'power', status: 'active',
        message: 'Out-of-range power event must be excluded.',
      },
    ].map((event) => JSON.stringify(event)).join('\n'));
    writeFileSync(join(directory, 'alerts.jsonl'), [
      {
        timestamp: '2026-08-19T11:57:20.500Z', severity: 'warning', kind: 'host', status: 'active',
        message: duplicateMessage,
      },
      {
        timestamp: '2026-08-19T11:58:10Z', severity: 'warn', kind: 'HOST', status: 'active',
        message: 'Host condition POWER-THROTTLE is active.',
      },
      {
        timestamp: '2026-08-19T11:58:20Z', severity: 'warn', kind: 'application', status: 'active',
        message: 'Application voltage label changed.',
      },
      {
        timestamp: '2026-08-19T11:54:10Z', severity: 'warn', kind: 'host', status: 'active',
        message: 'A hypervoltagefoo lookalike is not a controlled match.',
      },
    ].map((event) => JSON.stringify(event)).join('\n'));

    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);

    expect(response.body.latest).toMatchObject({
      supplyVoltageVolts: 5.1,
      throttledFlags: 4,
    });
    const invalidSample = response.body.series.find((sample: { timestamp: string }) => (
      sample.timestamp === '2026-08-19T11:55:00.000Z'
    ));
    expect(invalidSample).toMatchObject({ supplyVoltageVolts: null, throttledFlags: null });
    expect(response.body.powerSummary).toEqual({
      sampleCount: 6,
      voltageSampleCount: 4,
      minSupplyVoltageVolts: 4.7,
      averageSupplyVoltageVolts: 6.25,
      maxSupplyVoltageVolts: 10,
      underVoltageSampleCount: 2,
      throttledSampleCount: 2,
    });

    expect(response.body.powerEvents).toHaveLength(3);
    expect(response.body.powerEvents[0]).toEqual({
      timestamp: '2026-08-19T11:58:10.000Z',
      severity: 'warning',
      kind: 'HOST',
      status: 'active',
      message: 'Host condition POWER-THROTTLE is active.',
      supplyVoltageVolts: 10,
      throttledFlags: 0xffff_ffff,
    });
    expect(response.body.powerEvents[1]).toEqual({
      timestamp: '2026-08-19T11:57:20.900Z',
      severity: 'warning',
      kind: 'power',
      status: 'active',
      message: 'Supply voltage warning token=[redacted]',
      supplyVoltageVolts: 4.7,
      throttledFlags: 1,
    });
    expect(response.body.powerEvents[2]).toEqual({
      timestamp: '2026-08-19T11:51:00.000Z',
      severity: 'info',
      kind: 'nvme',
      status: 'recovered',
      message: 'NVMe power condition recovered.',
      supplyVoltageVolts: null,
      throttledFlags: null,
    });
    expect(Object.keys(response.body.powerEvents[0])).toEqual([
      'timestamp',
      'severity',
      'kind',
      'status',
      'message',
      'supplyVoltageVolts',
      'throttledFlags',
    ]);
    expect(JSON.stringify(response.body)).not.toContain('abc123');
  });

  it('merges a same-timestamp current sample into legacy history before power summaries and correlation', async () => {
    const directory = dataDirectory();
    const timestamp = '2026-08-19T11:59:00Z';
    writeFileSync(join(directory, 'history', '2026-08-19.jsonl'), `${JSON.stringify({
      timestamp,
      cpuPercent: 12,
      powerState: 'normal',
    })}\n`);
    writeFileSync(join(directory, 'current.json'), JSON.stringify({
      latest: {
        timestamp,
        powerState: 'under-voltage',
        supplyVoltageVolts: 4.75,
        throttledFlags: 1,
      },
    }));
    writeFileSync(join(directory, 'power.jsonl'), `${JSON.stringify({
      timestamp,
      severity: 'warning',
      kind: 'under-voltage',
      status: 'active',
      message: 'Kernel reported an under-voltage condition.',
    })}\n`);

    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);

    expect(response.body.latest).toMatchObject({
      powerState: 'under-voltage',
      supplyVoltageVolts: 4.75,
      throttledFlags: 1,
    });
    expect(response.body.series).toHaveLength(1);
    expect(response.body.series[0]).toMatchObject({
      cpuPercent: 12,
      powerState: 'under-voltage',
      supplyVoltageVolts: 4.75,
      throttledFlags: 1,
    });
    expect(response.body.powerSummary).toMatchObject({
      sampleCount: 1,
      voltageSampleCount: 1,
      minSupplyVoltageVolts: 4.75,
      averageSupplyVoltageVolts: 4.75,
      maxSupplyVoltageVolts: 4.75,
      underVoltageSampleCount: 1,
    });
    expect(response.body.powerEvents[0]).toMatchObject({
      supplyVoltageVolts: 4.75,
      throttledFlags: 1,
    });
  });

  it('downsamples history while preserving endpoints, voltage extrema, and power transitions', async () => {
    const directory = dataDirectory();
    const samples = Array.from({ length: 1_000 }, (_, index) => ({
      timestamp: new Date(NOW - 3_600_000 + index * 3_000).toISOString(),
      cpu: { percent: index % 101 },
      powerState: index === 400 ? 'under-voltage' : 'normal',
      supplyVoltageVolts: index === 137 ? 4.2 : index === 811 ? 5.8 : 5.1,
      throttledFlags: index === 400 ? 1 : 0,
    }));
    const lines = samples.map((sample) => JSON.stringify(sample)).join('\n');
    writeFileSync(join(directory, 'history', '2026-08-19.jsonl'), lines);
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.series).toHaveLength(360);
    const timestamps = new Set(response.body.series.map((sample: { timestamp: string }) => sample.timestamp));
    for (const index of [0, 137, 400, 401, 811, 999]) {
      expect(timestamps.has(samples[index]!.timestamp)).toBe(true);
    }
    expect(response.body.powerSummary).toEqual({
      sampleCount: 1_000,
      voltageSampleCount: 1_000,
      minSupplyVoltageVolts: 4.2,
      averageSupplyVoltageVolts: 5.1,
      maxSupplyVoltageVolts: 5.8,
      underVoltageSampleCount: 1,
      throttledSampleCount: 0,
    });
  });

  it('caps alerts, power events, privilege details, and incidents at 500 newest records', async () => {
    const directory = dataDirectory();
    const timestamps = Array.from({ length: 600 }, (_, index) => new Date(NOW - index * 1_000).toISOString());
    writeFileSync(join(directory, 'alerts.jsonl'), timestamps.map((timestamp, index) => JSON.stringify({
      timestamp,
      severity: 'info',
      kind: 'application',
      status: 'active',
      message: `Routine alert ${index}`,
    })).join('\n'));
    writeFileSync(join(directory, 'power.jsonl'), timestamps.map((timestamp, index) => JSON.stringify({
      timestamp,
      severity: 'warning',
      kind: 'power',
      status: 'active',
      message: `Power event ${index}`,
    })).join('\n'));
    writeFileSync(join(directory, 'privilege.jsonl'), timestamps.map((timestamp, index) => JSON.stringify({
      timestamp,
      actor: `user-${index}`,
      target: 'root',
      action: 'sudo',
      result: 'success',
    })).join('\n'));
    writeFileSync(join(directory, 'incidents.jsonl'), timestamps.map((observedAt, index) => JSON.stringify({
      id: `incident-${observedAt.replace(/[-:]/g, '').replace('.000', '')}`,
      startedAt: new Date(Date.parse(observedAt) - 60_000).toISOString(),
      observedAt,
      endedAt: null,
      phase: 'active',
      reasons: ['cpu'],
      metrics: {},
      pressure: {
        cpu: { someAvg10: null, fullAvg10: null },
        memory: { someAvg10: null, fullAvg10: null },
        io: { someAvg10: null, fullAvg10: null },
      },
      processes: [],
      containers: [],
      traffic: [],
      peaks: null,
      durationSeconds: null,
    })).join('\n'));

    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.alerts).toHaveLength(500);
    expect(response.body.powerEvents).toHaveLength(500);
    expect(response.body.privilegeEvents).toHaveLength(500);
    expect(response.body.incidents).toHaveLength(500);
    expect(response.body.alerts[0].message).toBe('Routine alert 0');
    expect(response.body.alerts.at(-1).message).toBe('Routine alert 499');
    expect(response.body.powerEvents[0].message).toBe('Power event 0');
    expect(response.body.powerEvents.at(-1).message).toBe('Power event 499');
    expect(response.body.incidents[0].id).toBe('incident-20260819T120000Z');
    expect(response.body.incidents.at(-1).id).toBe('incident-20260819T115141Z');
  });

  it('rejects an oversized incident export without affecting the dashboard', async () => {
    const directory = dataDirectory();
    writeFileSync(join(directory, 'incidents.jsonl'), 'x'.repeat(16 * 1024 * 1024 + 1));
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.incidents).toEqual([]);
  });

  it('does not follow collector symlinks outside the configured data directory', async () => {
    const directory = dataDirectory();
    const outsideDirectory = mkdtempSync(join(tmpdir(), 'monitor-outside-'));
    const outside = join(outsideDirectory, 'current.json');
    writeFileSync(outside, JSON.stringify({ timestamp: '2026-08-19T12:00:00Z', host: { hostname: 'leaked' } }));
    symlinkSync(outside, join(directory, 'current.json'));
    const outsidePower = join(outsideDirectory, 'power.jsonl');
    writeFileSync(outsidePower, `${JSON.stringify({
      timestamp: '2026-08-19T11:59:00Z', severity: 'critical', kind: 'power', status: 'active',
      message: 'token=outside-secret must not leak',
    })}\n`);
    symlinkSync(outsidePower, join(directory, 'power.jsonl'));
    const outsideIncidents = join(outsideDirectory, 'incidents.jsonl');
    writeFileSync(outsideIncidents, `${JSON.stringify({
      id: 'incident-20260819T115800Z',
      startedAt: '2026-08-19T11:58:00Z',
      observedAt: '2026-08-19T11:59:00Z',
      endedAt: null,
      phase: 'active',
      reasons: ['cpu'],
      metrics: {},
      pressure: {
        cpu: { someAvg10: null, fullAvg10: null },
        memory: { someAvg10: null, fullAvg10: null },
        io: { someAvg10: null, fullAvg10: null },
      },
      processes: [],
      containers: [],
      traffic: [],
      peaks: null,
      durationSeconds: null,
      secret: 'outside-incident-secret',
    })}\n`);
    symlinkSync(outsideIncidents, join(directory, 'incidents.jsonl'));
    const app = appFor(directory);
    const cookie = await loginCookie(app);
    const response = await request(app)
      .get('/monitor/api/dashboard?range=1h')
      .set('Cookie', cookie)
      .expect(200);
    expect(response.body.host.hostname).toBeNull();
    expect(response.body.latest.cpuPercent).toBeNull();
    expect(response.body.powerEvents).toEqual([]);
    expect(response.body.incidents).toEqual([]);
    expect(JSON.stringify(response.body)).not.toContain('outside-secret');
    expect(JSON.stringify(response.body)).not.toContain('outside-incident-secret');
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
      ssoEnabled: false,
    });
    const index = await request(app).get('/monitor/').expect(200);
    expect(index.text).toContain('<title>Monitor</title>');
    expect(index.headers['cache-control']).toBe('no-store');
    expect(index.headers['content-security-policy']).toContain("default-src 'self'");
    const details = await request(app).get('/monitor/details').expect(200);
    expect(details.text).toContain('<title>Monitor</title>');
    expect(details.headers['cache-control']).toBe('no-store');
    const asset = await request(app).get('/monitor/assets/app-ABC12345.js').expect(200);
    expect(asset.headers['cache-control']).toContain('immutable');
    await request(app).get('/monitor/api/not-a-route').expect(404).expect('Content-Type', /json/);
  });
});
