import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createApp } from './app.js';
import {
  normalizeSystemUpdateStatus,
  readSystemUpdateStatus,
  UpdateNonceStore,
  type SystemUpdateStatus,
  type UpdateGatewayRequest,
} from './system-updates.js';

const NOW = Date.parse('2026-08-19T12:00:00.000Z');
const EDGE_SECRET = 'test-edge-secret-is-at-least-32-bytes-long';
const ORIGIN = 'https://monitor.example.test';
const PLAN_ID = 'a'.repeat(64);

function status(): SystemUpdateStatus {
  return {
    schemaVersion: 1,
    generatedAt: '2026-08-19T12:00:00.000Z',
    state: 'available',
    requestId: 'update-123e4567-e89b-42d3-a456-426614174000',
    action: 'check',
    startedAt: '2026-08-19T11:59:00.000Z',
    completedAt: '2026-08-19T12:00:00.000Z',
    checkedAt: '2026-08-19T12:00:00.000Z',
    planId: PLAN_ID,
    planExpiresAt: '2026-08-19T12:05:00.000Z',
    summary: {
      upgradeCount: 1,
      installCount: 0,
      removeCount: 0,
      keptBackCount: 0,
      packageCount: 1,
      packagesTruncated: false,
    },
    packages: [{
      name: 'apt',
      installedVersion: '2.7.14build2',
      candidateVersion: '2.8.3',
      action: 'upgrade',
      category: 'core-system',
    }],
    rebootRequired: false,
    code: 'UPDATES_AVAILABLE',
  };
}

function directoryWithStatus(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-updates-'));
  mkdirSync(join(directory, 'history'));
  writeFileSync(join(directory, 'system-update.json'), `${JSON.stringify(status())}\n`, { mode: 0o644 });
  return directory;
}

function ssoHeaders(groups: string, subject = 'portfolio-owner'): Record<string, string> {
  return {
    'Remote-User': subject,
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': groups,
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

function mutationHeaders(groups: string): Record<string, string> {
  return {
    ...ssoHeaders(groups),
    Origin: ORIGIN,
    'Sec-Fetch-Site': 'same-origin',
  };
}

describe('system update status contract', () => {
  it('accepts only the bounded exact public status schema', () => {
    expect(normalizeSystemUpdateStatus(status())).toEqual(status());
    expect(normalizeSystemUpdateStatus({ ...status(), state: 'up-to-date', code: 'UPDATES_KEPT_BACK' }))
      .toEqual({ ...status(), state: 'up-to-date', code: 'UPDATES_KEPT_BACK' });
    expect(normalizeSystemUpdateStatus({ ...status(), rawOutput: 'untrusted apt output' })).toBeNull();
    expect(normalizeSystemUpdateStatus({ ...status(), code: 'UNKNOWN_CODE' })).toBeNull();
    expect(normalizeSystemUpdateStatus({
      ...status(),
      summary: { ...status().summary!, packageCount: 2, packagesTruncated: false },
    })).toBeNull();
    expect(normalizeSystemUpdateStatus({
      ...status(),
      packages: [{ ...status().packages[0], name: '../../etc/shadow' }],
    })).toBeNull();
  });

  it('reads a small non-writable regular file and rejects links or writable input', () => {
    const directory = directoryWithStatus();
    expect(readSystemUpdateStatus(directory)).toEqual(status());
    chmodSync(join(directory, 'system-update.json'), 0o666);
    expect(readSystemUpdateStatus(directory)).toBeNull();

    const linkedDirectory = mkdtempSync(join(tmpdir(), 'monitor-updates-link-'));
    symlinkSync(join(directory, 'system-update.json'), join(linkedDirectory, 'system-update.json'));
    expect(readSystemUpdateStatus(linkedDirectory)).toBeNull();
  });

  it('issues subject-and-plan-bound one-use confirmations with a short expiry', () => {
    let clock = NOW;
    const nonces = new UpdateNonceStore(() => clock, 1_000, 4);
    const first = nonces.issue('portfolio-owner', PLAN_ID);
    expect(first.expiresAt).toBe('2026-08-19T12:00:01.000Z');
    expect(nonces.consume(first.nonce, 'portfolio-owner', PLAN_ID)).toBe(true);
    expect(nonces.consume(first.nonce, 'portfolio-owner', PLAN_ID)).toBe(false);

    const mismatched = nonces.issue('portfolio-owner', PLAN_ID);
    expect(nonces.consume(mismatched.nonce, 'another-owner', PLAN_ID)).toBe(false);
    expect(nonces.consume(mismatched.nonce, 'portfolio-owner', PLAN_ID)).toBe(false);

    const expired = nonces.issue('portfolio-owner', PLAN_ID);
    clock += 1_001;
    expect(nonces.consume(expired.nonce, 'portfolio-owner', PLAN_ID)).toBe(false);
  });
});

describe('system update API authorization', () => {
  it('exposes status to authenticated viewers but capabilities follow SSO role', async () => {
    const directory = directoryWithStatus();
    const app = createApp({
      dataDir: directory,
      securityStateDir: directory,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      updateGatewayAvailable: () => true,
    });

    await request(app).get('/monitor/api/system-updates').expect(401);
    const viewer = await request(app)
      .get('/monitor/api/system-updates')
      .set(ssoHeaders('user,portfolio-v2,access-monitor'))
      .expect(200);
    expect(viewer.body.status).toEqual(status());
    expect(viewer.body.capabilities).toEqual({
      gatewayAvailable: true,
      canCheck: false,
      canApply: false,
    });

    const admin = await request(app)
      .get('/monitor/api/system-updates')
      .set(ssoHeaders('user,admin,portfolio-v2,access-monitor'))
      .expect(200);
    expect(admin.body.capabilities).toEqual({
      gatewayAvailable: true,
      canCheck: true,
      canApply: false,
    });

    const chief = await request(app)
      .get('/monitor/api/system-updates')
      .set(ssoHeaders('user,admin,chief-admin,portfolio-v2'))
      .expect(200);
    expect(chief.body.capabilities).toEqual({
      gatewayAvailable: true,
      canCheck: true,
      canApply: true,
    });

    const legacyAdmin = await request(app)
      .get('/monitor/api/system-updates')
      .set(ssoHeaders('user,developer,admin'))
      .expect(200);
    expect(legacyAdmin.body.capabilities).toEqual({
      gatewayAvailable: true,
      canCheck: true,
      canApply: false,
    });

    const unsupportedActor = await request(app)
      .get('/monitor/api/system-updates')
      .set(ssoHeaders('user,admin,portfolio-v2,access-monitor', 'portfolio owner'))
      .expect(200);
    expect(unsupportedActor.body.capabilities).toEqual({
      gatewayAvailable: true,
      canCheck: false,
      canApply: false,
    });
  });

  it('requires exact same-origin JSON and admin role for update checks', async () => {
    const gateway = vi.fn<(request: UpdateGatewayRequest) => Promise<{
      schemaVersion: 1;
      accepted: true;
      requestId: string;
      state: 'queued';
    }>>().mockResolvedValue({
      schemaVersion: 1,
      accepted: true,
      requestId: 'update-123e4567-e89b-42d3-a456-426614174001',
      state: 'queued',
    });
    const directory = directoryWithStatus();
    const app = createApp({
      dataDir: directory,
      securityStateDir: directory,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      updateGatewayAvailable: () => true,
      updateGateway: gateway,
    });

    await request(app)
      .post('/monitor/api/system-updates/check')
      .set(ssoHeaders('user,admin,portfolio-v2,access-monitor'))
      .send({})
      .expect(403, { error: 'Same-origin JSON request required', code: 'ORIGIN_REJECTED' });
    await request(app)
      .post('/monitor/api/system-updates/check')
      .set(mutationHeaders('user,portfolio-v2,access-monitor'))
      .send({})
      .expect(403, { error: 'Admin role required', code: 'ROLE_REQUIRED' });
    await request(app)
      .post('/monitor/api/system-updates/check')
      .set(mutationHeaders('user,admin,portfolio-v2,access-monitor'))
      .send({ unexpected: true })
      .expect(400);
    await request(app)
      .post('/monitor/api/system-updates/check')
      .set(mutationHeaders('user,admin,portfolio-v2,access-monitor'))
      .send({})
      .expect(202);
    expect(gateway).toHaveBeenCalledWith({
      schemaVersion: 1,
      action: 'check',
      actor: 'portfolio-owner',
      planId: null,
    });
  });

  it('binds safe apply to a current plan, chief role, and consumed confirmation', async () => {
    const gateway = vi.fn<(request: UpdateGatewayRequest) => Promise<{
      schemaVersion: 1;
      accepted: true;
      requestId: string;
      state: 'queued';
    }>>().mockResolvedValue({
      schemaVersion: 1,
      accepted: true,
      requestId: 'update-123e4567-e89b-42d3-a456-426614174002',
      state: 'queued',
    });
    const directory = directoryWithStatus();
    const app = createApp({
      dataDir: directory,
      securityStateDir: directory,
      now: () => NOW,
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      updateGatewayAvailable: () => true,
      updateGateway: gateway,
    });
    const chief = mutationHeaders('user,admin,chief-admin,portfolio-v2');

    await request(app)
      .post('/monitor/api/system-updates/prepare')
      .set(mutationHeaders('user,admin,portfolio-v2,access-monitor'))
      .send({ planId: PLAN_ID })
      .expect(403);
    await request(app)
      .post('/monitor/api/system-updates/prepare')
      .set(mutationHeaders('user,developer,admin'))
      .send({ planId: PLAN_ID })
      .expect(403, {
        error: 'Canonical chief admin role required',
        code: 'CANONICAL_ROLE_REQUIRED',
      });
    const prepared = await request(app)
      .post('/monitor/api/system-updates/prepare')
      .set(chief)
      .send({ planId: PLAN_ID })
      .expect(200);
    expect(prepared.body).toMatchObject({ planId: PLAN_ID });
    expect(prepared.body.nonce).toMatch(/^[a-f0-9]{64}$/u);

    await request(app)
      .post('/monitor/api/system-updates/apply')
      .set(chief)
      .send({ planId: PLAN_ID, nonce: prepared.body.nonce })
      .expect(202);
    expect(gateway).toHaveBeenCalledWith({
      schemaVersion: 1,
      action: 'apply-safe',
      actor: 'portfolio-owner',
      planId: PLAN_ID,
    });
    await request(app)
      .post('/monitor/api/system-updates/apply')
      .set(chief)
      .send({ planId: PLAN_ID, nonce: prepared.body.nonce })
      .expect(409, { error: 'Fresh confirmation required', code: 'CONFIRMATION_REQUIRED' });
  });
});
