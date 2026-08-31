import { createHash } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  chownSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ApplicationSecurityState,
  applicationSecurityStateLimits,
  parseApplicationAuditRecord,
  type ApplicationAuditInput,
  type ApplicationSecurityStateOptions,
} from './application-security-state.js';

const NOW = Date.parse('2026-08-31T03:00:00.000Z');
const ONE_HOUR = 60 * 60 * 1_000;

function secureDirectory(prefix = 'monitor-security-state-'): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(directory, 0o700);
  return directory;
}

function deterministicRandom(): (size: number) => Buffer {
  let call = 0;
  return (size) => {
    call += 1;
    return Buffer.alloc(size, call & 0xff);
  };
}

function options(
  clock: { now: number },
  overrides: Partial<ApplicationSecurityStateOptions> = {},
): ApplicationSecurityStateOptions {
  return {
    now: () => clock.now,
    randomBytes: deterministicRandom(),
    onDurabilityWarning: () => undefined,
    ...overrides,
  };
}

function expiresAt(clock: { now: number }, offset = ONE_HOUR): string {
  return new Date(clock.now + offset).toISOString();
}

function auditInput(index = 0, overrides: Partial<ApplicationAuditInput> = {}): ApplicationAuditInput {
  return {
    requestId: `request-${String(index).padStart(8, '0')}`,
    actor: { subject: 'portfolio-owner', role: 'chief-admin' },
    action: 'system-update.check',
    target: '/monitor/api/system-updates/check',
    outcome: 'success',
    sourceIp: '203.0.113.7',
    ...overrides,
  };
}

function stateFile(directory: string): string {
  return join(directory, applicationSecurityStateLimits.apiKeyFileName);
}

function auditFile(directory: string): string {
  return join(directory, applicationSecurityStateLimits.auditFileName);
}

describe('application security state filesystem boundary', () => {
  it('requires a normalized real 0700 directory owned by the configured uid', () => {
    const broad = secureDirectory();
    chmodSync(broad, 0o750);
    expect(() => new ApplicationSecurityState(broad)).toThrow(/0700/u);

    const parent = secureDirectory();
    const real = join(parent, 'real');
    mkdirSync(real, { mode: 0o700 });
    const linked = join(parent, 'linked');
    symlinkSync(real, linked);
    expect(() => new ApplicationSecurityState(linked)).toThrow(/real directory|symlinks/u);

    const foreign = secureDirectory();
    const actualUid = lstatSync(foreign).uid;
    expect(() => new ApplicationSecurityState(foreign, { ownerUid: actualUid + 1 }))
      .toThrow(/foreign owner/u);
  });

  it('rejects state and audit symlinks, hardlinks, foreign owners, or broad modes', async () => {
    const hardlinked = secureDirectory();
    new ApplicationSecurityState(hardlinked);
    linkSync(stateFile(hardlinked), join(hardlinked, 'second-link'));
    expect(() => new ApplicationSecurityState(hardlinked)).toThrow(/unlinked regular file/u);

    const broadState = secureDirectory();
    new ApplicationSecurityState(broadState);
    chmodSync(stateFile(broadState), 0o640);
    expect(() => new ApplicationSecurityState(broadState)).toThrow(/0600/u);

    const symlinkState = secureDirectory();
    new ApplicationSecurityState(symlinkState);
    const movedState = join(symlinkState, 'moved-state');
    renameSync(stateFile(symlinkState), movedState);
    symlinkSync(movedState, stateFile(symlinkState));
    expect(() => new ApplicationSecurityState(symlinkState)).toThrow(/unlinked regular file/u);

    const clock = { now: NOW };
    const linkedAudit = secureDirectory();
    const first = new ApplicationSecurityState(linkedAudit, options(clock));
    await first.audit(auditInput());
    linkSync(auditFile(linkedAudit), join(linkedAudit, 'audit-link'));
    expect(() => new ApplicationSecurityState(linkedAudit, options(clock)))
      .toThrow(/unlinked regular file/u);

    const foreignState = secureDirectory();
    new ApplicationSecurityState(foreignState);
    const actualUid = lstatSync(foreignState).uid;
    expect(() => new ApplicationSecurityState(foreignState, { ownerUid: actualUid + 1 }))
      .toThrow(/foreign owner/u);

    if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
      const foreignFile = secureDirectory();
      new ApplicationSecurityState(foreignFile);
      const stateStat = lstatSync(stateFile(foreignFile));
      chownSync(stateFile(foreignFile), stateStat.uid + 1, stateStat.gid);
      expect(() => new ApplicationSecurityState(foreignFile)).toThrow(/foreign owner/u);
    }
  });

  it('fails closed on extra, malformed, or non-canonical persisted fields', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    await security.issueApiKey({
      name: 'Automation',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const parsed = JSON.parse(readFileSync(stateFile(directory), 'utf8')) as Record<string, unknown>;
    writeFileSync(stateFile(directory), `${JSON.stringify({ ...parsed, plaintext: 'forbidden' })}\n`, {
      mode: 0o600,
    });
    expect(() => new ApplicationSecurityState(directory, options(clock))).toThrow(/invalid schema/u);

    const auditDirectory = secureDirectory();
    new ApplicationSecurityState(auditDirectory, options(clock));
    writeFileSync(auditFile(auditDirectory), `${JSON.stringify({ schemaVersion: 1, message: 'free form' })}\n`, {
      mode: 0o600,
    });
    expect(() => new ApplicationSecurityState(auditDirectory, options(clock)))
      .toThrow(/invalid record/u);
  });

  it('fails closed when state creation or mutation cannot fsync the parent directory', async () => {
    const clock = { now: NOW };
    const creationDirectory = secureDirectory();
    expect(() => new ApplicationSecurityState(creationDirectory, options(clock, {
      syncDirectory: () => { throw new Error('simulated directory fsync failure'); },
    }))).toThrow(/directory sync failed/u);

    const mutationDirectory = secureDirectory();
    const original = new ApplicationSecurityState(mutationDirectory, options(clock));
    const issued = await original.issueApiKey({
      name: 'Must remain revoked',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const failing = new ApplicationSecurityState(mutationDirectory, options(clock, {
      syncDirectory: () => { throw new Error('simulated directory fsync failure'); },
    }));
    await expect(failing.revokeApiKey(issued.id)).rejects.toThrow(/directory sync failed/u);
    expect(await failing.authenticateApiKey(issued.token, ['dashboard:read'], '203.0.113.7'))
      .toBeNull();
    const restarted = new ApplicationSecurityState(mutationDirectory, options(clock));
    expect(await restarted.authenticateApiKey(issued.token, ['dashboard:read'], '203.0.113.7'))
      .toBeNull();
  });

  it('fails audit creation and rotation when their directory entry cannot be synced', async () => {
    const clock = { now: NOW };
    const creationDirectory = secureDirectory();
    new ApplicationSecurityState(creationDirectory, options(clock));
    const creationFailure = new ApplicationSecurityState(creationDirectory, options(clock, {
      syncDirectory: () => { throw new Error('simulated directory fsync failure'); },
    }));
    await expect(creationFailure.audit(auditInput()))
      .rejects.toThrow(/audit file directory sync failed/u);

    const rotationDirectory = secureDirectory();
    const original = new ApplicationSecurityState(rotationDirectory, options(clock, {
      auditMaxBytes: 512,
      auditRetentionFiles: 2,
    }));
    await original.audit(auditInput());
    const rotationFailure = new ApplicationSecurityState(rotationDirectory, options(clock, {
      auditMaxBytes: 512,
      auditRetentionFiles: 2,
      syncDirectory: () => { throw new Error('simulated directory fsync failure'); },
    }));
    await expect(rotationFailure.audit(auditInput(1)))
      .rejects.toThrow(/audit rotation directory sync failed/u);
  });

  it('retries an unproven audit-file directory entry before acknowledging a later append', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    new ApplicationSecurityState(directory, options(clock));
    let syncAttempts = 0;
    const security = new ApplicationSecurityState(directory, options(clock, {
      syncDirectory: () => {
        syncAttempts += 1;
        if (syncAttempts === 1) throw new Error('simulated first directory fsync failure');
      },
    }));

    await expect(security.audit(auditInput()))
      .rejects.toThrow(/audit file directory sync failed/u);
    await expect(security.audit(auditInput(1))).resolves.toMatchObject({ schemaVersion: 1 });
    expect(syncAttempts).toBe(2);
  });
});

describe('application API key registry', () => {
  it('issues a 256-bit token once and persists only exact normalized metadata plus its digest', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    const issued = await security.issueApiKey({
      name: '  Seoul   Collector  ',
      scopes: ['system-updates:check', 'dashboard:read'],
      expiresAt: expiresAt(clock),
    });

    expect(issued.token).toMatch(/^mon_[A-Za-z0-9_-]{43}$/u);
    expect(Buffer.from(issued.token.slice(4), 'base64url')).toHaveLength(32);
    expect(issued).toMatchObject({
      name: 'Seoul Collector',
      scopes: ['dashboard:read', 'system-updates:check'],
      createdAt: '2026-08-31T03:00:00.000Z',
      expiresAt: '2026-08-31T04:00:00.000Z',
      lastUsedAt: null,
      revokedAt: null,
    });

    const serialized = readFileSync(stateFile(directory), 'utf8');
    expect(serialized).not.toContain(issued.token);
    expect(serialized).not.toContain(issued.token.slice(4));
    const persisted = JSON.parse(serialized) as {
      schemaVersion: number;
      keys: Array<Record<string, unknown>>;
    };
    expect(Object.keys(persisted).sort()).toEqual(['keys', 'schemaVersion']);
    expect(persisted.schemaVersion).toBe(2);
    expect(Object.keys(persisted.keys[0]!).sort()).toEqual([
      'createdAt',
      'digest',
      'expiresAt',
      'id',
      'lastUsedAt',
      'name',
      'revokedAt',
      'scopes',
      'sourceIpAllowlist',
    ]);
    const expectedDigest = createHash('sha256')
      .update(Buffer.from('monitor.application-security.api-key.v1\0', 'utf8'))
      .update(issued.token, 'utf8')
      .digest('hex');
    expect(persisted.keys[0]!.digest).toBe(`sha256:${expectedDigest}`);
    expect(persisted.keys[0]!.sourceIpAllowlist).toEqual([]);
    expect(lstatSync(stateFile(directory)).mode & 0o777).toBe(0o600);
  });

  it('normalizes and enforces a bounded exact source-IP allowlist without leaking mismatch details', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    const issued = await security.issueApiKey({
      name: 'IP restricted',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
      sourceIpAllowlist: ['203.0.113.7', '2001:0db8:0:0:0:0:0:1'],
    });

    expect(issued.sourceIpAllowlist).toEqual(['2001:db8::1', '203.0.113.7']);
    expect(await security.authenticateApiKey(
      issued.token,
      ['dashboard:read'],
      '203.0.113.7',
    )).toMatchObject({
      principal: { id: issued.id },
      requiredScopesSatisfied: true,
    });
    expect(await security.authenticateApiKey(
      issued.token,
      ['dashboard:read'],
      '198.51.100.8',
    )).toBeNull();
    expect(await security.authenticateApiKey(
      issued.token,
      ['dashboard:read'],
      null,
    )).toBeNull();
    expect(await security.authenticateApiKey(
      issued.token,
      ['dashboard:read'],
      '2001:db8::1',
    )).toMatchObject({ principal: { id: issued.id } });
    expect(await security.authenticateApiKey(
      issued.token,
      ['dashboard:read'],
      '::ffff:203.0.113.7',
    )).toMatchObject({ principal: { id: issued.id } });

    await expect(security.issueApiKey({
      name: 'Duplicate normalized IP',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
      sourceIpAllowlist: ['2001:db8::1', '2001:0db8:0:0:0:0:0:1'],
    })).rejects.toThrow(/source IP allowlist/u);
    await expect(security.issueApiKey({
      name: 'Duplicate mapped IPv4',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
      sourceIpAllowlist: ['203.0.113.7', '::ffff:203.0.113.7'],
    })).rejects.toThrow(/source IP allowlist/u);
    await expect(security.issueApiKey({
      name: 'Oversized IP list',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
      sourceIpAllowlist: Array.from(
        { length: applicationSecurityStateLimits.maximumSourceIpAllowlistEntries + 1 },
        (_, index) => `192.0.2.${index + 1}`,
      ),
    })).rejects.toThrow(/source IP allowlist/u);

    clock.now += 1_000;
    const rotated = await security.rotateApiKey({ id: issued.id, expiresAt: expiresAt(clock) });
    expect(rotated.sourceIpAllowlist).toEqual(['2001:db8::1', '203.0.113.7']);
    expect(await security.authenticateApiKey(
      rotated.token,
      ['dashboard:read'],
      '198.51.100.8',
    )).toBeNull();
    expect(await security.authenticateApiKey(
      rotated.token,
      ['dashboard:read'],
      '203.0.113.7',
    )).toMatchObject({ principal: { id: rotated.id } });
  });

  it('migrates schema-v1 keys to an explicit unrestricted source-IP allowlist', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const original = new ApplicationSecurityState(directory, options(clock));
    const issued = await original.issueApiKey({
      name: 'Legacy automation',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const legacy = JSON.parse(readFileSync(stateFile(directory), 'utf8')) as {
      schemaVersion: number;
      keys: Array<Record<string, unknown>>;
    };
    legacy.schemaVersion = 1;
    for (const key of legacy.keys) delete key.sourceIpAllowlist;
    writeFileSync(stateFile(directory), `${JSON.stringify(legacy)}\n`, { mode: 0o600 });

    const migrated = new ApplicationSecurityState(directory, options(clock));
    const persisted = JSON.parse(readFileSync(stateFile(directory), 'utf8')) as {
      schemaVersion: number;
      keys: Array<{ sourceIpAllowlist: string[] }>;
    };
    expect(persisted.schemaVersion).toBe(2);
    expect(persisted.keys[0]?.sourceIpAllowlist).toEqual([]);
    expect(await migrated.authenticateApiKey(issued.token, ['dashboard:read'], '198.51.100.8'))
      .toMatchObject({ principal: { id: issued.id } });
  });

  it('authenticates without early key selection, enforces scopes, and durably records last use', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    await security.issueApiKey({
      name: 'First key',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const second = await security.issueApiKey({
      name: 'Second key',
      scopes: ['dashboard:read', 'logs:read'],
      expiresAt: expiresAt(clock),
    });

    expect(await security.authenticateApiKey('mon_not-a-real-key')).toBeNull();
    expect(await security.authenticateApiKey(second.token, ['agents:write'])).toMatchObject({
      principal: { id: second.id },
      requiredScopesSatisfied: false,
    });
    clock.now += 1_000;
    expect(await security.authenticateApiKey(second.token, ['logs:read'])).toEqual({
      principal: {
        id: second.id,
        name: 'Second key',
        scopes: ['dashboard:read', 'logs:read'],
      },
      requiredScopesSatisfied: true,
    });
    const persisted = JSON.parse(readFileSync(stateFile(directory), 'utf8')) as {
      keys: Array<{ id: string; lastUsedAt: string | null }>;
    };
    expect(persisted.keys.find(({ id }) => id === second.id)?.lastUsedAt)
      .toBe('2026-08-31T03:00:01.000Z');
    expect(readFileSync(stateFile(directory), 'utf8')).not.toContain(second.token);
  });

  it('checks scope before mutation and coalesces durable last-use writes', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    let directorySyncs = 0;
    const security = new ApplicationSecurityState(directory, options(clock, {
      syncDirectory: () => { directorySyncs += 1; },
    }));
    const issued = await security.issueApiKey({
      name: 'Coalesced use',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const afterIssue = directorySyncs;

    expect(await security.authenticateApiKey(issued.token, ['logs:read'], '203.0.113.7'))
      .toMatchObject({
        principal: { id: issued.id },
        requiredScopesSatisfied: false,
      });
    expect(directorySyncs).toBe(afterIssue);

    expect(await security.authenticateApiKey(issued.token, ['dashboard:read'], '203.0.113.7'))
      .toMatchObject({ principal: { id: issued.id } });
    expect(directorySyncs).toBe(afterIssue + 1);
    clock.now += applicationSecurityStateLimits.defaultLastUsedWriteIntervalMs - 1;
    expect(await security.authenticateApiKey(issued.token, ['dashboard:read'], '203.0.113.7'))
      .toMatchObject({ principal: { id: issued.id } });
    expect(directorySyncs).toBe(afterIssue + 1);
    clock.now += 1;
    expect(await security.authenticateApiKey(issued.token, ['dashboard:read'], '203.0.113.7'))
      .toMatchObject({ principal: { id: issued.id } });
    expect(directorySyncs).toBe(afterIssue + 2);
  });

  it('enforces expiry and revocation and rotates without retaining either plaintext token', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    const expiring = await security.issueApiKey({
      name: 'Short lived',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock, 1_000),
    });
    clock.now += 1_000;
    expect(await security.authenticateApiKey(expiring.token)).toBeNull();

    const revoked = await security.issueApiKey({
      name: 'Revocable',
      scopes: ['logs:read'],
      expiresAt: expiresAt(clock),
    });
    expect((await security.revokeApiKey(revoked.id))?.revokedAt)
      .toBe('2026-08-31T03:00:01.000Z');
    expect(await security.authenticateApiKey(revoked.token)).toBeNull();

    const old = await security.issueApiKey({
      name: 'Rotating',
      scopes: ['agents:read', 'agents:write'],
      expiresAt: expiresAt(clock),
    });
    clock.now += 1_000;
    const replacement = await security.rotateApiKey({
      id: old.id,
      expiresAt: expiresAt(clock),
    });
    expect(replacement.id).not.toBe(old.id);
    expect(replacement.token).not.toBe(old.token);
    expect(await security.authenticateApiKey(old.token)).toBeNull();
    expect(await security.authenticateApiKey(replacement.token, ['agents:write']))
      .toMatchObject({ principal: { id: replacement.id } });
    const serialized = readdirSync(directory)
      .map((name) => readFileSync(join(directory, name), 'utf8'))
      .join('\n');
    expect(serialized).not.toContain(old.token);
    expect(serialized).not.toContain(replacement.token);
    const keys = await security.listApiKeys();
    expect(keys.find(({ id }) => id === old.id)?.revokedAt)
      .toBe('2026-08-31T03:00:02.000Z');
  });

  it('rejects unknown or duplicate scopes, excessive lifetime, extra fields, and the key bound', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock, { maxApiKeys: 2 }));
    await expect(security.issueApiKey({
      name: 'Unknown scope',
      scopes: ['unknown:scope' as 'dashboard:read'],
      expiresAt: expiresAt(clock),
    })).rejects.toThrow(/invalid name, scope, or source IP allowlist/u);
    await expect(security.issueApiKey({
      name: 'Duplicate scope',
      scopes: ['logs:read', 'logs:read'],
      expiresAt: expiresAt(clock),
    })).rejects.toThrow(/invalid name, scope, or source IP allowlist/u);
    await expect(security.issueApiKey({
      name: 'Too long',
      scopes: ['dashboard:read'],
      expiresAt: new Date(clock.now + applicationSecurityStateLimits.maximumKeyLifetimeMs + 1).toISOString(),
    })).rejects.toThrow(/allowed lifetime/u);
    await expect(security.issueApiKey({
      name: 'Extra field',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
      plaintext: 'do-not-store',
    } as never)).rejects.toThrow(/invalid schema/u);

    const one = await security.issueApiKey({
      name: 'One',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });
    const two = await security.issueApiKey({
      name: 'Two',
      scopes: ['logs:read'],
      expiresAt: expiresAt(clock),
    });
    await expect(security.issueApiKey({
      name: 'Three',
      scopes: ['agents:read'],
      expiresAt: expiresAt(clock),
    })).rejects.toThrow(/limit reached/u);
    expect((await security.listApiKeys()).map(({ id }) => id)).toEqual([one.id, two.id]);
  });

  it('compacts only inactive tombstones so rotation remains available after bounded churn', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock, { maxApiKeys: 2 }));
    let current = await security.issueApiKey({
      name: 'Continuously rotated',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock),
    });

    for (let rotation = 0; rotation < 8; rotation += 1) {
      const previous = current;
      clock.now += 1_000;
      current = await security.rotateApiKey({ id: previous.id, expiresAt: expiresAt(clock) });
      expect(await security.authenticateApiKey(previous.token, ['dashboard:read'], '203.0.113.7'))
        .toBeNull();
      const keys = await security.listApiKeys();
      expect(keys.length).toBeLessThanOrEqual(2);
      expect(keys.filter(({ revokedAt }) => revokedAt === null).map(({ id }) => id))
        .toEqual([current.id]);
      const persisted = JSON.parse(readFileSync(stateFile(directory), 'utf8')) as {
        keys: Array<{ id: string }>;
      };
      expect(persisted.keys).toHaveLength(keys.length);
      expect(persisted.keys.length).toBeLessThanOrEqual(2);
    }
    expect(await security.authenticateApiKey(current.token, ['dashboard:read'], '203.0.113.7'))
      .toMatchObject({ principal: { id: current.id } });
  });

  it('reclaims expired entries for issuance without pruning any active key', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock, { maxApiKeys: 2 }));
    const expired = await security.issueApiKey({
      name: 'Short lived',
      scopes: ['dashboard:read'],
      expiresAt: expiresAt(clock, 1_000),
    });
    const active = await security.issueApiKey({
      name: 'Must stay active',
      scopes: ['logs:read'],
      expiresAt: expiresAt(clock),
    });
    clock.now += 1_000;
    const replacement = await security.issueApiKey({
      name: 'Reuses expired capacity',
      scopes: ['agents:read'],
      expiresAt: expiresAt(clock),
    });
    const keys = await security.listApiKeys();
    expect(keys.map(({ id }) => id)).toEqual([active.id, replacement.id]);
    expect(keys.some(({ id }) => id === expired.id)).toBe(false);
    expect(await security.authenticateApiKey(active.token, ['logs:read'], '203.0.113.7'))
      .toMatchObject({ principal: { id: active.id } });
  });
});

describe('application audit journal', () => {
  it('writes only the exact bounded schema and hashes a normalized source IP in its own domain', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    const record = await security.audit(auditInput());
    const expectedHash = createHash('sha256')
      .update(Buffer.from('monitor.application-security.source-ip.v1\0', 'utf8'))
      .update('203.0.113.7', 'utf8')
      .digest('hex');
    expect(record).toEqual({
      schemaVersion: 1,
      timestamp: '2026-08-31T03:00:00.000Z',
      requestId: 'request-00000000',
      actor: { subject: 'portfolio-owner', role: 'chief-admin' },
      action: 'system-update.check',
      target: '/monitor/api/system-updates/check',
      outcome: 'success',
      sourceIpHash: `sha256:${expectedHash}`,
    });
    const serialized = readFileSync(auditFile(directory), 'utf8');
    expect(serialized).not.toContain('203.0.113.7');
    expect(serialized).not.toMatch(/authorization|cookie|requestHeaders|requestBody|secret/iu);
    expect(Buffer.byteLength(serialized, 'utf8'))
      .toBeLessThanOrEqual(applicationSecurityStateLimits.maximumAuditRecordBytes);
    const parsed = JSON.parse(serialized) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual([
      'action',
      'actor',
      'outcome',
      'requestId',
      'schemaVersion',
      'sourceIpHash',
      'target',
      'timestamp',
    ]);
    expect(parseApplicationAuditRecord(parsed)).toEqual(record);
    expect(lstatSync(auditFile(directory)).mode & 0o777).toBe(0o600);
  });

  it('rejects headers, bodies, secrets, malformed IPs, non-opaque IDs, and oversized values', async () => {
    const clock = { now: NOW };
    const security = new ApplicationSecurityState(secureDirectory(), options(clock));
    await expect(security.audit({
      ...auditInput(),
      headers: { authorization: 'Bearer secret' },
    } as never)).rejects.toThrow(/invalid schema/u);
    await expect(security.audit({
      ...auditInput(),
      body: { password: 'secret' },
    } as never)).rejects.toThrow(/invalid schema/u);
    await expect(security.audit(auditInput(1, { requestId: `mon_${'a'.repeat(43)}` })))
      .rejects.toThrow(/invalid value/u);
    await expect(security.audit(auditInput(2, { sourceIp: '203.0.113.7, 198.51.100.8' })))
      .rejects.toThrow(/invalid value/u);
    await expect(security.audit(auditInput(3, { target: `/monitor/${'a'.repeat(200)}` })))
      .rejects.toThrow(/invalid value/u);
  });

  it('serializes concurrent appends and rotates within byte and retention bounds', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock, {
      auditMaxBytes: 700,
      auditRetentionFiles: 3,
    }));
    const inputs = Array.from({ length: 12 }, (_, index) => auditInput(index));
    await Promise.all(inputs.map((input) => security.audit(input)));

    const names = readdirSync(directory)
      .filter((name) => /^application-audit(?:\.\d+)?\.jsonl$/u.test(name))
      .sort();
    expect(names.length).toBeGreaterThan(1);
    expect(names.length).toBeLessThanOrEqual(3);
    for (const name of names) {
      expect(statSync(join(directory, name)).size).toBeLessThanOrEqual(700);
      const contents = readFileSync(join(directory, name), 'utf8');
      expect(contents.endsWith('\n')).toBe(true);
      for (const line of contents.trimEnd().split('\n')) {
        expect(parseApplicationAuditRecord(JSON.parse(line))).not.toBeNull();
      }
    }
    const retained = await security.readAuditRecords();
    const allIds = inputs.map(({ requestId }) => requestId);
    expect(retained.length).toBeGreaterThan(0);
    expect(retained.length).toBeLessThan(12);
    expect(retained.map(({ requestId }) => requestId))
      .toEqual(allIds.slice(-retained.length));
  });

  it('recovers an interrupted trailing append without accepting malformed JSON', async () => {
    const clock = { now: NOW };
    const directory = secureDirectory();
    const security = new ApplicationSecurityState(directory, options(clock));
    await security.audit(auditInput());
    appendFileSync(auditFile(directory), '{"schemaVersion":1,"timestamp":"interrupted"');

    const recovered = new ApplicationSecurityState(directory, options(clock));
    expect(readFileSync(auditFile(directory), 'utf8').endsWith('\n')).toBe(true);
    expect((await recovered.readAuditRecords()).map(({ requestId }) => requestId))
      .toEqual(['request-00000000']);
    await recovered.audit(auditInput(1, { sourceIp: null, outcome: 'denied' }));
    const records = await recovered.readAuditRecords();
    expect(records).toHaveLength(2);
    expect(records[1]).toMatchObject({
      requestId: 'request-00000001',
      outcome: 'denied',
      sourceIpHash: null,
    });

    const withoutFinalNewline = readFileSync(auditFile(directory), 'utf8').slice(0, -1);
    writeFileSync(auditFile(directory), withoutFinalNewline);
    const salvaged = new ApplicationSecurityState(directory, options(clock));
    expect(readFileSync(auditFile(directory), 'utf8').endsWith('\n')).toBe(true);
    expect(await salvaged.readAuditRecords()).toHaveLength(2);
  });
});
