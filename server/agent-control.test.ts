import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { gzipSync } from 'node:zlib';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MAX_CONTROL_STATE_ENVELOPE_BYTES,
  MAX_CONTROL_STATE_PLAINTEXT_BYTES,
  preflightAgentControlState,
} from './agent-control.js';
import {
  AgentBodyGate,
  createApp,
  MAX_AGENT_BODY_REQUESTS_IN_FLIGHT,
  MAX_AGENT_BODY_REQUESTS_PER_CERTIFICATE,
  MAX_AGENT_BODY_WALL_TIME_MS,
  MAX_AGENT_CONTROL_BODY_BYTES,
} from './app.js';
import { loadConfig, type AgentStorageKeyringInput } from './config.js';

const START = Date.parse('2026-08-30T12:00:00.000Z');
const ORIGIN = 'https://monitor.example.test';
const EDGE_SECRET = 'agent-control-edge-secret-is-at-least-32-bytes';
const AGENT_EDGE_SECRET = 'agent-ingress-edge-secret-is-domain-separated-32-bytes';
const SESSION_SECRET = 'agent-control-session-secret-is-at-least-32-bytes';
const HOST_ID = '11111111-1111-4111-8111-111111111111';
const AGENT_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_HOST_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_AGENT_ID = '44444444-4444-4444-8444-444444444444';
const BATCH_ID = '55555555-5555-4555-8555-555555555555';
const CERTIFICATE = 'a'.repeat(64);
const NEXT_CERTIFICATE = 'b'.repeat(64);
const MACHINE_DIGEST = 'c'.repeat(64);
const temporaryDirectories: string[] = [];

function temporaryDirectory(prefix = 'monitor-agent-control-'): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function keyring(activeKeyId = 'key-1', includePrevious = false): AgentStorageKeyringInput {
  return {
    schemaVersion: 1,
    activeKeyId,
    keys: {
      ...(includePrevious ? { 'key-1': Buffer.alloc(32, 0x11).toString('base64') } : {}),
      [activeKeyId]: Buffer.alloc(32, activeKeyId === 'key-1' ? 0x11 : 0x22).toString('base64'),
    },
  };
}

function decodeTestEncrypted<T>(path: string, purpose: string): T {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as {
    keyId: string;
    iv: string;
    ciphertext: string;
    tag: string;
  };
  const key = Buffer.from(keyring().keys[envelope.keyId]!, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64url'));
  decipher.setAAD(Buffer.from(`monitor-agent:${purpose}:v1`, 'utf8'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64url'));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64url')),
    decipher.final(),
  ]).toString('utf8')) as T;
}

function writeTestEncrypted(path: string, purpose: string, value: unknown): void {
  const keyId = 'key-1';
  const key = Buffer.from(keyring().keys[keyId]!, 'base64');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`monitor-agent:${purpose}:v1`, 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(value), 'utf8')),
    cipher.final(),
  ]);
  writeFileSync(path, JSON.stringify({
    schemaVersion: 1,
    algorithm: 'aes-256-gcm',
    keyId,
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  }), { mode: 0o600 });
}

function testSha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function ssoHeaders(role: 'admin' | 'chief-admin' = 'chief-admin') {
  return {
    'Remote-User': 'portfolio-owner',
    'Remote-Email': 'owner@example.test',
    'Remote-Groups': role === 'chief-admin'
      ? 'user,admin,chief-admin,portfolio-v2'
      : 'user,admin,portfolio-v2,access-monitor',
    'X-Portfolio-Edge-Secret': EDGE_SECRET,
  };
}

function mutationHeaders(role: 'admin' | 'chief-admin' = 'chief-admin') {
  return {
    ...ssoHeaders(role),
    Origin: ORIGIN,
    'Sec-Fetch-Site': 'same-origin',
    'Content-Type': 'application/json',
  };
}

function agentHeaders(
  now: number,
  fingerprint = CERTIFICATE,
  edgeSecret = AGENT_EDGE_SECRET,
) {
  return {
    'X-Portfolio-Edge-Secret': edgeSecret,
    'X-Monitor-mTLS-Verified': 'SUCCESS',
    'X-Monitor-Client-Cert-SHA256': fingerprint,
    'X-Monitor-Client-Cert-Not-After': new Date(now + 30 * 24 * 60 * 60 * 1_000).toISOString(),
  };
}

function inventory(hostname = 'ubuntu-edge-1') {
  return {
    agentVersion: '1.2.3',
    hostname,
    ipAddresses: ['192.0.2.10'],
    operatingSystem: 'Ubuntu Linux',
    ubuntuVersion: '24.04',
    kernelVersion: '6.8.0-40-generic',
    architecture: 'amd64',
    cpuModel: 'Example CPU',
    memoryBytes: 8 * 1024 * 1024 * 1024,
  };
}

function registration(token: string, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    enrollmentToken: token,
    hostId: HOST_ID,
    agentId: AGENT_ID,
    machineIdentityDigest: MACHINE_DIGEST,
    installationEpoch: '2026-08-30T11:00:00.000Z',
    heartbeatIntervalSeconds: 60,
    inventory: inventory(),
    ...overrides,
  };
}

function heartbeat(now: number, sequence: number, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    agentId: AGENT_ID,
    sequence,
    observedAt: new Date(now).toISOString(),
    expectedIntervalSeconds: 60,
    lifecycle: 'active',
    inventory: inventory(),
    ...overrides,
  };
}

function metricRecord(now: number, sequence: number, metric = 'host.cpu.percent') {
  return {
    kind: 'metric',
    metric,
    target: 'host:primary',
    observedAt: new Date(now).toISOString(),
    sequence,
    value: 12.5,
    severity: null,
  };
}

function eventRecord(now: number, sequence: number) {
  return {
    kind: 'event',
    metric: 'system.oom',
    target: 'host:primary',
    observedAt: new Date(now).toISOString(),
    sequence,
    value: null,
    severity: 'critical',
  };
}

function batch(now: number, records: unknown[], batchId = BATCH_ID, agentId = AGENT_ID) {
  const sequences = records.map((entry) => (entry as { sequence: number }).sequence);
  return {
    schemaVersion: 1,
    agentId,
    batchId,
    sentAt: new Date(now).toISOString(),
    firstSequence: Math.min(...sequences),
    lastSequence: Math.max(...sequences),
    records,
  };
}

function bodyContaining(expected: Record<string, unknown>) {
  return (response: { body: unknown }) => {
    expect(response.body).toEqual(expect.objectContaining(expected));
  };
}

function fixture(overrides: Record<string, unknown> = {}) {
  const root = temporaryDirectory();
  const stateDir = join(root, 'agent-state');
  let clock = START;
  const app = createApp({
    ssoEnabled: true,
    edgeSecret: EDGE_SECRET,
    allowedOrigins: [ORIGIN],
    dataDir: join(root, 'telemetry'),
    securityStateDir: root,
    agentIngestEnabled: true,
    agentEdgeSecret: AGENT_EDGE_SECRET,
    agentStateDir: stateDir,
    agentStorageKeyring: keyring(),
    now: () => clock,
    ...overrides,
  });
  return {
    app,
    root,
    stateDir,
    now: () => clock,
    advance: (milliseconds: number) => { clock += milliseconds; },
  };
}

async function issueToken(app: ReturnType<typeof createApp>, ttlSeconds = 300): Promise<string> {
  const response = await request(app)
    .post('/monitor/api/agents/enrollment-tokens')
    .set(mutationHeaders())
    .send({ ttlSeconds })
    .expect(201);
  return response.body.token as string;
}

function enroll(
  app: ReturnType<typeof createApp>,
  now: number,
  token: string,
  body = registration(token),
  fingerprint = CERTIFICATE,
) {
  return request(app)
    .post('/monitor/api/agent/enroll')
    .set(agentHeaders(now, fingerprint))
    .send(body);
}

afterEach(() => {
  vi.unstubAllEnvs();
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('central agent control configuration', () => {
  it('bounds concurrent agent body admission with idempotent permits', () => {
    expect(MAX_AGENT_BODY_REQUESTS_IN_FLIGHT).toBe(4);
    expect(MAX_AGENT_BODY_REQUESTS_PER_CERTIFICATE).toBe(1);
    expect(MAX_AGENT_BODY_WALL_TIME_MS).toBe(15_000);
    expect(MAX_AGENT_CONTROL_BODY_BYTES).toBe(8 * 1024);
    const gate = new AgentBodyGate(2);
    const first = gate.tryAcquire();
    const second = gate.tryAcquire();
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(gate.tryAcquire()).toBeNull();
    first!();
    first!();
    const replacement = gate.tryAcquire();
    expect(replacement).not.toBeNull();
    expect(gate.tryAcquire()).toBeNull();
    second!();
    replacement!();

    const keyed = new AgentBodyGate(4, 1);
    const firstAgent = keyed.tryAcquire('agent-a');
    expect(firstAgent).not.toBeNull();
    expect(keyed.tryAcquire('agent-a')).toBeNull();
    const secondAgent = keyed.tryAcquire('agent-b');
    expect(secondAgent).not.toBeNull();
    firstAgent!();
    secondAgent!();
  });

  it('accepts the exact plaintext boundary and rejects one byte over before encryption', () => {
    const exact = preflightAgentControlState(
      'x'.repeat(MAX_CONTROL_STATE_PLAINTEXT_BYTES),
      'key-1',
    );
    expect(exact.plaintextBytes).toBe(MAX_CONTROL_STATE_PLAINTEXT_BYTES);
    expect(exact.envelopeBytes).toBeLessThanOrEqual(MAX_CONTROL_STATE_ENVELOPE_BYTES);

    try {
      preflightAgentControlState(
        'x'.repeat(MAX_CONTROL_STATE_PLAINTEXT_BYTES + 1),
        'key-1',
      );
      throw new Error('Expected control-state backpressure');
    } catch (error) {
      expect(error).toMatchObject({
        status: 429,
        code: 'CONTROL_STATE_BACKPRESSURE',
        retryAfterSeconds: 60,
      });
    }
  });

  it('is disabled by default and fails closed when production prerequisites are absent', async () => {
    const root = temporaryDirectory();
    const disabled = createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      dataDir: root,
      securityStateDir: root,
      now: () => START,
    });
    await request(disabled).post('/monitor/api/agent/enroll').send({}).expect(404);

    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentStateDir: join(root, 'state'),
      agentStorageKeyring: keyring(),
    })).toThrow('MONITOR_AGENT_EDGE_SECRET must contain at least 32 bytes');

    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
    })).toThrow('MONITOR_AGENT_STATE_DIR is required');

    expect(() => loadConfig({
      ssoEnabled: false,
      password: 'bootstrap password',
      sessionSecret: SESSION_SECRET,
      agentIngestEnabled: true,
      agentStateDir: join(root, 'state'),
      agentStorageKeyring: keyring(),
      agentEdgeSecret: AGENT_EDGE_SECRET,
    })).toThrow('requires SSO or an explicit test fixture');
  });

  it('requires domain-separated SSO and agent edge secrets', () => {
    const root = temporaryDirectory();
    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: EDGE_SECRET,
      agentStateDir: join(root, 'state'),
      agentStorageKeyring: keyring(),
    })).toThrow('MONITOR_AGENT_EDGE_SECRET must differ from the Monitor SSO edge secret');
  });

  it('permits an explicit test-only fixture and rejects malformed storage keys', () => {
    vi.stubEnv('NODE_ENV', 'test');
    const root = temporaryDirectory();
    expect(loadConfig({
      ssoEnabled: false,
      password: 'bootstrap password',
      sessionSecret: SESSION_SECRET,
      agentIngestEnabled: true,
      agentIngestTestFixture: true,
      agentStateDir: join(root, 'state'),
      agentStorageKeyring: keyring(),
      agentEdgeSecret: AGENT_EDGE_SECRET,
    }).agentControl).not.toBeNull();

    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: join(root, 'bad-state'),
      agentStorageKeyring: {
        schemaVersion: 1,
        activeKeyId: 'bad',
        keys: { bad: Buffer.alloc(31).toString('base64') },
      },
    })).toThrow('invalid key');
  });

  it('loads the production storage keyring only from a private file', () => {
    const root = temporaryDirectory();
    const keyringPath = join(root, 'agent-keyring.json');
    const agentEdgePath = join(root, 'agent-edge-secret');
    writeFileSync(keyringPath, JSON.stringify(keyring()), { mode: 0o600 });
    writeFileSync(agentEdgePath, `${AGENT_EDGE_SECRET}\n`, { mode: 0o600 });
    vi.stubEnv('MONITOR_AGENT_STORAGE_KEYRING_FILE', keyringPath);
    vi.stubEnv('MONITOR_AGENT_EDGE_SECRET_FILE', agentEdgePath);
    const config = loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentStateDir: join(root, 'state'),
    });
    expect(config.agentControl?.storageKeyring.activeKeyId).toBe('key-1');
    expect(config.agentControl?.proxyEdgeSecret).toBe(AGENT_EDGE_SECRET);

    const keyringLink = join(root, 'agent-keyring-link.json');
    linkSync(keyringPath, keyringLink);
    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: join(root, 'linked-keyring-state'),
    })).toThrow('MONITOR_AGENT_STORAGE_KEYRING_FILE must reference a private small regular file');
    unlinkSync(keyringLink);

    const agentEdgeLink = join(root, 'agent-edge-secret-link');
    linkSync(agentEdgePath, agentEdgeLink);
    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentStateDir: join(root, 'linked-agent-edge-state'),
      agentStorageKeyring: keyring(),
    })).toThrow('MONITOR_AGENT_EDGE_SECRET_FILE must reference a private small regular file');
    unlinkSync(agentEdgeLink);

    if (typeof process.geteuid !== 'function') throw new Error('test requires ownership metadata');
    const actualUid = process.geteuid();
    const getEffectiveUid = vi.spyOn(process, 'geteuid').mockReturnValue(actualUid + 1);
    try {
      expect(() => loadConfig({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        agentIngestEnabled: true,
        agentStateDir: join(root, 'foreign-agent-edge-state'),
        agentStorageKeyring: keyring(),
      })).toThrow('MONITOR_AGENT_EDGE_SECRET_FILE must reference a private small regular file');
      expect(() => loadConfig({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        agentIngestEnabled: true,
        agentEdgeSecret: AGENT_EDGE_SECRET,
        agentStateDir: join(root, 'foreign-keyring-state'),
      })).toThrow('MONITOR_AGENT_STORAGE_KEYRING_FILE must reference a private small regular file');
    } finally {
      getEffectiveUid.mockRestore();
    }

    chmodSync(keyringPath, 0o644);
    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentStateDir: join(root, 'unsafe-state'),
    })).toThrow('must reference a private small regular file');
  });

  it('rejects a state directory that is writable by group or other users', () => {
    const root = temporaryDirectory();
    const stateDir = join(root, 'unsafe');
    mkdirSync(stateDir, { mode: 0o755 });
    chmodSync(stateDir, 0o755);
    expect(() => createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: stateDir,
      agentStorageKeyring: keyring(),
      dataDir: root,
      securityStateDir: root,
    })).toThrow('private directory');
  });

  it('rejects a state directory not owned by the runtime user', () => {
    const root = temporaryDirectory();
    const stateDir = join(root, 'foreign-owner');
    mkdirSync(stateDir, { mode: 0o700 });
    if (typeof process.geteuid !== 'function') throw new Error('test requires ownership metadata');
    const actualUid = process.geteuid();
    const getEffectiveUid = vi.spyOn(process, 'geteuid').mockReturnValue(actualUid + 1);
    try {
      expect(() => createApp({
        ssoEnabled: true,
        edgeSecret: EDGE_SECRET,
        agentIngestEnabled: true,
        agentEdgeSecret: AGENT_EDGE_SECRET,
        agentStateDir: stateDir,
        agentStorageKeyring: keyring(),
        dataDir: root,
        securityStateDir: root,
      })).toThrow('private directory');
    } finally {
      getEffectiveUid.mockRestore();
    }
  });

  it('requires the receipt/queue retention to cover the admitted offline window', () => {
    const root = temporaryDirectory();
    expect(() => loadConfig({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: join(root, 'state'),
      agentStorageKeyring: keyring(),
      agentMaxBackfillAgeSeconds: 120,
      agentQueueRetentionSeconds: 60,
    })).toThrow('must cover the backfill age');
  });
});

describe('one-time enrollment and certificate binding', () => {
  it('rejects each edge secret at the other trust boundary', async () => {
    const context = fixture();

    await request(context.app)
      .get('/monitor/api/auth/session')
      .set({
        ...ssoHeaders(),
        'X-Portfolio-Edge-Secret': AGENT_EDGE_SECRET,
      })
      .expect(200)
      .expect(bodyContaining({ authenticated: false, mode: 'sso' }));
    await request(context.app)
      .get('/monitor/api/dashboard?range=1h')
      .set({
        ...ssoHeaders(),
        'X-Portfolio-Edge-Secret': AGENT_EDGE_SECRET,
      })
      .expect(401);
    await request(context.app)
      .get('/monitor/api/auth/session')
      .set(ssoHeaders())
      .expect(200)
      .expect(bodyContaining({ authenticated: true, mode: 'sso' }));

    const token = await issueToken(context.app);
    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set({
        ...agentHeaders(context.now()),
        Authorization: `Bearer mon_${'a'.repeat(43)}`,
      })
      .send(registration(token))
      .expect(403).expect(bodyContaining({ code: 'API_KEY_NOT_ALLOWED' }));
    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set(agentHeaders(context.now(), CERTIFICATE, EDGE_SECRET))
      .send(registration(token))
      .expect(401)
      .expect(bodyContaining({ code: 'MTLS_PROXY_AUTH_REQUIRED' }));
    await enroll(context.app, context.now(), token).expect(201);
  });

  it('requires canonical chief-admin issuance and proxy-verified mTLS headers', async () => {
    const context = fixture();
    await request(context.app)
      .post('/monitor/api/agents/enrollment-tokens')
      .set(mutationHeaders('admin'))
      .send({ ttlSeconds: 300 })
      .expect(403).expect(bodyContaining({ code: 'ROLE_REQUIRED' }));
    await request(context.app)
      .post('/monitor/api/agents/enrollment-tokens')
      .set(ssoHeaders())
      .send({ ttlSeconds: 300 })
      .expect(403).expect(bodyContaining({ code: 'ORIGIN_REJECTED' }));

    const token = await issueToken(context.app);
    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .send(registration(token))
      .expect(401).expect(bodyContaining({ code: 'MTLS_PROXY_AUTH_REQUIRED' }));
    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set(agentHeaders(context.now(), CERTIFICATE, `${AGENT_EDGE_SECRET}-wrong`))
      .send(registration(token))
      .expect(401).expect(bodyContaining({ code: 'MTLS_PROXY_AUTH_REQUIRED' }));
    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set({
        ...agentHeaders(context.now()),
        'X-Monitor-Client-Cert-Not-After': 'Sun, 30 Aug 2027 12:00:00 GMT',
      })
      .send(registration(token))
      .expect(401).expect(bodyContaining({ code: 'CERTIFICATE_INVALID' }));

    const response = await enroll(context.app, context.now(), token).expect(201);
    expect(response.body).toMatchObject({
      registered: true,
      duplicate: false,
      agentId: AGENT_ID,
      hostId: HOST_ID,
      status: 'healthy',
    });
    expect(JSON.stringify(response.body)).not.toContain(CERTIFICATE);
    expect(JSON.stringify(response.body)).not.toContain(MACHINE_DIGEST);
  });

  it('ignores agent-supplied forwarding metadata in inventory and audit records', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    const forgedAddress = '198.51.100.77';
    const response = await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set({
        ...agentHeaders(context.now()),
        'X-Forwarded-For': forgedAddress,
      })
      .send(registration(token))
      .expect(201);

    expect(response.body.inventory.ipAddresses).not.toContain(forgedAddress);
    const forgedAddressHash = createHash('sha256')
      .update(Buffer.from('monitor.application-security.source-ip.v1\0', 'utf8'))
      .update(forgedAddress, 'utf8')
      .digest('hex');
    expect(readFileSync(join(context.root, 'application-audit.jsonl'), 'utf8'))
      .not.toContain(`sha256:${forgedAddressHash}`);
  });

  it('authenticates before body parsing and bounds small and concurrent agent bodies', async () => {
    const context = fixture();
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now(), CERTIFICATE, `${AGENT_EDGE_SECRET}-wrong`))
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .serialize((value) => value as Buffer)
      .send(Buffer.from('not-a-gzip-stream'))
      .expect(401)
      .expect(bodyContaining({ code: 'MTLS_PROXY_AUTH_REQUIRED' }));

    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send({ padding: 'x'.repeat(MAX_AGENT_CONTROL_BODY_BYTES) })
      .expect(413)
      .expect(bodyContaining({ code: 'PAYLOAD_TOO_LARGE' }));

    await request(context.app)
      .post('/monitor/api/agent/enroll')
      .set(agentHeaders(context.now()))
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .serialize((value) => value as Buffer)
      .send(gzipSync(Buffer.from(JSON.stringify({ schemaVersion: 1 }))))
      .expect(415)
      .expect(bodyContaining({ code: 'UNSUPPORTED_CONTENT_ENCODING' }));

    const busyGate = new AgentBodyGate(1);
    const heldPermit = busyGate.tryAcquire();
    expect(heldPermit).not.toBeNull();
    const busy = fixture({ agentBodyGate: busyGate });
    await request(busy.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(busy.now()))
      .send({})
      .expect('Retry-After', '1')
      .expect(503)
      .expect(bodyContaining({ code: 'AGENT_BODY_BUSY' }));
    heldPermit!();
  });

  it('closes a slow authenticated body at the absolute deadline and releases its permit', async () => {
    const gate = new AgentBodyGate(4, 1);
    const context = fixture({ agentBodyGate: gate, agentBodyTimeoutMs: 50 });
    const server = createServer(context.app);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (address === null || typeof address === 'string') {
      server.close();
      throw new Error('Expected an ephemeral TCP address');
    }
    const socket = connect(address.port, '127.0.0.1');
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });
      const headers = agentHeaders(context.now());
      socket.write([
        'POST /monitor/api/agent/heartbeat HTTP/1.1',
        `Host: 127.0.0.1:${address.port}`,
        `X-Portfolio-Edge-Secret: ${headers['X-Portfolio-Edge-Secret']}`,
        `X-Monitor-mTLS-Verified: ${headers['X-Monitor-mTLS-Verified']}`,
        `X-Monitor-Client-Cert-SHA256: ${headers['X-Monitor-Client-Cert-SHA256']}`,
        `X-Monitor-Client-Cert-Not-After: ${headers['X-Monitor-Client-Cert-Not-After']}`,
        'Content-Type: application/json',
        'Content-Length: 100',
        'Connection: close',
        '',
        '{',
      ].join('\r\n'));
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Slow agent body connection remained open')),
          1_000,
        );
        socket.once('close', () => {
          clearTimeout(timeout);
          resolve();
        });
        socket.once('error', () => undefined);
      });
      const replacement = gate.tryAcquire(CERTIFICATE);
      expect(replacement).not.toBeNull();
      replacement!();
    } finally {
      socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('stores only encrypted state and supports exact retry without token reuse', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    const enrolledAt = context.now();
    await enroll(context.app, enrolledAt, token).expect(201);
    context.advance(301_000);
    await enroll(context.app, enrolledAt, token)
      .expect(200)
      .expect(bodyContaining({ duplicate: true }));
    await enroll(
      context.app,
      enrolledAt,
      token,
      registration(token, { inventory: inventory('changed-host') }),
    ).expect(409).expect(bodyContaining({ code: 'ENROLLMENT_TOKEN_CONSUMED' }));

    const statePath = join(context.stateDir, 'control-state.json.enc');
    const raw = readFileSync(statePath, 'utf8');
    expect(statSync(statePath).mode & 0o777).toBe(0o600);
    expect(statSync(context.stateDir).mode & 0o777).toBe(0o700);
    expect(raw).not.toContain(token);
    expect(raw).not.toContain('ubuntu-edge-1');
    expect(raw).not.toContain(MACHINE_DIGEST);
    expect(JSON.parse(raw)).toMatchObject({ schemaVersion: 1, algorithm: 'aes-256-gcm', keyId: 'key-1' });
    expect(Buffer.byteLength(raw, 'utf8')).toBeLessThanOrEqual(MAX_CONTROL_STATE_ENVELOPE_BYTES);

    const restarted = createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      dataDir: join(context.root, 'telemetry'),
      securityStateDir: context.root,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: context.stateDir,
      agentStorageKeyring: keyring(),
      now: context.now,
    });
    const restartedListing = await request(restarted)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(restartedListing.body.agents).toEqual([
      expect.objectContaining({ agentId: AGENT_ID, hostId: HOST_ID }),
    ]);

    const listing = await request(context.app)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(listing.body.transport).toMatchObject({ tlsTermination: 'trusted-reverse-proxy' });
    expect(JSON.stringify(listing.body)).not.toContain(CERTIFICATE);
    expect(JSON.stringify(listing.body)).not.toContain(MACHINE_DIGEST);
  });

  it('expires tokens and prevents host, machine, and certificate collisions', async () => {
    const context = fixture();
    const expired = await issueToken(context.app, 30);
    context.advance(31_000);
    await enroll(context.app, context.now(), expired)
      .expect(410)
      .expect(bodyContaining({ code: 'ENROLLMENT_TOKEN_EXPIRED' }));

    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);

    const hostConflictToken = await issueToken(context.app);
    await enroll(
      context.app,
      context.now(),
      hostConflictToken,
      registration(hostConflictToken, {
        agentId: OTHER_AGENT_ID,
        machineIdentityDigest: 'd'.repeat(64),
      }),
      NEXT_CERTIFICATE,
    ).expect(409).expect(bodyContaining({ code: 'HOST_ID_CONFLICT' }));

    const machineConflictToken = await issueToken(context.app);
    await enroll(
      context.app,
      context.now(),
      machineConflictToken,
      registration(machineConflictToken, {
        hostId: OTHER_HOST_ID,
        agentId: OTHER_AGENT_ID,
      }),
      NEXT_CERTIFICATE,
    ).expect(409).expect(bodyContaining({ code: 'MACHINE_IDENTITY_CONFLICT' }));

    const certificateConflictToken = await issueToken(context.app);
    await enroll(
      context.app,
      context.now(),
      certificateConflictToken,
      registration(certificateConflictToken, {
        hostId: OTHER_HOST_ID,
        agentId: OTHER_AGENT_ID,
        machineIdentityDigest: 'd'.repeat(64),
      }),
      CERTIFICATE,
    ).expect(409).expect(bodyContaining({ code: 'CERTIFICATE_CONFLICT' }));
  });
});

describe('heartbeat, lifecycle, revocation, and certificate renewal', () => {
  it('enforces sequence and clock-skew contracts while deriving fleet status', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);

    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 10))
      .expect(200).expect(bodyContaining({ duplicate: false, status: 'healthy' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 10))
      .expect(200).expect(bodyContaining({ duplicate: true }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now() + 1_000, 10))
      .expect(409).expect(bodyContaining({ code: 'SEQUENCE_CONFLICT' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 10, { lifecycle: 'maintenance' }))
      .expect(409).expect(bodyContaining({ code: 'SEQUENCE_CONFLICT' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now() + 301_000, 11))
      .expect(422).expect(bodyContaining({ code: 'CLOCK_SKEW', serverTime: new Date(context.now()).toISOString() }));

    context.advance(180_000);
    let listing = await request(context.app).get('/monitor/api/agents').set(ssoHeaders('admin')).expect(200);
    expect(listing.body.agents[0].status).toBe('delayed');
    context.advance(121_000);
    listing = await request(context.app).get('/monitor/api/agents').set(ssoHeaders('admin')).expect(200);
    expect(listing.body.agents[0].status).toBe('disconnected');
    context.advance(24 * 60 * 60 * 1_000);
    listing = await request(context.app).get('/monitor/api/agents').set(ssoHeaders('admin')).expect(200);
    expect(listing.body.agents[0].status).toBe('inactive');
  });

  it('rotates a bound certificate once and immediately rejects the old certificate', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);

    const rotation = await request(context.app)
      .post(`/monitor/api/agents/${AGENT_ID}/certificate-rotation-tokens`)
      .set(mutationHeaders())
      .send({ ttlSeconds: 300 })
      .expect(201);
    const rotationBody = {
      schemaVersion: 1,
      agentId: AGENT_ID,
      rotationToken: rotation.body.token,
    };
    await request(context.app)
      .post('/monitor/api/agent/certificate-rotations')
      .set(agentHeaders(context.now(), NEXT_CERTIFICATE))
      .send(rotationBody)
      .expect(200).expect(bodyContaining({ rotated: true, duplicate: false }));
    await request(context.app)
      .post('/monitor/api/agent/certificate-rotations')
      .set(agentHeaders(context.now(), NEXT_CERTIFICATE))
      .send(rotationBody)
      .expect(200).expect(bodyContaining({ rotated: true, duplicate: true }));

    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now(), CERTIFICATE))
      .send(heartbeat(context.now(), 2))
      .expect(401).expect(bodyContaining({ code: 'CERTIFICATE_UNBOUND' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now(), NEXT_CERTIFICATE))
      .send(heartbeat(context.now(), 2))
      .expect(200);
  });

  it('revokes idempotently and blocks every subsequent agent write', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    await request(context.app)
      .post(`/monitor/api/agents/${AGENT_ID}/revoke`)
      .set(mutationHeaders())
      .send({ reason: 'compromised' })
      .expect(200).expect(bodyContaining({ status: 'revoked', revokedReason: 'compromised' }));
    await request(context.app)
      .post(`/monitor/api/agents/${AGENT_ID}/revoke`)
      .set(mutationHeaders())
      .send({ reason: 'compromised' })
      .expect(200).expect(bodyContaining({ duplicate: true, revokedReason: 'compromised' }));
    await request(context.app)
      .post(`/monitor/api/agents/${AGENT_ID}/revoke`)
      .set(mutationHeaders())
      .send({ reason: 'operator' })
      .expect(409).expect(bodyContaining({ code: 'REVOCATION_CONFLICT' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 2))
      .expect(403).expect(bodyContaining({ code: 'AGENT_REVOKED' }));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [metricRecord(context.now(), 2)]))
      .expect(403).expect(bodyContaining({ code: 'AGENT_REVOKED' }));
  });
});

describe('idempotent compressed batch ingest and bounded durable backpressure', () => {
  it('rejects mixed metric/event batches before priority admission', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);

    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [
        metricRecord(context.now(), 2),
        eventRecord(context.now(), 3),
      ]))
      .expect(400)
      .expect(bodyContaining({ code: 'INVALID_INGEST_BATCH' }));

    const listing = await request(context.app)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(listing.body.queue).toMatchObject({
      entries: 0,
      normalEntries: 0,
      priorityEntries: 0,
    });
  });

  it('loads legacy mixed queue entries while retaining idempotency and capacity', async () => {
    const context = fixture({ agentMaxQueueEntriesPerAgent: 1 });
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const originalMetric = metricRecord(context.now(), 2);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [originalMetric]))
      .expect(202);

    const normalDirectory = join(context.stateDir, 'ingest-queue', 'normal');
    const priorityDirectory = join(context.stateDir, 'ingest-queue', 'priority');
    const queueFile = readdirSync(normalDirectory)[0]!;
    const normalPath = join(normalDirectory, queueFile);
    const priorityPath = join(priorityDirectory, queueFile);
    const queued = decodeTestEncrypted<{
      agentId: string;
      batchId: string;
      receivedAt: number;
      sentAt: number;
      firstSequence: number;
      lastSequence: number;
      priority: 'normal' | 'priority';
      digest: string;
      records: Array<Record<string, unknown>>;
      schemaVersion: 1;
    }>(normalPath, 'ingest-batch');
    const normalizedMetric = { ...originalMetric, observedAt: context.now() };
    const originalEvent = eventRecord(context.now(), 3);
    const normalizedEvent = { ...originalEvent, observedAt: context.now() };
    const normalizedLegacyBatch = {
      schemaVersion: 1,
      agentId: AGENT_ID,
      batchId: BATCH_ID,
      sentAt: context.now(),
      firstSequence: 2,
      lastSequence: 3,
      records: [normalizedMetric, normalizedEvent],
    };
    const legacyDigest = testSha256(JSON.stringify(normalizedLegacyBatch));
    queued.firstSequence = 2;
    queued.lastSequence = 3;
    queued.priority = 'priority';
    queued.digest = legacyDigest;
    queued.records = [
      originalMetric,
      originalEvent,
    ];
    renameSync(normalPath, priorityPath);
    writeTestEncrypted(priorityPath, 'ingest-batch', queued);

    const statePath = join(context.stateDir, 'control-state.json.enc');
    const state = decodeTestEncrypted<{
      agents: Array<{ agentId: string; maxSequence: number }>;
      receipts: Array<{
        agentId: string;
        batchId: string;
        digest: string;
        priority: 'normal' | 'priority';
        recordKeys: string[];
        recordDigests: string[];
        acceptedRecordCount: number;
      }>;
    } & Record<string, unknown>>(statePath, 'control-state');
    const legacyRecords = [normalizedMetric, normalizedEvent];
    const receipt = state.receipts[0]!;
    receipt.digest = legacyDigest;
    receipt.priority = 'priority';
    receipt.recordKeys = legacyRecords.map((record) => testSha256([
      AGENT_ID,
      record.metric,
      record.target,
      new Date(record.observedAt).toISOString(),
      String(record.sequence),
    ].join('\0')));
    receipt.recordDigests = legacyRecords.map((record) => (
      testSha256(JSON.stringify(record))
    ));
    receipt.acceptedRecordCount = 2;
    state.agents[0]!.maxSequence = 3;
    writeTestEncrypted(statePath, 'control-state', state);

    const restarted = createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      dataDir: join(context.root, 'telemetry'),
      securityStateDir: context.root,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: context.stateDir,
      agentStorageKeyring: keyring(),
      agentMaxQueueEntriesPerAgent: 1,
      now: context.now,
    });
    const listing = await request(restarted)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(listing.body.queue).toMatchObject({
      entries: 1,
      normalEntries: 0,
      priorityEntries: 1,
    });

    await request(restarted)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [originalMetric, originalEvent]))
      .expect(200)
      .expect(bodyContaining({
        duplicate: true,
        acceptedRecords: 2,
        duplicateRecords: 0,
      }));

    await request(restarted)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [originalMetric],
        '66666666-6666-4666-8666-666666666666',
      ))
      .expect(202)
      .expect(bodyContaining({ acceptedRecords: 0, duplicateRecords: 1 }));
    await request(restarted)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [metricRecord(context.now(), 4, 'host.memory.percent')],
        '77777777-7777-4777-8777-777777777777',
      ))
      .expect(429)
      .expect(bodyContaining({ code: 'AGENT_QUOTA_BACKPRESSURE' }));
  });

  it('deduplicates by agent, batch, metric, target, timestamp, and sequence', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const original = batch(context.now(), [
      metricRecord(context.now() - 1_000, 20),
      metricRecord(context.now(), 21, 'host.load.1'),
    ]);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(202).expect(bodyContaining({
        acceptedRecords: 2,
        duplicateRecords: 0,
        priority: 'normal',
      }));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(200).expect(bodyContaining({ duplicate: true }));

    const changed = structuredClone(original);
    (changed.records[0] as { value: number }).value = 99;
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(changed)
      .expect(409).expect(bodyContaining({ code: 'BATCH_ID_CONFLICT' }));

    const second = batch(context.now(), [
      metricRecord(context.now() - 2_000, 19, 'host.memory.percent'),
      metricRecord(context.now() - 1_000, 20),
    ], '66666666-6666-4666-8666-666666666666');
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(second)
      .expect(202).expect(bodyContaining({
        acceptedRecords: 1,
        duplicateRecords: 1,
        outOfOrderRecords: 1,
      }));

    const recordConflict = batch(context.now(), [
      { ...metricRecord(context.now() - 1_000, 20), value: 77 },
    ], '77777777-7777-4777-8777-777777777777');
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(recordConflict)
      .expect(409)
      .expect(bodyContaining({ code: 'RECORD_IDEMPOTENCY_CONFLICT' }));
  });

  it('replays an exact offline batch after the live clock-skew window', async () => {
    const context = fixture({ agentMaxBackfillAgeSeconds: 60 });
    const token = await issueToken(context.app);
    const certificateHeaders = agentHeaders(context.now());
    await enroll(context.app, context.now(), token).expect(201);
    const original = batch(context.now(), [metricRecord(context.now(), 2)]);

    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(certificateHeaders)
      .send(original)
      .expect(202);

    context.advance(10 * 60 * 1_000);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(certificateHeaders)
      .send(original)
      .expect(200)
      .expect(bodyContaining({ duplicate: true }));
  });

  it('accepts gzip, rejects decompression overflow and arbitrary payload fields', async () => {
    const context = fixture({ agentMaxBatchBytes: 8 * 1024 });
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const compressedBatch = batch(
      context.now(),
      [metricRecord(context.now(), 2)],
      '77777777-7777-4777-8777-777777777777',
    );
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .serialize((value) => value as Buffer)
      .send(gzipSync(Buffer.from(JSON.stringify(compressedBatch))))
      .expect(202);

    const withSecret = batch(
      context.now(),
      [{ ...metricRecord(context.now(), 3), rawToken: 'must-never-be-stored' }],
      '88888888-8888-4888-8888-888888888888',
    );
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(withSecret)
      .expect(400).expect(bodyContaining({ code: 'INVALID_INGEST_BATCH' }));

    const decreasingSequence = batch(context.now(), [
      metricRecord(context.now(), 5),
      metricRecord(context.now(), 4, 'host.memory.percent'),
    ], '99999999-9999-4999-8999-999999999999');
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(decreasingSequence)
      .expect(400).expect(bodyContaining({ code: 'INVALID_INGEST_BATCH' }));

    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .serialize((value) => value as Buffer)
      .send(Buffer.from('not-a-gzip-stream'))
      .expect(400)
      .expect(bodyContaining({ code: 'INVALID_BODY' }));

    const bomb = gzipSync(Buffer.from(JSON.stringify({ padding: 'x'.repeat(20 * 1024) })));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .serialize((value) => value as Buffer)
      .send(bomb)
      .expect(413).expect(bodyContaining({ code: 'PAYLOAD_TOO_LARGE' }));
  });

  it('quarantines future and expired offline records without affecting another request', async () => {
    const context = fixture({ agentMaxBackfillAgeSeconds: 60 });
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [metricRecord(context.now() + 301_000, 2)]))
      .expect(422).expect(bodyContaining({ code: 'CLOCK_SKEW' }));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [metricRecord(context.now() - 61_000, 2)],
        '99999999-9999-4999-8999-999999999999',
      ))
      .expect(422).expect(bodyContaining({ code: 'DATA_TOO_OLD' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 2))
      .expect(200).expect(bodyContaining({ status: 'healthy' }));
    const listing = await request(context.app)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(listing.body.agents[0].clockRejections.count).toBe(1);
  });

  it('reserves queue capacity for events and never blocks heartbeat on metric backpressure', async () => {
    const context = fixture({
      agentMaxQueueEntries: 2,
      agentMaxQueueBytes: 64 * 1024,
      agentPriorityReservePercent: 20,
    });
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [metricRecord(context.now(), 2)]))
      .expect(202);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [metricRecord(context.now(), 3, 'host.memory.percent')],
        '66666666-6666-4666-8666-666666666666',
      ))
      .expect(429).expect(bodyContaining({ code: 'INGEST_BACKPRESSURE' }))
      .expect('Retry-After', '30');
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [eventRecord(context.now(), 4)],
        '77777777-7777-4777-8777-777777777777',
      ))
      .expect(202).expect(bodyContaining({ priority: 'priority' }));
    await request(context.app)
      .post('/monitor/api/agent/heartbeat')
      .set(agentHeaders(context.now()))
      .send(heartbeat(context.now(), 5))
      .expect(200);

    const listing = await request(context.app)
      .get('/monitor/api/agents')
      .set(ssoHeaders('admin'))
      .expect(200);
    expect(listing.body.queue).toMatchObject({
      entries: 2,
      normalEntries: 1,
      priorityEntries: 1,
      rejectedBatches: 1,
    });
    for (const priority of ['normal', 'priority']) {
      const directory = join(context.stateDir, 'ingest-queue', priority);
      for (const file of readdirSync(directory)) {
        const path = join(directory, file);
        expect(statSync(path).mode & 0o777).toBe(0o600);
        const raw = readFileSync(path, 'utf8');
        expect(raw).not.toContain('host.cpu.percent');
        expect(JSON.parse(raw).algorithm).toBe('aes-256-gcm');
      }
    }
  });

  it('contains queue exhaustion to one agent before it harms another agent', async () => {
    const context = fixture({
      agentMaxQueueEntries: 4,
      agentMaxQueueEntriesPerAgent: 1,
      agentMaxQueueBytes: 256 * 1024,
      agentMaxQueueBytesPerAgent: 128 * 1024,
    });
    const firstToken = await issueToken(context.app);
    await enroll(context.app, context.now(), firstToken).expect(201);
    const secondToken = await issueToken(context.app);
    await enroll(
      context.app,
      context.now(),
      secondToken,
      registration(secondToken, {
        hostId: OTHER_HOST_ID,
        agentId: OTHER_AGENT_ID,
        machineIdentityDigest: 'd'.repeat(64),
        inventory: inventory('ubuntu-edge-2'),
      }),
      NEXT_CERTIFICATE,
    ).expect(201);

    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [metricRecord(context.now(), 2)]))
      .expect(202);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(
        context.now(),
        [metricRecord(context.now(), 3, 'host.memory.percent')],
        '66666666-6666-4666-8666-666666666666',
      ))
      .expect(429)
      .expect(bodyContaining({ code: 'AGENT_QUOTA_BACKPRESSURE' }));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now(), NEXT_CERTIFICATE))
      .send(batch(
        context.now(),
        [metricRecord(context.now(), 2)],
        '77777777-7777-4777-8777-777777777777',
        OTHER_AGENT_ID,
      ))
      .expect(202);
  });

  it('fails closed instead of acknowledging a receipt whose durable queue entry is missing', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const original = batch(context.now(), [metricRecord(context.now(), 2)]);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(202);

    const queueDirectory = join(context.stateDir, 'ingest-queue', 'normal');
    unlinkSync(join(queueDirectory, readdirSync(queueDirectory)[0]!));
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(503)
      .expect(bodyContaining({ code: 'AGENT_CONTROL_UNAVAILABLE' }));

    expect(() => createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      dataDir: join(context.root, 'telemetry'),
      securityStateDir: context.root,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: context.stateDir,
      agentStorageKeyring: keyring(),
      now: context.now,
    })).toThrow('missing durable queue entry');
  });

  it('rejects hard-linked control state and queue files', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(batch(context.now(), [metricRecord(context.now(), 2)]))
      .expect(202);

    const restart = () => createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      dataDir: join(context.root, 'telemetry'),
      securityStateDir: context.root,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: context.stateDir,
      agentStorageKeyring: keyring(),
      now: context.now,
    });
    const statePath = join(context.stateDir, 'control-state.json.enc');
    const stateLink = join(context.root, 'control-state-link.json.enc');
    linkSync(statePath, stateLink);
    expect(restart).toThrow('Agent control encrypted file cannot be read');
    unlinkSync(stateLink);

    const queueDirectory = join(context.stateDir, 'ingest-queue', 'normal');
    const queuePath = join(queueDirectory, readdirSync(queueDirectory)[0]!);
    const queueLink = join(context.root, 'queue-link.json.enc');
    linkSync(queuePath, queueLink);
    expect(restart).toThrow('Agent ingest queue entry is unsafe');
    unlinkSync(queueLink);
  });

  it('fails closed when a queue file is not owned by the runtime user', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const original = batch(context.now(), [metricRecord(context.now(), 2)]);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(202);

    if (typeof process.geteuid !== 'function') throw new Error('test requires ownership metadata');
    const actualUid = process.geteuid();
    const getEffectiveUid = vi.spyOn(process, 'geteuid').mockReturnValue(actualUid + 1);
    try {
      await request(context.app)
        .post('/monitor/api/agent/ingest')
        .set(agentHeaders(context.now()))
        .send(original)
        .expect(503)
        .expect(bodyContaining({ code: 'AGENT_CONTROL_UNAVAILABLE' }));
    } finally {
      getEffectiveUid.mockRestore();
    }
  });

  it('recovers idempotency after restart and supports key rotation with an old decrypt key', async () => {
    const context = fixture();
    const token = await issueToken(context.app);
    await enroll(context.app, context.now(), token).expect(201);
    const original = batch(context.now(), [metricRecord(context.now(), 2)]);
    await request(context.app)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(202);

    const restarted = createApp({
      ssoEnabled: true,
      edgeSecret: EDGE_SECRET,
      allowedOrigins: [ORIGIN],
      dataDir: join(context.root, 'telemetry'),
      securityStateDir: context.root,
      agentIngestEnabled: true,
      agentEdgeSecret: AGENT_EDGE_SECRET,
      agentStateDir: context.stateDir,
      agentStorageKeyring: keyring('key-2', true),
      now: context.now,
    });
    await request(restarted)
      .post('/monitor/api/agent/ingest')
      .set(agentHeaders(context.now()))
      .send(original)
      .expect(200).expect(bodyContaining({ duplicate: true }));
    expect(JSON.parse(readFileSync(
      join(context.stateDir, 'control-state.json.enc'),
      'utf8',
    )).keyId).toBe('key-2');
  });
});
