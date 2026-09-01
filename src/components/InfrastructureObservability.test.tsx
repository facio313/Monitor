import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, type SessionInfo } from '../api';
import type {
  DashboardPayload,
  RemoteAgentInventoryResponse,
  RemoteAgentSummary,
} from '../types';
import {
  InfrastructureObservabilityView,
  REMOTE_AGENT_REFRESH_MS,
  type RemoteAgentViewState,
  initialRemoteAgentState,
  loadRemoteAgentState,
  remoteAgentFailure,
  startRemoteAgentPolling,
} from './InfrastructureObservability';

const ADMIN: SessionInfo = {
  authenticated: true,
  mode: 'sso',
  user: 'operator',
  role: 'admin',
  permissions: ['dashboard:read'],
};

function dashboard(): DashboardPayload {
  return {
    generatedAt: '2026-09-01T03:00:00.000Z',
    range: '24h',
    stale: false,
    latestObservedAt: '2026-09-01T02:59:55.000Z',
    host: {
      hostname: 'monitor-host',
      os: 'Ubuntu 24.04',
      architecture: 'arm64',
      logicalCpuCount: 8,
      uptimeSeconds: 90_061,
    },
    agent: {
      hostId: '11111111-1111-4111-8111-111111111111',
      agentId: '22222222-2222-4222-8222-222222222222',
      installationEpoch: '2026-08-01T00:00:00.000Z',
      identityGeneration: 3,
      machineIdentityStatus: 'bound',
      bootId: '33333333-3333-4333-8333-333333333333',
      sequence: 92,
      observedAt: '2026-09-01T02:59:55.000Z',
      receivedAt: '2026-09-01T02:59:56.000Z',
      expectedIntervalSeconds: 60,
      lifecycle: 'active',
      transport: 'local-file',
      status: 'healthy',
      ageSeconds: 5,
      clockSkewSeconds: -1,
    },
    reliability: {
      bootStartedAt: '2026-08-31T02:00:00.000Z',
      collectorGapSeconds: 5,
      sshListenersAvailable: true,
      networkLinkAvailable: true,
      nvmeMitigationActive: true,
    },
    linux: { status: 'supported' },
    containerCollection: { status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z' },
    dockerEventCollection: {
      status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z', cursorAt: null,
      reconnectCount: 0, gapCount: 0, gapDetected: false, logCollectionStatus: 'unsupported',
    },
    syntheticProbeCollection: { status: 'fresh', observedAt: '2026-09-01T02:59:55.000Z' },
    ruleEvaluation: {
      schemaVersion: 1,
      status: 'ok',
      rulePackVersion: 'default-v1',
      evaluatedAt: '2026-09-01T02:59:56.000Z',
      summary: { inactive: 1 },
      states: {
        'IngestLagHigh:monitor': {
          ruleId: 'IngestLagHigh',
          target: 'monitor',
          metric: 'monitor.ingest.lag_seconds',
          severity: 'critical',
          description: 'safe',
          runbook: 'not rendered /var/lib/private',
          phase: 'inactive',
          breachSamples: 0,
          recoverySamples: 0,
          missingSamples: 0,
          openedAt: null,
          conditionStartedAt: null,
          recoveryStartedAt: null,
          missingStartedAt: null,
          evaluationIntervalSeconds: 60,
          changedAt: '2026-09-01T02:59:56.000Z',
          lastEvaluatedAt: '2026-09-01T02:59:56.000Z',
          lastValue: 5,
          observationStatus: 'ok',
        },
      },
    },
    ruleAlerts: { status: 'ok', events: [] },
    latest: null,
    series: [],
    telemetrySummary: { sampleCount: 0 },
    incidents: [],
    disks: [],
    containers: [],
    currentTraffic: [],
    alerts: [],
    privilegeEvents: [],
    powerEvents: [],
    reliabilityEvents: [],
    powerSummary: {},
    system: {},
  } as unknown as DashboardPayload;
}

function remoteAgent(index: number): RemoteAgentSummary {
  return {
    registered: true,
    duplicate: false,
    agentId: `agent-${index}`,
    hostId: `host-${index}`,
    installationEpoch: '2026-08-01T00:00:00.000Z',
    registeredAt: '2026-08-01T00:00:00.000Z',
    lastSeenAt: '2026-09-01T02:59:55.000Z',
    lastObservedAt: '2026-09-01T02:59:54.000Z',
    lifecycle: 'active',
    status: 'healthy',
    expectedHeartbeatIntervalSeconds: 60,
    maxSequence: index,
    inventory: {
      agentVersion: '1.2.3',
      hostname: `remote-host-${index}`,
      ipAddresses: index === 0
        ? Array.from({ length: 10 }, (_, address) => `192.0.2.${address + 1}`)
        : [`198.51.100.${index % 200 + 1}`],
      operatingSystem: index === 0 ? 'secret=do-not-render,path=/var/lib/agent-private' : 'Ubuntu',
      ubuntuVersion: '24.04',
      kernelVersion: '6.8.0',
      architecture: 'arm64',
      cpuModel: 'Safe CPU',
      memoryBytes: 8_589_934_592,
    },
    certificate: { expiresAt: '2027-09-01T00:00:00.000Z', renewalRequired: false },
    clockRejections: { count: 0, lastRejectedAt: null },
    revokedAt: null,
    revokedReason: null,
    serverTime: '2026-09-01T03:00:00.000Z',
  };
}

function remoteResponse(count = 1): RemoteAgentInventoryResponse {
  return {
    serverTime: '2026-09-01T03:00:00.000Z',
    transport: {
      tlsTermination: 'trusted-reverse-proxy',
      applicationVerifies: ['edge-secret', 'mtls-verified-marker'],
    },
    queue: {
      entries: 2,
      bytes: 2_048,
      priorityEntries: 1,
      priorityBytes: 1_024,
      normalEntries: 1,
      normalBytes: 1_024,
      maxEntries: 100,
      maxBytes: 1_048_576,
      maxBatchReceipts: 1_000,
      maxQueueEntriesPerAgent: 20,
      maxQueueBytesPerAgent: 262_144,
      maxBatchReceiptsPerAgent: 100,
      maxIdempotencyRecordsPerAgent: 1_000,
      priorityReservePercent: 20,
      rejectedBatches: 1,
      rejectedRecords: 2,
      duplicateBatches: 3,
      duplicateRecords: 4,
      outOfOrderRecords: 5,
      expiredQueueBatches: 6,
    },
    agents: Array.from({ length: count }, (_, index) => remoteAgent(index)),
  };
}

describe('InfrastructureObservabilityView', () => {
  it('always renders current safe host, local heartbeat, collector, and self-health detail', () => {
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data: dashboard(),
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));

    expect(markup).toContain('Host identity and capacity');
    expect(markup).toContain('monitor-host');
    expect(markup).toContain('Local agent and heartbeat');
    expect(markup).toContain('22222222-2222-4222-8222-222222222222');
    expect(markup).toContain('Collector state');
    expect(markup).toContain('Monitor self-health');
    expect(markup).toContain('IngestLagHigh');
    expect(markup).toContain('monitor.ingest.lag_seconds');
    expect(markup).toContain('Remote agent control is not configured');
    expect(markup).toContain('404 is the intentional contract');
    expect(markup).not.toContain('/var/lib/private');
  });

  it('does not present an aged-out snapshot as current or nominal', () => {
    const data = dashboard();
    data.stale = true;
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data,
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));

    expect(markup).toContain('Last known');
    expect(markup).toContain('Snapshot stale');
    expect(markup).toContain('infrastructure-status-card tone-danger');
    expect(markup).not.toContain('Current snapshot');

    const agentAt = markup.indexOf('Local agent and heartbeat');
    const agentCard = markup.slice(markup.lastIndexOf('<article', agentAt), markup.indexOf('</article>', agentAt));
    expect(agentCard).toContain('infrastructure-status-card tone-danger');
    expect(agentCard).toContain('STALE DATA');
  });

  it('marks a failed displayed collection source even when the heartbeat is healthy', () => {
    const data = dashboard();
    data.containerCollection.status = 'permission-denied';
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data,
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));
    const titleAt = markup.indexOf('Collector state');
    const card = markup.slice(markup.lastIndexOf('<article', titleAt), markup.indexOf('</article>', titleAt));

    expect(card).toContain('infrastructure-status-card tone-danger');
    expect(card).toContain('Collection degraded');
    expect(card).toContain('Permission denied');
    expect(card).not.toContain('All current');
  });

  it('makes a firing self-health rule visible in the card tone and badge', () => {
    const data = dashboard();
    data.ruleEvaluation.states['IngestLagHigh:monitor']!.phase = 'firing';
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data,
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));
    const titleAt = markup.indexOf('Monitor self-health');
    const card = markup.slice(markup.lastIndexOf('<article', titleAt), markup.indexOf('</article>', titleAt));

    expect(card).toContain('infrastructure-status-card tone-danger');
    expect(card).toContain('1 action required');
    expect(card).toContain('firing');
    expect(card).not.toContain('infrastructure-status-badge">OK');
  });

  it('assesses every self-health target before applying the rendering limit', () => {
    const data = dashboard();
    const template = data.ruleEvaluation.states['IngestLagHigh:monitor']!;
    data.ruleEvaluation.states = Object.fromEntries([
      ...Array.from({ length: 16 }, (_, index) => {
        const ruleId = `A${String(index).padStart(2, '0')}Nominal`;
        return [`${ruleId}:target-${index}`, {
          ...template,
          ruleId,
          target: `target-${index}`,
          metric: `monitor.test.${index}`,
          phase: 'inactive' as const,
        }];
      }),
      ['ZZHiddenFiring:late-target', {
        ...template,
        ruleId: 'ZZHiddenFiring',
        target: 'late-target',
        metric: 'monitor.test.hidden',
        phase: 'firing' as const,
      }],
    ]);
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data,
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));
    const titleAt = markup.indexOf('Monitor self-health');
    const card = markup.slice(markup.lastIndexOf('<article', titleAt), markup.indexOf('</article>', titleAt));

    expect(card).toContain('infrastructure-status-card tone-danger');
    expect(card).toContain('1 action required');
    expect(card).toContain('Self-health rule targets');
    expect(card).toContain('Showing the first 16 of 17 targets');
    expect(card).toContain('target target-0');
    expect(card).not.toContain('late-target');
  });

  it('does not call an empty self-health target set nominal', () => {
    const data = dashboard();
    data.ruleEvaluation.states = {};
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data,
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'not-configured' },
    }));
    const titleAt = markup.indexOf('Monitor self-health');
    const card = markup.slice(markup.lastIndexOf('<article', titleAt), markup.indexOf('</article>', titleAt));

    expect(card).toContain('infrastructure-status-card tone-neutral');
    expect(card).toContain('No rule target states');
    expect(card).not.toContain('infrastructure-status-badge">OK');
  });

  it('bounds remote agents and addresses and never renders control transport internals or raw paths', () => {
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data: dashboard(),
      locale: 'en',
      remote: { kind: 'ready', data: remoteResponse(102) },
    }));

    expect(markup).toContain('100/102 shown');
    expect(markup).toContain('remote-host-99');
    expect(markup).not.toContain('remote-host-100');
    expect(markup).toContain('192.0.2.8');
    expect(markup).not.toContain('192.0.2.9');
    expect(markup).toContain('The rendering limit of 100 agents is applied.');
    expect(markup).toContain('Priority bytes');
    expect(markup).toContain('Normal bytes');
    expect(markup).toContain('Per-agent idempotency records');
    expect(markup).toContain('Installation epoch');
    expect(markup).toContain('Registered at');
    expect(markup).toContain('Last clock rejection');
    expect(markup).toContain('Revoked at');
    expect(markup).toContain('Revocation reason');
    expect(markup).not.toContain('mtls-verified-marker');
    expect(markup).not.toContain('/var/lib/agent-private');
    expect(markup).not.toContain('do-not-render');
  });
});

describe('remote inventory access states', () => {
  it('refreshes a live or failed inventory every minute without loading-state flashes', async () => {
    const ready: RemoteAgentViewState = { kind: 'ready', data: remoteResponse() };
    const calls: Array<{ signal: AbortSignal; showLoading: boolean }> = [];
    let scheduled: (() => void) | null = null;
    const timerHandle = {};
    const scheduler = {
      setTimeout: vi.fn((callback: () => void, delayMilliseconds: number) => {
        expect(delayMilliseconds).toBe(REMOTE_AGENT_REFRESH_MS);
        scheduled = callback;
        return timerHandle;
      }),
      clearTimeout: vi.fn(),
    };
    const load = vi.fn(async (signal: AbortSignal, showLoading: boolean) => {
      calls.push({ signal, showLoading });
      return ready;
    });

    const stop = startRemoteAgentPolling(load, scheduler);
    await Promise.resolve();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.showLoading).toBe(true);
    expect(scheduler.setTimeout).toHaveBeenCalledTimes(1);

    scheduled!();
    await Promise.resolve();
    expect(calls).toHaveLength(2);
    expect(calls[0]!.signal.aborted).toBe(true);
    expect(calls[1]!.showLoading).toBe(false);

    stop();
    expect(calls[1]!.signal.aborted).toBe(true);
    expect(scheduler.clearTimeout).toHaveBeenCalledWith(timerHandle);
  });

  it('does not poll an intentionally disabled control plane', async () => {
    const scheduler = { setTimeout: vi.fn(), clearTimeout: vi.fn() };
    const load = vi.fn(async () => ({
      kind: 'unsupported',
      reason: 'not-configured',
    }) as const);

    const stop = startRemoteAgentPolling(load, scheduler);
    await Promise.resolve();
    expect(load).toHaveBeenCalledTimes(1);
    expect(scheduler.setTimeout).not.toHaveBeenCalled();
    stop();
  });

  it('keeps local mode and non-admin SSO access separate from an admin request', () => {
    expect(initialRemoteAgentState(false, null)).toEqual({ kind: 'unsupported', reason: 'local-mode' });
    expect(initialRemoteAgentState(true, { ...ADMIN, role: 'user' })).toEqual({ kind: 'restricted' });
    expect(initialRemoteAgentState(true, ADMIN)).toEqual({ kind: 'loading' });
  });

  it('maps the intentional disabled-control-plane 404 to not configured', () => {
    expect(remoteAgentFailure(new ApiError('Not found', 404, 'NOT_FOUND'))).toEqual({
      kind: 'unsupported',
      reason: 'not-configured',
    });
  });

  it('explains local mode without claiming that an unrequested endpoint returned 404', () => {
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data: dashboard(),
      locale: 'en',
      remote: { kind: 'unsupported', reason: 'local-mode' },
    }));
    expect(markup).toContain('Remote inventory is not used in local-auth mode');
    expect(markup).toContain('The central inventory endpoint is not requested');
    expect(markup).not.toContain('404 is the intentional contract');
  });

  it('calls the unauthorized callback for a 401 without exposing the server message', async () => {
    const onUnauthorized = vi.fn();
    const state = await loadRemoteAgentState(
      undefined,
      onUnauthorized,
      vi.fn().mockRejectedValue(new ApiError('token=raw-secret /var/lib/private', 401, 'AUTH_REQUIRED')),
    );

    expect(state).toEqual({ kind: 'unauthorized' });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('keeps 403 and other failures explicit and renders only bounded status metadata', () => {
    expect(remoteAgentFailure(new ApiError('denied', 403, 'ROLE_REQUIRED'))).toEqual({ kind: 'restricted' });
    const markup = renderToStaticMarkup(createElement(InfrastructureObservabilityView, {
      data: dashboard(),
      locale: 'en',
      remote: remoteAgentFailure(new ApiError('secret=raw /var/lib/private', 503, 'AGENT_CONTROL_UNAVAILABLE')),
    }));
    expect(markup).toContain('HTTP 503');
    expect(markup).toContain('AGENT_CONTROL_UNAVAILABLE');
    expect(markup).not.toContain('raw');
    expect(markup).not.toContain('/var/lib/private');
  });
});
