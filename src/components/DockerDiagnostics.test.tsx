import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { DashboardPayload } from '../types';
import { DockerDiagnosticsPanel } from './DockerDiagnostics';

function payload(): DashboardPayload {
  return {
    containers: [{
      name: 'monitor', project: 'monitor', owner: 'cks', state: 'running', health: 'healthy',
      healthcheckConfigured: true, cpuPercent: 95, memoryBytes: 900, memoryPercent: 90,
      memoryLimitBytes: 1000, cpuLimitCores: 1, pidLimit: 100, restartCount: 4,
      restartCountDelta: 3, oomKilled: false, startedAt: '2026-08-30T11:00:00Z', finishedAt: null,
      instanceId: 'a'.repeat(32), pidCount: 90, cpuThrottledPercent: 25,
      cpuThrottledPeriods: 50, cpuThrottledSeconds: 2.5,
      blockReadBytes: 1000, blockWriteBytes: 2000, blockReadBytesPerSecond: 10,
      blockWriteBytesPerSecond: 20, networkRxBytes: 3000, networkTxBytes: 4000,
      networkRxBytesPerSecond: 30, networkTxBytesPerSecond: 40, networkErrors: 5,
      networkErrorsPerSecond: 1.5,
      writableLayerBytes: 1_500_000_000, volumeCount: 1, bindMountCount: 2,
      tmpfsMountCount: 1, networkAttachmentCount: 1, publishedPortCount: 1,
      privileged: true, hostPid: true, hostIpc: false, hostNetwork: true,
      dockerSocketMounted: true, sensitiveBindMounted: true, writableSensitiveBindMounted: true,
      rootUser: true,
      readOnlyRootFilesystem: false, addedCapabilityCount: 2, dangerousCapabilityCount: 2,
      excessiveCapabilities: true, imageName: 'registry.example/ops/monitor', imageTag: 'latest',
      imageDigest: `sha256:${'1'.repeat(64)}`, imageDigestSource: 'local-image-id',
      usesLatestTag: true, imageDigestDrift: false, imageDigestChanged: true,
      mountPolicyStatus: 'unmanaged',
    }],
    containerCollection: {
      status: 'fresh', observedAt: '2026-08-30T12:01:00Z',
    },
    dockerEventCollection: {
      status: 'gap', observedAt: '2026-08-30T12:01:00Z', cursorAt: '2026-08-30T12:01:00Z',
      reconnectCount: 2, gapCount: 1, gapDetected: true, logCollectionStatus: 'unsupported',
    },
    dockerEvents: [{
      id: 'b'.repeat(32), occurredAt: '2026-08-30T12:00:30Z', action: 'die',
      containerName: 'monitor', project: 'monitor', instanceId: 'a'.repeat(32),
      exitCode: 137, healthStatus: null,
    }],
  } as DashboardPayload;
}

describe('DockerDiagnosticsPanel', () => {
  it('shows bounded resource, image, security, cursor, gap, and event evidence without raw IDs', () => {
    const markup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: payload(), locale: 'en',
    }));
    expect(markup).toContain('Docker diagnostics');
    expect(markup).toContain('State observed');
    expect(markup).toContain('Event observed');
    expect(markup).toMatch(/Event observed <strong>(?!—)[^<]+<\/strong>/);
    expect(markup).toContain('Healthcheck');
    expect(markup).toContain('healthy');
    expect(markup).toContain('CPU throttled');
    expect(markup).toContain('Throttled periods');
    expect(markup).toContain('Network received');
    expect(markup).toContain('Writable layer');
    expect(markup).toContain('registry.example/ops/monitor:latest');
    expect(markup).toContain('Docker socket mounted');
    expect(markup).toContain('<dt>Mount policy</dt><dd>unmanaged</dd>');
    expect(markup).toContain('Writable sensitive bind mount');
    expect(markup).toContain('Host PID namespace');
    expect(markup).toContain('Host network');
    expect(markup).toContain('Root user');
    expect(markup).toContain('Writable root filesystem');
    expect(markup).toContain('Elevated capabilities');
    expect(markup).toContain('The Docker event history may contain a gap');
    expect(markup).toContain('Not collected');
    expect(markup).toContain('exit 137');
    expect(markup).not.toContain('a'.repeat(64));
  });

  it('shows a known read-only sensitive bind as evidence without reporting it as high risk', () => {
    const readOnly = payload();
    Object.assign(readOnly.containers[0], {
      privileged: false,
      dockerSocketMounted: false,
      hostPid: false,
      hostIpc: false,
      hostNetwork: false,
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: false,
      mountPolicyStatus: 'unmanaged',
      rootUser: false,
      readOnlyRootFilesystem: true,
      excessiveCapabilities: false,
    });
    const markup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: readOnly, locale: 'en',
    }));

    expect(markup).toContain('<dt>Sensitive bind</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Writable sensitive bind</dt><dd>No</dd>');
    expect(markup).not.toContain('Writable sensitive bind mount');
    expect(markup).not.toContain('Sensitive bind writability unverified');
    expect(markup).toContain('No high-risk setting was found in the collected summary.');
  });

  it('keeps approved writable-bind facts visible while suppressing only their fresh policy finding', () => {
    const approved = payload();
    Object.assign(approved.containers[0], {
      privileged: false,
      dockerSocketMounted: false,
      hostPid: false,
      hostIpc: false,
      hostNetwork: false,
      sensitiveBindMounted: true,
      writableSensitiveBindMounted: true,
      mountPolicyStatus: 'approved',
      rootUser: false,
      readOnlyRootFilesystem: true,
      excessiveCapabilities: false,
    });
    const markup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: approved, locale: 'en',
    }));

    expect(markup).toContain('<dt>Mount policy</dt><dd>approved</dd>');
    expect(markup).toContain('<dt>Sensitive bind</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Writable sensitive bind</dt><dd>Yes</dd>');
    expect(markup).not.toContain('Writable sensitive bind mount');
    expect(markup).toContain('No high-risk setting was found in the collected summary.');
  });

  it('shows policy drift, unknown state, and nonfresh approval as explicit risks', () => {
    const drift = payload();
    Object.assign(drift.containers[0], {
      mountPolicyStatus: 'drift',
      privileged: false,
      dockerSocketMounted: false,
      hostPid: false,
      hostIpc: false,
      hostNetwork: false,
      rootUser: false,
      readOnlyRootFilesystem: true,
      excessiveCapabilities: false,
    });
    expect(renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: drift, locale: 'en',
    }))).toContain('Mount policy drift');

    drift.containers[0].mountPolicyStatus = 'unknown';
    expect(renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: drift, locale: 'en',
    }))).toContain('Mount policy unverified');

    drift.containers[0].mountPolicyStatus = 'approved';
    drift.containerCollection = {
      status: 'last-known', observedAt: '2026-08-30T11:55:00Z',
    };
    expect(renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: drift, locale: 'en',
    }))).toContain('Approved mount policy is not freshly verified');

    drift.containerCollection.status = 'fresh';
    drift.stale = true;
    expect(renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: drift, locale: 'en',
    }))).toContain('Approved mount policy is not freshly verified');
  });

  it('does not present last-known container diagnostics as current when events are fresh', () => {
    const lastKnown = payload();
    lastKnown.containerCollection = {
      status: 'last-known',
      observedAt: '2026-08-30T11:55:00Z',
    };
    lastKnown.dockerEventCollection = {
      status: 'fresh',
      observedAt: '2026-08-30T12:01:00Z',
      cursorAt: '2026-08-30T12:01:00Z',
      reconnectCount: 0,
      gapCount: 0,
      gapDetected: false,
      logCollectionStatus: 'unsupported',
    };
    const markup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: lastKnown, locale: 'en',
    }));
    expect(markup).toContain('STATE · last-known');
    expect(markup).toContain('EVENTS · fresh');
    expect(markup).toContain('Last-known services');
    expect(markup).toContain('not presented as current observations');
  });

  it('distinguishes an unconfigured healthcheck from unverified collection without calling either unhealthy', () => {
    const unconfigured = payload();
    unconfigured.containers[0].healthcheckConfigured = false;
    unconfigured.containers[0].health = 'none';
    const unconfiguredMarkup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: unconfigured, locale: 'en',
    }));
    expect(unconfiguredMarkup).toContain('Not configured');
    expect(unconfiguredMarkup).not.toContain('unhealthy');

    const unverified = payload();
    unverified.containers[0].healthcheckConfigured = null;
    unverified.containers[0].health = null;
    const unverifiedMarkup = renderToStaticMarkup(createElement(DockerDiagnosticsPanel, {
      data: unverified, locale: 'en',
    }));
    expect(unverifiedMarkup).toContain('Unverified');
    expect(unverifiedMarkup).not.toContain('Not configured');
  });
});
