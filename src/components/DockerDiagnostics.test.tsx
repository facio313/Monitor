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
      dockerSocketMounted: true, sensitiveBindMounted: true, rootUser: true,
      readOnlyRootFilesystem: false, addedCapabilityCount: 2, dangerousCapabilityCount: 2,
      excessiveCapabilities: true, imageName: 'registry.example/ops/monitor', imageTag: 'latest',
      imageDigest: `sha256:${'1'.repeat(64)}`, imageDigestSource: 'local-image-id',
      usesLatestTag: true, imageDigestDrift: false, imageDigestChanged: true,
    }],
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
