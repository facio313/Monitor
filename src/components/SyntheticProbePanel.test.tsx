import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { DashboardPayload } from '../types';
import { SyntheticProbePanel } from './SyntheticProbePanel';

function payload(): DashboardPayload {
  return {
    syntheticProbeCollection: { status: 'fresh', observedAt: '2026-09-01T11:45:33Z' },
    syntheticProbes: [{
      id: 'public-monitor-readiness', status: 'ok', checkedAt: '2026-09-01T11:45:33Z',
      httpStatus: 200, redirectCount: 1, latencyMilliseconds: 364,
      certificateExpiresAt: '2026-11-18T02:13:49Z', certificateDaysRemaining: 77,
    }],
  } as DashboardPayload;
}

describe('SyntheticProbePanel', () => {
  it('shows every retained HTTP and TLS result field and its replace-only cadence', () => {
    const markup = renderToStaticMarkup(createElement(SyntheticProbePanel, { data: payload(), locale: 'en' }));
    expect(markup).toContain('External HTTP and TLS probes');
    expect(markup).toContain('every five minutes');
    expect(markup).toContain('latest replace-only result');
    expect(markup).toContain('public-monitor-readiness');
    expect(markup).toContain('<td>200</td>');
    expect(markup).toContain('364 ms');
    expect(markup).toContain('<td>1</td>');
    expect(markup).toContain('77 d');
    expect(markup).toContain('Fresh');
  });

  it('keeps failures and unsupported collection explicit', () => {
    const failed = payload();
    failed.syntheticProbes![0] = { ...failed.syntheticProbes![0], status: 'tls', httpStatus: null };
    expect(renderToStaticMarkup(createElement(SyntheticProbePanel, { data: failed, locale: 'en' }))).toContain('TLS failure');

    failed.syntheticProbeCollection = { status: 'unsupported', observedAt: null };
    failed.syntheticProbes = [];
    const unsupported = renderToStaticMarkup(createElement(SyntheticProbePanel, { data: failed, locale: 'en' }));
    expect(unsupported).toContain('Unsupported');
    expect(unsupported).toContain('not supported in this environment');
  });
});
