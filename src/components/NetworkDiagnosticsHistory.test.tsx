import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { NetworkDiagnosticsResponse } from '../network-diagnostics-types';
import { diagnosticIncidentWindow, NetworkDiagnosticsEvidence, NetworkDiagnosticsHistory } from './NetworkDiagnosticsHistory';

function response(): NetworkDiagnosticsResponse {
  return { schemaVersion: 1, status: 'fresh', observedAt: '2026-09-13T12:00:00Z', range: '24h',
    from: '2026-09-12T12:00:00Z', to: '2026-09-13T12:00:00Z', page: 1, limit: 20, total: 1,
    problem: 'all', rejectedRows: 0, truncated: false, retentionDays: 30, records: [{ schemaVersion: 1,
      observedAt: '2026-09-13T12:00:00Z', probeStatus: 'stale', probeObservedAt: '2026-09-13T11:40:00Z',
      probes: [{ id: 'public-monitor', status: 'timeout', checkedAt: '2026-09-13T11:40:00Z', httpStatus: null, redirectCount: 1,
        errorPhase: 'tls', timings: { dnsMs: 12, tcpMs: 30, tlsMs: null, ttfbMs: null, totalMs: 5000 } }],
      tcp: { status: 'fresh', elapsedSeconds: 10, retransmittedSegments: 2, outboundSegments: 100, retransmitPercent: 2,
        retransmittedPerSecond: .2, outboundPerSecond: 10 },
      interfaces: { rxErrorsPerSecond: 1, txErrorsPerSecond: 0, rxDroppedPerSecond: 2, txDroppedPerSecond: 0 },
      context: { cpuPercent: 25, memoryPercent: 35, cpuPressureSomeAvg10: 1, cpuPressureFullAvg10: 0,
        memoryPressureSomeAvg10: 2, memoryPressureFullAvg10: 0, ioPressureSomeAvg10: 3, ioPressureFullAvg10: 0 }, problems: ['http', 'tcp'] }] };
}
describe('NetworkDiagnosticsHistory', () => {
  it('shows phase failures, missing timings and separate host/probe timestamps with useful context', () => {
    const html = renderToStaticMarkup(createElement(NetworkDiagnosticsEvidence, { response: response(), locale: 'en' }));
    for (const evidence of ['Failed phase', 'tls', 'DNS', 'TTFB', '12 ms', '30 ms', '<dd>—</dd>', 'Stale',
      '2 / 100 outbound segments', '10 s', 'PSI', '25%', '35%', '2026-09-13T11:40:00Z', '2026-09-13T12:00:00Z']) expect(html).toContain(evidence);
    expect(html).not.toContain('https://');
  });
  it('renders explicit no-data and error states in both locales', () => {
    const missing = { ...response(), status: 'no_data' as const, records: [], observedAt: null };
    expect(renderToStaticMarkup(createElement(NetworkDiagnosticsEvidence, { response: missing, locale: 'ko' }))).toContain('자료 없음');
    const broken = { ...missing, status: 'error' as const, rejectedRows: 3, truncated: true };
    const html = renderToStaticMarkup(createElement(NetworkDiagnosticsEvidence, { response: broken, locale: 'en' }));
    expect(html).toContain('role="alert"');
    expect(html).toContain('Rejected records');
    expect(html).toContain('Some history could not be read');
  });
  it('provides time/problem filtering, refresh and explains retained evidence semantics', () => {
    const html = renderToStaticMarkup(createElement(NetworkDiagnosticsHistory, { locale: 'en' }));
    for (const expected of ['Network diagnostics history', 'Diagnostic history time range', 'Diagnostic history problem type',
      '30d', 'Refresh', '30 days', 'final request', 'first response byte', 'Addresses, URLs and credentials',
      'Select an exact incident window', 'datetime-local', 'Apply window', 'Clear custom window']) expect(html).toContain(expected);
  });
  it('converts selected incident times to UTC and rejects reversed, future and expired ranges', () => {
    const now = Date.parse('2026-09-13T12:00:00Z');
    expect(diagnosticIncidentWindow('2026-09-13T11:00:00+09:00', '2026-09-13T11:30:00+09:00', now))
      .toEqual({ from: '2026-09-13T02:00:00.000Z', to: '2026-09-13T02:30:00.000Z' });
    for (const [from, to] of [['bad', 'bad'], ['2026-09-13T11:00:00Z', '2026-09-13T10:00:00Z'],
      ['2026-09-13T11:00:00Z', '2026-09-13T13:00:00Z'], ['2026-08-01T00:00:00Z', '2026-08-02T00:00:00Z']]) {
      expect(diagnosticIncidentWindow(from, to, now)).toBeNull();
    }
  });
});
