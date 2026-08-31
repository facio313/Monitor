import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  PublicMonitorProbeError,
  probeConfiguration,
  runPublicMonitorProbe,
  validateReadiness,
  validateSsoRedirect,
} from './check-public-monitor.mjs';

const TARGET = new URL('https://bonifacio.work/monitor/');

function redirect(location = 'https://bonifacio.work/sso/?rd=https%3A%2F%2Fbonifacio.work%2Fmonitor%2F&rm=GET') {
  return new Response('', { status: 302, headers: { location } });
}

function ready(body = { status: 'ready' }, headers = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}

describe('external Monitor dead-man probe', () => {
  it('persists one external incident, closes it on recovery, and still fails the probe run', () => {
    const workflow = readFileSync(
      new URL('../.github/workflows/external-monitor.yml', import.meta.url),
      'utf8',
    );
    expect(workflow).toContain('issues: write');
    expect(workflow).toContain('continue-on-error: true');
    expect(workflow).toContain("title='[dead-man] Monitor public boundary unavailable'");
    expect(workflow).toContain('gh issue create');
    expect(workflow).toContain('gh issue comment');
    expect(workflow).toContain('gh issue close');
    expect(workflow).toContain("if: steps.probe.outcome == 'failure'");
    expect(workflow).toContain('run: exit 1');
    expect(workflow).not.toContain('MONITOR_PROBE_OUTPUT');
  });

  it('accepts only the canonical credential-free HTTPS target', () => {
    expect(probeConfiguration({})).toMatchObject({
      target: TARGET,
      readinessTarget: new URL('https://bonifacio.work/monitor/readyz'),
      timeoutMs: 12_000,
      attempts: 3,
    });
    expect(() => probeConfiguration({ MONITOR_PUBLIC_URL: 'http://bonifacio.work/monitor/' }))
      .toThrow(PublicMonitorProbeError);
    expect(() => probeConfiguration({ MONITOR_PUBLIC_URL: 'https://user:secret@bonifacio.work/monitor/' }))
      .toThrow(PublicMonitorProbeError);
    expect(() => probeConfiguration({ MONITOR_PUBLIC_URL: 'https://bonifacio.work/monitor/?token=secret' }))
      .toThrow(PublicMonitorProbeError);
    expect(() => probeConfiguration({ MONITOR_PUBLIC_URL: 'https://other.example/monitor/' }))
      .toThrow(PublicMonitorProbeError);
  });

  it('requires the exact bounded readiness contract', async () => {
    await expect(validateReadiness(ready())).resolves.toBeUndefined();
    await expect(validateReadiness(new Response('', { status: 503, headers: { 'content-type': 'application/json' } })))
      .rejects.toMatchObject({ code: 'READINESS_STATUS_INVALID' });
    await expect(validateReadiness(new Response('{"status":"ready"}', { status: 200, headers: { 'content-type': 'text/plain' } })))
      .rejects.toMatchObject({ code: 'CONTENT_TYPE_INVALID' });
    await expect(validateReadiness(new Response('{"status":"ready"}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }))).rejects.toMatchObject({ code: 'CACHE_POLICY_INVALID' });
    await expect(validateReadiness(ready({ status: 'ready', detail: 'unexpected' })))
      .rejects.toMatchObject({ code: 'BODY_INVALID' });
    await expect(validateReadiness(ready({ status: 'ready' }, { 'content-length': '257' })))
      .rejects.toMatchObject({ code: 'BODY_INVALID' });
  });

  it('requires the exact same-origin SSO return contract', () => {
    expect(validateSsoRedirect(TARGET, redirect())).toContain('/sso/');
    expect(() => validateSsoRedirect(TARGET, new Response('', { status: 200 })))
      .toThrowError(/HTTP 200/u);
    expect(() => validateSsoRedirect(TARGET, redirect('https://attacker.invalid/sso/?rd=x&rm=GET')))
      .toThrowError(/origin or path/u);
    expect(() => validateSsoRedirect(TARGET, redirect('https://bonifacio.work/sso/?rd=https%3A%2F%2Fbonifacio.work%2F&rm=GET')))
      .toThrowError(/return target/u);
    expect(() => validateSsoRedirect(TARGET, redirect('https://bonifacio.work/sso/?rd=https%3A%2F%2Fbonifacio.work%2Fmonitor%2F&rm=GET&token=secret')))
      .toThrowError(/unexpected query/u);
  });

  it('retries bounded failures and emits only reduced success evidence', async () => {
    const fetcher = vi.fn()
      .mockRejectedValueOnce(new Error('raw network secret'))
      .mockResolvedValueOnce(ready())
      .mockResolvedValueOnce(redirect());
    const clock = vi.fn()
      .mockReturnValueOnce(1_000)
      .mockReturnValueOnce(1_010)
      .mockReturnValueOnce(1_510)
      .mockReturnValueOnce(1_520)
      .mockReturnValueOnce(1_540)
      .mockReturnValueOnce(1_550);
    const result = await runPublicMonitorProbe({
      target: TARGET,
      readinessTarget: new URL('https://bonifacio.work/monitor/readyz'),
      timeoutMs: 50,
      attempts: 2,
    }, fetcher, clock);
    expect(result).toMatchObject({
      status: 'ok', attempts: 2, readinessHttpStatus: 200, ssoHttpStatus: 302,
    });
    expect(JSON.stringify(result)).not.toContain('raw network secret');
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it('fails closed when the app is unavailable even if the SSO edge could redirect', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response('', { status: 503 }))
      .mockResolvedValueOnce(redirect());
    await expect(runPublicMonitorProbe({
      target: TARGET,
      readinessTarget: new URL('https://bonifacio.work/monitor/readyz'),
      timeoutMs: 50,
      attempts: 1,
    }, fetcher)).rejects.toMatchObject({ code: 'READINESS_STATUS_INVALID' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
