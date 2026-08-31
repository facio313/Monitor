import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('production container runtime boundary', () => {
  it('keeps container root for rootless-userns bind and secret compatibility', () => {
    const dockerfile = readFileSync('Dockerfile', 'utf8');
    expect(dockerfile).toContain('rootless Docker user namespace');
    expect(dockerfile).toContain('chmod 0700 /var/lib/monitor-security');
    expect(dockerfile).not.toMatch(/^USER\s+/mu);
  });

  it('uses an explicit non-creating host state bind instead of an opaque volume', () => {
    const compose = readFileSync('docker-compose.yml', 'utf8');
    expect(compose).toContain('source: ${MONITOR_SECURITY_STATE_PATH:-/var/lib/monitor-security}');
    expect(compose).toMatch(/target: \/var\/lib\/monitor-security[\s\S]*?create_host_path: false/u);
    expect(compose).not.toContain('monitor_security_state:');
    expect(compose).not.toMatch(/type: volume[\s\S]*?target: \/var\/lib\/monitor-security/u);
  });
});
