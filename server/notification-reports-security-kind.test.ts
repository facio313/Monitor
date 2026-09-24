import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readNotificationReports } from './notification-reports.js';

const NOW = Date.parse('2026-09-24T01:00:00Z');
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe('notification report security kinds', () => {
  it('retains an SSH authentication-success detection for the dashboard', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-notification-kind-'));
    temporaryDirectories.push(directory);
    writeFileSync(join(directory, 'notification-reports.json'), JSON.stringify({
      schemaVersion: 1,
      status: 'ok',
      observedAt: '2026-09-24T01:00:00Z',
      detections: [{
        id: 'a'.repeat(64),
        kind: 'ssh-auth-success',
        severity: 'critical',
        status: 'active',
        openedAt: '2026-09-24T00:59:00Z',
        observedAt: '2026-09-24T01:00:00Z',
        count: 1,
        windowSeconds: 300,
        evidence: 'Authentication accepted outside the trusted access list',
      }],
    }), { mode: 0o640 });

    const result = readNotificationReports(directory, NOW);

    expect(result.status).toBe('ok');
    expect(result.detections).toHaveLength(1);
    expect(result.detections[0]).toMatchObject({ kind: 'ssh-auth-success', severity: 'critical', status: 'active' });
  });
});
