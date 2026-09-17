import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readSshAccess } from './ssh-access.js';

describe('Python SSH export to authenticated read-model contract', () => {
  it('preserves canonical addresses and microsecond times without raw auth contents', () => {
    const directory = mkdtempSync(join(tmpdir(), 'monitor-ssh-contract-'));
    try {
      execFileSync('python3', ['-c', `
import datetime as dt, json, sys
from pathlib import Path
from ops.log_pipeline import LogSource
from ops.log_sources import SourceDefinition
from ops.ssh_access import collect_ssh_access
root = Path(sys.argv[1])
now = dt.datetime(2026, 9, 13, 12, 0, tzinfo=dt.timezone.utc)
definition = SourceDefinition(source=LogSource(source_id="journal:ssh", kind="journald", priority="security", parser="json"), unit="ssh.service")
class NoCountry:
    def lookup(self, address):
        return {"countryCode": None, "countryStatus": "unavailable", "databaseDate": None}
lines = [json.dumps({"timestamp":"2026-09-13T11:59:59.123456Z", "severity":"6", "message":message}) for message in (
    "Invalid user fixture-user from ::ffff:8.8.8.8 port 50123",
    "Accepted publickey for fixture-operator from 192.168.1.20 port 50124 ssh2: ED25519 SHA256:abcdefghijklmnop",
)]
batch = {"journal:ssh":{"status":"fresh", "lines":lines, "droppedLines":0}}
status, retry = collect_ssh_access(root, [definition], batch, now, country_lookup=NoCountry())
assert status["status"] == "fresh" and not retry, status
status, retry = collect_ssh_access(root, [definition], batch, now, country_lookup=NoCountry())
assert status["deduplicatedRecords"] == 2 and not retry, status
`, directory], { cwd: resolve('.'), encoding: 'utf8', timeout: 10_000 });
      const response = readSshAccess(directory, { range: '24h' }, Date.parse('2026-09-13T12:00:00Z'));
      expect(response.status).toBe('fresh');
      expect(response.partial).toBe(false);
      expect(response.rejectedRows).toBe(0);
      expect(response.total).toBe(2);
      expect(response.records.map(row => row.sourceIp).sort()).toEqual(['192.168.1.20', '8.8.8.8']);
      expect(response.records.every(row => row.observedAt === '2026-09-13T11:59:59.123456Z')).toBe(true);
      expect(response.deduplicatedRecords).toBe(2);
      const accepted = readSshAccess(directory, { event: 'accepted' }, Date.parse('2026-09-13T12:00:00Z'));
      expect(accepted.total).toBe(1);
      expect(accepted.records[0].authMethod).toBe('publickey');
      expect(JSON.stringify(response)).not.toMatch(/fixture-user|fixture-operator|abcdefghijklmnop|MESSAGE|__CURSOR/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
