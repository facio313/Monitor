import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  monitoringCatalogLimits,
  normalizeMonitoringCatalog,
  readMonitoringCatalog,
  REQUIRED_MONITORING_OBSERVATION_IDS,
  type MonitoringCatalog,
} from './monitoring-catalog.js';

function generatedCatalog(): MonitoringCatalog {
  const script = `
import datetime as dt, json
from pathlib import Path
from monitoring_catalog import build_monitoring_catalog
value = build_monitoring_catalog(
    now=dt.datetime(2026, 9, 1, 3, 4, 5, tzinfo=dt.timezone.utc),
    rule_pack_path=Path("ops/rules/default-rules.v1.json"),
    collection_interval_seconds=75,
    retention_days=45,
    max_log_records=4321,
    incident_retention_days=21,
    max_incident_records=876,
    generic_log_retention_days=14,
    generic_log_max_records=12345,
    generic_log_max_file_bytes=12582912,
)
print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
`;
  return JSON.parse(execFileSync('python3', ['-c', script], {
    cwd: process.cwd(),
    env: { ...process.env, PYTHONPATH: join(process.cwd(), 'ops') },
    encoding: 'utf8',
    maxBuffer: monitoringCatalogLimits.maximumBytes,
  })) as MonitoringCatalog;
}

function directory(): string {
  const root = mkdtempSync(join(tmpdir(), 'monitor-catalog-'));
  chmodSync(root, 0o700);
  return root;
}

function writeCatalog(root: string, value: unknown = generatedCatalog()): string {
  const path = join(root, monitoringCatalogLimits.fileName);
  writeFileSync(path, `${JSON.stringify(value)}\n`);
  chmodSync(path, 0o640);
  return path;
}

describe('monitoring catalog strict reader', () => {
  it('accepts the collector contract with all rules, observations, and resolved retention', () => {
    const root = directory();
    writeCatalog(root);
    const catalog = readMonitoringCatalog(root);
    expect(catalog).not.toBeNull();
    expect(catalog?.rules).toHaveLength(82);
    expect(catalog?.observations.map((item) => item.id).sort())
      .toEqual([...REQUIRED_MONITORING_OBSERVATION_IDS].sort());
    expect(catalog?.evidenceSources).toHaveLength(14);
    expect(catalog?.evidenceSources.find((source) => source.id === 'telemetry-history')?.retention)
      .toEqual({
        policy: 'daily-age-and-count',
        pruneCadence: 'every-collection',
        maxAgeDays: 45,
        maxRecords: 2_000,
        recordScope: 'daily-partition',
        maxBytes: null,
      });
    expect(catalog?.evidenceSources.find((source) => source.id === 'incident-events')?.retention.pruneCadence)
      .toBe('on-incident-write-or-daily');
    expect(catalog?.evidenceSources.find((source) => source.id === 'generic-log-events')?.retention.pruneCadence)
      .toBe('every-generic-collection');
    expect(catalog?.observations.find((item) => item.id === 'synthetic.http-tls')?.cadenceSeconds)
      .toBe(300);
    expect(catalog?.rules.every((rule) => (
      rule.effectiveEvaluationIntervalSeconds === 75
      && rule.eventRetention.maxRecords === 4_321
    ))).toBe(true);
  });

  it('requires exact schemas and the complete evidence and observation manifests', () => {
    const valid = generatedCatalog();
    expect(normalizeMonitoringCatalog(valid)).not.toBeNull();
    expect(normalizeMonitoringCatalog({ ...valid, extra: true })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      evidenceSources: valid.evidenceSources.map((source, index) => (
        index === 0 ? { ...source, extra: true } : source
      )),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      evidenceSources: valid.evidenceSources.slice(1),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      observations: valid.observations.slice(1),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      rules: valid.rules.map((rule, index) => index === 0
        ? { ...rule, eventRetention: { ...rule.eventRetention, extra: true } }
        : rule),
    })).toBeNull();
  });

  it('rejects raw paths, unsafe artifact substitution, and secret assignments', () => {
    const valid = generatedCatalog();
    expect(normalizeMonitoringCatalog({
      ...valid,
      observations: valid.observations.map((item, index) => index === 0
        ? { ...item, description: { ...item.description, en: 'Read /etc/private/config' } }
        : item),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      evidenceSources: valid.evidenceSources.map((source, index) => index === 0
        ? { ...source, artifactLabel: '/var/lib/private.json' }
        : source),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      rules: valid.rules.map((rule, index) => index === 0
        ? { ...rule, runbook: 'authorization=raw-credential' }
        : rule),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      rules: valid.rules.map((rule, index) => index === 0
        ? { ...rule, labels: { secret: 'opaqueCredential123' } }
        : rule),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      rules: valid.rules.map((rule, index) => index === 0
        ? { ...rule, runbook: 'Use ghp_abcdefghijklmnopqrstuvwxyz1234567890' }
        : rule),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      observations: valid.observations.map((item, index) => index === 0
        ? { ...item, description: { ...item.description, en: 'Read (/etc/private/config)' } }
        : item),
    })).toBeNull();
    expect(normalizeMonitoringCatalog({
      ...valid,
      rules: valid.rules.map((rule, index) => index === 0
        ? { ...rule, runbook: 'Read /opt/monitor/private.conf' }
        : rule),
    })).toBeNull();
  });

  it('fails closed for wrong ownership expectations and writable or untrusted modes', () => {
    const ownerRoot = directory();
    writeCatalog(ownerRoot);
    expect(readMonitoringCatalog(ownerRoot, process.getuid())).not.toBeNull();
    expect(readMonitoringCatalog(ownerRoot, process.getuid() + 1)).toBeNull();

    const writableFileRoot = directory();
    const writableFile = writeCatalog(writableFileRoot);
    chmodSync(writableFile, 0o660);
    expect(readMonitoringCatalog(writableFileRoot)).toBeNull();

    const writableRoot = directory();
    writeCatalog(writableRoot);
    chmodSync(writableRoot, 0o770);
    expect(readMonitoringCatalog(writableRoot)).toBeNull();
  });

  it('fails closed for symlinks, hard links, invalid UTF-8, and oversized files', () => {
    const linkedRoot = directory();
    const externalRoot = directory();
    const external = writeCatalog(externalRoot);
    symlinkSync(external, join(linkedRoot, monitoringCatalogLimits.fileName));
    expect(readMonitoringCatalog(linkedRoot)).toBeNull();

    const hardLinkedRoot = directory();
    const hardLinked = writeCatalog(hardLinkedRoot);
    linkSync(hardLinked, join(hardLinkedRoot, 'second-link.json'));
    expect(readMonitoringCatalog(hardLinkedRoot)).toBeNull();

    const utfRoot = directory();
    const utfPath = join(utfRoot, monitoringCatalogLimits.fileName);
    writeFileSync(utfPath, Buffer.from([0xff, 0xfe, 0xfd]));
    chmodSync(utfPath, 0o640);
    expect(readMonitoringCatalog(utfRoot)).toBeNull();

    const oversizedRoot = directory();
    const oversizedPath = join(oversizedRoot, monitoringCatalogLimits.fileName);
    writeFileSync(oversizedPath, Buffer.alloc(monitoringCatalogLimits.maximumBytes + 1, 0x20));
    chmodSync(oversizedPath, 0o640);
    expect(readMonitoringCatalog(oversizedRoot)).toBeNull();
  });

  it('rejects a symlinked data root even when the catalog itself is regular', () => {
    const realParent = directory();
    const realRoot = join(realParent, 'export');
    mkdirSync(realRoot, { mode: 0o700 });
    writeCatalog(realRoot);
    const aliasParent = directory();
    const alias = join(aliasParent, 'alias');
    symlinkSync(realRoot, alias);
    expect(readMonitoringCatalog(alias)).toBeNull();
  });
});
