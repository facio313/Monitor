import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDashboard } from './data.js';

const NOW_TEXT = '2026-08-30T12:00:00Z';
const NOW = Date.parse(NOW_TEXT);
const temporaryDirectories: string[] = [];

function dataDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-container-contract-'));
  temporaryDirectories.push(directory);
  mkdirSync(join(directory, 'history'));
  return directory;
}

function writeCurrent(
  directory: string,
  containers: unknown[],
  status: 'fresh' | 'last-known' = 'fresh',
): void {
  writeFileSync(join(directory, 'current.json'), `${JSON.stringify({
    generatedAt: NOW_TEXT,
    latest: { timestamp: NOW_TEXT },
    containerCollection: { status, observedAt: NOW_TEXT },
    containers,
  })}\n`);
}

function lifecycleRow() {
  return {
    name: 'monitor',
    project: 'monitor',
    owner: 'cks',
    state: 'running',
    health: 'healthy',
    healthcheckConfigured: true,
    cpuPercent: 37.5,
    memoryBytes: 67_108_864,
    memoryPercent: 25,
    memoryLimitBytes: 268_435_456,
    cpuLimitCores: 0.75,
    pidLimit: 128,
    restartCount: 4,
    restartCountDelta: 1,
    oomKilled: false,
    startedAt: '2026-08-30T11:30:00Z',
    finishedAt: null,
  };
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe('container lifecycle API contract', () => {
  it('preserves the exact reduced v2 lifecycle and limit fields', () => {
    const directory = dataDirectory();
    writeCurrent(directory, [lifecycleRow()]);

    expect(readDashboard(directory, '1h', NOW, 300_000).containers).toEqual([{
      ...lifecycleRow(),
      startedAt: '2026-08-30T11:30:00.000Z',
    }]);
  });

  it('drops inconsistent v2 rows and promotes safe legacy rows with unknown lifecycle fields', () => {
    const directory = dataDirectory();
    writeCurrent(directory, [
      { ...lifecycleRow(), restartCount: 1, restartCountDelta: 2 },
      {
        name: 'blog-frontend', owner: 'cks', state: 'running', health: 'healthy',
        cpuPercent: 12.5, memoryBytes: 1024, memoryPercent: 1,
      },
    ], 'last-known');

    expect(readDashboard(directory, '1h', NOW, 300_000).containers).toEqual([{
      name: 'blog-frontend',
      project: null,
      owner: 'cks',
      state: 'running',
      health: null,
      healthcheckConfigured: null,
      cpuPercent: 12.5,
      memoryBytes: 1024,
      memoryPercent: 1,
      memoryLimitBytes: null,
      cpuLimitCores: null,
      pidLimit: null,
      restartCount: null,
      restartCountDelta: null,
      oomKilled: null,
      startedAt: null,
      finishedAt: null,
    }]);
  });
});
