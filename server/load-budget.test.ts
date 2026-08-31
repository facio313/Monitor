import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import { dataLimits, readDashboard } from './data.js';

type Budget = {
  schemaVersion: 1;
  target: { historyRowsPerDay: number; concurrentReaders: number };
  stressMultiplier: number;
  budgets: {
    dashboardReadP95Milliseconds: number;
    dashboardConcurrentP95Milliseconds: number;
    heapGrowthBytes: number;
    maximumReturnedSeriesPoints: number;
    maximumDashboardResponseBytes: number;
  };
};

const budget = JSON.parse(readFileSync(
  resolve('ops/resilience-budgets.json'),
  'utf8',
)) as Budget;
const root = mkdtempSync(join(tmpdir(), 'monitor-load-budget-'));

afterAll(() => rmSync(root, { recursive: true, force: true }));

function percentile(values: number[], ratio: number): number {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * ratio) - 1)] ?? Number.POSITIVE_INFINITY;
}

function sample(timestamp: string, index: number) {
  return {
    timestamp,
    cpuPercent: index % 101,
    memoryPercent: 50,
    memoryUsedBytes: 512 * 1024 * 1024,
    memoryTotalBytes: 1024 * 1024 * 1024,
    swapTotalBytes: 1024 * 1024,
    swapUsedBytes: 0,
    swapPercent: 0,
    temperatureC: 45,
    load1: 0.5,
    load5: 0.4,
    load15: 0.3,
    cpuPressureSomeAvg10: 0,
    cpuPressureFullAvg10: 0,
    memoryPressureSomeAvg10: 0,
    memoryPressureFullAvg10: 0,
    ioPressureSomeAvg10: 0,
    ioPressureFullAvg10: 0,
    powerState: 'normal',
    supplyVoltageVolts: null,
    throttledFlags: null,
    gpuMemoryBytes: null,
    gpuClockHz: null,
    networkRxBytesPerSecond: index,
    networkTxBytesPerSecond: index,
    networkRxErrorsPerSecond: 0,
    networkTxErrorsPerSecond: 0,
    networkRxDroppedPerSecond: 0,
    networkTxDroppedPerSecond: 0,
    diskReadBytesPerSecond: index,
    diskWriteBytesPerSecond: index,
  };
}

describe('versioned Monitor load budget', () => {
  it('normalizes two-times target history within p95, heap, and response bounds', async () => {
    expect(budget).toMatchObject({ schemaVersion: 1, stressMultiplier: 2 });
    const historyRows = budget.target.historyRowsPerDay * budget.stressMultiplier;
    expect(historyRows).toBe(2000);
    mkdirSync(join(root, 'history'), { recursive: true });
    const now = Date.parse('2026-08-31T23:59:00.000Z');
    const start = now - (historyRows - 1) * 30_000;
    const rows = Array.from({ length: historyRows }, (_, index) => JSON.stringify(sample(
      new Date(start + index * 30_000).toISOString(),
      index,
    ))).join('\n');
    writeFileSync(join(root, 'history', '2026-08-31.jsonl'), `${rows}\n`);

    const readTimings: number[] = [];
    for (let index = 0; index < budget.target.concurrentReaders; index += 1) {
      const started = performance.now();
      const dashboard = readDashboard(root, '24h', now, 300_000);
      readTimings.push(performance.now() - started);
      expect(dashboard.series.length).toBeLessThanOrEqual(
        budget.budgets.maximumReturnedSeriesPoints,
      );
    }

    const server = createServer((_request, response) => {
      try {
        const body = JSON.stringify(readDashboard(root, '24h', now, 300_000));
        response.writeHead(200, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          'cache-control': 'no-store',
        });
        response.end(body);
      } catch {
        response.writeHead(500, { 'content-type': 'application/json' });
        response.end('{"error":"collection_error"}');
      }
    });
    await new Promise<void>((accept, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => accept());
    });
    const address = server.address() as AddressInfo;
    const endpoint = `http://127.0.0.1:${address.port}/monitor/api/dashboard?range=24h`;
    let peakHeap = process.memoryUsage().heapUsed;
    const baselineHeap = peakHeap;
    const timings: number[] = [];
    let maximumResponseBytes = 0;
    const iterations = budget.target.concurrentReaders * 3;
    try {
      for (let wave = 0; wave < 3; wave += 1) {
        await Promise.all(Array.from(
          { length: budget.target.concurrentReaders },
          async () => {
            const started = performance.now();
            const response = await fetch(endpoint, { headers: { accept: 'application/json' } });
            const body = await response.arrayBuffer();
            timings.push(performance.now() - started);
            maximumResponseBytes = Math.max(maximumResponseBytes, body.byteLength);
            peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
            expect(response.status).toBe(200);
            expect(response.headers.get('cache-control')).toBe('no-store');
            const dashboard = JSON.parse(Buffer.from(body).toString('utf8')) as ReturnType<typeof readDashboard>;
            expect(dashboard.series.length).toBeLessThanOrEqual(
              budget.budgets.maximumReturnedSeriesPoints,
            );
          },
        ));
      }
    } finally {
      await new Promise<void>((accept, reject) => server.close((error) => (
        error ? reject(error) : accept()
      )));
    }

    const readP95 = percentile(readTimings, 0.95);
    const concurrentP95 = percentile(timings, 0.95);
    const heapGrowth = Math.max(0, peakHeap - baselineHeap);
    console.info(JSON.stringify({
      test: 'monitor-dashboard-2x-target',
      historyRows,
      iterations,
      readP95Milliseconds: Math.round(readP95 * 100) / 100,
      concurrentP95Milliseconds: Math.round(concurrentP95 * 100) / 100,
      heapGrowthBytes: heapGrowth,
      maximumResponseBytes,
      maximumSeriesPoints: dataLimits.maximumSeriesPoints,
    }));
    expect(readP95).toBeLessThanOrEqual(budget.budgets.dashboardReadP95Milliseconds);
    expect(concurrentP95).toBeLessThanOrEqual(
      budget.budgets.dashboardConcurrentP95Milliseconds,
    );
    expect(heapGrowth).toBeLessThanOrEqual(budget.budgets.heapGrowthBytes);
    expect(maximumResponseBytes).toBeLessThanOrEqual(
      budget.budgets.maximumDashboardResponseBytes,
    );
    expect(dataLimits.maximumSeriesPoints).toBe(
      budget.budgets.maximumReturnedSeriesPoints,
    );
  }, 30_000);
});
