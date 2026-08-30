import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { OperationalLogEntry } from '../dashboard-model';
import type { ContainerStatus, DashboardPayload, PeakIncident, TelemetrySample } from '../types';
import { ContainerStatusTable, IncidentDetail, IncidentsWidget } from './CockpitVisuals';
import { OperationalLogView } from './OperationalLogView';

function logs(count: number): OperationalLogEntry[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `log-${index + 1}`,
    timestamp: `2026-08-30T00:${String(index).padStart(2, '0')}:00Z`,
    category: 'alert',
    severity: 'info',
    kind: 'metrics',
    status: 'observed',
    title: `Log title ${index + 1}`,
    message: `Message ${index + 1}`,
    actor: null,
    target: null,
  }));
}

function containers(count: number): ContainerStatus[] {
  return Array.from({ length: count }, (_, index) => ({
    name: `service${String(index + 1).padStart(2, '0')}`,
    owner: 'ops',
    state: 'running',
    health: 'healthy',
    cpuPercent: index,
    memoryBytes: 1_000 + index,
    memoryPercent: index,
  }));
}

function telemetry(): TelemetrySample {
  return {
    timestamp: '2026-08-30T00:00:00Z',
    cpuPercent: 10,
    memoryPercent: 20,
    memoryUsedBytes: 100,
    memoryTotalBytes: 500,
    swapTotalBytes: 0,
    swapUsedBytes: 0,
    swapPercent: 0,
    cpuPressureSomeAvg10: 0,
    cpuPressureFullAvg10: 0,
    memoryPressureSomeAvg10: 0,
    memoryPressureFullAvg10: 0,
    ioPressureSomeAvg10: 0,
    ioPressureFullAvg10: 0,
    temperatureC: 40,
    load1: 0.1,
    load5: 0.1,
    load15: 0.1,
    powerState: 'normal',
    supplyVoltageVolts: 5,
    throttledFlags: 0,
    gpuMemoryBytes: 0,
    gpuClockHz: 0,
    networkRxBytesPerSecond: 0,
    networkTxBytesPerSecond: 0,
    networkRxErrorsPerSecond: 0,
    networkTxErrorsPerSecond: 0,
    networkRxDroppedPerSecond: 0,
    networkTxDroppedPerSecond: 0,
    diskReadBytesPerSecond: 0,
    diskWriteBytesPerSecond: 0,
  };
}

function incidents(count: number): PeakIncident[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `incident-${index + 1}`,
    startedAt: `2026-08-${String(index + 1).padStart(2, '0')}T00:00:00Z`,
    observedAt: `2026-08-${String(index + 1).padStart(2, '0')}T00:01:00Z`,
    endedAt: null,
    phase: 'recovered',
    reasons: ['cpu'],
    metrics: telemetry(),
    pressure: {
      cpu: { someAvg10: 0, fullAvg10: 0 },
      memory: { someAvg10: 0, fullAvg10: 0 },
      io: { someAvg10: 0, fullAvg10: 0 },
    },
    processes: [],
    containers: [],
    traffic: [],
    peaks: null,
    durationSeconds: 60,
  }));
}

function payload(overrides: Partial<DashboardPayload>): DashboardPayload {
  return {
    containers: [],
    incidents: [],
    ...overrides,
  } as unknown as DashboardPayload;
}

describe('paginated operational lists', () => {
  it('bounds compact and full operational log pages', () => {
    const full = renderToStaticMarkup(createElement(OperationalLogView, { entries: logs(12), locale: 'en' }));
    const compact = renderToStaticMarkup(createElement(OperationalLogView, { entries: logs(12), locale: 'en', compact: true }));

    expect(full.match(/class="ops-log-row severity-info"/g)).toHaveLength(10);
    expect(full).toContain('Log title 10');
    expect(full).not.toContain('Log title 11');
    expect(full).toContain('1–10 of 12 records');
    expect(compact.match(/class="ops-log-row severity-info"/g)).toHaveLength(4);
    expect(compact).toContain('1–4 of 12 records');
  });

  it('bounds the full and grouped service boards without splitting the initial group page', () => {
    const data = payload({ containers: containers(12) });
    const full = renderToStaticMarkup(createElement(ContainerStatusTable, { data, locale: 'en' }));
    const grouped = renderToStaticMarkup(createElement(ContainerStatusTable, { data, locale: 'en', grouped: true }));

    expect(full).toContain('service10');
    expect(full).not.toContain('service11');
    expect(full).toContain('1–10 of 12 services');
    expect(grouped).toContain('service06');
    expect(grouped).not.toContain('service07');
    expect(grouped).toContain('1–6 of 12 services');
  });

  it('bounds both overview and detailed incident records', () => {
    const data = payload({ incidents: incidents(7) });
    const overview = renderToStaticMarkup(createElement(IncidentsWidget, { data, locale: 'en', onOpen: () => undefined }));
    const detail = renderToStaticMarkup(createElement(IncidentDetail, { data, locale: 'en' }));

    expect(overview.match(/<li><span class="phase-recovered">/g)).toHaveLength(4);
    expect(overview).toContain('1–4 of 7 incidents');
    expect(detail.match(/class="incident-detail-card phase-recovered"/g)).toHaveLength(5);
    expect(detail).toContain('1–5 of 7 incidents');
  });
});
