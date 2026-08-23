import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { ContainerStatus, PeakIncident } from '../types';
import {
  ContainerList,
  containerSummaryLabel,
  currentPowerStatusTone,
  decodeThrottledFlags,
  eventStatusTone,
  formatFlags,
  IncidentTimeline,
} from './Dashboard';

describe('container presentation', () => {
  const containers: ContainerStatus[] = [
    { name: 'sso', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1.2, memoryBytes: 10_000, memoryPercent: 1 },
    { name: 'sso-redis', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 2.3, memoryBytes: 20_000, memoryPercent: 2 },
    { name: 'feelmyrythm-frontend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 3.4, memoryBytes: 30_000, memoryPercent: 3 },
    { name: 'feelmyrythm-backend', owner: 'cks', state: 'running', health: 'unhealthy', cpuPercent: 4.5, memoryBytes: 40_000, memoryPercent: 4 },
    { name: 'feelmyrythm-redis', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 5.6, memoryBytes: 50_000, memoryPercent: 5 },
    { name: 'multtara-backend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 5.7, memoryBytes: 51_000, memoryPercent: 5.1 },
    { name: 'multtara-collector', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 5.8, memoryBytes: 52_000, memoryPercent: 5.2 },
    { name: 'multtara-database', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 5.9, memoryBytes: 53_000, memoryPercent: 5.3 },
    { name: 'multtara-frontend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 6, memoryBytes: 54_000, memoryPercent: 5.4 },
    { name: 'pilgrimage-frontend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 6.7, memoryBytes: 60_000, memoryPercent: 6 },
    { name: 'pilgrimage-backend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 7.8, memoryBytes: 70_000, memoryPercent: 7 },
    { name: 'pilgrimage-redis', owner: 'cks', state: 'exited', health: 'none', cpuPercent: null, memoryBytes: null, memoryPercent: null },
    { name: 'bonifacio', owner: 'cks', state: 'paused', health: 'unknown', cpuPercent: null, memoryBytes: null, memoryPercent: null },
  ];

  it('separates running entries from stopped or other entries and retains the total', () => {
    expect(containerSummaryLabel(containers)).toBe('11 running · 2 stopped/other · 13 tracked total · 1 unhealthy');
  });

  it('renders each final backend service name without legacy or removed names', () => {
    const markup = renderToStaticMarkup(createElement(ContainerList, { containers }));

    expect(markup).toContain('>bonifacio</strong>');
    expect(markup).toContain('>sso</strong>');
    expect(markup).toContain('>sso-redis</strong>');
    expect(markup).toContain('>feelmyrythm-frontend</strong>');
    expect(markup).toContain('>feelmyrythm-backend</strong>');
    expect(markup).toContain('>feelmyrythm-redis</strong>');
    expect(markup).toContain('>multtara-backend</strong>');
    expect(markup).toContain('>multtara-collector</strong>');
    expect(markup).toContain('>multtara-database</strong>');
    expect(markup).toContain('>multtara-frontend</strong>');
    expect(markup).toContain('>pilgrimage-frontend</strong>');
    expect(markup).toContain('>pilgrimage-backend</strong>');
    expect(markup).toContain('>pilgrimage-redis</strong>');
    expect(markup).not.toContain('sso-admin');
    expect(markup).not.toContain('bonifacio-web');
  });
});

describe('power presentation helpers', () => {
  it('keeps the full uint32 flag range unsigned', () => {
    const decoded = decodeThrottledFlags(0xffff_ffff);

    expect(decoded.available).toBe(true);
    expect(formatFlags(0xffff_ffff)).toBe('0xffffffff');
    expect(decoded.active).toContain('Unknown active bits 0x0000fff0');
    expect(decoded.historical).toContain('Unknown historical bits 0xfff00000');
    expect(decoded.historical).not.toContain(expect.stringContaining('Unavailable'));
  });

  it('uses event severity without painting active warnings as healthy', () => {
    expect(eventStatusTone('warning', 'active')).toBe('warn');
    expect(eventStatusTone('critical', 'active')).toBe('critical');
    expect(eventStatusTone('info', 'recovered')).toBe('good');
    expect(eventStatusTone('critical', 'abnormal')).toBe('critical');
  });

  it('treats high-bit-only history as currently normal', () => {
    expect(currentPowerStatusTone(0x1_0000, 'degraded-history')).toBe('good');
    expect(currentPowerStatusTone(0x1, 'under-voltage')).toBe('warn');
    expect(currentPowerStatusTone(0, null)).toBe('good');
  });

  it('keeps an explicit bad state visible when zero flags disagree', () => {
    expect(currentPowerStatusTone(0, 'under-voltage')).toBe('warn');
    expect(currentPowerStatusTone(0, 'throttled')).toBe('warn');
    expect(currentPowerStatusTone(0, 'thermal-limit')).toBe('warn');
    expect(currentPowerStatusTone(0, 'frequency-capped')).toBe('warn');
    expect(currentPowerStatusTone(0, 'critical')).toBe('critical');
  });
});

describe('incident timeline', () => {
  const incident: PeakIncident = {
    id: 'peak-20260822-183602',
    startedAt: '2026-08-22T09:34:58Z',
    observedAt: '2026-08-22T09:36:02Z',
    endedAt: '2026-08-22T09:40:21Z',
    phase: 'recovered',
    reasons: ['cpu', 'disk-io'],
    durationSeconds: 323,
    metrics: {
      timestamp: '2026-08-22T09:36:02Z',
      cpuPercent: 91.2,
      memoryPercent: 75.4,
      memoryUsedBytes: 4_294_967_296,
      memoryTotalBytes: 8_589_934_592,
      temperatureC: 79.5,
      load1: 7.4,
      load5: 4.2,
      load15: 2.1,
      powerState: 'normal',
      supplyVoltageVolts: 5.03,
      throttledFlags: 0,
      gpuMemoryBytes: null,
      gpuClockHz: null,
      networkRxBytesPerSecond: 12_000,
      networkTxBytesPerSecond: 8_000,
      diskReadBytesPerSecond: 15_000_000,
      diskWriteBytesPerSecond: 3_000_000,
    },
    peaks: {
      cpuPercent: 96.4,
      memoryPercent: 78.2,
      temperatureC: 81.3,
      load1: 11.66,
    },
    pressure: {
      cpu: { someAvg10: 3.14, fullAvg10: 0 },
      memory: { someAvg10: 0.25, fullAvg10: 0.04 },
      io: { someAvg10: 12.5, fullAvg10: 7.25 },
    },
    processes: [{ name: 'node', instances: 2, cpuPercent: 84.3, memoryBytes: 1_073_741_824 }],
    containers: [{ name: 'allowed-api', owner: 'portfolio', state: 'running', health: 'healthy', cpuPercent: 71.4, memoryBytes: 536_870_912, memoryPercent: 6.25 }],
    traffic: [{ app: 'Bonifacio', requestCount: 42, status2xx: 36, status3xx: 1, status4xx: 3, status5xx: 2, slowCount: 4, avgResponseMs: 120, maxResponseMs: 1_450 }],
  };

  it('renders correlated peaks and sanitized evidence groups', () => {
    const markup = renderToStaticMarkup(createElement(IncidentTimeline, { incidents: [incident] }));

    expect(markup).toContain('High CPU usage');
    expect(markup).toContain('High disk I/O');
    expect(markup).toContain('96.4%');
    expect(markup).toContain('78.2%');
    expect(markup).toContain('81.3°C');
    expect(markup).toContain('node');
    expect(markup).toContain('2 instances');
    expect(markup).toContain('Fixed executable classes · no argv or IDs');
    expect(markup).toContain('allowed-api');
    expect(markup).toContain('42 requests this capture');
    expect(markup).toContain('5xx 2');
    expect(markup).toContain('120 ms average');
    expect(markup).toContain('42 requests in this capture interval · not visitors');
    expect(markup).toContain('This capture interval only · request counts, not visitors or client identifiers');
  });

  it('describes an unresolved historical snapshot as open at that capture', () => {
    const unresolved: PeakIncident = {
      ...incident,
      endedAt: null,
      phase: 'follow-up',
      durationSeconds: undefined,
    };
    const markup = renderToStaticMarkup(createElement(IncidentTimeline, { incidents: [unresolved] }));

    expect(markup).toContain('Open at this capture');
    expect(markup).not.toContain('Capture window still open');
  });

  it('renders a positive empty state when no incident was captured', () => {
    const markup = renderToStaticMarkup(createElement(IncidentTimeline, { incidents: [] }));

    expect(markup).toContain('No peak incidents captured in this range');
    expect(markup).toContain('inline-empty positive');
  });
});
