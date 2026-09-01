import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { LinuxCollectionStatus, LinuxDiagnostics } from '../types';
import { LinuxDiagnosticsPanel } from './LinuxDiagnostics';

function capacity(status: LinuxCollectionStatus, current = 10, maximum = 100) {
  return { status, current, maximum, usedPercent: 10 };
}

function fixture(status: LinuxCollectionStatus = 'supported'): LinuxDiagnostics {
  return {
    schemaVersion: status === 'collection_error' ? null : 1,
    collectedAt: status === 'collection_error' ? null : '2026-08-30T12:00:00.000Z',
    status,
    resources: {
      status,
      processCount: 120,
      processCountIsLowerBound: false,
      observedProcessCount: 119,
      zombieCount: 2,
      threadCount: 450,
      scanTruncated: false,
      deadlineReached: false,
      pid: capacity(status, 120, 4_194_304),
      systemFileDescriptors: capacity(status, 900, 10_000),
      cgroupPids: { ...capacity(status, 120, 1000), version: 2 },
    },
    storage: {
      status,
      truncated: false,
      devices: [{
        name: 'sda',
        type: 'sata',
        rotational: false,
        rateStatus: 'ok',
        queueDepth: 2,
        readLatencyMilliseconds: 2.5,
        writeLatencyMilliseconds: 4,
        averageLatencyMilliseconds: 3.25,
        utilizationPercent: 62.5,
        averageQueueDepth: 0.75,
        smartStatus: 'unsupported',
        raidStatus: 'unsupported',
        raidDegradedDevices: null,
        raidArrayState: null,
      }],
    },
    network: {
      status,
      tcp: {
        status,
        rateStatus: 'ok',
        outgoingSegmentsPerSecond: 100,
        retransmittedSegmentsPerSecond: 2,
        retransmissionPercent: 2,
        states: {
          established: 20,
          synSent: 1,
          synRecv: 2,
          finWait1: 3,
          finWait2: 4,
          timeWait: 5,
          close: 6,
          closeWait: 7,
          lastAck: 8,
          listen: 9,
          closing: 10,
          newSynRecv: 11,
        },
        socketScanStatus: status,
        socketScanTruncated: false,
        ephemeralPorts: {
          ...capacity(status, 120, 28_232),
          rangeStart: 32_768,
          rangeEnd: 60_999,
        },
        conntrack: capacity(status, 250, 1000),
      },
    },
    reliability: {
      status,
      clock: {
        status,
        uptimeSeconds: 3600,
        bootTime: '2026-08-30T11:00:00.000Z',
        rebootDetectedSincePreviousSample: false,
        unexpectedReboot: null,
        unexpectedRebootStatus: 'not_inferable_from_local_counters',
        timeSync: {
          status,
          reason: null,
          synchronized: true,
          ntpEnabled: true,
          ntpSupported: true,
          clockDriftMilliseconds: null,
          clockDriftStatus: 'unsupported',
        },
      },
      systemd: {
        status,
        reason: null,
        truncated: false,
        units: [{
          unit: 'monitor-collector.service',
          loadState: 'loaded',
          activeState: 'active',
          subState: 'running',
          restartCount: 2,
          restartCountStatus: 'systemd_manager',
          result: 'success',
          execMainStatus: 0,
          invocationStatus: null,
        }],
      },
    },
    power: {
      status,
      truncated: false,
      maximumTemperatureCelsius: 55,
      sensors: [{
        source: 'thermal-zone',
        name: 'cpu-thermal',
        status,
        temperatureCelsius: 55,
      }],
      fans: [{ name: 'case-fan', status, rpm: 3200 }],
      raspberryPi: {
        status,
        detected: true,
        temperatureCelsius: 55,
        supplyVoltageVolts: 4.9,
        throttledFlags: 327685,
        currentUnderVoltage: true,
        currentFrequencyCapped: false,
        currentThrottled: true,
        currentSoftTemperatureLimit: false,
        underVoltageOccurred: true,
        frequencyCapOccurred: false,
        throttlingOccurred: true,
        softTemperatureLimitOccurred: false,
        flagSource: 'vcgencmd',
      },
    },
  };
}

function render(page: 'resources' | 'network' | 'storage' | 'reliability' | 'power', linux = fixture()) {
  return renderToStaticMarkup(createElement(LinuxDiagnosticsPanel, { linux, page, locale: 'en' }));
}

describe('Linux diagnostics detail panels', () => {
  it.each([
    ['supported', 'Supported'],
    ['partial', 'Partial'],
    ['unsupported', 'Unsupported'],
    ['permission_error', 'Permission error'],
    ['unavailable', 'Unavailable'],
    ['invalid', 'Invalid data'],
    ['collection_error', 'Collection error'],
  ] as const)('keeps %s visually and textually distinct', (status, label) => {
    const markup = render('resources', fixture(status));
    expect(markup).toContain(`data-linux-status="${status}"`);
    expect(markup).toContain(label);
  });

  it('uses an accessible labelled section and compact definition lists, not a raw table', () => {
    const markup = render('network');
    expect(markup).toContain('aria-labelledby="linux-network-diagnostics-heading"');
    expect(markup).toContain('id="linux-network-diagnostics-heading"');
    expect(markup).toContain('role="status"');
    expect(markup).toContain('<dl>');
    expect(markup).not.toContain('<table');
    expect(markup).toContain('TCP retransmission');
    expect(markup).toContain('2%');
    for (const state of [
      'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT',
      'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'CLOSING', 'NEW_SYN_RECV',
    ]) expect(markup).toContain(`<dt>${state}</dt>`);
    expect(markup).toContain('Conntrack headroom');
    expect(markup).toContain('Ephemeral port headroom');
    expect(markup).toContain('Next action');
  });

  it('renders storage latency, utilization, queue, and evidence source without a wide table', () => {
    const markup = render('storage');
    expect(markup).toContain('sda · sata');
    expect(markup).toContain('Read · write latency');
    expect(markup).toContain('Average latency · utilization');
    expect(markup).toContain('Current · average queue');
    expect(markup).toContain('<dt>Rotational device</dt><dd>No</dd>');
    expect(markup).toContain('<dt>RAID degraded devices</dt><dd>—</dd>');
    expect(markup).toContain('<dt>Collection truncated</dt><dd>No</dd>');
    expect(markup).toContain('SMART Unsupported · RAID Unsupported');
    expect(markup).not.toContain('<table');
  });

  it('keeps every bounded storage device reachable and reports truncation and RAID degradation', () => {
    const linux = fixture();
    const base = linux.storage.devices[0];
    linux.storage.truncated = true;
    linux.storage.devices = Array.from({ length: 10 }, (_, index) => ({
      ...base,
      name: `device-${index + 1}`,
      rotational: index % 2 === 0,
      raidDegradedDevices: index === 0 ? 2 : 0,
    }));
    const markup = render('storage', linux);

    expect(markup).toContain('device-8');
    expect(markup).not.toContain('device-9');
    expect(markup).toContain('1–8 of 10 diagnostics');
    expect(markup).toContain('<dt>Collection truncated</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>RAID degraded devices</dt><dd>2</dd>');
  });

  it('does not present empty or contract-error collection as a healthy zero', () => {
    const linux = fixture('collection_error');
    linux.storage.devices = [];
    const markup = render('storage', linux);
    expect(markup).toContain('Collection error');
    expect(markup).toContain('Block device diagnostics');
    expect(markup).toContain('Align the collector v1 and server contracts');
    expect(markup).not.toContain('Healthy');
  });

  it('shows clock, reboot, and allow-listed systemd restart/result evidence', () => {
    const linux = fixture();
    const base = linux.reliability.systemd.units[0];
    linux.reliability.systemd.truncated = true;
    linux.reliability.systemd.units = Array.from({ length: 5 }, (_, index) => ({
      ...base,
      unit: `observed-${index + 1}.service`,
      execMainStatus: index,
      invocationStatus: index === 4 ? 'partial' : null,
    }));
    const markup = render('reliability', linux);
    expect(markup).toContain('Clock synchronization');
    expect(markup).toContain('<dt>NTP supported</dt><dd>Yes</dd>');
    expect(markup).toContain('Boot continuity');
    expect(markup).toContain('<dt>Uptime</dt><dd>1h 0m (3,600 s)</dd>');
    expect(markup).toContain('Allow-listed systemd units');
    expect(markup).toContain('<dt>Collection truncated</dt><dd>Yes</dd>');
    expect(markup).toContain('observed-5.service');
    expect(markup).toContain('<dt>Load state</dt><dd>loaded</dd>');
    expect(markup).toContain('<dt>Active state</dt><dd>active</dd>');
    expect(markup).toContain('<dt>Sub-state</dt><dd>running</dd>');
    expect(markup).toContain('<dt>Restart count</dt><dd>2</dd>');
    expect(markup).toContain('<dt>Restart count source</dt><dd>systemd_manager</dd>');
    expect(markup).toContain('<dt>Result</dt><dd>success</dd>');
    expect(markup).toContain('<dt>ExecMainStatus</dt><dd>4</dd>');
    expect(markup).toContain('<dt>Invocation status</dt><dd>Partial</dd>');
  });

  it('shows thermal sources, fan evidence, Raspberry Pi flags, and their source', () => {
    const markup = render('power');
    expect(markup).toContain('Temperature sensor · cpu-thermal');
    expect(markup).toContain('<dt>Source</dt><dd>thermal-zone</dd>');
    expect(markup).toContain('Fan · case-fan');
    expect(markup).toContain('<dt>RPM</dt><dd>3,200</dd>');
    expect(markup).toContain('Raspberry Pi power and throttling');
    expect(markup).toContain('vcgencmd');
    expect(markup).toContain('<dt>Throttled flags</dt><dd>327,685 (0x50005)</dd>');
    expect(markup).toContain('<dt>Current undervoltage</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Current frequency cap</dt><dd>No</dd>');
    expect(markup).toContain('<dt>Current throttling</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Current soft temperature limit</dt><dd>No</dd>');
    expect(markup).toContain('<dt>Undervoltage occurred</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Frequency cap occurred</dt><dd>No</dd>');
    expect(markup).toContain('<dt>Throttling occurred</dt><dd>Yes</dd>');
    expect(markup).toContain('<dt>Soft temperature limit occurred</dt><dd>No</dd>');
  });

  it('renders every collected sensor and fan instead of silently slicing their arrays', () => {
    const sensors = fixture();
    const baseSensor = sensors.power.sensors[0];
    sensors.power.sensors = Array.from({ length: 4 }, (_, index) => ({
      ...baseSensor,
      name: `thermal-${index + 1}`,
      temperatureCelsius: 50 + index,
    }));
    const sensorMarkup = render('power', sensors);
    expect(sensorMarkup).toContain('thermal-4');
    expect(sensorMarkup).toContain('<dt>Temperature</dt><dd>53°C</dd>');
    expect(sensorMarkup).toContain('<dt>Collection status</dt><dd>Supported</dd>');

    const fans = fixture();
    const baseFan = fans.power.fans[0];
    fans.power.fans = Array.from({ length: 4 }, (_, index) => ({
      ...baseFan,
      name: `fan-${index + 1}`,
      rpm: 3000 + index,
    }));
    const fanMarkup = render('power', fans);
    expect(fanMarkup).toContain('fan-4');
    expect(fanMarkup).toContain('<dt>RPM</dt><dd>3,003</dd>');
    expect(fanMarkup).toContain('<dt>Collection status</dt><dd>Supported</dd>');
  });

  it('keeps diagnostic cards responsive at the narrow breakpoint', () => {
    const css = readFileSync(fileURLToPath(new URL('../monitor-dashboard.css', import.meta.url)), 'utf8');
    expect(css).toMatch(/\.linux-diagnostics\s*\{[^}]*grid-column:\s*1\s*\/\s*-1/s);
    expect(css).toMatch(/@media \(max-width: 560px\)[\s\S]*?\.linux-diagnostic-grid\s*\{\s*grid-template-columns:\s*1fr;/);
    expect(css).toMatch(/@media \(max-width: 560px\)[\s\S]*?\.linux-diagnostics-header\s*\{[^}]*flex-direction:\s*column;/);
  });
});
