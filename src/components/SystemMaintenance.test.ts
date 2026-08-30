import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { SystemStatus } from '../types';
import { bootloaderVersionTone, kernelVersionTone, SystemMaintenance } from './SystemMaintenance';

function system(overrides: Partial<SystemStatus['versions']> = {}): SystemStatus {
  const emptyEvent = { count: 0, lastEventAt: null };
  return {
    versions: {
      kernelRunning: '6.8.0-1062-raspi',
      kernelLatestInstalled: '6.8.0-1062-raspi',
      kernelRebootRequired: false,
      bootloaderCurrent: '2025-12-08',
      bootloaderLatest: '2025-12-08',
      bootloaderChannel: 'stable',
      nvmeModel: 'NE-256 2242',
      nvmeFirmware: 'SN25845',
      collector: '3',
      ...overrides,
    },
    pcie: {
      configuredGeneration: 1,
      negotiatedGeneration: 1,
      negotiatedSpeedGtps: 2.5,
      negotiatedWidth: 1,
      endpointMaxGeneration: 4,
      endpointMaxWidth: 4,
      aspmDisabled: true,
      nvmePowerSavingDisabled: true,
      aerCorrectableCount: 0,
      aerNonFatalCount: 0,
      aerFatalCount: 0,
      correctableStatusActive: false,
      nonFatalStatusActive: false,
      fatalStatusActive: false,
    },
    kernel: {
      warning: emptyEvent,
      oops: emptyEvent,
      panic: emptyEvent,
      hungTask: emptyEvent,
      rcuStall: emptyEvent,
      rcuExpedited: emptyEvent,
      oomKill: emptyEvent,
      filesystemError: emptyEvent,
      nvmeReset: emptyEvent,
      nvmeIo: emptyEvent,
      pcieAerCorrectable: emptyEvent,
      pcieAerNonFatal: emptyEvent,
      pcieAerFatal: emptyEvent,
    },
  };
}

describe('system maintenance presentation', () => {
  it('reports current versions and renders the bounded update placeholder', () => {
    const current = system();
    expect(kernelVersionTone(current)).toBe('ok');
    expect(bootloaderVersionTone(current)).toBe('ok');

    const markup = renderToStaticMarkup(createElement(SystemMaintenance, {
      system: current,
      generatedAt: '2026-08-27T06:00:00Z',
      locale: 'ko',
    }));
    expect(markup).toContain('6.8.0-1062-raspi');
    expect(markup).toContain('2025-12-08');
    expect(markup).toContain('NE-256 2242');
    expect(markup).toContain('SN25845');
    expect(markup).toContain('업데이트 확인');
    expect(markup).toContain('disabled=""');
  });

  it('marks a newer installed kernel and bootloader as pending', () => {
    const pending = system({
      kernelLatestInstalled: '6.8.0-1063-raspi',
      kernelRebootRequired: true,
      bootloaderLatest: '2026-01-15',
    });
    expect(kernelVersionTone(pending)).toBe('caution');
    expect(bootloaderVersionTone(pending)).toBe('caution');
  });

  it('accepts authorized update controls without changing the version panel', () => {
    const markup = renderToStaticMarkup(createElement(SystemMaintenance, {
      system: system(),
      generatedAt: '2026-08-27T06:00:00Z',
      locale: 'en',
      updateControls: createElement('button', { type: 'button' }, 'Run authorized check'),
    }));
    expect(markup).toContain('Run authorized check');
    expect(markup).toContain('System versions');
    expect(markup).not.toContain('Secure update controls are being connected');
  });
});
