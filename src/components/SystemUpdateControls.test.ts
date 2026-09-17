import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { SystemUpdateStatus } from '../api';
import type { SystemStatus } from '../types';
import { currentRebootRequirement, updateCheckIsFresh } from '../system-maintenance';
import { confirmationMatchesPlan, LiveRebootNotice, UpdateStatusSummary, updateCategoryCounts, updateStateTone } from './SystemUpdateControls';

describe('system update presentation', () => {
  const now = Date.parse('2026-09-13T07:00:00Z');

  it('makes old, invalid, and future update checks visibly historical', () => {
    expect(updateCheckIsFresh('2026-09-12T07:00:00Z', now)).toBe(true);
    expect(updateCheckIsFresh('2026-09-12T06:59:59Z', now)).toBe(false);
    for (const state of ['available', 'up-to-date', 'succeeded'] as const) {
      for (const checkedAt of ['2026-09-01T00:00:00Z', 'invalid', null, '2026-09-13T07:00:01Z']) {
        const status = { state, checkedAt } as SystemUpdateStatus;
        const markup = renderToStaticMarkup(createElement(UpdateStatusSummary, { status, locale: 'en', nowMs: now }));
        expect(markup).toContain('Update information is stale');
        expect(markup).toContain('list and counts below are historical');
        expect(markup).not.toContain('<h3>Up to date');
        expect(markup).not.toContain('<h3>Updates available');
      }
    }
    const status = { state: 'up-to-date', checkedAt: '2026-09-13T06:00:00Z' } as SystemUpdateStatus;
    const fresh = renderToStaticMarkup(createElement(UpdateStatusSummary, { status, locale: 'en', nowMs: now }));
    expect(fresh).toContain('<h3>Up to date</h3>');
    expect(fresh).not.toContain('historical');
  });

  it('uses current host observations for reboot instead of old updater flags', () => {
    const system = {
      versions: { kernelRunning: '6.8', kernelLatestInstalled: '6.8', kernelRebootRequired: false },
      reboot: { status: 'ok', required: true, observedAt: '2026-09-13T07:00:00Z', packages: ['libc6'], packagesStatus: 'ok', packagesTruncated: false },
    } as SystemStatus;
    expect(currentRebootRequirement(system, false, now)).toBe(true);
    const pending = renderToStaticMarkup(createElement(LiveRebootNotice, { system, locale: 'en', nowMs: now }));
    expect(pending).toContain('requires a reboot');
    system.reboot!.required = false;
    const clear = renderToStaticMarkup(createElement(LiveRebootNotice, { system, locale: 'en', nowMs: now }));
    expect(clear).toBe('');
    expect(currentRebootRequirement(system, true, now)).toBeNull();
    expect(currentRebootRequirement(system, false, now + 6 * 60_000)).toBeNull();
    delete system.reboot;
    const unknown = renderToStaticMarkup(createElement(LiveRebootNotice, { system, locale: 'en', nowMs: now }));
    expect(unknown).toContain('Current reboot status is unknown');
    system.versions.kernelLatestInstalled = '6.9';
    expect(currentRebootRequirement(system, false, now)).toBe(true);
  });
  it('maps operational states to stable tones', () => {
    expect(updateStateTone(null)).toBe('unknown');
    expect(updateStateTone('idle')).toBe('unknown');
    expect(updateStateTone('checking')).toBe('caution');
    expect(updateStateTone('available')).toBe('caution');
    expect(updateStateTone('applying')).toBe('caution');
    expect(updateStateTone('up-to-date')).toBe('ok');
    expect(updateStateTone('succeeded')).toBe('ok');
    expect(updateStateTone('failed')).toBe('danger');
    expect(updateStateTone('interrupted')).toBe('danger');
  });

  it('counts bounded package impact categories without deriving package names', () => {
    expect(updateCategoryCounts([
      { category: 'kernel' },
      { category: 'kernel' },
      { category: 'firmware' },
      { category: 'container-runtime' },
      { category: 'network' },
      { category: 'core-system' },
      { category: 'other' },
    ])).toEqual({
      kernel: 2,
      firmware: 1,
      'container-runtime': 1,
      network: 1,
      'core-system': 1,
      other: 1,
    });
  });

  it('invalidates human confirmation whenever polling replaces the reviewed plan', () => {
    const first = 'a'.repeat(64);
    const second = 'b'.repeat(64);
    expect(confirmationMatchesPlan(first, first)).toBe(true);
    expect(confirmationMatchesPlan(first, second)).toBe(false);
    expect(confirmationMatchesPlan(first, null)).toBe(false);
    expect(confirmationMatchesPlan(null, first)).toBe(false);
  });
});
