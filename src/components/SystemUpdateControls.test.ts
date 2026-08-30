import { describe, expect, it } from 'vitest';
import { confirmationMatchesPlan, updateCategoryCounts, updateStateTone } from './SystemUpdateControls';

describe('system update presentation', () => {
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
