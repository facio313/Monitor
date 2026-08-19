import { describe, expect, it } from 'vitest';
import { currentPowerStatusTone, decodeThrottledFlags, eventStatusTone, formatFlags } from './Dashboard';

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
