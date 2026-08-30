import { describe, expect, it } from 'vitest';
import { responsivePageSize } from './responsive-page-size';

describe('responsive page sizing', () => {
  it('bounds dense content more aggressively as the viewport narrows', () => {
    const sizes = { desktop: 12, tablet: 8, phone: 6, narrowPhone: 4 };
    expect(responsivePageSize(1440, sizes)).toBe(12);
    expect(responsivePageSize(1024, sizes)).toBe(8);
    expect(responsivePageSize(640, sizes)).toBe(6);
    expect(responsivePageSize(360, sizes)).toBe(4);
  });
});
