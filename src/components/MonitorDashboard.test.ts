import { describe, expect, it } from 'vitest';
import type { DashboardPayload } from '../types';
import { createOverviewDashboardItems } from './MonitorDashboard';

describe('monitor overview composition', () => {
  it('keeps every established chart widget in the home dashboard', () => {
    const items = createOverviewDashboardItems(
      {} as DashboardPayload,
      'ko',
      '24h',
      () => undefined,
    );

    expect(items.map((item) => item.id)).toEqual([
      'vitals',
      'resources',
      'load',
      'network',
      'storage',
      'containers',
      'power',
      'headroom',
      'reliability',
      'incidents',
      'events',
    ]);
    expect(items.find((item) => item.id === 'reliability')?.layout).toMatchObject({
      h: 5,
      minH: 4,
      maxH: 8,
    });
  });
});
