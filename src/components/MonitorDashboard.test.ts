import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SessionInfo } from '../api';
import type { DashboardPayload } from '../types';
import { createOverviewDashboardItems, MonitorDashboard } from './MonitorDashboard';

afterEach(() => {
  vi.unstubAllGlobals();
});

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

  it('puts operating status first and names mobile icon controls', () => {
    vi.stubGlobal('window', {
      localStorage: { getItem: () => 'en', setItem: () => undefined },
      location: { search: '' },
    });
    vi.stubGlobal('navigator', { languages: ['en-US'] });
    const viewer: SessionInfo = {
      authenticated: true,
      mode: 'local',
      user: 'operator',
      role: 'admin',
      permissions: [],
    };

    const markup = renderToStaticMarkup(createElement(MonitorDashboard, {
      page: 'overview',
      navigationVersion: 0,
      onNavigate: () => undefined,
      onLogout: async () => undefined,
      onPasswordChanged: () => undefined,
      onUnauthorized: () => undefined,
      viewer,
    }));

    expect(markup).toContain('class="control-skip-link" href="#monitor-main"');
    expect(markup).toContain('<main id="monitor-main" class="control-main" tabindex="-1">');
    expect(markup).toContain('aria-label="Overview"');
    expect(markup).toContain('aria-label="Change password"');
    expect(markup).toContain('aria-label="Sign out"');
    expect(markup).toContain('class="system-strip');
  });

  it('keeps operational evidence above the dashboard and restores the mobile traffic table as a scroller', () => {
    const css = readFileSync(new URL('../monitor-dashboard.css', import.meta.url), 'utf8');
    const source = readFileSync(new URL('./MonitorDashboard.tsx', import.meta.url), 'utf8');
    const overviewComposition = source.slice(source.lastIndexOf('return (\n    <div className="control-room"'));

    expect(css).toMatch(/\.current-traffic-table\.table-wrap\s*\{[^}]*display: block;[^}]*overflow-x: auto;/s);
    expect(overviewComposition.indexOf('<OperationalHealthOverview')).toBeLessThan(overviewComposition.indexOf('<RuleHealthSummary'));
    expect(overviewComposition.indexOf('<RuleHealthSummary')).toBeLessThan(overviewComposition.indexOf('<AdaptiveGrid'));
  });

  it('routes the logs page directly to the generic log actions without telemetry-only controls', () => {
    vi.stubGlobal('window', {
      localStorage: { getItem: () => 'en', setItem: () => undefined },
      location: { search: '?range=24h' },
    });
    vi.stubGlobal('navigator', { languages: ['en-US'] });
    const viewer: SessionInfo = {
      authenticated: true,
      mode: 'local',
      user: 'operator',
      role: 'admin',
      permissions: [],
    };

    const markup = renderToStaticMarkup(createElement(MonitorDashboard, {
      page: 'logs',
      navigationVersion: 0,
      onNavigate: () => undefined,
      onLogout: async () => undefined,
      onPasswordChanged: () => undefined,
      onUnauthorized: () => undefined,
      viewer,
    }));

    expect(markup).toContain('Search generic logs');
    expect(markup).toContain('aria-label="Generic log filters"');
    expect(markup).not.toContain('Explore all events');
    expect(markup).not.toContain('class="range-selector"');
    expect(markup).not.toContain('Loading instruments');
  });
});
