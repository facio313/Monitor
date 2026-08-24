import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { ContainerStatus, PeakIncident } from '../types';
import {
  ContainerList,
  containerNameParts,
  containerSummaryLabel,
  currentPowerStatusTone,
  decodeThrottledFlags,
  eventStatusTone,
  formatFlags,
  groupContainers,
  IncidentTimeline,
  nextContainerGroupExpansion,
  nextContainerSort,
  sortContainers,
  toggleContainerGroupExpansion,
} from './Dashboard';

describe('container presentation', () => {
  const containers: ContainerStatus[] = [
    { name: 'sso', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1.2, memoryBytes: 10_000, memoryPercent: 1 },
    { name: 'sso-redis', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 2.3, memoryBytes: 20_000, memoryPercent: 2 },
    { name: 'blog-backend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 2.4, memoryBytes: 21_000, memoryPercent: 2.1 },
    { name: 'blog-frontend', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 2.5, memoryBytes: 22_000, memoryPercent: 2.2 },
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
    { name: 'cks-database', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 0.8, memoryBytes: 80_000, memoryPercent: 8 },
    { name: 'monitor', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 0.9, memoryBytes: 81_000, memoryPercent: 8.1 },
    { name: 'react', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1, memoryBytes: 82_000, memoryPercent: 8.2 },
    { name: 'vue', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1.1, memoryBytes: 83_000, memoryPercent: 8.3 },
    { name: 'dukkeobi', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1.2, memoryBytes: 84_000, memoryPercent: 8.4 },
    { name: 'ddit-finalproject', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1.3, memoryBytes: 85_000, memoryPercent: 8.5 },
  ];

  it('separates running entries from stopped or other entries and retains the total', () => {
    expect(containerSummaryLabel(containers)).toBe('19 running · 2 stopped/other · 21 tracked total · 1 unhealthy');
  });

  it('uses the requested grouped default order before sorting the remaining names', () => {
    const originalNames = containers.map((container) => container.name);
    const names = sortContainers(containers).map((container) => container.name);

    expect(names).toEqual([
      'bonifacio',
      'sso',
      'sso-redis',
      'cks-database',
      'monitor',
      'blog-frontend',
      'blog-backend',
      'ddit-finalproject',
      'dukkeobi',
      'feelmyrythm-frontend',
      'feelmyrythm-backend',
      'feelmyrythm-redis',
      'multtara-frontend',
      'multtara-backend',
      'multtara-database',
      'multtara-collector',
      'pilgrimage-frontend',
      'pilgrimage-backend',
      'pilgrimage-redis',
      'react',
      'vue',
    ]);
    expect(containers.map((container) => container.name)).toEqual(originalNames);
  });

  it('orders application components by role and parses only exact known suffixes', () => {
    const componentNames = ['sample-collector', 'sample-redis', 'sample-database', 'sample-backend', 'sample-frontend'];
    const componentContainers = componentNames.map((name) => ({
      name,
      owner: 'cks',
      state: 'running',
      health: 'healthy',
      cpuPercent: 0,
      memoryBytes: 0,
      memoryPercent: 0,
    }));

    expect(sortContainers(componentContainers).map(({ name }) => name)).toEqual([
      'sample-frontend',
      'sample-backend',
      'sample-database',
      'sample-redis',
      'sample-collector',
    ]);
    expect(containerNameParts('team-blue-frontend')).toEqual({ application: 'team-blue', component: 'frontend' });
    expect(containerNameParts('sample-db')).toEqual({ application: 'sample', component: 'db' });
    expect(containerNameParts(`${'long-app-'.repeat(10)}frontend`).component).toBe('frontend');
    expect(containerNameParts('cks-database')).toEqual({ application: 'cks-database', component: null });
    expect(containerNameParts('redis-backup')).toEqual({ application: 'redis-backup', component: null });
  });

  it('builds aggregate service parents while keeping components ordered and input immutable', () => {
    const original = structuredClone(containers);
    const groups = groupContainers(containers);

    expect(groups.map((group) => group.application)).toEqual([
      'bonifacio',
      'sso',
      'cks-database',
      'monitor',
      'blog',
      'ddit-finalproject',
      'dukkeobi',
      'feelmyrythm',
      'multtara',
      'pilgrimage',
      'react',
      'vue',
    ]);

    const sso = groups.find((group) => group.application === 'sso');
    expect(sso).toMatchObject({ grouped: true, runningCount: 2, tone: 'good' });
    expect(sso?.children.map((child) => child.component)).toEqual(['main', 'redis']);
    expect(sso?.aggregate).toMatchObject({
      name: 'sso', state: '2/2 running', health: 'healthy', cpuPercent: 3.5,
      memoryBytes: 30_000, memoryPercent: null,
    });
    expect(sso?.key).not.toBe(sso?.children[0].key);

    const feelmyrythm = groups.find((group) => group.application === 'feelmyrythm');
    expect(feelmyrythm?.children.map((child) => child.component)).toEqual(['frontend', 'backend', 'redis']);
    expect(feelmyrythm).toMatchObject({ grouped: true, runningCount: 3, tone: 'critical' });
    expect(feelmyrythm?.aggregate).toMatchObject({
      name: 'feelmyrythm', owner: 'cks', state: '3/3 running', health: '1 unhealthy',
      cpuPercent: 13.5, memoryBytes: 120_000, memoryPercent: null,
    });

    const pilgrimage = groups.find((group) => group.application === 'pilgrimage');
    expect(pilgrimage).toMatchObject({ grouped: true, runningCount: 2, tone: 'critical' });
    expect(pilgrimage?.aggregate).toMatchObject({
      state: '2/3 running', health: '2 healthy · 1 not checked', cpuPercent: 14.5,
      memoryBytes: 130_000, memoryPercent: null,
    });
    expect(groups.find((group) => group.application === 'bonifacio')).toMatchObject({ grouped: false });
    expect(containers).toEqual(original);
  });

  it('does not publish a partial aggregate when a running child metric is unavailable', () => {
    const unavailable = containers.map((container) => container.name === 'feelmyrythm-backend'
      ? { ...container, cpuPercent: null, memoryBytes: null }
      : container);
    const feelmyrythm = groupContainers(unavailable).find((group) => group.application === 'feelmyrythm');

    expect(feelmyrythm?.aggregate.cpuPercent).toBeNull();
    expect(feelmyrythm?.aggregate.memoryBytes).toBeNull();

    const paused = containers.map((container) => container.name === 'sso'
      ? { ...container, state: 'paused', cpuPercent: null, memoryBytes: null }
      : container);
    const sso = groupContainers(paused).find((group) => group.application === 'sso');
    expect(sso?.aggregate.cpuPercent).toBeNull();
    expect(sso?.aggregate.memoryBytes).toBeNull();

    const stopped = containers
      .filter((container) => container.name === 'sso' || container.name === 'sso-redis')
      .map((container) => ({
        ...container,
        state: 'exited',
        health: 'none',
        cpuPercent: null,
        memoryBytes: null,
        memoryPercent: null,
      }));
    const stoppedSso = groupContainers(stopped)[0];
    expect(stoppedSso.aggregate).toMatchObject({
      state: '0/2 running', health: 'not checked', cpuPercent: 0, memoryBytes: 0, memoryPercent: null,
    });
  });

  it('sorts every displayed column in both directions and leaves missing values last', () => {
    const sortable: ContainerStatus[] = [
      { name: 'app-10', owner: null, state: null, health: null, cpuPercent: null, memoryBytes: null, memoryPercent: null },
      { name: 'app-2', owner: 'Zulu', state: 'running', health: 'unhealthy', cpuPercent: 10, memoryBytes: 100, memoryPercent: 5 },
      { name: 'app-1', owner: 'alpha', state: 'running', health: 'healthy', cpuPercent: 2, memoryBytes: 200, memoryPercent: 4 },
    ];

    expect(sortContainers(sortable, { key: 'name', direction: 'ascending' }).map(({ name }) => name)).toEqual(['app-1', 'app-2', 'app-10']);
    expect(sortContainers(sortable, { key: 'name', direction: 'descending' }).map(({ name }) => name)).toEqual(['app-10', 'app-2', 'app-1']);
    expect(sortContainers(sortable, { key: 'owner', direction: 'ascending' }).map(({ name }) => name)).toEqual(['app-1', 'app-2', 'app-10']);
    expect(sortContainers(sortable, { key: 'owner', direction: 'descending' }).map(({ name }) => name)).toEqual(['app-2', 'app-1', 'app-10']);
    expect(sortContainers(sortable, { key: 'status', direction: 'ascending' }).map(({ name }) => name)).toEqual(['app-1', 'app-2', 'app-10']);
    expect(sortContainers(sortable, { key: 'status', direction: 'descending' }).map(({ name }) => name)).toEqual(['app-2', 'app-1', 'app-10']);
    expect(sortContainers(sortable, { key: 'cpu', direction: 'ascending' }).map(({ name }) => name)).toEqual(['app-1', 'app-2', 'app-10']);
    expect(sortContainers(sortable, { key: 'cpu', direction: 'descending' }).map(({ name }) => name)).toEqual(['app-2', 'app-1', 'app-10']);
    expect(sortContainers(sortable, { key: 'memory', direction: 'ascending' }).map(({ name }) => name)).toEqual(['app-2', 'app-1', 'app-10']);
    expect(sortContainers(sortable, { key: 'memory', direction: 'descending' }).map(({ name }) => name)).toEqual(['app-1', 'app-2', 'app-10']);
  });

  it('sorts aggregate parents without splitting children and keeps missing statuses last', () => {
    const byCpu = groupContainers(containers, { key: 'cpu', direction: 'descending' });
    expect(byCpu[0].application).toBe('multtara');
    expect(byCpu[0].children.map((child) => child.component)).toEqual(['frontend', 'backend', 'database', 'collector']);
    expect(byCpu.at(-1)?.application).toBe('bonifacio');

    const statusRows: ContainerStatus[] = [
      { name: 'missing', owner: 'cks', state: null, health: null, cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 },
      { name: 'healthy', owner: 'cks', state: 'running', health: 'healthy', cpuPercent: 1, memoryBytes: 1, memoryPercent: 1 },
    ];
    expect(groupContainers(statusRows, { key: 'status', direction: 'ascending' }).map((group) => group.application)).toEqual(['healthy', 'missing']);
    expect(groupContainers(statusRows, { key: 'status', direction: 'descending' }).map((group) => group.application)).toEqual(['healthy', 'missing']);
  });

  it('toggles the selected column and starts a new column ascending', () => {
    expect(nextContainerSort({ key: null, direction: 'ascending' }, 'cpu')).toEqual({ key: 'cpu', direction: 'ascending' });
    expect(nextContainerSort({ key: 'cpu', direction: 'ascending' }, 'cpu')).toEqual({ key: 'cpu', direction: 'descending' });
    expect(nextContainerSort({ key: 'cpu', direction: 'descending' }, 'memory')).toEqual({ key: 'memory', direction: 'ascending' });
  });

  it('expands partial groups and collapses groups when all are open', () => {
    const groupKeys = ['sso', 'feelmyrythm', 'pilgrimage'];
    const partial = new Set(['sso']);

    expect([...toggleContainerGroupExpansion(partial, 'feelmyrythm')]).toEqual(['sso', 'feelmyrythm']);
    expect([...toggleContainerGroupExpansion(partial, 'sso')]).toEqual([]);
    expect([...nextContainerGroupExpansion(new Set(), groupKeys)]).toEqual(groupKeys);
    expect([...nextContainerGroupExpansion(partial, groupKeys)]).toEqual(groupKeys);
    expect([...partial]).toEqual(['sso']);
    expect([...nextContainerGroupExpansion(new Set(groupKeys), groupKeys)]).toEqual([]);
    expect([...nextContainerGroupExpansion(new Set(['stale']), [])]).toEqual([]);
  });

  it('renders collapsed aggregate parents and accessible disclosure controls on desktop and mobile', () => {
    const markup = renderToStaticMarkup(createElement(ContainerList, { containers }));

    expect(markup).toContain('>bonifacio</strong>');
    expect(markup).toContain('>cks-database</strong>');
    expect(markup).toMatch(/<strong>feelmyrythm<\/strong><button class="container-group-toggle"/);
    expect(markup).toMatch(/<strong>sso<\/strong><button class="container-group-toggle"/);
    expect(markup).toContain('title="3 containers"');
    expect(markup).not.toContain('class="container-group-row"');
    expect(markup).not.toContain('container-group-card');
    expect(markup).toContain('class="container-child-row"');
    expect(markup.match(/class="container-child-row"/g)).toHaveLength(14);
    expect(markup.match(/class="container-card container-child-card"/g)).toHaveLength(14);
    expect(markup.match(/class="container-child-name"/g)).toHaveLength(28);
    expect(markup).toContain('<strong aria-hidden="true">frontend</strong><span class="sr-only">feelmyrythm frontend container (feelmyrythm-frontend)</span>');
    expect(markup).toContain('<strong aria-hidden="true">main</strong><span class="sr-only">sso main container (sso)</span>');
    expect(markup).toContain('<strong aria-hidden="true">redis</strong><span class="sr-only">sso redis container (sso-redis)</span>');
    expect(markup).toContain('<span class="sr-only">multtara frontend container (multtara-frontend)</span>');
    expect(markup).toContain('3/3 running');
    expect(markup).toContain('13.5%');
    expect(markup).toContain('1 unhealthy');
    expect(markup).toContain('Combined usage');
    expect(markup.match(/class="container-groups-toggle-all"/g)).toHaveLength(1);
    expect(markup).toContain('aria-label="Expand all container groups"');
    expect(markup).toContain('>Expand all</button>');
    expect(markup.match(/aria-label="Expand feelmyrythm containers"/g)).toHaveLength(2);
    expect(markup.match(/class="container-group-toggle"/g)).toHaveLength(10);
    expect(markup.match(/aria-expanded="false"/g)).toHaveLength(10);
    expect(markup.match(/class="container-child-rows" hidden=""/g)).toHaveLength(5);
    expect(markup.match(/class="container-mobile-children" hidden=""/g)).toHaveLength(5);
    expect(markup).toContain('<span aria-hidden="true">+</span>');
    const controlledIds = Array.from(markup.matchAll(/aria-controls="([^"]+)"/g), (match) => match[1]);
    expect(new Set(controlledIds).size).toBe(controlledIds.length);
    controlledIds.forEach((id) => expect(markup).toContain(`id="${id}"`));
    expect(markup).toContain('aria-label="Container sorting controls"');
    expect(markup).toContain('aria-label="Sort services and containers by"');
    expect(markup).toContain('<option value="default" selected="">App groups</option>');
    expect(markup.match(/class="container-sort-button"/g)).toHaveLength(5);
    expect(markup).toContain('aria-sort="other"');
    expect(markup).toContain('aria-label="Sort by Service / container ascending"');
    expect(markup).not.toContain('class="container-name-hierarchy"');
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
