import { Fragment, useEffect, useMemo, useRef, useState, type ChangeEvent, type MouseEvent, type ReactNode } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useDashboard } from '../hooks/useDashboard';
import type {
  AlertEvent,
  ContainerStatus,
  DashboardPayload,
  MonitorPage,
  PeakIncident,
  PowerEvent,
  PowerSummary,
  PrivilegeEvent,
  TelemetrySample,
  TimeRange,
} from '../types';
import {
  clampPercent,
  formatBytes,
  formatClock,
  formatDateTime,
  formatPercent,
  formatRate,
  formatTime,
  formatUptime,
  safeText,
  toneForPercent,
} from '../utils';
import { Icon, type IconName } from './Icon';
import { PasswordChangeDialog } from './PasswordChangeDialog';

const RANGES: Array<{ value: TimeRange; label: string }> = [
  { value: '1h', label: '1H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
];

type StatusTone = 'good' | 'warn' | 'critical' | 'neutral';
const API_EVENT_CAP = 500;

export type ContainerSortKey = 'name' | 'owner' | 'status' | 'cpu' | 'memory';
export type ContainerSortDirection = 'ascending' | 'descending';

export interface ContainerSort {
  key: ContainerSortKey | null;
  direction: ContainerSortDirection;
}

const DEFAULT_CONTAINER_SORT: ContainerSort = { key: null, direction: 'ascending' };
const CONTAINER_SORT_COLLATOR = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });
const CONTAINER_SORT_OPTIONS: Array<{ key: ContainerSortKey; label: string }> = [
  { key: 'name', label: 'Container' },
  { key: 'owner', label: 'Owner' },
  { key: 'status', label: 'Status' },
  { key: 'cpu', label: 'CPU' },
  { key: 'memory', label: 'Memory' },
];
const FIXED_CONTAINER_NAMES = new Set(['bonifacio', 'sso', 'sso-redis', 'cks-database', 'monitor']);
const CONTAINER_COMPONENT_ORDER: Readonly<Record<string, number>> = {
  main: -1,
  frontend: 0,
  backend: 1,
  db: 2,
  database: 2,
  redis: 3,
  collector: 4,
};
// The API intentionally exposes fixed public names without Compose metadata.
// Keep grouping exact so retained legacy labels and unrelated hyphenated names
// remain visible as independent containers.
const CONTAINER_GROUP_MEMBERS: Readonly<Record<string, ContainerNameParts>> = {
  sso: { application: 'sso', component: 'main' },
  'sso-redis': { application: 'sso', component: 'redis' },
  'blog-frontend': { application: 'blog', component: 'frontend' },
  'blog-backend': { application: 'blog', component: 'backend' },
  'feelmyrythm-frontend': { application: 'feelmyrythm', component: 'frontend' },
  'feelmyrythm-backend': { application: 'feelmyrythm', component: 'backend' },
  'feelmyrythm-redis': { application: 'feelmyrythm', component: 'redis' },
  'multtara-frontend': { application: 'multtara', component: 'frontend' },
  'multtara-backend': { application: 'multtara', component: 'backend' },
  'multtara-database': { application: 'multtara', component: 'database' },
  'multtara-collector': { application: 'multtara', component: 'collector' },
  'pilgrimage-frontend': { application: 'pilgrimage', component: 'frontend' },
  'pilgrimage-backend': { application: 'pilgrimage', component: 'backend' },
  'pilgrimage-redis': { application: 'pilgrimage', component: 'redis' },
};

export interface ContainerNameParts {
  application: string;
  component: string | null;
}

export interface ContainerGroupChild {
  key: string;
  application: string;
  component: string;
  container: ContainerStatus;
}

export interface ContainerGroup {
  key: string;
  application: string;
  aggregate: ContainerStatus;
  children: ContainerGroupChild[];
  grouped: boolean;
  runningCount: number;
  tone: StatusTone;
}

interface DashboardProps {
  page: MonitorPage;
  navigationVersion: number;
  onNavigate: (page: MonitorPage, hash?: string) => void;
  onLogout: () => Promise<void>;
  onPasswordChanged: () => void;
  onUnauthorized: () => void;
  ssoEnabled?: boolean;
}

export function Dashboard({ page, navigationVersion, onNavigate, onLogout, onPasswordChanged, onUnauthorized, ssoEnabled = false }: DashboardProps) {
  const [range, setRange] = useState<TimeRange>('24h');
  const [loggingOut, setLoggingOut] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const { data, error, initialLoading, refreshing, lastUpdated, refresh } = useDashboard(range, onUnauthorized);
  const contentReady = data !== null;
  const anchorContentReady = contentReady && page === 'details' && Boolean(window.location.hash);

  async function handleLogout() {
    setLoggingOut(true);
    await onLogout();
  }

  useEffect(() => {
    document.title = page === 'details' ? 'Telemetry details · Monitor' : 'Monitor';
  }, [page]);

  useEffect(() => {
    const focusFrame = window.requestAnimationFrame(() => {
      const anchor = page === 'details' ? window.location.hash.slice(1) : '';
      const target = (anchor ? document.getElementById(anchor) : null) ?? titleRef.current;
      if (!target) return;
      target.scrollIntoView({ behavior: 'auto', block: 'start' });
      if (target instanceof HTMLElement) target.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(focusFrame);
  }, [anchorContentReady, navigationVersion, page]);

  function handlePageLink(event: MouseEvent<HTMLAnchorElement>, nextPage: MonitorPage, hash = '') {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    onNavigate(nextPage, hash);
  }

  return (
    <div className="app-shell">
      <header className="topbar" inert={passwordDialogOpen || undefined}>
        <div className="brand">
          <div className="brand-mark"><Icon name="activity" size={20} /></div>
          <div>
            <span className="brand-name">Monitor</span>
            <span className="brand-subtitle">Private host telemetry</span>
          </div>
        </div>
        <div className="header-actions">
          <nav className="page-nav" aria-label="Monitor pages">
            <a
              href="/monitor/"
              className={page === 'overview' ? 'active' : ''}
              aria-current={page === 'overview' ? 'page' : undefined}
              onClick={(event) => handlePageLink(event, 'overview')}
            >Overview</a>
            <a
              href="/monitor/details"
              className={page === 'details' ? 'active' : ''}
              aria-current={page === 'details' ? 'page' : undefined}
              onClick={(event) => handlePageLink(event, 'details')}
            >Details</a>
          </nav>
          <span className="secure-label"><span className="status-dot status-dot-good" />Secure session</span>
          {!ssoEnabled && (
            <button
              className="icon-button labeled-button"
              onClick={() => setPasswordDialogOpen(true)}
              type="button"
              aria-label="Change password"
              aria-haspopup="dialog"
              aria-expanded={passwordDialogOpen}
            >
              <Icon name="lock" size={16} />
              <span>Change password</span>
            </button>
          )}
          <button
            className="icon-button labeled-button"
            onClick={handleLogout}
            disabled={loggingOut}
            type="button"
            aria-label={loggingOut ? 'Signing out' : 'Sign out'}
          >
            <Icon name="logout" size={17} />
            <span>{loggingOut ? 'Signing out…' : 'Sign out'}</span>
          </button>
        </div>
      </header>

      <main className="dashboard-main" inert={passwordDialogOpen || undefined}>
        <section className="dashboard-heading" aria-labelledby="dashboard-title">
          <div>
            <span className="eyebrow">{page === 'details' ? 'Detailed telemetry' : 'System overview'}</span>
            <h1 ref={titleRef} tabIndex={-1} id="dashboard-title">
              {page === 'details' ? 'Telemetry details' : data ? safeText(data.host.hostname, 'Host') : 'Host telemetry'}
            </h1>
            <p className="heading-copy">
              {page === 'details'
                ? 'Power evidence, full event history, and resource trends for the selected range.'
                : 'Current health, performance, and operational activity at a glance.'}
            </p>
          </div>
          <div className="dashboard-controls">
            <div className="range-control" role="group" aria-label="Chart time range">
              {RANGES.map((item) => (
                <button
                  key={item.value}
                  className={range === item.value ? 'active' : ''}
                  type="button"
                  aria-pressed={range === item.value}
                  onClick={() => setRange(item.value)}
                >
                  {item.label}
                </button>
              ))}
            </div>
            <button
              className="refresh-button"
              type="button"
              onClick={() => void refresh()}
              disabled={refreshing}
              aria-label={refreshing ? 'Refreshing telemetry' : 'Refresh telemetry'}
            >
              <Icon name="refresh" size={17} className={refreshing ? 'spin' : ''} />
              <span>{refreshing ? 'Refreshing…' : 'Refresh'}</span>
            </button>
          </div>
        </section>

        <div className="refresh-meta" aria-live="polite">
          {data?.stale ? <span className="stale-label"><Icon name="alert" size={14} />Collector reports stale data</span> : <span><span className="status-dot status-dot-good" />Live collector</span>}
          <span>{lastUpdated ? `Refreshed ${formatDateTime(lastUpdated.toISOString())}` : 'Waiting for first update'}</span>
          <span>Automatic refresh every 60 seconds</span>
        </div>

        {error && (
          <div className="notice notice-error dashboard-notice" role="alert">
            <Icon name="alert" size={18} />
            <div><strong>Telemetry refresh failed</strong><span>{safeText(error)} {data ? 'Showing the last successful snapshot.' : ''}</span></div>
            <button type="button" onClick={() => void refresh()}>Try again</button>
          </div>
        )}

        {initialLoading && !data ? <DashboardSkeleton /> : data ? (page === 'details'
          ? <DetailsContent data={data} range={range} onNavigate={onNavigate} />
          : <OverviewContent data={data} range={range} onNavigate={onNavigate} />) : (
          <EmptyState icon="server" title="No telemetry available" detail="The collector has not returned a dashboard snapshot yet." action={<button className="secondary-button" onClick={() => void refresh()}>Retry</button>} />
        )}
      </main>

      <footer className="app-footer" inert={passwordDialogOpen || undefined}>
        <span><Icon name="shield" size={14} />Private monitor</span>
        <span>Generated {data ? formatDateTime(data.generatedAt) : '—'}</span>
      </footer>

      {!ssoEnabled && (
        <PasswordChangeDialog
          open={passwordDialogOpen}
          onClose={() => setPasswordDialogOpen(false)}
          onPasswordChanged={onPasswordChanged}
          onUnauthorized={onUnauthorized}
        />
      )}
    </div>
  );
}

function OverviewContent({ data, range, onNavigate }: { data: DashboardPayload; range: TimeRange; onNavigate: DashboardProps['onNavigate'] }) {
  const chartData = useMemo(() => data.series.map((point) => ({ ...point, label: formatTime(point.timestamp, range) })), [data.series, range]);
  const latest = data.latest;
  const incidents = data.incidents ?? [];
  const temperature = latest?.temperatureC ?? null;
  const maxDisk = data.disks.reduce((highest, disk) => Math.max(highest, disk.usedPercent ?? 0), 0);

  return (
    <div className="dashboard-content">
      <section className="metric-grid" aria-label="Current system metrics">
        <MetricCard icon="cpu" label="CPU usage" value={formatPercent(latest?.cpuPercent, 1)} detail={`Load ${formatDecimal(latest?.load1)} · 1 min`} percent={latest?.cpuPercent} accent="cyan" />
        <MetricCard icon="memory" label="Memory" value={formatPercent(latest?.memoryPercent, 1)} detail={`${formatBytes(latest?.memoryUsedBytes)} of ${formatBytes(latest?.memoryTotalBytes)}`} percent={latest?.memoryPercent} accent="violet" />
        <MetricCard icon="temperature" label="Temperature" value={temperature == null ? '—' : `${temperature.toFixed(1)}°C`} detail={temperature == null ? 'Sensor unavailable' : temperature >= 80 ? 'Running hot' : 'Within operating range'} percent={temperature == null ? undefined : temperature} accent="orange" />
        <MetricCard icon="activity" label="System load" value={formatDecimal(latest?.load1)} detail={`${formatDecimal(latest?.load5)} / ${formatDecimal(latest?.load15)} · 5m / 15m`} accent="green" />
      </section>

      <PowerOverview latest={latest} onNavigate={onNavigate} />

      <Panel
        title="Recent peak incidents"
        subtitle={`Showing the latest ${Math.min(incidents.length, 3)} of ${incidents.length} incident captures`}
        icon="activity"
        badge={summaryBadge(incidents.length)}
      >
        <IncidentTimeline incidents={incidents.slice(0, 3)} compact />
        {incidents.length > 0 && <DetailsLink section="incidents" count={incidents.length} label="Inspect incident evidence" onNavigate={onNavigate} />}
      </Panel>

      <section className="two-column chart-layout" aria-label="Historical telemetry">
        <Panel title="Resource history" subtitle="CPU and memory utilization" icon="activity" badge={range.toUpperCase()}>
          <ChartFrame empty={!chartData.length} label="CPU and memory utilization chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48d6cf" stopOpacity={0.32} /><stop offset="100%" stopColor="#48d6cf" stopOpacity={0.01} /></linearGradient>
                  <linearGradient id="memoryFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#9a8cff" stopOpacity={0.28} /><stop offset="100%" stopColor="#9a8cff" stopOpacity={0.01} /></linearGradient>
                </defs>
                <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} tickFormatter={(value) => `${value}%`} />
                <Tooltip content={<PercentTooltip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12, paddingTop: 12 }} />
                <Area type="monotone" dataKey="cpuPercent" name="CPU" stroke="#48d6cf" strokeWidth={2} fill="url(#cpuFill)" activeDot={{ r: 4 }} />
                <Area type="monotone" dataKey="memoryPercent" name="Memory" stroke="#9a8cff" strokeWidth={2} fill="url(#memoryFill)" activeDot={{ r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          </ChartFrame>
        </Panel>

        <Panel title="Thermals & load" subtitle="Temperature and 1-minute load" icon="temperature" badge={range.toUpperCase()}>
          <ChartFrame empty={!chartData.length} label="Temperature and load chart">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                <YAxis yAxisId="temp" stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} tickFormatter={(value) => `${value}°`} />
                <YAxis yAxisId="load" orientation="right" stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} width={34} />
                <Tooltip content={<ThermalTooltip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12, paddingTop: 12 }} />
                <Line yAxisId="temp" type="monotone" dataKey="temperatureC" name="Temperature" stroke="#ffad66" strokeWidth={2} dot={false} connectNulls />
                <Line yAxisId="load" type="monotone" dataKey="load1" name="Load 1m" stroke="#75dda2" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </ChartFrame>
        </Panel>
      </section>

      <section className="two-column overview-layout">
        <Panel title="I/O throughput" subtitle="Network and disk transfer rates" icon="network" badge="BYTES / SEC">
          <ChartFrame empty={!chartData.length} label="Network and disk throughput chart" tall>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 8, right: 8, left: 2, bottom: 0 }}>
                <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                <YAxis stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} width={54} tickFormatter={(value) => compactBytes(Number(value))} />
                <Tooltip content={<IoTooltip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 11, paddingTop: 12 }} />
                <Line type="monotone" dataKey="networkRxBytesPerSecond" name="Network ↓" stroke="#48d6cf" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="networkTxBytesPerSecond" name="Network ↑" stroke="#9a8cff" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="diskReadBytesPerSecond" name="Disk read" stroke="#75dda2" strokeWidth={1.5} strokeDasharray="4 3" dot={false} />
                <Line type="monotone" dataKey="diskWriteBytesPerSecond" name="Disk write" stroke="#ffad66" strokeWidth={1.5} strokeDasharray="4 3" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </ChartFrame>
          <div className="io-summary">
            <span><i className="legend-dot cyan" />Down <strong>{formatRate(latest?.networkRxBytesPerSecond)}</strong></span>
            <span><i className="legend-dot violet" />Up <strong>{formatRate(latest?.networkTxBytesPerSecond)}</strong></span>
          </div>
        </Panel>

        <Panel title="Host details" subtitle="Runtime and hardware summary" icon="server">
          <div className="host-status-row">
            <div className="host-online"><span className={`status-dot ${latest ? 'status-dot-good' : 'status-dot-idle'}`} /><div><strong>{latest ? 'Host online' : 'Awaiting telemetry'}</strong><span>Snapshot {formatDateTime(latest?.timestamp)}</span></div></div>
            <StatusBadge value={latest?.powerState} />
          </div>
          <dl className="detail-list">
            <DetailItem label="Hostname" value={safeText(data.host.hostname)} />
            <DetailItem label="Operating system" value={safeText(data.host.os)} />
            <DetailItem label="Architecture" value={safeText(data.host.architecture)} />
            <DetailItem label="Uptime" value={formatUptime(data.host.uptimeSeconds)} />
          </dl>
          <div className="hardware-strip">
            <div><span>GPU memory</span><strong>{latest?.gpuMemoryBytes == null ? 'Not available' : formatBytes(latest.gpuMemoryBytes)}</strong></div>
            <div><span>GPU clock</span><strong>{formatClock(latest?.gpuClockHz ?? null)}</strong></div>
          </div>
        </Panel>
      </section>

      <Panel title="Storage" subtitle={`${data.disks.length} mounted volume${data.disks.length === 1 ? '' : 's'}`} icon="drive" badge={data.disks.length ? `${formatPercent(maxDisk)} MAX` : undefined}>
        {data.disks.length ? <div className="disk-grid">{data.disks.map((disk, index) => (
          <article className="disk-card" key={`${disk.mount}-${index}`}>
            <div className="disk-heading"><div className="disk-icon"><Icon name="database" size={18} /></div><div><h3>{safeText(disk.mount, 'Volume', 72)}</h3><p>{formatBytes(disk.usedBytes)} of {formatBytes(disk.totalBytes)}</p></div><strong>{formatPercent(disk.usedPercent)}</strong></div>
            <ProgressBar value={disk.usedPercent} label={`${safeText(disk.mount)} storage used`} />
            <div className="disk-foot"><span>{formatFreeBytes(disk.totalBytes, disk.usedBytes)} free</span><span className={`tone-${toneForPercent(disk.usedPercent)}`}>{toneForPercent(disk.usedPercent) === 'good' ? 'Healthy' : toneForPercent(disk.usedPercent) === 'warn' ? 'Watch usage' : 'Low space'}</span></div>
          </article>
        ))}</div> : <InlineEmpty icon="drive" text="No mounted disks reported" />}
      </Panel>

      <Panel title="Tracked containers" subtitle={containerSummaryLabel(data.containers)} icon="server">
        {data.containers.length ? <ContainerList containers={data.containers} /> : <InlineEmpty icon="server" text="No tracked containers reported" />}
      </Panel>

      <section className="two-column activity-layout">
        <Panel title="Alerts" subtitle={`Showing the latest ${Math.min(data.alerts.length, 10)} of ${data.alerts.length} notices in this range`} icon="alert" badge={summaryBadge(data.alerts.length)}>
          <AlertList alerts={data.alerts.slice(0, 10)} />
          <DetailsLink section="alerts" count={data.alerts.length} label="View all alerts" onNavigate={onNavigate} />
        </Panel>

        <Panel title="Privilege activity" subtitle={`Showing the latest ${Math.min(data.privilegeEvents.length, 10)} of ${data.privilegeEvents.length} operations in this range`} icon="shield" badge={summaryBadge(data.privilegeEvents.length)}>
          <PrivilegeList events={data.privilegeEvents.slice(0, 10)} />
          <DetailsLink section="privilege" count={data.privilegeEvents.length} label="View all privilege activity" onNavigate={onNavigate} />
        </Panel>
      </section>
    </div>
  );
}

function PowerOverview({ latest, onNavigate }: { latest: TelemetrySample | null; onNavigate: DashboardProps['onNavigate'] }) {
  const flags = decodeThrottledFlags(latest?.throttledFlags);
  const hasActiveIssue = flags.active.length > 0;
  const stateTone = currentPowerStatusTone(latest?.throttledFlags, latest?.powerState);
  const currentSummary = hasActiveIssue
    ? `${flags.active.length} active power condition${flags.active.length === 1 ? '' : 's'}`
    : stateTone === 'warn' || stateTone === 'critical'
      ? safeText(latest?.powerState, 'Power issue reported', 72)
    : flags.available && flags.historical.length
      ? 'Currently normal · earlier this boot'
      : safeText(latest?.powerState, flags.available ? 'No active throttling flags' : 'Power flags unavailable', 72);

  return (
    <section className="power-spotlight" aria-labelledby="power-overview-title">
      <div className="power-spotlight-icon"><Icon name="zap" size={23} /></div>
      <div className="power-spotlight-reading">
        <span className="eyebrow">EXT5V supply</span>
        <strong id="power-overview-title">{formatVoltage(latest?.supplyVoltageVolts)}</strong>
        <span>{latest?.supplyVoltageVolts == null ? 'Current voltage sample unavailable' : 'Latest external 5V rail sample'}</span>
      </div>
      <div className="power-spotlight-state">
        <span className={`status-badge badge-${stateTone}`}><span />{currentSummary}</span>
        <p>Kernel/vcgencmd: {safeText(latest?.powerState, 'Unavailable', 80)}</p>
        <p>{flags.available ? `${formatFlags(latest?.throttledFlags)} · ${flags.historical.length} since-boot historical condition${flags.historical.length === 1 ? '' : 's'}` : 'Throttled flags were not reported.'}</p>
      </div>
      <a
        className="details-link power-details-link"
        href="/monitor/details#power"
        onClick={(event) => navigateInApp(event, onNavigate, 'details', '#power')}
      >Inspect power evidence <Icon name="chevron" size={15} /></a>
    </section>
  );
}

function DetailsContent({ data, range, onNavigate }: { data: DashboardPayload; range: TimeRange; onNavigate: DashboardProps['onNavigate'] }) {
  const chartData = useMemo(
    () => data.series.map((point) => ({ ...point, label: formatTime(point.timestamp, range) })),
    [data.series, range],
  );
  const latest = data.latest;
  const incidents = data.incidents ?? [];
  const flags = decodeThrottledFlags(latest?.throttledFlags);
  const powerEvents = data.powerEvents ?? [];
  const summary = normalizedPowerSummary(data.powerSummary, data.series);
  const voltageChartData = chartData.filter((point) => Number.isFinite(point.supplyVoltageVolts));
  const voltageDomain = voltageChartDomain(voltageChartData.map((point) => Number(point.supplyVoltageVolts)));
  const criticalPowerEvents = powerEvents.filter((event) => normalizeTone(event.severity) === 'critical').length;
  const warningPowerEvents = powerEvents.filter((event) => normalizeTone(event.severity) === 'warn').length;
  const currentPowerTone = currentPowerStatusTone(latest?.throttledFlags, latest?.powerState);
  const currentPowerNormal = flags.available && flags.active.length === 0 && currentPowerTone === 'good';
  const currentFlagValue = !flags.available
    ? '—'
    : currentPowerNormal
      ? 'Normal'
      : flags.active.length
        ? String(flags.active.length)
        : 'State issue';
  const currentPowerCopy = !flags.available
    ? 'No current vcgencmd flag sample is available.'
    : flags.active.length
      ? `${flags.active.length} condition${flags.active.length === 1 ? '' : 's'} active now.`
      : currentPowerTone === 'warn' || currentPowerTone === 'critical'
        ? `The reported kernel/vcgencmd state is ${safeText(latest?.powerState, 'abnormal', 64)}.`
      : currentPowerTone === 'neutral'
        ? 'No active bits are set, but the reported power state is unrecognized.'
        : flags.historical.length
          ? 'Currently normal. Historical bits record earlier conditions in this boot only.'
        : 'Currently normal with no active or historical throttling bits.';

  return (
    <div className="dashboard-content details-content">
      <nav className="detail-jump-nav" aria-label="Details sections">
        <a href="/monitor/details#power" onClick={(event) => navigateInApp(event, onNavigate, 'details', '#power')}>Power</a>
        <a href="/monitor/details#resources" onClick={(event) => navigateInApp(event, onNavigate, 'details', '#resources')}>Resources</a>
        <a href="/monitor/details#incidents" onClick={(event) => navigateInApp(event, onNavigate, 'details', '#incidents')}>Incidents</a>
        <a href="/monitor/details#alerts" onClick={(event) => navigateInApp(event, onNavigate, 'details', '#alerts')}>Alerts</a>
        <a href="/monitor/details#privilege" onClick={(event) => navigateInApp(event, onNavigate, 'details', '#privilege')}>Privilege</a>
      </nav>

      <section id="power" tabIndex={-1} className="detail-section" aria-labelledby="power-detail-title">
        <DetailSectionHeading
          eyebrow="Power integrity"
          title="Supply voltage and throttling evidence"
          id="power-detail-title"
          detail="Current readings are separated from historical conditions latched since boot."
        />

        <div className="power-card-grid">
          <SummaryCard label="Current EXT5V" value={formatVoltage(latest?.supplyVoltageVolts)} detail={latest?.supplyVoltageVolts == null ? 'No current sensor sample' : `Snapshot ${formatDateTime(latest.timestamp)}`} tone="cyan" />
          <SummaryCard label="Current flags" value={currentFlagValue} detail={currentPowerCopy} tone={!flags.available || currentPowerTone === 'neutral' ? 'violet' : currentPowerTone === 'critical' ? 'red' : currentPowerNormal ? 'green' : 'orange'} />
          <SummaryCard label="Historical flags" value={flags.available ? String(flags.historical.length) : '—'} detail={flags.historical.length ? 'Latched earlier in this boot; not necessarily active now.' : 'No since-boot historical bits reported.'} tone="violet" />
          <SummaryCard label="Power events" value={String(powerEvents.length)} detail={`${criticalPowerEvents} critical · ${warningPowerEvents} warning`} tone="orange" />
        </div>

        <div className="power-state-panel">
          <div>
            <span className="power-state-label">Kernel / vcgencmd state</span>
            <strong>{safeText(latest?.powerState, 'Unavailable', 100)}</strong>
            <StatusBadge value={currentPowerNormal ? 'Current normal' : latest?.powerState} tone={currentPowerNormal ? 'good' : currentPowerTone} />
          </div>
          <div>
            <span className="power-state-label">Active low bits · {formatFlags(latest?.throttledFlags)}</span>
            <FlagList values={flags.active} empty={flags.available ? 'No active low-bit conditions.' : 'Current flags unavailable.'} tone="active" />
          </div>
          <div>
            <span className="power-state-label">Historical high bits · since boot</span>
            <FlagList values={flags.historical} empty={flags.available ? 'No conditions recorded earlier in this boot.' : 'Historical flags unavailable.'} tone="historical" />
          </div>
        </div>

        <div className="power-explainer" role="note">
          <Icon name="info" size={18} />
          <p><strong>What this voltage means</strong><span>EXT5V is a sampled external 5V supply rail. It is not amperage, USB-C negotiated wattage, or wall-outlet power. Missing values mean this sensor did not provide a sample; they are not zero volts.</span></p>
        </div>

        <section className="power-summary-grid" aria-label="Full-range power summary">
          <SummaryStat label="Voltage samples" value={formatCount(summary.voltageSampleCount)} detail={`${formatCount(summary.sampleCount)} total telemetry samples`} />
          <SummaryStat label="Minimum EXT5V" value={formatVoltage(summary.minSupplyVoltageVolts)} detail="Full selected range" />
          <SummaryStat label="Average EXT5V" value={formatVoltage(summary.averageSupplyVoltageVolts)} detail="Full selected range" />
          <SummaryStat label="Maximum EXT5V" value={formatVoltage(summary.maxSupplyVoltageVolts)} detail="Full selected range" />
          <SummaryStat label="Under-voltage samples" value={formatCount(summary.underVoltageSampleCount)} detail="Full-range anomaly count" />
          <SummaryStat label="Throttled samples" value={formatCount(summary.throttledSampleCount)} detail="Full-range anomaly count" />
        </section>

        <Panel title="EXT5V history" subtitle="Downsampled chart · summary cards use the full selected range" icon="zap" badge={range.toUpperCase()}>
          <ChartFrame empty={!voltageChartData.length} label="EXT5V supply voltage time series" tall>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={voltageChartData} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                <YAxis domain={voltageDomain} stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} width={48} tickFormatter={(value) => `${Number(value).toFixed(2)}V`} />
                <Tooltip content={<VoltageTooltip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12, paddingTop: 12 }} />
                <Line type="linear" dataKey="supplyVoltageVolts" name="EXT5V" stroke="#48d6cf" strokeWidth={2.4} dot={false} activeDot={{ r: 4 }} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </ChartFrame>
        </Panel>

        <Panel title="Power event timeline" subtitle={`${powerEvents.length} newest power, storage, and recovery events in this range (up to ${API_EVENT_CAP})`} icon="alert" badge={exactEventBadge(powerEvents.length)}>
          <PowerEventList events={powerEvents} />
        </Panel>
      </section>

      <section id="resources" tabIndex={-1} className="detail-section" aria-labelledby="resource-detail-title">
        <DetailSectionHeading eyebrow="Performance" title="Resource telemetry" id="resource-detail-title" detail="Richer charts share the selected range and last-good snapshot." />
        <section className="metric-grid" aria-label="Current detailed system metrics">
          <MetricCard icon="cpu" label="CPU usage" value={formatPercent(latest?.cpuPercent, 1)} detail={`Load ${formatDecimal(latest?.load1)} · 1 min`} percent={latest?.cpuPercent} accent="cyan" />
          <MetricCard icon="memory" label="Memory" value={formatPercent(latest?.memoryPercent, 1)} detail={`${formatBytes(latest?.memoryUsedBytes)} of ${formatBytes(latest?.memoryTotalBytes)}`} percent={latest?.memoryPercent} accent="violet" />
          <MetricCard icon="temperature" label="Temperature" value={latest?.temperatureC == null ? '—' : `${latest.temperatureC.toFixed(1)}°C`} detail={latest?.temperatureC == null ? 'Sensor unavailable' : 'Current SoC temperature'} percent={latest?.temperatureC} accent="orange" />
          <MetricCard icon="activity" label="System load" value={formatDecimal(latest?.load1)} detail={`${formatDecimal(latest?.load5)} / ${formatDecimal(latest?.load15)} · 5m / 15m`} accent="green" />
        </section>

        <section className="two-column chart-layout" aria-label="Detailed resource charts">
          <Panel title="CPU & memory" subtitle="Utilization across the selected range" icon="activity" badge={range.toUpperCase()}>
            <ChartFrame empty={!chartData.length} label="Detailed CPU and memory utilization chart" tall>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="detailCpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48d6cf" stopOpacity={0.32} /><stop offset="100%" stopColor="#48d6cf" stopOpacity={0.01} /></linearGradient>
                    <linearGradient id="detailMemoryFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#9a8cff" stopOpacity={0.28} /><stop offset="100%" stopColor="#9a8cff" stopOpacity={0.01} /></linearGradient>
                  </defs>
                  <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                  <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 100]} stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} tickFormatter={(value) => `${value}%`} />
                  <Tooltip content={<PercentTooltip />} />
                  <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12, paddingTop: 12 }} />
                  <Area type="monotone" dataKey="cpuPercent" name="CPU" stroke="#48d6cf" strokeWidth={2} fill="url(#detailCpuFill)" activeDot={{ r: 4 }} />
                  <Area type="monotone" dataKey="memoryPercent" name="Memory" stroke="#9a8cff" strokeWidth={2} fill="url(#detailMemoryFill)" activeDot={{ r: 4 }} />
                </AreaChart>
              </ResponsiveContainer>
            </ChartFrame>
          </Panel>

          <Panel title="Temperature & load" subtitle="SoC thermals with 1, 5, and 15-minute load" icon="temperature" badge={range.toUpperCase()}>
            <ChartFrame empty={!chartData.length} label="Detailed temperature and load chart" tall>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}>
                  <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                  <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                  <YAxis yAxisId="temp" stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} tickFormatter={(value) => `${value}°`} />
                  <YAxis yAxisId="load" orientation="right" stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} width={34} />
                  <Tooltip content={<ThermalTooltip />} />
                  <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 11, paddingTop: 12 }} />
                  <Line yAxisId="temp" type="monotone" dataKey="temperatureC" name="Temperature" stroke="#ffad66" strokeWidth={2} dot={false} connectNulls />
                  <Line yAxisId="load" type="monotone" dataKey="load1" name="Load 1m" stroke="#75dda2" strokeWidth={2} dot={false} />
                  <Line yAxisId="load" type="monotone" dataKey="load5" name="Load 5m" stroke="#9a8cff" strokeWidth={1.5} dot={false} />
                  <Line yAxisId="load" type="monotone" dataKey="load15" name="Load 15m" stroke="#48d6cf" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </ChartFrame>
          </Panel>
        </section>

        <Panel title="Network & disk I/O" subtitle="Receive, transmit, read, and write throughput" icon="network" badge="BYTES / SEC">
          <ChartFrame empty={!chartData.length} label="Detailed network and disk throughput chart" tall>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 8, right: 8, left: 2, bottom: 0 }}>
                <CartesianGrid stroke="#21302f" strokeDasharray="4 5" vertical={false} />
                <XAxis dataKey="label" stroke="#6e807d" tickLine={false} axisLine={false} minTickGap={34} tick={{ fontSize: 11 }} />
                <YAxis stroke="#6e807d" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} width={54} tickFormatter={(value) => compactBytes(Number(value))} />
                <Tooltip content={<IoTooltip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 11, paddingTop: 12 }} />
                <Line type="monotone" dataKey="networkRxBytesPerSecond" name="Network ↓" stroke="#48d6cf" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="networkTxBytesPerSecond" name="Network ↑" stroke="#9a8cff" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="diskReadBytesPerSecond" name="Disk read" stroke="#75dda2" strokeWidth={1.7} dot={false} />
                <Line type="monotone" dataKey="diskWriteBytesPerSecond" name="Disk write" stroke="#ffad66" strokeWidth={1.7} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </ChartFrame>
        </Panel>
      </section>

      <section id="incidents" tabIndex={-1} className="detail-section" aria-labelledby="incidents-detail-title">
        <DetailSectionHeading
          eyebrow="Correlation"
          title="Peak incident timeline"
          id="incidents-detail-title"
          detail="Threshold windows combine resource peaks with safe process names, cks-owned workloads, pressure, and per-capture request counts—not visitors."
        />
        <Panel
          title="Captured incident evidence"
          subtitle={`${incidents.length} incident capture${incidents.length === 1 ? '' : 's'} in this range`}
          icon="activity"
          badge={exactEventBadge(incidents.length)}
        >
          <IncidentTimeline incidents={incidents} />
        </Panel>
      </section>

      <section id="alerts" tabIndex={-1} className="detail-section" aria-labelledby="alerts-detail-title">
        <DetailSectionHeading eyebrow="Operations" title="All recent alerts" id="alerts-detail-title" detail={`${data.alerts.length} newest records in this range (up to ${API_EVENT_CAP}).`} />
        <Panel title="Collector & system alerts" subtitle="Full list returned for this snapshot" icon="alert" badge={exactEventBadge(data.alerts.length)}>
          <AlertList alerts={data.alerts} />
        </Panel>
      </section>

      <section id="privilege" tabIndex={-1} className="detail-section" aria-labelledby="privilege-detail-title">
        <DetailSectionHeading eyebrow="Audit" title="All privilege activity" id="privilege-detail-title" detail={`${data.privilegeEvents.length} newest records in this range (up to ${API_EVENT_CAP}).`} />
        <Panel title="Elevated operations" subtitle="Semantic actions only; raw commands are not exposed" icon="shield" badge={exactEventBadge(data.privilegeEvents.length)}>
          <PrivilegeList events={data.privilegeEvents} />
        </Panel>
      </section>
    </div>
  );
}

function DetailSectionHeading({ eyebrow, title, id, detail }: { eyebrow: string; title: string; id: string; detail: string }) {
  return <header className="detail-section-heading"><span className="eyebrow">{eyebrow}</span><h2 id={id}>{title}</h2><p>{detail}</p></header>;
}

function SummaryCard({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: string }) {
  return <article className={`summary-card summary-${tone}`}><span>{label}</span><strong>{value}</strong><p>{detail}</p></article>;
}

function SummaryStat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="summary-stat"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function FlagList({ values, empty, tone }: { values: string[]; empty: string; tone: 'active' | 'historical' }) {
  if (!values.length) return <p className="flag-empty">{empty}</p>;
  return <ul className={`flag-list flag-${tone}`}>{values.map((value) => <li key={value}>{value}</li>)}</ul>;
}

export function IncidentTimeline({ incidents, compact = false }: { incidents: PeakIncident[]; compact?: boolean }) {
  if (!incidents.length) {
    return <InlineEmpty icon="check" text="No peak incidents captured in this range" positive />;
  }

  return (
    <div className={`incident-timeline${compact ? ' incident-timeline-compact' : ''}`}>
      {incidents.map((incident, index) => {
        const reasons = Array.isArray(incident.reasons)
          ? incident.reasons.map((reason) => incidentReasonLabel(reason)).filter(Boolean)
          : [];
        const processes = Array.isArray(incident.processes) ? incident.processes : [];
        const containers = Array.isArray(incident.containers) ? incident.containers : [];
        const traffic = Array.isArray(incident.traffic) ? incident.traffic : [];
        const tone = incidentPhaseTone(incident.phase);
        const titleId = `incident-title-${index}`;
        const metrics = incident.metrics;
        const cpuPeak = incident.peaks?.cpuPercent ?? metrics?.cpuPercent;
        const memoryPeak = incident.peaks?.memoryPercent ?? metrics?.memoryPercent;
        const temperaturePeak = incident.peaks?.temperatureC ?? metrics?.temperatureC;
        const loadPeak = incident.peaks?.load1 ?? metrics?.load1;
        const requestCount = traffic.reduce((total, item) => total + validCount(item.requestCount, 0), 0);
        const errorCount = traffic.reduce((total, item) => total + validCount(item.status5xx, 0), 0);
        const slowCount = traffic.reduce((total, item) => total + validCount(item.slowCount, 0), 0);

        return (
          <article className={`incident-card incident-${tone}`} key={`${incident.id}-${index}`} aria-labelledby={titleId}>
            <header className="incident-header">
              <div className="incident-heading">
                <div className="incident-time-row">
                  <time dateTime={incident.startedAt || undefined}>{formatDateTime(incident.startedAt)}</time>
                  <span>{formatIncidentDuration(incident)}</span>
                  <span className="incident-id">ID {safeText(incident.id, 'Unavailable', 48)}</span>
                </div>
                <h3 id={titleId}>{reasons[0] || 'Resource threshold exceeded'}</h3>
              </div>
              <StatusBadge value={incident.phase} tone={tone} />
            </header>

            <div className="incident-window">
              <span>Observed {formatDateTime(incident.observedAt)}</span>
              <span>{incident.endedAt ? `Ended ${formatDateTime(incident.endedAt)}` : 'Open at this capture'}</span>
            </div>

            <div className="incident-reasons" aria-label="Incident causes">
              {(reasons.length ? reasons : ['Cause not classified']).map((reason, reasonIndex) => (
                <span key={`${reason}-${reasonIndex}`}>{reason}</span>
              ))}
            </div>

            <dl className="incident-metrics" aria-label="Peak resource metrics">
              <IncidentMetric label="CPU peak" value={formatPercent(cpuPeak, 1)} tone={toneForPercent(cpuPeak)} />
              <IncidentMetric label="Memory peak" value={formatPercent(memoryPeak, 1)} tone={toneForPercent(memoryPeak)} />
              <IncidentMetric label="Temperature peak" value={formatTemperature(temperaturePeak)} tone={temperatureTone(temperaturePeak)} />
              <IncidentMetric label="Load 1m peak" value={formatDecimal(loadPeak)} tone={loadTone(loadPeak)} />
            </dl>

            <div className="incident-evidence-summary" aria-label="Captured evidence summary">
              <span><Icon name="cpu" size={14} />{formatCount(processes.length)} process name{processes.length === 1 ? '' : 's'}</span>
              <span><Icon name="server" size={14} />{formatCount(containers.length)} cks workload{containers.length === 1 ? '' : 's'}</span>
              <span><Icon name="network" size={14} />{formatCount(requestCount)} request{requestCount === 1 ? '' : 's'} in this capture interval · not visitors</span>
              {errorCount > 0 && <span className="tone-critical"><Icon name="alert" size={14} />{formatCount(errorCount)} server error{errorCount === 1 ? '' : 's'}</span>}
              {slowCount > 0 && <span className="tone-warn"><Icon name="clock" size={14} />{formatCount(slowCount)} slow</span>}
            </div>

            {!compact && (
              <div className="incident-detail-grid">
                <section className="incident-evidence-block" aria-label="Pressure stall information">
                  <IncidentEvidenceHeading icon="activity" title="Pressure" detail="PSI avg10 · some / full" />
                  <div className="incident-pressure-grid">
                    <IncidentPressure label="CPU" some={incident.pressure?.cpu?.someAvg10} full={incident.pressure?.cpu?.fullAvg10} />
                    <IncidentPressure label="Memory" some={incident.pressure?.memory?.someAvg10} full={incident.pressure?.memory?.fullAvg10} />
                    <IncidentPressure label="I/O" some={incident.pressure?.io?.someAvg10} full={incident.pressure?.io?.fullAvg10} />
                  </div>
                </section>

                <section className="incident-evidence-block" aria-label="Safe process aggregates">
                  <IncidentEvidenceHeading icon="cpu" title="Processes" detail="Fixed executable classes · no argv or IDs" />
                  {processes.length ? <ul className="incident-entity-list">{processes.map((process, processIndex) => (
                    <li key={`${process.name}-${processIndex}`}>
                      <div><strong>{safeText(process.name, 'Unnamed process', 72)}</strong><span>{formatCount(process.instances)} instance{process.instances === 1 ? '' : 's'}</span></div>
                      <span>CPU {formatPercent(process.cpuPercent, 1)} · {formatBytes(process.memoryBytes)}</span>
                    </li>
                  ))}</ul> : <IncidentEvidenceEmpty text="No process attribution captured" />}
                </section>

                <section className="incident-evidence-block" aria-label="cks app workloads">
                  <IncidentEvidenceHeading icon="server" title="App workloads" detail="cks-owned containers only" />
                  {containers.length ? <ul className="incident-entity-list">{containers.map((container, containerIndex) => (
                    <li key={`${container.name}-${containerIndex}`}>
                      <div><strong>{safeText(container.name, 'Unnamed workload', 72)}</strong><span>{safeText(container.owner, 'App workload', 48)}</span></div>
                      <span className="incident-container-stats"><StatusBadge value={container.health || container.state} /> CPU {formatPercent(container.cpuPercent, 1)} · {formatBytes(container.memoryBytes)}</span>
                    </li>
                  ))}</ul> : <IncidentEvidenceEmpty text="No cks workload attribution captured" />}
                </section>

                <section className="incident-evidence-block incident-traffic-block" aria-label="Privacy-preserving request aggregates">
                  <IncidentEvidenceHeading icon="network" title="Request traffic" detail="This capture interval only · request counts, not visitors or client identifiers" />
                  {traffic.length ? <div className="incident-traffic-list">{traffic.map((item, trafficIndex) => (
                    <article key={`${item.app}-${trafficIndex}`}>
                      <div className="incident-traffic-heading"><strong>{safeText(item.app, 'Unknown app', 72)}</strong><span>{formatCount(item.requestCount)} requests this capture</span></div>
                      <div className="incident-status-counts">
                        <span className="tone-good">2xx {formatCount(item.status2xx)}</span>
                        <span>3xx {formatCount(item.status3xx)}</span>
                        <span className="tone-warn">4xx {formatCount(item.status4xx)}</span>
                        <span className="tone-critical">5xx {formatCount(item.status5xx)}</span>
                        <span>{formatCount(item.slowCount)} slow</span>
                      </div>
                      <p>Response {formatMilliseconds(item.avgResponseMs)} average · {formatMilliseconds(item.maxResponseMs)} max</p>
                    </article>
                  ))}</div> : <IncidentEvidenceEmpty text="No request aggregate captured for this interval" />}
                </section>
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

function IncidentMetric({ label, value, tone }: { label: string; value: string; tone: StatusTone }) {
  return <div><dt>{label}</dt><dd className={`tone-${tone}`}>{value}</dd></div>;
}

function IncidentPressure({ label, some, full }: { label: string; some: number | null | undefined; full: number | null | undefined }) {
  return <div><strong>{label}</strong><span>Some {formatPercent(some, 2)}</span><span>Full {formatPercent(full, 2)}</span></div>;
}

function IncidentEvidenceHeading({ icon, title, detail }: { icon: IconName; title: string; detail: string }) {
  return <header className="incident-evidence-heading"><span><Icon name={icon} size={15} /></span><div><h4>{title}</h4><p>{detail}</p></div></header>;
}

function IncidentEvidenceEmpty({ text }: { text: string }) {
  return <p className="incident-evidence-empty">{text}</p>;
}

function PowerEventList({ events }: { events: PowerEvent[] }) {
  if (!events.length) return <InlineEmpty icon="check" text="No power or storage integrity events in this snapshot" positive />;
  return <div className="event-list power-event-list">{events.map((event, index) => {
    const eventTone = eventStatusTone(event.severity, event.status);
    return (
      <article className="event-item power-event-item" key={`${event.timestamp}-${event.kind}-${index}`}>
        <span className={`event-marker event-${eventTone}`}><Icon name={eventTone === 'critical' ? 'alert' : eventTone === 'warn' ? 'zap' : 'check'} size={15} /></span>
        <div className="event-body">
          <div className="event-title"><strong>{safeText(event.kind, 'Power event', 70)}</strong><EventBadges severity={event.severity} status={event.status} /></div>
          <p>{safeText(event.message, 'No details provided')}</p>
          <div className="power-event-meta">
            <time dateTime={event.timestamp || undefined}>{formatDateTime(event.timestamp)}</time>
            {event.supplyVoltageVolts != null && <span>EXT5V {formatVoltage(event.supplyVoltageVolts)}</span>}
            {event.throttledFlags != null && <span>Flags {formatFlags(event.throttledFlags)}</span>}
          </div>
        </div>
      </article>
    );
  })}</div>;
}

function AlertList({ alerts }: { alerts: AlertEvent[] }) {
  if (!alerts.length) return <InlineEmpty icon="check" text="No recent alerts" positive />;
  return <div className="event-list">{alerts.map((alert, index) => {
    const eventTone = eventStatusTone(alert.severity, alert.status);
    return <article className="event-item" key={`${alert.timestamp}-${index}`}><span className={`event-marker event-${eventTone}`}><Icon name={eventTone === 'critical' ? 'alert' : eventTone === 'warn' ? 'info' : 'check'} size={15} /></span><div className="event-body"><div className="event-title"><strong>{safeText(alert.kind, 'System event', 60)}</strong><EventBadges severity={alert.severity} status={alert.status} /></div><p>{safeText(alert.message, 'No details provided')}</p><time dateTime={alert.timestamp || undefined}>{formatDateTime(alert.timestamp)}</time></div></article>;
  })}</div>;
}

function EventBadges({ severity, status }: { severity: unknown; status: unknown }) {
  const severityLabel = safeText(severity, 'Unknown', 32);
  const statusLabel = safeText(status, '', 32);
  return (
    <span className="event-badges">
      <StatusBadge value={severityLabel} tone={eventSeverityTone(severityLabel)} />
      {statusLabel && statusLabel.toLowerCase() !== severityLabel.toLowerCase()
        ? <StatusBadge value={statusLabel} tone={eventStatusTone(severityLabel, statusLabel)} />
        : null}
    </span>
  );
}

function PrivilegeList({ events }: { events: PrivilegeEvent[] }) {
  if (!events.length) return <InlineEmpty icon="shield" text="No recent privilege activity" positive />;
  return <div className="event-list">{events.map((event, index) => (
    <article className="event-item" key={`${event.timestamp}-${index}`}><span className={`event-marker event-${normalizeTone(event.result)}`}><Icon name="shield" size={15} /></span><div className="event-body"><div className="event-title"><strong>{safeText(event.action, 'Privileged operation', 70)}</strong><StatusBadge value={event.result} /></div><p><span className="muted">Actor</span> {safeText(event.actor, 'Unknown', 60)} <span className="event-arrow">→</span> <span className="muted">Target</span> {safeText(event.target, 'Unknown', 80)}</p><time dateTime={event.timestamp || undefined}>{formatDateTime(event.timestamp)}</time></div></article>
  ))}</div>;
}

function DetailsLink({ section, count, label, onNavigate }: { section: string; count: number; label: string; onNavigate: DashboardProps['onNavigate'] }) {
  return (
    <div className="panel-link-row">
      <a href={`/monitor/details#${section}`} onClick={(event) => navigateInApp(event, onNavigate, 'details', `#${section}`)}>
        {label} <span className="sr-only">({count} total)</span><Icon name="chevron" size={14} />
      </a>
    </div>
  );
}

function navigateInApp(event: MouseEvent<HTMLAnchorElement>, onNavigate: DashboardProps['onNavigate'], page: MonitorPage, hash = '') {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  onNavigate(page, hash);
}

function summaryBadge(count: number): string | undefined {
  if (!count) return undefined;
  return count > 10 ? '10+' : String(count);
}

function exactEventBadge(count: number): string | undefined {
  if (!count) return undefined;
  return count >= API_EVENT_CAP ? `${count} MAX` : String(count);
}

function MetricCard({ icon, label, value, detail, percent, accent }: { icon: IconName; label: string; value: string; detail: string; percent?: number | null; accent: string }) {
  const tone = percent == null ? 'good' : toneForPercent(percent);
  return <article className={`metric-card accent-${accent}`}><div className="metric-top"><span className="metric-icon"><Icon name={icon} size={19} /></span>{percent != null && <span className={`metric-state tone-${tone}`}>{tone === 'good' ? 'Nominal' : tone === 'warn' ? 'Elevated' : 'Critical'}</span>}</div><strong className="metric-value">{value}</strong><span className="metric-label">{label}</span><p>{detail}</p>{percent != null && <ProgressBar value={percent} label={`${label} ${value}`} compact />}</article>;
}

function Panel({ title, subtitle, icon, badge, children }: { title: string; subtitle: string; icon: IconName; badge?: string; children: ReactNode }) {
  return <article className="panel"><header className="panel-header"><div className="panel-title"><span><Icon name={icon} size={18} /></span><div><h2>{title}</h2><p>{subtitle}</p></div></div>{badge && <span className="panel-badge">{badge}</span>}</header><div className="panel-content">{children}</div></article>;
}

function ChartFrame({ empty, label, tall, children }: { empty: boolean; label: string; tall?: boolean; children: ReactNode }) {
  return <div className={`chart-frame${tall ? ' chart-tall' : ''}`} role="img" aria-label={label}>{empty ? <InlineEmpty icon="activity" text="No samples in this range" /> : children}</div>;
}

function ProgressBar({ value, label, compact }: { value: number | null; label: string; compact?: boolean }) {
  const safeValue = clampPercent(value);
  return <div className={`progress-track${compact ? ' compact' : ''}`} role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(safeValue)}><span className={`progress-fill tone-bg-${toneForPercent(safeValue)}`} style={{ width: `${safeValue}%` }} /></div>;
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function StatusBadge({ value, tone }: { value: unknown; tone?: StatusTone }) {
  const safeValue = safeText(value, 'Unknown', 32);
  const label = safeValue.replace(/[-_]+/g, ' ');
  return <span className={`status-badge badge-${tone ?? normalizeTone(safeValue)}`}><span />{label}</span>;
}

export function ContainerList({ containers }: { containers: ContainerStatus[] }) {
  const [sort, setSort] = useState<ContainerSort>(DEFAULT_CONTAINER_SORT);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(() => new Set());
  const groups = useMemo(() => groupContainers(containers, sort), [containers, sort]);
  const groupedKeys = groups.filter((group) => group.grouped).map((group) => group.key);
  const allGroupsExpanded = groupedKeys.length > 0 && groupedKeys.every((key) => expandedGroups.has(key));

  function handleSort(key: ContainerSortKey) {
    setSort((current) => nextContainerSort(current, key));
  }

  function toggleGroup(key: string) {
    setExpandedGroups((current) => toggleContainerGroupExpansion(current, key));
  }

  function toggleAllGroups() {
    setExpandedGroups((current) => nextContainerGroupExpansion(current, groupedKeys));
  }

  function handleMobileSortChange(event: ChangeEvent<HTMLSelectElement>) {
    const key = event.currentTarget.value;
    setSort(key === 'default'
      ? DEFAULT_CONTAINER_SORT
      : { key: key as ContainerSortKey, direction: 'ascending' });
  }

  return (
    <>
      {groupedKeys.length > 0 && (
        <div className="container-list-actions">
          <button
            className="container-groups-toggle-all"
            type="button"
            onClick={toggleAllGroups}
            aria-label={`${allGroupsExpanded ? 'Collapse' : 'Expand'} all container groups`}
          >{allGroupsExpanded ? 'Collapse all' : 'Expand all'}</button>
        </div>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr>
            <ContainerSortHeader column="name" label="Service / container" sort={sort} onSort={handleSort} defaultGrouped />
            <ContainerSortHeader column="owner" label="Owner" sort={sort} onSort={handleSort} />
            <ContainerSortHeader column="status" label="Status" sort={sort} onSort={handleSort} />
            <ContainerSortHeader column="cpu" label="CPU" sort={sort} onSort={handleSort} />
            <ContainerSortHeader column="memory" label="Memory" sort={sort} onSort={handleSort} />
          </tr></thead>
          {groups.map((group, groupIndex) => {
            const expanded = group.grouped && expandedGroups.has(group.key);
            const childRegionId = containerGroupRegionId(group, groupIndex, 'desktop');
            return (
              <Fragment key={`${group.key}-desktop`}>
                <tbody>
                  <tr>
                    <td>
                      {group.grouped ? (
                        <ContainerGroupName
                          application={group.application}
                          count={group.children.length}
                          expanded={expanded}
                          controls={childRegionId}
                          onToggle={() => toggleGroup(group.key)}
                        />
                      ) : <ContainerName name={group.children[0].container.name} />}
                    </td>
                    <ContainerDataCells container={group.aggregate} tone={group.tone} combined={group.grouped} />
                  </tr>
                </tbody>
                {group.grouped && (
                  <tbody id={childRegionId} className="container-child-rows" hidden={!expanded}>
                    {group.children.map((child) => (
                      <tr className="container-child-row" key={`${child.key}-desktop`}>
                        <td><ContainerChildName child={child} /></td>
                        <ContainerDataCells container={child.container} />
                      </tr>
                    ))}
                  </tbody>
                )}
              </Fragment>
            );
          })}
        </table>
      </div>
      <div className="container-mobile-sort" role="group" aria-label="Container sorting controls">
        <label>
          <span>Sort by</span>
          <select value={sort.key ?? 'default'} onChange={handleMobileSortChange} aria-label="Sort services and containers by">
            <option value="default">App groups</option>
            {CONTAINER_SORT_OPTIONS.map((option) => <option value={option.key} key={option.key}>{option.label}</option>)}
          </select>
        </label>
        <button
          type="button"
          disabled={sort.key === null}
          onClick={() => sort.key !== null && handleSort(sort.key)}
          aria-label={sort.key === null ? 'Default app grouping active' : `Sort ${sort.direction === 'ascending' ? 'descending' : 'ascending'}`}
        >
          {sort.key === null ? 'Grouped' : sort.direction === 'ascending' ? 'Ascending ↑' : 'Descending ↓'}
        </button>
      </div>
      <div className="container-cards">{groups.map((group, groupIndex) => {
        const expanded = group.grouped && expandedGroups.has(group.key);
        const childRegionId = containerGroupRegionId(group, groupIndex, 'mobile');
        if (!group.grouped) {
          const child = group.children[0];
          return <ContainerCard container={child.container} key={`${child.key}-mobile`} />;
        }

        return (
          <section className="container-mobile-group" key={`${group.key}-mobile`}>
            <ContainerCard
              container={group.aggregate}
              combined
              tone={group.tone}
              heading={(
                <ContainerGroupName
                  application={group.application}
                  count={group.children.length}
                  expanded={expanded}
                  controls={childRegionId}
                  onToggle={() => toggleGroup(group.key)}
                />
              )}
            />
            <div id={childRegionId} className="container-mobile-children" hidden={!expanded}>
              {group.children.map((child) => (
                <ContainerCard
                  child={child}
                  container={child.container}
                  key={`${child.key}-mobile`}
                />
              ))}
            </div>
          </section>
        );
      })}</div>
    </>
  );
}

function ContainerName({ name }: { name: string }) {
  const displayName = safeText(name, 'Unnamed', 70);
  const accessibleName = safeText(name, 'Unnamed', 140);
  return <strong title={accessibleName === displayName ? undefined : accessibleName}>{displayName}</strong>;
}

function ContainerGroupName({
  application,
  count,
  expanded,
  controls,
  onToggle,
}: {
  application: string;
  count: number;
  expanded: boolean;
  controls: string;
  onToggle: () => void;
}) {
  const displayName = safeText(application, 'Unnamed', 70);
  const accessibleName = safeText(application, 'Unnamed', 140);
  const action = expanded ? 'Collapse' : 'Expand';
  return (
    <div className="container-group-name">
      <strong title={accessibleName === displayName ? undefined : accessibleName}>{displayName}</strong>
      <button
        className="container-group-toggle"
        type="button"
        aria-expanded={expanded}
        aria-controls={controls}
        aria-label={`${action} ${accessibleName} containers`}
        title={`${count} containers`}
        onClick={onToggle}
      ><span aria-hidden="true">{expanded ? '−' : '+'}</span></button>
    </div>
  );
}

function ContainerChildName({ child }: { child: ContainerGroupChild }) {
  const fullName = safeText(child.container.name, 'Unnamed', 140);
  const accessibleName = `${safeText(child.application, 'Unnamed', 70)} ${safeText(child.component, 'component', 28)} container (${fullName})`;
  return (
    <span className="container-child-name" title={fullName}>
      <strong aria-hidden="true">{safeText(child.component, 'component', 28)}</strong>
      <span className="sr-only">{accessibleName}</span>
    </span>
  );
}

function ContainerDataCells({
  container,
  tone,
  combined = false,
}: {
  container: ContainerStatus;
  tone?: StatusTone;
  combined?: boolean;
}) {
  return (
    <>
      <td>{safeText(container.owner, '—', 50)}</td>
      <td><ContainerStatusReading container={container} tone={tone} /></td>
      <td><strong>{formatPercent(container.cpuPercent, 1)}</strong></td>
      <td><ContainerMemoryReading container={container} combined={combined} /></td>
    </>
  );
}

function ContainerStatusReading({ container, tone }: { container: ContainerStatus; tone?: StatusTone }) {
  const status = containerStatusPresentation(container);
  return (
    <div className="status-stack">
      <StatusBadge value={status.badge} tone={tone ?? containerOperationalTone(container)} />
      {status.detail && <span className="health-detail">{safeText(status.detail, 'Unknown', 32)}</span>}
    </div>
  );
}

function ContainerMemoryReading({ container, combined = false }: { container: ContainerStatus; combined?: boolean }) {
  return (
    <div className="memory-cell">
      <strong>{formatBytes(container.memoryBytes)}</strong>
      <span>{combined ? 'Combined usage' : formatPercent(container.memoryPercent, 1)}</span>
    </div>
  );
}

function ContainerCard({
  container,
  child,
  heading,
  combined = false,
  tone,
}: {
  container: ContainerStatus;
  child?: ContainerGroupChild;
  heading?: ReactNode;
  combined?: boolean;
  tone?: StatusTone;
}) {
  const status = containerStatusPresentation(container);
  return (
    <article className={`container-card${child ? ' container-child-card' : ''}`}>
      <div className="container-card-head">
        <div>
          {heading ?? (child ? <ContainerChildName child={child} /> : <ContainerName name={container.name} />)}
          <span className="container-card-owner">{safeText(container.owner, 'No owner', 50)}</span>
        </div>
        <StatusBadge value={status.badge} tone={tone ?? containerOperationalTone(container)} />
      </div>
      <dl>
        <div><dt>State</dt><dd>{safeText(container.state)}</dd></div>
        <div><dt>CPU</dt><dd>{formatPercent(container.cpuPercent, 1)}</dd></div>
        <div><dt>Memory</dt><dd>{formatBytes(container.memoryBytes)}{combined ? ' · combined' : ` · ${formatPercent(container.memoryPercent, 1)}`}</dd></div>
      </dl>
    </article>
  );
}

function containerStatusPresentation(container: ContainerStatus): { badge: string | null; detail: string | null } {
  const state = sortableText(container.state);
  const health = sortableText(container.health);
  if (health && /(unhealthy|starting|unknown)/i.test(health)) {
    return { badge: health, detail: state && state.toLowerCase() !== health.toLowerCase() ? state : null };
  }
  if (!state && health) return { badge: health, detail: null };
  return {
    badge: state,
    detail: health && (!state || health.toLowerCase() !== state.toLowerCase()) ? health : null,
  };
}

function containerGroupRegionId(group: ContainerGroup, index: number, surface: 'desktop' | 'mobile'): string {
  const safeKey = group.key.replace(/[^a-zA-Z0-9_-]+/g, '-');
  return `container-${surface}-${index}-${safeKey}`;
}

function ContainerSortHeader({
  column,
  label,
  sort,
  onSort,
  defaultGrouped = false,
}: {
  column: ContainerSortKey;
  label: string;
  sort: ContainerSort;
  onSort: (key: ContainerSortKey) => void;
  defaultGrouped?: boolean;
}) {
  const active = sort.key === column;
  const grouped = sort.key === null && defaultGrouped;
  const ariaSort: ContainerSortDirection | 'other' | undefined = active ? sort.direction : grouped ? 'other' : undefined;
  const nextDirection: ContainerSortDirection = active && sort.direction === 'ascending' ? 'descending' : 'ascending';
  const indicator = active ? (sort.direction === 'ascending' ? '↑' : '↓') : grouped ? '◆' : '↕';

  return (
    <th scope="col" aria-sort={ariaSort}>
      <button
        className="container-sort-button"
        type="button"
        onClick={() => onSort(column)}
        aria-label={`Sort by ${label} ${nextDirection}`}
      >
        <span>{label}</span>
        <span className={`container-sort-indicator${active || grouped ? ' active' : ''}`} aria-hidden="true">{indicator}</span>
      </button>
    </th>
  );
}

export function nextContainerSort(current: ContainerSort, key: ContainerSortKey): ContainerSort {
  if (current.key !== key) return { key, direction: 'ascending' };
  return { key, direction: current.direction === 'ascending' ? 'descending' : 'ascending' };
}

export function toggleContainerGroupExpansion(current: ReadonlySet<string>, key: string): Set<string> {
  const next = new Set(current);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

export function nextContainerGroupExpansion(
  current: ReadonlySet<string>,
  groupKeys: string[],
): Set<string> {
  const allExpanded = groupKeys.length > 0 && groupKeys.every((key) => current.has(key));
  return allExpanded ? new Set() : new Set(groupKeys);
}

export function groupContainers(
  containers: ContainerStatus[],
  sort: ContainerSort = DEFAULT_CONTAINER_SORT,
): ContainerGroup[] {
  const candidates = new Map<string, Array<{ container: ContainerStatus; component: string; index: number }>>();

  containers.forEach((container, index) => {
    const parts = containerGroupParts(container.name);
    if (parts.component === null) return;
    const key = parts.application.toLowerCase();
    const members = candidates.get(key) ?? [];
    members.push({ container, component: parts.component, index });
    candidates.set(key, members);
  });

  const groupedApplications = new Set(
    Array.from(candidates.entries())
      .filter(([, members]) => members.length > 1)
      .map(([application]) => application),
  );
  const emittedApplications = new Set<string>();
  const groups: Array<ContainerGroup & { index: number }> = [];

  containers.forEach((container, index) => {
    const parts = containerGroupParts(container.name);
    const applicationKey = parts.application.toLowerCase();
    if (parts.component !== null && groupedApplications.has(applicationKey)) {
      if (emittedApplications.has(applicationKey)) return;
      emittedApplications.add(applicationKey);
      const members = candidates.get(applicationKey) ?? [];
      const children = members
        .slice()
        .sort((left, right) => {
          const byComponent = containerComponentRank(left.component) - containerComponentRank(right.component);
          return byComponent || compareText(left.container.name, right.container.name, 'ascending') || left.index - right.index;
        })
        .map((member) => ({
          key: `container:${member.index}:${member.container.name}`,
          application: parts.application,
          component: member.component,
          container: member.container,
        }));
      const aggregate = aggregateContainerGroup(parts.application, children.map((child) => child.container));
      groups.push({
        key: `group:${applicationKey}`,
        application: parts.application,
        aggregate,
        children,
        grouped: true,
        runningCount: runningContainerCount(children.map((child) => child.container)),
        tone: worstContainerTone(children.map((child) => child.container)),
        index: members[0]?.index ?? index,
      });
      return;
    }

    groups.push({
      key: `container:${index}:${container.name}`,
      application: container.name,
      aggregate: container,
      children: [{
        key: `container:${index}:${container.name}`,
        application: container.name,
        component: container.name,
        container,
      }],
      grouped: false,
      runningCount: runningContainerCount([container]),
      tone: containerOperationalTone(container),
      index,
    });
  });

  return groups
    .sort((left, right) => {
      let primary: number;
      if (sort.key === null) {
        primary = compareDefaultContainerOrder(left.aggregate, right.aggregate);
      } else if (sort.key === 'status') {
        const leftMissing = containerStatusMissing(left.aggregate);
        const rightMissing = containerStatusMissing(right.aggregate);
        primary = leftMissing !== rightMissing
          ? (leftMissing ? 1 : -1)
          : compareNumber(containerToneRank(left.tone), containerToneRank(right.tone), sort.direction)
            || compareContainerColumn(left.aggregate, right.aggregate, sort.key, sort.direction);
      } else {
        primary = compareContainerColumn(left.aggregate, right.aggregate, sort.key, sort.direction);
      }
      if (primary !== 0) return primary;
      const byName = compareText(left.application, right.application, 'ascending');
      return byName || left.index - right.index;
    })
    .map(({ index: _index, ...group }) => group);
}

function containerGroupParts(name: string): ContainerNameParts {
  const fullName = name.trim();
  const mapped = CONTAINER_GROUP_MEMBERS[fullName.toLowerCase()];
  return mapped ?? { application: fullName, component: null };
}

function aggregateContainerGroup(application: string, containers: ContainerStatus[]): ContainerStatus {
  const owners = containers
    .map((container) => sortableText(container.owner))
    .filter((owner): owner is string => owner !== null);
  const uniqueOwners = Array.from(new Set(owners.map((owner) => owner.toLowerCase())));
  const owner = owners.length === containers.length && uniqueOwners.length === 1
    ? owners[0]
    : uniqueOwners.length > 1
      ? 'Multiple'
      : null;
  const running = runningContainerCount(containers);

  return {
    name: application,
    owner,
    state: `${running}/${containers.length} running`,
    health: aggregateContainerHealth(containers),
    cpuPercent: aggregateContainerMetric(containers, (container) => container.cpuPercent),
    memoryBytes: aggregateContainerMetric(containers, (container) => container.memoryBytes),
    // Each percentage can have a different Docker memory limit. Without those
    // denominators, adding the percentages would present a false total.
    memoryPercent: null,
  };
}

function aggregateContainerMetric(
  containers: ContainerStatus[],
  select: (container: ContainerStatus) => number | null,
): number | null {
  let total = 0;
  let available = 0;
  for (const container of containers) {
    const value = select(container);
    if (typeof value === 'number' && Number.isFinite(value)) {
      total += value;
      available += 1;
      continue;
    }
    const state = safeText(container.state, '').toLowerCase();
    // These inactive states have no live resource usage. Other missing values
    // (notably paused/restarting containers) make the combined reading unknown.
    if (!/^(created|exited|dead)$/.test(state)) return null;
    available += 1;
  }
  return available ? total : null;
}

function aggregateContainerHealth(containers: ContainerStatus[]): string {
  const health = containers.map((container) => safeText(container.health, '').toLowerCase());
  const unhealthy = health.filter((value) => value === 'unhealthy').length;
  if (unhealthy) return `${unhealthy} unhealthy`;
  const starting = health.filter((value) => value === 'starting').length;
  if (starting) return `${starting} starting`;
  const healthy = health.filter((value) => value === 'healthy').length;
  if (healthy === health.length && health.length) return 'healthy';
  const unknown = health.filter((value) => !value || value === 'unknown').length;
  if (unknown) return `${unknown} unknown`;
  const unchecked = health.filter((value) => value === 'none').length;
  if (unchecked === health.length && health.length) return 'not checked';
  if (healthy + unchecked === health.length) return `${healthy} healthy · ${unchecked} not checked`;
  return 'mixed health';
}

function runningContainerCount(containers: ContainerStatus[]): number {
  return containers.filter((container) => safeText(container.state, '').toLowerCase() === 'running').length;
}

function containerOperationalTone(container: ContainerStatus): StatusTone {
  const state = safeText(container.state, '').toLowerCase();
  const health = safeText(container.health, '').toLowerCase();
  if (health === 'unhealthy' || /^(dead|exited)$/.test(state)) return 'critical';
  if (/^(created|paused|restarting|removing|unknown)$/.test(state) || /^(starting|unknown)$/.test(health)) return 'warn';
  if (state === 'running' && (!health || /^(healthy|none)$/.test(health))) return 'good';
  return normalizeTone(health || state);
}

function worstContainerTone(containers: ContainerStatus[]): StatusTone {
  return containers.reduce<StatusTone>((worst, container) => {
    const tone = containerOperationalTone(container);
    return containerToneRank(tone) > containerToneRank(worst) ? tone : worst;
  }, 'neutral');
}

function containerToneRank(tone: StatusTone): number {
  if (tone === 'critical') return 3;
  if (tone === 'warn') return 2;
  if (tone === 'good') return 1;
  return 0;
}

function containerStatusMissing(container: ContainerStatus): boolean {
  return sortableText(container.state) === null && sortableText(container.health) === null;
}

export function sortContainers(
  containers: ContainerStatus[],
  sort: ContainerSort = DEFAULT_CONTAINER_SORT,
): ContainerStatus[] {
  return containers
    .map((container, index) => ({ container, index }))
    .sort((left, right) => {
      const primary = sort.key === null
        ? compareDefaultContainerOrder(left.container, right.container)
        : compareContainerColumn(left.container, right.container, sort.key, sort.direction);
      if (primary !== 0) return primary;

      const byName = compareText(left.container.name, right.container.name, 'ascending');
      if (byName !== 0) return byName;
      return left.index - right.index;
    })
    .map(({ container }) => container);
}

function compareDefaultContainerOrder(left: ContainerStatus, right: ContainerStatus): number {
  const leftRank = defaultContainerRank(left.name);
  const rightRank = defaultContainerRank(right.name);
  const rankDifference = leftRank - rightRank;
  if (rankDifference !== 0) return rankDifference;

  if (leftRank === 4) {
    const leftParts = containerNameParts(left.name);
    const rightParts = containerNameParts(right.name);
    const byApplication = compareText(leftParts.application, rightParts.application, 'ascending');
    if (byApplication !== 0) return byApplication;

    const componentDifference = containerComponentRank(leftParts.component) - containerComponentRank(rightParts.component);
    if (componentDifference !== 0) return componentDifference;
  }

  return compareText(left.name, right.name, 'ascending');
}

function defaultContainerRank(name: string): number {
  const normalized = name.trim().toLowerCase();
  if (normalized === 'bonifacio' || normalized.startsWith('bonifacio-')) return 0;
  if (normalized === 'sso' || normalized.startsWith('sso-')) return 1;
  if (normalized === 'cks-database') return 2;
  if (normalized === 'monitor') return 3;
  return 4;
}

export function containerNameParts(name: string): ContainerNameParts {
  const fullName = name.trim();
  const normalized = fullName.toLowerCase();
  if (!fullName || FIXED_CONTAINER_NAMES.has(normalized)) {
    return { application: fullName, component: null };
  }

  const separatorIndex = normalized.lastIndexOf('-');
  if (separatorIndex <= 0 || separatorIndex === normalized.length - 1) {
    return { application: fullName, component: null };
  }

  const component = normalized.slice(separatorIndex + 1);
  if (!Object.prototype.hasOwnProperty.call(CONTAINER_COMPONENT_ORDER, component)) {
    return { application: fullName, component: null };
  }

  return {
    application: fullName.slice(0, separatorIndex),
    component: fullName.slice(separatorIndex + 1),
  };
}

function containerComponentRank(component: string | null): number {
  if (component === null) return -1;
  return CONTAINER_COMPONENT_ORDER[component.toLowerCase()] ?? Number.MAX_SAFE_INTEGER;
}

function compareContainerColumn(
  left: ContainerStatus,
  right: ContainerStatus,
  key: ContainerSortKey,
  direction: ContainerSortDirection,
): number {
  if (key === 'name') return compareText(left.name, right.name, direction);
  if (key === 'owner') return compareText(left.owner, right.owner, direction);
  if (key === 'cpu') return compareNumber(left.cpuPercent, right.cpuPercent, direction);
  if (key === 'memory') {
    return compareNumber(left.memoryBytes, right.memoryBytes, direction)
      || compareNumber(left.memoryPercent, right.memoryPercent, direction);
  }
  return compareText(left.state, right.state, direction)
    || compareText(left.health, right.health, direction);
}

function compareText(left: unknown, right: unknown, direction: ContainerSortDirection): number {
  const leftValue = sortableText(left);
  const rightValue = sortableText(right);
  if (leftValue === null) return rightValue === null ? 0 : 1;
  if (rightValue === null) return -1;
  const comparison = CONTAINER_SORT_COLLATOR.compare(leftValue, rightValue);
  return direction === 'ascending' ? comparison : -comparison;
}

function sortableText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function compareNumber(left: unknown, right: unknown, direction: ContainerSortDirection): number {
  const leftValue = sortableNumber(left);
  const rightValue = sortableNumber(right);
  if (leftValue === null) return rightValue === null ? 0 : 1;
  if (rightValue === null) return -1;
  const comparison = leftValue - rightValue;
  return direction === 'ascending' ? comparison : -comparison;
}

function sortableNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function InlineEmpty({ icon, text, positive }: { icon: IconName; text: string; positive?: boolean }) {
  return <div className={`inline-empty${positive ? ' positive' : ''}`}><Icon name={icon} size={19} /><span>{text}</span></div>;
}

function EmptyState({ icon, title, detail, action }: { icon: IconName; title: string; detail: string; action?: ReactNode }) {
  return <section className="empty-state"><span><Icon name={icon} size={26} /></span><h2>{title}</h2><p>{detail}</p>{action}</section>;
}

function DashboardSkeleton() {
  return <div className="skeleton-layout" aria-label="Loading telemetry" aria-busy="true"><div className="metric-grid">{Array.from({ length: 4 }, (_, index) => <div className="metric-card skeleton-card" key={index}><i /><i /><i /></div>)}</div><div className="two-column">{Array.from({ length: 2 }, (_, index) => <div className="panel skeleton-panel" key={index}><i /><i /></div>)}</div><span className="sr-only">Loading telemetry dashboard</span></div>;
}

function PercentTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item: any) => <span key={item.dataKey}><i style={{ background: item.color }} />{item.name}<b>{formatPercent(Number(item.value), 1)}</b></span>)}</div>;
}

function ThermalTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item: any) => <span key={item.dataKey}><i style={{ background: item.color }} />{item.name}<b>{item.dataKey === 'temperatureC' ? `${Number(item.value).toFixed(1)}°C` : Number(item.value).toFixed(2)}</b></span>)}</div>;
}

function IoTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item: any) => <span key={item.dataKey}><i style={{ background: item.color }} />{item.name}<b>{formatRate(Number(item.value))}</b></span>)}</div>;
}

function VoltageTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item: any) => <span key={item.dataKey}><i style={{ background: item.color }} />{item.name}<b>{formatVoltage(item.value)}</b></span>)}</div>;
}

export function decodeThrottledFlags(value: number | null | undefined): { available: boolean; active: string[]; historical: string[] } {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 0xffff_ffff) {
    return { available: false, active: [], historical: [] };
  }

  const flags = Number(value) >>> 0;
  const activeDefinitions: Array<[number, string]> = [
    [0x1, 'Under-voltage detected'],
    [0x2, 'ARM frequency capped'],
    [0x4, 'Throttling active'],
    [0x8, 'Soft temperature limit active'],
  ];
  const historicalDefinitions: Array<[number, string]> = [
    [0x1_0000, 'Under-voltage has occurred'],
    [0x2_0000, 'ARM frequency capping has occurred'],
    [0x4_0000, 'Throttling has occurred'],
    [0x8_0000, 'Soft temperature limit has occurred'],
  ];
  const active = activeDefinitions.filter(([mask]) => (flags & mask) !== 0).map(([, label]) => label);
  const historical = historicalDefinitions.filter(([mask]) => (flags & mask) !== 0).map(([, label]) => label);
  const unknownActive = (flags & 0x0000_fff0) >>> 0;
  const unknownHistorical = (flags & 0xfff0_0000) >>> 0;
  if (unknownActive) active.push(`Unknown active bits ${formatFlags(unknownActive)}`);
  if (unknownHistorical) historical.push(`Unknown historical bits ${formatFlags(unknownHistorical)}`);
  return { available: true, active, historical };
}

function normalizedPowerSummary(summary: PowerSummary | null | undefined, series: TelemetrySample[]): PowerSummary {
  const voltages = series
    .map((sample) => sample.supplyVoltageVolts)
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0);
  const fallback: PowerSummary = {
    sampleCount: series.length,
    voltageSampleCount: voltages.length,
    minSupplyVoltageVolts: voltages.length ? Math.min(...voltages) : null,
    averageSupplyVoltageVolts: voltages.length ? voltages.reduce((total, value) => total + value, 0) / voltages.length : null,
    maxSupplyVoltageVolts: voltages.length ? Math.max(...voltages) : null,
    underVoltageSampleCount: series.filter((sample) => validFlags(sample.throttledFlags) !== null && (validFlags(sample.throttledFlags)! & 0x1) !== 0).length,
    throttledSampleCount: series.filter((sample) => validFlags(sample.throttledFlags) !== null && (validFlags(sample.throttledFlags)! & 0x4) !== 0).length,
  };

  if (!summary || typeof summary !== 'object') return fallback;
  return {
    sampleCount: validCount(summary.sampleCount, fallback.sampleCount),
    voltageSampleCount: validCount(summary.voltageSampleCount, fallback.voltageSampleCount),
    minSupplyVoltageVolts: validNullableMeasurement(summary.minSupplyVoltageVolts, fallback.minSupplyVoltageVolts),
    averageSupplyVoltageVolts: validNullableMeasurement(summary.averageSupplyVoltageVolts, fallback.averageSupplyVoltageVolts),
    maxSupplyVoltageVolts: validNullableMeasurement(summary.maxSupplyVoltageVolts, fallback.maxSupplyVoltageVolts),
    underVoltageSampleCount: validCount(summary.underVoltageSampleCount, fallback.underVoltageSampleCount),
    throttledSampleCount: validCount(summary.throttledSampleCount, fallback.throttledSampleCount),
  };
}

function validCount(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}

function validNullableMeasurement(value: unknown, fallback: number | null): number | null {
  if (value === null) return null;
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function validFlags(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff
    ? value >>> 0
    : null;
}

function voltageChartDomain(values: number[]): [number, number] {
  const finiteValues = values.filter((value) => Number.isFinite(value) && value >= 0);
  if (!finiteValues.length) return [4.5, 5.5];
  const minimum = Math.min(...finiteValues);
  const maximum = Math.max(...finiteValues);
  const padding = Math.max(0.025, (maximum - minimum) * 0.15);
  return [
    Math.max(0, Math.floor((minimum - padding) * 100) / 100),
    Math.ceil((maximum + padding) * 100) / 100,
  ];
}

function formatVoltage(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value.toFixed(3)} V` : '—';
}

export function formatFlags(value: unknown): string {
  const flags = validFlags(value);
  return flags === null ? 'Unavailable' : `0x${flags.toString(16).padStart(8, '0')}`;
}

function formatCount(value: unknown): string {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : '—';
}

function incidentReasonLabel(value: unknown): string {
  const normalized = safeText(value, '', 72).toLowerCase();
  const labels: Record<string, string> = {
    cpu: 'High CPU usage',
    memory: 'High memory usage',
    temperature: 'High temperature',
    load: 'High system load',
    'disk-io': 'High disk I/O',
    'power-throttle': 'Power throttling',
    traffic: 'High request traffic',
  };
  return labels[normalized] ?? normalized.replace(/[-_]+/g, ' ');
}

function incidentPhaseTone(value: unknown): StatusTone {
  if (value === 'active') return 'critical';
  if (value === 'follow-up') return 'warn';
  if (value === 'recovered') return 'good';
  return 'neutral';
}

function formatIncidentDuration(incident: PeakIncident): string {
  let seconds = typeof incident.durationSeconds === 'number' && Number.isFinite(incident.durationSeconds)
    ? Math.max(0, incident.durationSeconds)
    : Number.NaN;
  if (!Number.isFinite(seconds)) {
    const start = new Date(incident.startedAt).getTime();
    const end = new Date(incident.endedAt ?? incident.observedAt).getTime();
    seconds = Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, (end - start) / 1_000) : Number.NaN;
  }
  if (!Number.isFinite(seconds)) return 'Duration unavailable';
  if (seconds < 60) return `${Math.round(seconds)}s window`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${Math.round(seconds % 60)}s window`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m window`;
}

function formatTemperature(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}°C` : '—';
}

function temperatureTone(value: number | null | undefined): StatusTone {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'neutral';
  if (value >= 85) return 'critical';
  if (value >= 75) return 'warn';
  return 'good';
}

function loadTone(value: number | null | undefined): StatusTone {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'neutral';
  if (value >= 8) return 'critical';
  if (value >= 4) return 'warn';
  return 'good';
}

function formatMilliseconds(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—';
  return value >= 1_000 ? `${(value / 1_000).toFixed(2)} s` : `${Math.round(value)} ms`;
}

function compactBytes(value: number): string {
  const text = formatBytes(value, 0);
  return text.replace(' ', '');
}

function normalizeTone(value: unknown): StatusTone {
  const normalized = safeText(value, '').toLowerCase();
  if (/(critical|error|fail|denied|unhealthy|dead|down|exited)/.test(normalized)) return 'critical';
  if (/(warn|pending|degrad|unknown|starting|stale|under.?voltage|throttl|thermal.?limit|frequency.?cap)/.test(normalized)) return 'warn';
  if (/(ok|success|healthy|running|online|active|resolved|allowed|nominal)/.test(normalized) || /\b(?:normal|on)\b/.test(normalized)) return 'good';
  return 'neutral';
}

export function eventStatusTone(severity: unknown, status: unknown): StatusTone {
  const normalizedStatus = safeText(status, '').toLowerCase();
  if (/\b(?:recovered|resolved|cleared|normal|nominal|restored)\b/.test(normalizedStatus)) return 'good';
  const severityTone = eventSeverityTone(severity);
  if (severityTone !== 'neutral') return severityTone;
  if (/\bactive\b/.test(normalizedStatus)) return 'warn';
  return severityTone;
}

function eventSeverityTone(severity: unknown): StatusTone {
  const normalizedSeverity = safeText(severity, '').toLowerCase();
  if (/(info|notice)/.test(normalizedSeverity)) return 'good';
  return normalizeTone(normalizedSeverity);
}

function powerStateTone(value: unknown): StatusTone {
  const normalized = safeText(value, '').toLowerCase();
  if (!normalized) return 'neutral';
  if (/\bactive\b/.test(normalized) && !/(inactive|not active)/.test(normalized)) return 'warn';
  return normalizeTone(normalized);
}

export function currentPowerStatusTone(throttledFlags: number | null | undefined, powerState: unknown): StatusTone {
  const flags = decodeThrottledFlags(throttledFlags);
  if (!flags.available) return powerStateTone(powerState);
  const normalizedState = safeText(powerState, '').toLowerCase();
  const reportedTone = powerStateTone(normalizedState);
  if (flags.active.length) return reportedTone === 'critical' ? 'critical' : 'warn';
  if (!normalizedState || /\b(?:normal|nominal)\b/.test(normalizedState) || /\bdegraded[-_ ]history\b/.test(normalizedState)) return 'good';
  return reportedTone;
}

export function containerSummaryLabel(containers: ContainerStatus[]): string {
  const running = containers.filter((container) => safeText(container.state, '').toLowerCase() === 'running').length;
  const stoppedOrOther = containers.length - running;
  const unhealthy = containers.filter((container) => safeText(container.health, '').toLowerCase() === 'unhealthy').length;
  return `${running} running · ${stoppedOrOther} stopped/other · ${containers.length} tracked total${unhealthy ? ` · ${unhealthy} unhealthy` : ''}`;
}

function formatDecimal(value: number | null | undefined): string {
  return Number.isFinite(value) ? Number(value).toFixed(2) : '—';
}

function formatFreeBytes(total: number | null, used: number | null): string {
  if (!Number.isFinite(total) || !Number.isFinite(used)) return '—';
  return formatBytes(Math.max(0, Number(total) - Number(used)));
}
