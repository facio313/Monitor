import { useMemo, useState, type ReactNode } from 'react';
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
import type { ContainerStatus, DashboardPayload, TimeRange } from '../types';
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

interface DashboardProps {
  onLogout: () => Promise<void>;
  onPasswordChanged: () => void;
  onUnauthorized: () => void;
}

export function Dashboard({ onLogout, onPasswordChanged, onUnauthorized }: DashboardProps) {
  const [range, setRange] = useState<TimeRange>('24h');
  const [loggingOut, setLoggingOut] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const { data, error, initialLoading, refreshing, lastUpdated, refresh } = useDashboard(range, onUnauthorized);

  async function handleLogout() {
    setLoggingOut(true);
    await onLogout();
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
          <span className="secure-label"><span className="status-dot status-dot-good" />Secure session</span>
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
            <span className="eyebrow">System overview</span>
            <h1 id="dashboard-title">{data ? safeText(data.host.hostname, 'Host') : 'Host telemetry'}</h1>
            <p className="heading-copy">Current health, performance, and operational activity at a glance.</p>
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

        {initialLoading && !data ? <DashboardSkeleton /> : data ? <DashboardContent data={data} range={range} /> : (
          <EmptyState icon="server" title="No telemetry available" detail="The collector has not returned a dashboard snapshot yet." action={<button className="secondary-button" onClick={() => void refresh()}>Retry</button>} />
        )}
      </main>

      <footer className="app-footer" inert={passwordDialogOpen || undefined}>
        <span><Icon name="shield" size={14} />Private monitor</span>
        <span>Generated {data ? formatDateTime(data.generatedAt) : '—'}</span>
      </footer>

      <PasswordChangeDialog
        open={passwordDialogOpen}
        onClose={() => setPasswordDialogOpen(false)}
        onPasswordChanged={onPasswordChanged}
        onUnauthorized={onUnauthorized}
      />
    </div>
  );
}

function DashboardContent({ data, range }: { data: DashboardPayload; range: TimeRange }) {
  const chartData = useMemo(() => data.series.map((point) => ({ ...point, label: formatTime(point.timestamp, range) })), [data.series, range]);
  const latest = data.latest;
  const temperature = latest?.temperatureC ?? null;
  const maxDisk = data.disks.reduce((highest, disk) => Math.max(highest, disk.usedPercent ?? 0), 0);
  const unhealthyContainers = data.containers.filter((container) => !isContainerHealthy(container)).length;

  return (
    <div className="dashboard-content">
      <section className="metric-grid" aria-label="Current system metrics">
        <MetricCard icon="cpu" label="CPU usage" value={formatPercent(latest?.cpuPercent, 1)} detail={`Load ${formatDecimal(latest?.load1)} · 1 min`} percent={latest?.cpuPercent} accent="cyan" />
        <MetricCard icon="memory" label="Memory" value={formatPercent(latest?.memoryPercent, 1)} detail={`${formatBytes(latest?.memoryUsedBytes)} of ${formatBytes(latest?.memoryTotalBytes)}`} percent={latest?.memoryPercent} accent="violet" />
        <MetricCard icon="temperature" label="Temperature" value={temperature == null ? '—' : `${temperature.toFixed(1)}°C`} detail={temperature == null ? 'Sensor unavailable' : temperature >= 80 ? 'Running hot' : 'Within operating range'} percent={temperature == null ? undefined : temperature} accent="orange" />
        <MetricCard icon="activity" label="System load" value={formatDecimal(latest?.load1)} detail={`${formatDecimal(latest?.load5)} / ${formatDecimal(latest?.load15)} · 5m / 15m`} accent="green" />
      </section>

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

      <Panel title="Containers" subtitle={`${data.containers.length} workload${data.containers.length === 1 ? '' : 's'} · ${unhealthyContainers ? `${unhealthyContainers} need attention` : 'all nominal'}`} icon="server">
        {data.containers.length ? <ContainerList containers={data.containers} /> : <InlineEmpty icon="server" text="No containers reported" />}
      </Panel>

      <section className="two-column activity-layout">
        <Panel title="Alerts" subtitle="Recent collector and system notices" icon="alert" badge={data.alerts.length ? String(data.alerts.length) : undefined}>
          {data.alerts.length ? <div className="event-list">{data.alerts.map((alert, index) => {
            const severity = normalizeTone(alert.severity);
            return <article className="event-item" key={`${alert.timestamp}-${index}`}><span className={`event-marker event-${severity}`}><Icon name={severity === 'critical' ? 'alert' : severity === 'warn' ? 'info' : 'check'} size={15} /></span><div className="event-body"><div className="event-title"><strong>{safeText(alert.kind, 'System event', 60)}</strong><StatusBadge value={alert.status} /></div><p>{safeText(alert.message, 'No details provided')}</p><time dateTime={alert.timestamp || undefined}>{formatDateTime(alert.timestamp)}</time></div></article>;
          })}</div> : <InlineEmpty icon="check" text="No recent alerts" positive />}
        </Panel>

        <Panel title="Privilege activity" subtitle="Recent elevated operations" icon="shield" badge={data.privilegeEvents.length ? String(data.privilegeEvents.length) : undefined}>
          {data.privilegeEvents.length ? <div className="event-list">{data.privilegeEvents.map((event, index) => (
            <article className="event-item" key={`${event.timestamp}-${index}`}><span className={`event-marker event-${normalizeTone(event.result)}`}><Icon name="shield" size={15} /></span><div className="event-body"><div className="event-title"><strong>{safeText(event.action, 'Privileged operation', 70)}</strong><StatusBadge value={event.result} /></div><p><span className="muted">Actor</span> {safeText(event.actor, 'Unknown', 60)} <span className="event-arrow">→</span> <span className="muted">Target</span> {safeText(event.target, 'Unknown', 80)}</p><time dateTime={event.timestamp || undefined}>{formatDateTime(event.timestamp)}</time></div></article>
          ))}</div> : <InlineEmpty icon="shield" text="No recent privilege activity" positive />}
        </Panel>
      </section>
    </div>
  );
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

function StatusBadge({ value }: { value: unknown }) {
  const safeValue = safeText(value, 'Unknown', 32);
  const label = safeValue.replace(/[-_]+/g, ' ');
  return <span className={`status-badge badge-${normalizeTone(safeValue)}`}><span />{label}</span>;
}

function ContainerList({ containers }: { containers: ContainerStatus[] }) {
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead><tr><th scope="col">Container</th><th scope="col">Owner</th><th scope="col">Status</th><th scope="col">CPU</th><th scope="col">Memory</th></tr></thead>
          <tbody>{containers.map((container, index) => (
            <tr key={`${container.name}-${index}`}>
              <td><strong>{safeText(container.name, 'Unnamed', 70)}</strong></td>
              <td>{safeText(container.owner, '—', 50)}</td>
              <td>
                <div className="status-stack">
                  <StatusBadge value={container.state} />
                  {container.health
                    && (!container.state || container.health.toLowerCase() !== container.state.toLowerCase())
                    && <span className="health-detail">{safeText(container.health, 'Unknown', 32)}</span>}
                </div>
              </td>
              <td><strong>{formatPercent(container.cpuPercent, 1)}</strong></td>
              <td><div className="memory-cell"><strong>{formatBytes(container.memoryBytes)}</strong><span>{formatPercent(container.memoryPercent, 1)}</span></div></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div className="container-cards">{containers.map((container, index) => (
        <article className="container-card" key={`${container.name}-mobile-${index}`}>
          <div className="container-card-head">
            <div><strong>{safeText(container.name, 'Unnamed', 70)}</strong><span>{safeText(container.owner, 'No owner', 50)}</span></div>
            <StatusBadge value={container.health || container.state} />
          </div>
          <dl>
            <div><dt>State</dt><dd>{safeText(container.state)}</dd></div>
            <div><dt>CPU</dt><dd>{formatPercent(container.cpuPercent, 1)}</dd></div>
            <div><dt>Memory</dt><dd>{formatBytes(container.memoryBytes)} · {formatPercent(container.memoryPercent, 1)}</dd></div>
          </dl>
        </article>
      ))}</div>
    </>
  );
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

function compactBytes(value: number): string {
  const text = formatBytes(value, 0);
  return text.replace(' ', '');
}

function normalizeTone(value: unknown): 'good' | 'warn' | 'critical' | 'neutral' {
  const normalized = safeText(value, '').toLowerCase();
  if (/(critical|error|fail|denied|unhealthy|dead|down|exited)/.test(normalized)) return 'critical';
  if (/(warn|pending|degrad|unknown|starting|stale|under.?voltage|throttl|thermal.?limit|frequency.?cap)/.test(normalized)) return 'warn';
  if (/(ok|success|healthy|running|online|active|resolved|allowed|on|nominal)/.test(normalized)) return 'good';
  return 'neutral';
}

function isContainerHealthy(container: ContainerStatus): boolean {
  return normalizeTone(container.health || container.state) === 'good';
}

function formatDecimal(value: number | null | undefined): string {
  return Number.isFinite(value) ? Number(value).toFixed(2) : '—';
}

function formatFreeBytes(total: number | null, used: number | null): string {
  if (!Number.isFinite(total) || !Number.isFinite(used)) return '—';
  return formatBytes(Math.max(0, Number(total) - Number(used)));
}
