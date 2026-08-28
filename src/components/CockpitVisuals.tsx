import { useMemo, type ReactNode } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  eventBuckets,
  localized,
  operationalLogs,
  relatedLogs,
  type OperationalLogEntry,
} from '../dashboard-model';
import type {
  ContainerStatus,
  DashboardPayload,
  MonitorDetailPage,
  MonitorLocale,
  PeakIncident,
  TimeRange,
} from '../types';
import {
  formatBytes,
  formatClock,
  formatDateTime,
  formatPercent,
  formatRate,
  formatTime,
  formatUptime,
  safeText,
} from '../utils';
import { Icon, type IconName } from './Icon';
import { useAdaptiveGridDetailVisibility } from './AdaptiveGrid';
import { OperationalLogView } from './OperationalLogView';

const CHART_COLORS = {
  cyan: '#55d9d1',
  violet: '#a99cff',
  green: '#7de2a8',
  orange: '#ffb46f',
  red: '#ff7779',
  blue: '#6aaeff',
  grid: '#293935',
  axis: '#83928f',
};

const TOOLTIP_STYLE = {
  border: '1px solid #40514d',
  borderRadius: 9,
  background: 'rgba(8, 17, 16, .97)',
  color: '#ecf3f1',
  fontSize: 12,
};

export interface VisualProps {
  data: DashboardPayload;
  range: TimeRange;
  locale: MonitorLocale;
  onOpen: (page: MonitorDetailPage) => void;
}

function t(locale: MonitorLocale, ko: string, en: string): string {
  return localized(locale, ko, en);
}

function chartSeries(data: DashboardPayload, range: TimeRange, locale: MonitorLocale) {
  return data.series.map((point) => ({
    ...point,
    label: formatTime(point.timestamp, range, locale),
    fullTime: point.timestamp ? new Intl.DateTimeFormat(locale === 'ko' ? 'ko-KR' : 'en-US', {
      dateStyle: 'medium',
      timeStyle: 'medium',
    }).format(new Date(point.timestamp)) : '—',
  }));
}

function decimal(value: number | null | undefined, digits = 2): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—';
}

function temperature(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}°C` : '—';
}

function voltage(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(3)} V` : '—';
}

function localUptime(seconds: number | null | undefined, locale: MonitorLocale): string {
  if (locale === 'en') return formatUptime(seconds);
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return '확인 불가';
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days) return `${days}일 ${hours}시간`;
  if (hours) return `${hours}시간 ${minutes}분`;
  return `${minutes}분`;
}

function statusTone(value: number | null | undefined, warning = 75, critical = 90): 'ok' | 'caution' | 'danger' | 'unknown' {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'unknown';
  if (value >= critical) return 'danger';
  if (value >= warning) return 'caution';
  return 'ok';
}

function statusWord(tone: ReturnType<typeof statusTone>, locale: MonitorLocale): string {
  if (tone === 'danger') return t(locale, '위험', 'WARNING');
  if (tone === 'caution') return t(locale, '주의', 'CAUTION');
  if (tone === 'ok') return t(locale, '정상', 'NOMINAL');
  return t(locale, '미확인', 'UNKNOWN');
}

interface PanelProps {
  title: string;
  description: string;
  icon: IconName;
  badge?: string;
  detailPage?: MonitorDetailPage;
  onOpen?: (page: MonitorDetailPage) => void;
  locale: MonitorLocale;
  children: ReactNode;
  className?: string;
}

export function CockpitPanel({ title, description, icon, badge, detailPage, onOpen, locale, children, className = '' }: PanelProps) {
  return (
    <article className={`cockpit-panel ${className}`}>
      <header className="cockpit-panel-header">
        <span className="cockpit-panel-icon"><Icon name={icon} size={19} /></span>
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        {badge && <span className="cockpit-panel-badge">{badge}</span>}
        {detailPage && onOpen && (
          <button className="cockpit-detail-link" type="button" onClick={() => onOpen(detailPage)}>
            {t(locale, '상세', 'Details')}<Icon name="chevron" size={14} />
          </button>
        )}
      </header>
      <div className="cockpit-panel-body">{children}</div>
    </article>
  );
}

function ChartEmpty({ locale }: { locale: MonitorLocale }) {
  return <div className="cockpit-chart-empty"><Icon name="activity" size={20} />{t(locale, '선택한 기간에 표본이 없습니다.', 'No samples in this range.')}</div>;
}

function SelectionEmpty({ locale }: { locale: MonitorLocale }) {
  return <div className="cockpit-chart-empty cockpit-selection-empty"><Icon name="info" size={20} />{t(locale, '표시할 항목이 꺼져 있습니다.', 'All details in this widget are hidden.')}</div>;
}

function Vital({ label, value, note, tone = 'ok', term }: { label: string; value: string; note: string; tone?: 'ok' | 'caution' | 'danger' | 'unknown'; term?: string }) {
  return (
    <div className={`cockpit-vital vital-${tone}`}>
      <span>{label}{term && <abbr title={term}>?</abbr>}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </div>
  );
}

export function VitalSignsWidget({ data, locale, onOpen }: Omit<VisualProps, 'range'>) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const latest = data.latest;
  const running = data.containers.filter((container) => safeText(container.state, '').toLowerCase() === 'running').length;
  const unhealthy = data.containers.filter((container) => /unhealthy|dead|exited/i.test(`${container.health} ${container.state}`)).length;
  const highestDisk = data.disks.length
    ? data.disks.reduce((maximum, disk) => Math.max(maximum, disk.usedPercent ?? 0), 0)
    : null;
  const diskIo = latest?.diskReadBytesPerSecond == null && latest?.diskWriteBytesPerSecond == null
    ? null
    : (latest?.diskReadBytesPerSecond ?? 0) + (latest?.diskWriteBytesPerSecond ?? 0);
  const voltageTone = typeof latest?.supplyVoltageVolts !== 'number'
    ? 'unknown'
    : latest.supplyVoltageVolts < 4.63
      ? 'danger'
      : latest.supplyVoltageVolts < 4.75
        ? 'caution'
        : 'ok';
  return (
    <CockpitPanel
      title={t(locale, '핵심 계기', 'Primary instruments')}
      description={t(locale, '현재 판단에 필요한 호스트 핵심 수치', 'Host readings needed for immediate decisions')}
      icon="activity"
      badge={t(locale, '실시간', 'LIVE')}
      detailPage="resources"
      onOpen={onOpen}
      locale={locale}
      className="vitals-panel"
    >
      <div className="cockpit-vital-grid">
        {detailVisible('cpu') && <Vital label="CPU" value={formatPercent(latest?.cpuPercent, 1)} note={statusWord(statusTone(latest?.cpuPercent), locale)} tone={statusTone(latest?.cpuPercent)} />}
        {detailVisible('memory') && <Vital label={t(locale, '메모리', 'Memory')} value={formatPercent(latest?.memoryPercent, 1)} note={`${formatBytes(latest?.memoryUsedBytes)} / ${formatBytes(latest?.memoryTotalBytes)}`} tone={statusTone(latest?.memoryPercent)} />}
        {detailVisible('temperature') && <Vital label={t(locale, '온도', 'Temperature')} value={temperature(latest?.temperatureC)} note={t(locale, '기기 센서', 'Device sensor')} tone={statusTone(latest?.temperatureC, 75, 85)} />}
        {detailVisible('load') && <Vital label={t(locale, '시스템 부하', 'System load')} term={t(locale, '실행 중이거나 실행을 기다리는 작업의 양입니다. CPU 개수와 함께 판단합니다.', 'Work running or waiting to run; interpret alongside CPU count.')} value={decimal(latest?.load1)} note={t(locale, '최근 1분 평균', '1-minute average')} tone={statusTone(latest?.load1, 4, 8)} />}
        {detailVisible('services') && <Vital label={t(locale, '서비스', 'Services')} value={data.containers.length ? `${running}/${data.containers.length}` : '—'} note={!data.containers.length ? t(locale, '추적 대상 없음', 'No services reported') : unhealthy ? t(locale, `${unhealthy}개 이상`, `${unhealthy} abnormal`) : t(locale, '모두 정상', 'All nominal')} tone={!data.containers.length ? 'unknown' : unhealthy ? 'danger' : 'ok'} />}
        {detailVisible('disk-usage') && <Vital label={t(locale, '디스크 최고 사용률', 'Highest disk usage')} value={formatPercent(highestDisk, 0)} note={t(locale, `${data.disks.length}개 볼륨`, `${data.disks.length} volumes`)} tone={statusTone(highestDisk)} />}
        {detailVisible('network-rx') && <Vital label={t(locale, '수신 처리량', 'Network receive')} value={formatRate(latest?.networkRxBytesPerSecond)} note={t(locale, '현재 초당 수신량', 'Current receive rate')} tone={latest?.networkRxBytesPerSecond == null ? 'unknown' : 'ok'} />}
        {detailVisible('network-tx') && <Vital label={t(locale, '송신 처리량', 'Network transmit')} value={formatRate(latest?.networkTxBytesPerSecond)} note={t(locale, '현재 초당 송신량', 'Current transmit rate')} tone={latest?.networkTxBytesPerSecond == null ? 'unknown' : 'ok'} />}
        {detailVisible('disk-io') && <Vital label={t(locale, '디스크 입출력', 'Disk I/O')} value={formatRate(diskIo)} note={`${t(locale, '읽기', 'read')} ${formatRate(latest?.diskReadBytesPerSecond)} · ${t(locale, '쓰기', 'write')} ${formatRate(latest?.diskWriteBytesPerSecond)}`} tone={diskIo == null ? 'unknown' : 'ok'} />}
        {detailVisible('voltage') && <Vital label={t(locale, '공급 전압', 'Supply voltage')} value={voltage(latest?.supplyVoltageVolts)} note={t(locale, 'EXT5V 입력', 'EXT5V input')} tone={voltageTone} />}
        {detailVisible('gpu-memory') && <Vital label={t(locale, 'GPU 메모리 할당', 'GPU memory allocation')} value={formatBytes(latest?.gpuMemoryBytes)} note={t(locale, '사용량이 아닌 예약 용량', 'Reserved allocation, not usage')} tone={latest?.gpuMemoryBytes == null ? 'unknown' : 'ok'} />}
        {detailVisible('gpu-clock') && <Vital label={t(locale, 'GPU 클럭', 'GPU clock')} value={formatClock(latest?.gpuClockHz ?? null)} note={t(locale, '현재 그래픽 코어 주파수', 'Current graphics core frequency')} tone={latest?.gpuClockHz == null ? 'unknown' : 'ok'} />}
        {detailVisible('uptime') && <Vital label={t(locale, '가동 시간', 'Uptime')} value={localUptime(data.host.uptimeSeconds, locale)} note={safeText(data.host.os, t(locale, '운영체제 미확인', 'OS unavailable'), 72)} tone={data.host.uptimeSeconds == null ? 'unknown' : 'ok'} />}
        {![
          'cpu', 'memory', 'temperature', 'load', 'services', 'disk-usage', 'network-rx',
          'network-tx', 'disk-io', 'voltage', 'gpu-memory', 'gpu-clock', 'uptime',
        ].some(detailVisible) && <SelectionEmpty locale={locale} />}
      </div>
    </CockpitPanel>
  );
}

export function ResourceWidget({ data, range, locale, onOpen }: VisualProps) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const cpuVisible = detailVisible('cpu');
  const memoryVisible = detailVisible('memory');
  const series = useMemo(() => chartSeries(data, range, locale), [data, range, locale]);
  const statistics = data.telemetrySummary;
  return (
    <CockpitPanel title={t(locale, '자원 사용 추세', 'Resource utilization')} description={t(locale, 'CPU와 메모리의 사용률 변화', 'CPU and memory utilization over time')} icon="cpu" badge={range.toUpperCase()} detailPage="resources" onOpen={onOpen} locale={locale}>
      {(cpuVisible || memoryVisible) && <div className="cockpit-mini-summary">
        {cpuVisible && <span>{t(locale, '평균 CPU', 'Avg CPU')} <strong>{formatPercent(statistics.cpuAveragePercent, 1)}</strong></span>}
        {cpuVisible && <span>{t(locale, '최고 CPU', 'Peak CPU')} <strong>{formatPercent(statistics.cpuPeakPercent, 1)}</strong></span>}
        {memoryVisible && <span>{t(locale, '최고 메모리', 'Peak memory')} <strong>{formatPercent(statistics.memoryPeakPercent, 1)}</strong></span>}
      </div>}
      <div className="cockpit-chart">
        {!cpuVisible && !memoryVisible ? <SelectionEmpty locale={locale} /> : !series.length ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 12, right: 12, left: -12, bottom: 0 }}>
              <defs>
                <linearGradient id="v2CpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART_COLORS.cyan} stopOpacity={0.35} /><stop offset="1" stopColor={CHART_COLORS.cyan} stopOpacity={0.01} /></linearGradient>
                <linearGradient id="v2MemoryFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART_COLORS.violet} stopOpacity={0.3} /><stop offset="1" stopColor={CHART_COLORS.violet} stopOpacity={0.01} /></linearGradient>
              </defs>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={34} tickLine={false} axisLine={false} />
              <YAxis domain={[0, 100]} stroke={CHART_COLORS.axis} tickFormatter={(value) => `${value}%`} tickLine={false} axisLine={false} width={42} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={(_label, payload) => payload?.[0]?.payload?.fullTime ?? _label} formatter={(value: any, name: any) => [formatPercent(Number(value), 1), name]} />
              <Legend />
              <ReferenceLine y={75} stroke={CHART_COLORS.orange} strokeDasharray="4 4" />
              {cpuVisible && <Area type="monotone" dataKey="cpuPercent" name="CPU" stroke={CHART_COLORS.cyan} fill="url(#v2CpuFill)" strokeWidth={2} connectNulls />}
              {memoryVisible && <Area type="monotone" dataKey="memoryPercent" name={t(locale, '메모리', 'Memory')} stroke={CHART_COLORS.violet} fill="url(#v2MemoryFill)" strokeWidth={2} connectNulls />}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </CockpitPanel>
  );
}

export function LoadWidget({ data, range, locale, onOpen }: VisualProps) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const loadVisible = detailVisible('load');
  const temperatureVisible = detailVisible('temperature');
  const series = useMemo(() => chartSeries(data, range, locale), [data, range, locale]);
  return (
    <CockpitPanel title={t(locale, '부하와 온도', 'Load and thermal')} description={t(locale, '1·5·15분 부하와 기기 온도', '1, 5, and 15-minute load with device temperature')} icon="temperature" badge={range.toUpperCase()} detailPage="resources" onOpen={onOpen} locale={locale}>
      {loadVisible && <p className="cockpit-explainer"><Icon name="info" size={15} />{t(locale, '부하는 CPU 사용률이 아니라 실행 중·대기 중인 작업의 양입니다.', 'Load is queued and running work, not CPU percentage.')}</p>}
      {(loadVisible || temperatureVisible) && <div className="cockpit-mini-summary">
        {loadVisible && <span>{t(locale, '평균 1분 부하', 'Avg 1m load')} <strong>{decimal(data.telemetrySummary.load1Average)}</strong></span>}
        {loadVisible && <span>{t(locale, '최고 1분 부하', 'Peak 1m load')} <strong>{decimal(data.telemetrySummary.load1Peak)}</strong></span>}
        {temperatureVisible && <span>{t(locale, '최고 온도', 'Peak temperature')} <strong>{temperature(data.telemetrySummary.temperaturePeakC)}</strong></span>}
      </div>}
      <div className="cockpit-chart">
        {!loadVisible && !temperatureVisible ? <SelectionEmpty locale={locale} /> : !series.length ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={series} margin={{ top: 12, right: 10, left: -15, bottom: 0 }}>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={34} tickLine={false} axisLine={false} />
              <YAxis yAxisId="load" stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} width={42} />
              <YAxis yAxisId="temp" orientation="right" stroke={CHART_COLORS.axis} tickFormatter={(value) => `${value}°`} tickLine={false} axisLine={false} width={42} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={(_label, payload) => payload?.[0]?.payload?.fullTime ?? _label} />
              <Legend />
              {loadVisible && <Line yAxisId="load" type="monotone" dataKey="load1" name={t(locale, '부하 1분', 'Load 1m')} stroke={CHART_COLORS.green} strokeWidth={2.2} dot={false} connectNulls />}
              {loadVisible && <Line yAxisId="load" type="monotone" dataKey="load5" name={t(locale, '부하 5분', 'Load 5m')} stroke={CHART_COLORS.cyan} strokeWidth={1.6} dot={false} connectNulls />}
              {loadVisible && <Line yAxisId="load" type="monotone" dataKey="load15" name={t(locale, '부하 15분', 'Load 15m')} stroke={CHART_COLORS.violet} strokeWidth={1.4} dot={false} connectNulls />}
              {temperatureVisible && <Line yAxisId="temp" type="monotone" dataKey="temperatureC" name={t(locale, '온도 °C', 'Temperature °C')} stroke={CHART_COLORS.orange} strokeWidth={1.8} strokeDasharray="5 3" dot={false} connectNulls />}
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </CockpitPanel>
  );
}

export function NetworkWidget({ data, range, locale, onOpen }: VisualProps) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const receiveVisible = detailVisible('receive');
  const transmitVisible = detailVisible('transmit');
  const series = useMemo(() => chartSeries(data, range, locale), [data, range, locale]);
  const stats = data.telemetrySummary;
  return (
    <CockpitPanel title={t(locale, '네트워크 처리량', 'Network throughput')} description={t(locale, '초당 송수신량과 기간 누적 추정치', 'Transfer rates with range totals estimated from samples')} icon="network" badge={t(locale, '초당', 'PER SECOND')} detailPage="network" onOpen={onOpen} locale={locale}>
      {(receiveVisible || transmitVisible) && <div className="cockpit-mini-summary">
        {receiveVisible && <span>{t(locale, '현재 수신', 'Receive now')} <strong>{formatRate(data.latest?.networkRxBytesPerSecond)}</strong></span>}
        {receiveVisible && <span>{t(locale, '기간 수신', 'Range received')} <strong>{formatBytes(stats.networkReceivedBytes)}</strong></span>}
        {transmitVisible && <span>{t(locale, '기간 송신', 'Range sent')} <strong>{formatBytes(stats.networkTransmittedBytes)}</strong></span>}
      </div>}
      <div className="cockpit-chart">
        {!receiveVisible && !transmitVisible ? <SelectionEmpty locale={locale} /> : !series.length ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 12, right: 12, left: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="networkRxFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART_COLORS.cyan} stopOpacity={0.35} /><stop offset="1" stopColor={CHART_COLORS.cyan} stopOpacity={0} /></linearGradient>
                <linearGradient id="networkTxFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={CHART_COLORS.violet} stopOpacity={0.28} /><stop offset="1" stopColor={CHART_COLORS.violet} stopOpacity={0} /></linearGradient>
              </defs>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={34} tickLine={false} axisLine={false} />
              <YAxis stroke={CHART_COLORS.axis} tickFormatter={(value) => formatRate(Number(value)).replace('/s', '')} tickLine={false} axisLine={false} width={58} />
              <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value: any, name: any) => [formatRate(Number(value)), name]} />
              <Legend />
              {receiveVisible && <Area type="monotone" dataKey="networkRxBytesPerSecond" name={t(locale, '수신', 'Receive')} stroke={CHART_COLORS.cyan} fill="url(#networkRxFill)" strokeWidth={2} connectNulls />}
              {transmitVisible && <Area type="monotone" dataKey="networkTxBytesPerSecond" name={t(locale, '송신', 'Transmit')} stroke={CHART_COLORS.violet} fill="url(#networkTxFill)" strokeWidth={2} connectNulls />}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </CockpitPanel>
  );
}

export function StorageWidget({ data, range, locale, onOpen }: VisualProps) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const capacityVisible = detailVisible('capacity');
  const readVisible = detailVisible('read');
  const writeVisible = detailVisible('write');
  const ioVisible = readVisible || writeVisible;
  const series = useMemo(() => chartSeries(data, range, locale), [data, range, locale]);
  const diskBars = data.disks.map((disk) => ({ name: safeText(disk.mount, 'volume', 24), used: disk.usedPercent ?? 0 }));
  return (
    <CockpitPanel title={t(locale, '저장장치', 'Storage')} description={t(locale, '볼륨 용량과 디스크 입출력', 'Volume capacity and disk I/O')} icon="database" badge={`${data.disks.length} VOL`} detailPage="storage" onOpen={onOpen} locale={locale}>
      {ioVisible && <div className="cockpit-mini-summary">
        {readVisible && <span>{t(locale, '기간 읽기', 'Range read')} <strong>{formatBytes(data.telemetrySummary.diskReadBytes)}</strong></span>}
        {writeVisible && <span>{t(locale, '기간 쓰기', 'Range written')} <strong>{formatBytes(data.telemetrySummary.diskWrittenBytes)}</strong></span>}
        <span>{t(locale, '원본 표본', 'Raw samples')} <strong>{data.telemetrySummary.sampleCount.toLocaleString()}</strong></span>
      </div>}
      {!capacityVisible && !ioVisible ? <SelectionEmpty locale={locale} /> : <div className={`cockpit-split-chart${capacityVisible !== ioVisible ? ' cockpit-split-chart-single' : ''}`}>
        {capacityVisible && <div className="cockpit-chart">
          {!diskBars.length ? <ChartEmpty locale={locale} /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={diskBars} layout="vertical" margin={{ top: 6, right: 15, left: 8, bottom: 0 }}>
                <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} tickFormatter={(value) => `${value}%`} stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" width={70} stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value: any) => formatPercent(Number(value), 1)} />
                <ReferenceLine x={75} stroke={CHART_COLORS.orange} strokeDasharray="4 4" />
                <Bar dataKey="used" name={t(locale, '사용률', 'Used')} radius={[0, 5, 5, 0]}>
                  {diskBars.map((entry) => <Cell key={entry.name} fill={entry.used >= 90 ? CHART_COLORS.red : entry.used >= 75 ? CHART_COLORS.orange : CHART_COLORS.green} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>}
        {ioVisible && <div className="cockpit-chart">
          {!series.length ? <ChartEmpty locale={locale} /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={series} margin={{ top: 6, right: 8, left: 4, bottom: 0 }}>
                <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
                <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={34} tickLine={false} axisLine={false} />
                <YAxis stroke={CHART_COLORS.axis} tickFormatter={(value) => formatBytes(Number(value), 0).replace(' ', '')} tickLine={false} axisLine={false} width={56} />
                <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value: any, name: any) => [formatRate(Number(value)), name]} />
                <Legend />
                {readVisible && <Bar dataKey="diskReadBytesPerSecond" name={t(locale, '읽기', 'Read')} stackId="io" fill={CHART_COLORS.green} />}
                {writeVisible && <Bar dataKey="diskWriteBytesPerSecond" name={t(locale, '쓰기', 'Write')} stackId="io" fill={CHART_COLORS.orange} />}
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>}
      </div>}
    </CockpitPanel>
  );
}

function containerTone(container: ContainerStatus): 'ok' | 'caution' | 'danger' | 'unknown' {
  const state = `${safeText(container.state, '')} ${safeText(container.health, '')}`.toLowerCase();
  if (/(unhealthy|dead|exited|failed)/.test(state)) return 'danger';
  if (/(starting|created|paused|unknown)/.test(state)) return 'caution';
  if (/running/.test(state) && !/unhealthy/.test(state)) return 'ok';
  return 'unknown';
}

export function ContainersWidget({ data, locale, onOpen }: Omit<VisualProps, 'range'>) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const cpuVisible = detailVisible('cpu');
  const memoryVisible = detailVisible('memory');
  const chart = data.containers.slice().sort((left, right) => (right.cpuPercent ?? 0) - (left.cpuPercent ?? 0)).slice(0, 10).map((container) => ({
    name: safeText(container.name, 'container', 24),
    cpu: container.cpuPercent ?? 0,
    memory: container.memoryPercent ?? 0,
  }));
  const nominal = data.containers.filter((container) => containerTone(container) === 'ok').length;
  return (
    <CockpitPanel title={t(locale, '서비스와 컨테이너', 'Services and containers')} description={t(locale, '현재 상태와 상대 자원 사용량', 'Current health and relative resource usage')} icon="server" badge={`${nominal}/${data.containers.length}`} detailPage="containers" onOpen={onOpen} locale={locale}>
      <div className="cockpit-chart container-chart">
        {!cpuVisible && !memoryVisible ? <SelectionEmpty locale={locale} /> : !chart.length ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chart} layout="vertical" margin={{ top: 5, right: 12, left: 10, bottom: 0 }}>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" horizontal={false} />
              <XAxis type="number" stroke={CHART_COLORS.axis} tickFormatter={(value) => `${value}%`} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" width={92} stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value: any, name: any) => [formatPercent(Number(value), 1), name]} />
              <Legend />
              {cpuVisible && <Bar dataKey="cpu" name="CPU" fill={CHART_COLORS.cyan} radius={[0, 4, 4, 0]} />}
              {memoryVisible && <Bar dataKey="memory" name={t(locale, '메모리', 'Memory')} fill={CHART_COLORS.violet} radius={[0, 4, 4, 0]} />}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </CockpitPanel>
  );
}

export function PowerWidget({ data, range, locale, onOpen }: VisualProps) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const currentVisible = detailVisible('current');
  const minimumVisible = detailVisible('minimum');
  const averageVisible = detailVisible('average');
  const trendVisible = detailVisible('trend');
  const series = useMemo(() => chartSeries(data, range, locale), [data, range, locale]);
  const summary = data.powerSummary;
  const currentFlags = data.latest?.throttledFlags;
  const activeThrottle = typeof currentFlags === 'number' && (currentFlags & 0xf) !== 0;
  const powerBadge = currentFlags == null && data.latest?.supplyVoltageVolts == null
    ? t(locale, '미확인', 'UNKNOWN')
    : activeThrottle || (data.latest?.supplyVoltageVolts ?? 5) < 4.75
      ? t(locale, '주의', 'CAUTION')
      : t(locale, '정상', 'NOMINAL');
  return (
    <CockpitPanel title={t(locale, '전원과 전압', 'Power and voltage')} description={t(locale, 'EXT5V 공급 전압과 제한 신호', 'EXT5V supply and throttle indicators')} icon="zap" badge={powerBadge} detailPage="power" onOpen={onOpen} locale={locale}>
      {(currentVisible || minimumVisible || averageVisible) && <div className="cockpit-mini-summary">
        {currentVisible && <span>{t(locale, '현재', 'Current')} <strong>{voltage(data.latest?.supplyVoltageVolts)}</strong></span>}
        {minimumVisible && <span>{t(locale, '최저', 'Minimum')} <strong>{voltage(summary.minSupplyVoltageVolts)}</strong></span>}
        {averageVisible && <span>{t(locale, '평균', 'Average')} <strong>{voltage(summary.averageSupplyVoltageVolts)}</strong></span>}
      </div>}
      {!currentVisible && !minimumVisible && !averageVisible && !trendVisible ? <SelectionEmpty locale={locale} /> : trendVisible && <div className="cockpit-chart">
        {!series.some((point) => typeof point.supplyVoltageVolts === 'number') ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={series} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={34} tickLine={false} axisLine={false} />
              <YAxis domain={['dataMin - 0.05', 'dataMax + 0.05']} stroke={CHART_COLORS.axis} tickFormatter={(value) => `${Number(value).toFixed(2)}V`} tickLine={false} axisLine={false} width={55} />
              <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value: any) => voltage(Number(value))} />
              <ReferenceLine y={4.75} stroke={CHART_COLORS.orange} strokeDasharray="4 4" label={{ value: '4.75V', fill: CHART_COLORS.orange, fontSize: 10 }} />
              <Line type="monotone" dataKey="supplyVoltageVolts" name={t(locale, '공급 전압', 'Supply voltage')} stroke={CHART_COLORS.cyan} strokeWidth={2.2} dot={false} connectNulls />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>}
    </CockpitPanel>
  );
}

export function ReliabilityWidget({ data, locale, onOpen }: Omit<VisualProps, 'range'>) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const summary = data.reliability;
  const stateDetail = (value: boolean | null, unavailable: string, available: string) => value === null
    ? t(locale, '보고 없음', 'Not reported')
    : value
      ? available
      : unavailable;
  const checks = [
    { id: 'ssh', label: t(locale, 'SSH 접속 경로', 'SSH listeners'), value: summary.sshListenersAvailable, detail: stateDetail(summary.sshListenersAvailable, t(locale, '수신 포트 없음', 'No listener detected'), t(locale, '접속 경로 확인', 'Listener available')) },
    { id: 'network', label: t(locale, '주 네트워크', 'Primary network'), value: summary.networkLinkAvailable, detail: stateDetail(summary.networkLinkAvailable, t(locale, '연결 끊김', 'Link unavailable'), t(locale, '연결 유지', 'Link available')) },
    { id: 'nvme', label: t(locale, 'NVMe 보호 설정', 'NVMe mitigation'), value: summary.nvmeMitigationActive, detail: stateDetail(summary.nvmeMitigationActive, t(locale, '보호 설정 불완전', 'Mitigation incomplete'), t(locale, '보호 설정 적용', 'Mitigation active')) },
    { id: 'collector-gap', label: t(locale, '수집 지연', 'Collector gap'), value: summary.collectorGapSeconds == null ? null : summary.collectorGapSeconds < 120, detail: summary.collectorGapSeconds == null ? t(locale, '보고 없음', 'Not reported') : `${Math.round(summary.collectorGapSeconds)}s` },
  ].filter((check) => detailVisible(check.id));
  const lastBootVisible = detailVisible('last-boot');
  return (
    <CockpitPanel title={t(locale, '호스트 신뢰성', 'Host reliability')} description={t(locale, '연결·수집·저장장치 보호 상태', 'Connectivity, collection, and storage safeguards')} icon="shield" badge={`${data.reliabilityEvents.length}`} detailPage="reliability" onOpen={onOpen} locale={locale}>
      <div className="cockpit-check-grid">
        {checks.map((check) => (
          <div key={check.label} className={`cockpit-check check-${check.value === true ? 'ok' : check.value === false ? 'danger' : 'unknown'}`}>
            <span>{check.value === true ? '✓' : check.value === false ? '▲' : '?'}</span>
            <div><strong>{check.label}</strong><small>{check.detail}</small></div>
          </div>
        ))}
        {!checks.length && !lastBootVisible && <SelectionEmpty locale={locale} />}
      </div>
      {lastBootVisible && <p className="cockpit-footnote">{t(locale, '최근 부팅', 'Last boot')} · {formatDateTime(summary.bootStartedAt, locale)}</p>}
    </CockpitPanel>
  );
}

function incidentReason(reason: string, locale: MonitorLocale): string {
  const labels: Record<string, [string, string]> = {
    cpu: ['CPU 과부하', 'CPU pressure'],
    memory: ['메모리 과부하', 'Memory pressure'],
    temperature: ['고온', 'High temperature'],
    load: ['시스템 부하', 'System load'],
    'disk-io': ['디스크 입출력', 'Disk I/O'],
    'power-throttle': ['전원 제한', 'Power throttle'],
    traffic: ['요청 급증', 'Traffic surge'],
  };
  const label = labels[reason];
  return label ? t(locale, ...label) : reason.replace(/[-_]+/g, ' ');
}

function incidentDistribution(incidents: PeakIncident[], locale: MonitorLocale) {
  const counts = new Map<string, number>();
  for (const incident of incidents) for (const reason of incident.reasons) counts.set(reason, (counts.get(reason) ?? 0) + 1);
  return [...counts.entries()].map(([reason, value]) => ({ name: incidentReason(reason, locale), value }));
}

export function IncidentsWidget({ data, locale, onOpen }: Omit<VisualProps, 'range'>) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const distributionVisible = detailVisible('distribution');
  const recentVisible = detailVisible('recent');
  const distribution = incidentDistribution(data.incidents, locale);
  const palette = [CHART_COLORS.red, CHART_COLORS.orange, CHART_COLORS.violet, CHART_COLORS.cyan, CHART_COLORS.green, CHART_COLORS.blue];
  return (
    <CockpitPanel title={t(locale, '피크 사건', 'Peak incidents')} description={t(locale, '임계치를 넘은 순간의 원인과 증거', 'Reasons and evidence captured at threshold crossings')} icon="alert" badge={`${data.incidents.length}`} detailPage="incidents" onOpen={onOpen} locale={locale}>
      {!distributionVisible && !recentVisible ? <SelectionEmpty locale={locale} /> : <div className={`incident-widget-layout${distributionVisible !== recentVisible ? ' incident-widget-layout-single' : ''}`}>
        {distributionVisible && <div className="cockpit-chart incident-donut">
          {!distribution.length ? <ChartEmpty locale={locale} /> : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={distribution} dataKey="value" nameKey="name" innerRadius="46%" outerRadius="76%" paddingAngle={3}>
                  {distribution.map((entry, index) => <Cell key={entry.name} fill={palette[index % palette.length]} />)}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend layout="vertical" align="right" verticalAlign="middle" />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>}
        {recentVisible && <ol className="incident-compact-list">
          {data.incidents.slice(0, 4).map((incident) => (
            <li key={incident.id}>
              <span className={`phase-${incident.phase}`}>{incident.phase === 'active' ? '▲' : incident.phase === 'follow-up' ? '●' : '✓'}</span>
              <div><strong>{incident.reasons.map((reason) => incidentReason(reason, locale)).join(' · ') || t(locale, '원인 미확인', 'Cause unavailable')}</strong><time dateTime={incident.observedAt}>{formatDateTime(incident.observedAt, locale)}</time></div>
            </li>
          ))}
          {!data.incidents.length && <li className="positive-empty">✓ {t(locale, '선택한 기간에 피크 사건이 없습니다.', 'No peak incidents in this range.')}</li>}
        </ol>}
      </div>}
    </CockpitPanel>
  );
}

export function EventsWidget({ data, locale, onOpen }: Omit<VisualProps, 'range'>) {
  const detailVisible = useAdaptiveGridDetailVisibility();
  const timelineVisible = detailVisible('timeline');
  const logVisible = detailVisible('log');
  const logs = useMemo(() => operationalLogs(data), [data]);
  const buckets = useMemo(() => eventBuckets(logs, 10).map((bucket) => ({
    ...bucket,
    label: formatTime(bucket.label, undefined, locale),
  })), [logs]);
  return (
    <CockpitPanel title={t(locale, '운영 이벤트', 'Operational events')} description={t(locale, '경고·신뢰성·전원·권한 기록을 한 시간축으로 통합', 'Alerts, reliability, power, and privilege records on one timeline')} icon="clock" badge={`${logs.length}`} detailPage="logs" onOpen={onOpen} locale={locale}>
      {!timelineVisible && !logVisible ? <SelectionEmpty locale={locale} /> : <div className={`event-widget-layout${timelineVisible !== logVisible ? ' event-widget-layout-single' : ''}`}>
        {timelineVisible && <div className="cockpit-chart event-histogram">
          {!buckets.length ? <ChartEmpty locale={locale} /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={buckets} margin={{ top: 8, right: 8, left: -14, bottom: 0 }}>
                <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
                <XAxis dataKey="label" stroke={CHART_COLORS.axis} minTickGap={30} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} width={34} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend />
                <Bar dataKey="critical" name={t(locale, '위험', 'Warning')} stackId="event" fill={CHART_COLORS.red} />
                <Bar dataKey="warning" name={t(locale, '주의', 'Caution')} stackId="event" fill={CHART_COLORS.orange} />
                <Bar dataKey="info" name={t(locale, '정보', 'Advisory')} stackId="event" fill={CHART_COLORS.blue} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>}
        {logVisible && <OperationalLogView entries={logs} locale={locale} compact />}
      </div>}
    </CockpitPanel>
  );
}

function trafficSummary(incidents: PeakIncident[]) {
  const apps = new Map<string, { app: string; requests: number; success: number; redirects: number; clientErrors: number; serverErrors: number; slow: number; maxMs: number }>();
  for (const incident of incidents) {
    for (const traffic of incident.traffic) {
      const app = safeText(traffic.app, 'unknown', 64);
      const current = apps.get(app) ?? { app, requests: 0, success: 0, redirects: 0, clientErrors: 0, serverErrors: 0, slow: 0, maxMs: 0 };
      current.requests += traffic.requestCount;
      current.success += traffic.status2xx;
      current.redirects += traffic.status3xx;
      current.clientErrors += traffic.status4xx;
      current.serverErrors += traffic.status5xx;
      current.slow += traffic.slowCount;
      current.maxMs = Math.max(current.maxMs, traffic.maxResponseMs ?? 0);
      apps.set(app, current);
    }
  }
  return [...apps.values()].sort((left, right) => right.requests - left.requests);
}

function TrafficEvidence({ data, locale }: { data: DashboardPayload; locale: MonitorLocale }) {
  const traffic = trafficSummary(data.incidents);
  return (
    <CockpitPanel title={t(locale, '사건별 서비스 요청', 'Requests captured in incidents')} description={t(locale, '피크 사건 순간에만 저장된 앱별 익명 집계', 'Anonymous per-app aggregates captured only during incidents')} icon="network" badge={`${traffic.length} APP`} locale={locale}>
      <div className="cockpit-chart detail-large-chart">
        {!traffic.length ? <ChartEmpty locale={locale} /> : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={traffic} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="app" stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} />
              <YAxis stroke={CHART_COLORS.axis} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend />
              <Bar dataKey="success" name="2xx" stackId="status" fill={CHART_COLORS.green} />
              <Bar dataKey="redirects" name="3xx" stackId="status" fill={CHART_COLORS.blue} />
              <Bar dataKey="clientErrors" name="4xx" stackId="status" fill={CHART_COLORS.orange} />
              <Bar dataKey="serverErrors" name="5xx" stackId="status" fill={CHART_COLORS.red} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
      <p className="cockpit-footnote">{t(locale, '사람 수나 방문자 추적이 아니라 해당 캡처 구간의 요청 수입니다.', 'Counts are requests in the capture window, not people or unique visitors.')}</p>
    </CockpitPanel>
  );
}

function ContainerDetail({ data, locale }: { data: DashboardPayload; locale: MonitorLocale }) {
  return (
    <CockpitPanel title={t(locale, '전체 서비스 상태표', 'Full service status board')} description={t(locale, '서비스별 현재 상태·CPU·메모리·소유 계정', 'Current state, CPU, memory, and owner by service')} icon="server" badge={`${data.containers.length}`} locale={locale}>
      <div className="cockpit-table-wrap">
        <table className="cockpit-table">
          <thead><tr><th>{t(locale, '서비스', 'Service')}</th><th>{t(locale, '상태', 'State')}</th><th>{t(locale, '건강', 'Health')}</th><th>CPU</th><th>{t(locale, '메모리', 'Memory')}</th><th>{t(locale, '소유', 'Owner')}</th></tr></thead>
          <tbody>{data.containers.map((container) => {
            const tone = containerTone(container);
            return <tr key={container.name}><td><strong>{safeText(container.name)}</strong></td><td><span className={`status-token status-${tone}`}>{safeText(container.state, t(locale, '미확인', 'Unknown'))}</span></td><td>{safeText(container.health, '—')}</td><td>{formatPercent(container.cpuPercent, 1)}</td><td>{formatBytes(container.memoryBytes)} <small>{formatPercent(container.memoryPercent, 1)}</small></td><td>{safeText(container.owner, '—')}</td></tr>;
          })}</tbody>
        </table>
      </div>
    </CockpitPanel>
  );
}

function IncidentDetail({ data, locale }: { data: DashboardPayload; locale: MonitorLocale }) {
  return (
    <CockpitPanel title={t(locale, '사건 증거 기록', 'Incident evidence records')} description={t(locale, '원인·지속시간·자원 압박·프로세스·서비스·요청 집계', 'Cause, duration, pressure, process, service, and request evidence')} icon="alert" badge={`${data.incidents.length}`} locale={locale}>
      <ol className="incident-detail-list">
        {data.incidents.map((incident) => (
          <li key={incident.id} className={`incident-detail-card phase-${incident.phase}`}>
            <header><div><span>{incident.phase === 'active' ? t(locale, '발생 중', 'ACTIVE') : incident.phase === 'follow-up' ? t(locale, '후속 관찰', 'FOLLOW-UP') : t(locale, '복구됨', 'RECOVERED')}</span><h3>{incident.reasons.map((reason) => incidentReason(reason, locale)).join(' · ') || t(locale, '원인 미확인', 'Cause unavailable')}</h3></div><time dateTime={incident.observedAt}>{formatDateTime(incident.observedAt, locale)}</time></header>
            <div className="incident-evidence-grid">
              <dl><div><dt>CPU</dt><dd>{formatPercent(incident.metrics.cpuPercent, 1)}</dd></div><div><dt>{t(locale, '메모리', 'Memory')}</dt><dd>{formatPercent(incident.metrics.memoryPercent, 1)}</dd></div><div><dt>{t(locale, '온도', 'Temperature')}</dt><dd>{temperature(incident.metrics.temperatureC)}</dd></div><div><dt>{t(locale, '부하', 'Load')}</dt><dd>{decimal(incident.metrics.load1)}</dd></div></dl>
              <div><strong>{t(locale, '압박 지표(PSI)', 'Pressure stall information')}</strong><p>CPU some {decimal(incident.pressure.cpu.someAvg10)} · full {decimal(incident.pressure.cpu.fullAvg10)}</p><p>MEM some {decimal(incident.pressure.memory.someAvg10)} · full {decimal(incident.pressure.memory.fullAvg10)}</p><p>I/O some {decimal(incident.pressure.io.someAvg10)} · full {decimal(incident.pressure.io.fullAvg10)}</p></div>
              <div><strong>{t(locale, '주요 프로세스', 'Top process classes')}</strong>{incident.processes.length ? <ul>{incident.processes.slice(0, 6).map((process) => <li key={process.name}>{safeText(process.name)} · {formatPercent(process.cpuPercent, 1)} · {formatBytes(process.memoryBytes)}</li>)}</ul> : <p>{t(locale, '수집된 프로세스 증거 없음', 'No process evidence captured')}</p>}</div>
            </div>
          </li>
        ))}
        {!data.incidents.length && <li className="detail-positive-empty">✓ {t(locale, '선택한 기간에 사건이 없습니다.', 'No incidents in this range.')}</li>}
      </ol>
    </CockpitPanel>
  );
}

export function DetailPage({ page, data, range, locale, onOpen }: VisualProps & { page: MonitorDetailPage }) {
  const logs = useMemo(() => operationalLogs(data), [data]);
  const relevant = useMemo(() => relatedLogs(logs, page), [logs, page]);
  const commonLogs = (
    <CockpitPanel title={t(locale, '관련 이벤트 로그', 'Related event log')} description={t(locale, '수집 단계에서 비밀과 명령 인자를 제거한 구조화 기록', 'Structured records with secrets and command arguments removed at collection')} icon="clock" badge={`${relevant.length}`} locale={locale}>
      <OperationalLogView entries={relevant} locale={locale} />
    </CockpitPanel>
  );

  if (page === 'logs') {
    return <div className="detail-dashboard"><EventsWidget data={data} locale={locale} onOpen={onOpen} /><CockpitPanel title={t(locale, '전체 이벤트 탐색', 'Explore all events')} description={t(locale, '분류·심각도·문구로 최대 500건의 안전한 기록 검색', 'Search up to 500 sanitized records by source, severity, and text')} icon="clock" badge={`${logs.length}`} locale={locale}><OperationalLogView entries={logs} locale={locale} /></CockpitPanel></div>;
  }
  if (page === 'resources') return <div className="detail-dashboard detail-two-column"><VitalSignsWidget data={data} locale={locale} onOpen={onOpen} /><ResourceWidget data={data} range={range} locale={locale} onOpen={onOpen} /><LoadWidget data={data} range={range} locale={locale} onOpen={onOpen} />{commonLogs}</div>;
  if (page === 'network') return <div className="detail-dashboard detail-two-column"><NetworkWidget data={data} range={range} locale={locale} onOpen={onOpen} /><TrafficEvidence data={data} locale={locale} />{commonLogs}</div>;
  if (page === 'storage') return <div className="detail-dashboard"><StorageWidget data={data} range={range} locale={locale} onOpen={onOpen} />{commonLogs}</div>;
  if (page === 'containers') return <div className="detail-dashboard"><ContainersWidget data={data} locale={locale} onOpen={onOpen} /><ContainerDetail data={data} locale={locale} />{commonLogs}</div>;
  if (page === 'reliability') return <div className="detail-dashboard"><ReliabilityWidget data={data} locale={locale} onOpen={onOpen} />{commonLogs}</div>;
  if (page === 'power') return <div className="detail-dashboard"><PowerWidget data={data} range={range} locale={locale} onOpen={onOpen} />{commonLogs}</div>;
  return <div className="detail-dashboard"><IncidentsWidget data={data} locale={locale} onOpen={onOpen} /><IncidentDetail data={data} locale={locale} /><TrafficEvidence data={data} locale={locale} />{commonLogs}</div>;
}

export function pageTitle(page: MonitorDetailPage, locale: MonitorLocale): { eyebrow: string; title: string; description: string } {
  const pages: Record<MonitorDetailPage, [[string, string], [string, string], [string, string]]> = {
    resources: [['호스트 계기', 'HOST INSTRUMENTS'], ['자원과 시스템 부하', 'Resources and system load'], ['CPU·메모리·온도·부하를 현재값과 기간 추세로 분석합니다.', 'Analyze CPU, memory, temperature, and load as current readings and trends.']],
    network: [['데이터 흐름', 'DATA FLOW'], ['네트워크와 요청 처리', 'Network and request handling'], ['송수신 처리량과 피크 사건에서 수집된 익명 서비스 요청을 비교합니다.', 'Compare transfer rates with anonymous service requests captured during incidents.']],
    storage: [['저장 계통', 'STORAGE SYSTEM'], ['디스크 용량과 입출력', 'Storage capacity and I/O'], ['볼륨별 남은 공간과 읽기·쓰기 변화, 관련 신뢰성 이벤트를 확인합니다.', 'Inspect free capacity, read/write activity, and related reliability events.']],
    containers: [['서비스 계통', 'SERVICE SYSTEM'], ['서비스와 컨테이너', 'Services and containers'], ['운영 중인 워크로드의 상태와 현재 자원 점유를 비교합니다.', 'Compare workload state and current resource occupancy.']],
    reliability: [['신뢰성 계통', 'RELIABILITY SYSTEM'], ['호스트 신뢰성과 연결', 'Host reliability and connectivity'], ['부팅·수집 공백·SSH·네트워크·NVMe·커널 사건을 시간순으로 점검합니다.', 'Review boot, collection, SSH, network, NVMe, and kernel events chronologically.']],
    power: [['전원 계통', 'POWER SYSTEM'], ['전원 품질과 제한 상태', 'Power quality and throttling'], ['공급 전압과 현재·과거 제한 플래그, 전원 이벤트를 함께 봅니다.', 'Inspect supply voltage, current and historic throttle flags, and power events.']],
    incidents: [['사건 분석', 'INCIDENT ANALYSIS'], ['피크 사건과 증거', 'Peak incidents and evidence'], ['임계치를 넘은 시점의 자원·압박·프로세스·서비스 요청 증거를 검토합니다.', 'Review resource, pressure, process, and service-request evidence at threshold crossings.']],
    logs: [['운영 기록', 'OPERATIONS JOURNAL'], ['통합 이벤트 로그', 'Unified event log'], ['경고·신뢰성·전원·권한 감사 기록을 분류하고 검색합니다.', 'Filter and search alert, reliability, power, and privilege-audit records.']],
  };
  const [eyebrow, title, description] = pages[page];
  return { eyebrow: t(locale, ...eyebrow), title: t(locale, ...title), description: t(locale, ...description) };
}
