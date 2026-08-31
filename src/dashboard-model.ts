import type {
  AlertEvent,
  DashboardPayload,
  DockerContainerEvent,
  MonitorDetailPage,
  MonitorLocale,
  MonitorPage,
  PowerEvent,
  PrivilegeEvent,
  ReliabilityEvent,
  RuleAlertEvent,
  TelemetrySample,
  TimeRange,
} from './types';

export const DETAIL_PAGES: readonly MonitorDetailPage[] = [
  'resources',
  'network',
  'storage',
  'containers',
  'reliability',
  'maintenance',
  'infrastructure',
  'power',
  'incidents',
  'logs',
] as const;

const DETAIL_PAGE_SET = new Set<string>(DETAIL_PAGES);

export function monitorPageFromPath(pathname: string): MonitorPage {
  const match = /^\/monitor\/details(?:\/([^/]+))?\/?$/.exec(pathname);
  if (!match) return 'overview';
  const section = match[1];
  if (!section) return 'resources';
  return DETAIL_PAGE_SET.has(section) ? section as MonitorDetailPage : 'overview';
}

export function monitorPathForPage(page: MonitorPage): string {
  if (page === 'overview') return '/monitor/';
  if (page === 'details') return '/monitor/details/resources';
  return `/monitor/details/${page}`;
}

export type OperationalAssessmentPresentation = 'overview' | 'details' | 'hidden';

export function operationalAssessmentPresentation(page: MonitorPage): OperationalAssessmentPresentation {
  if (page === 'overview') return 'overview';
  if (page === 'reliability') return 'details';
  return 'hidden';
}

const TIME_RANGE_SET = new Set<TimeRange>(['1h', '24h', '7d', '30d']);
export const MONITOR_STALE_AFTER_MS = 5 * 60_000;

export function monitorRangeFromSearch(search: string): TimeRange {
  try {
    const value = new URLSearchParams(search).get('range');
    return value && TIME_RANGE_SET.has(value as TimeRange) ? value as TimeRange : '24h';
  } catch {
    return '24h';
  }
}

export function monitorSnapshotIsStale(
  reportedStale: boolean,
  lastSuccessfulAtMs: number,
  nowMs: number,
  staleAfterMs = MONITOR_STALE_AFTER_MS,
): boolean {
  if (reportedStale) return true;
  if (!Number.isFinite(lastSuccessfulAtMs) || !Number.isFinite(nowMs)) return true;
  return nowMs - lastSuccessfulAtMs > staleAfterMs;
}

export function chooseInitialLocale(stored: string | null, browserLanguages: readonly string[]): MonitorLocale {
  if (stored === 'ko' || stored === 'en') return stored;
  return browserLanguages.some((language) => /^ko(?:-|$)/i.test(language)) ? 'ko' : 'ko';
}

export function localized(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

export interface RangeStatistics {
  samples: number;
  cpuAverage: number | null;
  cpuPeak: number | null;
  memoryAverage: number | null;
  memoryPeak: number | null;
  temperatureAverage: number | null;
  temperaturePeak: number | null;
  loadAverage: number | null;
  loadPeak: number | null;
  networkReceivedBytes: number;
  networkTransmittedBytes: number;
  diskReadBytes: number;
  diskWrittenBytes: number;
}

function finiteValues(series: TelemetrySample[], field: keyof TelemetrySample): number[] {
  return series
    .map((sample) => sample[field])
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
}

function average(values: number[]): number | null {
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function peak(values: number[]): number | null {
  return values.length ? Math.max(...values) : null;
}

function integratedRate(series: TelemetrySample[], field: keyof TelemetrySample): number {
  if (series.length < 2) return 0;
  let total = 0;
  for (let index = 1; index < series.length; index += 1) {
    const previous = series[index - 1];
    const current = series[index];
    const rate = current[field];
    const before = new Date(previous.timestamp ?? '').getTime();
    const after = new Date(current.timestamp ?? '').getTime();
    if (typeof rate !== 'number' || !Number.isFinite(rate) || rate < 0) continue;
    if (!Number.isFinite(before) || !Number.isFinite(after) || after <= before) continue;
    total += rate * Math.min((after - before) / 1_000, 300);
  }
  return total;
}

export function rangeStatistics(series: TelemetrySample[]): RangeStatistics {
  const cpu = finiteValues(series, 'cpuPercent');
  const memory = finiteValues(series, 'memoryPercent');
  const temperature = finiteValues(series, 'temperatureC');
  const load = finiteValues(series, 'load1');
  return {
    samples: series.length,
    cpuAverage: average(cpu),
    cpuPeak: peak(cpu),
    memoryAverage: average(memory),
    memoryPeak: peak(memory),
    temperatureAverage: average(temperature),
    temperaturePeak: peak(temperature),
    loadAverage: average(load),
    loadPeak: peak(load),
    networkReceivedBytes: integratedRate(series, 'networkRxBytesPerSecond'),
    networkTransmittedBytes: integratedRate(series, 'networkTxBytesPerSecond'),
    diskReadBytes: integratedRate(series, 'diskReadBytesPerSecond'),
    diskWrittenBytes: integratedRate(series, 'diskWriteBytesPerSecond'),
  };
}

export type OperationalLogCategory = 'alert' | 'reliability' | 'power' | 'privilege' | 'docker' | 'rule';
export type OperationalLogSeverity = 'critical' | 'warning' | 'info';

export interface OperationalLogEntry {
  id: string;
  timestamp: string;
  category: OperationalLogCategory;
  severity: OperationalLogSeverity;
  kind: string;
  status: string;
  title: string;
  message: string;
  actor: string | null;
  target: string | null;
}

function normalizedSeverity(value: unknown, status: unknown): OperationalLogSeverity {
  const severity = typeof value === 'string' ? value.toLowerCase() : '';
  if (/(critical|error|failure|failed|denied)/.test(severity)) return 'critical';
  if (/(warning|warn|caution|degraded)/.test(severity)) return 'warning';
  if (/(info|informational|advisory|success|ok)/.test(severity)) return 'info';

  // Status is only a fallback for legacy events without a canonical severity.
  // Treating every `active` status as a warning incorrectly promoted nominal
  // records such as `nvme-mitigation:active / info`.
  const state = typeof status === 'string' ? status.toLowerCase() : '';
  if (/(critical|error|failure|failed|denied|unhealthy|down)/.test(state)) return 'critical';
  if (/(warning|warn|active|degraded|stale|unknown|incomplete)/.test(state)) return 'warning';
  return 'info';
}

function safeLogText(value: unknown, fallback: string, maximum = 240): string {
  if (typeof value !== 'string') return fallback;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!cleaned) return fallback;
  return cleaned.length > maximum ? `${cleaned.slice(0, maximum - 1)}…` : cleaned;
}

function eventEntry(
  event: AlertEvent | PowerEvent | ReliabilityEvent,
  category: Exclude<OperationalLogCategory, 'privilege' | 'docker' | 'rule'>,
  index: number,
): OperationalLogEntry {
  const kind = safeLogText(event.kind, category, 64);
  const status = safeLogText(event.status, 'unknown', 48);
  return {
    id: `${category}:${event.timestamp}:${index}`,
    timestamp: event.timestamp,
    category,
    severity: normalizedSeverity(event.severity, event.status),
    kind,
    status,
    title: `${kind.replace(/[-_]+/g, ' ')} · ${status.replace(/[-_]+/g, ' ')}`,
    message: safeLogText(event.message, 'No additional detail was recorded.'),
    actor: null,
    target: null,
  };
}

function dockerEventEntry(event: DockerContainerEvent): OperationalLogEntry {
  const action = safeLogText(event.action, 'event', 48);
  const containerName = safeLogText(event.containerName, 'container', 96);
  const project = safeLogText(event.project, 'unknown project', 96);
  const nonZeroExit = event.action === 'die' && typeof event.exitCode === 'number' && event.exitCode !== 0;
  const severity: OperationalLogSeverity = event.action === 'oom'
    || event.healthStatus === 'unhealthy'
    || nonZeroExit
    ? 'critical'
    : event.action === 'kill'
      || event.action === 'restart'
      || event.action === 'pause'
      || event.healthStatus === 'starting'
      || (event.action === 'die' && event.exitCode === null)
      ? 'warning'
      : 'info';
  const status = event.healthStatus
    ?? (event.exitCode !== null ? `exit-${event.exitCode}` : action);
  const details = [
    `project ${project}`,
    event.healthStatus ? `health ${safeLogText(event.healthStatus, 'unknown', 32)}` : null,
    event.exitCode !== null ? `exit ${event.exitCode}` : null,
  ].filter((value): value is string => Boolean(value));
  return {
    id: `docker:${event.id}`,
    timestamp: event.occurredAt,
    category: 'docker',
    severity,
    kind: action,
    status,
    title: `${containerName} · ${action.replace(/[-_]+/g, ' ')}`,
    message: details.join(' · '),
    actor: null,
    target: containerName,
  };
}

function ruleAlertEntry(event: RuleAlertEvent): OperationalLogEntry {
  const ruleId = safeLogText(event.ruleId, 'rule', 96);
  const transition = safeLogText(event.transition, 'transition', 32);
  const notificationState = safeLogText(event.notificationState, 'unknown', 32);
  const observationStatus = safeLogText(event.status, 'unknown', 48);
  const value = typeof event.value === 'number' && Number.isFinite(event.value) ? String(event.value) : '—';
  return {
    id: `rule:${event.idempotencyKey}`,
    timestamp: event.observedAt,
    category: 'rule',
    severity: event.transition === 'resolved' ? 'info' : normalizedSeverity(event.severity, event.status),
    kind: ruleId,
    status: `${transition} · ${notificationState} · ${observationStatus}`,
    title: `${ruleId} · ${transition}`,
    message: `${safeLogText(event.description, 'No rule description was recorded.')} · value ${value} · notification ${notificationState}`,
    actor: null,
    target: safeLogText(event.target, 'unknown target', 160),
  };
}

function privilegeEntry(event: PrivilegeEvent, index: number): OperationalLogEntry {
  const result = safeLogText(event.result, 'unknown', 48);
  const action = safeLogText(event.action, 'privileged operation', 64);
  return {
    id: `privilege:${event.timestamp}:${index}`,
    timestamp: event.timestamp,
    category: 'privilege',
    severity: normalizedSeverity(event.result, event.result),
    kind: action,
    status: result,
    title: `${action.replace(/[-_]+/g, ' ')} · ${result.replace(/[-_]+/g, ' ')}`,
    message: 'A sanitized privilege outcome was recorded. Commands and arguments are intentionally unavailable.',
    actor: event.actor,
    target: event.target,
  };
}

export function operationalLogs(data: DashboardPayload): OperationalLogEntry[] {
  const generatedAt = Date.parse(data.generatedAt);
  const rangeMilliseconds: Record<TimeRange, number> = {
    '1h': 60 * 60_000,
    '24h': 24 * 60 * 60_000,
    '7d': 7 * 24 * 60 * 60_000,
    '30d': 30 * 24 * 60 * 60_000,
  };
  const dockerCutoff = Number.isFinite(generatedAt) ? generatedAt - (rangeMilliseconds[data.range] ?? rangeMilliseconds['24h']) : Number.NEGATIVE_INFINITY;
  const dockerEntries = (data.dockerEvents ?? [])
    .filter((event) => {
      const occurredAt = Date.parse(event.occurredAt);
      return Number.isFinite(occurredAt)
        && (!Number.isFinite(generatedAt) || (occurredAt >= dockerCutoff && occurredAt <= generatedAt));
    })
    .map(dockerEventEntry);
  const ruleEntries = data.ruleAlerts?.status === 'ok' ? data.ruleAlerts.events.map(ruleAlertEntry) : [];
  const entries = [
    ...data.alerts.map((event, index) => eventEntry(event, 'alert', index)),
    ...data.reliabilityEvents.map((event, index) => eventEntry(event, 'reliability', index)),
    ...data.powerEvents.map((event, index) => eventEntry(event, 'power', index)),
    ...data.privilegeEvents.map(privilegeEntry),
    ...dockerEntries,
    ...ruleEntries,
  ];
  const deduplicated = new Map<string, OperationalLogEntry>();
  for (const entry of entries) if (!deduplicated.has(entry.id)) deduplicated.set(entry.id, entry);
  const severityOrder: Record<OperationalLogSeverity, number> = { critical: 0, warning: 1, info: 2 };
  return [...deduplicated.values()].sort((left, right) => {
    const leftTime = Date.parse(left.timestamp);
    const rightTime = Date.parse(right.timestamp);
    const validTimeOrder = Number.isFinite(leftTime) && Number.isFinite(rightTime) ? rightTime - leftTime : 0;
    if (validTimeOrder) return validTimeOrder;
    if (!Number.isFinite(leftTime) && Number.isFinite(rightTime)) return 1;
    if (Number.isFinite(leftTime) && !Number.isFinite(rightTime)) return -1;
    return severityOrder[left.severity] - severityOrder[right.severity]
      || left.id.localeCompare(right.id);
  });
}

export interface EventBucket {
  label: string;
  info: number;
  warning: number;
  critical: number;
}

export function eventBuckets(entries: OperationalLogEntry[], bucketCount = 12): EventBucket[] {
  if (!entries.length || !Number.isInteger(bucketCount) || bucketCount < 1 || bucketCount > 48) return [];
  const timestamps = entries.map((entry) => new Date(entry.timestamp).getTime()).filter(Number.isFinite);
  if (!timestamps.length) return [];
  const minimum = Math.min(...timestamps);
  const maximum = Math.max(...timestamps);
  const width = Math.max(1, (maximum - minimum || 1) / bucketCount);
  const buckets = Array.from({ length: bucketCount }, (_, index): EventBucket & { start: number } => ({
    start: minimum + index * width,
    label: new Date(minimum + index * width).toISOString(),
    info: 0,
    warning: 0,
    critical: 0,
  }));
  for (const entry of entries) {
    const timestamp = new Date(entry.timestamp).getTime();
    if (!Number.isFinite(timestamp)) continue;
    const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((timestamp - minimum) / width)));
    buckets[index][entry.severity] += 1;
  }
  return buckets.map(({ start: _start, ...bucket }) => bucket);
}

export function relatedLogs(entries: OperationalLogEntry[], page: MonitorPage): OperationalLogEntry[] {
  if (page === 'logs' || page === 'overview' || page === 'details') return entries;
  const categories: Partial<Record<MonitorDetailPage, OperationalLogCategory[]>> = {
    reliability: ['alert', 'reliability', 'power', 'privilege', 'docker', 'rule'],
    maintenance: ['reliability', 'power', 'privilege'],
    power: ['power', 'alert'],
    resources: ['alert', 'reliability'],
    network: ['alert', 'reliability'],
    storage: ['alert', 'reliability'],
    containers: ['alert', 'docker', 'rule'],
    incidents: ['alert', 'reliability', 'power'],
  };
  const allowed = new Set(categories[page] ?? []);
  return entries.filter((entry) => allowed.has(entry.category));
}
