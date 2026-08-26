export type TimeRange = '1h' | '24h' | '7d' | '30d';
export type MonitorDetailPage =
  | 'resources'
  | 'network'
  | 'storage'
  | 'containers'
  | 'reliability'
  | 'power'
  | 'incidents'
  | 'logs';
// `details` remains a compatibility-only route token for the legacy dashboard
// component and old deep links. New navigation resolves it to `resources`.
export type MonitorPage = 'overview' | 'details' | MonitorDetailPage;
export type MonitorLocale = 'ko' | 'en';

export interface TelemetrySample {
  timestamp: string | null;
  cpuPercent: number | null;
  memoryPercent: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  temperatureC: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  powerState: string | null;
  supplyVoltageVolts: number | null;
  throttledFlags: number | null;
  gpuMemoryBytes: number | null;
  gpuClockHz: number | null;
  networkRxBytesPerSecond: number | null;
  networkTxBytesPerSecond: number | null;
  diskReadBytesPerSecond: number | null;
  diskWriteBytesPerSecond: number | null;
}

export interface DashboardPayload {
  generatedAt: string;
  range: TimeRange;
  stale: boolean;
  host: {
    hostname: string | null;
    os: string | null;
    architecture: string | null;
    uptimeSeconds: number | null;
  };
  reliability: ReliabilitySummary;
  latest: TelemetrySample | null;
  series: TelemetrySample[];
  telemetrySummary: TelemetrySummary;
  incidents: PeakIncident[];
  disks: DiskUsage[];
  containers: ContainerStatus[];
  alerts: AlertEvent[];
  privilegeEvents: PrivilegeEvent[];
  powerEvents: PowerEvent[];
  reliabilityEvents: ReliabilityEvent[];
  powerSummary: PowerSummary;
}

export interface TelemetrySummary {
  sampleCount: number;
  cpuAveragePercent: number | null;
  cpuPeakPercent: number | null;
  memoryAveragePercent: number | null;
  memoryPeakPercent: number | null;
  temperatureAverageC: number | null;
  temperaturePeakC: number | null;
  load1Average: number | null;
  load1Peak: number | null;
  networkReceivedBytes: number;
  networkTransmittedBytes: number;
  diskReadBytes: number;
  diskWrittenBytes: number;
}

export interface ReliabilitySummary {
  bootStartedAt: string | null;
  collectorGapSeconds: number | null;
  sshListenersAvailable: boolean | null;
  networkLinkAvailable: boolean | null;
  nvmeMitigationActive: boolean | null;
}

export type ReliabilityEventKind =
  | 'host-boot'
  | 'collector-gap'
  | 'ssh-listener'
  | 'network-link'
  | 'nvme-reset'
  | 'nvme-io'
  | 'rcu-stall'
  | 'oom-kill'
  | 'filesystem-error'
  | 'nvme-mitigation';

export interface ReliabilityEvent {
  timestamp: string;
  severity: 'info' | 'warning' | 'critical';
  kind: ReliabilityEventKind;
  status: string;
  message: string;
  durationSeconds: number | null;
}

export type IncidentPhase = 'active' | 'follow-up' | 'recovered';
export type IncidentReason = 'cpu' | 'memory' | 'temperature' | 'load' | 'disk-io' | 'power-throttle' | 'traffic';

export interface IncidentPressureMetric {
  someAvg10: number | null;
  fullAvg10: number | null;
}

export interface IncidentProcess {
  name: string;
  instances: number;
  cpuPercent: number | null;
  memoryBytes: number | null;
}

export interface IncidentTraffic {
  app: string;
  requestCount: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  slowCount: number;
  avgResponseMs: number | null;
  maxResponseMs: number | null;
}

export interface PeakIncident {
  id: string;
  startedAt: string;
  observedAt: string;
  endedAt: string | null;
  phase: IncidentPhase;
  reasons: IncidentReason[];
  metrics: TelemetrySample;
  pressure: {
    cpu: IncidentPressureMetric;
    memory: IncidentPressureMetric;
    io: IncidentPressureMetric;
  };
  processes: IncidentProcess[];
  containers: ContainerStatus[];
  traffic: IncidentTraffic[];
  peaks: {
    cpuPercent: number | null;
    memoryPercent: number | null;
    temperatureC: number | null;
    load1: number | null;
  } | null;
  durationSeconds: number | null;
}

export interface PowerEvent {
  timestamp: string;
  severity: string;
  kind: string | null;
  status: string | null;
  message: string;
  supplyVoltageVolts: number | null;
  throttledFlags: number | null;
}

export interface PowerSummary {
  sampleCount: number;
  voltageSampleCount: number;
  minSupplyVoltageVolts: number | null;
  averageSupplyVoltageVolts: number | null;
  maxSupplyVoltageVolts: number | null;
  underVoltageSampleCount: number;
  throttledSampleCount: number;
}

export interface DiskUsage {
  mount: string;
  totalBytes: number | null;
  usedBytes: number | null;
  usedPercent: number | null;
}

export interface ContainerStatus {
  name: string;
  owner: string | null;
  state: string | null;
  health: string | null;
  cpuPercent: number | null;
  memoryBytes: number | null;
  memoryPercent: number | null;
}

export interface AlertEvent {
  timestamp: string;
  severity: string;
  kind: string | null;
  status: string | null;
  message: string;
}

export interface PrivilegeEvent {
  timestamp: string;
  actor: string | null;
  target: string | null;
  action: string;
  result: string;
}
