export type TimeRange = '1h' | '24h' | '7d' | '30d';
export type MonitorDetailPage =
  | 'resources'
  | 'network'
  | 'storage'
  | 'containers'
  | 'reliability'
  | 'maintenance'
  | 'infrastructure'
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
  swapTotalBytes: number | null;
  swapUsedBytes: number | null;
  swapPercent: number | null;
  temperatureC: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  cpuPressureSomeAvg10: number | null;
  cpuPressureFullAvg10: number | null;
  memoryPressureSomeAvg10: number | null;
  memoryPressureFullAvg10: number | null;
  ioPressureSomeAvg10: number | null;
  ioPressureFullAvg10: number | null;
  powerState: string | null;
  supplyVoltageVolts: number | null;
  throttledFlags: number | null;
  gpuMemoryBytes: number | null;
  gpuClockHz: number | null;
  networkRxBytesPerSecond: number | null;
  networkTxBytesPerSecond: number | null;
  networkRxErrorsPerSecond: number | null;
  networkTxErrorsPerSecond: number | null;
  networkRxDroppedPerSecond: number | null;
  networkTxDroppedPerSecond: number | null;
  diskReadBytesPerSecond: number | null;
  diskWriteBytesPerSecond: number | null;
}

export interface DashboardPayload {
  generatedAt: string;
  range: TimeRange;
  stale: boolean;
  latestObservedAt: string | null;
  host: {
    hostname: string | null;
    os: string | null;
    architecture: string | null;
    logicalCpuCount: number | null;
    uptimeSeconds: number | null;
  };
  reliability: ReliabilitySummary;
  latest: TelemetrySample | null;
  series: TelemetrySample[];
  telemetrySummary: TelemetrySummary;
  incidents: PeakIncident[];
  disks: DiskUsage[];
  containers: ContainerStatus[];
  currentTraffic: IncidentTraffic[];
  alerts: AlertEvent[];
  privilegeEvents: PrivilegeEvent[];
  powerEvents: PowerEvent[];
  reliabilityEvents: ReliabilityEvent[];
  powerSummary: PowerSummary;
  system: SystemStatus;
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
  | 'pcie-aer'
  | 'pcie-link'
  | 'rcu-stall'
  | 'kernel-warning'
  | 'kernel-oops'
  | 'kernel-panic'
  | 'hung-task'
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

export interface SystemEventCount {
  count: number;
  lastEventAt: string | null;
}

export interface SystemVersions {
  kernelRunning: string | null;
  kernelLatestInstalled: string | null;
  kernelRebootRequired: boolean | null;
  bootloaderCurrent: string | null;
  bootloaderLatest: string | null;
  bootloaderChannel: string | null;
  nvmeModel: string | null;
  nvmeFirmware: string | null;
  collector: string | null;
}

export interface SystemPcieStatus {
  configuredGeneration: number | null;
  negotiatedGeneration: number | null;
  negotiatedSpeedGtps: number | null;
  negotiatedWidth: number | null;
  endpointMaxGeneration: number | null;
  endpointMaxWidth: number | null;
  aspmDisabled: boolean | null;
  nvmePowerSavingDisabled: boolean | null;
  aerCorrectableCount: number | null;
  aerNonFatalCount: number | null;
  aerFatalCount: number | null;
  correctableStatusActive: boolean | null;
  nonFatalStatusActive: boolean | null;
  fatalStatusActive: boolean | null;
}

export interface SystemKernelStatus {
  warning: SystemEventCount;
  oops: SystemEventCount;
  panic: SystemEventCount;
  hungTask: SystemEventCount;
  rcuStall: SystemEventCount;
  rcuExpedited: SystemEventCount;
  oomKill: SystemEventCount;
  filesystemError: SystemEventCount;
  nvmeReset: SystemEventCount;
  nvmeIo: SystemEventCount;
  pcieAerCorrectable: SystemEventCount;
  pcieAerNonFatal: SystemEventCount;
  pcieAerFatal: SystemEventCount;
}

export interface SystemStatus {
  versions: SystemVersions;
  pcie: SystemPcieStatus;
  kernel: SystemKernelStatus;
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
  availableBytes: number | null;
  usedPercent: number | null;
  inodeUsedPercent: number | null;
  readOnly: boolean | null;
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

export type InfrastructureLedgerCategory =
  | 'network'
  | 'security'
  | 'identity-access'
  | 'dns-edge'
  | 'reliability'
  | 'compute-kernel'
  | 'storage-filesystem'
  | 'backup-recovery'
  | 'observability-logging'
  | 'service-deployment'
  | 'containers'
  | 'packages-firmware'
  | 'governance-documentation'
  | 'hardware-physical';

export type InfrastructureLedgerStatus =
  | 'completed'
  | 'in-progress'
  | 'pending'
  | 'deferred'
  | 'recommended'
  | 'observed'
  | 'superseded'
  | 'not-applicable';

export type InfrastructureLedgerWorkType =
  | 'change'
  | 'configuration'
  | 'audit'
  | 'hardening'
  | 'mitigation'
  | 'update'
  | 'verification'
  | 'incident'
  | 'maintenance'
  | 'recommendation'
  | 'decision'
  | 'documentation';

export type InfrastructureLedgerPriority = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type InfrastructureLedgerConfidence = 'current-state' | 'documented' | 'inferred' | 'recommendation';
export type InfrastructureLedgerVerification = 'verified' | 'partially-verified' | 'unverified' | 'not-applicable';
export type InfrastructureLedgerApplicability = 'applicable' | 'needs-assessment' | 'not-applicable';
export type InfrastructureLedgerImpact = 'none' | 'observed-none' | 'low' | 'brief' | 'maintenance-window-required' | 'unknown';
export type InfrastructureLedgerSensitivity = 'public' | 'internal' | 'restricted';
export type InfrastructureLedgerCsfFunction = 'govern' | 'identify' | 'protect' | 'detect' | 'respond' | 'recover';

export interface InfrastructureLedgerText {
  ko: string;
  en: string;
}

export interface InfrastructureLedgerEvidence {
  kind: 'runtime' | 'file' | 'journal' | 'package-log' | 'repository' | 'session' | 'standard' | 'operator';
  reference: string;
  observedAt: string;
  note: InfrastructureLedgerText;
}

export interface InfrastructureLedgerEntry {
  id: string;
  itemKey: string;
  revision: number;
  occurredAt: string;
  recordedAt: string;
  category: InfrastructureLedgerCategory;
  workType: InfrastructureLedgerWorkType;
  status: InfrastructureLedgerStatus;
  priority: InfrastructureLedgerPriority;
  confidence: InfrastructureLedgerConfidence;
  verification: InfrastructureLedgerVerification;
  applicability: InfrastructureLedgerApplicability;
  impact: InfrastructureLedgerImpact;
  sensitivity: InfrastructureLedgerSensitivity;
  csfFunctions: InfrastructureLedgerCsfFunction[];
  title: InfrastructureLedgerText;
  summary: InfrastructureLedgerText;
  rationale: InfrastructureLedgerText;
  details: InfrastructureLedgerText;
  outcome: InfrastructureLedgerText;
  nextAction: InfrastructureLedgerText;
  actor: string;
  scope: string[];
  evidence: InfrastructureLedgerEvidence[];
  referenceIds: string[];
  relatedIds: string[];
  supersedes: string | null;
  dueAt: string | null;
  recurrence: InfrastructureLedgerText | null;
}

export interface InfrastructureLedgerReference {
  id: string;
  title: string;
  publisher: string;
  url: string;
  publishedAt: string | null;
  accessedAt: string;
}

export interface InfrastructureLedgerResponse {
  schemaVersion: 1;
  generatedAt: string;
  updatedAt: string;
  limits: {
    usedBytes: number;
    maximumBytes: number;
    maximumEntries: number;
    maximumReferences: number;
  };
  coverage: {
    from: string | null;
    through: string;
    sources: Array<{
      id: string;
      label: InfrastructureLedgerText;
      from: string | null;
      through: string | null;
    }>;
    limitations: InfrastructureLedgerText[];
  };
  references: InfrastructureLedgerReference[];
  entries: InfrastructureLedgerEntry[];
}
