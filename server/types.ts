export const DASHBOARD_RANGES = ['1h', '24h', '7d', '30d'] as const;

export type DashboardRange = (typeof DASHBOARD_RANGES)[number];

export interface TelemetrySample {
  timestamp: string;
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

export interface IncidentPressureWindow {
  someAvg10: number | null;
  fullAvg10: number | null;
}

export interface TrafficAggregate {
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

export type IncidentReason =
  | 'cpu'
  | 'memory'
  | 'temperature'
  | 'load'
  | 'disk-io'
  | 'power-throttle'
  | 'traffic';

export interface DashboardIncident {
  id: string;
  startedAt: string;
  observedAt: string;
  endedAt: string | null;
  phase: 'active' | 'follow-up' | 'recovered';
  reasons: IncidentReason[];
  metrics: TelemetrySample;
  pressure: {
    cpu: IncidentPressureWindow;
    memory: IncidentPressureWindow;
    io: IncidentPressureWindow;
  };
  processes: Array<{
    name: string;
    instances: number;
    cpuPercent: number | null;
    memoryBytes: number | null;
  }>;
  containers: Array<{
    name: string;
    owner: string | null;
    state: string | null;
    health: string | null;
    cpuPercent: number | null;
    memoryBytes: number | null;
    memoryPercent: number | null;
  }>;
  traffic: TrafficAggregate[];
  peaks: {
    cpuPercent: number | null;
    memoryPercent: number | null;
    temperatureC: number | null;
    load1: number | null;
  } | null;
  durationSeconds: number | null;
}

export interface KernelEventCounter {
  count: number;
  lastEventAt: string | null;
}

export interface SystemSnapshot {
  versions: {
    kernelRunning: string | null;
    kernelLatestInstalled: string | null;
    kernelRebootRequired: boolean | null;
    bootloaderCurrent: string | null;
    bootloaderLatest: string | null;
    bootloaderChannel: string | null;
    nvmeModel: string | null;
    nvmeFirmware: string | null;
    collector: string | null;
  };
  pcie: {
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
  };
  kernel: {
    warning: KernelEventCounter;
    oops: KernelEventCounter;
    panic: KernelEventCounter;
    hungTask: KernelEventCounter;
    rcuStall: KernelEventCounter;
    rcuExpedited: KernelEventCounter;
    oomKill: KernelEventCounter;
    filesystemError: KernelEventCounter;
    nvmeReset: KernelEventCounter;
    nvmeIo: KernelEventCounter;
    pcieAerCorrectable: KernelEventCounter;
    pcieAerNonFatal: KernelEventCounter;
    pcieAerFatal: KernelEventCounter;
  };
}

export type RuleEvaluationPhase =
  | 'inactive'
  | 'pending'
  | 'firing'
  | 'recovering'
  | 'no_data'
  | 'unsupported'
  | 'permission_denied'
  | 'collection_error';

export type RuleObservationStatus =
  | 'ok'
  | 'no_data'
  | 'stale'
  | 'collection_error'
  | 'permission_denied'
  | 'unsupported';

export interface RuleEvaluationState {
  ruleId: string;
  target: string;
  metric: string;
  severity: 'info' | 'warning' | 'critical';
  description: string;
  runbook: string;
  phase: RuleEvaluationPhase;
  breachSamples: number;
  recoverySamples: number;
  missingSamples: number;
  openedAt: string | null;
  changedAt: string;
  lastEvaluatedAt: string;
  lastValue: number | null;
  observationStatus: RuleObservationStatus;
}

export interface RuleAlertEvent {
  schemaVersion: 1;
  rulePackVersion: string;
  idempotencyKey: string;
  ruleId: string;
  target: string;
  transition: 'firing' | 'resolved';
  severity: 'info' | 'warning' | 'critical';
  notificationState: 'ready' | 'suppressed' | 'silenced';
  observedAt: string;
  openedAt: string;
  value: number | null;
  status: RuleObservationStatus;
  labels: Record<string, string>;
  description: string;
  runbook: string;
}

export interface DashboardResponse {
  generatedAt: string;
  range: DashboardRange;
  stale: boolean;
  latestObservedAt: string | null;
  host: {
    hostname: string | null;
    os: string | null;
    architecture: string | null;
    logicalCpuCount: number | null;
    uptimeSeconds: number | null;
  };
  reliability: {
    bootStartedAt: string | null;
    collectorGapSeconds: number | null;
    sshListenersAvailable: boolean | null;
    networkLinkAvailable: boolean | null;
    nvmeMitigationActive: boolean | null;
  };
  system: SystemSnapshot;
  latest: TelemetrySample;
  series: TelemetrySample[];
  telemetrySummary: {
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
  };
  powerSummary: {
    sampleCount: number;
    voltageSampleCount: number;
    minSupplyVoltageVolts: number | null;
    averageSupplyVoltageVolts: number | null;
    maxSupplyVoltageVolts: number | null;
    underVoltageSampleCount: number;
    throttledSampleCount: number;
  };
  disks: Array<{
    mount: string;
    totalBytes: number | null;
    usedBytes: number | null;
    availableBytes: number | null;
    usedPercent: number | null;
    inodeUsedPercent: number | null;
    readOnly: boolean | null;
  }>;
  containerCollection: {
    status: 'fresh' | 'last-known' | 'unavailable' | 'permission-denied';
    observedAt: string | null;
  };
  containers: Array<{
    name: string;
    project: string | null;
    owner: string | null;
    state: string | null;
    health: string | null;
    healthcheckConfigured: boolean | null;
    cpuPercent: number | null;
    memoryBytes: number | null;
    memoryPercent: number | null;
    memoryLimitBytes: number | null;
    cpuLimitCores: number | null;
    pidLimit: number | null;
    restartCount: number | null;
    restartCountDelta: number | null;
    oomKilled: boolean | null;
    startedAt: string | null;
    finishedAt: string | null;
  }>;
  currentTraffic: TrafficAggregate[];
  alerts: Array<{
    timestamp: string;
    severity: 'info' | 'warning' | 'critical';
    kind: string | null;
    status: string | null;
    message: string;
  }>;
  ruleEvaluation: {
    schemaVersion: 1;
    status: 'ok' | 'last-known' | 'collection_error' | 'unavailable';
    rulePackVersion: string | null;
    evaluatedAt: string | null;
    summary: Partial<Record<RuleEvaluationPhase, number>>;
    states: Record<string, RuleEvaluationState>;
  };
  ruleAlerts: {
    status: 'ok' | 'collection_error' | 'unavailable';
    events: RuleAlertEvent[];
  };
  powerEvents: Array<{
    timestamp: string;
    severity: 'info' | 'warning' | 'critical';
    kind: string | null;
    status: string | null;
    message: string;
    supplyVoltageVolts: number | null;
    throttledFlags: number | null;
  }>;
  reliabilityEvents: Array<{
    timestamp: string;
    severity: 'info' | 'warning' | 'critical';
    kind:
      | 'host-boot'
      | 'collector-gap'
      | 'ssh-listener'
      | 'network-link'
      | 'nvme-reset'
      | 'nvme-io'
      | 'rcu-stall'
      | 'oom-kill'
      | 'filesystem-error'
      | 'pcie-aer'
      | 'pcie-link'
      | 'kernel-warning'
      | 'kernel-oops'
      | 'kernel-panic'
      | 'hung-task'
      | 'nvme-mitigation';
    status: string;
    message: string;
    durationSeconds: number | null;
  }>;
  privilegeEvents: Array<{
    timestamp: string;
    actor: string | null;
    target: string | null;
    action: 'sudo' | 'su' | 'authentication' | 'policy' | 'unknown';
    result: 'success' | 'failure' | 'unknown';
  }>;
  incidents: DashboardIncident[];
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
