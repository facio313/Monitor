export const DASHBOARD_RANGES = ['1h', '24h', '7d', '30d'] as const;

export type DashboardRange = (typeof DASHBOARD_RANGES)[number];

export interface TelemetrySample {
  timestamp: string;
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

export interface DashboardResponse {
  generatedAt: string;
  range: DashboardRange;
  stale: boolean;
  host: {
    hostname: string | null;
    os: string | null;
    architecture: string | null;
    uptimeSeconds: number | null;
  };
  latest: TelemetrySample;
  series: TelemetrySample[];
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
    usedPercent: number | null;
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
  alerts: Array<{
    timestamp: string;
    severity: 'info' | 'warning' | 'critical';
    kind: string | null;
    status: string | null;
    message: string;
  }>;
  powerEvents: Array<{
    timestamp: string;
    severity: 'info' | 'warning' | 'critical';
    kind: string | null;
    status: string | null;
    message: string;
    supplyVoltageVolts: number | null;
    throttledFlags: number | null;
  }>;
  privilegeEvents: Array<{
    timestamp: string;
    actor: string | null;
    target: string | null;
    action: 'sudo' | 'su' | 'authentication' | 'policy' | 'unknown';
    result: 'success' | 'failure' | 'unknown';
  }>;
}
