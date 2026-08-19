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
  privilegeEvents: Array<{
    timestamp: string;
    actor: string | null;
    target: string | null;
    action: 'sudo' | 'su' | 'authentication' | 'policy' | 'unknown';
    result: 'success' | 'failure' | 'unknown';
  }>;
}
