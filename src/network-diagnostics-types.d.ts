export type NetworkDiagnosticRange = '1h' | '6h' | '24h' | '7d' | '30d';
export type NetworkDiagnosticProblem = 'all' | 'http' | 'tcp' | 'interface';
export type NetworkDiagnosticState = 'fresh' | 'stale' | 'no_data' | 'error';
export interface NetworkProbeDiagnostic {
  id: string;
  checkedAt: string;
  status: 'ok' | 'dns' | 'permission' | 'timeout' | 'tls' | 'http' | 'invalid' | 'unsupported';
  httpStatus: number | null;
  redirectCount: number;
  errorPhase: 'validation' | 'dns' | 'tcp' | 'tls' | 'request' | 'ttfb' | 'headers' | 'certificate' | 'redirect' | 'http' | null;
  timings: { dnsMs: number | null; tcpMs: number | null; tlsMs: number | null; ttfbMs: number | null; totalMs: number };
}
export interface NetworkDiagnosticRecord {
  schemaVersion: 1;
  observedAt: string;
  probeStatus: NetworkDiagnosticState;
  probeObservedAt: string | null;
  probes: NetworkProbeDiagnostic[];
  tcp: {
    status: 'fresh' | 'no_data' | 'error';
    elapsedSeconds: number | null;
    retransmittedSegments: number | null;
    outboundSegments: number | null;
    retransmitPercent: number | null;
    retransmittedPerSecond: number | null;
    outboundPerSecond: number | null;
  };
  interfaces: { rxErrorsPerSecond: number | null; txErrorsPerSecond: number | null; rxDroppedPerSecond: number | null; txDroppedPerSecond: number | null };
  context: {
    cpuPercent: number | null; memoryPercent: number | null;
    cpuPressureSomeAvg10: number | null; cpuPressureFullAvg10: number | null;
    memoryPressureSomeAvg10: number | null; memoryPressureFullAvg10: number | null;
    ioPressureSomeAvg10: number | null; ioPressureFullAvg10: number | null;
  };
  problems: Exclude<NetworkDiagnosticProblem, 'all'>[];
}
export interface NetworkDiagnosticsResponse {
  schemaVersion: 1;
  status: NetworkDiagnosticState;
  observedAt: string | null;
  range: NetworkDiagnosticRange;
  from: string;
  to: string;
  problem: NetworkDiagnosticProblem;
  page: number;
  limit: number;
  total: number;
  records: NetworkDiagnosticRecord[];
  rejectedRows: number;
  truncated: boolean;
  retentionDays: number;
}
