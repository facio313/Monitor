export type SshAccessRange = '1h' | '6h' | '24h' | '7d' | '30d';
export type SshAccessFilter = 'all' | 'failed' | 'accepted' | 'preauth_closed';
export type SshAccessState = 'fresh' | 'partial' | 'unavailable' | 'stale';
export type SshAccessEvent = 'denied' | 'invalid_user' | 'auth_failed' | 'accepted' | 'preauth_closed';
export type SshCountryStatus = 'estimated' | 'private' | 'unavailable' | 'not_found' | 'stale';
export type SshAccessError = 'not_configured' | 'acquisition_failed' | 'acquisition_partial' | 'persistence_failed' | 'invalid_input' | null;

export interface SshAccessRecord {
  schemaVersion: 1;
  id: string;
  observedAt: string;
  sourceId: 'journal:ssh' | 'journal:sshd';
  sourceIp: string;
  sourcePort: number | null;
  eventType: SshAccessEvent;
  authMethod: 'publickey' | 'password' | 'keyboard-interactive' | null;
  countryCode: string | null;
  countryStatus: SshCountryStatus;
  databaseDate: string | null;
}

export interface SshAccessSource {
  sourceId: SshAccessRecord['sourceId'];
  status: SshAccessState;
  observedAt: string | null;
  lastSuccessAt: string | null;
  errorClass: SshAccessError;
}

export interface SshAccessResponse {
  schemaVersion: 1;
  status: SshAccessState;
  stale: boolean;
  partial: boolean;
  observedAt: string | null;
  lastSuccessAt: string | null;
  errorClass: SshAccessError;
  sources: SshAccessSource[];
  acceptedRecords: number;
  deduplicatedRecords: number;
  droppedRecords: number;
  range: SshAccessRange;
  event: SshAccessFilter;
  ip: string | null;
  from: string;
  to: string;
  page: number;
  limit: number;
  total: number;
  records: SshAccessRecord[];
  rejectedRows: number;
  deduplicatedRows: number;
  truncated: boolean;
  scannedRows: number;
  scannedBytes: number;
  retentionDays: 30;
}
