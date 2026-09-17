export interface NotificationReportStatus {
  schemaVersion: 1;
  observedAt: string | null;
  stale: boolean;
  status: 'ok' | 'disabled' | 'error' | 'unavailable';
  hourly: { slot: string | null; lastQueuedAt: string | null; enqueued: number; deduplicated: number; dropped: number };
  immediate: { enqueued: number; deduplicated: number; dropped: number };
  delivery: { pending: number; retrying: number; sent: number; failed: number; lastAttemptAt: string | null; lastOutcome: string | null };
  sourceHealth: Array<{ source: string; status: string; observedAt: string | null; detail: string }>;
  detections: Array<{ id: string; kind: string; severity: string; status: 'active' | 'resolved'; openedAt: string; observedAt: string; count: number; windowSeconds: number; evidence: string }>;
}
