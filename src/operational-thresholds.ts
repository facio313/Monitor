export interface OperationalThreshold {
  caution: number | null;
  danger: number | null;
}

/** Mirror ops/notification_policy.py; instantaneous readings do not prove duration. */
export const RESOURCE_THRESHOLDS = {
  cpu: { caution: 90, danger: null },
  memory: { caution: 80, danger: 90 },
  temperature: { caution: 80, danger: 85 },
  load: { caution: 1.5, danger: null },
  disk: { caution: 85, danger: 95 },
  inode: { caution: 85, danger: 90 },
} as const satisfies Record<string, OperationalThreshold>;

/** Shared PSI policy; null means no tier, not an infinite displayed threshold. */
export const PSI_THRESHOLDS = {
  cpuSome: { caution: 20, danger: null },
  cpuFull: { caution: null, danger: null },
  memorySome: { caution: 2, danger: 10 },
  memoryFull: { caution: 5, danger: null },
  ioSome: { caution: 20, danger: null },
  ioFull: { caution: 8, danger: null },
} as const satisfies Record<string, OperationalThreshold>;

/** Interface errors and packet drops have different operational scales. */
export const NETWORK_ERROR_RATE_THRESHOLDS = {
  caution: 0.1,
  danger: 1,
} as const satisfies OperationalThreshold;

export const NETWORK_DROP_RATE_THRESHOLDS = {
  caution: 1,
  danger: 10,
} as const satisfies OperationalThreshold;
