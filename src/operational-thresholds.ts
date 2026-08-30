export interface OperationalThreshold {
  caution: number;
  danger: number;
}

/** Shared 10-second PSI thresholds for findings and at-a-glance meters. */
export const PSI_THRESHOLDS = {
  cpuSome: { caution: 5, danger: 20 },
  cpuFull: { caution: 1, danger: 8 },
  memorySome: { caution: 1, danger: 10 },
  memoryFull: { caution: 0.2, danger: 5 },
  ioSome: { caution: 5, danger: 20 },
  ioFull: { caution: 1, danger: 8 },
} as const satisfies Record<string, OperationalThreshold>;

export const NETWORK_FAULT_RATE_THRESHOLDS = {
  caution: 0.001,
  danger: 1,
} as const satisfies OperationalThreshold;
