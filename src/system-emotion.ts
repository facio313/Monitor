import {
  NETWORK_DROP_RATE_THRESHOLDS,
  NETWORK_ERROR_RATE_THRESHOLDS,
  PSI_THRESHOLDS,
} from './operational-thresholds';
import { unresolvedIncidents } from './incident-read-model';
import { operationalServiceState } from './operational-health';
import type { OperationalFindingId, OperationalFindingLevel, OperationalFindingScope } from './operational-health';
import type { DashboardPayload, MonitorDetailPage } from './types';

export type SystemMood = 'dormant' | 'serene' | 'watchful' | 'strained' | 'critical';

export type SystemEmotionAxisKey =
  | 'compute'
  | 'memory'
  | 'thermal'
  | 'network'
  | 'storage'
  | 'services'
  | 'reliability';

export interface SystemEmotionAxis {
  key: SystemEmotionAxisKey;
  intensity: number;
  observed: boolean;
}

export interface SystemEmotionPalette {
  background: string;
  primary: string;
  secondary: string;
  accent: string;
  warning: string;
}

export interface SystemEmotionModel {
  mood: SystemMood;
  score: number;
  energy: number;
  turbulence: number;
  coherence: number;
  volatility: number;
  waveAmplitude: number;
  tempoSeconds: number;
  particleCount: number;
  dominantAxis: SystemEmotionAxisKey | null;
  dominantPage: MonitorDetailPage | null;
  axes: SystemEmotionAxis[];
  palette: SystemEmotionPalette;
}

export interface SystemEmotionInput {
  data: DashboardPayload | null;
  stale: boolean;
  dangerCount: number;
  cautionCount: number;
  primaryFinding?: {
    id: OperationalFindingId;
    level: OperationalFindingLevel;
    scope: OperationalFindingScope;
    page: MonitorDetailPage;
  } | null;
}

const PALETTES: Record<SystemMood, SystemEmotionPalette> = {
  dormant: {
    background: '#081116',
    primary: '#7896a3',
    secondary: '#a28a68',
    accent: '#c8d5d8',
    warning: '#d9aa6f',
  },
  serene: {
    background: '#061713',
    primary: '#62efc3',
    secondary: '#4bb8ff',
    accent: '#d0fff4',
    warning: '#f6cf76',
  },
  watchful: {
    background: '#12160e',
    primary: '#f3cc72',
    secondary: '#5fc9bd',
    accent: '#fff0bd',
    warning: '#ffad66',
  },
  strained: {
    background: '#19100d',
    primary: '#ff9b61',
    secondary: '#c779ff',
    accent: '#ffe0c2',
    warning: '#ff725f',
  },
  critical: {
    background: '#1b090e',
    primary: '#ff5472',
    secondary: '#ff9a54',
    accent: '#ffd6dc',
    warning: '#ff385f',
  },
};

const AXIS_PAGE: Record<SystemEmotionAxisKey, MonitorDetailPage> = {
  compute: 'resources',
  memory: 'resources',
  thermal: 'power',
  network: 'network',
  storage: 'storage',
  services: 'containers',
  reliability: 'reliability',
};

const PAGE_AXIS: Record<MonitorDetailPage, SystemEmotionAxisKey> = {
  resources: 'compute',
  network: 'network',
  storage: 'storage',
  containers: 'services',
  reliability: 'reliability',
  maintenance: 'reliability',
  infrastructure: 'reliability',
  power: 'thermal',
  incidents: 'reliability',
  logs: 'reliability',
};

const FINDING_AXIS: Partial<Record<OperationalFindingId, SystemEmotionAxisKey>> = {
  'collection-stale': 'reliability',
  'collection-gap': 'reliability',
  'service-fault': 'services',
  'storage-capacity': 'storage',
  'power-quality': 'thermal',
  connectivity: 'reliability',
  'network-quality': 'network',
  'application-traffic': 'network',
  'kernel-crash': 'reliability',
  'kernel-stall': 'reliability',
  'rcu-expedited': 'reliability',
  'kernel-warning': 'reliability',
  'memory-oom': 'memory',
  'storage-integrity': 'storage',
  'pcie-integrity': 'reliability',
  'nvme-mitigation': 'reliability',
  'reboot-required': 'reliability',
};

function clamp(value: number, minimum = 0, maximum = 1): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}

function finite(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function ramp(value: number | null | undefined, quiet: number, severe: number): number | null {
  if (!finite(value)) return null;
  if (severe <= quiet) return value >= severe ? 1 : 0;
  return clamp((value - quiet) / (severe - quiet));
}

function combine(...values: Array<number | null>): { intensity: number; observed: boolean } {
  const observed = values.filter((value): value is number => value !== null);
  return {
    intensity: observed.length ? Math.max(...observed.map((value) => clamp(value))) : 0,
    observed: observed.length > 0,
  };
}

function maximumRamp<T>(items: T[], value: (item: T) => number | null | undefined, quiet: number, severe: number): number | null {
  const observed = items
    .map((item) => ramp(value(item), quiet, severe))
    .filter((item): item is number => item !== null);
  return observed.length ? Math.max(...observed) : null;
}

function serviceRisk(data: DashboardPayload): number | null {
  if (!data.containers.length) return null;
  let danger = 0;
  let caution = 0;
  for (const container of data.containers) {
    const state = operationalServiceState(container);
    if (state === 'danger') danger += 1;
    else if (state === 'caution') caution += 1;
  }
  return clamp((danger + caution * 0.45) / Math.max(1, data.containers.length));
}

function networkRisk(data: DashboardPayload): number | null {
  const errorValues = [
    data.latest?.networkRxErrorsPerSecond,
    data.latest?.networkTxErrorsPerSecond,
  ];
  const dropValues = [
    data.latest?.networkRxDroppedPerSecond,
    data.latest?.networkTxDroppedPerSecond,
  ];
  const errorObserved = errorValues.some(finite);
  const dropObserved = dropValues.some(finite);
  const errorRate = errorValues.reduce((total: number, value) => total + (finite(value) ? value : 0), 0);
  const dropRate = dropValues.reduce((total: number, value) => total + (finite(value) ? value : 0), 0);
  const faultRisk = errorObserved || dropObserved
    ? Math.max(
      errorObserved ? ramp(errorRate, 0, NETWORK_ERROR_RATE_THRESHOLDS.danger) ?? 0 : 0,
      dropObserved ? ramp(dropRate, 0, NETWORK_DROP_RATE_THRESHOLDS.danger) ?? 0 : 0,
    )
    : null;
  if (!data.currentTraffic.length) return faultRisk;
  const requests = data.currentTraffic.reduce((total, traffic) => total + traffic.requestCount, 0);
  if (requests <= 0) return combine(faultRisk, 0).intensity;
  const serverErrors = data.currentTraffic.reduce((total, traffic) => total + traffic.status5xx, 0);
  const slow = data.currentTraffic.reduce((total, traffic) => total + traffic.slowCount, 0);
  const maximumResponseMs = data.currentTraffic.reduce((maximum, traffic) => Math.max(maximum, traffic.maxResponseMs ?? 0), 0);
  return Math.max(
    faultRisk ?? 0,
    ramp((serverErrors / requests) * 100, 0.5, 10) ?? 0,
    ramp((slow / requests) * 100, 5, 40) ?? 0,
    ramp(maximumResponseMs, 1_000, 10_000) ?? 0,
  );
}

function findingIntensity(level: OperationalFindingLevel, scope: OperationalFindingScope): number {
  if (level === 'danger') {
    return scope === 'current' ? 0.96 : scope === 'last-known' ? 0.9 : scope === 'boot' ? 0.84 : 0.76;
  }
  return scope === 'current' ? 0.46 : scope === 'last-known' ? 0.42 : scope === 'boot' ? 0.36 : 0.3;
}

function axisForFinding(
  finding: NonNullable<SystemEmotionInput['primaryFinding']>,
  axes: SystemEmotionAxis[],
): SystemEmotionAxisKey {
  const fixed = FINDING_AXIS[finding.id];
  if (fixed) return fixed;
  if (finding.id === 'resource-pressure') {
    const pressureAxes = axes
      .filter((axis) => axis.key === 'compute' || axis.key === 'memory' || axis.key === 'thermal' || axis.key === 'storage')
      .sort((left, right) => right.intensity - left.intensity);
    if ((pressureAxes[0]?.intensity ?? 0) > 0) return pressureAxes[0].key;
  }
  return PAGE_AXIS[finding.page];
}

function reliabilityRisk(data: DashboardPayload, stale: boolean): number {
  const states = [data.reliability.networkLinkAvailable, data.reliability.sshListenersAvailable];
  const unavailable = states.filter((value) => value === false).length;
  const unknown = states.filter((value) => value === null).length;
  const gap = ramp(data.reliability.collectorGapSeconds, 90, 300) ?? 0;
  const mitigation = data.reliability.nvmeMitigationActive === false
    ? 0.72
    : data.reliability.nvmeMitigationActive === null ? 0.24 : 0;
  return Math.max(stale ? 1 : 0, unavailable ? 0.9 : 0, unknown * 0.22, gap, mitigation);
}

function trafficEnergy(data: DashboardPayload): number {
  const latest = data.latest;
  const network = (latest?.networkRxBytesPerSecond ?? 0) + (latest?.networkTxBytesPerSecond ?? 0);
  const disk = (latest?.diskReadBytesPerSecond ?? 0) + (latest?.diskWriteBytesPerSecond ?? 0);
  const networkEnergy = network > 0 ? clamp(Math.log10(network + 1) / 9) : 0;
  const diskEnergy = disk > 0 ? clamp(Math.log10(disk + 1) / 9) : 0;
  const requests = data.currentTraffic.reduce((total, traffic) => total + traffic.requestCount, 0);
  const requestEnergy = requests > 0 ? clamp(Math.log10(requests + 1) / 4) : 0;
  return clamp(networkEnergy * 0.45 + diskEnergy * 0.35 + requestEnergy * 0.2);
}

function signalVolatility(data: DashboardPayload): number {
  const samples = data.series.slice(-120);
  if (samples.length < 2) return 0;
  let movement = 0;
  let comparisons = 0;
  const add = (left: number | null | undefined, right: number | null | undefined, scale: number) => {
    if (!finite(left) || !finite(right) || scale <= 0) return;
    movement += Math.min(1, Math.abs(right - left) / scale);
    comparisons += 1;
  };
  for (let index = 1; index < samples.length; index += 1) {
    const previous = samples[index - 1];
    const current = samples[index];
    add(previous.cpuPercent, current.cpuPercent, 35);
    add(previous.memoryPercent, current.memoryPercent, 24);
    add(previous.temperatureC, current.temperatureC, 12);
    add(previous.load1, current.load1, 2);
    add(previous.cpuPressureSomeAvg10, current.cpuPressureSomeAvg10, 12);
    add(previous.ioPressureSomeAvg10, current.ioPressureSomeAvg10, 12);
  }
  return comparisons ? clamp((movement / comparisons) * 2.4) : 0;
}

export function deriveSystemEmotion({
  data,
  stale,
  dangerCount,
  cautionCount,
  primaryFinding = null,
}: SystemEmotionInput): SystemEmotionModel {
  if (!data) {
    const axes = (['compute', 'memory', 'thermal', 'network', 'storage', 'services', 'reliability'] as const)
      .map((key) => ({ key, intensity: key === 'reliability' ? 0.42 : 0, observed: false }));
    return {
      mood: 'dormant',
      score: 0,
      energy: 0.12,
      turbulence: 0.16,
      coherence: 0.24,
      volatility: 0,
      waveAmplitude: 0.14,
      tempoSeconds: 8.4,
      particleCount: 14,
      dominantAxis: 'reliability',
      dominantPage: 'reliability',
      axes,
      palette: PALETTES.dormant,
    };
  }

  const latest = data.latest;
  const logicalCpuCount = finite(data.host.logicalCpuCount) && data.host.logicalCpuCount > 0
    ? data.host.logicalCpuCount
    : null;
  const normalizedLoad = finite(latest?.load1)
    ? logicalCpuCount ? latest.load1 / logicalCpuCount : null
    : null;
  const compute = combine(
    ramp(latest?.cpuPercent, 55, 96),
    ramp(normalizedLoad, 0.7, 1.8),
    ramp(latest?.cpuPressureSomeAvg10, PSI_THRESHOLDS.cpuSome.caution, PSI_THRESHOLDS.cpuSome.danger),
    ramp(latest?.cpuPressureFullAvg10, PSI_THRESHOLDS.cpuFull.caution, PSI_THRESHOLDS.cpuFull.danger),
  );
  const memoryPressureActive = (latest?.memoryPercent ?? 0) >= 75
    || (latest?.memoryPressureSomeAvg10 ?? 0) >= PSI_THRESHOLDS.memorySome.caution
    || (latest?.memoryPressureFullAvg10 ?? 0) >= PSI_THRESHOLDS.memoryFull.caution;
  const memory = combine(
    ramp(latest?.memoryPercent, 65, 96),
    memoryPressureActive ? ramp(latest?.swapPercent, 10, 75) : null,
    ramp(latest?.memoryPressureSomeAvg10, PSI_THRESHOLDS.memorySome.caution, PSI_THRESHOLDS.memorySome.danger),
    ramp(latest?.memoryPressureFullAvg10, PSI_THRESHOLDS.memoryFull.caution, PSI_THRESHOLDS.memoryFull.danger),
  );
  const thermal = combine(
    ramp(latest?.temperatureC, 60, 88),
    finite(latest?.throttledFlags) ? ((latest.throttledFlags & 0xf) !== 0 ? 1 : 0) : null,
    finite(latest?.supplyVoltageVolts) ? ramp(4.85 - latest.supplyVoltageVolts, 0, 0.3) : null,
  );
  const storage = combine(
    maximumRamp(data.disks, (disk) => disk.usedPercent, 70, 97),
    data.disks.some((disk) => disk.readOnly === true)
      ? 1
      : data.disks.length > 0 && data.disks.every((disk) => disk.readOnly === false) ? 0 : null,
    maximumRamp(data.disks, (disk) => disk.inodeUsedPercent, 70, 97),
    ramp(latest?.ioPressureSomeAvg10, PSI_THRESHOLDS.ioSome.caution, PSI_THRESHOLDS.ioSome.danger),
    ramp(latest?.ioPressureFullAvg10, PSI_THRESHOLDS.ioFull.caution, PSI_THRESHOLDS.ioFull.danger),
  );
  const network = combine(networkRisk(data));
  const services = combine(serviceRisk(data));
  const reliability = combine(reliabilityRisk(data, stale));
  let axes: SystemEmotionAxis[] = [
    { key: 'compute', ...compute },
    { key: 'memory', ...memory },
    { key: 'thermal', ...thermal },
    { key: 'network', ...network },
    { key: 'storage', ...storage },
    { key: 'services', ...services },
    { key: 'reliability', ...reliability },
  ];
  const primaryFindingIntensity = primaryFinding
    ? findingIntensity(primaryFinding.level, primaryFinding.scope)
    : 0;
  const primaryFindingAxis = primaryFinding ? axisForFinding(primaryFinding, axes) : null;
  if (primaryFindingAxis) {
    axes = axes.map((axis) => axis.key === primaryFindingAxis
      ? { ...axis, intensity: Math.max(axis.intensity, primaryFindingIntensity), observed: true }
      : axis);
  }
  const sortedAxes = [...axes].sort((left, right) => {
    if (left.intensity !== right.intensity) return right.intensity - left.intensity;
    return Number(right.observed) - Number(left.observed);
  });
  const maximumRisk = sortedAxes[0]?.intensity ?? 0;
  const dominantAxis = maximumRisk > 0 ? sortedAxes[0]?.key ?? null : null;
  const averageRisk = axes.reduce((total, axis) => total + axis.intensity, 0) / axes.length;
  const findingRisk = Math.max(
    primaryFindingIntensity,
    dangerCount > 0 ? 0.84 : cautionCount >= 3 ? 0.55 : cautionCount > 0 ? 0.3 : 0,
  );
  const activeIncidents = unresolvedIncidents(data.incidents).length;
  const incidentRisk = clamp(activeIncidents * 0.36);
  const risk = Math.max(
    findingRisk,
    clamp(maximumRisk * 0.58 + averageRisk * 0.2 + findingRisk * 0.17 + incidentRisk * 0.18),
  );
  const observedAxes = axes.filter((axis) => axis.observed).length;
  const observationRatio = observedAxes / axes.length;
  const volatility = signalVolatility(data);
  const energy = clamp(0.16 + trafficEnergy(data) * 0.4 + volatility * 0.24 + risk * 0.46);
  const turbulence = clamp(risk * 0.78 + incidentRisk * 0.34 + volatility * 0.32 + (stale ? 0.12 : 0));
  const coherence = clamp(observationRatio * 0.3 + (1 - risk) * 0.7 - volatility * 0.18 - (stale ? 0.45 : 0));
  const score = Math.round(clamp((1 - risk) * (0.72 + observationRatio * 0.28) - (stale ? 0.35 : 0)) * 100);

  let mood: SystemMood;
  if (stale) mood = 'dormant';
  else if (dangerCount > 0 || maximumRisk >= 0.92 || risk >= 0.78) mood = 'critical';
  else if (risk >= 0.53 || cautionCount >= 3) mood = 'strained';
  else if (risk >= 0.22 || cautionCount > 0 || observationRatio < 0.67) mood = 'watchful';
  else mood = 'serene';

  return {
    mood,
    score,
    energy,
    turbulence,
    coherence,
    volatility,
    waveAmplitude: clamp(0.14 + energy * 0.28 + turbulence * 0.5),
    tempoSeconds: 8.2 - energy * 3.1 - turbulence * 2.2,
    particleCount: Math.round(16 + energy * 24 + turbulence * 18),
    dominantAxis,
    dominantPage: primaryFinding && dominantAxis === primaryFindingAxis
      ? primaryFinding.page
      : dominantAxis ? AXIS_PAGE[dominantAxis] : null,
    axes,
    palette: PALETTES[mood],
  };
}

export function systemEmotionPalette(mood: SystemMood): SystemEmotionPalette {
  return PALETTES[mood];
}
