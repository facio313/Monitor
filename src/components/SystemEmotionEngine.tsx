import { useEffect, useRef, type CSSProperties } from 'react';
import type { SystemEmotionAxisKey, SystemEmotionModel, SystemMood } from '../system-emotion';
import type { DashboardPayload, MonitorLocale, MonitorPage } from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';

interface SystemEmotionEngineProps {
  data: DashboardPayload | null;
  locale: MonitorLocale;
  model: SystemEmotionModel;
  onNavigate: (page: MonitorPage) => void;
  paused?: boolean;
}

interface PointerWake {
  x: number;
  y: number;
  bornAt: number;
}

type PointerField = {
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  active: boolean;
  wakes: PointerWake[];
};

export type ParticleTone = 0 | 1 | 2 | 3;

export interface GranularWaveSeed {
  axisIndex: number;
  stratum: number;
  baseU: number;
  phase: number;
  thickness: number;
  radius: number;
  flutter: number;
  direction: -1 | 1;
  occupancy: number;
  glow: boolean;
  tone: ParticleTone;
  lightTier: 0 | 1 | 2;
}

interface SprayGrainSeed {
  wave: GranularWaveSeed;
  cycle: number;
  lift: number;
  spread: number;
}

interface NucleusGrainSeed {
  angle: number;
  distance: number;
  speed: number;
  radius: number;
  elliptic: number;
  direction: -1 | 1;
  tone: ParticleTone;
  glow: boolean;
}

export interface GranularWavePlan {
  compact: boolean;
  strataPerAxis: number;
  strandCount: number;
  columnCount: number;
  waveParticleCount: number;
  waveBuckets: GranularWaveSeed[][];
  sprayBuckets: SprayGrainSeed[][];
  nucleusBuckets: NucleusGrainSeed[][];
}

const AXIS_LABELS: Record<SystemEmotionAxisKey, readonly [string, string]> = {
  compute: ['연산', 'Compute'],
  memory: ['메모리', 'Memory'],
  thermal: ['열·전원', 'Thermal'],
  network: ['네트워크', 'Network'],
  storage: ['저장', 'Storage'],
  services: ['서비스', 'Services'],
  reliability: ['신뢰성', 'Reliability'],
};

const MOOD_COPY: Record<SystemMood, {
  code: string;
  title: readonly [string, string];
  summary: readonly [string, string];
}> = {
  dormant: {
    code: 'SIGNAL / LOW',
    title: ['신호를 기다리는 중', 'Listening for signal'],
    summary: ['관측 흐름이 끊겼거나 아직 첫 표본이 없습니다. 고요함을 정상으로 해석하지 않습니다.', 'The observation stream is delayed or has not started. Silence is not treated as health.'],
  },
  serene: {
    code: 'STATE / SERENE',
    title: ['고요한 정상 상태', 'Systems in quiet balance'],
    summary: ['주요 계통이 서로 어긋나지 않고 낮은 진폭으로 흐르고 있습니다.', 'Primary systems are moving together with low amplitude and little friction.'],
  },
  watchful: {
    code: 'STATE / WATCHFUL',
    title: ['잔잔한 긴장', 'Quietly watchful'],
    summary: ['즉시 장애는 아니지만 한 계통의 파형이 평상시보다 선명해졌습니다.', 'No immediate failure is evident, but one subsystem is speaking more loudly than usual.'],
  },
  strained: {
    code: 'STATE / STRAINED',
    title: ['흐름이 거칠어지는 중', 'Rising turbulence'],
    summary: ['여러 신호가 겹치며 균형이 흐트러지고 있습니다. 지배 계통을 먼저 확인하세요.', 'Several signals are converging and balance is falling. Inspect the dominant subsystem first.'],
  },
  critical: {
    code: 'STATE / CRITICAL',
    title: ['즉시 확인할 파동', 'Critical disturbance'],
    summary: ['위험 신호가 전체 흐름을 바꾸고 있습니다. 시각 효과보다 연결된 운영 근거를 우선하세요.', 'A danger signal is reshaping the whole field. Follow the linked operational evidence now.'],
  },
};

function t(locale: MonitorLocale, pair: readonly [string, string]): string {
  return locale === 'ko' ? pair[0] : pair[1];
}

function clamp(value: number, minimum = 0, maximum = 1): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function rgb(hex: string): [number, number, number] {
  const value = hex.replace('#', '');
  if (!/^[0-9a-f]{6}$/i.test(value)) return [255, 255, 255];
  return [
    Number.parseInt(value.slice(0, 2), 16),
    Number.parseInt(value.slice(2, 4), 16),
    Number.parseInt(value.slice(4, 6), 16),
  ];
}

function rgba(hex: string, alpha: number): string {
  const [red, green, blue] = rgb(hex);
  return `rgba(${red}, ${green}, ${blue}, ${clamp(alpha)})`;
}

function seeded(index: number, salt: number): number {
  const value = Math.sin(index * 91.733 + salt * 47.117) * 43758.5453;
  return value - Math.floor(value);
}

const TAU = Math.PI * 2;
const PARTICLE_TONE_COUNT = 4;
const PARTICLE_LIGHT_TIERS = 3;

function wrap(value: number): number {
  return ((value % 1) + 1) % 1;
}

function lerp(start: number, end: number, amount: number): number {
  return start + (end - start) * amount;
}

function toneColor(model: SystemEmotionModel, tone: ParticleTone): string {
  if (tone === 1) return model.palette.secondary;
  if (tone === 2) return model.palette.accent;
  if (tone === 3) return model.palette.warning;
  return model.palette.primary;
}

export function createGranularWavePlan(
  width: number,
  height: number,
  model: SystemEmotionModel,
  coarsePointer = false,
): GranularWavePlan {
  const safeWidth = Number.isFinite(width) ? Math.max(1, width) : 1;
  const safeHeight = Number.isFinite(height) ? Math.max(1, height) : 1;
  const compact = safeWidth <= 640;
  const strataPerAxis = 2;
  const strandCount = model.axes.length * strataPerAxis;
  const stateDensity = 0.8
    + model.energy * 0.1
    + model.turbulence * 0.08
    + clamp((model.particleCount - 14) / 50) * 0.05;
  const desktopFloor = 840 + clamp((safeWidth - 640) / 500) * 360;
  const baseMinimum = compact ? 560 : coarsePointer ? 720 : desktopFloor;
  const minimum = Math.round(baseMinimum * (0.88 + model.energy * 0.06 + model.turbulence * 0.08));
  const maximum = compact ? 840 : coarsePointer ? 900 : 1_280;
  const target = Math.round(clamp((safeWidth * safeHeight / 400) * stateDensity, minimum, maximum));
  const columnCount = Math.max(1, Math.ceil(target / Math.max(1, strandCount)));
  const waveBuckets = Array.from(
    { length: PARTICLE_TONE_COUNT * PARTICLE_LIGHT_TIERS },
    () => [] as GranularWaveSeed[],
  );

  for (let axisIndex = 0; axisIndex < model.axes.length; axisIndex += 1) {
    const axis = model.axes[axisIndex];
    for (let stratum = 0; stratum < strataPerAxis; stratum += 1) {
      const strandIndex = axisIndex * strataPerAxis + stratum;
      const depth = strandCount > 1 ? strandIndex / (strandCount - 1) : 0.5;
      for (let column = 0; column < columnCount; column += 1) {
        const index = strandIndex * columnCount + column;
        const toneSeed = seeded(index, 8);
        const dominantHighlight = axis.key === model.dominantAxis && toneSeed < 0.34;
        const strandTone: ParticleTone = (axisIndex + stratum) % 2 === 0 ? 0 : 1;
        const tone: ParticleTone = dominantHighlight
          ? 3
          : toneSeed < 0.075 ? 2 : strandTone;
        const tierSeed = depth * 0.72 + seeded(index, 9) * 0.28;
        const lightTier: 0 | 1 | 2 = tierSeed > 0.72 ? 2 : tierSeed > 0.34 ? 1 : 0;
        const grain: GranularWaveSeed = {
          axisIndex,
          stratum,
          baseU: (column + seeded(index, 1) * 0.78) / columnCount,
          phase: seeded(index, 2) * TAU,
          thickness: seeded(index, 3) * 2 - 1,
          radius: (0.5 + depth * 1.02 + seeded(index, 4) * 0.54 + model.energy * 0.16)
            * (compact ? 0.92 : 1),
          flutter: seeded(index, 5) * TAU,
          direction: (axisIndex + stratum) % 2 === 0 ? 1 : -1,
          occupancy: seeded(index, 6),
          glow: seeded(index, 7) < 0.055 + model.turbulence * 0.04,
          tone,
          lightTier,
        };
        waveBuckets[tone * PARTICLE_LIGHT_TIERS + lightTier].push(grain);
      }
    }
  }

  const waveParticleCount = strandCount * columnCount;
  const sprayBuckets = Array.from({ length: PARTICLE_TONE_COUNT }, () => [] as SprayGrainSeed[]);
  const sprayCount = Math.round(waveParticleCount * (0.018 + model.turbulence * 0.052));
  for (let index = 0; index < sprayCount; index += 1) {
    const axisIndex = Math.min(model.axes.length - 1, Math.floor(seeded(index, 21) * model.axes.length));
    const stratum = Math.min(strataPerAxis - 1, Math.floor(seeded(index, 22) * strataPerAxis));
    const tone: ParticleTone = model.axes[axisIndex]?.key === model.dominantAxis && seeded(index, 23) < 0.4
      ? 3
      : seeded(index, 24) < 0.32 ? 2 : seeded(index, 25) < 0.5 ? 0 : 1;
    const wave: GranularWaveSeed = {
      axisIndex,
      stratum,
      baseU: wrap(0.69 + (seeded(index, 26) - 0.5) * 0.58),
      phase: seeded(index, 27) * TAU,
      thickness: seeded(index, 28) * 2 - 1,
      radius: 0.55 + seeded(index, 29) * 1.2 + model.turbulence * 0.35,
      flutter: seeded(index, 30) * TAU,
      direction: index % 2 === 0 ? 1 : -1,
      occupancy: seeded(index, 31),
      glow: seeded(index, 32) < 0.16,
      tone,
      lightTier: 2,
    };
    sprayBuckets[tone].push({
      wave,
      cycle: seeded(index, 33),
      lift: 0.55 + seeded(index, 34) * 0.9,
      spread: 0.55 + seeded(index, 35) * 0.8,
    });
  }

  const nucleusBuckets = Array.from({ length: PARTICLE_TONE_COUNT }, () => [] as NucleusGrainSeed[]);
  const nucleusCount = Math.round(78 + model.particleCount * 1.75);
  for (let index = 0; index < nucleusCount; index += 1) {
    const tone: ParticleTone = seeded(index, 41) < 0.24
      ? 2 : seeded(index, 42) < 0.12 + model.turbulence * 0.15 ? 3 : index % 3 === 0 ? 1 : 0;
    nucleusBuckets[tone].push({
      angle: seeded(index, 43) * TAU,
      distance: Math.pow(seeded(index, 44), 1.72),
      speed: 0.16 + seeded(index, 45) * 0.5,
      radius: 0.5 + seeded(index, 46) * 1.35 + model.energy * 0.32,
      elliptic: 0.42 + seeded(index, 47) * 0.25,
      direction: index % 2 === 0 ? 1 : -1,
      tone,
      glow: seeded(index, 48) < 0.1,
    });
  }

  return {
    compact,
    strataPerAxis,
    strandCount,
    columnCount,
    waveParticleCount,
    waveBuckets,
    sprayBuckets,
    nucleusBuckets,
  };
}

interface EmotionGeometry {
  width: number;
  height: number;
  compact: boolean;
  horizon: number;
  foreground: number;
  waveStart: number;
  waveEnd: number;
  fieldX: number;
  fieldY: number;
  coreRadius: number;
}

interface WavePoint {
  x: number;
  y: number;
  crest: number;
  depth: number;
}

function emotionGeometry(width: number, height: number, model: SystemEmotionModel): EmotionGeometry {
  const compact = width <= 640;
  const horizon = compact
    ? clamp(height * 0.12, 74, 96)
    : clamp(height * 0.2, 94, 124);
  const foreground = compact
    ? Math.min(height * 0.34, horizon + 138)
    : Math.min(height * 0.56, horizon + 178);
  const fieldX = width * (compact ? 0.6 : 0.7);
  const fieldY = lerp(horizon, foreground, compact ? 0.43 : 0.47);
  return {
    width,
    height,
    compact,
    horizon,
    foreground,
    waveStart: width * (compact ? -0.12 : 0.27),
    waveEnd: width * 1.08,
    fieldX,
    fieldY,
    coreRadius: Math.min(width, height) * (compact ? 0.105 : 0.077) * (0.92 + model.energy * 0.16),
  };
}

function sampleWavePoint(
  grain: GranularWaveSeed,
  plan: GranularWavePlan,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  pointer: PointerField,
  reducedMotion: boolean,
): WavePoint {
  const strandIndex = grain.axisIndex * plan.strataPerAxis + grain.stratum;
  const depth = plan.strandCount > 1 ? strandIndex / (plan.strandCount - 1) : 0.5;
  const axis = model.axes[grain.axisIndex];
  const axisIntensity = clamp(axis?.intensity ?? 0);
  const flow = reducedMotion ? 0 : time * (0.012 + model.energy * 0.015) * grain.direction;
  const u = wrap(grain.baseU + flow);
  const waveWidth = geometry.waveEnd - geometry.waveStart;
  let x = geometry.waveStart + u * waveWidth;
  const strandPhase = grain.axisIndex * 0.008 + grain.stratum * 0.018;
  const phaseJitter = (grain.phase - Math.PI) * (
    0.003
    + model.turbulence * 0.006
    + (1 - model.coherence) * 0.003
  );
  const alignedPhase = strandPhase + phaseJitter;
  const speed = reducedMotion ? 0 : time * (0.34 + model.energy * 0.46);
  const primaryAngle = u * TAU * 1.28 + speed + alignedPhase;
  const primary = Math.sin(primaryAngle) + Math.sin(primaryAngle * 2 - 0.58) * 0.18;
  const interference = Math.sin(
    u * TAU * (3.28 + grain.axisIndex * 0.025)
    - speed * 0.73
    + grain.axisIndex * 0.52
    + grain.stratum * 0.21,
  );
  const fine = Math.cos(u * TAU * 8.4 + speed * 0.42 + grain.flutter) * model.volatility;
  const crestEnvelope = 0.72 + Math.exp(-Math.pow((u - 0.62) / 0.2, 2)) * 0.5;
  const amplitude = (geometry.compact ? 11 : 13)
    + model.waveAmplitude * (geometry.compact ? 21 : 28)
    + axisIntensity * 6;
  const baseY = lerp(geometry.horizon, geometry.foreground, depth);
  const thickness = grain.thickness * (
    0.55
    + depth
    + model.turbulence * 1.35
    + (1 - model.coherence) * 0.75
  );
  let y = baseY
    + primary * amplitude * crestEnvelope * (0.84 + depth * 0.16)
    + interference * amplitude * model.turbulence * 0.075
    + fine * amplitude * 0.2
    + thickness;

  if (pointer.active && !reducedMotion) {
    const pointerX = pointer.x * geometry.width;
    const pointerY = pointer.y * geometry.height;
    const deltaX = x - pointerX;
    const deltaY = y - pointerY;
    const influenceRadius = geometry.compact ? 54 : 82;
    const distance = Math.hypot(deltaX, deltaY);
    if (distance > 0 && distance < influenceRadius) {
      const force = Math.pow(1 - distance / influenceRadius, 2) * (10 + model.energy * 13);
      x += (deltaX / distance) * force;
      y += (deltaY / distance) * force;
    }
  }

  return { x, y, crest: primary, depth };
}

function drawParticleWave(
  context: CanvasRenderingContext2D,
  plan: GranularWavePlan,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  pointer: PointerField,
  reducedMotion: boolean,
) {
  context.save();
  context.globalCompositeOperation = 'screen';
  for (let bucketIndex = 0; bucketIndex < plan.waveBuckets.length; bucketIndex += 1) {
    const bucket = plan.waveBuckets[bucketIndex];
    if (!bucket.length) continue;
    const tone = Math.floor(bucketIndex / PARTICLE_LIGHT_TIERS) as ParticleTone;
    const lightTier = bucketIndex % PARTICLE_LIGHT_TIERS;
    const glowPath = new Path2D();
    const particlePath = new Path2D();
    for (const grain of bucket) {
      const point = sampleWavePoint(grain, plan, time, model, geometry, pointer, reducedMotion);
      const perspective = 0.76 + point.depth * 0.46;
      const pulse = reducedMotion ? 1 : 0.92 + Math.sin(time * 0.72 + grain.flutter) * 0.08;
      const radius = Math.max(0.42, grain.radius * perspective * pulse * (0.84 + grain.occupancy * 0.24));
      particlePath.moveTo(point.x + radius, point.y);
      particlePath.arc(point.x, point.y, radius, 0, TAU);
      if (grain.glow) {
        const glowRadius = radius * (2.8 + model.energy * 0.7);
        glowPath.moveTo(point.x + glowRadius, point.y);
        glowPath.arc(point.x, point.y, glowRadius, 0, TAU);
      }
    }
    const color = toneColor(model, tone);
    context.fillStyle = rgba(color, 0.025 + lightTier * 0.018 + model.energy * 0.018);
    context.fill(glowPath);
    context.fillStyle = rgba(color, 0.2 + lightTier * 0.14 + model.energy * 0.08 + model.turbulence * 0.035);
    context.fill(particlePath);
  }

  for (let tone = 0; tone < plan.sprayBuckets.length; tone += 1) {
    const bucket = plan.sprayBuckets[tone];
    if (!bucket.length) continue;
    const path = new Path2D();
    for (const spray of bucket) {
      const point = sampleWavePoint(spray.wave, plan, time, model, geometry, pointer, reducedMotion);
      const cycle = wrap(spray.cycle + (reducedMotion ? 0.32 : time * (0.055 + model.turbulence * 0.085)));
      const lift = Math.sin(cycle * Math.PI) * (18 + model.turbulence * 47) * spray.lift;
      const drift = (cycle - 0.5) * (20 + model.turbulence * 38) * spray.spread;
      const radius = spray.wave.radius * (0.55 + (1 - cycle) * 0.6);
      const x = point.x + drift * spray.wave.direction;
      const y = point.y - lift - Math.abs(point.crest) * model.turbulence * 8;
      path.moveTo(x + radius, y);
      path.arc(x, y, radius, 0, TAU);
    }
    context.fillStyle = rgba(toneColor(model, tone as ParticleTone), 0.19 + model.turbulence * 0.35);
    context.fill(path);
  }
  context.restore();
}

function drawParticleNucleus(
  context: CanvasRenderingContext2D,
  plan: GranularWavePlan,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  reducedMotion: boolean,
) {
  const breath = reducedMotion ? 0.5 : (Math.sin((time / model.tempoSeconds) * TAU) + 1) / 2;
  context.save();
  context.translate(geometry.fieldX, geometry.fieldY);
  context.globalCompositeOperation = 'screen';
  for (let tone = 0; tone < plan.nucleusBuckets.length; tone += 1) {
    const bucket = plan.nucleusBuckets[tone];
    if (!bucket.length) continue;
    const glowPath = new Path2D();
    const pointPath = new Path2D();
    for (const grain of bucket) {
      const rotation = reducedMotion ? 0 : time * grain.speed * grain.direction;
      const angle = grain.angle + rotation;
      const distance = geometry.coreRadius * grain.distance * (1.12 + breath * 0.1);
      const x = Math.cos(angle) * distance;
      const y = Math.sin(angle) * distance * grain.elliptic;
      const radius = grain.radius * (0.86 + breath * 0.2);
      pointPath.moveTo(x + radius, y);
      pointPath.arc(x, y, radius, 0, TAU);
      if (grain.glow) {
        const glowRadius = radius * 3.2;
        glowPath.moveTo(x + glowRadius, y);
        glowPath.arc(x, y, glowRadius, 0, TAU);
      }
    }
    const color = toneColor(model, tone as ParticleTone);
    context.fillStyle = rgba(color, 0.075 + model.energy * 0.04);
    context.fill(glowPath);
    context.fillStyle = rgba(color, tone === 2 ? 0.72 : 0.38 + model.energy * 0.22);
    context.fill(pointPath);
  }
  context.restore();
}

function addDottedEllipse(
  path: Path2D,
  centerX: number,
  centerY: number,
  radiusX: number,
  radiusY: number,
  rotation: number,
  count: number,
  offset: number,
  dotRadius: number,
) {
  const cosine = Math.cos(rotation);
  const sine = Math.sin(rotation);
  for (let index = 0; index < count; index += 1) {
    if ((index + Math.floor(offset * count)) % 5 === 0) continue;
    const angle = (index / count + offset) * TAU;
    const ellipseX = Math.cos(angle) * radiusX;
    const ellipseY = Math.sin(angle) * radiusY;
    const x = centerX + ellipseX * cosine - ellipseY * sine;
    const y = centerY + ellipseX * sine + ellipseY * cosine;
    path.moveTo(x + dotRadius, y);
    path.arc(x, y, dotRadius, 0, TAU);
  }
}

function drawDottedDisturbances(
  context: CanvasRenderingContext2D,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  pointer: PointerField,
  reducedMotion: boolean,
) {
  context.save();
  context.globalCompositeOperation = 'screen';
  const disturbanceCount = 2 + Math.round(model.turbulence * 3);
  for (let ring = 0; ring < disturbanceCount; ring += 1) {
    const phase = wrap((reducedMotion ? 0.28 : time * (0.065 + model.turbulence * 0.07)) + ring / disturbanceCount);
    const radius = geometry.coreRadius * (1.25 + phase * 5.2);
    const path = new Path2D();
    addDottedEllipse(
      path,
      geometry.fieldX,
      geometry.fieldY,
      radius,
      radius * 0.52,
      -0.08,
      Math.round(30 + radius * 0.18),
      phase * 0.08,
      0.48 + (1 - phase) * 0.44,
    );
    context.fillStyle = rgba(model.palette.warning, (1 - phase) * (0.12 + model.turbulence * 0.22));
    context.fill(path);
  }

  pointer.wakes = pointer.wakes.filter((wake) => time - wake.bornAt < 1.8);
  for (const wake of pointer.wakes) {
    const age = clamp((time - wake.bornAt) / 1.8);
    const path = new Path2D();
    const radius = 12 + age * (geometry.compact ? 42 : 68);
    addDottedEllipse(
      path,
      wake.x * geometry.width,
      wake.y * geometry.height,
      radius,
      radius * 0.64,
      0,
      28,
      age * 0.12,
      0.72,
    );
    context.fillStyle = rgba(model.palette.accent, (1 - age) * 0.24);
    context.fill(path);
  }
  context.restore();
}

function drawEmotionField(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  elapsedSeconds: number,
  model: SystemEmotionModel,
  plan: GranularWavePlan,
  pointer: PointerField,
  reducedMotion: boolean,
) {
  const { palette } = model;
  const time = reducedMotion ? 1.7 : elapsedSeconds;
  const geometry = emotionGeometry(width, height, model);
  const breath = reducedMotion ? 0.5 : (Math.sin((time / model.tempoSeconds) * TAU) + 1) / 2;
  if (pointer.active && !reducedMotion) {
    pointer.x += (pointer.targetX - pointer.x) * 0.16;
    pointer.y += (pointer.targetY - pointer.y) * 0.16;
  }

  context.clearRect(0, 0, width, height);
  const backdrop = context.createLinearGradient(0, 0, width, height);
  backdrop.addColorStop(0, rgba(palette.background, 0.99));
  backdrop.addColorStop(0.58, rgba(palette.background, 0.84));
  backdrop.addColorStop(1, '#030807');
  context.fillStyle = backdrop;
  context.fillRect(0, 0, width, height);

  const halo = context.createRadialGradient(
    geometry.fieldX,
    geometry.fieldY,
    2,
    geometry.fieldX,
    geometry.fieldY,
    Math.max(width, height) * 0.48,
  );
  halo.addColorStop(0, rgba(palette.primary, 0.12 + breath * 0.055));
  halo.addColorStop(0.23, rgba(palette.secondary, 0.055 + model.energy * 0.045));
  halo.addColorStop(0.62, rgba(palette.primary, 0.016));
  halo.addColorStop(1, rgba(palette.background, 0));
  context.fillStyle = halo;
  context.fillRect(0, 0, width, height);

  drawParticleWave(context, plan, time, model, geometry, pointer, reducedMotion);
  drawDottedDisturbances(context, time, model, geometry, pointer, reducedMotion);
  drawParticleNucleus(context, plan, time, model, geometry, reducedMotion);
}

export function emotionThemeStyle(model: SystemEmotionModel): CSSProperties {
  return {
    '--emotion-bg': model.palette.background,
    '--emotion-primary': model.palette.primary,
    '--emotion-secondary': model.palette.secondary,
    '--emotion-accent': model.palette.accent,
    '--emotion-warning': model.palette.warning,
    '--emotion-primary-soft': rgba(model.palette.primary, 0.13),
    '--emotion-secondary-soft': rgba(model.palette.secondary, 0.1),
    '--emotion-warning-soft': rgba(model.palette.warning, 0.15),
    '--emotion-tempo': `${model.tempoSeconds.toFixed(2)}s`,
    '--emotion-turbulence': model.turbulence.toFixed(3),
  } as CSSProperties;
}

function moodMetric(value: number): string {
  return `${Math.round(clamp(value) * 100).toString().padStart(2, '0')}%`;
}

export function SystemEmotionEngine({ data, locale, model, onNavigate, paused = false }: SystemEmotionEngineProps) {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerRef = useRef<PointerField>({
    x: 0.5,
    y: 0.5,
    targetX: 0.5,
    targetY: 0.5,
    active: false,
    wakes: [],
  });
  const originRef = useRef<number | null>(null);
  const copy = MOOD_COPY[model.mood];
  const dominantLabel = model.dominantAxis
    ? t(locale, AXIS_LABELS[model.dominantAxis])
    : locale === 'ko' ? '없음' : 'None';

  useEffect(() => {
    const root = rootRef.current;
    const canvas = canvasRef.current;
    if (!root || !canvas) return undefined;
    const context = canvas.getContext('2d', { alpha: false });
    if (!context) return undefined;
    const motionQuery = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    let reducedMotion = motionQuery?.matches ?? false;
    let animationFrame = 0;
    let disposed = false;
    let width = 1;
    let height = 1;
    let lastPaint = 0;
    let intersecting = true;
    const coarsePointer = window.matchMedia?.('(pointer: coarse)').matches ?? false;
    let plan = createGranularWavePlan(width, height, model, coarsePointer);
    if (originRef.current === null) originRef.current = performance.now();
    const origin = originRef.current;

    const canAnimate = () => !reducedMotion && !document.hidden && intersecting && !paused;
    const syncAnimationState = () => {
      root.dataset.animationPaused = canAnimate() ? 'false' : 'true';
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      width = Math.max(1, bounds.width);
      height = Math.max(1, bounds.height);
      const maximumScale = Math.min(window.devicePixelRatio || 1, coarsePointer ? 1.25 : 1.6);
      const pixelBudgetScale = Math.sqrt(1_800_000 / Math.max(1, width * height));
      const deviceScale = Math.min(maximumScale, pixelBudgetScale);
      const backingWidth = Math.max(1, Math.round(width * deviceScale));
      const backingHeight = Math.max(1, Math.round(height * deviceScale));
      if (canvas.width !== backingWidth) canvas.width = backingWidth;
      if (canvas.height !== backingHeight) canvas.height = backingHeight;
      context.setTransform(deviceScale, 0, 0, deviceScale, 0, 0);
      plan = createGranularWavePlan(width, height, model, coarsePointer);
      drawEmotionField(context, width, height, (performance.now() - origin) / 1_000, model, plan, pointerRef.current, reducedMotion);
    };

    const paint = (now: number) => {
      if (disposed) return;
      if (canAnimate() && now - lastPaint >= 42) {
        lastPaint = now;
        drawEmotionField(context, width, height, (now - origin) / 1_000, model, plan, pointerRef.current, reducedMotion);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      reducedMotion = motionQuery?.matches ?? false;
      syncAnimationState();
      if (!document.hidden && intersecting && !paused) {
        drawEmotionField(context, width, height, (performance.now() - origin) / 1_000, model, plan, pointerRef.current, reducedMotion);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };
    const onVisibility = () => restart();
    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') return;
      const bounds = root.getBoundingClientRect();
      const nextX = clamp((event.clientX - bounds.left) / Math.max(1, bounds.width));
      const nextY = clamp((event.clientY - bounds.top) / Math.max(1, bounds.height));
      const now = (performance.now() - origin) / 1_000;
      const pointer = pointerRef.current;
      const wasActive = pointer.active;
      if (!wasActive) {
        pointer.x = nextX;
        pointer.y = nextY;
      }
      pointer.targetX = nextX;
      pointer.targetY = nextY;
      pointer.active = true;
      const lastWake = pointer.wakes[pointer.wakes.length - 1];
      if (wasActive && (!lastWake || (
        now - lastWake.bornAt > 0.11
        && Math.hypot(nextX - lastWake.x, nextY - lastWake.y) > 0.025
      ))) {
        pointer.wakes.push({ x: nextX, y: nextY, bornAt: now });
        if (pointer.wakes.length > 6) pointer.wakes.shift();
      }
    };
    const onPointerLeave = () => { pointerRef.current.active = false; };

    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(resize) : null;
    const intersectionObserver = typeof IntersectionObserver === 'function'
      ? new IntersectionObserver(([entry]) => {
        intersecting = entry?.isIntersecting ?? false;
        restart();
      }, { rootMargin: '120px 0px' })
      : null;
    observer?.observe(canvas);
    intersectionObserver?.observe(root);
    window.addEventListener('resize', resize, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    root.addEventListener('pointermove', onPointerMove, { passive: true });
    root.addEventListener('pointerleave', onPointerLeave, { passive: true });
    motionQuery?.addEventListener?.('change', restart);
    resize();
    restart();

    return () => {
      disposed = true;
      window.cancelAnimationFrame(animationFrame);
      observer?.disconnect();
      intersectionObserver?.disconnect();
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
      root.removeEventListener('pointermove', onPointerMove);
      root.removeEventListener('pointerleave', onPointerLeave);
      motionQuery?.removeEventListener?.('change', restart);
    };
  }, [model, paused]);

  return (
    <section
      ref={rootRef}
      className={`system-emotion-engine emotion-${model.mood}`}
      style={emotionThemeStyle(model)}
      aria-labelledby="system-emotion-title"
      data-mood={model.mood}
    >
      <canvas
        ref={canvasRef}
        className="system-emotion-canvas"
        aria-hidden="true"
        data-renderer="granular-particle-wave"
      />
      <div className="system-emotion-grain" aria-hidden="true" />
      <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {t(locale, copy.title)}. {locale === 'ko' ? `지배 신호 ${dominantLabel}` : `Dominant signal ${dominantLabel}`}.
      </p>
      <header className="emotion-engine-header">
        <span><i aria-hidden="true" />{locale === 'ko' ? '시스템 감응 · 입자파 합성' : 'SYSTEM AFFECT · PARTICLE WAVE'}</span>
        <span className="emotion-engine-sample">{safeText(data?.host.hostname, 'HOST', 40)} · {formatDateTime(data?.latestObservedAt, locale)}</span>
      </header>

      <div className="emotion-engine-copy">
        <span className="emotion-state-code">{copy.code}</span>
        <h2 id="system-emotion-title">{t(locale, copy.title)}</h2>
        <p>{t(locale, copy.summary)}</p>
        {model.dominantPage ? (
          <button type="button" onClick={() => onNavigate(model.dominantPage!)}>
            <span>{locale === 'ko' ? `지배 신호 · ${dominantLabel}` : `Dominant signal · ${dominantLabel}`}</span>
            <Icon name="chevron" size={16} />
          </button>
        ) : (
          <span className="emotion-balanced-state">{locale === 'ko' ? '계통 균형 · 지배 신호 없음' : 'Systems balanced · no dominant signal'}</span>
        )}
      </div>

      <div className="emotion-engine-readings" role="group" aria-label={locale === 'ko' ? '합성 상태 수치' : 'Synthesized state readings'}>
        <div><span>{locale === 'ko' ? '균형도' : 'BALANCE'}</span><strong>{model.score.toString().padStart(2, '0')}</strong></div>
        <div><span>{locale === 'ko' ? '활성' : 'ENERGY'}</span><strong>{moodMetric(model.energy)}</strong></div>
        <div><span>{locale === 'ko' ? '난류' : 'TURBULENCE'}</span><strong>{moodMetric(model.turbulence)}</strong></div>
        <div><span>{locale === 'ko' ? '결맞음' : 'COHERENCE'}</span><strong>{moodMetric(model.coherence)}</strong></div>
      </div>

      <div className="emotion-axis-field" role="group" aria-label={locale === 'ko' ? '계통별 신호 강도' : 'Subsystem signal intensity'}>
        {model.axes.map((axis) => (
          <div key={axis.key} className={axis.key === model.dominantAxis ? 'dominant' : ''}>
            <span>{t(locale, AXIS_LABELS[axis.key])}</span>
            <i aria-hidden="true"><b style={{ '--axis-level': axis.intensity.toFixed(3) } as CSSProperties} /></i>
            <strong>{axis.observed ? Math.round(axis.intensity * 100).toString().padStart(2, '0') : '—'}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
