import { useEffect, useRef } from 'react';
import type { SystemEmotionModel } from '../system-emotion';
import type { MonitorLocale } from '../types';

interface SystemEmotionEngineProps {
  locale: MonitorLocale;
  model: SystemEmotionModel;
  paused?: boolean;
}

export interface GranularWaveSeed {
  axisIndex: number;
  baseU: number;
  depth: number;
  phase: number;
  curl: number;
  speed: number;
}

export interface SprayGrainSeed {
  baseU: number;
  cycle: number;
  phase: number;
  lift: number;
  spread: number;
  activation: number;
  direction: -1 | 1;
}

export interface GranularWavePlan {
  compact: boolean;
  renderCohorts: number;
  waveParticleCount: number;
  sprayParticleCount: number;
  waveGrains: GranularWaveSeed[];
  sprayGrains: SprayGrainSeed[];
}

export const MONOCHROME_GRAIN_STYLE = Object.freeze({
  red: 255,
  green: 136,
  blue: 24,
  alpha: 0.28,
  diameterCssPixels: 1.28,
  compositeOperation: 'source-over' as const,
});

export const GRAIN_MOTION_PROFILE = Object.freeze({
  targetFramesPerSecond: 60,
  renderCohorts: 4,
  desktopCeiling: 0.018,
  compactCeiling: 0.028,
  baseMaximumNormalizedSpeed: 0.94,
  energySpeedBoost: 0.36,
  turbulenceSpeedBoost: 0.34,
  maximumNormalizedStep: 0.08,
});

export interface GranularFramePoint {
  u: number;
  v: number;
  hitCeiling: boolean;
  impact: number;
}

export interface GranularWaveFrame {
  ceiling: number;
  wave: GranularFramePoint[];
  spray: Array<GranularFramePoint | null>;
}

export interface GranularMotionClock {
  elapsedSeconds: number;
  phaseTime: number;
  travel: number;
}

interface EmotionGeometry {
  width: number;
  height: number;
  compact: boolean;
  waveStart: number;
  waveWidth: number;
}

interface FlowState {
  travel: number;
  primaryCenter: number;
  secondaryCenter: number;
  troughCenter: number;
  primaryPulse: number;
  secondaryPulse: number;
  impactPulse: number;
  phaseTime: number;
}

interface SurfacePoint {
  y: number;
  rawY: number;
  crest: number;
  impact: number;
}

interface SurfaceField {
  y: Float32Array;
  rawY: Float32Array;
  crest: Float32Array;
  impact: Float32Array;
  sampleCount: number;
}

interface Vortex {
  u: number;
  v: number;
  radius: number;
  radiusSquared: number;
  spin: number;
  hollow: number;
}

interface MutablePoint extends GranularFramePoint {
  u: number;
  v: number;
}

interface WaveMotionHistory {
  u: Float32Array;
  v: Float32Array;
  lastTime: Float64Array;
  activeCount: number;
}

interface GranularWaveCounts {
  compact: boolean;
  waveParticleCount: number;
  sprayParticleCount: number;
}

const TAU = Math.PI * 2;
const GOLDEN_RATIO_FRACTION = 0.6180339887498949;
const GRAIN_FILL_STYLE = `rgba(${MONOCHROME_GRAIN_STYLE.red}, ${MONOCHROME_GRAIN_STYLE.green}, ${MONOCHROME_GRAIN_STYLE.blue}, ${MONOCHROME_GRAIN_STYLE.alpha})`;
const BACKGROUND_COLOR = '#020100';
const TARGET_FRAME_MILLISECONDS = 1_000 / GRAIN_MOTION_PROFILE.targetFramesPerSecond;
const FRAME_DEADLINE_TOLERANCE = 0.8;
const REFERENCE_FADE_FRAME_MILLISECONDS = TARGET_FRAME_MILLISECONDS
  * GRAIN_MOTION_PROFILE.renderCohorts;
const DESKTOP_REFERENCE_FADE_ALPHA = 0.38;
const COMPACT_REFERENCE_FADE_ALPHA = 0.5;

function clamp(value: number, minimum = 0, maximum = 1): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(maximum, value));
}

function seeded(index: number, salt: number): number {
  const value = Math.sin(index * 91.733 + salt * 47.117) * 43758.5453;
  return value - Math.floor(value);
}

function wrap(value: number): number {
  return value - Math.floor(value);
}

function signedWrappedDistance(value: number, center: number): number {
  let distance = value - center;
  if (distance > 0.5) distance -= 1;
  else if (distance < -0.5) distance += 1;
  return distance;
}

export function constrainGranularMotionStep(
  previousU: number,
  previousV: number,
  targetU: number,
  targetV: number,
  maximumDistance: number,
): { u: number; v: number } {
  const horizontal = signedWrappedDistance(targetU, previousU);
  const vertical = targetV - previousV;
  const distanceSquared = horizontal * horizontal + vertical * vertical;
  const safeMaximum = Math.max(0, maximumDistance);
  if (distanceSquared <= safeMaximum * safeMaximum || distanceSquared <= 0.00000001) {
    return { u: targetU, v: targetV };
  }
  const scale = safeMaximum / Math.sqrt(distanceSquared);
  return {
    u: wrap(previousU + horizontal * scale),
    v: previousV + vertical * scale,
  };
}

function createWaveMotionHistory(length: number): WaveMotionHistory {
  const history: WaveMotionHistory = {
    u: new Float32Array(length),
    v: new Float32Array(length),
    lastTime: new Float64Array(length),
    activeCount: 0,
  };
  history.lastTime.fill(-1);
  return history;
}

function constrainWaveGrainMotionInto(
  point: MutablePoint,
  grainIndex: number,
  elapsedSeconds: number,
  model: SystemEmotionModel,
  history: WaveMotionHistory,
): void {
  const previousTime = history.lastTime[grainIndex];
  if (previousTime >= 0) {
    const elapsed = clamp(elapsedSeconds - previousTime, 1 / 120, 0.2);
    const maximumSpeed = GRAIN_MOTION_PROFILE.baseMaximumNormalizedSpeed
      + model.energy * GRAIN_MOTION_PROFILE.energySpeedBoost
      + model.turbulence * GRAIN_MOTION_PROFILE.turbulenceSpeedBoost;
    const maximumDistance = Math.min(
      GRAIN_MOTION_PROFILE.maximumNormalizedStep,
      maximumSpeed * elapsed,
    );
    const horizontal = signedWrappedDistance(point.u, history.u[grainIndex]);
    const vertical = point.v - history.v[grainIndex];
    const distanceSquared = horizontal * horizontal + vertical * vertical;
    if (distanceSquared > maximumDistance * maximumDistance) {
      const scale = maximumDistance / Math.sqrt(distanceSquared);
      point.u = wrap(history.u[grainIndex] + horizontal * scale);
      point.v = history.v[grainIndex] + vertical * scale;
    }
  }
  history.u[grainIndex] = point.u;
  history.v[grainIndex] = point.v;
  history.lastTime[grainIndex] = elapsedSeconds;
}

function ceilingFor(compact: boolean): number {
  return compact ? GRAIN_MOTION_PROFILE.compactCeiling : GRAIN_MOTION_PROFILE.desktopCeiling;
}

export function shouldPaintEmotionFrame(now: number, lastPaint: number): boolean {
  if (!Number.isFinite(now) || !Number.isFinite(lastPaint)) return false;
  return now - lastPaint >= TARGET_FRAME_MILLISECONDS - FRAME_DEADLINE_TOLERANCE;
}

export function advanceEmotionFrameClock(now: number, lastPaint: number): number {
  const elapsed = now - lastPaint;
  if (!Number.isFinite(elapsed) || elapsed <= 0 || elapsed > TARGET_FRAME_MILLISECONDS * 4) return now;
  const elapsedFrameCount = Math.max(
    1,
    Math.floor(
      (elapsed + FRAME_DEADLINE_TOLERANCE) / TARGET_FRAME_MILLISECONDS,
    ),
  );
  return lastPaint + elapsedFrameCount * TARGET_FRAME_MILLISECONDS;
}

export function emotionFrameFadeAlpha(deltaMilliseconds: number, compact: boolean): number {
  const safeDelta = clamp(deltaMilliseconds, 1, 100);
  const referenceAlpha = compact
    ? COMPACT_REFERENCE_FADE_ALPHA
    : DESKTOP_REFERENCE_FADE_ALPHA;
  return 1 - Math.pow(
    1 - referenceAlpha,
    safeDelta / REFERENCE_FADE_FRAME_MILLISECONDS,
  );
}

export function reflectCeilingOvershoot(
  rawV: number,
  ceiling: number,
  restitution = 0.58,
): { v: number; hitCeiling: boolean; impact: number } {
  if (rawV >= ceiling) return { v: rawV, hitCeiling: false, impact: 0 };
  const penetration = ceiling - rawV;
  return {
    v: ceiling + penetration * clamp(restitution, 0, 1),
    hitCeiling: true,
    impact: clamp(penetration / 0.18),
  };
}

function motionRates(model: SystemEmotionModel): { tempoScale: number; transport: number } {
  const tempoScale = clamp(8.4 / Math.max(2.6, model.tempoSeconds), 0.92, 2.65);
  return {
    tempoScale,
    transport: (0.05 + model.energy * 0.03 + model.turbulence * 0.025)
      * (0.92 + tempoScale * 0.08),
  };
}

export function advanceGranularMotionClock(
  clock: GranularMotionClock,
  deltaSeconds: number,
  model: SystemEmotionModel,
): GranularMotionClock {
  const safeDelta = Number.isFinite(deltaSeconds) ? Math.max(0, deltaSeconds) : 0;
  const rates = motionRates(model);
  return {
    elapsedSeconds: clock.elapsedSeconds + safeDelta,
    phaseTime: clock.phaseTime + safeDelta * rates.tempoScale,
    travel: clock.travel + safeDelta * rates.transport,
  };
}

export function blendGranularMotionModel(
  current: SystemEmotionModel,
  target: SystemEmotionModel,
  deltaSeconds: number,
): SystemEmotionModel {
  const safeDelta = Number.isFinite(deltaSeconds) ? Math.max(0, deltaSeconds) : 0;
  const amount = 1 - Math.exp(-safeDelta / 0.52);
  const mix = (from: number, to: number) => from + (to - from) * amount;
  const currentAxes = new Map(current.axes.map((axis) => [axis.key, axis]));
  return {
    ...target,
    score: mix(current.score, target.score),
    energy: mix(current.energy, target.energy),
    turbulence: mix(current.turbulence, target.turbulence),
    coherence: mix(current.coherence, target.coherence),
    volatility: mix(current.volatility, target.volatility),
    waveAmplitude: mix(current.waveAmplitude, target.waveAmplitude),
    tempoSeconds: mix(current.tempoSeconds, target.tempoSeconds),
    particleCount: mix(current.particleCount, target.particleCount),
    axes: target.axes.map((axis) => ({
      ...axis,
      intensity: mix(currentAxes.get(axis.key)?.intensity ?? axis.intensity, axis.intensity),
    })),
  };
}

function reflectCeilingOvershootInto(
  rawV: number,
  ceiling: number,
  restitution: number,
  point: MutablePoint,
): void {
  if (rawV >= ceiling) {
    point.v = rawV;
    point.hitCeiling = false;
    point.impact = 0;
    return;
  }
  const penetration = ceiling - rawV;
  point.v = ceiling + penetration * restitution;
  point.hitCeiling = true;
  point.impact = clamp(penetration / 0.18);
}

function asymmetricPacket(
  value: number,
  center: number,
  trailingSpread: number,
  leadingSpread: number,
): number {
  const distance = signedWrappedDistance(value, center);
  const spread = distance < 0 ? trailingSpread : leadingSpread;
  const normalized = distance / Math.max(0.001, spread);
  return Math.exp(-0.5 * normalized * normalized);
}

function emotionGeometry(width: number, height: number): EmotionGeometry {
  return {
    width,
    height,
    compact: width <= 640,
    waveStart: width * -0.045,
    waveWidth: width * 1.09,
  };
}

function createFlowState(
  time: number,
  model: SystemEmotionModel,
  motionClock?: GranularMotionClock,
): FlowState {
  const rates = motionRates(model);
  const phaseTime = motionClock?.phaseTime ?? time * rates.tempoScale;
  const travel = motionClock?.travel ?? time * rates.transport;
  const primaryCenter = wrap(
    0.14
      + travel
      + Math.sin(phaseTime * 0.23 + 0.35) * (0.018 + model.turbulence * 0.009),
  );
  const secondaryCenter = wrap(
    primaryCenter
      + 0.49
      + Math.sin(phaseTime * 0.17 + 1.4) * (0.067 + model.turbulence * 0.018),
  );
  const impactCarrier = Math.sin(phaseTime * 0.45 + 0.42) * 0.72
    + Math.sin(phaseTime * 0.72 + 2.1) * 0.28;
  return {
    travel,
    primaryCenter,
    secondaryCenter,
    troughCenter: wrap(
      primaryCenter
        + 0.285
        + Math.sin(phaseTime * 0.21) * (0.035 + model.volatility * 0.014),
    ),
    primaryPulse: 0.75
      + Math.sin(phaseTime * 0.86 + 0.45) * 0.2
      + Math.sin(phaseTime * 1.43 + 2.6) * model.turbulence * 0.045,
    secondaryPulse: 0.72
      + Math.sin(phaseTime * 0.69 + 2.35) * 0.2
      + Math.sin(phaseTime * 1.19 + 0.8) * model.volatility * 0.04,
    impactPulse: Math.pow(clamp((impactCarrier + 0.55) / 1.35), 2.05),
    phaseTime,
  };
}

function sampleSurfacePointInto(
  u: number,
  state: FlowState,
  model: SystemEmotionModel,
  compact: boolean,
  point: SurfacePoint,
): SurfacePoint {
  const primary = asymmetricPacket(u, state.primaryCenter, 0.16, 0.095)
    * state.primaryPulse
    * (0.29 + model.waveAmplitude * 0.065);
  const forwardSheet = asymmetricPacket(u, wrap(state.primaryCenter + 0.105), 0.075, 0.045)
    * (0.055 + model.turbulence * 0.04);
  const secondary = asymmetricPacket(u, state.secondaryCenter, 0.13, 0.105)
    * state.secondaryPulse
    * (0.18 + model.waveAmplitude * 0.045);
  const trailingRoll = asymmetricPacket(u, wrap(state.primaryCenter - 0.145), 0.08, 0.115)
    * (0.07 + model.coherence * 0.035);
  const trough = asymmetricPacket(u, state.troughCenter, 0.1, 0.1)
    * (0.075 + model.turbulence * 0.035);
  const largeCurl = Math.sin(
    u * TAU * 2.15
      - state.phaseTime * (0.43 + model.energy * 0.19)
      + Math.sin(u * TAU * 0.83 + state.phaseTime * 0.21) * 0.72,
  ) * (0.016 + model.turbulence * 0.021);
  const frayedEdge = Math.sin(
    u * TAU * (8.8 + model.turbulence * 3.1)
      - state.phaseTime * (0.78 + model.turbulence * 0.41)
      + Math.sin(u * TAU * 3.15 - state.phaseTime * 0.31),
  ) * (0.006 + model.turbulence * 0.011);
  const impactSurge = asymmetricPacket(
    u,
    wrap(state.primaryCenter + 0.038),
    0.26,
    0.2,
  ) * state.impactPulse * (
    0.37
      + model.waveAmplitude * 0.09
      + model.turbulence * 0.11
      + model.energy * 0.025
  );
  const crest = primary
    + forwardSheet
    + secondary
    + trailingRoll
    - trough
    + largeCurl
    + frayedEdge
    + impactSurge;
  const baseline = (compact ? 0.715 : 0.69) - model.energy * 0.018;
  const ceiling = ceilingFor(compact);
  const rawY = clamp(baseline - crest, -0.42, 0.79);
  const penetration = Math.max(0, ceiling - rawY);
  point.y = clamp(
    penetration > 0 ? ceiling + penetration * 0.58 : rawY,
    ceiling,
    0.79,
  );
  point.rawY = rawY;
  point.crest = clamp(crest, 0, 1.08);
  point.impact = clamp(penetration / 0.18);
  return point;
}

function createSurfaceField(
  state: FlowState,
  model: SystemEmotionModel,
  compact: boolean,
): SurfaceField {
  const sampleCount = compact ? 720 : 1_080;
  const y = new Float32Array(sampleCount);
  const rawY = new Float32Array(sampleCount);
  const crest = new Float32Array(sampleCount);
  const impact = new Float32Array(sampleCount);
  const point: SurfacePoint = { y: 0, rawY: 0, crest: 0, impact: 0 };
  for (let index = 0; index < sampleCount; index += 1) {
    sampleSurfacePointInto(index / sampleCount, state, model, compact, point);
    y[index] = point.y;
    rawY[index] = point.rawY;
    crest[index] = point.crest;
    impact[index] = point.impact;
  }
  return { y, rawY, crest, impact, sampleCount };
}

function sampleSurfaceFieldInto(
  u: number,
  field: SurfaceField,
  point: SurfacePoint,
): SurfacePoint {
  const position = wrap(u) * field.sampleCount;
  const leftIndex = Math.floor(position) % field.sampleCount;
  const rightIndex = (leftIndex + 1) % field.sampleCount;
  const mix = position - leftIndex;
  point.y = field.y[leftIndex] + (field.y[rightIndex] - field.y[leftIndex]) * mix;
  point.rawY = field.rawY[leftIndex] + (field.rawY[rightIndex] - field.rawY[leftIndex]) * mix;
  point.crest = field.crest[leftIndex] + (field.crest[rightIndex] - field.crest[leftIndex]) * mix;
  point.impact = field.impact[leftIndex] + (field.impact[rightIndex] - field.impact[leftIndex]) * mix;
  return point;
}

function vortex(
  u: number,
  v: number,
  radius: number,
  spin: number,
  hollow: number,
): Vortex {
  return { u, v, radius, radiusSquared: radius * radius, spin, hollow };
}

function createVortices(state: FlowState, model: SystemEmotionModel, compact: boolean): Vortex[] {
  const point: SurfacePoint = { y: 0, rawY: 0, crest: 0, impact: 0 };
  const primarySurface = sampleSurfacePointInto(
    state.primaryCenter,
    state,
    model,
    compact,
    point,
  ).y;
  const secondarySurface = sampleSurfacePointInto(
    state.secondaryCenter,
    state,
    model,
    compact,
    point,
  ).y;
  const trailingU = wrap(state.primaryCenter - 0.13);
  const trailingSurface = sampleSurfacePointInto(trailingU, state, model, compact, point).y;
  const troughSurface = sampleSurfacePointInto(
    state.troughCenter,
    state,
    model,
    compact,
    point,
  ).y;
  const ceiling = ceilingFor(compact);
  return [
    vortex(
      wrap(state.primaryCenter + 0.045),
      primarySurface + 0.075,
      0.19 + model.turbulence * 0.035,
      1.62 + model.energy * 0.42,
      0.012 + model.turbulence * 0.007,
    ),
    vortex(
      trailingU,
      trailingSurface + 0.12,
      0.135 + model.volatility * 0.04,
      -1.05 - model.turbulence * 0.32,
      0.009 + model.turbulence * 0.006,
    ),
    vortex(
      wrap(state.secondaryCenter - 0.025),
      secondarySurface + 0.09,
      0.16 + model.turbulence * 0.035,
      -1.34 - model.energy * 0.34,
      0.01 + model.volatility * 0.007,
    ),
    vortex(
      state.troughCenter,
      troughSurface + 0.18,
      0.105 + model.turbulence * 0.025,
      0.82 + model.turbulence * 0.3,
      0.006 + model.volatility * 0.005,
    ),
    vortex(
      wrap(state.primaryCenter + 0.064),
      ceiling + 0.052 + (1 - state.impactPulse) * 0.026,
      0.09 + state.impactPulse * 0.075 + model.turbulence * 0.025,
      -0.78 - state.impactPulse * 1.38 - model.turbulence * 0.28,
      0.006 + state.impactPulse * 0.011,
    ),
  ];
}

function warpByVortex(point: MutablePoint, currentVortex: Vortex): void {
  const horizontal = signedWrappedDistance(point.u, currentVortex.u);
  const verticalScale = 0.82;
  const vertical = (point.v - currentVortex.v) * verticalScale;
  if (Math.abs(horizontal) >= currentVortex.radius || Math.abs(vertical) >= currentVortex.radius) return;
  const distanceSquared = horizontal * horizontal + vertical * vertical;
  if (distanceSquared <= 0.00000001 || distanceSquared >= currentVortex.radiusSquared) return;

  const distance = Math.sqrt(distanceSquared);
  const influenceBase = 1 - distance / currentVortex.radius;
  const influence = influenceBase * influenceBase;
  const angle = currentVortex.spin * influence;
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  const radialScale = 1 + currentVortex.hollow * influence / Math.max(distance, 0.012);
  const rotatedHorizontal = (horizontal * cosine - vertical * sine) * radialScale;
  const rotatedVertical = (horizontal * sine + vertical * cosine) * radialScale;
  point.u = wrap(currentVortex.u + rotatedHorizontal);
  point.v = currentVortex.v + rotatedVertical / verticalScale;
}

function granularWaveCounts(
  width: number,
  height: number,
  model: SystemEmotionModel,
  coarsePointer: boolean,
): GranularWaveCounts {
  const safeWidth = Number.isFinite(width) ? Math.max(1, width) : 1;
  const safeHeight = Number.isFinite(height) ? Math.max(1, height) : 1;
  const compact = safeWidth <= 640;
  const stateDensity = 0.89
    + model.energy * 0.11
    + model.turbulence * 0.16
    + clamp((model.particleCount - 14) / 50) * 0.05;
  const baseTarget = safeWidth * safeHeight / (compact ? 4.4 : 7.5);
  const minimum = compact ? 24_000 : coarsePointer ? 36_000 : 48_000;
  const maximum = compact ? 45_000 : coarsePointer ? 62_000 : 100_000;
  const waveParticleCount = Math.round(clamp(baseTarget * stateDensity, minimum, maximum));
  return {
    compact,
    waveParticleCount,
    sprayParticleCount: Math.round(
      waveParticleCount * (0.032 + model.turbulence * 0.06 + model.energy * 0.018),
    ),
  };
}

export function createGranularWavePlan(
  width: number,
  height: number,
  model: SystemEmotionModel,
  coarsePointer = false,
): GranularWavePlan {
  const counts = granularWaveCounts(width, height, model, coarsePointer);
  const { compact, waveParticleCount, sprayParticleCount } = counts;
  const waveGrains: GranularWaveSeed[] = [];
  const axisCount = Math.max(1, model.axes.length);

  for (let index = 0; index < waveParticleCount; index += 1) {
    const depthSeed = seeded(index, 2);
    waveGrains.push({
      axisIndex: Math.min(axisCount - 1, Math.floor(seeded(index, 7) * axisCount)),
      baseU: wrap((index + 0.5) * GOLDEN_RATIO_FRACTION + (seeded(index, 1) - 0.5) * 0.013),
      depth: Math.pow(depthSeed, 1.72),
      phase: seeded(index, 3) * TAU,
      curl: seeded(index, 4) * 2 - 1,
      speed: 0.78 + seeded(index, 5) * 0.4,
    });
  }

  const sprayGrains: SprayGrainSeed[] = [];
  for (let index = 0; index < sprayParticleCount; index += 1) {
    sprayGrains.push({
      baseU: wrap((index + 0.5) * GOLDEN_RATIO_FRACTION + seeded(index, 11) * 0.17),
      cycle: seeded(index, 12),
      phase: seeded(index, 13) * TAU,
      lift: 0.72 + seeded(index, 14) * 0.55,
      spread: 0.72 + seeded(index, 15) * 0.5,
      activation: seeded(index, 16),
      direction: seeded(index, 17) < 0.82 ? 1 : -1,
    });
  }

  return {
    compact,
    renderCohorts: GRAIN_MOTION_PROFILE.renderCohorts,
    waveParticleCount,
    sprayParticleCount,
    waveGrains,
    sprayGrains,
  };
}

function sampleWaveGrainInto(
  grain: GranularWaveSeed,
  state: FlowState,
  surfaceField: SurfaceField,
  vortices: Vortex[],
  model: SystemEmotionModel,
  compact: boolean,
  point: MutablePoint,
  surface: SurfacePoint,
): MutablePoint {
  const axisIntensity = clamp(model.axes[grain.axisIndex]?.intensity ?? 0);
  let u = wrap(
    grain.baseU
      + state.travel * grain.speed
      + Math.sin(grain.phase + state.phaseTime * (0.21 + model.energy * 0.08))
        * (0.004 + model.turbulence * 0.006)
        * (1 - grain.depth),
  );
  sampleSurfaceFieldInto(u, surfaceField, surface);
  const depthFlow = clamp(
    grain.depth
      + Math.sin(
        grain.phase
          + u * TAU * (1.7 + grain.curl * 0.24)
          - state.phaseTime * (0.32 + model.turbulence * 0.26),
      ) * (0.017 + model.turbulence * 0.034) * (1 - grain.depth),
  );
  let v = surface.rawY + Math.pow(depthFlow, 0.93) * (1.055 - surface.rawY);

  const broadFlow = grain.phase
    + u * TAU * 2.05
    + v * TAU * 1.27
    - state.phaseTime * (0.46 + model.energy * 0.25);
  const fineFlow = grain.phase * 0.63
    - u * TAU * 5.1
    + v * TAU * 3.35
    + state.phaseTime * (0.62 + model.turbulence * 0.39);
  const surfaceWeight = Math.pow(1 - depthFlow, 2.1);
  u = wrap(
    u
      + Math.sin(broadFlow) * (0.0045 + model.turbulence * 0.0065)
      + Math.sin(fineFlow) * (0.0011 + model.turbulence * 0.0025) * surfaceWeight,
  );
  v += Math.cos(broadFlow + grain.curl)
    * (0.01 + model.turbulence * 0.018)
    * (0.35 + surfaceWeight);
  v += Math.cos(fineFlow) * (0.0025 + model.turbulence * 0.005) * surfaceWeight;

  const compression = Math.sin(
    u * TAU * 1.85
      - state.phaseTime * (0.56 + model.energy * 0.26)
      + v * TAU * 1.92
      + Math.sin(v * TAU * 2.35 + state.phaseTime * 0.34) * 0.82,
  ) + Math.sin(
    u * TAU * 4.15
      + state.phaseTime * (0.43 + model.turbulence * 0.31)
      - v * TAU * 3.05
      + Math.sin(u * TAU * 1.2 - state.phaseTime * 0.27) * 0.67,
  ) * 0.42;
  u = wrap(
    u
      + compression
        * (0.037 + model.turbulence * 0.02 + model.coherence * 0.006)
        * (1 - depthFlow * 0.62),
  );
  v += Math.cos(
    pointPhase(u, v, state.phaseTime, model.turbulence),
  ) * (0.003 + model.turbulence * 0.006) * Math.pow(1 - depthFlow, 1.22);

  point.u = u;
  point.v = v;
  point.hitCeiling = false;
  point.impact = 0;
  const preVortexU = point.u;
  const preVortexV = point.v;
  for (const currentVortex of vortices) warpByVortex(point, currentVortex);
  const vortexHorizontal = signedWrappedDistance(point.u, preVortexU);
  const vortexVertical = point.v - preVortexV;
  const vortexDistanceSquared = vortexHorizontal * vortexHorizontal
    + vortexVertical * vortexVertical;
  if (vortexDistanceSquared > 0.000000000001) {
    const vortexBlend = 0.2 + model.turbulence * 0.04;
    const maximumVortexOffset = 0.009 + model.turbulence * 0.004;
    const blendedDistanceSquared = vortexDistanceSquared * vortexBlend * vortexBlend;
    const vortexScale = blendedDistanceSquared <= maximumVortexOffset * maximumVortexOffset
      ? vortexBlend
      : maximumVortexOffset / Math.sqrt(vortexDistanceSquared);
    point.u = wrap(preVortexU + vortexHorizontal * vortexScale);
    point.v = preVortexV + vortexVertical * vortexScale;
  }

  const coherentBreakPhase = point.u * TAU * 3.35
    - state.phaseTime * (0.91 + model.turbulence * 0.53)
    + Math.sin(point.u * TAU * 1.17 - state.phaseTime * 0.31) * 1.1;
  const edgeBreak = Math.max(
    0,
    Math.sin(coherentBreakPhase) * 0.78
      + Math.sin(grain.phase - state.phaseTime * 0.76) * 0.22,
  );
  point.u = wrap(
    point.u
      + Math.cos(coherentBreakPhase)
        * surfaceWeight
        * surface.crest
        * (0.008 + model.turbulence * 0.018),
  );
  point.v -= edgeBreak
    * surfaceWeight
    * surface.crest
    * (0.026 + model.turbulence * 0.075 + axisIntensity * 0.01);

  const ceiling = ceilingFor(compact);
  reflectCeilingOvershootInto(point.v, ceiling, 0.58, point);
  point.v = clamp(point.v, ceiling, 1.08);
  point.impact = Math.max(point.impact, surface.impact * surfaceWeight * 0.7);
  if (point.hitCeiling) {
    const collisionShear = (0.008 + model.turbulence * 0.022 + model.energy * 0.008)
      * point.impact
      * (0.45 + surfaceWeight * 0.55);
    point.u = wrap(
      point.u
        + collisionShear
          * (0.72 + Math.sin(grain.phase + state.phaseTime * 0.83) * 0.28),
    );
  }
  return point;
}

function sampleSprayGrainInto(
  grain: SprayGrainSeed,
  state: FlowState,
  surfaceField: SurfaceField,
  model: SystemEmotionModel,
  compact: boolean,
  point: MutablePoint,
  surface: SurfacePoint,
): boolean {
  const cycle = wrap(
    grain.cycle
      + state.phaseTime * (0.075 + model.energy * 0.038 + model.turbulence * 0.052),
  );
  const activeWindow = 0.37 + model.turbulence * 0.1;
  if (cycle >= activeWindow) return false;

  const progress = cycle / activeWindow;
  const sourceU = wrap(
    grain.baseU
      + state.travel * 0.9
      + Math.sin(grain.phase + state.phaseTime * 0.29) * 0.008,
  );
  sampleSurfaceFieldInto(sourceU, surfaceField, surface);
  const crestGate = clamp((surface.crest - 0.055) / 0.28);
  const collisionActivation = surface.impact * (0.22 + state.impactPulse * 0.48);
  if (grain.activation > crestGate * (0.34 + model.turbulence * 0.46) + collisionActivation) {
    return false;
  }

  const arc = Math.sin(progress * Math.PI);
  const horizontal = progress
    * (0.052 + model.turbulence * 0.082 + surface.impact * 0.035)
    * grain.spread
    * grain.direction;
  const lift = arc
    * (0.055 + model.turbulence * 0.125 + model.energy * 0.04 + surface.impact * 0.045)
    * grain.lift
    * (0.5 + crestGate * 0.5);
  point.u = wrap(
    sourceU
      + horizontal
      + Math.sin(grain.phase + progress * TAU) * (0.003 + model.turbulence * 0.007),
  );
  const rawV = surface.y
    - lift
    + progress * progress * (0.018 + model.turbulence * 0.026)
    + Math.cos(grain.phase + progress * TAU * 1.2) * 0.004;
  const ceiling = ceilingFor(compact);
  reflectCeilingOvershootInto(rawV, ceiling, 0.52, point);
  point.v = clamp(point.v, ceiling, 1.04);
  point.impact = Math.max(point.impact, surface.impact * 0.65);
  if (point.hitCeiling) {
    point.u = wrap(
      point.u
        + point.impact
          * (0.012 + model.turbulence * 0.026)
          * (0.65 + Math.sin(grain.phase) * 0.35),
    );
  }
  return true;
}

export function sampleGranularWaveFrame(
  width: number,
  height: number,
  elapsedSeconds: number,
  model: SystemEmotionModel,
  waveGrains: readonly GranularWaveSeed[],
  sprayGrains: readonly SprayGrainSeed[],
  motionClock?: GranularMotionClock,
): GranularWaveFrame {
  const geometry = emotionGeometry(width, height);
  const state = createFlowState(elapsedSeconds, model, motionClock);
  const surfaceField = createSurfaceField(state, model, geometry.compact);
  const vortices = createVortices(state, model, geometry.compact);
  const point: MutablePoint = { u: 0, v: 0, hitCeiling: false, impact: 0 };
  const surface: SurfacePoint = { y: 0, rawY: 0, crest: 0, impact: 0 };
  const wave = waveGrains.map((grain) => {
    sampleWaveGrainInto(
      grain,
      state,
      surfaceField,
      vortices,
      model,
      geometry.compact,
      point,
      surface,
    );
    return { ...point };
  });
  const spray = sprayGrains.map((grain) => (
    sampleSprayGrainInto(
      grain,
      state,
      surfaceField,
      model,
      geometry.compact,
      point,
      surface,
    ) ? { ...point } : null
  ));
  return { ceiling: ceilingFor(geometry.compact), wave, spray };
}

function drawGrain(
  context: CanvasRenderingContext2D,
  geometry: EmotionGeometry,
  point: Pick<GranularFramePoint, 'u' | 'v'>,
) {
  const diameter = MONOCHROME_GRAIN_STYLE.diameterCssPixels;
  const x = geometry.waveStart + point.u * geometry.waveWidth;
  const y = point.v * geometry.height;
  if (
    x < -diameter
    || x > geometry.width + diameter
    || y < -diameter
    || y > geometry.height + diameter
  ) return;
  context.fillRect(x - diameter * 0.5, y - diameter * 0.5, diameter, diameter);
}

function pointPhase(u: number, v: number, time: number, turbulence: number): number {
  return u * TAU * 2.75
    - v * TAU * 1.8
    - time * (0.3 + turbulence * 0.22);
}

function drawEmotionField(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  elapsedSeconds: number,
  model: SystemEmotionModel,
  plan: GranularWavePlan,
  activeWaveParticleCount: number,
  activeSprayParticleCount: number,
  reducedMotion: boolean,
  resetFrame: boolean,
  deltaMilliseconds: number,
  frameIndex: number,
  motionClock?: GranularMotionClock,
  motionHistory?: WaveMotionHistory,
) {
  const time = reducedMotion ? 2.1 : elapsedSeconds;
  const geometry = emotionGeometry(width, height);
  const state = createFlowState(time, model, reducedMotion ? undefined : motionClock);
  const surfaceField = createSurfaceField(state, model, geometry.compact);
  const vortices = createVortices(state, model, geometry.compact);
  const point: MutablePoint = { u: 0, v: 0, hitCeiling: false, impact: 0 };
  const surface: SurfacePoint = { y: 0, rawY: 0, crest: 0, impact: 0 };

  context.globalCompositeOperation = MONOCHROME_GRAIN_STYLE.compositeOperation;
  context.globalAlpha = resetFrame
    ? 1
    : emotionFrameFadeAlpha(deltaMilliseconds, geometry.compact);
  context.fillStyle = BACKGROUND_COLOR;
  context.fillRect(0, 0, width, height);

  context.globalAlpha = 1;
  context.fillStyle = GRAIN_FILL_STYLE;
  const waveLimit = Math.min(plan.waveGrains.length, activeWaveParticleCount);
  const sprayLimit = Math.min(plan.sprayGrains.length, activeSprayParticleCount);
  if (motionHistory) {
    if (waveLimit > motionHistory.activeCount) {
      motionHistory.lastTime.fill(-1, motionHistory.activeCount, waveLimit);
    }
    motionHistory.activeCount = waveLimit;
  }
  const renderEveryGrain = resetFrame || reducedMotion;
  const cohortCount = renderEveryGrain ? 1 : Math.max(1, plan.renderCohorts);
  const cohort = renderEveryGrain ? 0 : frameIndex % cohortCount;
  for (let index = cohort; index < waveLimit; index += cohortCount) {
    sampleWaveGrainInto(
      plan.waveGrains[index],
      state,
      surfaceField,
      vortices,
      model,
      geometry.compact,
      point,
      surface,
    );
    if (motionHistory) {
      constrainWaveGrainMotionInto(
        point,
        index,
        time,
        model,
        motionHistory,
      );
    }
    drawGrain(context, geometry, point);
  }
  for (let index = 0; index < sprayLimit; index += 1) {
    if (sampleSprayGrainInto(
      plan.sprayGrains[index],
      state,
      surfaceField,
      model,
      geometry.compact,
      point,
      surface,
    )) drawGrain(context, geometry, point);
  }
}

export function SystemEmotionEngine({ locale, model, paused = false }: SystemEmotionEngineProps) {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const motionClockRef = useRef<GranularMotionClock>({
    elapsedSeconds: 0,
    phaseTime: 0,
    travel: 0,
  });
  const renderModelRef = useRef(model);
  const targetModelRef = useRef(model);
  const pausedRef = useRef(paused);
  const restartAnimationRef = useRef<(() => void) | null>(null);
  const syncModelRef = useRef<(() => void) | null>(null);
  targetModelRef.current = model;
  pausedRef.current = paused;

  useEffect(() => {
    const root = rootRef.current;
    const canvas = canvasRef.current;
    if (!root || !canvas) return undefined;
    const context = canvas.getContext('2d', { alpha: false });
    if (!context) return undefined;

    const motionQuery = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    const coarsePointer = window.matchMedia?.('(pointer: coarse)').matches ?? false;
    let reducedMotion = motionQuery?.matches ?? false;
    let animationFrame = 0;
    let disposed = false;
    let width = 0;
    let height = 0;
    let motionClock = motionClockRef.current;
    let renderModel = renderModelRef.current;
    let reducedModel = targetModelRef.current;
    let previousAnimationNow: number | null = null;
    let lastPaintClock = 0;
    let lastRenderedAt = 0;
    let frameIndex = 0;
    let intersecting = true;
    let plan: GranularWavePlan = {
      compact: true,
      renderCohorts: GRAIN_MOTION_PROFILE.renderCohorts,
      waveParticleCount: 0,
      sprayParticleCount: 0,
      waveGrains: [],
      sprayGrains: [],
    };
    let motionHistory = createWaveMotionHistory(0);

    const canAnimate = () => (
      !reducedMotion
      && !document.hidden
      && intersecting
      && !pausedRef.current
    );
    const syncAnimationState = () => {
      root.dataset.animationPaused = canAnimate() ? 'false' : 'true';
    };

    const render = (now: number, resetFrame = false) => {
      const deltaMilliseconds = lastRenderedAt > 0
        ? clamp(now - lastRenderedAt, 1, 100)
        : TARGET_FRAME_MILLISECONDS;
      const visibleModel = reducedMotion ? targetModelRef.current : renderModel;
      const activeCounts = granularWaveCounts(width, height, visibleModel, coarsePointer);
      drawEmotionField(
        context,
        width,
        height,
        motionClock.elapsedSeconds,
        visibleModel,
        plan,
        activeCounts.waveParticleCount,
        activeCounts.sprayParticleCount,
        reducedMotion,
        resetFrame,
        deltaMilliseconds,
        frameIndex,
        motionClock,
        motionHistory,
      );
      lastRenderedAt = now;
      if (!resetFrame && !reducedMotion) frameIndex += 1;
    };

    const resetAnimationClock = (now: number) => {
      previousAnimationNow = now;
      lastPaintClock = now;
    };

    const advanceSimulation = (now: number) => {
      if (previousAnimationNow === null) {
        previousAnimationNow = now;
        return;
      }
      const elapsed = clamp(now - previousAnimationNow, 0, 50);
      const elapsedSeconds = elapsed / 1_000;
      renderModel = blendGranularMotionModel(
        renderModel,
        targetModelRef.current,
        elapsedSeconds,
      );
      renderModelRef.current = renderModel;
      motionClock = advanceGranularMotionClock(motionClock, elapsedSeconds, renderModel);
      motionClockRef.current = motionClock;
      previousAnimationNow = now;
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      const nextWidth = Math.max(1, bounds.width);
      const nextHeight = Math.max(1, bounds.height);
      const maximumScale = Math.min(window.devicePixelRatio || 1, coarsePointer ? 1.2 : 1.5);
      const pixelBudgetScale = Math.sqrt(1_800_000 / Math.max(1, nextWidth * nextHeight));
      const deviceScale = Math.min(maximumScale, pixelBudgetScale);
      const backingWidth = Math.max(1, Math.round(nextWidth * deviceScale));
      const backingHeight = Math.max(1, Math.round(nextHeight * deviceScale));
      const geometryChanged = Math.abs(nextWidth - width) > 0.25
        || Math.abs(nextHeight - height) > 0.25;
      const backingChanged = canvas.width !== backingWidth || canvas.height !== backingHeight;
      if (!geometryChanged && !backingChanged && plan.waveParticleCount > 0) return;
      width = nextWidth;
      height = nextHeight;
      if (canvas.width !== backingWidth) canvas.width = backingWidth;
      if (canvas.height !== backingHeight) canvas.height = backingHeight;
      context.setTransform(deviceScale, 0, 0, deviceScale, 0, 0);
      plan = createGranularWavePlan(width, height, {
        ...targetModelRef.current,
        energy: 1,
        turbulence: 1,
        particleCount: 64,
      }, coarsePointer);
      motionHistory = createWaveMotionHistory(plan.waveParticleCount);
      frameIndex = 0;
      const now = performance.now();
      resetAnimationClock(now);
      render(now, true);
    };

    const paint = (now: number) => {
      if (disposed) return;
      if (canAnimate()) {
        advanceSimulation(now);
        if (shouldPaintEmotionFrame(now, lastPaintClock)) {
          render(now);
          lastPaintClock = advanceEmotionFrameClock(now, lastPaintClock);
        }
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      const wasReducedMotion = reducedMotion;
      reducedMotion = motionQuery?.matches ?? false;
      if (wasReducedMotion !== reducedMotion) {
        motionHistory = createWaveMotionHistory(plan.waveParticleCount);
        renderModel = targetModelRef.current;
        reducedModel = targetModelRef.current;
        renderModelRef.current = renderModel;
      }
      syncAnimationState();
      const now = performance.now();
      resetAnimationClock(now);
      if (
        !document.hidden
        && intersecting
        && !pausedRef.current
        && (reducedMotion || wasReducedMotion !== reducedMotion || now - lastRenderedAt > 100)
      ) {
        frameIndex = 0;
        render(now, true);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };
    restartAnimationRef.current = restart;
    const syncModel = () => {
      const targetModel = targetModelRef.current;
      if (!reducedMotion || reducedModel === targetModel) return;
      reducedModel = targetModel;
      renderModel = targetModel;
      renderModelRef.current = targetModel;
      motionHistory = createWaveMotionHistory(plan.waveParticleCount);
      frameIndex = 0;
      const now = performance.now();
      resetAnimationClock(now);
      if (!document.hidden && intersecting && !pausedRef.current) render(now, true);
    };
    syncModelRef.current = syncModel;
    const onVisibility = () => restart();
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
    motionQuery?.addEventListener?.('change', restart);
    resize();
    restart();

    return () => {
      disposed = true;
      motionClockRef.current = motionClock;
      renderModelRef.current = renderModel;
      if (restartAnimationRef.current === restart) restartAnimationRef.current = null;
      if (syncModelRef.current === syncModel) syncModelRef.current = null;
      window.cancelAnimationFrame(animationFrame);
      observer?.disconnect();
      intersectionObserver?.disconnect();
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
      motionQuery?.removeEventListener?.('change', restart);
    };
  }, []);

  useEffect(() => {
    syncModelRef.current?.();
  }, [model]);

  useEffect(() => {
    restartAnimationRef.current?.();
  }, [paused]);

  return (
    <section
      ref={rootRef}
      className="system-emotion-engine"
      role="img"
      aria-label={locale === 'ko' ? '현재 시스템 상태의 단색 앰버 입자 파동' : 'Monochrome amber grain wave of the current system state'}
      data-mood={model.mood}
    >
      <canvas
        ref={canvasRef}
        className="system-emotion-canvas"
        aria-hidden="true"
        data-renderer="monochrome-density-grain-wave"
      />
    </section>
  );
}
