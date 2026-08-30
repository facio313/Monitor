import { useEffect, useRef, type CSSProperties } from 'react';
import type { SystemEmotionModel } from '../system-emotion';
import type { MonitorLocale } from '../types';

interface SystemEmotionEngineProps {
  locale: MonitorLocale;
  model: SystemEmotionModel;
  paused?: boolean;
}

type PointerField = {
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  active: boolean;
};

export type ParticleTone = 0 | 1 | 2 | 3;

export interface GranularWaveSeed {
  axisIndex: number;
  baseU: number;
  depth: number;
  phase: number;
  radius: number;
  flutter: number;
  drift: number;
  direction: -1 | 1;
  occupancy: number;
  glow: boolean;
  tone: ParticleTone;
  lightTier: 0 | 1 | 2;
}

interface SprayGrainSeed {
  baseU: number;
  cycle: number;
  lift: number;
  spread: number;
  radius: number;
  phase: number;
  drift: number;
  direction: -1 | 1;
  tone: ParticleTone;
  lightTier: 0 | 1 | 2;
}

export interface GranularWavePlan {
  compact: boolean;
  strataPerAxis: number;
  strandCount: number;
  columnCount: number;
  waveParticleCount: number;
  sprayParticleCount: number;
  waveBuckets: GranularWaveSeed[][];
  sprayBuckets: SprayGrainSeed[][];
}

interface EmotionGeometry {
  width: number;
  height: number;
  compact: boolean;
  top: number;
  bottom: number;
  waveStart: number;
  waveEnd: number;
}

interface SurfacePoint {
  y: number;
  crest: number;
}

interface WavePoint extends SurfacePoint {
  x: number;
  depth: number;
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
  return 'rgba(' + red + ', ' + green + ', ' + blue + ', ' + clamp(alpha) + ')';
}

function seeded(index: number, salt: number): number {
  const value = Math.sin(index * 91.733 + salt * 47.117) * 43758.5453;
  return value - Math.floor(value);
}

const TAU = Math.PI * 2;
const PARTICLE_TONE_COUNT = 4;
const PARTICLE_LIGHT_TIERS = 3;
const PARTICLE_BUCKET_COUNT = PARTICLE_TONE_COUNT * PARTICLE_LIGHT_TIERS;
const AMBER_TONES: Record<ParticleTone, string> = {
  0: '#7a2400',
  1: '#d84d00',
  2: '#ff8b08',
  3: '#ffd26a',
};

function wrap(value: number): number {
  return ((value % 1) + 1) % 1;
}

function lerp(start: number, end: number, amount: number): number {
  return start + (end - start) * amount;
}

function toneColor(tone: ParticleTone): string {
  return AMBER_TONES[tone];
}

function bucketIndex(tone: ParticleTone, lightTier: 0 | 1 | 2): number {
  return tone * PARTICLE_LIGHT_TIERS + lightTier;
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
  const strataPerAxis = compact ? 5 : 6;
  const strandCount = Math.max(1, model.axes.length * strataPerAxis);
  const stateDensity = 0.9
    + model.energy * 0.08
    + model.turbulence * 0.08
    + clamp((model.particleCount - 14) / 50) * 0.04;
  const desktopFloor = 4_700 + clamp((safeWidth - 760) / 600) * 900;
  const baseMinimum = compact ? 2_100 : coarsePointer ? 3_000 : desktopFloor;
  const minimum = Math.round(baseMinimum * (0.94 + model.energy * 0.04 + model.turbulence * 0.05));
  const maximum = compact ? 3_200 : coarsePointer ? 4_200 : 7_400;
  const target = Math.round(clamp((safeWidth * safeHeight / 105) * stateDensity, minimum, maximum));
  const columnCount = Math.max(1, Math.ceil(target / strandCount));
  const waveBuckets = Array.from({ length: PARTICLE_BUCKET_COUNT }, () => [] as GranularWaveSeed[]);

  for (let axisIndex = 0; axisIndex < model.axes.length; axisIndex += 1) {
    const axis = model.axes[axisIndex];
    for (let stratum = 0; stratum < strataPerAxis; stratum += 1) {
      const strandIndex = axisIndex * strataPerAxis + stratum;
      const depthBase = strandCount > 1 ? strandIndex / (strandCount - 1) : 0.5;
      for (let column = 0; column < columnCount; column += 1) {
        const index = strandIndex * columnCount + column;
        const depth = clamp(depthBase + (seeded(index, 15) - 0.5) / strandCount * 3.2);
        const toneSeed = seeded(index, 8);
        const dominantHighlight = axis.key === model.dominantAxis && toneSeed < 0.2;
        const surfaceHighlight = depth < 0.18 && toneSeed > 0.7;
        const tone: ParticleTone = dominantHighlight || surfaceHighlight
          ? 3
          : toneSeed < 0.08 ? 0 : toneSeed < 0.4 ? 1 : 2;
        const tierSeed = (1 - depth) * 0.52 + seeded(index, 9) * 0.48;
        const lightTier: 0 | 1 | 2 = tierSeed > 0.73 ? 2 : tierSeed > 0.35 ? 1 : 0;
        const grain: GranularWaveSeed = {
          axisIndex,
          baseU: (column + seeded(index, 1) * 0.94) / columnCount,
          depth,
          phase: seeded(index, 2) * TAU,
          radius: (0.48 + seeded(index, 4) * 1.24 + depth * 0.68 + model.energy * 0.12)
            * (compact ? 0.88 : 1),
          flutter: seeded(index, 5) * TAU,
          drift: 0.004 + seeded(index, 10) * 0.011 + model.energy * 0.003,
          direction: seeded(index, 11) < 0.74 ? 1 : -1,
          occupancy: seeded(index, 6),
          glow: seeded(index, 7) < 0.025 + model.turbulence * 0.025,
          tone,
          lightTier,
        };
        waveBuckets[bucketIndex(tone, lightTier)].push(grain);
      }
    }
  }

  const waveParticleCount = strandCount * columnCount;
  const sprayParticleCount = Math.round(waveParticleCount * (0.1 + model.turbulence * 0.1));
  const sprayBuckets = Array.from({ length: PARTICLE_BUCKET_COUNT }, () => [] as SprayGrainSeed[]);
  for (let index = 0; index < sprayParticleCount; index += 1) {
    const toneSeed = seeded(index, 23);
    const tone: ParticleTone = toneSeed < 0.08 ? 0 : toneSeed < 0.42 ? 1 : toneSeed < 0.87 ? 2 : 3;
    const lightTier: 0 | 1 | 2 = seeded(index, 24) > 0.72 ? 2 : seeded(index, 25) > 0.3 ? 1 : 0;
    const direction: -1 | 1 = seeded(index, 31) < 0.62 ? 1 : -1;
    sprayBuckets[bucketIndex(tone, lightTier)].push({
      baseU: seeded(index, 26),
      cycle: seeded(index, 27),
      lift: 0.48 + seeded(index, 28) * 1.08,
      spread: 0.48 + seeded(index, 29) * 1.16,
      radius: 0.52 + seeded(index, 30) * 1.5 + model.turbulence * 0.28,
      phase: seeded(index, 32) * TAU,
      drift: 0.003 + seeded(index, 33) * 0.009,
      direction,
      tone,
      lightTier,
    });
  }

  return {
    compact,
    strataPerAxis,
    strandCount,
    columnCount,
    waveParticleCount,
    sprayParticleCount,
    waveBuckets,
    sprayBuckets,
  };
}

function emotionGeometry(width: number, height: number): EmotionGeometry {
  const compact = width <= 640;
  return {
    width,
    height,
    compact,
    top: height * (compact ? 0.075 : 0.055),
    bottom: height * (compact ? 0.965 : 0.975),
    waveStart: width * -0.07,
    waveEnd: width * 1.07,
  };
}

function wrappedDistance(left: number, right: number): number {
  const distance = Math.abs(left - right);
  return Math.min(distance, 1 - distance);
}

function bell(value: number, center: number, spread: number): number {
  const distance = wrappedDistance(value, center) / Math.max(0.001, spread);
  return Math.exp(-0.5 * distance * distance);
}

function crestCenters(time: number): [number, number, number] {
  return [
    0.245 + Math.sin(time * 0.12) * 0.048 + Math.sin(time * 0.037 + 0.8) * 0.018,
    0.775 + Math.sin(time * 0.095 + 2.1) * 0.058,
    0.51 + Math.sin(time * 0.073 + 0.45) * 0.105,
  ];
}

function sampleSurfacePoint(
  u: number,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
): SurfacePoint {
  const [leftCenter, rightCenter, rogueCenter] = crestCenters(time);
  const tempo = TAU / Math.max(2.8, model.tempoSeconds);
  const leftPeak = bell(u, leftCenter, 0.105 + model.coherence * 0.018)
    * (0.76 + Math.sin(time * tempo * 0.38 + 0.5) * 0.13);
  const leftShoulder = bell(u, leftCenter - 0.095, 0.075) * 0.27;
  const rightPeak = bell(u, rightCenter, 0.135 + model.coherence * 0.02)
    * (0.72 + Math.sin(time * tempo * 0.33 + 2.2) * 0.15);
  const rightShoulder = bell(u, rightCenter + 0.105, 0.082) * 0.25;
  const roguePulse = 0.5 + Math.sin(time * (0.29 + model.energy * 0.14) + 1.3) * 0.5;
  const rogue = bell(u, rogueCenter, 0.055 + model.turbulence * 0.035)
    * roguePulse
    * (0.06 + model.turbulence * 0.31);
  const travel = Math.sin(u * TAU * 1.82 - time * (0.2 + model.energy * 0.13)) * 0.085
    + Math.sin(u * TAU * 4.65 + time * 0.27 + Math.sin(time * 0.11)) * 0.045;
  const edgeBreakup = Math.sin(
    u * TAU * (8.6 + model.turbulence * 3.4)
      + time * (0.43 + model.turbulence * 0.31)
      + Math.sin(u * TAU * 2.2 - time * 0.17) * 0.9,
  ) * (0.022 + model.turbulence * 0.068 + model.volatility * 0.026);
  const crest = clamp(
    0.09
      + leftPeak
      + leftShoulder
      + rightPeak
      + rightShoulder
      + rogue
      + travel
      + edgeBreakup,
    0.025,
    1.45,
  );
  const baseSurface = geometry.height * (
    (geometry.compact ? 0.665 : 0.65)
    - model.energy * 0.025
  );
  const rise = geometry.height * (
    0.275
    + model.waveAmplitude * 0.07
    + model.turbulence * 0.035
  );
  return {
    y: clamp(baseSurface - crest * rise, geometry.top, geometry.bottom - geometry.height * 0.16),
    crest,
  };
}

function sampleWavePoint(
  grain: GranularWaveSeed,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  pointer: PointerField,
): WavePoint {
  const axisIntensity = clamp(model.axes[grain.axisIndex]?.intensity ?? 0);
  const flow = time * grain.drift * grain.direction;
  const advectedU = wrap(
    grain.baseU
      + flow
      + Math.sin(grain.flutter + time * 0.13 + grain.depth * 4.8) * (0.002 + model.turbulence * 0.004),
  );
  const waveWidth = geometry.waveEnd - geometry.waveStart;
  const curlPhase = grain.phase
    + advectedU * TAU * (2.25 + grain.axisIndex * 0.075)
    - time * (0.19 + model.energy * 0.18) * grain.direction;
  const surface = sampleSurfacePoint(advectedU, time, model, geometry);
  const surfaceWeight = Math.pow(1 - grain.depth, 1.6);
  const curlStrength = (
    3
    + model.turbulence * 18
    + model.volatility * 8
    + axisIntensity * 4
  ) * surfaceWeight;
  let x = geometry.waveStart
    + advectedU * waveWidth
    + Math.sin(curlPhase + Math.cos(grain.flutter + time * 0.21)) * curlStrength;
  const depthTravel = Math.pow(grain.depth, 1.08);
  const bodyY = lerp(surface.y, geometry.bottom + geometry.height * 0.035, depthTravel);
  const curlY = Math.cos(curlPhase * 1.31 - grain.flutter + Math.sin(time * 0.16)) * curlStrength * 0.68;
  const liftPulse = Math.max(
    0,
    Math.sin(grain.flutter + time * (0.31 + model.turbulence * 0.34) - advectedU * TAU * 2.15),
  );
  const lift = liftPulse
    * surface.crest
    * surfaceWeight
    * (4 + model.turbulence * 24 + model.energy * 7);
  let y = bodyY
    + curlY
    - lift
    + (grain.occupancy - 0.5) * (2 + grain.depth * 8);

  if (pointer.active) {
    const pointerX = pointer.x * geometry.width;
    const pointerY = pointer.y * geometry.height;
    const deltaX = x - pointerX;
    const deltaY = y - pointerY;
    const influenceRadius = geometry.compact ? 62 : 96;
    const distance = Math.hypot(deltaX, deltaY);
    if (distance > 0 && distance < influenceRadius) {
      const force = Math.pow(1 - distance / influenceRadius, 2) * (7 + model.energy * 11);
      x += (deltaX / distance) * force;
      y += (deltaY / distance) * force;
    }
  }

  return { x, y, crest: surface.crest, depth: grain.depth };
}

function waveSilhouette(
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  inset = 0,
): Path2D {
  const path = new Path2D();
  const samples = geometry.compact ? 70 : 112;
  path.moveTo(geometry.waveStart, geometry.bottom + geometry.height * 0.08);
  for (let index = 0; index <= samples; index += 1) {
    const u = index / samples;
    const x = geometry.waveStart + u * (geometry.waveEnd - geometry.waveStart);
    const surface = sampleSurfacePoint(u, time, model, geometry);
    path.lineTo(x, lerp(surface.y, geometry.bottom, inset));
  }
  path.lineTo(geometry.waveEnd, geometry.bottom + geometry.height * 0.08);
  path.closePath();
  return path;
}

function waveBand(
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  outerInset: number,
  innerInset: number,
): Path2D {
  const path = new Path2D();
  const samples = geometry.compact ? 70 : 112;
  for (let index = 0; index <= samples; index += 1) {
    const u = index / samples;
    const x = geometry.waveStart + u * (geometry.waveEnd - geometry.waveStart);
    const surface = sampleSurfacePoint(u, time, model, geometry);
    const y = lerp(surface.y, geometry.bottom, outerInset);
    if (index === 0) path.moveTo(x, y);
    else path.lineTo(x, y);
  }
  for (let index = samples; index >= 0; index -= 1) {
    const u = index / samples;
    const x = geometry.waveStart + u * (geometry.waveEnd - geometry.waveStart);
    const surface = sampleSurfacePoint(u, time, model, geometry);
    path.lineTo(x, lerp(surface.y, geometry.bottom, innerInset));
  }
  path.closePath();
  return path;
}

function drawAmberVolume(
  context: CanvasRenderingContext2D,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
) {
  const hazeSilhouette = waveSilhouette(time, model, geometry);
  const bodySilhouette = waveSilhouette(time, model, geometry, 0.18);
  context.save();
  context.globalCompositeOperation = 'screen';
  context.filter = 'blur(' + Math.round(geometry.compact ? 16 : 24) + 'px)';
  context.fillStyle = rgba('#ff6800', 0.16 + model.energy * 0.065 + model.turbulence * 0.045);
  context.fill(hazeSilhouette);
  context.restore();

  context.save();
  context.filter = 'blur(6px)';
  const body = context.createLinearGradient(0, geometry.top, 0, geometry.bottom);
  body.addColorStop(0, rgba('#ffc04f', 0.13 + model.energy * 0.04));
  body.addColorStop(0.34, rgba('#ff7905', 0.19 + model.energy * 0.05));
  body.addColorStop(0.7, rgba('#dc4700', 0.32 + model.turbulence * 0.045));
  body.addColorStop(1, rgba('#9b2500', 0.62));
  context.fillStyle = body;
  context.fill(bodySilhouette);
  context.restore();

  context.save();
  context.globalCompositeOperation = 'screen';
  const layerTones = ['#ffd67a', '#ffb12e', '#ff8808', '#ef5b00', '#ca3b00'] as const;
  for (let layer = 0; layer < layerTones.length; layer += 1) {
    const depth = 0.025 + layer * 0.036;
    const layerPath = waveBand(
      time + layer * 0.43,
      model,
      geometry,
      depth,
      depth + 0.13,
    );
    context.filter = 'blur(' + (2 + layer * 1.4).toFixed(1) + 'px)';
    context.fillStyle = rgba(
      layerTones[layer],
      0.055 + (layerTones.length - layer) * 0.011 + model.energy * 0.01,
    );
    context.fill(layerPath);
  }
  context.filter = 'none';
  const [leftCenter, rightCenter] = crestCenters(time);
  for (const center of [leftCenter, rightCenter]) {
    const surface = sampleSurfacePoint(center, time, model, geometry);
    const x = geometry.waveStart + center * (geometry.waveEnd - geometry.waveStart);
    const radius = Math.min(
      geometry.width * (geometry.compact ? 0.28 : 0.2),
      geometry.height * 0.62,
    );
    const glow = context.createRadialGradient(x, surface.y + radius * 0.18, 1, x, surface.y + radius * 0.18, radius);
    glow.addColorStop(0, rgba('#ffe3a0', 0.34 + model.energy * 0.085));
    glow.addColorStop(0.22, rgba('#ff9c19', 0.25 + model.energy * 0.065));
    glow.addColorStop(0.62, rgba('#e34b00', 0.075));
    glow.addColorStop(1, rgba('#7a1d00', 0));
    context.fillStyle = glow;
    context.fillRect(x - radius, surface.y - radius * 0.82, radius * 2, radius * 2);
  }

  for (let layer = 1; layer <= 5; layer += 1) {
    const depth = layer / 6;
    const ribbon = new Path2D();
    const samples = geometry.compact ? 56 : 88;
    for (let index = 0; index <= samples; index += 1) {
      const u = index / samples;
      const surface = sampleSurfacePoint(u, time, model, geometry);
      const x = geometry.waveStart + u * (geometry.waveEnd - geometry.waveStart);
      const y = lerp(surface.y, geometry.bottom, depth)
        + Math.sin(u * TAU * (2.4 + layer * 0.37) - time * (0.12 + layer * 0.025)) * (3 + depth * 7);
      if (index === 0) ribbon.moveTo(x, y);
      else ribbon.lineTo(x, y);
    }
    context.strokeStyle = rgba(layer <= 2 ? '#ff9b18' : '#c74400', 0.035 + (1 - depth) * 0.045);
    context.lineWidth = 0.65 + depth * 1.15;
    context.stroke(ribbon);
  }
  context.restore();
}

function drawParticleWave(
  context: CanvasRenderingContext2D,
  plan: GranularWavePlan,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
  pointer: PointerField,
) {
  context.save();
  context.globalCompositeOperation = 'screen';
  const bodyMistPath = new Path2D();
  const surfaceMistPath = new Path2D();
  const renderedBuckets: Array<{
    tone: ParticleTone;
    lightTier: number;
    glowPath: Path2D;
    particlePath: Path2D;
  }> = [];
  for (let index = 0; index < plan.waveBuckets.length; index += 1) {
    const bucket = plan.waveBuckets[index];
    if (!bucket.length) continue;
    const tone = Math.floor(index / PARTICLE_LIGHT_TIERS) as ParticleTone;
    const lightTier = index % PARTICLE_LIGHT_TIERS;
    const glowPath = new Path2D();
    const particlePath = new Path2D();
    for (const grain of bucket) {
      const point = sampleWavePoint(grain, time, model, geometry, pointer);
      const pulse = 0.93 + Math.sin(time * 0.48 + grain.flutter) * 0.07;
      const radius = Math.max(
        0.3,
        grain.radius
          * (0.82 + point.depth * 0.42)
          * pulse
          * (0.86 + grain.occupancy * 0.2),
      );
      particlePath.moveTo(point.x + radius, point.y);
      particlePath.arc(point.x, point.y, radius, 0, TAU);
      if (grain.depth < 0.34 && grain.occupancy < 0.64) {
        const mistRadius = radius * (3.6 + (1 - grain.depth) * 2.4);
        surfaceMistPath.moveTo(point.x + mistRadius, point.y);
        surfaceMistPath.arc(point.x, point.y, mistRadius, 0, TAU);
      }
      if (grain.depth > 0.18 && grain.depth < 0.88 && grain.occupancy < 0.22) {
        const bodyMistRadius = radius * (2.7 + (1 - grain.depth) * 1.5);
        bodyMistPath.moveTo(point.x + bodyMistRadius, point.y);
        bodyMistPath.arc(point.x, point.y, bodyMistRadius, 0, TAU);
      }
      if (grain.glow) {
        const glowRadius = radius * (2.5 + model.energy * 0.8);
        glowPath.moveTo(point.x + glowRadius, point.y);
        glowPath.arc(point.x, point.y, glowRadius, 0, TAU);
      }
    }
    renderedBuckets.push({ tone, lightTier, glowPath, particlePath });
  }

  context.save();
  context.filter = 'blur(4px)';
  context.fillStyle = rgba('#d84d00', 0.055 + model.turbulence * 0.018);
  context.fill(bodyMistPath);
  context.restore();
  context.save();
  context.filter = 'blur(3px)';
  context.fillStyle = rgba('#ff9b18', 0.1 + model.energy * 0.032);
  context.fill(surfaceMistPath);
  context.restore();

  for (const rendered of renderedBuckets) {
    const { tone, lightTier, glowPath, particlePath } = rendered;
    const color = toneColor(tone);
    context.fillStyle = rgba(color, 0.035 + lightTier * 0.02 + model.energy * 0.018);
    context.fill(glowPath);
    context.shadowColor = lightTier === 2 ? rgba(color, 0.34) : 'transparent';
    context.shadowBlur = lightTier === 2 ? 4 : 0;
    context.fillStyle = rgba(
      color,
      0.27
        + lightTier * 0.145
        + model.energy * 0.065
        + model.turbulence * 0.035,
    );
    context.fill(particlePath);
  }
  context.restore();
}

function drawSurfaceSpray(
  context: CanvasRenderingContext2D,
  plan: GranularWavePlan,
  time: number,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
) {
  context.save();
  context.globalCompositeOperation = 'screen';
  const sprayHazePath = new Path2D();
  const renderedBuckets: Array<{
    tone: ParticleTone;
    lightTier: number;
    path: Path2D;
  }> = [];
  for (let index = 0; index < plan.sprayBuckets.length; index += 1) {
    const bucket = plan.sprayBuckets[index];
    if (!bucket.length) continue;
    const tone = Math.floor(index / PARTICLE_LIGHT_TIERS) as ParticleTone;
    const lightTier = index % PARTICLE_LIGHT_TIERS;
    const path = new Path2D();
    for (const grain of bucket) {
      const u = wrap(grain.baseU + time * grain.drift * grain.direction);
      const surface = sampleSurfacePoint(u, time, model, geometry);
      const cycle = wrap(
        grain.cycle
          + time * (0.026 + model.energy * 0.018 + model.turbulence * 0.024),
      );
      const arc = Math.sin(cycle * Math.PI);
      const crestGate = clamp((surface.crest - 0.08) / 0.82);
      const lift = arc
        * (24 + geometry.height * (0.09 + model.turbulence * 0.15))
        * grain.lift
        * (0.28 + crestGate * 0.72);
      const spread = (cycle - 0.32)
        * (22 + model.turbulence * 54)
        * grain.spread
        * grain.direction;
      const x = geometry.waveStart
        + u * (geometry.waveEnd - geometry.waveStart)
        + spread
        + Math.sin(grain.phase + cycle * TAU) * (3 + model.turbulence * 8);
      const y = surface.y
        - lift
        + Math.cos(grain.phase + cycle * TAU * 1.4) * (2 + model.turbulence * 6)
        + cycle * geometry.height * 0.025;
      const fade = Math.pow(1 - cycle, 0.34);
      const radius = Math.max(0.28, grain.radius * (0.52 + fade * 0.7));
      path.moveTo(x + radius, y);
      path.arc(x, y, radius, 0, TAU);
      if (grain.lightTier === 2 && crestGate > 0.38) {
        const hazeRadius = radius * 4.2;
        sprayHazePath.moveTo(x + hazeRadius, y);
        sprayHazePath.arc(x, y, hazeRadius, 0, TAU);
      }
    }
    renderedBuckets.push({ tone, lightTier, path });
  }

  context.save();
  context.filter = 'blur(5px)';
  context.fillStyle = rgba('#ff8b08', 0.055 + model.turbulence * 0.045);
  context.fill(sprayHazePath);
  context.restore();

  for (const rendered of renderedBuckets) {
    const { tone, lightTier, path } = rendered;
    const color = toneColor(tone);
    context.shadowColor = lightTier === 2 ? rgba(color, 0.28) : 'transparent';
    context.shadowBlur = lightTier === 2 ? 5 : 0;
    context.fillStyle = rgba(
      color,
      0.22 + lightTier * 0.15 + model.turbulence * 0.17 + model.energy * 0.055,
    );
    context.fill(path);
  }
  context.restore();
}

function drawVignette(context: CanvasRenderingContext2D, geometry: EmotionGeometry) {
  context.save();
  const topShade = context.createLinearGradient(0, 0, 0, geometry.height);
  topShade.addColorStop(0, 'rgba(0, 0, 0, 0.54)');
  topShade.addColorStop(0.22, 'rgba(0, 0, 0, 0.12)');
  topShade.addColorStop(0.68, 'rgba(0, 0, 0, 0)');
  topShade.addColorStop(1, 'rgba(0, 0, 0, 0.18)');
  context.fillStyle = topShade;
  context.fillRect(0, 0, geometry.width, geometry.height);

  const edgeShade = context.createRadialGradient(
    geometry.width * 0.5,
    geometry.height * 0.6,
    Math.min(geometry.width, geometry.height) * 0.24,
    geometry.width * 0.5,
    geometry.height * 0.58,
    Math.max(geometry.width, geometry.height) * 0.72,
  );
  edgeShade.addColorStop(0, 'rgba(0, 0, 0, 0)');
  edgeShade.addColorStop(0.68, 'rgba(0, 0, 0, 0.05)');
  edgeShade.addColorStop(1, 'rgba(0, 0, 0, 0.72)');
  context.fillStyle = edgeShade;
  context.fillRect(0, 0, geometry.width, geometry.height);
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
  const time = reducedMotion ? 2.75 : elapsedSeconds;
  const geometry = emotionGeometry(width, height);
  if (pointer.active && !reducedMotion) {
    pointer.x += (pointer.targetX - pointer.x) * 0.13;
    pointer.y += (pointer.targetY - pointer.y) * 0.13;
  }

  context.clearRect(0, 0, width, height);
  const backdrop = context.createLinearGradient(0, 0, 0, height);
  backdrop.addColorStop(0, '#010101');
  backdrop.addColorStop(0.48, '#050200');
  backdrop.addColorStop(1, '#0a0200');
  context.fillStyle = backdrop;
  context.fillRect(0, 0, width, height);

  drawAmberVolume(context, time, model, geometry);
  drawParticleWave(context, plan, time, model, geometry, pointer);
  drawSurfaceSpray(context, plan, time, model, geometry);
  drawVignette(context, geometry);
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
    '--emotion-tempo': model.tempoSeconds.toFixed(2) + 's',
    '--emotion-turbulence': model.turbulence.toFixed(3),
  } as CSSProperties;
}

export function SystemEmotionEngine({ locale, model, paused = false }: SystemEmotionEngineProps) {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pointerRef = useRef<PointerField>({
    x: 0.5,
    y: 0.5,
    targetX: 0.5,
    targetY: 0.5,
    active: false,
  });
  const originRef = useRef<number | null>(null);
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
      const maximumScale = Math.min(window.devicePixelRatio || 1, coarsePointer ? 1.2 : 1.5);
      const pixelBudgetScale = Math.sqrt(1_800_000 / Math.max(1, width * height));
      const deviceScale = Math.min(maximumScale, pixelBudgetScale);
      const backingWidth = Math.max(1, Math.round(width * deviceScale));
      const backingHeight = Math.max(1, Math.round(height * deviceScale));
      if (canvas.width !== backingWidth) canvas.width = backingWidth;
      if (canvas.height !== backingHeight) canvas.height = backingHeight;
      context.setTransform(deviceScale, 0, 0, deviceScale, 0, 0);
      plan = createGranularWavePlan(width, height, model, coarsePointer);
      drawEmotionField(
        context,
        width,
        height,
        (performance.now() - origin) / 1_000,
        model,
        plan,
        pointerRef.current,
        reducedMotion,
      );
    };

    const paint = (now: number) => {
      if (disposed) return;
      if (canAnimate() && now - lastPaint >= 42) {
        lastPaint = now;
        drawEmotionField(
          context,
          width,
          height,
          (now - origin) / 1_000,
          model,
          plan,
          pointerRef.current,
          reducedMotion,
        );
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      reducedMotion = motionQuery?.matches ?? false;
      syncAnimationState();
      if (!document.hidden && intersecting && !paused) {
        drawEmotionField(
          context,
          width,
          height,
          (performance.now() - origin) / 1_000,
          model,
          plan,
          pointerRef.current,
          reducedMotion,
        );
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };
    const onVisibility = () => restart();
    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') return;
      const bounds = root.getBoundingClientRect();
      const nextX = clamp((event.clientX - bounds.left) / Math.max(1, bounds.width));
      const nextY = clamp((event.clientY - bounds.top) / Math.max(1, bounds.height));
      const pointer = pointerRef.current;
      if (!pointer.active) {
        pointer.x = nextX;
        pointer.y = nextY;
      }
      pointer.targetX = nextX;
      pointer.targetY = nextY;
      pointer.active = true;
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
      className="system-emotion-engine"
      style={emotionThemeStyle(model)}
      role="img"
      aria-label={locale === 'ko' ? '현재 시스템 상태의 앰버 입자 유체 파동' : 'Amber particle-fluid wave of the current system state'}
      data-mood={model.mood}
    >
      <canvas
        ref={canvasRef}
        className="system-emotion-canvas"
        aria-hidden="true"
        data-renderer="amber-fluid-particle-wave"
      />
    </section>
  );
}
