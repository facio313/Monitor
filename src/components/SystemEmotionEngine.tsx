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

interface EmotionGeometry {
  width: number;
  height: number;
  compact: boolean;
  waveStart: number;
  waveWidth: number;
}

interface FlowState {
  transport: number;
  primaryCenter: number;
  secondaryCenter: number;
  troughCenter: number;
  primaryPulse: number;
  secondaryPulse: number;
  time: number;
}

interface SurfacePoint {
  y: number;
  crest: number;
}

interface SurfaceField {
  y: Float32Array;
  crest: Float32Array;
  sampleCount: number;
}

interface Vortex {
  u: number;
  v: number;
  radius: number;
  spin: number;
  hollow: number;
}

interface NormalizedPoint {
  u: number;
  v: number;
}

const TAU = Math.PI * 2;
const GOLDEN_RATIO_FRACTION = 0.6180339887498949;
const GRAIN_FILL_STYLE = `rgba(${MONOCHROME_GRAIN_STYLE.red}, ${MONOCHROME_GRAIN_STYLE.green}, ${MONOCHROME_GRAIN_STYLE.blue}, ${MONOCHROME_GRAIN_STYLE.alpha})`;
const BACKGROUND_COLOR = '#020100';
const FRAME_FADE_COLOR = 'rgba(2, 1, 0, 0.38)';
const COMPACT_FRAME_FADE_COLOR = 'rgba(2, 1, 0, 0.5)';

function clamp(value: number, minimum = 0, maximum = 1): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.max(minimum, Math.min(maximum, value));
}

function seeded(index: number, salt: number): number {
  const value = Math.sin(index * 91.733 + salt * 47.117) * 43758.5453;
  return value - Math.floor(value);
}

function wrap(value: number): number {
  return ((value % 1) + 1) % 1;
}

function signedWrappedDistance(value: number, center: number): number {
  return wrap(value - center + 0.5) - 0.5;
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

function createFlowState(time: number, model: SystemEmotionModel): FlowState {
  const transport = 0.031 + model.energy * 0.019 + model.turbulence * 0.012;
  const primaryCenter = wrap(
    0.14
      + time * transport
      + Math.sin(time * 0.11 + 0.35) * 0.018,
  );
  const secondaryCenter = wrap(
    primaryCenter
      + 0.49
      + Math.sin(time * 0.073 + 1.4) * 0.072,
  );
  return {
    transport,
    primaryCenter,
    secondaryCenter,
    troughCenter: wrap(primaryCenter + 0.285 + Math.sin(time * 0.09) * 0.035),
    primaryPulse: 0.75 + Math.sin(time * 0.58 + 0.45) * 0.2,
    secondaryPulse: 0.72 + Math.sin(time * 0.47 + 2.35) * 0.2,
    time,
  };
}

function sampleSurfacePoint(
  u: number,
  state: FlowState,
  model: SystemEmotionModel,
  compact: boolean,
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
      - state.time * (0.31 + model.energy * 0.13)
      + Math.sin(u * TAU * 0.83 + state.time * 0.12) * 0.72,
  ) * (0.014 + model.turbulence * 0.015);
  const frayedEdge = Math.sin(
    u * TAU * (8.8 + model.turbulence * 3.1)
      - state.time * (0.52 + model.turbulence * 0.28)
      + Math.sin(u * TAU * 3.15 - state.time * 0.19),
  ) * (0.005 + model.turbulence * 0.008);
  const crest = primary + forwardSheet + secondary + trailingRoll - trough + largeCurl + frayedEdge;
  const baseline = (compact ? 0.715 : 0.69) - model.energy * 0.018;
  return {
    y: clamp(baseline - crest, compact ? 0.24 : 0.2, 0.79),
    crest: clamp(crest, 0, 0.62),
  };
}

function createSurfaceField(
  state: FlowState,
  model: SystemEmotionModel,
  compact: boolean,
): SurfaceField {
  const sampleCount = compact ? 720 : 1_080;
  const y = new Float32Array(sampleCount);
  const crest = new Float32Array(sampleCount);
  for (let index = 0; index < sampleCount; index += 1) {
    const point = sampleSurfacePoint(index / sampleCount, state, model, compact);
    y[index] = point.y;
    crest[index] = point.crest;
  }
  return { y, crest, sampleCount };
}

function sampleSurfaceField(u: number, field: SurfaceField): SurfacePoint {
  const position = wrap(u) * field.sampleCount;
  const leftIndex = Math.floor(position) % field.sampleCount;
  const rightIndex = (leftIndex + 1) % field.sampleCount;
  const mix = position - Math.floor(position);
  return {
    y: field.y[leftIndex] + (field.y[rightIndex] - field.y[leftIndex]) * mix,
    crest: field.crest[leftIndex] + (field.crest[rightIndex] - field.crest[leftIndex]) * mix,
  };
}

function createVortices(state: FlowState, model: SystemEmotionModel, compact: boolean): Vortex[] {
  const primarySurface = sampleSurfacePoint(state.primaryCenter, state, model, compact).y;
  const secondarySurface = sampleSurfacePoint(state.secondaryCenter, state, model, compact).y;
  const trailingU = wrap(state.primaryCenter - 0.13);
  const trailingSurface = sampleSurfacePoint(trailingU, state, model, compact).y;
  const troughSurface = sampleSurfacePoint(state.troughCenter, state, model, compact).y;
  const innerRollU = wrap(state.primaryCenter + 0.205);
  const innerRollSurface = sampleSurfacePoint(innerRollU, state, model, compact).y;
  return [
    {
      u: wrap(state.primaryCenter + 0.045),
      v: primarySurface + 0.075,
      radius: 0.19 + model.turbulence * 0.035,
      spin: 1.62 + model.energy * 0.42,
      hollow: 0.012 + model.turbulence * 0.007,
    },
    {
      u: trailingU,
      v: trailingSurface + 0.12,
      radius: 0.135 + model.volatility * 0.04,
      spin: -1.05 - model.turbulence * 0.32,
      hollow: 0.009 + model.turbulence * 0.006,
    },
    {
      u: wrap(state.secondaryCenter - 0.025),
      v: secondarySurface + 0.09,
      radius: 0.16 + model.turbulence * 0.035,
      spin: -1.34 - model.energy * 0.34,
      hollow: 0.01 + model.volatility * 0.007,
    },
    {
      u: state.troughCenter,
      v: troughSurface + 0.18,
      radius: 0.105 + model.turbulence * 0.025,
      spin: 0.82 + model.turbulence * 0.3,
      hollow: 0.006 + model.volatility * 0.005,
    },
    {
      u: innerRollU,
      v: innerRollSurface + 0.23,
      radius: 0.09 + model.volatility * 0.025,
      spin: -0.74 - model.energy * 0.24,
      hollow: 0.005 + model.turbulence * 0.004,
    },
  ];
}

function warpByVortex(point: NormalizedPoint, vortex: Vortex): NormalizedPoint {
  const horizontal = signedWrappedDistance(point.u, vortex.u);
  const verticalScale = 0.82;
  const vertical = (point.v - vortex.v) * verticalScale;
  const distance = Math.hypot(horizontal, vertical);
  if (distance <= 0.0001 || distance >= vortex.radius) return point;

  const influence = Math.pow(1 - distance / vortex.radius, 2);
  const angle = vortex.spin * influence;
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  const radialScale = 1 + vortex.hollow * influence / Math.max(distance, 0.012);
  const rotatedHorizontal = (horizontal * cosine - vertical * sine) * radialScale;
  const rotatedVertical = (horizontal * sine + vertical * cosine) * radialScale;
  return {
    u: wrap(vortex.u + rotatedHorizontal),
    v: vortex.v + rotatedVertical / verticalScale,
  };
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
  const stateDensity = 0.89
    + model.energy * 0.11
    + model.turbulence * 0.16
    + clamp((model.particleCount - 14) / 50) * 0.05;
  const baseTarget = safeWidth * safeHeight / (compact ? 4.4 : 7.5);
  const minimum = compact ? 24_000 : coarsePointer ? 36_000 : 48_000;
  const maximum = compact ? 45_000 : coarsePointer ? 62_000 : 100_000;
  const waveParticleCount = Math.round(clamp(baseTarget * stateDensity, minimum, maximum));
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

  const sprayParticleCount = Math.round(
    waveParticleCount * (0.032 + model.turbulence * 0.06 + model.energy * 0.018),
  );
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
    waveParticleCount,
    sprayParticleCount,
    waveGrains,
    sprayGrains,
  };
}

function sampleWaveGrain(
  grain: GranularWaveSeed,
  state: FlowState,
  surfaceField: SurfaceField,
  vortices: Vortex[],
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
): NormalizedPoint {
  const axisIntensity = clamp(model.axes[grain.axisIndex]?.intensity ?? 0);
  let u = wrap(
    grain.baseU
      + state.time * state.transport * grain.speed
      + Math.sin(grain.phase + state.time * (0.13 + model.energy * 0.04))
        * (0.003 + model.turbulence * 0.004)
        * (1 - grain.depth),
  );
  const surface = sampleSurfaceField(u, surfaceField);
  const depthFlow = clamp(
    grain.depth
      + Math.sin(
        grain.phase
          + u * TAU * (1.7 + grain.curl * 0.24)
          - state.time * (0.21 + model.turbulence * 0.16),
      ) * (0.014 + model.turbulence * 0.026) * (1 - grain.depth),
  );
  let v = surface.y + Math.pow(depthFlow, 0.93) * (1.055 - surface.y);

  const broadFlow = grain.phase
    + u * TAU * 2.05
    + v * TAU * 1.27
    - state.time * (0.3 + model.energy * 0.17);
  const fineFlow = grain.phase * 0.63
    - u * TAU * 5.1
    + v * TAU * 3.35
    + state.time * (0.39 + model.turbulence * 0.24);
  const surfaceWeight = Math.pow(1 - depthFlow, 2.1);
  u = wrap(
    u
      + Math.sin(broadFlow) * (0.003 + model.turbulence * 0.0045)
      + Math.sin(fineFlow) * (0.0008 + model.turbulence * 0.0017) * surfaceWeight,
  );
  v += Math.cos(broadFlow + grain.curl) * (0.008 + model.turbulence * 0.012) * (0.35 + surfaceWeight);
  v += Math.cos(fineFlow) * (0.002 + model.turbulence * 0.0035) * surfaceWeight;

  const compression = Math.sin(
    u * TAU * 1.85
      - state.time * (0.38 + model.energy * 0.17)
      + v * TAU * 1.92
      + Math.sin(v * TAU * 2.35 + state.time * 0.21) * 0.82,
  ) + Math.sin(
    u * TAU * 4.15
      + state.time * (0.26 + model.turbulence * 0.19)
      - v * TAU * 3.05
      + Math.sin(u * TAU * 1.2 - state.time * 0.16) * 0.67,
  ) * 0.42;
  u = wrap(
    u
      + compression
        * (0.034 + model.turbulence * 0.014 + model.coherence * 0.007)
        * (1 - depthFlow * 0.62),
  );
  v += Math.cos(
    pointPhase(u, v, state.time, model.turbulence),
  ) * (0.002 + model.turbulence * 0.004) * Math.pow(1 - depthFlow, 1.22);

  let point = { u, v };
  for (const vortex of vortices) point = warpByVortex(point, vortex);

  const coherentBreakPhase = point.u * TAU * 3.35
    - state.time * (0.62 + model.turbulence * 0.34)
    + Math.sin(point.u * TAU * 1.17 - state.time * 0.18) * 1.1;
  const edgeBreak = Math.max(
    0,
    Math.sin(coherentBreakPhase) * 0.78
      + Math.sin(grain.phase - state.time * 0.51) * 0.22,
  );
  point.u = wrap(
    point.u
      + Math.cos(coherentBreakPhase)
        * surfaceWeight
        * surface.crest
        * (0.006 + model.turbulence * 0.012),
  );
  point.v -= edgeBreak
    * surfaceWeight
    * surface.crest
    * (0.018 + model.turbulence * 0.052 + axisIntensity * 0.008);
  point.v = clamp(point.v, 0.08, 1.08);
  return point;
}

function sampleSprayGrain(
  grain: SprayGrainSeed,
  state: FlowState,
  surfaceField: SurfaceField,
  model: SystemEmotionModel,
  geometry: EmotionGeometry,
): NormalizedPoint | null {
  const cycle = wrap(
    grain.cycle
      + state.time * (0.047 + model.energy * 0.018 + model.turbulence * 0.024),
  );
  const activeWindow = 0.34 + model.turbulence * 0.08;
  if (cycle >= activeWindow) return null;

  const progress = cycle / activeWindow;
  const sourceU = wrap(
    grain.baseU
      + state.time * state.transport * 0.9
      + Math.sin(grain.phase + state.time * 0.17) * 0.006,
  );
  const surface = sampleSurfaceField(sourceU, surfaceField);
  const crestGate = clamp((surface.crest - 0.055) / 0.28);
  if (grain.activation > crestGate * (0.34 + model.turbulence * 0.46)) return null;

  const arc = Math.sin(progress * Math.PI);
  const horizontal = progress
    * (0.035 + model.turbulence * 0.055)
    * grain.spread
    * grain.direction;
  const lift = arc
    * (0.035 + model.turbulence * 0.085 + model.energy * 0.025)
    * grain.lift
    * (0.5 + crestGate * 0.5);
  return {
    u: wrap(
      sourceU
        + horizontal
        + Math.sin(grain.phase + progress * TAU) * (0.002 + model.turbulence * 0.005),
    ),
    v: clamp(
      surface.y
        - lift
        + progress * progress * (0.012 + model.turbulence * 0.018)
        + Math.cos(grain.phase + progress * TAU * 1.2) * 0.003,
      0.06,
      1.04,
    ),
  };
}

function drawGrain(
  context: CanvasRenderingContext2D,
  geometry: EmotionGeometry,
  point: NormalizedPoint,
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
  reducedMotion: boolean,
  resetFrame = false,
) {
  const time = reducedMotion ? 2.1 : elapsedSeconds;
  const geometry = emotionGeometry(width, height);
  const state = createFlowState(time, model);
  const surfaceField = createSurfaceField(state, model, geometry.compact);
  const vortices = createVortices(state, model, geometry.compact);

  context.globalAlpha = 1;
  context.globalCompositeOperation = MONOCHROME_GRAIN_STYLE.compositeOperation;
  context.fillStyle = resetFrame
    ? BACKGROUND_COLOR
    : geometry.compact ? COMPACT_FRAME_FADE_COLOR : FRAME_FADE_COLOR;
  context.fillRect(0, 0, width, height);

  context.fillStyle = GRAIN_FILL_STYLE;
  for (const grain of plan.waveGrains) {
    drawGrain(
      context,
      geometry,
      sampleWaveGrain(grain, state, surfaceField, vortices, model, geometry),
    );
  }
  for (const grain of plan.sprayGrains) {
    const point = sampleSprayGrain(grain, state, surfaceField, model, geometry);
    if (point) drawGrain(context, geometry, point);
  }
}

export function SystemEmotionEngine({ locale, model, paused = false }: SystemEmotionEngineProps) {
  const rootRef = useRef<HTMLElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const originRef = useRef<number | null>(null);

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
    let width = 1;
    let height = 1;
    let lastPaint = 0;
    let intersecting = true;
    let plan: GranularWavePlan = {
      compact: true,
      waveParticleCount: 0,
      sprayParticleCount: 0,
      waveGrains: [],
      sprayGrains: [],
    };
    if (originRef.current === null) originRef.current = performance.now();
    const origin = originRef.current;

    const canAnimate = () => !reducedMotion && !document.hidden && intersecting && !paused;
    const syncAnimationState = () => {
      root.dataset.animationPaused = canAnimate() ? 'false' : 'true';
    };

    const render = (now: number, resetFrame = false) => {
      drawEmotionField(
        context,
        width,
        height,
        (now - origin) / 1_000,
        model,
        plan,
        reducedMotion,
        resetFrame,
      );
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
      render(performance.now(), true);
    };

    const paint = (now: number) => {
      if (disposed) return;
      if (canAnimate() && now - lastPaint >= 42) {
        lastPaint = now;
        render(now);
      }
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };

    const restart = () => {
      window.cancelAnimationFrame(animationFrame);
      reducedMotion = motionQuery?.matches ?? false;
      syncAnimationState();
      if (!document.hidden && intersecting && !paused) render(performance.now(), reducedMotion);
      if (canAnimate()) animationFrame = window.requestAnimationFrame(paint);
    };
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
      window.cancelAnimationFrame(animationFrame);
      observer?.disconnect();
      intersectionObserver?.disconnect();
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
      motionQuery?.removeEventListener?.('change', restart);
    };
  }, [model, paused]);

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
