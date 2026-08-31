import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from '../system-emotion';
import {
  advanceGranularMotionClock,
  advanceEmotionFrameClock,
  blendGranularMotionModel,
  constrainGranularMotionStep,
  createGranularWavePlan,
  emotionFrameFadeAlpha,
  GRAIN_MOTION_PROFILE,
  MONOCHROME_GRAIN_STYLE,
  reflectCeilingOvershoot,
  sampleGranularWaveFrame,
  shouldPaintEmotionFrame,
  SystemEmotionEngine,
} from './SystemEmotionEngine';

const wrappedDelta = (from: number, to: number) => {
  let delta = to - from;
  if (delta > 0.5) delta -= 1;
  else if (delta < -0.5) delta += 1;
  return delta;
};

const mean = (values: number[]) => (
  values.reduce((total, value) => total + value, 0) / Math.max(1, values.length)
);

function motionStats(
  frames: Array<Array<{ u: number; v: number }>>,
  deltaSeconds: number,
) {
  const velocities = [0, 1].map((frameIndex) => frames[frameIndex].map((point, index) => ({
    x: wrappedDelta(point.u, frames[frameIndex + 1][index].u) / deltaSeconds,
    y: (frames[frameIndex + 1][index].v - point.v) / deltaSeconds,
  })));
  return {
    meanSpeed: mean(velocities[0].map(({ x, y }) => Math.hypot(x, y))),
    turning: mean(velocities[0].map(({ x, y }, index) => Math.hypot(
      velocities[1][index].x - x,
      velocities[1][index].y - y,
    ))),
  };
}

describe('system emotion engine presentation', () => {
  it('renders a labeled particle surface without operational overlays', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const markup = renderToStaticMarkup(createElement(SystemEmotionEngine, {
      locale: 'ko',
      model,
    }));

    expect(markup).toContain('role="img"');
    expect(markup).toContain('aria-label="현재 시스템 상태의 단색 앰버 입자 파동"');
    expect(markup).toContain('aria-hidden="true"');
    expect(markup).toContain('data-mood="dormant"');
    expect(markup).toContain('data-renderer="monochrome-density-grain-wave"');
    expect(markup).not.toContain('<header');
    expect(markup).not.toContain('<button');
    expect(markup).not.toContain('system-emotion-grain');
    expect(markup).not.toContain('emotion-engine-copy');
    expect(markup).not.toContain('emotion-engine-readings');
    expect(markup).not.toContain('emotion-axis-field');
    expect(markup).not.toContain('시스템 감응');
    expect(markup).not.toContain('STATE /');
    expect(markup).not.toContain('즉시 확인할 파동');
    expect(markup).not.toContain('위험 신호');
    expect(markup).not.toContain('지배 신호');
    expect(markup).not.toContain('Ubuntu');
    expect(markup).not.toContain('CRITICAL');
    expect(markup).not.toContain('<time');
  });

  it('builds a deterministic, continuous grain field at desktop and compact sizes', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const desktop = createGranularWavePlan(1_440, 590, model);
    const compact = createGranularWavePlan(375, 710, model, true);
    const deterministic = createGranularWavePlan(320, 220, model, true);
    const deterministicAgain = createGranularWavePlan(320, 220, model, true);

    expect(desktop.compact).toBe(false);
    expect(desktop.renderCohorts).toBe(GRAIN_MOTION_PROFILE.renderCohorts);
    expect(desktop.waveParticleCount).toBeGreaterThanOrEqual(80_000);
    expect(desktop.waveParticleCount).toBeLessThanOrEqual(100_000);
    expect(desktop.waveGrains).toHaveLength(desktop.waveParticleCount);
    expect(desktop.sprayGrains).toHaveLength(desktop.sprayParticleCount);
    expect(deterministicAgain.waveParticleCount).toBe(deterministic.waveParticleCount);
    expect(deterministicAgain.sprayParticleCount).toBe(deterministic.sprayParticleCount);
    expect(deterministicAgain.waveGrains.slice(0, 64)).toEqual(deterministic.waveGrains.slice(0, 64));
    expect(deterministicAgain.sprayGrains.slice(0, 64)).toEqual(deterministic.sprayGrains.slice(0, 64));

    expect(compact.compact).toBe(true);
    expect(compact.waveParticleCount).toBeGreaterThanOrEqual(24_000);
    expect(compact.waveParticleCount).toBeLessThanOrEqual(45_000);
    expect(compact.waveGrains).toHaveLength(compact.waveParticleCount);
    expect(compact.waveGrains.every((grain) => (
      Number.isFinite(grain.baseU)
      && grain.baseU >= 0
      && grain.baseU < 1
      && Number.isFinite(grain.depth)
      && grain.depth >= 0
      && grain.depth <= 1
      && Number.isFinite(grain.speed)
      && grain.speed > 0
      && grain.axisIndex >= 0
      && grain.axisIndex < model.axes.length
    ))).toBe(true);
  });

  it('uses one immutable grain appearance and no per-grain color or light tiers', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const plan = createGranularWavePlan(480, 320, model, true);
    const styleKeys = Object.keys(MONOCHROME_GRAIN_STYLE).sort();

    expect(styleKeys).toEqual([
      'alpha',
      'blue',
      'compositeOperation',
      'diameterCssPixels',
      'green',
      'red',
    ]);
    expect(MONOCHROME_GRAIN_STYLE.compositeOperation).toBe('source-over');
    expect(Object.isFrozen(MONOCHROME_GRAIN_STYLE)).toBe(true);
    expect(plan.waveGrains.every((grain) => (
      !('tone' in grain)
      && !('lightTier' in grain)
      && !('glow' in grain)
      && !('radius' in grain)
    ))).toBe(true);
    expect(plan.sprayGrains.every((grain) => (
      !('tone' in grain)
      && !('lightTier' in grain)
      && !('glow' in grain)
      && !('radius' in grain)
    ))).toBe(true);
  });

  it('keeps every visible amber mark particle-only and density-composited', () => {
    const source = readFileSync(new URL('./SystemEmotionEngine.tsx', import.meta.url), 'utf8');
    const forbiddenDrawingPrimitives = [
      'createLinearGradient',
      'createRadialGradient',
      'Path2D',
      'shadowBlur',
      'context.filter',
      'context.stroke',
      "'screen'",
      "'lighter'",
      'waveSilhouette',
      'waveBand',
    ];

    for (const primitive of forbiddenDrawingPrimitives) expect(source).not.toContain(primitive);
    expect(source).toContain('context.fillRect(x - diameter * 0.5');
    expect(source).toContain('context.globalCompositeOperation = MONOCHROME_GRAIN_STYLE.compositeOperation');
  });

  it('adds density and spray as the synthesized state becomes turbulent', () => {
    const calm = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const turbulent = {
      ...calm,
      energy: 0.94,
      turbulence: 0.92,
      coherence: 0.18,
      particleCount: 58,
    };
    const calmPlan = createGranularWavePlan(900, 500, calm);
    const turbulentPlan = createGranularWavePlan(900, 500, turbulent);
    const sprayCount = (plan: typeof calmPlan) => plan.sprayGrains.length;

    expect(turbulentPlan.waveParticleCount).toBeGreaterThan(calmPlan.waveParticleCount);
    expect(sprayCount(turbulentPlan)).toBeGreaterThan(sprayCount(calmPlan));
    expect(createGranularWavePlan(640, 500, calm).compact).toBe(true);
    expect(createGranularWavePlan(641, 500, calm).compact).toBe(false);
  });

  it('selects smooth 60 Hz paint deadlines and keeps temporal fading time-based', () => {
    const selectedFrames = (refreshRate: number) => {
      const rafTimes = Array.from(
        { length: refreshRate },
        (_, index) => (index + 1) * 1_000 / refreshRate,
      );
      let lastPaint = 0;
      const paints: number[] = [];
      for (const now of rafTimes) {
        if (!shouldPaintEmotionFrame(now, lastPaint)) continue;
        paints.push(now);
        lastPaint = advanceEmotionFrameClock(now, lastPaint);
      }
      return paints;
    };
    const paints = selectedFrames(60);

    const gaps = paints.slice(1).map((time, index) => time - paints[index]);
    expect(GRAIN_MOTION_PROFILE.targetFramesPerSecond).toBe(60);
    expect(GRAIN_MOTION_PROFILE.renderCohorts).toBe(4);
    expect(paints.length).toBeGreaterThanOrEqual(58);
    expect(Math.max(...gaps)).toBeLessThanOrEqual(1_000 / 60 + 0.01);
    for (const refreshRate of [90, 120, 144]) {
      expect(selectedFrames(refreshRate).length).toBeGreaterThanOrEqual(59);
      expect(selectedFrames(refreshRate).length).toBeLessThanOrEqual(61);
    }

    const desktopFade = emotionFrameFadeAlpha(1_000 / 60, false);
    const compactFade = emotionFrameFadeAlpha(1_000 / 60, true);
    expect(
      1 - Math.pow(1 - desktopFade, GRAIN_MOTION_PROFILE.renderCohorts),
    ).toBeCloseTo(0.38, 6);
    expect(
      1 - Math.pow(1 - compactFade, GRAIN_MOTION_PROFILE.renderCohorts),
    ).toBeCloseTo(0.5, 6);
  });

  it('moves a turbulent wave faster with stronger turning and no adjacent-frame teleporting', () => {
    const calm = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const storm = {
      ...calm,
      energy: 0.96,
      turbulence: 0.95,
      volatility: 0.92,
      coherence: 0.14,
      waveAmplitude: 0.96,
      tempoSeconds: 3.35,
    };
    const seeds = createGranularWavePlan(960, 540, calm).waveGrains.slice(0, 768);
    const times = [1, 1.2, 1.4];
    const calmFrames = times.map((time) => sampleGranularWaveFrame(
      960,
      540,
      time,
      calm,
      seeds,
      [],
    ).wave);
    const stormFrames = times.map((time) => sampleGranularWaveFrame(
      960,
      540,
      time,
      storm,
      seeds,
      [],
    ).wave);
    const calmMotion = motionStats(calmFrames, 0.2);
    const stormMotion = motionStats(stormFrames, 0.2);

    expect(stormMotion.meanSpeed).toBeGreaterThan(calmMotion.meanSpeed * 1.25);
    expect(stormMotion.turning).toBeGreaterThan(calmMotion.turning * 1.2);

    const adjacentA = sampleGranularWaveFrame(960, 540, 3, storm, seeds, []).wave;
    const adjacentB = sampleGranularWaveFrame(960, 540, 3 + 1 / 30, storm, seeds, []).wave;
    const displacements = adjacentA.map((point, index) => Math.hypot(
      wrappedDelta(point.u, adjacentB[index].u),
      adjacentB[index].v - point.v,
    )).sort((left, right) => left - right);
    const p99 = displacements[Math.floor(displacements.length * 0.99)];
    expect(p99).toBeLessThan(0.05);

    const updatesPerSecond = GRAIN_MOTION_PROFILE.targetFramesPerSecond
      / GRAIN_MOTION_PROFILE.renderCohorts;
    const trajectoryFrames = Array.from({ length: updatesPerSecond * 8 + 1 }, (_, index) => (
      sampleGranularWaveFrame(960, 540, index / updatesPerSecond, storm, seeds, []).wave
    ));
    let worstP99 = 0;
    let worstTargetPoint = 0;
    let renderedFrame = trajectoryFrames[0];
    const maximumRenderedDistance = Math.min(
      GRAIN_MOTION_PROFILE.maximumNormalizedStep,
      (
        GRAIN_MOTION_PROFILE.baseMaximumNormalizedSpeed
        + storm.energy * GRAIN_MOTION_PROFILE.energySpeedBoost
        + storm.turbulence * GRAIN_MOTION_PROFILE.turbulenceSpeedBoost
      ) / updatesPerSecond,
    );
    for (let frameIndex = 1; frameIndex < trajectoryFrames.length; frameIndex += 1) {
      const targetFrame = trajectoryFrames[frameIndex];
      const targetDisplacements = trajectoryFrames[frameIndex - 1].map((point, index) => Math.hypot(
        wrappedDelta(point.u, targetFrame[index].u),
        targetFrame[index].v - point.v,
      ));
      const nextRenderedFrame = targetFrame.map((point, index) => ({
        ...point,
        ...constrainGranularMotionStep(
          renderedFrame[index].u,
          renderedFrame[index].v,
          point.u,
          point.v,
          maximumRenderedDistance,
        ),
      }));
      const frameDisplacements = renderedFrame.map((point, index) => Math.hypot(
        wrappedDelta(point.u, nextRenderedFrame[index].u),
        nextRenderedFrame[index].v - point.v,
      )).sort((left, right) => left - right);
      worstP99 = Math.max(
        worstP99,
        frameDisplacements[Math.floor(frameDisplacements.length * 0.99)],
      );
      worstTargetPoint = Math.max(worstTargetPoint, ...targetDisplacements);
      renderedFrame = nextRenderedFrame;
    }
    expect(worstP99).toBeLessThanOrEqual(maximumRenderedDistance + 0.000001);
    expect(worstTargetPoint).toBeLessThan(0.3);
  });

  it('preserves phase and travel continuity across small telemetry model updates', () => {
    const base = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const before = {
      ...base,
      energy: 0.7,
      turbulence: 0.7,
      volatility: 0.64,
      coherence: 0.34,
      waveAmplitude: 0.72,
      tempoSeconds: 4,
    };
    const after = {
      ...before,
      energy: 0.72,
      turbulence: 0.72,
      volatility: 0.66,
      coherence: 0.33,
      waveAmplitude: 0.73,
      tempoSeconds: 3.9,
    };
    const seeds = createGranularWavePlan(960, 540, before).waveGrains.slice(0, 1_024);
    const clock = advanceGranularMotionClock(
      { elapsedSeconds: 0, phaseTime: 0, travel: 0 },
      60,
      before,
    );
    const beforeUpdate = sampleGranularWaveFrame(960, 540, 60, before, seeds, [], clock).wave;
    const unblendedUpdate = sampleGranularWaveFrame(960, 540, 60, after, seeds, [], clock).wave;
    const unblendedDisplacements = beforeUpdate.map((point, index) => Math.hypot(
      wrappedDelta(point.u, unblendedUpdate[index].u),
      unblendedUpdate[index].v - point.v,
    )).sort((left, right) => left - right);
    const blended = blendGranularMotionModel(before, after, 1 / 60);
    const nextClock = advanceGranularMotionClock(clock, 1 / 60, blended);
    const nextFrame = sampleGranularWaveFrame(
      960,
      540,
      nextClock.elapsedSeconds,
      blended,
      seeds,
      [],
      nextClock,
    ).wave;
    const nextDisplacements = beforeUpdate.map((point, index) => Math.hypot(
      wrappedDelta(point.u, nextFrame[index].u),
      nextFrame[index].v - point.v,
    )).sort((left, right) => left - right);

    expect(
      unblendedDisplacements[Math.floor(unblendedDisplacements.length * 0.99)],
    ).toBeLessThan(0.1);
    expect(nextDisplacements[Math.floor(nextDisplacements.length * 0.99)]).toBeLessThan(0.05);
  });

  it('reflects ceiling overshoot and makes the wave body strike the upper boundary', () => {
    const ceiling = GRAIN_MOTION_PROFILE.desktopCeiling;
    const nearImpact = reflectCeilingOvershoot(ceiling - 0.01, ceiling);
    const deepImpact = reflectCeilingOvershoot(ceiling - 0.02, ceiling);
    const untouched = reflectCeilingOvershoot(ceiling + 0.02, ceiling);

    expect(nearImpact.hitCeiling).toBe(true);
    expect(nearImpact.v).toBeGreaterThanOrEqual(ceiling);
    expect(deepImpact.v).toBeGreaterThan(nearImpact.v);
    expect(deepImpact.impact).toBeGreaterThan(nearImpact.impact);
    expect(untouched).toEqual({ v: ceiling + 0.02, hitCeiling: false, impact: 0 });

    const calm = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const storm = {
      ...calm,
      energy: 0.96,
      turbulence: 0.95,
      volatility: 0.92,
      coherence: 0.14,
      waveAmplitude: 0.96,
      tempoSeconds: 3.35,
    };
    const seeds = createGranularWavePlan(960, 540, storm).waveGrains.slice(0, 1_024);
    const impacts = Array.from({ length: 81 }, (_, index) => (
      sampleGranularWaveFrame(960, 540, index / 10, storm, seeds, []).wave
    )).flat().filter((point) => point.hitCeiling);

    expect(impacts.length).toBeGreaterThan(0);
    expect(Math.min(...impacts.map((point) => point.v))).toBeLessThanOrEqual(ceiling + 0.02);
    expect(impacts.every((point) => point.v >= ceiling)).toBe(true);
  });
});
