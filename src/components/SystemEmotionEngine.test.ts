import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from '../system-emotion';
import {
  createGranularWavePlan,
  MONOCHROME_GRAIN_STYLE,
  SystemEmotionEngine,
} from './SystemEmotionEngine';

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
});
