import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from '../system-emotion';
import { createGranularWavePlan, SystemEmotionEngine } from './SystemEmotionEngine';

describe('system emotion engine presentation', () => {
  it('keeps the canvas decorative and exposes an actionable textual state', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const markup = renderToStaticMarkup(createElement(SystemEmotionEngine, {
      data: null,
      locale: 'ko',
      model,
      onNavigate: () => undefined,
    }));

    expect(markup).toContain('aria-hidden="true"');
    expect(markup).toContain('신호를 기다리는 중');
    expect(markup).toContain('지배 신호 · 신뢰성');
    expect(markup).toContain('계통별 신호 강도');
    expect(markup).toContain('data-mood="dormant"');
    expect(markup).toContain('data-renderer="granular-particle-wave"');
    expect(markup).toContain('시스템 감응 · 입자파 합성');
    expect(markup.match(/role="group"/g)).toHaveLength(2);
  });

  it('builds a deterministic, dense particle sheet at desktop and compact sizes', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const desktop = createGranularWavePlan(1_440, 590, model);
    const desktopAgain = createGranularWavePlan(1_440, 590, model);
    const compact = createGranularWavePlan(375, 710, model, true);

    expect(desktop.compact).toBe(false);
    expect(desktop.strataPerAxis).toBe(2);
    expect(desktop.strandCount).toBe(model.axes.length * 2);
    expect(desktop.waveParticleCount).toBeGreaterThanOrEqual(1_200);
    expect(desktop.waveParticleCount).toBeLessThanOrEqual(1_300);
    expect(desktop.waveBuckets.flat()).toHaveLength(desktop.waveParticleCount);
    expect(desktopAgain).toEqual(desktop);

    expect(compact.compact).toBe(true);
    expect(compact.strataPerAxis).toBe(2);
    expect(compact.strandCount).toBe(model.axes.length * 2);
    expect(compact.waveParticleCount).toBeGreaterThanOrEqual(420);
    expect(compact.waveParticleCount).toBeLessThanOrEqual(740);
    expect(compact.waveBuckets.flat()).toHaveLength(compact.waveParticleCount);
    expect(compact.waveBuckets.flat().every((grain) => (
      Number.isFinite(grain.baseU)
      && grain.baseU >= 0
      && grain.baseU < 1
      && grain.radius > 0
      && grain.axisIndex >= 0
      && grain.axisIndex < model.axes.length
    ))).toBe(true);
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
    const sprayCount = (plan: typeof calmPlan) => plan.sprayBuckets.reduce((total, bucket) => total + bucket.length, 0);

    expect(turbulentPlan.waveParticleCount).toBeGreaterThan(calmPlan.waveParticleCount);
    expect(sprayCount(turbulentPlan)).toBeGreaterThan(sprayCount(calmPlan));
    expect(createGranularWavePlan(640, 500, calm).compact).toBe(true);
    expect(createGranularWavePlan(641, 500, calm).compact).toBe(false);
  });
});
