import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from '../system-emotion';
import { createGranularWavePlan, SystemEmotionEngine } from './SystemEmotionEngine';

describe('system emotion engine presentation', () => {
  it('renders a labeled particle surface without operational overlays', () => {
    const model = deriveSystemEmotion({ data: null, stale: false, dangerCount: 0, cautionCount: 0 });
    const markup = renderToStaticMarkup(createElement(SystemEmotionEngine, {
      locale: 'ko',
      model,
    }));

    expect(markup).toContain('role="img"');
    expect(markup).toContain('aria-label="현재 시스템 상태의 입자 파동 시각화"');
    expect(markup).toContain('aria-hidden="true"');
    expect(markup).toContain('data-mood="dormant"');
    expect(markup).toContain('data-renderer="granular-particle-wave"');
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
