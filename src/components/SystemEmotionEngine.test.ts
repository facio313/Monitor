import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { deriveSystemEmotion } from '../system-emotion';
import { SystemEmotionEngine } from './SystemEmotionEngine';

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
  });
});
