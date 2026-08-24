import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { BonifacioReturnLink } from './BonifacioReturnLink';

describe('BonifacioReturnLink', () => {
  it('returns to the portfolio in the current tab', () => {
    const markup = renderToStaticMarkup(createElement(BonifacioReturnLink));

    expect(markup).toContain('class="bonifacio-return-link"');
    expect(markup).toContain('href="https://bonifacio.work/"');
    expect(markup).toContain('aria-label="← Bonifacio"');
    expect(markup).toContain('← Bonifacio');
    expect(markup).not.toContain('target=');
  });
});
