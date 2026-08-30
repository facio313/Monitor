import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  Pagination,
  paginateItems,
  paginationTokens,
  resolvePagination,
} from './Pagination';

describe('pagination', () => {
  it('normalizes input and clamps pages after a result set shrinks', () => {
    expect(resolvePagination(23, 10, 3)).toEqual({
      page: 3,
      pageCount: 3,
      pageSize: 10,
      totalItems: 23,
      startIndex: 20,
      endIndex: 23,
    });
    expect(resolvePagination(3, 10, 9)).toMatchObject({ page: 1, pageCount: 1, startIndex: 0, endIndex: 3 });
    expect(resolvePagination(-1, 0, -4)).toMatchObject({ page: 1, pageCount: 1, pageSize: 1, totalItems: 0, startIndex: 0, endIndex: 0 });
  });

  it('returns only the bounded slice for the active page', () => {
    const items = Array.from({ length: 25 }, (_, index) => index + 1);
    expect(paginateItems(items, resolvePagination(items.length, 8, 2))).toEqual([9, 10, 11, 12, 13, 14, 15, 16]);
    expect(paginateItems(items, resolvePagination(items.length, 8, 4))).toEqual([25]);
  });

  it('keeps page controls compact while retaining the first, current, and last pages', () => {
    expect(paginationTokens(1, 10)).toEqual([1, 2, 3, 'ellipsis', 10]);
    expect(paginationTokens(5, 10)).toEqual([1, 'ellipsis', 4, 5, 6, 'ellipsis', 10]);
    expect(paginationTokens(10, 10)).toEqual([1, 'ellipsis', 8, 9, 10]);
  });

  it('renders an accessible range, current page, and previous/next controls', () => {
    const model = resolvePagination(24, 10, 2);
    const markup = renderToStaticMarkup(createElement(Pagination, {
      model,
      locale: 'en',
      onPageChange: () => undefined,
      ariaLabel: 'Log pages',
      itemLabel: 'records',
    }));

    expect(markup).toContain('aria-label="Log pages"');
    expect(markup).toContain('11–20 of 24 records');
    expect(markup).toContain('Page 2 of 3');
    expect(markup).toContain('aria-current="page"');
    expect(markup).toContain('aria-label="Previous page"');
    expect(markup).toContain('aria-label="Next page"');
  });
});
