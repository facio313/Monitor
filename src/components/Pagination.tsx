import { useCallback, useEffect, useId, useState } from 'react';
import type { MonitorLocale } from '../types';
import './pagination.css';

export interface PaginationModel {
  page: number;
  pageCount: number;
  pageSize: number;
  totalItems: number;
  startIndex: number;
  endIndex: number;
}

export interface PaginationController extends PaginationModel {
  setPage: (page: number) => void;
}

interface UsePaginationOptions {
  totalItems: number;
  pageSize: number;
  resetKey?: unknown;
}

type PaginationToken = number | 'ellipsis';

function nonNegativeInteger(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

export function resolvePagination(totalItems: number, pageSize: number, requestedPage = 1): PaginationModel {
  const normalizedTotal = nonNegativeInteger(totalItems);
  const normalizedPageSize = Math.max(1, nonNegativeInteger(pageSize));
  const pageCount = Math.max(1, Math.ceil(normalizedTotal / normalizedPageSize));
  const page = Math.min(pageCount, Math.max(1, nonNegativeInteger(requestedPage) || 1));
  const startIndex = normalizedTotal === 0 ? 0 : (page - 1) * normalizedPageSize;
  const endIndex = Math.min(normalizedTotal, startIndex + normalizedPageSize);

  return {
    page,
    pageCount,
    pageSize: normalizedPageSize,
    totalItems: normalizedTotal,
    startIndex,
    endIndex,
  };
}

export function paginateItems<T>(items: readonly T[], pagination: Pick<PaginationModel, 'startIndex' | 'endIndex'>): T[] {
  return items.slice(pagination.startIndex, pagination.endIndex);
}

export function paginationTokens(page: number, pageCount: number): PaginationToken[] {
  const resolved = resolvePagination(pageCount, 1, page);
  const current = resolved.page;
  const total = resolved.totalItems;
  if (total <= 5) return Array.from({ length: total }, (_, index) => index + 1);

  const visible = new Set<number>([1, total, current]);
  visible.add(Math.max(1, current - 1));
  visible.add(Math.min(total, current + 1));

  if (current <= 3) {
    visible.add(2);
    visible.add(3);
  }
  if (current >= total - 2) {
    visible.add(total - 2);
    visible.add(total - 1);
  }

  const ordered = [...visible].filter((value) => value >= 1 && value <= total).sort((left, right) => left - right);
  const tokens: PaginationToken[] = [];
  ordered.forEach((value, index) => {
    if (index > 0 && value - ordered[index - 1] > 1) tokens.push('ellipsis');
    tokens.push(value);
  });
  return tokens;
}

export function usePagination({ totalItems, pageSize, resetKey }: UsePaginationOptions): PaginationController {
  const normalizedTotal = nonNegativeInteger(totalItems);
  const normalizedPageSize = Math.max(1, nonNegativeInteger(pageSize));
  const [state, setState] = useState<{ page: number; resetKey: unknown }>(() => ({ page: 1, resetKey }));
  const resetPending = !Object.is(state.resetKey, resetKey);
  const model = resolvePagination(normalizedTotal, normalizedPageSize, resetPending ? 1 : state.page);

  useEffect(() => {
    setState((current) => {
      if (!Object.is(current.resetKey, resetKey)) return { page: 1, resetKey };
      const clampedPage = resolvePagination(normalizedTotal, normalizedPageSize, current.page).page;
      return clampedPage === current.page ? current : { ...current, page: clampedPage };
    });
  }, [normalizedPageSize, normalizedTotal, resetKey]);

  const setPage = useCallback((nextPage: number) => {
    setState({
      page: resolvePagination(normalizedTotal, normalizedPageSize, nextPage).page,
      resetKey,
    });
  }, [normalizedPageSize, normalizedTotal, resetKey]);

  return { ...model, setPage };
}

interface PaginationProps {
  model: PaginationModel;
  locale: MonitorLocale;
  onPageChange: (page: number) => void;
  ariaLabel: string;
  itemLabel?: string;
  className?: string;
}

export function Pagination({
  model,
  locale,
  onPageChange,
  ariaLabel,
  itemLabel,
  className = '',
}: PaginationProps) {
  const statusId = useId();
  if (model.totalItems === 0) return null;

  const firstItem = model.startIndex + 1;
  const rangeText = locale === 'ko'
    ? `${firstItem.toLocaleString()}–${model.endIndex.toLocaleString()} / ${model.totalItems.toLocaleString()}${itemLabel ?? '개 항목'}`
    : `${firstItem.toLocaleString()}–${model.endIndex.toLocaleString()} of ${model.totalItems.toLocaleString()} ${itemLabel ?? 'items'}`;
  const previousLabel = locale === 'ko' ? '이전 페이지' : 'Previous page';
  const nextLabel = locale === 'ko' ? '다음 페이지' : 'Next page';

  return (
    <nav className={`monitor-pagination${className ? ` ${className}` : ''}`} aria-label={ariaLabel} aria-describedby={statusId}>
      <output id={statusId} className="monitor-pagination-range" aria-live="polite">
        {rangeText}
        <span>{locale === 'ko' ? `${model.page} / ${model.pageCount} 페이지` : `Page ${model.page} of ${model.pageCount}`}</span>
      </output>
      <div className="monitor-pagination-controls">
        <button
          type="button"
          className="monitor-pagination-action"
          disabled={model.page === 1}
          aria-label={previousLabel}
          onClick={() => onPageChange(model.page - 1)}
        >
          <span aria-hidden="true">←</span><span className="monitor-pagination-action-text">{locale === 'ko' ? '이전' : 'Previous'}</span>
        </button>
        <span className="monitor-pagination-pages">
          {paginationTokens(model.page, model.pageCount).map((token, index) => token === 'ellipsis'
            ? <span className="monitor-pagination-ellipsis" aria-hidden="true" key={`ellipsis-${index}`}>…</span>
            : (
              <button
                type="button"
                className="monitor-pagination-page"
                aria-current={token === model.page ? 'page' : undefined}
                aria-label={locale === 'ko'
                  ? `${token}페이지${token === model.page ? ', 현재 페이지' : '로 이동'}`
                  : `${token === model.page ? 'Current page' : 'Go to page'} ${token}`}
                onClick={() => onPageChange(token)}
                key={token}
              >{token}</button>
            ))}
        </span>
        <button
          type="button"
          className="monitor-pagination-action"
          disabled={model.page === model.pageCount}
          aria-label={nextLabel}
          onClick={() => onPageChange(model.page + 1)}
        >
          <span className="monitor-pagination-action-text">{locale === 'ko' ? '다음' : 'Next'}</span><span aria-hidden="true">→</span>
        </button>
      </div>
    </nav>
  );
}
