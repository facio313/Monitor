import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from 'react';
import type {
  GridItemHTMLElement,
  GridStack,
  GridStackOptions,
  GridStackWidget,
} from 'gridstack';
import 'gridstack/dist/gridstack.min.css';
import '../adaptive-grid.css';

export const ADAPTIVE_GRID_SCHEMA_VERSION = 1 as const;
export const ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION = 1 as const;
export const ADAPTIVE_GRID_BASE_COLUMNS = 12;
export const ADAPTIVE_GRID_MAX_ROWS = 256;
export const ADAPTIVE_GRID_TABLET_MAX_WIDTH = 1024;
export const ADAPTIVE_GRID_PHONE_MAX_WIDTH = 640;

const ADAPTIVE_GRID_MAX_WIDGET_HEIGHT = 64;
const ADAPTIVE_GRID_MAX_JSON_LENGTH = 64 * 1024;
const ADAPTIVE_GRID_HISTORY_LIMIT = 24;
const ADAPTIVE_GRID_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const STORAGE_PREFIX = 'monitor.adaptive-grid';
const DETAILS_STORAGE_PREFIX = 'monitor.adaptive-grid-details';

export interface AdaptiveGridPosition {
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
  maxW?: number;
  maxH?: number;
}

export interface AdaptiveGridItem {
  id: string;
  label: string;
  layout: AdaptiveGridPosition;
  details?: readonly AdaptiveGridDetailItem[];
  content: ReactNode;
}

export interface AdaptiveGridDetailItem {
  id: string;
  label: string;
}

export interface AdaptiveGridDetailVisibilityItem {
  widgetId: string;
  detailId: string;
  visible: boolean;
}

export interface AdaptiveGridLayoutItem {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export type AdaptiveGridViewportMode = 'desktop' | 'tablet' | 'phone';

export interface AdaptiveGridCompactPlacement {
  id: string;
  order: number;
  tabletSpan: 1 | 2;
}

export type AdaptiveGridLocale = 'ko' | 'en';

export interface AdaptiveGridProps {
  items: readonly AdaptiveGridItem[];
  storageKey: string;
  locale?: AdaptiveGridLocale;
  ariaLabel?: string;
  className?: string;
  onLayoutChange?: (layout: readonly AdaptiveGridLayoutItem[]) => void;
  onDetailVisibilityChange?: (visibility: readonly AdaptiveGridDetailVisibilityItem[]) => void;
}

export type AdaptiveGridCommand =
  | 'move-left'
  | 'move-right'
  | 'move-up'
  | 'move-down'
  | 'grow-width'
  | 'shrink-width'
  | 'grow-height'
  | 'shrink-height';

export type AdaptiveGridCommandFailure =
  | 'invalid-layout'
  | 'unknown-widget'
  | 'boundary'
  | 'minimum'
  | 'maximum'
  | 'collision';

export interface AdaptiveGridCommandResult {
  layout: AdaptiveGridLayoutItem[];
  changed: boolean;
  reason?: AdaptiveGridCommandFailure;
}

interface WidgetConstraint {
  id: string;
  minW: number;
  minH: number;
  maxW: number;
  maxH: number;
}

interface StoredAdaptiveGridLayout {
  schemaVersion: typeof ADAPTIVE_GRID_SCHEMA_VERSION;
  columns: typeof ADAPTIVE_GRID_BASE_COLUMNS;
  layout: AdaptiveGridLayoutItem[];
}

interface StoredAdaptiveGridDetails {
  schemaVersion: typeof ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION;
  visibility: AdaptiveGridDetailVisibilityItem[];
}

interface AdaptiveGridEditSnapshot {
  layout: AdaptiveGridLayoutItem[];
  hiddenDetailTokens: Set<string>;
}

interface AdaptiveGridDetailContextValue {
  widgetId: string;
  hiddenDetailTokens: ReadonlySet<string>;
}

interface Announcement {
  sequence: number;
  text: string;
}

interface AdaptiveGridStrings {
  grid: string;
  toolbar: string;
  edit: string;
  save: string;
  cancel: string;
  undo: string;
  reset: string;
  detailTitle: string;
  detailHint: string;
  detailControls: (label: string) => string;
  detailToggle: (label: string, visible: boolean) => string;
  detailState: (visible: boolean) => string;
  controls: (label: string) => string;
  dragHandle: (label: string) => string;
  command: Record<AdaptiveGridCommand, string>;
  commandGlyph: Record<AdaptiveGridCommand, string>;
  editingStarted: string;
  saved: string;
  cancelled: string;
  undone: string;
  resetApplied: string;
  unavailable: string;
  saveFailed: string;
  invalidLayout: string;
  compactEditingCancelled: string;
  changed: string;
  detailShown: (label: string) => string;
  detailHidden: (label: string) => string;
  commandApplied: (label: string, command: string) => string;
  commandBlocked: (label: string, command: string) => string;
}

const COMMANDS: readonly AdaptiveGridCommand[] = [
  'move-left',
  'move-right',
  'move-up',
  'move-down',
  'grow-width',
  'shrink-width',
  'grow-height',
  'shrink-height',
];

const STRINGS: Record<AdaptiveGridLocale, AdaptiveGridStrings> = {
  en: {
    grid: 'Adaptive dashboard widgets',
    toolbar: 'Widget layout controls',
    edit: 'Edit layout',
    save: 'Save layout',
    cancel: 'Cancel editing',
    undo: 'Undo',
    reset: 'Reset to default',
    detailTitle: 'Visible details',
    detailHint: 'Choose the details shown inside each widget, then save the layout.',
    detailControls: (label) => `${label} visible details`,
    detailToggle: (label, visible) => `${visible ? 'Hide' : 'Show'} ${label}`,
    detailState: (visible) => visible ? 'ON' : 'OFF',
    controls: (label) => `${label} layout controls`,
    dragHandle: (label) => `Drag ${label}`,
    command: {
      'move-left': 'Move left',
      'move-right': 'Move right',
      'move-up': 'Move up',
      'move-down': 'Move down',
      'grow-width': 'Make wider',
      'shrink-width': 'Make narrower',
      'grow-height': 'Make taller',
      'shrink-height': 'Make shorter',
    },
    commandGlyph: {
      'move-left': '←',
      'move-right': '→',
      'move-up': '↑',
      'move-down': '↓',
      'grow-width': 'W+',
      'shrink-width': 'W−',
      'grow-height': 'H+',
      'shrink-height': 'H−',
    },
    editingStarted: 'Layout editing enabled.',
    saved: 'Layout saved.',
    cancelled: 'Layout changes cancelled.',
    undone: 'Last layout change undone.',
    resetApplied: 'Curated default layout applied. Save to keep it.',
    unavailable: 'Layout editing is not ready yet.',
    saveFailed: 'The layout could not be saved in this browser.',
    invalidLayout: 'The visible layout is invalid. Cancel or reset before saving.',
    compactEditingCancelled: 'Layout changes were cancelled for the compact view.',
    changed: 'Layout changed. Save to keep it.',
    detailShown: (label) => `${label} is now shown. Save to keep it.`,
    detailHidden: (label) => `${label} is now hidden. Save to keep it.`,
    commandApplied: (label, command) => `${label}: ${command.toLowerCase()}.`,
    commandBlocked: (label, command) => `${label}: cannot ${command.toLowerCase()}.`,
  },
  ko: {
    grid: '적응형 대시보드 위젯',
    toolbar: '위젯 배치 제어',
    edit: '배치 편집',
    save: '배치 저장',
    cancel: '편집 취소',
    undo: '되돌리기',
    reset: '기본 배치로 초기화',
    detailTitle: '표시 항목',
    detailHint: '각 위젯 안에서 표시할 항목을 선택한 뒤 배치를 저장하세요.',
    detailControls: (label) => `${label} 표시 항목`,
    detailToggle: (label, visible) => `${label} ${visible ? '숨기기' : '보이기'}`,
    detailState: (visible) => visible ? 'ON' : 'OFF',
    controls: (label) => `${label} 배치 제어`,
    dragHandle: (label) => `${label} 드래그`,
    command: {
      'move-left': '왼쪽으로 이동',
      'move-right': '오른쪽으로 이동',
      'move-up': '위로 이동',
      'move-down': '아래로 이동',
      'grow-width': '가로 늘리기',
      'shrink-width': '가로 줄이기',
      'grow-height': '세로 늘리기',
      'shrink-height': '세로 줄이기',
    },
    commandGlyph: {
      'move-left': '←',
      'move-right': '→',
      'move-up': '↑',
      'move-down': '↓',
      'grow-width': '가로+',
      'shrink-width': '가로−',
      'grow-height': '세로+',
      'shrink-height': '세로−',
    },
    editingStarted: '배치 편집을 시작했습니다.',
    saved: '배치를 저장했습니다.',
    cancelled: '배치 변경을 취소했습니다.',
    undone: '마지막 배치 변경을 되돌렸습니다.',
    resetApplied: '기본 배치를 적용했습니다. 저장하면 유지됩니다.',
    unavailable: '아직 배치 편집을 사용할 수 없습니다.',
    saveFailed: '이 브라우저에 배치를 저장하지 못했습니다.',
    invalidLayout: '현재 배치를 검증하지 못했습니다. 저장하기 전에 취소하거나 초기화하세요.',
    compactEditingCancelled: '작은 화면으로 전환되어 배치 변경을 취소했습니다.',
    changed: '배치가 변경되었습니다. 저장하면 유지됩니다.',
    detailShown: (label) => `${label} 항목을 표시합니다. 저장하면 유지됩니다.`,
    detailHidden: (label) => `${label} 항목을 숨깁니다. 저장하면 유지됩니다.`,
    commandApplied: (label, command) => `${label}: ${command}.`,
    commandBlocked: (label, command) => `${label}: ${command}할 수 없습니다.`,
  },
};

const AdaptiveGridDetailContext = createContext<AdaptiveGridDetailContextValue | null>(null);

function detailToken(widgetId: string, detailId: string): string {
  return JSON.stringify([widgetId, detailId]);
}

export function useAdaptiveGridDetailVisibility(): (detailId: string) => boolean {
  const context = useContext(AdaptiveGridDetailContext);
  return useCallback((detailId: string) => {
    if (!context) return true;
    return !context.hiddenDetailTokens.has(detailToken(context.widgetId, detailId));
  }, [context]);
}

export function getAdaptiveGridViewportMode(width: number): AdaptiveGridViewportMode {
  if (!Number.isFinite(width) || width < 0) {
    throw new RangeError('Adaptive-grid viewport width must be a finite, non-negative number.');
  }
  if (width <= ADAPTIVE_GRID_PHONE_MAX_WIDTH) return 'phone';
  if (width <= ADAPTIVE_GRID_TABLET_MAX_WIDTH) return 'tablet';
  return 'desktop';
}

export function getAdaptiveGridCompactPlacements(
  layout: readonly Pick<AdaptiveGridLayoutItem, 'id' | 'x' | 'y' | 'w'>[],
): AdaptiveGridCompactPlacement[] {
  const orderedIndexes = layout
    .map((entry, index) => ({ entry, index }))
    .sort((left, right) => (
      left.entry.y - right.entry.y
      || left.entry.x - right.entry.x
      || left.index - right.index
    ));
  const orderByIndex = new Map(
    orderedIndexes.map(({ index }, order) => [index, order]),
  );

  return layout.map((entry, index) => ({
    id: entry.id,
    order: orderByIndex.get(index) ?? index,
    // A canonical widget wider than half of the 12-column canvas is a
    // feature/summary panel and should keep visual priority in the 2-column flow.
    tabletSpan: entry.w > ADAPTIVE_GRID_BASE_COLUMNS / 2 ? 2 : 1,
  }));
}

function currentAdaptiveGridViewportMode(): AdaptiveGridViewportMode {
  if (typeof window === 'undefined') return 'desktop';
  return Number.isFinite(window.innerWidth) && window.innerWidth >= 0
    ? getAdaptiveGridViewportMode(window.innerWidth)
    : 'desktop';
}

function listenForMediaQueryChange(
  media: MediaQueryList,
  listener: (event: MediaQueryListEvent) => void,
): () => void {
  if (typeof media.addEventListener === 'function') {
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }
  if (typeof media.addListener === 'function') {
    media.addListener(listener);
    return () => media.removeListener(listener);
  }
  return () => undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

function detailDefinitionsForItems(
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
): Array<{ widgetId: string; detailId: string }> {
  const definitions: Array<{ widgetId: string; detailId: string }> = [];
  const seenWidgets = new Set<string>();
  for (const item of items) {
    if (!ADAPTIVE_GRID_ID_PATTERN.test(item.id) || seenWidgets.has(item.id)) {
      throw new TypeError(`Invalid or duplicate adaptive-grid widget id: ${item.id}`);
    }
    seenWidgets.add(item.id);
    const seen = new Set<string>();
    for (const detail of item.details ?? []) {
      if (
        !ADAPTIVE_GRID_ID_PATTERN.test(detail.id)
        || seen.has(detail.id)
        || typeof detail.label !== 'string'
        || detail.label.length < 1
        || detail.label.length > 160
        || detail.label.trim() !== detail.label
        || /[\u0000-\u001f\u007f]/.test(detail.label)
      ) {
        throw new TypeError(`Invalid or duplicate adaptive-grid detail id: ${item.id}.${detail.id}`);
      }
      seen.add(detail.id);
      definitions.push({ widgetId: item.id, detailId: detail.id });
    }
  }
  return definitions;
}

function cloneHiddenDetailTokens(tokens: ReadonlySet<string>): Set<string> {
  return new Set(tokens);
}

function hiddenDetailTokensEqual(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((token) => right.has(token));
}

function cloneLayout(layout: readonly AdaptiveGridLayoutItem[]): AdaptiveGridLayoutItem[] {
  return layout.map((item) => ({ ...item }));
}

function layoutsEqual(
  left: readonly AdaptiveGridLayoutItem[],
  right: readonly AdaptiveGridLayoutItem[],
): boolean {
  return left.length === right.length && left.every((item, index) => {
    const other = right[index];
    return other !== undefined
      && item.id === other.id
      && item.x === other.x
      && item.y === other.y
      && item.w === other.w
      && item.h === other.h;
  });
}

function overlaps(left: AdaptiveGridLayoutItem, right: AdaptiveGridLayoutItem): boolean {
  return left.x < right.x + right.w
    && left.x + left.w > right.x
    && left.y < right.y + right.h
    && left.y + left.h > right.y;
}

function constraintsForItems(items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[]): WidgetConstraint[] {
  const seen = new Set<string>();

  return items.map((item) => {
    if (!ADAPTIVE_GRID_ID_PATTERN.test(item.id) || seen.has(item.id)) {
      throw new TypeError(`Invalid or duplicate adaptive-grid widget id: ${item.id}`);
    }
    seen.add(item.id);

    const { layout } = item;
    const required = [layout.x, layout.y, layout.w, layout.h];
    if (!required.every(isSafeInteger)) {
      throw new TypeError(`Widget ${item.id} has a non-integer curated layout.`);
    }

    const minW = layout.minW ?? 1;
    const minH = layout.minH ?? 1;
    const maxW = layout.maxW ?? ADAPTIVE_GRID_BASE_COLUMNS;
    const maxH = layout.maxH ?? ADAPTIVE_GRID_MAX_WIDGET_HEIGHT;
    if (![minW, minH, maxW, maxH].every(isSafeInteger)) {
      throw new TypeError(`Widget ${item.id} has a non-integer size constraint.`);
    }
    if (
      minW < 1
      || minH < 1
      || maxW < minW
      || maxH < minH
      || maxW > ADAPTIVE_GRID_BASE_COLUMNS
      || maxH > ADAPTIVE_GRID_MAX_ROWS
    ) {
      throw new RangeError(`Widget ${item.id} has an invalid size constraint.`);
    }

    return { id: item.id, minW, minH, maxW, maxH };
  });
}

function normalizeLayoutWithConstraints(
  value: unknown,
  constraints: readonly WidgetConstraint[],
  columns: number,
): AdaptiveGridLayoutItem[] | null {
  if (!Number.isSafeInteger(columns) || columns < 1 || columns > ADAPTIVE_GRID_BASE_COLUMNS) return null;
  if (!Array.isArray(value) || value.length !== constraints.length) return null;

  const byId = new Map<string, AdaptiveGridLayoutItem>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !hasExactKeys(candidate, ['id', 'x', 'y', 'w', 'h'])) return null;
    if (
      typeof candidate.id !== 'string'
      || !isSafeInteger(candidate.x)
      || !isSafeInteger(candidate.y)
      || !isSafeInteger(candidate.w)
      || !isSafeInteger(candidate.h)
      || byId.has(candidate.id)
    ) return null;

    const constraint = constraints.find((entry) => entry.id === candidate.id);
    if (!constraint) return null;
    const minW = Math.min(constraint.minW, columns);
    const maxW = Math.min(Math.max(constraint.maxW, minW), columns);
    if (
      candidate.x < 0
      || candidate.y < 0
      || candidate.w < minW
      || candidate.w > maxW
      || candidate.h < constraint.minH
      || candidate.h > constraint.maxH
      || candidate.x + candidate.w > columns
      || candidate.y + candidate.h > ADAPTIVE_GRID_MAX_ROWS
    ) return null;

    byId.set(candidate.id, {
      id: candidate.id,
      x: candidate.x,
      y: candidate.y,
      w: candidate.w,
      h: candidate.h,
    });
  }

  const normalized: AdaptiveGridLayoutItem[] = [];
  for (const constraint of constraints) {
    const item = byId.get(constraint.id);
    if (!item) return null;
    normalized.push(item);
  }

  for (let left = 0; left < normalized.length; left += 1) {
    for (let right = left + 1; right < normalized.length; right += 1) {
      if (overlaps(normalized[left], normalized[right])) return null;
    }
  }
  return normalized;
}

export function normalizeAdaptiveGridLayout(
  value: unknown,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
  columns = ADAPTIVE_GRID_BASE_COLUMNS,
): AdaptiveGridLayoutItem[] | null {
  let constraints: WidgetConstraint[];
  try {
    constraints = constraintsForItems(items);
  } catch {
    return null;
  }
  return normalizeLayoutWithConstraints(value, constraints, columns);
}

export function getCuratedAdaptiveGridLayout(
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
): AdaptiveGridLayoutItem[] {
  const constraints = constraintsForItems(items);
  const curated = items.map(({ id, layout }) => ({
    id,
    x: layout.x,
    y: layout.y,
    w: layout.w,
    h: layout.h,
  }));
  const normalized = normalizeLayoutWithConstraints(
    curated,
    constraints,
    ADAPTIVE_GRID_BASE_COLUMNS,
  );
  if (!normalized) throw new RangeError('The curated adaptive-grid layout is invalid or overlaps.');
  return normalized;
}

function validatedStorageKey(storageKey: string): string {
  if (
    typeof storageKey !== 'string'
    || storageKey.length < 1
    || storageKey.length > 200
    || storageKey.trim() !== storageKey
    || /[\u0000-\u001f\u007f]/.test(storageKey)
  ) {
    throw new TypeError('Adaptive-grid storageKey must be a non-empty per-user key without control characters.');
  }
  return encodeURIComponent(storageKey);
}

export function adaptiveGridStorageKey(storageKey: string): string {
  return `${STORAGE_PREFIX}.v${ADAPTIVE_GRID_SCHEMA_VERSION}.${validatedStorageKey(storageKey)}`;
}

export function adaptiveGridDetailsStorageKey(storageKey: string): string {
  return `${DETAILS_STORAGE_PREFIX}.v${ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION}.${validatedStorageKey(storageKey)}`;
}

export function parseAdaptiveGridLayout(
  source: string | null | undefined,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
): AdaptiveGridLayoutItem[] | null {
  if (typeof source !== 'string' || source.length === 0 || source.length > ADAPTIVE_GRID_MAX_JSON_LENGTH) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return null;
  }
  if (!isRecord(parsed) || !hasExactKeys(parsed, ['schemaVersion', 'columns', 'layout'])) return null;
  if (
    parsed.schemaVersion !== ADAPTIVE_GRID_SCHEMA_VERSION
    || parsed.columns !== ADAPTIVE_GRID_BASE_COLUMNS
  ) return null;

  return normalizeAdaptiveGridLayout(parsed.layout, items);
}

export function serializeAdaptiveGridLayout(
  layout: unknown,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
): string {
  const normalized = normalizeAdaptiveGridLayout(layout, items);
  if (!normalized) throw new TypeError('Cannot serialize an invalid adaptive-grid layout.');
  const stored: StoredAdaptiveGridLayout = {
    schemaVersion: ADAPTIVE_GRID_SCHEMA_VERSION,
    columns: ADAPTIVE_GRID_BASE_COLUMNS,
    layout: normalized,
  };
  return JSON.stringify(stored);
}

export function getCuratedAdaptiveGridDetailVisibility(
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
): AdaptiveGridDetailVisibilityItem[] {
  return detailDefinitionsForItems(items).map(({ widgetId, detailId }) => ({
    widgetId,
    detailId,
    visible: true,
  }));
}

export function normalizeAdaptiveGridDetailVisibility(
  value: unknown,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
): AdaptiveGridDetailVisibilityItem[] | null {
  let definitions: Array<{ widgetId: string; detailId: string }>;
  try {
    definitions = detailDefinitionsForItems(items);
  } catch {
    return null;
  }
  if (!Array.isArray(value) || value.length > 1_024) return null;

  const known = new Set(definitions.map(({ widgetId, detailId }) => detailToken(widgetId, detailId)));
  const overrides = new Map<string, boolean>();
  const seen = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !hasExactKeys(candidate, ['widgetId', 'detailId', 'visible'])) return null;
    if (
      typeof candidate.widgetId !== 'string'
      || typeof candidate.detailId !== 'string'
      || typeof candidate.visible !== 'boolean'
      || !ADAPTIVE_GRID_ID_PATTERN.test(candidate.widgetId)
      || !ADAPTIVE_GRID_ID_PATTERN.test(candidate.detailId)
    ) return null;
    const token = detailToken(candidate.widgetId, candidate.detailId);
    if (seen.has(token)) return null;
    seen.add(token);
    if (known.has(token)) overrides.set(token, candidate.visible);
  }

  return definitions.map(({ widgetId, detailId }) => ({
    widgetId,
    detailId,
    visible: overrides.get(detailToken(widgetId, detailId)) ?? true,
  }));
}

export function parseAdaptiveGridDetailVisibility(
  source: string | null | undefined,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
): AdaptiveGridDetailVisibilityItem[] | null {
  if (typeof source !== 'string' || source.length === 0 || source.length > ADAPTIVE_GRID_MAX_JSON_LENGTH) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return null;
  }
  if (!isRecord(parsed) || !hasExactKeys(parsed, ['schemaVersion', 'visibility'])) return null;
  if (parsed.schemaVersion !== ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION) return null;
  return normalizeAdaptiveGridDetailVisibility(parsed.visibility, items);
}

export function serializeAdaptiveGridDetailVisibility(
  visibility: unknown,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
): string {
  const normalized = normalizeAdaptiveGridDetailVisibility(visibility, items);
  if (!normalized) throw new TypeError('Cannot serialize invalid adaptive-grid detail visibility.');
  const stored: StoredAdaptiveGridDetails = {
    schemaVersion: ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION,
    visibility: normalized,
  };
  return JSON.stringify(stored);
}

export function applyAdaptiveGridCommand(
  layout: unknown,
  widgetId: string,
  command: AdaptiveGridCommand,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
  columns = ADAPTIVE_GRID_BASE_COLUMNS,
): AdaptiveGridCommandResult {
  const normalized = normalizeAdaptiveGridLayout(layout, items, columns);
  if (!normalized) return { layout: [], changed: false, reason: 'invalid-layout' };
  const index = normalized.findIndex((item) => item.id === widgetId);
  if (index < 0) return { layout: normalized, changed: false, reason: 'unknown-widget' };

  const constraints = constraintsForItems(items);
  const constraint = constraints.find((entry) => entry.id === widgetId)!;

  const minW = Math.min(constraint.minW, columns);
  const maxW = Math.min(Math.max(constraint.maxW, minW), columns);
  const candidate = { ...normalized[index] };
  let blocked: AdaptiveGridCommandFailure | undefined;

  switch (command) {
    case 'move-left':
      if (candidate.x === 0) blocked = 'boundary';
      else candidate.x -= 1;
      break;
    case 'move-right':
      if (candidate.x + candidate.w >= columns) blocked = 'boundary';
      else candidate.x += 1;
      break;
    case 'move-up':
      if (candidate.y === 0) blocked = 'boundary';
      else candidate.y -= 1;
      break;
    case 'move-down':
      if (candidate.y + candidate.h >= ADAPTIVE_GRID_MAX_ROWS) blocked = 'boundary';
      else candidate.y += 1;
      break;
    case 'grow-width':
      if (candidate.w >= maxW || candidate.x + candidate.w >= columns) blocked = 'maximum';
      else candidate.w += 1;
      break;
    case 'shrink-width':
      if (candidate.w <= minW) blocked = 'minimum';
      else candidate.w -= 1;
      break;
    case 'grow-height':
      if (candidate.h >= constraint.maxH || candidate.y + candidate.h >= ADAPTIVE_GRID_MAX_ROWS) {
        blocked = 'maximum';
      } else candidate.h += 1;
      break;
    case 'shrink-height':
      if (candidate.h <= constraint.minH) blocked = 'minimum';
      else candidate.h -= 1;
      break;
  }

  if (blocked) return { layout: normalized, changed: false, reason: blocked };
  if (normalized.some((item, itemIndex) => itemIndex !== index && overlaps(candidate, item))) {
    return { layout: normalized, changed: false, reason: 'collision' };
  }

  const next = cloneLayout(normalized);
  next[index] = candidate;
  return { layout: next, changed: true };
}

export function applyAdaptiveGridListCommand(
  baseLayout: unknown,
  visibleLayout: unknown,
  widgetId: string,
  command: Extract<AdaptiveGridCommand, 'move-up' | 'move-down' | 'grow-height' | 'shrink-height'>,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
): AdaptiveGridCommandResult {
  const base = normalizeAdaptiveGridLayout(baseLayout, items, ADAPTIVE_GRID_BASE_COLUMNS);
  const visible = normalizeAdaptiveGridLayout(visibleLayout, items, 1);
  if (!base || !visible) return { layout: [], changed: false, reason: 'invalid-layout' };
  const original = cloneLayout(base);
  const target = base.find((entry) => entry.id === widgetId);
  const definition = items.find((entry) => entry.id === widgetId);
  if (!target || !definition) return { layout: original, changed: false, reason: 'unknown-widget' };

  const order = [...visible].sort((left, right) => left.y - right.y).map((entry) => entry.id);
  const orderIndex = order.indexOf(widgetId);
  if (command === 'move-up' || command === 'move-down') {
    const swapIndex = command === 'move-up' ? orderIndex - 1 : orderIndex + 1;
    if (swapIndex < 0 || swapIndex >= order.length) {
      return { layout: original, changed: false, reason: 'boundary' };
    }
    [order[orderIndex], order[swapIndex]] = [order[swapIndex]!, order[orderIndex]!];
  } else {
    const minimum = definition.layout.minH ?? 1;
    const maximum = definition.layout.maxH ?? ADAPTIVE_GRID_MAX_WIDGET_HEIGHT;
    if (command === 'grow-height' && target.h >= maximum) {
      return { layout: original, changed: false, reason: 'maximum' };
    }
    if (command === 'shrink-height' && target.h <= minimum) {
      return { layout: original, changed: false, reason: 'minimum' };
    }
    target.h += command === 'grow-height' ? 1 : -1;
  }

  const byId = new Map(base.map((entry) => [entry.id, entry]));
  const reflowed: AdaptiveGridLayoutItem[] = [];
  let x = 0;
  let y = 0;
  let rowHeight = 0;
  for (const id of order) {
    const entry = byId.get(id)!;
    if (entry.w === ADAPTIVE_GRID_BASE_COLUMNS || x + entry.w > ADAPTIVE_GRID_BASE_COLUMNS) {
      if (x > 0) y += rowHeight;
      x = 0;
      rowHeight = 0;
    }
    reflowed.push({ ...entry, x, y });
    if (entry.w === ADAPTIVE_GRID_BASE_COLUMNS) {
      y += entry.h;
      x = 0;
      rowHeight = 0;
    } else {
      x += entry.w;
      rowHeight = Math.max(rowHeight, entry.h);
      if (x === ADAPTIVE_GRID_BASE_COLUMNS) {
        y += rowHeight;
        x = 0;
        rowHeight = 0;
      }
    }
  }
  if (y + rowHeight > ADAPTIVE_GRID_MAX_ROWS) {
    return { layout: original, changed: false, reason: 'maximum' };
  }
  const normalized = normalizeAdaptiveGridLayout(reflowed, items, ADAPTIVE_GRID_BASE_COLUMNS);
  return normalized
    ? { layout: normalized, changed: !layoutsEqual(original, normalized) }
    : { layout: original, changed: false, reason: 'invalid-layout' };
}

function gridWidget(
  layout: AdaptiveGridLayoutItem,
  item: Pick<AdaptiveGridItem, 'layout'>,
): GridStackWidget {
  return {
    ...layout,
    minW: item.layout.minW ?? 1,
    minH: item.layout.minH ?? 1,
    maxW: item.layout.maxW ?? ADAPTIVE_GRID_BASE_COLUMNS,
    maxH: item.layout.maxH ?? ADAPTIVE_GRID_MAX_WIDGET_HEIGHT,
  };
}

function gridWidgets(
  layout: readonly AdaptiveGridLayoutItem[],
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
): GridStackWidget[] {
  const byId = new Map(items.map((item) => [item.id, item]));
  return layout.map((entry) => gridWidget(entry, byId.get(entry.id)!));
}

function layoutFromGrid(
  grid: GridStack,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
  columns: number,
): AdaptiveGridLayoutItem[] | null {
  const saved = grid.save(false, false, undefined, columns);
  return inflateGridStackSavedLayout(saved, items, columns);
}

export function inflateGridStackSavedLayout(
  saved: unknown,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
  columns = ADAPTIVE_GRID_BASE_COLUMNS,
): AdaptiveGridLayoutItem[] | null {
  if (!Array.isArray(saved)) return null;
  const byId = new Map(items.map((item) => [item.id, item]));
  const candidate = saved.map((value) => {
    if (!isRecord(value) || typeof value.id !== 'string') return null;
    const definition = byId.get(value.id);
    if (!definition) return null;
    return {
      id: value.id,
      x: value.x ?? 0,
      y: value.y ?? 0,
      // GridStack deliberately omits dimensions equal to the widget minimum
      // when serializing. Restore those values before strict validation.
      w: value.w ?? Math.min(definition.layout.minW ?? 1, columns),
      h: value.h ?? (definition.layout.minH ?? 1),
    };
  });
  if (candidate.some((value) => value === null)) return null;
  return normalizeAdaptiveGridLayout(candidate, items, columns);
}

function initialStoredLayout(
  namespacedStorageKey: string,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'layout'>[],
  curated: readonly AdaptiveGridLayoutItem[],
): AdaptiveGridLayoutItem[] {
  if (typeof window === 'undefined') return cloneLayout(curated);
  try {
    return parseAdaptiveGridLayout(window.localStorage.getItem(namespacedStorageKey), items)
      ?? cloneLayout(curated);
  } catch {
    return cloneLayout(curated);
  }
}

function initialStoredDetailVisibility(
  namespacedStorageKey: string,
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
  curated: readonly AdaptiveGridDetailVisibilityItem[],
): AdaptiveGridDetailVisibilityItem[] {
  if (typeof window === 'undefined') return curated.map((entry) => ({ ...entry }));
  try {
    return parseAdaptiveGridDetailVisibility(window.localStorage.getItem(namespacedStorageKey), items)
      ?? curated.map((entry) => ({ ...entry }));
  } catch {
    return curated.map((entry) => ({ ...entry }));
  }
}

function hiddenTokensFromVisibility(
  visibility: readonly AdaptiveGridDetailVisibilityItem[],
): Set<string> {
  return new Set(
    visibility
      .filter((entry) => !entry.visible)
      .map((entry) => detailToken(entry.widgetId, entry.detailId)),
  );
}

function visibilityFromHiddenTokens(
  items: readonly Pick<AdaptiveGridItem, 'id' | 'details'>[],
  hiddenTokens: ReadonlySet<string>,
): AdaptiveGridDetailVisibilityItem[] {
  return getCuratedAdaptiveGridDetailVisibility(items).map((entry) => ({
    ...entry,
    visible: !hiddenTokens.has(detailToken(entry.widgetId, entry.detailId)),
  }));
}

function configurationSignature(items: readonly Pick<AdaptiveGridItem, 'id' | 'layout' | 'details'>[]): string {
  detailDefinitionsForItems(items);
  return JSON.stringify(items.map(({ id, layout, details }) => ({
    id,
    x: layout.x,
    y: layout.y,
    w: layout.w,
    h: layout.h,
    minW: layout.minW ?? 1,
    minH: layout.minH ?? 1,
    maxW: layout.maxW ?? ADAPTIVE_GRID_BASE_COLUMNS,
    maxH: layout.maxH ?? ADAPTIVE_GRID_MAX_WIDGET_HEIGHT,
    details: (details ?? []).map((detail) => detail.id),
  })));
}

function widgetElement(grid: GridStack, widgetId: string): GridItemHTMLElement | undefined {
  return grid.getGridItems().find((element) => element.gridstackNode?.id === widgetId);
}

export function AdaptiveGrid({
  items,
  storageKey,
  locale = 'en',
  ariaLabel,
  className,
  onLayoutChange,
  onDetailVisibilityChange,
}: AdaptiveGridProps) {
  const strings = STRINGS[locale] ?? STRINGS.en;
  const curatedLayout = getCuratedAdaptiveGridLayout(items);
  const curatedDetailVisibility = getCuratedAdaptiveGridDetailVisibility(items);
  const namespacedStorageKey = adaptiveGridStorageKey(storageKey);
  const namespacedDetailsStorageKey = adaptiveGridDetailsStorageKey(storageKey);
  const configSignature = configurationSignature(items);
  const initialLayout = useMemo(
    () => initialStoredLayout(namespacedStorageKey, items, curatedLayout),
    // configSignature captures all layout fields while allowing content to update independently.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [configSignature, namespacedStorageKey],
  );
  const initialDetailVisibility = useMemo(
    () => initialStoredDetailVisibility(
      namespacedDetailsStorageKey,
      items,
      curatedDetailVisibility,
    ),
    // Detail labels and live content can change without changing persistence identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [configSignature, namespacedDetailsStorageKey],
  );
  const initialHiddenDetailTokens = useMemo(
    () => hiddenTokensFromVisibility(initialDetailVisibility),
    [initialDetailVisibility],
  );
  const gridId = useId().replace(/:/g, '');
  const gridElementRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<GridStack | null>(null);
  const itemsRef = useRef(items);
  const stringsRef = useRef(strings);
  const curatedRef = useRef(curatedLayout);
  const onLayoutChangeRef = useRef(onLayoutChange);
  const onDetailVisibilityChangeRef = useRef(onDetailVisibilityChange);
  const committedLayoutRef = useRef(cloneLayout(initialLayout));
  const workingLayoutRef = useRef(cloneLayout(initialLayout));
  const editSnapshotRef = useRef<AdaptiveGridLayoutItem[] | null>(null);
  const committedHiddenDetailTokensRef = useRef(cloneHiddenDetailTokens(initialHiddenDetailTokens));
  const workingHiddenDetailTokensRef = useRef(cloneHiddenDetailTokens(initialHiddenDetailTokens));
  const editHiddenDetailSnapshotRef = useRef<Set<string> | null>(null);
  const historyRef = useRef<AdaptiveGridEditSnapshot[]>([]);
  const editingRef = useRef(false);
  const suppressGridChangeRef = useRef(false);
  const [renderLayout, setRenderLayout] = useState(() => cloneLayout(initialLayout));
  const [renderHiddenDetailTokens, setRenderHiddenDetailTokens] = useState(
    () => cloneHiddenDetailTokens(initialHiddenDetailTokens),
  );
  const [editing, setEditing] = useState(false);
  const [ready, setReady] = useState(false);
  const [canUndo, setCanUndo] = useState(false);
  const [announcement, setAnnouncement] = useState<Announcement>({ sequence: 0, text: '' });
  const [viewportMode, setViewportMode] = useState<AdaptiveGridViewportMode>(
    currentAdaptiveGridViewportMode,
  );

  itemsRef.current = items;
  stringsRef.current = strings;
  curatedRef.current = curatedLayout;
  onLayoutChangeRef.current = onLayoutChange;
  onDetailVisibilityChangeRef.current = onDetailVisibilityChange;

  const layoutById = new Map(renderLayout.map((entry) => [entry.id, entry]));
  const compactPlacementById = useMemo(() => new Map(
    getAdaptiveGridCompactPlacements(renderLayout).map((placement) => [placement.id, placement]),
  ), [renderLayout]);

  function announce(text: string) {
    setAnnouncement((current) => ({ sequence: current.sequence + 1, text }));
  }

  function setGridInteraction(enabled: boolean) {
    editingRef.current = enabled;
    setEditing(enabled);
    gridRef.current?.enableMove(enabled).enableResize(enabled);
  }

  function loadWithoutRemovingReactNodes(layout: readonly AdaptiveGridLayoutItem[]) {
    const grid = gridRef.current;
    if (!grid) return;
    suppressGridChangeRef.current = true;
    try {
      const visibleColumns = grid.getColumn();
      if (visibleColumns !== ADAPTIVE_GRID_BASE_COLUMNS) {
        grid.column(ADAPTIVE_GRID_BASE_COLUMNS, 'moveScale');
      }
      // addRemove=false is essential: React, not GridStack, owns every content node.
      grid.load(gridWidgets(layout, itemsRef.current), false);
      if (visibleColumns !== ADAPTIVE_GRID_BASE_COLUMNS) {
        // Reflow from the canonical geometry so cancel/reset cannot feed
        // 12-column coordinates directly into a narrower live engine.
        grid.column(visibleColumns, visibleColumns === 1 ? 'list' : 'moveScale');
      }
    } finally {
      suppressGridChangeRef.current = false;
    }
  }

  function recordWorkingConfiguration(
    nextLayout: readonly AdaptiveGridLayoutItem[],
    nextHiddenDetailTokens: ReadonlySet<string>,
  ) {
    if (
      layoutsEqual(workingLayoutRef.current, nextLayout)
      && hiddenDetailTokensEqual(workingHiddenDetailTokensRef.current, nextHiddenDetailTokens)
    ) return;
    historyRef.current = [
      ...historyRef.current,
      {
        layout: cloneLayout(workingLayoutRef.current),
        hiddenDetailTokens: cloneHiddenDetailTokens(workingHiddenDetailTokensRef.current),
      },
    ].slice(-ADAPTIVE_GRID_HISTORY_LIMIT);
    workingLayoutRef.current = cloneLayout(nextLayout);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(nextHiddenDetailTokens);
    setCanUndo(historyRef.current.length > 0);
  }

  function recordWorkingLayout(next: readonly AdaptiveGridLayoutItem[]) {
    recordWorkingConfiguration(next, workingHiddenDetailTokensRef.current);
  }

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const updateFromViewport = () => setViewportMode(currentAdaptiveGridViewportMode());
    window.addEventListener('resize', updateFromViewport, { passive: true });
    window.addEventListener('orientationchange', updateFromViewport, { passive: true });
    updateFromViewport();
    return () => {
      window.removeEventListener('resize', updateFromViewport);
      window.removeEventListener('orientationchange', updateFromViewport);
    };
  }, []);

  useEffect(() => {
    const element = gridElementRef.current;
    if (!element) return undefined;
    let cancelled = false;
    const selected = initialStoredLayout(namespacedStorageKey, items, curatedLayout);
    const selectedDetailVisibility = initialStoredDetailVisibility(
      namespacedDetailsStorageKey,
      items,
      curatedDetailVisibility,
    );
    const selectedHiddenDetailTokens = hiddenTokensFromVisibility(selectedDetailVisibility);
    committedLayoutRef.current = cloneLayout(selected);
    workingLayoutRef.current = cloneLayout(selected);
    editSnapshotRef.current = null;
    committedHiddenDetailTokensRef.current = cloneHiddenDetailTokens(selectedHiddenDetailTokens);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(selectedHiddenDetailTokens);
    editHiddenDetailSnapshotRef.current = null;
    historyRef.current = [];
    editingRef.current = false;
    setRenderLayout(cloneLayout(selected));
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(selectedHiddenDetailTokens));
    setEditing(false);
    setCanUndo(false);
    setReady(false);
    let stopListeningForMotionPreference: (() => void) | null = null;

    void import('gridstack').then(({ GridStack }) => {
      if (cancelled) return;
      const motionPreference = typeof window.matchMedia === 'function'
        ? window.matchMedia('(prefers-reduced-motion: reduce)')
        : null;
      const reducedMotion = motionPreference?.matches ?? false;
      const options: GridStackOptions = {
        acceptWidgets: false,
        alwaysShowResizeHandle: false,
        animate: !reducedMotion,
        cellHeight: 84,
        column: ADAPTIVE_GRID_BASE_COLUMNS,
        disableDrag: true,
        disableResize: true,
        draggable: {
          handle: '.adaptive-grid__drag-handle',
          cancel: 'button,a,input,select,textarea,[data-grid-no-drag]',
          scroll: true,
        },
        // Preserve intentional keyboard moves and saved vertical gaps.
        float: true,
        handle: '.adaptive-grid__drag-handle',
        margin: 8,
        maxRow: ADAPTIVE_GRID_MAX_ROWS,
        resizable: { handles: 'se', autoHide: true },
      };
      const grid = GridStack.init(options, element);
      if (!grid) throw new Error('Adaptive grid element could not be initialized.');
      if (cancelled) {
        grid.destroy(false);
        return;
      }
      gridRef.current = grid;
      suppressGridChangeRef.current = true;
      try {
        // GridStack always retains the canonical editable 12-column geometry.
        // Compact screens render that geometry as a natural-height CSS flow,
        // so rotating a device cannot corrupt or overwrite the saved desktop layout.
        grid.load(gridWidgets(selected, items), false);
        grid.enableMove(false).enableResize(false);
      } finally {
        suppressGridChangeRef.current = false;
      }
      if (motionPreference) {
        stopListeningForMotionPreference = listenForMediaQueryChange(
          motionPreference,
          (event) => grid.setAnimation(!event.matches),
        );
      }
      grid.on('change', () => {
        if (
          !editingRef.current
          || suppressGridChangeRef.current
          || grid.isIgnoreChangeCB()
        ) return;
        const next = layoutFromGrid(grid, itemsRef.current, ADAPTIVE_GRID_BASE_COLUMNS);
        if (!next) {
          announce(stringsRef.current.invalidLayout);
          return;
        }
        recordWorkingLayout(next);
        announce(stringsRef.current.changed);
      });
      setReady(true);
    }).catch(() => {
      if (!cancelled) {
        setReady(false);
        announce(stringsRef.current.unavailable);
      }
    });

    return () => {
      cancelled = true;
      stopListeningForMotionPreference?.();
      const grid = gridRef.current;
      if (grid) {
        gridRef.current = null;
        grid.offAll();
        // false preserves the grid element and all React-rendered widget content.
        grid.destroy(false);
      }
    };
    // The string signature intentionally controls re-initialization, rather than item content identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configSignature, namespacedDetailsStorageKey, namespacedStorageKey]);

  useEffect(() => {
    const grid = gridRef.current;
    if (!grid) return;
    if (viewportMode === 'desktop') {
      grid.enableMove(editingRef.current).enableResize(editingRef.current);
      return;
    }

    grid.enableMove(false).enableResize(false);
    if (!editingRef.current) return;

    // A fixed-row drag session cannot be represented faithfully by the compact
    // natural-height flow. Restore the pre-edit snapshot when a resize/orientation
    // change crosses the compact breakpoint rather than persisting ambiguous geometry.
    const snapshot = editSnapshotRef.current ?? committedLayoutRef.current;
    const hiddenDetailSnapshot = editHiddenDetailSnapshotRef.current
      ?? committedHiddenDetailTokensRef.current;
    loadWithoutRemovingReactNodes(snapshot);
    workingLayoutRef.current = cloneLayout(snapshot);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(hiddenDetailSnapshot);
    historyRef.current = [];
    editSnapshotRef.current = null;
    editHiddenDetailSnapshotRef.current = null;
    editingRef.current = false;
    setEditing(false);
    setCanUndo(false);
    setRenderLayout(cloneLayout(committedLayoutRef.current));
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(committedHiddenDetailTokensRef.current));
    announce(stringsRef.current.compactEditingCancelled);
    // loadWithoutRemovingReactNodes and announce are stable ref-backed component helpers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewportMode]);

  function beginEditing() {
    const grid = gridRef.current;
    if (!ready || !grid || viewportMode !== 'desktop') {
      announce(strings.unavailable);
      return;
    }
    const current = layoutFromGrid(grid, items, ADAPTIVE_GRID_BASE_COLUMNS);
    if (!current) {
      announce(strings.invalidLayout);
      return;
    }
    committedLayoutRef.current = cloneLayout(current);
    workingLayoutRef.current = cloneLayout(current);
    editSnapshotRef.current = cloneLayout(current);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(
      committedHiddenDetailTokensRef.current,
    );
    editHiddenDetailSnapshotRef.current = cloneHiddenDetailTokens(
      committedHiddenDetailTokensRef.current,
    );
    historyRef.current = [];
    setCanUndo(false);
    setGridInteraction(true);
    announce(strings.editingStarted);
  }

  function cancelEditing() {
    const snapshot = editSnapshotRef.current ?? committedLayoutRef.current;
    const hiddenDetailSnapshot = editHiddenDetailSnapshotRef.current
      ?? committedHiddenDetailTokensRef.current;
    loadWithoutRemovingReactNodes(snapshot);
    workingLayoutRef.current = cloneLayout(snapshot);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(hiddenDetailSnapshot);
    historyRef.current = [];
    editSnapshotRef.current = null;
    editHiddenDetailSnapshotRef.current = null;
    setCanUndo(false);
    setGridInteraction(false);
    setRenderLayout(cloneLayout(committedLayoutRef.current));
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(committedHiddenDetailTokensRef.current));
    announce(strings.cancelled);
  }

  function saveEditing() {
    const grid = gridRef.current;
    if (!grid) {
      announce(strings.unavailable);
      return;
    }
    const next = layoutFromGrid(grid, items, ADAPTIVE_GRID_BASE_COLUMNS);
    if (!next) {
      announce(strings.saveFailed);
      return;
    }
    const nextDetailVisibility = visibilityFromHiddenTokens(
      items,
      workingHiddenDetailTokensRef.current,
    );
    let previousLayout: string | null = null;
    let previousDetails: string | null = null;
    let layoutWritten = false;
    let detailsWritten = false;
    try {
      previousLayout = window.localStorage.getItem(namespacedStorageKey);
      previousDetails = window.localStorage.getItem(namespacedDetailsStorageKey);
      window.localStorage.setItem(
        namespacedStorageKey,
        serializeAdaptiveGridLayout(next, items),
      );
      layoutWritten = true;
      window.localStorage.setItem(
        namespacedDetailsStorageKey,
        serializeAdaptiveGridDetailVisibility(nextDetailVisibility, items),
      );
      detailsWritten = true;
    } catch {
      try {
        if (layoutWritten) {
          if (previousLayout === null) window.localStorage.removeItem(namespacedStorageKey);
          else window.localStorage.setItem(namespacedStorageKey, previousLayout);
        }
        if (detailsWritten) {
          if (previousDetails === null) window.localStorage.removeItem(namespacedDetailsStorageKey);
          else window.localStorage.setItem(namespacedDetailsStorageKey, previousDetails);
        }
      } catch {
        // Best-effort rollback. The in-memory committed state stays unchanged.
      }
      announce(strings.saveFailed);
      return;
    }

    committedLayoutRef.current = cloneLayout(next);
    workingLayoutRef.current = cloneLayout(next);
    committedHiddenDetailTokensRef.current = cloneHiddenDetailTokens(
      workingHiddenDetailTokensRef.current,
    );
    editSnapshotRef.current = null;
    editHiddenDetailSnapshotRef.current = null;
    historyRef.current = [];
    setCanUndo(false);
    setRenderLayout(cloneLayout(next));
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(workingHiddenDetailTokensRef.current));
    setGridInteraction(false);
    onLayoutChangeRef.current?.(cloneLayout(next));
    onDetailVisibilityChangeRef.current?.(nextDetailVisibility.map((entry) => ({ ...entry })));
    announce(strings.saved);
  }

  function undoLayoutChange() {
    const previous = historyRef.current.at(-1);
    if (!previous) return;
    historyRef.current = historyRef.current.slice(0, -1);
    workingLayoutRef.current = cloneLayout(previous.layout);
    workingHiddenDetailTokensRef.current = cloneHiddenDetailTokens(previous.hiddenDetailTokens);
    setCanUndo(historyRef.current.length > 0);
    loadWithoutRemovingReactNodes(previous.layout);
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(previous.hiddenDetailTokens));
    announce(strings.undone);
  }

  function resetToCuratedLayout() {
    const curated = cloneLayout(curatedRef.current);
    const curatedHiddenDetailTokens = new Set<string>();
    recordWorkingConfiguration(curated, curatedHiddenDetailTokens);
    loadWithoutRemovingReactNodes(curated);
    setRenderHiddenDetailTokens(curatedHiddenDetailTokens);
    announce(strings.resetApplied);
  }

  function toggleDetailVisibility(widgetId: string, detail: AdaptiveGridDetailItem) {
    if (!editingRef.current) return;
    const token = detailToken(widgetId, detail.id);
    const nextHiddenDetailTokens = cloneHiddenDetailTokens(workingHiddenDetailTokensRef.current);
    const currentlyVisible = !nextHiddenDetailTokens.has(token);
    if (currentlyVisible) nextHiddenDetailTokens.add(token);
    else nextHiddenDetailTokens.delete(token);
    recordWorkingConfiguration(workingLayoutRef.current, nextHiddenDetailTokens);
    setRenderHiddenDetailTokens(cloneHiddenDetailTokens(nextHiddenDetailTokens));
    announce(currentlyVisible ? strings.detailHidden(detail.label) : strings.detailShown(detail.label));
  }

  function applyKeyboardCommand(widgetId: string, command: AdaptiveGridCommand) {
    const grid = gridRef.current;
    const item = items.find((candidate) => candidate.id === widgetId);
    if (!editingRef.current || !grid || !item) return;
    const columns = grid.getColumn();
    const visibleLayout = layoutFromGrid(grid, items, columns);
    if (!visibleLayout) {
      announce(strings.invalidLayout);
      return;
    }

    if (
      columns === 1
      && (command === 'move-up' || command === 'move-down' || command === 'grow-height' || command === 'shrink-height')
    ) {
      const previous = layoutFromGrid(grid, items, ADAPTIVE_GRID_BASE_COLUMNS);
      if (!previous) {
        announce(strings.invalidLayout);
        return;
      }
      const result = applyAdaptiveGridListCommand(
        previous,
        visibleLayout,
        widgetId,
        command,
        items,
      );
      if (!result.changed) {
        announce(strings.commandBlocked(item.label, strings.command[command]));
        return;
      }
      historyRef.current = [...historyRef.current, {
        layout: cloneLayout(previous),
        hiddenDetailTokens: cloneHiddenDetailTokens(workingHiddenDetailTokensRef.current),
      }]
        .slice(-ADAPTIVE_GRID_HISTORY_LIMIT);
      workingLayoutRef.current = cloneLayout(result.layout);
      setCanUndo(true);
      loadWithoutRemovingReactNodes(result.layout);
      announce(strings.commandApplied(item.label, strings.command[command]));
      return;
    }

    const result = applyAdaptiveGridCommand(visibleLayout, widgetId, command, items, columns);
    if (!result.changed) {
      announce(strings.commandBlocked(item.label, strings.command[command]));
      return;
    }

    const element = widgetElement(grid, widgetId);
    const nextWidget = result.layout.find((entry) => entry.id === widgetId);
    if (!element || !nextWidget) {
      announce(strings.commandBlocked(item.label, strings.command[command]));
      return;
    }
    const previous = layoutFromGrid(grid, items, ADAPTIVE_GRID_BASE_COLUMNS);
    if (!previous) {
      announce(strings.invalidLayout);
      return;
    }
    suppressGridChangeRef.current = true;
    try {
      grid.update(element, {
        x: nextWidget.x,
        y: nextWidget.y,
        w: nextWidget.w,
        h: nextWidget.h,
      });
    } finally {
      suppressGridChangeRef.current = false;
    }
    const next = layoutFromGrid(grid, items, ADAPTIVE_GRID_BASE_COLUMNS);
    if (!next) {
      loadWithoutRemovingReactNodes(previous);
      announce(strings.commandBlocked(item.label, strings.command[command]));
      return;
    }
    if (!layoutsEqual(previous, next)) {
      historyRef.current = [...historyRef.current, {
        layout: cloneLayout(previous),
        hiddenDetailTokens: cloneHiddenDetailTokens(workingHiddenDetailTokensRef.current),
      }]
        .slice(-ADAPTIVE_GRID_HISTORY_LIMIT);
      workingLayoutRef.current = cloneLayout(next);
      setCanUndo(true);
    }
    announce(strings.commandApplied(item.label, strings.command[command]));
  }

  const rootClassName = [
    'adaptive-grid',
    editing ? 'adaptive-grid--editing' : '',
    `adaptive-grid--${viewportMode}`,
    className ?? '',
  ].filter(Boolean).join(' ');

  return (
    <section
      className={rootClassName}
      aria-label={ariaLabel ?? strings.grid}
      data-layout-mode={viewportMode}
    >
      <div
        className="adaptive-grid__toolbar"
        role="toolbar"
        aria-label={strings.toolbar}
        hidden={viewportMode !== 'desktop'}
      >
        {!editing ? (
          <button type="button" onClick={beginEditing} disabled={!ready}>
            {strings.edit}
          </button>
        ) : (
          <>
            <span className="adaptive-grid__edit-hint">{strings.detailHint}</span>
            <button type="button" onClick={undoLayoutChange} disabled={!canUndo}>
              {strings.undo}
            </button>
            <button type="button" onClick={resetToCuratedLayout}>
              {strings.reset}
            </button>
            <button type="button" onClick={cancelEditing}>
              {strings.cancel}
            </button>
            <button type="button" className="adaptive-grid__save" onClick={saveEditing}>
              {strings.save}
            </button>
          </>
        )}
      </div>

      <div ref={gridElementRef} className="grid-stack adaptive-grid__grid">
        {items.map((item, index) => {
          const layout = layoutById.get(item.id) ?? curatedLayout[index];
          const compactPlacement = compactPlacementById.get(item.id);
          const headingId = `${gridId}-widget-${index}`;
          const detailContext: AdaptiveGridDetailContextValue = {
            widgetId: item.id,
            hiddenDetailTokens: renderHiddenDetailTokens,
          };
          const widgetStyle: CSSProperties = { order: compactPlacement?.order ?? index };
          const attributes = {
            'gs-id': item.id,
            'gs-x': String(layout.x),
            'gs-y': String(layout.y),
            'gs-w': String(layout.w),
            'gs-h': String(layout.h),
            'gs-min-w': String(item.layout.minW ?? 1),
            'gs-min-h': String(item.layout.minH ?? 1),
            'gs-max-w': String(item.layout.maxW ?? ADAPTIVE_GRID_BASE_COLUMNS),
            'gs-max-h': String(item.layout.maxH ?? ADAPTIVE_GRID_MAX_WIDGET_HEIGHT),
          };
          return (
            <div
              key={item.id}
              className={[
                'grid-stack-item',
                'adaptive-grid__widget',
                compactPlacement?.tabletSpan === 2 ? 'adaptive-grid__widget--wide' : '',
              ].filter(Boolean).join(' ')}
              data-widget-id={item.id}
              data-compact-span={compactPlacement?.tabletSpan ?? 1}
              role="group"
              aria-labelledby={headingId}
              style={widgetStyle}
              {...attributes}
            >
              <div className="grid-stack-item-content adaptive-grid__widget-content">
                <header className="adaptive-grid__widget-header">
                  <h2 id={headingId}>{item.label}</h2>
                  <span
                    className="adaptive-grid__drag-handle"
                    aria-label={strings.dragHandle(item.label)}
                    role="img"
                  >
                    <span aria-hidden="true">⠇</span>
                  </span>
                  <div
                    className="adaptive-grid__widget-controls"
                    role="group"
                    aria-label={strings.controls(item.label)}
                    hidden={!editing}
                    data-grid-no-drag
                  >
                    {COMMANDS.map((command) => (
                      <button
                        key={command}
                        type="button"
                        aria-label={strings.command[command]}
                        title={strings.command[command]}
                        onClick={() => applyKeyboardCommand(item.id, command)}
                      >
                        {strings.commandGlyph[command]}
                      </button>
                    ))}
                  </div>
                </header>
                {(item.details?.length ?? 0) > 0 && (
                  <div
                    className="adaptive-grid__detail-controls"
                    role="group"
                    aria-label={strings.detailControls(item.label)}
                    hidden={!editing}
                    data-grid-no-drag
                  >
                    <span className="adaptive-grid__detail-controls-title">
                      {strings.detailTitle}
                    </span>
                    <div className="adaptive-grid__detail-switches">
                      {item.details?.map((detail) => {
                        const visible = !renderHiddenDetailTokens.has(detailToken(item.id, detail.id));
                        return (
                          <button
                            key={detail.id}
                            type="button"
                            className="adaptive-grid__detail-switch"
                            role="switch"
                            aria-checked={visible}
                            aria-label={strings.detailToggle(detail.label, visible)}
                            title={strings.detailToggle(detail.label, visible)}
                            data-detail-id={detail.id}
                            data-detail-visible={visible ? 'true' : 'false'}
                            onClick={() => toggleDetailVisibility(item.id, detail)}
                          >
                            <b aria-hidden="true">{strings.detailState(visible)}</b>
                            <span>{detail.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
                <div className="adaptive-grid__widget-body" data-grid-no-drag>
                  <AdaptiveGridDetailContext.Provider value={detailContext}>
                    {item.content}
                  </AdaptiveGridDetailContext.Provider>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="adaptive-grid__live" aria-live="polite" aria-atomic="true" role="status">
        <span key={announcement.sequence}>{announcement.text}</span>
      </div>
    </section>
  );
}

export default AdaptiveGrid;
