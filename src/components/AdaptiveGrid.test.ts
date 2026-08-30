import { describe, expect, it } from 'vitest';
import {
  ADAPTIVE_GRID_BASE_COLUMNS,
  ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION,
  ADAPTIVE_GRID_MAX_ROWS,
  ADAPTIVE_GRID_PHONE_MAX_WIDTH,
  ADAPTIVE_GRID_SCHEMA_VERSION,
  ADAPTIVE_GRID_TABLET_MAX_WIDTH,
  adaptiveGridDetailsStorageKey,
  adaptiveGridStorageKey,
  applyAdaptiveGridCommand,
  applyAdaptiveGridListCommand,
  getAdaptiveGridCompactPlacements,
  getCuratedAdaptiveGridDetailVisibility,
  getCuratedAdaptiveGridLayout,
  getAdaptiveGridViewportMode,
  inflateGridStackSavedLayout,
  normalizeAdaptiveGridDetailVisibility,
  normalizeAdaptiveGridLayout,
  parseAdaptiveGridDetailVisibility,
  parseAdaptiveGridLayout,
  serializeAdaptiveGridDetailVisibility,
  serializeAdaptiveGridLayout,
  type AdaptiveGridDetailVisibilityItem,
  type AdaptiveGridItem,
  type AdaptiveGridLayoutItem,
} from './AdaptiveGrid';

type LayoutDefinition = Pick<AdaptiveGridItem, 'id' | 'layout'>;
type DetailDefinition = Pick<AdaptiveGridItem, 'id' | 'details'>;

const definitions: LayoutDefinition[] = [
  {
    id: 'health',
    layout: { x: 0, y: 0, w: 4, h: 3, minW: 2, minH: 2, maxW: 6, maxH: 5 },
  },
  {
    id: 'traffic',
    layout: { x: 4, y: 0, w: 8, h: 3, minW: 3, minH: 2, maxW: 10, maxH: 6 },
  },
  {
    id: 'events',
    layout: { x: 0, y: 3, w: 12, h: 4, minW: 1, minH: 2, maxH: 8 },
  },
];

const curated: AdaptiveGridLayoutItem[] = [
  { id: 'health', x: 0, y: 0, w: 4, h: 3 },
  { id: 'traffic', x: 4, y: 0, w: 8, h: 3 },
  { id: 'events', x: 0, y: 3, w: 12, h: 4 },
];

const detailDefinitions: DetailDefinition[] = [
  {
    id: 'health',
    details: [
      { id: 'cpu', label: 'CPU' },
      { id: 'memory', label: 'Memory' },
    ],
  },
  {
    id: 'traffic',
    details: [
      { id: 'receive', label: 'Receive' },
      { id: 'transmit', label: 'Transmit' },
    ],
  },
  { id: 'events', details: [{ id: 'timeline', label: 'Timeline' }] },
];

const curatedDetailVisibility: AdaptiveGridDetailVisibilityItem[] = [
  { widgetId: 'health', detailId: 'cpu', visible: true },
  { widgetId: 'health', detailId: 'memory', visible: true },
  { widgetId: 'traffic', detailId: 'receive', visible: true },
  { widgetId: 'traffic', detailId: 'transmit', visible: true },
  { widgetId: 'events', detailId: 'timeline', visible: true },
];

function stored(layout: unknown, overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    schemaVersion: ADAPTIVE_GRID_SCHEMA_VERSION,
    columns: ADAPTIVE_GRID_BASE_COLUMNS,
    layout,
    ...overrides,
  });
}

describe('adaptive-grid compact presentation', () => {
  it.each([
    [320, 'phone'],
    [ADAPTIVE_GRID_PHONE_MAX_WIDTH, 'phone'],
    [ADAPTIVE_GRID_PHONE_MAX_WIDTH + 1, 'tablet'],
    [768, 'tablet'],
    [820, 'tablet'],
    [ADAPTIVE_GRID_TABLET_MAX_WIDTH, 'tablet'],
    [ADAPTIVE_GRID_TABLET_MAX_WIDTH + 1, 'desktop'],
    [1440, 'desktop'],
  ] as const)('maps a %dpx viewport to the %s flow', (width, expected) => {
    expect(getAdaptiveGridViewportMode(width)).toBe(expected);
  });

  it('rejects viewport widths that cannot represent a CSS viewport', () => {
    expect(() => getAdaptiveGridViewportMode(-1)).toThrow(/viewport width/i);
    expect(() => getAdaptiveGridViewportMode(Number.NaN)).toThrow(/viewport width/i);
    expect(() => getAdaptiveGridViewportMode(Number.POSITIVE_INFINITY)).toThrow(/viewport width/i);
  });

  it('derives saved-layout reading order and makes only wider-than-half widgets span tablet columns', () => {
    expect(getAdaptiveGridCompactPlacements([
      { id: 'last', x: 0, y: 8, w: 6 },
      { id: 'feature', x: 0, y: 0, w: 12 },
      { id: 'right', x: 6, y: 4, w: 6 },
      { id: 'left', x: 0, y: 4, w: 6 },
      { id: 'wide', x: 0, y: 12, w: 7 },
    ])).toEqual([
      { id: 'last', order: 3, tabletSpan: 1 },
      { id: 'feature', order: 0, tabletSpan: 2 },
      { id: 'right', order: 2, tabletSpan: 1 },
      { id: 'left', order: 1, tabletSpan: 1 },
      { id: 'wide', order: 4, tabletSpan: 2 },
    ]);
  });
});

describe('adaptive-grid curated layout and storage identity', () => {
  it('returns a fresh, exact copy of the curated 12-column layout', () => {
    const first = getCuratedAdaptiveGridLayout(definitions);
    const second = getCuratedAdaptiveGridLayout(definitions);

    expect(first).toEqual(curated);
    expect(second).toEqual(curated);
    expect(first).not.toBe(second);
    expect(first[0]).not.toBe(second[0]);

    first[0].x = 2;
    expect(getCuratedAdaptiveGridLayout(definitions)).toEqual(curated);
  });

  it('rejects malformed definitions, duplicate ids, invalid constraints, and curated overlap', () => {
    expect(() => getCuratedAdaptiveGridLayout([
      definitions[0],
      { ...definitions[1], id: definitions[0].id },
    ])).toThrow(/duplicate/i);
    expect(() => getCuratedAdaptiveGridLayout([
      { id: '../unsafe', layout: { x: 0, y: 0, w: 1, h: 1 } },
    ])).toThrow(/widget id/i);
    expect(() => getCuratedAdaptiveGridLayout([
      { id: 'bad-size', layout: { x: 0, y: 0, w: 1, h: 1, minW: 3, maxW: 2 } },
    ])).toThrow(/constraint/i);
    expect(() => getCuratedAdaptiveGridLayout([
      { id: 'one', layout: { x: 0, y: 0, w: 4, h: 2 } },
      { id: 'two', layout: { x: 3, y: 1, w: 4, h: 2 } },
    ])).toThrow(/overlap/i);
  });

  it('namespaces a per-user key with the schema version and encodes it exactly', () => {
    expect(adaptiveGridStorageKey('alice@example.com')).toBe(
      'monitor.adaptive-grid.v1.alice%40example.com',
    );
    expect(adaptiveGridStorageKey('alice')).not.toBe(adaptiveGridStorageKey('bob'));
    expect(adaptiveGridDetailsStorageKey('alice@example.com')).toBe(
      'monitor.adaptive-grid-details.v1.alice%40example.com',
    );
    expect(ADAPTIVE_GRID_DETAILS_SCHEMA_VERSION).toBe(1);
    expect(() => adaptiveGridStorageKey('')).toThrow(/storageKey/);
    expect(() => adaptiveGridStorageKey(' alice')).toThrow(/storageKey/);
    expect(() => adaptiveGridStorageKey('alice\nadmin')).toThrow(/storageKey/);
  });
});

describe('adaptive-grid layout parser and serializer', () => {
  it('restores minimum dimensions omitted by GridStack at responsive columns', () => {
    expect(inflateGridStackSavedLayout([
      { id: 'health', x: 0, y: 0, w: 2, h: 3 },
      { id: 'traffic', x: 2, y: 0, h: 3 },
      { id: 'events', x: 0, y: 3, w: 8 },
    ], definitions, 8)).toEqual([
      { id: 'health', x: 0, y: 0, w: 2, h: 3 },
      { id: 'traffic', x: 2, y: 0, w: 3, h: 3 },
      { id: 'events', x: 0, y: 3, w: 8, h: 2 },
    ]);
    expect(inflateGridStackSavedLayout([{ id: 'unknown' }], definitions, 8)).toBeNull();
  });

  it('round-trips a valid layout and canonicalizes it to the known widget order', () => {
    const unordered = [curated[2], curated[0], curated[1]];
    const serialized = serializeAdaptiveGridLayout(unordered, definitions);

    expect(JSON.parse(serialized)).toEqual({
      schemaVersion: 1,
      columns: 12,
      layout: curated,
    });
    expect(parseAdaptiveGridLayout(serialized, definitions)).toEqual(curated);
  });

  it('returns detached objects rather than caller-owned layout references', () => {
    const parsed = normalizeAdaptiveGridLayout(curated, definitions)!;
    expect(parsed).toEqual(curated);
    expect(parsed).not.toBe(curated);
    expect(parsed[0]).not.toBe(curated[0]);
  });

  it('fails closed on malformed JSON, oversized input, schema drift, or extra envelope fields', () => {
    expect(parseAdaptiveGridLayout('{', definitions)).toBeNull();
    expect(parseAdaptiveGridLayout('', definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(' '.repeat(64 * 1024 + 1), definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(stored(curated, { schemaVersion: 2 }), definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(stored(curated, { columns: 8 }), definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(JSON.stringify({
      schemaVersion: 1,
      columns: 12,
      layout: curated,
      owner: 'alice',
    }), definitions)).toBeNull();
  });

  it('requires exactly all known widget ids with no unknowns or duplicates', () => {
    expect(parseAdaptiveGridLayout(stored(curated.slice(0, 2)), definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(stored([
      curated[0],
      curated[1],
      { ...curated[2], id: 'unknown' },
    ]), definitions)).toBeNull();
    expect(parseAdaptiveGridLayout(stored([
      curated[0],
      curated[1],
      { ...curated[2], id: curated[1].id },
    ]), definitions)).toBeNull();
  });

  it('rejects extra item fields and every non-integer or unsafe coordinate form', () => {
    expect(parseAdaptiveGridLayout(stored([
      { ...curated[0], label: 'forged' },
      curated[1],
      curated[2],
    ]), definitions)).toBeNull();

    for (const invalid of [1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(normalizeAdaptiveGridLayout([
        { ...curated[0], x: invalid },
        curated[1],
        curated[2],
      ], definitions)).toBeNull();
    }
  });

  it('enforces grid bounds, per-widget min/max size, maximum rows, and collision freedom', () => {
    const invalidLayouts: AdaptiveGridLayoutItem[][] = [
      [{ ...curated[0], x: -1 }, curated[1], curated[2]],
      [{ ...curated[0], x: 10 }, curated[1], curated[2]],
      [{ ...curated[0], w: 1 }, curated[1], curated[2]],
      [{ ...curated[0], w: 7 }, curated[1], curated[2]],
      [{ ...curated[0], h: 1 }, curated[1], curated[2]],
      [{ ...curated[0], h: 6 }, curated[1], curated[2]],
      [{ ...curated[0], y: ADAPTIVE_GRID_MAX_ROWS - curated[0].h + 1 }, curated[1], curated[2]],
      [curated[0], { ...curated[1], x: 3 }, curated[2]],
    ];

    for (const layout of invalidLayouts) {
      expect(normalizeAdaptiveGridLayout(layout, definitions)).toBeNull();
      expect(() => serializeAdaptiveGridLayout(layout, definitions)).toThrow(/invalid/i);
    }
  });

  it('validates responsive layouts against their actual 8/4/1-column bounds', () => {
    const compactDefinitions: LayoutDefinition[] = [
      { id: 'a', layout: { x: 0, y: 0, w: 6, h: 2, minW: 2 } },
      { id: 'b', layout: { x: 6, y: 0, w: 6, h: 2, minW: 2 } },
    ];
    const fourColumns = [
      { id: 'a', x: 0, y: 0, w: 2, h: 2 },
      { id: 'b', x: 2, y: 0, w: 2, h: 2 },
    ];
    const eightColumns = [
      { id: 'a', x: 0, y: 0, w: 4, h: 2 },
      { id: 'b', x: 4, y: 0, w: 4, h: 2 },
    ];
    const oneColumn = [
      { id: 'a', x: 0, y: 0, w: 1, h: 2 },
      { id: 'b', x: 0, y: 2, w: 1, h: 2 },
    ];

    expect(normalizeAdaptiveGridLayout(eightColumns, compactDefinitions, 8)).toEqual(eightColumns);
    expect(normalizeAdaptiveGridLayout(fourColumns, compactDefinitions, 4)).toEqual(fourColumns);
    expect(normalizeAdaptiveGridLayout(oneColumn, compactDefinitions, 1)).toEqual(oneColumn);
    expect(normalizeAdaptiveGridLayout(fourColumns, compactDefinitions, 1)).toBeNull();
    expect(normalizeAdaptiveGridLayout(fourColumns, compactDefinitions, 0)).toBeNull();
    expect(normalizeAdaptiveGridLayout(fourColumns, compactDefinitions, 13)).toBeNull();
  });
});

describe('adaptive-grid detail visibility', () => {
  it('defaults every declared detail to visible in stable widget and detail order', () => {
    const first = getCuratedAdaptiveGridDetailVisibility(detailDefinitions);
    const second = getCuratedAdaptiveGridDetailVisibility(detailDefinitions);

    expect(first).toEqual(curatedDetailVisibility);
    expect(second).toEqual(curatedDetailVisibility);
    expect(first).not.toBe(second);
    expect(first[0]).not.toBe(second[0]);
  });

  it('round-trips hidden details and canonicalizes partial saved visibility', () => {
    const saved = [
      { widgetId: 'traffic', detailId: 'transmit', visible: false },
      { widgetId: 'health', detailId: 'cpu', visible: false },
    ];
    const normalized = normalizeAdaptiveGridDetailVisibility(saved, detailDefinitions)!;
    const serialized = serializeAdaptiveGridDetailVisibility(normalized, detailDefinitions);

    expect(normalized).toEqual([
      { widgetId: 'health', detailId: 'cpu', visible: false },
      { widgetId: 'health', detailId: 'memory', visible: true },
      { widgetId: 'traffic', detailId: 'receive', visible: true },
      { widgetId: 'traffic', detailId: 'transmit', visible: false },
      { widgetId: 'events', detailId: 'timeline', visible: true },
    ]);
    expect(JSON.parse(serialized)).toEqual({
      schemaVersion: 1,
      visibility: normalized,
    });
    expect(parseAdaptiveGridDetailVisibility(serialized, detailDefinitions)).toEqual(normalized);
  });

  it('ignores stale unknown definitions while making newly introduced details visible', () => {
    const source = JSON.stringify({
      schemaVersion: 1,
      visibility: [
        { widgetId: 'health', detailId: 'cpu', visible: false },
        { widgetId: 'retired-widget', detailId: 'old-detail', visible: false },
      ],
    });

    expect(parseAdaptiveGridDetailVisibility(source, detailDefinitions)).toEqual([
      { widgetId: 'health', detailId: 'cpu', visible: false },
      { widgetId: 'health', detailId: 'memory', visible: true },
      { widgetId: 'traffic', detailId: 'receive', visible: true },
      { widgetId: 'traffic', detailId: 'transmit', visible: true },
      { widgetId: 'events', detailId: 'timeline', visible: true },
    ]);
  });

  it('rejects malformed storage, duplicate entries, and unsafe detail definitions', () => {
    expect(parseAdaptiveGridDetailVisibility('{', detailDefinitions)).toBeNull();
    expect(parseAdaptiveGridDetailVisibility(JSON.stringify({
      schemaVersion: 2,
      visibility: [],
    }), detailDefinitions)).toBeNull();
    expect(parseAdaptiveGridDetailVisibility(JSON.stringify({
      schemaVersion: 1,
      visibility: [{ widgetId: 'health', detailId: 'cpu', visible: 'yes' }],
    }), detailDefinitions)).toBeNull();
    expect(parseAdaptiveGridDetailVisibility(JSON.stringify({
      schemaVersion: 1,
      visibility: [
        { widgetId: 'health', detailId: 'cpu', visible: true },
        { widgetId: 'health', detailId: 'cpu', visible: false },
      ],
    }), detailDefinitions)).toBeNull();
    expect(() => getCuratedAdaptiveGridDetailVisibility([
      {
        id: 'health',
        details: [
          { id: 'cpu', label: 'CPU' },
          { id: 'cpu', label: 'Duplicate CPU' },
        ],
      },
    ])).toThrow(/detail id/i);
    expect(() => serializeAdaptiveGridDetailVisibility('invalid', detailDefinitions)).toThrow(/invalid/i);
  });
});

describe('adaptive-grid keyboard layout commands', () => {
  const commandDefinitions: LayoutDefinition[] = [
    {
      id: 'target',
      layout: { x: 2, y: 2, w: 3, h: 3, minW: 2, minH: 2, maxW: 5, maxH: 5 },
    },
    {
      id: 'neighbour',
      layout: { x: 7, y: 2, w: 3, h: 3, minW: 1, minH: 1 },
    },
  ];
  const commandLayout = getCuratedAdaptiveGridLayout(commandDefinitions);

  it.each([
    ['move-left', { x: 1, y: 2, w: 3, h: 3 }],
    ['move-right', { x: 3, y: 2, w: 3, h: 3 }],
    ['move-up', { x: 2, y: 1, w: 3, h: 3 }],
    ['move-down', { x: 2, y: 3, w: 3, h: 3 }],
    ['grow-width', { x: 2, y: 2, w: 4, h: 3 }],
    ['shrink-width', { x: 2, y: 2, w: 2, h: 3 }],
    ['grow-height', { x: 2, y: 2, w: 3, h: 4 }],
    ['shrink-height', { x: 2, y: 2, w: 3, h: 2 }],
  ] as const)('applies %s one grid unit at a time', (command, expected) => {
    const result = applyAdaptiveGridCommand(
      commandLayout,
      'target',
      command,
      commandDefinitions,
    );

    expect(result.changed).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.layout[0]).toEqual({ id: 'target', ...expected });
    expect(commandLayout).toEqual(getCuratedAdaptiveGridLayout(commandDefinitions));
  });

  it('rejects commands that cross a boundary, minimum, maximum, or another widget', () => {
    const boundaryLayout = [
      { id: 'target', x: 0, y: 0, w: 5, h: 5 },
      { id: 'neighbour', x: 5, y: 0, w: 3, h: 3 },
    ];

    expect(applyAdaptiveGridCommand(
      boundaryLayout,
      'target',
      'move-left',
      commandDefinitions,
    ).reason).toBe('boundary');
    expect(applyAdaptiveGridCommand(
      boundaryLayout,
      'target',
      'move-up',
      commandDefinitions,
    ).reason).toBe('boundary');
    expect(applyAdaptiveGridCommand(
      boundaryLayout,
      'target',
      'grow-width',
      commandDefinitions,
    ).reason).toBe('maximum');
    expect(applyAdaptiveGridCommand(
      boundaryLayout,
      'target',
      'grow-height',
      commandDefinitions,
    ).reason).toBe('maximum');

    const minimumLayout = [
      { id: 'target', x: 0, y: 0, w: 2, h: 2 },
      { id: 'neighbour', x: 4, y: 0, w: 3, h: 3 },
    ];
    expect(applyAdaptiveGridCommand(
      minimumLayout,
      'target',
      'shrink-width',
      commandDefinitions,
    ).reason).toBe('minimum');
    expect(applyAdaptiveGridCommand(
      minimumLayout,
      'target',
      'shrink-height',
      commandDefinitions,
    ).reason).toBe('minimum');

    const collisionLayout = [
      { id: 'target', x: 2, y: 2, w: 3, h: 3 },
      { id: 'neighbour', x: 5, y: 2, w: 3, h: 3 },
    ];
    expect(applyAdaptiveGridCommand(
      collisionLayout,
      'target',
      'move-right',
      commandDefinitions,
    ).reason).toBe('collision');
    expect(applyAdaptiveGridCommand(
      collisionLayout,
      'target',
      'grow-width',
      commandDefinitions,
    ).reason).toBe('collision');
  });

  it('fails without partial output for an invalid layout and preserves valid input for an unknown id', () => {
    expect(applyAdaptiveGridCommand(
      [{ ...commandLayout[0], x: -1 }, commandLayout[1]],
      'target',
      'move-right',
      commandDefinitions,
    )).toEqual({ layout: [], changed: false, reason: 'invalid-layout' });

    expect(applyAdaptiveGridCommand(
      commandLayout,
      'missing',
      'move-right',
      commandDefinitions,
    )).toEqual({ layout: commandLayout, changed: false, reason: 'unknown-widget' });
  });

  it('keeps one-column mobile commands within one column while retaining vertical controls', () => {
    const mobileDefinitions: LayoutDefinition[] = [
      { id: 'only', layout: { x: 0, y: 0, w: 12, h: 3, minW: 3, minH: 2 } },
    ];
    const mobileLayout = [{ id: 'only', x: 0, y: 0, w: 1, h: 3 }];

    expect(applyAdaptiveGridCommand(
      mobileLayout,
      'only',
      'grow-width',
      mobileDefinitions,
      1,
    ).changed).toBe(false);
    expect(applyAdaptiveGridCommand(
      mobileLayout,
      'only',
      'move-right',
      mobileDefinitions,
      1,
    ).changed).toBe(false);
    expect(applyAdaptiveGridCommand(
      mobileLayout,
      'only',
      'move-down',
      mobileDefinitions,
      1,
    ).layout[0].y).toBe(1);
  });
});

describe('adaptive-grid single-column list commands', () => {
  const visible = [
    { id: 'health', x: 0, y: 0, w: 1, h: 3 },
    { id: 'traffic', x: 0, y: 3, w: 1, h: 3 },
    { id: 'events', x: 0, y: 6, w: 1, h: 4 },
  ];

  it('reorders a mobile list and deterministically repacks the canonical layout', () => {
    expect(applyAdaptiveGridListCommand(
      curated,
      visible,
      'health',
      'move-down',
      definitions,
    )).toEqual({
      changed: true,
      layout: [
        { id: 'health', x: 8, y: 0, w: 4, h: 3 },
        { id: 'traffic', x: 0, y: 0, w: 8, h: 3 },
        { id: 'events', x: 0, y: 3, w: 12, h: 4 },
      ],
    });
  });

  it('resizes a mobile item and shifts following canonical rows without overlap', () => {
    expect(applyAdaptiveGridListCommand(
      curated,
      visible,
      'health',
      'grow-height',
      definitions,
    )).toEqual({
      changed: true,
      layout: [
        { id: 'health', x: 0, y: 0, w: 4, h: 4 },
        { id: 'traffic', x: 4, y: 0, w: 8, h: 3 },
        { id: 'events', x: 0, y: 4, w: 12, h: 4 },
      ],
    });
    expect(applyAdaptiveGridListCommand(
      curated,
      visible,
      'health',
      'move-up',
      definitions,
    ).reason).toBe('boundary');
  });
});
