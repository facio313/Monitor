import type {
  InfrastructureLedgerCategory,
  InfrastructureLedgerCsfFunction,
  InfrastructureLedgerEntry,
  InfrastructureLedgerPriority,
  InfrastructureLedgerSensitivity,
  InfrastructureLedgerStatus,
  InfrastructureLedgerVerification,
  InfrastructureLedgerWorkType,
  MonitorLocale,
} from './types';

export type InfrastructureLedgerMode = 'current' | 'history';
export type InfrastructureLedgerGroup = 'date' | 'category' | 'status';

export interface InfrastructureLedgerFilters {
  query: string;
  category: InfrastructureLedgerCategory | 'all';
  status: InfrastructureLedgerStatus | 'all';
  workType: InfrastructureLedgerWorkType | 'all';
  priority: InfrastructureLedgerPriority | 'all';
  verification: InfrastructureLedgerVerification | 'all';
  sensitivity: InfrastructureLedgerSensitivity | 'all';
  csfFunction: InfrastructureLedgerCsfFunction | 'all';
  from: string;
  to: string;
}

export interface InfrastructureLedgerSummary {
  total: number;
  completed: number;
  open: number;
  pending: number;
  recommended: number;
  deferred: number;
  highPriorityOpen: number;
}

export const INFRASTRUCTURE_LEDGER_CATEGORIES: readonly InfrastructureLedgerCategory[] = [
  'security',
  'identity-access',
  'network',
  'dns-edge',
  'reliability',
  'compute-kernel',
  'storage-filesystem',
  'backup-recovery',
  'observability-logging',
  'service-deployment',
  'containers',
  'packages-firmware',
  'governance-documentation',
  'hardware-physical',
];

export const INFRASTRUCTURE_LEDGER_STATUSES: readonly InfrastructureLedgerStatus[] = [
  'in-progress',
  'pending',
  'deferred',
  'recommended',
  'completed',
  'observed',
  'not-applicable',
  'superseded',
];

export const INFRASTRUCTURE_LEDGER_WORK_TYPES: readonly InfrastructureLedgerWorkType[] = [
  'change',
  'configuration',
  'audit',
  'hardening',
  'mitigation',
  'update',
  'verification',
  'incident',
  'maintenance',
  'recommendation',
  'decision',
  'documentation',
];

export const INFRASTRUCTURE_LEDGER_PRIORITIES: readonly InfrastructureLedgerPriority[] = [
  'critical', 'high', 'medium', 'low', 'informational',
];

export const INFRASTRUCTURE_LEDGER_VERIFICATIONS: readonly InfrastructureLedgerVerification[] = [
  'verified', 'partially-verified', 'unverified', 'not-applicable',
];

export const INFRASTRUCTURE_LEDGER_SENSITIVITIES: readonly InfrastructureLedgerSensitivity[] = [
  'public', 'internal', 'restricted',
];

export const INFRASTRUCTURE_LEDGER_CSF_FUNCTIONS: readonly InfrastructureLedgerCsfFunction[] = [
  'govern', 'identify', 'protect', 'detect', 'respond', 'recover',
];

const OPEN_STATUSES = new Set<InfrastructureLedgerStatus>([
  'in-progress', 'pending', 'deferred', 'recommended',
]);

export function localizedLedgerText(
  value: { ko: string; en: string },
  locale: MonitorLocale,
): string {
  return locale === 'ko' ? value.ko : value.en;
}

export function currentInfrastructureLedgerEntries(
  entries: readonly InfrastructureLedgerEntry[],
): InfrastructureLedgerEntry[] {
  const current = new Map<string, InfrastructureLedgerEntry>();
  for (const entry of entries) {
    const previous = current.get(entry.itemKey);
    if (
      !previous
      || entry.revision > previous.revision
      || entry.revision === previous.revision && entry.occurredAt > previous.occurredAt
    ) current.set(entry.itemKey, entry);
  }
  return [...current.values()].sort((left, right) => (
    right.occurredAt.localeCompare(left.occurredAt) || right.id.localeCompare(left.id)
  ));
}

function dateBoundary(value: string, end: boolean): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return null;
  const time = new Date(`${value}T${end ? '23:59:59.999' : '00:00:00.000'}`).getTime();
  return Number.isFinite(time) ? time : null;
}

export function filterInfrastructureLedgerEntries(
  entries: readonly InfrastructureLedgerEntry[],
  filters: InfrastructureLedgerFilters,
  locale: MonitorLocale,
): InfrastructureLedgerEntry[] {
  const query = filters.query.trim().toLocaleLowerCase();
  const from = dateBoundary(filters.from, false);
  const to = dateBoundary(filters.to, true);
  return entries.filter((entry) => {
    if (filters.category !== 'all' && entry.category !== filters.category) return false;
    if (filters.status !== 'all' && entry.status !== filters.status) return false;
    if (filters.workType !== 'all' && entry.workType !== filters.workType) return false;
    if (filters.priority !== 'all' && entry.priority !== filters.priority) return false;
    if (filters.verification !== 'all' && entry.verification !== filters.verification) return false;
    if (filters.sensitivity !== 'all' && entry.sensitivity !== filters.sensitivity) return false;
    if (filters.csfFunction !== 'all' && !entry.csfFunctions.includes(filters.csfFunction)) return false;
    const occurredAt = Date.parse(entry.occurredAt);
    if (from !== null && occurredAt < from) return false;
    if (to !== null && occurredAt > to) return false;
    if (!query) return true;
    const searchable = [
      entry.id,
      entry.itemKey,
      entry.category,
      entry.workType,
      entry.status,
      entry.priority,
      entry.actor,
      ...entry.csfFunctions,
      ...entry.scope,
      localizedLedgerText(entry.title, locale),
      localizedLedgerText(entry.summary, locale),
      localizedLedgerText(entry.rationale, locale),
      localizedLedgerText(entry.details, locale),
      localizedLedgerText(entry.outcome, locale),
      localizedLedgerText(entry.nextAction, locale),
      ...entry.evidence.flatMap((evidence) => [
        evidence.kind,
        evidence.reference,
        localizedLedgerText(evidence.note, locale),
      ]),
    ].join(' ').toLocaleLowerCase();
    return searchable.includes(query);
  });
}

export function summarizeInfrastructureLedger(
  entries: readonly InfrastructureLedgerEntry[],
): InfrastructureLedgerSummary {
  const current = currentInfrastructureLedgerEntries(entries);
  return {
    total: current.length,
    completed: current.filter((entry) => entry.status === 'completed').length,
    open: current.filter((entry) => OPEN_STATUSES.has(entry.status)).length,
    pending: current.filter((entry) => entry.status === 'pending' || entry.status === 'in-progress').length,
    recommended: current.filter((entry) => entry.status === 'recommended').length,
    deferred: current.filter((entry) => entry.status === 'deferred').length,
    highPriorityOpen: current.filter((entry) => (
      OPEN_STATUSES.has(entry.status) && (entry.priority === 'critical' || entry.priority === 'high')
    )).length,
  };
}

export function infrastructureLedgerDateKey(timestamp: string): string {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return 'unknown';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function groupInfrastructureLedgerEntries(
  entries: readonly InfrastructureLedgerEntry[],
  group: InfrastructureLedgerGroup,
): Array<{ key: string; entries: InfrastructureLedgerEntry[] }> {
  const groups = new Map<string, InfrastructureLedgerEntry[]>();
  for (const entry of entries) {
    const key = group === 'date'
      ? infrastructureLedgerDateKey(entry.occurredAt)
      : group === 'category'
        ? entry.category
        : entry.status;
    const values = groups.get(key) ?? [];
    values.push(entry);
    groups.set(key, values);
  }
  return [...groups.entries()]
    .map(([key, values]) => ({
      key,
      entries: [...values].sort((left, right) => right.occurredAt.localeCompare(left.occurredAt)),
    }))
    .sort((left, right) => {
      if (group === 'date') return right.key.localeCompare(left.key);
      return left.key.localeCompare(right.key);
    });
}
