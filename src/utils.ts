const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function clampPercent(value: number | null | undefined): number {
  const numeric = typeof value === 'number' && Number.isFinite(value) ? value : 0;
  return Math.max(0, Math.min(100, numeric));
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  return Number.isFinite(value) ? `${Number(value).toFixed(digits)}%` : '—';
}

export function formatBytes(value: number | null | undefined, digits = 1): string {
  if (!Number.isFinite(value) || Number(value) < 0) return '—';
  value = Number(value);
  if (value === 0) return '0 B';
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), BYTE_UNITS.length - 1);
  const amount = value / 1024 ** unit;
  return `${amount.toFixed(amount >= 100 || unit === 0 ? 0 : digits)} ${BYTE_UNITS[unit]}`;
}

export function formatRate(value: number | null | undefined): string {
  const formatted = formatBytes(value);
  return formatted === '—' ? formatted : `${formatted}/s`;
}

export function formatClock(hz: number | null): string {
  if (hz == null || !Number.isFinite(hz)) return 'Not available';
  return hz >= 1_000_000_000 ? `${(hz / 1_000_000_000).toFixed(2)} GHz` : `${Math.round(hz / 1_000_000)} MHz`;
}

export function formatUptime(seconds: number | null | undefined): string {
  if (!Number.isFinite(seconds) || Number(seconds) < 0) return 'Unknown';
  seconds = Number(seconds);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function formatTime(value: string | null | undefined, range?: string): string {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  const includeDate = range === '7d' || range === '30d';
  return new Intl.DateTimeFormat(undefined, {
    month: includeDate ? 'short' : undefined,
    day: includeDate ? 'numeric' : undefined,
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'Unknown time';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown time';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

export function safeText(value: unknown, fallback = 'Unknown', maxLength = 180): string {
  if (typeof value !== 'string') return fallback;
  const clean = value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]')
    .replace(/\b(password|passwd|token|secret|authorization|api[-_]?key)\s*[:=]\s*([^\s,;]+)/gi, '$1=[redacted]')
    .replace(/\s+/g, ' ')
    .trim();
  if (!clean) return fallback;
  return clean.length > maxLength ? `${clean.slice(0, maxLength - 1)}…` : clean;
}

export function toneForPercent(value: number | null | undefined): 'good' | 'warn' | 'critical' {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'good';
  if (value >= 90) return 'critical';
  if (value >= 75) return 'warn';
  return 'good';
}
