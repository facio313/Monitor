import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';
import type { SshAccessFilter, SshAccessRange, SshAccessRecord, SshAccessResponse, SshAccessSource, SshAccessState } from '../src/ssh-access-types.js';

const DAY = 86_400_000;
const MAX_DAY_BYTES = 4 * 1024 * 1024;
const MAX_ROW_BYTES = 2048;
const MAX_ROWS = 10_000;
const MAX_SCAN_BYTES = 16 * 1024 * 1024;
const MAX_SCAN_ROWS = 40_000;
const STALE_AFTER = 300_000;
const RANGES = { '1h': 3_600_000, '6h': 21_600_000, '24h': DAY, '7d': 7 * DAY, '30d': 30 * DAY };
const STATES = ['fresh', 'partial', 'unavailable', 'stale'];
const EVENTS = ['denied', 'invalid_user', 'auth_failed', 'accepted', 'preauth_closed'];
const FILTERS = ['all', 'failed', 'accepted', 'preauth_closed'];
const SOURCES = ['journal:ssh', 'journal:sshd'];
const ERRORS = [null, 'not_configured', 'acquisition_failed', 'acquisition_partial', 'persistence_failed', 'invalid_input'];
const COUNTRIES = new Set(('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ '
  + 'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR '
  + 'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP '
  + 'KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ '
  + 'NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ '
  + 'TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split(' '));
// DB-IP's explicit Kosovo code is a provider exception, not an ISO claim.
COUNTRIES.add('XK');
type Obj = Record<string, unknown>;

export class SshAccessQueryError extends Error {
  constructor() { super('Invalid SSH access query.'); this.name = 'SshAccessQueryError'; }
}

function exact(value: unknown, fields: string[]): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === value.slice(0, 19);
}

function date(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && timestamp(`${value}T00:00:00Z`);
}

/** Do not perform DNS resolution or accept URLs, zones, ports or noncanonical forms. */
export function canonicalSshIp(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 45 || value.includes('%')) return null;
  const family = isIP(value);
  if (family === 4) return value;
  if (family !== 6) return null;
  try {
    const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
    if (normalized !== value) return null;
    const mapped = /^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(normalized);
    if (mapped) {
      const high = Number.parseInt(mapped[1], 16), low = Number.parseInt(mapped[2], 16);
      return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
    }
    return value;
  } catch { return null; }
}

export function parseSshAccessRecord(raw: unknown): SshAccessRecord | null {
  if (!exact(raw, ['schemaVersion', 'id', 'observedAt', 'sourceId', 'sourceIp', 'sourcePort', 'eventType', 'authMethod', 'countryCode', 'countryStatus', 'databaseDate'])
    || raw.schemaVersion !== 1 || typeof raw.id !== 'string' || !/^[a-f0-9]{64}$/.test(raw.id)
    || !timestamp(raw.observedAt) || !SOURCES.includes(raw.sourceId as string) || typeof raw.sourceIp !== 'string' || canonicalSshIp(raw.sourceIp) !== raw.sourceIp
    || !(raw.sourcePort === null || Number.isInteger(raw.sourcePort) && Number(raw.sourcePort) >= 1 && Number(raw.sourcePort) <= 65535)
    || !EVENTS.includes(raw.eventType as string) || ![null, 'publickey', 'password', 'keyboard-interactive'].includes(raw.authMethod as string | null)
    || !(raw.countryCode === null || typeof raw.countryCode === 'string' && /^[A-Z]{2}$/.test(raw.countryCode))
    || !['estimated', 'private', 'unavailable', 'not_found', 'stale'].includes(raw.countryStatus as string)
    || !(raw.databaseDate === null || date(raw.databaseDate))) return null;
  if (raw.countryStatus === 'estimated' && raw.countryCode === null
    || ['private', 'unavailable', 'not_found'].includes(raw.countryStatus as string) && raw.countryCode !== null) return null;
  // Provider-specific/non-ISO codes must not hide otherwise valid access logs.
  const countryCode = typeof raw.countryCode === 'string' && COUNTRIES.has(raw.countryCode) ? raw.countryCode : null;
  const countryStatus = raw.countryCode !== null && countryCode === null && raw.countryStatus !== 'stale' ? 'not_found' : raw.countryStatus;
  // Reconstruct only reviewed fields. No usernames, raw log messages or arbitrary labels.
  return { schemaVersion: 1, id: raw.id, observedAt: raw.observedAt, sourceId: raw.sourceId as SshAccessRecord['sourceId'],
    sourceIp: raw.sourceIp as string, sourcePort: raw.sourcePort as number | null, eventType: raw.eventType as SshAccessRecord['eventType'],
    authMethod: raw.authMethod as SshAccessRecord['authMethod'], countryCode,
    countryStatus: countryStatus as SshAccessRecord['countryStatus'], databaseDate: raw.databaseDate as string | null };
}

function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function parseSource(raw: unknown): SshAccessSource | null {
  if (!exact(raw, ['sourceId', 'status', 'observedAt', 'lastSuccessAt', 'errorClass'])
    || !SOURCES.includes(raw.sourceId as string) || !STATES.includes(raw.status as string)
    || !(raw.observedAt === null || timestamp(raw.observedAt)) || !(raw.lastSuccessAt === null || timestamp(raw.lastSuccessAt))
    || !ERRORS.includes(raw.errorClass as string | null)) return null;
  return raw as unknown as SshAccessSource;
}

function readBounded(path: string, max: number): string | null {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.mode & 0o022 || stat.size > max) throw new Error('Invalid SSH export file');
    const buffer = Buffer.alloc(max + 1);
    let length = 0;
    for (;;) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      length += count;
      if (length > max) throw new Error('Oversized SSH export file');
      if (!count) break;
    }
    const content = buffer.subarray(0, length).toString('utf8');
    if (content.includes('\ufffd')) throw new Error('Invalid SSH export encoding');
    return content;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  } finally { if (fd !== undefined) closeSync(fd); }
}

function validateDirectory(path: string): void {
  const info = lstatSync(path);
  if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o022) throw new Error('Invalid SSH export directory');
}

function orderTime(value: string): string {
  return `${value.slice(0, 19)}.${(value.includes('.') ? value.slice(20, -1) : '').padEnd(6, '0')}Z`;
}

/** Auth is enforced by the sole logs:read API route. No caller-controlled paths. */
export function readSshAccess(dataDir: string, query: Record<string, unknown> = {}, nowMs = Date.now()): SshAccessResponse {
  if (Object.keys(query).some(key => !['range', 'event', 'ip', 'page', 'limit'].includes(key))) throw new SshAccessQueryError();
  const range = query.range ?? '24h', event = query.event ?? 'all';
  if (typeof range !== 'string' || !Object.hasOwn(RANGES, range) || typeof event !== 'string' || !FILTERS.includes(event)) throw new SshAccessQueryError();
  const parseInteger = (value: unknown, fallback: number, maximum: number) => {
    if (value === undefined) return fallback;
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,5}$/.test(value) || Number(value) > maximum) throw new SshAccessQueryError();
    return Number(value);
  };
  const page = parseInteger(query.page, 1, 300_000), limit = parseInteger(query.limit, 20, 100);
  const ip = query.ip === undefined ? null : canonicalSshIp(query.ip);
  if (query.ip !== undefined && ip === null) throw new SshAccessQueryError();
  const fromMs = Math.max(nowMs - RANGES[range as SshAccessRange], Math.floor(nowMs / DAY) * DAY - 29 * DAY);
  const result: SshAccessResponse = { schemaVersion: 1, status: 'unavailable', stale: true, partial: false,
    observedAt: null, lastSuccessAt: null, errorClass: null, sources: [], acceptedRecords: 0, deduplicatedRecords: 0, droppedRecords: 0,
    range: range as SshAccessRange, event: event as SshAccessFilter, ip, from: new Date(fromMs).toISOString(), to: new Date(nowMs).toISOString(),
    page, limit, total: 0, records: [], rejectedRows: 0, deduplicatedRows: 0, truncated: false, scannedRows: 0, scannedBytes: 0, retentionDays: 30 };
  const base = resolve(dataDir), root = join(base, 'ssh-access');
  try { validateDirectory(base); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { result.status = 'partial'; result.partial = true; result.rejectedRows++; }
    return result;
  }
  try {
    const content = readBounded(join(base, 'ssh-access-status.json'), 16 * 1024);
    if (content !== null) {
      const raw: unknown = JSON.parse(content);
      if (!exact(raw, ['schemaVersion', 'observedAt', 'status', 'lastSuccessAt', 'errorClass', 'sources', 'acceptedRecords', 'deduplicatedRecords', 'droppedRecords', 'retentionDays'])
        || raw.schemaVersion !== 1 || !timestamp(raw.observedAt) || !STATES.includes(raw.status as string)
        || !(raw.lastSuccessAt === null || timestamp(raw.lastSuccessAt)) || !ERRORS.includes(raw.errorClass as string | null)
        || !Array.isArray(raw.sources) || raw.sources.length > 2 || !integer(raw.acceptedRecords)
        || !integer(raw.deduplicatedRecords) || !integer(raw.droppedRecords) || raw.retentionDays !== 30) throw new Error('Invalid SSH status');
      const sources = raw.sources.map(parseSource);
      if (sources.some(source => source === null) || new Set(sources.map(source => source?.sourceId)).size !== sources.length) throw new Error('Invalid SSH sources');
      result.observedAt = raw.observedAt;
      result.lastSuccessAt = raw.lastSuccessAt as string | null;
      result.errorClass = raw.errorClass as SshAccessResponse['errorClass'];
      result.status = raw.status as SshAccessState;
      result.stale = raw.status === 'stale' || nowMs - Date.parse(raw.observedAt) > STALE_AFTER || Date.parse(raw.observedAt) > nowMs + 60_000;
      result.sources = (sources as SshAccessSource[]).map(source => ({ ...source, status: source.observedAt !== null
        && (nowMs - Date.parse(source.observedAt) > STALE_AFTER || Date.parse(source.observedAt) > nowMs + 60_000) ? 'stale' : source.status }));
      result.acceptedRecords = raw.acceptedRecords;
      result.deduplicatedRecords = raw.deduplicatedRecords;
      result.droppedRecords = raw.droppedRecords;
      result.partial = raw.status === 'partial' || raw.droppedRecords > 0;
      if (result.stale && result.status === 'fresh') result.status = 'stale';
    }
  } catch { result.partial = true; result.rejectedRows++; }
  try {
    validateDirectory(root);
    const seen = new Set<string>();
    // At most 30 UTC files, each 4 MiB/10k records, and a request-wide 16 MiB /
    // 40k-row ceiling. Hold one day's parsed rows, bounded IDs and the page.
    for (let day = Math.floor(nowMs / DAY) * DAY; day >= Math.floor(fromMs / DAY) * DAY; day -= DAY) {
      if (result.scannedBytes >= MAX_SCAN_BYTES || result.scannedRows >= MAX_SCAN_ROWS) {
        result.partial = true; result.truncated = true; break;
      }
      let content: string | null;
      try { content = readBounded(join(root, `${new Date(day).toISOString().slice(0, 10)}.jsonl`), Math.min(MAX_DAY_BYTES, MAX_SCAN_BYTES - result.scannedBytes)); }
      catch { result.partial = true; result.truncated = true; result.rejectedRows++; continue; }
      if (!content) continue;
      result.scannedBytes += Buffer.byteLength(content);
      const lines = content.trimEnd().split('\n');
      if (lines.length > MAX_ROWS) { result.partial = true; result.truncated = true; result.rejectedRows++; continue; }
      if (result.scannedRows + lines.length > MAX_SCAN_ROWS) { result.partial = true; result.truncated = true; break; }
      result.scannedRows += lines.length;
      const rows: SshAccessRecord[] = [];
      for (const line of lines) {
        let record: SshAccessRecord | null = null;
        try { if (Buffer.byteLength(line) <= MAX_ROW_BYTES && !/wgang/i.test(line)) record = parseSshAccessRecord(JSON.parse(line)); } catch { /* Reject without reflecting raw log data. */ }
        if (!record || Date.parse(record.observedAt) < day || Date.parse(record.observedAt) >= day + DAY
          || Date.parse(record.observedAt) > nowMs + 60_000) { result.rejectedRows++; continue; }
        if (seen.has(record.id)) { result.deduplicatedRows++; continue; }
        seen.add(record.id);
        if (Date.parse(record.observedAt) < fromMs || Date.parse(record.observedAt) > nowMs
          || ip !== null && record.sourceIp !== ip
          || event === 'failed' && !['denied', 'invalid_user', 'auth_failed'].includes(record.eventType)
          || event === 'accepted' && record.eventType !== 'accepted'
          || event === 'preauth_closed' && record.eventType !== 'preauth_closed') continue;
        rows.push(record);
      }
      rows.sort((a, b) => orderTime(b.observedAt).localeCompare(orderTime(a.observedAt)) || a.id.localeCompare(b.id));
      for (const record of rows) {
        if (result.total >= (page - 1) * limit && result.records.length < limit) result.records.push(record);
        result.total++;
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { result.partial = true; result.truncated = true; result.rejectedRows++; }
  }
  result.partial ||= result.rejectedRows > 0;
  if (result.partial) result.status = 'partial';
  return result;
}
