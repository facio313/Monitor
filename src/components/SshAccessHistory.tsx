import { useEffect, useState } from 'react';
import type { SshAccessEvent, SshAccessFilter, SshAccessRange, SshAccessRecord, SshAccessResponse, SshAccessState } from '../ssh-access-types';
import type { MonitorLocale } from '../types';
import { Pagination, resolvePagination } from './Pagination';
import './ssh-access.css';

const t = (locale: MonitorLocale, ko: string, en: string) => locale === 'ko' ? ko : en;

function stateLabel(state: SshAccessState, locale: MonitorLocale): string {
  return ({ fresh: t(locale, '최신', 'Fresh'), partial: t(locale, '일부만 관측', 'Partial'),
    unavailable: t(locale, '수집 불가', 'Unavailable'), stale: t(locale, '오래된 자료', 'Stale') })[state];
}

export function sshEventLabel(event: SshAccessEvent, locale: MonitorLocale): string {
  return ({ denied: t(locale, '접근 거부', 'Access denied'), invalid_user: t(locale, '존재하지 않는 사용자', 'Invalid user'),
    auth_failed: t(locale, '인증 실패', 'Authentication failed'), accepted: t(locale, '인증 성공', 'Authentication accepted'),
    preauth_closed: t(locale, '인증 전 연결 종료', 'Closed before authentication') })[event];
}

/** Deliberately fixed to KST regardless of the viewer's browser timezone. */
export function formatSshTime(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(date) + ' KST';
}

export function sshCountryLabel(record: Pick<SshAccessRecord, 'countryCode' | 'countryStatus'>, locale: MonitorLocale): string {
  if (record.countryStatus === 'private') return t(locale, '사설·예약 주소', 'Private / reserved address');
  if (record.countryStatus === 'stale' && !record.countryCode) return t(locale, '국가 미확인 · 오래된 DB', 'Country unknown · stale database');
  if (!record.countryCode) return record.countryStatus === 'not_found' ? t(locale, '국가 미확인', 'Country not found') : t(locale, '국가 조회 불가', 'Country unavailable');
  let country = record.countryCode;
  try { country = new Intl.DisplayNames([locale === 'ko' ? 'ko' : 'en'], { type: 'region' }).of(record.countryCode) ?? country; }
  catch { /* The validated ISO code remains visible if the browser lacks locale data. */ }
  return `${country} (${record.countryCode}) · ${record.countryStatus === 'stale' ? t(locale, '오래된 DB 추정', 'Stale database estimate') : t(locale, '추정', 'Estimated')}`;
}

export function normalizeSshIpInput(value: string): string | null {
  const input = value.trim();
  if (/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(input)
    && input.split('.').every(part => Number(part) <= 255)) return input;
  if (input.length > 45 || !/^[a-fA-F0-9:.]+$/.test(input) || !input.includes(':')) return null;
  try {
    const normalized = new URL(`http://[${input}]/`).hostname.slice(1, -1);
    const mapped = /^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(normalized);
    if (mapped) {
      const high = Number.parseInt(mapped[1], 16), low = Number.parseInt(mapped[2], 16);
      return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
    }
    return normalized;
  }
  catch { return null; }
}

export function SshAccessEvidence({ response, locale }: { response: SshAccessResponse; locale: MonitorLocale }) {
  return <>
    <p className="ssh-access-health" role={response.partial || response.status === 'unavailable' ? 'alert' : 'status'}>
      <strong>{stateLabel(response.status, locale)}</strong>
      {response.stale && response.status !== 'stale' && <> · {t(locale, '상태 정보 지연', 'Status is stale')}</>}
      {' · '}{t(locale, '수집 확인', 'Collection checked')}: {response.observedAt ? formatSshTime(response.observedAt) : '—'}
      {' · '}{t(locale, '마지막 정상 수집', 'Last successful collection')}: {response.lastSuccessAt ? formatSshTime(response.lastSuccessAt) : '—'}
    </p>
    {(response.partial || response.stale || response.status === 'unavailable') && <p className="ssh-access-warning">
      {t(locale, '일부 기간의 기록이 없거나 수집 상태가 불완전합니다. 빈 목록을 접속이 없었다는 뜻으로 해석하지 마세요.', 'Some history is missing or collection is incomplete. An empty result does not establish that no access occurred.')}
      {response.rejectedRows > 0 && <> {t(locale, '읽지 못한 기록', 'Rejected records')}: {response.rejectedRows}.</>}
      {response.droppedRecords > 0 && <> {t(locale, '수집 중 제외된 기록', 'Dropped during collection')}: {response.droppedRecords}.</>}
      {response.truncated && <> {t(locale, '파일·행 한도 또는 읽기 오류로 일부 자료가 생략됐습니다.', 'Some history was omitted due to file/row limits or read errors.')}</>}
    </p>}
    {response.sources.length > 0 && <ul className="ssh-access-sources" aria-label={t(locale, 'SSH 수집 소스 상태', 'SSH source availability')}>
      {response.sources.map(source => <li key={source.sourceId}><code>{source.sourceId}</code> · {stateLabel(source.status, locale)}</li>)}
    </ul>}
    <p className="ssh-access-window">{formatSshTime(response.from)} – {formatSshTime(response.to)} · {response.partial ? t(locale, '읽은 자료에서 ', 'Within scanned data: ') : ''}{response.total.toLocaleString()} {t(locale, '로그 행', 'log rows')}</p>
    {response.records.length === 0 ? <p className="ssh-access-empty">{t(locale, '선택한 조건에 일치하는 저장 로그가 없습니다. 이 목록은 인식된 SSH 이벤트 행만 포함합니다.', 'No saved logs match these filters. This list includes recognized SSH event rows only.')}</p>
      : <div className="ssh-access-table-wrap"><table className="ssh-access-table">
        <thead><tr><th>{t(locale, '시각 (KST)', 'Time (KST)')}</th><th>{t(locale, '출처 IP', 'Source IP')}</th><th>{t(locale, '추정 국가', 'Estimated country')}</th><th>{t(locale, '이벤트·방식', 'Event / method')}</th><th>{t(locale, '로그 행', 'Rows')}</th></tr></thead>
        <tbody>{response.records.map(record => <tr key={record.id}>
          <td><time dateTime={record.observedAt}>{formatSshTime(record.observedAt)}</time><small>{record.sourceId}</small></td>
          <td><code className="ssh-access-ip">{record.sourceIp}</code><small>{t(locale, '출처 포트', 'Source port')}: {record.sourcePort ?? '—'}</small></td>
          <td>{sshCountryLabel(record, locale)}<small>{record.databaseDate ? `${t(locale, '국가 DB', 'Country DB')}: ${record.databaseDate}` : t(locale, 'DB 날짜 미확인', 'DB date unavailable')}</small></td>
          <td><span className={`ssh-access-event ssh-access-event-${record.eventType}`}>{sshEventLabel(record.eventType, locale)}</span><small>{record.authMethod ?? t(locale, '인증 방식 미확인', 'Authentication method unknown')}</small></td>
          <td>1</td>
        </tr>)}</tbody>
      </table></div>}
    {response.deduplicatedRows > 0 && <p className="ssh-access-note">{t(locale, '중복 로그 ID 제외', 'Duplicate log IDs omitted')}: {response.deduplicatedRows}</p>}
  </>;
}

export function SshAccessHistory({ locale, onUnauthorized }: { locale: MonitorLocale; onUnauthorized: () => void }) {
  const [range, setRange] = useState<SshAccessRange>('24h');
  const [event, setEvent] = useState<SshAccessFilter>('all');
  const [ipInput, setIpInput] = useState('');
  const [ip, setIp] = useState('');
  const [invalidIp, setInvalidIp] = useState(false);
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [response, setResponse] = useState<SshAccessResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<'permission' | 'invalid' | 'request' | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    const query = new URLSearchParams({ range, event, page: String(page), limit: '20' });
    if (ip) query.set('ip', ip);
    async function load() {
      try {
        const result = await fetch(`/monitor/api/ssh-access?${query}`, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: controller.signal });
        if (result.status === 401) { onUnauthorized(); throw new Error('request'); }
        if (!result.ok) throw new Error(result.status === 403 ? 'permission' : result.status === 400 ? 'invalid' : 'request');
        const data = await result.json() as SshAccessResponse;
        if (!controller.signal.aborted) {
          const currentPage = resolvePagination(data.total, data.limit, data.page).page;
          if (currentPage !== data.page) { setResponse(null); setPage(currentPage); }
          else setResponse(data);
        }
      } catch (cause) {
        if (!controller.signal.aborted) {
          setResponse(null);
          setError(cause instanceof Error && cause.message === 'permission' ? 'permission' : cause instanceof Error && cause.message === 'invalid' ? 'invalid' : 'request');
        }
      } finally { if (!controller.signal.aborted) setLoading(false); }
    }
    void load();
    return () => controller.abort();
  }, [range, event, ip, page, refresh, onUnauthorized]);
  useEffect(() => {
    if (page !== 1) return;
    const timer = window.setInterval(() => { if (!document.hidden) setRefresh(value => value + 1); }, 60_000);
    return () => window.clearInterval(timer);
  }, [page]);
  const chooseRange = (value: SshAccessRange) => { setRange(value); setPage(1); };
  return <section id="ssh-access-history" className="ssh-access-history" aria-label={t(locale, 'SSH 출처·국가 접속 기록', 'SSH source and country history')}>
    <div className="evidence-panel-heading"><div><h2>{t(locale, 'SSH 출처·국가 접속 기록', 'SSH source and country history')}</h2><p>{t(locale, '인증된 로그 읽기 권한으로만 원본 출처 IP를 조회합니다.', 'Original source IPs are available only through authenticated log-read access.')}</p></div><span>30{t(locale, '일', ' days')}</span></div>
    <p className="ssh-access-note">{t(locale, 'IP 국가는 VPN·프록시·클라우드 출구의 추정 위치이며 공격자의 실제 위치를 뜻하지 않습니다. 로그 행 수는 고유 접속 시도 수가 아닙니다. 인증 성공은 별도 이벤트이며, 인증 전 종료나 불명확한 기록을 인증 실패로 단정하지 않습니다.', 'An IP country estimates a VPN, proxy or cloud exit location, not an attacker’s actual location. Log-row counts are not unique connection attempts. Authentication accepted is a separate event; pre-authentication closures and unclear records are not assumed to be failed authentication.')}</p>
    <div className="ssh-access-filters">
      <div className="ssh-access-shortcuts" aria-label={t(locale, '빠른 기간 선택', 'Quick time ranges')}>
        {(['6h', '24h'] as const).map(value => <button type="button" key={value} aria-pressed={range === value} onClick={() => chooseRange(value)}>{value}</button>)}
      </div>
      <label>{t(locale, '기간', 'Time range')}<select aria-label={t(locale, 'SSH 기록 기간', 'SSH history time range')} value={range} onChange={event => chooseRange(event.target.value as SshAccessRange)}>
        {(['1h', '6h', '24h', '7d', '30d'] as const).map(value => <option key={value} value={value}>{value}</option>)}
      </select></label>
      <label>{t(locale, '이벤트', 'Event')}<select aria-label={t(locale, 'SSH 이벤트 필터', 'SSH event filter')} value={event} onChange={event => { setEvent(event.target.value as SshAccessFilter); setPage(1); }}>
        <option value="all">{t(locale, '전체', 'All')}</option><option value="failed">{t(locale, '실패·거부 기록', 'Failures and denials')}</option>
        <option value="accepted">{t(locale, '인증 성공', 'Authentication accepted')}</option><option value="preauth_closed">{t(locale, '인증 전 종료', 'Closed before authentication')}</option>
      </select></label>
      <button type="button" disabled={loading} onClick={() => { setPage(1); setRefresh(value => value + 1); }}>{t(locale, '새로고침', 'Refresh')}</button>
    </div>
    <form className="ssh-access-ip-filter" onSubmit={event => {
      event.preventDefault();
      const normalized = ipInput.trim() ? normalizeSshIpInput(ipInput) : '';
      setInvalidIp(normalized === null);
      if (normalized !== null) { setIp(normalized); setIpInput(normalized); setPage(1); }
    }}>
      <label htmlFor="ssh-source-ip">{t(locale, '출처 IP 정확히 일치', 'Exact source IP')}</label>
      <input id="ssh-source-ip" value={ipInput} onChange={event => setIpInput(event.target.value)} maxLength={45} autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="203.0.113.10 / 2001:db8::1" aria-invalid={invalidIp} />
      <button type="submit">{t(locale, 'IP 적용', 'Apply IP')}</button>
      {ip && <button type="button" onClick={() => { setIp(''); setIpInput(''); setInvalidIp(false); setPage(1); }}>{t(locale, 'IP 해제', 'Clear IP')}</button>}
    </form>
    {invalidIp && <p role="alert">{t(locale, '유효한 IPv4 또는 IPv6 주소를 입력하세요. URL·포트·호스트 이름은 사용할 수 없습니다.', 'Enter a valid IPv4 or IPv6 address, without a URL, port or hostname.')}</p>}
    {loading ? <p role="status">{t(locale, 'SSH 기록을 불러오는 중…', 'Loading SSH history…')}</p>
      : error ? <p role="alert">{error === 'permission' ? t(locale, '로그 읽기 권한이 필요합니다.', 'Log-read permission is required.')
        : error === 'invalid' ? t(locale, '조회 조건이 올바르지 않습니다. 기간과 IP 주소를 확인하세요.', 'The query is invalid. Check the time range and IP address.')
        : t(locale, 'SSH 기록을 불러오지 못했습니다. 로그인 상태와 수집 상태를 확인하세요.', 'SSH history could not be loaded. Check your session and collection status.')}</p>
        : response && <><SshAccessEvidence response={response} locale={locale} />
          <Pagination model={resolvePagination(response.total, response.limit, response.page)} locale={locale} onPageChange={setPage} ariaLabel={t(locale, 'SSH 기록 페이지', 'SSH history pages')} itemLabel={t(locale, '개 로그 행', 'log rows')} />
        </>}
    <p className="ssh-access-note">{t(locale, '최대 30일 보관, UTC 날짜별 10,000행·4 MiB 한도. 한 번에 최신 자료부터 최대 40,000행·16 MiB를 읽으며, 한도에 도달하면 일부 자료와 읽은 범위의 건수만 표시합니다. 국가 정보는 오프라인 DB 기준이며 오래됨·미확인 상태를 구분합니다.', 'Retained up to 30 days, capped at 10,000 rows / 4 MiB per UTC day. Each query scans newest data first, up to 40,000 rows / 16 MiB; limited results and counts cover scanned data only. Country estimates use an offline database; stale and unknown results are labeled.')}
      {' '}{t(locale, '국가 데이터', 'Country data')}: <a href="https://db-ip.com" target="_blank" rel="noreferrer noopener">IP Geolocation by DB-IP.com</a>.</p>
  </section>;
}
