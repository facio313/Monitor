import { useEffect, useState } from 'react';
import type { MonitorLocale } from '../types';
import type { NetworkDiagnosticRange, NetworkDiagnosticProblem, NetworkDiagnosticState, NetworkDiagnosticsResponse } from '../network-diagnostics-types';
import { formatDateTime } from '../utils';
import { Icon } from './Icon';
import { Pagination, resolvePagination } from './Pagination';
import './network-diagnostics.css';

const text = (locale: MonitorLocale, ko: string, en: string) => locale === 'ko' ? ko : en;
const value = (number: number | null, suffix = '') => number === null ? '—' : `${number.toLocaleString(undefined, { maximumFractionDigits: 3 })}${suffix}`;
const stateLabel = (state: NetworkDiagnosticState, locale: MonitorLocale) => ({
  fresh: text(locale, '최신', 'Fresh'), stale: text(locale, '오래된 자료', 'Stale'),
  no_data: text(locale, '자료 없음', 'No data'), error: text(locale, '수집 오류', 'Collection error'),
})[state];

export function diagnosticIncidentWindow(from: string, to: string, nowMs = Date.now()): { from: string; to: string } | null {
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  const day = 86_400_000;
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end || end > nowMs + 60_000
    || start < Math.floor(nowMs / day) * day - 29 * day || end - start > 30 * day) return null;
  return { from: new Date(start).toISOString(), to: new Date(end).toISOString() };
}

export function NetworkDiagnosticsEvidence({ response, locale }: { response: NetworkDiagnosticsResponse; locale: MonitorLocale }) {
  return <>
    <p role={response.status === 'error' ? 'alert' : 'status'}>
      <strong>{stateLabel(response.status, locale)}</strong>
      {' · '}{text(locale, '마지막 호스트 수집', 'Latest host sample')}: {response.observedAt ? formatDateTime(response.observedAt, locale) : '—'}
      {response.rejectedRows > 0 && <> · {text(locale, '읽지 못한 기록', 'Rejected records')}: {response.rejectedRows}</>}
      {response.truncated && <> · {text(locale, '일부 기록을 읽지 못했습니다.', 'Some history could not be read.')}</>}
    </p>
    {response.records.length === 0 ? <div className="detail-positive-empty">{text(locale, '선택한 기간·유형의 저장 기록이 없습니다.', 'No saved records match this time window and problem type.')}</div> :
      <div className="cockpit-table-wrap"><table className="cockpit-table network-diagnostics-table">
        <thead><tr><th>{text(locale, '호스트 수집 시각', 'Host sample time')}</th><th>{text(locale, 'HTTP 단계별 기록', 'HTTP phase evidence')}</th><th>{text(locale, 'TCP 송신 재전송', 'TCP outbound retransmissions')}</th><th>{text(locale, '인터페이스·부하', 'Interfaces and load')}</th></tr></thead>
        <tbody>{response.records.map((record) => <tr key={record.observedAt}>
          <td><time dateTime={record.observedAt}>{formatDateTime(record.observedAt, locale)}</time><small>{record.problems.length ? record.problems.join(' · ') : text(locale, '특이사항 없음', 'No flagged condition')}</small></td>
          <td><strong>{stateLabel(record.probeStatus, locale)}</strong>
            {record.probes.map((probe) => <details key={probe.id}>
              <summary>{probe.id} · {probe.status} · {value(probe.timings.totalMs, ' ms')}{probe.errorPhase ? ` · ${text(locale, '실패 단계', 'Failed phase')}: ${probe.errorPhase}` : ''}</summary>
              <p>{text(locale, '검사 시각', 'Probe checked')}: <time dateTime={probe.checkedAt}>{formatDateTime(probe.checkedAt, locale)}</time><br />HTTP: {value(probe.httpStatus)} · {text(locale, '리다이렉트', 'Redirects')}: {probe.redirectCount}</p>
              <dl className="network-phase-values"><dt>DNS</dt><dd>{value(probe.timings.dnsMs, ' ms')}</dd><dt>TCP</dt><dd>{value(probe.timings.tcpMs, ' ms')}</dd><dt>TLS</dt><dd>{value(probe.timings.tlsMs, ' ms')}</dd><dt>TTFB</dt><dd>{value(probe.timings.ttfbMs, ' ms')}</dd><dt>{text(locale, '전체', 'Total')}</dt><dd>{value(probe.timings.totalMs, ' ms')}</dd></dl>
            </details>)}
          </td>
          <td><strong>{value(record.tcp.retransmitPercent, '%')}</strong> · {stateLabel(record.tcp.status, locale)}<br />
            {value(record.tcp.retransmittedSegments)} / {value(record.tcp.outboundSegments)} {text(locale, '송신 세그먼트', 'outbound segments')}<br />
            {text(locale, '관측 간격', 'Interval')}: {value(record.tcp.elapsedSeconds, ' s')}<br />
            {text(locale, '재전송/송신 속도', 'Retransmit/outbound rate')}: {value(record.tcp.retransmittedPerSecond)} / {value(record.tcp.outboundPerSecond, ' /s')}
          </td>
          <td><details><summary>CPU {value(record.context.cpuPercent, '%')} · RAM {value(record.context.memoryPercent, '%')}</summary>
            <p>{text(locale, '오류 RX/TX', 'Errors RX/TX')}: {value(record.interfaces.rxErrorsPerSecond)} / {value(record.interfaces.txErrorsPerSecond, ' /s')}<br />
              {text(locale, '드롭 RX/TX', 'Drops RX/TX')}: {value(record.interfaces.rxDroppedPerSecond)} / {value(record.interfaces.txDroppedPerSecond, ' /s')}</p>
            <p>PSI {text(locale, '10초 평균 일부/전체', '10s average some/full')}<br />
              CPU: {value(record.context.cpuPressureSomeAvg10)} / {value(record.context.cpuPressureFullAvg10, '%')}<br />
              RAM: {value(record.context.memoryPressureSomeAvg10)} / {value(record.context.memoryPressureFullAvg10, '%')}<br />
              I/O: {value(record.context.ioPressureSomeAvg10)} / {value(record.context.ioPressureFullAvg10, '%')}</p>
          </details></td>
        </tr>)}</tbody>
      </table></div>}
  </>;
}

export function NetworkDiagnosticsHistory({ locale }: { locale: MonitorLocale }) {
  const [range, setRange] = useState<NetworkDiagnosticRange>('24h');
  const [problem, setProblem] = useState<NetworkDiagnosticProblem>('all');
  const [page, setPage] = useState(1);
  const [to, setTo] = useState(() => new Date().toISOString());
  const [fromInput, setFromInput] = useState('');
  const [toInput, setToInput] = useState('');
  const [incidentWindow, setIncidentWindow] = useState<{ from: string; to: string } | null>(null);
  const [windowError, setWindowError] = useState(false);
  const [response, setResponse] = useState<NetworkDiagnosticsResponse | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(false);
    const query = new URLSearchParams({ range, problem, page: String(page), limit: '20', to: incidentWindow?.to ?? to });
    if (incidentWindow) query.set('from', incidentWindow.from);
    fetch(`/monitor/api/network-diagnostics?${query}`, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: controller.signal })
      .then(async (result) => { if (!result.ok) throw new Error('Request failed'); return result.json() as Promise<NetworkDiagnosticsResponse>; })
      .then((result) => { if (!controller.signal.aborted) setResponse(result); })
      .catch(() => { if (!controller.signal.aborted) { setError(true); setResponse(null); } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [range, problem, page, to, incidentWindow]);
  useEffect(() => {
    if (page !== 1 || incidentWindow) return;
    const timer = window.setInterval(() => setTo(new Date().toISOString()), 60_000);
    return () => window.clearInterval(timer);
  }, [page, incidentWindow]);
  return <article id="network-diagnostics-history" className="cockpit-panel network-diagnostics-history">
    <header className="cockpit-panel-header"><span className="cockpit-panel-icon"><Icon name="network" size={19} /></span><div>
      <h2>{text(locale, '네트워크 진단 이력', 'Network diagnostics history')}</h2>
      <p>{text(locale, 'HTTP 단계 시간, TCP 송신 재전송 분자·분모, 인터페이스 오류와 당시 서버 부하를 함께 보관합니다.', 'HTTP phase timings, TCP outbound numerator and denominator, interface faults and contemporaneous host load.')}</p>
    </div><span className="cockpit-panel-badge">30{locale === 'ko' ? '일' : ' DAYS'}</span></header>
    <div className="network-diagnostic-filters">
      <label>{text(locale, '기간', 'Time range')} <select aria-label={text(locale, '진단 이력 기간', 'Diagnostic history time range')} value={range} onChange={(event) => { setRange(event.target.value as NetworkDiagnosticRange); setPage(1); setTo(new Date().toISOString()); setIncidentWindow(null); setWindowError(false); }}>
        {(['1h', '6h', '24h', '7d', '30d'] as const).map((choice) => <option value={choice} key={choice}>{choice}</option>)}
      </select></label>
      <label>{text(locale, '유형', 'Problem type')} <select aria-label={text(locale, '진단 이력 문제 유형', 'Diagnostic history problem type')} value={problem} onChange={(event) => { setProblem(event.target.value as NetworkDiagnosticProblem); setPage(1); }}>
        <option value="all">{text(locale, '전체', 'All')}</option><option value="http">HTTP / DNS / TLS</option><option value="tcp">TCP ≥ 1%</option><option value="interface">{text(locale, '인터페이스 오류·드롭', 'Interface errors/drops')}</option>
      </select></label>
      <button type="button" disabled={loading} onClick={() => { setPage(1); setTo(new Date().toISOString()); }}>{text(locale, '새로고침', 'Refresh')}</button>
    </div>
    <details className="network-incident-window"><summary>{text(locale, '사건 발생 시간 직접 선택', 'Select an exact incident window')}</summary>
      <form className="network-diagnostic-filters" onSubmit={(event) => {
        event.preventDefault();
        const selected = diagnosticIncidentWindow(fromInput, toInput);
        setWindowError(!selected);
        if (selected) { setIncidentWindow(selected); setPage(1); }
      }}>
        <label>{text(locale, '시작 (현지 시각)', 'From (local time)')} <input type="datetime-local" step="1" required value={fromInput} onChange={(event) => setFromInput(event.target.value)} /></label>
        <label>{text(locale, '종료 (현지 시각)', 'To (local time)')} <input type="datetime-local" step="1" required value={toInput} onChange={(event) => setToInput(event.target.value)} /></label>
        <button type="submit" disabled={!fromInput || !toInput}>{text(locale, '기간 적용', 'Apply window')}</button>
        <button type="button" onClick={() => { setIncidentWindow(null); setFromInput(''); setToInput(''); setWindowError(false); setPage(1); setTo(new Date().toISOString()); }}>{text(locale, '직접 선택 해제', 'Clear custom window')}</button>
      </form>
      {windowError && <p role="alert">{text(locale, '보관 기간 내의 시작·종료 시각을 입력해 주세요. 종료는 시작 이후이며 현재 시각을 넘을 수 없습니다.', 'Choose a retained start and end time. The end must follow the start and cannot be in the future.')}</p>}
    </details>
    {incidentWindow && <p role="status">{text(locale, '선택한 사건 구간', 'Selected incident window')}: {formatDateTime(incidentWindow.from, locale)} – {formatDateTime(incidentWindow.to, locale)} · {text(locale, '자동 갱신 일시 정지', 'Automatic refresh paused')}</p>}
    {loading ? <p role="status">{text(locale, '진단 기록을 불러오는 중…', 'Loading diagnostic history…')}</p> : error ? <p role="alert">{text(locale, '진단 기록을 불러오지 못했습니다. 로그인 상태와 수집 상태를 확인해 주세요.', 'Diagnostic history could not be loaded. Check your session and collection status.')}</p> : response && <>
      <NetworkDiagnosticsEvidence response={response} locale={locale} />
      <Pagination model={resolvePagination(response.total, response.limit, response.page)} locale={locale} onPageChange={setPage} ariaLabel={text(locale, '네트워크 진단 이력 페이지', 'Network diagnostic history pages')} />
    </>}
    <p className="network-diagnostic-note">{text(locale,
      '최대 30일 보관(하루 10,000건·8MiB 한도). HTTP 필터는 실패·1초 이상 지연·오래된 검사 자료를 표시합니다. 호스트 지표는 호스트 수집 시각, HTTP는 별도 검사 시각 기준입니다. DNS/TCP/TLS/TTFB는 마지막 요청 구간이며 전체 시간에는 리다이렉트가 포함됩니다. TTFB는 요청 전송 완료부터 첫 응답 바이트까지입니다. —는 미측정 또는 적용되지 않음을 뜻합니다. 주소·URL·인증정보는 이력에 보관하지 않습니다.',
      'Retained for up to 30 days, capped at 10,000 records / 8 MiB per day. HTTP filters failures, latency ≥ 1 s and stale/missing probes. Host and probe timestamps are separate. DNS/TCP/TLS/TTFB describe the final request; total includes redirects. TTFB starts after sending the request and ends at the first response byte. — means unmeasured or not applicable. Addresses, URLs and credentials are not retained in history.')}</p>
  </article>;
}
