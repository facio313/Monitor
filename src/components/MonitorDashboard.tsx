import { useEffect, useMemo, useRef, useState } from 'react';
import type { SessionInfo } from '../api';
import { chooseInitialLocale, localized, operationalLogs } from '../dashboard-model';
import { useDashboard } from '../hooks/useDashboard';
import type { MonitorDetailPage, MonitorLocale, MonitorPage, TimeRange } from '../types';
import { formatDateTime, safeText } from '../utils';
import { AdaptiveGrid, type AdaptiveGridItem } from './AdaptiveGrid';
import { BonifacioReturnLink } from './BonifacioReturnLink';
import {
  ContainersWidget,
  DetailPage,
  EventsWidget,
  IncidentsWidget,
  LoadWidget,
  NetworkWidget,
  pageTitle,
  PowerWidget,
  ReliabilityWidget,
  ResourceWidget,
  StorageWidget,
  VitalSignsWidget,
} from './CockpitVisuals';
import { Icon, type IconName } from './Icon';
import { PasswordChangeDialog } from './PasswordChangeDialog';

const LOCALE_STORAGE_KEY = 'monitor.locale.v2';
const RANGES: Array<{ value: TimeRange; ko: string; en: string }> = [
  { value: '1h', ko: '1시간', en: '1 hour' },
  { value: '24h', ko: '24시간', en: '24 hours' },
  { value: '7d', ko: '7일', en: '7 days' },
  { value: '30d', ko: '30일', en: '30 days' },
];

const NAVIGATION: Array<{ page: MonitorPage; icon: IconName; ko: string; en: string; koHint: string; enHint: string }> = [
  { page: 'overview', icon: 'activity', ko: '관제 개요', en: 'Overview', koHint: '전체 계통', enHint: 'All systems' },
  { page: 'resources', icon: 'cpu', ko: '자원·부하', en: 'Resources', koHint: 'CPU · 메모리 · 온도', enHint: 'CPU · memory · thermal' },
  { page: 'network', icon: 'network', ko: '네트워크', en: 'Network', koHint: '송수신 · 요청', enHint: 'Transfer · requests' },
  { page: 'storage', icon: 'database', ko: '저장장치', en: 'Storage', koHint: '용량 · 입출력', enHint: 'Capacity · I/O' },
  { page: 'containers', icon: 'server', ko: '서비스', en: 'Services', koHint: '컨테이너 상태', enHint: 'Container state' },
  { page: 'reliability', icon: 'shield', ko: '신뢰성', en: 'Reliability', koHint: '연결 · 커널 · NVMe', enHint: 'Links · kernel · NVMe' },
  { page: 'power', icon: 'zap', ko: '전원', en: 'Power', koHint: '전압 · 제한 상태', enHint: 'Voltage · throttle' },
  { page: 'incidents', icon: 'alert', ko: '사건 분석', en: 'Incidents', koHint: '피크 증거', enHint: 'Peak evidence' },
  { page: 'logs', icon: 'clock', ko: '이벤트 로그', en: 'Event log', koHint: '안전한 운영 기록', enHint: 'Sanitized records' },
];

const DEFAULT_LAYOUT = {
  vitals: { x: 0, y: 0, w: 12, h: 6, minW: 4, minH: 5, maxH: 8 },
  resources: { x: 0, y: 6, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  load: { x: 6, y: 6, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  network: { x: 0, y: 12, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  storage: { x: 6, y: 12, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  containers: { x: 0, y: 18, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  power: { x: 6, y: 18, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  reliability: { x: 0, y: 24, w: 6, h: 5, minW: 4, minH: 4, maxH: 8 },
  incidents: { x: 6, y: 24, w: 6, h: 6, minW: 4, minH: 5, maxH: 10 },
  events: { x: 0, y: 30, w: 12, h: 8, minW: 4, minH: 6, maxH: 14 },
} as const;

interface MonitorDashboardProps {
  page: MonitorPage;
  navigationVersion: number;
  onNavigate: (page: MonitorPage) => void;
  onLogout: () => Promise<void>;
  onPasswordChanged: () => void;
  onUnauthorized: () => void;
  ssoEnabled?: boolean;
  viewer: SessionInfo | null;
}

function t(locale: MonitorLocale, korean: string, english: string): string {
  return localized(locale, korean, english);
}

function detail(locale: MonitorLocale, id: string, korean: string, english: string) {
  return { id, label: t(locale, korean, english) };
}

function normalizePage(page: MonitorPage): 'overview' | MonitorDetailPage {
  return page === 'details' ? 'resources' : page;
}

function severityCounts(data: ReturnType<typeof useDashboard>['data']) {
  if (!data) return { critical: 0, caution: 0 };
  const logs = operationalLogs(data);
  return {
    critical: logs.filter((entry) => entry.severity === 'critical').length,
    caution: logs.filter((entry) => entry.severity === 'warning').length,
  };
}

function useLocale() {
  const [locale, setLocaleState] = useState<MonitorLocale>(() => {
    try {
      return chooseInitialLocale(window.localStorage.getItem(LOCALE_STORAGE_KEY), navigator.languages);
    } catch {
      return 'ko';
    }
  });
  function setLocale(next: MonitorLocale) {
    setLocaleState(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      // Locale persistence is optional; the current page still updates.
    }
  }
  return [locale, setLocale] as const;
}

export function MonitorDashboard({
  page,
  navigationVersion,
  onNavigate,
  onLogout,
  onPasswordChanged,
  onUnauthorized,
  ssoEnabled = false,
  viewer,
}: MonitorDashboardProps) {
  const normalizedPage = normalizePage(page);
  const [locale, setLocale] = useLocale();
  const [range, setRange] = useState<TimeRange>('24h');
  const [loggingOut, setLoggingOut] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const { data, error, initialLoading, refreshing, lastUpdated, refresh } = useDashboard(range, onUnauthorized);
  const counts = severityCounts(data);
  const unhealthy = data?.containers.filter((container) => /unhealthy|dead|exited|failed/i.test(`${container.health} ${container.state}`)).length ?? 0;
  const overall = !data || data.stale || counts.critical || unhealthy
    ? 'danger'
    : counts.caution
      ? 'caution'
      : 'nominal';
  const selectedRange = RANGES.find((item) => item.value === range)!;
  const storageSubject = viewer?.user ?? 'local';
  const centralAccount = viewer?.role === 'chief-admin'
    ? { href: '/sso/admin/', ko: 'SSO ADMIN', en: 'SSO ADMIN' }
    : { href: '/sso/user/', ko: '내 정보', en: 'My account' };
  const heading = normalizedPage === 'overview'
    ? {
      eyebrow: t(locale, '통합 시스템 관제', 'INTEGRATED SYSTEMS CONTROL'),
      title: t(locale, '운영 관제 개요', 'Operations overview'),
      description: t(locale, '정상은 조용하게, 대응이 필요한 변화는 분명하게 표시합니다.', 'Nominal systems stay quiet; actionable changes stand out.'),
    }
    : pageTitle(normalizedPage, locale);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.title = normalizedPage === 'overview'
      ? t(locale, 'Monitor 관제실 · Bonifacio', 'Monitor control room · Bonifacio')
      : `${heading.title} · Monitor`;
  }, [heading.title, locale, normalizedPage]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      titleRef.current?.scrollIntoView({ block: 'start' });
      titleRef.current?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [navigationVersion, normalizedPage]);

  async function handleLogout() {
    setLoggingOut(true);
    await onLogout();
  }

  const overviewItems = useMemo<AdaptiveGridItem[]>(() => {
    if (!data) return [];
    const common = { data, locale, onOpen: (next: MonitorDetailPage) => onNavigate(next) };
    return [
      {
        id: 'vitals',
        label: t(locale, '핵심 계기', 'Primary instruments'),
        layout: DEFAULT_LAYOUT.vitals,
        details: [
          detail(locale, 'cpu', 'CPU', 'CPU'),
          detail(locale, 'memory', '메모리', 'Memory'),
          detail(locale, 'temperature', '온도', 'Temperature'),
          detail(locale, 'load', '시스템 부하', 'System load'),
          detail(locale, 'services', '서비스', 'Services'),
          detail(locale, 'disk-usage', '디스크 사용률', 'Disk usage'),
          detail(locale, 'network-rx', '네트워크 수신', 'Network receive'),
          detail(locale, 'network-tx', '네트워크 송신', 'Network transmit'),
          detail(locale, 'disk-io', '디스크 입출력', 'Disk I/O'),
          detail(locale, 'voltage', '공급 전압', 'Supply voltage'),
          detail(locale, 'gpu-memory', 'GPU 메모리', 'GPU memory'),
          detail(locale, 'gpu-clock', 'GPU 클럭', 'GPU clock'),
          detail(locale, 'uptime', '가동 시간', 'Uptime'),
        ],
        content: <VitalSignsWidget {...common} />,
      },
      {
        id: 'resources',
        label: t(locale, '자원 사용 추세', 'Resource utilization'),
        layout: DEFAULT_LAYOUT.resources,
        details: [
          detail(locale, 'cpu', 'CPU', 'CPU'),
          detail(locale, 'memory', '메모리', 'Memory'),
        ],
        content: <ResourceWidget {...common} range={range} />,
      },
      {
        id: 'load',
        label: t(locale, '부하와 온도', 'Load and thermal'),
        layout: DEFAULT_LAYOUT.load,
        details: [
          detail(locale, 'load', '시스템 부하', 'System load'),
          detail(locale, 'temperature', '온도', 'Temperature'),
        ],
        content: <LoadWidget {...common} range={range} />,
      },
      {
        id: 'network',
        label: t(locale, '네트워크 처리량', 'Network throughput'),
        layout: DEFAULT_LAYOUT.network,
        details: [
          detail(locale, 'receive', '수신', 'Receive'),
          detail(locale, 'transmit', '송신', 'Transmit'),
        ],
        content: <NetworkWidget {...common} range={range} />,
      },
      {
        id: 'storage',
        label: t(locale, '저장장치', 'Storage'),
        layout: DEFAULT_LAYOUT.storage,
        details: [
          detail(locale, 'capacity', '볼륨 용량', 'Volume capacity'),
          detail(locale, 'read', '디스크 읽기', 'Disk read'),
          detail(locale, 'write', '디스크 쓰기', 'Disk write'),
        ],
        content: <StorageWidget {...common} range={range} />,
      },
      {
        id: 'containers',
        label: t(locale, '서비스와 컨테이너', 'Services and containers'),
        layout: DEFAULT_LAYOUT.containers,
        details: [
          detail(locale, 'cpu', 'CPU', 'CPU'),
          detail(locale, 'memory', '메모리', 'Memory'),
        ],
        content: <ContainersWidget {...common} />,
      },
      {
        id: 'power',
        label: t(locale, '전원과 전압', 'Power and voltage'),
        layout: DEFAULT_LAYOUT.power,
        details: [
          detail(locale, 'current', '현재 전압', 'Current voltage'),
          detail(locale, 'minimum', '최저 전압', 'Minimum voltage'),
          detail(locale, 'average', '평균 전압', 'Average voltage'),
          detail(locale, 'trend', '전압 추세', 'Voltage trend'),
        ],
        content: <PowerWidget {...common} range={range} />,
      },
      {
        id: 'reliability',
        label: t(locale, '호스트 신뢰성', 'Host reliability'),
        layout: DEFAULT_LAYOUT.reliability,
        details: [
          detail(locale, 'ssh', 'SSH 접속 경로', 'SSH listeners'),
          detail(locale, 'network', '주 네트워크', 'Primary network'),
          detail(locale, 'nvme', 'NVMe 보호 설정', 'NVMe mitigation'),
          detail(locale, 'collector-gap', '수집 지연', 'Collector gap'),
          detail(locale, 'last-boot', '최근 부팅', 'Last boot'),
        ],
        content: <ReliabilityWidget {...common} />,
      },
      {
        id: 'incidents',
        label: t(locale, '피크 사건', 'Peak incidents'),
        layout: DEFAULT_LAYOUT.incidents,
        details: [
          detail(locale, 'distribution', '원인 분포', 'Cause distribution'),
          detail(locale, 'recent', '최근 사건', 'Recent incidents'),
        ],
        content: <IncidentsWidget {...common} />,
      },
      {
        id: 'events',
        label: t(locale, '운영 이벤트', 'Operational events'),
        layout: DEFAULT_LAYOUT.events,
        details: [
          detail(locale, 'timeline', '이벤트 시간축', 'Event timeline'),
          detail(locale, 'log', '이벤트 목록', 'Event list'),
        ],
        content: <EventsWidget {...common} />,
      },
    ];
  }, [data, locale, onNavigate, range]);

  return (
    <div className="control-room" data-locale={locale}>
      <header className="control-topbar" inert={passwordDialogOpen || helpOpen || undefined}>
        <div className="control-brand-group">
          <div className="control-brand"><span><Icon name="activity" size={21} /></span><div><strong>MONITOR</strong><small>{t(locale, '비공개 호스트 관제', 'Private host control')}</small></div></div>
          <BonifacioReturnLink />
        </div>
        <div className="control-top-actions">
          <a className="control-account-link" href={centralAccount.href}>{locale === 'ko' ? centralAccount.ko : centralAccount.en}</a>
          <div className="locale-switch" role="group" aria-label={t(locale, '언어 선택', 'Language selection')}>
            <button type="button" aria-pressed={locale === 'ko'} onClick={() => setLocale('ko')}>한국어</button>
            <button type="button" aria-pressed={locale === 'en'} onClick={() => setLocale('en')}>EN</button>
          </div>
          <button className="control-icon-button" type="button" onClick={() => setHelpOpen(true)} aria-label={t(locale, '용어 설명 열기', 'Open terminology guide')}><Icon name="info" size={18} /><span>{t(locale, '용어', 'Terms')}</span></button>
          {!ssoEnabled && <button className="control-icon-button" type="button" onClick={() => setPasswordDialogOpen(true)}><Icon name="lock" size={17} /><span>{t(locale, '암호', 'Password')}</span></button>}
          <button className="control-icon-button" type="button" onClick={handleLogout} disabled={loggingOut}><Icon name="logout" size={18} /><span>{loggingOut ? t(locale, '종료 중', 'Signing out') : t(locale, '로그아웃', 'Sign out')}</span></button>
        </div>
      </header>

      <div className="control-layout" inert={passwordDialogOpen || helpOpen || undefined}>
        <aside className="control-rail" aria-label={t(locale, 'Monitor 계통 탐색', 'Monitor systems navigation')}>
          <div className="rail-mode"><span className={`mode-light mode-${overall}`} /> <div><strong>{overall === 'danger' ? t(locale, '확인 필요', 'CHECK SYSTEMS') : overall === 'caution' ? t(locale, '주의 관찰', 'CAUTION') : t(locale, '정상 운용', 'ALL NOMINAL')}</strong><small>{viewer?.role === 'chief-admin' ? t(locale, '최고 관리자 관제', 'Chief operator view') : t(locale, '읽기 전용 관제', 'Read-only control')}</small></div></div>
          <nav>
            {NAVIGATION.map((item) => {
              const active = normalizedPage === item.page;
              return <a key={item.page} href={item.page === 'overview' ? '/monitor/' : `/monitor/details/${item.page}`} className={active ? 'active' : ''} aria-current={active ? 'page' : undefined} onClick={(event) => { if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return; event.preventDefault(); onNavigate(item.page); }}><Icon name={item.icon} size={18} /><span><strong>{locale === 'ko' ? item.ko : item.en}</strong><small>{locale === 'ko' ? item.koHint : item.enHint}</small></span></a>;
            })}
          </nav>
          <div className="rail-identity"><span>{t(locale, '접속 계정', 'SIGNED IN')}</span><strong>{safeText(viewer?.user, t(locale, '로컬 운영자', 'Local operator'), 64)}</strong><small>{viewer?.role ?? (ssoEnabled ? 'user' : 'local')}</small></div>
        </aside>

        <main className="control-main">
          <section className="control-heading" aria-labelledby="control-title">
            <div>
              <span className="control-eyebrow">{heading.eyebrow}</span>
              <h1 id="control-title" ref={titleRef} tabIndex={-1}>{heading.title}</h1>
              <p>{heading.description}</p>
            </div>
            <div className="control-actions">
              <label className="range-selector"><span>{t(locale, '분석 기간', 'TIME RANGE')}</span><select value={range} onChange={(event) => setRange(event.target.value as TimeRange)}>{RANGES.map((item) => <option key={item.value} value={item.value}>{locale === 'ko' ? item.ko : item.en}</option>)}</select></label>
              <button className="refresh-control" type="button" onClick={() => void refresh()} disabled={refreshing}><Icon name="refresh" size={18} className={refreshing ? 'spin' : ''} /><span>{refreshing ? t(locale, '갱신 중', 'Refreshing') : t(locale, '지금 갱신', 'Refresh now')}</span></button>
            </div>
          </section>

          <section className={`system-strip strip-${overall}`} aria-label={t(locale, '항상 표시되는 핵심 운영 상태', 'Persistent operating status')}>
            <div className="system-state"><span>{overall === 'danger' ? '▲' : overall === 'caution' ? '●' : '✓'}</span><div><small>{t(locale, '전체 상태', 'OVERALL')}</small><strong>{overall === 'danger' ? t(locale, '확인 필요', 'CHECK SYSTEMS') : overall === 'caution' ? t(locale, '주의 관찰', 'CAUTION') : t(locale, '정상 운용', 'ALL NOMINAL')}</strong></div></div>
            <div><small>{t(locale, '수집 상태', 'COLLECTOR')}</small><strong>{data?.stale ? t(locale, '데이터 지연', 'STALE DATA') : data ? t(locale, '실시간', 'LIVE') : t(locale, '대기 중', 'WAITING')}</strong><span>{data?.latest?.timestamp ? formatDateTime(data.latest.timestamp, locale) : '—'}</span></div>
            <div><small>{t(locale, '위험 / 주의', 'WARNING / CAUTION')}</small><strong><b className="strip-danger">{counts.critical}</b> / <b className="strip-caution">{counts.caution}</b></strong><span>{t(locale, '선택 기간 이벤트', 'events in range')}</span></div>
            <div><small>{t(locale, '서비스 이상', 'SERVICE FAULTS')}</small><strong>{unhealthy}</strong><span>{t(locale, `총 ${data?.containers.length ?? 0}개`, `${data?.containers.length ?? 0} tracked`)}</span></div>
            <div><small>{t(locale, '현재 분석 범위', 'ACTIVE RANGE')}</small><strong>{locale === 'ko' ? selectedRange.ko : selectedRange.en}</strong><span>{data ? t(locale, `차트 ${data.series.length} · 원본 ${data.telemetrySummary.sampleCount}`, `${data.series.length} chart · ${data.telemetrySummary.sampleCount} raw`) : '—'}</span></div>
            <div><small>{t(locale, '화면 갱신', 'DISPLAY UPDATE')}</small><strong>{lastUpdated ? formatDateTime(lastUpdated.toISOString(), locale) : '—'}</strong><span>{t(locale, '60초마다 자동 갱신', 'automatic every 60s')}</span></div>
          </section>

          {error && <div className="control-notice" role="alert"><Icon name="alert" size={19} /><div><strong>{t(locale, '원격 측정 갱신 실패', 'Telemetry refresh failed')}</strong><span>{safeText(error)} {data ? t(locale, '마지막 정상 화면을 유지합니다.', 'The last good snapshot remains visible.') : ''}</span></div><button type="button" onClick={() => void refresh()}>{t(locale, '재시도', 'Retry')}</button></div>}

          {initialLoading && !data ? <ControlSkeleton locale={locale} /> : data ? (
            normalizedPage === 'overview'
              ? <AdaptiveGrid items={overviewItems} storageKey={`monitor.layout.v3.${storageSubject}`} locale={locale} />
              : <DetailPage page={normalizedPage} data={data} range={range} locale={locale} onOpen={(next) => onNavigate(next)} />
          ) : <div className="control-empty"><Icon name="server" size={32} /><h2>{t(locale, '수집 데이터가 아직 없습니다', 'Telemetry is not available yet')}</h2><p>{t(locale, '수집기가 첫 스냅샷을 만들면 계기판이 자동으로 나타납니다.', 'The instruments will appear after the collector writes its first snapshot.')}</p><button type="button" onClick={() => void refresh()}>{t(locale, '다시 확인', 'Try again')}</button></div>}
        </main>
      </div>

      <footer className="control-footer"><span><Icon name="shield" size={14} />{t(locale, '비공개 읽기 전용 관제', 'Private read-only control')}</span><span>{data ? `${t(locale, 'API 생성', 'API generated')} ${formatDateTime(data.generatedAt, locale)}` : '—'}</span></footer>

      {helpOpen && <TerminologyDialog locale={locale} onClose={() => setHelpOpen(false)} />}
      {!ssoEnabled && <PasswordChangeDialog open={passwordDialogOpen} onClose={() => setPasswordDialogOpen(false)} onPasswordChanged={onPasswordChanged} onUnauthorized={onUnauthorized} />}
    </div>
  );
}

function ControlSkeleton({ locale }: { locale: MonitorLocale }) {
  return <div className="control-skeleton" aria-busy="true" aria-label={t(locale, '계기판 불러오는 중', 'Loading instruments')}>{Array.from({ length: 8 }, (_, index) => <div key={index}><i /><i /><i /></div>)}</div>;
}

function TerminologyDialog({ locale, onClose }: { locale: MonitorLocale; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  const terms = [
    [t(locale, '시스템 부하 (Load)', 'System load'), t(locale, 'CPU를 사용 중이거나 사용 차례를 기다리는 작업의 평균 개수입니다. CPU 사용률과 다른 값이며, CPU 코어 수와 함께 판단합니다.', 'Average work running or waiting for CPU. It differs from CPU percentage and should be read alongside the CPU count.')],
    [t(locale, '처리량 (Throughput)', 'Throughput'), t(locale, '1초 동안 네트워크나 저장장치가 처리한 데이터 양입니다. 순간 최대치보다 지속적인 변화가 더 중요할 수 있습니다.', 'Data handled by a network or storage device each second. Sustained change can matter more than a brief peak.')],
    [t(locale, '압박 지표 (PSI)', 'Pressure stall information'), t(locale, 'CPU·메모리·입출력 자원이 부족해 작업이 실제로 기다린 정도입니다. 사건이 발생한 순간의 병목을 판단하는 데 사용합니다.', 'Time work actually stalled for CPU, memory, or I/O, used to identify the bottleneck during an incident.')],
    [t(locale, '데이터 지연 (Stale)', 'Stale data'), t(locale, '마지막 수집 시각이 허용 범위를 넘었다는 뜻입니다. 수치가 정상이어도 현재 상태라고 판단하면 안 됩니다.', 'The last sample is older than the accepted threshold. Even nominal values must not be treated as current.')],
    [t(locale, '피크 사건', 'Peak incident'), t(locale, 'CPU·메모리·온도·부하·입출력·전원·요청량이 임계치를 넘을 때 안전하게 축약한 증거 묶음입니다.', 'A sanitized evidence bundle captured when CPU, memory, temperature, load, I/O, power, or traffic crosses a threshold.')],
  ];
  return <div className="control-dialog-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="terms-dialog" role="dialog" aria-modal="true" aria-labelledby="terms-title"><header><div><span className="control-eyebrow">{t(locale, '계기판 도움말', 'INSTRUMENT GUIDE')}</span><h2 id="terms-title">{t(locale, '운영 용어 설명', 'Operational terminology')}</h2></div><button ref={closeRef} type="button" onClick={onClose} aria-label={t(locale, '용어 설명 닫기', 'Close terminology guide')}>×</button></header><dl>{terms.map(([term, description]) => <div key={term}><dt>{term}</dt><dd>{description}</dd></div>)}</dl><footer><button type="button" onClick={onClose}>{t(locale, '계기판으로 돌아가기', 'Return to instruments')}</button></footer></section></div>;
}
