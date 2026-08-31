import type { MouseEvent } from 'react';
import { monitorPathForPage } from '../dashboard-model';
import {
  localizedFindingText,
  operationalFindingAnchor,
  operationalFindingHref,
  type OperationalFinding,
  type OperationalFindingLevel,
  type OperationalFindingScope,
} from '../operational-health';
import type { MonitorDetailPage, MonitorLocale, TimeRange } from '../types';
import { formatDateTime } from '../utils';
import { Icon } from './Icon';

interface OperationalHealthSummaryProps {
  findings: readonly OperationalFinding[];
  locale: MonitorLocale;
  range: TimeRange;
  onNavigate: (page: MonitorDetailPage, anchor?: string, range?: TimeRange) => void;
}

type OperationalHealthOverviewProps = OperationalHealthSummaryProps;

interface OperationalGuidanceProps {
  findings: readonly OperationalFinding[];
  locale: MonitorLocale;
  page: MonitorDetailPage;
  range: TimeRange;
}

const PRIMARY_FINDING_LIMIT = 4;
const OVERVIEW_FINDING_LIMIT = 3;

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

function levelLabel(level: OperationalFindingLevel, locale: MonitorLocale): string {
  return level === 'danger' ? t(locale, '위험', 'Danger') : t(locale, '주의', 'Caution');
}

function scopeLabel(scope: OperationalFindingScope, locale: MonitorLocale): string {
  if (scope === 'current') return t(locale, '현재 상태', 'Current state');
  if (scope === 'boot') return t(locale, '이번 부팅', 'Current boot');
  if (scope === 'last-known') return t(locale, '마지막 유효 표본', 'Last known sample');
  return t(locale, '선택 기간 관측', 'Selected-range observation');
}

function allowBrowserNavigation(event: MouseEvent<HTMLAnchorElement>): boolean {
  return event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey;
}

function FindingLink({ finding, locale, range, onNavigate, compact = false }: {
  finding: OperationalFinding;
  locale: MonitorLocale;
  range: TimeRange;
  onNavigate: OperationalHealthSummaryProps['onNavigate'];
  compact?: boolean;
}) {
  const href = operationalFindingHref(finding, range);
  const title = localizedFindingText(finding.title, locale);
  return (
    <a
      className={`${compact ? 'health-more-link' : 'health-finding-card'} finding-${finding.level}`}
      href={href}
      onClick={(event) => {
        if (allowBrowserNavigation(event)) return;
        event.preventDefault();
        onNavigate(finding.page, operationalFindingAnchor(finding.id), range);
      }}
    >
      <span className="health-finding-symbol" aria-hidden="true">{finding.level === 'danger' ? '▲' : '●'}</span>
      <span className="health-finding-copy">
        <span className="health-finding-meta">
          <b>{levelLabel(finding.level, locale)}</b>
          <i>{scopeLabel(finding.scope, locale)}</i>
        </span>
        <strong>{title}</strong>
        {!compact && <small>{localizedFindingText(finding.summary, locale)}</small>}
        <em>{localizedFindingText(finding.evidence, locale)}</em>
      </span>
      <span className="health-finding-action">
        {!compact && t(locale, '원인·증상·해결', 'Cause, symptoms, resolution')}
        <Icon name="chevron" size={15} />
      </span>
    </a>
  );
}

export function OperationalHealthOverview({ findings, locale, range, onNavigate }: OperationalHealthOverviewProps) {
  const dangerCount = findings.filter((finding) => finding.level === 'danger').length;
  const cautionCount = findings.length - dangerCount;
  const href = `${monitorPathForPage('reliability')}?range=${encodeURIComponent(range)}`;
  const tone = dangerCount ? 'danger' : cautionCount ? 'caution' : 'nominal';
  const primary = findings.slice(0, OVERVIEW_FINDING_LIMIT);

  return (
    <section className={`operational-health-overview overview-${tone}`} aria-labelledby="operational-health-overview-title">
      <span className="health-overview-icon"><Icon name={findings.length ? 'alert' : 'check'} size={19} /></span>
      <div className="health-overview-copy">
        <span>{t(locale, '운영 판단 개요', 'OPERATIONAL OVERVIEW')}</span>
        <h2 id="operational-health-overview-title">
          {findings.length
            ? t(locale, '확인할 항목이 있습니다', 'Some items need review')
            : t(locale, '즉시 대응할 항목 없음', 'No items need immediate action')}
        </h2>
        <p>{t(locale, '홈에서는 핵심 상태만 요약합니다. 전체 진단 목록은 신뢰성 상세에서 확인합니다.', 'The home page shows key status only; the complete assessment is available in Reliability details.')}</p>
      </div>
      <div className="health-overview-counts" aria-label={t(locale, `위험 ${dangerCount}개, 주의 ${cautionCount}개`, `${dangerCount} danger and ${cautionCount} caution findings`)}>
        <span><b className="count-danger">{dangerCount}</b>{t(locale, '위험', 'Danger')}</span>
        <span><b className="count-caution">{cautionCount}</b>{t(locale, '주의', 'Caution')}</span>
      </div>
      <a
        className="health-overview-link"
        href={href}
        onClick={(event) => {
          if (allowBrowserNavigation(event)) return;
          event.preventDefault();
          onNavigate('reliability', undefined, range);
        }}
      >
        {t(locale, '전체 진단 보기', 'View full assessment')}<Icon name="chevron" size={15} />
      </a>
      {primary.length > 0 && (
        <div className="health-overview-findings" aria-label={t(locale, '우선 확인 항목', 'Priority findings')}>
          {primary.map((finding) => <FindingLink key={finding.id} finding={finding} locale={locale} range={range} onNavigate={onNavigate} compact />)}
        </div>
      )}
    </section>
  );
}

export function OperationalHealthSummary({ findings, locale, range, onNavigate }: OperationalHealthSummaryProps) {
  const dangerCount = findings.filter((finding) => finding.level === 'danger').length;
  const cautionCount = findings.length - dangerCount;
  const primaryLimit = Math.max(PRIMARY_FINDING_LIMIT, dangerCount);
  const primary = findings.slice(0, primaryLimit);
  const remaining = findings.slice(primaryLimit);

  return (
    <section className={`operational-health-summary${dangerCount ? ' summary-danger' : cautionCount ? ' summary-caution' : ' summary-nominal'}`} aria-labelledby="operational-health-title">
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {findings.length
          ? t(locale, `운영 판단 갱신: 위험 ${dangerCount}개, 주의 ${cautionCount}개. ${primary.map((finding) => localizedFindingText(finding.title, locale)).join(', ')}`, `Operational assessment updated: ${dangerCount} danger and ${cautionCount} caution findings. ${primary.map((finding) => localizedFindingText(finding.title, locale)).join(', ')}`)
          : t(locale, '운영 판단 갱신: 즉시 대응할 항목 없음.', 'Operational assessment updated: no items need immediate action.')}
      </p>
      <header className="health-summary-header">
        <span className="health-summary-icon"><Icon name={findings.length ? 'alert' : 'check'} size={21} /></span>
        <div>
          <span>{t(locale, '운영 판단 요약', 'OPERATIONAL ASSESSMENT')}</span>
          <h2 id="operational-health-title">{findings.length ? t(locale, '지금 확인할 항목', 'Items to review now') : t(locale, '즉시 대응할 항목 없음', 'No items need immediate action')}</h2>
          <p>{findings.length
            ? t(locale, '현재 상태·이번 부팅·마지막 유효 표본·선택 기간 이력을 구분해 우선순위 순으로 표시합니다.', 'Prioritized findings distinguish current state, current-boot evidence, last-known samples, and selected-range history.')
            : t(locale, '수집된 현재 상태와 이번 부팅의 치명적 증거가 정상 범위입니다.', 'Collected current state and critical current-boot evidence are within nominal bounds.')}</p>
        </div>
        <div className="health-summary-counts" aria-label={t(locale, `위험 ${dangerCount}개, 주의 ${cautionCount}개`, `${dangerCount} danger and ${cautionCount} caution findings`)}>
          <span><b className="count-danger">{dangerCount}</b>{t(locale, '위험', 'Danger')}</span>
          <span><b className="count-caution">{cautionCount}</b>{t(locale, '주의', 'Caution')}</span>
        </div>
      </header>

      {primary.length > 0 && (
        <div className="health-finding-grid">
          {primary.map((finding) => <FindingLink key={finding.id} finding={finding} locale={locale} range={range} onNavigate={onNavigate} />)}
        </div>
      )}

      {remaining.length > 0 && (
        <details className="health-more-findings">
          <summary>{t(locale, `그 외 확인할 항목 ${remaining.length}개`, `${remaining.length} more findings`)}</summary>
          <div>{remaining.map((finding) => <FindingLink key={finding.id} finding={finding} locale={locale} range={range} onNavigate={onNavigate} compact />)}</div>
        </details>
      )}
    </section>
  );
}

export function OperationalGuidance({ findings, locale, page, range }: OperationalGuidanceProps) {
  const relevant = findings.filter((finding) => finding.page === page);
  if (!relevant.length) return null;
  const systemAnchor = `system-${page}`;
  const systemHref = `${monitorPathForPage(page)}?range=${encodeURIComponent(range)}#${systemAnchor}`;

  return (
    <section className="operational-guidance" aria-labelledby={`guidance-title-${page}`}>
      <header className="guidance-heading">
        <span><Icon name="shield" size={20} /></span>
        <div>
          <span>{t(locale, '진단·대응 가이드', 'DIAGNOSIS AND RESPONSE')}</span>
          <h2 id={`guidance-title-${page}`}>{t(locale, '무엇이 문제이고 어떻게 확인할까요?', 'What is wrong and how should it be checked?')}</h2>
          <p>{t(locale, '수집된 증거만으로 원인을 단정하지 않고, 가능한 증상과 안전한 확인 순서를 안내합니다.', 'The guide does not overstate causality; it explains likely symptoms and a safe verification order.')}</p>
        </div>
      </header>

      <div className="guidance-list">
        {relevant.map((finding) => {
          const titleId = `${operationalFindingAnchor(finding.id)}-title`;
          return (
            <article
              key={finding.id}
              id={operationalFindingAnchor(finding.id)}
              className={`guidance-card guidance-${finding.level}`}
              aria-labelledby={titleId}
              tabIndex={-1}
            >
              <header>
                <span className="guidance-symbol" aria-hidden="true">{finding.level === 'danger' ? '▲' : '●'}</span>
                <div>
                  <span className="guidance-meta"><b>{levelLabel(finding.level, locale)}</b><i>{scopeLabel(finding.scope, locale)}</i></span>
                  <h3 id={titleId}>{localizedFindingText(finding.title, locale)}</h3>
                  <p>{localizedFindingText(finding.summary, locale)}</p>
                </div>
                <dl>
                  <div><dt>{t(locale, '관측 근거', 'Evidence')}</dt><dd>{localizedFindingText(finding.evidence, locale)}</dd></div>
                  {finding.lastObservedAt && <div><dt>{finding.scope === 'last-known' ? t(locale, '표본 시각', 'Sample time') : t(locale, '최근 시각', 'Last observed')}</dt><dd>{formatDateTime(finding.lastObservedAt, locale)}</dd></div>}
                </dl>
              </header>
              <div className="guidance-sections">
                <section>
                  <h4>{t(locale, '문제점', 'Problem')}</h4>
                  <p>{localizedFindingText(finding.problem, locale)}</p>
                </section>
                <section>
                  <h4>{t(locale, '나타나는 증상', 'Likely symptoms')}</h4>
                  <ul>{finding.symptoms.map((symptom) => <li key={symptom[0]}>{localizedFindingText(symptom, locale)}</li>)}</ul>
                </section>
                <section>
                  <h4>{t(locale, '해결·확인 방법', 'Resolution and checks')}</h4>
                  <ol>{finding.resolutions.map((resolution) => <li key={resolution[0]}>{localizedFindingText(resolution, locale)}</li>)}</ol>
                </section>
              </div>
              <footer>
                <a href={systemHref}>{t(locale, '관련 계통 데이터 보기', 'View related system data')}<Icon name="chevron" size={15} /></a>
              </footer>
            </article>
          );
        })}
      </div>
    </section>
  );
}
