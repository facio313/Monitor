import type {
  MonitorLocale,
  RuleAlertCollection,
  RuleAlertEvent,
  RuleEvaluation,
  RuleEvaluationPhase,
  RuleEvaluationState,
  RuleObservationStatus,
  RuleSeverity,
} from '../types';
import { formatDateTime, safeText } from '../utils';
import { Icon } from './Icon';

interface RuleHealthSummaryProps {
  evaluation: RuleEvaluation;
  alerts: RuleAlertCollection;
  locale: MonitorLocale;
  stale: boolean;
}

const ACTIVE_RULE_LIMIT = 5;
const TRANSITION_LIMIT = 5;
const RULE_PHASES: RuleEvaluationPhase[] = [
  'inactive',
  'pending',
  'firing',
  'recovering',
  'no_data',
  'unsupported',
  'permission_denied',
  'collection_error',
];
const SEVERITY_PRIORITY: Record<RuleSeverity, number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

function timestampValue(value: string | null | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function rulePhaseCounts(evaluation: RuleEvaluation): Record<RuleEvaluationPhase, number> {
  const counts = Object.fromEntries(RULE_PHASES.map((phase) => [phase, 0])) as Record<RuleEvaluationPhase, number>;
  for (const state of Object.values(evaluation.states)) counts[state.phase] += 1;
  return counts;
}

export function selectFiringRules(evaluation: RuleEvaluation, limit = ACTIVE_RULE_LIMIT): RuleEvaluationState[] {
  return Object.values(evaluation.states)
    .filter((state) => state.phase === 'firing')
    .sort((left, right) => (
      SEVERITY_PRIORITY[left.severity] - SEVERITY_PRIORITY[right.severity]
      || timestampValue(left.openedAt, Number.POSITIVE_INFINITY) - timestampValue(right.openedAt, Number.POSITIVE_INFINITY)
      || left.ruleId.localeCompare(right.ruleId)
      || left.target.localeCompare(right.target)
    ))
    .slice(0, Math.max(0, limit));
}

export function selectActiveRules(evaluation: RuleEvaluation, limit = ACTIVE_RULE_LIMIT): RuleEvaluationState[] {
  return Object.values(evaluation.states)
    .filter((state) => state.phase === 'firing' || state.phase === 'recovering')
    .sort((left, right) => (
      (left.phase === right.phase ? 0 : left.phase === 'firing' ? -1 : 1)
      || SEVERITY_PRIORITY[left.severity] - SEVERITY_PRIORITY[right.severity]
      || timestampValue(left.openedAt, Number.POSITIVE_INFINITY) - timestampValue(right.openedAt, Number.POSITIVE_INFINITY)
      || left.ruleId.localeCompare(right.ruleId)
      || left.target.localeCompare(right.target)
    ))
    .slice(0, Math.max(0, limit));
}

export function selectRecentRuleTransitions(alerts: RuleAlertCollection, limit = TRANSITION_LIMIT): RuleAlertEvent[] {
  if (alerts.status !== 'ok') return [];
  return [...alerts.events]
    .sort((left, right) => (
      timestampValue(right.observedAt, Number.NEGATIVE_INFINITY) - timestampValue(left.observedAt, Number.NEGATIVE_INFINITY)
      || left.idempotencyKey.localeCompare(right.idempotencyKey)
    ))
    .slice(0, Math.max(0, limit));
}

function severityLabel(severity: RuleSeverity, locale: MonitorLocale): string {
  if (severity === 'critical') return t(locale, '심각', 'Critical');
  if (severity === 'warning') return t(locale, '경고', 'Warning');
  return t(locale, '정보', 'Info');
}

function phaseLabel(phase: RuleEvaluationPhase, locale: MonitorLocale): string {
  if (phase === 'inactive') return t(locale, '정상 대기', 'Inactive');
  if (phase === 'pending') return t(locale, '발화 확인 중', 'Pending');
  if (phase === 'firing') return t(locale, '발화 중', 'Firing');
  if (phase === 'recovering') return t(locale, '회복 확인 중', 'Recovering');
  if (phase === 'no_data') return t(locale, '데이터 없음', 'No data');
  if (phase === 'unsupported') return t(locale, '환경 비적용', 'Unsupported');
  if (phase === 'permission_denied') return t(locale, '권한 부족', 'Permission denied');
  return t(locale, '수집 오류', 'Collection error');
}

function observationLabel(status: RuleObservationStatus, locale: MonitorLocale): string {
  if (status === 'ok') return t(locale, '관측 정상', 'Observation current');
  if (status === 'stale') return t(locale, '관측 지연', 'Observation stale');
  if (status === 'no_data') return t(locale, '관측 데이터 없음', 'No observation data');
  if (status === 'unsupported') return t(locale, '이 환경에서는 비적용', 'Not applicable in this environment');
  if (status === 'permission_denied') return t(locale, '관측 권한 부족', 'Observation permission denied');
  return t(locale, '관측 수집 오류', 'Observation collection error');
}

function evaluatorCopy(
  evaluation: RuleEvaluation,
  stale: boolean,
  counts: Record<RuleEvaluationPhase, number>,
  locale: MonitorLocale,
) {
  const firingCount = counts.firing;
  if (evaluation.status === 'collection_error') return {
    tone: 'error',
    badge: t(locale, '수집 오류', 'COLLECTION ERROR'),
    title: t(locale, '규칙 평가 결과를 읽지 못했습니다', 'Rule evaluation could not be collected'),
    detail: t(locale, '평가기 자체의 장애와 규칙 발화를 구분해야 합니다. 다음 수집에서 복구 여부를 확인하세요.', 'This is an evaluator-output failure, not a firing rule. Check whether the next collection recovers.'),
  } as const;
  if (evaluation.status === 'unavailable') return {
    tone: 'unavailable',
    badge: t(locale, '평가 결과 없음', 'UNAVAILABLE'),
    title: t(locale, '규칙 평가 결과가 아직 없습니다', 'Rule evaluation is not available yet'),
    detail: t(locale, '미지원 규칙이나 시스템 장애로 단정하지 않습니다. 평가 출력이 준비되면 이 영역에 표시됩니다.', 'This does not imply an unsupported rule or a system fault. Results appear here when evaluator output is available.'),
  } as const;
  if (stale) return {
    tone: 'stale',
    badge: t(locale, '마지막 확인', 'LAST KNOWN'),
    title: firingCount && counts.recovering
      ? t(locale, `마지막 평가에서 활성 규칙 ${firingCount + counts.recovering}개`, `${firingCount + counts.recovering} active rules in the last evaluation`)
      : firingCount
        ? t(locale, `마지막 평가에서 ${firingCount}개 규칙 발화`, firingCount === 1 ? '1 rule was firing in the last evaluation' : `${firingCount} rules were firing in the last evaluation`)
        : counts.recovering
          ? t(locale, `마지막 평가에서 ${counts.recovering}개 규칙 회복 확인 중`, counts.recovering === 1 ? '1 rule was awaiting recovery confirmation in the last evaluation' : `${counts.recovering} rules were awaiting recovery confirmation in the last evaluation`)
          : t(locale, '마지막 평가에서 활성 규칙 없음', 'No active rules in the last evaluation'),
    detail: t(locale, '규칙 평가 결과가 지연되어 현재 상태로 단정하지 않습니다.', 'The rule evaluation is stale, so these results are not presented as current.'),
  } as const;
  if (firingCount) return {
    tone: 'firing',
    badge: t(locale, '확인 필요', 'ACTION'),
    title: t(locale, `${firingCount}개 규칙이 발화 중입니다`, firingCount === 1 ? '1 rule is firing' : `${firingCount} rules are firing`),
    detail: t(locale, '규칙 엔진의 지속 조건을 충족한 항목만 표시합니다. 기존 화면 판단과 별도 신호입니다.', 'Only rules that met evaluator duration conditions are shown. This signal remains separate from the existing screen assessment.'),
  } as const;
  if (counts.recovering) return {
    tone: 'recovering',
    badge: t(locale, '회복 확인', 'RECOVERY'),
    title: t(locale, `${counts.recovering}개 규칙이 회복 확인 중입니다`, counts.recovering === 1 ? '1 rule is awaiting recovery confirmation' : `${counts.recovering} rules are awaiting recovery confirmation`),
    detail: t(locale, '해소 전 단계입니다. 설정된 복구 표본 수를 모두 충족할 때까지 활성 사건으로 유지합니다.', 'These incidents are not resolved yet and remain active until every configured recovery sample is satisfied.'),
  } as const;
  if (counts.collection_error || counts.permission_denied || counts.no_data) return {
    tone: 'coverage',
    badge: t(locale, '범위 확인', 'COVERAGE'),
    title: t(locale, '일부 규칙의 관측 범위를 확인해야 합니다', 'Some rule observations need coverage review'),
    detail: t(locale, '수집 오류·권한 부족·데이터 없음을 세부 범위에서 각각 구분합니다. 환경 비적용은 장애가 아닙니다.', 'Coverage details distinguish collection errors, permission denial, and no data. Unsupported checks are not faults.'),
  } as const;
  return {
    tone: 'nominal',
    badge: t(locale, '평가 정상', 'EVALUATED'),
    title: t(locale, '발화 중인 규칙이 없습니다', 'No rules are firing'),
    detail: t(locale, '규칙 평가 결과이며, 지원되지 않는 항목은 장애 수에 포함하지 않습니다.', 'This is the rule-evaluator result; unsupported checks are not counted as faults.'),
  } as const;
}

function RuleCard({ state, locale, stale }: { state: RuleEvaluationState; locale: MonitorLocale; stale: boolean }) {
  const observationIsCurrent = state.observationStatus === 'ok' && !stale;
  return (
    <li className={`rule-firing-card rule-severity-${state.severity}`}>
      <header>
        <span className="rule-severity-label">{severityLabel(state.severity, locale)}</span>
        <strong>{safeText(state.ruleId, t(locale, '규칙 ID 없음', 'Missing rule ID'), 96)}</strong>
        <span className="rule-phase-label">{stale ? t(locale, '마지막 평가 기준', 'Last-known evaluation') : phaseLabel(state.phase, locale)}</span>
      </header>
      <dl className="rule-firing-facts">
        <div><dt>{t(locale, '대상', 'Target')}</dt><dd>{safeText(state.target, t(locale, '대상 미확인', 'Unknown target'), 160)}</dd></div>
        <div><dt>{t(locale, '열린 시각', 'Opened')}</dt><dd>{state.openedAt ? formatDateTime(state.openedAt, locale) : t(locale, '기록 없음', 'Not recorded')}</dd></div>
      </dl>
      <p className="rule-description">{safeText(state.description, t(locale, '설명 없음', 'No description'), 320)}</p>
      <div className="rule-runbook">
        <Icon name="shield" size={16} />
        <div><strong>{t(locale, '안전 확인 절차', 'Safe runbook')}</strong><p>{safeText(state.runbook, t(locale, '등록된 절차 없음', 'No runbook provided'), 500)}</p></div>
      </div>
      {!observationIsCurrent && (
        <small className={`rule-observation-status observation-${state.observationStatus}`}>
          {observationLabel(stale && state.observationStatus === 'ok' ? 'stale' : state.observationStatus, locale)}
        </small>
      )}
    </li>
  );
}

function TransitionList({ events, locale }: { events: RuleAlertEvent[]; locale: MonitorLocale }) {
  return (
    <ul className="rule-transition-list">
      {events.map((event) => (
        <li key={event.idempotencyKey} className={`transition-${event.transition}`}>
          <span>{event.transition === 'firing' ? t(locale, '발화', 'Firing') : t(locale, '해소', 'Resolved')}</span>
          <div><strong>{safeText(event.ruleId, 'rule', 96)}</strong><small>{safeText(event.target, 'target', 160)}</small></div>
          <time dateTime={event.observedAt}>{formatDateTime(event.observedAt, locale)}</time>
        </li>
      ))}
    </ul>
  );
}

export function RuleHealthSummary({ evaluation, alerts, locale, stale }: RuleHealthSummaryProps) {
  const counts = rulePhaseCounts(evaluation);
  const evaluationStale = stale || evaluation.status === 'last-known';
  const activeRules = selectActiveRules(evaluation);
  const firingCount = counts.firing;
  const activeCount = firingCount + counts.recovering;
  const hiddenActiveCount = Math.max(0, activeCount - activeRules.length);
  const totalRules = Object.keys(evaluation.states).length;
  const transitions = selectRecentRuleTransitions(alerts);
  const copy = evaluatorCopy(evaluation, evaluationStale, counts, locale);
  const evaluatedAt = evaluation.evaluatedAt ? formatDateTime(evaluation.evaluatedAt, locale) : t(locale, '기록 없음', 'Not recorded');

  return (
    <section className={`rule-health-summary rule-health-${copy.tone}`} aria-labelledby="rule-health-title" data-evaluator-status={evaluation.status}>
      <p className="sr-only" aria-live="polite" aria-atomic="true">{copy.title}</p>
      <header className="rule-health-header">
        <span className="rule-health-icon"><Icon name={copy.tone === 'nominal' ? 'check' : copy.tone === 'firing' || copy.tone === 'error' ? 'alert' : 'info'} size={19} /></span>
        <div>
          <span>{t(locale, '지속 규칙 평가', 'RULE EVALUATOR')}</span>
          <h2 id="rule-health-title">{copy.title}</h2>
          <p>{copy.detail}</p>
        </div>
        <strong className="rule-evaluator-badge">{copy.badge}</strong>
      </header>

      {(evaluation.status === 'ok' || evaluation.status === 'last-known') && (
        <>
          <div className="rule-lifecycle-summary" role="list" aria-label={t(locale, '규칙 수명주기 요약', 'Rule lifecycle summary')}>
            <span className="lifecycle-firing" role="listitem"><b>{counts.firing}</b>{phaseLabel('firing', locale)}</span>
            <span className="lifecycle-recovering" role="listitem"><b>{counts.recovering}</b>{phaseLabel('recovering', locale)}</span>
            <span className="lifecycle-pending" role="listitem"><b>{counts.pending}</b>{phaseLabel('pending', locale)}</span>
          </div>

          {activeRules.length > 0 && (
            <section className="rule-firing-section" aria-labelledby="rule-firing-title">
              <h3 id="rule-firing-title">{evaluationStale
                ? t(locale, '마지막 평가의 활성 규칙', 'Active rules in the last evaluation')
                : counts.recovering
                  ? t(locale, '발화·회복 확인 중 규칙', 'Firing and recovering rules')
                  : t(locale, '발화 중 규칙', 'Firing rules')}</h3>
              <ul className="rule-firing-list">{activeRules.map((state) => <RuleCard key={`${state.ruleId}:${state.target}`} state={state} locale={locale} stale={evaluationStale} />)}</ul>
              {hiddenActiveCount > 0 && <p className="rule-list-overflow">{counts.recovering
                ? t(locale, `우선순위가 낮은 활성 규칙 ${hiddenActiveCount}개는 이 요약에서 생략했습니다.`, hiddenActiveCount === 1 ? '1 lower-priority active rule is omitted from this summary.' : `${hiddenActiveCount} lower-priority active rules are omitted from this summary.`)
                : t(locale, `우선순위가 낮은 발화 규칙 ${hiddenActiveCount}개는 이 요약에서 생략했습니다.`, hiddenActiveCount === 1 ? '1 lower-priority firing rule is omitted from this summary.' : `${hiddenActiveCount} lower-priority firing rules are omitted from this summary.`)}</p>}
            </section>
          )}

          <details className="rule-coverage-details">
            <summary>{t(locale, `규칙 지원 범위 ${totalRules}개 · 세부 상태`, `${totalRules} ${totalRules === 1 ? 'rule' : 'rules'} in scope · coverage details`)}</summary>
            <div className="rule-coverage-content">
              <p>{t(locale, '환경 비적용은 장애가 아니며, 데이터 없음·권한 부족·수집 오류와 별도로 집계합니다.', 'Unsupported checks are not faults and are counted separately from no data, permission denial, and collection errors.')}</p>
              <dl>
                {RULE_PHASES.map((phase) => (
                  <div key={phase} className={`coverage-${phase}`}><dt>{phaseLabel(phase, locale)}</dt><dd>{counts[phase].toLocaleString()}</dd></div>
                ))}
              </dl>
              <p>{t(locale, '규칙 팩', 'Rule pack')} <strong>{safeText(evaluation.rulePackVersion, t(locale, '미확인', 'Unknown'), 80)}</strong> · {t(locale, '평가 시각', 'Evaluated')} <strong>{evaluatedAt}</strong></p>
            </div>
          </details>
        </>
      )}

      {(transitions.length > 0 || alerts.status === 'collection_error') && (
        <details className="rule-transition-details">
          <summary>{alerts.status === 'collection_error'
            ? t(locale, '최근 전환 기록 수집 오류', 'Recent transition collection error')
            : t(locale, `최근 규칙 전환 ${transitions.length}개`, `${transitions.length} recent rule ${transitions.length === 1 ? 'transition' : 'transitions'}`)}</summary>
          {alerts.status === 'collection_error'
            ? <p>{t(locale, '규칙 평가 상태와 별개로 전환 기록 파일을 읽지 못했습니다.', 'The transition log could not be read; this is separate from current evaluator state.')}</p>
            : <TransitionList events={transitions} locale={locale} />}
        </details>
      )}
    </section>
  );
}
