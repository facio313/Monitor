import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ApiError, getRemoteAgents, type SessionInfo } from '../api';
import { agentHeartbeatLabel } from '../collection-status';
import type {
  DashboardPayload,
  MonitorLocale,
  RemoteAgentInventoryResponse,
  RemoteAgentStatus,
  RuleEvaluationState,
} from '../types';
import { formatBytes, formatDateTime, formatUptime, safeText } from '../utils';
import { Icon } from './Icon';
import './infrastructure-observability.css';

const MAX_REMOTE_AGENTS = 100;
const MAX_REMOTE_ADDRESSES = 8;
const MAX_SELF_HEALTH_RULES = 16;
export const REMOTE_AGENT_REFRESH_MS = 60_000;
const RAW_PATH = /(?:^|[^A-Za-z0-9/])\/(?!\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*/u;

type Tone = 'ok' | 'caution' | 'danger' | 'neutral';

export type RemoteAgentViewState =
  | { kind: 'loading' }
  | { kind: 'ready'; data: RemoteAgentInventoryResponse }
  | { kind: 'unsupported'; reason: 'local-mode' | 'not-configured' }
  | { kind: 'restricted' }
  | { kind: 'unauthorized' }
  | { kind: 'failure'; status: number | null; code: string };

interface InfrastructureObservabilityProps {
  data: DashboardPayload | null;
  locale: MonitorLocale;
  ssoEnabled: boolean;
  viewer: SessionInfo | null;
  onUnauthorized: () => void;
}

interface InfrastructureObservabilityViewProps {
  data: DashboardPayload | null;
  locale: MonitorLocale;
  remote: RemoteAgentViewState;
  onRetry?: () => void;
}

interface Fact {
  label: string;
  value: string;
}

interface RemoteAgentPollingScheduler {
  setTimeout: (callback: () => void, delayMilliseconds: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

const DEFAULT_POLLING_SCHEDULER: RemoteAgentPollingScheduler = {
  setTimeout: (callback, delayMilliseconds) => globalThis.setTimeout(callback, delayMilliseconds),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function shouldContinueRemoteAgentPolling(state: RemoteAgentViewState | null): boolean {
  return state?.kind === 'ready' || state?.kind === 'failure';
}

export function startRemoteAgentPolling(
  load: (signal: AbortSignal, showLoading: boolean) => Promise<RemoteAgentViewState | null>,
  scheduler: RemoteAgentPollingScheduler = DEFAULT_POLLING_SCHEDULER,
): () => void {
  let stopped = false;
  let controller: AbortController | null = null;
  let timer: unknown | null = null;

  const poll = async (showLoading: boolean) => {
    controller?.abort();
    const nextController = new AbortController();
    controller = nextController;
    const state = await load(nextController.signal, showLoading);
    if (stopped || nextController.signal.aborted || !shouldContinueRemoteAgentPolling(state)) return;
    timer = scheduler.setTimeout(() => void poll(false), REMOTE_AGENT_REFRESH_MS);
  };

  void poll(true);
  return () => {
    stopped = true;
    controller?.abort();
    if (timer !== null) scheduler.clearTimeout(timer);
  };
}

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

function canReadRemoteAgents(ssoEnabled: boolean, viewer: SessionInfo | null): boolean {
  return ssoEnabled && (viewer?.role === 'admin' || viewer?.role === 'chief-admin');
}

export function initialRemoteAgentState(
  ssoEnabled: boolean,
  viewer: SessionInfo | null,
): RemoteAgentViewState {
  if (!ssoEnabled) return { kind: 'unsupported', reason: 'local-mode' };
  if (!canReadRemoteAgents(ssoEnabled, viewer)) return { kind: 'restricted' };
  return { kind: 'loading' };
}

export function remoteAgentFailure(error: unknown): RemoteAgentViewState {
  if (!(error instanceof ApiError)) return { kind: 'failure', status: null, code: 'NETWORK_ERROR' };
  if (error.status === 401) return { kind: 'unauthorized' };
  if (error.status === 403) return { kind: 'restricted' };
  if (error.status === 404) return { kind: 'unsupported', reason: 'not-configured' };
  return { kind: 'failure', status: error.status, code: safeText(error.code, 'REQUEST_FAILED', 64) };
}

export async function loadRemoteAgentState(
  signal: AbortSignal | undefined,
  onUnauthorized: () => void,
  fetchAgents: (signal?: AbortSignal) => Promise<RemoteAgentInventoryResponse> = getRemoteAgents,
): Promise<RemoteAgentViewState> {
  try {
    return { kind: 'ready', data: await fetchAgents(signal) };
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    const failure = remoteAgentFailure(error);
    if (failure.kind === 'unauthorized') onUnauthorized();
    return failure;
  }
}

function collectionTone(status: string): Tone {
  if (['healthy', 'fresh', 'ok', 'supported'].includes(status)) return 'ok';
  if (['delayed', 'last-known', 'partial', 'maintenance', 'inactive', 'gap', 'stale'].includes(status)) return 'caution';
  if (['unknown', 'unsupported'].includes(status)) return 'neutral';
  return 'danger';
}

function agentTone(status: RemoteAgentStatus | DashboardPayload['agent']['status']): Tone {
  if (status === 'healthy') return 'ok';
  if (status === 'delayed' || status === 'maintenance' || status === 'inactive') return 'caution';
  if (status === 'unknown') return 'neutral';
  return 'danger';
}

function selfHealthAssessment(
  data: DashboardPayload,
  rules: RuleEvaluationState[],
  locale: MonitorLocale,
): { tone: Tone; label: string } {
  if (
    data.stale
    || ['disconnected', 'collection_error'].includes(data.agent.status)
    || data.ruleEvaluation.status === 'collection_error'
    || data.ruleAlerts.status === 'collection_error'
  ) return { tone: 'danger', label: t(locale, '자체 건강 수집 이상', 'Self-health degraded') };
  const dangerRules = rules.filter((rule) => ['firing', 'collection_error', 'permission_denied'].includes(rule.phase));
  if (dangerRules.length) {
    return { tone: 'danger', label: t(locale, `${dangerRules.length}개 조치 필요`, `${dangerRules.length} action required`) };
  }
  const cautionRules = rules.filter((rule) => ['pending', 'recovering', 'no_data'].includes(rule.phase));
  if (cautionRules.length) {
    return { tone: 'caution', label: t(locale, `${cautionRules.length}개 관찰 필요`, `${cautionRules.length} need observation`) };
  }
  if (
    data.agent.status !== 'healthy'
    || data.ruleEvaluation.status !== 'ok'
    || data.ruleAlerts.status !== 'ok'
  ) return { tone: 'caution', label: t(locale, '마지막 정상 상태', 'Last known') };
  if (!rules.length) return { tone: 'neutral', label: t(locale, '규칙 대상 상태 없음', 'No rule target states') };
  if (rules.some((rule) => rule.phase === 'unsupported')) {
    return { tone: 'neutral', label: t(locale, '일부 규칙 미지원', 'Some rules unsupported') };
  }
  return { tone: 'ok', label: t(locale, '정상', 'OK') };
}

function collectorAssessment(data: DashboardPayload, locale: MonitorLocale): { tone: Tone; label: string } {
  if (data.stale) return { tone: 'danger', label: t(locale, '스냅샷 지연', 'Snapshot stale') };
  const statuses: string[] = [
    data.agent.status,
    data.containerCollection.status,
    data.linux.status,
  ];
  if (data.dockerEventCollection) statuses.push(data.dockerEventCollection.status);
  if (data.syntheticProbeCollection) statuses.push(data.syntheticProbeCollection.status);
  const tones = statuses.map(collectionTone);
  if (tones.includes('danger')) return { tone: 'danger', label: t(locale, '수집 계통 이상', 'Collection degraded') };
  if (tones.includes('caution')) return { tone: 'caution', label: t(locale, '수집 지연·공백', 'Collection delayed or partial') };
  if (tones.includes('neutral')) return { tone: 'neutral', label: t(locale, '일부 수집 미지원', 'Some collection unsupported') };
  return { tone: 'ok', label: t(locale, '전체 최신', 'All current') };
}

function numberLabel(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value.toLocaleString()
    : '—';
}

function secondsLabel(value: number | null | undefined, locale: MonitorLocale): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? t(locale, `${value.toLocaleString()}초`, `${value.toLocaleString()}s`)
    : '—';
}

function boolLabel(value: boolean | null | undefined, locale: MonitorLocale): string {
  if (value === true) return t(locale, '예', 'Yes');
  if (value === false) return t(locale, '아니요', 'No');
  return '—';
}

function statusLabel(value: string | null | undefined, locale: MonitorLocale): string {
  if (!value) return '—';
  const labels: Record<string, [string, string]> = {
    healthy: ['정상', 'Healthy'], delayed: ['지연', 'Delayed'], disconnected: ['연결 끊김', 'Disconnected'],
    maintenance: ['유지보수', 'Maintenance'], inactive: ['비활성', 'Inactive'], revoked: ['폐기됨', 'Revoked'],
    active: ['활성', 'Active'], fresh: ['최신', 'Fresh'], stale: ['오래됨', 'Stale'], ok: ['정상', 'OK'],
    'last-known': ['마지막 정상 상태', 'Last known'], collection_error: ['수집 오류', 'Collection error'],
    unavailable: ['사용 불가', 'Unavailable'], unsupported: ['지원 안 됨', 'Unsupported'],
    'permission-denied': ['권한 거부', 'Permission denied'], gap: ['수집 공백', 'Gap'], partial: ['부분 수집', 'Partial'],
  };
  const label = labels[value];
  return label ? t(locale, ...label) : safeText(value.replaceAll('_', ' '), '—', 48);
}

function remoteAgentStatusLabel(status: RemoteAgentStatus, locale: MonitorLocale): string {
  return statusLabel(status, locale);
}

function safeValue(value: unknown, maximum = 96): string {
  const sanitized = safeText(value, '—', maximum);
  return RAW_PATH.test(sanitized) ? '—' : sanitized;
}

function Facts({ facts, limit = 16 }: { facts: Fact[]; limit?: number }) {
  return (
    <dl className="infrastructure-facts">
      {facts.slice(0, limit).map((fact) => (
        <div key={fact.label}><dt>{fact.label}</dt><dd>{fact.value}</dd></div>
      ))}
    </dl>
  );
}

function StatusCard({ title, tone, status, facts, children }: {
  title: string;
  tone: Tone;
  status: string;
  facts: Fact[];
  children?: ReactNode;
}) {
  return (
    <article className={`infrastructure-status-card tone-${tone}`}>
      <header><h3>{title}</h3><span className="infrastructure-status-badge">{status}</span></header>
      <Facts facts={facts} />
      {children}
    </article>
  );
}

function monitoringRuleStates(data: DashboardPayload): RuleEvaluationState[] {
  return Object.values(data.ruleEvaluation.states)
    .filter((state) => (
      state.metric.startsWith('monitor.')
      || state.metric === 'host.heartbeat.age_seconds'
      || state.metric === 'agent.heartbeat.age_seconds'
      || state.metric === 'agent.sample.age_seconds'
      || state.metric === 'heartbeat.late_ratio'
    ))
    .sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

function ruleValue(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '—';
  return Math.abs(value) >= 1_000 ? value.toLocaleString() : String(Number(value.toFixed(3)));
}

function LocalObservability({ data, locale }: { data: DashboardPayload | null; locale: MonitorLocale }) {
  if (!data) {
    return (
      <div className="infrastructure-local-unavailable" role="status">
        <Icon name="clock" size={22} />
        <div><strong>{t(locale, '호스트 상태를 불러오는 중', 'Loading host state')}</strong><span>{t(locale, '원격 인벤토리와 별개로 현재 dashboard 스냅샷을 기다리고 있습니다.', 'Waiting for the current dashboard snapshot independently of remote inventory.')}</span></div>
      </div>
    );
  }

  const rules = monitoringRuleStates(data);
  const actionableRules = rules.filter((rule) => ['firing', 'collection_error', 'permission_denied', 'no_data'].includes(rule.phase)).length;
  const agentStatus = agentHeartbeatLabel(data.agent.status, locale, data.stale);
  const collector = collectorAssessment(data, locale);
  const selfHealth = selfHealthAssessment(data, rules, locale);

  return (
    <div className="infrastructure-status-grid">
      <StatusCard
        title={t(locale, '호스트 신원·용량', 'Host identity and capacity')}
        tone={data.stale ? 'caution' : 'ok'}
        status={data.stale ? t(locale, '마지막 상태', 'Last known') : t(locale, '현재 스냅샷', 'Current snapshot')}
        facts={[
          { label: t(locale, '호스트명', 'Hostname'), value: safeValue(data.host.hostname, 96) },
          { label: t(locale, '운영체제', 'Operating system'), value: safeValue(data.host.os, 128) },
          { label: t(locale, '아키텍처', 'Architecture'), value: safeValue(data.host.architecture, 32) },
          { label: t(locale, '논리 CPU', 'Logical CPUs'), value: numberLabel(data.host.logicalCpuCount) },
          { label: t(locale, '가동 시간', 'Uptime'), value: formatUptime(data.host.uptimeSeconds) },
        ]}
      />
      <StatusCard
        title={t(locale, '로컬 에이전트·하트비트', 'Local agent and heartbeat')}
        tone={data.stale ? 'danger' : agentTone(data.agent.status)}
        status={agentStatus}
        facts={[
          { label: 'hostId', value: safeValue(data.agent.hostId, 64) },
          { label: 'agentId', value: safeValue(data.agent.agentId, 64) },
          { label: t(locale, '설치 시점', 'Installation epoch'), value: formatDateTime(data.agent.installationEpoch, locale) },
          { label: t(locale, '신원 세대', 'Identity generation'), value: numberLabel(data.agent.identityGeneration) },
          { label: t(locale, '머신 신원', 'Machine identity'), value: statusLabel(data.agent.machineIdentityStatus, locale) },
          { label: 'bootId', value: safeValue(data.agent.bootId, 64) },
          { label: t(locale, '시퀀스', 'Sequence'), value: numberLabel(data.agent.sequence) },
          { label: t(locale, '수명주기', 'Lifecycle'), value: statusLabel(data.agent.lifecycle, locale) },
          { label: t(locale, '전송', 'Transport'), value: safeValue(data.agent.transport, 32) },
          { label: t(locale, '관찰 시각', 'Observed'), value: formatDateTime(data.agent.observedAt, locale) },
          { label: t(locale, '수신 시각', 'Received'), value: formatDateTime(data.agent.receivedAt, locale) },
          { label: t(locale, '예상 주기', 'Expected interval'), value: secondsLabel(data.agent.expectedIntervalSeconds, locale) },
          { label: t(locale, '하트비트 나이', 'Heartbeat age'), value: secondsLabel(data.agent.ageSeconds, locale) },
          { label: t(locale, '시계 편차', 'Clock skew'), value: secondsLabel(data.agent.clockSkewSeconds === null ? null : Math.abs(data.agent.clockSkewSeconds), locale) },
        ]}
      />
      <StatusCard
        title={t(locale, '수집기 상태', 'Collector state')}
        tone={collector.tone}
        status={collector.label}
        facts={[
          { label: t(locale, 'API 생성', 'API generated'), value: formatDateTime(data.generatedAt, locale) },
          { label: t(locale, '최근 관찰', 'Latest observed'), value: formatDateTime(data.latestObservedAt, locale) },
          { label: t(locale, '수집 공백', 'Collector gap'), value: secondsLabel(data.reliability.collectorGapSeconds, locale) },
          { label: t(locale, '컨테이너 스냅샷', 'Container snapshot'), value: statusLabel(data.containerCollection.status, locale) },
          { label: t(locale, 'Docker 이벤트', 'Docker events'), value: statusLabel(data.dockerEventCollection?.status, locale) },
          { label: t(locale, '합성 검사', 'Synthetic probes'), value: statusLabel(data.syntheticProbeCollection?.status, locale) },
          { label: t(locale, 'Linux 진단', 'Linux diagnostics'), value: statusLabel(data.linux.status, locale) },
        ]}
      />
      <StatusCard
        title={t(locale, 'Monitor 자체 건강', 'Monitor self-health')}
        tone={selfHealth.tone}
        status={selfHealth.label}
        facts={[
          { label: t(locale, '규칙 평가', 'Rule evaluation'), value: statusLabel(data.ruleEvaluation.status, locale) },
          { label: t(locale, '최근 평가', 'Last evaluated'), value: formatDateTime(data.ruleEvaluation.evaluatedAt, locale) },
          { label: t(locale, '전체 평가 상태', 'All rule states'), value: numberLabel(Object.keys(data.ruleEvaluation.states).length) },
          { label: t(locale, '자체 건강 규칙 대상', 'Self-health rule targets'), value: numberLabel(rules.length) },
          { label: t(locale, '조치 필요 대상', 'Actionable targets'), value: numberLabel(actionableRules) },
          { label: t(locale, '규칙 이벤트 저장', 'Rule event storage'), value: statusLabel(data.ruleAlerts.status, locale) },
          { label: t(locale, '보존 전환 이벤트', 'Retained transitions'), value: numberLabel(data.ruleAlerts.events.length) },
        ]}
      >
        <ul className="self-health-rules" aria-label={t(locale, '자체 건강 규칙 상태', 'Self-health rule states')}>
          {rules.slice(0, MAX_SELF_HEALTH_RULES).map((rule) => (
            <li key={`${rule.ruleId}:${rule.target}`} className={`phase-${rule.phase}`}>
              <div><strong>{safeValue(rule.ruleId, 80)}</strong><span>{statusLabel(rule.phase, locale)}</span></div>
              <small>{t(locale, '대상', 'target')} {safeValue(rule.target, 96)} · {safeValue(rule.metric, 96)} · {t(locale, '값', 'value')} {ruleValue(rule.lastValue)} · {formatDateTime(rule.lastEvaluatedAt, locale)}</small>
            </li>
          ))}
          {rules.length > MAX_SELF_HEALTH_RULES && <li className="phase-unsupported"><div><strong>{t(locale, `전체 ${rules.length}개 대상 중 첫 ${MAX_SELF_HEALTH_RULES}개만 표시`, `Showing the first ${MAX_SELF_HEALTH_RULES} of ${rules.length} targets`)}</strong></div><small>{t(locale, '카드 상태와 개수는 숨겨진 항목을 포함한 전체 대상으로 계산합니다.', 'Card tone and counts use the complete target set, including hidden entries.')}</small></li>}
          {!rules.length && <li className="phase-unsupported"><div><strong>{t(locale, '자체 건강 규칙 상태 없음', 'No self-health rule states')}</strong></div><small>{t(locale, '현재 규칙 평가 스냅샷에 자체 건강 대상이 없습니다.', 'The current rule snapshot has no self-health targets.')}</small></li>}
        </ul>
      </StatusCard>
    </div>
  );
}

function RemoteStateMessage({ remote, locale, onRetry }: {
  remote: Exclude<RemoteAgentViewState, { kind: 'ready' }>;
  locale: MonitorLocale;
  onRetry?: () => void;
}) {
  if (remote.kind === 'loading') return <div className="remote-agent-state" aria-busy="true"><Icon name="clock" size={22} /><strong>{t(locale, '원격 에이전트 상태를 불러오는 중…', 'Loading remote agent state…')}</strong></div>;
  if (remote.kind === 'restricted') return <div className="remote-agent-state tone-caution" role="status"><Icon name="lock" size={22} /><strong>{t(locale, '원격 인벤토리는 SSO 관리자 전용입니다', 'Remote inventory requires an SSO administrator')}</strong><span>{t(locale, '로컬 호스트·수집기·자체 건강 상태는 위에서 계속 확인할 수 있습니다.', 'Local host, collector, and self-health state remains available above.')}</span></div>;
  if (remote.kind === 'unauthorized') return <div className="remote-agent-state tone-danger" role="alert"><Icon name="alert" size={22} /><strong>{t(locale, 'SSO 세션을 다시 확인해야 합니다', 'The SSO session must be renewed')}</strong><span>{t(locale, '인증 상태가 만료되어 원격 인벤토리를 읽지 못했습니다.', 'Remote inventory could not be read because authentication expired.')}</span></div>;
  if (remote.kind === 'unsupported') {
    const notConfigured = remote.reason === 'not-configured';
    return <div className="remote-agent-state tone-neutral" role="status"><Icon name="server" size={22} /><strong>{notConfigured ? t(locale, '원격 에이전트 제어면이 구성되지 않았습니다', 'Remote agent control is not configured') : t(locale, '로컬 인증 모드에서는 원격 인벤토리를 사용하지 않습니다', 'Remote inventory is not used in local-auth mode')}</strong><span>{notConfigured ? t(locale, '404는 제어면 비활성 배포의 의도된 계약이며 로컬 수집 실패를 뜻하지 않습니다.', 'A 404 is the intentional contract for a deployment without the control plane; it does not mean local collection failed.') : t(locale, '중앙 인벤토리 endpoint를 요청하지 않으며 위의 로컬 dashboard 상태가 이 배포의 기준입니다.', 'The central inventory endpoint is not requested; the local dashboard state above is authoritative for this deployment.')}</span></div>;
  }
  return (
    <div className="remote-agent-state tone-danger" role="alert">
      <Icon name="alert" size={22} />
      <strong>{t(locale, '원격 인벤토리를 불러오지 못했습니다', 'Remote inventory could not be loaded')}</strong>
      <span>{remote.status === null ? t(locale, '네트워크 또는 응답 오류', 'Network or response error') : `HTTP ${remote.status}`} · {safeValue(remote.code, 64)}</span>
      {onRetry && <button type="button" onClick={onRetry}>{t(locale, '다시 확인', 'Try again')}</button>}
    </div>
  );
}

function RemoteAgents({ remote, locale, onRetry }: {
  remote: RemoteAgentViewState;
  locale: MonitorLocale;
  onRetry?: () => void;
}) {
  if (remote.kind !== 'ready') return <RemoteStateMessage remote={remote} locale={locale} onRetry={onRetry} />;
  const agents = remote.data.agents.slice(0, MAX_REMOTE_AGENTS);
  const queue = remote.data.queue;
  return (
    <div className="remote-agent-ready">
      <div className="remote-agent-summary">
        <div><strong>{t(locale, '등록된 원격 에이전트', 'Registered remote agents')}</strong><span>{t(locale, `${agents.length}/${remote.data.agents.length}개 표시 · 서버 ${formatDateTime(remote.data.serverTime, locale)}`, `${agents.length}/${remote.data.agents.length} shown · server ${formatDateTime(remote.data.serverTime, locale)}`)}</span></div>
        {onRetry && <button type="button" onClick={onRetry}><Icon name="refresh" size={15} />{t(locale, '원격 상태 갱신', 'Refresh remote state')}</button>}
      </div>
      <Facts facts={[
        { label: t(locale, '큐 항목', 'Queue entries'), value: `${numberLabel(queue.entries)} / ${numberLabel(queue.maxEntries)}` },
        { label: t(locale, '큐 용량', 'Queue bytes'), value: `${formatBytes(queue.bytes)} / ${formatBytes(queue.maxBytes)}` },
        { label: t(locale, '우선순위 항목', 'Priority entries'), value: numberLabel(queue.priorityEntries) },
        { label: t(locale, '우선순위 용량', 'Priority bytes'), value: formatBytes(queue.priorityBytes) },
        { label: t(locale, '일반 항목', 'Normal entries'), value: numberLabel(queue.normalEntries) },
        { label: t(locale, '일반 용량', 'Normal bytes'), value: formatBytes(queue.normalBytes) },
        { label: t(locale, '배치 영수증 상한', 'Batch receipt limit'), value: numberLabel(queue.maxBatchReceipts) },
        { label: t(locale, '에이전트당 큐 항목 상한', 'Per-agent queue entries'), value: numberLabel(queue.maxQueueEntriesPerAgent) },
        { label: t(locale, '에이전트당 큐 용량 상한', 'Per-agent queue bytes'), value: formatBytes(queue.maxQueueBytesPerAgent) },
        { label: t(locale, '에이전트당 영수증 상한', 'Per-agent batch receipts'), value: numberLabel(queue.maxBatchReceiptsPerAgent) },
        { label: t(locale, '에이전트당 멱등 기록 상한', 'Per-agent idempotency records'), value: numberLabel(queue.maxIdempotencyRecordsPerAgent) },
        { label: t(locale, '우선순위 예약률', 'Priority reserve'), value: `${numberLabel(queue.priorityReservePercent)}%` },
        { label: t(locale, '거부 배치', 'Rejected batches'), value: numberLabel(queue.rejectedBatches) },
        { label: t(locale, '거부 레코드', 'Rejected records'), value: numberLabel(queue.rejectedRecords) },
        { label: t(locale, '중복 배치', 'Duplicate batches'), value: numberLabel(queue.duplicateBatches) },
        { label: t(locale, '중복 레코드', 'Duplicate records'), value: numberLabel(queue.duplicateRecords) },
        { label: t(locale, '순서 역전 레코드', 'Out-of-order records'), value: numberLabel(queue.outOfOrderRecords) },
        { label: t(locale, '만료 큐 배치', 'Expired queue batches'), value: numberLabel(queue.expiredQueueBatches) },
      ]} limit={24} />
      <ol className="remote-agent-list">
        {agents.map((agent) => (
          <li key={agent.agentId} className={`tone-${agentTone(agent.status)}`}>
            <header>
              <div><strong>{safeValue(agent.inventory.hostname, 96)}</strong><span>{safeValue(agent.inventory.agentVersion, 64)}</span></div>
              <b>{remoteAgentStatusLabel(agent.status, locale)}</b>
            </header>
            <Facts facts={[
              { label: t(locale, '등록 상태', 'Registered'), value: boolLabel(agent.registered, locale) },
              { label: t(locale, '중복 등록', 'Duplicate registration'), value: boolLabel(agent.duplicate, locale) },
              { label: 'hostId', value: safeValue(agent.hostId, 64) },
              { label: 'agentId', value: safeValue(agent.agentId, 64) },
              { label: t(locale, '수명주기', 'Lifecycle'), value: statusLabel(agent.lifecycle, locale) },
              { label: t(locale, '설치 시점', 'Installation epoch'), value: formatDateTime(agent.installationEpoch, locale) },
              { label: t(locale, '등록 시각', 'Registered at'), value: formatDateTime(agent.registeredAt, locale) },
              { label: t(locale, '최근 수신', 'Last seen'), value: formatDateTime(agent.lastSeenAt, locale) },
              { label: t(locale, '최근 관찰', 'Last observed'), value: formatDateTime(agent.lastObservedAt, locale) },
              { label: t(locale, '하트비트 주기', 'Heartbeat interval'), value: secondsLabel(agent.expectedHeartbeatIntervalSeconds, locale) },
              { label: t(locale, '최대 시퀀스', 'Max sequence'), value: numberLabel(agent.maxSequence) },
              { label: t(locale, '운영체제', 'Operating system'), value: safeValue(agent.inventory.operatingSystem, 128) },
              { label: 'Ubuntu', value: safeValue(agent.inventory.ubuntuVersion, 64) },
              { label: t(locale, '커널', 'Kernel'), value: safeValue(agent.inventory.kernelVersion, 128) },
              { label: t(locale, '아키텍처', 'Architecture'), value: safeValue(agent.inventory.architecture, 32) },
              { label: 'CPU', value: safeValue(agent.inventory.cpuModel, 128) },
              { label: t(locale, '메모리', 'Memory'), value: formatBytes(agent.inventory.memoryBytes) },
              { label: t(locale, '인증서 만료', 'Certificate expiry'), value: formatDateTime(agent.certificate.expiresAt, locale) },
              { label: t(locale, '인증서 갱신 필요', 'Certificate renewal'), value: boolLabel(agent.certificate.renewalRequired, locale) },
              { label: t(locale, '시계 거부', 'Clock rejections'), value: numberLabel(agent.clockRejections.count) },
              { label: t(locale, '최근 시계 거부', 'Last clock rejection'), value: formatDateTime(agent.clockRejections.lastRejectedAt, locale) },
              { label: t(locale, '폐기 시각', 'Revoked at'), value: formatDateTime(agent.revokedAt, locale) },
              { label: t(locale, '폐기 사유', 'Revocation reason'), value: safeValue(agent.revokedReason, 32) },
              { label: t(locale, '에이전트 서버 시각', 'Agent server time'), value: formatDateTime(agent.serverTime, locale) },
            ]} limit={28} />
            <div className="remote-agent-addresses"><span>{t(locale, '주소', 'Addresses')}</span><code>{agent.inventory.ipAddresses.slice(0, MAX_REMOTE_ADDRESSES).map((address) => safeValue(address, 45)).join(' · ') || '—'}</code>{agent.inventory.ipAddresses.length > MAX_REMOTE_ADDRESSES && <small>+{agent.inventory.ipAddresses.length - MAX_REMOTE_ADDRESSES}</small>}</div>
          </li>
        ))}
      </ol>
      {!agents.length && <div className="remote-agent-empty"><Icon name="server" size={22} /><strong>{t(locale, '등록된 원격 에이전트가 없습니다', 'No remote agents are registered')}</strong></div>}
      {remote.data.agents.length > MAX_REMOTE_AGENTS && <p className="remote-agent-boundary">{t(locale, `렌더링 상한 ${MAX_REMOTE_AGENTS}개가 적용되었습니다.`, `The rendering limit of ${MAX_REMOTE_AGENTS} agents is applied.`)}</p>}
    </div>
  );
}

export function InfrastructureObservabilityView({ data, locale, remote, onRetry }: InfrastructureObservabilityViewProps) {
  return (
    <section className="infrastructure-observability" aria-label={t(locale, '호스트·에이전트·모니터링 상태', 'Host, agent, and monitoring state')}>
      <header className="infrastructure-observability-header">
        <div><span>{t(locale, '현재 운영 상태', 'CURRENT OPERATING STATE')}</span><h2>{t(locale, '호스트·에이전트·자체 건강', 'Host, agent, and self-health')}</h2><p>{t(locale, 'dashboard의 축약된 안전 필드와 권한이 허용한 원격 인벤토리만 읽기 전용으로 표시합니다.', 'Read-only view of reduced safe dashboard fields and remote inventory allowed by the current role.')}</p></div>
        <Icon name="shield" size={25} />
      </header>
      <LocalObservability data={data} locale={locale} />
      <section className="remote-agent-section" aria-label={t(locale, '원격 에이전트 인벤토리', 'Remote agent inventory')}>
        <header><div><span>{t(locale, '중앙 제어면', 'CENTRAL CONTROL PLANE')}</span><h3>{t(locale, '원격 에이전트 인벤토리', 'Remote agent inventory')}</h3></div></header>
        <RemoteAgents remote={remote} locale={locale} onRetry={onRetry} />
      </section>
    </section>
  );
}

export function InfrastructureObservability({
  data,
  locale,
  ssoEnabled,
  viewer,
  onUnauthorized,
}: InfrastructureObservabilityProps) {
  const initial = useMemo(() => initialRemoteAgentState(ssoEnabled, viewer), [ssoEnabled, viewer]);
  const [remote, setRemote] = useState<RemoteAgentViewState>(initial);

  const load = useCallback(async (
    signal?: AbortSignal,
    showLoading = true,
  ): Promise<RemoteAgentViewState | null> => {
    if (!canReadRemoteAgents(ssoEnabled, viewer)) {
      const next = initialRemoteAgentState(ssoEnabled, viewer);
      setRemote(next);
      return next;
    }
    if (showLoading) setRemote({ kind: 'loading' });
    try {
      const next = await loadRemoteAgentState(signal, onUnauthorized);
      setRemote(next);
      return next;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return null;
      const next: RemoteAgentViewState = { kind: 'failure', status: null, code: 'REQUEST_FAILED' };
      setRemote(next);
      return next;
    }
  }, [onUnauthorized, ssoEnabled, viewer]);

  useEffect(() => {
    if (initial.kind !== 'loading') {
      setRemote(initial);
      return;
    }
    return startRemoteAgentPolling(load);
  }, [initial, load]);

  return <InfrastructureObservabilityView data={data} locale={locale} remote={remote} onRetry={() => void load(undefined, true)} />;
}
