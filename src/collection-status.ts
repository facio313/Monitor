import type { AgentHeartbeatStatus, DashboardPayload, MonitorLocale } from './types';

export type CollectionStatusTone = 'ok' | 'caution' | 'danger' | 'unknown';

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

export function agentHeartbeatTone(
  status: AgentHeartbeatStatus | null | undefined,
  stale = false,
): CollectionStatusTone {
  if (stale) return 'danger';
  if (status === 'healthy') return 'ok';
  if (status === 'disconnected' || status === 'collection_error') return 'danger';
  if (status === 'delayed' || status === 'maintenance' || status === 'inactive') return 'caution';
  return 'unknown';
}

export function agentHeartbeatLabel(
  status: AgentHeartbeatStatus | null | undefined,
  locale: MonitorLocale,
  stale = false,
): string {
  if (stale) return t(locale, '데이터 지연', 'STALE DATA');
  if (status === 'healthy') return t(locale, '실시간', 'LIVE');
  if (status === 'delayed') return t(locale, '수집 지연', 'DELAYED');
  if (status === 'disconnected') return t(locale, '수집 중단', 'DISCONNECTED');
  if (status === 'maintenance') return t(locale, '유지보수', 'MAINTENANCE');
  if (status === 'inactive') return t(locale, '비활성', 'INACTIVE');
  if (status === 'collection_error') return t(locale, '계약 오류', 'CONTRACT ERROR');
  return t(locale, '미확인', 'UNKNOWN');
}

export function agentHeartbeatDetail(
  agent: DashboardPayload['agent'],
  locale: MonitorLocale,
): string {
  const age = typeof agent.ageSeconds === 'number' && Number.isFinite(agent.ageSeconds)
    ? `${Math.round(agent.ageSeconds)}s`
    : t(locale, '시각 없음', 'No timestamp');
  const sequence = typeof agent.sequence === 'number'
    ? t(locale, `순번 ${agent.sequence.toLocaleString()}`, `sequence ${agent.sequence.toLocaleString()}`)
    : t(locale, '순번 없음', 'No sequence');
  return `${agentHeartbeatLabel(agent.status, locale)} · ${age} · ${sequence}`;
}

export function containerCollectionTone(
  status: DashboardPayload['containerCollection']['status'] | null | undefined,
): CollectionStatusTone {
  if (status === 'fresh') return 'ok';
  if (status === 'last-known') return 'caution';
  if (status === 'unavailable' || status === 'permission-denied') return 'danger';
  return 'unknown';
}

export function containerCollectionLabel(
  status: DashboardPayload['containerCollection']['status'] | null | undefined,
  locale: MonitorLocale,
): string {
  if (status === 'fresh') return t(locale, '서비스 수집 정상', 'Service collection current');
  if (status === 'last-known') return t(locale, '마지막 서비스 상태', 'Last-known services');
  if (status === 'permission-denied') return t(locale, '서비스 수집 권한 부족', 'Service collection denied');
  if (status === 'unavailable') return t(locale, '서비스 수집 불가', 'Service collection unavailable');
  return t(locale, '서비스 수집 미확인', 'Service collection unknown');
}
