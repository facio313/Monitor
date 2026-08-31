import { useMemo, useState } from 'react';
import { containerCollectionLabel } from '../collection-status';
import type { ContainerStatus, DashboardPayload, MonitorLocale } from '../types';
import { formatBytes, formatDateTime, formatPercent, formatRate, safeText } from '../utils';
import { Icon } from './Icon';

function t(locale: MonitorLocale, ko: string, en: string): string {
  return locale === 'ko' ? ko : en;
}

function reading(value: number | null | undefined, formatter: (candidate: number) => string): string {
  return typeof value === 'number' && Number.isFinite(value) ? formatter(value) : '—';
}

function count(value: number | null | undefined): string {
  return reading(value, (candidate) => Math.round(candidate).toLocaleString());
}

function booleanState(value: boolean | null | undefined, locale: MonitorLocale): string {
  if (value === true) return t(locale, '예', 'Yes');
  if (value === false) return t(locale, '아니요', 'No');
  return '—';
}

function healthcheckState(container: ContainerStatus, locale: MonitorLocale): string {
  if (container.healthcheckConfigured === false) return t(locale, '미설정', 'Not configured');
  if (container.healthcheckConfigured !== true) return t(locale, '확인 불가', 'Unverified');
  return safeText(container.health, t(locale, '상태 미확인', 'Unknown'), 48);
}

function instanceKey(container: ContainerStatus, index: number): string {
  return container.instanceId ?? `legacy-${index}`;
}

function imageReference(container: ContainerStatus): string {
  if (!container.imageName) return '—';
  if (container.imageTag) return `${container.imageName}:${container.imageTag}`;
  return container.imageName;
}

function digestLabel(value: string | null | undefined): string {
  if (!value) return '—';
  return value.length > 27 ? `${value.slice(0, 19)}…${value.slice(-7)}` : value;
}

function securityFindings(container: ContainerStatus, locale: MonitorLocale): string[] {
  const findings: string[] = [];
  if (container.privileged) findings.push(t(locale, 'privileged 모드', 'Privileged mode'));
  if (container.dockerSocketMounted) findings.push(t(locale, 'Docker 소켓 연결', 'Docker socket mounted'));
  if (container.hostPid) findings.push(t(locale, '호스트 PID 공유', 'Host PID namespace'));
  if (container.hostIpc) findings.push(t(locale, '호스트 IPC 공유', 'Host IPC namespace'));
  if (container.hostNetwork) findings.push(t(locale, '호스트 네트워크 공유', 'Host network'));
  if (container.sensitiveBindMounted) findings.push(t(locale, '민감 경로 bind', 'Sensitive bind mount'));
  if (container.rootUser) findings.push(t(locale, 'root 사용자', 'Root user'));
  if (container.readOnlyRootFilesystem === false) findings.push(t(locale, '쓰기 가능한 rootfs', 'Writable root filesystem'));
  if (container.excessiveCapabilities) findings.push(t(locale, '과도한 capability', 'Elevated capabilities'));
  return findings;
}

export function DockerDiagnosticsPanel({ data, locale }: {
  data: DashboardPayload;
  locale: MonitorLocale;
}) {
  const choices = useMemo(
    () => data.containers.map((container, index) => ({ container, key: instanceKey(container, index) })),
    [data.containers],
  );
  const [selectedKey, setSelectedKey] = useState(() => choices[0]?.key ?? '');
  const selected = choices.find((choice) => choice.key === selectedKey) ?? choices[0] ?? null;
  const container = selected?.container ?? null;
  const containerCollection: DashboardPayload['containerCollection'] = data.containerCollection ?? {
    status: 'unavailable',
    observedAt: null,
  };
  const eventCollection = data.dockerEventCollection ?? {
    status: 'unavailable' as const,
    observedAt: null,
    cursorAt: null,
    reconnectCount: 0,
    gapCount: 0,
    gapDetected: true,
    logCollectionStatus: 'unsupported' as const,
  };
  const events = (data.dockerEvents ?? [])
    .filter((event) => !container || event.instanceId === container.instanceId || (
      container.instanceId == null && event.containerName === container.name
    ))
    .slice(-20)
    .reverse();
  const findings = container ? securityFindings(container, locale) : [];

  return (
    <section className="docker-diagnostics" aria-labelledby="docker-diagnostics-heading">
      <header className="docker-diagnostics-head">
        <span className="cockpit-panel-icon"><Icon name="server" size={19} /></span>
        <div>
          <h2 id="docker-diagnostics-heading">{t(locale, 'Docker 진단', 'Docker diagnostics')}</h2>
          <p>{t(locale, '한 컨테이너의 자원, 이미지, 저장소, 보안, 이벤트를 함께 확인합니다.', 'Inspect one container’s resources, image, storage, security, and events together.')}</p>
        </div>
        <div className="docker-source-states" aria-label={t(locale, 'Docker 데이터 원본 상태', 'Docker data source status')}>
          <span className={`docker-source-state state-${containerCollection.status}`}>
            {t(locale, '상태', 'STATE')} · {safeText(containerCollection.status, 'unavailable', 32)}
          </span>
          <span className={`docker-source-state state-${eventCollection.status}`}>
            {t(locale, '이벤트', 'EVENTS')} · {safeText(eventCollection.status, 'unavailable', 32)}
          </span>
        </div>
      </header>

      <div className="docker-source-summary">
        <span>{t(locale, '상태 관측', 'State observed')} <strong>{formatDateTime(containerCollection.observedAt, locale)}</strong></span>
        <span>{t(locale, '이벤트 관측', 'Event observed')} <strong>{formatDateTime(eventCollection.observedAt, locale)}</strong></span>
        <span>{t(locale, '이벤트 커서', 'Event cursor')} <strong>{formatDateTime(eventCollection.cursorAt, locale)}</strong></span>
        <span>{t(locale, '재연결', 'Reconnects')} <strong>{eventCollection.reconnectCount.toLocaleString()}</strong></span>
        <span>{t(locale, '누락 구간', 'Event gaps')} <strong>{eventCollection.gapCount.toLocaleString()}</strong></span>
        <span>{t(locale, 'stdout/stderr', 'stdout/stderr')} <strong>{t(locale, '미수집', 'Not collected')}</strong></span>
      </div>
      {containerCollection.status !== 'fresh' && (
        <p
          className="docker-gap-notice"
          role={containerCollection.status === 'last-known' ? 'status' : 'alert'}
        >
          {containerCollectionLabel(containerCollection.status, locale)} · {t(
            locale,
            '아래 컨테이너 값은 현재 관측으로 단정하지 않습니다.',
            'The container values below are not presented as current observations.',
          )}
        </p>
      )}
      {eventCollection.gapDetected && (
        <p className="docker-gap-notice" role="status">{t(locale, 'Docker 이벤트 이력에 누락 가능성이 있어 현재 상태와 다시 맞췄습니다.', 'The Docker event history may contain a gap; the current state was reconciled separately.')}</p>
      )}

      {!container ? (
        <div className="cockpit-chart-empty">{t(locale, '관측된 컨테이너가 없습니다.', 'No observed containers.')}</div>
      ) : (
        <>
          <label className="docker-container-picker">
            <span>{t(locale, '컨테이너', 'Container')}</span>
            <select value={selected?.key ?? ''} onChange={(event) => setSelectedKey(event.currentTarget.value)}>
              {choices.map((choice) => (
                <option value={choice.key} key={choice.key}>{choice.container.name} · {choice.container.project ?? 'unknown'}</option>
              ))}
            </select>
          </label>

          <div className="docker-diagnostic-grid">
            <article>
              <h3>{t(locale, '실행 상태', 'Runtime')}</h3>
              <dl>
                <div><dt>{t(locale, '상태', 'State')}</dt><dd>{safeText(container.state)}</dd></div>
                <div><dt>{t(locale, 'Healthcheck', 'Healthcheck')}</dt><dd>{healthcheckState(container, locale)}</dd></div>
                <div><dt>{t(locale, '재시작', 'Restarts')}</dt><dd>{count(container.restartCount)} (+{count(container.restartCountDelta)})</dd></div>
                <div><dt>OOMKilled</dt><dd>{booleanState(container.oomKilled, locale)}</dd></div>
                <div><dt>PID</dt><dd>{count(container.pidCount)} / {count(container.pidLimit)}</dd></div>
                <div><dt>{t(locale, '시작', 'Started')}</dt><dd>{formatDateTime(container.startedAt, locale)}</dd></div>
              </dl>
            </article>

            <article>
              <h3>{t(locale, '자원', 'Resources')}</h3>
              <dl>
                <div><dt>CPU</dt><dd>{formatPercent(container.cpuPercent, 1)} / {reading(container.cpuLimitCores, (value) => `${value.toFixed(2)} core`)}</dd></div>
                <div><dt>{t(locale, 'CPU 제한 발생률', 'CPU throttled')}</dt><dd>{formatPercent(container.cpuThrottledPercent, 1)}</dd></div>
                <div><dt>{t(locale, '제한 period', 'Throttled periods')}</dt><dd>{count(container.cpuThrottledPeriods)}</dd></div>
                <div><dt>{t(locale, '누적 제한 시간', 'Throttled time')}</dt><dd>{reading(container.cpuThrottledSeconds, (value) => `${value.toFixed(3)} s`)}</dd></div>
                <div><dt>{t(locale, '메모리', 'Memory')}</dt><dd>{formatBytes(container.memoryBytes)} / {formatBytes(container.memoryLimitBytes)}</dd></div>
                <div><dt>{t(locale, 'Block 읽기', 'Block read')}</dt><dd>{formatBytes(container.blockReadBytes)} · {formatRate(container.blockReadBytesPerSecond)}</dd></div>
                <div><dt>{t(locale, 'Block 쓰기', 'Block write')}</dt><dd>{formatBytes(container.blockWriteBytes)} · {formatRate(container.blockWriteBytesPerSecond)}</dd></div>
                <div><dt>{t(locale, '네트워크 수신', 'Network received')}</dt><dd>{formatBytes(container.networkRxBytes)} · {formatRate(container.networkRxBytesPerSecond)}</dd></div>
                <div><dt>{t(locale, '네트워크 송신', 'Network sent')}</dt><dd>{formatBytes(container.networkTxBytes)} · {formatRate(container.networkTxBytesPerSecond)}</dd></div>
                <div><dt>{t(locale, '네트워크 오류', 'Network errors')}</dt><dd>{count(container.networkErrors)} · {reading(container.networkErrorsPerSecond, (value) => `${value.toFixed(value >= 1 ? 1 : 3)}/s`)}</dd></div>
              </dl>
            </article>

            <article>
              <h3>{t(locale, '이미지와 저장소', 'Image and storage')}</h3>
              <dl>
                <div><dt>{t(locale, '이미지', 'Image')}</dt><dd>{safeText(imageReference(container), '—', 220)}</dd></div>
                <div><dt>Digest</dt><dd title={container.imageDigest ?? undefined}>{digestLabel(container.imageDigest)}</dd></div>
                <div><dt>{t(locale, 'Digest 출처', 'Digest source')}</dt><dd>{safeText(container.imageDigestSource)}</dd></div>
                <div><dt>latest</dt><dd>{booleanState(container.usesLatestTag, locale)}</dd></div>
                <div><dt>{t(locale, 'Digest 혼재', 'Digest drift')}</dt><dd>{booleanState(container.imageDigestDrift, locale)}</dd></div>
                <div><dt>{t(locale, 'Digest 변경', 'Digest changed')}</dt><dd>{booleanState(container.imageDigestChanged, locale)}</dd></div>
                <div><dt>{t(locale, 'Writable layer', 'Writable layer')}</dt><dd>{formatBytes(container.writableLayerBytes)}</dd></div>
                <div><dt>{t(locale, 'Volume / bind / tmpfs', 'Volume / bind / tmpfs')}</dt><dd>{count(container.volumeCount)} / {count(container.bindMountCount)} / {count(container.tmpfsMountCount)}</dd></div>
                <div><dt>{t(locale, '네트워크 / 공개 포트', 'Networks / published ports')}</dt><dd>{count(container.networkAttachmentCount)} / {count(container.publishedPortCount)}</dd></div>
              </dl>
            </article>

            <article className={findings.length ? 'has-risk' : ''}>
              <h3>{t(locale, '보안 요약', 'Security summary')}</h3>
              <dl>
                <div><dt>Privileged</dt><dd>{booleanState(container.privileged, locale)}</dd></div>
                <div><dt>{t(locale, '호스트 PID', 'Host PID')}</dt><dd>{booleanState(container.hostPid, locale)}</dd></div>
                <div><dt>{t(locale, '호스트 IPC', 'Host IPC')}</dt><dd>{booleanState(container.hostIpc, locale)}</dd></div>
                <div><dt>{t(locale, '호스트 네트워크', 'Host network')}</dt><dd>{booleanState(container.hostNetwork, locale)}</dd></div>
                <div><dt>{t(locale, 'Docker 소켓', 'Docker socket')}</dt><dd>{booleanState(container.dockerSocketMounted, locale)}</dd></div>
                <div><dt>{t(locale, '민감 bind', 'Sensitive bind')}</dt><dd>{booleanState(container.sensitiveBindMounted, locale)}</dd></div>
                <div><dt>{t(locale, 'root 사용자', 'Root user')}</dt><dd>{booleanState(container.rootUser, locale)}</dd></div>
                <div><dt>{t(locale, '읽기 전용 rootfs', 'Read-only rootfs')}</dt><dd>{booleanState(container.readOnlyRootFilesystem, locale)}</dd></div>
                <div><dt>{t(locale, '추가 / 고위험 capability', 'Added / dangerous capabilities')}</dt><dd>{count(container.addedCapabilityCount)} / {count(container.dangerousCapabilityCount)}</dd></div>
              </dl>
              {findings.length ? (
                <ul>{findings.map((finding) => <li key={finding}>{finding}</li>)}</ul>
              ) : (
                <p>{t(locale, '수집된 항목에서 높은 위험 설정을 찾지 못했습니다.', 'No high-risk setting was found in the collected summary.')}</p>
              )}
            </article>
          </div>

          <article className="docker-event-timeline">
            <h3>{t(locale, '최근 Docker 이벤트', 'Recent Docker events')}</h3>
            {events.length ? (
              <ol>{events.map((event) => (
                <li key={event.id}>
                  <time dateTime={event.occurredAt}>{formatDateTime(event.occurredAt, locale)}</time>
                  <strong>{safeText(event.action, 'event', 32)}</strong>
                  {event.healthStatus && <span>{event.healthStatus}</span>}
                  {event.exitCode !== null && <span>exit {event.exitCode}</span>}
                </li>
              ))}</ol>
            ) : <p>{t(locale, '선택한 컨테이너의 보존된 이벤트가 없습니다.', 'No retained events for the selected container.')}</p>}
          </article>
        </>
      )}
    </section>
  );
}
