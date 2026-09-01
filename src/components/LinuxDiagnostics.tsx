import type {
  LinuxCapacityEvidence,
  LinuxCollectionStatus,
  LinuxDiagnostics,
  LinuxRateStatus,
  MonitorLocale,
} from '../types';
import { formatDateTime, formatUptime, safeText } from '../utils';
import { paginateItems, Pagination, usePagination } from './Pagination';

type LinuxDiagnosticsPage = 'resources' | 'network' | 'storage' | 'reliability' | 'power';

interface Evidence {
  label: string;
  value: string;
}

interface DiagnosticCardProps {
  title: string;
  status: LinuxCollectionStatus;
  evidence: Evidence[];
  action: string;
  locale: MonitorLocale;
}

function t(locale: MonitorLocale, korean: string, english: string): string {
  return locale === 'ko' ? korean : english;
}

export function linuxCollectionStatusLabel(
  status: LinuxCollectionStatus,
  locale: MonitorLocale,
): string {
  const labels: Record<LinuxCollectionStatus, [string, string]> = {
    supported: ['지원됨', 'Supported'],
    partial: ['부분 수집', 'Partial'],
    unsupported: ['미지원', 'Unsupported'],
    permission_error: ['권한 오류', 'Permission error'],
    unavailable: ['사용 불가', 'Unavailable'],
    invalid: ['잘못된 값', 'Invalid data'],
    collection_error: ['수집 계약 오류', 'Collection error'],
  };
  return t(locale, ...labels[status]);
}

function rateStatusLabel(status: LinuxRateStatus, locale: MonitorLocale): string {
  if (status === 'ok') return t(locale, '계산 가능', 'Ready');
  if (status === 'warmup') return t(locale, '다음 표본 대기', 'Waiting for next sample');
  if (status === 'counter_reset') return t(locale, '카운터 재시작', 'Counter restarted');
  return linuxCollectionStatusLabel(status, locale);
}

function statusTone(status: LinuxCollectionStatus): string {
  if (status === 'supported') return 'ok';
  if (status === 'partial' || status === 'unsupported') return 'caution';
  return 'danger';
}

function collectionAction(status: LinuxCollectionStatus, locale: MonitorLocale): string {
  const actions: Record<LinuxCollectionStatus, [string, string]> = {
    supported: ['현재 근거를 기준선으로 유지하고 변화만 추적합니다.', 'Keep this evidence as the baseline and track changes.'],
    partial: ['잘린 범위와 수집 제한 시간을 확인합니다.', 'Review truncation and the collection deadline.'],
    unsupported: ['이 호스트에서 지원할 수 있는 수집 경로인지 확인합니다.', 'Confirm whether this host has a supported collection path.'],
    permission_error: ['필요한 procfs·sysfs 읽기 권한만 최소 범위로 허용합니다.', 'Grant only the required read access to procfs or sysfs.'],
    unavailable: ['호스트의 procfs·sysfs 또는 관련 시스템 서비스를 확인합니다.', 'Check procfs, sysfs, or the related host service.'],
    invalid: ['원본 커널 값의 형식과 범위를 점검합니다.', 'Inspect the source kernel value and its bounds.'],
    collection_error: ['collector v1과 서버 계약 버전을 맞춘 뒤 다시 수집합니다.', 'Align the collector v1 and server contracts, then collect again.'],
  };
  return t(locale, ...actions[status]);
}

function number(value: number | null, locale: MonitorLocale): string {
  return value === null || !Number.isFinite(value)
    ? '—'
    : new Intl.NumberFormat(locale === 'ko' ? 'ko-KR' : 'en-US', { maximumFractionDigits: 3 }).format(value);
}

function percent(value: number | null, locale: MonitorLocale): string {
  return value === null ? '—' : `${number(value, locale)}%`;
}

function milliseconds(value: number | null, locale: MonitorLocale): string {
  return value === null ? '—' : `${number(value, locale)} ms`;
}

function yesNo(value: boolean | null, locale: MonitorLocale): string {
  if (value === null) return t(locale, '확인 불가', 'Unknown');
  return value ? t(locale, '예', 'Yes') : t(locale, '아니요', 'No');
}

function capacity(value: LinuxCapacityEvidence, locale: MonitorLocale): string {
  const observed = `${number(value.current, locale)} / ${number(value.maximum, locale)}`;
  return value.usedPercent === null ? observed : `${observed} (${percent(value.usedPercent, locale)})`;
}

function DiagnosticCard({ title, status, evidence, action, locale }: DiagnosticCardProps) {
  return (
    <article className={`linux-diagnostic-card tone-${statusTone(status)}`}>
      <header>
        <h3>{title}</h3>
        <span className={`linux-status-badge tone-${statusTone(status)}`}>
          {linuxCollectionStatusLabel(status, locale)}
        </span>
      </header>
      <dl>
        {evidence.map((item) => (
          <div key={item.label}>
            <dt>{item.label}</dt>
            <dd>{item.value}</dd>
          </div>
        ))}
      </dl>
      <p className="linux-next-action">
        <strong>{t(locale, '다음 조치', 'Next action')}</strong>
        <span>{action}</span>
      </p>
    </article>
  );
}

function resourcesCards(linux: LinuxDiagnostics, locale: MonitorLocale) {
  const resources = linux.resources;
  const processPrefix = resources.processCountIsLowerBound ? '≥ ' : '';
  const zombieAction = resources.zombieCount !== null && resources.zombieCount > 0
    ? t(locale, '좀비를 만든 허용 목록 서비스의 종료 처리를 확인합니다.', 'Inspect shutdown handling in the allow-listed service that created zombies.')
    : collectionAction(resources.status, locale);
  return [
    <DiagnosticCard
      key="processes"
      title={t(locale, '프로세스 관찰', 'Process observation')}
      status={resources.status}
      locale={locale}
      evidence={[
        { label: t(locale, '프로세스', 'Processes'), value: `${processPrefix}${number(resources.processCount, locale)}` },
        { label: t(locale, '관찰 완료', 'Observed'), value: number(resources.observedProcessCount, locale) },
        { label: t(locale, '스레드 · 좀비', 'Threads · zombies'), value: `${number(resources.threadCount, locale)} · ${number(resources.zombieCount, locale)}` },
        { label: t(locale, '상태 근거', 'Status basis'), value: resources.scanTruncated || resources.deadlineReached ? t(locale, '범위 또는 제한 시간에 도달', 'Range or deadline reached') : linuxCollectionStatusLabel(resources.status, locale) },
      ]}
      action={zombieAction}
    />,
    <DiagnosticCard
      key="pid"
      title={t(locale, '호스트 PID 여유', 'Host PID headroom')}
      status={resources.pid.status}
      locale={locale}
      evidence={[
        { label: t(locale, '현재 / 최대', 'Current / maximum'), value: capacity(resources.pid, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: linuxCollectionStatusLabel(resources.pid.status, locale) },
      ]}
      action={resources.pid.usedPercent !== null && resources.pid.usedPercent >= 80
        ? t(locale, '프로세스 증가 원인을 확인하고 PID 한도 변경은 마지막에 검토합니다.', 'Find the source of process growth before considering a PID limit change.')
        : collectionAction(resources.pid.status, locale)}
    />,
    <DiagnosticCard
      key="fds"
      title={t(locale, '시스템 파일 디스크립터', 'System file descriptors')}
      status={resources.systemFileDescriptors.status}
      locale={locale}
      evidence={[
        { label: t(locale, '사용 / 최대', 'Used / maximum'), value: capacity(resources.systemFileDescriptors, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: '/proc/sys/fs/file-nr' },
      ]}
      action={resources.systemFileDescriptors.usedPercent !== null && resources.systemFileDescriptors.usedPercent >= 80
        ? t(locale, '허용 목록 서비스의 열린 파일 증가를 점검합니다.', 'Inspect open-file growth in allow-listed services.')
        : collectionAction(resources.systemFileDescriptors.status, locale)}
    />,
    <DiagnosticCard
      key="cgroup"
      title={t(locale, 'cgroup PID 한도', 'cgroup PID limit')}
      status={resources.cgroupPids.status}
      locale={locale}
      evidence={[
        { label: t(locale, '버전', 'Version'), value: resources.cgroupPids.version === null ? '—' : `v${resources.cgroupPids.version}` },
        { label: t(locale, '현재 / 최대', 'Current / maximum'), value: capacity(resources.cgroupPids, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: 'pids.current · pids.max' },
      ]}
      action={resources.cgroupPids.usedPercent !== null && resources.cgroupPids.usedPercent >= 80
        ? t(locale, '해당 cgroup의 프로세스 증가와 설정 한도를 함께 확인합니다.', 'Review process growth and the configured limit for this cgroup.')
        : collectionAction(resources.cgroupPids.status, locale)}
    />,
  ];
}

function networkCards(linux: LinuxDiagnostics, locale: MonitorLocale) {
  const tcp = linux.network.tcp;
  return [
    <DiagnosticCard
      key="retransmission"
      title={t(locale, 'TCP 재전송', 'TCP retransmission')}
      status={tcp.status}
      locale={locale}
      evidence={[
        { label: t(locale, '재전송률', 'Retransmission'), value: percent(tcp.retransmissionPercent, locale) },
        { label: t(locale, '재전송 / 송신', 'Retransmitted / outgoing'), value: `${number(tcp.retransmittedSegmentsPerSecond, locale)}/s · ${number(tcp.outgoingSegmentsPerSecond, locale)}/s` },
        { label: t(locale, '계산 근거', 'Rate basis'), value: rateStatusLabel(tcp.rateStatus, locale) },
      ]}
      action={tcp.retransmissionPercent !== null && tcp.retransmissionPercent >= 1
        ? t(locale, '링크 손실, 혼잡, 애플리케이션 재시도를 함께 확인합니다.', 'Check link loss, congestion, and application retries together.')
        : collectionAction(tcp.status, locale)}
    />,
    <DiagnosticCard
      key="states"
      title={t(locale, 'TCP 연결 상태', 'TCP connection states')}
      status={tcp.socketScanStatus}
      locale={locale}
      evidence={[
        { label: 'ESTABLISHED', value: number(tcp.states.established, locale) },
        { label: 'SYN_SENT', value: number(tcp.states.synSent, locale) },
        { label: 'SYN_RECV', value: number(tcp.states.synRecv, locale) },
        { label: 'FIN_WAIT1', value: number(tcp.states.finWait1, locale) },
        { label: 'FIN_WAIT2', value: number(tcp.states.finWait2, locale) },
        { label: 'TIME_WAIT', value: number(tcp.states.timeWait, locale) },
        { label: 'CLOSE', value: number(tcp.states.close, locale) },
        { label: 'CLOSE_WAIT', value: number(tcp.states.closeWait, locale) },
        { label: 'LAST_ACK', value: number(tcp.states.lastAck, locale) },
        { label: 'LISTEN', value: number(tcp.states.listen, locale) },
        { label: 'CLOSING', value: number(tcp.states.closing, locale) },
        { label: 'NEW_SYN_RECV', value: number(tcp.states.newSynRecv, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: tcp.socketScanTruncated ? t(locale, '소켓 상한 도달', 'Socket cap reached') : linuxCollectionStatusLabel(tcp.socketScanStatus, locale) },
      ]}
      action={tcp.states.closeWait > 0
        ? t(locale, '연결 종료를 미완료한 서비스의 소켓 처리를 점검합니다.', 'Inspect socket cleanup in services leaving connections open.')
        : collectionAction(tcp.socketScanStatus, locale)}
    />,
    <DiagnosticCard
      key="conntrack"
      title={t(locale, 'conntrack 여유', 'Conntrack headroom')}
      status={tcp.conntrack.status}
      locale={locale}
      evidence={[
        { label: t(locale, '현재 / 최대', 'Current / maximum'), value: capacity(tcp.conntrack, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: 'nf_conntrack_count · nf_conntrack_max' },
      ]}
      action={tcp.conntrack.usedPercent !== null && tcp.conntrack.usedPercent >= 80
        ? t(locale, '연결 churn과 방화벽 추적 한도를 함께 점검합니다.', 'Review connection churn and the firewall tracking limit.')
        : collectionAction(tcp.conntrack.status, locale)}
    />,
    <DiagnosticCard
      key="ephemeral"
      title={t(locale, '임시 포트 여유', 'Ephemeral port headroom')}
      status={tcp.ephemeralPorts.status}
      locale={locale}
      evidence={[
        { label: t(locale, '사용 / 범위 용량', 'Used / range capacity'), value: capacity(tcp.ephemeralPorts, locale) },
        { label: t(locale, '포트 범위', 'Port range'), value: `${number(tcp.ephemeralPorts.rangeStart, locale)}–${number(tcp.ephemeralPorts.rangeEnd, locale)}` },
        { label: t(locale, '상태 근거', 'Status basis'), value: 'ip_local_port_range · bounded socket scan' },
      ]}
      action={tcp.ephemeralPorts.usedPercent !== null && tcp.ephemeralPorts.usedPercent >= 80
        ? t(locale, '짧은 연결의 생성률과 keep-alive 설정을 점검합니다.', 'Review short-lived connection churn and keep-alive settings.')
        : collectionAction(tcp.ephemeralPorts.status, locale)}
    />,
  ];
}

function storageCards(linux: LinuxDiagnostics, locale: MonitorLocale) {
  const storage = linux.storage;
  if (!storage.devices.length) {
    return [<DiagnosticCard
      key="empty-storage"
      title={t(locale, '블록 장치 진단', 'Block device diagnostics')}
      status={storage.status}
      locale={locale}
      evidence={[
        { label: t(locale, '관찰 장치', 'Observed devices'), value: '0' },
        { label: t(locale, '수집 범위 잘림', 'Collection truncated'), value: yesNo(storage.truncated, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: linuxCollectionStatusLabel(storage.status, locale) },
      ]}
      action={collectionAction(storage.status, locale)}
    />];
  }
  return storage.devices.map((device, index) => {
    const degraded = device.raidDegradedDevices !== null && device.raidDegradedDevices > 0;
    const pressure = (device.utilizationPercent ?? 0) >= 80 || (device.averageLatencyMilliseconds ?? 0) >= 20;
    const action = degraded
      ? t(locale, 'RAID 구성과 교체 대상 장치를 확인합니다.', 'Inspect the RAID set and the device requiring replacement.')
      : pressure
        ? t(locale, '대기열을 만든 워크로드와 장치 지연을 함께 확인합니다.', 'Correlate the workload queue with device latency.')
        : device.rateStatus !== 'ok'
          ? t(locale, '다음 유효 표본에서 카운터 차분을 다시 확인합니다.', 'Recheck counter deltas on the next valid sample.')
          : collectionAction(storage.status, locale);
    return <DiagnosticCard
      key={`${device.name}-${index}`}
      title={`${safeText(device.name, 'device', 64)} · ${safeText(device.type, 'block', 32)}`}
      status={storage.status}
      locale={locale}
      evidence={[
        { label: t(locale, '읽기 · 쓰기 지연', 'Read · write latency'), value: `${milliseconds(device.readLatencyMilliseconds, locale)} · ${milliseconds(device.writeLatencyMilliseconds, locale)}` },
        { label: t(locale, '평균 지연 · 사용률', 'Average latency · utilization'), value: `${milliseconds(device.averageLatencyMilliseconds, locale)} · ${percent(device.utilizationPercent, locale)}` },
        { label: t(locale, '현재 · 평균 큐', 'Current · average queue'), value: `${number(device.queueDepth, locale)} · ${number(device.averageQueueDepth, locale)}` },
        { label: t(locale, '회전식 장치', 'Rotational device'), value: yesNo(device.rotational, locale) },
        { label: t(locale, 'RAID 저하 장치', 'RAID degraded devices'), value: number(device.raidDegradedDevices, locale) },
        { label: t(locale, '수집 범위 잘림', 'Collection truncated'), value: yesNo(storage.truncated, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: `${rateStatusLabel(device.rateStatus, locale)} · SMART ${linuxCollectionStatusLabel(device.smartStatus, locale)} · RAID ${device.raidArrayState ?? linuxCollectionStatusLabel(device.raidStatus, locale)}` },
      ]}
      action={action}
    />;
  });
}

function reliabilityCards(linux: LinuxDiagnostics, locale: MonitorLocale) {
  const { clock, systemd } = linux.reliability;
  const problematicUnit = systemd.units.find((unit) => (
    unit.activeState !== 'active' || (unit.restartCount ?? 0) > 0 || !['success', 'unknown'].includes(unit.result)
  ));
  const cards = [
    <DiagnosticCard
      key="clock"
      title={t(locale, '시계 동기화', 'Clock synchronization')}
      status={clock.timeSync.status}
      locale={locale}
      evidence={[
        { label: t(locale, '동기화 · NTP 활성', 'Synchronized · NTP enabled'), value: `${yesNo(clock.timeSync.synchronized, locale)} · ${yesNo(clock.timeSync.ntpEnabled, locale)}` },
        { label: t(locale, 'NTP 지원', 'NTP supported'), value: yesNo(clock.timeSync.ntpSupported, locale) },
        { label: t(locale, '드리프트', 'Drift'), value: `${milliseconds(clock.timeSync.clockDriftMilliseconds, locale)} · ${linuxCollectionStatusLabel(clock.timeSync.clockDriftStatus, locale)}` },
        { label: t(locale, '상태 근거', 'Status basis'), value: clock.timeSync.reason ?? linuxCollectionStatusLabel(clock.timeSync.status, locale) },
      ]}
      action={clock.timeSync.synchronized === false
        ? t(locale, 'NTP 연결과 시간 동기화 서비스를 복구합니다.', 'Restore NTP connectivity and the time synchronization service.')
        : collectionAction(clock.timeSync.status, locale)}
    />,
    <DiagnosticCard
      key="reboot"
      title={t(locale, '부팅 연속성', 'Boot continuity')}
      status={clock.status}
      locale={locale}
      evidence={[
        { label: t(locale, '가동 시간', 'Uptime'), value: clock.uptimeSeconds === null ? '—' : `${formatUptime(clock.uptimeSeconds)} (${number(clock.uptimeSeconds, locale)} s)` },
        { label: t(locale, '부팅 시각', 'Boot time'), value: clock.bootTime ? formatDateTime(clock.bootTime, locale) : '—' },
        { label: t(locale, '표본 사이 재부팅', 'Reboot between samples'), value: yesNo(clock.rebootDetectedSincePreviousSample, locale) },
        { label: t(locale, '예상 밖 재부팅', 'Unexpected reboot'), value: `${yesNo(clock.unexpectedReboot, locale)} · ${safeText(clock.unexpectedRebootStatus, 'unknown', 64)}` },
      ]}
      action={clock.rebootDetectedSincePreviousSample
        ? t(locale, '유지보수 기록과 같은 시각의 커널·전원 이벤트를 대조합니다.', 'Correlate maintenance records with kernel and power events at that time.')
        : collectionAction(clock.status, locale)}
    />,
    <DiagnosticCard
      key="systemd"
      title={t(locale, '허용 목록 systemd unit', 'Allow-listed systemd units')}
      status={systemd.status}
      locale={locale}
      evidence={[
        { label: t(locale, '허용 목록 unit', 'Allow-listed units'), value: number(systemd.units.length, locale) },
        { label: t(locale, '수집 범위 잘림', 'Collection truncated'), value: yesNo(systemd.truncated, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: systemd.reason ?? linuxCollectionStatusLabel(systemd.status, locale) },
      ]}
      action={problematicUnit
        ? t(locale, `${safeText(problematicUnit.unit, 'unit', 128)}의 상태·결과·재시작 원인을 확인합니다.`, `Inspect state, result, and restart cause for ${safeText(problematicUnit.unit, 'unit', 128)}.`)
        : collectionAction(systemd.status, locale)}
    />,
  ];

  systemd.units.forEach((unit, index) => {
    const unitProblem = unit.activeState !== 'active'
      || (unit.restartCount ?? 0) > 0
      || !['success', 'unknown'].includes(unit.result);
    cards.push(<DiagnosticCard
      key={`systemd-${unit.unit}-${index}`}
      title={safeText(unit.unit, 'unit', 128)}
      status={systemd.status}
      locale={locale}
      evidence={[
        { label: t(locale, '로드 상태', 'Load state'), value: safeText(unit.loadState, 'unknown', 32) },
        { label: t(locale, '활성 상태', 'Active state'), value: safeText(unit.activeState, 'unknown', 32) },
        { label: t(locale, '하위 상태', 'Sub-state'), value: safeText(unit.subState, 'unknown', 32) },
        { label: t(locale, '재시작 횟수', 'Restart count'), value: number(unit.restartCount, locale) },
        { label: t(locale, '재시작 근거', 'Restart count source'), value: safeText(unit.restartCountStatus, 'unknown', 64) },
        { label: t(locale, '실행 결과', 'Result'), value: safeText(unit.result, 'unknown', 32) },
        { label: 'ExecMainStatus', value: number(unit.execMainStatus, locale) },
        { label: t(locale, 'Invocation 상태', 'Invocation status'), value: unit.invocationStatus === null ? '—' : linuxCollectionStatusLabel(unit.invocationStatus, locale) },
      ]}
      action={unitProblem
        ? t(locale, '이 unit의 상태·결과·재시작 원인을 확인합니다.', 'Inspect this unit’s state, result, and restart cause.')
        : collectionAction(systemd.status, locale)}
    />);
  });

  return cards;
}

function powerCards(linux: LinuxDiagnostics, locale: MonitorLocale) {
  const power = linux.power;
  const rpi = power.raspberryPi;
  const hasRpiFault = [
    rpi.currentUnderVoltage, rpi.currentFrequencyCapped, rpi.currentThrottled,
    rpi.currentSoftTemperatureLimit, rpi.underVoltageOccurred,
    rpi.frequencyCapOccurred, rpi.throttlingOccurred,
    rpi.softTemperatureLimitOccurred,
  ].some((value) => value === true);
  const cards = [
    <DiagnosticCard
      key="thermal"
      title={t(locale, '열원과 팬 근거', 'Thermal and fan evidence')}
      status={power.status}
      locale={locale}
      evidence={[
        { label: t(locale, '최고 온도', 'Maximum temperature'), value: power.maximumTemperatureCelsius === null ? '—' : `${number(power.maximumTemperatureCelsius, locale)}°C` },
        { label: t(locale, '센서', 'Sensors'), value: number(power.sensors.length, locale) },
        { label: t(locale, '팬', 'Fans'), value: number(power.fans.length, locale) },
        { label: t(locale, '수집 범위 잘림', 'Collection truncated'), value: yesNo(power.truncated, locale) },
        { label: t(locale, '상태 근거', 'Status basis'), value: linuxCollectionStatusLabel(power.status, locale) },
      ]}
      action={power.maximumTemperatureCelsius !== null && power.maximumTemperatureCelsius >= 80
        ? t(locale, '냉각 경로, 팬 회전, 지속 부하를 함께 확인합니다.', 'Check airflow, fan rotation, and sustained load together.')
        : collectionAction(power.status, locale)}
    />,
  ];

  power.sensors.forEach((sensor, index) => {
    cards.push(<DiagnosticCard
      key={`sensor-${sensor.name}-${index}`}
      title={`${t(locale, '온도 센서', 'Temperature sensor')} · ${safeText(sensor.name, 'sensor', 64)}`}
      status={sensor.status}
      locale={locale}
      evidence={[
        { label: t(locale, '출처', 'Source'), value: sensor.source },
        { label: t(locale, '온도', 'Temperature'), value: sensor.temperatureCelsius === null ? '—' : `${number(sensor.temperatureCelsius, locale)}°C` },
        { label: t(locale, '수집 상태', 'Collection status'), value: linuxCollectionStatusLabel(sensor.status, locale) },
      ]}
      action={sensor.temperatureCelsius !== null && sensor.temperatureCelsius >= 80
        ? t(locale, '센서 위치의 냉각 경로와 지속 부하를 확인합니다.', 'Check airflow and sustained load at this sensor.')
        : collectionAction(sensor.status, locale)}
    />);
  });

  power.fans.forEach((fan, index) => {
    cards.push(<DiagnosticCard
      key={`fan-${fan.name}-${index}`}
      title={`${t(locale, '팬', 'Fan')} · ${safeText(fan.name, 'fan', 64)}`}
      status={fan.status}
      locale={locale}
      evidence={[
        { label: 'RPM', value: number(fan.rpm, locale) },
        { label: t(locale, '수집 상태', 'Collection status'), value: linuxCollectionStatusLabel(fan.status, locale) },
      ]}
      action={collectionAction(fan.status, locale)}
    />);
  });

  cards.push(<DiagnosticCard
      key="raspberry-pi"
      title={t(locale, 'Raspberry Pi 전원·제한', 'Raspberry Pi power and throttling')}
      status={rpi.status}
      locale={locale}
      evidence={[
        { label: t(locale, '감지 · 플래그 출처', 'Detected · flag source'), value: `${yesNo(rpi.detected, locale)} · ${rpi.flagSource ?? '—'}` },
        { label: t(locale, '제한 플래그', 'Throttled flags'), value: rpi.throttledFlags === null ? '—' : `${number(rpi.throttledFlags, locale)} (0x${rpi.throttledFlags.toString(16)})` },
        { label: t(locale, '현재 저전압', 'Current undervoltage'), value: yesNo(rpi.currentUnderVoltage, locale) },
        { label: t(locale, '현재 주파수 제한', 'Current frequency cap'), value: yesNo(rpi.currentFrequencyCapped, locale) },
        { label: t(locale, '현재 쓰로틀링', 'Current throttling'), value: yesNo(rpi.currentThrottled, locale) },
        { label: t(locale, '현재 소프트 온도 제한', 'Current soft temperature limit'), value: yesNo(rpi.currentSoftTemperatureLimit, locale) },
        { label: t(locale, '과거 저전압', 'Undervoltage occurred'), value: yesNo(rpi.underVoltageOccurred, locale) },
        { label: t(locale, '과거 주파수 제한', 'Frequency cap occurred'), value: yesNo(rpi.frequencyCapOccurred, locale) },
        { label: t(locale, '과거 쓰로틀링', 'Throttling occurred'), value: yesNo(rpi.throttlingOccurred, locale) },
        { label: t(locale, '과거 소프트 온도 제한', 'Soft temperature limit occurred'), value: yesNo(rpi.softTemperatureLimitOccurred, locale) },
        { label: t(locale, '온도 · 공급 전압', 'Temperature · supply voltage'), value: `${rpi.temperatureCelsius === null ? '—' : `${number(rpi.temperatureCelsius, locale)}°C`} · ${rpi.supplyVoltageVolts === null ? '—' : `${number(rpi.supplyVoltageVolts, locale)} V`}` },
      ]}
      action={hasRpiFault
        ? t(locale, '전원 어댑터·케이블·냉각 상태를 확인하고 플래그 변화를 재검증합니다.', 'Check the adapter, cable, and cooling, then verify the flag changes.')
        : collectionAction(rpi.status, locale)}
    />);

  return cards;
}

export function LinuxDiagnosticsPanel({
  linux,
  page,
  locale,
}: {
  linux: LinuxDiagnostics;
  page: LinuxDiagnosticsPage;
  locale: MonitorLocale;
}) {
  const titles: Record<LinuxDiagnosticsPage, [string, string]> = {
    resources: ['Linux 자원 진단', 'Linux resource diagnostics'],
    network: ['Linux 네트워크 진단', 'Linux network diagnostics'],
    storage: ['Linux 저장장치 진단', 'Linux storage diagnostics'],
    reliability: ['Linux 신뢰성 진단', 'Linux reliability diagnostics'],
    power: ['Linux 열·전원 진단', 'Linux thermal and power diagnostics'],
  };
  const pageStatus = linux[page].status;
  const cards = page === 'resources'
    ? resourcesCards(linux, locale)
    : page === 'network'
      ? networkCards(linux, locale)
      : page === 'storage'
        ? storageCards(linux, locale)
        : page === 'reliability'
          ? reliabilityCards(linux, locale)
          : powerCards(linux, locale);
  const pagination = usePagination({
    totalItems: cards.length,
    pageSize: 8,
    resetKey: page,
  });
  const visibleCards = paginateItems(cards, pagination);
  const headingId = `linux-${page}-diagnostics-heading`;

  return (
    <section className="linux-diagnostics" aria-labelledby={headingId} data-linux-status={pageStatus}>
      <header className="linux-diagnostics-header">
        <div>
          <p>{t(locale, 'collector v1 · 축약된 호스트 근거', 'collector v1 · reduced host evidence')}</p>
          <h2 id={headingId}>{t(locale, ...titles[page])}</h2>
        </div>
        <div className="linux-diagnostics-meta">
          <span className={`linux-status-badge tone-${statusTone(pageStatus)}`} role="status">
            {linuxCollectionStatusLabel(pageStatus, locale)}
          </span>
          {linux.collectedAt && <time dateTime={linux.collectedAt}>{formatDateTime(linux.collectedAt, locale)}</time>}
        </div>
      </header>
      <div className="linux-diagnostic-grid">{visibleCards}</div>
      {pagination.pageCount > 1 && (
        <Pagination
          model={pagination}
          locale={locale}
          onPageChange={pagination.setPage}
          ariaLabel={t(locale, 'Linux 진단 페이지', 'Linux diagnostic pages')}
          itemLabel={t(locale, '개 진단', 'diagnostics')}
        />
      )}
    </section>
  );
}
