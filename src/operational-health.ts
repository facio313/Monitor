import { NETWORK_FAULT_RATE_THRESHOLDS, PSI_THRESHOLDS } from './operational-thresholds';
import type {
  ContainerStatus,
  DashboardPayload,
  LinuxCollectionStatus,
  MonitorDetailPage,
  RuleEvaluationState,
  TimeRange,
} from './types';

export type OperationalFindingLevel = 'danger' | 'caution';
export type OperationalFindingScope = 'current' | 'boot' | 'last-known' | 'range';
export type LocalizedText = readonly [korean: string, english: string];

export type OperationalFindingId =
  | 'collection-stale'
  | 'agent-heartbeat'
  | 'service-collection'
  | 'rule-evaluation'
  | 'collection-gap'
  | 'service-fault'
  | 'resource-pressure'
  | 'storage-capacity'
  | 'power-quality'
  | 'connectivity'
  | 'network-quality'
  | 'application-traffic'
  | 'kernel-crash'
  | 'kernel-stall'
  | 'rcu-expedited'
  | 'kernel-warning'
  | 'memory-oom'
  | 'storage-integrity'
  | 'pcie-integrity'
  | 'nvme-mitigation'
  | 'reboot-required'
  | 'linux-reliability'
  | 'container-security'
  | 'docker-event-coverage'
  | 'synthetic-availability'
  | 'active-incident';

interface OperationalFindingDefinition {
  id: OperationalFindingId;
  page: MonitorDetailPage;
  priority: number;
  title: LocalizedText;
  summary: LocalizedText;
  problem: LocalizedText;
  symptoms: readonly LocalizedText[];
  resolutions: readonly LocalizedText[];
}

export interface OperationalFinding extends OperationalFindingDefinition {
  level: OperationalFindingLevel;
  scope: OperationalFindingScope;
  evidence: LocalizedText;
  count: number | null;
  lastObservedAt: string | null;
}

const DEFINITIONS: Record<OperationalFindingId, OperationalFindingDefinition> = {
  'collection-stale': {
    id: 'collection-stale',
    page: 'reliability',
    priority: 1,
    title: ['수집 데이터 지연', 'Telemetry collection delay'],
    summary: ['화면의 수치가 현재 상태를 반영하지 않을 수 있습니다.', 'The displayed readings may no longer represent the current host state.'],
    problem: ['수집기가 예정된 간격 안에 새 스냅샷을 만들지 못했습니다. 수치가 정상처럼 보여도 현재 상태로 판단하면 안 됩니다.', 'The collector did not publish a fresh snapshot within its expected interval. Nominal-looking values must not be treated as current.'],
    symptoms: [
      ['화면 갱신 시각이 멈추거나 데이터 지연 표시가 계속됩니다.', 'The display timestamp stops advancing or a stale-data state persists.'],
      ['최근 사건과 자원 변화가 뒤늦게 나타나거나 누락된 것처럼 보입니다.', 'Recent incidents and resource changes appear late or seem to be missing.'],
    ],
    resolutions: [
      ['Monitor 수집 타이머와 마지막 실행 결과를 확인합니다.', 'Check the Monitor collector timer and its most recent run result.'],
      ['수집 로그의 권한·디스크 공간·입력 파일 오류를 확인합니다.', 'Inspect collection logs for permission, disk-space, or input-file errors.'],
      ['수집이 복구된 뒤 새 생성 시각이 계속 증가하는지 확인합니다.', 'After recovery, verify that the generated timestamp keeps advancing.'],
    ],
  },
  'agent-heartbeat': {
    id: 'agent-heartbeat',
    page: 'reliability',
    priority: 1,
    title: ['수집기 연결 상태 확인', 'Collector heartbeat needs review'],
    summary: ['수집기 하트비트가 지연·중단됐거나 명시적으로 비활성 상태입니다.', 'The collector heartbeat is delayed, disconnected, or explicitly inactive.'],
    problem: ['수집기 연결 상태가 정상이 아니면 화면의 수치와 사건 기록이 현재 호스트 상태를 빠뜨릴 수 있습니다.', 'When the collector connection is not healthy, displayed readings and incident records can miss the current host state.'],
    symptoms: [
      ['하트비트 순번 또는 관측 시각이 증가하지 않거나 수집 상태가 지연·중단·오류로 표시됩니다.', 'The heartbeat sequence or observation time stops advancing, or collection shows delayed, disconnected, or error.'],
      ['유지보수·비활성 상태라면 새 원격 측정이 의도적으로 멈출 수 있습니다.', 'Maintenance or inactive lifecycle can intentionally stop new telemetry.'],
    ],
    resolutions: [
      ['수집 타이머와 마지막 실행 결과, 출력 디렉터리 권한을 확인합니다.', 'Check the collector timer, its last result, and output-directory permissions.'],
      ['호스트 ID·에이전트 ID가 예상 설치와 일치하고 하트비트 순번이 계속 증가하는지 확인합니다.', 'Confirm the host and agent IDs match the expected installation and that the heartbeat sequence advances.'],
      ['계획된 유지보수가 아니라면 수집기를 복구한 뒤 새 표본과 규칙 평가가 함께 갱신되는지 확인합니다.', 'If this is not planned maintenance, restore the collector and verify both samples and rule evaluation refresh.'],
    ],
  },
  'service-collection': {
    id: 'service-collection',
    page: 'containers',
    priority: 2,
    title: ['서비스 수집 상태 확인', 'Service collection needs review'],
    summary: ['컨테이너 목록이 비어 있는 것이 아니라 Docker 관측이 오래됐거나 실패했을 수 있습니다.', 'An empty service list may mean Docker observation is stale or failed, not that no services exist.'],
    problem: ['수집 실패를 0개 정상 서비스로 해석하면 실제 중단·재시작·비정상 상태를 놓칠 수 있습니다.', 'Treating collection failure as zero healthy services can hide real outages, restarts, or unhealthy states.'],
    symptoms: [
      ['서비스 수집이 마지막 상태·권한 부족·수집 불가로 표시됩니다.', 'Service collection reports last-known, permission denied, or unavailable.'],
      ['서비스 개수가 갑자기 0으로 보이지만 Docker 자체 상태는 확인되지 않습니다.', 'The service count suddenly appears as zero while Docker itself is unverified.'],
    ],
    resolutions: [
      ['Docker 소켓 접근 권한과 제한된 수집 프록시 상태를 확인합니다.', 'Check Docker socket access and the restricted collection proxy.'],
      ['마지막 관측 시각과 다음 수집에서 fresh 상태로 회복되는지 확인합니다.', 'Check the last observation time and whether the next collection returns to fresh.'],
      ['수집이 복구될 때까지 마지막 상태를 현재 상태로 단정하지 않습니다.', 'Do not present last-known service state as current until collection recovers.'],
    ],
  },
  'rule-evaluation': {
    id: 'rule-evaluation',
    page: 'reliability',
    priority: 2,
    title: ['지속 규칙 평가 확인', 'Rule evaluation needs review'],
    summary: ['발화·회복 중인 규칙 또는 규칙 평가 범위 오류가 있습니다.', 'Rules are firing or recovering, or evaluator coverage has an error.'],
    problem: ['지속 조건을 충족한 규칙과 평가기 장애가 전체 상태에서 빠지면 정상으로 오인할 수 있습니다.', 'If persistent rule signals or evaluator failures are omitted from overall state, the system can be mistaken for nominal.'],
    symptoms: [
      ['규칙 카드가 firing·recovering·collection error·permission denied 상태를 표시합니다.', 'Rule cards report firing, recovering, collection error, or permission denied.'],
      ['전체 상태와 규칙 평가 상태가 서로 다르게 보일 수 있습니다.', 'Overall status and rule-evaluator status can otherwise disagree.'],
    ],
    resolutions: [
      ['발화 규칙의 대상·관측값·열린 시각과 안전 확인 절차를 검토합니다.', 'Review each firing rule target, value, opened time, and safe runbook.'],
      ['평가 오류라면 규칙 팩과 평가 출력 파일의 권한·스키마·최신성을 확인합니다.', 'For evaluator errors, check rule-pack and output-file permissions, schema, and freshness.'],
      ['복구 표본 수를 충족해 resolved 전이가 기록되는지 확인합니다.', 'Verify recovery samples complete and a resolved transition is recorded.'],
    ],
  },
  'collection-gap': {
    id: 'collection-gap',
    page: 'reliability',
    priority: 10,
    title: ['수집 공백 이력', 'Telemetry collection gap'],
    summary: ['직전 수집 사이에 평소보다 긴 관측 공백이 있었지만 새 스냅샷은 다시 들어왔습니다.', 'The previous collection interval had a longer-than-normal gap, but a fresh snapshot has arrived again.'],
    problem: ['공백 구간의 상태 변화와 피크는 Monitor에 기록되지 않았을 수 있습니다. 현재 데이터 지연과는 구분해서 봐야 합니다.', 'State changes and peaks during the gap may not have been recorded. This is historical coverage loss, not the same as currently stale data.'],
    symptoms: [
      ['그래프에 표본이 비거나 직전 수집 간격이 2분 이상으로 표시됩니다.', 'The chart has a sample gap or the previous collection interval is two minutes or longer.'],
      ['새 생성 시각은 다시 증가하므로 화면 자체는 현재 상태로 복구됐을 수 있습니다.', 'The generated timestamp advances again, so the display itself may already be current.'],
    ],
    resolutions: [
      ['수집 타이머의 이전 실패·지연 기록과 당시 호스트 부하를 확인합니다.', 'Review prior collector timer failures or delays and host load at that time.'],
      ['권한·디스크 공간·입력 지연이 반복되는지 관찰합니다.', 'Watch for recurring permission, disk-space, or input-delay issues.'],
      ['최신 생성 시각이 1분 간격으로 계속 증가하면 복구된 이력으로 유지합니다.', 'If the generated timestamp continues advancing every minute, retain this as recovered history.'],
    ],
  },
  'service-fault': {
    id: 'service-fault',
    page: 'containers',
    priority: 2,
    title: ['서비스 상태 확인', 'Service state needs review'],
    summary: ['중지·비정상·전환 중이거나 상태가 불확실한 서비스가 있습니다.', 'One or more services are stopped, unhealthy, transitioning, or uncertain.'],
    problem: ['관측된 워크로드 상태가 명확한 정상 실행 범위를 벗어났습니다. 위험 상태는 기능 중단을, 주의 상태는 전환 지연이나 상태 확인 필요를 뜻합니다.', 'An observed workload state was outside a clearly healthy running state. Danger indicates likely service loss; caution indicates a transition or uncertain state that needs review.'],
    symptoms: [
      ['서비스 요청 실패, 연결 거부 또는 반복 재시작이 나타날 수 있습니다.', 'Requests may fail, connections may be refused, or the workload may restart repeatedly.'],
      ['서비스 상태표에 unhealthy·exited·dead·failed뿐 아니라 starting·restarting·paused·created·removing·unknown 같은 전환 또는 불확실 상태가 표시될 수 있습니다.', 'The service board can report unhealthy, exited, dead, or failed, as well as transitional or uncertain states such as starting, restarting, paused, created, removing, or unknown.'],
    ],
    resolutions: [
      ['전환 중이거나 상태가 불확실한 경우 다음 수집에서도 정상 running 상태로 바뀌는지 먼저 재확인합니다.', 'For transitional or uncertain states, first check whether the next collection returns to a normal running state.'],
      ['중지·unhealthy·반복 restarting이면 서비스 자체 로그와 의존 서비스 상태를 함께 확인합니다.', 'For stopped, unhealthy, or repeatedly restarting workloads, inspect service logs and dependency health together.'],
      ['원인을 해소한 뒤 정상 상태가 안정적으로 유지되는지 확인합니다.', 'Correct the cause, then verify that a healthy state remains stable.'],
    ],
  },
  'resource-pressure': {
    id: 'resource-pressure',
    page: 'resources',
    priority: 8,
    title: ['호스트 자원 압박', 'Host resource pressure'],
    summary: ['CPU·메모리·온도 또는 시스템 부하가 관찰 임계치를 넘었습니다.', 'CPU, memory, temperature, or system load crossed an observation threshold.'],
    problem: ['관측된 자원 수치가 지속될 경우 처리 지연, 스로틀링 또는 메모리 부족으로 이어질 수 있습니다.', 'If the observed readings persist, they can lead to latency, throttling, or memory exhaustion.'],
    symptoms: [
      ['응답 시간이 길어지고 작업 대기열이나 시스템 부하가 증가합니다.', 'Response times rise and work queues or system load increase.'],
      ['온도가 높으면 클럭 제한이, 메모리가 부족하면 OOM 종료가 나타날 수 있습니다.', 'High temperature can cap clocks, while memory exhaustion can trigger OOM termination.'],
    ],
    resolutions: [
      ['관측값과 기간 추세를 비교해 순간 피크인지 지속 압박인지 구분합니다.', 'Compare the observed readings with the time-range trend to distinguish a spike from sustained pressure.'],
      ['사건 분석에서 당시 프로세스·PSI·서비스 증거를 확인합니다.', 'Use incident analysis to inspect process, PSI, and service evidence from the event.'],
      ['원인 워크로드를 조정하고 냉각·메모리·CPU 용량을 점검합니다.', 'Tune the responsible workload and verify cooling, memory, and CPU capacity.'],
    ],
  },
  'storage-capacity': {
    id: 'storage-capacity',
    page: 'storage',
    priority: 5,
    title: ['저장공간·아이노드 여유 부족', 'Low storage or inode headroom'],
    summary: ['하나 이상의 볼륨이 용량 또는 파일 개수 임계치에 도달했습니다.', 'One or more volumes reached a byte-capacity or file-count threshold.'],
    problem: ['남은 공간이나 아이노드가 부족하면 로그·데이터베이스·임시 파일 쓰기가 실패하고 서비스가 중단될 수 있습니다.', 'Low free space or exhausted inodes can break log, database, and temporary-file writes and can stop services.'],
    symptoms: [
      ['파일 생성 실패, 데이터베이스 쓰기 오류 또는 로그 누락이 나타납니다.', 'File creation fails, database writes error, or logs go missing.'],
      ['바이트 또는 아이노드 사용률이 계속 증가하며 100%에 가까워집니다.', 'Byte or inode utilization keeps rising toward 100%.'],
    ],
    resolutions: [
      ['저장장치 상세에서 임계치를 넘은 마운트와 증가 추세를 확인합니다.', 'Identify the affected mount and its growth trend in storage details.'],
      ['불필요한 로그·캐시·백업의 보존 정책을 검토해 안전하게 정리합니다.', 'Review retention for unnecessary logs, caches, and backups and clean them safely.'],
      ['반복된다면 볼륨 확장 또는 데이터 이동을 계획합니다.', 'If growth recurs, plan a volume expansion or data migration.'],
    ],
  },
  'power-quality': {
    id: 'power-quality',
    page: 'power',
    priority: 3,
    title: ['전원 품질 또는 제한 감지', 'Power-quality or throttling condition'],
    summary: ['저전압·제한 플래그 또는 전원 이벤트가 감지되었습니다.', 'An undervoltage or throttle flag, or a power event, was detected.'],
    problem: ['권위 있는 플래그나 이벤트에 전원 불안정 또는 전원·온도 보호에 따른 성능 제한 증거가 있습니다.', 'Authoritative flags or events contain evidence of supply instability or power/thermal protection throttling.'],
    symptoms: [
      ['성능 저하, USB·저장장치 연결 불안정 또는 예기치 않은 재부팅이 나타날 수 있습니다.', 'Performance drops, USB or storage instability, or unexpected reboots may occur.'],
      ['throttle 플래그나 전원 이벤트가 기록되며, 전압 그래프는 당시 상황을 해석하는 보조 근거로 사용합니다.', 'Throttle flags or power events are recorded; the voltage chart is supporting context for that evidence.'],
    ],
    resolutions: [
      ['정격 전원 어댑터, 케이블, 커넥터와 전압 추세를 확인합니다.', 'Check the rated power supply, cable, connectors, and voltage trend.'],
      ['주변기기 전력 소비와 냉각 상태를 점검합니다.', 'Inspect peripheral power draw and cooling.'],
      ['조정 후 저전압·제한 이벤트가 다시 생기지 않는지 관찰합니다.', 'After remediation, watch for recurrence of undervoltage or throttling events.'],
    ],
  },
  connectivity: {
    id: 'connectivity',
    page: 'reliability',
    priority: 4,
    title: ['관리 연결 경로 확인 필요', 'Management connectivity needs review'],
    summary: ['주 네트워크 링크 또는 SSH 접속 경로가 정상으로 확인되지 않았습니다.', 'The primary network link or SSH management path is not confirmed healthy.'],
    problem: ['호스트가 네트워크에서 고립되거나 원격 복구 경로를 잃을 수 있습니다.', 'The host may be isolated from the network or lose its remote recovery path.'],
    symptoms: [
      ['원격 접속 실패, 패킷 손실 또는 서비스 연결 실패가 나타납니다.', 'Remote login fails, packets are lost, or service connections fail.'],
      ['신뢰성 화면에서 네트워크 또는 SSH 상태가 사용 불가이거나 미확인으로 표시됩니다.', 'Reliability details show the network or SSH path as unavailable or unknown.'],
    ],
    resolutions: [
      ['물리 링크, 주소·라우팅 설정과 주 인터페이스 상태를 확인합니다.', 'Check the physical link, addressing, routing, and primary interface state.'],
      ['SSH 수신 소켓과 방화벽 정책을 로컬 콘솔에서 확인합니다.', 'Verify the SSH listener and firewall policy from a local console.'],
      ['변경 전에는 다른 관리 경로를 확보해 원격 잠금을 방지합니다.', 'Keep an alternate management path before changes to avoid remote lockout.'],
    ],
  },
  'network-quality': {
    id: 'network-quality',
    page: 'network',
    priority: 5,
    title: ['네트워크 인터페이스 오류·드롭', 'Network interface errors or drops'],
    summary: ['루프백을 제외한 인터페이스에서 패킷 오류 또는 드롭 증가가 관측되었습니다.', 'Packet errors or drops increased on one or more non-loopback interfaces.'],
    problem: ['물리 링크·드라이버·큐 혼잡 때문에 패킷이 손상되거나 호스트에 도달하기 전에 버려지고 있을 수 있습니다.', 'A physical link, driver, or queue-congestion issue may be corrupting packets or discarding them before delivery.'],
    symptoms: [
      ['재전송, 응답 지연, 간헐적 연결 끊김 또는 처리량 저하가 나타날 수 있습니다.', 'Retransmits, latency, intermittent disconnects, or reduced throughput may follow.'],
      ['네트워크 상세에서 수신·송신 error/drop 초당 증가율이 0보다 크게 표시됩니다.', 'Network details show a positive receive or transmit error/drop rate.'],
    ],
    resolutions: [
      ['인터페이스별 오류·드롭 카운터와 링크 속도·duplex 상태를 비교합니다.', 'Compare per-interface error/drop counters with link speed and duplex state.'],
      ['케이블·스위치 포트·드라이버 로그와 큐 혼잡 여부를 확인합니다.', 'Inspect cabling, switch ports, driver logs, and queue congestion.'],
      ['원인을 조정한 뒤 증가율이 0으로 돌아오는지 다음 수집 구간에서 확인합니다.', 'After remediation, verify that rates return to zero in subsequent collection intervals.'],
    ],
  },
  'application-traffic': {
    id: 'application-traffic',
    page: 'network',
    priority: 6,
    title: ['최근 요청 오류·지연', 'Recent request errors or latency'],
    summary: ['직전 수집 구간의 익명 앱 집계에서 5xx 응답 또는 느린 요청이 관측되었습니다.', 'The latest anonymous app aggregate contains 5xx responses or slow requests.'],
    problem: ['서비스 내부 오류나 의존성 지연이 현재 요청 성공률과 응답시간에 영향을 주고 있을 수 있습니다.', 'Service errors or a slow dependency may be affecting current request success and latency.'],
    symptoms: [
      ['사용자 요청 실패, 게이트웨이 오류 또는 평소보다 긴 응답시간이 나타날 수 있습니다.', 'Requests may fail, return gateway errors, or take longer than normal.'],
      ['네트워크 상세의 최근 요청 구간에서 5xx·느린 요청·최대 응답시간이 증가합니다.', 'The latest request interval in network details shows elevated 5xx, slow requests, or maximum latency.'],
    ],
    resolutions: [
      ['영향 앱의 5xx·느린 요청 비율과 같은 시각의 서비스·자원 상태를 비교합니다.', 'Compare the affected app’s 5xx and slow-request ratios with service and resource state from the same interval.'],
      ['앱·프록시의 안전한 구조화 로그에서 오류 종류와 느린 의존성을 확인합니다.', 'Use safe structured app and proxy logs to identify error classes and slow dependencies.'],
      ['조정 후 다음 수집 구간에서 오류와 지연 집계가 정상으로 돌아오는지 확인합니다.', 'After remediation, confirm that errors and latency return to normal in the next collection interval.'],
    ],
  },
  'kernel-crash': {
    id: 'kernel-crash',
    page: 'reliability',
    priority: 1,
    title: ['커널 Oops 또는 패닉', 'Kernel oops or panic'],
    summary: ['커널이 치명적인 내부 오류를 보고했습니다.', 'The kernel reported a severe internal failure.'],
    problem: ['커널 코드나 드라이버가 복구하기 어려운 오류 상태에 들어갔습니다. 데이터 무결성과 호스트 안정성에 직접 영향을 줄 수 있습니다.', 'Kernel code or a driver entered a severe failure state that can directly affect data integrity and host stability.'],
    symptoms: [
      ['서비스 전체 정지, 갑작스러운 재부팅, 장치 사라짐 또는 Call Trace가 나타날 수 있습니다.', 'The host may freeze or reboot, devices may disappear, or a Call Trace may be emitted.'],
      ['같은 부팅에서 후속 드라이버·파일시스템 오류가 연이어 발생할 수 있습니다.', 'Driver or filesystem errors may follow during the same boot.'],
    ],
    resolutions: [
      ['사건 시각 전후의 커널 로그와 Call Trace를 보존합니다.', 'Preserve kernel logs and the Call Trace around the event.'],
      ['실행 중인 커널·드라이버·펌웨어를 지원되는 최신 조합으로 갱신합니다.', 'Update the running kernel, drivers, and firmware to a supported combination.'],
      ['반복되면 관련 장치·모듈을 분리해 재현하고 하드웨어 상태를 점검합니다.', 'If it recurs, isolate the related device or module and inspect the hardware.'],
    ],
  },
  'kernel-stall': {
    id: 'kernel-stall',
    page: 'reliability',
    priority: 2,
    title: ['실제 커널 정지 지연 기록', 'Recorded kernel stall'],
    summary: ['이번 부팅 중 RCU 또는 커널 작업이 정상 진행을 멈춘 증거가 기록됐습니다.', 'Evidence that RCU or a kernel task stopped making normal progress was recorded during this boot.'],
    problem: ['관측 당시 CPU 또는 커널 작업이 오래 양보하지 않아 RCU grace period나 다른 작업 진행을 막았습니다. 짧은 expedited 경고와 달리 실제 장애였지만, 누적 기록만으로 지금도 진행 중이라고 단정하지는 않습니다.', 'At the time observed, a CPU or kernel task failed to yield for an extended period and blocked RCU grace-period or task progress. Unlike a short expedited warning, it was a real fault, but the cumulative record does not prove it is still active.'],
    symptoms: [
      ['호스트 멈춤, 긴 응답 지연, soft/hard lockup 또는 hung task 경고가 함께 나타날 수 있습니다.', 'The host may freeze or exhibit long latency, soft/hard lockups, or hung-task warnings.'],
      ['커널 로그에 stall 지속시간, CPU 목록과 Call Trace가 기록됩니다.', 'Kernel logs include stall duration, affected CPUs, and a Call Trace.'],
    ],
    resolutions: [
      ['Call Trace와 영향을 받은 CPU·모듈을 기준으로 원인 드라이버나 작업을 식별합니다.', 'Use the Call Trace and affected CPU or module to identify the responsible driver or task.'],
      ['커널·펌웨어를 갱신하고 반복 시 의심 모듈을 안전하게 분리해 비교합니다.', 'Update kernel and firmware and, if recurring, safely isolate the suspected module.'],
      ['서비스 영향이 크면 로그를 먼저 보존한 뒤 안전한 유지보수 시간에 재부팅합니다.', 'If impact is severe, preserve logs and reboot during a safe maintenance window.'],
    ],
  },
  'rcu-expedited': {
    id: 'rcu-expedited',
    page: 'reliability',
    priority: 12,
    title: ['짧은 RCU expedited 지연', 'Short expedited RCU delay'],
    summary: ['빠른 RCU 대기 시간이 짧은 임계치를 넘었지만 실제 장기 stall은 아닙니다.', 'A fast RCU wait crossed its short timeout, but this is not an active long-duration stall.'],
    problem: ['동기 RCU 정리 작업이 설정된 expedited 대기 임계치보다 조금 늦게 끝났습니다. 반복 횟수는 성능 신호지만 이것만으로 커널 장애를 의미하지는 않습니다.', 'A synchronous RCU cleanup completed later than the configured expedited timeout. Repetition is a performance signal, but does not by itself indicate a kernel failure.'],
    symptoms: [
      ['대개 사용자가 느끼는 멈춤 없이 커널 로그에 짧은 지연 경고만 남습니다.', 'Usually only a short-delay kernel warning appears, with no user-visible freeze.'],
      ['컨테이너·네임스페이스 정리처럼 커널 동기화가 잦을 때 반복될 수 있습니다.', 'It can repeat during frequent kernel synchronization such as container or namespace cleanup.'],
    ],
    resolutions: [
      ['지연 시간과 빈도를 관찰하고 실제 RCU stall·lockup·hung task가 동반되는지 구분합니다.', 'Track duration and frequency and distinguish it from active RCU stalls, lockups, or hung tasks.'],
      ['커널과 관련 드라이버를 최신 지원 버전으로 유지합니다.', 'Keep the kernel and related drivers on a current supported version.'],
      ['임계치 조정 후에도 긴 지연이 반복되면 당시 부하와 커널 호출 경로를 추적합니다.', 'If long delays persist after timeout tuning, trace workload and kernel call paths at the event time.'],
    ],
  },
  'kernel-warning': {
    id: 'kernel-warning',
    page: 'reliability',
    priority: 11,
    title: ['커널 WARNING 기록', 'Kernel WARNING record'],
    summary: ['커널이 일반 WARNING 조건을 보고했거나 세부 종류가 없는 warning 집계가 남았습니다.', 'The kernel reported a general WARNING condition or a warning aggregate without a more specific retained kind.'],
    problem: ['커널 또는 드라이버가 비정상 조건을 감지했지만 축약된 기록만으로 원인을 확정할 수 없습니다.', 'The kernel or a driver detected an abnormal condition, but the reduced record alone cannot identify the cause.'],
    symptoms: [
      ['관련 장치 오류, 성능 저하 또는 경고 로그만 나타날 수 있습니다.', 'A device fault, degraded performance, or only a warning log may appear.'],
      ['같은 문구가 반복되면 특정 드라이버나 작업과 연관될 가능성이 높습니다.', 'Repeated identical messages are more likely to correlate with a driver or workload.'],
    ],
    resolutions: [
      ['관련 이벤트 로그에서 종류·시각·반복 패턴을 확인합니다.', 'Inspect the related event log for kind, time, and recurrence.'],
      ['같은 시각의 장치·서비스 상태와 커널 버전을 대조합니다.', 'Correlate device and service state and the kernel version at the same time.'],
      ['반복되거나 영향이 있으면 원문 커널 로그를 보존해 원인을 분석합니다.', 'If recurring or impactful, preserve the raw kernel log for diagnosis.'],
    ],
  },
  'memory-oom': {
    id: 'memory-oom',
    page: 'resources',
    priority: 3,
    title: ['메모리 부족 강제 종료', 'Out-of-memory termination'],
    summary: ['커널이 메모리를 확보하기 위해 작업을 강제 종료했습니다.', 'The kernel forcibly terminated a task to reclaim memory.'],
    problem: ['사용 가능한 메모리와 회수 가능한 캐시가 부족해 OOM killer가 실행되었습니다.', 'Available memory and reclaimable cache were exhausted, causing the OOM killer to run.'],
    symptoms: [
      ['서비스가 갑자기 종료되거나 재시작되고 요청이 실패할 수 있습니다.', 'A service may stop or restart abruptly and requests may fail.'],
      ['사건 직전 메모리 사용률과 PSI가 크게 상승할 수 있습니다.', 'Memory utilization and PSI may rise sharply before the event.'],
    ],
    resolutions: [
      ['사건 분석에서 당시 메모리 상위 프로세스와 PSI를 확인합니다.', 'Inspect top memory consumers and PSI in incident analysis.'],
      ['메모리 누수·무제한 캐시를 수정하고 워크로드 제한을 설정합니다.', 'Fix leaks or unbounded caches and set workload limits.'],
      ['정상 부하에도 반복되면 메모리 또는 swap 용량 계획을 검토합니다.', 'If it recurs under normal load, review memory or swap capacity.'],
    ],
  },
  'storage-integrity': {
    id: 'storage-integrity',
    page: 'storage',
    priority: 1,
    title: ['저장장치 무결성 오류', 'Storage integrity fault'],
    summary: ['파일시스템 또는 NVMe 입출력·재설정 오류가 기록되었습니다.', 'A filesystem or NVMe I/O or reset error was recorded.'],
    problem: ['저장 계층이 요청을 정상 처리하지 못했습니다. 반복되면 데이터 손상이나 서비스 중단으로 이어질 수 있습니다.', 'The storage stack failed to process an operation normally. Recurrence can lead to data corruption or service outages.'],
    symptoms: [
      ['읽기·쓰기 실패, 파일시스템 read-only 전환, I/O 멈춤 또는 NVMe 재설정이 나타날 수 있습니다.', 'Reads or writes may fail, filesystems may become read-only, I/O may stall, or NVMe may reset.'],
      ['서비스 오류와 높은 I/O 대기가 같은 시각에 나타날 수 있습니다.', 'Service errors and high I/O wait may coincide.'],
    ],
    resolutions: [
      ['중요 데이터의 최신 백업 상태를 먼저 확인합니다.', 'Verify current backups of important data first.'],
      ['SMART/NVMe 상태, 파일시스템 로그, PCIe 오류와 전원 품질을 함께 점검합니다.', 'Inspect SMART/NVMe health, filesystem logs, PCIe errors, and power quality together.'],
      ['오류가 반복되면 안전한 점검 창에서 파일시스템 검사와 장치 교체를 검토합니다.', 'If errors recur, schedule filesystem checks and consider device replacement.'],
    ],
  },
  'pcie-integrity': {
    id: 'pcie-integrity',
    page: 'reliability',
    priority: 4,
    title: ['PCIe 링크 오류 또는 성능 저하', 'PCIe link error or downgrade'],
    summary: ['PCIe AER 오류나 설정 세대보다 낮은 링크 협상이 감지되었습니다.', 'PCIe AER errors or a link negotiated below its configured generation were detected.'],
    problem: ['관측 당시 호스트와 장치 사이에 오류 증거가 있었거나 링크가 기대한 속도로 협상되지 않았습니다.', 'The observation contains link-error evidence or shows that the host-device link did not negotiate at the configured speed.'],
    symptoms: [
      ['NVMe 재설정, I/O 오류, 처리량 저하 또는 AER 반복 기록이 나타날 수 있습니다.', 'NVMe resets, I/O errors, reduced throughput, or repeated AER records may occur.'],
      ['교정 가능 오류만 있으면 동작은 계속되지만 반복 여부를 관찰해야 합니다.', 'With correctable-only errors, operation continues but recurrence should be monitored.'],
    ],
    resolutions: [
      ['설정 세대와 실제 협상 세대·레인 폭을 비교합니다.', 'Compare configured and negotiated generation and lane width.'],
      ['케이블·어댑터·장착 상태와 전원 안정성을 확인합니다.', 'Check cables, adapters, seating, and power stability.'],
      ['펌웨어·커널 갱신 후에도 비치명·치명 오류가 반복되면 링크 속도 완화나 장치 교체를 검토합니다.', 'If non-fatal or fatal errors recur after firmware and kernel updates, consider link-speed mitigation or device replacement.'],
    ],
  },
  'nvme-mitigation': {
    id: 'nvme-mitigation',
    page: 'reliability',
    priority: 13,
    title: ['NVMe 보호 설정 확인 필요', 'NVMe mitigation needs review'],
    summary: ['이 호스트에 기대되는 NVMe 안정성 완화 설정이 미적용이거나 현재 확인되지 않습니다.', 'The NVMe stability mitigation expected on this host is inactive or could not be confirmed.'],
    problem: ['NVMe 전원 절약이나 PCIe 링크 전원 관리가 특정 하드웨어 조합에서 재설정·I/O 오류를 유발할 수 있습니다.', 'NVMe or PCIe link power saving can trigger resets or I/O errors on some hardware combinations.'],
    symptoms: [
      ['유휴 후 저장장치가 늦게 응답하거나 NVMe reset이 반복될 수 있습니다.', 'Storage may respond slowly after idle or report repeated NVMe resets.'],
      ['신뢰성 화면의 NVMe 보호 상태가 미적용 또는 미확인으로 표시됩니다.', 'Reliability details report the NVMe mitigation as inactive or unknown.'],
    ],
    resolutions: [
      ['현재 하드웨어에 필요한 ASPM/APST 완화 정책을 확인합니다.', 'Confirm the ASPM/APST mitigation required for the hardware.'],
      ['부팅 설정 변경은 영향 범위를 검토하고 유지보수 시간에 적용합니다.', 'Review impact and apply boot-setting changes during a maintenance window.'],
      ['적용 후 실제 PCIe·NVMe 상태와 재발 여부를 확인합니다.', 'After applying it, verify live PCIe/NVMe state and recurrence.'],
    ],
  },
  'reboot-required': {
    id: 'reboot-required',
    page: 'maintenance',
    priority: 14,
    title: ['새 커널 적용 대기', 'New kernel awaiting reboot'],
    summary: ['더 최신 커널이 설치됐지만 아직 실행 중이지 않습니다.', 'A newer kernel is installed but is not running yet.'],
    problem: ['업데이트 파일은 준비됐지만 재부팅 전까지 기존 커널과 드라이버가 계속 사용됩니다.', 'The update is staged, but the existing kernel and drivers remain active until reboot.'],
    symptoms: [
      ['실행 중 커널과 최신 설치 커널 버전이 다르게 표시됩니다.', 'The running and latest installed kernel versions differ.'],
      ['수정된 드라이버 문제나 보안 패치가 아직 효력을 내지 않습니다.', 'Driver fixes or security patches are not yet effective.'],
    ],
    resolutions: [
      ['중요 서비스와 원격 접속 경로의 재시작 영향을 확인합니다.', 'Review restart impact for critical services and remote access.'],
      ['안전한 유지보수 시간에 재부팅하고 새 커널 부팅을 확인합니다.', 'Reboot during a safe maintenance window and verify the new kernel.'],
      ['재부팅 후 서비스·네트워크·저장장치 회귀 검사를 수행합니다.', 'After reboot, run service, network, and storage regression checks.'],
    ],
  },
  'linux-reliability': {
    id: 'linux-reliability',
    page: 'reliability',
    priority: 2,
    title: ['Linux 신뢰성 상태 확인', 'Linux reliability needs review'],
    summary: ['시계·재부팅·systemd 관측 중 현재 확인할 근거가 있습니다.', 'Clock, reboot, or systemd evidence needs current review.'],
    problem: ['시간 동기화 실패, 예상 밖 재부팅 또는 중요 systemd unit 장애는 수집과 서비스 판단을 왜곡하거나 실제 중단을 나타낼 수 있습니다.', 'Time synchronization failure, an unexpected reboot, or an important systemd unit fault can invalidate observations or indicate a real outage.'],
    symptoms: [
      ['인증서·로그 시각이 어긋나거나 허용 목록 서비스가 inactive/failed로 표시됩니다.', 'Certificate and log timestamps can disagree, or an allow-listed service can appear inactive or failed.'],
      ['표본 사이 부팅 ID가 바뀌거나 unit 재시작 횟수가 증가합니다.', 'The boot identity changes between samples or unit restart counts rise.'],
    ],
    resolutions: [
      ['NTP 연결과 시간 동기화 서비스 상태를 먼저 확인합니다.', 'Check NTP connectivity and the time synchronization service first.'],
      ['재부팅 시각의 전원·커널·저장장치 사건과 유지보수 기록을 대조합니다.', 'Correlate the reboot time with power, kernel, storage, and maintenance records.'],
      ['실패한 unit의 상태·결과·재시작 근거를 확인한 뒤 안전한 복구 절차를 따릅니다.', 'Inspect failed-unit state, result, and restart evidence before following its safe recovery procedure.'],
    ],
  },
  'container-security': {
    id: 'container-security',
    page: 'containers',
    priority: 1,
    title: ['컨테이너 권한 노출 확인', 'Container privilege exposure needs review'],
    summary: ['호스트 또는 Docker 제어면에 과도하게 접근할 수 있는 컨테이너가 있습니다.', 'A container has elevated access to the host or Docker control plane.'],
    problem: ['privileged 모드, Docker 소켓, 민감 bind 또는 고위험 capability는 컨테이너 침해가 호스트 침해로 확대될 가능성을 높입니다.', 'Privileged mode, Docker socket access, sensitive binds, or dangerous capabilities increase the chance that a container compromise reaches the host.'],
    symptoms: [
      ['보안 요약에 privileged, Docker socket, host namespace 또는 capability 노출이 표시됩니다.', 'The security summary reports privileged mode, Docker socket access, host namespaces, or capability exposure.'],
      ['컨테이너 내부 작업이 호스트 프로세스·네트워크·Docker 객체에 영향을 줄 수 있습니다.', 'Activity inside the container may affect host processes, networking, or Docker objects.'],
    ],
    resolutions: [
      ['해당 권한이 실제로 필요한지 확인하고 최소 capability·읽기 전용 경로로 축소합니다.', 'Confirm the access is required, then reduce it to minimal capabilities and read-only paths.'],
      ['Docker 소켓 mount는 제거하거나 허용 작업이 고정된 감사 가능한 broker로 교체합니다.', 'Remove Docker socket mounts or replace them with an audited broker exposing fixed operations.'],
      ['변경 뒤 서비스 기능과 권한 축소가 함께 유지되는지 확인합니다.', 'After the change, verify both service function and the reduced privilege set remain stable.'],
    ],
  },
  'docker-event-coverage': {
    id: 'docker-event-coverage',
    page: 'containers',
    priority: 2,
    title: ['Docker 이벤트 범위 확인', 'Docker event coverage needs review'],
    summary: ['Docker 이벤트 스트림이 끊겼거나 보존 이력에 누락 가능성이 있습니다.', 'The Docker event stream is unavailable or retained history may contain a gap.'],
    problem: ['이벤트 범위가 불완전하면 재시작·OOM·health 상태 변화의 순서와 원인을 잘못 판단할 수 있습니다.', 'Incomplete event coverage can obscure the order and cause of restarts, OOM events, and health changes.'],
    symptoms: [
      ['이벤트 상태가 gap, unavailable 또는 permission-denied로 표시됩니다.', 'Event status reports gap, unavailable, or permission-denied.'],
      ['현재 컨테이너 상태는 다시 맞춰졌지만 일부 상태 전이 기록이 없을 수 있습니다.', 'Current container state may be reconciled while some transition records remain missing.'],
    ],
    resolutions: [
      ['Docker daemon과 제한된 소켓 접근 권한, 이벤트 커서와 재연결 상태를 확인합니다.', 'Check the Docker daemon, restricted socket permissions, event cursor, and reconnect state.'],
      ['다음 수집에서 fresh 상태와 증가하는 관측 시각을 확인합니다.', 'Verify a fresh state and advancing observation time on the next collection.'],
      ['gap 구간은 현재 상태와 보존 로그를 함께 사용해 해석합니다.', 'Interpret a gap interval with both current state and retained logs.'],
    ],
  },
  'synthetic-availability': {
    id: 'synthetic-availability',
    page: 'network',
    priority: 2,
    title: ['외부 엔드포인트 확인 필요', 'Endpoint probes need review'],
    summary: ['HTTP·TLS 검사 실패, 높은 지연 또는 인증서 만료 위험이 관측되었습니다.', 'HTTP/TLS failure, high latency, or certificate-expiry risk was observed.'],
    problem: ['합성 검사가 실패하거나 오래되면 실제 사용자 경로의 DNS·연결·TLS·HTTP 상태를 현재 증거로 확인할 수 없습니다.', 'A failed or stale synthetic check leaves the user-facing DNS, connection, TLS, or HTTP path without current evidence.'],
    symptoms: [
      ['DNS·timeout·TLS·HTTP 상태가 실패로 표시되거나 응답 지연이 지속됩니다.', 'DNS, timeout, TLS, or HTTP status reports failure, or probe latency remains elevated.'],
      ['인증서 남은 기간이 경고 구간에 들어가거나 검사 결과가 갱신되지 않습니다.', 'Certificate lifetime enters the warning window or probe results stop advancing.'],
    ],
    resolutions: [
      ['검사 ID의 DNS, 공개 연결 경로, TLS 체인·SNI와 예상 HTTP 상태를 순서대로 확인합니다.', 'Check the probe ID’s DNS, public connection path, TLS chain/SNI, and expected HTTP status in order.'],
      ['검사 수집 권한과 timer 상태를 확인하되 비밀 URL이나 인증정보를 화면·로그에 복사하지 않습니다.', 'Check probe collection permissions and timer state without copying secret URLs or credentials into the UI or logs.'],
      ['원인을 해소한 뒤 fresh·ok 결과와 증가하는 관측 시각을 확인합니다.', 'After remediation, verify a fresh, successful result and advancing observation time.'],
    ],
  },
  'active-incident': {
    id: 'active-incident',
    page: 'incidents',
    priority: 6,
    title: ['미종료 임계치 사건', 'Unresolved threshold incident'],
    summary: ['자원·전원·입출력 또는 트래픽 임계치를 넘은 사건이 ACTIVE 기록으로 남아 있습니다.', 'An incident crossing a resource, power, I/O, or traffic threshold remains recorded as ACTIVE.'],
    problem: ['최근 관측이면 호스트가 아직 임계치를 넘는 중일 수 있습니다. 오래된 기록이면 복구 관측이 누락됐거나 사건 종료 처리가 필요할 수 있습니다.', 'A recent observation can mean the host is still over threshold. An older record can indicate a missed recovery observation or incomplete incident closure.'],
    symptoms: [
      ['높은 지연, 오류율 증가, 온도 상승 또는 서비스 불안정이 나타날 수 있습니다.', 'High latency, increased error rates, rising temperature, or service instability may occur.'],
      ['사건 카드가 ACTIVE 상태로 유지되고 PSI·프로세스 증거가 기록됩니다.', 'The incident card remains ACTIVE and records PSI and process evidence.'],
    ],
    resolutions: [
      ['사건 상세에서 원인 지표와 당시 프로세스·서비스·요청 증거를 확인합니다.', 'Inspect causal metrics and captured process, service, and request evidence.'],
      ['영향이 큰 원인 워크로드를 제한하거나 안전하게 우회합니다.', 'Limit or safely divert the highest-impact workload.'],
      ['오래된 ACTIVE 기록이면 최신 수집 상태를 확인하고 사건이 RECOVERED로 닫히는지 점검합니다.', 'For an older ACTIVE record, verify fresh collection and confirm the incident closes as RECOVERED.'],
    ],
  },
};

function numericCount(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.max(0, value) : 0;
}

function latestTimestamp(values: Array<string | null | undefined>): string | null {
  let latest: { value: string; time: number } | null = null;
  for (const value of values) {
    if (!value) continue;
    const time = new Date(value).getTime();
    if (!Number.isFinite(time)) continue;
    if (!latest || time > latest.time) latest = { value, time };
  }
  return latest?.value ?? null;
}

function definition(id: OperationalFindingId): OperationalFindingDefinition {
  return DEFINITIONS[id];
}

function finding(
  id: OperationalFindingId,
  level: OperationalFindingLevel,
  scope: OperationalFindingScope,
  evidence: LocalizedText,
  count: number | null = null,
  lastObservedAt: string | null = null,
): OperationalFinding {
  return { ...definition(id), level, scope, evidence, count, lastObservedAt };
}

function percent(value: number): string {
  return `${value.toFixed(value >= 10 ? 0 : 1)}%`;
}

interface FindingSignal {
  key: string;
  level: OperationalFindingLevel;
  ko: string;
  en: string;
  entityKey?: string;
}

interface LinuxFindingSignals {
  resource: FindingSignal[];
  network: FindingSignal[];
  storage: FindingSignal[];
  reliability: FindingSignal[];
  power: FindingSignal[];
  observedAt: string | null;
}

function strongerLevel(left: OperationalFindingLevel | null, right: OperationalFindingLevel): OperationalFindingLevel {
  return left === 'danger' || right === 'danger' ? 'danger' : 'caution';
}

function signalLevel(signals: readonly FindingSignal[]): OperationalFindingLevel | null {
  return signals.reduce<OperationalFindingLevel | null>((level, signal) => strongerLevel(level, signal.level), null);
}

function uniqueSignals(signals: readonly FindingSignal[]): FindingSignal[] {
  const seen = new Set<string>();
  return signals.filter((signal) => {
    if (seen.has(signal.key)) return false;
    seen.add(signal.key);
    return true;
  });
}

function boundedSignalEvidence(signals: readonly FindingSignal[], maximum = 3): LocalizedText {
  const ordered = [...signals].sort((left, right) => (
    (left.level === right.level ? 0 : left.level === 'danger' ? -1 : 1)
    || left.key.localeCompare(right.key)
  ));
  const shown = ordered.slice(0, maximum);
  const hidden = Math.max(0, ordered.length - shown.length);
  return [
    `${shown.map((signal) => signal.ko).join(' · ')}${hidden ? ` · 그 외 ${hidden.toLocaleString()}건` : ''}`,
    `${shown.map((signal) => signal.en).join(' · ')}${hidden ? ` · ${hidden.toLocaleString()} more` : ''}`,
  ];
}

function collectionLevel(status: LinuxCollectionStatus | string | null | undefined): OperationalFindingLevel | null {
  if (status === 'permission_error' || status === 'invalid' || status === 'collection_error') return 'danger';
  if (status === 'partial' || status === 'unavailable') return 'caution';
  return null;
}

function collectionSignal(key: string, labelKo: string, labelEn: string, status: LinuxCollectionStatus | string | null | undefined): FindingSignal | null {
  const level = collectionLevel(status);
  return level ? { key, level, ko: `${labelKo} ${status}`, en: `${labelEn} ${status}` } : null;
}

function addCapacitySignal(
  signals: FindingSignal[],
  key: string,
  labelKo: string,
  labelEn: string,
  usedPercent: number | null | undefined,
) {
  if (typeof usedPercent !== 'number' || !Number.isFinite(usedPercent) || usedPercent < 80) return;
  signals.push({
    key,
    level: usedPercent >= 90 ? 'danger' : 'caution',
    ko: `${labelKo} ${percent(usedPercent)}`,
    en: `${labelEn} ${percent(usedPercent)}`,
  });
}

function projectedLinuxSignals(data: DashboardPayload): LinuxFindingSignals {
  const result: LinuxFindingSignals = {
    resource: [], network: [], storage: [], reliability: [], power: [], observedAt: null,
  };
  const linux = data.linux;
  // Old unsupported payloads intentionally contained only `status`.
  if (!linux || linux.schemaVersion !== 1) {
    const topLevelStatus = collectionSignal('reliability:linux-status', 'Linux 진단', 'Linux diagnostics', linux?.status);
    if (topLevelStatus) result.reliability.push(topLevelStatus);
    result.observedAt = linux?.collectedAt ?? data.latestObservedAt;
    return result;
  }
  result.observedAt = linux.collectedAt ?? data.latestObservedAt;

  const resourceStatus = collectionSignal('resource:status', '자원 수집', 'resource collection', linux.resources.status);
  if (resourceStatus) result.resource.push(resourceStatus);
  addCapacitySignal(result.resource, 'resource:pid', 'PID', 'PID', linux.resources.pid.usedPercent);
  addCapacitySignal(result.resource, 'resource:fds', '파일 디스크립터', 'file descriptors', linux.resources.systemFileDescriptors.usedPercent);
  addCapacitySignal(result.resource, 'resource:cgroup-pids', 'cgroup PID', 'cgroup PIDs', linux.resources.cgroupPids.usedPercent);
  if ((linux.resources.zombieCount ?? 0) >= 10) result.resource.push({
    key: 'resource:zombies', level: 'caution',
    ko: `좀비 ${linux.resources.zombieCount!.toLocaleString()}개`,
    en: `${linux.resources.zombieCount!.toLocaleString()} zombies`,
  });
  if (linux.resources.scanTruncated || linux.resources.deadlineReached) result.resource.push({
    key: 'resource:bounded-scan', level: 'caution',
    ko: '프로세스 스캔 범위 제한', en: 'process scan was bounded',
  });

  const networkStatus = collectionSignal('network:status', '네트워크 수집', 'network collection', linux.network.status);
  const tcpStatus = collectionSignal('network:tcp-status', 'TCP 수집', 'TCP collection', linux.network.tcp.status);
  const socketStatus = collectionSignal('network:socket-status', '소켓 스캔', 'socket scan', linux.network.tcp.socketScanStatus);
  if (networkStatus) result.network.push(networkStatus);
  if (tcpStatus) result.network.push(tcpStatus);
  if (socketStatus) result.network.push(socketStatus);
  const retransmission = linux.network.tcp.retransmissionPercent;
  if (typeof retransmission === 'number' && Number.isFinite(retransmission) && retransmission >= 1) result.network.push({
    key: 'network:tcp-retransmission', level: retransmission >= 5 ? 'danger' : 'caution',
    ko: `TCP 재전송 ${percent(retransmission)}`, en: `TCP retransmission ${percent(retransmission)}`,
  });
  addCapacitySignal(result.network, 'network:conntrack', 'conntrack', 'conntrack', linux.network.tcp.conntrack.usedPercent);
  addCapacitySignal(result.network, 'network:ephemeral', '임시 포트', 'ephemeral ports', linux.network.tcp.ephemeralPorts.usedPercent);
  if (linux.network.tcp.socketScanTruncated) result.network.push({
    key: 'network:socket-truncated', level: 'caution',
    ko: '소켓 스캔 상한 도달', en: 'socket scan limit reached',
  });

  const storageStatus = collectionSignal('storage:status', '저장장치 수집', 'storage collection', linux.storage.status);
  if (storageStatus) result.storage.push(storageStatus);
  if (linux.storage.truncated) result.storage.push({ key: 'storage:truncated', level: 'caution', ko: '장치 목록 축약', en: 'device list truncated' });
  for (const device of linux.storage.devices) {
    const deviceName = device.name.slice(0, 64) || 'device';
    const degraded = device.raidDegradedDevices ?? 0;
    if (degraded > 0) result.storage.push({
      key: `storage:${deviceName}:raid`, level: 'danger',
      ko: `${deviceName} RAID degraded ${degraded.toLocaleString()}`,
      en: `${deviceName} RAID degraded ${degraded.toLocaleString()}`,
    });
    const latency = device.averageLatencyMilliseconds;
    if (typeof latency === 'number' && Number.isFinite(latency) && latency >= 20) result.storage.push({
      key: `storage:${deviceName}:latency`, level: latency >= 100 ? 'danger' : 'caution',
      ko: `${deviceName} 지연 ${latency.toFixed(1)}ms`, en: `${deviceName} latency ${latency.toFixed(1)}ms`,
    });
    const utilization = device.utilizationPercent;
    if (typeof utilization === 'number' && Number.isFinite(utilization) && utilization >= 80) result.storage.push({
      key: `storage:${deviceName}:utilization`, level: utilization >= 95 ? 'danger' : 'caution',
      ko: `${deviceName} 사용률 ${percent(utilization)}`, en: `${deviceName} utilization ${percent(utilization)}`,
    });
    for (const [suffix, labelKo, labelEn, status] of [
      ['smart', 'SMART 수집', 'SMART collection', device.smartStatus],
      ['raid-status', 'RAID 수집', 'RAID collection', device.raidStatus],
    ] as const) {
      const signal = collectionSignal(`storage:${deviceName}:${suffix}`, `${deviceName} ${labelKo}`, `${deviceName} ${labelEn}`, status);
      if (signal) result.storage.push(signal);
    }
  }

  const reliabilityStatus = collectionSignal('reliability:status', '신뢰성 수집', 'reliability collection', linux.reliability.status);
  const clockStatus = collectionSignal('reliability:clock', '시계 수집', 'clock collection', linux.reliability.clock.status);
  const timeStatus = collectionSignal('reliability:time-sync', '시간 동기화 수집', 'time synchronization collection', linux.reliability.clock.timeSync.status);
  const systemdStatus = collectionSignal('reliability:systemd', 'systemd 수집', 'systemd collection', linux.reliability.systemd.status);
  for (const signal of [reliabilityStatus, clockStatus, timeStatus, systemdStatus]) if (signal) result.reliability.push(signal);
  if (linux.reliability.clock.timeSync.synchronized === false) result.reliability.push({
    key: 'reliability:not-synchronized', level: 'danger', ko: '시간 동기화 실패', en: 'time not synchronized',
  });
  const drift = Math.abs(linux.reliability.clock.timeSync.clockDriftMilliseconds ?? 0);
  if (drift >= 15_000) result.reliability.push({
    key: 'reliability:clock-drift', level: drift >= 60_000 ? 'danger' : 'caution',
    ko: `시계 차이 ${Math.round(drift).toLocaleString()}ms`, en: `clock drift ${Math.round(drift).toLocaleString()}ms`,
  });
  if (linux.reliability.clock.unexpectedReboot === true) result.reliability.push({
    key: 'reliability:unexpected-reboot', level: 'danger', ko: '예상 밖 재부팅', en: 'unexpected reboot',
  });
  if (linux.reliability.clock.rebootDetectedSincePreviousSample === true) result.reliability.push({
    key: 'reliability:reboot-detected', level: 'caution', ko: '표본 사이 재부팅', en: 'reboot between samples',
  });
  if (linux.reliability.systemd.truncated) result.reliability.push({
    key: 'reliability:systemd-truncated', level: 'caution', ko: 'systemd unit 목록 축약', en: 'systemd unit list truncated',
  });
  for (const unit of linux.reliability.systemd.units) {
    const unitName = unit.unit.slice(0, 96) || 'unit';
    if (unit.activeState !== 'active' || !['success', 'unknown'].includes(unit.result)) result.reliability.push({
      key: `reliability:unit:${unitName}:state`, level: 'danger',
      ko: `${unitName} ${unit.activeState}/${unit.result}`, en: `${unitName} ${unit.activeState}/${unit.result}`,
    });
    else if ((unit.restartCount ?? 0) > 0) result.reliability.push({
      key: `reliability:unit:${unitName}:restarts`, level: 'caution',
      ko: `${unitName} 재시작 ${unit.restartCount!.toLocaleString()}회`, en: `${unitName} ${unit.restartCount!.toLocaleString()} restarts`,
    });
  }

  const powerStatus = collectionSignal('power:status', '열·전원 수집', 'thermal and power collection', linux.power.status);
  if (powerStatus) result.power.push(powerStatus);
  if (linux.power.truncated) result.power.push({ key: 'power:truncated', level: 'caution', ko: '열원 목록 축약', en: 'thermal source list truncated' });
  for (const sensor of linux.power.sensors) {
    const signal = collectionSignal(`power:sensor:${sensor.name}`, `${sensor.name.slice(0, 64)} 센서`, `${sensor.name.slice(0, 64)} sensor`, sensor.status);
    if (signal) result.power.push(signal);
  }
  for (const fan of linux.power.fans) {
    const signal = collectionSignal(`power:fan:${fan.name}`, `${fan.name.slice(0, 64)} 팬`, `${fan.name.slice(0, 64)} fan`, fan.status);
    if (signal) result.power.push(signal);
  }
  const maximumTemperature = linux.power.maximumTemperatureCelsius;
  if (typeof maximumTemperature === 'number' && Number.isFinite(maximumTemperature) && maximumTemperature >= 80) result.power.push({
    key: 'power:temperature', level: maximumTemperature >= 85 ? 'danger' : 'caution',
    ko: `최고 온도 ${maximumTemperature.toFixed(1)}°C`, en: `maximum temperature ${maximumTemperature.toFixed(1)}°C`,
  });
  const rpi = linux.power.raspberryPi;
  for (const [key, ko, en, active] of [
    ['undervoltage', '현재 저전압', 'current undervoltage', rpi.currentUnderVoltage],
    ['frequency-cap', '현재 주파수 제한', 'current frequency cap', rpi.currentFrequencyCapped],
    ['throttled', '현재 스로틀링', 'current throttling', rpi.currentThrottled],
    ['soft-temperature', '현재 온도 제한', 'current soft-temperature limit', rpi.currentSoftTemperatureLimit],
  ] as const) {
    if (active === true) result.power.push({ key: `power:rpi:${key}`, level: 'danger', ko, en });
  }

  result.resource = uniqueSignals(result.resource);
  result.network = uniqueSignals(result.network);
  result.storage = uniqueSignals(result.storage);
  result.reliability = uniqueSignals(result.reliability);
  result.power = uniqueSignals(result.power);
  return result;
}

function containerIdentity(container: ContainerStatus, index: number): string {
  return container.instanceId ?? `${container.project ?? ''}\u0000${container.name}\u0000${index}`;
}

function containerLabel(container: ContainerStatus): string {
  const name = container.name.slice(0, 80) || 'container';
  return container.project ? `${container.project.slice(0, 64)}/${name}` : name;
}

function projectedContainerRuntimeSignals(data: DashboardPayload): FindingSignal[] {
  const signals: FindingSignal[] = [];
  for (const [index, container] of data.containers.entries()) {
    const entityKey = containerIdentity(container, index);
    const label = containerLabel(container);
    const add = (key: string, level: OperationalFindingLevel, ko: string, en: string) => signals.push({ key: `${entityKey}:${key}`, entityKey, level, ko: `${label} ${ko}`, en: `${label} ${en}` });
    if (container.oomKilled === true) add('oom', 'danger', 'OOM 종료', 'OOM killed');
    const restartDelta = container.restartCountDelta;
    if (typeof restartDelta === 'number' && Number.isFinite(restartDelta) && restartDelta > 0) add(
      'restarts', restartDelta >= 3 ? 'danger' : 'caution',
      `재시작 +${Math.round(restartDelta).toLocaleString()}`,
      `restarts +${Math.round(restartDelta).toLocaleString()}`,
    );
    const throttled = container.cpuThrottledPercent;
    if (typeof throttled === 'number' && Number.isFinite(throttled) && throttled >= 20) add(
      'cpu-throttled', throttled >= 50 ? 'danger' : 'caution',
      `CPU 제한 ${percent(throttled)}`, `CPU throttled ${percent(throttled)}`,
    );
    const memoryRatio = typeof container.memoryBytes === 'number' && typeof container.memoryLimitBytes === 'number' && container.memoryLimitBytes > 0
      ? (container.memoryBytes / container.memoryLimitBytes) * 100 : null;
    if (memoryRatio !== null && Number.isFinite(memoryRatio) && memoryRatio >= 80) add(
      'memory-limit', memoryRatio >= 90 ? 'danger' : 'caution',
      `메모리 한도 ${percent(memoryRatio)}`, `memory limit ${percent(memoryRatio)}`,
    );
    const pidRatio = typeof container.pidCount === 'number' && typeof container.pidLimit === 'number' && container.pidLimit > 0
      ? (container.pidCount / container.pidLimit) * 100 : null;
    if (pidRatio !== null && Number.isFinite(pidRatio) && pidRatio >= 80) add(
      'pid-limit', pidRatio >= 90 ? 'danger' : 'caution',
      `PID 한도 ${percent(pidRatio)}`, `PID limit ${percent(pidRatio)}`,
    );
    const networkErrors = container.networkErrorsPerSecond;
    if (typeof networkErrors === 'number' && Number.isFinite(networkErrors) && networkErrors >= NETWORK_FAULT_RATE_THRESHOLDS.caution) add(
      'network-errors', networkErrors >= NETWORK_FAULT_RATE_THRESHOLDS.danger ? 'danger' : 'caution',
      `네트워크 오류 ${networkErrors.toFixed(networkErrors >= 1 ? 1 : 3)}/s`,
      `network errors ${networkErrors.toFixed(networkErrors >= 1 ? 1 : 3)}/s`,
    );
    if (container.imageDigestDrift === true) add('digest-drift', 'caution', '이미지 digest 혼재', 'image digest drift');
    if (container.imageDigestChanged === true) add('digest-changed', 'caution', '이미지 digest 변경', 'image digest changed');
  }
  return uniqueSignals(signals);
}

function projectedContainerSecuritySignals(data: DashboardPayload): FindingSignal[] {
  const signals: FindingSignal[] = [];
  for (const [index, container] of data.containers.entries()) {
    const entityKey = containerIdentity(container, index);
    const label = containerLabel(container);
    const add = (key: string, level: OperationalFindingLevel, ko: string, en: string) => signals.push({ key: `${entityKey}:${key}`, entityKey, level, ko: `${label} ${ko}`, en: `${label} ${en}` });
    if (container.privileged === true) add('privileged', 'danger', 'privileged', 'privileged');
    if (container.dockerSocketMounted === true) add('docker-socket', 'danger', 'Docker 소켓', 'Docker socket');
    if (container.sensitiveBindMounted === true) add('sensitive-bind', 'danger', '민감 bind', 'sensitive bind');
    if ((container.dangerousCapabilityCount ?? 0) > 0) add('dangerous-capabilities', 'danger', '고위험 capability', 'dangerous capabilities');
    if (container.hostPid === true) add('host-pid', 'caution', 'host PID', 'host PID');
    if (container.hostIpc === true) add('host-ipc', 'caution', 'host IPC', 'host IPC');
    if (container.hostNetwork === true) add('host-network', 'caution', 'host network', 'host network');
    if (container.excessiveCapabilities === true && !(container.dangerousCapabilityCount ?? 0)) add('excessive-capabilities', 'caution', '과도한 capability', 'excessive capabilities');
  }
  return uniqueSignals(signals);
}

const RULE_SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 } as const;

function orderedActiveRules(states: readonly RuleEvaluationState[]): RuleEvaluationState[] {
  return [...states].sort((left, right) => (
    (left.phase === right.phase ? 0 : left.phase === 'firing' ? -1 : 1)
    || RULE_SEVERITY_ORDER[left.severity] - RULE_SEVERITY_ORDER[right.severity]
    || left.ruleId.localeCompare(right.ruleId)
    || left.target.localeCompare(right.target)
  ));
}

function ruleEvidence(states: readonly RuleEvaluationState[], locale: 'ko' | 'en'): string {
  const shown = orderedActiveRules(states).slice(0, 2).map((state) => {
    const value = typeof state.lastValue === 'number' && Number.isFinite(state.lastValue) ? `=${state.lastValue}` : '';
    return `${state.ruleId} (${state.target}${value})`;
  });
  const hidden = Math.max(0, states.length - shown.length);
  return `${shown.join(', ')}${hidden ? locale === 'ko' ? ` 외 ${hidden.toLocaleString()}개` : ` +${hidden.toLocaleString()} more` : ''}`;
}

function uniqueReliabilityEvents(data: DashboardPayload, kind: string, status?: string) {
  const seen = new Set<string>();
  return data.reliabilityEvents.filter((event) => {
    if (event.kind !== kind || (status && event.status.toLowerCase() !== status)) return false;
    const key = `${event.timestamp}\u0000${event.kind}\u0000${event.status}\u0000${event.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const SCOPE_ORDER: Record<OperationalFindingScope, number> = { current: 0, boot: 1, 'last-known': 2, range: 3 };

export type OperationalServiceState = 'danger' | 'caution' | 'nominal';

export function operationalServiceState(container: Pick<ContainerStatus, 'state' | 'health'>): OperationalServiceState {
  const state = (container.state ?? '').toLowerCase();
  const health = (container.health ?? '').toLowerCase();
  if (/(unhealthy|dead|exited|failed)/.test(`${state} ${health}`)) return 'danger';
  if (state === 'running' && (health === 'healthy' || health === 'none')) return 'nominal';
  return 'caution';
}

function serviceStatesWithRuntimeSignals(
  data: DashboardPayload,
  runtimeSignals: FindingSignal[],
): OperationalServiceState[] {
  const runtimeByContainer = new Map<string, OperationalFindingLevel>();
  for (const signal of runtimeSignals) {
    if (!signal.entityKey) continue;
    runtimeByContainer.set(
      signal.entityKey,
      strongerLevel(runtimeByContainer.get(signal.entityKey) ?? null, signal.level),
    );
  }
  return data.containers.map((container, index): OperationalServiceState => {
    const base = operationalServiceState(container);
    const runtime = runtimeByContainer.get(containerIdentity(container, index));
    if (!runtime) return base;
    if (runtime === 'danger' || base === 'danger') return 'danger';
    return 'caution';
  });
}

export function operationalServiceStates(data: DashboardPayload): OperationalServiceState[] {
  return serviceStatesWithRuntimeSignals(data, projectedContainerRuntimeSignals(data));
}

export function operationalFindings(data: DashboardPayload): OperationalFinding[] {
  const findings: OperationalFinding[] = [];
  const gap = data.reliability.collectorGapSeconds;
  const snapshotScope: OperationalFindingScope = data.stale ? 'last-known' : 'current';
  const bootScope: OperationalFindingScope = data.stale ? 'last-known' : 'boot';
  const snapshotObservedAt = data.latestObservedAt;
  const linuxSignals = projectedLinuxSignals(data);
  const containerRuntimeSignals = projectedContainerRuntimeSignals(data);
  const containerSecuritySignals = projectedContainerSecuritySignals(data);
  if (data.stale) {
    const lastObservedAt = data.latestObservedAt;
    findings.push(finding(
      'collection-stale',
      'danger',
      'current',
      [
        lastObservedAt
          ? `마지막 유효 표본 ${lastObservedAt}`
          : `유효 표본 없음 · 판정 시각 ${data.generatedAt}`,
        lastObservedAt
          ? `Last valid sample ${lastObservedAt}`
          : `No valid samples · assessed at ${data.generatedAt}`,
      ],
      null,
      lastObservedAt ?? data.generatedAt,
    ));
  } else if (typeof gap === 'number' && Number.isFinite(gap) && gap >= 120) {
    findings.push(finding(
      'collection-gap',
      'caution',
      'range',
      [`직전 수집 간격 ${Math.round(gap)}초 · 현재는 갱신됨`, `Previous collection interval ${Math.round(gap)}s · now refreshed`],
      1,
      data.generatedAt,
    ));
  }

  const agent = data.agent;
  if (agent && agent.status !== 'healthy') {
    const agentDanger = agent.status === 'disconnected' || agent.status === 'collection_error';
    const age = typeof agent.ageSeconds === 'number' && Number.isFinite(agent.ageSeconds)
      ? `${Math.round(agent.ageSeconds)}초`
      : '관측 시각 없음';
    const ageEn = typeof agent.ageSeconds === 'number' && Number.isFinite(agent.ageSeconds)
      ? `${Math.round(agent.ageSeconds)}s old`
      : 'observation time unavailable';
    findings.push(finding(
      'agent-heartbeat',
      agentDanger ? 'danger' : 'caution',
      'current',
      [
        `상태 ${agent.status} · ${age}${agent.sequence == null ? '' : ` · 순번 ${agent.sequence.toLocaleString()}`}`,
        `status ${agent.status} · ${ageEn}${agent.sequence == null ? '' : ` · sequence ${agent.sequence.toLocaleString()}`}`,
      ],
      1,
      agent.receivedAt ?? data.generatedAt,
    ));
  }

  const serviceCollection = data.containerCollection;
  if (serviceCollection && serviceCollection.status !== 'fresh') {
    const denied = serviceCollection.status === 'permission-denied';
    const unavailable = serviceCollection.status === 'unavailable';
    findings.push(finding(
      'service-collection',
      denied || unavailable ? 'danger' : 'caution',
      serviceCollection.status === 'last-known' ? 'last-known' : 'current',
      [
        `Docker 관측 ${serviceCollection.status}${serviceCollection.observedAt ? ` · 마지막 ${serviceCollection.observedAt}` : ''}`,
        `Docker observation ${serviceCollection.status}${serviceCollection.observedAt ? ` · last ${serviceCollection.observedAt}` : ''}`,
      ],
      null,
      serviceCollection.observedAt ?? data.generatedAt,
    ));
  }

  const ruleStates = Object.values(data.ruleEvaluation.states);
  const activeRules = ruleStates.filter((state) => state.phase === 'firing' || state.phase === 'recovering');
  const ruleCoverageFailures = ruleStates.filter((state) => (
    state.phase === 'collection_error'
    || state.phase === 'permission_denied'
    || state.phase === 'no_data'
  ));
  if (activeRules.length) {
    const firing = activeRules.filter((state) => state.phase === 'firing');
    const recovering = activeRules.length - firing.length;
    const lastKnown = data.stale || data.ruleEvaluation.status === 'last-known';
    const critical = firing.filter((state) => state.severity === 'critical').length;
    const ruleNamesKo = ruleEvidence(activeRules, 'ko');
    const ruleNamesEn = ruleEvidence(activeRules, 'en');
    const alertCollection = data.ruleAlerts.status === 'ok' ? '' : ` · 전환 기록 ${data.ruleAlerts.status}`;
    const alertCollectionEn = data.ruleAlerts.status === 'ok' ? '' : ` · transition log ${data.ruleAlerts.status}`;
    findings.push(finding(
      'rule-evaluation',
      !lastKnown && critical > 0 ? 'danger' : 'caution',
      lastKnown ? 'last-known' : 'current',
      [
        `발화 ${firing.length.toLocaleString()} · 회복 확인 ${recovering.toLocaleString()}${critical ? ` · 심각 ${critical.toLocaleString()}` : ''} · ${ruleNamesKo}${alertCollection}`,
        `${firing.length.toLocaleString()} firing · ${recovering.toLocaleString()} recovering${critical ? ` · ${critical.toLocaleString()} critical` : ''} · ${ruleNamesEn}${alertCollectionEn}`,
      ],
      activeRules.length,
      latestTimestamp(activeRules.map((state) => state.lastEvaluatedAt)),
    ));
  } else if (data.ruleEvaluation.status !== 'ok' || ruleCoverageFailures.length || data.ruleAlerts.status !== 'ok') {
    const evaluatorError = data.ruleEvaluation.status === 'collection_error';
    findings.push(finding(
      'rule-evaluation',
      evaluatorError ? 'danger' : 'caution',
      data.ruleEvaluation.status === 'last-known' ? 'last-known' : 'current',
      [
        `평가 상태 ${data.ruleEvaluation.status} · 범위 오류 ${ruleCoverageFailures.length.toLocaleString()} · 전환 기록 ${data.ruleAlerts.status}`,
        `evaluation ${data.ruleEvaluation.status} · ${ruleCoverageFailures.length.toLocaleString()} coverage failures · transition log ${data.ruleAlerts.status}`,
      ],
      ruleCoverageFailures.length + Number(data.ruleAlerts.status !== 'ok') || null,
      data.ruleEvaluation.evaluatedAt ?? data.generatedAt,
    ));
  }

  const serviceStates = serviceStatesWithRuntimeSignals(data, containerRuntimeSignals);
  const serviceDangerCount = serviceStates.filter((state) => state === 'danger').length;
  const serviceCautionCount = serviceStates.filter((state) => state === 'caution').length;
  if (serviceDangerCount || serviceCautionCount) {
    const serviceEvidenceCurrent = data.containerCollection?.status === 'fresh';
    const runtimeEvidence = containerRuntimeSignals.length ? boundedSignalEvidence(containerRuntimeSignals) : null;
    findings.push(finding(
      'service-fault',
      serviceEvidenceCurrent && serviceDangerCount ? 'danger' : 'caution',
      serviceEvidenceCurrent ? snapshotScope : 'last-known',
      [
        `위험 ${serviceDangerCount.toLocaleString()}개 · 주의 ${serviceCautionCount.toLocaleString()}개${runtimeEvidence ? ` · ${runtimeEvidence[0]}` : ''}`,
        `${serviceDangerCount.toLocaleString()} danger · ${serviceCautionCount.toLocaleString()} caution${runtimeEvidence ? ` · ${runtimeEvidence[1]}` : ''}`,
      ],
      serviceDangerCount + serviceCautionCount,
      serviceEvidenceCurrent ? snapshotObservedAt : data.containerCollection?.observedAt ?? snapshotObservedAt,
    ));
  }

  if (containerSecuritySignals.length) {
    const affected = new Set(containerSecuritySignals.map((signal) => signal.entityKey).filter(Boolean));
    const securityEvidenceCurrent = data.containerCollection?.status === 'fresh';
    findings.push(finding(
      'container-security',
      securityEvidenceCurrent && signalLevel(containerSecuritySignals) === 'danger' ? 'danger' : 'caution',
      securityEvidenceCurrent ? snapshotScope : 'last-known',
      boundedSignalEvidence(containerSecuritySignals),
      affected.size,
      securityEvidenceCurrent ? snapshotObservedAt : data.containerCollection?.observedAt ?? snapshotObservedAt,
    ));
  }

  const dockerEvents = data.dockerEventCollection;
  if (dockerEvents && dockerEvents.status !== 'fresh') {
    const unavailable = dockerEvents.status === 'unavailable' || dockerEvents.status === 'permission-denied';
    const eventScope: OperationalFindingScope = data.stale
      ? 'last-known'
      : dockerEvents.status === 'gap' ? 'range' : 'current';
    findings.push(finding(
      'docker-event-coverage',
      unavailable ? 'danger' : 'caution',
      eventScope,
      [
        `상태 ${dockerEvents.status} · 누락 ${dockerEvents.gapCount.toLocaleString()} · 재연결 ${dockerEvents.reconnectCount.toLocaleString()}`,
        `status ${dockerEvents.status} · ${dockerEvents.gapCount.toLocaleString()} gaps · ${dockerEvents.reconnectCount.toLocaleString()} reconnects`,
      ],
      dockerEvents.gapCount || 1,
      dockerEvents.observedAt ?? data.generatedAt,
    ));
  }

  const syntheticCollection = data.syntheticProbeCollection;
  if (syntheticCollection && syntheticCollection.status !== 'fresh' && syntheticCollection.status !== 'unsupported') {
    const failed = syntheticCollection.status === 'permission-denied'
      || syntheticCollection.status === 'unavailable'
      || syntheticCollection.status === 'collection-error';
    findings.push(finding(
      'synthetic-availability',
      failed ? 'danger' : 'caution',
      syntheticCollection.status === 'stale' || data.stale ? 'last-known' : 'current',
      [
        `합성 검사 수집 ${syntheticCollection.status}`,
        `synthetic probe collection ${syntheticCollection.status}`,
      ],
      null,
      syntheticCollection.observedAt ?? data.generatedAt,
    ));
  } else if (syntheticCollection?.status === 'fresh') {
    const signals: FindingSignal[] = [];
    const probes = data.syntheticProbes;
    if (!probes) {
      signals.push({ key: 'missing-probe-list', entityKey: 'collector', level: 'danger', ko: '검사 결과 목록 누락', en: 'probe result list missing' });
    } else {
      for (const probe of probes) {
        const prefix = probe.id;
        const add = (key: string, level: OperationalFindingLevel, ko: string, en: string) => {
          signals.push({ key: `${probe.id}:${key}`, entityKey: probe.id, level, ko: `${prefix} ${ko}`, en: `${prefix} ${en}` });
        };
        if (probe.status !== 'ok' && probe.status !== 'unsupported') {
          add(
            'status',
            ['dns', 'timeout', 'tls', 'http'].includes(probe.status) ? 'danger' : 'caution',
            `상태 ${probe.status}`,
            `status ${probe.status}`,
          );
        }
        if (probe.latencyMilliseconds >= 1_000) add(
          'latency',
          probe.latencyMilliseconds >= 3_000 ? 'danger' : 'caution',
          `지연 ${Math.round(probe.latencyMilliseconds).toLocaleString()}ms`,
          `latency ${Math.round(probe.latencyMilliseconds).toLocaleString()}ms`,
        );
        const days = probe.certificateDaysRemaining;
        if (typeof days === 'number' && Number.isFinite(days) && days <= 30) add(
          'certificate',
          days <= 7 ? 'danger' : 'caution',
          `인증서 ${Math.trunc(days).toLocaleString()}일 남음`,
          `certificate ${Math.trunc(days).toLocaleString()}d remaining`,
        );
      }
    }
    if (signals.length) {
      const affected = new Set(signals.map((signal) => signal.entityKey).filter(Boolean));
      findings.push(finding(
        'synthetic-availability',
        signalLevel(signals) ?? 'caution',
        data.stale ? 'last-known' : 'current',
        boundedSignalEvidence(signals),
        affected.size || null,
        latestTimestamp(probes?.map((probe) => probe.checkedAt) ?? [syntheticCollection.observedAt]),
      ));
    }
  }

  const pressure: string[] = [];
  const pressureEn: string[] = [];
  let pressureLevel: OperationalFindingLevel | null = null;
  const pressureMetric = (label: string, english: string, value: number | null | undefined, caution: number, danger: number, suffix = '%') => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < caution) return;
    const formatted = suffix === '%' ? percent(value) : `${value.toFixed(1)}${suffix}`;
    pressure.push(`${label} ${formatted}`);
    pressureEn.push(`${english} ${formatted}`);
    if (value >= danger) pressureLevel = 'danger';
    else if (!pressureLevel) pressureLevel = 'caution';
  };
  pressureMetric('CPU', 'CPU', data.latest?.cpuPercent, 75, 90);
  pressureMetric('메모리', 'memory', data.latest?.memoryPercent, 75, 90);
  pressureMetric('스왑', 'swap', data.latest?.swapPercent, 50, 85);
  pressureMetric('온도', 'temperature', data.latest?.temperatureC, 75, 85, '°C');
  const logicalCpuCount = typeof data.host.logicalCpuCount === 'number'
    && Number.isSafeInteger(data.host.logicalCpuCount)
    && data.host.logicalCpuCount > 0
    ? data.host.logicalCpuCount
    : null;
  if (logicalCpuCount && typeof data.latest?.load1 === 'number' && Number.isFinite(data.latest.load1)) {
    pressureMetric('코어당 부하', 'load per CPU', data.latest.load1 / logicalCpuCount, 0.75, 1.5, '×');
  } else {
    pressureMetric('부하', 'load', data.latest?.load1, 4, 8, '');
  }
  pressureMetric('CPU PSI', 'CPU PSI', data.latest?.cpuPressureSomeAvg10, PSI_THRESHOLDS.cpuSome.caution, PSI_THRESHOLDS.cpuSome.danger);
  pressureMetric('CPU full PSI', 'CPU full PSI', data.latest?.cpuPressureFullAvg10, PSI_THRESHOLDS.cpuFull.caution, PSI_THRESHOLDS.cpuFull.danger);
  pressureMetric('메모리 PSI', 'memory PSI', data.latest?.memoryPressureSomeAvg10, PSI_THRESHOLDS.memorySome.caution, PSI_THRESHOLDS.memorySome.danger);
  pressureMetric('메모리 full PSI', 'memory full PSI', data.latest?.memoryPressureFullAvg10, PSI_THRESHOLDS.memoryFull.caution, PSI_THRESHOLDS.memoryFull.danger);
  pressureMetric('I/O PSI', 'I/O PSI', data.latest?.ioPressureSomeAvg10, PSI_THRESHOLDS.ioSome.caution, PSI_THRESHOLDS.ioSome.danger);
  pressureMetric('I/O full PSI', 'I/O full PSI', data.latest?.ioPressureFullAvg10, PSI_THRESHOLDS.ioFull.caution, PSI_THRESHOLDS.ioFull.danger);
  for (const signal of linuxSignals.resource) {
    pressure.push(signal.ko);
    pressureEn.push(signal.en);
    pressureLevel = strongerLevel(pressureLevel, signal.level);
  }
  if (pressureLevel) {
    findings.push(finding(
      'resource-pressure',
      pressureLevel,
      snapshotScope,
      [pressure.join(' · '), pressureEn.join(' · ')],
      pressure.length,
      latestTimestamp([snapshotObservedAt, linuxSignals.resource.length ? linuxSignals.observedAt : null]),
    ));
  }

  const storageSignals = data.disks.flatMap((disk) => {
    const signals: Array<{ value: number; ko: string; en: string }> = [];
    if (typeof disk.usedPercent === 'number' && Number.isFinite(disk.usedPercent) && disk.usedPercent >= 75) {
      signals.push({ value: disk.usedPercent, ko: `${disk.mount} 용량 ${percent(disk.usedPercent)}`, en: `${disk.mount} capacity ${percent(disk.usedPercent)}` });
    }
    if (typeof disk.inodeUsedPercent === 'number' && Number.isFinite(disk.inodeUsedPercent) && disk.inodeUsedPercent >= 75) {
      signals.push({ value: disk.inodeUsedPercent, ko: `${disk.mount} 아이노드 ${percent(disk.inodeUsedPercent)}`, en: `${disk.mount} inodes ${percent(disk.inodeUsedPercent)}` });
    }
    return signals;
  });
  if (storageSignals.length) {
    const maximum = Math.max(...storageSignals.map((signal) => signal.value));
    findings.push(finding(
      'storage-capacity',
      maximum >= 90 ? 'danger' : 'caution',
      snapshotScope,
      [storageSignals.map((signal) => signal.ko).join(' · '), storageSignals.map((signal) => signal.en).join(' · ')],
      storageSignals.length,
      snapshotObservedAt,
    ));
  }

  const voltage = data.latest?.supplyVoltageVolts;
  const flags = typeof data.latest?.throttledFlags === 'number' && Number.isFinite(data.latest.throttledFlags)
    ? Math.max(0, Math.trunc(data.latest.throttledFlags))
    : 0;
  const currentThrottle = (flags & 0x0f) !== 0;
  const historicalThrottle = flags !== 0
    || data.powerSummary.underVoltageSampleCount > 0
    || data.powerSummary.throttledSampleCount > 0;
  const powerEvents = data.powerEvents.filter((event) => {
    const severity = event.severity.toLowerCase();
    const kind = (event.kind ?? '').toLowerCase();
    const status = (event.status ?? '').toLowerCase();
    return /(warning|critical|error)/.test(severity)
      && status !== 'recovered'
      && /(power|voltage|host)/.test(kind);
  });
  if (currentThrottle || historicalThrottle || powerEvents.length || linuxSignals.power.length) {
    const powerEventTimes = powerEvents.map((event) => event.timestamp);
    const powerSampleTimes = data.series
      .filter((sample) => (
        typeof sample.throttledFlags === 'number' && (sample.throttledFlags & 0x0f) !== 0
      ))
      .map((sample) => sample.timestamp);
    const rangeAnomalyAt = latestTimestamp([...powerEventTimes, ...powerSampleTimes]);
    const hasRangeAnomaly = rangeAnomalyAt !== null
      || data.powerSummary.underVoltageSampleCount > 0
      || data.powerSummary.throttledSampleCount > 0;
    const powerScope: OperationalFindingScope = currentThrottle
      ? snapshotScope
      : linuxSignals.power.length
        ? snapshotScope
      : hasRangeAnomaly
        ? 'range'
        : bootScope;
    const criticalPowerEventCount = powerEvents.filter((event) => /critical|error/.test(event.severity.toLowerCase())).length;
    const powerEvidenceKo = [
      (powerScope === 'current' || powerScope === 'last-known') && typeof voltage === 'number' && Number.isFinite(voltage)
        ? `${powerScope === 'current' ? '현재' : '마지막 표본'} ${voltage.toFixed(3)}V`
        : null,
      flags ? `throttled 플래그 0x${flags.toString(16)}${currentThrottle ? (powerScope === 'current' ? ' (현재 제한 포함)' : ' (마지막 표본의 제한 비트)') : ' (과거 이력 비트)'}` : null,
      data.powerSummary.underVoltageSampleCount ? `저전압 표본 ${data.powerSummary.underVoltageSampleCount.toLocaleString()}건` : null,
      data.powerSummary.throttledSampleCount ? `제한 표본 ${data.powerSummary.throttledSampleCount.toLocaleString()}건` : null,
      powerEvents.length ? `전원 이벤트 ${powerEvents.length.toLocaleString()}건${criticalPowerEventCount ? ` (위험 ${criticalPowerEventCount.toLocaleString()}건)` : ''}` : null,
      ...linuxSignals.power.map((signal) => signal.ko),
    ].filter((value): value is string => Boolean(value));
    const powerEvidenceEn = [
      (powerScope === 'current' || powerScope === 'last-known') && typeof voltage === 'number' && Number.isFinite(voltage)
        ? `${powerScope === 'current' ? 'current' : 'last sample'} ${voltage.toFixed(3)}V`
        : null,
      flags ? `throttled flags 0x${flags.toString(16)}${currentThrottle ? (powerScope === 'current' ? ' (includes current state)' : ' (set in the last sample)') : ' (historic bits)'}` : null,
      data.powerSummary.underVoltageSampleCount ? `${data.powerSummary.underVoltageSampleCount.toLocaleString()} undervoltage samples` : null,
      data.powerSummary.throttledSampleCount ? `${data.powerSummary.throttledSampleCount.toLocaleString()} throttled samples` : null,
      powerEvents.length ? `${powerEvents.length.toLocaleString()} power ${powerEvents.length === 1 ? 'event' : 'events'}${criticalPowerEventCount ? ` (${criticalPowerEventCount.toLocaleString()} critical)` : ''}` : null,
      ...linuxSignals.power.map((signal) => signal.en),
    ].filter((value): value is string => Boolean(value));
    findings.push(finding(
      'power-quality',
      currentThrottle || criticalPowerEventCount || signalLevel(linuxSignals.power) === 'danger' ? 'danger' : 'caution',
      powerScope,
      [powerEvidenceKo.join(' · '), powerEvidenceEn.join(' · ')],
      Math.max(data.powerSummary.underVoltageSampleCount + data.powerSummary.throttledSampleCount, flags ? 1 : 0, powerEvents.length, linuxSignals.power.length),
      powerScope === 'current' || powerScope === 'last-known'
        ? latestTimestamp([snapshotObservedAt, linuxSignals.power.length ? linuxSignals.observedAt : null])
        : powerScope === 'range' ? rangeAnomalyAt : null,
    ));
  }

  const networkState = data.reliability.networkLinkAvailable;
  const sshState = data.reliability.sshListenersAvailable;
  const networkDown = networkState === false;
  const sshDown = sshState === false;
  const networkUnknown = networkState === null;
  const sshUnknown = sshState === null;
  if (networkDown || sshDown || networkUnknown || sshUnknown) {
    const ko = [
      networkDown ? '주 네트워크 연결 끊김' : networkUnknown ? '주 네트워크 상태 미확인' : null,
      sshDown ? 'SSH 수신 경로 없음' : sshUnknown ? 'SSH 수신 상태 미확인' : null,
    ].filter(Boolean).join(' · ');
    const en = [
      networkDown ? 'primary network unavailable' : networkUnknown ? 'primary network state unknown' : null,
      sshDown ? 'SSH listener unavailable' : sshUnknown ? 'SSH listener state unknown' : null,
    ].filter(Boolean).join(' · ');
    findings.push(finding('connectivity', networkDown ? 'danger' : 'caution', snapshotScope, [ko, en], Number(networkDown || networkUnknown) + Number(sshDown || sshUnknown), snapshotObservedAt));
  }

  const networkFaults = [
    ['수신 오류', 'RX errors', data.latest?.networkRxErrorsPerSecond],
    ['송신 오류', 'TX errors', data.latest?.networkTxErrorsPerSecond],
    ['수신 드롭', 'RX drops', data.latest?.networkRxDroppedPerSecond],
    ['송신 드롭', 'TX drops', data.latest?.networkTxDroppedPerSecond],
  ] as const;
  const observedNetworkFaults = networkFaults.filter((entry) => typeof entry[2] === 'number' && Number.isFinite(entry[2]) && entry[2] > 0);
  const networkFaultRate = observedNetworkFaults.reduce((total, entry) => total + (entry[2] ?? 0), 0);
  const networkEvidenceKo: string[] = [];
  const networkEvidenceEn: string[] = [];
  let networkLevel: OperationalFindingLevel | null = null;
  if (networkFaultRate >= NETWORK_FAULT_RATE_THRESHOLDS.caution) {
    const formatRate = (value: number | null | undefined) => `${(value ?? 0).toFixed((value ?? 0) >= 1 ? 1 : 3)}/s`;
    networkEvidenceKo.push(...observedNetworkFaults.map(([ko, , value]) => `${ko} ${formatRate(value)}`));
    networkEvidenceEn.push(...observedNetworkFaults.map(([, en, value]) => `${en} ${formatRate(value)}`));
    networkLevel = networkFaultRate >= NETWORK_FAULT_RATE_THRESHOLDS.danger ? 'danger' : 'caution';
  }
  for (const signal of linuxSignals.network) {
    networkEvidenceKo.push(signal.ko);
    networkEvidenceEn.push(signal.en);
    networkLevel = strongerLevel(networkLevel, signal.level);
  }
  if (networkLevel) {
    findings.push(finding(
      'network-quality',
      networkLevel,
      snapshotScope,
      [networkEvidenceKo.join(' · '), networkEvidenceEn.join(' · ')],
      observedNetworkFaults.length + linuxSignals.network.length,
      latestTimestamp([snapshotObservedAt, linuxSignals.network.length ? linuxSignals.observedAt : null]),
    ));
  }

  if (linuxSignals.reliability.length) {
    findings.push(finding(
      'linux-reliability',
      signalLevel(linuxSignals.reliability) ?? 'caution',
      snapshotScope,
      boundedSignalEvidence(linuxSignals.reliability),
      linuxSignals.reliability.length,
      linuxSignals.observedAt ?? snapshotObservedAt,
    ));
  }

  const currentRequestCount = data.currentTraffic.reduce((total, entry) => total + entry.requestCount, 0);
  if (currentRequestCount > 0) {
    const serverErrors = data.currentTraffic.reduce((total, entry) => total + entry.status5xx, 0);
    const slowRequests = data.currentTraffic.reduce((total, entry) => total + entry.slowCount, 0);
    const maximumResponseMs = data.currentTraffic.reduce((maximum, entry) => Math.max(maximum, entry.maxResponseMs ?? 0), 0);
    const serverErrorPercent = (serverErrors / currentRequestCount) * 100;
    const slowPercent = (slowRequests / currentRequestCount) * 100;
    const noteworthy = serverErrors > 0 || slowPercent >= 10 || maximumResponseMs >= 5_000;
    if (noteworthy) {
      const danger = serverErrorPercent >= 5 || slowPercent >= 40 || maximumResponseMs >= 15_000;
      findings.push(finding(
        'application-traffic',
        danger ? 'danger' : 'caution',
        snapshotScope,
        [
          `요청 ${currentRequestCount.toLocaleString()} · 5xx ${serverErrors.toLocaleString()} (${percent(serverErrorPercent)}) · 느림 ${slowRequests.toLocaleString()} (${percent(slowPercent)}) · 최대 ${maximumResponseMs.toFixed(0)}ms`,
          `${currentRequestCount.toLocaleString()} requests · ${serverErrors.toLocaleString()} 5xx (${percent(serverErrorPercent)}) · ${slowRequests.toLocaleString()} slow (${percent(slowPercent)}) · ${maximumResponseMs.toFixed(0)}ms max`,
        ],
        serverErrors + slowRequests,
        snapshotObservedAt,
      ));
    }
  }

  const kernel = data.system.kernel;
  const crashCount = numericCount(kernel.panic.count) + numericCount(kernel.oops.count);
  if (crashCount) {
    findings.push(finding(
      'kernel-crash',
      'danger',
      bootScope,
      [`패닉 ${numericCount(kernel.panic.count)}건 · Oops ${numericCount(kernel.oops.count)}건`, `${numericCount(kernel.panic.count)} panic · ${numericCount(kernel.oops.count)} oops`],
      crashCount,
      latestTimestamp([kernel.panic.lastEventAt, kernel.oops.lastEventAt]),
    ));
  }

  const stallCount = numericCount(kernel.rcuStall.count) + numericCount(kernel.hungTask.count);
  if (stallCount) {
    findings.push(finding(
      'kernel-stall',
      'danger',
      bootScope,
      [`실제 RCU stall 기록 ${numericCount(kernel.rcuStall.count)}건 · hung task 기록 ${numericCount(kernel.hungTask.count)}건`, `${numericCount(kernel.rcuStall.count)} recorded RCU stalls · ${numericCount(kernel.hungTask.count)} recorded hung tasks`],
      stallCount,
      latestTimestamp([kernel.rcuStall.lastEventAt, kernel.hungTask.lastEventAt]),
    ));
  }

  const oomCount = numericCount(kernel.oomKill.count);
  if (oomCount) {
    findings.push(finding('memory-oom', 'danger', bootScope, [`OOM 종료 ${oomCount.toLocaleString()}건`, `${oomCount.toLocaleString()} OOM kills`], oomCount, kernel.oomKill.lastEventAt));
  }

  const readOnlyMounts = data.disks.filter((disk) => disk.readOnly === true);
  const storageErrorCount = numericCount(kernel.filesystemError.count) + numericCount(kernel.nvmeReset.count) + numericCount(kernel.nvmeIo.count);
  if (storageErrorCount || readOnlyMounts.length || linuxSignals.storage.length) {
    const readOnlyKo = readOnlyMounts.length ? ` · 읽기 전용 ${readOnlyMounts.map((disk) => disk.mount).join(', ')}` : '';
    const readOnlyEn = readOnlyMounts.length ? ` · read-only ${readOnlyMounts.map((disk) => disk.mount).join(', ')}` : '';
    const legacyKo = storageErrorCount || readOnlyMounts.length
      ? `파일시스템 ${numericCount(kernel.filesystemError.count)} · NVMe reset ${numericCount(kernel.nvmeReset.count)} · I/O ${numericCount(kernel.nvmeIo.count)}${readOnlyKo}`
      : null;
    const legacyEn = storageErrorCount || readOnlyMounts.length
      ? `filesystem ${numericCount(kernel.filesystemError.count)} · NVMe reset ${numericCount(kernel.nvmeReset.count)} · I/O ${numericCount(kernel.nvmeIo.count)}${readOnlyEn}`
      : null;
    const currentStorageEvidence = linuxSignals.storage.length > 0 || readOnlyMounts.length > 0;
    findings.push(finding(
      'storage-integrity',
      storageErrorCount || readOnlyMounts.length || signalLevel(linuxSignals.storage) === 'danger' ? 'danger' : 'caution',
      currentStorageEvidence ? snapshotScope : bootScope,
      [
        [legacyKo, ...linuxSignals.storage.map((signal) => signal.ko)].filter(Boolean).join(' · '),
        [legacyEn, ...linuxSignals.storage.map((signal) => signal.en)].filter(Boolean).join(' · '),
      ],
      storageErrorCount + readOnlyMounts.length + linuxSignals.storage.length,
      currentStorageEvidence
        ? latestTimestamp([snapshotObservedAt, linuxSignals.observedAt])
        : latestTimestamp([kernel.filesystemError.lastEventAt, kernel.nvmeReset.lastEventAt, kernel.nvmeIo.lastEventAt]),
    ));
  }

  const pcie = data.system.pcie;
  const fatalPcie = Math.max(numericCount(kernel.pcieAerFatal.count), numericCount(pcie.aerFatalCount));
  const nonFatalPcie = Math.max(numericCount(kernel.pcieAerNonFatal.count), numericCount(pcie.aerNonFatalCount));
  const correctablePcie = Math.max(numericCount(kernel.pcieAerCorrectable.count), numericCount(pcie.aerCorrectableCount));
  const downgradedPcie = pcie.configuredGeneration != null
    && pcie.negotiatedGeneration != null
    && pcie.negotiatedGeneration < pcie.configuredGeneration;
  const pcieStatusActive = pcie.fatalStatusActive === true || pcie.nonFatalStatusActive === true || pcie.correctableStatusActive === true;
  if (fatalPcie || nonFatalPcie || correctablePcie || downgradedPcie || pcieStatusActive) {
    const pcieLevel: OperationalFindingLevel = fatalPcie || nonFatalPcie || pcie.fatalStatusActive === true || pcie.nonFatalStatusActive === true ? 'danger' : 'caution';
    const generationKo = downgradedPcie ? `링크 Gen${pcie.negotiatedGeneration}/설정 Gen${pcie.configuredGeneration}` : null;
    const generationEn = downgradedPcie ? `link Gen${pcie.negotiatedGeneration}/configured Gen${pcie.configuredGeneration}` : null;
    const statusBitsKo = [
      pcie.fatalStatusActive === true ? '치명 감지 비트' : null,
      pcie.nonFatalStatusActive === true ? '비치명 감지 비트' : null,
      pcie.correctableStatusActive === true ? '교정 감지 비트' : null,
    ].filter(Boolean).join(' · ');
    const statusBitsEn = [
      pcie.fatalStatusActive === true ? 'fatal detected bit' : null,
      pcie.nonFatalStatusActive === true ? 'non-fatal detected bit' : null,
      pcie.correctableStatusActive === true ? 'correctable detected bit' : null,
    ].filter(Boolean).join(' · ');
    findings.push(finding(
      'pcie-integrity',
      pcieLevel,
      downgradedPcie ? snapshotScope : bootScope,
      [
        [`치명 ${fatalPcie} · 비치명 ${nonFatalPcie} · 교정 ${correctablePcie}`, statusBitsKo || null, generationKo].filter(Boolean).join(' · '),
        [`fatal ${fatalPcie} · non-fatal ${nonFatalPcie} · correctable ${correctablePcie}`, statusBitsEn || null, generationEn].filter(Boolean).join(' · '),
      ],
      Math.max(fatalPcie + nonFatalPcie + correctablePcie, pcieStatusActive ? 1 : 0),
      latestTimestamp([
        kernel.pcieAerFatal.lastEventAt,
        kernel.pcieAerNonFatal.lastEventAt,
        kernel.pcieAerCorrectable.lastEventAt,
        downgradedPcie ? snapshotObservedAt : null,
      ]),
    ));
  }

  const expeditedBootCount = numericCount(kernel.rcuExpedited.count);
  const expedited = uniqueReliabilityEvents(data, 'rcu-stall', 'expedited');
  if (expeditedBootCount) {
    findings.push(finding(
      'rcu-expedited',
      'caution',
      bootScope,
      data.stale
        ? [`마지막 확인 부팅에 기록된 짧은 지연 ${expeditedBootCount.toLocaleString()}건`, `${expeditedBootCount.toLocaleString()} short delays recorded in the last known boot`]
        : [`이번 부팅에 기록된 짧은 지연 ${expeditedBootCount.toLocaleString()}건`, `${expeditedBootCount.toLocaleString()} short delays recorded this boot`],
      expeditedBootCount,
      kernel.rcuExpedited.lastEventAt,
    ));
  } else if (expedited.length) {
    findings.push(finding(
      'rcu-expedited',
      'caution',
      'range',
      [`선택 기간에 표시된 짧은 지연 ${expedited.length.toLocaleString()}건`, `${expedited.length.toLocaleString()} displayed short delays in the selected range`],
      expedited.length,
      latestTimestamp(expedited.map((event) => event.timestamp)),
    ));
  }

  const genericWarnings = uniqueReliabilityEvents(data, 'kernel-warning');
  if (genericWarnings.length) {
    findings.push(finding(
      'kernel-warning',
      'caution',
      'range',
      [`선택 기간에 표시된 일반 WARNING ${genericWarnings.length.toLocaleString()}건`, `${genericWarnings.length.toLocaleString()} displayed general WARNING records in the selected range`],
      genericWarnings.length,
      latestTimestamp(genericWarnings.map((event) => event.timestamp)),
    ));
  } else if (numericCount(kernel.warning.count)) {
    const warningCount = numericCount(kernel.warning.count);
    findings.push(finding('kernel-warning', 'caution', bootScope, [`세부 종류 미확인 warning 집계 ${warningCount.toLocaleString()}건`, `${warningCount.toLocaleString()} warning records with no retained specific kind`], warningCount, kernel.warning.lastEventAt));
  }

  if (data.reliability.nvmeMitigationActive !== true) {
    const unknown = data.reliability.nvmeMitigationActive === null;
    findings.push(finding(
      'nvme-mitigation',
      'caution',
      snapshotScope,
      unknown ? ['보호 설정 확인 불가', 'mitigation state unknown'] : ['보호 설정 미적용', 'mitigation not active'],
      1,
      snapshotObservedAt,
    ));
  }

  const runningKernel = data.system.versions.kernelRunning;
  const installedKernel = data.system.versions.kernelLatestInstalled;
  if (data.system.versions.kernelRebootRequired === true || (runningKernel && installedKernel && runningKernel !== installedKernel)) {
    findings.push(finding(
      'reboot-required',
      'caution',
      snapshotScope,
      [`실행 ${runningKernel ?? '미확인'} · 설치 ${installedKernel ?? '미확인'}`, `running ${runningKernel ?? 'unknown'} · installed ${installedKernel ?? 'unknown'}`],
      1,
      snapshotScope === 'current' ? data.generatedAt : snapshotObservedAt,
    ));
  }

  const activeIncidents = data.incidents.filter((incident) => incident.phase === 'active');
  if (activeIncidents.length) {
    const generatedAt = new Date(data.generatedAt).getTime();
    const freshnessCutoff = Number.isFinite(generatedAt) ? generatedAt - 5 * 60_000 : Number.POSITIVE_INFINITY;
    const freshIncidents = activeIncidents.filter((incident) => {
      const observedAt = new Date(incident.observedAt).getTime();
      return Number.isFinite(observedAt) && observedAt >= freshnessCutoff;
    });
    const current = !data.stale && freshIncidents.length > 0;
    const considered = current ? freshIncidents : activeIncidents;
    findings.push(finding(
      'active-incident',
      current ? 'danger' : 'caution',
      current ? 'current' : 'range',
      current
        ? [`최근 5분 내 진행 중 사건 ${considered.length.toLocaleString()}건`, `${considered.length.toLocaleString()} incidents observed active in the last 5 minutes`]
        : [`선택 기간의 오래된 미종료 기록 ${considered.length.toLocaleString()}건`, `${considered.length.toLocaleString()} older unresolved records in the selected range`],
      considered.length,
      latestTimestamp(considered.map((incident) => incident.observedAt)),
    ));
  }

  return findings.sort((left, right) => {
    if (left.level !== right.level) return left.level === 'danger' ? -1 : 1;
    if (left.scope !== right.scope) return SCOPE_ORDER[left.scope] - SCOPE_ORDER[right.scope];
    if (left.priority !== right.priority) return left.priority - right.priority;
    const leftTime = left.lastObservedAt ? new Date(left.lastObservedAt).getTime() : 0;
    const rightTime = right.lastObservedAt ? new Date(right.lastObservedAt).getTime() : 0;
    const timestampOrder = (Number.isFinite(rightTime) ? rightTime : 0) - (Number.isFinite(leftTime) ? leftTime : 0);
    return timestampOrder || left.id.localeCompare(right.id);
  });
}

export function localizedFindingText(text: LocalizedText, locale: 'ko' | 'en'): string {
  return locale === 'ko' ? text[0] : text[1];
}

export function operationalFindingAnchor(id: OperationalFindingId): string {
  return `issue-${id}`;
}

export function operationalFindingHref(finding: Pick<OperationalFinding, 'page' | 'id'>, range: TimeRange): string {
  return `/monitor/details/${finding.page}?range=${encodeURIComponent(range)}#${operationalFindingAnchor(finding.id)}`;
}
