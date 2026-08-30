# Monitor 운영 투입 전 최종 감사

> 기준 커밋: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 감사 기준일: 2026-08-30
> 기준 명세: `/home/cks/Monitor.md` 21장 50항목
> 범위: `/home/cks/Monitor` 저장소의 코드, 테스트, Compose, systemd 단위와 문서. 외부 SSO, Nginx 실설정, 배포 forced-command 구현 및 실제 하드웨어 상태는 저장소 증거가 아니므로 별도 표기한다.

이 문서는 구현 완료 선언이 아니다. 현재 증거로 입증되는 범위와 입증되지 않는 범위를 분리한 추적표다. 여섯 분석 문서의 공통 기준표이며, 세부 구조는 [갭 분석](monitoring-gap-analysis.md), [데이터 흐름](monitoring-data-flow.md), [장애 분석](monitoring-failure-analysis.md), [데이터 모델](monitoring-data-model.md), [확장성](monitoring-scalability.md), [로드맵](monitoring-roadmap.md)을 따른다.

## 판정 원칙

| 상태 | 의미 |
| --- | --- |
| 통과 | 요구 범위의 실행 경로, 기본 동작, 실패 동작과 테스트 증거가 모두 있다. |
| 부분 통과 | 유효한 일부 실행 경로가 있으나 요구한 범위·상태·복구·테스트 중 하나 이상이 없다. |
| 실패 | 기능은 연결되어 있지만 명세의 안전성 또는 정확성 조건과 모순된다. |
| 미구현 | 데이터 모델이나 실행 경로가 없다. UI 문구나 문서만으로는 구현으로 보지 않는다. |
| 검증 불가 | 구현이 저장소 밖에 있고 현재 증거로 실행 상태를 입증할 수 없다. |

`server/*.test.ts`, `src/*.test.ts`, `ops/tests/*.py`의 테스트 이름만으로 통과 처리하지 않았다. 코드 경로와 스키마를 먼저 확인하고 테스트가 그 경로를 실제로 호출하거나 계약을 검증하는 경우에만 보조 증거로 사용했다. 감사 시점에 Vitest 22개 파일/186개 테스트, Python 142개 테스트, 클라이언트·서버 TypeScript 검사가 통과했지만, 아래의 미구현 기능은 해당 테스트 모집단에 들어 있지 않다.

## 50항목 추적 매트릭스

| ID | 점검 항목 | 상태 | 현재 증거와 범위 | 갭 |
| --- | --- | --- | --- | --- |
| FA-01 | 호스트 등록과 중복 식별 | 미구현 | `ops/collector.py:4846-4853`은 매 실행의 hostname/OS/architecture만 내보낸다. 등록 API, 영속 `hostId`, 중복 병합 정책이 없다. | GAP-FLEET |
| FA-02 | 에이전트 heartbeat 정확도 | 부분 통과 | 로컬 systemd 수집 간격과 `collector-gap`은 있다(`ops/systemd/monitor-collector.timer:4-10`, `ops/collector.py:1886-1889`). 독립 agent ID/서버 수신시각/네트워크 heartbeat는 없다. | GAP-FLEET |
| FA-03 | 데이터 지연과 데이터 없음 구분 | 부분 통과 | API는 마지막 표본을 기준으로 전역 `stale`을 계산하고 빈 경우 `latestObservedAt=null`을 준다(`server/data.ts:1518-1531`). 메트릭별 no-data, unsupported, permission-denied, collection-failed 상태는 없다. | GAP-FLEET |
| FA-04 | CPU, 메모리, swap, PSI | 통과 | procfs 파서와 고정 스키마가 CPU/메모리/swap/PSI some/full avg10을 수집한다(`ops/collector.py:4770-4787,4805-4829`). 누락은 `null`로 유지된다. 파서·계약 테스트가 있다. | — |
| FA-05 | 디스크 용량, inode, I/O latency | 부분 통과 | `statvfs` 용량/inode와 `/proc/diskstats` 처리량은 있다(`ops/collector.py:706-751,988-1052`). 장치별 latency/queue/utilization은 없다. | GAP-HOST |
| FA-06 | 네트워크 오류와 TCP 상태 | 부분 통과 | 비-loopback RX/TX byte/error/drop rate는 있다(`ops/collector.py:657-704`; `src/operational-health.ts:621-642`). TCP retransmit, socket 상태, conntrack은 없다. | GAP-HOST |
| FA-07 | 프로세스와 systemd 서비스 | 부분 통과 | 허용 UID 프로세스를 고정 실행파일 분류로 축약한다(`ops/collector.py:811-944`). 평시 프로세스/서비스 모델, systemd unit 상태/재시작 횟수는 없다. | GAP-HOST |
| FA-08 | OOM과 커널 이벤트 | 부분 통과 | 커널 로그를 OOM, warning/oops/panic, hung task, RCU, filesystem/NVMe/PCIe 고정 이벤트로 축약한다(`ops/collector.py:209-238,1877-1977`). journald fallback과 로그 접근 실패 상태가 없다. | GAP-HOST |
| FA-09 | Raspberry Pi 온도, throttling, 저전압 | 부분 통과 | sysfs/vcgencmd 온도와 hwmon 저전압 bit 0, 커널 저전압 전환을 수집한다(`ops/collector.py:945-986,1496-1551,4219-4246`). 현재 throttle bit 전체는 수집하지 않으며 UI의 4.75/4.63V 판정은 문서의 “전압으로 상태를 발명하지 않음”과 모순된다(`src/operational-health.ts:543-599`, `README.md:598-606`). | GAP-HOST |
| FA-10 | Docker daemon 상태 | 부분 통과 | exporter가 daemon GET 실패 시 이전 snapshot을 교체하지 않고 상위 collector를 실패시킨다(`ops/collector.py:1668-1677`, `ops/tests/test_container_exporter.py:51-77`). 명시적 daemon 상태·오류 종류·복구 시각은 없다. | GAP-DOCKER |
| FA-11 | Docker event stream | 미구현 | Docker API 사용은 project-filtered list와 one-shot stats뿐이다(`ops/collector.py:1598-1764`). `/events` 연결·cursor·재연결이 없다. | GAP-DOCKER |
| FA-12 | 컨테이너 CPU, 메모리, I/O, 네트워크 | 부분 통과 | 고정 컨테이너 스키마는 CPU와 memory bytes/percent만 포함한다(`ops/collector.py:1621-1657,1817-1853`). block I/O, network, pids는 없다. | GAP-DOCKER |
| FA-13 | restart loop | 미구현 | container schema에 restart count와 started/finished timestamp가 없다(`ops/collector.py:1817-1819`). | GAP-DOCKER |
| FA-14 | OOMKilled | 미구현 | inspect state/error/exit reason을 수집하지 않아 host OOM과 container OOMKilled를 구분할 수 없다. | GAP-DOCKER |
| FA-15 | healthcheck | 부분 통과 | `docker ps` 상태 문자열에서 healthy/unhealthy/starting을 파싱한다(`ops/collector.py:1630-1633`). healthcheck 미설정과 접근 실패를 안정적으로 구분하거나 이력을 저장하지 않는다. | GAP-DOCKER |
| FA-16 | limit 대비 사용률 | 부분 통과 | stats의 memory limit 대비 percent만 계산한다(`ops/collector.py:1637-1647`). 명시적 memory limit 유무, CPU quota/limit, pids limit는 없다. | GAP-DOCKER |
| FA-17 | Docker Compose 프로젝트 그룹 | 부분 통과 | project/service allowlist와 프론트 그룹화는 있으나 public schema는 고정 `name`으로 축약되어 project/service identity를 잃는다(`ops/collector.py:142-167,1609-1618,1649-1657`). | GAP-DOCKER |
| FA-18 | 볼륨과 writable layer | 미구현 | 보안을 위해 mounts와 image metadata를 전부 버리며 writable layer/volume usage 스키마가 없다(`ops/README.md:168-176`). | GAP-DOCKER |
| FA-19 | 이미지 digest drift | 미구현 | image ID/tag/digest/deployed revision이 container snapshot에 없다. | GAP-DOCKER |
| FA-20 | 로그 수집과 멀티라인 파싱 | 부분 통과 | 선택된 event/kernel/privilege/traffic 파일을 inode cursor로 tail한다(`ops/collector.py:2711-2777,4204-4281`). Docker stdout/stderr, journald, 범용 파일, logfmt/syslog 구조화, multiline 묶기는 없다. | GAP-LOG |
| FA-21 | 민감정보 마스킹 | 부분 통과 | 수집 단계 고정 allowlist와 API 2차 redaction이 있다(`ops/collector.py:2037-2125,2566-2638`; `server/data.ts:284-295`). 범용 로그가 없고 마스킹 규칙 버전/변경이력/시험 API가 없다. | GAP-LOG |
| FA-22 | 로그 폭증 제어 | 부분 통과 | 입력 byte/line과 출력 record cap, traffic logrotate/retention이 있다(`ops/collector.py:2641-2680,4108-4131`; `ops/logrotate/monitor-traffic`). 서비스 quota, 우선순위, sampling, drop count가 없다. | GAP-LOG |
| FA-23 | 알림 지속 시간 | 부분 통과 | incident CPU streak은 설정 가능하지만 기본이 한 표본이며 다른 이유는 즉시 진입한다(`ops/collector.py:3294-3310,4376-4388`). 범용 rule duration/평가 누락 정책이 없다. | GAP-ALERT |
| FA-24 | hysteresis | 부분 통과 | 7개 incident reason에 발생/복구 임계값이 분리되어 있다(`ops/collector.py:3304-3363`). 복구 지속시간과 범용 규칙 상태 전이는 없다. | GAP-ALERT |
| FA-25 | no-data와 stale-data | 부분 통과 | 응답 전역 stale만 있다(`server/data.ts:1530`). agent, Docker, 개별 metric no-data 정책과 사용자 설정이 없다. | GAP-ALERT |
| FA-26 | 알림 dedup | 부분 통과 | power exact-row dedup과 incident lifecycle ID가 있다(`ops/collector.py:2537-2563,3258-3432`). label/time-window 기반 범용 alert group/dedup은 없다. | GAP-ALERT |
| FA-27 | 상위 장애 기반 억제 | 미구현 | host→daemon→container/service topology와 inhibition evaluator가 없다. | GAP-ALERT |
| FA-28 | silence와 유지보수 창 | 미구현 | maintenance **event** 파싱만 있으며 silence 모델/API/반복 일정이 없다(`ops/collector.py:1979-1992,2044-2058`). | GAP-ALERT |
| FA-29 | 알림 전송 retry | 미구현 | 이메일/Slack/Discord/Telegram/webhook adapter, outbox, delivery log가 없다. `package.json:33-40`의 runtime dependency도 해당 기능을 제공하지 않는다. | GAP-ALERT |
| FA-30 | incident 타임라인 | 부분 통과 | threshold incident와 operational event UI가 있으나 서로 별도이고 사용자 조치·배포·알림 전송을 완전 통합하지 않는다(`src/dashboard-model.ts:230-234`; `src/components/OperationalLogView.tsx:13-19`). | GAP-INCIDENT |
| FA-31 | 사용자 인증과 RBAC | 부분 통과 | edge-secret 기반 SSO identity와 user/admin/chief-admin API gate가 있다(`server/sso.ts:76-151`; `server/app.ts:351-409`). host/environment/team scope와 로그/설정별 권한은 없다. OIDC lifecycle은 외부 시스템이라 검증 불가다. | GAP-SECURITY |
| FA-32 | 감사 로그 | 부분 통과 | host privilege semantic feed와 package update audit은 있다(`ops/collector.py:2566-2638`; `ops/monitor_update_worker.py:1157-1232`). 로그인/로그아웃/비밀번호/권한/rule/silence/config 변경의 application audit은 없다. | GAP-SECURITY |
| FA-33 | SSRF 방어 | 미구현 | synthetic URL fetch 기능 자체가 없어 현재 직접 sink는 없지만, allow/deny resolver나 redirect 재검증 모듈도 없다. 기능 추가 전에 선행 구현해야 한다. | GAP-SECURITY |
| FA-34 | API key와 secret 저장 | 부분 통과 | secret file 크기·mode·nofollow 검사와 local scrypt hash가 있다(`server/config.ts:90-117`, `server/password-store.ts:83-94`). API key scope/hash/expiry/rotation이 없고 env secret fallback도 허용한다. | GAP-SECURITY |
| FA-35 | 시계열 파티셔닝 | 부분 통과 | 일자별 `history/YYYY-MM-DD.jsonl`로 나뉜다(`ops/collector.py:4883-4891`). host/metric partition, index, compaction manifest와 DB query plan은 없다. | GAP-STORAGE |
| FA-36 | retention과 downsampling | 부분 통과 | 30일/일 2,000행 retention과 API 최대 360 point downsampling이 있다(`README.md:539-569`; `server/data.ts:23-25,1536`). 장기 multi-resolution rollup과 per-tenant 정책은 없다. | GAP-STORAGE |
| FA-37 | cardinality 보호 | 통과 | compose/project/service와 traffic app을 고정 allowlist label로 축약하고 raw container/process identity를 공개하지 않는다(`ops/collector.py:123-187,1609-1618`; `README.md:630-650`). | — |
| FA-38 | 중복 데이터와 역순 데이터 | 부분 통과 | pending journal digest와 exact replay dedup, API timestamp sort/동일 timestamp merge가 있다(`ops/collector.py:4157-4201`; `server/data.ts:1505-1516`). 다중 agent idempotency key와 일반 out-of-order ingest 정책은 없다. | GAP-STORAGE |
| FA-39 | backpressure | 부분 통과 | input byte/record caps, Docker stats worker/deadline, updater queue depth 8이 있다(`ops/collector.py:1709-1735`; `ops/monitor_update_gateway.py:26-28,191-205`). 중앙 ingest queue/agent shedding/drop accounting은 없다. | GAP-STORAGE |
| FA-40 | DB 백업과 실제 복구 | 미구현 | 운영 DB가 없고 telemetry/ledger 전체 백업·복구 자동화와 복구 시험이 없다. local auth hash만 별도 backup/restore를 지원한다(`ops/monitor_auth_state.py:282-322`). | GAP-STORAGE |
| FA-41 | 에이전트 오프라인 버퍼 | 미구현 | 중앙 전송 agent가 없고 실패한 수집 구간은 재생되지 않는다. | GAP-STORAGE |
| FA-42 | 에이전트 자체 자원 사용량 | 부분 통과 | systemd MemoryHigh/Max/TasksMax와 nice/I/O priority가 있다(`ops/systemd/monitor-collector.service:47-57`; exporter `:42-50`). 실제 CPU/RSS/write amplification budget 계측은 없다. | GAP-STORAGE |
| FA-43 | amd64·arm64 빌드 | 부분 통과 | Python/Node 구현은 아키텍처 중립이고 base image는 digest pin이다. CI는 `ubuntu-24.04-arm`, `linux/arm64`만 빌드한다(`.github/workflows/deploy.yml:24-25,76-88`). amd64 gate와 multiarch manifest가 없다. | GAP-DELIVERY |
| FA-44 | Docker Compose 배포 | 부분 통과 | Compose 설정과 CI config 검증, `deploy monitor <sha>` 요청은 있다(`docker-compose.yml`; `.github/workflows/deploy.yml:56-64,90-123`). 실제 production compose/dispatcher/rollback 코드는 저장소 밖이어서 전체 검증은 불가다. | GAP-DELIVERY |
| FA-45 | 부하 테스트 | 미구현 | 목표 규모와 2배 규모 workload, ingest/API p95/memory/alert lag 측정 도구가 없다. | GAP-TEST |
| FA-46 | 네트워크 단절 테스트 | 미구현 | latency/loss/DNS/disconnect/duplicate/reorder 후 복구 시험이 없다. | GAP-TEST |
| FA-47 | 디스크 부족 테스트 | 부분 통과 | updater free-space preflight 단위 테스트만 있다(`ops/monitor_update_worker.py:1294-1310`; `ops/tests/test_monitor_update_worker.py:697`). collector/export/API의 ENOSPC/inode/PID/FD 고갈 시험은 없다. | GAP-TEST |
| FA-48 | clock skew 테스트 | 부분 통과 | API가 60초보다 먼 미래 표본을 제외하고 container snapshot도 -60초 future bound를 둔다(`server/data.ts:1492-1504`; `ops/collector.py:1806-1808`). skew 탐지·보정·복구 후 중복 시험은 없다. | GAP-TEST |
| FA-49 | 모니터링 시스템 자체 모니터링 | 부분 통과 | `/healthz`, telemetry 기반 `/readyz`, collector gap, monitor container 관측이 있다(`server/app.ts:124-134`; `ops/collector.py:1886-1889`). ingest lag/queue/evaluator/delivery failure와 외부 관점 가용성은 없다. | GAP-SELF |
| FA-50 | 외부 dead man's switch | 미구현 | 내부 collector-gap만 있고 외부 서비스로 보내는 heartbeat와 부재 경보가 없다. | GAP-SELF |

## 미충족 갭 레지스터

각 매트릭스 행의 `갭`은 아래 한 항목에 연결된다. 이 레지스터가 부분 통과·미구현 항목의 위험, 재현, 구현, 시험 및 완료 조건을 제공한다.

### GAP-FLEET — 등록·heartbeat·상태 의미

- **관련 요구사항:** FA-01~03, Monitor.md 2-1/2-5, 8-3, 9-10, 11-3/11-5/11-9.
- **근거:** `current.json`은 단일 host snapshot이며 `hostId`, `agentId`, server-received time이 없다. API는 응답 전체에 Boolean `stale` 하나만 둔다.
- **실제 위험:** hostname 재사용·복제 호스트가 하나로 보일 수 있고, agent 단절·collector 실패·특정 metric 미지원을 구분하지 못한다. 마지막 값이 남아 정상처럼 보일 수 있다.
- **재현/확인:** `rg -n "hostId|agentId|permission.denied|unsupported" ops/collector.py server src` 결과와 `server/types.ts:153-174` 응답 모델을 비교한다. collector를 6분 중단한 fixture에서는 전역 stale만 변하고 원인은 표현되지 않는다.
- **우선순위:** P0.
- **구현 계획:** owner-only 영속 UUID 기반 host/agent identity, `observedAt`/`receivedAt`, source별 `fresh|stale|no_data|unsupported|permission_denied|failed` 상태와 heartbeat sequence를 하위 호환 optional field로 추가한다.
- **테스트:** duplicate UUID/hostname 충돌, reboot, metric 일부 누락, permission error, delayed/out-of-order heartbeat를 가상 clock으로 검증한다.
- **완료 조건:** 동일 호스트 재등록은 idempotent하고 복제 host는 분리되며, UI/API가 0·unknown·no-data·stale·permission failure를 각각 표현한다.

### GAP-HOST — Linux·Raspberry Pi 신호 완전성

- **관련 요구사항:** FA-05~09, 기본 규칙 M18-20~34.
- **근거:** 현재 고정 sample에는 aggregate disk throughput/network error/drop/temperature만 있고 RAID/SMART/TCP/conntrack/FD/PID/systemd/clock skew 필드가 없다. `src/operational-health.ts:543-599`는 공급 전압만으로 경고를 만든다.
- **실제 위험:** 저장장치·TCP·systemd·자원 고갈을 사전 탐지하지 못하며 Pi 전압의 비공식 임계값으로 false positive가 발생한다.
- **재현/확인:** `rg -n -i "raid|smart|retrans|conntrack|systemd.*failed|clock.*skew" ops/collector.py server/types.ts`로 모델 부재를 확인한다. flags=0, voltage=4.70 fixture를 operational health에 넣으면 문서 정책과 달리 경고가 생긴다.
- **우선순위:** P0. RAID/SMART 상세는 권한·도구 검증 후 P1로 분리 가능하지만 “미지원” 상태는 P0다.
- **구현 계획:** procfs/sysfs 기반 안전 신호부터 fixed schema로 추가하고 privileged command는 strict allowlist/helper로 격리한다. Pi 상태는 hwmon/kernel authoritative condition만 경고에 사용하고 voltage는 evidence로만 둔다.
- **테스트:** Ubuntu cgroup v1/v2 fixture, amd64/arm64, Pi sysfs supported/unsupported/permission denied, counter reset, disk/TCP fixture 및 전압-only non-alert 회귀 테스트.
- **완료 조건:** 기본 규칙 20~34 각각에 signal availability·permission·unsupported 상태와 versioned rule 정의가 있고 단일 샘플/unknown으로 오경보하지 않는다.

### GAP-DOCKER — daemon·event·container identity와 자원

- **관련 요구사항:** FA-10~19, 기본 규칙 M18-40, M18-44~50.
- **근거:** `container_from_api()`의 public row는 7개 field뿐이고 event/inspect/image/volume/security metadata가 없다.
- **실제 위험:** restart loop, OOMKilled, throttle, no-limit, privileged/socket mount, writable layer, digest drift를 탐지할 수 없다. fixed display name은 재생성 lifecycle을 연결하지 못한다.
- **재현/확인:** `ops/collector.py:1649-1657,1817-1853`와 Monitor.md 기본 container rule 35~53을 field-by-field 비교한다.
- **우선순위:** P0.
- **구현 계획:** unprivileged exporter 내부에서 inspect/event/stats를 즉시 privacy-reduced booleans/counters/digests로 변환한다. private runtime에는 daemon/container cursor를 두되 public API에는 stable Compose identity와 digest만 노출한다.
- **테스트:** restart/OOM/unhealthy/no-healthcheck/no-limit/privileged/socket/digest fixtures, daemon restart, socket permission loss, event reconnect replay와 200-container cap.
- **완료 조건:** 10~19 및 기본 container rules가 각자 required signal과 unknown semantics를 가지며 raw mounts/env/command/container ID는 공개 export에 없다.

### GAP-LOG — 범용 로그 파이프라인

- **관련 요구사항:** FA-20~22, Monitor.md 7-1~10.
- **근거:** 세 semantic JSONL export만 존재하고 multiline/live stream/search storage가 없다.
- **실제 위험:** 애플리케이션 stack trace와 Docker/journald 장애 증거가 사라지고 폭증 시 cursor jump로 버린 양을 알 수 없다.
- **재현/확인:** 1MiB보다 큰 unconsumed fixture 또는 128KiB 초과 line을 `read_new_lines`에 입력해 output과 cursor를 비교한다. Docker/journald source adapter/API route 부재를 검색한다.
- **우선순위:** P0은 source 상태·multiline bound·drop accounting·수집단계 masking, P1은 tail/search, P2는 trace/bundle.
- **구현 계획:** source별 cursor/status, bounded JSON/logfmt/syslog/plain/multiline parser, pre-storage redaction version, quota/sampling/drop counters를 추가한다. raw retention은 최소 권한의 별도 저장소로 격리한다.
- **테스트:** rotation/recreation, partial tail, 10만-line storm, multiline max lines/bytes, JWT/cookie/card masking, slow live-tail client backpressure.
- **완료 조건:** supported sources에서 loss/duplicate/drop count가 측정되고 secret 원문이 저장 전에 제거되며 한 source 폭증이 telemetry를 중단시키지 않는다.

### GAP-ALERT — 규칙·평가·억제·전송

- **관련 요구사항:** FA-23~29, Monitor.md 8-1~16, 18장 82-rule pack.
- **근거:** `incident_transition()`은 7개의 코드 상수 reason만 처리하며 rule CRUD/version/channel/outbox가 없다. CPU 기본 `warn_samples=1`은 단일 샘플 금지와 모순된다.
- **실제 위험:** 일시 spike 오경보, host down 시 하위 alert 폭주, maintenance 중 전송, 채널 장애 시 영구 유실이 발생한다.
- **재현/확인:** `server/app.ts`의 route 목록에 rule/silence/delivery endpoint가 없고 `INCIDENT_REASONS`가 7개인지 확인한다. 한 CPU high sample로 active incident가 생성되는 단위 fixture가 현재 동작이다.
- **우선순위:** P0.
- **구현 계획:** versioned rule seed, validated rule model, virtual-clock evaluator, durable pending/firing/recover state, no-data policy, topology inhibition, silence, dedup group과 bounded delivery outbox를 단계적으로 추가한다.
- **테스트:** duration 중 missing evaluation, hysteresis/recovery duration, dedup window, parent down/recovery reevaluation, silence expiry, retry exponential backoff+jitter, idempotency key와 crash replay.
- **완료 조건:** 기본 pack이 코드 상수가 아닌 versioned data이고 82개 rule마다 support/permission/no-data/runbook metadata가 있으며, 전송 실패가 평가기를 막지 않고 최종 실패가 조회된다.

### GAP-INCIDENT — 통합 사건 시간축

- **관련 요구사항:** FA-30, Monitor.md 7-8, 8-14, 10-1~5.
- **근거:** incident capture와 alert/reliability/power/privilege log가 별도 배열과 화면이다.
- **실제 위험:** 원인·배포·조치·알림 발송을 한 시간축에서 상관 분석할 수 없고 MTTA/MTTR을 계산할 근거가 없다.
- **재현/확인:** 동일 timestamp의 incident와 privilege fixture를 API에 넣어도 하나의 correlation ID/timeline으로 묶이지 않는다.
- **우선순위:** P1(알림 엔진 이후).
- **구현 계획:** immutable event envelope과 incident correlation/ack/assignee/note 모델을 추가하고 원본 entity link를 보존한다.
- **테스트:** out-of-order event, duplicate delivery, actor authorization, incident merge/close/reopen, reload-safe UI link.
- **완료 조건:** metric/log/container/deploy/action/delivery event가 한 incident에 traceable하고 모든 사용자 조치가 audit된다.

### GAP-SECURITY — scope·API key·감사·SSRF

- **관련 요구사항:** FA-31~34, Monitor.md 13-1~10.
- **근거:** 역할 gate와 secret file 보호는 있으나 resource scope/API key/application audit/SSRF policy/threat model이 없다.
- **실제 위험:** 모든 dashboard-entitled 사용자가 동일 telemetry/log 범위를 보고 자동화 인증을 안전하게 분리할 수 없다. 향후 synthetic fetch 추가 시 SSRF가 열릴 수 있다.
- **재현/확인:** 일반 user가 dashboard의 privilege/log payload를 읽을 수 있고 API key route/storage가 없다. application mutation 뒤 audit file 변화가 없다.
- **우선순위:** P0.
- **구현 계획:** central subject 기반 team/resource scopes, backend permission middleware, hashed/scoped/expiring API keys, append-only application audit, encrypted secret provider abstraction과 SSRF-safe resolver를 구현한다. threat model을 함께 유지한다.
- **테스트:** horizontal/vertical privilege escalation, forged edge headers, scope isolation, key expiry/revoke/rotation, audit tamper, DNS rebinding/redirect/private IP SSRF, XSS/log injection.
- **완료 조건:** 권한은 모든 API에서 entity scope로 강제되고 민감 mutation은 immutable audit를 남기며 API key 원문은 발급 시 한 번만 표시된다.

### GAP-STORAGE — 내구성·backpressure·복구

- **관련 요구사항:** FA-35~42, Monitor.md 11-5/11-6, 12-1~10, 15-12.
- **근거:** single-host JSON/JSONL과 crash journal은 강하지만 중앙 ingest DB/queue/offline buffer/전체 백업 복구는 없다.
- **실제 위험:** collector가 멈춘 구간은 영구 공백이고 여러 host로 확장할 수 없다. 파일 손상·storage loss 후 복구 목표가 없다.
- **재현/확인:** collector를 여러 interval 중지했다 재시작하면 공백 표본을 backfill하지 않는다. export directory를 새 fixture로 바꾸면 restore source가 없다.
- **우선순위:** P0은 상태 semantics/ENOSPC 안전 저하/backup proof, multi-host DB는 P1.
- **구현 계획:** 현재 atomic file journal을 유지하며 manifest/checksum/backup restore harness와 bounded local spool을 먼저 추가한다. multi-host가 필요할 때 metadata와 timeseries를 분리하고 dual-write/migration gate를 둔다.
- **테스트:** crash at every fsync boundary, ENOSPC/inode/FD/memory, duplicate/out-of-order batch, spool overflow policy, backup checksum과 clean-host restore.
- **완료 조건:** 문서화된 RPO/RTO를 실제 restore test가 만족하고 overflow/drop가 계측되며 재시작 후 idempotent replay된다.

### GAP-DELIVERY — 아키텍처·Compose 배포 증거

- **관련 요구사항:** FA-43~44, Monitor.md 11-1, 15-7/10/11, 17-2.
- **근거:** CI는 arm64 단일 build이고 실제 dispatcher/production compose가 저장소 외부다.
- **실제 위험:** amd64 회귀와 platform별 image 차이를 알 수 없고 rollback 성공을 저장소 CI가 증명하지 못한다.
- **재현/확인:** workflow의 `platforms: linux/arm64`와 실행 runner를 확인하고 GHCR manifest에 amd64가 없음을 release gate에서 검사한다.
- **우선순위:** P0.
- **구현 계획:** amd64/arm64 test-build matrix, multiarch manifest 및 platform digest/SBOM artifact, Compose contract test, canary readiness와 rollback readback을 추가한다.
- **테스트:** 두 architecture image에서 test/health/collector fixture, bad image/failed readiness/rollback, old/new API compatibility.
- **완료 조건:** 두 platform digest와 SBOM이 보관되고 실패 배포가 이전 immutable image로 복구됐음을 CI artifact가 증명한다.

### GAP-TEST — 부하·장애 주입·clock skew

- **관련 요구사항:** FA-45~48, Monitor.md 15-3~9.
- **근거:** unit/integration fixture는 풍부하지만 load/E2E/axe/network/resource/cgroup matrix tooling은 없다.
- **실제 위험:** 256MiB container에서 큰 동기 JSON read, reconnect storm, ENOSPC, skew가 운영에서 처음 검증된다.
- **재현/확인:** `package.json:9-31`과 workflow에 load/E2E/security/perf job이 없음을 확인한다.
- **우선순위:** P0.
- **구현 계획:** 목표 규모를 먼저 고정하고 API p95/RSS/write/alert lag budget, deterministic fault injection, browser E2E/axe를 CI와 scheduled job으로 나눈다.
- **테스트:** 2배 target load, simultaneous reconnect, tc/netem or protocol fake, disk/inode/FD/PID/memory exhaustion, ±clock skew, cgroup v1/v2, slow browser.
- **완료 조건:** 예산과 실패 기준이 versioned artifact로 남고 초과 시 gate가 실패하며 테스트를 skip해 통과시킬 수 없다.

### GAP-SELF — 자체 모니터링과 외부 dead man

- **관련 요구사항:** FA-49~50, Monitor.md 8-16, 12-10, 기본 규칙 75~82.
- **근거:** local readiness와 collector gap만 있으며 외부 heartbeat/ingest/evaluator/delivery metrics가 없다.
- **실제 위험:** Monitor와 동일 host·Nginx·SSO가 함께 장애 나면 내부 화면은 경고를 전달할 수 없다.
- **재현/확인:** Monitor container와 Nginx를 함께 격리하면 외부 수신자에게 생성되는 heartbeat-missing alert가 없다.
- **우선순위:** P0은 외부 heartbeat와 core internal metrics, SLO burn은 P2.
- **구현 계획:** collector duration/failure, API latency/error, storage usage, evaluator lag, outbox depth/delivery failure를 노출하고 독립 외부 endpoint에 dead-man heartbeat를 보낸다.
- **테스트:** service/host/network/SSO 동시 장애와 missed-heartbeat alert/recovery, duplicate heartbeat idempotency.
- **완료 조건:** Monitor 전체 경계 밖에서 heartbeat 부재가 탐지되고 자체 장애가 일반 대상 장애와 구별되어 전달된다.

## 즉시 중단 조건

다음 중 하나라도 참이면 운영 완료로 표시하지 않는다.

1. GAP-ALERT의 versioned rule/evaluator/outbox 없이 UI finding을 “알림 시스템”으로 부르는 경우.
2. GAP-FLEET의 상태 의미 없이 `null` 또는 마지막 값을 정상으로 해석하는 경우.
3. 공급 전압 단일 값으로 저전압 장애를 확정하는 현재 모순이 남은 경우.
4. amd64와 arm64 중 한쪽만 빌드·실행 검증한 이미지를 multi-architecture 지원으로 표시하는 경우.
5. 실제 restore와 rollback readback 없이 백업·배포 복구를 통과 처리하는 경우.
