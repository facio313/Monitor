# Monitor 구현 증분 감사 — 2026-08-31

> 기준선: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 대상: 이 문서를 포함하는 후속 커밋
> 범위: `/home/cks/Monitor`만 해당한다. 다른 저장소나 서비스는 포함하지 않는다.

## 결론

이번 증분은 기존 단일 호스트 Monitor의 가장 위험한 거짓 정상과 부분 실패
경로를 줄였다. Docker 수집 실패가 호스트 표본을 막지 않게 분리했고, Docker
관측 상태를 fresh/last-known/unavailable/permission-denied로 명시했으며,
inspect 기반 생명주기·health·limit 증거를 축약 계약으로 연결했다. 여기에
stable random host/agent UUID, 사설 machine-id hash binding과 clone rekey,
축약된 공개 boot digest, monotonic heartbeat sequence/expected interval/lifecycle
계약을 추가했다. API와 화면은 heartbeat, Docker source status, 규칙 평가를
전체 운영 판정에 연결하며, 장식용 canvas는 overview에서 제거됐다. 82개 기본
규칙은 versioned data, restart-safe 평가 상태, bounded
transition log, strict API, 우선순위 UI까지 실제 production graph에 들어갔다.
배포 CI는 amd64와 arm64를 같은 manifest로 만들고 두 플랫폼을 각각 검사한다.

이는 Monitor.md 전체 완료 선언이 아니다. local-file UUID/heartbeat는 여전히
동일-host 연속성 계약이지만, 별도의 default-off 중앙 경로에는 one-use
enrollment, trusted-proxy mTLS fingerprint binding/rotation/revocation, network
heartbeat, compressed batch admission, duplicate/out-of-order 정책과 encrypted
finite disk queue가 구현됐다. 별도 agent transport package도 stable batch,
bounded durable offline spool, mTLS/gzip/timeout/Retry-After/backoff/jitter와
one-use token 처리를 구현했지만 기존 local collector나 production unit에는
기본 연결하지 않았다. 외부 PKI/mTLS listener, 인증서 lifecycle 배포,
downstream queue consumer와 fleet 화면은 아직 없다. 이번 증분에는 Linux 세부 수집과
local export,
privacy-first file/journald 로그 파이프라인·탐색기, 그리고 별도 systemd worker가
drain하는 finite notification outbox까지 연결됐다. 규칙 CRUD/override, 반복
silence, Docker raw-log adapter, 전체 backup/restore 증명과 외부 synthetic은
여전히 구현되지 않았다. 기준선 분석 문서의 미구현 판정은 아래에서
명시적으로 승격한 범위 외에는 유효하다.

## 실제 연결된 변경

| 영역 | 이번 증거 | 현재 판정 |
| --- | --- | --- |
| local identity | schema-v2 snapshot이 stable UUIDv4 `hostId`/`agentId`, installation epoch와 generation을 공개한다. mode-0600 private state만 domain-separated machine-id SHA-256 binding을 보관하고, 검증 가능한 machine 변경 시 두 UUID를 재발급한다. | 단일-host identity continuity 통과; central 등록은 별도 opt-in path |
| boot/heartbeat | raw boot UUID 대신 domain-separated 128-bit digest를 공개한다. sequence state를 snapshot보다 먼저 durable하게 올리고 expected interval, observed/received time, lifecycle, `local-file` transport를 내보낸다. | local gap 관측 통과; optional central network receipt 구현, local collector 전송은 미구현 |
| agent API | exact identity/heartbeat를 검증하고 healthy/delayed/disconnected/maintenance/inactive/unknown/collection_error를 구분한다. legacy는 unknown, malformed partial contract는 collection_error다. | single-host status API 통과 |
| central agent control | 짧은 TTL/1회 token hash, keyed machine identity collision, proxy-verified certificate fingerprint binding/rotation/revoke, strict heartbeat/inventory와 admin fleet read를 encrypted atomic state로 구현한다. | server vertical slice 통과; PKI/proxy와 remote installer는 외부 의존 |
| central ingest | gzip/size/record caps, agent+batch/record content idempotency, sequence reorder counter, clock-skew/backfill policy, event reserve와 heartbeat bypass를 가진 encrypted finite queue를 구현한다. | admission/backpressure 통과; downstream time-series consumer/load proof는 미구현 |
| agent transport package | exact private config/credential 검증, one-use enrollment token stdin/private-file 처리, reduced inventory, stable immutable batch와 bounded mode-0600 spool, mTLS/gzip/timeout/Retry-After/backoff/jitter를 구현한다. | client transport vertical slice 통과; collector adapter·installer enablement·실제 PKI 상호운용은 미구현 |
| Linux telemetry | CPU/core mode·freq, memory/swap/vmstat/PSI, filesystem/inode/RO, block I/O, NIC/TCP, bounded process/PID/FD/cgroup, allowlisted systemd, thermal/RPi, boot/time/kernel 상태를 `current.linux`와 private delta에 연결했다. | collector/export slice 통과; server API와 전용 UI는 아직 연결되지 않았고 SMART/drift 등 privileged 외부 신호는 explicit unsupported |
| generic logs | exact root-owned allowlist의 file/journald 입력을 bounded tail/cursor로 읽고 pre-parse credential/PII redaction, priority quota, source/drop status, crash-safe record→status→cursor commit을 적용했다. 인증 API와 action-first explorer는 digest-bound pagination을 쓴다. | file/journald end-to-end 통과; Docker acquisition adapter는 미구현 |
| notification delivery | deterministic event/channel key를 가진 finite SQLite outbox, lease/crash recovery, timeout·retry/backoff/jitter, final-failure/drop counters와 webhook/Slack/Discord/Telegram/TLS-SMTP adapter를 별도 network-capable systemd worker에 연결했다. | async delivery vertical slice 통과; 실제 channel secrets/config와 receiver idempotency는 운영 의존 |
| Docker 부분 실패 | exporter unit은 `Wants`, reduced snapshot bind는 optional이다. 실패 원인은 typed source status가 되고 host current/history publication은 계속된다. | P0 단일-host 경로 통과 |
| Docker v2 | current row는 정확히 17필드이며 inspect 30, stats 30, worker 6, 전체 20초, list 1 MiB/detail 256 KiB로 제한된다. | lifecycle 핵심 부분 통과 |
| lifecycle 정확도 | restart total/delta, OOM, start/finish, healthcheck support, memory/CPU/PID limit을 identity-bound inspect에서 축약한다. raw ID는 private mode-0600 state에만 있다. | FA-13~16 부분 승격 |
| legacy/incident | legacy 7필드는 project·health/lifecycle/limit을 추정하지 않고 null로 승격한다. incident는 의도적으로 기존 7필드 projection을 유지한다. | 호환/개인정보 경계 통과 |
| rules | Monitor.md의 82개 ID를 고정 순서의 strict JSON pack으로 제공한다. threshold/recovery, severity, samples, no-data, parent, labels, description/runbook, enabled를 검증한다. | seed pack 부분 통과 |
| evaluator | pending/firing/recovering/recovery, hysteresis, independent no-data, parent suppression, silence disposition, gap reset과 deterministic transition identity를 구현한다. | FA-33~37 부분 승격 |
| persistence | event-before-private-state-before-public-evaluation 순서, replay dedup, atomic bounded files, explicit collection_error를 적용한다. | local crash safety 통과 |
| API | identity/heartbeat, container source, evaluation과 transition을 strict schema/size/path/mode 검증 후 반환한다. rule transition은 legacy alert와 분리되고 malformed partial input은 collection_error다. | single-host read API 통과 |
| overall 판정 | non-healthy heartbeat, non-fresh Docker collection, firing/recovering rule과 evaluator coverage failure가 operational findings와 상단 overall에 들어간다. Docker unavailable/permission-denied는 서비스 0개 정상으로 표시하지 않는다. | 거짓 nominal 핵심 경로 축소 |
| 화면 구성 | 시스템 strip → operational health → rule evaluator → widgets 순서다. 장식용 canvas와 그 overview 공간을 제거했다. | action-first composition 부분 승격 |
| release | pinned actions, Node 22.23.2, type/test/audit gates, amd64+arm64 manifest, provenance/SBOM, 플랫폼별 Trivy critical gate를 둔다. | source gate 통과; 실제 run은 배포 readback 필요 |

## 로컬 identity 및 heartbeat 공개 계약

`current.json`의 top-level은 schema version 2이며 `schemaVersion`,
`generatedAt`, `identity`, `heartbeat`, 기존 host/telemetry/source 필드를 가진다.

```text
identity: hostId, agentId, installationEpoch, identityGeneration,
          machineIdentityStatus, bootId
heartbeat: sequence, observedAt, receivedAt, expectedIntervalSeconds,
           lifecycle, transport
```

- `hostId`와 `agentId`는 서로 독립적인 UUIDv4이며 보통의 collector 재시작과
  host reboot에서 유지된다. `bootId`는 raw Linux boot UUID가 아니라 별도
  namespace의 32-hex BLAKE2s digest다.
- `.state/collector-identity.json`만 exact-schema mode-`0600` state, sequence와
  domain-separated machine-id SHA-256 hash를 보관한다. raw machine-id와 그 hash는
  공개 export/API에 없다.
- 이전·현재 hash가 모두 유효하고 다르면 copied state로 판단해 host/agent ID를
  모두 다시 만들고 generation을 올리며 sequence와 installation epoch를
  재시작한다. `unavailable`은 아직 valid binding이 한 번도 생기지 않았다는
  뜻이다. 현재 machine-id를 일시적으로 읽지 못해도 기존 binding은 보존되지만,
  clone 비교에는 이전·현재 hash가 모두 필요하다. unsafe mode/link/size/schema는
  조용히 재발급하지 않고 collection을 fail closed한다.
- local sequence state는 matching snapshot 전에 기록된다. 이후 publication 실패는
  번호 재사용 대신 gap으로 남는다. local history row에는 sequence가 없다. 별도
  central ingest v1은 agent/batch/record sequence와 idempotency를 저장하지만 현재
  collector가 그 API로 전송하지는 않는다.
- 현재 transport는 `local-file`이고 `receivedAt == observedAt`이다. 이는 원격
  receipt가 아니다. expected interval은 기본 60초, 10~86,400초로 제한된다.
  lifecycle은 host 설정의 `active|maintenance|inactive`이며 관리 API, 승인,
  변경 이력 또는 fleet lifecycle이 아니다.
- active status는 age가 `max(90초, 2 × expected interval)`을 넘으면 delayed,
  `max(application stale threshold, 5 × expected interval)`을 넘으면
  disconnected다. 명시적 maintenance/inactive가 age보다 우선하며, legacy
  snapshot은 unknown이고, local-file의 generated/observed/received 시각이
  다르거나 불완전·extra-field·invalid contract이면 collection_error다.

## Docker 공개 계약

현재 row의 필드 순서는 다음과 같다.

```text
name, project, owner, state, health, healthcheckConfigured,
cpuPercent, memoryBytes, memoryPercent, memoryLimitBytes, cpuLimitCores,
pidLimit, restartCount, restartCountDelta, oomKilled, startedAt, finishedAt
```

- resource limit `0`은 명시적인 unlimited, `null`은 미확인/비지원/검증 실패다.
- fresh가 아닌 source에서는 restart delta나 last-known 값을 현재 증거로 평가하지
  않는다.
- configured PID limit은 있지만 current PID usage는 없으므로
  `ContainerPidNearLimit`은 unsupported다.
- security, socket mount, image digest/tag, writable layer와 container network
  신호도 아직 unsupported다.
- 공개 stable instance ID가 없으므로 replica는 `(project, name)` multiset이며,
  삭제·재생성 lifecycle을 장기 연결하지 못한다.

## 규칙 시스템의 남은 경계

현재 pack은 실행 가능한 표현식이나 사용자 편집 모델이 아닌 안전한 seed data다.
Monitor.md 18장이 요구하는 가능한 원인, 확인 항목, dashboard link, 지원 환경,
필요 권한, 사용자별 override는 아직 별도 구조 필드가 아니다. 현재 silence는
평가 API에 전달할 수 있는 bounded one-shot model일 뿐 CRUD, 반복 일정,
유지보수 창 UI가 없다. notification state의 ready 항목은 별도 finite outbox로
라우팅되고 email/Slack/Discord/Telegram/webhook adapter가 retry/backoff/jitter와
delivery log를 처리한다. suppressed/silenced는 기록만 하고 큐에 넣지 않는다.
원격 수락 뒤 local ack 전에 worker가 중단되면 at-least-once 재전송될 수 있으므로
transition 생성이나 enqueue 성공을 수신자 exactly-once 성공으로 해석하면 안 된다.

## 검증 증거와 범위

최신 전체 worktree에서 identity/heartbeat, Linux telemetry, generic log,
notification outbox/worker, central admission과 agent transport를 함께 포함한
전체 회귀를 다시 실행했다.

- Python: `python3 -m unittest discover -s ops/tests -p 'test_*.py'` — 321/321
- TypeScript/Vitest: 30 files, 250/250
- client/server TypeScript typecheck — 통과
- Vite client와 server production build — 통과
- `npm audit --audit-level=critical` — 모든 severity 0 vulnerabilities
- SSO `main`과 fixture `ci/local` Compose config — 통과
- tracked shell syntax, Python byte compilation, JSON examples, 전체 systemd unit,
  branch/auth contract와 `git diff --check` — 통과
- retained Chromium evidence는 generic log 화면 추가 전 overview까지만 다룬다.
  현재 Logs UI는 자동화된 반응형 구성·accessible-name·필터/재시도 회귀를
  통과했으며, 새 화면의 fresh browser screenshot 검증은 별도 후속 증거로 남긴다.

central 경로의 focused 검증도 별도로 실행했다.

- agent control 보안/통합 focused Vitest — 28/28
- standalone agent transport — 21/21
- generic log pipeline/store/collector/transport focused Python — 58/58

로컬 Node 18에서 Vite가 Node 20.19+/22.12+ 권장 경고를 냈지만 build는
성공했다. CI와 image build는 존재가 확인된 Node 22.23.2로 고정되어 있다.

## 다음 P0

1. external CA/mTLS listener와 header stripping을 배포하고 인증서 폐기 readback
2. agent transport를 collector output adapter와 systemd installer에 opt-in 연결하고 실제 CA/certificate로 enrollment·rotation·offline replay 상호운용 증명
3. encrypted ingest queue consumer, claim/ack, time-series partition과 부하/복구 증명
4. 관리자 agent lifecycle 승인/감사와 fleet 화면 상태 전파
5. full rule metadata, validated CRUD/version history와 scoped override
6. recurring silence/maintenance window, grouping/dedup과 deterministic routing
7. production delivery channel config/secrets, receiver idempotency와 delivery readback
8. clean-host backup restore와 immutable deployment rollback proof
9. external dead-man synthetic와 evaluator/queue/delivery 자체 계측

각 항목은 failure injection과 운영 readback이 생기기 전까지 완료로 승격하지
않는다.
