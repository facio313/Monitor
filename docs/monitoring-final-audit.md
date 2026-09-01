# Monitor 운영 투입 전 최종 감사

> 감사 기준일: 2026-08-31
> 기준 명세: `/home/cks/Monitor.md` 21장의 최종 감사 50항목
> 코드 기준: 이 문서를 포함하는 현재 worktree. 최종 커밋, 원격 CI, 배포 readback은 아직 감사 증거가 아니다.

## 결론

현재 판정은 **통과 14개, 부분 통과 36개, 실패 0개, 미구현 0개, 검증 불가 0개**다.
이번 구현은 Linux 상세 진단, Docker v4 및 event stream, 합성 검사, 로그·규칙·전송,
애플리케이션 API key·감사, 암호화 백업, opt-in 중앙 agent 경로, 복원력 gate와
외부 dead-man을 실제 실행 경로로 만들었다. 그러나 중앙 agent/PKI, 알림 채널,
합성 timer는 기본 운영 경로에서 명시적으로 꺼져 있거나 운영 설정이 필요하고,
전체 백업 범위·실복구, 원격 CI·multiarch image, 최종 배포·rollback, 외부 workflow
실행은 아직 readback이 없다. 코드 존재와 운영 완료를 같은 뜻으로 사용하지 않는다.

## 판정 원칙과 운영 증거

| 상태 | 이 문서의 의미 |
| --- | --- |
| 통과 | 해당 FA 항목의 핵심 수집·계약·실패 의미·표시·회귀 테스트가 현재 코드 경로에 연결되어 있다. |
| 부분 통과 | 유효한 구현은 있으나 명세 범위, 기본 enablement, 운영 설정, 장애 주입 또는 실환경 readback 중 하나 이상이 남았다. |
| 실패 | 연결된 구현이 명세의 안전성·정확성 조건과 직접 모순된다. |
| 미구현 | 실행 경로 또는 데이터 모델이 없다. |
| 검증 불가 | 필요한 구현이 저장소 밖에만 있고 현재 증거로 판정할 수 없다. |

감사 시 확인된 운영 증거는 공개 `GET /monitor/readyz`의 exact `200
{"status":"ready"}`·`Cache-Control: no-store`와 `/monitor/`의 same-origin SSO
redirect까지다. 저장소에는 이를 검증하는
`.github/workflows/external-monitor.yml`, `scripts/check-public-monitor.mjs`,
`ops/nginx/monitor-public-readiness.conf`가 있다. API-key 전용 Nginx alias,
Cloudflare real-IP 경계와 header stripping도
`ops/nginx/monitor-api-key-*.conf`에 구현되어 실행형 TLS Nginx 시험을 통과했다.
그러나 현재 원본 Nginx는 HTTP만 수신하므로 bearer 기밀성 전제에 맞지 않아 운영
include를 의도적으로 제거했다. alias는 SSO 뒤에 있으며, 원본 TLS·Cloudflare Full
(strict)·원본 방화벽을 입증하기 전에는 실제 bearer 요청을 운영 증거로 만들지 않는다.
다음은 아직 완료 증거로 사용하지 않았다.

- 현재 worktree 전체 회귀, 최종 커밋과 원격 CI 결과
- 새 multiarch image digest·SBOM·취약점 scan과 production revision 일치
- 새 코드가 동작하는 container의 health/readiness 및 rollback readback
- 실제 delivery channel secret/수신자와 agent CA·mTLS listener·certificate lifecycle
- production state의 암호화 off-host copy, verify, clean-host restore와 애플리케이션 readback
- GitHub-hosted dead-man workflow의 실제 실패 issue 생성 및 회복 close run

`ops/systemd/monitor-synthetic-probe.timer`, `monitor-agent-producer.timer`,
`monitor-agent-transport.timer`는 설계상 default-off다. 이 상태를 “배포됨”으로
해석하지 않는다.

## 50항목 추적 매트릭스

| ID | 점검 항목 | 상태 | 현재 코드·설정 증거와 경계 |
| --- | --- | --- | --- |
| FA-01 | 호스트 등록과 중복 식별 | 부분 통과 | `ops/collector.py`의 stable host/agent UUID와 clone rekey, `server/agent-control.ts`의 one-use enrollment·collision 방지는 있다. 중앙 경로는 default-off이며 실제 fleet/PKI가 없다. |
| FA-02 | 에이전트 heartbeat 정확도 | 부분 통과 | local monotonic heartbeat와 중앙 network heartbeat 계약은 있으나 기본 collector는 `local-file`이며 실제 원격 receipt가 아니다. |
| FA-03 | 데이터 지연과 데이터 없음 구분 | **통과** | `server/data.ts`, `server/types.ts`, `src/collection-status.ts`가 source별 fresh/stale/no-data/unsupported/permission/error와 heartbeat 상태를 구분한다. |
| FA-04 | CPU, 메모리, swap, PSI | **통과** | `ops/linux_telemetry.py`가 CPU/core, memory/vmstat, swap, CPU·memory·I/O PSI를 수집하고 API/UI/rule로 연결한다. |
| FA-05 | 디스크 용량, inode, I/O latency | **통과** | filesystem 용량·inode·RO와 block device latency/queue/utilization/rate를 `current.linux`와 `LinuxDiagnosticsPanel`에 연결한다. |
| FA-06 | 네트워크 오류와 TCP 상태 | **통과** | NIC 오류/drop/link와 TCP retransmit/state, ephemeral port, conntrack를 bounded schema와 rule/UI로 제공한다. |
| FA-07 | 프로세스와 systemd 서비스 | **통과** | command-line 비수집 allowlist process와 allowlist systemd 상태·restart/invocation, PID/FD/cgroup headroom이 연결된다. |
| FA-08 | OOM과 커널 이벤트 | 부분 통과 | OOM/panic/oops/hung/RCU/filesystem/NVMe 이벤트와 source 상태는 있으나 kernel 전용 수집은 고정 로그 중심이며 모든 journald/systemd/watchdog/segfault 경로를 포괄하지 않는다. |
| FA-09 | Raspberry Pi 온도, throttling, 저전압 | **통과** | `ops/linux_telemetry.py`와 rule/UI가 firmware·hwmon의 authoritative flag와 unsupported를 보존하고 전압만으로 상태를 발명하지 않는다. |
| FA-10 | Docker daemon 상태 | 부분 통과 | typed collection/event-source 상태와 daemon 불가 rule은 있으나 daemon lifecycle/version/복구 자체의 완전한 상태 모델은 없다. |
| FA-11 | Docker event stream | **통과** | `ops/collector.py`의 cursor/replay/reconnect/dedup/gap과 bounded privacy-reduced event, API/UI timeline이 연결된다. |
| FA-12 | 컨테이너 CPU, 메모리, I/O, 네트워크 | **통과** | 58-field Docker v4 row가 CPU/memory/PID/throttling/block/network total·rate와 reset semantics를 제공한다. |
| FA-13 | restart loop | 부분 통과 | restart total/delta·event와 duration rule은 있으나 exit code, 생존 시간, policy, manual/automatic 원인을 함께 판정하지 않는다. |
| FA-14 | OOMKilled | 부분 통과 | inspect OOMKilled와 `oom` event/rule은 있으나 cgroup memory event 및 OOM 직전 상관 증거 bundle이 불완전하다. |
| FA-15 | healthcheck | 부분 통과 | configured/healthy/unhealthy/unknown과 duration/recovery rule은 있으나 연속 실패 수·bounded output·최근 성공/실패 시각은 없다. |
| FA-16 | limit 대비 사용률 | 부분 통과 | CPU/memory/PID limit, throttling, no-limit 판정은 있으나 reservation/cpuset/memory event/host보다 큰 limit 검증은 없다. |
| FA-17 | Docker Compose 프로젝트 그룹 | 부분 통과 | project/service identity, group/UI 및 digest 혼재는 있으나 replica desired state·배포 의도·project aggregate 전체가 없다. |
| FA-18 | 볼륨과 writable layer | 부분 통과 | writable bytes와 volume/bind/tmpfs count는 있으나 실제 filesystem/inode 연결, orphan 탐지, 예상 회수량은 없다. |
| FA-19 | 이미지 digest drift | **통과** | image name/tag/digest/source, latest, same-service drift와 mutable-reference change가 수집·rule·UI에 연결된다. |
| FA-20 | 로그 수집과 멀티라인 파싱 | 부분 통과 | allowlist file/journald, JSON/logfmt/syslog/plain, bounded multiline와 explorer는 있으나 Docker stdout/stderr adapter는 explicit unsupported다. |
| FA-21 | 민감정보 마스킹 | **통과** | `ops/log_pipeline.py`의 pre-storage credential/PII/PEM redaction, exact public schema와 privacy 회귀가 fail closed한다. |
| FA-22 | 로그 폭증 제어 | **통과** | source/aggregate byte·line·record caps, priority quota, durable cursor, drop reason/count, retention이 연결된다. |
| FA-23 | 알림 지속 시간 | **통과** | rule pack과 `ops/alert_engine.py`가 elapsed duration과 sample count를 함께 요구하며 gap에서 pending을 reset한다. |
| FA-24 | hysteresis | **통과** | 별도 recovery threshold/time/sample과 pending/firing/recovering/resolved 상태가 restart-safe로 평가된다. |
| FA-25 | no-data와 stale-data | 부분 통과 | no_data/unsupported/permission 및 stale source는 보존되지만 어떤 rule에도 별도 stale threshold/action schema가 없고 stale은 no_data와 같은 branch/policy로 처리된다. |
| FA-26 | 알림 dedup | 부분 통과 | deterministic transition/delivery key와 retained delivery log가 재전송을 억제하지만 configurable label grouping/time window는 없다. |
| FA-27 | 상위 장애 기반 억제 | 부분 통과 | static parent suppression과 parent 회복 시 child의 restart-safe exactly-once ready release/outbox는 동작하지만 host→daemon→project/service→endpoint의 동적 topology/dependency model은 불완전하다. |
| FA-28 | silence와 유지보수 창 | 부분 통과 | private one-shot silence는 매 평가에 다시 읽히고 만료 시 활성 사건을 exactly-once release한다. 다만 CRUD·반복 일정·scope UI·감사 경로가 없다. |
| FA-29 | 알림 전송 retry | 부분 통과 | finite SQLite outbox와 lease/retry/backoff/jitter/final-failure, 5개 channel adapter는 있으나 production channel/readback이 없다. |
| FA-30 | incident 타임라인 | 부분 통과 | rule, Docker, host operational event를 같은 action-first 화면에서 볼 수 있으나 ack/담당자/메모/배포·조치의 완전한 incident 모델은 없다. |
| FA-31 | 사용자 인증과 RBAC | 부분 통과 | SSO user/admin/chief-admin, exact route gate와 API-key scope는 있으나 host/team/environment resource scope와 외부 IdP lifecycle 증거가 없다. |
| FA-32 | 감사 로그 | 부분 통과 | API-key lifecycle, privileged mutation, local login intent/outcome은 durable audit되지만 rule/silence/config와 외부 SSO lifecycle 전체는 포괄하지 않는다. |
| FA-33 | SSRF 방어 | **통과** | `ops/synthetic_probe.py`가 public-only DNS, pinned IP, redirect별 재해석, proxy 거부, Host/SNI 보존과 body 미보관을 강제한다. |
| FA-34 | API key와 secret 저장 | 부분 통과 | digest-only scoped/expiring/rotating/revocable/IP-bound key와 fail-closed exact Nginx alias가 있으나 원본 TLS 미충족으로 운영 ingress는 비활성이고 real-IP/firewall·rotation readback이 남았다. |
| FA-35 | 시계열 파티셔닝 | 부분 통과 | 날짜별 JSONL partition은 있으나 host/metric index, compaction manifest와 중앙 query store가 없다. |
| FA-36 | retention과 downsampling | 부분 통과 | bounded 일별 retention과 API 최대 series downsampling은 있으나 장기 multi-resolution rollup/정책 migration은 없다. |
| FA-37 | cardinality 보호 | 부분 통과 | central agent는 fixed metric/target/label allowlist이고 local 진단 배열도 bounded지만, mount/interface identity는 local API field이며 per-target label·전체 series 측정/상한/초과 기록은 없다. |
| FA-38 | 중복 데이터와 역순 데이터 | 부분 통과 | local crash journal과 중앙 idempotency/reorder policy, legacy mixed-queue migration은 있으나 downstream consumer까지의 end-to-end 보장은 없다. |
| FA-39 | backpressure | 부분 통과 | bounded source/spool/quarantine/ingest/outbox와 event reserve·heartbeat bypass는 있으나 중앙 consumer 및 전체 overload 운영 시험이 없다. |
| FA-40 | DB 백업과 실제 복구 | 부분 통과 | signed+AES-256-GCM JSON/JSONL/SQLite/family backup·verify·restore·SIGKILL recovery와 TOCTOU 재검증은 있으나 범위와 production clean-host drill이 미완료다. |
| FA-41 | 에이전트 오프라인 버퍼 | 부분 통과 | immutable bounded spool, exact replay, permanent-rejection quarantine가 있으나 opt-in이고 latest-snapshot producer는 중간 표본을 보존하지 않는다. |
| FA-42 | 에이전트 자체 자원 사용량 | 부분 통과 | CPU/RSS/I/O/duration/outcome/retry/spool/quarantine와 sample-age/stale 지표는 있으나 opt-in 경로의 실운영 budget 추세가 없다. |
| FA-43 | amd64·arm64 빌드 | 부분 통과 | workflow가 두 platform manifest, SBOM, platform별 scan을 정의하지만 현재 변경의 원격 성공 artifact는 아직 없다. |
| FA-44 | Docker Compose 배포 | 부분 통과 | rootless Compose hardening과 restricted deploy workflow는 있으나 새 revision/image/health/rollback production readback이 아직 없다. |
| FA-45 | 부하 테스트 | 부분 통과 | versioned 2배 목표와 concurrent HTTP p95/heap/response gate가 있으나 ingest·delivery·browser·장시간/end-to-end 부하는 제한적이다. |
| FA-46 | 네트워크 단절 테스트 | 부분 통과 | timeout/DNS/TLS/429/retry/offline replay를 deterministic fake로 검증하지만 실제 netem·PKI·edge 단절 복구 시험은 없다. |
| FA-47 | 디스크 부족 테스트 | 부분 통과 | queue/spool/backup/log/update의 bounded/fail-closed 시험은 있으나 실제 ENOSPC·inode 고갈을 전체 writer에 주입하지 않았다. |
| FA-48 | clock skew 테스트 | 부분 통과 | future/backfill/skew/retry 계약 시험은 있으나 실제 host clock/NTP 변화와 복구 후 전체 evaluator·storage 상호운용 시험은 없다. |
| FA-49 | 모니터링 시스템 자체 모니터링 | 부분 통과 | health/ready, collector gap, agent self, delivery/queue/synthetic 상태는 있으나 모든 core component SLI와 독립 운영 경보 readback은 없다. |
| FA-50 | 외부 dead man's switch | 부분 통과 | GitHub-hosted 5분 probe가 readiness+SSO를 확인하고 단일 issue를 열고 회복 시 닫지만 원격 failure/recovery run 증거가 아직 없다. |

## 부분 통과 36항목 상세 갭

### FA-01 — 호스트 등록과 중복 식별

- **근거 코드·설정:** `ops/collector.py`, `server/agent-control.ts`, `ops/agent_transport/`, `docs/agent-ingest-contract.md`.
- **실제 위험:** 기본 local-file 경로만으로는 여러 호스트의 중복 등록·폐기·소유권을 중앙에서 확정할 수 없다.
- **재현/확인:** 기본 설치 후 `current.json`의 `heartbeat.transport`가 `local-file`인지, 중앙 agent API가 disabled인지 확인하고 fleet 화면/실 PKI listener가 없음을 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** 외부 CA와 header-stripping mTLS listener를 배포하고 one-use enrollment, clone rekey, revoke/rotation을 실제 agent installer와 fleet inventory에 연결한다.
- **테스트 방법:** 동일 token 재사용, 동일 machine binding·hostname 충돌, clone, cert revoke/rotation과 server restart를 실제 두 architecture agent로 시험한다.
- **완료 조건:** 모든 운영 host가 unique durable ID와 verified certificate로 한 번만 등록되고 duplicate/clone/revoked 상태가 중앙 UI·audit에 재현 가능하다.

### FA-02 — 에이전트 heartbeat 정확도

- **근거 코드·설정:** `ops/collector.py`의 sequence/observedAt/receivedAt, `server/agent-control.ts`, `ops/agent_transport/transport.py`.
- **실제 위험:** local `receivedAt == observedAt`는 network 지연·단절을 측정하지 못해 원격 agent 장애를 collector 장애와 혼동할 수 있다.
- **재현/확인:** 기본 snapshot에서 두 시각과 `local-file`을 비교한 뒤 collector를 중단한다. 중앙 receipt 없이 local age만 증가한다.
- **수정 우선순위:** P0.
- **구현 계획:** opt-in producer/transport와 central heartbeat를 실제 PKI 경로에 enable하고 server receive time, sequence gap, skew와 lifecycle을 fleet에 저장한다.
- **테스트 방법:** 지연·손실·중복·역순·reboot·maintenance를 가상 시계와 실제 네트워크 장애 양쪽에서 주입한다.
- **완료 조건:** observed/received/network age가 분리되고 delayed/disconnected/recovered 판정과 알림이 실제 원격 단절 readback으로 증명된다.

### FA-08 — OOM과 커널 이벤트

- **근거 코드·설정:** `ops/collector.py`의 reliability/kernel parser, `ops/linux_telemetry.py::collect_event_sources`, `ops/rules/default-rules.v1.json`.
- **실제 위험:** 배포별 kernel log 위치·권한 또는 journald-only 환경에서는 panic, watchdog, segfault, systemd failure가 빠져 거짓 무사고가 될 수 있다.
- **재현/확인:** `/var/log/kern.log`를 unavailable로 만든 fixture에서 `linux.eventSources.kernelLogStatus`와 각 event status를 확인하고 journald-only fixture와 기대 event를 비교한다.
- **수정 우선순위:** P0(OOM/panic), P1(나머지 확장).
- **구현 계획:** strict journald kernel/systemd fallback, boot-bound cursor, watchdog/segfault/systemd-failure allowlist와 source별 coverage 상태를 추가한다.
- **테스트 방법:** Ubuntu rsyslog/journald-only, rotation, permission loss, reboot, duplicate kernel message와 partial source failure fixture를 실행한다.
- **완료 조건:** 지원 event마다 observed/zero/unsupported/permission/failure가 구분되고 두 표준 Ubuntu log 구성이 같은 핵심 사건을 보존한다.

### FA-10 — Docker daemon 상태

- **근거 코드·설정:** `ops/container_exporter.py`, `ops/collector.py`의 `containerCollection`/`dockerEventCollection`, `DockerDaemonUnavailable` rule, `DockerDiagnosticsPanel`.
- **실제 위험:** socket permission, daemon down, daemon restart와 event gap을 일부 구분해도 daemon version/start/recovery 자체가 없어 원인과 영향 시간을 정확히 연결하기 어렵다.
- **재현/확인:** socket permission denial과 daemon connection failure fixture를 각각 실행해 typed status는 달라지지만 daemon identity/version/startedAt가 없는지 API를 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** privacy-reduced daemon identity/version/start epoch, rootless mode, last success/failure/recovery와 event continuity 상태를 exact schema로 추가한다.
- **테스트 방법:** daemon restart, socket revoke/restore, stale snapshot, event cursor gap을 container state reconciliation과 함께 시험한다.
- **완료 조건:** UI/rule이 host down·permission denied·daemon down·daemon restart/gap을 독립 상태와 시간으로 표시한다.

### FA-13 — restart loop

- **근거 코드·설정:** Docker v4 `restartCount`/`restartCountDelta`/timestamps, Docker events, `ContainerRestartLoop` rule.
- **실제 위험:** 수동 재시작이나 batch restart를 crash loop로 오인하고, 짧게 살다 죽는 container를 단순 count 간격 때문에 놓칠 수 있다.
- **재현/확인:** 같은 restart delta를 가진 manual restart와 non-zero exit/restart-policy fixture를 넣으면 현재 rule 입력이 동일한지 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** bounded recent restart intervals, exit code/reason, uptime, restart policy와 actor/deployment maintenance evidence를 reduced lifecycle model에 추가한다.
- **테스트 방법:** manual, always-policy crash, healthcheck-triggered, daemon restart, recreation/replica 교체 시나리오를 가상 시간으로 평가한다.
- **완료 조건:** 명세의 원인 증거가 timeline에 함께 있고 manual/deployment restart는 자동 crash loop와 구별된다.

### FA-14 — OOMKilled

- **근거 코드·설정:** `ops/collector.py` inspect/event reduction, `ops/alert_runtime.py`, `ContainerOOMKilled` rule, Docker diagnostics UI.
- **실제 위험:** destroy/recreate 뒤 OOM state가 사라지거나 host OOM과 cgroup limit OOM의 원인을 잘못 분류할 수 있다.
- **재현/확인:** OOM 후 destroy/recreate event fixture와 host oom_kill counter를 함께 넣고 남는 evidence가 OOM 직전 memory/limit/PSI/log를 묶지 못함을 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** cgroup v1/v2 memory events와 pre-event bounded metric window, exit reason, host pressure, sanitized log link를 event identity에 결합한다.
- **테스트 방법:** host-wide OOM, container max OOM, manual SIGKILL, recreated container와 missing cgroup source를 각각 검증한다.
- **완료 조건:** incident가 OOM 종류를 구분하고 직전 사용량·limit·host PSI·exit/log 증거를 동일 시간축에 보존한다.

### FA-15 — healthcheck

- **근거 코드·설정:** Docker v4 `health`/`healthcheckConfigured`, event stream, `ContainerUnhealthy`/`ContainerNoHealthcheck`, `DockerDiagnosticsPanel`.
- **실제 위험:** 상태만으로는 flapping·연속 실패 원인과 마지막 정상 시각을 알 수 없고 대응자가 raw Docker를 다시 조회해야 한다.
- **재현/확인:** inspect fixture에 여러 health log entry를 넣어도 API row가 상태·configured만 보존하는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** bounded/redacted health failure count, last success/failure time, exit code와 safe output digest/summary를 추가한다.
- **테스트 방법:** no-healthcheck, starting, repeated unhealthy, recovery, secret-like output redaction과 oversized output를 검증한다.
- **완료 조건:** 설정 없음은 오류와 분리되고 지속 unhealthy/recovery 알림 및 최근 실패 원인이 privacy boundary 안에서 표시된다.

### FA-16 — limit 대비 사용률

- **근거 코드·설정:** Docker v4 CPU/memory/PID limit와 throttling fields, `ops/alert_runtime.py`, near-limit/no-limit rules.
- **실제 위험:** reservation·cpuset·memory high/events와 host capacity 불일치를 놓쳐 실제 pressure나 잘못된 설정을 과소평가할 수 있다.
- **재현/확인:** cpuset-only, memory reservation, memory.high와 host RAM 초과 limit fixture를 넣어 해당 값이 public row/rule에 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** cgroup-version-aware quota/cpuset/reservation/memory event와 host capacity comparison을 bounded schema에 추가한다.
- **테스트 방법:** cgroup v1/v2, unlimited 0, unknown null, quota+cpuset 조합, counter reset과 host-overcommit fixture를 실행한다.
- **완료 조건:** 각 제한의 설정/미설정/미지원과 실제 사용률·throttling·memory event·host 불일치가 독립적으로 보인다.

### FA-17 — Docker Compose 프로젝트 그룹

- **근거 코드·설정:** Docker v4 project/owner/name, `src/components/Dashboard.tsx` grouping, `DockerDiagnosticsPanel`, digest drift.
- **실제 위험:** 원하는 replica 수나 배포 의도가 없으면 의도된 `compose down`과 project-wide 장애를 구분하지 못한다.
- **재현/확인:** 같은 project의 replica 하나를 제거하거나 전체를 의도적으로 내린 fixture에서 현재 aggregate와 maintenance evidence를 비교한다.
- **수정 우선순위:** P1.
- **구현 계획:** service identity/replica ordinal, desired count, project totals, deploy/maintenance marker와 partial-outage semantics를 추가한다.
- **테스트 방법:** scale up/down, rolling update, mixed digest, partial replica down, deliberate down과 daemon failure를 검증한다.
- **완료 조건:** project/service별 desired/observed replica와 aggregate resource/health가 보이고 의도된 정지와 장애가 구분된다.

### FA-18 — 볼륨과 writable layer

- **근거 코드·설정:** Docker v4 `writableLayerBytes`, volume/bind/tmpfs counts, `mountPolicyStatus`와 `ContainerWritableLayerHigh` rule/UI.
- **실제 위험:** 어느 filesystem이 가득 차는지, orphan volume인지, 정리 시 실제 확보량이 얼마인지 알 수 없다.
- **재현/확인:** 동일 count이나 서로 다른 host filesystem·inode 상태와 orphan volume fixture를 비교하면 현재 API가 같은 축약값만 내보낸다.
- **수정 우선순위:** P1.
- **구현 계획:** raw path를 노출하지 않는 opaque mount identity로 host filesystem capacity/inode를 연결하고 orphan age·reference·reclaim estimate를 read-only로 수집한다.
- **테스트 방법:** named volume/bind/tmpfs, deleted container, shared volume, inaccessible mount, path-redaction과 no-delete 회귀를 검증한다.
- **완료 조건:** volume별 backing filesystem pressure와 orphan 근거/예상 회수량을 보여주되 자동 삭제나 민감 path 공개가 없다.

### FA-20 — 로그 수집과 멀티라인 파싱

- **근거 코드·설정:** `ops/generic_log_collector.py`, `ops/log_pipeline.py`, `ops/log_store.py`, `server/generic-logs.ts`, `GenericLogExplorer`.
- **실제 위험:** Docker stdout/stderr에만 남는 stack trace와 container 장애 문맥은 Monitor 검색·incident에서 보이지 않는다.
- **재현/확인:** source config의 Docker adapter status가 `unsupported`인지 확인하고 file/journald multiline fixture와 container stdout fixture의 수집 결과를 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** allowlisted Compose service 전용 bounded Docker log adapter를 exporter 경계에 추가해 acquisition 즉시 redaction/multiline/quota를 적용한다.
- **테스트 방법:** Docker log framing, rotation/restart, partial multiline, secret/PEM, burst/drop accounting, permission/socket failure를 검증한다.
- **완료 조건:** file/journald/Docker source가 동일 normalized schema와 explicit status로 검색되며 raw secret·container ID·unbounded body가 저장되지 않는다.

### FA-25 — no-data와 stale-data

- **근거 코드·설정:** `ops/alert_engine.py`, `ops/alert_runtime.py`, `server/data.ts` source status와 `noDataPolicy`.
- **실제 위험:** 모든 rule에서 stale이 no_data와 같은 branch/policy로 처리되므로 장시간 last-known과 실제 미수집을 구분한 경보 시간·행동을 설정할 수 없다.
- **재현/확인:** 동일 rule에 fresh missing, stale last-known, unsupported, permission-denied observation을 넣고 rule schema에 stale 전용 field가 없으며 stale과 no_data 결과가 같은지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** observation age/source freshness를 evaluator 입력으로 표준화하고 rule별 stale threshold/action을 no-data와 별도 versioned field로 만든다.
- **테스트 방법:** source별 last-success age, clock skew, active incident 중 stale 전환과 유효 recovery를 가상 clock으로 검증한다.
- **완료 조건:** 모든 enabled rule이 no-data·stale·unsupported·permission 정책을 명시하고 UI/transition이 서로 다른 이유를 보존한다.

### FA-26 — 알림 dedup

- **근거 코드·설정:** `ops/alert_engine.py` deterministic transition ID, `ops/alert_delivery.py` event/channel key와 retained delivery log.
- **실제 위험:** 같은 근본 장애가 target별로 대량 발생하거나 label 변경 시 notification storm이 생길 수 있다.
- **재현/확인:** 하나의 host failure로 여러 child target transition을 만들고 현재 parent suppression 밖의 group/dedup 결과를 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** bounded label grouping, group wait/interval/repeat interval과 stable incident key를 versioned routing config에 추가한다.
- **테스트 방법:** duplicate replay, label order/change, restart, concurrent worker, retention 경계와 group window를 가상 clock으로 시험한다.
- **완료 조건:** 동일 사건은 정책대로 한 group으로 전달되고 신규·갱신·복구 notification 수가 deterministic하다.

### FA-27 — 상위 장애 기반 억제

- **근거 코드·설정:** rule `parentRuleId`, `ops/alert_engine.py` target-label parent suppression/release, `ops/alert_store.py` private notification lifecycle와 SQLite outbox.
- **실제 위험:** static parent만으로는 Docker daemon·Compose service·synthetic dependency 장애에서 수십 개 child 경보가 중복 전송될 수 있다.
- **재현/확인:** parent와 child를 함께 firing한 뒤 parent만 회복시키면 child의 같은 `openedAt`에 ready firing이 한 번 생기고 outbox에도 한 행만 추가된다. 반면 topology가 없는 service/endpoint는 자동 억제되지 않는다.
- **수정 우선순위:** P0.
- **구현 계획:** host→daemon→project→service/container 및 endpoint dependency를 privacy-reduced topology로 만들고 suppression reason을 transition에 기록한다.
- **테스트 방법:** parent 먼저/나중 firing, parent 회복 뒤 재평가·event-first crash·opening-event retention 탈락, partial project failure, missing topology와 cycle 거부를 검증한다.
- **완료 조건:** 모든 기본 child rule이 검증된 parent/dependency에 연결되고 suppression·unsuppression이 UI/delivery log에서 설명 가능하다.

### FA-28 — silence와 유지보수 창

- **근거 코드·설정:** `ops/alert_engine.py::Silence`, `ops/alert_store.py` private config/lifecycle, `ops/rules/alert-silences.example.v1.json`, collector lifecycle maintenance.
- **실제 위험:** owner-only one-shot 파일은 재시작 뒤에도 다시 읽히지만 반복 작업을 표현하거나 변경 주체를 감사할 API/UI가 없다. 이미 ready로 기록·queue된 사건에 뒤늦게 추가한 silence는 의도적으로 소급 취소하지 않는다.
- **재현/확인:** silence 안에서 firing한 사건을 만료 뒤 다시 평가하면 같은 `openedAt`의 ready event/outbox 행이 한 번만 생긴다. 재평가·stale private-state replay에도 중복되지 않으며 late silence는 기존 ready 권위를 유지한다.
- **수정 우선순위:** P0.
- **구현 계획:** RBAC·audit된 silence CRUD, exact matcher, UTC interval/recurrence, expiry와 maintenance lifecycle 연계를 durable state로 추가한다.
- **테스트 방법:** UTC overlap/expiry, restart, event-log retention, event-first crash, late-silence 비소급, scope collision, unauthorized mutation과 silenced recovery 기록을 검증한다.
- **완료 조건:** 승인된 사용자가 UI/API에서 반복·일회 창을 관리하고 평가·delivery·audit가 동일 silence ID를 보존한다.

### FA-29 — 알림 전송 retry

- **근거 코드·설정:** `ops/alert_store.py`, `ops/alert_delivery.py`, `ops/systemd/monitor-alert-delivery.*`, `docs/alert-delivery.md`.
- **실제 위험:** production secret/channel이 없으면 firing transition이 durable queue에만 남고 운영자에게 도달하지 않는다. at-least-once 수신 중복도 가능하다.
- **재현/확인:** delivery config가 없는 운영 경로에서 status를 확인하고, fake 429/5xx는 retry되지만 실제 receiver readback이 없음을 구분한다.
- **수정 우선순위:** P0.
- **구현 계획:** 최소 두 독립 channel을 private secret file로 provision하고 receiver idempotency, test-alert, final-failure escalation과 ownership을 운영화한다.
- **테스트 방법:** 실제 sandbox receiver로 timeout/429/5xx/partial SMTP/crash-after-accept/recovery를 주입하고 delivery log를 대조한다.
- **완료 조건:** production test alert와 실제 firing/recovery가 정해진 SLA 안에 수신되고 retry/final failure가 Monitor 밖에서도 확인된다.

### FA-30 — incident 타임라인

- **근거 코드·설정:** rule alerts/transitions, Docker events, collector reliability/incidents, `OperationalLogView`, `DockerDiagnosticsPanel`.
- **실제 위험:** 메트릭·상태 사건은 보여도 누가 확인·조치했는지 없어 MTTA/MTTR과 사후 분석이 불완전하다.
- **재현/확인:** container restart와 rule firing fixture를 시간순으로 표시한 뒤 ack/assignee/note/deploy action을 기록할 API가 없는지 확인한다.
- **수정 우선순위:** P1.
- **구현 계획:** durable incident entity에 transition, deploy/maintenance, sanitized log evidence, ack/assignee/note/action audit를 append-only로 결합한다.
- **테스트 방법:** 동시 ack, reopen, duplicate event, clock skew, RBAC와 retention/export를 검증한다.
- **완료 조건:** 한 incident에서 탐지→전송→ack→조치→복구의 주체·시간·근거가 같은 timeline으로 조회된다.

### FA-31 — 사용자 인증과 RBAC

- **근거 코드·설정:** `server/sso.ts`, `server/app.ts`, `server/auth.ts`, application API-key scope, Nginx exact alias snippets.
- **실제 위험:** 전역 role만으로 여러 host/team/environment를 운영하면 최소권한 분리가 어렵고 외부 SSO lifecycle 장애를 저장소만으로 검증할 수 없다.
- **재현/확인:** user/admin/chief-admin별 endpoint matrix를 실행하고 특정 host/project만 허용하는 정책을 표현할 수 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** canonical resource IDs와 team/environment scope, deny-by-default policy, IdP group mapping·deprovision audit/readback을 추가한다.
- **테스트 방법:** cross-scope read/write, group change, deprovision, legacy header spoof, direct-origin 및 bearer/SSO 혼합 시도를 검증한다.
- **완료 조건:** 모든 API·UI·remote action이 resource-scoped 권한을 일관되게 적용하고 IdP 탈퇴가 운영 readback에서 즉시 차단된다.

### FA-32 — 감사 로그

- **근거 코드·설정:** `server/application-security-state.ts`, `server/app.ts`의 intent/outcome audit, security audit API와 backup family.
- **실제 위험:** rule/silence/config 및 외부 SSO lifecycle이 기록되지 않으면 경보 정책 변경이나 권한 오용의 책임 추적이 끊긴다.
- **재현/확인:** API-key issue/rotate/revoke와 local login은 audit된 뒤, rule/silence 변경 API 부재 및 SSO login/logout source 범위를 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** 모든 보안·운영 mutation에 공통 audit wrapper를 적용하고 SSO event correlation, immutable off-host forwarding과 retention policy를 추가한다.
- **테스트 방법:** intent fsync failure에서 side effect 차단, rotation/crash, secret 비노출, concurrent append와 off-host delivery failure를 검증한다.
- **완료 조건:** 요구된 mutation/login lifecycle 각각에 actor/action/target/outcome record가 있고 누락·변조·보관 상태가 외부에서 감시된다.

### FA-34 — API key와 secret 저장

- **근거 코드·설정:** `server/application-security-state.ts`, `server/application-security-app.test.ts`, `ops/nginx/monitor-api-key-ingress.conf`, `monitor-api-key-proxy.conf`, `monitor-api-key-peer-map.conf`, `ops/tests/test_api_key_nginx_runtime.py`.
- **실제 위험:** 현재 원본은 HTTP-only라 alias를 켜면 bearer가 Cloudflare→원본에서 평문이 된다. 이후 live edge의 real-IP/header stripping 또는 direct-origin 차단이 틀려도 source-IP allowlist가 우회될 수 있다.
- **재현/확인:** 현재 public·직접 원본 alias가 SSO 302인지 확인한다. 임시 TLS Nginx 시험에서는 HTTP 426, non-loopback 403, duplicate Authorization 400과 exact rewrite/header stripping을 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** Nginx origin TLS와 Cloudflare Full (strict), proxy-only origin firewall을 먼저 배포·검증한 뒤 reviewed include를 명시적으로 활성화하고 key rotation/expiry runbook을 운영한다.
- **테스트 방법:** HTTP origin·spoofed forwarding headers·non-Cloudflare peer, allowed/denied IP, scoped GET/POST, CSRF-cookie 혼합, revoke/rotate와 Nginx reload를 시험한다.
- **완료 조건:** Cloudflare→원본 기밀성과 peer ACL이 입증되고 live alias만 bearer를 app에 전달하며 trusted client IP·scope·expiry/revoke가 readback되고 security-management/mTLS 경로는 우회되지 않는다.

### FA-35 — 시계열 파티셔닝

- **근거 코드·설정:** `ops/collector.py`의 `history/YYYY-MM-DD.jsonl`, `server/data.ts` bounded reader.
- **실제 위험:** host·metric 수가 늘면 일자 파일 전체 parse가 CPU/memory를 소비하고 특정 series 조회 latency가 예측 불가해진다.
- **재현/확인:** `ops/resilience-budgets.json`의 2배 history를 생성해 query p95를 측정하고 host/metric index 파일이나 query plan이 없는지 확인한다.
- **수정 우선순위:** P0(중앙 fleet enable 전).
- **구현 계획:** metadata와 series를 분리한 indexed partition, atomic manifest/compaction과 bounded query planner를 중앙 consumer에 구현한다.
- **테스트 방법:** partition rollover, crash during compaction, missing/corrupt index, concurrent write/read와 high-cardinality reject를 시험한다.
- **완료 조건:** 목표 fleet·retention에서 query가 partition/index만 읽고 p95/RSS budget을 만족하며 rebuild 가능한 manifest가 있다.

### FA-36 — retention과 downsampling

- **근거 코드·설정:** collector history/log/incident retention, `server/data.ts::downsampleTelemetry`, bounded series maximum.
- **실제 위험:** 장기 추세는 삭제되고 단일 downsample 방식이 peak/incident를 희석할 수 있으며 정책 변경 migration이 없다.
- **재현/확인:** 30일 초과 fixture와 narrow spike series를 조회해 삭제 및 최대 point 축약 결과를 원본과 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** metric 특성별 min/max/avg/count multi-resolution rollup, raw/rollup retention manifest와 migration/dry-run을 추가한다.
- **테스트 방법:** boundary day, spike preservation, late data, policy change, crash/rebuild와 disk budget을 검증한다.
- **완료 조건:** versioned raw/rollup 정책과 보존량이 UI/API에 보이고 장기 query가 peak를 보존하며 storage budget을 만족한다.

### FA-37 — cardinality 보호

- **근거 코드·설정:** `ops/agent_records.py`와 `server/agent-control.ts`의 fixed metric/target/label 계약, collector/API의 bounded arrays, `ops/linux_telemetry.py`의 filesystem mount·interface diagnostic identity.
- **실제 위험:** local 진단 배열이 bounded여도 host·container·metric·label 조합의 전체 series 수와 대상별 label 수를 측정하지 않으면 fleet 확장 시 저장·질의 비용 초과를 사전에 거부하거나 설명할 수 없다.
- **재현/확인:** central agent의 임의 metric/target/label 거부를 확인한 뒤 local API의 mount/interface identity와 전역 series-count/overflow counter가 없는지 확인한다.
- **수정 우선순위:** P0(중앙 fleet enable 전).
- **구현 계획:** 수집·ingest·materialization 경계에 per-target label cap, 전체 active-series budget, deterministic reject/drop reason과 bounded overflow counter를 추가한다.
- **테스트 방법:** ephemeral container·mount·interface churn, 최대 label 조합, 한계 직전/초과, restart와 retention expiry에서 series count·reject accounting을 검증한다.
- **완료 조건:** metric/host/container/labels cardinality가 실제 측정되고 대상별·전체 상한을 초과한 입력은 명시적으로 거부되며 초과 원인·수량이 운영 화면과 경보에 보인다.

### FA-38 — 중복 데이터와 역순 데이터

- **근거 코드·설정:** collector pending journals, `server/agent-control.ts` batch/record idempotency·reorder, `ops/agent_transport`, legacy mixed queue migration test.
- **실제 위험:** 중앙 queue 이후 consumer가 없으므로 admission에서 지킨 idempotency와 순서가 최종 시계열까지 유지된다는 보장이 없다.
- **재현/확인:** exact batch replay와 out-of-order batch는 server test에서 확인한 뒤 queue를 조회할 downstream claim/ack/series 결과가 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** encrypted queue consumer에 durable claim/ack, record identity, allowed lateness와 deterministic conflict policy를 구현한다.
- **테스트 방법:** crash at claim/write/ack, duplicate old/new batch, mixed legacy entry restart, reorder window와 conflicting payload를 검증한다.
- **완료 조건:** agent enqueue부터 query 결과까지 exact duplicate는 한 번만, 역순은 정책대로 저장/격리되며 restart에도 결과가 같다.

### FA-39 — backpressure

- **근거 코드·설정:** generic log caps, alert outbox, agent spool/quarantine, central ingest finite queue/event reserve/heartbeat bypass.
- **실제 위험:** consumer 부재나 장기 outage에서 bounded queue가 가득 차면 최신 telemetry를 거절하고 운영자가 어느 계층이 막혔는지 놓칠 수 있다.
- **재현/확인:** spool/ingest/outbox를 각 limit까지 채워 status/counters와 heartbeat/event 우선권을 확인하고 end-to-end consumer drain이 없음을 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** downstream consumer와 계층별 queue depth/oldest/drop/reject SLI, producer shedding policy 및 escalation을 연결한다.
- **테스트 방법:** 여러 agent 동시 burst, slow consumer, quarantine saturation, outbox saturation과 recovery drain을 2배 규모로 시험한다.
- **완료 조건:** overload가 한 agent/source에 격리되고 heartbeat·critical event가 보존되며 모든 drop/reject와 회복 시간이 관측된다.

### FA-40 — DB 백업과 실제 복구

- **근거 코드·설정:** `ops/state_backup.py`, `ops/state-backup-sources.example.json`, `docs/backup-recovery.md`, `ops/tests/test_state_backup.py`.
- **실제 위험:** 현재 source map은 collector identity, rule alerts, delivery SQLite, application-security family만 포함하며 production off-host archive·복구 증거가 없어서 장애 시 telemetry/agent state가 유실될 수 있다.
- **재현/확인:** source map을 실제 state inventory와 비교하고 production writer를 quiesce하지 않은 family backup, in-place mutation, ciphertext tamper가 실패하는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** 모든 필요한 durable state를 reviewed map에 추가하고 signer/recipient custody, schedule, off-host copy, RPO/RTO와 clean-host drill을 운영화한다.
- **테스트 방법:** actual encrypted backup→verify→empty-root restore→Monitor startup/API-key auth/audit/outbox readback, TOCTOU rotation 및 SIGKILL rollback을 수행한다.
- **완료 조건:** 현재 production generation의 off-host archive가 독립 verify와 clean-host application readback을 통과하고 측정 RPO/RTO가 보관된다.

### FA-41 — 에이전트 오프라인 버퍼

- **근거 코드·설정:** `ops/agent_transport/transport.py`, `ops/agent_producer.py`, `ops/agent_records.py`, 별도 default-off units.
- **실제 위험:** default 설치에는 중앙 전송이 없고 latest `current.json`이 교체되는 동안 막히면 중간 collector 표본은 spool에 들어가기 전 사라진다.
- **재현/확인:** producer pending 상태에서 spool을 가득 채우고 collector snapshot sequence를 여러 번 전진시킨 뒤 복구해 중간 sequence가 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** collector와 협조하는 bounded append-only reduced outbox 또는 durable publication feed를 만들고 opt-in installer/PKI enablement를 완성한다.
- **테스트 방법:** long offline, full spool, crash journal, BATCH/DATA_TOO_OLD quarantine, inspect+single purge와 reconnect replay를 검증한다.
- **완료 조건:** 선언한 offline window 안의 모든 accepted source checkpoint가 순서대로 재생되고 영구 거부는 bounded private quarantine에서 운영 처리된다.

### FA-42 — 에이전트 자체 자원 사용량

- **근거 코드·설정:** transport self-metrics, `ops/agent_records.py`의 sample age/stale projection, producer/transport systemd resource limits.
- **실제 위험:** opt-in 경로가 실제 host에서 돌지 않으면 CPU/RSS/I/O/retry/spool 악화가 중앙에 보이지 않고 SD/NVMe wear budget도 검증되지 않는다.
- **재현/확인:** stale self-metrics fixture가 fresh host batch를 오염하지 않음을 확인한 뒤 production agent series와 장기 budget artifact가 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** 실 agent enablement 후 self metric을 rule/UI에 연결하고 architecture·storage별 CPU/RSS/write/queue budget을 versioning한다.
- **테스트 방법:** idle/2배 load/offline/retry/quarantine 상태에서 wall time, CPU, RSS, procfs I/O와 sample age를 장시간 측정한다.
- **완료 조건:** self metrics가 실제 중앙 series에서 fresh/stale로 보이고 모든 platform이 선언 budget을 지속적으로 만족한다.

### FA-43 — amd64·arm64 빌드

- **근거 코드·설정:** `.github/workflows/deploy.yml`의 `linux/amd64,linux/arm64` manifest, SBOM/provenance와 platform별 Trivy gate.
- **실제 위험:** workflow 정의만 있고 현재 변경의 성공 artifact가 없으면 한 platform build/runtime 회귀를 배포 전에 확정할 수 없다.
- **재현/확인:** 원격 run의 manifest raw JSON, 두 digest, scan step와 image health 결과가 현재 commit SHA를 가리키는지 확인한다.
- **수정 우선순위:** P0 release gate.
- **구현 계획:** 최종 commit을 push해 pinned workflow를 완료하고 platform별 smoke/health artifact와 immutable digest를 보관한다.
- **테스트 방법:** 두 architecture image에서 startup, readiness, schema fixture, backup CLI와 rootless mount contract를 실행한다.
- **완료 조건:** 현재 commit의 manifest가 두 platform을 포함하고 build/test/critical scan/SBOM/provenance가 모두 성공한다.

### FA-44 — Docker Compose 배포

- **근거 코드·설정:** `docker-compose.yml`, `Dockerfile`, runtime-hardening test, `.github/workflows/deploy.yml`, restricted `deploy monitor <sha>` 호출.
- **실제 위험:** source config 성공만으로는 production이 새 digest를 실행하거나 readiness 실패 시 rollback됐음을 증명하지 못한다.
- **재현/확인:** deploy 뒤 production revision file, exact Monitor container image/digest, compose project label, health와 loopback/public readiness를 현재 SHA와 비교한다.
- **수정 우선순위:** P0 release gate.
- **구현 계획:** final CI deploy 후 immutable revision/digest/health readback을 남기고 intentional bad-readiness rollback drill을 별도로 수행한다.
- **테스트 방법:** Compose config, rootless secret/state binds, read-only filesystem, health transition, failed cutover와 previous image recovery를 검증한다.
- **완료 조건:** production revision·running digest·health가 현재 commit과 일치하고 실패 배포가 이전 immutable image로 복원된 증거가 있다.

### FA-45 — 부하 테스트

- **근거 코드·설정:** `ops/resilience-budgets.json`, `server/load-budget.test.ts`, `scripts/run-resilience-suite.sh`, `.github/workflows/resilience.yml`.
- **실제 위험:** read query 중심의 짧은 2배 fixture만으로 ingest burst, delivery, browser rendering과 장시간 memory/write amplification을 예측하기 어렵다.
- **재현/확인:** `npm run test:resilience`의 workload와 budget을 읽어 포함된 rows/readers/API p95와 빠진 end-to-end 부하를 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** target fleet/series/log/alert rate를 고정하고 ingest→evaluate→deliver→query/browser 전체의 p95/RSS/write/lag budget을 추가한다.
- **테스트 방법:** 1배/2배/soak, simultaneous reconnect, high log burst, rule storm, slow reader와 both-architecture image를 시험한다.
- **완료 조건:** versioned 목표의 모든 end-to-end budget이 scheduled artifact로 남고 초과 시 gate가 실패한다.

### FA-46 — 네트워크 단절 테스트

- **근거 코드·설정:** agent transport/control, synthetic probe, alert delivery의 DNS/TLS/timeout/429/retry 가상 네트워크 tests와 resilience suite.
- **실제 위험:** 실제 kernel socket, resolver, proxy, CA/CRL과 Cloudflare 경계는 fake와 다르게 실패해 reconnect storm이나 인증 복구 문제를 만들 수 있다.
- **재현/확인:** deterministic tests를 실행한 뒤 live netem/DNS/PKI/edge failure artifact가 없는지 확인한다.
- **수정 우선순위:** P0.
- **구현 계획:** 격리 staging에서 tc/netem 또는 동등한 network fault harness와 실제 CA/proxy/receiver를 사용한 복구 시나리오를 만든다.
- **테스트 방법:** loss/latency/DNS NXDOMAIN·rebind/TLS expiry/revoke/connection reset/partition/reconnect storm을 주입한다.
- **완료 조건:** declared offline window 안에서 heartbeat와 telemetry가 중복 없이 회복되고 queue/alert/retry SLI가 budget을 만족한다.

### FA-47 — 디스크 부족 테스트

- **근거 코드·설정:** updater free-space preflight, log/outbox/spool/backup bound와 fsync failure tests, systemd filesystem limits.
- **실제 위험:** 실제 ENOSPC 또는 inode exhaustion에서 atomic rename/fsync/journal cleanup이 예상과 달라 state publication이나 복구가 멈출 수 있다.
- **재현/확인:** bounded temp filesystem을 가득 채워 collector history/current, alert SQLite, security audit와 agent spool write를 각각 실행한다.
- **수정 우선순위:** P0.
- **구현 계획:** loopback filesystem 기반 byte/inode/readonly/IO-error fault harness와 component별 reserved headroom·operator signal을 추가한다.
- **테스트 방법:** ENOSPC before/after fsync/rename, inode exhaustion, SQLite WAL growth, recovery after freeing space와 no-partial-state를 검증한다.
- **완료 조건:** 모든 durable writer가 fail closed하고 기존 good state를 보존하며 disk 원인·drop/retry와 자동 회복이 화면/alert에 나타난다.

### FA-48 — clock skew 테스트

- **근거 코드·설정:** central agent skew/backfill policy, producer monotonic checkpoint, API future bound, evaluator virtual-clock tests.
- **실제 위험:** 실제 NTP step/clock rollback이 alert duration, retention partition, TLS, Retry-After와 dedup을 동시에 왜곡할 수 있다.
- **재현/확인:** agent timestamp를 허용 범위 앞/뒤로 보내고 host clock을 ±변경한 staging에서 evaluator·partition·delivery 결과를 비교한다.
- **수정 우선순위:** P1.
- **구현 계획:** wall/monotonic clock separation과 skew SLI를 모든 component에 문서화하고 bounded correction/recovery 정책을 통합한다.
- **테스트 방법:** ±small/large step, leap-like boundary, reboot, TLS validity, Retry-After HTTP-date, midnight partition과 recovery를 검증한다.
- **완료 조건:** skew가 explicit 상태/경보로 보이고 시간 복구 후 duplicate·잘못된 resolution·무한 retry 없이 정상화된다.

### FA-49 — 모니터링 시스템 자체 모니터링

- **근거 코드·설정:** `/healthz`, `/readyz`, collector gap, rule runtime/delivery signals, agent self metrics, synthetic source status와 external probe.
- **실제 위험:** evaluator·storage·queue·delivery의 일부 failure가 한 화면 또는 local outbox에만 남아 Monitor 전체 장애와 함께 사라질 수 있다.
- **재현/확인:** collector, API, evaluator state, outbox worker를 각각 중단하고 어떤 신호가 public readiness와 외부 incident까지 전파되는지 비교한다.
- **수정 우선순위:** P0.
- **구현 계획:** ingest/evaluator/query/outbox duration/error/lag/depth/oldest/storage SLI를 고정하고 외부 dead-man과 독립 escalation에 연결한다.
- **테스트 방법:** host/app/Nginx/storage/evaluator/delivery 단독 및 동시 장애, stale cache와 recovery를 실제 staging에서 주입한다.
- **완료 조건:** 모든 core component 장애가 대상 장애와 구분되고 Monitor 경계 밖의 수신자가 탐지·회복을 확인한다.

### FA-50 — 외부 dead man's switch

- **근거 코드·설정:** `.github/workflows/external-monitor.yml`, `scripts/check-public-monitor.mjs`, public readiness Nginx snippet과 probe tests.
- **실제 위험:** workflow가 원격에서 실제 동작하지 않거나 issue permission/search가 실패하면 host 전체 장애 때 지속 incident가 남지 않는다.
- **재현/확인:** manual remote run으로 정상 성공을 확인하고 격리된 test boundary에서 실패 run이 정확히 한 issue를 열며 첫 성공이 comment+close하는지 확인한다.
- **수정 우선순위:** P0 운영 gate.
- **구현 계획:** 최종 push 후 workflow_dispatch/schedule을 검증하고 issue ownership·notification·runner outage 대체 경로와 runbook을 운영화한다.
- **테스트 방법:** readiness 5xx/timeout, SSO redirect 변조, TLS failure, repeated failure dedup, recovery close와 GitHub API failure를 시험한다.
- **완료 조건:** 실제 외부 run의 failure issue와 recovery close 링크가 보존되고 담당자가 Monitor host 없이도 해당 incident를 수신한다.

## 운영 완료를 막는 잔여 P0

다음 증거가 생기기 전에는 전체 Monitor를 “운영 완료”로 표시하지 않는다.

1. 실제 PKI/mTLS listener와 remote agent enrollment·heartbeat·offline replay
2. production channel로 test/firing/recovery 전달 및 final-failure readback
3. 원본 TLS·Cloudflare Full (strict) 후 API-key live alias·trusted real-IP·direct-origin 차단 검증
4. 전체 durable state를 포함한 off-host encrypted backup과 clean-host application restore
5. 최종 원격 CI의 두 architecture artifact와 production revision/digest/health/rollback readback
6. GitHub-hosted dead-man의 실제 정상 및 failure→issue→recovery close 증거
7. end-to-end overload, live network fault, ENOSPC와 clock step 복구 시험
