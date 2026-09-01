# Monitor 구현 증분 감사 — 2026-08-31

> 기준선: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 대상: 이 문서를 포함하는 현재 worktree
> 범위: `/home/cks/Monitor` 코드·설정·테스트와 명시된 Monitor 운영 readback

## 결론

이번 증분은 기준선의 “단일 host snapshot 화면”을 action-first 운영 경로로
확장했다. Linux 상세 telemetry와 Docker v4/event stream은 strict server 계약과
전용 UI까지 연결됐고, generic log, versioned rule evaluator, durable notification
outbox, SSRF-safe synthetic probe, application API key/audit, encrypted backup/restore,
opt-in central agent producer/transport가 구현됐다. 공개 readiness와 SSO를 외부에서
확인하는 GitHub-hosted dead-man은 반복 실패를 하나의 durable issue로 남기고 회복
시에 닫도록 구성됐다.

이는 Monitor.md 전체 완료 선언이 아니다. 중앙 agent와 synthetic timer는
default-off이고 실제 CA/mTLS listener·downstream ingest consumer가 없다. delivery
channel은 운영 secret/receiver가 필요하다. API-key ingress는 현재 HTTP-only 원본에서
의도적으로 비활성이고, 원본 TLS·Cloudflare Full (strict)·firewall readback이 필요하다. backup은
production off-host copy와 clean-host application restore가 필요하다. 현재 worktree의
최종 전체 회귀, 원격 CI, 새 multiarch image, production deploy/rollback과 외부
dead-man 실제 run도 최종 증거가 생기기 전까지 pending이다. 최신 50항목 판정과
항목별 완료 조건은 [최종 감사](monitoring-final-audit.md)를 기준으로 한다.

## 구현 증분

| 영역 | 현재 구현 증거 | 상태 경계 |
| --- | --- | --- |
| local identity·heartbeat | `ops/collector.py`가 owner-only state의 stable UUIDv4 host/agent ID, machine-id hash binding·clone rekey, boot digest, durable monotonic sequence와 observed/received/interval/lifecycle을 발행한다. | 기본 transport는 `local-file`; 원격 receipt가 아니다. |
| central agent control | `server/agent-control.ts`가 one-use enrollment, certificate fingerprint binding/rotation/revoke, strict heartbeat/inventory와 encrypted finite ingest admission을 구현한다. | default-off; 외부 PKI/proxy와 downstream consumer 필요. |
| agent producer·transport | `ops/agent_records.py`, `ops/agent_producer.py`, `ops/agent_transport/`가 fixed projection, identity-bound checkpoint, homogeneous batch, mTLS/gzip/retry와 bounded offline spool을 제공한다. | collector installer와 분리된 opt-in units. latest snapshot source라 blocked 구간의 중간 표본은 보존하지 않는다. |
| permanent rejection | `BATCH_TOO_OLD`/`DATA_TOO_OLD`는 exact immutable batch를 private bounded quarantine로 옮기며 metadata-only inspect와 단일-ID explicit purge를 제공한다. | 자동 삭제·purge-all 없음. quarantine는 spool capacity를 계속 사용한다. |
| agent self telemetry | wall/CPU/RSS/procfs I/O, outcome/retry, heartbeat age, spool/quarantine count·oldest/status를 fixed metrics로 투영한다. old sample은 fresh checkpoint 시각으로 위장하지 않고 age/stale로 표시해 batch 전체를 오염시키지 않는다. | opt-in path의 production 장기 budget 증거 없음. |
| ingest compatibility | 신규 admission은 metric/event homogeneous만 허용한다. 기존 mixed queue entry는 startup에서 거부하지 않고 idempotency·capacity를 보존한 채 읽는 migration 경로가 있다. | downstream claim/ack와 시계열 materializer 없음. |
| Linux telemetry | `ops/linux_telemetry.py`가 CPU/core/frequency, memory/swap/vmstat/PSI, filesystem/inode/RO, block latency/queue/utilization, NIC/TCP/conntrack, process/PID/FD/cgroup, allowlist systemd, thermal/RPi, boot/time/kernel source 상태를 발행한다. | privileged SMART·일부 platform event는 explicit unsupported/partial. |
| Linux API·UI | `server/data.ts`와 `server/types.ts`가 exact bounded `linux` contract를 검증하며 `LinuxDiagnosticsPanel`이 resources/network/storage/reliability/power 화면에 연결된다. | 기준선 문서의 “server/UI 미연결” 설명은 더 이상 유효하지 않다. |
| Docker v4 | exact 58-field row가 lifecycle, CPU/memory/PID/throttling, block/network total·rate, storage counts, security booleans/capability counts, image digest evidence와 `mountPolicyStatus`를 제공한다. 승인 상태는 identity-bound inspect의 전체 host-storage multiset과 named-volume metadata가 검토된 profile에 정확히 맞을 때만 생성된다. V3는 dual-read하며 검토 대상의 과거 row를 `unknown`으로 승격한다. raw ID는 opaque digest이고 env/command/raw mount/profile/address는 버린다. | health output, restart 원인, cgroup memory event, volume filesystem 연결은 남음. |
| Docker event stream | cursor/replay/reconnect/dedup/gap과 최대 128개 allowlisted lifecycle event를 발행하고 API·`DockerDiagnosticsPanel` timeline에 연결한다. stale/permission/unavailable은 container 0개 정상으로 승격되지 않는다. | daemon 자체 lifecycle 상세 모델은 부분적. |
| Compose·image UX | project/service grouping, resource·security·image·storage diagnostics, digest drift/latest/change와 상단 action links가 연결된다. 정상 rule 목록은 compact하고 Docker/rule 운영 timeline은 함께 볼 수 있다. | desired replica/deploy intent/orphan volume은 없음. |
| generic logs | allowlist file/journald input, bounded cursor/tail, JSON/logfmt/syslog/plain/multiline parser, pre-storage credential·PII·PEM redaction, priority quota/drop accounting과 digest-bound explorer가 연결된다. | Docker stdout/stderr acquisition은 explicit unsupported. |
| rule evaluator | 82개 고정 ID rule pack과 duration+samples, hysteresis, no-data, parent suppression, one-shot silence, restart-safe state/transition 및 strict API/UI가 연결된다. parent 회복·silence 만료는 private lifecycle과 event-first replay를 통해 활성 사건의 ready event/outbox를 exactly-once 생성하며 late silence는 기존 ready 권위를 소급 취소하지 않는다. | editable CRUD/version history, independent stale policy, dynamic topology, recurring silence는 없음. |
| notification delivery | finite SQLite outbox, deterministic event/channel key, lease/crash recovery, retry/backoff/jitter/Retry-After/final-failure와 webhook·Slack·Discord·Telegram·TLS-SMTP adapter가 별도 worker로 연결된다. | 실제 channel config/secret/receiver idempotency readback 없음. |
| synthetic probe | `ops/synthetic_probe.py`가 HTTP(S)·TLS를 public-only DNS answer와 pinned address로 검사하고 redirect마다 DNS를 재검증한다. proxy env·credentials·private/mixed answer를 거부하고 body/header를 보관하지 않는다. collector/API/operational findings와 HTTP/TLS rules에 연결된다. | installer는 unit을 설치하지만 timer는 default-off; 운영 target 승인·enablement 필요. |
| public readiness | app과 exact Nginx route가 credential-free exact JSON, no-store, body bound를 제공한다. public probe는 readiness와 same-origin SSO redirect를 함께 검사한다. | 공개 readback은 확인됐지만 최종 새 application image 배포 증거와는 별도다. |
| external dead-man | `.github/workflows/external-monitor.yml`이 5분마다 GitHub-hosted runner에서 probe하며, 실패 시 fixed-title open issue를 하나만 만들고 회복 성공 시 comment+close한다. probe 실패 run 자체도 실패로 남는다. | 최종 remote workflow의 실제 정상 및 failure→recovery run은 pending. |
| application API keys | 256-bit one-time token, digest-only registry, scopes/expiry/revoke/rotate, canonical source-IP allowlist, last-used coalescing, inactive tombstone compaction과 per-key/invalid-attempt limiter를 구현한다. mutation은 successful bearer auth 뒤 cookie CSRF check와 분리된다. | live edge/source-IP/rotation 운영 readback 필요. |
| API-key Nginx ingress | future activation용 exact `/monitor/api-key/v1/...` method/path aliases가 있다. proxy는 TLS·original-peer gate 뒤 cookie/SSO/mTLS headers를 지우고 forwarding chain을 교체한다. 실행형 TLS Nginx 시험이 rewrite/header/body/cache/method/path와 HTTP·비신뢰-peer 거부를 검증한다. | 현재 HTTP-only 원본에서는 include가 제거되어 alias도 SSO 뒤다. 원본 TLS+Full (strict), Cloudflare range 갱신과 direct-origin firewall을 입증한 뒤에만 활성화한다. security management/agent mTLS는 alias에 없음. |
| application audit | local login과 privileged mutation/API-key lifecycle에 intent-before-side-effect와 outcome audit을 적용한다. file와 directory fsync 실패는 fail closed하고 records는 raw IP/secret/header/body를 저장하지 않는다. | rule/silence/config 및 외부 SSO lifecycle 전체 audit은 남음. |
| application state runtime | explicit host bind `create_host_path: false`, mode-0700 state와 mode-0600 files를 요구한다. rootless Docker에서 container uid 0이 host `cks`로 매핑되므로 image는 의도적으로 `USER 1001`을 사용하지 않는다. | host directory 선행 provision과 deploy readback 필요. |
| encrypted backup | `ops/state_backup.py`가 exact source map의 JSON/JSONL, SQLite online snapshot과 fixed-member security family를 producer-signed CMS 후 AES-256-GCM AuthEnvelopedData로 암호화한다. verify, clean/replace restore, durable journal와 SIGKILL recovery를 제공한다. | 현재 map은 전체 Monitor state가 아니며 scheduling/off-host RPO 없음. production drill 필요. |
| backup TOCTOU fix | quiesced family도 initial capture 뒤 각 member를 anchored directory FD로 다시 열어 identity/full metadata/content hash를 재검증하고 마지막 directory enumeration을 수행한다. same-length in-place mutation, rotation, link/extra member를 거부한다. | writer stop을 대체하지 않는다; `--confirm-quiesced`가 필수. |
| resilience budget | `ops/resilience-budgets.json`이 2배 history/readers, p95, heap, response/series cap을 versioning하고 `server/load-budget.test.ts`, `scripts/run-resilience-suite.sh`, scheduled workflow가 실행 경로를 둔다. | full ingest/delivery/browser/soak와 live fault는 제한적. |
| release hygiene | deploy workflow는 tracked Python compile, JSON parse, shell syntax, systemd verify, backup CLI, full tests, Compose, two-platform manifest, SBOM/provenance와 platform별 critical scan을 gate한다. | 현재 worktree의 원격 성공 artifact와 production readback은 pending. |
| 화면 구성 | operational health → compact rule summary → adaptive widgets 순서이며 Linux/Docker 상세, generic logs, synthetic 상태와 top action links가 실제 components에 연결된다. 반응형 CSS와 contract rendering tests가 있다. | 최종 fresh browser screenshot/visual readback은 pending. |

## 핵심 공개 계약

### 상태 의미

- host heartbeat는 `healthy|delayed|disconnected|maintenance|inactive|unknown|collection_error`를 구분한다.
- Linux source는 `supported|partial|unsupported|permission_error|unavailable|invalid`를 구분한다.
- container snapshot은 `fresh|last-known|unavailable|permission-denied`, Docker event는 `fresh|gap|unavailable|permission-denied`를 구분한다.
- synthetic source/result와 generic-log source는 stale, unsupported, permission, unavailable, collection error를 빈 성공과 분리한다.
- rule evaluator는 관측 없음으로 active alert를 자동 resolve하지 않고 valid recovery evidence를 요구한다.

### Docker 개인정보 경계

Docker v4의 58 fields에는 자원 total/rate, lifecycle, limit, mount/network count,
security boolean, image evidence와 exact reviewed host-storage 판정만 있다. raw container ID는 domain-separated opaque
digest가 되고 raw mount path, IP/MAC, command, environment, health/log body는 공개되지
않는다. `approved`는 fresh exact match에만 허용되고 `drift`·`unknown`은 위험으로
남는다. counter 감소·instance 변경·긴 gap의 rate는 0이 아니라 `null`이며 last-known
source의 delta를 현재 evidence로 평가하지 않는다.

### API-key edge 경계

애플리케이션 route allowlist와 외부 alias allowlist는 별도다. 활성화된 외부
automation은 `/monitor/api-key/v1/...`만 사용한다. 현재는 원본 TLS가 없어 alias
include 자체가 비활성이고 그 경로도 SSO 경계 아래 있다. 일반 `/monitor/`와
`/monitor/api/...`, security management, agent mTLS route도 계속 SSO/전용 edge
경계 아래 있다. source-IP 제한은 Nginx의 trusted single-hop 주소에 의존하므로 원본
TLS, Cloudflare Full (strict), range와 direct-origin 차단을 검증하지 않고 “client IP
제한 완료”라고 선언하지 않는다.

### 백업 신뢰 경계

backup 도구는 glob이나 임의 CLI source path를 받지 않는다. application-security
family는 required `api-keys.json`과 optional audit generation의 존재/부재까지 signed
manifest에 묶으며, unexpected file 하나도 전체 backup을 실패시킨다. 암호화 archive
생성만으로 FA-40을 통과시키지 않는다. off-host copy, independent verify, empty-root
restore, Monitor startup/API-key authentication/audit readback과 측정 RPO/RTO가 필요하다.

## 코드·기본값·운영 상태 구분

| 기능 | 코드 경로 | 기본 상태 | 현재 운영 증거 |
| --- | --- | --- | --- |
| local collector/Linux/Docker/rules | production graph에 연결 | enabled | 새 worktree deploy 후 재확인 필요 |
| synthetic probe | collector contract와 rule/UI 연결 | timer disabled | target/config/enable readback 없음 |
| alert delivery | evaluator→outbox→worker 연결 | config 의존 | 실제 channel/receiver 없음 |
| central agent control/ingest | server vertical slice | disabled | PKI/proxy/consumer 없음 |
| agent producer/transport | 별도 units와 CLI | disabled | enrollment/replay 실증 없음 |
| application API key | app route와 state 연결; external alias disabled | security state 필요 | HTTP-only 원본 때문에 SSO 뒤에 유지; origin-TLS activation pending |
| public readiness | app+Nginx+external probe | public exact route | exact 200/no-store와 SSO redirect 확인 |
| external dead-man issue | GitHub Actions workflow | push 후 schedule/manual | remote issue lifecycle run pending |
| state backup | opt-in CLI | unscheduled | production off-host/clean restore pending |
| multiarch release/deploy | GitHub Actions | main push 시 | final commit CI/deploy pending |

## 검증 상태

각 변경에는 focused regression이 포함된다. 특히 다음 실패 경계를 자동화했다.

- Linux/Docker exact schema, counter reset, unsupported/permission/stale와 UI rendering
- synthetic DNS rebinding·private/mixed answer·redirect·proxy·TLS/HTTP failure
- log redaction·multiline·burst quota·rotation·crash-safe cursor
- alert duration/hysteresis/no-data, suppression·silence 해제의 restart-safe exactly-once enqueue, outbox retry/lease/final failure
- API-key filesystem/fsync, scope/IP/expiry/revoke/rotation, tombstone churn과 bearer mutation
- backup ciphertext/signature tamper, clean restore, TOCTOU in-place change, SIGKILL rollback
- agent immutable replay, homogeneous batches, stale self sample, permanent quarantine,
  legacy mixed-queue restart와 spool bounds
- external readiness exact body/cache/SSO contract 및 durable issue workflow shape

이 목록은 최종 전체 gate 성공 선언이 아니다. 모든 agent 수정이 끝난 동일 worktree에서
Python 전체 suite, TypeScript typecheck/Vitest, production build, dependency audit,
shell/Python/JSON/systemd/Compose 검사, resilience suite와 `git diff --check`를 다시
실행해야 한다. 그 뒤에만 원격 CI·deploy·readback 결과를 이 문서와 최종 감사의
FA-43/44/50에 반영한다. 특정 테스트 수는 작업 중 변하므로 고정하지 않는다.

## 남은 우선순위

1. 원본 TLS·Cloudflare Full (strict) 후 실제 API-key alias와 trusted real-IP/direct-origin firewall readback
2. actual CA/mTLS listener, agent enrollment/rotation/revoke와 offline replay
3. central ingest consumer/partition/query 및 end-to-end idempotency/backpressure
4. production delivery channels와 receiver idempotency/final-failure escalation
5. recurring silence, dynamic dependency suppression, rule CRUD/version/audit와 incident ack/owner/note
6. 전체 durable state map, off-host encrypted backup과 clean-host application restore
7. full load/soak, live network fault, ENOSPC/inode와 real clock-step recovery
8. final two-platform CI artifact, production revision/digest/health/rollback readback
9. GitHub-hosted dead-man 정상 run과 failure issue→recovery close 증거
