# Monitor 데이터 흐름 분석

> 요구사항: Monitor.md 1-2, M0-07/09~15/17/20~24
> 기준 커밋: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 후속 증분: 2026-08-30 local identity/heartbeat, typed Docker source,
> rule/overall 연결 변경을 이 문서에 반영한다.
> 상태 ID는 [최종 감사](monitoring-final-audit.md)와 [갭 분석](monitoring-gap-analysis.md)을 참조한다.

## 핵심 판단

현재 데이터 흐름은 여전히 중앙 ingest 서버로 전송하는 agent 구조가 아니다.
**동일 호스트의 systemd one-shot collector가 host 파일과 축약된 Docker
snapshot을 읽고, stable local host/agent identity와 sequenced heartbeat를 붙여
local JSON/JSONL을 원자적으로 교체하며, Express가 그 파일을 요청 시
동기적으로 읽는 구조**다. 따라서 UUID와 sequence가 생겼어도 host→server
network 전송, remote registration/enrollment, mTLS, offline resend/ack,
duplicate/out-of-order merge 경로는 존재하지 않는다. local filesystem과 한
host가 수집·저장·API의 공통 장애 영역이다.

## 전체 흐름

```mermaid
flowchart LR
  subgraph Host[Ubuntu / Raspberry Pi host]
    PROC[/proc + /sys + statvfs/]
    KLOG[fixed host log files]
    NGINX[Nginx privacy traffic JSONL]
    DSOCK[cks rootless Docker socket]
    EXP[cks one-shot container exporter]
    SNAP[/run/.../containers.json]
    TIMER[systemd 60 s timer]
    COL[root collector]
    STATE[private identity/sequence + cursors + pending journals]
    EXPORT[/var/lib/monitor-export JSON/JSONL]
    UG[unprivileged update gateway]
    QUEUE[private bounded update queue]
    UW[root fixed-policy APT worker]
    AUDIT[update audit JSONL]
  end

  subgraph Web[rootless Monitor container]
    API[Express API]
    AUTH[SSO edge headers or local signed session]
    UI[React dashboard]
  end

  subgraph External[External boundaries]
    EDGE[TLS Nginx + central SSO]
    BROWSER[Browser]
    APT[Ubuntu package repositories]
    DEPLOY[GitHub Actions + external deploy dispatcher]
  end

  DSOCK -->|Unix HTTP GET list/stats| EXP
  EXP -->|atomic fixed-schema file| SNAP
  TIMER --> COL
  PROC --> COL
  KLOG -->|bounded inode cursor| COL
  NGINX -->|bounded JSONL cursor| COL
  SNAP -->|read-only bind| COL
  STATE <-->|crash replay| COL
  COL -->|schema-v2 identity/heartbeat + atomic JSON/JSONL| EXPORT
  EXPORT -->|read-only bind; synchronous read| API
  AUTH --> API
  BROWSER -->|HTTPS via edge| EDGE --> API
  API -->|bounded JSON| UI
  API -->|Unix fixed JSON request| UG --> QUEUE --> UW
  UW -->|fixed argv; network| APT
  UW --> EXPORT
  UW --> AUDIT
  DEPLOY -->|deploy monitor SHA| Host
```

### 보안 경계

1. Docker socket은 `User=cks` one-shot exporter만 보고 root collector와 web container는 보지 않는다(`ops/systemd/monitor-container-exporter.service:16-46`).
2. root collector는 protected logs를 읽지만 host write는 export/runtime 경로로 제한된다(`ops/systemd/monitor-collector.service:20-57`).
3. web container는 telemetry를 read-only로 받고 capability를 모두 drop한다(`docker-compose.yml:18-40`). update Unix socket은 의도된 유일한 host mutation capability다.
4. SSO header는 edge secret이 일치할 때만 신뢰한다(`server/sso.ts:120-136`). 이 저장소 밖 Nginx가 client-supplied headers를 제거해야 전체 경계가 성립한다.
5. raw Docker metadata와 raw log line은 export 전에 fixed label/semantic event로 축약된다.
6. raw `/etc/machine-id`, 그 private SHA-256 binding, raw Linux boot UUID는 API에
   전달되지 않는다. 공개 identity는 random UUIDv4 두 개, binding status와 별도
   namespace의 reduced boot digest만 포함한다.

### 흐름별 현재 판정

| DF ID | 판정 | 판정 근거 |
| --- | --- | --- |
| DF-01 | 부분 통과 | host sample/timer와 stable local identity, sequence/expected-interval heartbeat는 있지만 missed interval replay나 remote ack가 없다. |
| DF-02 | 부분 통과 | rootless list/inspect/stats와 typed source status는 연결됐으나 Docker event/retry가 없고 inspect/stats가 각각 30개 cap이다. |
| DF-03 | 구현 완료(제한 범위) | reduced handoff 실패가 host publication을 막지 않고 fresh/last-known/unavailable/permission-denied로 격리된다. 이는 단일-host file handoff 판정이며 중앙 source model 완료는 아니다. |
| DF-04 | 부분 통과 | selected semantic cursor/journal은 있으나 generic source, multiline, loss/drop accounting이 없다. |
| DF-05 | 부분 통과 | incident의 7-reason lifecycle은 durable하고 별도 82-rule versioned evaluator도 연결됐지만 rule CRUD/override와 delivery outbox는 없다. |
| DF-06 | 부분 통과 | atomic file/journal/retention은 있으나 full backup/restore와 ENOSPC degradation이 없다. |
| DF-07 | 부분 통과 | bounded normalization은 있으나 sync N-file scan, request budget/cache/load proof가 없다. |
| DF-08 | 부분 통과 | refresh abort/error UI는 있으나 wall timeout, offline cache, realtime stream이 없다. |
| DF-09 | 구현 완료(제한 범위) | chief-admin→gateway→fixed APT worker의 현재 package-action 범위에서 queue/audit/failure path가 연결된다. 일반 remote action은 아니다. |
| DF-10 | 부분 통과/검증 불가 | CI는 amd64+arm64 manifest와 플랫폼별 scan을 정의하지만 external dispatcher rollback/readiness readback은 저장소만으로 검증할 수 없다. |

## 단계별 계약과 실패 특성

| DF ID | 단계 | 입력 → 출력 / 프로토콜 | 주기·timeout | retry·중복 처리 | 유실·지연·장애 전파 | 보안·architecture |
| --- | --- | --- | --- | --- | --- | --- |
| DF-01 | Host metric sampling | procfs/sysfs/statvfs → fixed sample + schema-v2 local identity/heartbeat | timer 60s + 0~2s jitter; collector `TimeoutStartSec=45s`; declared interval 10~86,400s | overlap은 nonblocking flock으로 skip. identity sequence를 snapshot 전에 durable하게 증가시켜 publication 실패는 gap으로 남김 | 실패 interval은 backfill되지 않는다. sequence gap은 보이지만 central ack/replay는 없음 | Linux-specific. machine-id hash는 private이며 raw boot UUID 대신 reduced digest만 공개 |
| DF-02 | Docker list/inspect/stats | Unix socket HTTP filtered list + bounded inspect/stats → 17-field rows | per curl 2s 기본, 최대 5s; worker 6; detail deadline 20s; outer 35s; inspect/stats 각 30 | retry/backoff 없음. source 실패 시 이전 admitted observation 보존 | allowlisted project list 실패 시 exporter는 새 snapshot을 쓰지 않지만 root collector는 host sample을 계속 쓰고 source status를 내보냄 | UID 1001 socket only; raw ID는 private. daemon/version/cgroup matrix 미검증 |
| DF-03 | Reduced container handoff | mode 0640 `containers.json` → `containers` + `containerCollection` | fresh age 최대 180s, future tolerance 60s | owner/mode/link/size/exact schema 재검증; previous admitted observation만 last-known으로 재사용 | invalid/unavailable/permission failure는 typed source 상태가 되고 host current/history는 계속 publication | raw ID/image/mount/env 제거. stable public container instance identity는 없음 |
| DF-04 | Semantic log tail | event/kernel/privilege/traffic files → fixed event rows/current traffic | 일반 source 최대 1MiB/run, kernel 8MiB/run; line bound | inode+offset cursor, rotated residual tail, pending publication digest | backlog가 max byte보다 크면 newest window로 점프하여 old data 유실 가능. drop count 없음. incomplete line은 다음 poll | protected logs read-only; fixed message로 raw secret exposure 최소화; journald 없음 |
| DF-05 | Incident/rule evaluation | latest metrics + reduced evidence + private state → incident lifecycle, 82-rule evaluation/transition | collector run마다 1회 | incident pending commit과 deterministic rule transition replay | incident는 고정 reason model이고 rules는 seed pack이다. CRUD/override/outbox 장애 격리는 없음 | reduced bounded evidence only; unsupported 신호는 명시적으로 구분 |
| DF-06 | File persistence | current/history/events/incidents → atomic files | 매 run; history 2,000/day; retention 30d | temp+fsync+rename, private pending journals, digest readback | ENOSPC/inode error 시 old atomic target이 남을 수 있으나 새 interval 유실. 전체 export backup/restore 없음 | root:cks 0640 public, private state 0600. SD write amplification은 측정 안 됨 |
| DF-07 | API read | bounded JSON/JSONL files → `DashboardResponse` JSON over HTTP | request마다 sync read/parse; server request timeout 없음 | network retry 없음. API normalizes/sorts; current/history 동일 timestamp merge | 30d worst bound는 여러 파일 sync read로 event loop를 막을 수 있음. malformed source는 해당 data를 drop하고 shape 유지 | no-store, Helmet, auth required. local timezone formatting은 browser layer |
| DF-08 | Browser refresh | `GET /monitor/api/dashboard?range=` → React state/charts | visible tab 60s; fetch `AbortController`지만 wall timeout 없음 | 새 refresh가 이전 fetch abort; 실패 후 next interval/manual refresh | browser/network/SSO failure는 기존 data와 error 표시. offline cache/buffer 없음 | same-origin credentials; client is arch-independent, low-end performance not measured |
| DF-09 | Host package action | authenticated JSON → Unix gateway → private queue → fixed APT plan/status/audit | API socket timeout은 `server/system-updates.ts`에서 bounded; queue depth 8; apt phases별 30s~10m, apply precommit 90m | queue request IDs, one-use plan nonce, terminal audit replay; arbitrary automatic retry 없음 | restart before apply invalidates in-memory nonce. worker crash terminalizes without replaying APT. package network failure yields failed status | chief-admin + exact same-origin + peer UID + fixed argv. Ubuntu/architecture is plan digest input |
| DF-10 | Deployment | Git SHA amd64+arm64 manifest → GHCR → external dispatcher → Compose | CI 60m; SSH connect 15s/keepalive | concurrency no cancel; external rollback is documented but implementation external | GitHub/GHCR/DNS/SSH failure stops deploy. actual rollback/readiness proof cannot be reconstructed from repo | both platform entries and per-platform critical scans are source-gated |

## 데이터 구조

### Collector public snapshot

`current.json`은 다음 top-level fixed fields를 가진다.

```text
schemaVersion = 2
generatedAt
identity { hostId, agentId, installationEpoch, identityGeneration,
           machineIdentityStatus, bootId }
heartbeat { sequence, observedAt, receivedAt, expectedIntervalSeconds,
            lifecycle, transport=local-file }
host { hostname, os, architecture, logicalCpuCount, uptimeSeconds }
latest { timestamp, CPU/memory/swap/load/PSI/power/network/disk scalar fields }
disks[] { mount, total/used/available bytes, used/inode percent, readOnly }
containers[] { 17-field name/project/owner/state/health/resource-limit/restart/OOM/lifecycle contract }
containerCollection { fresh|last-known|unavailable|permission-denied, observedAt }
currentTraffic[] { fixed app, request/status/slow counts, avg/max response }
reliability { bootStartedAt, collectorGapSeconds, SSH/network/NVMe states }
system { versions, PCIe, kernel event counters }
```

Stable local host/agent UUID와 local-file heartbeat, Docker project/source
availability는 있다. Docker daemon identity, public container instance/digest,
일반 metric source status, 중앙 registration/transport state는 없다. 자세한
현재·개선 model은 [데이터 모델](monitoring-data-model.md)을 본다.

### Durable files

| 파일 | 역할 | 보존/크기 | replay |
| --- | --- | --- | --- |
| `current.json` | 최신 snapshot | 1 object, atomic replace | 없음; 마지막 valid copy 사용 |
| `history/YYYY-MM-DD.jsonl` | scalar time series | 2,000 rows/day, 30d default | delta counter는 runtime only; missed interval backfill 없음 |
| `alerts/power/privilege/reliability.jsonl` | semantic events | 각 bounded, API newest 500 | cursor+pending digest replay |
| `incidents.jsonl` | threshold evidence captures | 1,000 records/16MiB/30d | lifecycle+pending commit replay |
| `.state/collector-identity.json` | UUID, generation, private machine hash, sequence | exact 4KiB 이하, private 0600 | normal restart continuity; verified machine change rekey |
| `.state/*.json` | cursors/lifecycle/pending journals | private 0600 | startup/re-run pre-read replay |
| `system-update.json` | updater public state | atomic 0640 | worker startup status recovery |

## 시각·중복·순서 정책

- collector는 UTC ISO timestamp를 쓴다. syslog timestamp는 host local time을 `time.mktime`으로 UTC 변환하므로 host timezone/clock 정확도에 의존한다(`ops/collector.py:1995-2022`).
- API는 현재 시각보다 60초 넘게 미래인 sample/event를 제외하고, history를 timestamp로 정렬한다(`server/data.ts:1492-1516`). skew 원인이나 correction은 기록하지 않는다.
- current와 history의 timestamp가 같으면 non-null field를 merge한다. 현재
  snapshot에는 monotonic local heartbeat sequence가 있지만 history row에는 없고,
  central receiver의 duplicate/out-of-order merge도 없다. identity state를 public
  snapshot보다 먼저 기록하므로 publication failure는 sequence gap으로 보인다.
- power event는 same-second semantic duplicate를 collapse하지만 alert/privilege는 서로 다른 source row가 동일해도 보존한다.
- collector crash journal은 “output write 후 cursor write 전” replay를 안전하게 처리한다. 이는 network agent 중복 처리와는 별개다.

## 네트워크 단절 동작

| 단절 지점 | 현재 동작 | 복구 | 결손 |
| --- | --- | --- | --- |
| Browser ↔ Nginx/API | fetch error, 기존 화면과 error indicator; 60초 후 재시도 | 다음 visible refresh/manual | server 데이터는 유지, browser 실시간성만 손실 |
| Central SSO ↔ Nginx | 인증 진입/refresh 실패. app은 trusted header 없으면 거부 | SSO 복구 후 새 request | telemetry 손실 없음; 사용자 접근 불가 |
| Docker Unix socket | exporter 실패 시 이전 admitted list를 typed last-known/permission 상태로 유지하거나 no-prior unavailable 표시; host publication은 계속 | 다음 timer가 전체 project list 재시도 | Docker interval만 결손이며 last-known을 current로 평가하면 안 됨 |
| APT repositories | check/apply status 실패, raw output 미공개 | operator 재요청; 자동 exponential retry 없음 | package action만 실패; telemetry는 독립 |
| GitHub/GHCR/SSH | workflow/deploy 실패 | workflow 재실행 | 현재 service는 유지된다고 문서화되나 external dispatcher 검증 필요 |
| Remote agent ↔ central server | 해당 경로 없음. `receivedAt`은 local-file에서 `observedAt`과 같다 | 없음 | registration/mTLS/offline spool/ack/central dedup 미구현 |

## 재시작 복구

```mermaid
sequenceDiagram
  participant T as systemd timer
  participant C as Collector
  participant J as Pending journal
  participant E as Public export
  participant A as Express API

  T->>C: next one-shot
  C->>J: replay pending commits before reads
  alt pending base digest matches
    J->>E: finish atomic destinations
    J->>J: persist cursors, remove journal
  else unsafe/diverged journal
    C-->>T: fail closed; preserve journal
  end
  C->>E: publish new current/history/state
  A->>E: stateless read after restart
```

- **Collector restart:** private pending journal을 먼저 replay한다. `/run` delta counters는 systemd `RuntimeDirectoryPreserve=yes`이지만 host reboot에는 없어져 첫 rate가 `null`이 된다.
- **Identity restart/clone:** mode-`0600` identity state가 UUID와 sequence를 이어간다.
  retained/current machine hash가 모두 있고 다르면 두 UUID를 재발급하고 generation을
  올린 뒤 sequence 1로 시작한다. retained binding은 일시적 read 실패에도
  유지되지만, 두 hash 중 하나라도 없으면 그 run의 clone 비교는 불가능하다.
- **Host reboot:** persistent identity/sequence는 남고 reduced boot digest가 바뀌며
  uptime/boot transition을 기록한다. missed intervals는 복원하지 않는다.
- **Express restart:** telemetry는 read-only files이므로 stateless하게 복구한다. local auth state는 file에 있고 SSO identity는 request마다 재계산된다.
- **Update API restart:** `UpdateNonceStore`가 memory-only라 prepare nonce가 무효화된다. 재확인을 강제하는 안전한 실패다.
- **Updater worker restart:** claimed request와 terminal audit/status를 복구하고 APT apply를 자동 재실행하지 않는다.

## 병목과 장애 전파

1. **Synchronous API read:** 각 dashboard request가 최대 30개 history file과 여러 event file을 Node event loop에서 sync parse한다. cache/index가 없다.
2. **Sequential project lists:** 각 allowlisted Compose project의 Docker list request가 순차이고 retry가 없다. 여러 timeout은 35초 outer limit에 근접한다.
3. **Single filesystem/local heartbeat:** telemetry, identity, cursor와 API input이 같은 storage failure domain에 있다. heartbeat는 독립 dead-man이나 remote receipt가 아니다.
4. **No central merge/spool:** sequence는 current snapshot에만 있어 receiver ack, replay, duplicate/out-of-order 처리와 remote copy/restore가 없다.
5. **No notification pipeline:** incident 생성 후 사용자에게 전달되는 비동기 경로가 없다.
6. **Partial source envelope:** Docker와 rule status는 typed지만 일반 metric/log source는 여전히 `null`/empty/failure가 섞인다.

## P0 데이터 흐름 수정 순서

1. Docker 외 DF-01~04 source에도 `sourceStatus`, `observedAt`, error class와 drop counters를 추가한다.
2. local UUID/sequence를 중앙 registration, mTLS enrollment와 연결하고 identity conflict/revocation을 정의한다.
3. bounded offline spool/ack/retry와 sequence 기반 duplicate/out-of-order receiver merge를 구현한다.
4. 관리자 lifecycle 변경의 actor/reason/time/audit workflow를 구현한다.
5. alert evaluator/outbox를 collector publication과 별도 journal/worker로 분리해 backpressure를 격리한다.
6. API sync read 비용을 measured cache/index로 제한하고 memory budget을 CI load gate로 검증한다.

완료 기준은 DF 단계 하나가 실패해도 다른 source의 fresh data가 계속 publication되고, downstream이 `unsupported`, `permission_denied`, `failed`, `no_data`, `stale`을 구분하며, 유실·drop·retry를 수치로 설명할 수 있는 것이다.
