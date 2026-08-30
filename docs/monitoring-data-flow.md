# Monitor 데이터 흐름 분석

> 요구사항: Monitor.md 1-2, M0-07/09~15/17/20~24
> 기준 커밋: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 상태 ID는 [최종 감사](monitoring-final-audit.md)와 [갭 분석](monitoring-gap-analysis.md)을 참조한다.

## 핵심 판단

현재 데이터 흐름은 중앙 ingest 서버로 전송하는 agent 구조가 아니다. **동일 호스트의 systemd one-shot collector가 host 파일과 축약된 Docker snapshot을 읽고, local JSON/JSONL을 원자적으로 교체하며, Express가 그 파일을 요청 시 동기적으로 읽는 구조**다. 따라서 host→server network 단절·offline resend·remote registration이라는 명세 경로는 존재하지 않는다. 대신 local filesystem과 한 host가 수집·저장·API의 공통 장애 영역이다.

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
    STATE[private cursors + pending journals]
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
  COL -->|atomic JSON/JSONL| EXPORT
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

### 흐름별 현재 판정

| DF ID | 판정 | 판정 근거 |
| --- | --- | --- |
| DF-01 | 부분 통과 | host sample 실행 경로와 timer는 있지만 source별 status와 missed interval replay가 없다. |
| DF-02 | 부분 통과 | rootless list/stats는 연결됐으나 event/retry/source status가 없고 30개 stats cap이 있다. |
| DF-03 | 실패 | privacy-reduced handoff 자체는 안전하지만 invalid/exporter failure가 host collector dependency로 전파될 수 있다. |
| DF-04 | 부분 통과 | selected semantic cursor/journal은 있으나 generic source, multiline, loss/drop accounting이 없다. |
| DF-05 | 부분 통과 | 7 reason state는 durable하지만 general versioned rule/evaluator가 아니며 CPU 기본 single-sample이다. |
| DF-06 | 부분 통과 | atomic file/journal/retention은 있으나 full backup/restore와 ENOSPC degradation이 없다. |
| DF-07 | 부분 통과 | bounded normalization은 있으나 sync N-file scan, request budget/cache/load proof가 없다. |
| DF-08 | 부분 통과 | refresh abort/error UI는 있으나 wall timeout, offline cache, realtime stream이 없다. |
| DF-09 | 구현 완료(제한 범위) | chief-admin→gateway→fixed APT worker의 현재 package-action 범위에서 queue/audit/failure path가 연결된다. 일반 remote action은 아니다. |
| DF-10 | 부분 통과/검증 불가 | ARM64 CI build와 deploy request는 있으나 amd64 artifact와 external dispatcher rollback readback은 없다. |

## 단계별 계약과 실패 특성

| DF ID | 단계 | 입력 → 출력 / 프로토콜 | 주기·timeout | retry·중복 처리 | 유실·지연·장애 전파 | 보안·architecture |
| --- | --- | --- | --- | --- | --- | --- |
| DF-01 | Host metric sampling | procfs/sysfs/statvfs text → `latest` fixed JSON fields; local file read | timer 60s + 0~2s jitter; collector `TimeoutStartSec=45s` | collector overlap은 nonblocking flock으로 skip; delta counters는 private state | 한 실행 실패 시 그 interval은 영구 공백. 일부 read helper는 empty/null로 축약하지만 top-level exception은 run 전체 실패 | Linux-specific. proc/sys fixture는 arch-neutral이나 Pi sysfs path는 hardware-specific |
| DF-02 | Docker list/stats | Unix socket HTTP `/v1.41/containers/json?...`와 `/stats` → 7-field rows | per curl 2s 기본, 최대 5s; 최대 6 stats worker; stats global deadline 20s; service outer 35s | retry/backoff 없음. source 실패 시 이전 snapshot 보존 | allowlisted project list 하나만 실패해도 exporter 전체 실패. 다음 timer까지 stale; 최대 30 running container만 stats | UID 1001 socket only. Docker API는 arch-neutral; daemon/version/cgroup matrix 미검증 |
| DF-03 | Reduced container handoff | mode 0640 `containers.json` → root collector current snapshot | age 허용 -60~180s | owner/mode/link/size/schema 재검증; exact list sort | invalid/stale snapshot이면 collector 실패, old `current.json`이 남고 결국 전역 stale | raw ID/image/mount/env 제거. stable container identity도 함께 손실 |
| DF-04 | Semantic log tail | event/kernel/privilege/traffic files → fixed event rows/current traffic | 일반 source 최대 1MiB/run, kernel 8MiB/run; line bound | inode+offset cursor, rotated residual tail, pending publication digest | backlog가 max byte보다 크면 newest window로 점프하여 old data 유실 가능. drop count 없음. incomplete line은 다음 poll | protected logs read-only; fixed message로 raw secret exposure 최소화; journald 없음 |
| DF-05 | Incident evaluation | latest metrics + processes/containers/traffic + prior state → optional incident row/state | collector run마다 1회 | durable pending incident commit과 lifecycle replay. exact crash stage idempotent | evaluator 자체가 throw하면 current/history가 이미 써진 뒤 incident/log commit이 지연될 수 있음. 7 reasons 외 신호는 평가하지 않음 | arch-neutral arithmetic; CPU default 1 sample은 명세 duration과 충돌 |
| DF-06 | File persistence | current/history/events/incidents → atomic files | 매 run; history 2,000/day; retention 30d | temp+fsync+rename, private pending journals, digest readback | ENOSPC/inode error 시 old atomic target이 남을 수 있으나 새 interval 유실. 전체 export backup/restore 없음 | root:cks 0640 public, private state 0600. SD write amplification은 측정 안 됨 |
| DF-07 | API read | bounded JSON/JSONL files → `DashboardResponse` JSON over HTTP | request마다 sync read/parse; server request timeout 없음 | network retry 없음. API normalizes/sorts; current/history 동일 timestamp merge | 30d worst bound는 여러 파일 sync read로 event loop를 막을 수 있음. malformed source는 해당 data를 drop하고 shape 유지 | no-store, Helmet, auth required. local timezone formatting은 browser layer |
| DF-08 | Browser refresh | `GET /monitor/api/dashboard?range=` → React state/charts | visible tab 60s; fetch `AbortController`지만 wall timeout 없음 | 새 refresh가 이전 fetch abort; 실패 후 next interval/manual refresh | browser/network/SSO failure는 기존 data와 error 표시. offline cache/buffer 없음 | same-origin credentials; client is arch-independent, low-end performance not measured |
| DF-09 | Host package action | authenticated JSON → Unix gateway → private queue → fixed APT plan/status/audit | API socket timeout은 `server/system-updates.ts`에서 bounded; queue depth 8; apt phases별 30s~10m, apply precommit 90m | queue request IDs, one-use plan nonce, terminal audit replay; arbitrary automatic retry 없음 | restart before apply invalidates in-memory nonce. worker crash terminalizes without replaying APT. package network failure yields failed status | chief-admin + exact same-origin + peer UID + fixed argv. Ubuntu/architecture is plan digest input |
| DF-10 | Deployment | Git SHA image → GHCR → external dispatcher → Compose | CI 60m; SSH connect 15s/keepalive | concurrency no cancel; external rollback is documented but implementation external | GitHub/GHCR/DNS/SSH failure stops deploy. actual rollback/readiness proof cannot be reconstructed from repo | ARM64 only build. amd64 artifact absent |

## 데이터 구조

### Collector public snapshot

`current.json`은 다음 top-level fixed fields를 가진다.

```text
generatedAt
host { hostname, os, architecture, logicalCpuCount, uptimeSeconds }
latest { timestamp, CPU/memory/swap/load/PSI/power/network/disk scalar fields }
disks[] { mount, total/used/available bytes, used/inode percent, readOnly }
containers[] { name, owner, state, health, cpuPercent, memoryBytes, memoryPercent }
currentTraffic[] { fixed app, request/status/slow counts, avg/max response }
reliability { bootStartedAt, collectorGapSeconds, SSH/network/NVMe states }
system { versions, PCIe, kernel event counters }
```

Host/agent UUID, Docker daemon, Compose project/service, container instance/digest, source availability와 metric status는 없다. 자세한 현재·개선 model은 [데이터 모델](monitoring-data-model.md)을 본다.

### Durable files

| 파일 | 역할 | 보존/크기 | replay |
| --- | --- | --- | --- |
| `current.json` | 최신 snapshot | 1 object, atomic replace | 없음; 마지막 valid copy 사용 |
| `history/YYYY-MM-DD.jsonl` | scalar time series | 2,000 rows/day, 30d default | delta counter는 runtime only; missed interval backfill 없음 |
| `alerts/power/privilege/reliability.jsonl` | semantic events | 각 bounded, API newest 500 | cursor+pending digest replay |
| `incidents.jsonl` | threshold evidence captures | 1,000 records/16MiB/30d | lifecycle+pending commit replay |
| `.state/*.json` | cursors/lifecycle/pending journals | private 0600 | startup/re-run pre-read replay |
| `system-update.json` | updater public state | atomic 0640 | worker startup status recovery |

## 시각·중복·순서 정책

- collector는 UTC ISO timestamp를 쓴다. syslog timestamp는 host local time을 `time.mktime`으로 UTC 변환하므로 host timezone/clock 정확도에 의존한다(`ops/collector.py:1995-2022`).
- API는 현재 시각보다 60초 넘게 미래인 sample/event를 제외하고, history를 timestamp로 정렬한다(`server/data.ts:1492-1516`). skew 원인이나 correction은 기록하지 않는다.
- current와 history의 timestamp가 같으면 non-null field를 merge한다. general batch ID/sequence는 없다.
- power event는 same-second semantic duplicate를 collapse하지만 alert/privilege는 서로 다른 source row가 동일해도 보존한다.
- collector crash journal은 “output write 후 cursor write 전” replay를 안전하게 처리한다. 이는 network agent 중복 처리와는 별개다.

## 네트워크 단절 동작

| 단절 지점 | 현재 동작 | 복구 | 결손 |
| --- | --- | --- | --- |
| Browser ↔ Nginx/API | fetch error, 기존 화면과 error indicator; 60초 후 재시도 | 다음 visible refresh/manual | server 데이터는 유지, browser 실시간성만 손실 |
| Central SSO ↔ Nginx | 인증 진입/refresh 실패. app은 trusted header 없으면 거부 | SSO 복구 후 새 request | telemetry 손실 없음; 사용자 접근 불가 |
| Docker Unix socket | exporter 실패, 이전 snapshot 유지; required dependency로 collector도 실패 가능 | 다음 timer가 전체 project list 재시도 | 실패 interval 전체 host history까지 빠질 수 있음 |
| APT repositories | check/apply status 실패, raw output 미공개 | operator 재요청; 자동 exponential retry 없음 | package action만 실패; telemetry는 독립 |
| GitHub/GHCR/SSH | workflow/deploy 실패 | workflow 재실행 | 현재 service는 유지된다고 문서화되나 external dispatcher 검증 필요 |
| Remote agent ↔ central server | 해당 경로 없음 | 없음 | multi-host/offline buffer 기능 미구현 |

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
- **Host reboot:** persistent export/state는 남고 uptime/boot transition을 기록한다. missed intervals는 복원하지 않는다.
- **Express restart:** telemetry는 read-only files이므로 stateless하게 복구한다. local auth state는 file에 있고 SSO identity는 request마다 재계산된다.
- **Update API restart:** `UpdateNonceStore`가 memory-only라 prepare nonce가 무효화된다. 재확인을 강제하는 안전한 실패다.
- **Updater worker restart:** claimed request와 terminal audit/status를 복구하고 APT apply를 자동 재실행하지 않는다.

## 병목과 장애 전파

1. **Required Docker exporter:** daemon/list 하나의 실패가 root collector service 실패로 이어져 host metric까지 한 interval 잃을 수 있다. Docker와 host sampling을 분리 publication해야 한다.
2. **Synchronous API read:** 각 dashboard request가 최대 30개 history file과 여러 event file을 Node event loop에서 sync parse한다. cache/index가 없다.
3. **Sequential project lists:** 각 allowlisted Compose project의 Docker list request가 순차이고 retry가 없다. 여러 timeout은 35초 outer limit에 근접한다.
4. **Single filesystem:** telemetry, cursor와 API input이 같은 storage failure domain에 있다. remote copy/restore가 없다.
5. **No notification pipeline:** incident 생성 후 사용자에게 전달되는 비동기 경로가 없다.
6. **No source status envelope:** unavailable input이 `null`/empty/whole collector failure로 섞여 장애 원인이 하류에서 소실된다.

## P0 데이터 흐름 수정 순서

1. DF-01~04 각각에 `sourceStatus`, `observedAt`, error class와 drop counters를 추가하되 기존 fields는 유지한다.
2. Docker failure가 host sampling publication을 막지 않도록 collector stage를 격리하고 snapshot-level completeness를 표시한다.
3. stable host/agent ID와 monotonic sequence를 도입해 duplicate/out-of-order policy를 명시한다.
4. alert evaluator/outbox를 collector publication과 별도 journal/worker로 분리해 backpressure를 격리한다.
5. API sync read 비용을 measured cache/index로 제한하고 memory budget을 CI load gate로 검증한다.
6. amd64/arm64와 Pi fixture에 동일 contract test를 실행한다.

완료 기준은 DF 단계 하나가 실패해도 다른 source의 fresh data가 계속 publication되고, downstream이 `unsupported`, `permission_denied`, `failed`, `no_data`, `stale`을 구분하며, 유실·drop·retry를 수치로 설명할 수 있는 것이다.
