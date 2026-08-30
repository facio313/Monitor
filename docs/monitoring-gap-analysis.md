# Monitor 전체 기능 갭 분석

> 기준 커밋: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 요구사항: Monitor.md 1-1, 공통 M0-01~25
> 관련 최종 감사: [50항목 매트릭스](monitoring-final-audit.md)

## 결론

현재 Monitor는 **한 대의 Ubuntu/Raspberry Pi 계열 호스트를 1분마다 읽어 privacy-reduced JSON/JSONL로 내보내고, 인증된 React 대시보드에서 조회하는 단일 호스트 관제 도구**로는 실제 연결되어 있다. procfs/sysfs, 제한된 kernel/event/privilege log, rootless Docker의 allowlisted Compose workload, crash-safe 파일 publication, SSO 경계, 제한된 host package update는 구체적인 실행 경로와 테스트가 있다.

반면 Monitor.md가 정의한 **다중 host agent 플랫폼, 범용 로그 시스템, versioned alert rule/evaluator/notification, API key·resource-scoped RBAC·application audit, 중앙 시계열 저장소, offline buffer, multi-architecture release와 장애·부하 시험**은 아직 구현되지 않았다. 프론트의 operational finding과 collector의 7-reason incident lifecycle은 유용하지만 알림 시스템으로 간주하면 안 된다.

### 집계

| 상태 | 기능군 수 | 해석 |
| --- | ---: | --- |
| 구현 완료 | 8 | 현재 단일 host 범위에서 수집→파일→API→UI가 연결되고 안전 경계가 검증됨 |
| 부분 구현 | 16 | 실제 경로는 있으나 Monitor.md의 범위·상태·복구·architecture 검증이 불완전 |
| 코드만 존재/부분 연결 | 2 | 유틸리티 또는 legacy presentation 일부만 production graph에 연결 |
| UI만 존재 | 2 | 화면에서 계산·표시하지만 durable backend rule/state가 없음 |
| 데이터 수집만 존재 | 3 | signal은 있으나 alert/rule/action으로 이어지지 않음 |
| 미구현 | 15 | model/API/collector/worker 중 시작점이 없음 |
| 중복/사용 여부 재검토 | 1 | legacy `Dashboard` export와 새 `MonitorDashboard`가 공존 |

수치는 기능군 분류이며 Monitor.md 전체 prompt 개수의 완료율이 아니다. 한 행에 여러 명세 요구사항이 포함될 수 있다.

## 현재 구조

| 계층 | 구현 | 권위 있는 파일 |
| --- | --- | --- |
| Host collector | root one-shot Python, 60초 timer, procfs/sysfs/statvfs와 semantic log tail | `ops/collector.py`, `ops/systemd/monitor-collector.*` |
| Docker exporter | UID 1001 rootless socket에서 allowlisted list/stats를 읽고 reduced snapshot 생성 | `ops/container_exporter.py`, `ops/systemd/monitor-container-exporter.service` |
| 저장소 | atomic JSON/JSONL, 날짜 history, fixed caps, cursor와 pending commit journal | `ops/collector.py:319-555,2780-2825,3435-4201` |
| Backend | Express 5, sync bounded file reader, SSO/local auth, dashboard/ledger/update API | `server/app.ts`, `server/data.ts`, `server/sso.ts` |
| Frontend | React 19, adaptive grid, detail routes, 60초 visible-tab refresh | `src/App.tsx`, `src/components/MonitorDashboard.tsx`, `src/hooks/useDashboard.ts` |
| Privileged update | unprivileged Unix gateway→private bounded queue→fixed-policy root APT worker | `ops/monitor_update_gateway.py`, `ops/monitor_update_worker.py`, `ops/UPDATER.md` |
| Deployment | ARM64 image test/build/push, main에서 외부 restricted dispatcher 호출 | `.github/workflows/deploy.yml`, `Dockerfile`, `docker-compose.yml` |

## 기능 현황표

### Agent·host·storage

| 요구사항 ID | 기능 | 상태 | 증거 | 우선순위/남은 갭 |
| --- | --- | --- | --- | --- |
| M2-01, M11-03 | host/agent 등록 | 미구현 | `current.json` host에는 hostname/OS/architecture/uptime만 있음(`ops/collector.py:4846-4853`) | P0: stable hostId/agentId와 idempotent registration |
| M2-01, M11-09 | heartbeat | 부분 구현 | local timer와 collector-gap event(`ops/systemd/monitor-collector.timer`, `ops/collector.py:1886-1889`) | P0: receivedAt/sequence/source status |
| M3-01~02 | CPU/memory/swap/PSI | 구현 완료 | `ops/collector.py:4770-4829`; `server/types.ts:5-37` | 현재 단일 host 계약 유지 |
| M3-04 | filesystem capacity/inode/read-only | 구현 완료 | `ops/collector.py:988-1052` | multi-host identity만 추가 필요 |
| M3-05 | disk throughput | 부분 구현 | aggregate read/write B/s(`ops/collector.py:706-751`) | P0: device latency/util/queue, counter reset state |
| M3-07 | network throughput/error/drop | 부분 구현 | aggregate non-loopback rates(`ops/collector.py:657-704`) | P0: per-interface safe identity/TCP/conntrack |
| M3-09 | process/systemd | 데이터 수집만 존재 | incident evidence용 fixed process class(`ops/collector.py:811-944`) | P0: 평시 process/service state와 systemd collector |
| M3-03, M3-12 | OOM/kernel/reboot | 부분 구현 | fixed current-boot kernel/reliability events(`ops/collector.py:209-238,1877-1977`) | P0: journald fallback/source failure status/clock skew |
| M3-11, M17-03 | Pi temperature/power | 부분 구현 | temperature, EXT5V evidence, hwmon undervoltage(`ops/collector.py:945-986,1496-1551`) | P0: authoritative throttle state; voltage false-positive 제거 |
| M12-03 | file retention | 구현 완료 | 날짜 30일/2,000 row와 incident/log cap(`README.md:539-569`) | 장기 rollup은 P1 |
| M12-05 | crash replay/idempotency | 구현 완료 | pending incident/log/reliability journals and digests(`ops/collector.py:3470-4201`) | 다중 sender idempotency는 P1 |
| M12-01/02 | metadata/time-series DB | 미구현 | DB dependency/migration/index 없음 | P1: multi-host 필요 시 점진 도입 |
| M11-05/06 | offline buffer/network send | 미구현 | 중앙 ingest protocol 없음 | P0 status semantics, P1 bounded spool |

### Docker·Compose

| 요구사항 ID | 기능 | 상태 | 증거 | 우선순위/남은 갭 |
| --- | --- | --- | --- | --- |
| M4-01 | container state/CPU/memory | 구현 완료(제한 범위) | 7-field exact schema(`ops/collector.py:1649-1657`) | I/O/network/pids/limit은 별도 부분 |
| M4-05 | health | 부분 구현 | `docker ps` Status regex(`ops/collector.py:1630-1633`) | P0: configured/none/unknown/source error 분리와 history |
| M4-02/03 | lifecycle/restart loop | 미구현 | restart count/timestamps 없음 | P0 |
| M4-04 | OOMKilled | 미구현 | inspect state/exit reason 없음 | P0 |
| M4-06/07 | limits/throttling | 부분 구현 | Docker-reported memory limit 비율만 계산(`ops/collector.py:1637-1648`) | P0: explicit no-limit, CPU throttle/quota, pids |
| M4-09 | network | 미구현 | container schema에 network 없음 | P1 |
| M4-10 | Compose grouping | 부분 구현 | collector allowlist와 frontend name grouping | P0: public project/service stable identity |
| M4-08 | volume/writable layer | 미구현 | mounts를 의도적으로 폐기(`ops/README.md:168-176`) | P1: count/bytes/boolean만 privacy-reduced |
| M4-11 | image digest drift | 미구현 | image digest 없음 | P1 |
| M4-13 | security posture | 미구현 | privileged/socket mount/caps/security option 없음 | P0: boolean-only security snapshot |
| M4 event | Docker event stream | 미구현 | list/stats GET만 사용 | P0: cursor/reconnect/replay |
| M0-22 | socket least privilege | 구현 완료 | UID 1001 one-shot exporter만 socket bind, root/web에는 socket 없음(`ops/systemd/monitor-container-exporter.service:16-46`) | rootless daemon owner 경계 문서 유지 |

### Logs·alerts·incidents

| 요구사항 ID | 기능 | 상태 | 증거 | 우선순위/남은 갭 |
| --- | --- | --- | --- | --- |
| M7-01 | selected semantic log collection | 부분 구현 | inode/rotation cursor for fixed files(`ops/collector.py:2711-2777,4204-4281`) | P0: Docker/journald/generic file source state |
| M7-02 | JSON/logfmt/syslog/multiline | 부분 연결 | privilege JSON과 timestamp regex만 있음 | P0: parser registry and bounded multiline |
| M7-06 | sensitive reduction | 구현 완료(현재 feed) | collection allowlist + API redaction(`server/data.ts:284-295`) | rule version/history/test UI는 P1 |
| M7-07 | retention/storm control | 부분 구현 | byte/line/record caps, traffic rotate | P0: drop count/quota/priority/sampling |
| M7-03~05,09~10 | tail/search/saved search/trace/bundle | 미구현 | stream/search/OTel API 없음 | P1/P2 |
| M8-01~12 | alert system | 미구현 | general rule/channel/outbox model/API 없음 | P0 |
| M8-02/04 | incident duration/hysteresis | 데이터 수집만 존재 | 7-reason `incident_transition()` | P0: versioned evaluator; default one-sample CPU 수정 |
| M8-03 | stale/no-data | UI만 존재 | global stale Boolean and display | P0: source/metric policy |
| M8-08 | dedup | 부분 구현 | incident lifecycle, power exact dedup | P0: label/time-window alert grouping |
| M8-09~12 | suppression/silence/routing/reliable delivery | 미구현 | corresponding state/routes/workers absent | P0 |
| M7-08, M10-01~03 | timeline/incident | UI만 존재 | incident list and operational log are separately derived | P1: unified event envelope/correlation/actions |

### Auth·security·operations

| 요구사항 ID | 기능 | 상태 | 증거 | 우선순위/남은 갭 |
| --- | --- | --- | --- | --- |
| M13-01 | SSO consumer/local auth | 구현 완료(저장소 경계) | edge-secret trusted headers, signed local cookie (`server/sso.ts`, `server/auth.ts`) | OIDC provider lifecycle은 외부라 검증 불가 |
| M13-02 | RBAC | 부분 구현 | user/admin/chief role gates | P0: team/environment/host scopes; separate log/action rights |
| M13-03 | API key | 미구현 | key route/model/store 없음 | P0 |
| M13-04 | TLS/secret encryption | 부분 구현 | TLS는 external Nginx contract, private secret files | P0: env fallback 제한, encrypted external secrets/rotation docs |
| M13-05 | SSRF | 미구현 | synthetic fetch가 아직 없음 | P0 prerequisite before M5 synthetic |
| M13-06 | audit | 부분 구현 | updater audit와 imported privilege feed만 있음 | P0: application mutation audit |
| M13-07 | minimal collection | 구현 완료 | fixed labels/no raw env/mount/command/IDs | 새 Docker fields도 동일 원칙 유지 |
| M13-08 | remote action protection | 부분 구현 | only fixed APT check/apply-safe; role, re-confirmation, queue, audit | generic restart action은 미구현(P2) |
| M13-09 | supply chain | 부분 구현 | pinned Actions/base image and immutable SHA tag | P0: SCA/image scan/SBOM/multiarch digest |
| M13-10 | threat model/security tests | 부분 구현 | attack-path unit tests scattered; threat model 없음 | P0 |
| M14-07, M15-11 | deployment/rollback | 부분 구현/외부 연결 | workflow dispatches fixed command; external rollback claimed in README | P0: dispatcher contract/readback artifact를 저장소에서 검증 |
| M12-10 | self monitoring | 부분 구현 | healthz/readyz/collector-gap/monitor container | P0: queue/evaluator/delivery metrics + external dead man |

### Frontend·tests·documentation

| 요구사항 ID | 기능 | 상태 | 증거 | 우선순위/남은 갭 |
| --- | --- | --- | --- | --- |
| M9-01~03/06/10 | overview/detail/drilldown/freshness | 구현 완료 | `MonitorDashboard`, detail routes, stale/error indicator | multi-host 대상 선택은 없음 |
| M9-04/05 | ranges/refresh | 구현 완료 | 1h/24h/7d/30d and visible-tab 60s refresh | comparison/live stream은 P1 |
| M9-11 | large list bound | 부분 구현 | API caps and UI pagination | P0: measured performance/virtualization |
| M9-12 | accessibility | 부분 구현 | semantic controls/keyboard grid/reduced motion | P1: axe/browser E2E |
| M15-01 | unit/integration fixtures | 구현 완료(현재 기능) | 186 Vitest + 142 Python at audit baseline | missing subsystem tests는 구현과 함께 추가 |
| M15-03~09 | load/failure/compat/perf/E2E | 미구현/부분 | no load/netem/resource/cgroup/browser tooling | P0 |
| M15-10 | CI gate | 부분 구현 | collector tests, Compose validation, ARM64 Docker test/build | P0: lint/client type gate/SBOM/scans/amd64 |
| M0-19 | README/ops docs | 부분 구현 | current single-host behavior is extensively documented | P0: API schema, threat model, restore evidence, feature support matrix |
| CODE-LEGACY | presentation duplication | 중복/부분 사용 | production mounts `MonitorDashboard`; `Dashboard` export is not mounted, but `ContainerList`와 helpers는 `CockpitVisuals`에서 사용(`src/components/CockpitVisuals.tsx:55`) | P2: helper extraction 후 dead component 제거 여부 검증 |

## 환경별 실제 가능 범위

| 환경 | 현재 증거 | 판정 | 영향 |
| --- | --- | --- | --- |
| Ubuntu + systemd | unit files, proc/sys fixtures, production paths | 부분 통과 | 실제 지원의 중심 환경. journald collector는 없음. |
| Linux amd64 | 코드가 Python stdlib/Node 기반 | 검증 불가 | CI·image·collector live run 증거가 없다. “지원 완료”로 표시하면 안 됨. |
| Linux arm64 | GitHub ARM runner에서 image build/test | 부분 통과 | ARM64 build는 입증되지만 hardware sensor/host systemd live test는 아님. |
| Raspberry Pi 5 | Pi sysfs/vcgencmd fixtures와 code path | 부분 통과 | temperature/EXT5V/hwmon은 있으나 현재 throttle 전체와 실제 hardware matrix가 없다. |
| cgroup v1/v2 | Docker stats API와 PSI parser가 간접 사용 | 검증 불가 | 명시적 compatibility fixture/matrix가 없다. |
| Docker Compose | fixed project/service allowlist와 Compose deployment | 부분 통과 | topology가 고정 local portfolio에 종속되고 public identity가 축약됨. |
| 불안정한 네트워크 | local file pipeline에는 중앙 network hop 없음 | 미구현 | agent buffer/retry/reconnect semantics가 없으며 browser refresh만 실패 표시. |

## P0/P1/P2 갭 우선순위

### P0 — 정확성과 운영 안전성

1. stable host/agent identity, heartbeat와 per-source 상태 의미.
2. voltage-only Pi fault 판정 제거와 single-sample incident 기본값 수정.
3. Docker event/inspect reduced schema와 default rules 20~34/40/44~50 signal 완성.
4. versioned alert rule/evaluator/no-data/hysteresis/dedup/inhibition/silence.
5. bounded notification outbox, retry/backoff/jitter/idempotency/delivery log.
6. generic log source의 cursor/status, multiline bound, pre-storage masking, drop accounting.
7. resource-scoped RBAC, API keys, application audit, SSRF-safe prerequisite와 threat model.
8. ENOSPC/clock/network/load/cgroup failure harness 및 amd64+arm64 CI/SBOM/scans.
9. backup/restore와 deployment rollback의 실제 readback 증거.
10. external dead man's switch와 Monitor 자체 core metrics.

### P1 — 운영 범위 확장

- multi-host ingest, metadata/time-series 분리, partition/index/downsampling.
- live log tail/search/context, unified incident timeline와 ack/assignee/note.
- Compose stable identity, volumes/writable layer/image drift, synthetic HTTP/TLS.
- long-term rollups, report, status page, accessibility/performance browser tests.

### P2 — 고급 기능

- OpenTelemetry trace, dynamic anomaly, SLO burn rate, capacity forecast.
- approved restart actions, diagnostic bundle, multi-location/edge fleet.
- customizable dashboard/templates after reliability core is complete.

## 완료로 오해하면 안 되는 항목

- `operationalFindings()`는 presentation assessment이며 durable alert firing/delivery가 아니다.
- `incidents.jsonl`은 7개 threshold evidence capture이며 Incident 관리 모델 전체가 아니다.
- 하루별 JSONL은 날짜 분할이지만 multi-host time-series DB partition/index가 아니다.
- ARM64 Docker build 성공은 amd64·arm64 multiarchitecture 검증이 아니다.
- README의 외부 forced-command rollback 설명은 저장소에서 실행 검증 가능한 rollback 구현 증거가 아니다.
- 현재 green test 수는 존재하지 않는 API key, alert channel, offline buffer, log stream을 입증하지 않는다.
