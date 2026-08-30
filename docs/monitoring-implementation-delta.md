# Monitor 구현 증분 감사 — 2026-08-30

> 기준선: `3c2a0a8ae7d44154d2a5dee960315a72338c3ffc`
> 대상: 이 문서를 포함하는 후속 커밋
> 범위: `/home/cks/Monitor`만 해당한다. 다른 저장소나 서비스는 포함하지 않는다.

## 결론

이번 증분은 기존 단일 호스트 Monitor의 가장 위험한 거짓 정상과 부분 실패
경로를 줄였다. Docker 수집 실패가 호스트 표본을 막지 않게 분리했고, Docker
관측 상태를 fresh/last-known/unavailable/permission-denied로 명시했으며,
inspect 기반 생명주기·health·limit 증거를 축약 계약으로 연결했다. 82개 기본
규칙은 versioned data, restart-safe 평가 상태, bounded transition log, strict API,
우선순위 UI까지 실제 production graph에 들어갔다. 배포 CI는 amd64와 arm64를
같은 manifest로 만들고 두 플랫폼을 각각 검사한다.

이는 Monitor.md 전체 완료 선언이 아니다. 다중 호스트 등록·mTLS·offline spool,
중앙 저장소, 규칙 CRUD/override, 반복 silence, 라우팅, 비동기 delivery outbox,
로그 플랫폼, backup/restore 증명과 외부 synthetic은 여전히 구현되지 않았다.
기준선 분석 문서의 미구현 판정은 아래에서 명시적으로 승격한 범위 외에는
유효하다.

## 실제 연결된 변경

| 영역 | 이번 증거 | 현재 판정 |
| --- | --- | --- |
| Docker 부분 실패 | exporter unit은 `Wants`, reduced snapshot bind는 optional이다. 실패 원인은 typed source status가 되고 host current/history publication은 계속된다. | P0 단일-host 경로 통과 |
| Docker v2 | current row는 정확히 17필드이며 inspect 30, stats 30, worker 6, 전체 20초, list 1 MiB/detail 256 KiB로 제한된다. | lifecycle 핵심 부분 통과 |
| lifecycle 정확도 | restart total/delta, OOM, start/finish, healthcheck support, memory/CPU/PID limit을 identity-bound inspect에서 축약한다. raw ID는 private mode-0600 state에만 있다. | FA-13~16 부분 승격 |
| legacy/incident | legacy 7필드는 project·health/lifecycle/limit을 추정하지 않고 null로 승격한다. incident는 의도적으로 기존 7필드 projection을 유지한다. | 호환/개인정보 경계 통과 |
| rules | Monitor.md의 82개 ID를 고정 순서의 strict JSON pack으로 제공한다. threshold/recovery, severity, samples, no-data, parent, labels, description/runbook, enabled를 검증한다. | seed pack 부분 통과 |
| evaluator | pending/firing/recovering/recovery, hysteresis, independent no-data, parent suppression, silence disposition, gap reset과 deterministic transition identity를 구현한다. | FA-33~37 부분 승격 |
| persistence | event-before-private-state-before-public-evaluation 순서, replay dedup, atomic bounded files, explicit collection_error를 적용한다. | local crash safety 통과 |
| API | evaluation과 transition을 legacy alert와 분리해 strict schema/size/path/mode 검증 후 반환한다. malformed partial input은 collection_error다. | single-host read API 통과 |
| 화면 | 시스템/신선도 → operational health → rule evaluator → 164~187px pure canvas → widgets 순서다. 캔버스에는 보이는 텍스트나 overlay가 없다. | action-first composition 통과 |
| release | pinned actions, Node 22.23.2, type/test/audit gates, amd64+arm64 manifest, provenance/SBOM, 플랫폼별 Trivy critical gate를 둔다. | source gate 통과; 실제 run은 배포 readback 필요 |

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
유지보수 창 UI가 없다. notification state는 ready/suppressed/silenced를
기록하지만 email/Slack/Discord/Telegram/webhook adapter, routing, retry,
backoff/jitter와 delivery log/outbox는 없다. 따라서 transition 생성 성공을
알림 전송 성공으로 해석하면 안 된다.

## 검증 증거

- Python: `python3 -m unittest discover -s ops/tests -p 'test_*.py'` — 193/193
- TypeScript/Vitest: 25 files, 205/205
- client/server TypeScript typecheck — 통과
- Vite client와 server production build — 통과
- `npm audit --audit-level=critical` — 모든 severity 0 vulnerabilities
- SSO `main`과 fixture `ci/local` Compose config — 통과
- tracked shell syntax, Python byte compilation, workflow YAML parse,
  `git diff --check` — 통과
- Chromium: 1440×1200, 1024×1366, 390×844에서 순서/겹침/overflow,
  responsive cards, accessible names, skip focus, console/page/request errors를
  검사했다. 오류는 모두 0이었다.

로컬 Node 18에서 Vite가 Node 20.19+/22.12+ 권장 경고를 냈지만 build는
성공했다. CI와 image build는 존재가 확인된 Node 22.23.2로 고정되어 있다.

## 다음 P0

1. host identity/registration, mTLS enrollment와 duplicate/clone 정책
2. bounded offline spool, ack/retry와 central ingest/storage
3. full rule metadata, validated CRUD/version history와 scoped override
4. recurring silence/maintenance window, grouping/dedup과 deterministic routing
5. asynchronous delivery outbox, channel adapters, retry/backoff/jitter/readback
6. clean-host backup restore와 immutable deployment rollback proof
7. external dead-man synthetic와 evaluator/queue/delivery 자체 계측

각 항목은 failure injection과 운영 readback이 생기기 전까지 완료로 승격하지
않는다.
