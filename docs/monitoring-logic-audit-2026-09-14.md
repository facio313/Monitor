# Monitor 운영·탐지·판정 로직 점검 — 2026-09-14

## 결론과 범위

관측 가능한 범위에서 진행 중인 큰 장애나 자원 고갈은 확인하지 못했다.
다만 **불필요한 경고를 만드는 경로와 실제 장애를 놓치는 경로가 모두 있다.**
메일 수를 줄이는 것만으로 감시의 신뢰성이 해결되지는 않는다.

재부팅 관련 판단·조치는 제외했다. `wgang` 저장소·컨테이너·설정·서비스는
점검하지 않았고, Monitor의 공용 내보내기 자료에서는 해당 레코드를 제외했다.
이번 점검에서는 운영 코드·설정·서비스·발송 상태를 변경하지 않았다.
앞서 적용한 이메일 과다 발송 완화와는 별도의 후속 진단이다.

확인 방법은 설치된 수집·평가 코드와 저장소 비교, Monitor 축약 telemetry,
격리된 입력 재현, API/UI 순수 함수 실행, 현재 제공 중인 브라우저 JS 확인이다.
전체 포트폴리오에 대한 장애 주입이나 종단간 테스트는 하지 않았다.

## 현재 상태와 필요한 조치

호스트 최종 대조 표본은 **9월 14일 00:00:40 KST**, UI 재현은 00:01 KST다.
각 출처의 관측 시각은 서로 다르므로 하나의 원자적 스냅샷으로 해석하지 않는다.

| 항목 | 확인한 상태 | 지금 필요한 조치 |
| --- | --- | --- |
| 전체 화면 판단 | 제외 항목을 빼면 위험 0, 주의 1. 주의는 아래의 과거 RCU 이력 | 현재 장애와 과거 검토 이력의 집계를 분리 |
| RCU expedited | 9월 9일 21:10:34 KST 짧은 지연 1건. 현재 RCU stall/hung task는 0 | 이력은 보존하되 현재 장애로 취급하지 않기. 새 사건 증가·반복·실제 응답 지연이 있을 때 조사 |
| CPU / RAM / 온도 | 24.2% / 29.06% / 52.9°C. 전원 정상, 현재 제한 플래그 0 | 긴급 조치 근거 없음 |
| 디스크 | 루트 사용률 29.42%, inode 15.2%, 읽기 전용 아님 | 용량 부족 조치 불필요. 이것이 SMART 상태까지 증명하지는 않음 |
| 컨테이너 | 범위 내 20개 모두 running/healthy. 현재 OOM·재시작 증가 신호 없음 | 현재 컨테이너 재시작·삭제 근거 없음. 기대 서비스 누락 탐지는 별도 보완 필요 |
| HTTP / TLS | Monitor 검사 9월 13일 23:58:11, HTTP 200, 566ms, 인증서 65일 | 이 경로는 정상. 다른 서비스의 공개 경로까지 정상임을 뜻하지 않음 |
| TCP | 23:54:20 주의 발생, 23:57:32 복구. 마지막 이상 집계는 253초·4구간, 120/11,898 ≈ 1.01%. 00:00:40 순간값은 0.358% | 이번 주의에는 실제 합산 근거가 있음. 반복 시 허용된 서비스별 지연·재전송과 링크 오류를 대조. 이 비율만으로 회선 고장 단정 금지 |
| PCIe / NVMe | 설정 Gen1, 실제 Gen1. 관측된 AER 오류 0, 완화 설정 활성 | 설정과 실제 링크가 일치함. 화면을 정상색으로 만들 목적으로 기존 안정화 설정을 변경할 근거 없음 |
| 민감 bind 메타데이터 | 5개 컨테이너의 플래그는 정확한 마운트 프로필에서 모두 approved | 현재 보안 경고가 아님. 플래그 하나만 보고 운영 마운트를 제거하지 않기 |
| 패키지 업데이트 정보 | 9월 1일 03:40:49에 만든 오래된 계획: upgrade 165 + install 1 | 현재 필요한 개수로 단정하지 않기. 별도 유지보수 때 새 계획을 확인하고 검토 후 적용. 이번에는 패키지 작업 없음 |

TCP 수치는 커널 세그먼트 카운터의 비율이며 사용자 요청 실패율이나 정확한
패킷 손실 확률과 같지 않다. `TcpOutSegs`는 재전송을 제외하고 제어 세그먼트도
포함한다. [Linux 커널 SNMP 카운터 문서](https://docs.kernel.org/networking/snmp_counter.html)

## 먼저 고칠 감시 누락

### 1. 제한된 프로세스 관측을 호스트 전체 정상값처럼 평가

현재 프로세스 수는 1, 관측 프로세스도 1, 좀비는 0이며 상태는 `supported`다.
실제로 관측한 목록은 collector Python 하나다. 제한된 collector의 `/proc`
관측 범위로 전체 호스트의 PID·좀비 상태가 정상이라고 결론 내릴 수 없다.
이를 `ProtectProc` 단일 옵션의 효과라고만 단정하지는 않는다.

근거: [linux_telemetry.py:1303](../ops/linux_telemetry.py#L1303),
[collector 서비스 샌드박스](../ops/systemd/monitor-collector.service#L51),
[alert_runtime.py:555](../ops/alert_runtime.py#L555).

조치: 관측 범위와 부분 관측 상태를 전달하고, 전체 범위가 확인되지 않은
PID·좀비 값은 정상 0으로 평가하지 않는다. 샌드박스를 무작정 해제하지 말고
허용된 대상의 축약 정보만 제공하는 별도 관측 경로를 연결한다.
회귀 조건: 자기 자신만 보이는 입력에서 whole-host 정상 판정이 나오지 않아야 한다.

### 2. systemd 실패를 cgroup 부재와 혼동하여 정상 처리

현재 6개 유닛은 fallback 관측이고 실행 결과가 모두 `unknown`이다.
fallback은 cgroup 디렉터리가 없으면 `inactive`로 만들며, 평가기는 이를
장애 아님으로 처리한다. cgroup/invocation이 없는 격리 입력에서
`SystemdServiceFailed value=0.0, status=ok`를 재현했다.

근거: [linux_telemetry.py:1468](../ops/linux_telemetry.py#L1468),
[alert_runtime.py:569](../ops/alert_runtime.py#L569).

조치: 허용된 유닛의 `Type/ActiveState/SubState/Result/NRestarts`를 확인하고,
결과를 모르면 unknown으로 남긴다. 상시 서비스와 주기적 oneshot 작업의
기대 상태·마지막 성공 시각·실행 간격을 구분한다.
회귀 조건: failed, 정상 oneshot 완료, 실행 중, 미관측을 각각 구별해야 한다.

현재 oneshot의 `inactive/dead, Result=success`는 정상 완료다.
collector의 큰 `restartCount`는 실제 `NRestarts=0`과 달리 invocation 변화
횟수이며, UI는 이를 이미 특별 취급한다. 수천 번 장애 재시작했다는 뜻이 아니다.

### 3. 정상 컨테이너가 목록에서 사라지면 장애 사건이 생기지 않음

평가 대상은 현재 목록에서 생성되고, 사라진 대상 중 이미 발생 중인 사건만
유지된다. 정상 컨테이너를 다음 성공한 전체 목록에서 제거하는 재현에서
`ContainerDown` 사건은 0건이었다.

근거: [alert_runtime.py:615](../ops/alert_runtime.py#L615),
[alert_engine.py:769](../ops/alert_engine.py#L769).

조치: 현재 발견 목록과 별도로 기대 서비스·원하는 복제 수를 관리한다.
완전한 목록 수집에 성공했는데 기대 대상이 없으면 부재를 탐지한다.
계획된 폐기는 명시적 제외 절차를 사용한다.
회귀 조건: 예상치 못한 삭제는 발생, 계획된 폐기는 제외, 목록 수집 실패는
컨테이너 장애가 아닌 관측 불가로 분류해야 한다.

### 4. 늦게 발견한 OOM·커널 오류가 알림에서 빠짐

OOM 규칙은 누적 카운터를 새 사건으로 오인하지 않도록 `unsupported`로 남는다.
그러나 대체 알림은 최근 300초의 사건만 본다. 지원되는 최신 수집 자료에
6분 전 OOM 1건을 넣으면 OOM 규칙은 unsupported, 추가 OOM 알림은 0건이다.
`DiskIoErrors`도 규칙 입력이 연결되지 않았다.

근거: [alert_runtime.py:459](../ops/alert_runtime.py#L459),
[security_signals.py:359](../ops/security_signals.py#L359).

조치: 사건 커서·누적값 체크포인트·시스템 세대 식별자를 이용해 이전에
처리하지 않은 사건을 추적한다. 지연 수집은 ‘지연 발견’으로 알리고,
초기 과거 이력을 전부 새 사건으로 보내지 않는다.
회귀 조건: 6분 이상 지연한 새 사건은 한 번 알림, 재수집은 중복 없음,
초기 과거 기록은 이력 처리.

### 5. 관측 실패를 정상 또는 조용한 미지원으로 숨기는 경로

서로 다른 세 경로가 있다.

- 평가기: `collection_error`·`permission_denied`는 `noDataPolicy: alert`와
  별도로 처리된다. `DatabaseWriteFailure` 입력을 10분간 collection_error로
  주면 missingSamples 10이지만 알림은 0이다.
- 저장소 API 코드: 커널 데이터 누락을 `{count:0,lastEventAt:null}`로 정규화하며,
  Linux 전체 상태 계산에서 kernel log 출처 상태를 빠뜨린다.
  kernel source unavailable + 요약 누락 재현에서 UI 경고가 전부 사라졌다.
- 감시 범위 UI: 프로세스·SMART·외부 감시 지원 여부 대신 더 넓은 상위
  subsystem 상태로 정상색을 정한다.

근거: [alert_engine.py:477](../ops/alert_engine.py#L477),
[notification_reports.py:117](../ops/notification_reports.py#L117),
[server/data.ts:1057](../server/data.ts#L1057),
[server/data.ts:3800](../server/data.ts#L3800),
[MonitoringCoverage.tsx:172](../src/components/MonitoringCoverage.tsx#L172).

조치: ‘정상 0’, ‘원래 적용 대상 아님’, ‘지원되지만 관측 실패’를 분리한다.
필수 관측원의 지속 실패는 원래 자원 장애와 다른 이름으로 알린다.
지원 여부·최종 성공 시각·실제 관측 대상 수를 capability별로 표시한다.
일부 출처의 기존 별도 경고는 유지하며 중복을 정리한다.

## 남은 오탐·중복과 표시 문제

### 6. 동일 자원 문제에 서로 다른 등급의 메일이 중복 발생

TCP와 HTTP 지연의 발송 경로 중복은 앞선 조치로 막았지만, 모든 항목의
사건 통합이 완료된 것은 아니다. CPU 95%를 1분마다 입력한 재현에서
1분 후 `OperationalCaution 위험`, 4분 후 `CpuUsageHigh 주의`가 발생했다.
현재 SMTP 경로는 이 두 사건 모두를 대상으로 한다.

온도도 추가 알림은 85°C 위험, 지속 규칙은 80°C 위험으로 다르다.

근거: [security_signals.py:450](../ops/security_signals.py#L450),
[notification_reports.py:242](../ops/notification_reports.py#L242),
[기본 규칙](../ops/rules/default-rules.v1.json).

조치: 동일 대상·문제의 사건 키와 기준을 통합하여 주의→위험→복구를 관리한다.
화면의 순간값은 유지할 수 있지만 지속 경고와 명확히 구분한다.
모든 규칙 메일을 일괄 차단하는 방식은 다른 장애를 누락할 수 있어 부적절하다.
회귀 조건: 한 CPU 사건에 최초 통지·실제 승격·복구만 있고,
위험 통지 뒤 같은 문제의 별도 주의 메일이 생기지 않아야 한다.

### 7. DNS 실패가 인증서 만료·무효 알림으로 번짐

DNS/연결 실패로 인증서를 확인하지 못한 경우 TLS 규칙은 `no_data`를 받는다.
캐시된 DNS 실패 표본을 반복 평가하면 2분 후 만료·무효 두 규칙이 발생한다.
이때 인증서를 검사한 증거는 없고, HTTP 가용성 규칙은 새 표본을 기다린다.

근거: [alert_runtime.py:414](../ops/alert_runtime.py#L414),
[기본 TLS 규칙](../ops/rules/default-rules.v1.json#L63),
[notification_reports.py:611](../ops/notification_reports.py#L611).

조치: DNS/TCP 가용성 실패, 인증서 판정 불가, 실제 인증서 만료·무효를
구분한다. 관측 불가는 원인 장애 아래 묶고 인증서 문제로 명명하지 않는다.
회귀 조건: DNS 실패만으로 인증서 만료·무효 메일은 0건이어야 한다.

### 8. 화면의 출처별 최신성·유효성 검사가 불충분

저장소 API/UI 순수 함수에서 다음을 재현했다.

- 최신 호스트 표본 + 하루 전 Linux TCP 10% → `danger/current`와 최신 호스트
  관측 시각을 표시한다.
- 최신 합성 collection + 하루 전 성공 probe → 개별 검사를 정상 취급한다.
- TCP `rateStatus=warmup` + 남은 비율 10% → 위험으로 표시한다.

근거: [server/data.ts:3431](../server/data.ts#L3431),
[server/data.ts:1804](../server/data.ts#L1804),
[operational-health.ts:966](../src/operational-health.ts#L966),
[operational-health.ts:1161](../src/operational-health.ts#L1161),
[TCP 판정](../src/operational-health.ts#L657).

조치: Linux 수집 시각·probe 검사 시각·rate 상태를 각각 검증하고,
오래된 값은 마지막 알려진 값으로 표시한다. 다른 출처의 새 시각을 붙이지 않는다.
메일 평가기에는 개별 합성 표본 나이 제한이 이미 있으므로,
위 UI 재현을 그대로 현재 메일 오탐의 증거로 해석하면 안 된다.
현재 실제 Linux·probe 자료는 최신이다.

### 9. 현재 장애·과거 이력·서비스 요약의 의미가 서로 다름

현재 유일한 주의인 RCU는 과거 이력 scope를 갖는다. 이력을 보존하는 것은
의도된 기능이지만, 전체 위험·주의 합계는 scope를 무시하고 이를
‘현재 판단 항목’에 포함한다.

또한 `restarting/healthy` 컨테이너를 재현하면 공식 서비스 상태는 caution인데,
Vital Signs는 초록색 `0/1 All nominal`을 표시한다.

근거: [MonitorDashboard.tsx:296](../src/components/MonitorDashboard.tsx#L296),
[RCU 이력 판정](../src/operational-health.ts#L1534),
[CockpitVisuals.tsx:282](../src/components/CockpitVisuals.tsx#L282).

조치: 현재 장애·미확인 과거 이력·관측 불가를 별도 집계하고,
서비스 요약은 공통 `operationalServiceStates`와 collection 상태를 사용한다.
과거 기록을 삭제해서 정상색을 만드는 방식은 피한다.

### 10. 임계값의 의미를 정리하고 실제 서비스 영향과 연결할 필요

| 지표 | 현재 차이/문제 | 권장 방향 |
| --- | --- | --- |
| CPU | 추가 알림 75/90%, 지속 규칙은 90%를 warning으로 판정 | 하나의 등급 정책, 지속 시간·PSI·응답 지연과 함께 판단 |
| 온도 | 추가 알림 위험 85°C, 지속 규칙 위험 80°C | 장치 기준에 맞춰 통합. 순간 온도만으로 고장 단정 금지 |
| TCP | 화면은 한 표본 1/5%, 메일은 합산·최소 표본 조건 | 순간 관측과 지속 경고를 구분. 화면도 rate 유효성 확인 |
| HTTP 비율 | 메일에는 작은 분모 보호가 있지만 화면 집계에는 없음 | 1/3 같은 작은 표본의 높은 비율을 곧바로 전체 위험으로 만들지 않기. 절대 오류·매우 느린 응답은 별도 유지 |
| 호스트 CPU full PSI | 1/8% 임계값이 있지만 시스템 수준에서 의미 없는 값 | N/A로 처리하고 CPU some PSI를 사용. cgroup의 full PSI와 구분 |

Linux 문서는 시스템 수준의 CPU full PSI가 정의되지 않아 호환성을 위해
0으로 제공된다고 명시한다. 따라서 이 0을 ‘CPU 압박 없음’의 근거로 삼으면
안 된다. [Linux PSI 공식 문서](https://docs.kernel.org/accounting/psi.html)

## 감시 범위의 한계

제외 항목을 뺀 현재 81개 규칙, 413개 대상 상태는 inactive 359,
unsupported 54다. 28개 규칙은 모든 대상에서 unsupported다.
이는 54개 장애라는 뜻도, 413개를 모두 정상 검증했다는 뜻도 아니다.

외부 heartbeat는 연결되지 않았고, 현재 합성 검사는 같은 호스트에서 실행하는
Monitor 공개 readiness 하나뿐이다. 호스트나 감시기 자체가 완전히 멈추면
자기 자신이 메일을 보낼 수 없다. 중요한 서비스의 외부 경로와 Monitor 생존을
별도 호스트에서 확인할 필요가 있다.
근거: [collector.py:7841](../ops/collector.py#L7841).

SMART·시계 오차·DB 내부 지표 등 필수로 삼을 항목은 실제 입력 연결 여부를
검토해야 한다. 반면 RAID 미사용, PID 제한 없음, 특정 파일시스템의 inode
미지원은 곧바로 장애가 아니다. 현재 13개 컨테이너의 PID 제한 없음도
긴급 장애가 아닌 향후 자원 제한 정책 검토 대상이다.

시간 동기화 marker는 현재 최근에 갱신되었으나 코드가 marker 나이를
확인하지 않는 한계가 있다. 과거 marker 존재와 현재 동기화·offset을 구분해야 한다.

## 권장 작업 순서와 검증 범위

1. 프로세스·systemd·커널 관측 실패를 정상과 구분하고, 기대 컨테이너 부재와
   지연 사건을 탐지한다. 필수 감시원의 관측 불가 알림과 외부 감시를 설계한다.
2. DNS/TLS 원인 분류와 자원 사건 통합으로 남은 오탐·중복을 정리한다.
3. 출처별 최신성, 과거 이력 집계, 서비스 요약, 공통 임계값을 정리한다.
4. 격리된 장애 입력과 실제 표본 재생으로 누락·중복·잘못된 복구가 없는지
   검증하고, 이후 정상 운영 관측으로 메일 수와 실제 장애 탐지율을 함께 확인한다.

설치된 Python 핵심 수집·평가·알림 모듈은 점검한 저장소 코드와 일치했다.
현재 제공되는 JS에서도 TCP 즉시 판정, 과거 RCU 집계, 서비스 정상색 판정의
문제 코드를 확인했다. 제공 JS의 해시는
`b6ff57699f53569125b3b727ed9f9e429fdc69922c3f5d62063630e264cfff1a`다.
전체 배포 이미지와 저장소의 동일성은 확인하지 못했으므로,
서버 API의 커널 정규화·출처 최신성 문제는 **저장소 코드에서 재현된 결함**으로
한정한다. 현재 운영에서 그 조건이 발생 중이라는 주장은 하지 않는다.

UI 재현 스크립트: `/tmp/monitor-ui-audit.Mnkkco/repro.mjs`.
운영 export를 메모리에서 필터·변형하여 실행하며 운영 파일은 바꾸지 않는다.
앞선 메일 완화의 적용·검증 내역은
[이메일 과다 발송 수정 기록](notification-noise-remediation-2026-09-13.md)에 별도로 남아 있다.
