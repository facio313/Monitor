# Alert policy remediation — 2026-09-24

## 목적과 근거

최근 7일 SMTP outbox에는 615건이 기록되었다. 이 중 정기 보고가 96건,
즉시 알림이 519건이었다. 반복량이 큰 직접 경로는 TCP 재전송 206건,
SSH 보안 패턴 130건, 합성 점검 88건, 컨테이너 자원·상태 59건이었다.
이는 개별 사건이 모두 오탐이었다는 뜻이 아니라, 같은 관측을 여러 소유자가
메일로 만들거나 짧은 사건에 firing/resolved 두 통을 보내는 정책이 운영자
주의를 과도하게 소비했다는 근거다.

## 단일 알림 소유권

동일한 장애 조건은 한 경로만 메일을 소유한다.

| 관측 | 메일 소유자 | 진입/해제 기준 |
| --- | --- | --- |
| TCP 재전송 | `TcpRetransmissionHigh` | 보정 비율 5% 이상, 서로 다른 5표본/240초; 1% 이하 3표본/120초 해제 |
| NIC 오류·드롭 | `NetworkErrorsHigh`, `NetworkDropsHigh` | 기본 rule pack의 지속 조건 |
| Docker daemon/컨테이너 상태·자원 | 대응하는 `Docker*`/`Container*` 규칙 | 기본 rule pack의 지속 조건 |
| HTTP 상태·지연, TLS 인증서 | `HttpEndpointDown`, `HttpLatencyHigh`, `TlsCertificate*` | 성공·실패 표본의 원래 `checkedAt`을 사용하는 지속 조건 |

기존 직접 신호 상태는 정책 변경으로 행정 종료하며 복구 메일을 만들지 않는다.
로컬 진단 표본과 canonical rule history는 유지한다.

## 보안 신호 기준

- SSH 실패·거부는 한 건부터 로컬 감지와 일일 보고에 남기되, 즉시 메일은
  최근 5분에 서로 다른 로그 행 5건 이상일 때 한 번 보낸다. 증거 문구는
  성공하지 않은 인증 관측임을 명시하며 “침입 성공”으로 표현하지 않는다.
- 인증 성공은 국가와 관계없이 `(대상 계정, 공개키 지문)`이 신뢰 목록과
  정확히 일치하는 public-key 접속만 억제한다. 그 외 성공은 즉시 warning
  한 번을 보낸다. 주소·계정·키 지문은 메일과 공개 상태에 넣지 않는다.
- SSH 사건이 관측 창에서 사라진 것은 보안 조치 완료의 증거가 아니므로
  recovery 메일을 보내지 않는다. 로컬 상태만 fresh 표본 두 번 후 resolved로
  전환할 수 있다.
- 일반 SSH 로그의 drop counter가 0이 아니거나 유효하지 않은 경우, 또는
  구조화 SSH access 상태가 누락·지연된 경우 coverage는 `partial`이다.
  partial/unavailable 관측은 기존 사건의 해제를 증명할 수 없다.

## 새로 연결한 관측과 기준

- Docker event stream의 `gapDetected`는 3개의 서로 다른 표본과 120초 지속 후
  warning을 열고, 두 개의 clear 표본 후 닫는다.
- md RAID는 `raidStatus=supported`이고 `raidDegradedDevices`가 존재할 때만
  `RaidDegraded`를 평가한다. degraded 장치가 있으면 1, 없으면 0이다.
  권한 거부는 `permission_denied`, 미지원·필드 부재는 `unsupported`, 그 밖의
  읽기 실패는 `collection_error`이며 어느 것도 정상 0으로 대체하지 않는다.
- kernel 사건의 표본 식별자는 collector 실행 시각이 아니라 실제
  `lastEventAt`이다. 보존된 한 사건을 매분 새 경보 표본으로 세지 않는다.
- 호스트 링크와 SSH listener 가용성 실패는 서로 다른 critical 표본 2개와
  60초 지속 후 메일을 보낸다. 실제 power 및 critical kernel 사건은 단일
  사건 처리를 유지한다.
- 정기 보고는 KST 09:00 경계를 기준으로 하루 한 번만 큐에 넣는다. 공개
  `hourly` 필드와 `HourlyReport` rule ID는 기존 client 호환용 이름으로 남긴다.

## 아직 활성화하지 않는 규칙의 관측 계약

다음 계열은 rule metadata가 있어도 현재 신뢰할 관측원이 없으므로 계속
`unsupported`다. 수집하지 않은 값을 0이나 healthy로 만들지 않는다.

- 디스크 I/O 오류와 SMART: 장치별 지원 여부, 실제 health 결과, 누적 counter의
  boot/reset 경계를 제공하는 collector가 먼저 필요하다.
- cron heartbeat: 등록된 job ID, 기대 주기, 허용 지연, 실제 완료 heartbeat를
  명시한 allowlist가 있어야 한다. 단순히 로그가 없다는 이유로 경보하지 않는다.
- 프로세스 CPU·메모리 budget·FD와 worker/connection pool: 감시 대상 allowlist와
  PID 재사용에 안전한 identity, 그리고 budget/pool 분모가 모두 있어야 한다.
- 데이터베이스 가용성·연결·장기 transaction·lock/deadlock·replication·성장·유지보수:
  DB별 최소권한 read-only adapter, 비밀정보 비공개 계약, 대상별 지원 상태가
  준비된 뒤에만 활성화한다.
- reverse-proxy upstream 오류: upstream별 요청 수와 실패 수의 동일 구간 counter,
  reset 처리, 최소 요청량이 있어야 한다. client 오류를 upstream 장애로 대신 쓰지 않는다.

새 관측원을 추가할 때는 `ok`, `no_data`, `stale`, `unsupported`,
`permission_denied`, `collection_error`를 구분하고, 서로 다른 source timestamp로
진입과 복구를 검증하는 회귀 테스트를 함께 추가한다.

## 검증

- Python 변경 파일 문법 검사를 통과했다.
- 일일 dedup, 단일 소유권, SSH 실패/성공과 개인정보 비공개, source drop,
  Docker gap, kernel 표본 identity, 링크/listener debounce, RAID 지원/미지원
  관련 회귀 테스트 47개를 통과했다.
- 프로젝트 요구사항을 충족하는 임시 Node 22.23.2 환경에서 프론트 문구 단위
  테스트 3개를 통과했다. 소스 변경의 운영 반영은 번들 재빌드가 가능한
  승인된 웹 배포 경로에서 별도로 수행한다.

## 운영 반영

- 2026-09-24 KST에 producer, 신호 판정, rule runtime, 메일 시각화 4개 모듈과
  SMTP route를 함께 반영했다. 이전 설치본과 설정은
  `/var/backups/monitor-alert-policy-20260924T221842+0900`에 보관했다.
- SMTP route에서 `TcpRetransmissionHigh` 제외만 제거했다. 단일 소유권으로
  전환한 TCP·NIC·Docker·HTTP/TLS·container canonical rule 16개가 모두 한 개의
  활성 채널을 선택하고, 대응 direct signal은 producer에서 재생성되지 않는다.
- 수동 collector 실행과 이후 timer 실행이 모두 성공했다. 공개 producer 상태는
  `ok`, snapshot/rules/SSH/HTTP coverage는 fresh, 새 보고·즉시 알림 enqueue는 0,
  pending/retry/failed도 0이었다. 로컬·공개 readiness는 모두 HTTP 200이었다.
- 현재 호스트에는 지원되는 md RAID 관측이 없어 `RaidDegraded`는 정상 0이 아닌
  `unsupported`로 유지된다. Docker event source는 fresh이고 현재 gap은 없다.
