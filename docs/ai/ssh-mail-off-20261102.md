# SSH 로그인 성공 메일 중지 · 2026-11-02

- 사용자 요청: SSH 로그인 이력은 기록하고 메일은 보내지 않는다.
- 적용 범위: 성공 로그인(`ssh-auth-success`)의 즉시 메일과 일일 보고 항목을 제외한다. SSH 수집·탐지 이력, 실패·거부 반복 경고 및 다른 시스템/앱 알림은 유지한다.
- 변경: `ops/notification_reports.py`의 메일 enqueue 경계와 일일 보고 투영에서 성공 로그인만 제외. `ops/tests/test_ssh_country_policy.py`를 새 동작에 맞추고, 기존 실패 임계값 20건과 어긋난 5건 fixture 2개를 실제 상수로 정정했다. 그 2개 실패는 변경 전 설치본에서도 재현했다.
- 검증: SSH 국가/이력·메일정책 및 일반 경고/일일 보고 관련 20개 테스트 통과. 설치본 대상으로 성공 로그인 기록 유지·발생/복구 메일 없음·실패 반복 경고 유지 3개 테스트 통과. 모두 임시 출력/SQLite fixture 사용, 운영 로그·outbox·DB를 테스트 입력으로 쓰지 않았다.
- 운영 설치: `/usr/local/lib/monitor-collector/notification_reports.py`만 원자적으로 교체. 매분 새 프로세스로 실행되는 기존 collector가 다음 실행부터 반영하며 수동 실행·메일 발송·sshd/SSO/방화벽 변경은 하지 않았다.
- 백업: `/var/backups/monitor-ssh-login-mail-off-20261102T161657`에 수정 전 설치본/checkout 모듈/관련 테스트 저장.
- 설치 전 확인: 성공 로그인 outbox는 기존 succeeded 75건만 있고 대기·재시도·실패 없음. SSH 수집 상태 fresh, droppedRecords=0. 기존 전달 이력은 삭제하지 않았다.
- 설치 모듈 SHA-256: `72cd02aa68a3c933a6cba3747ea07fd3d1905dc97c05749b5f15cf7f02be0fa5`.
- 기존 작업 중인 checkout 변경은 보존했다. 이후 사용자 승인으로 `fix/ssh-login-mail-off-20261102` 브랜치에 이번 메일 억제만 별도 커밋한다. Pongdang 정적 운영 전환은 별도 작업이며 이 기록의 범위가 아니다.
- 설치 후 자동 collector 실행 16:18:39 KST Result=success/exit 0, SSH 수집 16:18:22 KST fresh/drop 0 확인. 수정 파일 diff 공백 검사도 통과.

## 원격 코드 보존

- 기준은 기존 원격 `fix/tcp-verified-ssh-20260921`의 `33e3fdf2bbb14c668f008cdab3623aef729f4a84`다. main에는 아직 성공 로그인 탐지 계약이 없으므로 main을 변경하거나 배포하지 않는다.
- 별도 worktree에서 메일 억제 4줄과 관련 회귀 기대값만 적용했다. 기존 checkout의 다른 수정과 임계값 변경은 포함하지 않는다. 이 브랜치의 기존 실패 알림 기준은 그대로 유지한다.
- 별도 원격 기반 코드에서 SSH 정책 13개와 일반 경고·비활성 채널·정기 보고 3개 검사를 통과했다. SSH 성공 이벤트가 원본 이력에 그대로 남고, 즉시·정기·복구 메일에는 포함되지 않으며 기존 실패 반복 알림이 유지되는 것을 확인했다.
