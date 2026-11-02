# SSH 성공 로그인 기록과 메일 정책

2026-11-02 사용자 요청에 따라 성공 로그인은 SSH 이력과 탐지 기록에 보존하되
즉시 메일과 정기 보고의 성공 로그인 항목에서는 제외한다. 실패·거부 반복 경고와
일반 시스템 메일은 유지한다.

현재 운영 호스트에는 최신 설치본의 해당 네 줄만 이미 반영했다. 원격 main은
그보다 오래된 SSH 생산자이므로 이번 통합에서는 발생·복구 이벤트의 `signal_kind`
전달 계약을 함께 추가하고 accepted 이력·탐지 유지·메일 억제를 검증했다.
이 작업은 과거 작업 브랜치 전체나 서버의 다른 미커밋 변경을 통합하지 않는다.

호스트 알림 모듈은 웹 이미지 배포가 자동으로 설치하지 않는다. `deploy.yml`은
기존 전체 검사·이미지 빌드·게시를 유지하되, push 전체가 한 커밋이며 변경 파일이
`ops/deployment_scope.py`의 호스트 알림 전용 목록에 전부 포함될 때만 웹 배포를
생략한다. 실제 앱 파일이 하나라도 바뀌거나 범위를 입증하지 못하면 기존 배포를
유지한다. 명시적 workflow_dispatch 역시 기존 배포를 유지한다.

이미 최신 모듈이 설치된 호스트에 원격 main의 파일 전체를 덮어쓰지 않는다.
설치가 필요한 다른 호스트는 설치본과 차이를 검토하고 이 알림 정책에 필요한 부분만
백업 후 반영한다. 로그인 기록 삭제·sshd 변경·시험 메일 발송은 이 작업에 포함하지 않는다.

## 2026-11-02 의존성 보안 검사 복구

기존 main CI의 npm audit 실패를 수정했다. Vitest는 tinypool을 사용하지 않는
4.1.12로 올리고, 다른 취약 패키지는 기존 호환 범위 안에서 lockfile을 갱신했다.
타입 검사, 기존 JS 테스트 554개, SSH 알림·배포 범위 테스트 7개가 통과했고
전체 npm audit는 취약점 0개다. 운영 코드의 압축 JSON 처리와 관련된 body-parser도
2.4.0으로 갱신한다. 감사 결과는 확인 당시 공개된 npm advisory 기준이다.

서버의 사용자 수정본은 main보다 앞서 있다. 저장소 변수 `MONITOR_RUNTIME_HOLD_SHA`가
정확히 일치하는 커밋만 서버 교체를 보류한다. 이 변수는 CI 검사·이미지 게시를
생략하지 않으며 다른 SHA에는 영향을 주지 않는다. 이번 커밋 SHA를 push 전에
설정한다. 운영 소스를 main에 통합한 후 정상 배포할 때 변수를 삭제한다.

운영 의존성은 `ops/Dockerfile.runtime-dependencies`로 별도 적용한다. 이 파일은
현재 운영 이미지의 dist·설정·진입점을 보존하고 node_modules만 잠긴 운영 의존성으로
교체한다. 사용 전 원본 이미지의 package.json 운영 dependencies가 저장소와 같음을
확인해야 한다. 전체 웹 소스를 이 이미지로부터 복원할 수 있다고 가정하면 안 된다.

현재 원본 이미지: `monitor:dashboard-mail-20260924`.
패치 이미지: `monitor:runtime-dependencies-20261102`.
빌드 명령: `docker build -f ops/Dockerfile.runtime-dependencies --build-arg MONITOR_BASE_IMAGE=monitor:dashboard-mail-20260924 -t monitor:runtime-dependencies-20261102 .`.
서버의 rootless Docker(`/run/user/1001/docker.sock`)에서 cks 계정으로 실행한다.
교체는 기존 `/etc/portfolio-deploy/monitor.compose.yml`과 project `monitor`를 사용해
`MONITOR_IMAGE`를 패치 이미지로 지정하고 `up -d --no-deps monitor`로 수행한다.
문제가 있으면 동일 명령의 이미지 값을 원본으로 바꿔 복구한다. 데이터·비밀 설정은
기존 마운트를 유지하며 원본 이미지를 지우지 않는다.

운영 교체 완료: readiness ready, 웹 GET 200, 컨테이너 healthy. 원본·패치 이미지의
`/app/dist`와 `/app/scripts` 파일 해시 집계가 동일했다. 실제 운영 컨테이너에서
body-parser 2.4.0, proxy-addr 2.0.8, qs 6.17.1, ip-address 10.7.5를 확인했다.
운영 이미지 빌드에서도 `npm audit --omit=dev --audit-level=critical`가 취약점 0개로
통과했다. 로컬 `npm run build:raw`도 통과했다. 기존 이미지와 데이터는 보존했다.
GitHub CI 최종 결과는 이 변경 커밋의 Build and deploy 실행에서 확인한다.
