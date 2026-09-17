# SSH 대한민국 출처 제한과 GitHub 예외

2026-09-13 21:25:48 KST에 호스트 SSH의 공인 출처를 대한민국으로
분류된 IP 대역으로 제한했다. 현재 관리 접속인 `eth0`의
`192.168.75.190/32`와 서버의 loopback 접속은 명시적 예외다.
다른 내부 PC는 자동 허용하지 않는다. 관리 PC의 DHCP 주소가 바뀌면
예외를 검토해야 한다. 서버 목적지 주소는 DHCP 변경에 대비해 고정하지 않는다.

2026-09-14에는 운영자 요청으로 GitHub의 공식 공개 IPv4·IPv6 대역을
추가 예외로 허용했다. 이전 정책은 해외 GitHub Actions 실행 서버도 차단하여
Pongdang의 CI 통과 후 SSH 배포를 실패시켰다. 기존 한국 출처 규칙과 관리 PC
예외 뒤에 GitHub 예외를 평가하고, 나머지 SSH 출처는 계속 차단한다.

## 적용 범위와 데이터

- TCP 목적지 포트 **22, 22022**만 대상이며 IPv4와 IPv6를 모두 제한한다.
- 전용 `inet monitor_ssh_geo` 테이블의 `input` hook(priority -10)을 사용한다.
  다른 포트, forwarding, NAT, 컨테이너, 웹서비스 및 프록시 설정은 변경하지 않는다.
- 허용 규칙은 이 테이블에서 `return`하고, 기존 UFW·Fail2ban 검사를 계속 받는다.
  기존 UFW의 SSH `Anywhere` 표시는 전용 선행 필터를 표시하지 않으므로,
  실제 국가 제한 여부는 아래 nft 명령으로 확인해야 한다.
- 대한민국이나 GitHub 예외에 해당하지 않는 공인 주소와 지정하지 않은 내부 주소는 차단한다.
  기존 연결 전체를 무조건 허용하는 conntrack 우회 규칙은 없다.
- [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
  2026-09-01 자료(CC BY 4.0)의 KR IPv4 2,608개, IPv6 880개 원본 구간을 사용한다.
  nftables가 인접 구간을 병합하므로 실행 중 표시되는 요소 수는 다를 수 있다.
- 국가 조회는 오프라인이며 관측 IP를 외부로 전송하지 않는다. 국가 위치는
  추정이다. 한국 VPN·프록시·침해된 한국 서버를 통한 접속이나 인증정보 탈취를
  이 제한만으로 막을 수는 없다. 비밀번호·키 인증 정책은 이번에 변경하지 않았다.

## GitHub 배포 접속 예외

- 출처는 인증정보 없이 HTTPS로 조회하는 [GitHub Meta API](https://api.github.com/meta)다.
  `actions`, `actions_macos`뿐 아니라 `git`, `api`, `web`, `hooks`, `packages`,
  `pages`, `codespaces`, `copilot`, importer 계열 등 API가 공개하는 모든 IP 배열을
  합친다. 키 문자열과 도메인 목록은 IP 예외에 사용하지 않는다.
- IPv4·IPv6 `github4`/`github6` interval set으로 정확히 중복·인접 대역만 병합한다.
  기본 경로, 사설·특수 주소, 잘못된 CIDR, 빈 Actions 목록, 과대 응답을 거부한다.
  출처 목록은 GitHub가 발표한 네트워크 범위이며 특정 계정·저장소의 신원을
  증명하지 않는다. 공유 클라우드 대역도 포함되므로 실제 배포 권한은 기존 SSH
  인증과 제한 배포 명령이 판단한다.
- GitHub 예외도 TCP **22, 22022**만 `return`하며 UFW·Fail2ban 및 SSH 인증 검사를
  계속 받는다. 외부 `ssh.bonifacio.work:22022` 접속이 서버에서 `DPT=22`로 관측되므로
  한쪽 포트만 예외로 추가하면 배포 문제가 남을 수 있다.
- 적용 명령은 `/usr/local/sbin/monitor-ssh-geo-apply --update-github`다.
  `--check`를 함께 지정하면 다운로드·검증만 하고 정책 파일과 방화벽을 변경하지 않는다.
- `monitor-ssh-github-update.timer`가 서버 시각으로 매일 06:15부터 30분 이내에
  실행한다. `Persistent=true`로 서버가 꺼져 놓친 실행은 기동 후 보충한다.
  수동 갱신은 `systemctl start monitor-ssh-github-update.service`다.
- HTTPS 인증서를 검증하고 리다이렉트를 거부한다. 다운로드·데이터·nft 구문 검증에
  실패하면 기존 정책을 유지하고 서비스가 실패 상태로 기록된다. 부팅 시에는 저장된
  정상 정책을 즉시 적용하며 GitHub API 연결을 기다리지 않는다.
- 갱신은 기존 적용기와 같은 잠금을 사용한다. 검증 후 이전 정책을
  `/etc/monitor/ssh-kr-only.nft.previous`에 보관하고, root 소유 0600 파일을 원자적으로
  교체한 다음 전용 테이블만 하나의 nft transaction으로 적용한다. 적용 실패 시
  디스크와 실행 중 정책을 모두 이전 값으로 복구한다. 목록이 같으면 파일과 카운터를
  그대로 유지한다. 자동 갱신은 한국 국가 데이터나 관리 PC 예외를 변경하지 않는다.

```sh
sudo systemctl status monitor-ssh-github-update.timer --no-pager
sudo journalctl -u monitor-ssh-github-update.service -n 10 --no-pager
sudo nft list counter inet monitor_ssh_geo ssh_geo_github4
sudo nft list counter inet monitor_ssh_geo ssh_geo_github6
```

설치 소스는 `ops/github_ssh_ranges.py`, `ops/ssh_geo_apply.py` 및
`ops/systemd/monitor-ssh-github-update.{service,timer}`다. 파서는 root 소유
`/usr/local/lib/monitor-ssh-geo/github_ssh_ranges.py`로 설치하며, 앱 배포와 독립적으로
운영자가 설치한다. 다른 서비스나 컨테이너의 배포는 이 설치에 포함되지 않는다.

## 설치와 재부팅 시 동작

- 정책: `/etc/monitor/ssh-kr-only.nft` (root:root 0600)
- 적용 도구: `/usr/local/sbin/monitor-ssh-geo-apply`
  ([소스](../ops/ssh_geo_apply.py))
- 부팅 서비스: `/etc/systemd/system/monitor-ssh-geo.service` (enabled)
- SSH daemon/socket 각각의 `60-monitor-ssh-geo.conf` drop-in은
  `Wants`/`After`와 필수 `ExecStartPre`를 사용한다. 소켓 활성화도 빠뜨리지 않는다.

필터 서비스와 두 SSH 시작 전 검사가 정책을 적용하며, 파일 누락·구문 오류·적용
실패 시 새 SSH daemon/socket 시작이 실패한다. 활성 서비스의 상태만 믿지 않고
시작 전 재적용한다. `Wants`이므로 필터 서비스 중지 자체가 SSH 중지로 전파되지는
않으며, 필터 서비스에는 규칙을 지우는 `ExecStop`이 없다.

변경은 전용 테이블의 add/delete/recreate를 **하나의 nft transaction**으로 수행한다.
전체 ruleset을 flush하지 않는다. 잠금을 획득한 후 정책을 읽고 검사·적용하여 동시
갱신의 역전을 방지한다. 실패한 변경은 기존 테이블을 유지한다.
현재 적용 과정에서는 SSH daemon/socket을 재시작하지 않았고, 호스트도 재부팅하지 않았다.

## 로그와 확인

`ssh_geo_denied`는 차단된 **패킷 수**이며 고유 IP·접속·공격 횟수가 아니다.
`SSH_GEO_DROP ` 접두사의 커널 로그는 분당 3개, 초기 burst 5개로 제한한다.
로그 제한과 별개로 차단은 계속된다. 로그 우선순위는 `info`다.
방화벽에서 차단된 패킷은 sshd까지 도달하지 않으므로 Monitor의 기존
SSH 접속 이력에는 나타나지 않는다. 기록 감소를 공격 시도 종료로 해석하면 안 된다.

```sh
sudo systemctl status monitor-ssh-geo.service --no-pager
sudo nft list chain inet monitor_ssh_geo input
sudo nft list counters table inet monitor_ssh_geo
sudo journalctl -k --grep 'SSH_GEO_DROP' -n 30 --no-pager
```

## 국가 데이터 갱신

한국 국가 데이터는 검증한 월별 자료의 고정 사본이다. 국가 DB 자동 다운로드·갱신은
없으므로 **월 1회 국가 데이터 갱신을 검토해야 한다.** GitHub 대역의 일일 갱신과는
별개다. 기존
[오프라인 데이터 갱신 절차](ssh-access-observations.md#offline-country-estimates)로
공식 checksum을 검증한 새 DB를 설치한 뒤, 아래 생성기로 새 정책을 생성한다.

```sh
python3 /home/cks/Monitor/ops/ssh_geo_guard.py \
  --database /usr/local/share/monitor-collector/ip-country.sqlite \
  --github-policy /etc/monitor/ssh-kr-only.nft
```

생성기는 stdout만 사용하며 DB의 구조·전체 구간·중복·공인 주소·양쪽 IP family·
데이터 날짜를 검증한다. 90일을 넘긴 DB나 잘못된 자료로는 새 정책을 만들지 않는다.
생성 결과를 보호된 staging 파일에서 검토하고 `nft --check`로 확인한 다음,
root 소유의 정책 파일을 원자적으로 교체하고 `systemctl reload monitor-ssh-geo.service`
로 반영한다. 기존 정상 규칙은 데이터의 날짜가 지났다고 자동 삭제되거나 개방되지 않는다.
갱신 중에는 현재 접속을 유지하고 별도 복구 경로/타이머를 준비한다.
`--github-policy`는 현재 저장된 GitHub 예외를 오프라인으로 보존한다. 생성부터 파일
교체·적용까지 `/run/monitor-ssh-geo/apply.lock`을 잡아 일일 GitHub 갱신과 직렬화한다.
잠금 내부에서 잠금을 다시 잡는 적용 명령을 호출하지 말고, 검증한 transaction을
직접 적용하거나 잠금 관리가 통합된 운영 도구를 사용한다.

## 검증과 복구

### 2026-09-14 GitHub 예외 검증

- 메타데이터 파싱·정책 보존·원자적 적용 및 실패 복구 관련 단위 테스트 33개 통과.
- 공식 목록의 정확한 합집합은 적용 시점 기준 IPv4 3,850개, IPv6 1,362개 CIDR이다.
- 실제 운영 후보 정책으로 격리된 network namespace TCP 접속 검사 31개 통과:
  한국·GitHub IPv4/IPv6, 기존 실패 실행 서버 두 IP, 관리 PC 및 loopback 허용;
  다른 해외·내부 PC SSH 차단; 다른 TCP 포트 허용. 호스트 네트워크와 분리해 검사했다.
- 기존 정책에서 GitHub 관리 블록만 제거하면 최초 정책과 바이트 단위로 일치한다.
  국가 DB 재생성 CLI도 저장된 GitHub 예외를 그대로 보존함을 확인했다.
- 15:24:54 KST 운영 적용 및 일일 timer 활성화 완료. 저장된 정책과 이전 정책은
  root:root 0600이며 부팅 적용기는 기존 저장 파일을 사용한다.
- 15:25:23 KST GitHub 실행 서버 `135.232.193.42`의 `cks` 공개키 인증이 성공했고,
  [Pongdang 실행 34807392737의 두 번째 시도](https://github.com/facio313/Pongdang/actions/runs/34807392737)
  는 15:26:03 KST에 성공했다. 배포된 main SHA는
  `5c5a89582467904ee2ed7465ca969cb9c8507f1b`다.
- 변경 전 정책·적용기와 검증에 사용한 공식 메타데이터·후보 정책은 root 전용
  `/etc/monitor/ssh-github-rollout-20260914-QrKH0V/`에 보관한다.

### 2026-09-13 국가 전용 정책 최초 검증

- Python 국가 DB·생성·적용 transaction 테스트 21개 통과.
- 격리된 서버/클라이언트 network namespace에서 실제 TCP 검사 18개 통과:
  한국 IPv4/IPv6 허용, 해외 IPv4/IPv6 차단, 관리 PC 허용, 다른 내부 PC 차단,
  양쪽 loopback 허용, 비-SSH 포트 무영향. 두 SSH 포트 각각 검사했다.
- 동일 정책의 원자적 재적용 2회 및 잘못된 원자적 변경 시 기존 테이블 유지 확인.
- systemd daemon/socket/service 구문·의존성 검사 통과. 실제 재부팅 검사는 하지 않았다.
- 운영 적용 직후 내부 관리 연결 유지, 양쪽 loopback/두 포트 SSH banner 응답,
  기존 Fail2ban 규칙 유지, Monitor readiness 정상 확인.
- 21:27:15 KST까지 차단 패킷 37개를 확인했다. 제한 로그에서 미국·나이지리아로
  분류된 출처가 차단되었다. 실제 한국/해외 외부 회선에서의 별도 접속 시험은 하지 않았다.
- 자동 복구 타이머는 검증 후 취소했으며 복구 서비스가 실행되지 않았음을 확인했다.

GitHub 예외 추가 전 국가 전용 정책 SHA-256:
`cea4e8ace0fad839fadcd92105d4fb4792ebf1ba9b389a152b2fcc7f640030db`.
운영 기록과 복구 도구 사본은 비공개 rollout 디렉터리에 보관한다.
복구가 필요하면 이번에 추가한 SSH 두 drop-in만 회수하고 daemon-reload한 뒤,
필터 서비스를 `disable`(중지 없이)하고 **전용 `inet monitor_ssh_geo` 테이블만**
삭제한다. 이는 국가 제한을 해제하므로 명시적인 운영자 결정 후 수행한다.
다른 방화벽 테이블이나 SSH 설정을 되돌리지 않는다.

GitHub 예외만 이전 목록으로 복구하려면 자동 갱신 타이머를 중지한 뒤 보관된 정상
정책을 확인하여 같은 잠금·원자적 적용 절차로 복구한다. 타이머를 다시 켜면 다음
갱신에서 공식 최신 목록이 복원된다.
