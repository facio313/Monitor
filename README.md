# Monitor

Monitor is the private host-status dashboard served at
`https://bonifacio.work/monitor/`. It combines one-minute host telemetry,
rootless Docker status, storage information, sanitized alerts, and sanitized
privilege activity in a responsive React dashboard protected by the central
Bonifacio SSO boundary.

## Architecture

```text
cks rootless Docker socket -> short-lived cks exporter -> reduced /run snapshot
                                                        |
host proc/sys + selected logs + privacy request counts -+
                                                        |
                                              root systemd collector
                                                        |
                                /var/lib/monitor-export (bounded JSON/JSONL)
                                                        ^
root-only append ledger -> validated public ledger -----+
                                                        | read-only bind mount
                                                        v
browser -> TLS/Nginx + central SSO -> Express API + React UI
                                      |
                                      +-> /run/monitor-update/gateway.sock
                                          (narrow host bind from
                                           /var/lib/monitor-update-socket)
                                          -> unprivileged request queue
                                          -> fixed-policy root APT worker
```

The privilege boundary is intentional: the root collector reads protected host
inputs but its mount namespace contains no Docker socket. A separate one-shot
helper runs as the same unprivileged `cks` account that already owns the sole
rootless daemon and writes only a strictly validated, fixed-schema snapshot.
The web container receives neither Docker sockets nor raw logs; it can read
only the collector's reduced export. Its host-operation capability is the exact
`/run/monitor-update/gateway.sock` Unix socket described below, supplied by a
read-only bind of the narrow host directory
`/var/lib/monitor-update-socket`. That socket
accepts only bounded `check` and plan-bound `apply-safe` requests and leads to
an unprivileged gateway, not directly to APT. In production SSO
mode the application has no password database, session database, auth-state
directory, or other writable user store. Its separate application-state write
boundary is the exact `/var/lib/monitor-security` bind used for digest-only API
key metadata and the audit journal. It consumes SSO user identity only from the
central edge, protected by a dedicated read-only edge secret.

Local mode is deliberately different: it creates a disposable, application-
specific password hash and signed cookie under the worktree so the application
can be developed without the SSO stack. That state is a local development aid,
not a second production identity system.

The collector gives the single-host file path stable random host/agent UUIDs,
private machine binding, a reduced per-boot digest, and a sequenced heartbeat.
An optional, default-off central control path now adds short-lived one-use
enrollment, proxy-verified mTLS fingerprint binding/rotation/revocation,
network heartbeat, idempotent compressed batch admission, clock-skew policy,
and an encrypted finite disk queue. Its mTLS proxy uses a second, domain-
separated edge secret; reusing the SSO origin secret fails startup. A
standalone, default-off client package
implements private enrollment state, mTLS, deterministic gzip batches, bounded
offline spool and stable timeout/Retry-After/backoff retries. It is deliberately
not wired into the existing local collector or installer: the external
PKI/mTLS listener, certificate lifecycle, persistent server state mount,
reduced-record producer and downstream queue consumer remain deployment
dependencies. See [the central agent contract](docs/agent-ingest-contract.md)
and [the transport package guide](docs/agent-transport.md).

## Branch authentication contract

`scripts/portfolio-auth-mode.sh` is the only branch-to-authentication resolver.
It uses `PORTFOLIO_BRANCH`, then `GITHUB_REF_NAME`, then the current Git branch.
`main` and `dev` resolve to `sso`; every other branch resolves to `local`. If an
explicit `PORTFOLIO_AUTH_MODE` disagrees, startup, build, or Compose validation
fails closed. Container images additionally carry a read-only build contract;
runtime branch/mode overrides must match the branch and mode used to build the
image.

In `sso` mode Monitor still requires the edge secret and accepts `Remote-*`
identity only when the Nginx-injected secret matches. Canonical v2
`Remote-Groups` starts with `user`, may add `admin` and then `chief-admin`, and
must then include the `portfolio-v2` marker. Non-chief identities append their
assigned grants in this fixed relative order: `access-react`, `access-vue`,
`access-dukkeobi`, `access-ddit-finalproject`, `access-monitor`,
`access-pilgrimage`, `access-multtara`, `access-feelmyrythm`, `access-garak`.
Monitor requires `access-monitor`; `chief-admin` is universal and therefore
carries no grants. Missing/reordered/duplicate markers, role gaps, unknown or
out-of-order grants, whitespace, and missing Monitor entitlement fail closed.

During central cutover only the exact v1 strings remain recognized. Legacy
`user,developer` becomes an ordinary Monitor-entitled `user`, while
`user,developer,admin` becomes `chief-admin`; legacy `user` keeps its former
no-dashboard behavior. `developer` is never exposed as a current runtime role
and never grants the admin-only auth inventory. Every entitled user can read the
dashboard, while the metadata-only legacy auth inventory requires `admin` or
`chief-admin`. The legacy admin compatibility identity may check for updates,
but it is deliberately denied host package apply; applying requires a canonical
v2 `chief-admin` header. Roles and grants are recalculated from trusted headers on every
request and are never stored in a Monitor cookie.
Local login and password changes stay disabled, and the SSO session check
expires any legacy Monitor cookie presented by that browser. In `local` mode
the existing password screen, scrypt state, and signed Monitor cookie remain
active; local mode is not an unauthenticated SSO bypass. `MONITOR_SSO_ENABLED`
is now only a compatibility check: if an older deployment still supplies it,
it must agree with the canonical mode.

The dashboard provides:

- a Korean-first control-room view with an explicit English switch, large page
  and panel headings, persistent critical-state strip, and an in-product guide
  for load, throughput, PSI, stale data, and peak incidents;
- an action-first overview whose persistent status, operational findings, and
  rule summary share heartbeat, Docker collection, rule, compute, memory,
  thermal, network, storage, service, and reliability evidence. Delayed or
  failed collection and firing rules therefore affect the overall state, while
  a status-driven monochrome grain-wave canvas visualizes the same assessment;
- CPU, memory, temperature, 1/5/15-minute load, network, disk-I/O, filesystem,
  container, power, reliability, incident, and event views using area, line,
  composed, horizontal/stacked bar, histogram, and donut charts;
- operator headroom for logical-CPU-normalized load, swap, CPU/memory/I/O PSI
  `some` and `full`, free bytes, filesystem/inode use, read-only mounts,
  non-loopback interface error/drop rates, and the latest privacy-reduced app
  request/5xx/slow/latency interval;
- `1h`, `24h`, `7d`, and `30d` ranges, with at most 360 chart points;
- host, EXT5V supply/power/GPU, filesystem, and allow-listed `cks` container status;
- host-reliability state with stable local collector identity, sequenced
  heartbeat status, expected cadence and explicit lifecycle, plus a
  fixed-message timeline for boot transitions, collector gaps, SSH listeners,
  the primary network link, NVMe/RCU/OOM/filesystem signals, and NVMe runtime
  mitigation;
- bounded peak-incident evidence with PSI, fixed executable classes,
  fixed-label `cks` workloads, and per-capture app request counts (not visitors);
- recent semantic alerts and privilege outcomes without commands or arguments;
- a privacy-first generic log explorer for reviewed file and journald sources,
  with pre-parse credential/PII redaction, source health, bounded literal
  search, digest-bound pagination, and explicit stale/no-data/error states;
- a separate administrator-only infrastructure work ledger for completed,
  observed, pending, deferred, and standards-recommended work, including
  revision history, rationale, impact, evidence, and follow-up filters;
- a prioritized operational assessment that separates current state,
  current-boot evidence, last-known samples, and selected-range observations. Named danger/caution
  links open reload-safe subsystem guidance with the problem, likely symptoms,
  resolution checks, collected evidence, and a jump to the related data grid;
- stale-data and refresh-error indicators and one-minute visible-tab refreshes;
- a desktop 12-column adaptive GridStack layout. At 1024px and below it becomes
  a natural-height two-column reading flow, and at 640px and below a one-column
  flow, so saved desktop row heights cannot clip tablet or phone content.
  Pointer move/resize is available only in explicit desktop edit mode; keyboard
  controls, undo, cancel, save, and curated default reset remain available.
  Strictly validated schema-versioned geometry is stored per SSO subject in
  browser local storage and contains no telemetry;
- bounded pagination for operational logs, incidents, service groups and full
  service tables, infrastructure ledger entries, update packages, vital-sign
  tiles, and current app traffic. Filters reset or clamp the active page and
  every pager exposes localized range/total and keyboard-readable controls.

The overview keeps operational scanning compact while every subsystem has a
reload-safe detail route under `/monitor/details/:section`: `resources`,
`network`, `storage`, `containers`, `reliability`, `maintenance`,
`infrastructure`, `power`, `incidents`, and `logs`. Detail pages use the same
authenticated, bounded API
snapshot and add diagnosis/response guidance, range summaries, full charts,
service tables, incident evidence, traffic status-class aggregates, and
searchable structured event records. The event view never presents those
reduced records as raw logs and states that commands, arguments, and credentials
are not collected.

## Requirements

- Linux with systemd and Python 3 (the collector uses only the standard
  library)
- Node.js 22.12 or newer and npm
- `curl`, Docker with Compose, and the `cks` rootless Docker daemon
- Nginx with HTTPS termination for production
- `openssl` for generating credentials

## Production installation

These commands match the Bonifacio host. Run them from a trusted server
terminal.

### 1. Install and start the collector

```sh
cd /home/cks/Monitor
sudo sh ops/install.sh
sudo systemctl status monitor-collector.timer monitor-container-exporter.service monitor-collector.service
sudo journalctl -u monitor-collector.service -n 50 --no-pager
sudo python3 -m json.tool /var/lib/monitor-export/current.json >/dev/null
```

The timer runs the one-shot collector approximately once per minute. Local
overrides belong in `/etc/default/monitor-collector`. Each successful upgrade
replaces that file with the reviewed repository baseline (and restores the
prior copy only if installation fails), so keep intended changes in the
tracked baseline or reapply them deliberately after review.

The installer seeds `/etc/monitor-collector/log-sources.json` only when it is
absent. Review that allowlist before enabling application sources; see
[Generic log collection and explorer](docs/generic-logs.md). Existing source
configuration is never overwritten by an upgrade.

The same transaction installs the isolated alert-delivery worker and timer,
but never creates or overwrites operator secrets or
`/etc/monitor/alert-delivery.json`. Without that reviewed configuration the
worker is skipped. Upgrades retain the timer's prior enabled/active state, and
a first install leaves it disabled. To enable routing, start from the installed
example and follow [Alert delivery outbox](docs/alert-delivery.md); the
collector only enqueues, while the separate network-capable worker performs
delivery.

Encrypted state backup is also deliberately opt-in and is never scheduled by
the installer. Review the checked-in source-map template and complete a real
verify/clean-host restore drill before declaring an RPO; see
[Monitor state backup and recovery](docs/backup-recovery.md).

### 2. Create the production edge credential

Production needs only the shared edge-to-origin credential. It must be distinct
from every SSO or application secret and readable only by `cks`:

```sh
sudo install -d -o cks -g cks -m 0700 /home/cks/.config/monitor
sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/edge-secret'
sudo chmod 0600 /home/cks/.config/monitor/edge-secret
```

That is the SSO origin secret only. If the default-off central agent ingress is
enabled, generate and mount a separate `MONITOR_AGENT_EDGE_SECRET_FILE` for its
private mTLS proxy. It must not contain the same value as
`MONITOR_EDGE_SECRET_FILE`; startup fails closed when the agent secret is
missing, shorter than 32 bytes, or equal to the SSO secret.

Do not mount `MONITOR_PASSWORD_FILE`, `MONITOR_SESSION_SECRET_FILE`, or
`MONITOR_AUTH_STATE_FILE` in a `main`/ `dev` deployment. SSO mode does not
read credential contents and does not instantiate the local password store.
`GET /monitor/api/operations/auth-inventory` is admin-gated and reports
only aggregate file/cookie counts. If an old local state file remains, stop the
container and run the explicit owner-only `retire` procedure described below;
do not expose hash contents or remove a running local-mode store.

### 3. Build and start the rootless container

The host-specific production definition is
`/etc/portfolio-deploy/monitor.compose.yml`. It binds the application to
`127.0.0.1:5181`, mounts `/var/lib/monitor-export` read-only, mounts only the
edge secret at `/run/secrets/monitor_edge_secret`, and binds only the narrow
`/var/lib/monitor-update-socket` read-only at the container's
`/run/monitor-update` directory for the updater socket. It also binds the
cks-owned mode-`0700` `/var/lib/monitor-security` directory read-write at the
same container path for the digest-only API-key registry and durable
application audit journal; the application validates that boundary before
serving requests. It
requires an explicit image tag. There must be no writable auth-state mount,
local password/session secret, Docker socket, or broader host path mount in
this definition. This baseline leaves central agent ingress disabled. A
reviewed agent-ingress deployment must additionally mount its distinct agent
edge-secret file, private encrypted state directory, and storage keyring as
documented in `docs/agent-ingest-contract.md`.

Install the separate updater broker before adding that socket-directory bind. The
installer creates no package plan and runs no package action:

```sh
sudo sh ops/install-updater.sh
systemctl status monitor-update-gateway.socket monitor-update-worker.path
```

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker build \
    --build-arg PORTFOLIO_BRANCH=main \
    --build-arg PORTFOLIO_AUTH_MODE=sso \
    --tag portfolio-local/monitor:bootstrap \
    /home/cks/Monitor

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE=portfolio-local/monitor:bootstrap \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml \
    up --detach --no-deps --pull never monitor

curl --fail --silent --show-error http://127.0.0.1:5181/readyz
```

The image contains a read-only build-authentication contract. Server startup
compares it with the runtime branch and mode, so changing environment variables
cannot turn a `main`/ `dev` SSO image into a local-password image.

### 4. Publish `/monitor/` through Nginx

The location must preserve the `/monitor` prefix because both the frontend and
API are built for that base path. Install the reviewed Monitor-only snippets.
The API-key ingress remains dormant until the origin-TLS preconditions below
are satisfied. The peer map is an `http`-context file, while the API-key proxy
and Cloudflare real-IP files are location fragments and must not be included
directly at server scope:

```sh
sudo install -o root -g root -m 0644 \
  ops/nginx/monitor-public-readiness.conf \
  ops/nginx/monitor-api-key-ingress.conf \
  ops/nginx/monitor-api-key-proxy.conf \
  ops/nginx/monitor-cloudflare-real-ip.conf \
  /etc/nginx/snippets/

sudo install -o root -g root -m 0644 \
  ops/nginx/monitor-api-key-peer-map.conf \
  /etc/nginx/conf.d/monitor-api-key-peer-map.conf
```

The production server block uses this safe baseline. The public readiness
include must precede the broader SSO prefix:

```nginx
location = /monitor {
    return 308 /monitor/;
}

# One reduced readiness endpoint is public for the independent dead-man check.
include /etc/nginx/snippets/monitor-public-readiness.conf;

# Keep this absent until the origin-TLS and peer-boundary activation checklist
# below has been completed.
# include /etc/nginx/snippets/monitor-api-key-ingress.conf;

location ^~ /monitor/ {
    include /etc/nginx/snippets/bonifacio-sso-authrequest.conf;
    include /etc/nginx/snippets/monitor-edge-secret.conf;
    proxy_pass         http://127.0.0.1:5181;
    proxy_http_version 1.1;
    proxy_set_header   Host                $host;
    proxy_set_header   X-Real-IP           $remote_addr;
    proxy_set_header   X-Forwarded-For     $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto   https;
    proxy_set_header   X-Forwarded-Prefix  /monitor;
    proxy_intercept_errors on;
    error_page 502 503 504 =503 /_portfolio_unavailable.html;
}
```

External automation, once explicitly enabled, uses
`/monitor/api-key/v1/...`, not `/monitor/api/...`. The alias file maps only the
routes listed in
[`docs/application-security-state.md`](docs/application-security-state.md) to
the internal bearer middleware. Wrong methods return `405`; other paths remain
under SSO or return `404`. The proxy replaces the incoming forwarding chain
and accepts `CF-Connecting-IP` only from Cloudflare's published origin-facing
ranges, so API-key source-address restrictions receive one connection-derived
address. It also injects the private SSO edge credential; the application
rejects every bearer request before rate limiting or source-address evaluation
unless that credential matches. Express proxy trust is disabled globally; the
application reads the proxy-controlled rightmost address only after the SSO/API
edge credential has authenticated that hop. Agent mTLS requests deliberately
use the socket peer for audit and registration metadata; their certificate edge
proof does not grant trust to forwarding headers. Direct loopback calls
therefore cannot turn a forged forwarding header into a trusted client address,
including in local login rate limits, agent inventory, and audit metadata. Refresh
`monitor-cloudflare-real-ip.conf` from
<https://www.cloudflare.com/ips/> whenever Cloudflare publishes a range change,
validate with `nginx -t`, and keep direct origin access firewall-restricted.
The peer map is an application-layer backstop, not a replacement for that
network policy.

Do **not** activate `monitor-api-key-ingress.conf` while Cloudflare connects to
the origin over plain HTTP (including Flexible mode). Before activation, all of
the following must be demonstrated in the live deployment:

1. Nginx itself terminates origin HTTPS with a valid origin certificate and
   Cloudflare uses Full (strict), or an authenticated tunnel has an independently
   reviewed equivalent transport and peer-identity gate.
2. Non-Cloudflare direct origin access is denied by the host or upstream
   firewall, in addition to the checked-in `$realip_remote_addr` peer map.
3. `nginx -t` succeeds and negative tests prove that plain-HTTP and untrusted
   peers cannot reach an alias.
4. The high-impact `agents:write` and `system-updates:apply` aliases have
   explicit operator approval; their keys use the minimum scope, expiry, and
   source-IP allowlist.

The current Bonifacio production origin exposes only HTTP to Nginx, so the
API-key include is intentionally absent. Its public alias paths therefore stay
behind SSO until the checklist is completed.

After updating `/etc/nginx/sites-available/bonifacio.work`:

```sh
sudo nginx -t
sudo systemctl reload nginx
curl --fail --silent --show-error https://bonifacio.work/monitor/readyz
curl --head --silent --show-error https://bonifacio.work/monitor/
curl --silent --show-error \
  --header 'Authorization: Bearer invalid' \
  https://bonifacio.work/monitor/api-key/v1/dashboard
```

With the safe baseline, the last request must follow the normal SSO boundary;
an `INVALID_API_KEY` response is expected only after deliberate activation.

Only the Nginx/TLS endpoint should be exposed publicly. Port `5181` remains
loopback-only. The exact readiness location is currently the sole non-SSO
path. If the activation checklist is later completed, only the exact versioned
API-key aliases join it; the dashboard, security management, agent mTLS
ingress, and every other API remain behind SSO and the edge secret.

`.github/workflows/external-monitor.yml` checks both the exact readiness JSON
and the SSO redirect from a GitHub-hosted runner every five minutes. A failed
probe opens at most one fixed-title GitHub issue outside the monitored host and
still fails the workflow; the first later success comments on and closes that
issue. Neither path stores response bodies, credentials, or request headers.
This external incident is deliberately independent of Monitor's local alert
outbox, so a host, Nginx, application, or local delivery failure cannot silence
the only dead-man signal.

Install the separate privacy-preserving request counter after the site is
working:

```sh
cd /home/cks/Monitor
sudo sh ops/install-traffic-logging.sh
sudo systemctl restart monitor-collector.service
sudo systemctl status monitor-traffic-logrotate.timer monitor-traffic-retention.timer
```

The installed HTTP-level map has a fixed allowlist and writes one
identifier-free observation for each matching request: timestamp, fixed app
label, status code, and request duration. It does not persist IP, SSO subject,
method, URI/path/query, referrer, user agent, or cookies. Unknown paths are not
logged. `/blog` and `/blog/` are reduced to the fixed `blog` label before the
record is written, enabling Blog request/latency correlation without recording
which visitor or Blog path produced it. A dedicated timer checks the supplied logrotate rule every minute;
`maxsize 5M` means rotate on the next check after the active file crosses that
size, not a synchronous 5 MiB cap. Under-size non-empty files rotate daily and
at most two numbered, uncompressed archives are retained so a delayed collector
can finish reading an old inode. Before each rename, logrotate durably creates
the root-only marker
`/var/lib/monitor-traffic-logrotate/reopen-required`. A successful Nginx log
reopen durably removes it; a failed reopen leaves it in place, fails the unit,
and is retried before any later rotation. The one-shot uses a bounded
`Restart=on-failure` loop with a two-second delay, while the minute timer remains
the long-term retry path. Nginx is never signaled on marker-free timer checks.
An independent retention timer removes
exact-name, regular, single-link rotations older than 48 hours. Rotation,
retention, installation, and removal share one maintenance lock. The retention
path remains installed after traffic logging is removed; only a marker created
after a successful Nginx reload permits it to expire the final inactive log.
That marker must itself age for 48 hours, giving graceful Nginx workers time to
release the old descriptor before deletion.

The collector reduces those observations to per-app request, status-class,
slow-request, and response-time summaries for one capture interval. The newest
complete interval is exposed as `currentTraffic`; the same fixed-schema list is
attached to bounded peak incidents for correlation. An empty list means either
that no accepted request rows occurred in the interval or that the optional
source was unavailable—it is not proof of zero traffic. Dashboard request
counts therefore describe requests in one capture, not people or unique
visitors.

## Infrastructure work ledger

The telemetry event views and the infrastructure ledger serve different
purposes. Telemetry remains a bounded signal stream for current diagnosis. The
ledger at `/monitor/details/infrastructure` is an administrator-only,
long-lived work record for what was changed or observed, why it mattered, how
it was verified, its service impact, and what remains open. SSO `user` roles
cannot list or read it; `admin` and `chief-admin` can read it. The browser and
web container never write it.

Prepare the reviewed bootstrap as a root-only file outside the checkout, then
install the root-only writer before deploying the UI/API. The real bootstrap
is deliberately ignored by Git because this repository is public and the
ledger contains environment-specific operational history:

```sh
cd /home/cks/Monitor
sudo install -o root -g root -m 0600 \
  /path/to/reviewed-monitor-ledger-seed.json \
  /root/reviewed-monitor-ledger-seed.json
sudo sh ops/install-infrastructure-ledger.sh \
  /root/reviewed-monitor-ledger-seed.json
sudo /usr/local/sbin/monitor-infrastructure-ledger publish
sudo -u cks python3 -m json.tool \
  /var/lib/monitor-export/infrastructure-ledger.json >/dev/null
```

On an upgrade where the canonical stream already exists, omit the seed path;
the installer replaces the validated writer and republishes the existing
append-only stream. Initial installation fails closed without an explicit
absolute seed path.

The canonical append-only stream and catalog live under
`/var/lib/monitor-infrastructure-ledger` as `root:root` mode `0600` inside a
mode-`0700` directory. A validated, credential-free snapshot is atomically
published as `/var/lib/monitor-export/infrastructure-ledger.json`, owned
`root:cks` mode `0640`, through the export directory already mounted read-only
into Monitor. Files that are linked, broadly writable, malformed, oversized,
or contain credential-like material fail closed. Existing event IDs and source
definitions cannot silently change; corrections are appended as a new
revision with an explicit `supersedes` link.

The private bootstrap reconstruction's coverage block states the retained
evidence windows and deliberate gaps:
history outside retention, raw shell/session contents, secrets, personal
identifiers, authenticated third-party control-plane settings, and backup
contents are not claimed as known. Future changes should be prepared as one
strict entry object and appended with:

```sh
sudo /usr/local/sbin/monitor-infrastructure-ledger append \
  --input /root/reviewed-monitor-ledger-entry.json
```

The append input must be a root-owned regular file that is not group- or
world-writable; mode `0600` under `/root` is the expected staging boundary.
Do not put command lines, arguments, tokens, cookies, passwords, private keys,
client addresses, or personal data in that input. `publish` rebuilds the
public snapshot from the canonical stream without deleting history. The
writer fails when the 5,000-entry or 16 MiB safety bound is reached; it never
prunes silently. Backup and restore-test the private canonical directory as a
separate operational control.

## Local development

Use a branch other than `main` or `dev`. The shortest direct path creates a
private disposable password, session secret, and auth-state directory beneath
`.runtime/monitor-dev`; the password value is never printed and remains only in
the mode-`0600` file named by the startup message:

```sh
npm ci
npm run dev
```

This helper does not inspect host container sockets or synthesize telemetry.
Point `MONITOR_DATA_DIR` at a prepared collector export when dashboard data is
needed; the login UI and API can still start with the private disposable local
authentication state.

For an explicit reusable local setup, create disposable local data and secrets
without copying production values:

```sh
cd /home/cks/Monitor
install -d -m 0700 data secrets
MONITOR_AUTH_STATE_PATH="$PWD/auth-state" python3 ops/monitor_auth_state.py prepare
umask 077
openssl rand -hex 24 > secrets/password
openssl rand -hex 32 > secrets/session-secret
python3 ops/collector.py \
  --docker-sockets '' \
  --events-log /dev/null \
  --privilege-logs '' \
  --output-dir "$PWD/data" \
  --runtime-dir "/tmp/monitor-collector-$UID"
npm ci
```

Run the Vite frontend and Express API together:

```sh
MONITOR_DATA_DIR="$PWD/data" \
MONITOR_AUTH_STATE_FILE="$PWD/auth-state/password.json" \
MONITOR_PASSWORD_FILE="$PWD/secrets/password" \
MONITOR_SESSION_SECRET_FILE="$PWD/secrets/session-secret" \
MONITOR_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 \
npm run dev
```

Open `http://localhost:5173/monitor/`. Authentication cookies are always
`Secure`; use a browser that treats localhost as a secure development origin,
or put a local HTTPS reverse proxy in front of it.

Useful checks:

```sh
npm test
npm run test:collector
npm run build
docker build \
  --build-arg PORTFOLIO_BRANCH=feature/local-monitor \
  --build-arg PORTFOLIO_AUTH_MODE=local \
  --tag monitor:local .
```

To exercise the repository Compose definition with the disposable files:

```sh
MONITOR_IMAGE=monitor:local \
MONITOR_EXPORT_DIR="$PWD/data" \
MONITOR_AUTH_STATE_PATH="$PWD/auth-state" \
MONITOR_PASSWORD_PATH="$PWD/secrets/password" \
MONITOR_SESSION_SECRET_PATH="$PWD/secrets/session-secret" \
MONITOR_ALLOWED_ORIGINS=http://localhost:5181 \
npm run compose -- up --detach --build
```

## Configuration

Application variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORTFOLIO_BRANCH` | current Git branch outside packaged builds | Canonical branch identity; CI and Docker builds must set it explicitly |
| `PORTFOLIO_AUTH_MODE` | derived from the canonical branch | Must be `sso` for `main`/`dev` and `local` for every other branch |
| `HOST` | `0.0.0.0` | Express listen address |
| `PORT` | `8080` | Express listen port |
| `MONITOR_DATA_DIR` | `/data` | Sanitized collector export root |
| `MONITOR_UPDATE_SOCKET` | `/run/monitor-update/gateway.sock` | SSO-only fixed-protocol updater gateway path inside the container |
| `MONITOR_AUTH_STATE_FILE` | `/var/lib/monitor-auth/password.json` | Local-only disposable password-hash/session-epoch state file |
| `MONITOR_PASSWORD_FILE` | unset | Local-only bootstrap password file; used only when auth state is absent |
| `MONITOR_SESSION_SECRET_FILE` | unset | Local-only cookie HMAC secret file; at least 32 bytes |
| `MONITOR_EDGE_SECRET_FILE` | unset | SSO-only edge-to-origin shared secret file; at least 32 bytes and distinct from the session secret |
| `MONITOR_PASSWORD` | unset | Local-only bootstrap fallback when no password file is set |
| `MONITOR_SESSION_SECRET` | unset | Local-only fallback when no file is set |
| `MONITOR_EDGE_SECRET` | unset | Edge-secret fallback; use the private file in production |
| `MONITOR_ALLOWED_ORIGINS` | empty | Comma-separated permitted mutation origins |
| `MONITOR_SSO_ENABLED` | unset | Deprecated compatibility assertion; when present it must agree with `PORTFOLIO_AUTH_MODE` |
| `MONITOR_SESSION_TTL_SECONDS` | `3600` | Signed-session lifetime; capped at 24 hours |
| `MONITOR_STALE_AFTER_SECONDS` | `300` | Age at which telemetry is marked stale |
| `MONITOR_AGENT_INGEST_ENABLED` | `false` | Enables the optional SSO-only central enrollment/ingest path; missing prerequisites fail startup |
| `MONITOR_AGENT_EDGE_SECRET_FILE` | unset | Required private mTLS-proxy-to-origin secret file when agent ingest is enabled; at least 32 bytes and unequal to `MONITOR_EDGE_SECRET_FILE` |
| `MONITOR_AGENT_EDGE_SECRET` | unset | Agent-edge-secret fallback; use the private file in production |
| `MONITOR_AGENT_STATE_DIR` | unset | Required explicit private writable persistent root when central ingest is enabled; its host bind source/ancestor ownership and anti-rollback recovery contract are defined in `docs/agent-ingest-contract.md` |
| `MONITOR_AGENT_STORAGE_KEYRING_FILE` | unset | Required mode-`0600` AES-256-GCM keyring; see `docs/agent-ingest-contract.md` |
| `MONITOR_AGENT_MAX_BATCH_BYTES` | `262144` | Maximum compressed Content-Length and inflated agent JSON body |
| `MONITOR_AGENT_MAX_RECORDS_PER_BATCH` | `500` | Strict record count limit |
| `MONITOR_AGENT_MAX_QUEUE_BYTES` | `33554432` | Encrypted durable ingest queue byte limit |
| `MONITOR_AGENT_MAX_QUEUE_ENTRIES` | `256` | Encrypted durable ingest queue entry limit |
| `MONITOR_AGENT_MAX_QUEUE_BYTES_PER_AGENT` | `8388608` | Per-agent encrypted queue byte isolation cap |
| `MONITOR_AGENT_MAX_QUEUE_ENTRIES_PER_AGENT` | `64` | Per-agent encrypted queue entry isolation cap |
| `MONITOR_AGENT_MAX_BATCH_RECEIPTS` | `4096` | Retained batch acknowledgement window cap |
| `MONITOR_AGENT_MAX_BATCH_RECEIPTS_PER_AGENT` | `1024` | Per-agent acknowledgement isolation cap |
| `MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS` | `100000` | Retained record-deduplication window cap |
| `MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS_PER_AGENT` | `25000` | Per-agent record-deduplication isolation cap |
| `MONITOR_AGENT_PRIORITY_RESERVE_PERCENT` | `20` | Queue capacity reserved for event batches |
| `MONITOR_AGENT_MAX_CLOCK_SKEW_SECONDS` | `300` | Agent send/future-observation tolerance |
| `MONITOR_AGENT_MAX_BACKFILL_AGE_SECONDS` | `604800` | Oldest admitted offline record |
| `MONITOR_AGENT_QUEUE_RETENTION_SECONDS` | `604800` | Queue and idempotency retention |
| `MONITOR_AGENT_MAX_ENROLLMENT_TTL_SECONDS` | `900` | Maximum one-use enrollment/rotation token lifetime |
| `MONITOR_AGENT_CERTIFICATE_EXPIRY_WARNING_SECONDS` | `1209600` | Renewal-warning horizon returned to agents/admins |

Central-agent control state uses fixed non-configurable memory guards: 4 MiB
for the serialized UTF-8 state and 6 MiB for its AES-256-GCM envelope. Capacity
is checked before encryption and returns `429 CONTROL_STATE_BACKPRESSURE`;
ingest batch and queue limits above remain separate. Agent proxy authentication
runs before body parsing, small control requests are capped at 8 KiB, and a
fixed four-request global body gate bounds concurrent JSON/gzip memory. The
gate permits only one incomplete body per verified certificate and closes it
at a 15-second absolute deadline, so one enrolled agent cannot occupy every
global permit with slow uploads.

The repository Compose launcher automatically selects `docker-compose.sso.yml` or
`docker-compose.local.yml` from the canonical mode. Common options are
`MONITOR_IMAGE`, `MONITOR_PORT`, `MONITOR_EXPORT_DIR`, and the pre-provisioned
`MONITOR_SECURITY_STATE_PATH`. SSO mode additionally
accepts `MONITOR_EDGE_SECRET_PATH`; local mode accepts
`MONITOR_AUTH_STATE_PATH`, `MONITOR_PASSWORD_PATH`, and
`MONITOR_SESSION_SECRET_PATH`. The repository baseline Compose files do not
enable central agent ingress or mount its separate secret/state/keyring.

Collector variables and defaults are:

| Variable | Default |
| --- | --- |
| `MONITOR_OUTPUT_DIR` | `/var/lib/monitor-export` |
| `MONITOR_RUNTIME_DIR` | `/run/monitor-collector` |
| `MONITOR_PROC_ROOT`, `MONITOR_SYS_ROOT`, `MONITOR_ETC_ROOT` | `/proc`, `/sys`, `/etc` |
| `MONITOR_PACKAGE_ROOT` | `/`; fixture root for installed kernels and packaged Pi EEPROM files |
| `MONITOR_EVENTS_LOG` | `/var/log/server-watch/events.log` |
| `MONITOR_KERNEL_LOG` | `/var/log/kern.log` |
| `MONITOR_PRIVILEGE_LOGS` | `/var/log/privilege-events.log` |
| `MONITOR_TRAFFIC_LOG` | `/var/log/nginx/monitor-traffic.jsonl` |
| `MONITOR_CONTAINER_INPUT` | `/run/monitor-container-exporter/containers.json` in production |
| `MONITOR_SYNTHETIC_INPUT` | `/var/lib/monitor-synthetic/results.json`; URL-free result handoff from the opt-in worker |
| `MONITOR_DOCKER_SOCKETS` | empty in production; direct socket mode is fixture/development-only and rejects non-`cks` owners |
| `MONITOR_PROCESS_UIDS` | `0,1001` (root and `cks`; other UIDs are rejected) |
| `MONITOR_CURL` | `/usr/bin/curl` |
| `MONITOR_VCGENCMD` | `/usr/bin/vcgencmd` |
| `MONITOR_COMMAND_TIMEOUT` | `2` seconds per command |
| `MONITOR_EXPECTED_INTERVAL_SECONDS` | `60`; heartbeat cadence declaration, clamped to 10–86,400 seconds (does not reschedule the systemd timer) |
| `MONITOR_AGENT_LIFECYCLE` | `active`; exact alternatives are `maintenance` and `inactive`, and this is host configuration rather than an admin workflow |
| `MONITOR_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_LOG_RECORDS` | `5000` per event export |
| `MONITOR_INCIDENT_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_INCIDENT_RECORDS` | `1000` |
| `MONITOR_INCIDENT_FOLLOW_UP_SAMPLES` | `5` |
| `MONITOR_CPU_WARN_PERCENT`, `MONITOR_CPU_RECOVER_PERCENT` | `85`, `75` |
| `MONITOR_CPU_WARN_SAMPLES` | `2` consecutive one-minute samples |
| `MONITOR_MEMORY_AVAILABLE_WARN_PERCENT`, `MONITOR_MEMORY_AVAILABLE_RECOVER_PERCENT` | `20`, `25` |
| `MONITOR_TEMPERATURE_WARN_C`, `MONITOR_TEMPERATURE_RECOVER_C` | `75`, `72` |
| `MONITOR_LOAD_WARN`, `MONITOR_LOAD_RECOVER` | `4`, `2` |
| `MONITOR_DISK_IO_WARN_BYTES_PER_SECOND`, `MONITOR_DISK_IO_RECOVER_BYTES_PER_SECOND` | `104857600`, `52428800` |
| `MONITOR_TRAFFIC_REQUEST_WARN`, `MONITOR_TRAFFIC_REQUEST_RECOVER` | `300`, `200` per collector interval |
| `MONITOR_TRAFFIC_SLOW_SECONDS` | `1` |
| `MONITOR_MAX_INPUT_BYTES` | `1048576` per input read |
| `MONITOR_KERNEL_MAX_INPUT_BYTES` | `8388608` per kernel-log read |
| `MONITOR_RULE_PACK` | `/usr/local/lib/monitor-collector/rules/default-rules.v1.json` |
| `MONITOR_LOG_SOURCES_CONFIG` | `/etc/monitor-collector/log-sources.json`; exact reviewed file/journald allowlist |
| `MONITOR_LOG_SOURCES_REQUIRED` | `false`; missing optional config publishes no-data, while `true` fails the log subsystem closed |
| `MONITOR_JOURNALCTL` | `/usr/bin/journalctl` |
| `MONITOR_GENERIC_LOG_RETENTION_DAYS` | `30` |
| `MONITOR_GENERIC_LOG_MAX_RECORDS` | `20000` |
| `MONITOR_GENERIC_LOG_MAX_FILE_BYTES` | `16777216` |
| `MONITOR_GENERIC_LOG_TOTAL_TIMEOUT` | `15` seconds across one collection cycle |

`MONITOR_MOUNTINFO` and `MONITOR_MOUNT_ROOT` remain fixture overrides. The
production unit pins `--mountinfo=/proc/1/mountinfo` so filesystem state comes
from the host mount namespace rather than the collector's intentionally
read-only `ProtectSystem` view. The installed source of truth is
`/etc/default/monitor-collector`, seeded from
`ops/monitor-collector.default`. Colon-separate additional privilege log
fallbacks only when necessary; enabling overlapping sources can duplicate
events. `ops/install.sh` transactionally replaces this file with the reviewed
production baseline on upgrade, so obsolete socket or user entries cannot
survive; a failed install restores the previous file. The shipped production unit additionally disables direct Docker
collection and pins the exact reduced container input, process UID set, and
traffic-log path on its command line, so a later-edited environment file
cannot widen those collection boundaries.
Restart the one-shot service after a change:

```sh
sudo systemctl restart monitor-collector.service
```

## Export schema and retention

The default root is `/var/lib/monitor-export`:

- `current.json` is schema version 2 and contains exactly `schemaVersion`,
  `generatedAt`, `identity`, `heartbeat`, `host`, `latest`, `disks`,
  `containers`, `containerCollection`, `dockerEventCollection`, `dockerEvents`,
  `syntheticProbeCollection`, `syntheticProbes`, `currentTraffic`,
  `reliability`, `system`, and `linux`. Container source status distinguishes
  fresh, bounded last-known, unavailable, permission-denied, and collection
  error observations. A new container row is the fixed 58-field reduced v4
  contract. Its 17-field compatibility prefix covers safe identity/lifecycle,
  health, CPU/memory, limits, restart/OOM and timestamps; the v3-compatible suffix covers
  opaque instance identity, PIDs/throttling, block I/O, network totals/rates,
  writable-layer and mount/network counts, security booleans including sensitive-bind
  writability, capability counts,
  and validated image tag/digest/drift evidence. V4 adds `mountPolicyStatus`:
  a fresh exact reviewed host-storage profile is `approved`; any valid mismatch
  is `drift`; incomplete or stale evidence is `unknown`; services without a
  profile are `unmanaged` and keep the prior bind heuristic. Missing Docker evidence remains
  `null`; raw IDs, commands, environment, raw mount paths, Actor attributes, and
  network addresses and reviewed profile details are never published. Exact V3
  rows remain readable, with reviewed services normalized to `unknown` rather
  than approved. Legacy seven-field rows are read with
  new fields unknown, and incident evidence intentionally remains the smaller
  seven-field projection. Docker event status and at most 128 reduced lifecycle
  events are independent from list/stats freshness. Docker stdout/stderr is
  explicitly `unsupported` rather than silently empty. Synthetic source status
  and its bounded URL-free HTTP/TLS results likewise distinguish unsupported,
  stale, permission, and collection failures.
- `history/YYYY-MM-DD.jsonl` contains one reduced telemetry sample per line.
  Each day is capped at 2,000 rows and the default calendar retention is 30
  days.
- `alerts.jsonl`, `power.jsonl`, and `privilege.jsonl` are each capped at 5,000
  records. Every `power.jsonl` record has exactly `timestamp`, `severity`,
  `kind`, `status`, and a fixed semantic `message`; it never contains the raw
  kernel line.
- `rule-evaluation.json` contains the latest versioned fixed-schema rule
  evaluation, including explicit unsupported, no-data, permission, and
  collection-error phases. `rule-alerts.jsonl` keeps at most 5,000
  idempotent firing/resolution transitions. The seed pack defines all 82
  documented defaults; rules without a proven signal remain unsupported
  rather than appearing healthy.
- `monitoring-catalog.json` is rebuilt on each collector pass and lists all
  reviewed public evidence artifacts, grouped observation families, and every
  loaded alert rule. It resolves runtime cadence, retention bounds, and pruning
  timing without exposing absolute input paths, credentials, private state, or
  raw telemetry. Authenticated dashboard readers access the strict normalized
  contract at `GET /monitor/api/monitoring-catalog`; unsafe ownership, mode,
  links, size, UTF-8, or schema make the endpoint fail closed. A generation
  failure removes the prior public catalog rather than serving stale runtime
  policy as current.
- `generic-logs.jsonl` and `generic-log-sources.json` contain only pre-parse
  redacted, exact-schema generic records and per-source acquisition/drop state.
  Their matching mode-`0600` cursor/quota state and pending transaction live
  under `.state`; an unsafe config or persistence failure is an explicit
  `generic-log-collection-error.json`, isolated from host snapshot publication.
- `incidents.jsonl` is capped at 1,000 records, 16 MiB, and 30 days. A record is
  written only on incident entry, during at most five one-minute follow-ups,
  when another threshold joins the same window, and on recovery.
- `infrastructure-ledger.json` is a separately managed, bounded public
  materialization of the root-only append stream. It is not collector telemetry
  and is not pruned by telemetry retention. The API exposes it only to an
  authenticated local session or an SSO `admin`/`chief-admin` identity.
- `.state/log-cursors.json` stores durable source positions. New fixed-schema
  alert, power, and privilege rows plus next cursors and per-output base/final
  digests first enter the bounded mode-`0600`
  `.state/pending-sanitized-log-commit.json`; replay uses the digests to finish
  each output exactly once before advancing the cursor. Identical public rows
  from distinct alert or privilege source events remain distinct.
  `.state/incident-lifecycle.json` keeps only the active incident ID, reasons,
  hysteresis/follow-up state, and peaks so recovery survives a reboot. Incident
  record, lifecycle, and request cursor changes similarly first enter
  `.state/pending-incident-commit.json`. Startup replays both journals before
  new source reads and removes each only after every destination is fsynced.
  An unsafe pending journal is preserved unchanged and collection fails closed
  instead of deleting or replacing it.
  Short-lived host-rate and hashed process counters live in mode-`0600`
  `/run/monitor-collector/delta-state.json`; the request source uses a separate
  mode-`0600` durable cursor. Container IDs and CPU baselines stay only in the
  `cks` exporter's private runtime file and are never mounted into the root
  collector.

`identity` publishes only random UUIDv4 `hostId`/`agentId`,
`installationEpoch`, `identityGeneration`, `machineIdentityStatus`, and a
nullable reduced `bootId`. The UUIDs survive normal collector and host restarts.
The mode-`0600` `.state/collector-identity.json` additionally keeps sequence
state and a domain-separated SHA-256 hash of a valid `/etc/machine-id`; neither
the raw machine ID nor that hash is public. When both the retained and current
hash exist and differ, the collector treats the state as a copied installation,
creates new host/agent UUIDs, increments the generation, and resets sequence to
1. `machineIdentityStatus=unavailable` means no valid binding has yet been
established. A temporarily unreadable current machine ID does not discard a
retained binding, but clone comparison requires both hashes. Invalid private
state permissions, links, size, or schema fail closed.

`heartbeat` publishes `sequence`, `observedAt`, `receivedAt`,
`expectedIntervalSeconds`, `lifecycle`, and `transport=local-file`. The private
sequence is advanced before the public snapshot, so publication failures create
detectable gaps instead of number reuse. In this same-host path, received and
observed times are equal; they are not evidence of network delivery. The API
strictly validates both objects, maps legacy snapshots with neither object to
`unknown`, and maps malformed partial contracts to `collection_error`. An
active heartbeat is `delayed` after the greater of 90 seconds or two expected
intervals, then `disconnected` after the greater of the configured application
stale threshold or five intervals. Explicit `maintenance` and `inactive` values
take precedence. The UI feeds these states, non-fresh `containerCollection`,
and firing/recovering or failed rule evaluations into operational findings and
the overall strip; unavailable/permission-denied Docker collection shows no
healthy zero-service count, and last-known collection remains visibly stale.

`host` contains hostname, OS, architecture, online logical-CPU count, and
uptime. Top-level `system`
contains a fixed, serial-free snapshot of running/latest-installed kernel,
Raspberry Pi bootloader channel and dates, NVMe model/firmware, collector
version, negotiated/configured PCIe generations and widths, ASPM/NVMe power
settings, bounded AER counters/status flags, and current-boot semantic kernel
event counts with their last timestamps. Missing legacy `system` data remains
readable as explicit unknown values and zero event counts. A `latest`/history
sample contains a timestamp plus CPU and memory percentages and byte totals;
swap total/used bytes and percentage; temperature and 1/5/15-minute load;
current Linux PSI `some`/`full` avg10 percentages for CPU, memory, and I/O;
power state, the sampled `supplyVoltageVolts`, numeric uint32
`throttledFlags`, GPU memory/clock, aggregate non-loopback network RX/TX byte,
error, and dropped-packet rates, and disk read/write rates. Interface names are
not exported. Missing, unsupported, reset, or invalid counters are represented
as `null`.
`latestObservedAt` is the timestamp of the last real telemetry sample, or
`null` when `latest` is only the bounded synthetic fallback used to keep the
response shape stable.

Once per collector run, `vcgencmd pmic_read_adc EXT5V_V` supplies the single
external 5 V rail sample, while the standard `rpi_volt/in0_lcrit_alarm` hwmon
attribute supplies the current under-voltage state in bit 0 of the compatible
flags field. The collector never invokes deprecated `vcgencmd get_throttled`.
EXT5V is a point-in-time rail voltage—not input current
in amperes, consumed or available watts, wall-outlet power, or the USB-C
negotiated power profile. Monitor does not invent a voltage threshold from this
sample. Kernel under-voltage/recovery reports and the hwmon alarm are
the authoritative condition signals; a missing voltage is unknown, not zero.

The collector reads only its configured bounded portion of `/var/log/kern.log`
and recognizes a narrow semantic allow-list: the exact Raspberry Pi
`Undervoltage detected!` and `Voltage normalised` events; NVMe controller reset
and I/O-error patterns; RCU stalls, OOM kills, filesystem errors, hung tasks,
kernel warnings/oops/panics; and fixed PCIe AER and link transitions. It maps
those to fixed messages and exports no device-specific raw text. Reliability
records retain available sub-second precision and deduplicate only exact
replays; the dedicated kernel power feed keeps its documented same-second
semantic burst collapse.
Short expedited RCU delays have their own current-boot `rcuExpedited` counter;
they are not merged into the generic `warning` counter or the active
`rcuStall` counter. That boot counter is authoritative when the bounded API
timeline cap omits older individual rows.
A missing kernel log is non-fatal and simply yields no new kernel power events.

The hardened collector intentionally has no `CAP_SYS_ADMIN`. Linux therefore
limits its PCI config-space read to the conventional 64-byte header, so the
three PCIe Device Status active-bit fields normally remain `null` in production.
They are optional diagnostics, not health evidence. The capability-free sysfs
AER counters and fixed kernel-log AER events are the authoritative PCIe error
signals; do not grant `CAP_SYS_ADMIN` merely to populate the optional bits.

Each filesystem is reduced to its mount, total/used/available bytes, used and
inode-used percentages, and read-only state. These are aggregate `statvfs`
properties; no filenames, directory contents, or inode identities are read or
exported. Docker
list requests are restricted to explicitly reviewed Compose projects, and
only exact reviewed project/service pairs become fixed, distinct workload
labels. Previous app-level labels and the generic `cks-workload` value remain
readable in retained history but are never emitted for a new observation. Each admitted workload is
reduced to that label/project, owner, state, authoritative health support,
CPU/memory usage, configured limits, restart/OOM state, and lifecycle
timestamps. The Blog Compose services `blogWeb` and `blogServer` are
published only as `blog-frontend` and `blog-backend`; the default dashboard
order keeps them together, frontend before backend, among the alphabetically
ordered non-core apps. Incident process evidence is grouped into fixed executable
classes such as `node`, `python`, `web-server`, or `other` and contains only
instance count, CPU percentage, and memory bytes. Request evidence contains
only a fixed app label, total/status-class/
slow counts, and average/maximum response time. Alerts contain only timestamp,
severity, kind, status, and a bounded semantic message. Privilege records
contain only timestamp, actor, target, action, and result—never PID, UID,
command, arguments, environment, client identifier, URI, container ID, image,
mount, or a raw log line.

The API validates and bounds the files again, rejects malformed, out-of-range,
or future data, and marks a response stale when no recent sample exists. It
returns at most 360 chart samples and 500 each of incidents, alerts, power
events, privilege events, and rule transitions. Rule evaluation and rule
transitions remain separate from legacy semantic alerts. Chart downsampling retains the first/last sample,
power-state/flag transitions, and global minima/maxima for CPU, memory,
temperature, 1/5/15-minute load, voltage, network receive/transmit, and disk
read/write rates. `telemetrySummary` is calculated from every valid sample
before downsampling and contains exact range sample count, resource averages
and peaks, plus gap-capped network and disk transfer totals. `powerSummary` is
also calculated from every valid sample and contains `sampleCount`,
`voltageSampleCount`, minimum/average/maximum EXT5V, and active
under-voltage/throttle sample counts. `powerEvents` contains exactly
`timestamp`, `severity`, `kind`, `status`, `message`,
`supplyVoltageVolts`, and `throttledFlags`; dedicated `power.jsonl` events take
precedence, legacy power alerts are merged with semantic deduplication, and
only a telemetry sample within two minutes may be attached to an event.

Supported requests are:

```text
GET    /healthz
GET    /readyz
POST   /monitor/api/auth/login
GET    /monitor/api/auth/session
DELETE /monitor/api/auth/session
POST   /monitor/api/auth/password
GET    /monitor/api/dashboard?range=1h|24h|7d|30d
GET    /monitor/api/generic-logs               # authenticated, safe-snapshot cache, 20 reads/min/IP
GET    /monitor/api/infrastructure-ledger      # admin/chief-admin in SSO mode
GET    /monitor/api/operations/auth-inventory  # admin/chief-admin, aggregate only
GET    /monitor/api/system-updates              # authenticated, sanitized state
POST   /monitor/api/system-updates/check        # canonical/legacy admin or canonical chief-admin
POST   /monitor/api/system-updates/prepare      # canonical chief-admin, current plan only
POST   /monitor/api/system-updates/apply        # canonical chief-admin, one-use confirmation
GET    /monitor/api/agents                      # optional central path; SSO admin
POST   /monitor/api/agents/enrollment-tokens    # optional central path; canonical chief-admin
POST   /monitor/api/agents/:id/certificate-rotation-tokens # canonical chief-admin
POST   /monitor/api/agents/:id/revoke           # canonical chief-admin
POST   /monitor/api/agent/enroll                # enrollment token + trusted proxy mTLS metadata
POST   /monitor/api/agent/heartbeat             # bound proxy-verified certificate
POST   /monitor/api/agent/ingest                # bound certificate; bounded JSON/gzip batch
POST   /monitor/api/agent/certificate-rotations # bound one-use token + new certificate
```

## Security boundaries

- The root collector is a hardened, one-shot systemd unit with a restricted
  capability set, read-only host paths, and writes limited to its export and
  runtime directories.
- The root collector has no Docker socket. A short-lived helper running as
  `cks` sees only that account's rootless socket, maps mutable names to fixed
  labels, and atomically writes a mode-`0640` snapshot. The root service sees
  only that exact snapshot file and revalidates its owner, mode, age, size, and
  nested schema. The web container also has no socket mount.
- Export files are bounded, atomically replaced, and readable by the `cks`
  deployment boundary without becoming world-readable.
- Stable collector UUIDs and sequence state are kept in an exact-schema,
  owner-only mode-`0600` file. The raw machine ID and raw Linux boot UUID are
  never exported; the public contract exposes only binding availability and a
  domain-separated reduced boot digest. A verified machine-hash change rekeys a
  copied identity. A retained binding survives a temporary read failure, but
  clone comparison is possible only when both hashes are available.
- The infrastructure ledger has a separate root-only append stream. A narrow
  writer validates exact fields, revision chains, source references, size,
  links, permissions, and credential-like content before atomically replacing
  the read-only public snapshot; the API independently validates it and applies
  the administrator role gate.
- Hashed process identifiers exist only in the mode-`0600` runtime delta file
  and are never exported. Incident evidence contains fixed executable classes
  only. The bounded Nginx input has no client or request identifier;
  its rotation and independent 48-hour retention checks run every minute, and
  both collector and API independently enforce the fixed app allowlist. A
  root-only, fsync-backed pending-reopen marker prevents a failed Nginx reopen
  from being forgotten merely because logrotate already advanced its state.
- The production rootless container has a read-only filesystem and telemetry
  mount, no writable local password/session store, no Linux capabilities,
  `no-new-privileges`, a small tmpfs, and CPU, memory, PID, and log-size limits.
  Its one deliberate application-state write boundary is the cks-owned
  mode-`0700` `/var/lib/monitor-security` bind for the digest-only API-key
  registry and audit journal. Only the local Compose overlay adds a disposable
  writable password auth-state mount.
- The updater socket is a deliberate write capability. Its unprivileged gateway
  verifies peer UID 1001 and cannot invoke APT. A separate root worker revalidates
  the queue and exposes only fixed package-check and confirmed safe-apply
  operations. Host processes running as trusted deployment account `cks` share
  that UID trust boundary; no other container receives the runtime-directory
  bind. See `ops/UPDATER.md` for the exact plan, audit, and failure contracts.
- Local-mode sessions are HMAC-signed, one-hour by default, and stored in `HttpOnly`,
  `Secure`, `SameSite=Strict` cookies scoped to `/monitor`. Login permits five
  failed attempts per 15 minutes; state-changing API requests enforce origin
  checks.
- Production SSO requests reach the app only through Nginx on the same host.
  Nginx removes client-supplied identity headers, obtains them from Authelia,
  overwrites `Remote-User`/`Remote-Email`/`Remote-Groups`, and overwrites a
  dedicated secret header which the application compares in constant time;
  port `5181` remains loopback-only. Identity headers without the matching
  secret and canonical v2 app-entitled groups fail closed.
  Signing out redirects to the central `/sso/logout` endpoint. Local password
  authentication remains available only when the canonical authentication mode
  is `local`.
- API responses are `no-store`; Helmet supplies a restrictive CSP and related
  headers. The data reader refuses symlink escapes, oversized files/lines, and
  non-allow-listed fields, and applies a second redaction pass to messages.
- Kernel power evidence is reduced to the fixed `power.jsonl` schema before the
  web container can read it. The container never receives `/var/log/kern.log`
  or another raw host log, including the Nginx aggregate source.

This is a private operations view. Keep it behind the central HTTPS SSO gate,
do not expose port `5181`, and do not mount additional host paths into the
container beyond the read-only telemetry export, edge secret, the exact
read-only `/var/lib/monitor-update-socket` host directory at
`/run/monitor-update`, and the exact read-write `/var/lib/monitor-security`
application-state directory. Never mount broader `/var/lib` or `/run`, Docker,
systemd, APT, or host filesystem paths.

## GitHub Actions deployment

`.github/workflows/deploy.yml` runs on `main` and `dev` pushes and by manual
dispatch. It builds and tests both SSO branches, but only `main` publishes
`:latest` and requests a deployment. It:

1. runs the Python collector and branch/Compose contract tests;
2. builds and tests one `linux/amd64` + `linux/arm64` manifest with provenance
   and SBOM, verifies both platform entries, and scans each platform for critical
   vulnerabilities;
3. publishes the immutable SHA tag (and `:latest` only for `main`);
4. on `main` only, connects with the repository `DEPLOY_KEY` secret and requests only
   `deploy monitor <40-character-sha>`.

The server-side forced-command dispatcher validates that command, logs in to
GHCR using the short-lived Actions credential received on standard input,
pulls the immutable SHA tag, remembers the current image as
`portfolio-local/monitor:rollback`, recreates only the Monitor service, and
checks telemetry readiness plus the Nginx HTML and JSON session paths. On
failure it restores the prior image automatically. A successful revision is recorded at
`/home/cks/.local/state/portfolio-deploy/monitor.revision`.

The only long-lived repository secret required by the workflow is
`DEPLOY_KEY`; the corresponding public key must remain restricted to the
server dispatcher.

## Local-only password state

Password state, session signing, password changes, backups, and recovery exist
only for branches outside `main` and `dev`. The default helper keeps this
disposable state beneath `.runtime/monitor-dev`, which is ignored by Git.
The repository's `docker-compose.local.yml` likewise adds the password and
session secrets plus the writable auth-state mount only when the canonical mode
is `local`.

Local password state stores a scrypt hash and session epoch, never plaintext.
It is not an application user database and must not be copied into production.
Delete the disposable local directory to reset local access; never reuse the
central SSO password, edge secret, or production data as local credentials.

## Rollback, diagnostics, and uninstall

Action-driven deployments roll back automatically on a failed health check.
To select the saved image manually:

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker image inspect portfolio-local/monitor:rollback >/dev/null

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE=portfolio-local/monitor:rollback \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml \
    up --detach --no-deps --pull never monitor
curl --fail --silent --show-error http://127.0.0.1:5181/readyz
```

Diagnostics do not require exposing secret values:

```sh
sudo systemctl status monitor-collector.timer monitor-collector.service
sudo journalctl -u monitor-collector.service -n 100 --no-pager
sudo /usr/bin/vcgencmd pmic_read_adc EXT5V_V
sudo -u cks jq '.latest | {powerState, supplyVoltageVolts, throttledFlags}' /var/lib/monitor-export/current.json
for hwmon in /sys/class/hwmon/hwmon*; do
  [ "$(cat "$hwmon/name" 2>/dev/null)" = rpi_volt ] || continue
  cat "$hwmon/in0_lcrit_alarm"
done
sudo systemctl start monitor-collector.service
sudo -u cks tail -n 20 /var/lib/monitor-export/power.jsonl
sudo -u cks env XDG_RUNTIME_DIR=/run/user/1001 DOCKER_HOST=unix:///run/user/1001/docker.sock docker logs --tail 100 monitor
sudo nginx -t
```

`pmic_read_adc EXT5V_V` confirms whether this board exposes the sampled rail.
The fixed-schema snapshot and the Raspberry Pi `rpi_volt` hwmon alarm expose the
safe current power state. Do not invoke deprecated `vcgencmd get_throttled` on
this kernel: merely reading it emits a kernel warning. An unsupported command or
missing reading should appear as `null`, not as a fabricated zero. Inspect the
sanitized `power.jsonl` export rather than copying raw kernel-log lines into
tickets or chat. If the file is absent, run the collector once and check its
journal; absence remains normal on hosts without a matching kernel event.

Remove the container and active privacy request logging, then the collector:

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE=unused \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml down
sudo sh /home/cks/Monitor/ops/uninstall-traffic-logging.sh
sudo sh /home/cks/Monitor/ops/uninstall.sh
```

The traffic uninstaller leaves its independent retention service and timer in
place so exact-name logs expire even though Nginx no longer writes them. It
marks the active file retired only after Nginx has successfully reloaded without
the logging configuration, then waits 48 hours before that final file becomes
eligible. The collector uninstaller
deliberately preserves
`/var/lib/monitor-export` and
`/etc/default/monitor-collector`. It does not remove the independent
`/var/lib/monitor-infrastructure-ledger` canonical record. It also leaves the
edge credential, production Compose file, deployment
dispatcher entry, Nginx route, and container images in place. Local disposable
auth state beneath the worktree is separate and can be removed when no longer
needed.
