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
                                                        | read-only bind mount
                                                        v
browser -> TLS/Nginx + central SSO -> Express API + React UI
```

The privilege boundary is intentional: the root collector reads protected host
inputs but its mount namespace contains no Docker socket. A separate one-shot
helper runs as the same unprivileged `cks` account that already owns the sole
rootless daemon and writes only a strictly validated, fixed-schema snapshot.
The web container receives neither Docker sockets nor raw logs; it can read
only the collector's reduced export. In production SSO
mode the application has no password database, session database, auth-state
directory, or other writable user store. It consumes only the identity asserted
by the central SSO edge, protected by a dedicated read-only edge secret.

Local mode is deliberately different: it creates a disposable, application-
specific password hash and signed cookie under the worktree so the application
can be developed without the SSO stack. That state is a local development aid,
not a second production identity system.

## Branch authentication contract

`scripts/portfolio-auth-mode.sh` is the only branch-to-authentication resolver.
It uses `PORTFOLIO_BRANCH`, then `GITHUB_REF_NAME`, then the current Git branch.
`main` and `dev` resolve to `sso`; every other branch resolves to `local`. If an
explicit `PORTFOLIO_AUTH_MODE` disagrees, startup, build, or Compose validation
fails closed. Container images additionally carry a read-only build contract;
runtime branch/mode overrides must match the branch and mode used to build the
image.

In `sso` mode Monitor still requires the edge secret and accepts `Remote-*`
identity only when the Nginx-injected secret matches. `Remote-Groups` must be
one whitespace-free, exact hierarchy-closed prefix: `user`, `user,developer`,
or `user,developer,admin`; missing, empty, whitespace-padded, duplicate,
unknown, or reordered groups fail closed. A valid `user` can inspect only its SSO session identity; both the
dashboard and metadata-only legacy auth inventory require `developer` or
`admin`, matching the outer `/monitor` ACL in a second application-level
boundary. Roles are recalculated from the trusted headers on every request and
are never stored in a Monitor cookie.
Local login and password changes stay disabled, and the SSO session check
expires any legacy Monitor cookie presented by that browser. In `local` mode
the existing password screen, scrypt state, and signed Monitor cookie remain
active; local mode is not an unauthenticated SSO bypass. `MONITOR_SSO_ENABLED`
is now only a compatibility check: if an older deployment still supplies it,
it must agree with the canonical mode.

The dashboard provides:

- CPU, memory, temperature, load, network, and disk-I/O summaries and charts;
- `1h`, `24h`, `7d`, and `30d` ranges, with at most 360 chart points;
- host, EXT5V supply/power/GPU, filesystem, and allow-listed `cks` container status;
- bounded peak-incident evidence with PSI, fixed executable classes,
  fixed-label `cks` workloads, and per-capture app request counts (not visitors);
- recent semantic alerts and privilege outcomes without commands or arguments;
- stale-data and refresh-error indicators, one-minute visible-tab refreshes,
  and a responsive table/card layout.

The overview keeps operational scanning compact: it shows the latest EXT5V and
throttle state, the latest three incident captures, and at most the newest 10
alerts and 10 privilege records from the selected range. `/monitor/details`
uses the same authenticated API snapshot to show the full API-bounded event and
incident lists (up to 500 each), the EXT5V history and power/storage event
timeline, full-range power statistics, and expanded CPU, memory,
temperature/load, network, and disk-I/O charts.

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
overrides belong in `/etc/default/monitor-collector`; the installer preserves
an existing file.

### 2. Create the production edge credential

Production needs only the shared edge-to-origin credential. It must be distinct
from every SSO or application secret and readable only by `cks`:

```sh
sudo install -d -o cks -g cks -m 0700 /home/cks/.config/monitor
sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/edge-secret'
sudo chmod 0600 /home/cks/.config/monitor/edge-secret
```

Do not mount `MONITOR_PASSWORD_FILE`, `MONITOR_SESSION_SECRET_FILE`, or
`MONITOR_AUTH_STATE_FILE` in a `main`/ `dev` deployment. SSO mode does not
read credential contents and does not instantiate the local password store.
`GET /monitor/api/operations/auth-inventory` is developer-gated and reports
only aggregate file/cookie counts. If an old local state file remains, stop the
container and run the explicit owner-only `retire` procedure described below;
do not expose hash contents or remove a running local-mode store.

### 3. Build and start the rootless container

The host-specific production definition is
`/etc/portfolio-deploy/monitor.compose.yml`. It binds the application to
`127.0.0.1:5181`, mounts `/var/lib/monitor-export` read-only, mounts only the
edge secret at `/run/secrets/monitor_edge_secret`, and requires an explicit
image tag. There must be no writable auth-state mount or local password/session
secret in this definition.

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
API are built for that base path. The production server block uses this shape:

```nginx
location = /monitor {
    return 308 /monitor/;
}

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

After updating `/etc/nginx/sites-available/bonifacio.work`:

```sh
sudo nginx -t
sudo systemctl reload nginx
curl --fail --silent --show-error https://bonifacio.work/monitor/ >/dev/null
```

Only the Nginx/TLS endpoint should be exposed publicly. Port `5181` remains
loopback-only.

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
logged. A dedicated timer checks the supplied logrotate rule every minute;
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

The collector reduces those observations to per-app request and response-time
summaries for one capture interval and attaches them only to bounded peak
incidents. Dashboard request counts therefore show requests in that capture,
not people or unique visitors.

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

The repository Compose launcher automatically selects `docker-compose.sso.yml` or
`docker-compose.local.yml` from the canonical mode. Common options are
`MONITOR_IMAGE`, `MONITOR_PORT`, and `MONITOR_EXPORT_DIR`. SSO mode additionally
accepts `MONITOR_EDGE_SECRET_PATH`; local mode accepts
`MONITOR_AUTH_STATE_PATH`, `MONITOR_PASSWORD_PATH`, and
`MONITOR_SESSION_SECRET_PATH`.

Collector variables and defaults are:

| Variable | Default |
| --- | --- |
| `MONITOR_OUTPUT_DIR` | `/var/lib/monitor-export` |
| `MONITOR_RUNTIME_DIR` | `/run/monitor-collector` |
| `MONITOR_PROC_ROOT`, `MONITOR_SYS_ROOT`, `MONITOR_ETC_ROOT` | `/proc`, `/sys`, `/etc` |
| `MONITOR_EVENTS_LOG` | `/var/log/server-watch/events.log` |
| `MONITOR_KERNEL_LOG` | `/var/log/kern.log` |
| `MONITOR_PRIVILEGE_LOGS` | `/var/log/privilege-events.log` |
| `MONITOR_TRAFFIC_LOG` | `/var/log/nginx/monitor-traffic.jsonl` |
| `MONITOR_CONTAINER_INPUT` | `/run/monitor-container-exporter/containers.json` in production |
| `MONITOR_DOCKER_SOCKETS` | empty in production; direct socket mode is fixture/development-only and rejects non-`cks` owners |
| `MONITOR_PROCESS_UIDS` | `0,1001` (root and `cks`; other UIDs are rejected) |
| `MONITOR_CURL` | `/usr/bin/curl` |
| `MONITOR_VCGENCMD` | `/usr/bin/vcgencmd` |
| `MONITOR_COMMAND_TIMEOUT` | `2` seconds per command |
| `MONITOR_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_LOG_RECORDS` | `5000` per event export |
| `MONITOR_INCIDENT_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_INCIDENT_RECORDS` | `1000` |
| `MONITOR_INCIDENT_FOLLOW_UP_SAMPLES` | `5` |
| `MONITOR_CPU_WARN_PERCENT`, `MONITOR_CPU_RECOVER_PERCENT` | `85`, `75` |
| `MONITOR_CPU_WARN_SAMPLES` | `1` one-minute sample |
| `MONITOR_MEMORY_AVAILABLE_WARN_PERCENT`, `MONITOR_MEMORY_AVAILABLE_RECOVER_PERCENT` | `20`, `25` |
| `MONITOR_TEMPERATURE_WARN_C`, `MONITOR_TEMPERATURE_RECOVER_C` | `75`, `72` |
| `MONITOR_LOAD_WARN`, `MONITOR_LOAD_RECOVER` | `4`, `2` |
| `MONITOR_DISK_IO_WARN_BYTES_PER_SECOND`, `MONITOR_DISK_IO_RECOVER_BYTES_PER_SECOND` | `104857600`, `52428800` |
| `MONITOR_TRAFFIC_REQUEST_WARN`, `MONITOR_TRAFFIC_REQUEST_RECOVER` | `300`, `200` per collector interval |
| `MONITOR_TRAFFIC_SLOW_SECONDS` | `1` |
| `MONITOR_MAX_INPUT_BYTES` | `1048576` per input read |
| `MONITOR_KERNEL_MAX_INPUT_BYTES` | `8388608` per kernel-log read |

`MONITOR_MOUNTINFO` and `MONITOR_MOUNT_ROOT` are normally unset and exist for
fixture roots. The installed source of truth is
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

- `current.json` contains `generatedAt`, `host`, `latest`, `disks`, and
  `containers`.
- `history/YYYY-MM-DD.jsonl` contains one reduced telemetry sample per line.
  Each day is capped at 2,000 rows and the default calendar retention is 30
  days.
- `alerts.jsonl`, `power.jsonl`, and `privilege.jsonl` are each capped at 5,000
  records. Every `power.jsonl` record has exactly `timestamp`, `severity`,
  `kind`, `status`, and a fixed semantic `message`; it never contains the raw
  kernel line.
- `incidents.jsonl` is capped at 1,000 records, 16 MiB, and 30 days. A record is
  written only on incident entry, during at most five one-minute follow-ups,
  when another threshold joins the same window, and on recovery.
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

`host` contains hostname, OS, architecture, and uptime. A `latest`/history
sample contains a timestamp plus CPU and memory percentages and byte totals,
temperature, 1/5/15-minute load, power state, the sampled `supplyVoltageVolts`,
numeric uint32 `throttledFlags`, GPU memory/clock, network RX/TX rates, and disk
read/write rates. Missing or invalid sensors are represented as `null`.

Once per collector run, `vcgencmd pmic_read_adc EXT5V_V` supplies the single
external 5 V rail sample and `vcgencmd get_throttled` supplies the numeric
current/latched flags. EXT5V is a point-in-time rail voltage—not input current
in amperes, consumed or available watts, wall-outlet power, or the USB-C
negotiated power profile. Monitor does not invent a voltage threshold from this
sample. Kernel under-voltage/recovery reports and `vcgencmd` throttle flags are
the authoritative condition signals; a missing voltage is unknown, not zero.

The collector reads only its configured bounded portion of `/var/log/kern.log`
and recognizes a narrow semantic allow-list: the exact Raspberry Pi
`Undervoltage detected!` and `Voltage normalised` events, an NVMe controller
down/reset pattern, and NVMe I/O-error patterns. It maps those to fixed
under-voltage, recovery, NVMe-reset, or NVMe-I/O messages, deduplicates repeated
same-second event kinds and statuses, and exports no device-specific raw text.
A missing kernel log is non-fatal and simply yields no new kernel power events.

Each disk is reduced to mount, total/used bytes, and used percentage. Docker
list requests are restricted to explicitly reviewed Compose projects, and
only exact reviewed project/service pairs become fixed, distinct workload
labels. Previous app-level labels and the generic `cks-workload` value remain
readable in retained history but are never emitted for a new observation. Each admitted workload is
reduced to that label, owner, state, health, CPU percentage, and memory
bytes/percentage. Incident process evidence is grouped into fixed executable
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
events, and privilege events. Chart downsampling preferentially retains the first/last
sample, voltage extrema, and power-state/flag transitions. `powerSummary` is
calculated from every valid sample in the selected range before downsampling
and contains `sampleCount`, `voltageSampleCount`, minimum/average/maximum EXT5V,
and active under-voltage/throttle sample counts. `powerEvents` contains exactly
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
GET    /monitor/api/operations/auth-inventory  # developer/admin, aggregate only
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
- Hashed process identifiers exist only in the mode-`0600` runtime delta file
  and are never exported. Incident evidence contains fixed executable classes
  only. The bounded Nginx input has no client or request identifier;
  its rotation and independent 48-hour retention checks run every minute, and
  both collector and API independently enforce the fixed app allowlist. A
  root-only, fsync-backed pending-reopen marker prevents a failed Nginx reopen
  from being forgotten merely because logrotate already advanced its state.
- The production rootless container has a read-only filesystem and telemetry
  mount, no writable user/auth store, no Linux capabilities,
  `no-new-privileges`, a small tmpfs, and CPU, memory, PID, and log-size limits.
  Only the local Compose overlay adds a disposable writable auth-state mount.
- Local-mode sessions are HMAC-signed, one-hour by default, and stored in `HttpOnly`,
  `Secure`, `SameSite=Strict` cookies scoped to `/monitor`. Login permits five
  failed attempts per 15 minutes; state-changing API requests enforce origin
  checks.
- Production SSO requests reach the app only through Nginx on the same host.
  Nginx removes client-supplied identity headers, obtains them from Authelia,
  overwrites `Remote-User`/`Remote-Email`/`Remote-Groups`, and overwrites a
  dedicated secret header which the application compares in constant time;
  port `5181` remains loopback-only. Identity headers without the matching
  secret and canonical hierarchy-closed groups fail closed.
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
container.

## GitHub Actions deployment

`.github/workflows/deploy.yml` runs on `main` and `dev` pushes and by manual
dispatch. It builds and tests both SSO branches, but only `main` publishes
`:latest` and requests a deployment. It:

1. runs the Python collector tests;
2. builds and tests the ARM64 image;
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
sudo /usr/bin/vcgencmd get_throttled
sudo systemctl start monitor-collector.service
sudo -u cks tail -n 20 /var/lib/monitor-export/power.jsonl
sudo -u cks env XDG_RUNTIME_DIR=/run/user/1001 DOCKER_HOST=unix:///run/user/1001/docker.sock docker logs --tail 100 monitor
sudo nginx -t
```

`pmic_read_adc EXT5V_V` confirms whether this board exposes the sampled rail;
`get_throttled` reports current low bits and latched historical high bits. An
unsupported command or missing reading should appear as `null`, not as a
fabricated zero. Inspect the sanitized `power.jsonl` export rather than copying
raw kernel-log lines into tickets or chat. If the file is absent, run the
collector once and check its journal; absence remains normal on hosts without a
matching kernel event.

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
`/etc/default/monitor-collector`. It also leaves the edge credential, production Compose file, deployment
dispatcher entry, Nginx route, and container images in place. Local disposable
auth state beneath the worktree is separate and can be removed when no longer
needed.
