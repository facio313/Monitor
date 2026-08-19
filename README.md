# Monitor

Monitor is the private host-status dashboard served at
`https://bonifacio.work/monitor/`. It combines one-minute host telemetry,
rootless Docker status, storage information, sanitized alerts, and sanitized
privilege activity in a responsive React dashboard protected by a shared
password.

## Architecture

```text
host proc/sys + selected logs + named rootless Docker sockets
                              |
                    systemd timer (root)
                              |
                 sanitizing Python collector
                              |
            /var/lib/monitor-export (bounded JSON/JSONL)
                              | read-only bind mount
                              v
browser -> TLS/Nginx /monitor/ -> rootless Docker -> Express API + React UI
                                                        |
                                      dedicated writable hash-state bind
                                                        |
                              /home/cks/.local/state/monitor-auth (0700)
```

The privilege boundary is intentional: only the short-lived collector can
read protected host inputs. The web container receives neither Docker sockets
nor raw logs; it can read only the collector's reduced export. Its only durable
writable mount is a separate owner-only directory containing the password hash
and session epoch; telemetry and the session-signing secret remain separate.

The dashboard provides:

- CPU, memory, temperature, load, network, and disk-I/O summaries and charts;
- `1h`, `24h`, `7d`, and `30d` ranges, with at most 360 chart points;
- host, EXT5V supply/power/GPU, filesystem, and per-owner container status;
- recent semantic alerts and privilege outcomes without commands or arguments;
- stale-data and refresh-error indicators, one-minute visible-tab refreshes,
  and a responsive table/card layout.

The overview keeps operational scanning compact: it shows the latest EXT5V and
throttle state plus at most the newest 10 alerts and 10 privilege records from
the selected range. `/monitor/details` uses the same authenticated API snapshot
to show the full API-bounded event lists (up to 500 each), the EXT5V history and
power/storage event timeline, full-range power statistics, and expanded CPU,
memory, temperature/load, network, and disk-I/O charts.

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
sudo systemctl status monitor-collector.timer monitor-collector.service
sudo journalctl -u monitor-collector.service -n 50 --no-pager
sudo python3 -m json.tool /var/lib/monitor-export/current.json >/dev/null
```

The timer runs the one-shot collector approximately once per minute. Local
overrides belong in `/etc/default/monitor-collector`; the installer preserves
an existing file.

### 2. Create credentials and the auth-state directory once

Do not rerun this block over credentials already in use.

```sh
sudo install -d -o cks -g cks -m 0700 /home/cks/.config/monitor
sudo -u cks sh -c 'umask 077; openssl rand -hex 24 > /home/cks/.config/monitor/password'
sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/session-secret'
sudo chmod 0600 /home/cks/.config/monitor/password /home/cks/.config/monitor/session-secret
sudo install -d -o cks -g cks -m 0700 /home/cks/.local/state/monitor-auth
sudo -u cks python3 ops/monitor_auth_state.py prepare
sudo -u cks python3 ops/monitor_auth_state.py status
```

During first migration, the production Compose definition reads the plaintext
bootstrap and signing files through Docker secrets; secret values are not
placed in the image, Compose file, process arguments, or environment. The
helper creates
`/home/cks/.local/state/monitor-auth` as `cks` mode `0700` but deliberately does
not create `password.json`. On the first application start, the application
derives a scrypt password hash from the bootstrap password and atomically
creates the mode-`0600` state file with a new session epoch. An existing valid
state file always wins and is never replaced from the bootstrap secret.

### 3. Bootstrap the rootless container

The host-specific production definition is
`/etc/portfolio-deploy/monitor.compose.yml`. It binds the application to
`127.0.0.1:5181`, mounts `/var/lib/monitor-export` read-only, and requires an
explicit image tag. Before deploying a password-state-aware image, its Monitor
service must also contain the following dedicated writable bind. Do not reuse
the telemetry directory or either secret path:

```yaml
environment:
  MONITOR_AUTH_STATE_FILE: /var/lib/monitor-auth/password.json
volumes:
  - type: bind
    source: /home/cks/.local/state/monitor-auth
    target: /var/lib/monitor-auth
    read_only: false
    bind:
      create_host_path: false
```

The repository Compose definition already contains the equivalent parameterized
mount. The host-specific `/etc` definition must be updated separately by an
operator; this repository does not modify live host configuration.

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker build --tag portfolio-local/monitor:bootstrap /home/cks/Monitor

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE=portfolio-local/monitor:bootstrap \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml \
    up --detach --no-deps --pull never monitor

curl --fail --silent --show-error http://127.0.0.1:5181/readyz
sudo -u cks python3 /home/cks/Monitor/ops/monitor_auth_state.py status
sudo -u cks python3 /home/cks/Monitor/ops/monitor_auth_state.py backup
```

The Docker build runs the API test suite before producing the image. The final
two commands verify first-time atomic initialization and create the first local
owner-only auth-state snapshot.

After that snapshot succeeds, complete the second migration stage: remove
`MONITOR_PASSWORD_FILE` and the `monitor_password` service secret from
`/etc/portfolio-deploy/monitor.compose.yml` (and remove its top-level secret
definition if nothing else uses it). Keep the host bootstrap file mode `0600`
for offline recovery, but do not leave it mounted in the running container.
Retain `MONITOR_SESSION_SECRET_FILE` and `monitor_session_secret`.

Force-recreate the same deployed image so Docker applies the reduced secret
set, verify readiness, then make this password-state-aware image the immediate
local rollback baseline:

```sh
monitor_current_image=$(sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker container inspect --format '{{.Config.Image}}' monitor)

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE="$monitor_current_image" \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml \
    up --detach --force-recreate --no-deps --pull never monitor

curl --fail --silent --show-error http://127.0.0.1:5181/readyz

monitor_feature_image_id=$(sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker container inspect --format '{{.Image}}' monitor)
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker image tag "$monitor_feature_image_id" portfolio-local/monitor:rollback
unset monitor_current_image monitor_feature_image_id
```

State-aware startup reads the bootstrap secret lazily only when
`password.json` is absent. Consequently, normal post-migration restarts need no
bootstrap mount, while deletion/corruption without an explicit recovery setup
fails closed. A pre-feature image also fails closed after this second stage
because its required password configuration is absent. The repository's generic
Compose file intentionally keeps the password secret for fresh development and
first-run bootstrap; do not copy that service secret back into an already
migrated production definition except during deliberate offline recovery.

### 4. Publish `/monitor/` through Nginx

The location must preserve the `/monitor` prefix because both the frontend and
API are built for that base path. The production server block uses this shape:

```nginx
location = /monitor {
    return 308 /monitor/;
}

location ^~ /monitor/ {
    proxy_pass         http://127.0.0.1:5181;
    proxy_http_version 1.1;
    proxy_set_header   Host                $host;
    proxy_set_header   X-Real-IP           $remote_addr;
    proxy_set_header   X-Forwarded-For     $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto   $http_x_forwarded_proto;
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

## Local development

Create disposable local data and secrets without copying production values:

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
docker build --tag monitor:local .
```

To exercise the repository Compose definition with the disposable files:

```sh
MONITOR_IMAGE=monitor:local \
MONITOR_EXPORT_DIR="$PWD/data" \
MONITOR_AUTH_STATE_PATH="$PWD/auth-state" \
MONITOR_PASSWORD_PATH="$PWD/secrets/password" \
MONITOR_SESSION_SECRET_PATH="$PWD/secrets/session-secret" \
MONITOR_ALLOWED_ORIGINS=http://localhost:5181 \
docker compose up --detach --build
```

## Configuration

Application variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Express listen address |
| `PORT` | `8080` | Express listen port |
| `MONITOR_DATA_DIR` | `/data` | Sanitized collector export root |
| `MONITOR_AUTH_STATE_FILE` | `/var/lib/monitor-auth/password.json` | Writable, persistent password-hash/session-epoch state file |
| `MONITOR_PASSWORD_FILE` | unset | Preferred bootstrap password file; used only when auth state is absent |
| `MONITOR_SESSION_SECRET_FILE` | unset | Preferred HMAC secret file; at least 32 bytes |
| `MONITOR_PASSWORD` | unset | Development-only bootstrap fallback when no password file is set |
| `MONITOR_SESSION_SECRET` | unset | Development-only fallback when no file is set |
| `MONITOR_ALLOWED_ORIGINS` | empty | Comma-separated permitted mutation origins |
| `MONITOR_SESSION_TTL_SECONDS` | `3600` | Signed-session lifetime; capped at 24 hours |
| `MONITOR_STALE_AFTER_SECONDS` | `300` | Age at which telemetry is marked stale |

The repository Compose file additionally accepts `MONITOR_IMAGE`,
`MONITOR_PORT`, `MONITOR_EXPORT_DIR`, `MONITOR_AUTH_STATE_PATH`,
`MONITOR_PASSWORD_PATH`, and `MONITOR_SESSION_SECRET_PATH`.

Collector variables and defaults are:

| Variable | Default |
| --- | --- |
| `MONITOR_OUTPUT_DIR` | `/var/lib/monitor-export` |
| `MONITOR_RUNTIME_DIR` | `/run/monitor-collector` |
| `MONITOR_PROC_ROOT`, `MONITOR_SYS_ROOT`, `MONITOR_ETC_ROOT` | `/proc`, `/sys`, `/etc` |
| `MONITOR_EVENTS_LOG` | `/var/log/server-watch/events.log` |
| `MONITOR_KERNEL_LOG` | `/var/log/kern.log` |
| `MONITOR_PRIVILEGE_LOGS` | `/var/log/privilege-events.log` |
| `MONITOR_DOCKER_SOCKETS` | `cks=/run/user/1001/docker.sock,psy=/run/user/1002/docker.sock,wgang=/run/user/1003/docker.sock` |
| `MONITOR_CURL` | `/usr/bin/curl` |
| `MONITOR_VCGENCMD` | `/usr/bin/vcgencmd` |
| `MONITOR_COMMAND_TIMEOUT` | `2` seconds per command |
| `MONITOR_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_LOG_RECORDS` | `5000` per event export |
| `MONITOR_MAX_INPUT_BYTES` | `1048576` per input read |
| `MONITOR_KERNEL_MAX_INPUT_BYTES` | `8388608` per kernel-log read |

`MONITOR_MOUNTINFO` and `MONITOR_MOUNT_ROOT` are normally unset and exist for
fixture roots. The installed source of truth is
`/etc/default/monitor-collector`, seeded from
`ops/monitor-collector.default`. Colon-separate additional privilege log
fallbacks only when necessary; enabling overlapping sources can duplicate
events. Restart the one-shot service after a change:

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
- `.state/log-cursors.json` prevents replay after service restarts. Short-lived
  rate counters live in `/run/monitor-collector/delta-state.json`.

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

Each disk is reduced to mount, total/used bytes, and used percentage. Each
container is reduced to name, owner, state, health, CPU percentage, and memory
bytes/percentage. Alerts contain only timestamp, severity, kind, status, and a
bounded semantic message. Privilege records contain only timestamp, actor,
target, action, and result—never a command, arguments, environment, container
ID, image, mount, or raw log line.

The API validates and bounds the files again, rejects malformed, out-of-range,
or future data, and marks a response stale when no recent sample exists. It
returns at most 360 chart samples and 500 each of alerts, power events, and
privilege events. Chart downsampling preferentially retains the first/last
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
```

## Security boundaries

- The root collector is a hardened, one-shot systemd unit with a restricted
  capability set, read-only host paths, and writes limited to its export and
  runtime directories.
- Only explicitly configured Unix sockets are queried. Docker responses are
  immediately allow-listed; the web container has no socket mount.
- Export files are bounded, atomically replaced, and readable by the `cks`
  deployment boundary without becoming world-readable.
- The rootless container has a read-only filesystem/data mount, no Linux
  capabilities, `no-new-privileges`, a small tmpfs, and CPU, memory, PID, and
  log-size limits. Its sole persistent writable mount is the owner-only auth
  state directory; auth backups are never mounted into the container.
- Sessions are HMAC-signed, one-hour by default, and stored in `HttpOnly`,
  `Secure`, `SameSite=Strict` cookies scoped to `/monitor`. Login permits five
  failed attempts per 15 minutes; state-changing API requests enforce origin
  checks.
- API responses are `no-store`; Helmet supplies a restrictive CSP and related
  headers. The data reader refuses symlink escapes, oversized files/lines, and
  non-allow-listed fields, and applies a second redaction pass to messages.
- Kernel power evidence is reduced to the fixed `power.jsonl` schema before the
  web container can read it. The container never receives `/var/log/kern.log`
  or another raw host log.

This is a shared-password operations view. Keep it behind HTTPS, do not expose
port `5181`, and do not mount additional host paths into the container.

## GitHub Actions deployment

`.github/workflows/deploy.yml` runs on every `main` push and by manual
dispatch. It:

1. runs the Python collector tests;
2. builds and tests the ARM64 image;
3. publishes `ghcr.io/facio313/monitor:<commit-sha>` and `:latest`;
4. connects with the repository `DEPLOY_KEY` secret and requests only
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

## Password state, backup, recovery, and rotation

The writable auth state never contains the active password in plaintext. The
host file at `/home/cks/.config/monitor/password` remains a plaintext
bootstrap/recovery credential and initially matches the password used to create
the hash. Replacing it has no effect while a valid `password.json` exists, and
it no longer matches the active password after a dashboard password change.
There is no supported way to retrieve a changed password.

An authenticated operator changes the active password from the dashboard's
**Change password** control. The current password is required, the replacement
must contain at least 16 characters and at most 256 UTF-8 bytes, and a successful
change atomically writes a fresh scrypt hash and session epoch. Every existing
session is invalidated, including the caller's session.

The hash state is still sensitive because it permits offline guessing. Never
print it, attach it to an issue, place it in Git, or copy it into telemetry. The
operations helper reports only path/status metadata and refuses symlinks,
additional hard links, non-regular files, wrong owners, or group/other-readable
state. Run it as `cks`, not root:

```sh
cd /home/cks/Monitor
sudo -u cks python3 ops/monitor_auth_state.py status
sudo -u cks python3 ops/monitor_auth_state.py backup
```

Backups are atomically created under `/home/cks/backups/monitor-auth` with
directory mode `0700` and file mode `0600`. Create the first state snapshot
immediately after successful initialization, then after important password
changes and before auth-related upgrades. Backups are not mounted into the
container. This local snapshot helper is not a substitute for encrypted
off-host disaster-recovery backups; before the first migration, protect the
bootstrap credential and session-signing secret, and afterward protect those
plus the auth state with equivalent access control.

Before using an off-host snapshot, copy it into the backup directory as owner
`cks` with mode `0600`; the helper refuses a differently owned or more broadly
readable restore source.

Restore only while Monitor is stopped, so the in-memory state cannot race with
or mask the restored file. The helper automatically preserves the replaced
state as a new `pre-restore` backup, restores only the selected password hash,
and generates a fresh random session epoch. It never displays either hash, and
cookies issued under the snapshot's old epoch cannot become valid again:

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker stop monitor

sudo -u cks python3 /home/cks/Monitor/ops/monitor_auth_state.py \
  restore --confirm-container-stopped \
  /home/cks/backups/monitor-auth/password-YYYYMMDDTHHMMSSZ-XXXXXXXX.json

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker start monitor
curl --fail --silent --show-error http://127.0.0.1:5181/readyz
```

A restore makes the snapshot's password active. Change it immediately after
login if that password may be known to an attacker. A normal restore otherwise
needs only the stop/restore/start sequence above. If
the independent session-signing secret may also have leaked, rotate its host
file and force-recreate the container. Atomic replacement of a host secret file
does not update the inode already mounted by Docker into an existing container:

```sh
monitor_current_image=$(sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  docker container inspect --format '{{.Config.Image}}' monitor)

sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/session-secret.next && mv /home/cks/.config/monitor/session-secret.next /home/cks/.config/monitor/session-secret'

sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE="$monitor_current_image" \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml \
    up --detach --force-recreate --no-deps --pull never monitor
unset monitor_current_image
```

If no usable hash-state backup exists, the last-resort recovery path is to stop
Monitor, preserve the existing `password.json` outside the mounted state
directory with mode `0600`, and atomically replace the offline bootstrap password
file. Temporarily restore the `MONITOR_PASSWORD_FILE`/`monitor_password` entries
to the production Compose definition and force-recreate the current
password-state-aware image with `password.json` absent. A plain `docker start`
cannot add the removed secret and must not be used. The new container will
initialize a fresh hash and session epoch from the replacement bootstrap value.
After verifying login, create a state snapshot, remove the bootstrap mount
again, and force-recreate once more. Do not delete or move the only state copy
until a protected backup exists.

The external bind survives normal container recreation, deployments, and
rollbacks to any password-state-aware image. During the first-stage deployment,
the old rollback image can still use the mounted bootstrap credential; do not
change the password before initialization, readiness, and backup succeed. Once
the second stage removes that mount, a pre-feature image cannot silently revert
the password and instead fails to start. Keep the offline bootstrap credential
protected, take a pre-deploy state backup whenever state already exists, and
retag the verified password-state-aware image as the rollback baseline using the
procedure above.

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

Remove the container, then the collector:

```sh
sudo -u cks env \
  XDG_RUNTIME_DIR=/run/user/1001 \
  DOCKER_HOST=unix:///run/user/1001/docker.sock \
  MONITOR_IMAGE=unused \
  docker compose --project-name monitor \
    --file /etc/portfolio-deploy/monitor.compose.yml down
sudo sh /home/cks/Monitor/ops/uninstall.sh
```

The uninstall script deliberately preserves `/var/lib/monitor-export` and
`/etc/default/monitor-collector`. It also leaves credentials, auth state and
auth-state backups, the production Compose file, deployment dispatcher entry,
Nginx route, and container images in place. Remove those explicit paths only
after deciding their data and rollback value are no longer needed.
