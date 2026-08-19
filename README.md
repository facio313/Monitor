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
```

The privilege boundary is intentional: only the short-lived collector can
read protected host inputs. The web container receives neither Docker sockets
nor raw logs; it can read only the collector's reduced export.

The dashboard provides:

- CPU, memory, temperature, load, network, and disk-I/O summaries and charts;
- `1h`, `24h`, `7d`, and `30d` ranges, with at most 360 chart points;
- host, power/GPU, filesystem, and per-owner container status;
- recent semantic alerts and privilege outcomes without commands or arguments;
- stale-data and refresh-error indicators, one-minute visible-tab refreshes,
  and a responsive table/card layout.

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

### 2. Create credentials once

Do not rerun this block over credentials already in use.

```sh
sudo install -d -o cks -g cks -m 0700 /home/cks/.config/monitor
sudo -u cks sh -c 'umask 077; openssl rand -hex 24 > /home/cks/.config/monitor/password'
sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/session-secret'
sudo chmod 0600 /home/cks/.config/monitor/password /home/cks/.config/monitor/session-secret
```

The production Compose definition reads these files through Docker secrets;
secret values are not placed in the image, Compose file, process arguments, or
environment.

### 3. Bootstrap the rootless container

The host-specific production definition is
`/etc/portfolio-deploy/monitor.compose.yml`. It binds the application to
`127.0.0.1:5181`, mounts `/var/lib/monitor-export` read-only, and requires an
explicit image tag.

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
```

The Docker build runs the API test suite before producing the image.

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
| `MONITOR_PASSWORD_FILE` | unset | Preferred password file |
| `MONITOR_SESSION_SECRET_FILE` | unset | Preferred HMAC secret file; at least 32 bytes |
| `MONITOR_PASSWORD` | unset | Development-only fallback when no file is set |
| `MONITOR_SESSION_SECRET` | unset | Development-only fallback when no file is set |
| `MONITOR_ALLOWED_ORIGINS` | empty | Comma-separated permitted mutation origins |
| `MONITOR_SESSION_TTL_SECONDS` | `3600` | Signed-session lifetime; capped at 24 hours |
| `MONITOR_STALE_AFTER_SECONDS` | `300` | Age at which telemetry is marked stale |

The repository Compose file additionally accepts `MONITOR_IMAGE`,
`MONITOR_PORT`, `MONITOR_EXPORT_DIR`, `MONITOR_PASSWORD_PATH`, and
`MONITOR_SESSION_SECRET_PATH`.

Collector variables and defaults are:

| Variable | Default |
| --- | --- |
| `MONITOR_OUTPUT_DIR` | `/var/lib/monitor-export` |
| `MONITOR_RUNTIME_DIR` | `/run/monitor-collector` |
| `MONITOR_PROC_ROOT`, `MONITOR_SYS_ROOT`, `MONITOR_ETC_ROOT` | `/proc`, `/sys`, `/etc` |
| `MONITOR_EVENTS_LOG` | `/var/log/server-watch/events.log` |
| `MONITOR_PRIVILEGE_LOGS` | `/var/log/privilege-events.log` |
| `MONITOR_DOCKER_SOCKETS` | `cks=/run/user/1001/docker.sock,psy=/run/user/1002/docker.sock,wgang=/run/user/1003/docker.sock` |
| `MONITOR_CURL` | `/usr/bin/curl` |
| `MONITOR_VCGENCMD` | `/usr/bin/vcgencmd` |
| `MONITOR_COMMAND_TIMEOUT` | `2` seconds per command |
| `MONITOR_RETENTION_DAYS` | `30` |
| `MONITOR_MAX_LOG_RECORDS` | `5000` per event export |
| `MONITOR_MAX_INPUT_BYTES` | `1048576` per input read |

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
- `alerts.jsonl` and `privilege.jsonl` are each capped at 5,000 records.
- `.state/log-cursors.json` prevents replay after service restarts. Short-lived
  rate counters live in `/run/monitor-collector/delta-state.json`.

`host` contains hostname, OS, architecture, and uptime. A `latest`/history
sample contains a timestamp plus CPU and memory percentages and byte totals,
temperature, 1/5/15-minute load, power state, GPU memory/clock, network RX/TX
rates, and disk read/write rates. Missing sensors are represented as `null`.

Each disk is reduced to mount, total/used bytes, and used percentage. Each
container is reduced to name, owner, state, health, CPU percentage, and memory
bytes/percentage. Alerts contain only timestamp, severity, kind, status, and a
bounded semantic message. Privilege records contain only timestamp, actor,
target, action, and result—never a command, arguments, environment, container
ID, image, mount, or raw log line.

The API validates and bounds the files again, rejects malformed/future data,
returns at most 100 alerts and 100 privilege events, and marks a response stale
when no recent sample exists. Supported requests are:

```text
GET    /healthz
GET    /readyz
POST   /monitor/api/auth/login
GET    /monitor/api/auth/session
DELETE /monitor/api/auth/session
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
  log-size limits.
- Sessions are HMAC-signed, one-hour by default, and stored in `HttpOnly`,
  `Secure`, `SameSite=Strict` cookies scoped to `/monitor`. Login permits five
  failed attempts per 15 minutes; state-changing API requests enforce origin
  checks.
- API responses are `no-store`; Helmet supplies a restrictive CSP and related
  headers. The data reader refuses symlink escapes, oversized files/lines, and
  non-allow-listed fields, and applies a second redaction pass to messages.

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

## Password retrieval and rotation

The application never prints credentials. When the generated dashboard
password is needed, display it only in a trusted local terminal (the command
itself contains no secret):

```sh
sudo -u cks cat /home/cks/.config/monitor/password
```

Generate replacements into owner-only temporary files and atomically rename
them so values never appear in shell history or process arguments:

```sh
sudo -u cks sh -c 'umask 077; openssl rand -hex 24 > /home/cks/.config/monitor/password.next && mv /home/cks/.config/monitor/password.next /home/cks/.config/monitor/password'
```

After replacing a secret, force-recreate the container so Docker remounts the
file while retaining the currently deployed image:

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
unset monitor_current_image
```

Changing only the password does not revoke already issued sessions. If a
credential may have leaked, rotate the session HMAC secret too, then run the
same force-recreate command:

```sh
sudo -u cks sh -c 'umask 077; openssl rand -hex 32 > /home/cks/.config/monitor/session-secret.next && mv /home/cks/.config/monitor/session-secret.next /home/cks/.config/monitor/session-secret'
```

Session-secret rotation signs everyone out immediately.

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
sudo -u cks env XDG_RUNTIME_DIR=/run/user/1001 DOCKER_HOST=unix:///run/user/1001/docker.sock docker logs --tail 100 monitor
sudo nginx -t
```

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
`/etc/default/monitor-collector`. It also leaves credentials, the production
Compose file, deployment dispatcher entry, Nginx route, and container images
in place. Remove those explicit paths only after deciding their data and
rollback value are no longer needed.
