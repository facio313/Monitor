# Monitor host collector

`collector.py` is a Python 3 standard-library-only, one-shot exporter intended
to run as root once per minute. It reads aggregate host telemetry, explicitly
named rootless Docker sockets, and selected logs. It never changes Docker or
host configuration.

## Outputs

The default output root is `/var/lib/monitor-export`:

- `current.json`: atomically replaced snapshot with exactly the public keys
  `generatedAt`, `host`, `latest`, `disks`, and `containers`.
  `latest` includes memory byte totals, all three load averages, current power
  state, supply voltage, the complete `get_throttled` flags integer, and GPU
  allocation/clock fields in addition to the rate metrics. The nullable fields
  `supplyVoltageVolts` and `throttledFlags` immediately follow `powerState` in
  both current and history samples.
  Each disk is exactly `mount`, `totalBytes`, `usedBytes`, and `usedPercent`.
- `history/YYYY-MM-DD.jsonl`: atomically replaced daily sample series. At most
  2,000 valid rows are kept per day, and files older than 30 calendar days are
  pruned. On rewrite, valid rows from the immediately preceding sample contract
  are migrated by adding the two new nullable power fields; foreign fields,
  invalid timestamps, booleans in numeric fields, and non-finite numbers are
  not propagated.
- `alerts.jsonl`: at most 5,000 semantic `SNAPSHOT`, `metrics`, or `RECOVERED`
  events. Raw lines are never copied. On Raspberry Pi-class hosts with
  `vcgencmd`, current throttle/power transitions are also emitted here. A
  transition message includes the validated full flags and, when available,
  the validated supply-voltage observation; voltage changes alone never create
  an alert.
- `power.jsonl`: at most 5,000 fixed-message kernel power/storage events with
  exactly `timestamp`, `severity`, `kind`, `status`, and `message`. Only kernel
  `Undervoltage detected!`, `Voltage normalised`, NVMe controller-reset, and
  NVMe I/O-error patterns are accepted. Raw kernel lines and their variable
  details are never exported. Repeated events of the same kind and status in
  one second are collapsed, while an active/recovered pair remains distinct.
- `privilege.jsonl`: at most 5,000 records containing **only** `timestamp`,
  `actor`, `target`, `action`, and `result`. In particular, command text and
  arguments are never exported. The default source is the already-focused
  `/var/log/privilege-events.log`; `auth.log`/`secure` can be configured as
  fallbacks but are not enabled together by default, avoiding duplicates.

Durable server-watch, kernel, and privilege-log cursors live under the hidden
output `.state` directory so service restarts and reboots do not duplicate
events. A replaced or truncated kernel log is detected by inode/offset and its
bounded tail is read again; semantic same-second deduplication prevents a
rotated overlap from duplicating exported events. Short-lived host and
per-container CPU/network/disk delta counters live in
`/run/monitor-collector/delta-state.json`; each run atomically replaces that
mode-`0600` file rather than appending it. Container CPU state is keyed by
owner and container ID internally, pruned to containers still listed, and
hard-capped at 600 entries. IDs never enter a public export.

When `vcgencmd` exists, the collector reads throttle/power flags, GPU
temperature, allocated memory, core clock, core voltage, and on Raspberry Pi 5
the external supply rail using `/usr/bin/vcgencmd pmic_read_adc EXT5V_V`, all
with the same strict command timeout and a 256-byte output limit per command.
Only a finite `EXT5V_V` value in the protocol sanity range 0–10 V is accepted;
it is rounded to three decimal places. That broad input bound is not a health
threshold. A malformed response, unsupported command, timeout, or non-zero
exit produces `null`, never zero fabricated from failure.

GPU temperature is used as the host temperature fallback; memory, clock,
supply voltage, and full unsigned 32-bit throttle flags populate the public
snapshot; and current throttle transitions become semantic alerts. Active
low-bit conditions take precedence. When those bits are clear but historical
high bits remain set (for example `0x50000`), the snapshot reports
`powerState: "degraded-history"`; it reports `normal` only when neither current
nor historical flags are present. No voltage threshold is used to classify
power state or emit alerts: kernel events and `vcgencmd get_throttled` remain
authoritative. The dedicated kernel cursor also captures brief under-voltage
events that begin and recover between one-minute `vcgencmd` samples.

`MONITOR_KERNEL_LOG` defaults to `/var/log/kern.log`. On the first run and after
rotation, the collector examines only the newest 8 MiB
(`MONITOR_KERNEL_MAX_INPUT_BYTES=8388608`) so recent incidents are retained
without loading an unbounded historical log. The command-line/environment
value is clamped to at most 16 MiB. The ordinary event/privilege input bound
remains separately controlled by `MONITOR_MAX_INPUT_BYTES`.

The Docker response is reduced immediately to `name`, `owner`, `state`,
`health`, `cpuPercent`, `memoryBytes`, and `memoryPercent`. Environment,
mounts, images, commands, IDs, and socket paths are not written or logged.

## Install

From this directory:

```sh
sudo sh ./install.sh
systemctl status monitor-collector.timer monitor-collector.service
sudo journalctl -u monitor-collector.service -n 50 --no-pager
```

The expected rootless Docker sockets are:

- `cks` (UID 1001): `/run/user/1001/docker.sock`
- `psy` (UID 1002): `/run/user/1002/docker.sock`
- `wgang` (UID 1003): `/run/user/1003/docker.sock`

Root must be able to traverse `/run/user/{1001,1002,1003}` and read/write the
Unix sockets. The supplied service retains only `CAP_DAC_OVERRIDE` and
`CAP_DAC_READ_SEARCH` for root to read protected logs and connect to those
sockets. It grants writes only to `/var/lib/monitor-export` and
`/run/monitor-collector`. The unit runs with group `cks`; output directories are
`root:cks` mode `0750` and public files are mode `0640`, allowing the rootless
`cks` Monitor container to read an explicitly bind-mounted export directory.
The otherwise-private device namespace exposes only `/dev/vcio` with the
device-cgroup permission needed by `vcgencmd`; `/var/log` is available read-only
for the configured semantic inputs. If an LSM (SELinux/AppArmor) independently
denies socket access, add a narrow local policy for these three paths; do not
expose the sockets over TCP and do not make them world-readable.

The one-shot cgroup uses `MemoryHigh=160M`, `MemoryMax=192M`, and
`TasksMax=64`. These limits leave substantial room for the bounded 8 MiB kernel
tail, parsed telemetry, six concurrent Docker-stat requests, and their `curl`
children on the 8 GiB host, while containing an unexpectedly large captured
Docker response instead of exposing the whole host to its memory/task growth.

`/etc/default/monitor-collector` is installed only when it does not already
exist. Edit it to select different input/output paths, then run:

```sh
sudo systemctl restart monitor-collector.service
```

No logrotate rule is needed: the collector atomically enforces row bounds on
its three event exports and calendar retention on history. Journald owns service
logs.

## Password-hash state operations

`monitor_auth_state.py` manages the web application's separate persistent auth
state; it does not run as part of the root collector. The application needs a
writable directory bind because a single-file bind cannot be replaced with the
same-directory atomic rename used for password changes. On the Bonifacio host,
create the exact host directory as root (the existing `.local/state` parent may
be root-owned), then validate it as the rootless deployment user:

```sh
cd /home/cks/Monitor
sudo install -d -o cks -g cks -m 0700 /home/cks/.local/state/monitor-auth
sudo -u cks python3 ops/monitor_auth_state.py prepare
sudo -u cks python3 ops/monitor_auth_state.py status
```

Defaults are `/home/cks/.local/state/monitor-auth` for live state and
`/home/cks/backups/monitor-auth` for local snapshots. Override them with
`MONITOR_AUTH_STATE_PATH` and `MONITOR_AUTH_BACKUP_PATH`. Directories must be
owned by the invoking user with mode `0700`; state and snapshot files must be
single-link regular files with mode `0600`. Symlinked paths are refused.

The application, not this helper, initializes missing `password.json` from the
bootstrap password and atomically updates it after a password change. The
helper's `backup` and offline `restore --confirm-container-stopped` commands
validate the same version-1 scrypt state shape, copy without displaying hash
material, fsync temporary files, and atomically rename them. Restore first
creates a `pre-restore` snapshot of valid current state, restores the selected
password hash, and generates a fresh session epoch so old cookies cannot become
valid again. See the repository README for stop/start ordering, session-secret
rotation, legacy rollback limits, and off-host disaster recovery.

Docker list and per-container stats calls use a 2-second curl timeout. All
owner list endpoints are read first, then stats use the fast
`stream=false&one-shot=true` endpoint with at most six bounded worker threads,
a 20-second global deadline, and a 30-container cap. Because one-shot Docker
stats contain no usable `precpu_stats`, CPU percent is calculated from the
protected previous-run counters described above; the first observation is
`null`. Memory is available immediately from the one-shot response. If the
deadline is reached, every listed container remains present but unavailable
stats fields are `null`, never misleading zeroes. The service still has a
45-second outer timeout.

## Fixture run and tests

All input roots and logs are configurable by flags or the matching environment
variables shown in `monitor-collector.default`. Docker collection can be
disabled for an unprivileged fixture run with `--docker-sockets ''`.

```sh
python3 collector.py \
  --proc-root /tmp/fixture/proc \
  --sys-root /tmp/fixture/sys \
  --etc-root /tmp/fixture/etc \
  --mountinfo /tmp/fixture/mountinfo \
  --mount-root /tmp/fixture/root \
  --events-log /tmp/fixture/events.log \
  --kernel-log /tmp/fixture/kern.log \
  --privilege-logs /tmp/fixture/auth.log \
  --docker-sockets '' \
  --output-dir /tmp/monitor-export \
  --runtime-dir /tmp/monitor-run

python3 -m unittest discover -s tests -v
```

## Uninstall

```sh
sudo sh ./uninstall.sh
```

Uninstall deliberately preserves `/var/lib/monitor-export`,
`/etc/default/monitor-collector`, `/home/cks/.local/state/monitor-auth`, and
`/home/cks/backups/monitor-auth`. Remove those separately only after deciding
the retained telemetry, authentication recovery, and configuration value is no
longer needed.
