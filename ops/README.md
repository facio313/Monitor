# Monitor host collector

`collector.py` is a Python 3 standard-library-only, one-shot exporter intended
to run as root once per minute. It reads aggregate host telemetry, a strictly
validated reduced container snapshot, fixed process classes, and selected
logs. Its namespace contains no Docker socket. `container_exporter.py` runs
briefly as `cks`, the same unprivileged account that owns the one rootless
daemon, and reduces only fixed Docker GET responses before the root collector
starts. Neither helper changes Docker or host configuration.

## Outputs

The default output root is `/var/lib/monitor-export`:

- `current.json`: atomically replaced snapshot with exactly the public keys
  `generatedAt`, `host`, `latest`, `disks`, `containers`,
  `containerCollection`, `currentTraffic`, `reliability`, and `system`.
  `containerCollection` distinguishes a fresh Docker observation from a
  bounded last-known snapshot, source unavailability, or permission denial;
  stale workloads are never presented as current evidence.
  `host` includes the online logical-CPU count derived from aggregate
  `/proc/stat`. `latest` includes memory and swap byte totals/usage, swap
  percentage, all three load averages, current CPU/memory/I/O PSI `some` and
  `full` avg10 percentages, current power state, supply voltage, the standard
  Raspberry Pi hwmon under-voltage alarm encoded in bit 0 of
  `throttledFlags`, GPU allocation/clock fields, and aggregate non-loopback
  network byte/error/drop rates in addition to the disk rate metrics. Network
  interface names never enter the export. The nullable fields
  `supplyVoltageVolts` and `throttledFlags` immediately follow `powerState` in
  both current and history samples.
  Each disk is exactly `mount`, `totalBytes`, `usedBytes`, `availableBytes`,
  `usedPercent`, `inodeUsedPercent`, and `readOnly`. Inode usage is aggregate;
  filenames and inode identities are never collected.
  Each current `containers` row is the exact 17-field reduced contract:
  `name`, `project`, `owner`, `state`, `health`,
  `healthcheckConfigured`, `cpuPercent`, `memoryBytes`, `memoryPercent`,
  `memoryLimitBytes`, `cpuLimitCores`, `pidLimit`, `restartCount`,
  `restartCountDelta`, `oomKilled`, `startedAt`, and `finishedAt`.
  Health, restart/OOM state, lifecycle timestamps, and configured limits come
  from an identity-bound Docker inspect response; an unavailable detail stays
  `null` and is never inferred from presentation text. Container IDs remain
  private. Retained seven-field snapshots are promoted with unverified
  lifecycle fields set to `null`, while incident evidence deliberately keeps
  its smaller seven-field projection.
  Each `currentTraffic` entry is exactly `app`, `requestCount`, `status2xx`,
  `status3xx`, `status4xx`, `status5xx`, `slowCount`, `avgResponseMs`, and
  `maxResponseMs`; at most 16 allow-listed app groups are emitted.
  `reliability` contains only the calculated boot time, the prior collector
  heartbeat gap, expected SSH-listener availability, primary physical-link
  availability, and runtime NVMe power-management mitigation state. The boot
  ID used to detect a restart stays in private collector state.
  `system` is a fixed, serial-free snapshot containing running/latest-installed
  kernel versions, bootloader channel/dates, NVMe model/firmware, collector
  version, configured/negotiated PCIe link properties, AER counters/status,
  power-saving settings, and current-boot semantic kernel-event counters with
  their last timestamps.
  The collector deliberately lacks `CAP_SYS_ADMIN`, so Linux normally truncates
  PCI config-space reads before the optional Device Status bits. Those three
  nullable flags remain unknown while capability-free AER counters and semantic
  kernel events remain authoritative; do not broaden collector capabilities.
- `history/YYYY-MM-DD.jsonl`: atomically replaced daily sample series. At most
  2,000 valid rows are kept per day, and files older than 30 calendar days are
  pruned. On rewrite, valid rows from all three retained sample contracts
  (before nullable power fields, after power fields, and after swap/PSI fields)
  are migrated to the current exact schema by adding nullable aggregate network
  error/drop rates. Foreign fields, invalid timestamps, booleans in numeric
  fields, inconsistent swap values, negative rates, out-of-range percentages,
  and non-finite numbers are not propagated.
  The private delta-state migration accepts the prior two-counter network
  baseline: RX/TX byte rates remain available on the first upgraded interval,
  while the four newly introduced error/drop rates remain `null` until the next
  complete six-counter interval.
- `alerts.jsonl`: at most 5,000 semantic `SNAPSHOT`, `metrics`, `RECOVERED`, or
  fixed maintenance events. Raw lines are never copied. On Raspberry Pi-class
  hosts with the `rpi_volt` hwmon sensor, current under-voltage transitions are
  also emitted here. A transition message includes the validated flags and, when
  available, the validated supply-voltage observation; voltage changes alone
  never create an alert.
- `rule-evaluation.json`: the latest exact-schema evaluation of the versioned
  default rule pack. It publishes every rule as `inactive`, `pending`,
  `firing`, `recovering`, `no_data`, `unsupported`, `permission_denied`, or
  `collection_error`; an unimplemented signal can therefore never look
  healthy. The installed pack defines all 82 documented defaults, while only
  signals proven by the current reduced snapshot are evaluated as data.
- `rule-alerts.jsonl`: at most 5,000 opening/resolution transitions from that
  evaluator. Each row has a deterministic SHA-256 idempotency key, rule and
  bounded target IDs, severity, delivery disposition, timestamps, normalized
  value/status, bounded labels, fixed description, and runbook. Raw samples,
  mount paths, commands, and log lines are never copied.
- `power.jsonl`: at most 5,000 fixed-message kernel power/storage events with
  exactly `timestamp`, `severity`, `kind`, `status`, and `message`. Only kernel
  `Undervoltage detected!`, `Voltage normalised`, NVMe controller-reset, and
  NVMe I/O-error patterns are accepted. Raw kernel lines and their variable
  details are never exported. Repeated events of the same kind and status in
  one second produce the same canonical public row and are collapsed, while an
  active/recovered pair remains distinct.
- `reliability.jsonl`: at most 5,000 fixed-message host-availability events
  with exactly `timestamp`, `severity`, `kind`, `status`, `message`, and
  nullable `durationSeconds`. It records boot transitions, collector gaps over
  three minutes, expected SSH listener loss/recovery, primary-link
  loss/recovery, NVMe reset/I/O errors, RCU stalls, OOM kills, filesystem
  errors, PCIe AER/link events, kernel warnings/oops/panics, hung tasks, and
  runtime NVMe mitigation transitions. Kernel lines are mapped to fixed
  messages; IP addresses, ports, PIDs, process names, paths, usernames,
  commands, and raw log text are never exported.
  Expedited RCU short-delay rows remain in this log and are also counted in a
  dedicated current-boot `system.kernel.rcuExpedited` field rather than the
  generic warning or active-stall counters. Kernel reliability timestamps keep
  available microsecond precision, so distinct reports within the same second
  remain distinct while exact replayed rows are still deduplicated.
- `privilege.jsonl`: at most 5,000 records containing **only** `timestamp`,
  `actor`, `target`, `action`, and `result`. In particular, command text and
  arguments are never exported. The default source is the already-focused
  `/var/log/privilege-events.log`; `auth.log`/`secure` can be configured as
  fallbacks but are not enabled together by default, avoiding duplicates.
- `incidents.jsonl`: a bounded, 30-day series written only when a resource,
  power, disk-I/O, load, or request-volume threshold opens an incident, during
  its limited follow-up window, and when it recovers. Each record contains the
  reduced host sample, PSI `avg10`, fixed executable-class aggregates for
  root/`cks` processes, fixed-label `cks` workload fields, and app-level request
  totals. It never contains PID, UID, command line, arguments, environment,
  working directory, open files, client address, user identity, URI/query,
  referrer, user agent, or cookie data.

Durable server-watch, kernel, privilege, and request cursors live under the
hidden output `.state` directory. Before changing alerts, power events,
privilege events, or their cursors, the collector stages only the new reduced
rows, next cursors, limits, and each output's canonical base/final digest in the
bounded mode-`0600` `.state/pending-sanitized-log-commit.json`. Replay compares
those digests after each atomic output rewrite, so a crash cannot append the
same batch twice or commit a cursor before its rows. Two genuinely distinct
source events remain two rows even when every public field is identical; only
the documented same-second fixed kernel power burst collapse is semantic.
Before changing an incident record, lifecycle, or request cursor, the collector
atomically stages only their validated, bounded forms in mode-`0600`
`.state/pending-incident-commit.json`. The next run replays that journal before
reading lifecycle or request-cursor state; incident rows upsert by incident ID,
observation time, and phase. The journal is removed and its directory fsynced
only after all three destinations are durable. A replaced or truncated source
is detected by inode/offset; a complete residual rotated tail is consumed
before the new inode, while incomplete tails wait for their final newline.
Oversized raw rows are discarded before parsing. Any malformed, oversized,
mis-owned, linked, unreadable, or otherwise unsafe pending journal is preserved
unchanged and stops collection for explicit recovery; it is never silently
deleted or overwritten. The sole linked-file exception is the collector's own
interrupted no-replace publication: exactly one strict-name temporary sibling
with the same device/inode, owner, mode, and link count is unlinked and the
state directory fsynced before the journal is fully revalidated and replayed.
Reliability rows and their boot/listener/link/kernel-cursor/current-boot-count
state use the same
events-before-state invariant through a separate bounded mode-`0600`
`.state/pending-reliability-commit.json`. A crash after the public atomic
rewrite but before private state publication is replayed by digest without
duplicating the event batch.

Rule transitions use the same event-before-state invariant with deterministic
transition identities. The evaluator first atomically publishes any changed
bounded public event log, then its private mode-`0600` state, and finally the public
evaluation. If collection stops between those writes, replay from the prior
state produces the same identity and retains the first durable row. A rule-pack
or evaluator failure writes only an explicit `collection_error` evaluation;
it does not stop the independently collected host snapshot or history.
The transition log is not rewritten when it is unchanged, and private state
stores only counters/timestamps rather than duplicating public descriptions and
runbooks, limiting steady-state writes on small systems.

Short-lived host-rate and hashed process counters live in
`/run/monitor-collector/delta-state.json`; each run atomically replaces that
mode-`0600` file rather than appending it. PID/start-time material never leaves
that private file, while public process evidence uses fixed classes such as
`node`, `python`, `web-server`, or `other`. Container IDs and CPU baselines stay
only in `/run/monitor-container-exporter/cpu-state.json`, owned by `cks` mode
`0600`; the root collector is bind-mounted only the separate reduced
`containers.json` file. Neither PID nor container ID enters a public export.

When `vcgencmd` exists, the collector reads GPU temperature, allocated memory,
core clock, core voltage, and on Raspberry Pi 5
the external supply rail using `/usr/bin/vcgencmd pmic_read_adc EXT5V_V`, all
with the same strict command timeout and a 256-byte output limit per command.
Only a finite `EXT5V_V` value in the protocol sanity range 0–10 V is accepted;
it is rounded to three decimal places. That broad input bound is not a health
threshold. A malformed response, unsupported command, timeout, or non-zero
exit produces `null`, never zero fabricated from failure.

GPU temperature is used as the host temperature fallback; memory, clock, and
supply voltage populate the public snapshot. The current under-voltage alarm is
discovered by the exact hwmon sensor name `rpi_volt` and read from its standard
read-only `in0_lcrit_alarm` attribute; hwmon indices are never assumed stable.
It maps to bit 0 of the compatible unsigned 32-bit `throttledFlags` field.
Retained samples can still contain legacy high-bit history, but the collector
never invokes deprecated `vcgencmd get_throttled`, which emits a kernel warning
on current Raspberry Pi kernels. No voltage threshold is used to classify power
state or emit alerts: the hwmon alarm and kernel events remain authoritative.
The dedicated kernel cursor also captures brief under-voltage events that begin
and recover between one-minute hwmon samples.

`MONITOR_KERNEL_LOG` defaults to `/var/log/kern.log`. On the first run and after
rotation, the collector examines only the newest 8 MiB
(`MONITOR_KERNEL_MAX_INPUT_BYTES=8388608`) so recent incidents are retained
without loading an unbounded historical log. The command-line/environment
value is clamped to at most 16 MiB. The ordinary event/privilege input bound
remains separately controlled by `MONITOR_MAX_INPUT_BYTES`.

The unprivileged Docker helper reduces each workload immediately to the fixed
17-field current contract documented above. It never exports a container ID,
raw image reference, command, environment, mount, network address, or Docker
inspect document.
Each Docker list request is filtered to one explicitly reviewed Compose
project. A result is admitted only when its returned project/service labels
match one exact pair in the fixed map, and it receives that pair's distinct
public name. Unknown pairs are dropped before any stats request. New exports
never use the old app-level labels or generic `cks-workload` label; both remain
accepted only so retained snapshots and incident history can be read safely. Raw container names,
environment, mounts, images, commands, IDs, and socket paths never persist.
The reviewed Blog pairs are exported as `blog-frontend` for `blog/blogWeb` and
`blog-backend` for `blog/blogServer`; no mutable Docker name reaches Monitor.
The retired `pongdang-multtara/db` pair is handled the same way: a live Docker
observation is dropped before stats collection, while its fixed
`multtara-database` label remains valid only when reading retained snapshots or
incident history.
The root collector accepts the snapshot only when it is a fresh, single-link,
`cks:cks` mode-`0640` regular file under the exact production bind and every
nested value satisfies the fixed schema.

The existing server-watch event input can annotate the one-time database
cutover without admitting arbitrary operator text. It accepts only these exact
event/status pairs (an ISO timestamp may precede the token):

```text
MAINTENANCE event=multtara-cksdb-cutover status=started
MAINTENANCE event=multtara-cksdb-cutover status=completed
MAINTENANCE event=multtara-cksdb-cutover status=rolled-back
```

They become fixed `kind=topology` alert rows. Unknown events/statuses and every
extra raw detail are discarded. The cutover runner must use the existing
owner/locking policy of the configured `MONITOR_EVENTS_LOG`; the collector does
not write back to that host log.

The optional Nginx input is deliberately not a conventional access log.
`nginx/monitor-traffic.conf` maps only explicitly allow-listed portfolio paths
to fixed app labels and writes one identifier-free observation per matching
request with exactly timestamp, label, status, and request duration. All
unspecified paths are dropped. The `/blog` and `/blog/` boundary maps only to
the fixed `blog` label, so Blog request counts and latency can be correlated
with host peaks without retaining a path or visitor identifier.
`monitor-traffic-logrotate.timer` checks
`logrotate/monitor-traffic` every minute. Its `maxsize 5M` condition is evaluated
at a timer run, so it initiates rotation after the active file crosses that size
rather than imposing a synchronous 5 MiB cap. Under-size non-empty files rotate
daily and logrotate keeps at most two numbered archives.
The archives remain uncompressed so a collector delayed across more than one
interval can finish the unread tail of a rotated inode.

Before logrotate renames the active file, a root-owned helper atomically creates
and fsyncs `/var/lib/monitor-traffic-logrotate/reopen-required`. It removes and
directory-fsyncs that marker only after Nginx accepts the log-reopen signal. A
failed reopen therefore fails the one-shot without losing the obligation: the
service retries after two seconds (bounded to five starts per minute), and every
minute activation retries an existing marker before asking logrotate to rotate
anything else. Marker-free timer checks never signal Nginx.

`monitor-traffic-retention.timer` independently checks every minute and deletes
only exact-name, regular, single-link rotations older than 48 hours. While the
Nginx config is live it never unlinks the active file. Rotation, retention,
installation, and removal share one maintenance lock. The retention path
remains installed after traffic logging is removed, and a root-owned retirement
marker created only after a successful Nginx reload then permits it to expire
the final inactive file once the marker itself has aged for 48 hours. Only
per-app counts, status classes, slow counts, and latency summaries for one
collector capture interval can enter `currentTraffic` and an incident export.
An empty current list can also mean the optional source was unavailable. These
are request counts, not people or unique visitors; calculating visitors would
require a stable client identifier that this input intentionally never records.

## Infrastructure work ledger

`infrastructure_ledger.py` manages a record deliberately separate from the
collector's bounded telemetry and event retention. The canonical stream is
`/var/lib/monitor-infrastructure-ledger/events.jsonl`; its catalog and lock are
in the same root-only mode-`0700` directory. The Monitor-readable
materialization is `/var/lib/monitor-export/infrastructure-ledger.json`, owned
`root:cks` mode `0640` and consumed through the existing read-only `/data`
mount.

Keep the reviewed bootstrap record outside the public checkout as a root-owned
mode-`0600` file. Verify it, then install it explicitly:

```sh
cd /home/cks/Monitor/ops
sudo /usr/bin/python3 infrastructure_ledger.py verify \
  --input /root/reviewed-monitor-ledger-seed.json
sudo sh install-infrastructure-ledger.sh \
  /root/reviewed-monitor-ledger-seed.json
sudo /usr/local/sbin/monitor-infrastructure-ledger publish
sudo -u cks python3 -m json.tool \
  /var/lib/monitor-export/infrastructure-ledger.json >/dev/null
```

For an upgrade with an existing canonical stream, run the installer without a
seed argument. It updates the writer and republishes that stream. A first-time
installation refuses to proceed without an explicit absolute private seed
path. Real ledger seeds are ignored by Git; the public repository contains the
schema, implementation, and synthetic test fixtures only.

`sync-seed` is idempotent: an identical event is skipped, while reusing an ID
or reference with different content fails. `append --input FILE` accepts one
exact-schema entry and checks revision and source links against the full stream
before appending and fsyncing it. `publish` recreates only the sanitized public
snapshot. None of these commands prune canonical history.

Mutation input is staged as a root-owned regular file with no group/world write
permission; mode `0600` under `/root` is the expected boundary for append. The
installer copies the explicitly supplied private seed into a short-lived
mode-`0600` staging file before invoking the installed writer.

The writer rejects symlinks, hard links, broad permissions, oversized input,
unknown fields and enums, broken revision chains, and credential-like text.
Inputs must contain semantic evidence references, never raw shell commands or
arguments, passwords, tokens, cookies, private keys, client addresses, or
personal identifiers. Completed work requires evidence and a verified or
partially verified state. Back up the private canonical directory separately
and exercise restore; the Monitor export is a derived copy, not the backup.

## Install

From this directory:

```sh
sudo sh ./install.sh
systemctl status monitor-collector.timer monitor-container-exporter.service monitor-collector.service
sudo journalctl -u monitor-collector.service -n 50 --no-pager
```

Install the privacy-preserving Nginx aggregate input separately, then validate
that both services remain healthy:

```sh
sudo sh ./install-traffic-logging.sh
sudo systemctl restart monitor-collector.service
sudo nginx -t
sudo systemctl status monitor-traffic-logrotate.timer monitor-traffic-retention.timer
```

The sole expected rootless Docker socket is owned by `cks` (UID 1001) at
`/run/user/1001/docker.sock`; every other owner is excluded. Only the
short-lived `User=cks` exporter namespace binds that socket. This does not make
the Docker API read-only, so the security boundary is privilege separation:
the helper has no authority beyond the account that already owns the daemon,
uses only fixed GET paths, exits, and leaves a reduced file. The root collector
replaces `/run` with an empty read-only view and binds back only its own runtime
directory plus the exact reduced `containers.json`; it cannot reach the socket
or the exporter's private ID/counter state.

The root service retains only `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` to
read protected logs. It grants writes only to `/var/lib/monitor-export` and
`/run/monitor-collector`. The unit runs with group `cks`; output directories are
`root:cks` mode `0750` and public files are mode `0640`, allowing the rootless
`cks` Monitor container to read an explicitly bind-mounted export directory.
The otherwise-private device namespace exposes only `/dev/vcio` with the
device-cgroup permission needed by `vcgencmd`; `/var/log` is available read-only
for the configured semantic inputs. If an LSM (SELinux/AppArmor) independently
denies the unprivileged helper's socket access, add a narrow local policy for
this path; do not expose the socket over TCP or make it world-readable.

The root one-shot cgroup uses `MemoryHigh=160M`, `MemoryMax=192M`, and
`TasksMax=64`; the unprivileged Docker helper uses 128/160 MiB and 48 tasks.
These limits leave room for the bounded 8 MiB kernel tail and at most six
concurrent Docker-stat requests while containing unexpected input growth.

`/etc/default/monitor-collector` is transactionally replaced with the reviewed
production baseline on every install, so obsolete socket and user entries do
not survive an upgrade; a failed install restores the previous file. The
production unit also pins direct Docker sockets to empty, the exact reduced
container input, the process UID set, and the request source on its command
line. Edit other input/output or threshold values after installation, then run:

```sh
sudo systemctl restart monitor-collector.service
```

The collector atomically enforces row and calendar bounds on its exports. The
separate identifier-free Nginx input is checked by the supplied one-minute
rotation and retention timers. Journald owns collector service logs.

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

Before replacing a local deployment with central SSO, stop the container and
retire the active record explicitly:

```sh
sudo -u cks python3 ops/monitor_auth_state.py retire \
  --confirm-container-stopped --confirm-sso-mode
```

`retire` validates the same owner/mode/link/schema boundary, creates an
owner-only `retired-sso-*` recovery snapshot outside the mounted state
directory, rechecks the source identity, removes only the active
`password.json`, and fsyncs the directory. Repeating it with no active record
is a no-op. Production SSO must not mount the active state or its recovery
snapshots; restoring one is a deliberate return to local mode and creates a
fresh session epoch.

Docker list and per-container stats calls use a 2-second curl timeout. The
helper issues only project-filtered list requests for the fixed project map and
fails without replacing its previous snapshot if any of those queries is
unavailable or malformed. Admitted running workloads then use the fast
`stream=false&one-shot=true` stats endpoint with at most six bounded worker
threads, a 20-second global deadline, and a 30-container stats cap. Because
one-shot Docker stats contain no usable `precpu_stats`, CPU percent is
calculated from the protected previous-run counters described above; the first
observation is `null`. Memory is available immediately from the one-shot
response. If the stats deadline is reached, every admitted container remains
present but unavailable stats fields are `null`, never misleading zeroes. The
helper has a 35-second outer timeout and the dependent root collector has 45
seconds.

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
  --traffic-log /tmp/fixture/traffic.jsonl \
  --container-input '' \
  --docker-sockets '' \
  --output-dir /tmp/monitor-export \
  --runtime-dir /tmp/monitor-run

python3 -m unittest discover -s tests -v
```

## Uninstall

```sh
sudo sh ./uninstall.sh
sudo sh ./uninstall-traffic-logging.sh
```

Uninstall deliberately preserves `/var/lib/monitor-export`,
`/etc/default/monitor-collector`, `/home/cks/.local/state/monitor-auth`, and
`/home/cks/backups/monitor-auth`. Remove those separately only after deciding
the retained telemetry, authentication recovery, and configuration value is no
longer needed.

The traffic uninstaller first enables the independent retention timer, then
removes and reloads the Nginx request-log configuration and disables the
rotation timer. It intentionally leaves
`monitor-traffic-retention.service`, `monitor-traffic-retention.timer`, and the
exact-name pruning helper installed. Existing numbered rotations, and the final
inactive `monitor-traffic.jsonl`, are removed after they are older than 48
hours. The active filename becomes eligible only after Nginx reload succeeds
and the uninstaller writes the retirement marker while holding the shared lock;
the marker must then age for 48 hours so graceful workers can release the old
descriptor first.
unrelated Nginx logs, symlinks, and multiply linked files are never targets.
Confirm the retained cleanup path with:

```sh
systemctl status monitor-traffic-retention.timer
systemctl list-timers monitor-traffic-retention.timer
```
