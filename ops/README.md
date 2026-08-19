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
  state, and GPU allocation/clock fields in addition to the rate metrics.
  Each disk is exactly `mount`, `totalBytes`, `usedBytes`, and `usedPercent`.
- `history/YYYY-MM-DD.jsonl`: atomically replaced daily sample series. At most
  2,000 valid rows are kept per day, and files older than 30 calendar days are
  pruned.
- `alerts.jsonl`: at most 5,000 semantic `SNAPSHOT`, `metrics`, or `RECOVERED`
  events. Raw lines are never copied. On Raspberry Pi-class hosts with
  `vcgencmd`, current throttle/power transitions are also emitted here.
- `privilege.jsonl`: at most 5,000 records containing **only** `timestamp`,
  `actor`, `target`, `action`, and `result`. In particular, command text and
  arguments are never exported. The default source is the already-focused
  `/var/log/privilege-events.log`; `auth.log`/`secure` can be configured as
  fallbacks but are not enabled together by default, avoiding duplicates.

Durable log cursors live under the hidden output `.state` directory so service
restarts and reboots do not duplicate events. Short-lived host and per-container
CPU/network/disk delta counters live in
`/run/monitor-collector/delta-state.json`; each run atomically replaces that
mode-`0600` file rather than appending it. Container CPU state is keyed by
owner and container ID internally, pruned to containers still listed, and
hard-capped at 600 entries. IDs never enter a public export.

When `vcgencmd` exists, the collector reads throttle/power flags, GPU
temperature, allocated memory, core clock, and core voltage with a strict
timeout. GPU temperature is used as the host temperature fallback; memory and
clock populate the public snapshot; and current throttle transitions become
semantic alerts. Active low-bit conditions take precedence. When those bits
are clear but the historical high bits remain set (for example `0x50000`), the
snapshot reports `powerState: "degraded-history"`; it reports `normal` only
when neither current nor historical flags are present. This avoids presenting
one-minute samples as healthy while under-voltage is flapping between samples.

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
device-cgroup permission needed by `vcgencmd`. If an LSM (SELinux/AppArmor) independently denies
socket access, add a narrow local policy for these three paths; do not expose
the sockets over TCP and do not make them world-readable.

`/etc/default/monitor-collector` is installed only when it does not already
exist. Edit it to select different input/output paths, then run:

```sh
sudo systemctl restart monitor-collector.service
```

No logrotate rule is needed: the collector atomically enforces row bounds on
its two event exports and calendar retention on history. Journald owns service
logs.

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

Uninstall deliberately preserves `/var/lib/monitor-export` and
`/etc/default/monitor-collector`. Remove those separately only after deciding
the retained telemetry/configuration is no longer needed.
