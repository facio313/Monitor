# Monitor host update broker

The host update broker lets the Monitor UI request a fresh Ubuntu package
check and apply one previously confirmed safe plan. It is intentionally
separate from the host telemetry collector and from every container or
portfolio deployment mechanism.

## Security boundary

The public Monitor process remains rootless and read-only. On the host, its
only new handle is
`/var/lib/monitor-update-socket/gateway.sock`, a Unix stream
socket accepting one newline-terminated JSON request of at most 4,096 bytes.
That narrow directory is bind-mounted read-only at `/run/monitor-update` in
the Monitor container, so the application still connects to
`/run/monitor-update/gateway.sock`. The socket gateway runs as the dedicated
unprivileged `monitor-updater` account, verifies
`SO_PEERCRED` UID 1001, validates an exact schema, creates the request ID, and
writes a bounded private queue. It cannot invoke APT or modify public status.

The host path deliberately lives under root-owned `/var/lib`, which remains
visible to the long-running rootless Docker daemon when the leaf is created or
its socket inode is replaced. This avoids `/run`, which RootlessKit presents
through a private copy-up view, and avoids a replaceable user-owned ancestor.
The leaf directory is `root:cks` mode `0750`. The socket unit opens the
pathname before activating the gateway and systemd passes that already-open
listening socket as FD 3. The gateway never resolves or reopens the socket
pathname inside its private mount namespace; it keeps `ProtectHome=true` and
`InaccessiblePaths=/home /root`. `monitor_update_gateway.py` also requires
exactly one systemd descriptor and validates that it is a listening Unix
stream socket.

The root worker is activated by `monitor-update-worker.path`. It first moves a
request into a root-only directory, then revalidates its name, type, owner,
mode, link count, size, complete schema, actor, peer UID, timestamp, action,
and plan ID. No request field is ever inserted into a command line.

Do not grant the Monitor container sudo, mount the host Docker socket, mount
systemd D-Bus, or make APT/dpkg directories writable. Do not add another
action without a separate threat review and tests.

## Wire protocol

Each connection carries exactly one compact or ordinary JSON object followed
by one newline. The request has exactly these keys:

```json
{"schemaVersion":1,"action":"check","actor":"alice","planId":null}
```

`action` is only `check` or `apply-safe`. An apply request uses the same shape
with the 64-character lowercase hexadecimal `planId` returned by the last
fresh check. `actor` must match
`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$`; the Monitor API must derive it from the
trusted SSO identity, never from a browser body.

An accepted request receives exactly:

```json
{"schemaVersion":1,"accepted":true,"requestId":"update-<uuid>","state":"queued"}
```

A rejected request receives exactly:

```json
{"schemaVersion":1,"accepted":false,"code":"INVALID_PLAN"}
```

The only rejection codes are `BUSY`, `QUEUE_FULL`, `INVALID_REQUEST`,
`INVALID_ACTION`, `INVALID_ACTOR`, `INVALID_PLAN`, `PEER_REJECTED`, and
`INTERNAL_ERROR`.

## Update policy

`check` performs, in order:

1. writable-filesystem and minimum-free-space checks;
2. a clean `dpkg --audit` preflight;
3. fixed `apt-get update` with a bounded package-lock wait;
4. fixed `apt-get -s --with-new-pkgs --no-remove upgrade`;
5. strict parsing into bounded package/version/action/category records and a
   SHA-256 plan ID.

`apply-safe` requires that private plan to be unexpired and match the supplied
ID. It repeats every preflight, refreshes APT metadata, regenerates the plan,
and refuses the operation if the digest changed. Package architecture is part
of that digest. The worker constructs a bounded root-generated target for
every planned package as `name:architecture=candidateVersion`.
The exact `apt-get -s --mark-auto --no-remove install ...` transaction must
match every package, old version, candidate version, install/upgrade action,
and zero-removal count from the confirmed broad plan. Only the broad plan's
kept-back count may differ from this explicit-target simulation.

The real command uses those same pinned targets, `--mark-auto`, `--no-remove`,
a zero-second package-lock wait, noninteractive `--force-confold`, and a
shutdown/sleep inhibitor. Immediately before process creation the worker
writes a root-owned mode `0600` expected transaction with a strict schema,
expiry, and SHA-256 digest, then invalidates the one-use confirmation token.
Request fields never enter this file or any command line.

The invocation-local `apt-exact.conf` clears earlier dpkg pre-invoke/package
hooks and installs the root-owned worker as the first `Pre-Install-Pkgs` hook
using APT protocol v3. In the same lock-holding APT process, after solving and
downloads but before APT changes auto/manual state or invokes dpkg, that hook
revalidates the expected file's owner, mode, link count, size, complete schema,
freshness, and digest. It then requires a one-to-one match for every unpack and
configure row including package identity, native/foreign architecture, old and
new versions, and action. A removal, downgrade, configure-only outsider,
duplicate, missing target, unknown action, malformed input, or mismatch exits
non-zero and APT aborts before dpkg. Normal post-hooks and package maintainer
scripts still run after this boundary.

The broker never runs `full-upgrade`, `dist-upgrade`, `autoremove`, a release
upgrade, a downgrade, source changes, arbitrary package selection, `dpkg
--configure -a`, a reboot, a container update, or a user-selected firmware
image/channel. `rpi-eeprom` remains visible as a `firmware` package; normal
official package hooks may stage its default-channel update. Reboot remains a
separate manual operation.

The worker does not remove or break package-manager locks. Refresh and
simulation commands have bounded waits. The real command has a 90-minute bound
only while it is downloading/solving before the validator starts. A root-only
marker plus advisory phase lock closes the timeout/validator race. Once the
validator begins, dpkg can start immediately, so the worker deliberately waits
without a kill deadline. The systemd unit uses `KillMode=process` and never
SIGKILLs an apt/dpkg child; this follows the distro APT safety posture and
avoids trading a hung operation for a corrupted package database. Do not stop
an active worker. Its inhibitor blocks shutdown and sleep during the command.

## Public state and audit

The worker atomically writes `/var/lib/monitor-export/system-update.json` as
`root:cks` mode `0640`. It contains the exact schema documented by the Monitor
API: schema/generation timestamps, state, request/action timestamps, fresh
plan ID/expiry, summary, at most 512 bounded package rows, reboot-required
state, and a fixed result code. The full private plan is capped at 2,048
packages and stored root-only under `/var/lib/monitor-update`.

A zero-action check still publishes its summary. If APT reports packages held
back while no safe package action is available, state is `up-to-date`, code is
`UPDATES_KEPT_BACK`, `planId` remains null, and the nonzero `keptBackCount` is
visible. This is distinct from code `UP_TO_DATE`.

`/var/log/monitor-update-audit.jsonl` contains only semantic fields: timestamp,
generated request ID, validated SSO actor, peer UID, fixed action, fixed result
and code, plan ID, package count, and reboot-required state. Raw APT output,
maintainer-script output, command lines, paths, and request bytes are never
copied into the public status or audit. The root service journal remains the
operator-only diagnostic source. Audit appends are semantic-idempotent, and a
root-claimed request is unlinked only after terminal status and audit are both
durable. On a worker restart, a previously claimed request is marked
`INTERRUPTED` (or its durable terminal audit is repaired) without replaying
APT. Both incoming and recovery directories activate the path unit.

## Install and connect

Install the host units separately from the existing collector:

```sh
sudo sh ./install-updater.sh
systemctl status monitor-update-gateway.socket monitor-update-worker.path
```

Then bind the stable runtime directory read-only into the Monitor service. A
directory bind follows a safely recreated socket inode; binding the socket file
itself would strand the container on a stale inode after a unit restart.

```yaml
volumes:
  - type: bind
    source: /var/lib/monitor-update-socket
    target: /run/monitor-update
    read_only: true
    bind:
      create_host_path: false
```

The socket is the write capability despite the directory's read-only mount.
The directory contains only this socket and is created `root:cks` mode `0750`
at every boot. Keep the container target at `/run/monitor-update`; do not set
the application socket path to the host path. Never bind `/var/lib` or another
broader host path. The backend should use
a short connect/read/write timeout, return `202` for accepted work, and poll
the public status rather than keeping the HTTP request open during APT.

Remove executable units without deleting forensic state or audit history:

```sh
sudo sh ./uninstall-updater.sh
```

Uninstall refuses to interrupt an active worker.
