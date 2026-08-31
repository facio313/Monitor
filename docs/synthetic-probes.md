# SSRF-safe synthetic HTTP and TLS probes

`ops/synthetic_probe.py` provides the opt-in external probe worker installed by
`ops/install.sh`. The same transaction installs its hardened service, timer,
operator example, and this document, but it deliberately does not provision a
real target configuration or activate probing on a first install.

Start with the installed
`/usr/local/share/doc/monitor-collector/synthetic-probes.example.json`, review
the real targets outside the repository, and copy that reviewed document to an
absolute, `cks`-owned mode-`0600` regular file. Its exact version-1 shape
supports at most 32 probes. Each has a unique bounded ID, an HTTP(S) URL, one
expected final status, a 1–30-second timeout, and 0–5 redirects. A configuration
file must be owned by the invoking UID, have one link, not be group/world
writable, and be smaller than 64 KiB. Unknown/duplicate fields and unsafe URLs
fail closed.

The production path is intentionally a separate operator action. The installer
does not create `/etc/monitor-synthetic-probe`, because creating a placeholder
or example as the live configuration could accidentally probe the wrong target.
Provision the final private document and run one reviewed check before enabling
the timer:

```sh
sudo install -d -o cks -g cks -m 0700 /etc/monitor-synthetic-probe
sudo install -o cks -g cks -m 0600 \
  /root/reviewed-monitor-synthetic-probes.json \
  /etc/monitor-synthetic-probe/probes.json
sudo systemctl start monitor-synthetic-probe.service
sudo -u cks python3 -m json.tool \
  /var/lib/monitor-synthetic/results.json >/dev/null
sudo systemctl enable --now monitor-synthetic-probe.timer
```

The service executes as the dedicated unprivileged `cks` identity. A direct
CLI run prints one reduced JSON result per reviewed probe and exits nonzero when
any probe is non-`ok`; it does not expose an HTTP endpoint.

For a service, `--output` is required. It publishes one exact, bounded JSON
document rather than a partial stream:

```sh
python3 ops/synthetic_probe.py \
  --config /etc/monitor-synthetic-probe/probes.json \
  --output /var/lib/monitor-synthetic/results.json
```

The public file has only `schemaVersion`, UTC `generatedAt`, and an exact
`results` array. Each result has a bounded ID/status/timestamp, final HTTP
status, redirect count, latency, and optional final HTTPS expiry evidence; no
response body or response-header value is published. `--output` validates that
contract again, writes an exclusive temporary mode-`0640` single-link file,
fsyncs it, atomically replaces the prior safe file under a directory lock, and
fsyncs the private output directory. The parent must already be owned by the
service UID/GID and not group/world writable. Existing output links, wrong
owner/group/mode, hard links, path races, and invalid documents fail closed.
The normalized final URL is part of each result, so target paths and query
strings must themselves be safe to expose to Monitor. Never embed a token,
password, cookie, or other credential in a probe URL.

`ops/systemd/monitor-synthetic-probe.service` and its five-minute timer run
the required output mode as the install contract's unprivileged `cks` account
with an empty capability set, private config/output paths, no proxy environment,
a 40-second deadline, 80 MiB memory ceiling, 16-task ceiling, and only Unix/DNS
plus IPv4/IPv6 network families. The installer establishes the distinct
`/var/lib/monitor-synthetic` state directory as `cks:cks` mode `0750`; the
worker's atomic output is a single-link `cks:cks` mode-`0640` regular file. It
must not write the root-owned collector export directory. The root collector
unit receives only the exact `/var/lib/monitor-synthetic/results.json` path
through `BindReadOnlyPaths`; the producer directory is never a collector write
surface. The collector independently checks ownership, mode, link count,
schema, size, and freshness before publishing reduced probe state.

Upgrades stop the worker while replacing assets, then restore the synthetic
timer's prior enabled and active states. A first installation has neither state
and remains disabled. If any later installation step fails, the installer
restores the prior program, documentation, units, timer state, and pre-existing
state-directory metadata. It never writes or removes the operator configuration.
`ops/uninstall.sh` disables the worker and removes installed assets, while
preserving both `/etc/monitor-synthetic-probe/probes.json` and
`/var/lib/monitor-synthetic/results.json` for explicit operator disposition.

The probe never uses proxy environment variables. If any common proxy variable
is present, it returns `unsupported` rather than risking a proxy-selected route.
URLs must be credential-free HTTP(S), cannot contain fragments, are normalized
with IDNA and canonical default ports, and have a bounded request target.

For every initial request and redirect, DNS is resolved again. All returned
addresses must be globally routable; localhost, RFC1918/private, link-local
(including cloud metadata), multicast, reserved, unspecified, loopback, and
IPv4-mapped IPv6 addresses are rejected. The selected validated sockaddr is
passed directly to `connect`; Host and TLS SNI/hostname verification retain the
normalized hostname. This prevents a second client-side resolver lookup and DNS
rebinding. Redirects are never followed automatically: at most five are
validated one at a time.

Only a bounded HTTP response header is read. Response bodies, response header
values, URL credentials, request cookies, and proxy values are never retained.
Results contain a UTC check time, reduced category (`ok`, `dns`, `permission`,
`timeout`, `tls`, `http`, `invalid`, or `unsupported`), final status code,
redirect count, latency, and HTTPS certificate expiry timestamp/days evidence.

External deployment validation is still required for every real target: verify
DNS, redirect, certificate, expected-status, alert, and recovery behavior from
the production network. Do not give the web service a Docker socket or a
general network-fetch endpoint for this feature.
