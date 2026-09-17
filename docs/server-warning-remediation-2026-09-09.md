# Server warning remediation — 2026-09-09

## Findings and scope

Seven firing critical rules referred to the archived Multtara containers:
three `ContainerDown`, three `ContainerUnhealthy`, and one
`ContainerMemoryNearLimit`. The last rule correctly remained active with no
current evidence; removing a target from collection alone must not count as
recovery. The independently deployed Pongdang containers were healthy but
missing from Monitor's active allowlist and had no explicit resource limits.

The excluded `wgang` workload was not inspected or changed. No shared proxy,
Docker daemon, host networking, legacy database, or host reboot was modified.

## Applied changes

- Monitor's active Docker allowlist now selects only the exact
  `pongdang/{backend,db,frontend}` project/service pairs for this application.
  Archived Multtara identifiers remain readable in historical exports/events.
- The API and UI recognize the three standalone Pongdang components.
- An optional root-owned mode-0600 exact-target retirement configuration
  explicitly closes the seven old incidents, only with fresh complete
  container-source evidence and no current observation of the target.
  See [retirement semantics](retired-monitoring-targets.md).
- Pongdang's live resource limits were applied with `docker update`, without
  restarting any of its containers. Persistent Compose/CI changes are tracked
  by commit `2fed4d4cefc0e89faefb5772ed72d01cba211496` in Pongdang.

| Service | RAM limit | RAM + swap limit | CPU cores | PID limit |
| --- | --- | --- | --- | --- |
| Pongdang DB | 1 GiB | 2 GiB | 1.5 | 256 |
| Pongdang backend | 512 MiB | 1 GiB | 1 | 128 |
| Pongdang frontend | 128 MiB | 256 MiB | 0.5 | 64 |

Observed pre-change peak memory was approximately 32.4, 64, and 7.85 MiB,
respectively. Limits leave substantial headroom; they are safeguards rather
than evidence of an existing memory-exhaustion incident.

## Deployment and readback

The Monitor-only image
`ghcr.io/facio313/monitor:hotfix-active-inventory-20260909-1`
(`sha256:c3ad20f2fe390a74106e4237ece8254b90ef280f1985fc3174cfca8a6793190a`)
was deployed through its existing Compose service. It includes the earlier
response-streaming fix. Its rollback image is
`ghcr.io/facio313/monitor:hotfix-response-streaming-20260909-1`.
Application artifacts and rollback metadata are retained in
`/tmp/monitor-active-inventory.U1MQ0s`.

Only the installed `collector.py`, `alert_engine.py`, `alert_runtime.py`, and
`alert_store.py` modules were updated. The collector timer was paused while
idle, an exact runtime/state/history backup was made in the root-private
`/tmp/monitor-retirement-runtime.foBdSx`, and the timer was restored after a
successful collection. Configuration lives at
`/etc/monitor/alert-retirements.json`; no incident-state file was manually
rewritten. Do not restore old state/history over later events during a code
rollback; retained history contains the authoritative retirement records.

At 20:36:07 KST, all seven incidents received one explicit retirement event
each, with original opening times and all 181 prior events preserved. The
event log grew to 188 records with seven unique retirement keys. Active rules
became zero. The next completed evaluation at 20:37:09 KST was `ok`, with
358 inactive and 56 explicitly unsupported rule states, and no coverage
errors. Unsupported telemetry was not invented or reported as healthy.

The authenticated local API returned HTTP 200, complete fresh data, and
`X-Accel-Buffering: no`. The new Pongdang inventory reported three running,
healthy containers with the expected limits and zero restarts. Pongdang's
`/api/ready` returned `{"status":"ok"}`.

Browser readback rendered eight charts and eleven panels, including Pongdang,
without empty-state, refresh-failure, JavaScript, or failed-request errors.
The focused application/API/presentation/operational-health suite passed
113 tests. The collector/exporter/alert/delivery suite passed 216 tests as the
repository owner with the real retirement config installed. Test fixtures now
isolate optional operator configuration paths/environment; an additional
109-test run with deliberately invalid inherited config paths also passed.

## Remaining cautions

TCP retransmission was approximately 1.7–2.2%, above the UI's 1% caution
threshold but below the persistent rule's 5% threshold. The primary link was
1 Gbit/s full duplex with zero observed interface/FCS errors or drops, no
TCP queue/memory/backlog drops, and a six-packet connectivity check had zero
loss. No interface restart or speculative kernel tuning was justified by
these observations; the caution remains visible when its condition holds.
A brief CPU/I/O pressure caution during verification was no longer present in
the 20:40:23 KST sample; at that point only TCP quality and reboot cautions
remained, with zero active rule incidents.

Kernel `6.8.0-1064-raspi` is installed while `6.8.0-1063-raspi` is running.
The pending reboot was not executed because a host-wide restart would also
affect the explicitly excluded workload and requires separate authorization.
CPU, memory, disk, temperature, voltage, throttling, OOM, NVMe, and PCIe checks
did not identify another immediate host fault at inspection time.

## Persistent Pongdang deployment

The exact two-file Compose/CI commit
`2fed4d4cefc0e89faefb5772ed72d01cba211496` passed
[feature CI](https://github.com/facio313/Pongdang/actions/runs/34346444705),
then was fast-forwarded to `main` with a normal non-force push after verifying
the remote base had not moved. The existing
[main CI and deployment](https://github.com/facio313/Pongdang/actions/runs/34346686695)
also passed. No manual deployment bypassed CI.

After that deployment, backend/frontend image tags and the release pointer
matched the exact commit, all three containers were healthy, limits matched
the table above, and readiness was HTTP 200. There were no OOMs or restarts.
The first post-deployment Monitor sample at 20:41:28 KST was fresh and reported
zero firing/recovering rules. Counter deltas initially require a second sample
after container recreation and are not invented during warmup.
At 20:42:32 KST, the next sample had valid CPU and restart deltas for all
three healthy containers, zero restart deltas, no rule coverage failures,
and zero firing/recovering rules. CPU PSI was 2.83% and full I/O PSI 0.03%,
below the transient caution observed during deployment verification.
