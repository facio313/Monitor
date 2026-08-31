# Monitor default alert rules

`default-rules.v1.json` is the versioned seed pack for the 82 rules named in
`/home/cks/Monitor.md`. The exact ordered list is enforced by
`ops/tests/test_alert_engine.py`, so a rule cannot disappear silently during a
refactor.

The pack is declarative data, not executable Python or an expression language.
`ops/alert_engine.py` accepts only a bounded fixed schema, finite thresholds,
known comparison operators, explicit recovery thresholds, minimum breach and
recovery sample counts, explicit evaluation/breach/recovery/no-data durations,
a no-data policy, optional parent suppression, bounded labels, and fixed-length
operator guidance. Unknown fields, duplicate IDs,
invalid hysteresis, parent cycles, symlinks, and oversized files fail closed.

## Honest support status

Defining a rule does not mean its signal is collected. `ops/alert_runtime.py`
emits an explicit `unsupported`, `permission_denied`, `collection_error`,
`stale`, or `no_data` observation when the current collector cannot prove a
value. Unsupported rules must never appear healthy and must not send fault
notifications.

The current single-host collector evaluates the subset backed by its reduced
snapshot: aggregate/per-mode CPU, load per core, CPU and memory PSI, available
memory, swap usage and churn, filesystem capacity/inodes/read-only state,
block latency, network errors/drops, TCP retransmission and conntrack pressure,
system FD/PID/zombie pressure, allow-listed systemd state, clock/reboot evidence,
temperature, authoritative Raspberry Pi throttle flags, local Monitor cadence
and filesystem health, notification final failures, and the reduced Docker v3
running state, restart delta,
OOM state, authoritative healthcheck state, configured CPU/memory limits, and
CPU/memory percentage of those limits. Current PID saturation, CPU throttle
periods, network errors, writable-layer bytes, privileged/socket-mount state,
image digest drift/latest-tag use, and Docker event-poll continuity are also
mapped. `ContainerWritableLayerHigh` uses an absolute 1 GiB default because
Docker `SizeRw` does not expose a truthful per-container capacity denominator;
the Docker data-root filesystem is evaluated separately. Missing detail stays
explicitly unsupported rather than becoming a healthy zero. The remaining rules stay visibly unsupported until
their collector, agent, central ingest, or synthetic source is implemented and
tested.

## Evaluation semantics

- Gauge rules require both `forSamples` and `forSeconds`; repeated fast calls
  cannot satisfy wall-clock persistence early. Missing evaluations never
  advance a pending breach. A gap beyond the cadence tolerance resets pending
  and no-data duration instead of counting the gap as a continuous condition.
- Recovery requires both `recoverySamples` and `recoverySeconds` at the separate
  recovery threshold.
- No-data has its own policy, counter, and `noDataSeconds` duration.
- Each state records the configured `evaluationIntervalSeconds` and the breach,
  recovery, and missing start timestamps. A cadence change resets a pending
  duration; an already firing incident remains open and must recover on valid
  evidence.
- Missing, stale, permission-denied, or failed observations never resolve an
  already firing condition; a valid recovery observation is required.
- Silence suppresses delivery, not evaluation history. If the incident remains
  firing when the silence expires, one deterministic ready event retains the
  original incident `openedAt`; a silence added after ready authority exists is
  non-retroactive.
- Optional persistent silences are loaded from the owner-only mode-`0600`
  `/etc/monitor/alert-silences.json` file (or the absolute
  `MONITOR_ALERT_SILENCES` path). The schema is exact and bounded to 256
  one-shot UTC intervals of at most 366 days; duplicate keys/IDs, links,
  hardlinks, broad permissions, invalid selectors, and malformed intervals
  fail rule evaluation closed. See `alert-silences.example.v1.json`.
- A firing parent suppresses child delivery while preserving child state. If
  the child remains firing when the parent recovers, private lifecycle state
  emits one ready event even if the bounded log no longer retains the opening
  suppressed row.
- A transition carries a deterministic SHA-256 idempotency key.
- The engine performs no delivery and no file mutation itself. The collector
  persists returned state and a bounded transition log. When an explicit
  delivery configuration is present, `alert_store.py` only inserts recent
  `ready` transitions into the finite SQLite outbox; it performs no network I/O.
- `alert_delivery.py` owns leasing, crash recovery, timeout, capped exponential
  retry with jitter, final-failure accounting, and the common webhook, Slack,
  Discord, Telegram, and SMTP adapters. Secrets are env/private-file references
  resolved at send time and never outbox fields. See `docs/alert-delivery.md`
  and `alert-delivery.example.v1.json`.
- Delivery tests use a separate `purpose=test` identity and counters. They do
  not mutate evaluator state, the transition log, or incident statistics.

The default cadence is one minute. Changing the declared cadence or pack
version intentionally resets pending streaks while preserving active incident
identity.
