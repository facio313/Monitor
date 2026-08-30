# Monitor default alert rules

`default-rules.v1.json` is the versioned seed pack for the 82 rules named in
`/home/cks/Monitor.md`. The exact ordered list is enforced by
`ops/tests/test_alert_engine.py`, so a rule cannot disappear silently during a
refactor.

The pack is declarative data, not executable Python or an expression language.
`ops/alert_engine.py` accepts only a bounded fixed schema, finite thresholds,
known comparison operators, explicit recovery thresholds, minimum breach and
recovery sample counts, a no-data policy, optional parent suppression, bounded
labels, and fixed-length operator guidance. Unknown fields, duplicate IDs,
invalid hysteresis, parent cycles, symlinks, and oversized files fail closed.

## Honest support status

Defining a rule does not mean its signal is collected. `ops/alert_runtime.py`
emits an explicit `unsupported`, `permission_denied`, `collection_error`,
`stale`, or `no_data` observation when the current collector cannot prove a
value. Unsupported rules must never appear healthy and must not send fault
notifications.

The current single-host collector can directly evaluate only the subset backed
by its reduced snapshot: aggregate CPU, load per core, CPU and memory PSI,
available memory, swap usage, filesystem capacity/inodes/read-only state,
aggregate network errors/drops, temperature, authoritative Raspberry Pi
throttle flags, and the reduced Docker v2 running state, restart delta,
OOM state, authoritative healthcheck state, configured CPU/memory limits, and
CPU/memory percentage of those limits. PID-limit saturation remains
unsupported because only the configured limit—not current PID usage—is
collected; security, image, writable-layer, and container-network rules are
also still unsupported. The remaining rules stay visibly unsupported until
their collector, agent, central ingest, or synthetic source is implemented and
tested.

## Evaluation semantics

- Gauge rules require every configured `forSamples`; missing evaluations never
  advance a pending breach. At the one-minute cadence, a gap over 90 seconds
  resets pending/no-data streaks instead of counting elapsed wall time as a
  continuous condition.
- Recovery requires `recoverySamples` at the separate recovery threshold.
- No-data has its own policy and counter.
- Missing, stale, permission-denied, or failed observations never resolve an
  already firing condition; a valid recovery observation is required.
- Silence suppresses delivery, not evaluation history.
- A firing parent suppresses child delivery while preserving child state.
- A transition carries a deterministic SHA-256 idempotency key.
- The engine performs no delivery and no file mutation itself. The collector
  persists returned state and a bounded transition log; notification adapters,
  retry scheduling, and a delivery outbox are not implemented yet and must
  remain a separate failure domain when added.

The default cadence is one minute. A future remote-agent path may use elapsed
duration in addition to sample counts, but it must preserve the rule-pack
version and these no-data and hysteresis guarantees. Changing cadence requires
a new pack version; the store intentionally resets pending streaks when the
pack version changes.
