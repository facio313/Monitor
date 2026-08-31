# Opt-in collector-to-agent producer

`ops/agent_producer.py` is the disabled-by-default bridge between the existing
same-host collector snapshot and `ops/agent_transport`. Nothing in the standard
collector installer enables it. Merely installing the example, service, or
timer does not start central telemetry; an operator must provision the two
private configs, bind identity, enroll, and explicitly enable both timers.
The producer unit permits only `AF_UNIX`; it can append to the private local
spool but cannot use the transport's HTTPS network path.

Cross-process transport state lock acquisition is bounded to five seconds.
The producer's 90-second oneshot deadline covers construction, identity bind,
and enqueue without waiting for the transport worker's four-minute network
deadline. Contention leaves the already-fsynced pending checkpoint intact, so
a later timer invocation retries the same source digest without advancing the
cursor or inventing a new batch.

## Fixed projection and identity

`ops/agent_records.py` is a pure allowlist. It accepts only collector schema 2
with the exact top-level, identity, heartbeat, and latest-sample fields emitted
by `ops/collector.py`. It projects fixed `host.*` measurements and the fixed
degraded `host.power.state` event. It has no raw-message, arbitrary label,
container-name, path, command, process, or user projection.

The checked-in example and unit read the standard collector publication at
`/var/lib/monitor-export/current.json`. A deployment that deliberately changes
`MONITOR_OUTPUT_DIR` must review and change both the private producer config and
its systemd `ConditionPathExists`/read-only path before enabling the timer.

The same allowlist accepts transport `self-metrics.json` only with its exact
schema and matching agent ID. It projects fixed `agent.self.*` and
`agent.spool.*` series for wall duration, user/system CPU, maximum RSS,
per-run procfs I/O deltas, component outcomes and retry streaks, heartbeat
acknowledgement age, active spool usage, and permanently rejected quarantine
counters/status/oldest age. Every self value is projected at the fresh collector
checkpoint time with an explicit `agent.self.sample_age_seconds`; a sample more
than 60 seconds older than that checkpoint is reported as stale and its old
values are omitted. Thus an optional old self sample cannot make fresh host
records fail the central replay window. A missing, unreadable, corrupt, or stale
self-metrics file yields explicit availability/status metrics and does not block
the collector checkpoint.

`agent.self.metrics_status_code` is fixed to `0=valid`, `1=missing`,
`2=corrupt`, `3=unreadable`, and `4=stale`. Component outcome codes are fixed to
`0=not-enrolled`, `1=no work due/pending`, `2=backoff`, `3=retry scheduled`,
`4=acknowledged`, `5=error`, and `6=permanently rejected and quarantined`; the
adjacent retry-streak series retains the
exact consecutive-attempt count. CPU and procfs I/O values are deltas for the
transport run being reported, while maximum RSS is the process high-water
mark. Measurement publication itself is best effort and never changes the
transport result.

The producer binds the collector `hostId`, `agentId`, installation epoch, and
identity generation to transport state. A fresh, unenrolled transport can be
seeded from that mapping. After any enrollment, heartbeat sequence, enqueue,
or binding side effect, a mismatch fails closed and requires explicit
re-enrollment; the producer never silently creates a second central identity.

## Crash and full-spool behavior

For each new collector heartbeat sequence, the producer:

1. writes and fsyncs a mode-`0600` pending checkpoint containing the exact
   reduced records;
2. calls the transport with the collector identity/generation/sequence as an
   idempotency checkpoint;
3. writes and fsyncs its private source cursor; and
4. durably unlinks the pending checkpoint.

The transport journal durably binds that checkpoint to the original batch IDs,
record digest, and allocated sequence range. An exact retry returns those IDs
even after the batches were acknowledged and removed. Reusing the checkpoint
with changed records, replaying an older source sequence, or changing source
identity conflicts before new IDs or sequences are allocated. A mixed metric
and event projection is split into homogeneous batches so the server's event
reserve never carries metrics.

If the bounded local spool cannot admit the complete checkpoint, no partial
batch or sequence advance is committed. The producer exits with temporary
failure status `75` and retains its pending file for the next timer run. It
does not evict unacknowledged data or skip forward to a newer `current.json`.
Active spool and quarantine files share that same byte/entry bound. A server
`BATCH_TOO_OLD` or `DATA_TOO_OLD` response atomically moves the immutable batch
to quarantine instead of retrying forever; capacity is released only after an
operator inspects its reduced metadata and explicitly purges that batch ID.

The source remains the collector's atomic latest snapshot, not a collector-owned
append-only outbox. While one checkpoint is blocked by a full spool, subsequent
collector runs may replace `current.json`; after recovery the producer observes
the then-current sequence, not every overwritten intermediate snapshot. Closing
that bounded-source gap would require a coordinated collector outbox change and
is not claimed by this opt-in adapter.

## Provisioning order

Install these files without changing the collector unit:

```text
/usr/local/lib/monitor-agent/agent_records.py
/usr/local/lib/monitor-agent/agent_producer.py
/usr/local/lib/monitor-agent/agent_transport/*.py
/etc/monitor-agent/producer.json              root-owned mode 0600
/etc/monitor-agent/transport.json             root-owned mode 0600
/var/lib/monitor-agent                        mode 0700
/var/lib/monitor-agent-producer               mode 0700
```

Copy `ops/agent-producer.example.json`, replace deployment paths, and validate
the current collector snapshot. Before enrollment, seed and verify identity:

```bash
PYTHONPATH=/usr/local/lib/monitor-agent \
  python3 /usr/local/lib/monitor-agent/agent_producer.py \
  --config /etc/monitor-agent/producer.json bind-identity

PYTHONPATH=/usr/local/lib/monitor-agent \
  python3 -m agent_transport --config /etc/monitor-agent/transport.json status
```

Confirm `collectorIdentityBound` is true and the reported agent/host IDs equal
the private collector identity. Then perform one-use enrollment as documented
in `docs/agent-transport.md`. Only after enrollment, proxy/PKI validation, and
an operator-reviewed test enqueue should the distinct units be enabled:

```bash
systemctl daemon-reload
systemctl enable --now monitor-agent-producer.timer
systemctl enable --now monitor-agent-transport.timer
```

Disable the producer timer first during rollback. Its private cursor/pending
state is not interchangeable with transport state; retain both until all
spooled batches are acknowledged or an operator explicitly abandons them.

This core ends at the server's encrypted durable ingest queue. A production
downstream materializer still needs its own claim/ack, retention, restore, and
duplicate-handling contract before central ingest is a time-series store.
