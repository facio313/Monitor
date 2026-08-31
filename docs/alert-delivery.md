# Alert delivery outbox

The alert evaluator and network delivery are separate failure domains. The
collector writes normalized, deterministic transition events first. When
`/etc/monitor/alert-delivery.json` exists, `alert_store.py` routes recent
`notificationState=ready` events and inserts one SQLite row per event/channel.
It never opens a network connection. `suppressed` and `silenced` transitions
remain in `rule-alerts.jsonl` but are not queued. While the incident remains
firing, parent recovery or silence expiry creates one deterministic
`notificationState=ready` firing event with the original `openedAt`; that event
is then queued normally. The private evaluator state retains this notification
authority even after the bounded transition log drops the opening row. Event
publication precedes the state replacement, so crash replay treats a durable
ready event as irrevocable and does not enqueue it twice. For the same reason,
adding a silence after a ready event was already recorded is deliberately
non-retroactive: it cannot retract a row that may already be queued or delivered.

`alert_delivery.py drain`, normally invoked only by
`monitor-alert-delivery.service`, is the network-capable path. It atomically
leases one due row immediately before sending, records every attempt, and
completes or reschedules the row in a second transaction. A worker crash expires
the lease; another worker records `lease_expired` and retries it. A crash after
a remote service accepted a request but before local completion can still cause
an at-least-once retry, so the deterministic `Idempotency-Key` must be honored
by generic webhook receivers. Slack, Discord, Telegram, and SMTP do not promise
receiver-side exactly-once processing; SMTP uses the key as a stable Message-ID.
After SMTP `DATA` is accepted the worker closes the local connection without a
network `QUIT`; a slow or failed courtesy shutdown cannot turn accepted mail
into an unnecessary retry.
SMTP never treats a non-empty partial-recipient refusal map as full success. If
any refused recipient returns a transient 4xx status, the complete row retries;
recipients already accepted by that attempt can therefore receive a duplicate
under this at-least-once contract. If every reported refusal is permanent, the
row fails permanently without retrying.

## Files and bounds

- Active configuration: `/etc/monitor/alert-delivery.json`. Start from
  `ops/rules/alert-delivery.example.v1.json` (installed as
  `/usr/local/share/doc/monitor-collector/alert-delivery.example.v1.json`); all
  example channels and routes are disabled.
- Durable database: `<collector-output>/.state/alert-delivery/alert-delivery.sqlite`, mode
  `0600`, SQLite schema version 1, maximum 64 MiB.
- Enqueue health: `<collector-output>/alert-delivery-enqueue.json`, mode `0640`,
  contains only status, observation time, and bounded enqueue/dedup/drop/skip
  counters. Configuration or SQLite failures publish fixed `status=error`
  without exception text or secrets and never change rule-evaluation status.
- The collector reads only the outbox's cumulative operational final-failure
  counter, keeps its prior value in private runtime state, and supplies the
  resulting interval delta to the `NotificationDeliveryFailure` rule. A
  missing configuration is `unsupported`; unsafe configuration/storage is an
  explicit permission or collection error rather than a healthy zero. Firing
  and recovery events from `NotificationDeliveryFailure` remain in the local
  rule history but are never routed back into this same outbox. This prevents a
  failed channel from recursively generating more work for itself; alert on
  delivery-path availability through an independent external dead-man channel.
- Defaults: 1,000 active rows, 5,000 completed rows, 10,000 delivery-log rows,
  300-second leases, 10 deliveries per worker invocation, and a 15-minute event
  replay window. Every bound is validated and configuration cannot exceed the
  compiled safety ceilings.
- The standalone drain command stops claiming new rows after a 45-second
  monotonic runtime budget by default. The command rejects budgets outside
  1–300 seconds and batches outside 1–100 rows. Each already leased network send
  has its own shorter absolute deadline; the packaged service provides a
  separate five-minute hard limit.
- Individual channels have a 0.25–30 second timeout, 1–12 attempts, capped
  exponential backoff, and ±20% jitter. HTTP 408/425/429 and 5xx, timeouts, and
  transport failures retry. Other HTTP 4xx and invalid configuration fail
  permanently. SMTP 4xx retries and SMTP 5xx fails permanently. Each channel's
  timeout and, for SMTP, TLS mode and recipient count define an explicit
  end-to-end wall budget. A Linux main-thread `SIGALRM` watchdog enforces that
  budget across secret resolution, DNS, connect, TLS, authentication, request
  writes, and arbitrarily fragmented or multiline response parsing; per-socket
  idle timeouts are not treated as a session bound. Configuration requires the
  lease to exceed the enforced deadline by five seconds and rejects combinations
  that cannot fit the 300-second lease ceiling. A non-main-thread invocation,
  unsupported platform, blocked `SIGALRM`, unavailable signal-mask inspection,
  custom `SIGALRM` handler, or pre-existing real-time timer performs no network
  I/O and returns fixed retryable
  `deadline_unavailable`; expiry returns `delivery_deadline_exceeded`.
- A full queue rejects a new item unless it has higher alert priority than the
  oldest lowest-priority pending/retry row. Every rejection or eviction is
  counted separately for operational and test traffic.
- A deterministic delivery key remains deduplicated while either its outbox
  history row or delivery-attempt audit is retained. This prevents a pruned
  terminal row from being recreated with an attempt number that collides with
  its retained audit. Once both retention windows expire, the same key may be
  admitted again.
- Evaluator enqueue is one SQLite transaction capped at 4,096 routed deliveries
  per evaluation. Critical/firing/newer events are selected first; excess work
  increments `enqueue_batch_overflow` and the operational drop counter instead
  of extending collector latency without bound.

## Secret boundary

Inline URL, token, password, Authorization/Cookie header, and arbitrary secret
fields are rejected by the exact configuration schema. A channel contains only
a `secretRef`:

- `{"provider":"env","key":"MONITOR_SLACK_WEBHOOK_URL"}` resolves the
  value in the delivery worker environment. The packaged unit reads optional
  values from the root-only mode-`0600` file
  `/etc/monitor/alert-delivery.env`; the JSON still contains only the reference.
- `{"provider":"file","key":"/etc/monitor/secrets/slack-url"}` reads one
  absolute, owner-validated, non-symlinked, single-link file with mode `0400` or
  `0600` and at most 8 KiB. The packaged unit exposes only
  `/etc/monitor/secrets` for file-backed secret references.

Secrets are resolved only after a row is leased. They are never written to the
outbox, delivery log, test output, or exception text. This is a reference-based
fail-closed design because the repository has no encryption-key lifecycle or
KMS integration; it does not claim application-managed encryption at rest.

## HTTPS egress boundary

Webhook, Slack, Discord, and Telegram deliveries permit HTTPS only. On every
delivery attempt the worker canonicalizes the endpoint hostname to its ASCII
IDNA form, resolves A and AAAA records, and validates the complete answer set
before opening a socket. An empty, malformed, or oversized answer set fails
closed. Any private, loopback, link-local, multicast, unspecified, reserved,
shared, IPv4-mapped IPv6, IPv6 transition, scoped, or otherwise non-global
address rejects the complete set; a public/private mixed answer never falls
back to its public member.

After validation, the worker connects directly to one validated numeric address
and does not resolve the hostname again during that connection. The canonical
original hostname remains the TLS SNI/certificate-verification name and HTTP
`Host` authority. HTTP redirects are never followed, including redirects to
another HTTPS origin. A later outbox retry performs a fresh full resolution and
validation, preventing DNS rebinding between validation and use. The channel
socket timeout bounds connect, TLS, request, and response-header inactivity;
the lease-safe absolute delivery deadline also covers credential lookup and a
blocking system resolver. SMTP retains its independently documented TLS and
deadline behavior and is not routed through the webhook egress policy.

## Routing and commands

Routes are evaluated by descending numeric priority and then route ID. A match
selects its enabled channels. `continue=false` stops evaluation; `continue=true`
unions subsequent matching channels. The per-channel delivery identity is:

`SHA-256(event idempotency key + NUL + channel ID + NUL + purpose)`.

Run a bounded delivery batch from a separate network-enabled service or timer:

```sh
python3 ops/alert_delivery.py \
  --config /etc/monitor/alert-delivery.json \
  --db /var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite \
  drain --worker-id monitor-delivery-1 --max-items 10 \
  --max-runtime-seconds 45
```

Enqueue a delivery-only test, then run the worker:

```sh
python3 ops/alert_delivery.py --config /etc/monitor/alert-delivery.json \
  --db /var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite \
  test --channel slack-operations --request-id change-1234 \
  --message "Pre-change notification test"
```

Test rows have `purpose=test`, use separate counters, and do not enter rule
state, `rule-alerts.jsonl`, or incident statistics. `status` prints only bounded
state/counter totals; `delivery_log()` exposes channel ID, purpose, attempt,
timestamps, outcome, response code, and fixed error code, never payloads or
remote response bodies.
Network delivery attempts are numbered from 1. Audit-only queue rejection or
eviction records use attempt `0`, so they cannot replace a prior retry attempt.

## Systemd operation

Start from `ops/rules/alert-delivery.example.v1.json`, enable only reviewed
channels and routes, and install it as
`/etc/monitor/alert-delivery.json` owned by root without group/world write bits.
Create `/etc/monitor/secrets` as root mode `0700`; keep every file-provider
secret root-owned, single-link, and mode `0400` or `0600`. If environment
references are used, make `/etc/monitor/alert-delivery.env` a root-owned,
single-link mode-`0600` regular file. Never put a secret value on an
`ExecStart` command line or in the delivery JSON.

Enable the recurring worker after the collector and configuration are
installed. The collector installer preserves an existing timer's enabled and
active state; a first install deliberately leaves outbound delivery disabled:

```sh
systemctl enable --now monitor-alert-delivery.timer
systemctl start monitor-alert-delivery.service
systemctl list-timers monitor-alert-delivery.timer
journalctl -u monitor-alert-delivery.service --since today
```

The service is skipped without both the configuration and an initialized
outbox. The collector creates and enqueues into that outbox without network
access; the next timer activation drains it. Each oneshot handles at most ten
rows, stops taking new leases after 45 seconds, and cannot overlap another
activation of the same systemd service. If the five-minute systemd limit stops
an in-flight transport, its existing lease eventually expires and the next
worker retries it under the same attempt cap and idempotency key.

The outbox is mode `0600` and owned by the root collector, so the delivery
service also uses UID 0. It has an empty capability set, `NoNewPrivileges`, only
`AF_UNIX`, `AF_INET`, and `AF_INET6`, and an isolated mount view. That view
contains the delivery JSON, secret directory, TLS/DNS inputs, and the private
outbox directory; only the outbox directory is writable. The collector unit
remains restricted to `AF_UNIX` and never invokes the worker.

Disabling the timer does not remove queued or completed rows. Inspect bounded,
payload-free counters with:

```sh
sudo /usr/bin/python3 /usr/local/lib/monitor-collector/alert_delivery.py \
  --config=/etc/monitor/alert-delivery.json \
  --db=/var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite status
```

## Architecture and recovery

The implementation uses only Python's standard library and SQLite, so its data
format and behavior are the same on Linux amd64 and arm64/Raspberry Pi. SQLite
uses full synchronous commits and a finite DELETE journal. Batching and bounded
history limit writes, but alert transitions, retry attempts, and lease recovery
still cause durable writes; place `/var/lib/monitor-export` on storage with an
appropriate endurance and backup policy. Evaluation remains functional if
configuration, SQLite, the timer, or the delivery module is unavailable;
retained recent events are retried on the next evaluation inside the replay
window, while already queued work stays durable until a worker can process it.
