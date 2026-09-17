# Hourly mail and immediate observations

Current resource/HTTP/SSH policy and deployment notes are in
[the 2026-09-14 remediation record](monitoring-policy-remediation-2026-09-14.md).
Its thresholds and one-minute synthetic cadence supersede the earlier noise
policy examples below. `notification_policy.py` is installed with the producer;
entry/recovery rules and resource cards use that shared policy. External host
monitoring is not configured, and hourly text states this limitation explicitly.

`ops/notification_reports.py` exposes:

```python
produce_notifications(
    output_dir: Path, now: datetime, *,
    current: Mapping | None = None,
    evaluation: Mapping | None = None,
    delivery_config_path: Path | None = None,
    traffic_available: bool | None = None,
) -> dict
```

The collector calls it after committing current metrics, generic logs, and rule
evaluation. Pass the collector's `traffic_available` result so a successful
zero-request interval is distinguished from unavailable HTTP input. It does not
read SMTP credentials or open sockets. Install `notification_reports.py`,
`security_signals.py`, `notification_policy.py`, `notification_visuals.py` and `email_visuals.py` alongside
the existing collector modules; the existing
`monitor-alert-delivery.timer`/worker drains their rows.

The delivery configuration must enable an SMTP channel and routes accepting
`info`, `warning`, `critical`, and both `firing` and `resolved` transitions.
Recipient and sender configuration remains in the existing owner-controlled
delivery JSON; the SMTP password remains a send-time secret reference. There is
no recipient, credential, URL, username, IP address or raw log content in the
public report status. Reports select SMTP channels only. Excluded workload
records are removed before signal evaluation or mail construction, and the
delivery boundary rejects excluded targets too.

## Schedule and durability

A healthy report is queued once per UTC hour, at the first collector run in
that hour. The mail is written in Korean with KST timestamps and covers current
CPU, memory, temperature, load, pressure, TCP retransmissions, disk capacity,
reboot requirement, active rules, immediate signals, recent HTTP/network rule
transitions and source coverage. Historical short RCU delays are identified as
history. Stale metrics are not described as current healthy readings. Downtime
does not cause a backlog of hourly reports to be recreated; the next current
hour is reported when collection returns.

The producer checkpoint, current incident states, and queue inserts commit in
one transaction in the existing delivery SQLite database. An unchanged warning
does not enqueue every minute. Discrete critical failures (availability, OOM,
current power failures and kernel faults) enqueue immediately. Resource warnings
require three distinct observations spanning at least 120 seconds; resource
critical escalation requires two spanning 60 seconds. Continuous warning-level
breaches remain continuous when severity fluctuates. Synthetic latency requires
two actual successful probe observations spanning at least 240 seconds. Both
detection and recovery use the original `checkedAt`. Two distinct healthy source observations
establish recovery, and an episode that never qualified for mail has no recovery
mail. Repeated warning episodes have a durable 15-minute cooldown; a new critical
escalation can still notify. Discrete critical availability failures are not
subject to this cooldown. Reboot and certificate maintenance notices retain their
single-episode notification behavior. Single refused SSH logins remain visible
in local detections (and hourly reports while active); immediate SSH mail starts at five observations
in five minutes, with the existing critical threshold of twenty.
Missing/null metrics, unavailable sources and repeated snapshots cannot prove
recovery. SSH conditions clear after their five-minute observation window plus
the two fresh recovery samples. These recoveries describe the observation
condition, not proof that an attempted attack succeeded or was remediated.

Queue-full drops do not consume the hourly slot or signal notification
checkpoint. Never-sent rows dropped or evicted for capacity can be admitted
again with the same event/channel identity when space returns, including if
only their attempt-zero audit remains. Successful, leased and attempted rows
retain ordinary deduplication/retry semantics. Current hourly and active signal
rows are checked for later capacity eviction. Pending recovery notifications
are retained across queue pressure, including recoveries admitted and subsequently
evicted before any delivery attempt. A fresh active rule can notify on SMTP
activation even when its ready opening event is older than the ordinary replay
window; suppressed/silenced state is not promoted to ready.

Transport remains at least once: SMTP acceptance followed by a worker crash
before the durable success checkpoint can produce a duplicate. The existing
stable Message-ID, timeout, bounded retry and audit behavior are unchanged.
The public `lastQueuedAt` means queued, not delivered.

## Card-based email and trend graphs

SMTP mail includes a responsive, light card layout and a complete plain-text
alternative. Hourly cards show the latest CPU, memory, temperature, maximum
disk use, TCP retransmission ratio and maximum HTTP probe response time.
The subject, plain-text summary and HTML heading share one hourly assessment.
Only qualified unresolved incidents raise warning/critical incident severity;
single raw peaks do not. Cards are explicitly labeled observations and cannot
raise the overall verdict by themselves. A card's color never exceeds either
its current measurement range or the corresponding confirmed incident level.
Missing or stale values are not presented as zero or healthy. Immediate mail
puts the condition, first observation and suggested checks in a shorter layout.

Hourly TCP cards and text use the same bounded segment-count window as immediate
TCP detection, never the instantaneous raw ratio. Insufficient samples remain
unavailable. Routed-out alternate TCP/HTTP latency rule paths do not reintroduce
their old verdict through the hourly report. Rule episodes require ready
notification authority; public `firing` rows alone do not establish it.

Qualification is independent of SMTP success or resend cooldown. Confirmed
incidents survive missing observations until recovery is verified. After a
critical resource condition improves into the warning range, two distinct fresh
warning observations spanning at least 60 seconds lower its confirmed report
severity to warning. Cached values and observation gaps cannot advance that
confirmation. Historical mail severity does not restore the old critical level;
genuine renewed critical observations must qualify again. Full recovery still
requires the existing two fresh clear samples. The existing once-per-episode
immediate notification/deduplication policy is unchanged.

Read-only hourly previews reuse the private producer qualification and TCP
checkpoint through a query-only SQLite connection. They do not infer qualification
from the truncated public detections list, create an outbox, update checkpoints,
load credentials or send mail. When that authority is unavailable, the preview
reports a coverage limitation instead of guessing a critical or healthy state.
The public report schema and existing stored delivery payloads are unchanged.

Two inline PNG charts show CPU/memory and TCP over the preceding hour. Thirty
two-minute buckets use CPU/memory maxima and the TCP ratio
`100 * sum(retransmitted segments) / sum(outbound segments)`. Missing samples,
reset counters and zero denominators remain gaps. CPU/memory use a 0–100% scale;
TCP uses a scale starting at zero with an upper bound of at least 5%.
KST time bounds, observed-bucket counts and numeric summaries remain readable
when images are hidden. Chart summaries describe the bucketed observations,
not the unsampled seconds between collector runs.

The producer freezes a validated, data-only visual model in the outbox; the
delivery worker does not need access to history files. Only the one or two UTC
history dates intersecting the hour are read, with bounded regular-file checks.
The renderer uses Python's standard library, table/inline-CSS layout and
CID-attached PNGs, with no JavaScript, SVG, remote images, fonts or tracking.
The only link is the fixed Monitor dashboard. Each model is limited to 4 KiB,
HTML to 60 KiB and each of at most two PNGs to 200 KiB. If a visual cannot be
built or rendered, the existing text report remains available. Visual data is
omitted when needed to preserve the existing 16 KiB outbox payload limit.
Delivery identity, credentials, retry policy and schedule are unchanged.

An explicitly marked design sample can be queued through the same configured
SMTP channel without consuming a production hourly slot:

```sh
sudo python3 /usr/local/lib/monitor-collector/alert_delivery.py \
  --config=/etc/monitor/alert-delivery.json \
  --db=/var/lib/monitor-export/.state/alert-delivery/alert-delivery.sqlite \
  test --channel=CHANNEL_ID --request-id=UNIQUE_DESIGN_SAMPLE \
  --message='카드형 보고서 디자인 확인용 시험 메일입니다.' --preview-hourly
```

Reuse the same request ID when checking a sample to retain test deduplication.
This command enqueues a real email; local unit and browser previews do not.
Stop the collector and delivery timers and let any running oneshots finish
before replacing these modules. Keep the upgraded delivery reader during a
producer rollback: older workers reject the optional `presentation.visual`
field. Do not restore an older worker against queued rich payloads without a
separately verified compatibility conversion or successfully draining them.
The general installer's automatic code rollback also has this limitation if a
new producer has already queued rich mail before a later timer-start failure.
For this rollout only the four mail modules were replaced while both timers
were paused and their running oneshots had completed; the code commit point
preceded restarting either producer or worker. Existing data was not restored
from an older database backup, which could otherwise replay accepted mail.

## Immediate coverage

All ready warning/critical rule transitions keep their original delivery IDs.
Additional immediate conditions use current reviewed exports:

| Source | Observation thresholds |
| --- | --- |
| SSH | AllowUsers denial, invalid-user pre-auth close, failed authentication; first episode warning, at least 20 observations in five minutes critical repeated-pattern signal |
| HTTP requests | At least 20 4xx and 20% share warning (attack unconfirmed); any 5xx warning, critical at 20 errors or at least 5 errors/20 requests and 5% share; slow share 10%/40% requires at least 20 requests and 3 slow responses, while max response 5/15 seconds still qualifies |
| Host | CPU/memory 75%/90%, temperature 75/85°C, dashboard PSI/error/drop thresholds, load, disk/inode 75%/90%, current power/link/SSH-listener failures, reboot-required marker |
| TCP | Weighted retransmission 1%/5% warning/critical over up to five minutes, at least three distinct counter intervals spanning two minutes, and at least 1,000 outbound segments or 20 retransmissions; sparse high ratios remain insufficient evidence |
| Synthetic | DNS/timeout/TLS/HTTP failure critical; latency 1/3 seconds; certificate expiry within 30/7 days |
| Containers | Fresh state/health failures, OOM, restart delta 1/3, memory/PID limit use 80%/90%, CPU throttling 20%/50%, interface errors |
| Kernel/clock | Supported kernel observations whose latest event occurred within five minutes; clock explicitly unsynchronized or absolute drift 15/60 seconds |

SSH detection consumes only redacted `journal:ssh`/`journal:sshd` records from
the reviewed generic-log export. It never reads arbitrary auth log paths.
Duplicate identical sanitized records are ignored, and failure categories are
combined using their maximum count to avoid counting a denial plus pre-auth
close twice. Counts are conservative observations, not unique attackers or
verified sessions. Firewall multicast records are not classified as attacks.
HTTP detection uses service response counts, not request bodies or URL scans;
it cannot determine exploit success.

The TCP projection is private to notifications: raw current/history measurements
and charts remain unchanged. Exact `OutSegs`/`RetransSegs` counters, boot identity,
source timestamps and a bounded eight-entry window are checkpointed together with
the outbox. Reset, stale, missing and backward observations cannot synthesize a
healthy zero. Repeated observations never add another interval. When traffic is
low, sustained retransmissions can still qualify through the absolute count floor.

The production Gmail route uses optional `excludeRuleIds` for
`TcpRetransmissionHigh` and `HttpLatencyHigh`, whose mail is owned by the qualified
additional signal path above. Their local rule evaluations/history remain intact;
other rules and separately configured routes retain delivery. Install the upgraded
producer and delivery reader before enabling these exclusions. The ordinary rule
evaluator also preserves original synthetic sample timestamps in private state,
so it cannot mistake cached probe results for repeated checks.

Reads are bounded to 16 MiB documents and the final 2 MiB/20,000 records of log
exports. Up to 128 immediate signal groups and 32 public recent entries are
retained; reports and mail envelopes have byte limits. Public source status
distinguishes fresh, partial, stale and unavailable observations. A source with
no new SSH records can still be healthy; source failure cannot be interpreted
as absence of attempts.

The public `notification-reports.json` includes overall producer status,
hourly/immediate enqueue counters, last queued hour, source health, bounded
detection evidence and delivery counts. `delivery.sent` is SMTP acceptance as
recorded by the worker, not inbox receipt; `delivery.failed` includes final
failures and dropped rows. `lastAttemptAt` and `lastOutcome` are audit readback.
No enabled SMTP channel gives `status=disabled` while local detections continue.
Unsafe input/configuration/persistence gives fixed `status=error` without
exception contents. This local producer cannot send when its host or collector
is fully down; that requires an independent external monitor.

## Verification

```sh
python3 -m unittest ops.tests.test_notification_reports \
  ops.tests.test_security_signals ops.tests.test_notification_coverage \
  ops.tests.test_alert_delivery ops.tests.test_delivery_contract \
  ops.tests.test_notification_visuals ops.tests.test_email_visuals \
  ops.tests.test_email_delivery_visuals
```

Tests use temporary data, a fake SMTP client and crash/queue-pressure injection;
they do not send external mail.
