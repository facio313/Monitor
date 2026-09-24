# Notification reports and immediate observations

The current schedule, single-owner routing, SSH policy and unsupported-observation
contracts are defined in
[the 2026-09-24 remediation record](alert-policy-remediation-2026-09-24.md).
It supersedes older policy text in this document. Public `hourly` fields,
`HourlyReport` rule IDs and hourly-named preview functions remain compatibility
names; they do not change the once-daily KST schedule. Earlier resource-policy
background remains in
[the 2026-09-14 remediation record](monitoring-policy-remediation-2026-09-14.md).
`notification_policy.py` is installed with the producer; entry/recovery rules
and resource cards use that shared policy.

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

A daily report is queued once per KST day, at the first notification-producing collector run on or
after the 09:00 KST boundary. The mail is written in Korean with KST timestamps
and covers current CPU, memory, temperature, load, pressure, TCP retransmissions,
disk capacity, reboot requirement, active rules, immediate signals, recent
HTTP/network rule transitions and source coverage. Historical short RCU delays
are identified as history. Stale metrics are not described as current healthy
readings. Downtime does not cause a backlog of daily reports to be recreated;
the current day is reported when processing returns after its 09:00 boundary.

The producer checkpoint, current incident states, and queue inserts commit in
one transaction in the existing delivery SQLite database. Daily checkpoints are
stored as `lastDailySlot` and `lastDailyQueuedAt`. A legacy `lastHour` is migrated
only when it exactly matches the current daily slot; its queue timestamp is copied
only when valid. Unrelated hourly values are not accepted as proof. Before 09:00 KST
there is no current-day slot and no previous-day catch-up mail. An unchanged
warning does not enqueue every minute. Discrete critical failures (availability,
OOM, current power failures and kernel faults) enqueue immediately. Ordinary
host-resource warnings require five distinct observations spanning at least 240
seconds, and critical escalation requires three spanning at least 120 seconds.
Temperature warning is the deliberate shorter exception at three observations
over at least 120 seconds. Continuous warning-level breaches remain continuous
when severity fluctuates. I/O PSI `some` and `full` share one incident: either
entry threshold can open it, while both recovery thresholds and a complete
metric pair are required to clear it. Synthetic latency requires
two actual successful probe observations spanning at least 240 seconds. Both
detection and recovery use the original `checkedAt`. Two distinct healthy source observations
establish recovery, and an episode that never qualified for mail has no recovery
mail. Repeated warning episodes have a durable 15-minute cooldown; a new critical
escalation can still notify. Discrete critical availability failures are not
subject to this cooldown. Reboot and certificate maintenance notices retain their
single-episode notification behavior. Single refused SSH logins remain visible
in local detections (and the daily report while active); immediate SSH mail starts
at five distinct log rows in five minutes. Twenty rows change the classification
to a repeated pattern but remain warning severity. An accepted public-key login
is suppressed only when its exact account
and key-fingerprint pair is trusted; other accepted logins notify immediately.
SSH security conditions do not send recovery mail.
Missing/null metrics, unavailable sources and repeated snapshots cannot prove
recovery. SSH conditions clear after their five-minute observation window plus
the two fresh recovery samples. These recoveries describe the observation
condition, not proof that an attempted attack succeeded or was remediated.

Queue-full drops do not consume the daily slot or signal notification
checkpoint. Never-sent rows dropped or evicted for capacity can be admitted
again with the same event/channel identity when space returns, including if
only their attempt-zero audit remains. Successful, leased and attempted rows
retain ordinary deduplication/retry semantics. Current daily and active signal
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
alternative. The validated, bounded detailed report is also included as escaped
HTML, so active rules and source-coverage limits are not lost in rich-mail clients.
Daily cards show the latest CPU, memory, temperature, maximum
disk use, TCP retransmission ratio and maximum HTTP probe response time.
The subject, plain-text summary and HTML heading share one daily assessment.
Only qualified unresolved incidents raise warning/critical incident severity;
single raw peaks do not. Cards are explicitly labeled observations and cannot
raise the overall verdict by themselves. A card's color never exceeds either
its current measurement range or the corresponding confirmed incident level.
Missing or stale values are not presented as zero or healthy. Immediate mail
puts the condition, first observation and suggested checks in a shorter layout.

Daily TCP cards and text use the same bounded segment-count window as the
canonical TCP rule, never the instantaneous raw ratio. Insufficient samples
remain unavailable. Diagnostic direct TCP/HTTP paths do not own mail or
reintroduce a duplicate verdict through the daily report. Rule episodes require
ready notification authority; public `firing` rows alone do not establish it.

Qualification is independent of SMTP success or resend cooldown. Confirmed
incidents survive missing observations until recovery is verified. After a
critical resource condition improves into the warning range, two distinct fresh
warning observations spanning at least 60 seconds lower its confirmed report
severity to warning. Cached values and observation gaps cannot advance that
confirmation. Historical mail severity does not restore the old critical level;
genuine renewed critical observations must qualify again. Full recovery still
requires the existing two fresh clear samples. The existing once-per-episode
immediate notification/deduplication policy is unchanged.

Read-only report previews reuse the private producer qualification and TCP
checkpoint through a query-only SQLite connection. They do not infer qualification
from the truncated public detections list, create an outbox, update checkpoints,
load credentials or send mail. When that authority is unavailable, the preview
reports a coverage limitation instead of guessing a critical or healthy state.
The public report schema and existing stored delivery payloads are unchanged.
The dashboard separates current detections from collapsed resolved history,
labels pending (including leased/sending) and retry as current queue state and sent/undelivered terminal outcomes
(final failure or queue exclusion) as cumulative,
and displays the latest worker outcome explicitly.

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
The renderer itself does not change delivery identity, credentials or retry policy.

An explicitly marked design sample can be queued through the same configured
SMTP channel without consuming a production daily slot:

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
| SSH | Failures/denials stay local from the first row; mail starts at five distinct rows in five minutes. Twenty changes the kind to a repeated pattern but not to critical. An accepted login not matched by an exact trusted account/key pair sends an immediate warning |
| HTTP requests | At least 20 4xx and 20% share warning (attack unconfirmed); any 5xx is a warning, and critical requires either 3 errors at 50% share or 5 errors at 5% share. Slow responses require at least 20 requests and 3 slow rows: 10%/40% share gives warning/critical, while a 5s/15s maximum also qualifies |
| Host | Shared policy: CPU 90% warning only; memory 80%/90%; temperature 80/85°C; I/O PSI `some` 20% or `full` 8% as one warning-only incident; load 1.5/core; disk 85%/95%; inode 85%/90%; plus current power/link/SSH-listener failures and reboot-required marker |
| TCP | Canonical rule firing at 5% over five distinct samples spanning 240 seconds; recovery at 1% or lower over three samples spanning 120 seconds; sparse evidence remains insufficient |
| Synthetic | DNS/timeout/TLS/HTTP failure critical; latency 1/3 seconds; certificate expiry within 30/7 days |
| Containers | Fresh state/health failures, OOM, restart delta 1/3, memory/PID limit use 80%/90%, CPU throttling 20%/50%, interface errors |
| Kernel/clock | Supported kernel observations whose latest event occurred within five minutes; clock explicitly unsynchronized or absolute drift 15/60 seconds |

SSH detection consumes only redacted `journal:ssh`/`journal:sshd` records from
the reviewed generic-log export. It never reads arbitrary auth log paths.
Duplicate identical sanitized records are ignored. Each remaining generic row
enters at most one failure category, and those categories are summed. Counts are
log-row observations, not unique attackers or
verified sessions. Firewall multicast records are not classified as attacks.
HTTP detection uses service response counts, not request bodies or URL scans;
it cannot determine exploit success.

The TCP projection is private to notifications: raw current/history measurements
and charts remain unchanged. Exact `OutSegs`/`RetransSegs` counters, boot identity,
source timestamps and a bounded eight-entry window are checkpointed together with
the outbox. Reset, stale, missing and backward observations cannot synthesize a
healthy zero. Repeated observations never add another interval. When traffic is
low, sustained retransmissions can still qualify through the absolute count floor.

Canonical TCP, NIC, container, HTTP, TLS and synthetic rules are the sole mail
owners for their conditions. Diagnostic direct-signal state remains available
locally but does not enqueue duplicate mail. Route exclusions must not suppress
those canonical owners. The ordinary rule evaluator preserves original synthetic
sample timestamps in private state, so it cannot mistake cached probe results for
repeated checks.

Reads are bounded to 16 MiB documents and the final 2 MiB/20,000 records of log
exports. Up to 128 immediate signal groups and 32 public recent entries are
retained; reports and mail envelopes have byte limits. Public source status
distinguishes fresh, partial, stale and unavailable observations. A source with
no new SSH records can still be healthy; source failure cannot be interpreted
as absence of attempts.

The public `notification-reports.json` includes overall producer status,
legacy-named `hourly`/immediate enqueue counters, the last queued daily slot,
source health, bounded detection evidence and delivery counts. Active detections
are retained ahead of resolved history in the 32-item public list; the dashboard
marks the limit when reached because additional history may exist.
`delivery.sent` is SMTP acceptance as
recorded by the worker, not inbox receipt; `delivery.failed` includes final
failures and dropped rows. `lastAttemptAt` and `lastOutcome` are audit readback.
No enabled SMTP channel gives `status=disabled` while local detections continue.
Unsafe input/configuration/persistence gives fixed `status=error` without
exception contents. This local producer cannot send when its host or collector
is fully down. The independent GitHub Actions probe checks the public readiness,
TLS and SSO boundary on a nominal five-minute schedule, persists one issue per
outage and closes it after recovery. Scheduled runs are not an SLA, the probe
does not send SMTP, and GitHub Actions or Issues downtime remains a coverage gap.

## Verification

```sh
python3 -m unittest ops.tests.test_notification_reports \
  ops.tests.test_security_signals ops.tests.test_notification_coverage \
  ops.tests.test_alert_delivery ops.tests.test_delivery_contract \
  ops.tests.test_notification_visuals ops.tests.test_email_visuals \
  ops.tests.test_email_delivery_visuals ops.tests.test_daily_report_schedule \
  ops.tests.test_email_visuals_detail ops.tests.test_notification_visuals_security \
  ops.tests.test_io_pressure_policy ops.tests.test_ssh_mail_threshold \
  ops.tests.test_detection_history_priority
```

Tests use temporary data, a fake SMTP client and crash/queue-pressure injection;
they do not send external mail.
