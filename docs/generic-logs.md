# Generic log collection and explorer

Monitor collects only explicitly reviewed file and journald sources. Raw input
never enters the web container: the root collector reads a bounded tail,
redacts credentials and common personal identifiers before parsing, admits a
finite priority-aware batch, and publishes one reduced schema under
`/var/lib/monitor-export`.

## Configure sources

The installed allowlist is `/etc/monitor-collector/log-sources.json`. Start
from `ops/log-sources.example.json`. The file must be a root-owned, regular,
single-link JSON file without group/other write permission. Its schema is
exact, source IDs are unique and bounded, and file paths must remain below
`/var/log` or `/run/log`. Journald sources require one exact systemd unit.
Unknown fields, raw container IDs, secret-labelled dimensions, unsafe paths,
and more than 64 sources fail closed.

Each source chooses a fixed priority (`security`, `incident`, `normal`, or
`debug`), parser (`auto`, `json`, `logfmt`, `syslog`, or `plain`), bounded
multiline mode, and at most 16 reviewed structured fields. The current
host-side acquisition adapters are `file` and `journald`; `docker` is reserved
in the normalized/API schema but is not accepted by this root collector. That
prevents the web service from receiving a Docker socket or arbitrary container
metadata.

After editing the allowlist:

```sh
sudo chmod 0600 /etc/monitor-collector/log-sources.json
sudo chown root:root /etc/monitor-collector/log-sources.json
sudo systemctl restart monitor-collector.service
```

Adding or removing reviewed sources migrates matching private cursors. A
pending transaction created under the prior allowlist is replayed before that
migration, so a config deployment cannot silently skip an acknowledged tail.

## Privacy and bounds

Redaction runs before JSON/logfmt/syslog parsing. It removes credential-bearing
keys and values, bearer/JWT and common provider tokens, private-key blocks, URL
userinfo, email addresses, IP addresses, Korean mobile numbers, and
Luhn-valid payment-card candidates. Only fixed-cardinality metadata and
explicitly allowlisted scalar fields survive. Invalid UTF-8 is replaced; raw
input, process arguments, environment, arbitrary journald metadata, and full
container IDs are never stored.

Sensitive PEM armor is tracked per reviewed source before multiline grouping.
No physical `BEGIN ... PRIVATE KEY/SECRET`, payload, or matching `END` line is
written: a completed block produces only `[REDACTED_PRIVATE_KEY]`. The private
state retains only a bounded label and line/byte counters, never payload bytes,
so a block split across collector runs remains suppressed without affecting
another source. Unterminated blocks fail closed through the normal multiline
line/byte ceilings. After overflow, plausible Base64 payload, blank lines, and
PEM encryption metadata remain suppressed, while the first ordinary line
recovers collection; consequently an ordinary Base64-only diagnostic line can
be conservatively suppressed only while that source is recovering from an
unterminated/oversized block, an initial tail, an acquisition gap, or a v1
cursor migration. Initial file/journald tails and file rotation/backlog/
copytruncate gaps enter this recovery mode before their first retained line, so
a `BEGIN` line skipped outside the acquisition window cannot expose its body.

`monitor-log-redaction-v2` intentionally rejects v1 public rows. On the first
collector run after upgrade, the entire v1 generic-log snapshot and any v1
pending transaction are durably cleared rather than reprocessed: an orphaned
Base64 row cannot be proven unrelated after its older `BEGIN` row has aged out.
Existing cursors are preserved when valid, and every migrated source enters the
bounded recovery mode before collection resumes.

Per source and globally, input bytes, lines, line/event size, multiline depth,
events per minute, command output, and wall time are finite. One run has a
16 MiB aggregate raw-input ceiling. It divides that ceiling equally across all
configured sources (up to the 2 MiB per-source ceiling), so every reviewed
source gets a deterministic share and a busy source cannot starve a peer.
Unused shares are not reassigned within the run.

Normalization admits at most 2,000 records and 16 MiB of serialized JSONL per
run. It processes security and incident sources before normal/debug sources,
then restores configured source/event order in the published rows. This keeps
the existing priority policy without retaining an unbounded all-source
candidate list. Events beyond the per-run count/byte ceilings or the persistent
10,000-event shared window increment the existing `globalQuota` drop counter;
per-source window overflow increments `sourceQuota`, and aggregate input
overflow increments `inputByteLimit`. The packaged 192 MiB service budget is
therefore above explicit input and admitted-output ceilings instead of relying
on 64 independent 2 MiB allocations. Raw acquisition references are released
before retained history is loaded and serialized for the durable commit.

The durable store, pending-commit path, and HTTP reader have a separate hard
ceiling of 20,000 records and 16 MiB; the installed defaults use that ceiling
with 30-day retention. One collector run spends at most 15 seconds across
journald commands.

The first journald read intentionally tails the newest `maxLines` entries.
After a cursor exists, each read instead consumes the oldest unseen entries in
order and requests one lookahead entry. A lookahead marks the source truncated
but remains pending for the next run, so it is not counted as dropped; only
malformed or oversized rows increment the acquisition drop counter. The cursor
advances through the last emitted row or a row with a valid journal cursor that
was deliberately counted as malformed; this prevents a poison row from blocking
later entries. The same bounded cursor-only recovery applies to an oversized row,
including a command-output cut after the cursor. It never advances through the
lookahead. A journalctl execution failure is `failed/read_failed`, never healthy
`no_data`.

For an established file cursor, growth beyond the per-run byte budget is not
treated like an initial tail. The collector reads the bounded newest segment,
marks the source `truncated`/`output_limit`, and increments an acquisition-gap
sentinel because the exact number of skipped complete lines is no longer
recoverable. File cursors also retain a bounded SHA-256 guard over the bytes
immediately before the committed offset. A same-inode copytruncate/rewrite that
regrows past that offset fails the guard, rereads the bounded current file, and
surfaces the same explicit acquisition gap instead of silently skipping its
new prefix.

## Durable files and failure semantics

- `generic-logs.jsonl` is the reduced mode-`0640` record stream.
- `generic-log-sources.json` reports per-source fresh/no-data/truncated/
  unsupported/permission-denied/failed state plus drop counters.
- `.state/generic-log-state.json` is mode `0600` and contains only source
  cursors, quota counters, and bounded raw-free per-source PEM suppression state.
- `.state/pending-generic-log-commit.json` stages the base/final digests,
  reduced rows, public status, and next private state. Replay publishes records,
  then status, then cursors without duplicates. The marker is fully written and
  file-synced under a private temporary name before Linux
  `renameat2(RENAME_NOREPLACE)` publishes it atomically under one name; the
  publication is directory-synced and cannot leave a two-link crash artifact.
  A concurrently created or pre-existing marker is preserved and fails closed.
- `generic-log-collection-error.json` is a strict, non-secret marker for unsafe
  configuration or persistence failure. A successful transaction clears it.

The HTTP reader derives the expected public-file UID from the stable,
canonical, non-group/world-writable export root before checking every snapshot file. This
keeps ownership validation intact when a rootless user namespace represents
host `root` with its overflow UID inside the container; an unsafe or changing
root still fails closed as `collection_error`.

The generic-log subsystem is isolated from host telemetry. An unsafe source is
visible as a per-source degraded state; an unsafe configuration or durable
store is `collection_error`; neither prevents `current.json` and host history
from being refreshed.

## API and UI

Authenticated clients use `GET /monitor/api/generic-logs`. Supported query
parameters are `limit`, `cursor`, `text`, `from`, `to`, and repeated
`sourceId`, `sourceKind`, `priority`, and `severity`. Unknown, nested,
duplicate-single, malformed, or unbounded values return `400`. Text matching is
bounded literal search over reduced fields. Pages contain at most 200 records
and cursors are bound to a digest of the current stream; an append makes an old
cursor explicitly `stale` instead of mixing snapshots.

The server revalidates the export root, owner, mode, link count, file identity,
size, and modification/change times on every request. One bounded LRU entry
then reuses the normalized, searchable, fixed-sort result for an unchanged
digest-bearing snapshot, avoiding a repeated 16 MiB read/parse/sort cycle.
Atomic replacement changes the snapshot identity and reparses it; a changed
digest preserves the existing stale-cursor response. Unsafe metadata, invalid
content/status, or a collection-error marker still fails closed and never
serves cached records. After authentication, the HTTP route additionally
permits at most 20 reads per minute for one proxy-resolved client IP and returns
`429 RATE_LIMITED` beyond that budget; rejected unauthenticated traffic cannot
consume an authenticated reader's allowance.

The Logs page shows collection health and per-source status before records,
supports keyboard-accessible filtering and row expansion, and distinguishes
no data, unsupported acquisition, permission denial, stale collection, and a
collection error. It does not display the removed decorative system-signal or
waveform language.
