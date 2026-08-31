# Central agent enrollment and ingest contract

This document defines the optional central-agent vertical slice for
Monitor.md 2-1, 11-3 through 11-6, 12-5 through 12-6, and the applicable
transport/storage portion of 13-4. The existing same-host collector and its
`local-file` snapshot remain independent. Central ingest is disabled unless
all production prerequisites are explicitly configured.

## Trust boundary

The Express process **does not terminate TLS and does not validate an X.509
chain itself**. A separately operated reverse proxy must:

1. terminate TLS using a private agent listener that requires a client
   certificate from the approved agent CA;
2. reject an invalid, expired, or revoked certificate before proxying;
3. remove every client-supplied `X-Portfolio-Edge-Secret` and
   `X-Monitor-*` header;
4. inject the agent listener's private `X-Portfolio-Edge-Secret`, sourced from
   `MONITOR_AGENT_EDGE_SECRET_FILE` and never from the SSO origin secret;
5. inject exactly `X-Monitor-mTLS-Verified: SUCCESS`, a lowercase 64-hex
   `X-Monitor-Client-Cert-SHA256`, and an RFC 3339
   `X-Monitor-Client-Cert-Not-After` derived from the verified certificate;
6. forward only to the loopback/private origin and apply request/time limits.

The application constant-time checks the agent-specific edge secret, validates the proxy
marker and certificate metadata, and binds the fingerprint to one agent. A
direct request, a forged marker without the edge secret, a fingerprint bound
to another agent, an expired certificate, and a revoked agent all fail closed
with distinct non-secret error codes.

Agent requests never use `X-Forwarded-For` for inventory or audit metadata,
even after mTLS proxy authentication. The application records only its socket
peer for this path, so an incomplete external header-sanitization policy cannot
let an agent forge those records.

Certificate signing and CRL/OCSP enforcement belong to the external PKI and
TLS proxy. Initial enrollment binds the already PKI-issued long-lived
certificate presented on that request; the application does not claim to
issue a PEM certificate. Renewal uses a new proxy-verified certificate plus a
chief-admin-issued one-use rotation token. Deploying this API without the
private mTLS listener and PKI does not satisfy mTLS end to end.

## Enablement and durable storage

Production enablement requires SSO mode and all of the following:

- `MONITOR_AGENT_INGEST_ENABLED=true`
- `MONITOR_AGENT_STATE_DIR` set to an explicit writable, persistent directory
  mounted only into the Monitor container; every directory is owned by the
  Monitor runtime uid with mode `0700`, every file is runtime-owned,
  single-link, and mode `0600`, and foreign ownership, hard links, symlinks,
  or broad permissions fail startup or admission. Before enablement, resolve
  the host bind source with `findmnt` and inspect it with `namei -l`: the source
  and every replace-capable ancestor must be owned by root or the single
  trusted deployment identity and must not be group/world writable. That host
  identity is part of the trusted computing base because it can also replace
  the container image and mounts; never share it with a portfolio workload
- a runtime-owned, single-link private `MONITOR_AGENT_EDGE_SECRET_FILE`
  containing at least 32 bytes and a value different from the SSO
  `MONITOR_EDGE_SECRET_FILE`
- `MONITOR_AGENT_STORAGE_KEYRING_FILE`, a runtime-owned, single-link
  mode-`0600` JSON file such as:

```json
{
  "schemaVersion": 1,
  "activeKeyId": "2026-08",
  "keys": {
    "2026-08": "<canonical base64 for exactly 32 random bytes>"
  }
}
```

The control state and every queued batch use AES-256-GCM with purpose-bound
AAD, a fresh nonce, and the active key ID. Writes use create-exclusive private
temporary files, `fsync`, atomic rename, and directory `fsync`. Enrollment
plaintext, raw machine IDs, supplied machine digests, certificate
fingerprints, host inventory, and telemetry do not appear in plaintext files.
The random enrollment secret is returned once; only its SHA-256 digest is in
the encrypted control state.

Agent routes trust only the agent edge secret; SSO identity/admin routes trust
only the SSO edge secret. Although both proxies inject the fixed
`X-Portfolio-Edge-Secret` header after stripping client input, their configured
values are domain-separated. Missing, short, or identical values make agent
ingress fail closed at startup.

For key rotation, add the new 32-byte key alongside the old key, change
`activeKeyId`, restart, and verify a control-state write. New files use the new
key; old queue entries remain readable with the retained key. Keep the prior
key offline and in the runtime keyring until the configured queue retention
has elapsed and recovery backups have been tested. Removing a key too early
causes an explicit fail-closed read error, not data replacement. Recovery
requires the encrypted state/queue and every referenced key; restore them to a
private directory before starting one Monitor writer. AES-GCM authenticates a
snapshot but does not make it rollback-proof. Never restore an older control
state over a live revision: stop ingress, reconcile every agent and revocation
performed after the backup, rotate affected certificates/tokens, and record an
operator-approved recovery epoch before reopening the listener.

Local mode cannot enable this path. Unit/integration tests have a code-only
`agentIngestTestFixture` dependency-injection seam that works only when
`NODE_ENV=test`; no environment variable enables that bypass.

## Enrollment and lifecycle API

All endpoints are under `/monitor/api` and return `Cache-Control: no-store`.
Chief-admin mutations additionally require the existing exact same-origin JSON
contract.

| Endpoint | Authentication | Result |
| --- | --- | --- |
| `POST /agents/enrollment-tokens` | canonical SSO chief-admin | Issues a random one-use token with `ttlSeconds` from 30 seconds through the configured maximum; plaintext is returned only here. |
| `POST /agent/enroll` | one-use token plus trusted proxy mTLS headers | Registers exact UUIDv4 host/agent IDs, keyed machine identity, install epoch, cadence, certificate binding, and bounded inventory. Exact retry is idempotent; host, machine, agent, and certificate collisions require operator reconciliation. |
| `POST /agent/heartbeat` | bound certificate | Updates receipt/observation times, inventory, version, lifecycle, cadence, and monotonic heartbeat sequence. Repeating a sequence is accepted only when the complete normalized heartbeat is unchanged. |
| `GET /agents` | SSO admin | Returns reduced fleet state and queue counters; never returns token hashes, machine identity keys, or certificate fingerprints. |
| `POST /agents/:agentId/certificate-rotation-tokens` | canonical SSO chief-admin | Creates a short-lived one-use token bound to one active agent. |
| `POST /agent/certificate-rotations` | new proxy-verified certificate plus rotation token | Atomically replaces the binding; the old fingerprint is rejected immediately. |
| `POST /agents/:agentId/revoke` | canonical SSO chief-admin | Idempotently revokes the agent using one fixed reason; changing the reason conflicts, and heartbeat, ingest, and renewal then fail. |

Do not put enrollment or rotation tokens in command arguments, URLs, unit
files, shell history, or process titles. An agent installer must read a token
once from a mode-`0600` file descriptor or standard input, erase that input
after a successful registration, and never log it. That installer/client
change is deliberately not simulated in the existing local collector.

The fleet statuses are `healthy`, `delayed`, `disconnected`, `maintenance`,
`inactive`, and `revoked`. For an active agent, delayed means older than the
greater of 90 seconds or two declared intervals; disconnected means older than
the greater of five minutes or five intervals; inactive means older than the
greater of one day or 60 intervals. Explicit maintenance/inactive and
revocation take precedence. Every response carries server time; clock-skew
errors expose the safe server time but not submitted telemetry.

## Batch contract, retry, and idempotency

`POST /agent/ingest` accepts strict JSON schema version 1 with `agentId`, a
UUIDv4 `batchId`, stable `sentAt`, first/last sequence, and bounded records.
Every `/agent/*` request must pass the header-only agent-edge-secret and mTLS
certificate check before Express reads or inflates its body. Enrollment,
heartbeat, and certificate rotation accept only identity-encoded JSON with a
mandatory `Content-Length` and an 8 KiB wire/body ceiling. Ingest additionally
supports the bounded gzip contract below. A fixed global gate admits at most
four agent bodies at once and at most one body per verified certificate. It
returns `503 AGENT_BODY_BUSY` with a one-second retry hint before reading an
excess body. A 15-second absolute body deadline closes an incomplete request
and releases its idempotent permit; a client cannot extend that deadline by
dripping bytes below the socket idle timeout. The permit remains held through
body parsing and request handling, while rate-limit identity is the verified
certificate fingerprint rather than a client-supplied forwarded IP.
Only identity and gzip content encoding are supported. Both compressed wire
size and inflated JSON size are bounded, `Content-Length` is mandatory, and
arbitrary fields/raw messages are rejected. All timestamps use RFC 3339 with
at most millisecond precision, and records are ordered by nondecreasing
sequence. Every batch is homogeneous: it contains metrics or events, never
both. This prevents a priority event queue entry from carrying metric payload
through the event reserve. A record contains only:

```text
kind = metric | event
metric, target = bounded low-cardinality names
observedAt, sequence
value = finite number for metric, otherwise null
severity = info | warning | critical for event, otherwise null
```

The batch key is `(agentId, batchId, canonical-content-digest)`. A retry keeps
the same body and `sentAt`; a past `sentAt` is valid throughout the configured
offline window, while a future value beyond skew is rejected. Record
idempotency is `(agentId, metric, target, observedAt, sequence)` plus a content
digest. An exact retry returns the prior acknowledgement. Reusing a batch or
record key with different content returns a conflict. Exact records repeated
in a later batch are counted and omitted. Lower but still retained sequences
are accepted as out of order and counted. Future records may differ from server
time only by the configured skew; batches/records older than the configured
offline window are rejected. This leaves the agent's
durable spool authoritative until it receives an acknowledgement.

For the packaged transport, `BATCH_TOO_OLD` and `DATA_TOO_OLD` are terminal
replay-window dispositions. The exact immutable envelope is atomically retained
in a bounded private quarantine, remains visible through reduced local status,
and requires an explicit batch-ID purge after operator inspection. It is never
silently deleted or retried forever. Other invalid or unknown responses remain
retryable.

Once a batch has been durably admitted, an exact retry returns its retained
receipt before timestamp admission is re-evaluated. Thus a lost HTTP response
cannot turn a previously accepted batch into `BATCH_TOO_OLD`; the guarantee
lasts until the configured receipt/queue retention expires. Likewise, a
consumed enrollment or rotation token may replay only its exact successful
request while its encrypted audit record remains; expiry still blocks every
first use.

The standalone package in `ops/agent_transport` batches reduced records,
gzip-compresses useful batches, keeps a bounded private disk spool, and retries
the same batch bytes and ID with timeout, exponential jittered backoff and
bounded `Retry-After`. Its exact configuration, enrollment handling, systemd
template and external dependencies are documented in
[`agent-transport.md`](agent-transport.md). The repository does not modify or
implicitly wire `ops/collector.py`; the distinct disabled-by-default producer
in [`agent-producer.md`](agent-producer.md) and the external PKI/mTLS deployment
must be installed, identity-bound, validated, and explicitly enabled before
telemetry is sent.

## Backpressure and failure isolation

Admission writes an encrypted batch to a finite disk queue before returning
202. Queue bytes, entries, idempotency records, records per batch, inflated
body size, retention, and control state are all finite. Control state has a
fixed 4 MiB UTF-8 plaintext ceiling and a 6 MiB encrypted-envelope read/write
ceiling. The server serializes state once, calculates the exact AES-256-GCM
base64url envelope size, and returns `429 CONTROL_STATE_BACKPRESSURE` before
creating plaintext/ciphertext Buffers or writing a new queue file when either
ceiling would be exceeded. Startup also rejects an envelope above 6 MiB or
decoded control plaintext above 4 MiB before accepting its state contract.
These state ceilings are independent of the configured per-batch and durable
queue limits.

A configured percentage of queue byte and entry capacity is reserved for event
batches; normal metric batches cannot consume it. Heartbeats bypass the
telemetry queue and persist only a bounded agent record, so metric saturation
does not hide liveness. The server never evicts an already acknowledged live
batch to admit another one. Full capacity returns 429 with `Retry-After`,
persists rejected batch/record counters when state capacity permits, and lets
the agent retain its local copy.

Expired queue entries and their idempotency window are removed together and
counted. Live receipts are cryptographically decoded and matched to their
queue entry at startup, admin read, and exact retry, so a missing or mismatched
durable file never produces a duplicate acknowledgement. Duplicate,
reordered, rejected, and expired counts are visible only through the admin
fleet endpoint. An invalid request or one revoked agent does not mutate other
agents. A runtime queue read failure closes the optional agent request with a
generic 503 while unrelated routes remain available; unsafe startup state or
permissions prevent service startup. A downstream time-series consumer
must process the encrypted queue with its own durable claim/ack contract before
this optional queue is treated as a long-term metrics database.

Deployments upgrading from the earlier mixed-batch format may retain already
authenticated, receipt-bound mixed queue entries until normal retention or a
downstream drain removes them. Startup validates those legacy entries against
the original invariant (any event means priority) and their receipts. An exact
lost-response retry may recover its retained acknowledgement, but every new or
changed API admission and every newly written queue entry remain strictly
homogeneous.

## Configuration limits

| Variable | Default |
| --- | --- |
| `MONITOR_AGENT_MAX_BATCH_BYTES` | `262144` compressed header bound and inflated JSON limit |
| `MONITOR_AGENT_MAX_RECORDS_PER_BATCH` | `500` |
| `MONITOR_AGENT_MAX_QUEUE_BYTES` | `33554432` |
| `MONITOR_AGENT_MAX_QUEUE_ENTRIES` | `256` |
| `MONITOR_AGENT_MAX_QUEUE_BYTES_PER_AGENT` | `8388608` |
| `MONITOR_AGENT_MAX_QUEUE_ENTRIES_PER_AGENT` | `64` |
| `MONITOR_AGENT_MAX_BATCH_RECEIPTS` | `4096` |
| `MONITOR_AGENT_MAX_BATCH_RECEIPTS_PER_AGENT` | `1024` |
| `MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS` | `100000` |
| `MONITOR_AGENT_MAX_IDEMPOTENCY_RECORDS_PER_AGENT` | `25000` |
| `MONITOR_AGENT_PRIORITY_RESERVE_PERCENT` | `20` |
| `MONITOR_AGENT_MAX_CLOCK_SKEW_SECONDS` | `300` |
| `MONITOR_AGENT_MAX_BACKFILL_AGE_SECONDS` | `604800` |
| `MONITOR_AGENT_QUEUE_RETENTION_SECONDS` | `604800` |
| `MONITOR_AGENT_MAX_ENROLLMENT_TTL_SECONDS` | `900` |
| `MONITOR_AGENT_CERTIFICATE_EXPIRY_WARNING_SECONDS` | `1209600` |

Invalid booleans or out-of-range numbers fail startup rather than silently
falling back. The repository's production Compose overlay does not mount an
agent state directory or enable this feature; the mTLS listener, CA policy,
keyring secret, persistent mount, and downstream queue consumer must be added
and verified as one deployment change.
