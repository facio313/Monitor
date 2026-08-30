# Central agent transport package

`ops/agent_transport` is the independent, Python-standard-library client for
the optional API in `docs/agent-ingest-contract.md`. It does not alter or
implicitly enable the same-host collector. A producer explicitly hands this
package reduced records; the package owns central identity, enrollment,
heartbeat, sequence allocation, batching, the offline spool, and mTLS HTTPS.

## Local durability and privacy

The configured state directory must be an owner-owned, non-linked mode-`0700`
directory beneath a trusted path chain. Every ancestor must be a real directory
owned by root or the effective service uid, and a group/world-writable ancestor
is accepted only when sticky-directory semantics protect the next trusted
child. The same rule is applied before creating the state directory, so the
client never creates state through a foreign or replaceable parent. The client
binds the state and spool directory identities at startup and revalidates both
before and after acquiring the state lock; a later rename, symlink substitution,
or real-directory rollback fails closed before state or spool traversal.

The package creates only mode-`0600` lock, state, enrollment, journal, and
immutable batch files beneath those directories. It rejects links, foreign
owners, broad modes, replaced directory identities, malformed envelopes,
changed machine identity, unknown spool files, and digest mismatches instead of
resetting state.

An enqueue operation first writes and fsyncs `pending-enqueue.json`, atomically
materializes each immutable `<UUIDv4>.batch`, advances and fsyncs sequence
state, then unlinks the journal and fsyncs its directory. Startup completes
that journal using its original batch IDs, `sentAt`, record sequences, content
encoding, and wire bytes. A retry sends those bytes unchanged. A batch is
unlinked and its directory fsynced only after a bounded 2xx JSON response says
`accepted=true`, returns the same `batchId`, accounts for every submitted
record, and includes a valid `serverTime`. A crash after the server accepts but
before local deletion therefore produces an exact server-side duplicate, not
a new batch.

The byte/entry limits include the enqueue journal while it coexists with new
batch files. Capacity failure does not evict an unacknowledged batch. Useful
bodies are gzip-compressed once with deterministic gzip metadata; bodies for
which gzip is not smaller use identity encoding. Retry state uses capped
exponential equal jitter. A valid `Retry-After` delta or HTTP date on 429 is a
lower bound on the next attempt, subject to the configured defensive
`retryAfterMaximumSeconds` ceiling.

Heartbeat has its own pending body and retry schedule. `run-once` attempts the
heartbeat before one due telemetry batch, so ingest backpressure never consumes
the heartbeat path or delays it to the telemetry retry time. A lost heartbeat
response retries the exact same sequence and normalized inventory.

Inventory is reduced to the nine fields accepted by
`server/agent-control.ts`: agent version, hostname, canonical IP addresses,
OS/Ubuntu/kernel/architecture, CPU model, and total memory. It does not collect
serial numbers, MAC addresses, raw machine IDs, process data, commands, paths,
or arbitrary text. The raw `/etc/machine-id` is read through a no-follow,
bounded descriptor and only a domain-separated SHA-256 digest is persisted or
sent.

## Exact configuration

Install `ops/agent-transport.example.json` as
`/etc/monitor-agent/transport.json`, replace every site-specific value, own it
by the service uid, and set mode `0600`. Extra, missing, mistyped, or
out-of-range fields fail closed. `baseUrl` must be an HTTPS URL whose path is
exactly `/monitor/api`; redirects and URL credentials are not supported.

The private key must be a root/service-owned, non-linked regular mode-`0600`
file. The client certificate and dedicated agent CA file must be regular,
unlinked, root/service-owned, bounded files that are not group/world writable.
The config, credentials, machine-identity, and state-directory paths must be
absolute and every directory component must be a real directory owned by root
or the effective service uid. A group/world-writable component is rejected when
another uid can replace its next component; a trusted sticky directory such as
`/tmp` remains usable for tests and explicit temporary workflows. The HTTPS
sink repeats credential validation before OpenSSL reopens the names, so a
directory-to-symlink substitution after an earlier check fails closed. The TLS
context requires the configured CA, hostname verification, and the configured
client certificate/key; it does not use an ambient proxy or ambient CA set.

Keep `maxBatchRecords` and `maxBatchBytes` at or below the corresponding server
admission values. Do not reduce either limit below a currently queued body.
`maxSpoolEntries` and `maxSpoolBytes` are local admission limits; choose them
within the server's offline replay window and the host's storage/endurance
budget. The client rejects values above 64 entries or 4 MiB so whole-spool
validation, decoded envelopes, and a coexisting crash journal remain inside the
packaged 96 MiB memory sandbox. The supplied example uses those maxima.

One `enqueue` accepts at most 2,000 normalized records and a 2 MiB canonical
record array. The CLI independently stops reading stdin at 2 MiB before JSON
parsing; this is not derived from the larger durable spool allowance. Batching
canonicalizes each normalized/sequenced record once for incremental byte
accounting, serializes each final batch once, and reuses canonical envelope
bytes when assembling the journal. Runtime and serialization work therefore
grow linearly with record count instead of repeatedly serializing every growing
candidate batch.

## Producer input and commands

Install the package directory without merging it into collector code:

```text
/usr/local/lib/monitor-agent/agent_transport/*.py
/etc/monitor-agent/transport.json              mode 0600
/etc/monitor-agent/client.key                   mode 0600
/etc/monitor-agent/client.crt                   not writable by group/world
/etc/monitor-agent/agent-ca.crt                 not writable by group/world
/var/lib/monitor-agent                          mode 0700
```

The `enqueue` command reads one JSON array of at most 2 MiB and 2,000 records on
standard input. Each producer record has exactly the following shape; the
transport allocates and persists sequence numbers itself:

```json
[
  {
    "kind": "metric",
    "metric": "host.cpu.percent",
    "target": "host/primary",
    "observedAt": "2026-08-31T00:20:00.000Z",
    "value": 12.5,
    "severity": null
  },
  {
    "kind": "event",
    "metric": "host.power.state",
    "target": "host/primary",
    "observedAt": "2026-08-31T00:20:01.000Z",
    "value": null,
    "severity": "warning"
  }
]
```

```bash
PYTHONPATH=/usr/local/lib/monitor-agent \
  python3 -m agent_transport --config /etc/monitor-agent/transport.json enqueue \
  < /run/monitor-agent/reduced-records.json

PYTHONPATH=/usr/local/lib/monitor-agent \
  python3 -m agent_transport --config /etc/monitor-agent/transport.json status
```

Record input deliberately has no raw-message or arbitrary-label escape hatch.
An external producer is responsible for reducing collector output to these
fixed metric/event fields. The repository does not wire `ops/collector.py` to
this package.

## Enrollment and token handling

The certificate and key must already have been issued by the external agent
PKI. Obtain a one-use token through the chief-admin endpoint over the
administrator path. Never put it in a command argument, URL, environment/unit
file, shell history, or process title.

Preferred provisioning writes the token into a private, non-shared directory
as one owner-owned mode-`0600` regular file, then supplies only its path:

```bash
PYTHONPATH=/usr/local/lib/monitor-agent \
  python3 -m agent_transport --config /etc/monitor-agent/transport.json enroll \
  --token-file /run/monitor-agent/enrollment-token
```

With no `--token-file`, `enroll` reads a bounded token from standard input.
The request, including the token, is staged mode `0600` before HTTPS so a lost
response or process restart can replay the exact registration. Later
`run-once` invocations resume it without requesting the token again. After a
validated registration acknowledgement, state is durably marked registered,
then a token file is overwritten, fsynced, truncated, fsynced, unlinked, and
its parent directory fsynced; the staged request is erased the same way. For
stdin backed by a pipe there is no source file to erase. A caller that redirects
stdin from a file remains responsible for erasing that source; use
`--token-file` when the client should do so.

Overwrite is best effort, not a physical-erasure claim on copy-on-write,
journaled, flash, snapshot, or backed-up media. Put one-use token files on a
private non-persistent tmpfs and exclude them from backups when media-level
removal matters.

## systemd

Copy the supplied service and timer to `/etc/systemd/system`, review every path
and sandbox directive, then enable the timer only after enrollment succeeds:

```bash
systemctl daemon-reload
systemctl enable --now monitor-agent-transport.timer
```

The template is a root oneshot because its example key, machine identity, and
state are root-owned. It has an empty capability set, a strict filesystem view,
and write access only to `/var/lib/monitor-agent`. A dedicated service user is
preferable where the PKI provisioner can make the key and state owner match;
the config/file validators intentionally do not accept loose group sharing.
Each run performs at most enrollment, one heartbeat, and one telemetry request,
each with the configured timeout. The four-minute service deadline covers the
accepted three-by-60-second worst case plus local recovery overhead. The
five-second timer drives durable retry times without a long-running process.

## Required external deployment work

This package alone is not end-to-end central monitoring. Production requires
all of the following as one reviewed rollout:

1. Issue a unique long-lived client key/certificate per agent from the approved
   private CA. Operate expiry, one-use rotation-token delivery, certificate
   replacement, and CRL/OCSP/revocation outside this package.
2. Deploy a private TLS listener that requires that CA, validates expiry and
   revocation, strips every client `X-Portfolio-Edge-Secret` and `X-Monitor-*`
   header, injects the dedicated agent edge secret (not the SSO secret) and
   verified certificate metadata, and can reach only the private/loopback
   Monitor origin.
3. Enable the server only in SSO mode with
   `MONITOR_AGENT_INGEST_ENABLED=true`, a persistent private
   `MONITOR_AGENT_STATE_DIR`, a domain-separated
   `MONITOR_AGENT_EDGE_SECRET_FILE`, the SSO `MONITOR_EDGE_SECRET_FILE`, and the
   mode-`0600` AES-256-GCM keyring described in
   `docs/agent-ingest-contract.md`. Align
   request, record, queue, skew, and offline-window bounds with this config.
4. Issue the one-use enrollment token as chief-admin and pass it by stdin or a
   private mode-`0600` token file. Confirm `status` reports `registered=true`
   before enabling the timer/producer.
5. Supply and validate a reduced-record producer. This change intentionally
   does not modify `ops/collector.py` or its installer, so no telemetry is
   enqueued until that separate integration exists.
6. Deploy a downstream consumer with its own durable claim/ack protocol for
   the server's encrypted ingest queue. Server admission is not a long-term
   time-series database.
7. Exercise certificate expiry/rotation, revocation, DNS/TLS failure, 429,
   offline replay, clock skew, full local/server queues, host cloning, and
   restore with the actual proxy and PKI before calling the path production
   ready.

Certificate issuance/rotation, the trusted proxy, server secret/state mounts,
the producer adapter, and the downstream queue consumer are external
dependencies; the repository templates cannot prove or create them.
