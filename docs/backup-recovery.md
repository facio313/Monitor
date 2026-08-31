# Monitor state backup and recovery

`ops/state_backup.py` is the bounded backup and real-restore slice for Monitor's
local JSON, JSONL, SQLite, and application-security state. It is intentionally
opt-in: the tool reads one reviewed source map and never accepts source paths,
globs, or directories on the command line.

The format provides:

- byte-exact JSON and JSONL snapshots after strict UTF-8 JSON validation;
- an exhaustive, fixed-member family snapshot for a private mode-`0700`
  directory whose explicitly listed files may be required or optional;
- a WAL-consistent SQLite snapshot made with Python's SQLite online backup API;
- per-member SHA-256, source metadata, and a second-precision UTC creation time;
- a normalized gzip USTAR stream wrapped in opaque CMS SignedData by a pinned
  producer key, then encrypted to CMS AuthEnvelopedData with AES-256-GCM;
- verification and clean-host restore without writing a plaintext tar archive
  or decrypted archive to disk; and
- a mode-`0600`, fsynced transaction journal for explicit crash rollback.

The SQLite online backup uses a short-lived mode-`0600` database in the
mode-`0700` ciphertext output directory. This is a database snapshot, not a tar
archive. It is switched out of WAL mode, integrity-checked, read into bounded
memory, and removed before archive encryption. Put the output directory on
storage with the same confidentiality guarantees as the source state.

## Trust and scope

The source map is a trust root. It must be a normalized absolute path, a
single-link regular file, owned by the uid selected by the operator, mode
`0600`, and no larger than 64 KiB. Unknown, missing, duplicate, non-finite, or
mistyped JSON members are rejected. Non-root callers can trust only their own
uid; root can explicitly select another map owner.

Schema-version 1 maps remain supported unchanged and every v1 source is
required. Schema-version 2 adds a bounded `family` entry. A family declares one
fixed absolute directory, one fixed restore directory, exact uid/gid/mode, and
an explicit ordered member list. Member names are single safe filenames, never
patterns or paths. At least one member is required; a missing optional member is
recorded as absent by omission from the signed manifest. Every unlisted
directory entry fails the backup, so a new rotation or state file cannot be
silently left outside recovery coverage.

Files must be regular, single-link files with no symlink in the path and must
exactly match their declared uid, gid, and mode. Supported file modes are
`0600` and `0640`; a family directory must be `0700`. Family capture holds an
opened directory descriptor, anchors member opens to it with no-follow
semantics, and compares inode and full metadata before and after every read.
After the initial capture it reopens every present member, checks the original
identity and metadata, hashes its bounded content again, and only then
re-enumerates the exact member set and checks directory identity/mtime/ctime.
These checks detect changes observed across both capture passes, including an
in-place update to an earlier member while a later member is captured. No
sequential userspace reader can make concurrently written files atomic, so this
is not a substitute for stopping the application writer: family backup requires
the explicit `--confirm-quiesced` flag.

SQLite WAL, SHM, and rollback journal sidecars, when present, must meet the same
metadata and size policy, but they are never placed in the archive.

The current hard ceilings are 64 expanded sources, eight families, 16 members
per family, 64 MiB per individual source, 62 MiB
of declared/captured source payload, 64 MiB for every decrypted or decompressed
plaintext layer, and 1,024 UTF-8 bytes per configured path. The 2 MiB payload
reserve is for the manifest and bounded CMS/gzip/USTAR framing; ciphertext has
a separate 2 MiB framing allowance. Each source also has a reviewed `maxBytes`
within those ceilings. Restore paths may introduce at most 512 distinct parent
directories, keeping the durable journal below 1 MiB. JSONL additionally
requires a final newline, has no blank or partial records, and is bounded to
100,000 records and 1 MiB per row.

The checked-in template is
[`ops/state-backup-sources.example.json`](../ops/state-backup-sources.example.json).
Copy it to a mode-`0600` operator-owned file and review every uid, gid, path, and
bound for the host. Its shape is:

The template uses schema version 2 and includes the existing flat sources plus
this application-security family:

```json
{
  "id": "application-security",
  "kind": "family",
  "path": "/var/lib/monitor-security",
  "restorePath": "var/lib/monitor-security",
  "uid": 1001,
  "gid": 1001,
  "mode": "0700",
  "members": [
    {
      "id": "api-keys",
      "name": "api-keys.json",
      "kind": "json",
      "mode": "0600",
      "maxBytes": 131072,
      "required": true
    },
    {
      "id": "audit-0",
      "name": "application-audit.jsonl",
      "kind": "jsonl",
      "mode": "0600",
      "maxBytes": 1048576,
      "required": false
    }
  ]
}
```

The checked-in entry explicitly continues through
`application-audit.1.jsonl`, `.2.jsonl`, and `.3.jsonl`, matching the default
four-file retention and 1 MiB-per-file runtime limit. If production changes
either limit, review and change the fixed member list and bounds before taking
a backup. An unexpected `.4.jsonl`, temporary file, preserved restore file, or
any other directory entry intentionally fails closed.

`restorePath` is relative to the explicit restore root. It is validated as a
normalized POSIX path. Archive member names are derived only from the fixed
source `id` and `kind`; tar-controlled names are never used as destinations.
The exact source-map bytes are SHA-256-bound into the manifest, so verify and
restore require the same reviewed map. For a family, the signed manifest's
ordered source IDs are also the authoritative presence set: a missing optional
rotation is restored as missing, not as an invented empty file.

Do not add raw channel secrets, TLS private keys, enrollment plaintext, or other
credential material merely because it is a state file. Maintain a separately
reviewed secret-recovery policy and recipient set for those assets.

## Recipient, producer signer, and output directory

Create or provision an encryption certificate whose private key is retained
off-host. The public recipient certificate may be mode `0644` but must not be
group/world writable. The recovery private key must be a single-link,
root/operator-owned mode-`0600` regular file. The current command expects an
unencrypted private-key file supplied only during offline verification/recovery;
store and transport that file using the organization's recovery-key controls.

Provision a separate producer signing certificate and private key. The backup
host receives the mode-`0600` signing key and certificate; recovery operators
pin the independently distributed public signing certificate. Backup signs the
opaque gzip stream first and encrypts that SignedData second. Verify decrypts,
then runs OpenSSL CMS verification with `-nointern` and only the supplied
`-certfile`; certificates embedded by an archive are never signer candidates.
The signer argument must contain exactly one PEM certificate; bundles are
rejected so the pin cannot silently widen to another certificate.
`-noverify` deliberately skips public-PKI chain building, but signature
verification against the externally pinned certificate remains mandatory. A
recipient certificate alone is not producer authentication, so do not use the
same operational trust distribution for the signer and recipient keys.

The backup output directory must already exist, be owned by the invoking uid,
and be mode `0700`. The final CMS file is created mode `0600` using an exclusive
temporary file, fsynced, published without replacing an existing name, and then
the parent directory is fsynced.

OpenSSL's streaming CMS encoding uses indefinite-length BER even though the CLI
selects `-outform DER`; the file extension should therefore be `.cms`, not a
claim of canonical DER. Verification requires exactly AuthEnvelopedData with
AES-256-GCM and rejects trailing or concatenated BER values before decryption.

The mode-`0600` source map, producer key, archive, pinned signer certificate,
and recovery key still need audited storage and rotation. A forged encrypted
archive made only with the public recipient certificate fails producer-signature
verification. Losing or replacing the pinned signer certificate makes archives
unverifiable; retain certificates for every still-supported recovery generation.

## Backup and verify

Quiesce JSON/JSONL writers or take the backup at a documented publication
boundary. Stop Monitor before capturing `/var/lib/monitor-security`; the family
path cannot be backed up without `--confirm-quiesced`. The tool refuses a
JSON/JSONL file that changes during its read. A family also performs a bounded
second identity/metadata/content pass and rejects an observed rotation,
addition, removal, replacement, or in-place modification before its final
directory check. SQLite may remain open: `Connection.backup()` captures a
consistent committed view, including rows currently present only in a WAL.
Long/busy backups have a wall-clock and page-byte bound.

```bash
sudo install -d -o root -g root -m 0700 /var/backups/monitor-state
sudo install -o root -g root -m 0600 reviewed-state-sources.json \
  /etc/monitor/state-sources.json

sudo python3 ops/state_backup.py backup \
  --source-map /etc/monitor/state-sources.json \
  --recipient-cert /etc/monitor-backup/recipient.crt \
  --signer-cert /etc/monitor-backup/producer-signer.crt \
  --signer-key /etc/monitor-backup/producer-signer.key \
  --confirm-quiesced \
  --output /var/backups/monitor-state/monitor-20260831T120000Z.cms
```

Copy the ciphertext off-host according to the declared RPO. Verification fully
reads the mode-`0600` ciphertext, checks that it is one AES-256-GCM CMS value,
authenticates and decrypts it in bounded memory, accepts the inner SignedData
only from the externally pinned producer certificate, validates the gzip CRC
and exact ordered USTAR members, checks the manifest SHA-256 member, validates
every source hash and JSON record, and runs SQLite `PRAGMA integrity_check`.

```bash
sudo python3 ops/state_backup.py verify \
  --source-map /etc/monitor/state-sources.json \
  --archive /var/backups/monitor-state/monitor-20260831T120000Z.cms \
  --recipient-cert /run/monitor-recovery/recipient.crt \
  --private-key /run/monitor-recovery/recipient.key \
  --signer-cert /run/monitor-recovery/pinned-producer-signer.crt
```

An exit status of zero and `verified=true` are both required. A filename,
successful decryption alone, or a checksum recorded outside this command is not
a restore proof.

## Clean-host recovery

Recovery always requires an explicit absolute `--target-root`. It must be a real,
operator-owned directory that is not group/world writable; no component may be
a symlink. The default path is clean-host behavior: any existing target aborts
the entire operation before it is replaced. Missing destination directories
are created mode `0700`; files are written to exclusive siblings, assigned
their manifest uid/gid/mode, fsynced, renamed, and parent directories fsynced.
After all renames, every target is reopened without following links, byte-hash
checked, and SQLite is integrity-checked again.

A family restore additionally recreates its declared directory uid/gid/mode
(`1001:1001`, `0700` in the checked-in application-security entry), restores
only the signed presence set, and re-enumerates the completed directory. On an
existing destination, an unreviewed file or a configured optional rotation that
the archive records as absent aborts before the restore journal or any target
mutation. Use an empty clean-host destination for the canonical drill; the tool
never silently leaves a newer audit generation beside an older restored set.

For a rehearsal, use an empty mode-`0700` root and perform application-level
readback from that tree:

```bash
sudo install -d -o root -g root -m 0700 /srv/monitor-restore-drill
sudo python3 ops/state_backup.py restore \
  --source-map /etc/monitor/state-sources.json \
  --archive /var/backups/monitor-state/monitor-20260831T120000Z.cms \
  --recipient-cert /run/monitor-recovery/recipient.crt \
  --private-key /run/monitor-recovery/recipient.key \
  --signer-cert /run/monitor-recovery/pinned-producer-signer.crt \
  --target-root /srv/monitor-restore-drill
```

For an actual clean host, `--target-root /` rebases the same relative
`restorePath` values to their production locations. Keep services stopped until
application/API/evaluator readback completes. For application-security state,
verify that Monitor starts without a state-boundary error, the chief-admin key
inventory and audit endpoint return the expected retained metadata, and a
known non-expired client credential still authenticates with its prior scope.
The registry contains digests rather than plaintext bearer tokens, so the
restore does not disclose or recreate a lost client-side token.

## Explicit quiesced replacement

Replacing live state is never implicit. Stop every writer and reader that may
cache or mutate the mapped files, then supply both flags:

```bash
sudo python3 ops/state_backup.py restore \
  --source-map /etc/monitor/state-sources.json \
  --archive /var/backups/monitor-state/monitor-20260831T120000Z.cms \
  --recipient-cert /run/monitor-recovery/recipient.crt \
  --private-key /run/monitor-recovery/recipient.key \
  --signer-cert /run/monitor-recovery/pinned-producer-signer.crt \
  --target-root / \
  --replace-existing \
  --confirm-quiesced
```

Each existing regular, single-link target must still match the reviewed
uid/gid/mode. It is renamed in place to a unique hidden
`.NAME.pre-restore-UTC-RANDOM` path before the new target is installed. Those
files are deliberately retained after success until application readback and
the rollback retention decision are complete.

Before the first destination mutation, restore creates
`TARGET_ROOT/.monitor-state-restore.json` as an operator-owned mode-`0600`
journal. Each directory creation, stage write, preservation rename, install
rename, and rollback mutation is bracketed by an atomically replaced, file- and
directory-fsynced journal update: pending action first, mutation and parent
fsync second, completed state third. A killed journal update may also leave
`.monitor-state-restore.pending`; its older published journal remains the
authoritative pre-action state.

Restore and recover also take a non-blocking advisory lock on the target-root
directory inode. A second invocation fails instead of racing the journal; the
kernel releases that lock automatically on normal exit or `SIGKILL`, without a
stale lock file.

If an ordinary exception occurs, the command replays the same rollback engine
and removes the journal only after the original files (or clean absence) are
verified. If `SIGKILL` or process loss leaves either journal file, keep every
writer stopped and run the explicit recovery command with the exact same source
map and target root:

```bash
sudo python3 ops/state_backup.py recover \
  --source-map /etc/monitor/state-sources.json \
  --target-root / \
  --confirm-rollback
```

Recovery validates the protected journal against the reviewed source map,
resolves the pre/post-action ambiguity by inode and SHA-256, removes only the
recorded new inode/stage, restores the recorded old inode, fsyncs each parent,
then durably removes the journal. It refuses to mutate anything without
`--confirm-rollback`. Repeating the command after a successful rollback returns
`journalFound=false action=none`, so restart automation may call it
idempotently. If the journal contains a durable `committed` marker (the process
died only during final journal removal), recovery validates and finalizes the
committed result rather than reverting it.

This remains an offline multi-file transaction, not a filesystem-wide atomic
snapshot. A storage device that loses already acknowledged fsyncs, an operator
changing recorded files while services should be quiesced, or loss of both the
journal and destination filesystem is outside its guarantee. Preserve the
filesystem and journal for investigation if recovery reports an inode/hash or
metadata mismatch; do not delete hidden files by hand.

For SQLite replacement, remove no sidecar by hand while a process is running.
The service must be stopped, and the mapped target should be the canonical
database file. Restore and recover fail closed if `-wal`, `-shm`, or `-journal`
exists beside that target: checkpoint and close the database through the owning
service's documented procedure before retrying. The restored single-file
snapshot is in DELETE journal mode and does not depend on archived WAL/SHM
files.

## Drill evidence, RPO, and RTO

The manifest `createdAt` is the snapshot's UTC recovery point. This helper does
not schedule backups or claim an RPO; scheduling and successful off-host copy
frequency define it. RTO includes key retrieval, verify, clean restore, and
application-level readback.

For every release and periodically in production-like staging, retain evidence
of:

1. backup exit status and manifest UTC/source count;
2. off-host copy completion and ciphertext size;
3. independent `verify` success;
4. restore into an empty root;
5. byte-exact JSON/JSONL comparison, SQLite integrity/application queries, and
   exact application-security member presence plus directory/file metadata;
6. Monitor startup, API-key inventory/authentication, and audit readback from
   the restored application-security state;
7. measured elapsed time versus the declared RTO; and
8. cleanup approval for retained pre-restore files and recovery keys.

Never mark FA-40 complete from backup creation alone. A current encrypted
archive must pass verify and a clean-host restore/readback drill.
