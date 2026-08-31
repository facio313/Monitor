# Application security state

Monitor keeps API-key metadata and its application audit journal in the private
directory selected by `MONITOR_SECURITY_STATE_DIR`. The default is
`/var/lib/monitor-security` in both SSO and local mode.

The directory is a startup trust boundary. It must already exist as a real,
normalized directory, be owned by Monitor's effective uid, and have mode
`0700`. State files must remain owner-owned, mode `0600`, regular, and
single-link. Monitor refuses symlinks, hardlinks, foreign ownership, broad
permissions, malformed state, and over-limit files; it does not repair an
unsafe deployment at runtime.

Compose bind-mounts the reviewed host path selected by
`MONITOR_SECURITY_STATE_PATH` (default `/var/lib/monitor-security`) read-write
at the same container path while the container root filesystem remains
read-only. `create_host_path: false` prevents Docker from silently creating a
root-owned directory. Production uses the `cks` rootless Docker daemon:
container uid/gid 0 maps to the unprivileged host `cks` account, which is also
required to read the existing edge secret, telemetry bind, and updater socket.
Do not set an image `USER 1001`; that maps to a subordinate host identity and
breaks those mounts. Provision the host boundary before deployment with
`install -d -o cks -g cks -m 0700 /var/lib/monitor-security`, and correct
unsafe metadata only while Monitor is stopped. It appears as owner `0:0` inside
the rootless container and as `1001:1001` to the host backup tool.

## API keys

Only a canonical SSO `chief-admin` may list, issue, revoke, or rotate keys at
`/monitor/api/security/api-keys`. Management requests are rate limited;
mutations require the existing strict same-origin JSON contract. Issue and
rotation responses contain the `mon_` bearer token once. The registry stores
only a domain-separated SHA-256 digest and bounded metadata.

Issuance may include `sourceIpAllowlist`, an array of at most 32 exact IPv4 or
IPv6 addresses. Addresses are normalized to their canonical form, duplicates
and non-address values are rejected, and an empty or omitted array means the
key is not source-address restricted. A restricted key is accepted only when
the trusted proxy-derived `request.ip` matches one of those exact addresses;
the same generic authentication failure is returned for a bad token, expiry,
or source address, while a valid key lacking the route scope receives the fixed
scope-required response. The edge must preserve the single trusted proxy-hop
contract so the rightmost forwarded client address is connection-derived.

Successful authentication updates `lastUsedAt` durably on first use and then at
most once per minute. Scope and source-address checks happen before that write.
GET requests are additionally limited per opaque key identifier (never by the
raw bearer token), so a valid low-privilege key cannot turn reads into
unbounded registry fsyncs. Bearer-bearing requests also pass a trusted-source-IP
failure limiter before key hashing; successful requests are removed from that
counter, and limiter keys and responses never contain the raw token. State
schema v2 stores the canonical allowlist;
schema-v1 files migrate at startup with an empty allowlist, preserving the
previous unrestricted behavior.

Issue and rotation compact registry capacity transactionally before publishing
the new state. Active keys are never removed. Only revoked or expired entries
are eligible, with at most the 16 newest tombstones from the last 30 days kept
when active-key capacity permits; smaller configured registries scale that
count down. This keeps repeated rotation available without making the registry
an unbounded history database. The durable application audit journal is the
authoritative full lifecycle history.
Successful issue records identify the generated key ID; revoke records identify
the revoked ID; successful rotation records link the prior and replacement IDs.

Bearer authentication is separate from SSO and local-cookie principals. A
request that supplies `Authorization` cannot fall back to another identity.
The application first authenticates the private edge credential injected by
the dedicated Nginx proxy and rejects missing or incorrect credentials before
any IP-keyed failure limiter or API-key lookup. Only then may the
proxy-controlled rightmost address be used for rate limiting, audit metadata,
or the key's source-IP allowlist. Ambient Express proxy trust is disabled;
local-mode and unauthenticated direct requests use the socket peer and ignore
`X-Forwarded-For`. Thus the loopback-published backend is not an alternate
bearer ingress and a direct client cannot select its identity with that header.
Because a bearer key is explicit rather than ambient browser authority, the
cookie-oriented Origin check is skipped only after the key, route scope,
expiry, and source address have all been validated; SSO mutations keep the
strict same-origin JSON contract.

Agent mTLS endpoints never accept bearer authorization. The application and
external ingress allowlists are exact:

Agent certificate proof is not also proof of forwarded-address sanitation.
Agent enrollment, rotation, and related audit records therefore ignore
`X-Forwarded-For` and use only the application socket peer for source metadata.

| Scope | Application route | External API-key alias |
| --- | --- | --- |
| `dashboard:read` | `GET /monitor/api/dashboard` | `GET /monitor/api-key/v1/dashboard` |
| `logs:read` | `GET /monitor/api/generic-logs` | `GET /monitor/api-key/v1/generic-logs` |
| `agents:read` | `GET /monitor/api/agents` | `GET /monitor/api-key/v1/agents` |
| `agents:write` | `POST /monitor/api/agents/enrollment-tokens`; `POST /monitor/api/agents/:agentId/certificate-rotation-tokens`; `POST /monitor/api/agents/:agentId/revoke`; never `/monitor/api/agent/*` | The corresponding paths below `/monitor/api-key/v1/agents`; dynamic `:agentId` aliases require a lowercase UUIDv4 |
| `infrastructure-ledger:read` | `GET /monitor/api/infrastructure-ledger` | `GET /monitor/api-key/v1/infrastructure-ledger` |
| `system-updates:read` | `GET /monitor/api/system-updates` | `GET /monitor/api-key/v1/system-updates` |
| `system-updates:check` | `POST /monitor/api/system-updates/check` | `POST /monitor/api-key/v1/system-updates/check` |
| `system-updates:apply` | `POST /monitor/api/system-updates/prepare` and `/apply` | `POST /monitor/api-key/v1/system-updates/prepare` and `/apply` |
| `auth-inventory:read` | `GET /monitor/api/operations/auth-inventory` | `GET /monitor/api-key/v1/operations/auth-inventory` |

The external aliases bypass browser SSO only for those method/path pairs.
Fixed paths use exact Nginx locations, and the sole dynamic family accepts only
the two documented agent administration actions with a lowercase UUIDv4.
Before proxying, Nginx strips cookies, SSO identity fields, and all Monitor
mTLS identity fields, then replaces (rather than appends to) `X-Forwarded-For`.
It injects the root-readable edge secret that the application requires on all
bearer requests; this is proof of the trusted proxy hop, not bearer identity.
It derives that address from `CF-Connecting-IP` only when the TCP peer belongs
to the maintained Cloudflare trusted-range list. Keep that list synchronized
with Cloudflare and block direct origin access; otherwise source-IP key
restrictions do not have a trustworthy client-address boundary.

These aliases are implemented configuration, not an assertion that public
bearer ingress is currently enabled. As of 2026-08-31 the production Nginx
origin listens on HTTP only, so Cloudflare-to-origin transport does not meet the
bearer-token confidentiality requirement. The production server therefore
must not include `monitor-api-key-ingress.conf`: alias requests remain behind
the ordinary SSO location. Install `monitor-api-key-peer-map.conf` in Nginx's
`http` context, but treat it as defense in depth rather than a firewall.

Activation requires live evidence of Nginx origin TLS with Cloudflare Full
(strict), plus an origin firewall that admits only reviewed proxy peers. An
authenticated tunnel may replace that design only after its equivalent
transport and peer-identity gate is reviewed and the checked-in `$https` gate
is deliberately adapted. Plain HTTP receives `426` and an untrusted original
TCP peer receives `403` when the alias is active. Re-run both negative tests,
the SSO regression checks, and a valid/invalid/scope/IP bearer matrix after any
activation.

`agents:write` can issue enrollment or certificate-rotation tokens and revoke
an agent; `system-updates:apply` can initiate host package changes. Their
presence in the future-facing allowlist is a conscious high-impact capability,
not permission to enable it by default. Activation requires explicit operator
approval and narrowly scoped, expiring, source-IP-restricted keys.

## Audit behavior

Privileged mutations append a durable `intent` record before their side effect
and a fixed-schema outcome afterward. An intent append failure returns a fixed
`SECURITY_AUDIT_UNAVAILABLE` response and prevents the mutation. Records never
contain request/response bodies, headers, cookies, bearer tokens, passwords, or
raw source addresses. Source IPs become a domain-separated SHA-256 value.

File and parent-directory fsync failures are fatal to the request. Monitor may
reload an inode that was atomically renamed before a directory fsync error, but
it never acknowledges the key mutation or permits the dependent side effect as
durable until the directory entry itself has been synchronized.

Local login auditing deliberately does not reveal password correctness. When
the supplied password is valid but its intent or success record cannot be made
durable, Monitor issues no session and returns the same `INVALID_CREDENTIALS`
response used for a bad password. Logout still clears the cookie if audit
storage is unavailable.

A canonical chief admin can read at most 100 recent records per request from
`GET /monitor/api/security/audit?limit=N`. The endpoint returns newest first,
accepts no other query fields, and requires an explicit same-origin request.

## Backup and recovery

The schema-version 2 family in
[`ops/state-backup-sources.example.json`](../ops/state-backup-sources.example.json)
binds the exact host directory `/var/lib/monitor-security`, its `1001:1001`
ownership and `0700` mode, required `api-keys.json`, and optional audit files
`application-audit.jsonl` through `application-audit.3.jsonl`. Each file must be
owner-controlled mode `0600`, regular, single-link, and within its reviewed
bound. There is no glob expansion: an unexpected generation, temporary file,
symlink, hardlink, or other directory entry fails the complete backup.

Stop Monitor before backup and pass `--confirm-quiesced`. After its initial
capture, the family reopens every present member and verifies its original
identity, full metadata, and bounded content hash before the final directory
check. This detects observed in-place changes as well as member publication and
audit rotation; the encrypted, producer-signed manifest records exactly which
optional generations existed. Verification and clean-host restore therefore
preserve both bytes and absence rather than creating empty audit files. Restore
also recreates the private directory ownership/mode and rejects a stale
destination generation before any mutation.

Follow [`backup-recovery.md`](backup-recovery.md) for recipient/signer custody,
off-host copy, verify, restore, and crash rollback. A completed drill must start
Monitor from the restored directory, read back the expected API-key inventory
and retained audit records, and authenticate a known non-expired scoped key.
Backup creation alone is not recovery evidence.
