# SSH source observations

Monitor's authenticated Logs page includes a dedicated SSH access history.
The later [SSH Korea source restriction with GitHub exceptions](ssh-korea-only.md) acts before
sshd; packets rejected there appear in rate-limited firewall logs, not here.
It displays source IP, source port when present, country estimate, KST event
time, event category and authentication method. Country is an IP database
estimate, not the attacker's nationality or physical location. Proxies, VPNs,
cloud hosts and compromised systems can obscure the actual origin.

## Collection and privacy boundary

The collector uses only the already configured `journal:ssh` / `ssh.service`
and `journal:sshd` / `sshd.service` sources. It extracts tightly validated fields
from known OpenSSH log formats before the ordinary generic-log redactor masks
IP addresses. The generic log export stays redacted. Usernames, raw messages,
public-key fingerprints, journal cursors and authentication contents are not
included in the SSH export or API. Excluded workload records are discarded
before extraction. SSH configuration, authentication policy and firewall rules
are not modified by this feature.

Events distinguish `denied`, `invalid_user`, `auth_failed`, `accepted` and
`preauth_closed`. An accepted event is evidence of successful authentication;
a pre-authentication close alone is not proof of an authentication failure.
One connection can generate multiple events, so the displayed count is a log
record count, not unique attacks, sessions or people. Only supported, complete
OpenSSH message shapes are retained; this is not a full intrusion-detection
system or proof that every attempted connection was observed.

The separate `ssh-access/YYYY-MM-DD.jsonl` export retains 30 UTC calendar days,
with at most 10,000 records / 4 MiB per day. Files are mode 0640 and directories
0750 under the existing root:cks export boundary. Exact-date retention removes
only expired SSH observation files. The status document
`ssh-access-status.json` distinguishes fresh, partial, stale and unavailable
observations. Missing input is not presented as zero activity or successful
security checks. Repeated collection deduplicates stable observation IDs.

SSH rows are durably written before the existing generic journal cursor is
committed. On SSH persistence failure, that source's cursor and generic
redaction state remain aligned for replay; unrelated sources continue.
Restarting after a completed SSH write is safe because a replay deduplicates it.
The HTTP route `GET /monitor/api/ssh-access` requires the existing `logs:read`
capability. It accepts only bounded range, event, literal-IP and pagination
filters, never paths, hostnames or arbitrary URLs. Missing or damaged data is
explicitly indicated while usable history remains available.
Each request scans at most 16 MiB / 40,000 rows, newest first; when capped,
the response and displayed count explicitly cover only the scanned subset.

## Offline country estimates

Country enrichment uses a local SQLite range index of the
[DB-IP IP to Country Lite database](https://db-ip.com/db/download/ip-to-country-lite),
whose [CSV format](https://db-ip.com/db/format/ip-to-country-lite/csv.html) contains
IP start/end addresses and a country code. No observed IP is sent to a third
party. The service performs no country-data downloads or runtime database
writes and needs no additional Python packages. A missing, corrupt, future-dated
or unsafe database does not stop IP collection. Private/reserved addresses
receive no country estimate; provider code `ZZ` means unknown, while `XK` is
retained as the provider's Kosovo code. Data older than 90 days is marked stale.

The dataset is licensed under CC BY 4.0. The SSH history page includes the
required DB-IP attribution link. Estimates are fixed with
their database date when each observation is stored, so later updates do not
rewrite historical evidence.

To refresh the optional country data, download the current monthly CSV/gzip
from the provider's official page into a private staging directory, verify its
published checksum, and build the index with the supplied checksum:

```sh
sudo python3 /usr/local/lib/monitor-collector/ip_country.py \
  --input=/absolute/staging/dbip-country-lite-YYYY-MM.csv.gz \
  --output=/usr/local/share/monitor-collector/ip-country.sqlite \
  --database-date=YYYY-MM-01 --sha256=VERIFIED_DOWNLOAD_SHA256
```

The SHA-256 argument is for the supplied compressed file. The provider's page
may publish checksums for the uncompressed CSV; verify that stream separately
before pinning the compressed download's SHA-256. The builder reads bounded,
non-overlapping IPv4/IPv6 ranges, validates them and atomically replaces the old
index only after a successful build. Database directory owner/mode must remain
root:root 0755 and the index root:root 0644. The normal installer copies only
code and deliberately neither downloads nor deletes this optional dataset.

## Verification

```sh
python3 -m unittest ops.tests.test_ssh_access ops.tests.test_ip_country \
  ops.tests.test_generic_log_collector ops.tests.test_ssh_install_contract
```

Tests cover hostile usernames, malformed messages, literal IPv4/IPv6, unknown
countries, duplicate/replayed events, retention, unsafe files, persistence
failure, and bounded country lookups. API/UI tests cover authorization, filters,
pagination, unavailable data and responsive rendering. Runtime verification
must additionally confirm the collector's root:cks file ownership and that
ordinary generic logs still redact source IPs.

## Production verification — 2026-09-13 KST

The collector extension and September 2026 offline country index were deployed
at 20:16 KST. A bounded, one-time backfill imported 362 recognized records from
the preceding 24 hours without resetting the generic journal cursor. Subsequent
scheduled runs added new records, advanced the successful collection timestamp
and reported fresh status with no dropped records. Export ownership is
root:cks, and ordinary SSH generic-log records still mask IPv4 addresses.

The country index contains 717,170 ranges (25,329,664 bytes). The official
uncompressed CSV SHA-1 was checked against
`2d99eae57714d39e7670a12985ae3083f8df807b`; the downloaded gzip was pinned with
SHA-256 `a32bb3c384bd3de60ad9024596aa5b395a6dd5beaa27a7223407cc2edc681d0b`.
Refresh is manual; the feature does not create an automatic updater.

Only the Monitor application container was replaced, at 20:20:53 KST, with
`ghcr.io/facio313/monitor:ssh-origin-20260913-1`
(`sha256:221e54641ed3698bd124c0fa2d43c1ffe0ad6d656b8a8082ca59d71f14fb575f`).
Readiness and container health passed. The previous image and exact collector
file backups remain available in the private rollout directory. Existing mail
timers, SSH configuration, authentication policy, firewall and proxy
configuration were not changed. TCP alert thresholds were also left unchanged.

Final verification passed 590 Python tests (one skipped), 485 native TypeScript
tests and both typechecks. The production image passed its 484-test suite;
the existing image build omits one host wall-clock load-budget test that passed
in the native suite. Browser checks against the deployed application confirmed
anonymous 401 responses, authenticated fresh data, exact-IP and event filters,
pagination, explicit invalid-query rejection, desktop and mobile rendering,
no page-wide mobile overflow, and no JavaScript errors. A local test-only font
was used by the headless browser; no production fonts or CSP rules changed.
