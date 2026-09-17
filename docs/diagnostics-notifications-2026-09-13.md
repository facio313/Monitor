# Network evidence, live reboot state, and email reports

Monitor now retains bounded network diagnostic history and can send hourly
email reports plus notifications for newly observed warning/critical conditions.
All collection and notification projections exclude the out-of-scope workload.
The host collector still has no network access; only the existing delivery
worker contacts a configured SMTP service.

## Evidence and UI

- Network details include the new diagnostic history panel. It supports a time
  range, an exact incident window, problem filters and pagination. Per-probe
  DNS, TCP, TLS and first-response times are shown separately from total time.
  Failed or unobserved phases remain unknown. HTTP evidence includes the probe's
  own time, so an older five-minute probe is not presented as a new HTTP test
  on every one-minute host sample.
- Host samples retain TCP retransmission numerator/denominator deltas and rates,
  interface error/drop rates and contemporaneous CPU, memory and PSI values.
  Stored evidence contains neither endpoint addresses nor request contents.
- `network-diagnostics/YYYY-MM-DD.jsonl` retains 30 UTC calendar days, with
  maximum 10,000 records and 8 MiB per day. Existing alerts and generic logs
  remain available. Detailed phase history begins at deployment; past network
  delays cannot retrospectively acquire timings that were never collected.
- The logs and maintenance pages expose notification status, detection source
  availability, recent reduced detections and delivery counts. Queue insertion,
  retries and SMTP acceptance are distinct; SMTP acceptance is not confirmation
  of inbox delivery.
- Main and maintenance views use fresh `system.reboot` telemetry from the host
  reboot marker and bounded package labels. This includes library upgrades,
  independently of whether the running kernel is the latest installed version.
  Unavailable and stale evidence do not become a healthy `false` value.
- Update package lists remain operator-triggered. A check older than 24 hours,
  or with an invalid/future date, is visibly historical and requires another
  check. Rebooting alone does not refresh that saved update list.

Authenticated read routes:

- `GET /monitor/api/network-diagnostics` uses the existing `logs:read` boundary.
- `GET /monitor/api/notification-reports` uses the same boundary.

## Delivery configuration

The existing `/etc/monitor/alert-delivery.json` must contain an enabled SMTP
channel, its sender/recipient settings and a file-backed credential reference.
Credentials remain outside the repository and public exports. Hourly summaries
and immediate notifications share the existing SQLite outbox and retry worker.
The timer must be enabled only after valid sender configuration is installed.
See [alert delivery](alert-delivery.md) for the transport and credential contract.

An hourly report is queued once per UTC hour and displays local times in the UI.
Immediate means the next delivery cycle after a collector detects a condition:
the host collector normally runs once a minute and the delivery worker every
15 seconds. HTTP synthetic checks normally run every five minutes. Detection is
limited to the configured, successfully observed sources. SSH refusal/failure
evidence and repeated HTTP error patterns are suspicious activity, not proof of
a successful intrusion.

## Installation and verification

The installer now transactions the diagnostic and notification modules with the
collector. Its rollback preserves telemetry and operator configuration. The
synthetic unit writes a separate reduced `diagnostics.json`; the collector binds
that exact input and the two reboot marker files read-only. No Docker socket,
shared proxy changes, host reboot, or broader privilege is required.

Validate phase failures and retention, notification hourly/dedup/retry behavior,
authenticated API bounds and rendered freshness notices before replacing the
Monitor image. After installation, verify advancing host samples, new diagnostic
records, live reboot state, notification source health and the exact delivery
timer. Mail completion additionally requires an actual SMTP acceptance record
for the configured recipient; a passing fake-SMTP test alone does not prove it.

## Production verification — 2026-09-13

The collector transaction was applied successfully and the exact `monitor`
Compose service was first replaced at 17:20 KST. The final wide-table layout
was applied at 17:31 KST with local immutable image
`ghcr.io/facio313/monitor:observability-20260913-2`
(`sha256:6da1320064c4611b81fc2820f57179944a9961bf2e20f81613f5899d6defa466`).
The container is healthy and its readiness endpoint succeeds. No host reboot,
package installation, shared-proxy change or other workload deployment occurred.

Verification covered 465 native TypeScript tests, client and server typechecks,
521 Python tests (one intentionally skipped), and ten installer contract tests.
The image independently passed its 464 deterministic TypeScript tests and
production build; its pre-existing Dockerfile excludes the native load budget.
The native suite included that load budget.

Live checks confirmed advancing daily diagnostic records with no reader
rejections, HTTP 200 with all five timing fields, and a readable TCP numerator,
denominator and interval. An observed 8.696% retransmission episode was 14/161
outbound segments; subsequent 14/2,867 and 5/4,068 observations correctly
resolved it after two distinct healthy samples. A high ratio with a small
denominator alone is not evidence of an attack or a failed network path.

Read-only browser verification exercised the deployed network, maintenance and
logs pages, their authenticated API responses, all 16 catalog sources and a
390-pixel mobile viewport. There were no JavaScript errors or horizontal page
overflow. The maintenance view showed the current `libc6` reboot marker and
separately marked the saved September 1 update check as historical.

A second read-only browser pass verified exact Asia/Seoul incident-window
conversion, each problem filter, distinct paginated API records and rejection
of an invalid page number. Both added read APIs reject unauthenticated requests
with HTTP 401. The recovery presentation was additionally corrected for new
and previously stored detections: a historical abnormal value is explicitly
labelled as the last pre-recovery observation; stored incident evidence is not
rewritten and no current healthy value is invented.

The final layout passed the same browser checks again: the diagnostic panel
spans 1,130 pixels at a 1,440-pixel desktop viewport, and the 390-pixel mobile
layout scrolls the table internally without widening the page. After the build
and browser processes exited, direct host observations showed 94–99% CPU idle
and a temperature of 65.55°C. Build-time observations remain in the history.

The hourly/immediate producer is installed and local detections are current.
All four source-health observations were fresh. After the operator supplied
the Gmail app password directly in the protected secret file, the configured
delivery timer was enabled. The first test was accepted by SMTP at 18:01:08 KST
and the operator confirmed inbox receipt. A live reboot caution and the hourly
report were accepted at 18:03:16 and 18:03:18; a subsequent TCP caution was
accepted at 18:04:20. Audit readback showed success/250 with no pending, retry
or failed deliveries at the verification checkpoint. The hourly queue identity
remained unchanged across later collector runs. Credentials were not copied
into the repository, logs or public status exports.

At 18:26 KST the mail presentation was upgraded to responsive light cards and
two inline PNG trend charts, without changing the Monitor image, SMTP settings,
secrets or notification schedule. Only `alert_delivery.py`,
`notification_reports.py`, `notification_visuals.py` and `email_visuals.py` were
replaced. Both affected timers were paused while existing oneshots finished;
the module import/byte comparison check and commit preceded resuming them.
The immediate operational path generated an `incident` visual after the upgrade.
The explicitly marked hourly design sample was accepted by Gmail at 18:27:19
KST on its first attempt (SMTP 250). Readback confirmed a persisted hourly
visual, HTML alternative and two CID PNGs. This sample did not consume or
duplicate the existing production hourly slot. The queue subsequently showed
seven successes (five operational and two tests), with no pending, retry,
leased, dropped or failed rows. The collector remained healthy with current
source observations, and the unchanged Monitor container remained healthy.

Final email verification covered 561 Python tests (one skipped), installer
shell syntax, and an independent review of MIME, bounded payloads and rollback
compatibility. Read-only Korean-font browser previews at 800 and 390 pixels
had loaded inline charts, no horizontal overflow, JavaScript errors or outbound
resource requests. These previews are not a substitute for a real mail client's
rendering; the operator was asked to confirm the new design in Gmail.
See [notification reports](notification-reports.md) for image-hidden behavior,
test-mail usage and the old-worker rollback constraint.

The prior image remains available as
`ghcr.io/facio313/monitor:hotfix-active-inventory-20260909-1`.
An exact pre-change collector/unit/Compose archive is retained outside Git at
`.runtime/rollouts/observability-20260913-1/monitor-runtime-before.tar` for rollback;
this copy survives host reboot. Public and private telemetry state was preserved.
The pre-design mail modules are separately retained at
`.runtime/rollouts/email-design-20260913.zFIn7V/`. Preserve the upgraded delivery
reader when rolling back only the producer; older readers reject queued visual
fields. Do not restore only the old mail modules against rich queued payloads.
