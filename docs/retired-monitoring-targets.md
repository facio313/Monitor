# Retired monitoring targets

Removing a container from the collection allowlist does not prove recovery:
active incidents normally remain open when their observations disappear.
An intentionally decommissioned service can instead be retired explicitly.

The optional `/etc/monitor/alert-retirements.json` must be a regular,
root-owned mode-0600 file containing only `schemaVersion: 1` and a `targets`
list. Up to 128 exact `container/<name>` identifiers are accepted; patterns,
duplicates, and other target kinds are rejected. No file means no retirements.

```json
{
  "schemaVersion": 1,
  "targets": [
    "container/multtara-backend",
    "container/multtara-collector",
    "container/multtara-frontend"
  ]
}
```

These three targets belong to the archived Multtara stack. The independent
Pongdang deployment uses project `pongdang` and services `backend`, `db`, and
`frontend`; these are now the active collection targets. Historical Multtara
snapshot and event identities remain readable.

Retirement requires fresh container collection evidence, an intact inventory,
and absence of the exact target from the current inventory and rule
observations. It does not silence an observed container or turn missing source
data into healthy telemetry. An active incident receives one deterministic
`resolved` event with `status: unsupported`, no invented measurement, a
`retirement: service-retired` label, and an explicit statement that retirement
does not assert service recovery. The original opening time and event history
are preserved. Event-first recovery prevents a crash from reopening the same
retired incident.

The normal collector installer includes the changed evaluator modules. It
does not create or overwrite the operator's retirement configuration.
