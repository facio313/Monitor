# Private infrastructure ledger input

This directory intentionally contains no real infrastructure ledger data in
Git. `initial-ledger.json` is ignored because it holds environment-specific
operational history that is suitable for the root-owned host store and the
administrator-gated Monitor view, not a public source repository.

Prepare and review the initial document outside the checkout, store it as a
root-owned mode-`0600` regular file, and pass its absolute path to
`ops/install-infrastructure-ledger.sh`. The schema, validation behavior, and
synthetic fixtures remain versioned in `infrastructure_ledger.py` and its
tests.
