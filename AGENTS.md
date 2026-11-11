# Monitor project policy

Only `main` (production) and `dev` (development) are active branches. All agents implement and run local apps on the actual `dev` checkout. Fetch the latest `origin/main` before changing code and integrate it into `dev` without overwriting local work. CI validates both branches; production publishing/deployment remains restricted to reviewed `main` history. Tool/feature branches are retired. Preserve their unique commits and dirty/untracked/ignored files before cleanup; archived worktrees must not run local services. Never force-push or discard uncommitted work.

`main=sso`, `dev=local`; the canonical `scripts/portfolio-auth-mode.sh` rejects every other branch. `scripts/dev-only.sh` checks the actual Git branch for local app execution. Keep production edge authentication and the runtime hold/deployment scope protections intact. Read `README.md` for build and deployment procedures.

Use the vowline skill for substantive work.
