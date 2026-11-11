# Main/dev migration — 2026-11-12

The user replaced tool/feature and retired-dev rules with two active branches: `main` is production and `dev` is development. Fetch `origin/main` before changes, validate on `dev`, and publish/deploy only reviewed main history. Local apps run only from the actual dev checkout through `scripts/dev-only.sh`; setting PORTFOLIO_BRANCH cannot bypass this checkout guard. The canonical resolver permits only main/sso and dev/local.

Pre-migration refs were saved in a verified Git bundle under `~/.local/share/cks-main-dev-migration/2026-11-12/Monitor/before-migration.bundle`. Original dirty/untracked/ignored files and worktrees are preserved. Existing branches are not deleted in this change. CI on dev must not publish or deploy production artifacts.

The old alert feature history is retained with an ours merge: latest main already integrated the requested SSH-success-mail policy separately and explicitly excluded the older whole feature tree in `docs/ai/ssh-mail-off-20261102.md`. The current runtime hold and dependency patch remain intact.

Validation completed:

- 39 authentication/API tests passed
- client and server TypeScript checks passed
- shell branch and actual checkout guard passed in dev and main CI environment
- workflow YAML parsed

CI follow-up: the image build executes the actual-checkout regression in a disposable Git fixture. Its build stage now installs Git alongside Python; runtime stages remain unchanged. The first dev CI passed native checks but failed this new fixture because Git was absent from the build stage.
