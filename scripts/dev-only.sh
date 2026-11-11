#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
branch=$(git -C "$root" branch --show-current)
[ "$branch" = dev ] || { printf '%s\n' 'Local execution requires the actual dev checkout.' >&2; exit 1; }
if [ "${PORTFOLIO_BRANCH+x}" = x ] && [ "$PORTFOLIO_BRANCH" != dev ] && [ "$PORTFOLIO_BRANCH" != refs/heads/dev ]; then
  printf '%s\n' 'Local execution cannot override the dev branch.' >&2
  exit 1
fi
PORTFOLIO_BRANCH=dev
PORTFOLIO_AUTH_MODE=${PORTFOLIO_AUTH_MODE-local}
export PORTFOLIO_BRANCH PORTFOLIO_AUTH_MODE
exec "$root/scripts/portfolio-auth-mode.sh" exec -- "$@"
