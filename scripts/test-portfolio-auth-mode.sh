#!/bin/sh
set -eu
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
resolver=$script_directory/portfolio-auth-mode.sh
for branch in main refs/heads/main dev refs/heads/dev; do
  case "$branch" in *main) expected=sso ;; *) expected=local ;; esac
  actual=$(unset PORTFOLIO_AUTH_MODE GITHUB_REF_NAME; PORTFOLIO_BRANCH=$branch "$resolver" print)
  [ "$actual" = "$expected" ]
done
for branch in codex cursor anthropic feature/auth-contract topic ''; do
  if (unset PORTFOLIO_AUTH_MODE; PORTFOLIO_BRANCH=$branch "$resolver" check) 2>/dev/null; then
    printf 'Unsupported branch accepted: %s\n' "$branch" >&2; exit 1
  fi
done
for pair in main:local dev:sso; do
  if PORTFOLIO_BRANCH=${pair%:*} PORTFOLIO_AUTH_MODE=${pair#*:} "$resolver" check 2>/dev/null; then
    printf 'Mismatched mode accepted: %s\n' "$pair" >&2; exit 1
  fi
done
github_mode=$(unset PORTFOLIO_BRANCH PORTFOLIO_AUTH_MODE; GITHUB_REF_NAME=dev "$resolver" print)
[ "$github_mode" = local ]
contract=$(PORTFOLIO_BRANCH=dev PORTFOLIO_AUTH_MODE=local "$resolver" contract)
[ "$contract" = "$(printf 'dev\nlocal')" ]
environment=$(PORTFOLIO_BRANCH=dev PORTFOLIO_AUTH_MODE=local "$resolver" exec -- env)
printf '%s\n' "$environment" | grep -Fqx 'PORTFOLIO_BRANCH=dev'
printf '%s\n' "$environment" | grep -Fqx 'PORTFOLIO_AUTH_MODE=local'
printf '%s\n' 'portfolio main/dev auth contract: ok'

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir "$fixture/scripts"
cp "$resolver" "$script_directory/dev-only.sh" "$fixture/scripts/"
git -C "$fixture" init -q -b dev
PORTFOLIO_BRANCH=dev PORTFOLIO_AUTH_MODE=local "$fixture/scripts/dev-only.sh" sh -c '[ "$PORTFOLIO_BRANCH:$PORTFOLIO_AUTH_MODE" = dev:local ]'
git -C "$fixture" symbolic-ref HEAD refs/heads/main
if PORTFOLIO_BRANCH=dev PORTFOLIO_AUTH_MODE=local "$fixture/scripts/dev-only.sh" true 2>/dev/null; then
  printf '%s\n' 'A main checkout bypassed the local dev guard.' >&2; exit 1
fi
printf '%s\n' 'actual dev checkout guard: ok'
