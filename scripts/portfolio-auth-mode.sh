#!/bin/sh
set -eu

fail() {
  printf '%s\n' "portfolio auth mode: $*" >&2
  exit 1
}

resolve_branch() {
  if [ "${PORTFOLIO_BRANCH+x}" = x ]; then
    resolved_branch=$PORTFOLIO_BRANCH
  elif [ -n "${GITHUB_REF_NAME:-}" ]; then
    resolved_branch=$GITHUB_REF_NAME
  else
    resolved_branch=$(git branch --show-current 2>/dev/null || true)
  fi

  case "$resolved_branch" in
    refs/heads/*) resolved_branch=${resolved_branch#refs/heads/} ;;
  esac
  [ -n "$resolved_branch" ] || fail 'branch is required (set PORTFOLIO_BRANCH for detached or packaged builds)'
  case "$resolved_branch" in
    *[!A-Za-z0-9._/-]*) fail 'branch contains unsupported characters' ;;
  esac
}

resolve_branch
case "$resolved_branch" in
  main|dev) resolved_mode=sso ;;
  *) resolved_mode=local ;;
esac

if [ "${PORTFOLIO_AUTH_MODE+x}" = x ] && [ "$PORTFOLIO_AUTH_MODE" != "$resolved_mode" ]; then
  fail "branch '$resolved_branch' requires '$resolved_mode', not '$PORTFOLIO_AUTH_MODE'"
fi

build_contract=/etc/portfolio-auth-build
if [ -e "$build_contract" ]; then
  if [ ! -f "$build_contract" ] || [ -L "$build_contract" ]; then
    fail "$build_contract must be a regular image file"
  fi
  {
    IFS= read -r build_branch || fail "$build_contract is missing its branch"
    IFS= read -r build_mode || fail "$build_contract is missing its authentication mode"
    if IFS= read -r _build_extra; then
      fail "$build_contract contains unexpected data"
    fi
  } < "$build_contract"
  case "$build_branch" in
    refs/heads/*) build_branch=${build_branch#refs/heads/} ;;
  esac
  if [ "$build_branch" != "$resolved_branch" ] || [ "$build_mode" != "$resolved_mode" ]; then
    fail "runtime '$resolved_branch/$resolved_mode' does not match image '$build_branch/$build_mode'"
  fi
fi

PORTFOLIO_BRANCH=$resolved_branch
PORTFOLIO_AUTH_MODE=$resolved_mode
export PORTFOLIO_BRANCH PORTFOLIO_AUTH_MODE

case "${1:-print}" in
  print)
    printf '%s\n' "$PORTFOLIO_AUTH_MODE"
    ;;
  contract)
    printf '%s\n%s\n' "$PORTFOLIO_BRANCH" "$PORTFOLIO_AUTH_MODE"
    ;;
  check)
    ;;
  exec)
    shift
    if [ "${1:-}" = -- ]; then
      shift
    fi
    [ "$#" -gt 0 ] || fail 'exec requires a command'
    exec "$@"
    ;;
  *)
    fail 'expected print, contract, check, or exec -- <command>'
    ;;
esac
