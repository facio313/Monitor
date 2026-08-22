#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
mode=$($script_dir/portfolio-auth-mode.sh print)

case "$mode" in
  sso|local) ;;
  *)
    printf '%s\n' "monitor compose: unexpected authentication mode '$mode'" >&2
    exit 1
    ;;
esac

exec "$script_dir/portfolio-auth-mode.sh" exec -- \
  docker compose \
    --file "$repository_root/docker-compose.yml" \
    --file "$repository_root/docker-compose.$mode.yml" \
    "$@"
