#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-infrastructure-ledger.sh must run as root" >&2
    exit 1
fi
if ! getent group cks >/dev/null 2>&1; then
    echo "required group 'cks' does not exist" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
writer_source=$script_dir/infrastructure_ledger.py
writer_target=/usr/local/sbin/monitor-infrastructure-ledger
canonical_events=/var/lib/monitor-infrastructure-ledger/events.jsonl
seed_source=${1:-}

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [/absolute/path/to/private-ledger-seed.json]" >&2
    exit 2
fi

if [ -n "$seed_source" ]; then
    case "$seed_source" in
        /*) ;;
        *)
            echo "ledger seed path must be absolute" >&2
            exit 2
            ;;
    esac
elif [ ! -f "$canonical_events" ]; then
    echo "initial installation requires a private ledger seed path" >&2
    exit 2
fi

if [ ! -f "$writer_source" ] || [ -L "$writer_source" ] || [ "$(stat -c %h -- "$writer_source")" -ne 1 ]; then
    echo "required ledger writer is missing or unsafe: $writer_source" >&2
    exit 1
fi

if [ -n "$seed_source" ]; then
    if [ ! -f "$seed_source" ] || [ -L "$seed_source" ] || [ "$(stat -c %h -- "$seed_source")" -ne 1 ]; then
        echo "private ledger seed is missing or unsafe: $seed_source" >&2
        exit 1
    fi
    if [ "$(stat -c %u -- "$seed_source")" -ne 0 ]; then
        echo "private ledger seed must be owned by root" >&2
        exit 1
    fi
    case "$(stat -c %a -- "$seed_source")" in
        400|600) ;;
        *)
            echo "private ledger seed must have mode 0400 or 0600" >&2
            exit 1
            ;;
    esac
fi

if [ -e "$writer_target" ] || [ -L "$writer_target" ]; then
    if [ ! -f "$writer_target" ] || [ -L "$writer_target" ] || [ "$(stat -c %h -- "$writer_target")" -ne 1 ]; then
        echo "refusing to replace unsafe ledger writer target: $writer_target" >&2
        exit 1
    fi
fi

if [ -n "$seed_source" ]; then
    /usr/bin/python3 "$writer_source" verify --input "$seed_source"
fi

temporary=$(mktemp /usr/local/sbin/.monitor-infrastructure-ledger.XXXXXX)
seed_temporary=
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    [ -z "$temporary" ] || rm -f "$temporary"
    [ -z "$seed_temporary" ] || rm -f "$seed_temporary"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

install -o root -g root -m 0755 "$writer_source" "$temporary"
if [ -n "$seed_source" ]; then
    seed_temporary=$(mktemp /run/monitor-infrastructure-ledger-seed.XXXXXX)
    install -o root -g root -m 0600 "$seed_source" "$seed_temporary"
fi
mv -f "$temporary" "$writer_target"
temporary=

if [ -n "$seed_temporary" ]; then
    "$writer_target" sync-seed \
        --seed "$seed_temporary" \
        --canonical-dir /var/lib/monitor-infrastructure-ledger \
        --public-file /var/lib/monitor-export/infrastructure-ledger.json
else
    "$writer_target" publish \
        --canonical-dir /var/lib/monitor-infrastructure-ledger \
        --public-file /var/lib/monitor-export/infrastructure-ledger.json
fi

echo "Installed append-only infrastructure ledger."
echo "Verify with: $writer_target publish"
