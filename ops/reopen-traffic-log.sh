#!/bin/sh
set -eu
umask 077

state_dir=/var/lib/monitor-traffic-logrotate
marker="$state_dir/reopen-required"
temporary=

cleanup() {
    if [ -n "$temporary" ]; then
        rm -f -- "$temporary"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

validate_state_dir() {
    if [ ! -d "$state_dir" ] || [ -L "$state_dir" ] || \
        [ "$(stat -c %u -- "$state_dir")" -ne 0 ] || \
        [ "$(stat -c %g -- "$state_dir")" -ne 0 ] || \
        [ "$(stat -c %a -- "$state_dir")" -ne 700 ]; then
        echo "refusing unsafe Monitor traffic logrotate state directory" >&2
        return 1
    fi
}

validate_marker() {
    if [ -L "$marker" ] || [ ! -f "$marker" ] || \
        [ "$(stat -c %u -- "$marker")" -ne 0 ] || \
        [ "$(stat -c %g -- "$marker")" -ne 0 ] || \
        [ "$(stat -c %h -- "$marker")" -ne 1 ] || \
        [ "$(stat -c %a -- "$marker")" -ne 600 ]; then
        echo "refusing unsafe Monitor traffic reopen marker" >&2
        return 1
    fi
}

fsync_path() {
    /usr/bin/python3 -I -c '
import os
import stat
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=False)
flags = os.O_RDONLY
if stat.S_ISDIR(metadata.st_mode):
    flags |= getattr(os, "O_DIRECTORY", 0)
flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
descriptor = os.open(sys.argv[1], flags)
try:
    opened = os.fstat(descriptor)
    if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
        raise RuntimeError("fsync target changed during validation")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
' "$1"
}

mark_required() {
    validate_state_dir
    if [ -e "$marker" ] || [ -L "$marker" ]; then
        validate_marker
        return 0
    fi
    temporary=$(mktemp "$state_dir/.reopen-required.XXXXXX")
    install -o root -g root -m 0600 /dev/null "$temporary"
    fsync_path "$temporary"
    mv -f -- "$temporary" "$marker"
    temporary=
    fsync_path "$state_dir"
}

retry_reopen() {
    if [ ! -e "$state_dir" ] && [ ! -L "$state_dir" ]; then
        return 0
    fi
    validate_state_dir
    if [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
        return 0
    fi
    validate_marker
    if ! /usr/sbin/invoke-rc.d nginx rotate >/dev/null 2>&1; then
        echo "Nginx did not reopen the Monitor traffic log; retry marker retained" >&2
        return 1
    fi
    rm -f -- "$marker"
    if ! fsync_path "$state_dir"; then
        mark_required || true
        echo "failed to durably clear the Monitor traffic reopen marker" >&2
        return 1
    fi
}

case "${1:-}" in
    mark)
        mark_required
        ;;
    retry)
        retry_reopen
        ;;
    *)
        echo "usage: reopen-traffic-log.sh {mark|retry}" >&2
        exit 2
        ;;
esac
