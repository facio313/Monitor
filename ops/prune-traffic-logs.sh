#!/bin/sh
set -eu

log_dir=/var/log/nginx
retired_marker=/usr/local/lib/monitor-traffic/logging-disabled

if [ ! -d "$log_dir" ]; then
    exit 0
fi
if [ -e "$retired_marker" ] || [ -L "$retired_marker" ]; then
    if [ ! -f "$retired_marker" ] || [ -L "$retired_marker" ] || \
        [ "$(stat -c %u -- "$retired_marker")" -ne 0 ] || \
        [ "$(stat -c %g -- "$retired_marker")" -ne 0 ] || \
        [ "$(stat -c %h -- "$retired_marker")" -ne 1 ] || \
        [ "$(stat -c %a -- "$retired_marker")" -ne 600 ]; then
        echo "refusing unsafe Monitor traffic retirement marker" >&2
        exit 1
    fi
fi

# Never follow symlinks or remove multiply linked files.  The expression accepts
# only the active filename and the numeric rotations emitted by the supplied
# logrotate rule; unrelated Nginx logs are outside this service's authority.
/usr/bin/find -P "$log_dir" -xdev -maxdepth 1 -regextype posix-extended \
    -type f -links 1 \
    -regex '.*/monitor-traffic\.jsonl\.[0-9]+(\.gz)?' \
    -mmin +2880 -delete

# Only the uninstaller creates this marker, while holding the shared maintenance
# lock and after Nginx has successfully reloaded without the logging config.
# Absence of the config alone is never proof that the active descriptor closed.
# Waiting for the marker itself to age for 48 hours also gives gracefully exiting
# Nginx workers time to release their old descriptor before unlink is eligible.
marker_expired=false
if [ -f "$retired_marker" ] && \
    [ "$(/usr/bin/find -P "$retired_marker" -xdev -maxdepth 0 -type f -links 1 -mmin +2880 -print)" = "$retired_marker" ]; then
    marker_expired=true
fi
if [ "$marker_expired" = true ]; then
    /usr/bin/find -P "$log_dir" -xdev -maxdepth 1 -regextype posix-extended \
        -type f -links 1 \
        -regex '.*/monitor-traffic\.jsonl' \
        -mmin +2880 -delete
fi
