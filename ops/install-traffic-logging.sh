#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "install-traffic-logging.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
nginx_source="$script_dir/nginx/monitor-traffic.conf"
logrotate_source="$script_dir/logrotate/monitor-traffic"
prune_source="$script_dir/prune-traffic-logs.sh"
reopen_source="$script_dir/reopen-traffic-log.sh"
rotate_service_source="$script_dir/systemd/monitor-traffic-logrotate.service"
rotate_timer_source="$script_dir/systemd/monitor-traffic-logrotate.timer"
retention_service_source="$script_dir/systemd/monitor-traffic-retention.service"
retention_timer_source="$script_dir/systemd/monitor-traffic-retention.timer"

nginx_target=/etc/nginx/conf.d/monitor-traffic.conf
logrotate_dir=/etc/monitor-traffic
logrotate_target="$logrotate_dir/logrotate.conf"
legacy_logrotate_target=/etc/logrotate.d/monitor-traffic
prune_dir=/usr/local/lib/monitor-traffic
prune_target="$prune_dir/prune-logs.sh"
reopen_target="$prune_dir/reopen-log.sh"
rotate_service_target=/etc/systemd/system/monitor-traffic-logrotate.service
rotate_timer_target=/etc/systemd/system/monitor-traffic-logrotate.timer
retention_service_target=/etc/systemd/system/monitor-traffic-retention.service
retention_timer_target=/etc/systemd/system/monitor-traffic-retention.timer
traffic_log=/var/log/nginx/monitor-traffic.jsonl
retired_marker="$prune_dir/logging-disabled"
maintenance_lock_dir=/run/monitor-traffic-maintenance
maintenance_lock="$maintenance_lock_dir/maintenance.lock"
lock_open=false

for source in \
    "$nginx_source" "$logrotate_source" "$prune_source" "$reopen_source" \
    "$rotate_service_source" "$rotate_timer_source" \
    "$retention_service_source" "$retention_timer_source"
do
    if [ ! -f "$source" ] || [ -L "$source" ]; then
        echo "required traffic logging source is missing or unsafe: $source" >&2
        exit 1
    fi
done

if ! getent passwd www-data >/dev/null 2>&1 || ! getent group adm >/dev/null 2>&1; then
    echo "required www-data user or adm group does not exist" >&2
    exit 1
fi
if [ ! -x /usr/bin/flock ] || [ ! -x /usr/bin/python3 ] || [ ! -x /usr/sbin/invoke-rc.d ]; then
    echo "required flock, Python, or Nginx service helper is unavailable" >&2
    exit 1
fi
if [ ! -d /var/log/nginx ] || [ -L /var/log/nginx ]; then
    echo "required Nginx log directory is missing or unsafe" >&2
    exit 1
fi
for directory in "$logrotate_dir" "$prune_dir" "$maintenance_lock_dir"; do
    if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
        echo "refusing to use a symlinked or non-directory traffic logging root: $directory" >&2
        exit 1
    fi
    if [ -d "$directory" ] && {
        [ "$(stat -c %u -- "$directory")" -ne 0 ] ||
        [ $((0$(stat -c %a -- "$directory") & 0022)) -ne 0 ]
    }; then
        echo "refusing to use a non-root-owned or writable traffic logging root: $directory" >&2
        exit 1
    fi
done

if [ ! -d "$maintenance_lock_dir" ]; then
    install -d -o root -g root -m 0700 "$maintenance_lock_dir"
fi
exec 9>>"$maintenance_lock"
lock_open=true
if [ -L "$maintenance_lock" ] || [ ! -f "$maintenance_lock" ] || \
    [ "$(stat -c %u -- "$maintenance_lock")" -ne 0 ] || \
    [ "$(stat -c %h -- "$maintenance_lock")" -ne 1 ] || \
    [ $((0$(stat -c %a -- "$maintenance_lock") & 0022)) -ne 0 ]; then
    echo "traffic maintenance lock is unsafe" >&2
    exit 1
fi
if ! /usr/bin/flock --exclusive --timeout 30 9; then
    echo "another traffic logging maintenance operation is still running" >&2
    exit 1
fi

for target in \
    "$nginx_target" "$logrotate_target" "$legacy_logrotate_target" \
    "$prune_target" "$reopen_target" "$retired_marker" \
    "$rotate_service_target" "$rotate_timer_target" \
    "$retention_service_target" "$retention_timer_target" "$traffic_log"
do
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        echo "refusing to replace a symlinked or non-regular traffic logging target: $target" >&2
        exit 1
    fi
    if [ -e "$target" ] && [ "$(stat -c %h -- "$target")" -ne 1 ]; then
        echo "refusing to replace a multiply linked traffic logging target: $target" >&2
        exit 1
    fi
done

backup_dir=$(mktemp -d /tmp/monitor-traffic-install.XXXXXX)
committed=false
transaction_started=false
nginx_reload_attempted=false
traffic_existed=false
traffic_uid=
traffic_gid=
traffic_mode=
rotate_was_enabled=false
rotate_was_active=false
retention_was_enabled=false
retention_was_active=false
logrotate_dir_existed=false
prune_dir_existed=false

if [ -d "$logrotate_dir" ]; then
    logrotate_dir_existed=true
fi
if [ -d "$prune_dir" ]; then
    prune_dir_existed=true
fi

if systemctl is-enabled --quiet monitor-traffic-logrotate.timer >/dev/null 2>&1; then
    rotate_was_enabled=true
fi
if systemctl is-active --quiet monitor-traffic-logrotate.timer >/dev/null 2>&1; then
    rotate_was_active=true
fi
if systemctl is-enabled --quiet monitor-traffic-retention.timer >/dev/null 2>&1; then
    retention_was_enabled=true
fi
if systemctl is-active --quiet monitor-traffic-retention.timer >/dev/null 2>&1; then
    retention_was_active=true
fi

backup_target() {
    target=$1
    name=$2
    if [ -e "$target" ]; then
        cp -p -- "$target" "$backup_dir/$name"
    fi
}

restore_target() {
    backup=$1
    target=$2
    if [ -e "$backup" ]; then
        cp -p -- "$backup" "$target"
    else
        rm -f -- "$target"
    fi
}

restore_timer_state() {
    timer=$1
    was_enabled=$2
    was_active=$3
    if [ "$was_enabled" = true ]; then
        if ! systemctl enable "$timer" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    else
        systemctl disable "$timer" >/dev/null 2>&1 || true
        if systemctl is-enabled --quiet "$timer" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
    if [ "$was_active" = true ]; then
        if ! systemctl start "$timer" >/dev/null 2>&1 || \
            ! systemctl is-active --quiet "$timer" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    else
        systemctl stop "$timer" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$timer" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
}

quiesce_traffic_units() {
    systemctl stop \
        monitor-traffic-logrotate.timer monitor-traffic-retention.timer \
        monitor-traffic-logrotate.service monitor-traffic-retention.service \
        >/dev/null 2>&1 || true
    for unit in \
        monitor-traffic-logrotate.timer monitor-traffic-retention.timer \
        monitor-traffic-logrotate.service monitor-traffic-retention.service
    do
        if systemctl is-active --quiet "$unit"; then
            echo "traffic maintenance unit did not stop: $unit" >&2
            return 1
        fi
    done
}

rollback() {
    set +e
    rollback_failed=false
    rollback_can_remove_new_log=true
    systemctl disable --now monitor-traffic-logrotate.timer monitor-traffic-retention.timer >/dev/null 2>&1
    systemctl stop monitor-traffic-logrotate.service monitor-traffic-retention.service >/dev/null 2>&1

    for restore_pair in \
        "nginx.conf:$nginx_target" \
        "logrotate.conf:$logrotate_target" \
        "legacy-logrotate.conf:$legacy_logrotate_target" \
        "prune-logs.sh:$prune_target" \
        "reopen-log.sh:$reopen_target" \
        "retired.marker:$retired_marker" \
        "rotate.service:$rotate_service_target" \
        "rotate.timer:$rotate_timer_target" \
        "retention.service:$retention_service_target" \
        "retention.timer:$retention_timer_target"
    do
        backup_name=${restore_pair%%:*}
        restore_path=${restore_pair#*:}
        if ! restore_target "$backup_dir/$backup_name" "$restore_path"; then
            rollback_failed=true
        fi
    done

    if [ "$logrotate_dir_existed" != true ] && [ -d "$logrotate_dir" ]; then
        if ! rmdir "$logrotate_dir" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
    if [ "$prune_dir_existed" != true ] && [ -d "$prune_dir" ]; then
        if ! rmdir "$prune_dir" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
    if ! systemctl daemon-reload >/dev/null 2>&1; then
        rollback_failed=true
    fi
    if [ "$nginx_reload_attempted" = true ]; then
        rollback_can_remove_new_log=false
        if /usr/sbin/nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1; then
            rollback_can_remove_new_log=true
        else
            rollback_failed=true
        fi
    fi
    if [ "$traffic_existed" = true ]; then
        if ! chown "$traffic_uid:$traffic_gid" "$traffic_log" >/dev/null 2>&1; then
            rollback_failed=true
        fi
        if ! chmod "$traffic_mode" "$traffic_log" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    elif [ "$rollback_can_remove_new_log" = true ]; then
        if ! rm -f -- "$traffic_log"; then
            rollback_failed=true
        fi
    else
        echo "Nginx rollback reload failed; retained the newly created traffic log in case it is still open" >&2
    fi
    restore_timer_state monitor-traffic-logrotate.timer "$rotate_was_enabled" "$rotate_was_active"
    restore_timer_state monitor-traffic-retention.timer "$retention_was_enabled" "$retention_was_active"
    if [ "$rollback_failed" = true ]; then
        echo "traffic logging installation failed and rollback was incomplete; inspect Nginx and traffic timer state" >&2
    else
        echo "traffic logging installation failed; previous configuration was restored" >&2
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$transaction_started" = true ] && [ "$committed" != true ]; then
        rollback
    fi
    if [ "$lock_open" = true ]; then
        exec 9>&-
    fi
    case "$backup_dir" in
        /tmp/monitor-traffic-install.*) rm -rf -- "$backup_dir" ;;
    esac
    exit "$status"
}

trap 'exit 1' HUP INT TERM
trap finish EXIT

if ! /usr/sbin/nginx -t >/dev/null; then
    echo "existing Nginx configuration is invalid; refusing to install" >&2
    exit 1
fi
if ! /usr/sbin/logrotate --debug --state "$backup_dir/preflight.state" "$logrotate_source" >/dev/null 2>&1; then
    echo "traffic logrotate source failed validation" >&2
    exit 1
fi
if ! sh -n "$prune_source"; then
    echo "traffic retention helper failed validation" >&2
    exit 1
fi
if ! sh -n "$reopen_source"; then
    echo "traffic reopen helper failed validation" >&2
    exit 1
fi

backup_target "$nginx_target" nginx.conf
backup_target "$logrotate_target" logrotate.conf
backup_target "$legacy_logrotate_target" legacy-logrotate.conf
backup_target "$prune_target" prune-logs.sh
backup_target "$reopen_target" reopen-log.sh
backup_target "$retired_marker" retired.marker
backup_target "$rotate_service_target" rotate.service
backup_target "$rotate_timer_target" rotate.timer
backup_target "$retention_service_target" retention.service
backup_target "$retention_timer_target" retention.timer

if [ -e "$traffic_log" ]; then
    traffic_existed=true
    traffic_uid=$(stat -c %u -- "$traffic_log")
    traffic_gid=$(stat -c %g -- "$traffic_log")
    traffic_mode=$(stat -c %a -- "$traffic_log")
fi

transaction_started=true
quiesce_traffic_units
if [ "$traffic_existed" = true ]; then
    chown www-data:adm "$traffic_log"
    chmod 0640 "$traffic_log"
else
    install -o www-data -g adm -m 0640 /dev/null "$traffic_log"
fi

if [ ! -d "$logrotate_dir" ]; then
    install -d -o root -g root -m 0755 "$logrotate_dir"
fi
if [ ! -d "$prune_dir" ]; then
    install -d -o root -g root -m 0755 "$prune_dir"
fi
install -m 0644 "$nginx_source" "$nginx_target"
install -m 0644 "$logrotate_source" "$logrotate_target"
install -o root -g root -m 0755 "$prune_source" "$prune_target"
install -o root -g root -m 0755 "$reopen_source" "$reopen_target"
install -m 0644 "$rotate_service_source" "$rotate_service_target"
install -m 0644 "$rotate_timer_source" "$rotate_timer_target"
install -m 0644 "$retention_service_source" "$retention_service_target"
install -m 0644 "$retention_timer_source" "$retention_timer_target"
rm -f -- "$legacy_logrotate_target"
rm -f -- "$retired_marker"

if ! /usr/sbin/nginx -t; then
    echo "new Nginx traffic configuration failed validation" >&2
    exit 1
fi
if ! /usr/sbin/logrotate --debug --state "$backup_dir/validate.state" "$logrotate_target" >/dev/null 2>&1; then
    echo "installed traffic logrotate configuration failed validation" >&2
    exit 1
fi
if ! systemd-analyze verify \
    "$rotate_service_target" "$rotate_timer_target" \
    "$retention_service_target" "$retention_timer_target"
then
    echo "traffic logging systemd units failed validation" >&2
    exit 1
fi

systemctl daemon-reload
nginx_reload_attempted=true
systemctl reload nginx
systemctl enable --now monitor-traffic-logrotate.timer monitor-traffic-retention.timer
for timer in monitor-traffic-logrotate.timer monitor-traffic-retention.timer; do
    if ! systemctl is-enabled --quiet "$timer" || ! systemctl is-active --quiet "$timer"; then
        echo "traffic logging timer failed to remain enabled and active: $timer" >&2
        exit 1
    fi
done

committed=true
echo "Installed identifier-free request observations with one-minute rotation and retention checks."
