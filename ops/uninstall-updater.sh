#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall-updater.sh must run as root" >&2
    exit 1
fi

socket_dir=/var/lib/monitor-update-socket
legacy_socket_dir=/run/monitor-update

worker_is_quiescent() {
    worker_load_state=$(systemctl show monitor-update-worker.service --property=LoadState --value 2>/dev/null) || return 1
    worker_job=$(systemctl show monitor-update-worker.service --property=Job --value 2>/dev/null) || return 1
    worker_active_state=$(systemctl show monitor-update-worker.service --property=ActiveState --value 2>/dev/null) || return 1
    [ -z "$worker_job" ] || return 1
    case "$worker_load_state:$worker_active_state" in
        loaded:inactive|not-found:inactive) return 0 ;;
        *) return 1 ;;
    esac
}

unit_is_stopped() {
    inspected_unit=$1
    inspected_load_state=$(systemctl show "$inspected_unit" --property=LoadState --value 2>/dev/null) || return 1
    inspected_job=$(systemctl show "$inspected_unit" --property=Job --value 2>/dev/null) || return 1
    inspected_active_state=$(systemctl show "$inspected_unit" --property=ActiveState --value 2>/dev/null) || return 1
    [ -z "$inspected_job" ] || return 1
    case "$inspected_load_state:$inspected_active_state" in
        loaded:inactive|not-found:inactive) return 0 ;;
        *) return 1 ;;
    esac
}

capture_enable_state() {
    inspected_unit=$1
    inspected_load_state=$(systemctl show "$inspected_unit" --property=LoadState --value 2>/dev/null) || return 1
    inspected_enable_state=$(systemctl show "$inspected_unit" --property=UnitFileState --value 2>/dev/null) || return 1
    case "$inspected_load_state:$inspected_enable_state" in
        loaded:enabled) printf '%s\n' enabled ;;
        loaded:disabled) printf '%s\n' disabled ;;
        not-found:) printf '%s\n' not-found ;;
        *) return 1 ;;
    esac
}

capture_active_state() {
    inspected_unit=$1
    inspected_load_state=$(systemctl show "$inspected_unit" --property=LoadState --value 2>/dev/null) || return 1
    inspected_job=$(systemctl show "$inspected_unit" --property=Job --value 2>/dev/null) || return 1
    inspected_active_state=$(systemctl show "$inspected_unit" --property=ActiveState --value 2>/dev/null) || return 1
    [ -z "$inspected_job" ] || return 1
    case "$inspected_load_state:$inspected_active_state" in
        loaded:active) printf '%s\n' active ;;
        loaded:inactive|not-found:inactive) printf '%s\n' inactive ;;
        *) return 1 ;;
    esac
}

unit_is_disabled() {
    inspected_unit=$1
    inspected_load_state=$(systemctl show "$inspected_unit" --property=LoadState --value 2>/dev/null) || return 1
    inspected_enable_state=$(systemctl show "$inspected_unit" --property=UnitFileState --value 2>/dev/null) || return 1
    case "$inspected_load_state:$inspected_enable_state" in
        loaded:disabled|not-found:) return 0 ;;
        *) return 1 ;;
    esac
}

if ! worker_is_quiescent; then
    echo "refusing to uninstall unless the update worker is exactly inactive" >&2
    exit 1
fi

if [ -L "$socket_dir" ] || { [ -e "$socket_dir" ] && [ ! -d "$socket_dir" ]; } || \
   { [ -d "$socket_dir" ] && [ "$(stat -c %u:%g:%a -- "$socket_dir")" != "0:1001:750" ]; }; then
    echo "refusing to remove an unsafe updater socket directory" >&2
    exit 1
fi

for target in \
    /etc/systemd/system/monitor-update-gateway.socket \
    /etc/systemd/system/monitor-update-gateway.service \
    /etc/systemd/system/monitor-update-worker.path \
    /etc/systemd/system/monitor-update-worker.service \
    /usr/local/lib/monitor-updater/monitor_update_gateway.py \
    /usr/local/lib/monitor-updater/monitor_update_worker.py \
    /usr/local/lib/monitor-updater/apt-exact.conf \
    /usr/local/share/doc/monitor-updater/README.md \
    /etc/logrotate.d/monitor-update \
    /etc/tmpfiles.d/monitor-update.conf
do
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; } || \
       { [ -e "$target" ] && [ "$(stat -c %h -- "$target")" -ne 1 ]; }; then
        echo "refusing to remove an unsafe updater target: $target" >&2
        exit 1
    fi
done

backup_dir=$(mktemp -d /tmp/monitor-updater-uninstall.XXXXXX)
committed=false
transaction_started=false
rollback_failed=false

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
        cp -p -- "$backup" "$target" || rollback_failed=true
    else
        rm -f -- "$target" || rollback_failed=true
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$transaction_started" = true ] && [ "$committed" != true ]; then
        restore_target "$backup_dir/gateway.socket" /etc/systemd/system/monitor-update-gateway.socket
        restore_target "$backup_dir/gateway.service" /etc/systemd/system/monitor-update-gateway.service
        restore_target "$backup_dir/worker.path" /etc/systemd/system/monitor-update-worker.path
        restore_target "$backup_dir/worker.service" /etc/systemd/system/monitor-update-worker.service
        restore_target "$backup_dir/gateway.py" /usr/local/lib/monitor-updater/monitor_update_gateway.py
        restore_target "$backup_dir/worker.py" /usr/local/lib/monitor-updater/monitor_update_worker.py
        restore_target "$backup_dir/apt-exact.conf" /usr/local/lib/monitor-updater/apt-exact.conf
        restore_target "$backup_dir/README.md" /usr/local/share/doc/monitor-updater/README.md
        restore_target "$backup_dir/logrotate" /etc/logrotate.d/monitor-update
        restore_target "$backup_dir/tmpfiles" /etc/tmpfiles.d/monitor-update.conf
        systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
        case "$socket_enable_state" in
            enabled) systemctl enable monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true ;;
            disabled) systemctl disable monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true ;;
        esac
        case "$path_enable_state" in
            enabled) systemctl enable monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true ;;
            disabled) systemctl disable monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true ;;
        esac
        if [ "$socket_active_state" = active ]; then systemctl start monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$path_active_state" = active ]; then systemctl start monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$gateway_active_state" = active ]; then systemctl start monitor-update-gateway.service >/dev/null 2>&1 || rollback_failed=true; fi
    fi
    rm -rf -- "$backup_dir"
    if [ "$rollback_failed" = true ]; then
        echo "updater uninstall rollback was incomplete; inspect units and files" >&2
        status=1
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

for pair in \
    /etc/systemd/system/monitor-update-gateway.socket:gateway.socket \
    /etc/systemd/system/monitor-update-gateway.service:gateway.service \
    /etc/systemd/system/monitor-update-worker.path:worker.path \
    /etc/systemd/system/monitor-update-worker.service:worker.service \
    /usr/local/lib/monitor-updater/monitor_update_gateway.py:gateway.py \
    /usr/local/lib/monitor-updater/monitor_update_worker.py:worker.py \
    /usr/local/lib/monitor-updater/apt-exact.conf:apt-exact.conf \
    /usr/local/share/doc/monitor-updater/README.md:README.md \
    /etc/logrotate.d/monitor-update:logrotate \
    /etc/tmpfiles.d/monitor-update.conf:tmpfiles
do
    backup_target "${pair%%:*}" "${pair#*:}"
done

socket_enable_state=$(capture_enable_state monitor-update-gateway.socket) || {
    echo "could not safely inspect the updater socket enable state" >&2
    exit 1
}
path_enable_state=$(capture_enable_state monitor-update-worker.path) || {
    echo "could not safely inspect the updater path enable state" >&2
    exit 1
}
socket_active_state=$(capture_active_state monitor-update-gateway.socket) || {
    echo "could not safely inspect the updater socket active state" >&2
    exit 1
}
path_active_state=$(capture_active_state monitor-update-worker.path) || {
    echo "could not safely inspect the updater path active state" >&2
    exit 1
}
gateway_active_state=$(capture_active_state monitor-update-gateway.service) || {
    echo "could not safely inspect the updater gateway active state" >&2
    exit 1
}

transaction_started=true
systemctl disable --now monitor-update-worker.path monitor-update-gateway.socket >/dev/null 2>&1 || true
systemctl stop monitor-update-gateway.service >/dev/null 2>&1 || true
if ! worker_is_quiescent \
   || ! unit_is_stopped monitor-update-worker.path \
   || ! unit_is_stopped monitor-update-gateway.socket \
   || ! unit_is_stopped monitor-update-gateway.service \
   || ! unit_is_disabled monitor-update-worker.path \
   || ! unit_is_disabled monitor-update-gateway.socket
then
    echo "updater state changed during uninstall; restored the previous unit state" >&2
    exit 1
fi

rm -f -- \
    /etc/systemd/system/monitor-update-gateway.socket \
    /etc/systemd/system/monitor-update-gateway.service \
    /etc/systemd/system/monitor-update-worker.path \
    /etc/systemd/system/monitor-update-worker.service \
    /usr/local/lib/monitor-updater/monitor_update_gateway.py \
    /usr/local/lib/monitor-updater/monitor_update_worker.py \
    /usr/local/lib/monitor-updater/apt-exact.conf \
    /usr/local/share/doc/monitor-updater/README.md \
    /etc/logrotate.d/monitor-update \
    /etc/tmpfiles.d/monitor-update.conf
systemctl daemon-reload
committed=true

rmdir "$socket_dir" 2>/dev/null || true
rmdir "$legacy_socket_dir" 2>/dev/null || true
rmdir /usr/local/lib/monitor-updater 2>/dev/null || true
rmdir /usr/local/share/doc/monitor-updater 2>/dev/null || true

echo "Monitor host updater executables and units removed."
echo "Preserved state/audit and the locked service account for forensic continuity:"
echo "  /var/lib/monitor-update"
echo "  /var/lib/monitor-export/system-update.json"
echo "  /var/log/monitor-update-audit.jsonl"
echo "  monitor-updater account"
