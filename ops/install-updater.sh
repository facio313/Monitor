#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "install-updater.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gateway_source="$script_dir/monitor_update_gateway.py"
worker_source="$script_dir/monitor_update_worker.py"
apt_config_source="$script_dir/monitor-update-apt.conf"
documentation_source="$script_dir/UPDATER.md"
socket_source="$script_dir/systemd/monitor-update-gateway.socket"
gateway_service_source="$script_dir/systemd/monitor-update-gateway.service"
path_source="$script_dir/systemd/monitor-update-worker.path"
worker_service_source="$script_dir/systemd/monitor-update-worker.service"
logrotate_source="$script_dir/logrotate/monitor-update"
tmpfiles_source="$script_dir/tmpfiles/monitor-update.conf"

library_dir=/usr/local/lib/monitor-updater
gateway_target="$library_dir/monitor_update_gateway.py"
worker_target="$library_dir/monitor_update_worker.py"
apt_config_target="$library_dir/apt-exact.conf"
documentation_dir=/usr/local/share/doc/monitor-updater
documentation_target="$documentation_dir/README.md"
socket_target=/etc/systemd/system/monitor-update-gateway.socket
gateway_service_target=/etc/systemd/system/monitor-update-gateway.service
path_target=/etc/systemd/system/monitor-update-worker.path
worker_service_target=/etc/systemd/system/monitor-update-worker.service
logrotate_target=/etc/logrotate.d/monitor-update
tmpfiles_target=/etc/tmpfiles.d/monitor-update.conf
state_dir=/var/lib/monitor-update
incoming_dir="$state_dir/incoming"
processing_dir="$state_dir/processing"
public_dir=/var/lib/monitor-export
public_status="$public_dir/system-update.json"
audit_log=/var/log/monitor-update-audit.jsonl
socket_parent=/var/lib
socket_dir=/var/lib/monitor-update-socket
legacy_socket_dir=/run/monitor-update
updater_user=monitor-updater
updater_group=monitor-updater

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

for source in \
    "$gateway_source" "$worker_source" "$apt_config_source" "$documentation_source" \
    "$socket_source" "$gateway_service_source" "$path_source" \
    "$worker_service_source" "$logrotate_source" "$tmpfiles_source"
do
    if [ ! -f "$source" ] || [ -L "$source" ] || [ "$(stat -c %h -- "$source")" -ne 1 ]; then
        echo "required updater source is missing or unsafe: $source" >&2
        exit 1
    fi
done

for command in \
    /usr/bin/python3 /usr/bin/apt-get /usr/bin/apt-config /usr/bin/dpkg /usr/bin/systemd-inhibit \
    /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/groupadd /usr/sbin/groupdel \
    /usr/bin/systemd-tmpfiles /usr/bin/systemd-analyze
do
    if [ ! -x "$command" ]; then
        echo "required updater command is unavailable: $command" >&2
        exit 1
    fi
done

if ! getent passwd cks >/dev/null 2>&1 || ! getent group cks >/dev/null 2>&1 || \
   ! getent group adm >/dev/null 2>&1; then
    echo "required cks user/group or adm group does not exist" >&2
    exit 1
fi
if [ "$(id -u cks)" -ne 1001 ] || [ "$(getent group cks | cut -d: -f3)" -ne 1001 ]; then
    echo "cks must retain UID/GID 1001 for the pinned Unix peer credential" >&2
    exit 1
fi
if ! worker_is_quiescent; then
    echo "refusing to replace updater files unless the update worker is exactly inactive" >&2
    exit 1
fi

/usr/bin/python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' "$gateway_source"
/usr/bin/python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' "$worker_source"

for target in \
    "$gateway_target" "$worker_target" "$apt_config_target" "$documentation_target" \
    "$socket_target" "$gateway_service_target" "$path_target" \
    "$worker_service_target" "$logrotate_target" "$tmpfiles_target" "$public_status" "$audit_log"
do
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        echo "refusing to replace a symlinked or non-regular updater target: $target" >&2
        exit 1
    fi
    if [ -e "$target" ] && [ "$(stat -c %h -- "$target")" -ne 1 ]; then
        echo "refusing to replace a multiply linked updater target: $target" >&2
        exit 1
    fi
done

if [ ! -d "$public_dir" ] || [ -L "$public_dir" ] || \
   [ "$(stat -c %u -- "$public_dir")" -ne 0 ] || \
   [ "$(stat -c %g -- "$public_dir")" -ne 1001 ] || \
   [ $((0$(stat -c %a -- "$public_dir") & 0022)) -ne 0 ]; then
    echo "existing Monitor export directory is missing or unsafe" >&2
    exit 1
fi

backup_dir=$(mktemp -d /tmp/monitor-updater-install.XXXXXX)
committed=false
transaction_started=false
rollback_failed=false
user_created=false
group_created=false
library_dir_created=false
documentation_dir_created=false
state_dir_created=false
incoming_dir_created=false
processing_dir_created=false
socket_dir_created=false
audit_created=false
public_status_created=false
socket_was_enabled=false
socket_was_active=false
gateway_was_active=false
path_was_enabled=false
path_was_active=false

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
        systemctl stop monitor-update-worker.path monitor-update-gateway.service monitor-update-gateway.socket >/dev/null 2>&1 || true
        # `enable --now` can create one wants symlink before a later unit
        # fails. Remove only links that did not exist before this transaction
        # while the newly installed unit files are still available.
        if [ "$socket_was_enabled" != true ]; then
            systemctl disable monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true
        fi
        if [ "$path_was_enabled" != true ]; then
            systemctl disable monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true
        fi
        restore_target "$backup_dir/gateway.py" "$gateway_target"
        restore_target "$backup_dir/worker.py" "$worker_target"
        restore_target "$backup_dir/apt-exact.conf" "$apt_config_target"
        restore_target "$backup_dir/README.md" "$documentation_target"
        restore_target "$backup_dir/gateway.socket" "$socket_target"
        restore_target "$backup_dir/gateway.service" "$gateway_service_target"
        restore_target "$backup_dir/worker.path" "$path_target"
        restore_target "$backup_dir/worker.service" "$worker_service_target"
        restore_target "$backup_dir/logrotate" "$logrotate_target"
        restore_target "$backup_dir/tmpfiles" "$tmpfiles_target"
        restore_target "$backup_dir/public-status" "$public_status"
        restore_target "$backup_dir/audit" "$audit_log"
        systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
        if [ "$socket_was_enabled" = true ]; then systemctl enable monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$path_was_enabled" = true ]; then systemctl enable monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$socket_was_active" = true ]; then systemctl start monitor-update-gateway.socket >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$path_was_active" = true ]; then systemctl start monitor-update-worker.path >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$gateway_was_active" = true ]; then systemctl start monitor-update-gateway.service >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$processing_dir_created" = true ]; then rmdir "$processing_dir" 2>/dev/null || true; fi
        if [ "$incoming_dir_created" = true ]; then rmdir "$incoming_dir" 2>/dev/null || true; fi
        if [ "$state_dir_created" = true ]; then rmdir "$state_dir" 2>/dev/null || true; fi
        if [ "$documentation_dir_created" = true ]; then rmdir "$documentation_dir" 2>/dev/null || true; fi
        if [ "$library_dir_created" = true ]; then rmdir "$library_dir" 2>/dev/null || true; fi
        if [ "$socket_dir_created" = true ]; then rmdir "$socket_dir" 2>/dev/null || true; fi
        if [ "$user_created" = true ]; then /usr/sbin/userdel "$updater_user" >/dev/null 2>&1 || rollback_failed=true; fi
        if [ "$group_created" = true ]; then /usr/sbin/groupdel "$updater_group" >/dev/null 2>&1 || rollback_failed=true; fi
    fi
    rm -rf -- "$backup_dir"
    if [ "$rollback_failed" = true ]; then
        echo "updater installation rollback was incomplete; inspect units and files" >&2
        status=1
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

for pair in \
    "$gateway_target:gateway.py" "$worker_target:worker.py" \
    "$apt_config_target:apt-exact.conf" \
    "$documentation_target:README.md" "$socket_target:gateway.socket" \
    "$gateway_service_target:gateway.service" "$path_target:worker.path" \
    "$worker_service_target:worker.service" "$logrotate_target:logrotate" \
    "$tmpfiles_target:tmpfiles" \
    "$public_status:public-status" "$audit_log:audit"
do
    backup_target "${pair%%:*}" "${pair#*:}"
done

if systemctl is-enabled --quiet monitor-update-gateway.socket 2>/dev/null; then socket_was_enabled=true; fi
if systemctl is-active --quiet monitor-update-gateway.socket 2>/dev/null; then socket_was_active=true; fi
if systemctl is-active --quiet monitor-update-gateway.service 2>/dev/null; then gateway_was_active=true; fi
if systemctl is-enabled --quiet monitor-update-worker.path 2>/dev/null; then path_was_enabled=true; fi
if systemctl is-active --quiet monitor-update-worker.path 2>/dev/null; then path_was_active=true; fi

transaction_started=true

if ! getent group "$updater_group" >/dev/null 2>&1; then
    /usr/sbin/groupadd --system "$updater_group"
    group_created=true
fi
updater_gid=$(getent group "$updater_group" | cut -d: -f3)
if [ -z "$updater_gid" ] || [ "$updater_gid" -eq 0 ]; then
    echo "dedicated updater group is invalid" >&2
    exit 1
fi
if ! getent passwd "$updater_user" >/dev/null 2>&1; then
    /usr/sbin/useradd --system --gid "$updater_group" --home-dir /nonexistent --shell /usr/sbin/nologin "$updater_user"
    user_created=true
fi
updater_uid=$(id -u "$updater_user")
passwd_record=$(getent passwd "$updater_user")
if [ "$updater_uid" -eq 0 ] || [ "$(printf '%s' "$passwd_record" | cut -d: -f4)" -ne "$updater_gid" ] || \
   [ "$(printf '%s' "$passwd_record" | cut -d: -f6)" != /nonexistent ] || \
   [ "$(printf '%s' "$passwd_record" | cut -d: -f7)" != /usr/sbin/nologin ]; then
    echo "dedicated updater account does not match the required locked contract" >&2
    exit 1
fi

for directory in "$library_dir" "$documentation_dir" "$state_dir" "$incoming_dir" "$processing_dir"; do
    if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
        echo "refusing to use a symlinked or non-directory updater path: $directory" >&2
        exit 1
    fi
done
if [ ! -d "$library_dir" ]; then library_dir_created=true; fi
if [ ! -d "$documentation_dir" ]; then documentation_dir_created=true; fi
if [ ! -d "$state_dir" ]; then state_dir_created=true; fi
if [ ! -d "$incoming_dir" ]; then incoming_dir_created=true; fi
if [ ! -d "$processing_dir" ]; then processing_dir_created=true; fi
if [ -d "$library_dir" ] && { [ "$(stat -c %u:%g -- "$library_dir")" != "0:0" ] || [ $((0$(stat -c %a -- "$library_dir") & 0022)) -ne 0 ]; }; then
    echo "existing updater library directory is not root-owned and protected" >&2
    exit 1
fi
if [ -d "$documentation_dir" ] && { [ "$(stat -c %u:%g -- "$documentation_dir")" != "0:0" ] || [ $((0$(stat -c %a -- "$documentation_dir") & 0022)) -ne 0 ]; }; then
    echo "existing updater documentation directory is not root-owned and protected" >&2
    exit 1
fi
if [ -d "$state_dir" ] && [ "$(stat -c %u:%g:%a -- "$state_dir")" != "0:$updater_gid:750" ]; then
    echo "existing updater state directory violates its root-owned contract" >&2
    exit 1
fi
if [ -d "$incoming_dir" ] && [ "$(stat -c %u:%g:%a -- "$incoming_dir")" != "$updater_uid:$updater_gid:700" ]; then
    echo "existing updater queue violates its dedicated-user contract" >&2
    exit 1
fi
if [ -d "$processing_dir" ] && [ "$(stat -c %u:%g:%a -- "$processing_dir")" != "0:0:700" ]; then
    echo "existing updater processing directory violates its root-only contract" >&2
    exit 1
fi
for directory in /var "$socket_parent"; do
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
        echo "updater socket parent is missing or unsafe: $directory" >&2
        exit 1
    fi
    directory_uid=$(stat -c %u -- "$directory")
    directory_gid=$(stat -c %g -- "$directory")
    directory_mode=$((0$(stat -c %a -- "$directory")))
    if [ "$directory_uid" -ne 0 ] || \
       [ $((directory_mode & 0022)) -ne 0 ]; then
        echo "updater socket parent has an unsafe owner or mode: $directory" >&2
        exit 1
    fi
    if [ "$directory_gid" -eq 1001 ]; then
        traverse_bit=0010
    else
        traverse_bit=0001
    fi
    if [ $((directory_mode & traverse_bit)) -eq 0 ]; then
        echo "cks cannot traverse updater socket parent: $directory" >&2
        exit 1
    fi
done
if [ -L "$socket_dir" ] || { [ -e "$socket_dir" ] && [ ! -d "$socket_dir" ]; }; then
    echo "refusing to use an unsafe updater socket directory" >&2
    exit 1
fi
if [ ! -d "$socket_dir" ]; then socket_dir_created=true; fi
if [ -d "$socket_dir" ] && [ "$(stat -c %u:%g:%a -- "$socket_dir")" != "0:1001:750" ]; then
    echo "existing updater socket directory violates its root:cks contract" >&2
    exit 1
fi

systemctl stop monitor-update-worker.path monitor-update-gateway.service monitor-update-gateway.socket >/dev/null 2>&1 || true
if ! worker_is_quiescent \
   || ! unit_is_stopped monitor-update-worker.path \
   || ! unit_is_stopped monitor-update-gateway.service \
   || ! unit_is_stopped monitor-update-gateway.socket
then
    echo "an update worker started during installation; no updater file was replaced" >&2
    exit 1
fi
install -d -o root -g root -m 0755 "$library_dir" "$documentation_dir"
install -d -o root -g "$updater_group" -m 0750 "$state_dir"
install -d -o "$updater_user" -g "$updater_group" -m 0700 "$incoming_dir"
install -d -o root -g root -m 0700 "$processing_dir"

install -o root -g root -m 0755 "$gateway_source" "$gateway_target"
install -o root -g root -m 0755 "$worker_source" "$worker_target"
install -o root -g root -m 0644 "$apt_config_source" "$apt_config_target"
install -o root -g root -m 0644 "$documentation_source" "$documentation_target"
install -o root -g root -m 0644 "$socket_source" "$socket_target"
install -o root -g root -m 0644 "$gateway_service_source" "$gateway_service_target"
install -o root -g root -m 0644 "$path_source" "$path_target"
install -o root -g root -m 0644 "$worker_service_source" "$worker_service_target"
install -o root -g root -m 0644 "$logrotate_source" "$logrotate_target"
install -o root -g root -m 0644 "$tmpfiles_source" "$tmpfiles_target"

if [ ! -e "$audit_log" ]; then audit_created=true; fi
if [ ! -e "$public_status" ]; then public_status_created=true; fi
if [ ! -e "$audit_log" ]; then
    install -o root -g adm -m 0640 /dev/null "$audit_log"
else
    chown root:adm "$audit_log"
    chmod 0640 "$audit_log"
fi
if [ -e "$public_status" ]; then
    chown root:cks "$public_status"
    chmod 0640 "$public_status"
fi

systemctl daemon-reload
/usr/bin/apt-config -c "$apt_config_target" dump >/dev/null
/usr/bin/systemd-tmpfiles --create "$tmpfiles_target"
if [ ! -d "$socket_dir" ] || [ -L "$socket_dir" ] || \
   [ "$(stat -c %u:%g:%a -- "$socket_dir")" != "0:1001:750" ]; then
    echo "socket directory was not created with the pinned root:cks 0750 contract" >&2
    exit 1
fi
/usr/bin/systemd-analyze verify "$socket_target" "$gateway_service_target" "$path_target" "$worker_service_target"
/usr/bin/python3 "$worker_target" \
    --incoming="$incoming_dir" --processing="$processing_dir" \
    --plan="$state_dir/plan.json" --public-status="$public_status" \
    --audit-log="$audit_log" --lock=/run/monitor-update-worker.lock \
    --request-user="$updater_user" --peer-uid=1001 --public-group=cks --initialize-only
systemctl enable --now monitor-update-gateway.socket monitor-update-worker.path
committed=true
rmdir "$legacy_socket_dir" 2>/dev/null || true

echo "Monitor host updater installed but no package action was run."
echo "Inspect: systemctl status monitor-update-gateway.socket monitor-update-worker.path"
