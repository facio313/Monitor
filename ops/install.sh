#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

if ! getent passwd cks >/dev/null 2>&1 || ! getent group cks >/dev/null 2>&1; then
    echo "required user or group 'cks' does not exist" >&2
    exit 1
fi
if [ "$(id -u cks)" -ne 1001 ]; then
    echo "required user 'cks' must have UID 1001 for the pinned rootless socket" >&2
    exit 1
fi
if [ "$(getent group cks | cut -d: -f3)" -ne 1001 ]; then
    echo "required group 'cks' must have GID 1001 for the reduced snapshot" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

collector_target=/usr/local/lib/monitor-collector/collector.py
exporter_target=/usr/local/lib/monitor-collector/container_exporter.py
documentation_target=/usr/local/share/doc/monitor-collector/README.md
collector_service_target=/etc/systemd/system/monitor-collector.service
exporter_service_target=/etc/systemd/system/monitor-container-exporter.service
timer_target=/etc/systemd/system/monitor-collector.timer
default_target=/etc/default/monitor-collector

for source in \
    "$script_dir/collector.py" \
    "$script_dir/container_exporter.py" \
    "$script_dir/README.md" \
    "$script_dir/systemd/monitor-collector.service" \
    "$script_dir/systemd/monitor-container-exporter.service" \
    "$script_dir/systemd/monitor-collector.timer" \
    "$script_dir/monitor-collector.default"
do
    if [ ! -f "$source" ] || [ -L "$source" ]; then
        echo "required collector source is missing or unsafe: $source" >&2
        exit 1
    fi
done

backup_dir=$(mktemp -d /tmp/monitor-collector-install.XXXXXX)
had_collector=false
had_exporter=false
had_documentation=false
had_collector_service=false
had_exporter_service=false
had_timer=false
had_default=false
committed=false
transaction_started=false
was_timer_enabled=false
was_timer_active=false

restore_file() {
    backup=$1
    target=$2
    existed=$3
    if [ "$existed" = true ]; then
        cp -p "$backup" "$target"
    else
        rm -f "$target"
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    rollback_failed=false

    if [ "$transaction_started" = true ] && [ "$committed" != true ]; then
        systemctl stop monitor-collector.timer monitor-collector.service monitor-container-exporter.service >/dev/null 2>&1 || true
        restore_file "$backup_dir/collector.py" "$collector_target" "$had_collector" || rollback_failed=true
        restore_file "$backup_dir/container_exporter.py" "$exporter_target" "$had_exporter" || rollback_failed=true
        restore_file "$backup_dir/README.md" "$documentation_target" "$had_documentation" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.service" "$collector_service_target" "$had_collector_service" || rollback_failed=true
        restore_file "$backup_dir/monitor-container-exporter.service" "$exporter_service_target" "$had_exporter_service" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.timer" "$timer_target" "$had_timer" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.default" "$default_target" "$had_default" || rollback_failed=true
        systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
        if [ "$was_timer_enabled" = true ]; then
            systemctl enable monitor-collector.timer >/dev/null 2>&1 || rollback_failed=true
        else
            systemctl disable monitor-collector.timer >/dev/null 2>&1 || true
        fi
        if [ "$was_timer_active" = true ]; then
            systemctl start monitor-collector.timer >/dev/null 2>&1 || rollback_failed=true
        fi
    fi

    rm -f \
        "$backup_dir/collector.py" \
        "$backup_dir/container_exporter.py" \
        "$backup_dir/README.md" \
        "$backup_dir/monitor-collector.service" \
        "$backup_dir/monitor-container-exporter.service" \
        "$backup_dir/monitor-collector.timer" \
        "$backup_dir/monitor-collector.default"
    rmdir "$backup_dir" 2>/dev/null || true
    if [ "$rollback_failed" = true ]; then
        echo "collector installation rollback was incomplete; inspect installed unit and program files" >&2
        status=1
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

for target in \
    "$collector_target" \
    "$exporter_target" \
    "$documentation_target" \
    "$collector_service_target" \
    "$exporter_service_target" \
    "$timer_target" \
    "$default_target"
do
    if [ -L "$target" ]; then
        echo "refusing to replace a symlinked collector target: $target" >&2
        exit 1
    fi
    if [ -e "$target" ] && [ ! -f "$target" ]; then
        echo "refusing to replace a non-regular collector target: $target" >&2
        exit 1
    fi
    if [ -e "$target" ] && [ "$(stat -c %h -- "$target")" -ne 1 ]; then
        echo "refusing to replace a multiply linked collector target: $target" >&2
        exit 1
    fi
done

if systemctl is-enabled --quiet monitor-collector.timer 2>/dev/null; then
    was_timer_enabled=true
fi
if systemctl is-active --quiet monitor-collector.timer 2>/dev/null; then
    was_timer_active=true
fi

if [ -e "$collector_target" ]; then cp -p "$collector_target" "$backup_dir/collector.py"; had_collector=true; fi
if [ -e "$exporter_target" ]; then cp -p "$exporter_target" "$backup_dir/container_exporter.py"; had_exporter=true; fi
if [ -e "$documentation_target" ]; then cp -p "$documentation_target" "$backup_dir/README.md"; had_documentation=true; fi
if [ -e "$collector_service_target" ]; then cp -p "$collector_service_target" "$backup_dir/monitor-collector.service"; had_collector_service=true; fi
if [ -e "$exporter_service_target" ]; then cp -p "$exporter_service_target" "$backup_dir/monitor-container-exporter.service"; had_exporter_service=true; fi
if [ -e "$timer_target" ]; then cp -p "$timer_target" "$backup_dir/monitor-collector.timer"; had_timer=true; fi
if [ -e "$default_target" ]; then cp -p "$default_target" "$backup_dir/monitor-collector.default"; had_default=true; fi

transaction_started=true
systemctl stop monitor-collector.timer monitor-collector.service monitor-container-exporter.service >/dev/null 2>&1 || true
for unit in monitor-collector.timer monitor-collector.service monitor-container-exporter.service
do
    if systemctl is-active --quiet "$unit"; then
        echo "collector unit did not stop: $unit" >&2
        exit 1
    fi
done

install -d -m 0755 /usr/local/lib/monitor-collector
install -m 0755 "$script_dir/collector.py" "$collector_target"
install -m 0755 "$script_dir/container_exporter.py" "$exporter_target"
install -d -m 0755 /usr/local/share/doc/monitor-collector
install -m 0644 "$script_dir/README.md" "$documentation_target"
install -m 0644 "$script_dir/systemd/monitor-collector.service" "$collector_service_target"
install -m 0644 "$script_dir/systemd/monitor-container-exporter.service" "$exporter_service_target"
install -m 0644 "$script_dir/systemd/monitor-collector.timer" "$timer_target"
install -m 0640 "$script_dir/monitor-collector.default" "$default_target"

install -d -o root -g cks -m 0750 /var/lib/monitor-export /run/monitor-collector
install -d -o cks -g cks -m 0750 /run/monitor-container-exporter
systemctl daemon-reload
systemctl enable --now monitor-collector.timer
systemctl start monitor-collector.service
committed=true
echo "Installed. Inspect with: systemctl status monitor-collector.timer monitor-collector.service"
