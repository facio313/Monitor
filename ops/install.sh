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
linux_telemetry_target=/usr/local/lib/monitor-collector/linux_telemetry.py
log_pipeline_target=/usr/local/lib/monitor-collector/log_pipeline.py
log_sources_target=/usr/local/lib/monitor-collector/log_sources.py
log_store_target=/usr/local/lib/monitor-collector/log_store.py
generic_log_collector_target=/usr/local/lib/monitor-collector/generic_log_collector.py
exporter_target=/usr/local/lib/monitor-collector/container_exporter.py
alert_engine_target=/usr/local/lib/monitor-collector/alert_engine.py
alert_runtime_target=/usr/local/lib/monitor-collector/alert_runtime.py
alert_store_target=/usr/local/lib/monitor-collector/alert_store.py
alert_delivery_target=/usr/local/lib/monitor-collector/alert_delivery.py
rule_target=/usr/local/lib/monitor-collector/rules/default-rules.v1.json
documentation_target=/usr/local/share/doc/monitor-collector/README.md
alert_delivery_doc_target=/usr/local/share/doc/monitor-collector/alert-delivery.md
alert_delivery_example_target=/usr/local/share/doc/monitor-collector/alert-delivery.example.v1.json
collector_service_target=/etc/systemd/system/monitor-collector.service
exporter_service_target=/etc/systemd/system/monitor-container-exporter.service
timer_target=/etc/systemd/system/monitor-collector.timer
default_target=/etc/default/monitor-collector
delivery_service_target=/etc/systemd/system/monitor-alert-delivery.service
delivery_timer_target=/etc/systemd/system/monitor-alert-delivery.timer
log_source_config_target=/etc/monitor-collector/log-sources.json

for source in \
    "$script_dir/collector.py" \
    "$script_dir/linux_telemetry.py" \
    "$script_dir/log_pipeline.py" \
    "$script_dir/log_sources.py" \
    "$script_dir/log_store.py" \
    "$script_dir/generic_log_collector.py" \
    "$script_dir/container_exporter.py" \
    "$script_dir/alert_engine.py" \
    "$script_dir/alert_runtime.py" \
    "$script_dir/alert_store.py" \
    "$script_dir/alert_delivery.py" \
    "$script_dir/rules/default-rules.v1.json" \
    "$script_dir/README.md" \
    "$script_dir/../docs/alert-delivery.md" \
    "$script_dir/rules/alert-delivery.example.v1.json" \
    "$script_dir/systemd/monitor-collector.service" \
    "$script_dir/systemd/monitor-container-exporter.service" \
    "$script_dir/systemd/monitor-collector.timer" \
    "$script_dir/systemd/monitor-alert-delivery.service" \
    "$script_dir/systemd/monitor-alert-delivery.timer" \
    "$script_dir/monitor-collector.default" \
    "$script_dir/log-sources.example.json"
do
    if [ ! -f "$source" ] || [ -L "$source" ]; then
        echo "required collector source is missing or unsafe: $source" >&2
        exit 1
    fi
done

backup_dir=$(mktemp -d /tmp/monitor-collector-install.XXXXXX)
had_collector=false
had_linux_telemetry=false
had_log_pipeline=false
had_log_sources=false
had_log_store=false
had_generic_log_collector=false
had_exporter=false
had_alert_engine=false
had_alert_runtime=false
had_alert_store=false
had_alert_delivery=false
had_rule=false
had_rule_directory=false
had_documentation=false
had_alert_delivery_doc=false
had_alert_delivery_example=false
had_collector_service=false
had_exporter_service=false
had_timer=false
had_default=false
had_delivery_service=false
had_delivery_timer=false
had_log_source_config=false
had_log_source_config_directory=false
had_output_directory=false
had_collector_runtime_directory=false
had_exporter_runtime_directory=false
created_output_directory=false
created_collector_runtime_directory=false
created_exporter_runtime_directory=false
output_directory_uid=
output_directory_gid=
output_directory_mode=
collector_runtime_directory_uid=
collector_runtime_directory_gid=
collector_runtime_directory_mode=
exporter_runtime_directory_uid=
exporter_runtime_directory_gid=
exporter_runtime_directory_mode=
committed=false
transaction_started=false
was_timer_enabled=false
was_timer_active=false
was_delivery_timer_enabled=false
was_delivery_timer_active=false

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

capture_directory_metadata() {
    metadata=$(stat -c '%u %g %a' -- "$1")
    captured_directory_uid=${metadata%% *}
    metadata=${metadata#* }
    captured_directory_gid=${metadata%% *}
    captured_directory_mode=${metadata#* }
}

restore_directory() {
    target=$1
    existed=$2
    created=$3
    owner=$4
    group=$5
    mode=$6
    if [ "$existed" = true ]; then
        if [ -L "$target" ] || [ ! -d "$target" ]; then
            return 1
        fi
        chown "$owner:$group" "$target" && chmod "$mode" "$target"
    elif [ "$created" != true ]; then
        # The installer never created this path. Leave anything that appeared
        # after the preflight snapshot untouched.
        return 0
    elif [ ! -e "$target" ] && [ ! -L "$target" ]; then
        return 0
    elif [ -L "$target" ] || [ ! -d "$target" ]; then
        return 1
    else
        # Never delete data created by a partially started collector. Only a
        # known-empty directory can be removed during rollback.
        rmdir "$target"
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    rollback_failed=false

    if [ "$transaction_started" = true ] && [ "$committed" != true ]; then
        systemctl stop monitor-alert-delivery.timer monitor-alert-delivery.service monitor-collector.timer monitor-collector.service monitor-container-exporter.service >/dev/null 2>&1 || true
        restore_file "$backup_dir/collector.py" "$collector_target" "$had_collector" || rollback_failed=true
        restore_file "$backup_dir/linux_telemetry.py" "$linux_telemetry_target" "$had_linux_telemetry" || rollback_failed=true
        restore_file "$backup_dir/log_pipeline.py" "$log_pipeline_target" "$had_log_pipeline" || rollback_failed=true
        restore_file "$backup_dir/log_sources.py" "$log_sources_target" "$had_log_sources" || rollback_failed=true
        restore_file "$backup_dir/log_store.py" "$log_store_target" "$had_log_store" || rollback_failed=true
        restore_file "$backup_dir/generic_log_collector.py" "$generic_log_collector_target" "$had_generic_log_collector" || rollback_failed=true
        restore_file "$backup_dir/container_exporter.py" "$exporter_target" "$had_exporter" || rollback_failed=true
        restore_file "$backup_dir/alert_engine.py" "$alert_engine_target" "$had_alert_engine" || rollback_failed=true
        restore_file "$backup_dir/alert_runtime.py" "$alert_runtime_target" "$had_alert_runtime" || rollback_failed=true
        restore_file "$backup_dir/alert_store.py" "$alert_store_target" "$had_alert_store" || rollback_failed=true
        restore_file "$backup_dir/alert_delivery.py" "$alert_delivery_target" "$had_alert_delivery" || rollback_failed=true
        restore_file "$backup_dir/default-rules.v1.json" "$rule_target" "$had_rule" || rollback_failed=true
        if [ "$had_rule_directory" != true ]; then
            rmdir /usr/local/lib/monitor-collector/rules 2>/dev/null || true
        fi
        restore_file "$backup_dir/README.md" "$documentation_target" "$had_documentation" || rollback_failed=true
        restore_file "$backup_dir/alert-delivery.md" "$alert_delivery_doc_target" "$had_alert_delivery_doc" || rollback_failed=true
        restore_file "$backup_dir/alert-delivery.example.v1.json" "$alert_delivery_example_target" "$had_alert_delivery_example" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.service" "$collector_service_target" "$had_collector_service" || rollback_failed=true
        restore_file "$backup_dir/monitor-container-exporter.service" "$exporter_service_target" "$had_exporter_service" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.timer" "$timer_target" "$had_timer" || rollback_failed=true
        restore_file "$backup_dir/monitor-collector.default" "$default_target" "$had_default" || rollback_failed=true
        restore_file "$backup_dir/monitor-alert-delivery.service" "$delivery_service_target" "$had_delivery_service" || rollback_failed=true
        restore_file "$backup_dir/monitor-alert-delivery.timer" "$delivery_timer_target" "$had_delivery_timer" || rollback_failed=true
        if [ "$had_log_source_config" != true ]; then
            rm -f "$log_source_config_target" || rollback_failed=true
        fi
        if [ "$had_log_source_config_directory" != true ]; then
            rmdir /etc/monitor-collector 2>/dev/null || true
        fi
        restore_directory /var/lib/monitor-export "$had_output_directory" "$created_output_directory" "$output_directory_uid" "$output_directory_gid" "$output_directory_mode" || rollback_failed=true
        restore_directory /run/monitor-collector "$had_collector_runtime_directory" "$created_collector_runtime_directory" "$collector_runtime_directory_uid" "$collector_runtime_directory_gid" "$collector_runtime_directory_mode" || rollback_failed=true
        restore_directory /run/monitor-container-exporter "$had_exporter_runtime_directory" "$created_exporter_runtime_directory" "$exporter_runtime_directory_uid" "$exporter_runtime_directory_gid" "$exporter_runtime_directory_mode" || rollback_failed=true
        systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
        if [ "$was_timer_enabled" = true ]; then
            systemctl enable monitor-collector.timer >/dev/null 2>&1 || rollback_failed=true
        else
            systemctl disable monitor-collector.timer >/dev/null 2>&1 || true
        fi
        if [ "$was_timer_active" = true ]; then
            systemctl start monitor-collector.timer >/dev/null 2>&1 || rollback_failed=true
        fi
        if [ "$was_delivery_timer_enabled" = true ]; then
            systemctl enable monitor-alert-delivery.timer >/dev/null 2>&1 || rollback_failed=true
        else
            systemctl disable monitor-alert-delivery.timer >/dev/null 2>&1 || true
        fi
        if [ "$was_delivery_timer_active" = true ]; then
            systemctl start monitor-alert-delivery.timer >/dev/null 2>&1 || rollback_failed=true
        fi
    fi

    rm -f \
        "$backup_dir/collector.py" \
        "$backup_dir/linux_telemetry.py" \
        "$backup_dir/log_pipeline.py" \
        "$backup_dir/log_sources.py" \
        "$backup_dir/log_store.py" \
        "$backup_dir/generic_log_collector.py" \
        "$backup_dir/container_exporter.py" \
        "$backup_dir/alert_engine.py" \
        "$backup_dir/alert_runtime.py" \
        "$backup_dir/alert_store.py" \
        "$backup_dir/alert_delivery.py" \
        "$backup_dir/default-rules.v1.json" \
        "$backup_dir/README.md" \
        "$backup_dir/alert-delivery.md" \
        "$backup_dir/alert-delivery.example.v1.json" \
        "$backup_dir/monitor-collector.service" \
        "$backup_dir/monitor-container-exporter.service" \
        "$backup_dir/monitor-collector.timer" \
        "$backup_dir/monitor-collector.default" \
        "$backup_dir/monitor-alert-delivery.service" \
        "$backup_dir/monitor-alert-delivery.timer"
    rmdir "$backup_dir" 2>/dev/null || true
    if [ "$rollback_failed" = true ]; then
        echo "collector installation rollback was incomplete; inspect installed unit and program files" >&2
        status=1
    fi
    exit "$status"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

for directory in \
    /usr/local/lib/monitor-collector \
    /usr/local/lib/monitor-collector/rules \
    /usr/local/share/doc/monitor-collector \
    /etc/monitor-collector \
    /var/lib/monitor-export \
    /run/monitor-collector \
    /run/monitor-container-exporter
do
    if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
        echo "refusing to use an unsafe collector installation directory: $directory" >&2
        exit 1
    fi
done

if [ -d /etc/monitor-collector ] && {
    [ "$(stat -c %u -- /etc/monitor-collector)" -ne 0 ] \
    || [ -n "$(find /etc/monitor-collector -maxdepth 0 -perm /022 -print -quit)" ];
}; then
    echo "existing generic-log configuration directory is not root-controlled" >&2
    exit 1
fi
if [ -e "$log_source_config_target" ] && {
    [ "$(stat -c %u -- "$log_source_config_target")" -ne 0 ] \
    || [ -n "$(find "$log_source_config_target" -maxdepth 0 -perm /022 -print -quit)" ];
}; then
    echo "existing generic-log source configuration is not root-controlled" >&2
    exit 1
fi

for target in \
    "$collector_target" \
    "$linux_telemetry_target" \
    "$log_pipeline_target" \
    "$log_sources_target" \
    "$log_store_target" \
    "$generic_log_collector_target" \
    "$exporter_target" \
    "$alert_engine_target" \
    "$alert_runtime_target" \
    "$alert_store_target" \
    "$alert_delivery_target" \
    "$rule_target" \
    "$documentation_target" \
    "$alert_delivery_doc_target" \
    "$alert_delivery_example_target" \
    "$collector_service_target" \
    "$exporter_service_target" \
    "$timer_target" \
    "$default_target" \
    "$delivery_service_target" \
    "$delivery_timer_target" \
    "$log_source_config_target"
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
if systemctl is-enabled --quiet monitor-alert-delivery.timer 2>/dev/null; then
    was_delivery_timer_enabled=true
fi
if systemctl is-active --quiet monitor-alert-delivery.timer 2>/dev/null; then
    was_delivery_timer_active=true
fi

if [ -e "$collector_target" ]; then cp -p "$collector_target" "$backup_dir/collector.py"; had_collector=true; fi
if [ -e "$linux_telemetry_target" ]; then cp -p "$linux_telemetry_target" "$backup_dir/linux_telemetry.py"; had_linux_telemetry=true; fi
if [ -e "$log_pipeline_target" ]; then cp -p "$log_pipeline_target" "$backup_dir/log_pipeline.py"; had_log_pipeline=true; fi
if [ -e "$log_sources_target" ]; then cp -p "$log_sources_target" "$backup_dir/log_sources.py"; had_log_sources=true; fi
if [ -e "$log_store_target" ]; then cp -p "$log_store_target" "$backup_dir/log_store.py"; had_log_store=true; fi
if [ -e "$generic_log_collector_target" ]; then cp -p "$generic_log_collector_target" "$backup_dir/generic_log_collector.py"; had_generic_log_collector=true; fi
if [ -e "$exporter_target" ]; then cp -p "$exporter_target" "$backup_dir/container_exporter.py"; had_exporter=true; fi
if [ -e "$alert_engine_target" ]; then cp -p "$alert_engine_target" "$backup_dir/alert_engine.py"; had_alert_engine=true; fi
if [ -e "$alert_runtime_target" ]; then cp -p "$alert_runtime_target" "$backup_dir/alert_runtime.py"; had_alert_runtime=true; fi
if [ -e "$alert_store_target" ]; then cp -p "$alert_store_target" "$backup_dir/alert_store.py"; had_alert_store=true; fi
if [ -e "$alert_delivery_target" ]; then cp -p "$alert_delivery_target" "$backup_dir/alert_delivery.py"; had_alert_delivery=true; fi
if [ -e "$rule_target" ]; then cp -p "$rule_target" "$backup_dir/default-rules.v1.json"; had_rule=true; fi
if [ -d /usr/local/lib/monitor-collector/rules ]; then had_rule_directory=true; fi
if [ -e "$documentation_target" ]; then cp -p "$documentation_target" "$backup_dir/README.md"; had_documentation=true; fi
if [ -e "$alert_delivery_doc_target" ]; then cp -p "$alert_delivery_doc_target" "$backup_dir/alert-delivery.md"; had_alert_delivery_doc=true; fi
if [ -e "$alert_delivery_example_target" ]; then cp -p "$alert_delivery_example_target" "$backup_dir/alert-delivery.example.v1.json"; had_alert_delivery_example=true; fi
if [ -e "$collector_service_target" ]; then cp -p "$collector_service_target" "$backup_dir/monitor-collector.service"; had_collector_service=true; fi
if [ -e "$exporter_service_target" ]; then cp -p "$exporter_service_target" "$backup_dir/monitor-container-exporter.service"; had_exporter_service=true; fi
if [ -e "$timer_target" ]; then cp -p "$timer_target" "$backup_dir/monitor-collector.timer"; had_timer=true; fi
if [ -e "$default_target" ]; then cp -p "$default_target" "$backup_dir/monitor-collector.default"; had_default=true; fi
if [ -e "$delivery_service_target" ]; then cp -p "$delivery_service_target" "$backup_dir/monitor-alert-delivery.service"; had_delivery_service=true; fi
if [ -e "$delivery_timer_target" ]; then cp -p "$delivery_timer_target" "$backup_dir/monitor-alert-delivery.timer"; had_delivery_timer=true; fi
if [ -e "$log_source_config_target" ]; then had_log_source_config=true; fi
if [ -d /etc/monitor-collector ]; then had_log_source_config_directory=true; fi
if [ -d /var/lib/monitor-export ]; then
    had_output_directory=true
    capture_directory_metadata /var/lib/monitor-export
    output_directory_uid=$captured_directory_uid
    output_directory_gid=$captured_directory_gid
    output_directory_mode=$captured_directory_mode
fi
if [ -d /run/monitor-collector ]; then
    had_collector_runtime_directory=true
    capture_directory_metadata /run/monitor-collector
    collector_runtime_directory_uid=$captured_directory_uid
    collector_runtime_directory_gid=$captured_directory_gid
    collector_runtime_directory_mode=$captured_directory_mode
fi
if [ -d /run/monitor-container-exporter ]; then
    had_exporter_runtime_directory=true
    capture_directory_metadata /run/monitor-container-exporter
    exporter_runtime_directory_uid=$captured_directory_uid
    exporter_runtime_directory_gid=$captured_directory_gid
    exporter_runtime_directory_mode=$captured_directory_mode
fi

transaction_started=true
systemctl stop monitor-alert-delivery.timer monitor-alert-delivery.service >/dev/null 2>&1 || true
systemctl stop monitor-collector.timer monitor-collector.service monitor-container-exporter.service >/dev/null 2>&1 || true
for unit in monitor-alert-delivery.timer monitor-alert-delivery.service monitor-collector.timer monitor-collector.service monitor-container-exporter.service
do
    if systemctl is-active --quiet "$unit"; then
        echo "collector unit did not stop: $unit" >&2
        exit 1
    fi
done

install -d -m 0755 /usr/local/lib/monitor-collector
install -m 0755 "$script_dir/collector.py" "$collector_target"
install -m 0644 "$script_dir/linux_telemetry.py" "$linux_telemetry_target"
install -m 0644 "$script_dir/log_pipeline.py" "$log_pipeline_target"
install -m 0644 "$script_dir/log_sources.py" "$log_sources_target"
install -m 0644 "$script_dir/log_store.py" "$log_store_target"
install -m 0644 "$script_dir/generic_log_collector.py" "$generic_log_collector_target"
install -m 0755 "$script_dir/container_exporter.py" "$exporter_target"
install -m 0644 "$script_dir/alert_engine.py" "$alert_engine_target"
install -m 0644 "$script_dir/alert_runtime.py" "$alert_runtime_target"
install -m 0644 "$script_dir/alert_store.py" "$alert_store_target"
install -m 0755 "$script_dir/alert_delivery.py" "$alert_delivery_target"
install -d -m 0755 /usr/local/lib/monitor-collector/rules
install -m 0644 "$script_dir/rules/default-rules.v1.json" "$rule_target"
install -d -m 0755 /usr/local/share/doc/monitor-collector
install -m 0644 "$script_dir/README.md" "$documentation_target"
install -m 0644 "$script_dir/../docs/alert-delivery.md" "$alert_delivery_doc_target"
install -m 0644 "$script_dir/rules/alert-delivery.example.v1.json" "$alert_delivery_example_target"
install -m 0644 "$script_dir/systemd/monitor-collector.service" "$collector_service_target"
install -m 0644 "$script_dir/systemd/monitor-container-exporter.service" "$exporter_service_target"
install -m 0644 "$script_dir/systemd/monitor-collector.timer" "$timer_target"
install -m 0644 "$script_dir/systemd/monitor-alert-delivery.service" "$delivery_service_target"
install -m 0644 "$script_dir/systemd/monitor-alert-delivery.timer" "$delivery_timer_target"
install -m 0640 "$script_dir/monitor-collector.default" "$default_target"
if [ "$had_log_source_config_directory" != true ]; then
    install -d -o root -g root -m 0750 /etc/monitor-collector
fi
if [ "$had_log_source_config" != true ]; then
    install -o root -g root -m 0600 "$script_dir/log-sources.example.json" "$log_source_config_target"
fi

if [ "$had_output_directory" != true ]; then
    mkdir -- /var/lib/monitor-export
    created_output_directory=true
fi
install -d -o root -g cks -m 0750 /var/lib/monitor-export
if [ "$had_collector_runtime_directory" != true ]; then
    mkdir -- /run/monitor-collector
    created_collector_runtime_directory=true
fi
install -d -o root -g cks -m 0750 /run/monitor-collector
if [ "$had_exporter_runtime_directory" != true ]; then
    mkdir -- /run/monitor-container-exporter
    created_exporter_runtime_directory=true
fi
install -d -o cks -g cks -m 0750 /run/monitor-container-exporter
systemctl daemon-reload
systemctl enable --now monitor-collector.timer
systemctl start monitor-collector.service
if [ "$was_delivery_timer_enabled" = true ]; then
    systemctl enable monitor-alert-delivery.timer
else
    systemctl disable monitor-alert-delivery.timer >/dev/null 2>&1 || true
fi
if [ "$was_delivery_timer_active" = true ]; then
    systemctl start monitor-alert-delivery.timer
fi
committed=true
echo "Installed. Alert delivery retained its prior enable/active state; review its configuration before first enablement."
echo "Inspect with: systemctl status monitor-collector.timer monitor-collector.service monitor-alert-delivery.timer"
