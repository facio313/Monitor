#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root" >&2
    exit 1
fi

systemctl disable --now monitor-collector.timer 2>/dev/null || true
systemctl disable --now monitor-alert-delivery.timer 2>/dev/null || true
systemctl disable --now monitor-synthetic-probe.timer 2>/dev/null || true
systemctl stop monitor-synthetic-probe.service 2>/dev/null || true
systemctl stop monitor-alert-delivery.service 2>/dev/null || true
systemctl stop monitor-collector.service 2>/dev/null || true
systemctl stop monitor-container-exporter.service 2>/dev/null || true
rm -f \
    /etc/systemd/system/monitor-collector.service \
    /etc/systemd/system/monitor-container-exporter.service \
    /etc/systemd/system/monitor-collector.timer \
    /etc/systemd/system/monitor-alert-delivery.service \
    /etc/systemd/system/monitor-alert-delivery.timer \
    /etc/systemd/system/monitor-synthetic-probe.service \
    /etc/systemd/system/monitor-synthetic-probe.timer
rm -f \
    /usr/local/lib/monitor-collector/collector.py \
    /usr/local/lib/monitor-collector/linux_telemetry.py \
    /usr/local/lib/monitor-collector/log_pipeline.py \
    /usr/local/lib/monitor-collector/log_sources.py \
    /usr/local/lib/monitor-collector/log_store.py \
    /usr/local/lib/monitor-collector/generic_log_collector.py \
    /usr/local/lib/monitor-collector/container_exporter.py \
    /usr/local/lib/monitor-collector/alert_engine.py \
    /usr/local/lib/monitor-collector/alert_runtime.py \
    /usr/local/lib/monitor-collector/alert_store.py \
    /usr/local/lib/monitor-collector/alert_delivery.py \
    /usr/local/lib/monitor-collector/synthetic_probe.py \
    /usr/local/lib/monitor-collector/rules/default-rules.v1.json
rmdir /usr/local/lib/monitor-collector/rules 2>/dev/null || true
rmdir /usr/local/lib/monitor-collector 2>/dev/null || true
rm -f \
    /usr/local/share/doc/monitor-collector/README.md \
    /usr/local/share/doc/monitor-collector/alert-delivery.md \
    /usr/local/share/doc/monitor-collector/alert-delivery.example.v1.json \
    /usr/local/share/doc/monitor-collector/synthetic-probes.md \
    /usr/local/share/doc/monitor-collector/synthetic-probes.example.json
rmdir /usr/local/share/doc/monitor-collector 2>/dev/null || true
systemctl daemon-reload
rm -f \
    /run/monitor-container-exporter/containers.json \
    /run/monitor-container-exporter/cpu-state.json \
    /run/monitor-container-exporter/exporter.lock
rmdir /run/monitor-container-exporter 2>/dev/null || true

echo "Collector removed. Data and local configuration were preserved:"
echo "  /var/lib/monitor-export"
echo "  /etc/default/monitor-collector"
echo "  /etc/monitor-collector/log-sources.json"
echo "  /etc/monitor/alert-delivery.json and referenced secrets"
echo "  /etc/monitor-synthetic-probe/probes.json"
echo "  /var/lib/monitor-synthetic/results.json"
echo "Monitor application auth state and its backups were not modified:"
echo "  /home/cks/.local/state/monitor-auth"
echo "  /home/cks/backups/monitor-auth"
