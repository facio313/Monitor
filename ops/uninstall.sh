#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root" >&2
    exit 1
fi

systemctl disable --now monitor-collector.timer 2>/dev/null || true
systemctl stop monitor-collector.service 2>/dev/null || true
systemctl stop monitor-container-exporter.service 2>/dev/null || true
rm -f \
    /etc/systemd/system/monitor-collector.service \
    /etc/systemd/system/monitor-container-exporter.service \
    /etc/systemd/system/monitor-collector.timer
rm -f \
    /usr/local/lib/monitor-collector/collector.py \
    /usr/local/lib/monitor-collector/container_exporter.py \
    /usr/local/lib/monitor-collector/alert_engine.py \
    /usr/local/lib/monitor-collector/alert_runtime.py \
    /usr/local/lib/monitor-collector/alert_store.py \
    /usr/local/lib/monitor-collector/rules/default-rules.v1.json
rmdir /usr/local/lib/monitor-collector/rules 2>/dev/null || true
rmdir /usr/local/lib/monitor-collector 2>/dev/null || true
rm -f /usr/local/share/doc/monitor-collector/README.md
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
echo "Monitor application auth state and its backups were not modified:"
echo "  /home/cks/.local/state/monitor-auth"
echo "  /home/cks/backups/monitor-auth"
