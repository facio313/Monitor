#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root" >&2
    exit 1
fi

systemctl disable --now monitor-collector.timer 2>/dev/null || true
systemctl stop monitor-collector.service 2>/dev/null || true
rm -f /etc/systemd/system/monitor-collector.service /etc/systemd/system/monitor-collector.timer
rm -f /usr/local/lib/monitor-collector/collector.py
rmdir /usr/local/lib/monitor-collector 2>/dev/null || true
rm -f /usr/local/share/doc/monitor-collector/README.md
rmdir /usr/local/share/doc/monitor-collector 2>/dev/null || true
systemctl daemon-reload

echo "Collector removed. Data and local configuration were preserved:"
echo "  /var/lib/monitor-export"
echo "  /etc/default/monitor-collector"
