#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

if ! getent group cks >/dev/null 2>&1; then
    echo "required group 'cks' does not exist" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d -m 0755 /usr/local/lib/monitor-collector
install -m 0755 "$script_dir/collector.py" /usr/local/lib/monitor-collector/collector.py
install -d -m 0755 /usr/local/share/doc/monitor-collector
install -m 0644 "$script_dir/README.md" /usr/local/share/doc/monitor-collector/README.md
install -m 0644 "$script_dir/systemd/monitor-collector.service" /etc/systemd/system/monitor-collector.service
install -m 0644 "$script_dir/systemd/monitor-collector.timer" /etc/systemd/system/monitor-collector.timer
if [ ! -e /etc/default/monitor-collector ]; then
    install -m 0640 "$script_dir/monitor-collector.default" /etc/default/monitor-collector
fi

install -d -o root -g cks -m 0750 /var/lib/monitor-export /run/monitor-collector
systemctl daemon-reload
systemctl enable --now monitor-collector.timer
systemctl start monitor-collector.service
echo "Installed. Inspect with: systemctl status monitor-collector.timer monitor-collector.service"
