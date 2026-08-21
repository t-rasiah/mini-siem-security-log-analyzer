#!/bin/bash
set -e

echo "[INFO] Provisioning mini-siem..."

apt-get update

apt-get install -y \
    rsyslog \
    python3 \
    python3-pip \
    python3-venv \
    python3-pytest

mkdir -p /var/log/remote

chmod 755 /var/log/remote

systemctl enable rsyslog
systemctl restart rsyslog

echo "[INFO] mini-siem provisioning completed."