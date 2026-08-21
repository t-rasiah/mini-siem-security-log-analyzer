#!/bin/bash
set -e

echo "[INFO] Provisioning log-client..."

apt-get update

apt-get install -y \
    openssh-server \
    rsyslog

systemctl enable ssh
systemctl restart ssh

systemctl enable rsyslog
systemctl restart rsyslog

echo "[INFO] log-client provisioning completed."