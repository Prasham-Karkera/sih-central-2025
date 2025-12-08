#!/bin/bash

# Usage: sudo ./update_syslog.sh <SERVER_IP_OR_URL> <PORT>
# Example: sudo ./update_syslog.sh 192.168.0.105 514

CONFIG_FILE="/etc/rsyslog.conf"
BACKUP_FILE="/etc/rsyslog.conf.bak_$(date +%F_%T)"

if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo)."
  exit 1
fi

if [ $# -ne 2 ]; then
  echo "Usage: $0 <SERVER_IP_OR_URL> <PORT>"
  exit 1
fi

SERVER="$1"
PORT="$2"

echo "➡ Backing up original config to: $BACKUP_FILE"
cp "$CONFIG_FILE" "$BACKUP_FILE"

echo "➡ Updating syslog forwarding rule..."

# Remove any existing forwarding lines
sed -i '/^\*\.\* @@/d' "$CONFIG_FILE"
sed -i '/^\*\.\* @[^@]/d' "$CONFIG_FILE"

# Append new forwarding rule
echo "*.* @@${SERVER}:${PORT}" >> "$CONFIG_FILE"

echo "➡ Restarting rsyslog service..."
systemctl restart rsyslog

if systemctl status rsyslog >/dev/null 2>&1; then
  echo "✅ Syslog forwarding updated successfully!"
  echo "➡ Now forwarding logs to: $SERVER:$PORT"
else
  echo "❌ Error: rsyslog failed to restart. Check logs."
fi
