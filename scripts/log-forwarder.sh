#!/bin/bash
# ============================================================
# log-forwarder.sh
# KShield Homelab — Agentless Log Pipeline
#
# Purpose: Forward application logs from shared hosting
#          (no root access) to Wazuh server via SSH/SCP
#
# Environment: Hostinger shared hosting → Wazuh (wazuh.mywire.org)
# Schedule: Cron job every 12 hours
#
# Cron entry (add via: crontab -e):
#   0 */12 * * * /path/to/log-forwarder.sh >> /tmp/forwarder.log 2>&1
# ============================================================

# --- Configuration ---
LOG_SOURCE="/home/deployment/logs/app.log"
REMOTE_USER="deployment"
REMOTE_HOST="wazuh.mywire.org"
REMOTE_PATH="/home/deployment/shared-logs/app.log"
SSH_KEY="/home/deployment/.ssh/id_rsa"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# --- Validation ---
if [ ! -f "$LOG_SOURCE" ]; then
    echo "[$TIMESTAMP] ERROR: Log source not found at $LOG_SOURCE"
    exit 1
fi

if [ ! -s "$LOG_SOURCE" ]; then
    echo "[$TIMESTAMP] INFO: Log file is empty, skipping transfer"
    exit 0
fi

# --- Transfer ---
echo "[$TIMESTAMP] INFO: Starting log transfer to $REMOTE_HOST"

scp -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=30 \
    "$LOG_SOURCE" \
    "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"

# --- Result check ---
if [ $? -eq 0 ]; then
    echo "[$TIMESTAMP] SUCCESS: Logs transferred to $REMOTE_HOST:$REMOTE_PATH"
else
    echo "[$TIMESTAMP] ERROR: Transfer failed — check SSH key and connectivity"
    exit 1
fi

# --- Optional: clear log after transfer to avoid duplicate ingestion ---
# Uncomment the line below if you want to rotate the log after each push
# > "$LOG_SOURCE"

exit 0
