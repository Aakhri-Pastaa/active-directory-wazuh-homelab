#!/bin/bash
# ============================================================
# virustotal-scanner.sh
# KShield Homelab — VirusTotal Malware Detection Pipeline
#
# Purpose: Recursively scan directories, extract SHA256 hashes,
#          submit to VirusTotal API, log results for Wazuh ingestion
#
# Schedule: Cron job every 12 hours
# Cron entry:
#   0 */12 * * * /path/to/virustotal-scanner.sh >> /var/log/vt-scanner.log 2>&1
# ============================================================

# --- Configuration ---
VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY_HERE"
SCAN_DIRS=("/home/deployment/uploads" "/tmp")
RESULTS_LOG="/var/log/vt-results.log"
SLEEP_INTERVAL=15       # seconds between API calls (free tier: 4 req/min)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# --- Dependencies check ---
for cmd in curl sha256sum find jq; do
    if ! command -v $cmd &> /dev/null; then
        echo "[$TIMESTAMP] ERROR: Required command '$cmd' not found"
        exit 1
    fi
done

echo "[$TIMESTAMP] INFO: Starting VirusTotal scan"
echo "[$TIMESTAMP] INFO: Scanning directories: ${SCAN_DIRS[*]}"

# --- Scan function ---
scan_file() {
    local filepath="$1"
    local hash

    # Extract SHA256 hash
    hash=$(sha256sum "$filepath" | awk '{print $1}')

    if [ -z "$hash" ]; then
        echo "[$TIMESTAMP] WARN: Could not hash $filepath"
        return
    fi

    echo "[$TIMESTAMP] INFO: Scanning $filepath (SHA256: $hash)"

    # Submit hash to VirusTotal API
    local response
    response=$(curl -s --request GET \
        --url "https://www.virustotal.com/api/v3/files/$hash" \
        --header "x-apikey: $VT_API_KEY")

    # Parse response
    local malicious
    malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)

    local suspicious
    suspicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.suspicious' 2>/dev/null)

    # Log result
    if [ "$malicious" = "null" ] || [ -z "$malicious" ]; then
        echo "[$TIMESTAMP] RESULT: $filepath | Hash: $hash | Status: NOT_FOUND_IN_VT" >> "$RESULTS_LOG"
    elif [ "$malicious" -gt 0 ]; then
        echo "[$TIMESTAMP] ALERT: $filepath | Hash: $hash | Malicious: $malicious | Suspicious: $suspicious" >> "$RESULTS_LOG"
        echo "[$TIMESTAMP] ALERT: MALICIOUS FILE DETECTED — $filepath"
    else
        echo "[$TIMESTAMP] RESULT: $filepath | Hash: $hash | Malicious: 0 | Clean" >> "$RESULTS_LOG"
    fi

    # Rate limiting — respect free tier limit
    sleep "$SLEEP_INTERVAL"
}

# --- Main loop ---
for dir in "${SCAN_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "[$TIMESTAMP] WARN: Directory not found, skipping: $dir"
        continue
    fi

    echo "[$TIMESTAMP] INFO: Scanning directory: $dir"

    # Recursively find files and scan each
    while IFS= read -r -d '' file; do
        scan_file "$file"
    done < <(find "$dir" -type f -print0)
done

echo "[$TIMESTAMP] INFO: Scan complete. Results logged to $RESULTS_LOG"
exit 0
