#!/bin/bash
#
# sync-baseline.sh - Sync SRP baseline from Windows agent to Wazuh Manager
#
# Modes:
#   ./sync-baseline.sh --decode <agent_id> <base64_data>   # Decode and save CDB
#   ./sync-baseline.sh --from-alert                         # Called by active response
#   ./sync-baseline.sh <agent_id>                           # Check for uploaded file
#

set -e

WAZUH_DIR="/var/ossec"
CDB_LIST_DIR="$WAZUH_DIR/etc/lists/srp"
CDB_LIST_FILE="$CDB_LIST_DIR/srp_baseline"
LOG_FILE="$WAZUH_DIR/logs/baseline-sync.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Ensure CDB directory exists
mkdir -p "$CDB_LIST_DIR"

# Mode: Decode base64 data and save
if [[ "$1" == "--decode" ]]; then
    AGENT_ID="$2"
    BASE64_DATA="$3"

    if [[ -z "$AGENT_ID" || -z "$BASE64_DATA" ]]; then
        log "ERROR: --decode requires agent_id and base64_data"
        exit 1
    fi

    log "Decoding CDB upload from agent $AGENT_ID"

    # Backup existing baseline
    if [[ -f "$CDB_LIST_FILE" ]]; then
        cp "$CDB_LIST_FILE" "${CDB_LIST_FILE}.bak"
    fi

    # Decode and save
    echo "$BASE64_DATA" | base64 -d > "$CDB_LIST_FILE"

    # Count entries
    ENTRY_COUNT=$(wc -l < "$CDB_LIST_FILE")
    log "Saved CDB with $ENTRY_COUNT entries from agent $AGENT_ID"

    # Recompile CDB lists
    if [[ -x "$WAZUH_DIR/bin/wazuh-makelists" ]]; then
        "$WAZUH_DIR/bin/wazuh-makelists" 2>/dev/null || true
        log "CDB lists recompiled"
    fi

    exit 0
fi

# Mode: Called from active response with alert JSON on stdin
if [[ "$1" == "--from-alert" ]]; then
    read -r INPUT

    AGENT_ID=$(echo "$INPUT" | jq -r '.agent.id // empty')
    CDB_DATA=$(echo "$INPUT" | jq -r '.data.srp.cdb_data // empty')

    if [[ -z "$AGENT_ID" || -z "$CDB_DATA" ]]; then
        log "ERROR: Missing agent.id or srp.cdb_data in alert"
        exit 1
    fi

    exec "$0" --decode "$AGENT_ID" "$CDB_DATA"
fi

# Mode: Manual check for agent
AGENT_ID="$1"

if [[ -z "$AGENT_ID" ]]; then
    echo "Usage:"
    echo "  $0 --decode <agent_id> <base64_data>  Decode and save CDB"
    echo "  $0 --from-alert                        Process alert from stdin"
    echo "  $0 <agent_id>                          Check for uploaded file"
    exit 1
fi

log "Checking for baseline from agent $AGENT_ID"

# Check standard file location
AGENT_BASELINE="$WAZUH_DIR/queue/agent-files/$AGENT_ID/srp_baseline.cdb"

if [[ -f "$AGENT_BASELINE" ]]; then
    log "Found baseline file from agent $AGENT_ID"

    if [[ -f "$CDB_LIST_FILE" ]]; then
        cp "$CDB_LIST_FILE" "${CDB_LIST_FILE}.bak"
    fi

    cp "$AGENT_BASELINE" "$CDB_LIST_FILE"
    ENTRY_COUNT=$(wc -l < "$CDB_LIST_FILE")
    log "Updated CDB list with $ENTRY_COUNT entries"

    if [[ -x "$WAZUH_DIR/bin/wazuh-makelists" ]]; then
        "$WAZUH_DIR/bin/wazuh-makelists" 2>/dev/null || true
    fi
else
    log "No baseline file at $AGENT_BASELINE"
    log "Agent will upload via CDB_UPLOAD log entry (hourly)"
fi
