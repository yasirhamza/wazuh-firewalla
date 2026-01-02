#!/bin/bash
#
# sync-baseline.sh - Sync SRP baseline from Windows agent to Wazuh Manager
#
# This script is triggered by Wazuh active response when a BASELINE_SYNC event
# is detected, or can be run manually/via cron to pull baselines from agents.
#
# Usage:
#   ./sync-baseline.sh <agent_id>           # Sync from specific agent
#   ./sync-baseline.sh --from-event         # Called by active response
#
# The script uses Wazuh agent file collection or API to retrieve the
# baseline file from the Windows agent and update the manager's CDB list.

set -e

WAZUH_DIR="/var/ossec"
CDB_LIST_DIR="$WAZUH_DIR/etc/lists/srp"
CDB_LIST_FILE="$CDB_LIST_DIR/srp_baseline"
LOG_FILE="$WAZUH_DIR/logs/baseline-sync.log"
AGENT_FILES_DIR="$WAZUH_DIR/queue/agent-files"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Ensure CDB directory exists
mkdir -p "$CDB_LIST_DIR"

# Check if called from active response
if [[ "$1" == "--from-event" ]]; then
    # Read event data from stdin (active response format)
    read -r INPUT
    AGENT_ID=$(echo "$INPUT" | jq -r '.agent.id // empty')

    if [[ -z "$AGENT_ID" ]]; then
        log "ERROR: No agent ID in event data"
        exit 1
    fi
else
    AGENT_ID="$1"
fi

if [[ -z "$AGENT_ID" ]]; then
    echo "Usage: $0 <agent_id> | --from-event"
    echo ""
    echo "Syncs SRP baseline from Windows agent to Wazuh Manager CDB list."
    echo ""
    echo "Methods:"
    echo "  1. Agent file collection: Agent uploads baseline to queue/agent-files/"
    echo "  2. Active response: Triggered by BASELINE_SYNC event"
    echo ""
    exit 1
fi

log "Starting baseline sync for agent $AGENT_ID"

# Look for baseline file uploaded by agent
# Wazuh agents can upload files via localfile with 'command' log format
AGENT_BASELINE="$AGENT_FILES_DIR/$AGENT_ID/srp_baseline.cdb"

if [[ -f "$AGENT_BASELINE" ]]; then
    log "Found baseline file from agent $AGENT_ID"

    # Backup existing baseline
    if [[ -f "$CDB_LIST_FILE" ]]; then
        cp "$CDB_LIST_FILE" "${CDB_LIST_FILE}.bak"
    fi

    # Copy new baseline
    cp "$AGENT_BASELINE" "$CDB_LIST_FILE"

    # Count entries
    ENTRY_COUNT=$(wc -l < "$CDB_LIST_FILE")
    log "Updated CDB list with $ENTRY_COUNT entries"

    # Recompile CDB (Wazuh will do this on restart, but we can force it)
    if [[ -x "$WAZUH_DIR/bin/wazuh-makelists" ]]; then
        "$WAZUH_DIR/bin/wazuh-makelists" 2>/dev/null || true
    fi

    log "Baseline sync complete for agent $AGENT_ID"
else
    log "WARN: No baseline file found for agent $AGENT_ID at $AGENT_BASELINE"
    log "Ensure agent is configured to upload srp_baseline.cdb"
    exit 1
fi
