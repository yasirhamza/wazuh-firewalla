#!/usr/bin/env bash
# Refresh the cached MITRE ATT&CK enterprise STIX bundle.
# Run weekly via /schedule. Idempotent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="$REPO_ROOT/cti-cache/attack"
TARGET="$CACHE_DIR/enterprise-attack.json"
TMP="$TARGET.tmp"
URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

mkdir -p "$CACHE_DIR"

echo "Fetching $URL ..."
curl -fsSL --max-time 120 -o "$TMP" "$URL"

# Validate it parses as JSON before swapping in.
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$TMP"

mv "$TMP" "$TARGET"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$CACHE_DIR/LAST_REFRESHED.txt"
SIZE=$(du -h "$TARGET" | cut -f1)
echo "ATT&CK bundle refreshed: $TARGET ($SIZE)"
