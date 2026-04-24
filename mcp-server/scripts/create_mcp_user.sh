#!/usr/bin/env bash
# Idempotently create a read-only OpenSearch role + user for wazuh-mcp.
#
# Usage:
#   INDEXER_PASSWORD=... MCP_OS_PASSWORD=... ./scripts/create_mcp_user.sh
#
# Runs against the live single-node Wazuh indexer on localhost:9200.

set -euo pipefail

OS_URL="${OS_URL:-https://localhost:9200}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${INDEXER_PASSWORD:?set INDEXER_PASSWORD}"
MCP_USER="${MCP_OS_USER:-mcp_read}"
MCP_PASSWORD="${MCP_OS_PASSWORD:?set MCP_OS_PASSWORD}"

auth=(-u "${ADMIN_USER}:${ADMIN_PASSWORD}" -k)  # -k: self-signed cert

curl -sS "${auth[@]}" -X PUT \
    "${OS_URL}/_plugins/_security/api/roles/wazuh_mcp_read" \
    -H 'Content-Type: application/json' \
    -d '{
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [{
            "index_patterns": ["wazuh-alerts-*"],
            "allowed_actions": ["read", "search", "indices:data/read/*", "indices:admin/get"]
        }]
    }' \
    -o /dev/null -w "role: HTTP %{http_code}\n"

curl -sS "${auth[@]}" -X PUT \
    "${OS_URL}/_plugins/_security/api/internalusers/${MCP_USER}" \
    -H 'Content-Type: application/json' \
    -d "{
        \"password\": \"${MCP_PASSWORD}\",
        \"backend_roles\": [],
        \"attributes\": {\"purpose\": \"wazuh-mcp read-only\"}
    }" \
    -o /dev/null -w "user: HTTP %{http_code}\n"

curl -sS "${auth[@]}" -X PUT \
    "${OS_URL}/_plugins/_security/api/rolesmapping/wazuh_mcp_read" \
    -H 'Content-Type: application/json' \
    -d "{
        \"users\": [\"${MCP_USER}\"]
    }" \
    -o /dev/null -w "mapping: HTTP %{http_code}\n"

echo "Done. Verify:"
echo "  curl -sk -u ${MCP_USER}:\$MCP_OS_PASSWORD ${OS_URL}/wazuh-alerts-*/_count"
