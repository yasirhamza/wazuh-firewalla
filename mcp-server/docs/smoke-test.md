# wazuh-mcp Smoke Test

Run these 8 questions in Claude Code after adding the wazuh-mcp MCP server
to its config. Each question should trigger the named tool and produce a
response matching the expected shape (not exact numbers — those vary).

**Pre-req:** Add to Claude Code's MCP config (e.g., `~/.claude.json` under `mcpServers`):

```json
{
  "wazuh": {
    "transport": "sse",
    "url": "http://localhost:8800/sse",
    "headers": {"Authorization": "Bearer <MCP_API_KEY>"}
  }
}
```

## Questions

| # | Ask Claude | Expected tool | Expected shape |
|---|---|---|---|
| 1 | What's going on in the SIEM today? | `alert_overview` | total count, source breakdown, severity histogram, top agents |
| 2 | Compare this week's alerts to last week's. | `trend_delta` with `alerts_by_source` or `alerts_by_rule_group` | current, prior, delta %, top movers |
| 3 | Show me threat-intel hits this month. | `threat_intel_matches` | list of matches with list, IOC, agent |
| 4 | Give me all activity for agent `kids-laptop` in the last 24h. | `entity_activity` (entity_type=agent) | summary + sample_alerts |
| 5 | Are the sidecars healthy? | `sidecar_health` | per-sidecar status + summary |
| 6 | Search for rule 100651 alerts today. | `search_alerts` with filters | results array |
| 7 | Show me top source IPs over last 7 days. | `aggregate_alerts` on `data.srcip` | buckets with key + count |
| 8 | Get full detail for alert `<id from Q6>`. | `get_alert` | full `_source` object |

## Pass criteria

- Every tool invocation succeeds.
- Claude's narration mentions specific numbers from the tool response (not made up).
- No `"error": "internal"` responses.
- `sidecar_health` reports `wazuh-mcp` itself as `ok`.

## If a question fails

1. Check `docker logs single-node-wazuh-mcp --tail 50` for the JSON error line.
2. Correlate via `req_id` if Claude reports one.
3. Common causes:
   - OpenSearch unavailable → check `wazuh.indexer` status.
   - 401 → `MCP_API_KEY` mismatch between `.env` and Claude Code config.
   - Empty results → check `sidecar_health` and `msp-poller` logs — is data arriving?
