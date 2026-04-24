# Wazuh MCP Server — Design Spec

**Date:** 2026-04-24
**Status:** Design approved, pending implementation plan
**Target environment:** Wazuh 4.14.3 single-node deployment at `/opt/wazuh-docker/single-node/`

## Context & Motivation

The existing Wazuh SIEM aggregates alerts from Firewalla MSP (alarms, flows, devices), Windows SRP (executable allow/block), multi-source threat intelligence (Feodo, ThreatFox, URLhaus, MalwareBazaar, built-in `malicious-ioc`), OSSEC host events, and syscheck FIM. Manual exploration via the Wazuh dashboard scales poorly for trend-style questions ("what's different this week?", "who's responsible for this spike?"). An LLM can narrate pre-aggregated data well but cannot safely compose arbitrary OpenSearch queries on its own.

This spec defines a **Model Context Protocol (MCP) server** that exposes the SIEM as a bounded set of read-only analytical tools to an LLM client. MVP target client is Claude Code (already in daily use). The server is architected so a future web UI or Wazuh dashboard plugin can reuse the same service layer without rewriting the data-access logic.

## Goals

- Natural-language trend analysis and drill-down against the SIEM, from Claude Code today.
- Cross-source insights (Firewalla + Windows SRP + threat intel + OSSEC/FIM) — not Firewalla-specific.
- A foundation (service layer) for a future dashboard chatbot or standalone web UI.
- Read-only, token-budgeted, auditable: LLM never composes destructive or unbounded queries.

## Non-Goals (MVP)

- No write operations (no rule creation, CDB edits, service restarts).
- No model choice — the MCP client (Claude Code) picks the model; server is model-agnostic.
- No LLM-driven anomaly scoring — statistics come from OpenSearch aggregations, not from the LLM.
- No proper Wazuh dashboard plugin in MVP (deferred to v2).
- No multi-tenant auth — single user, single bearer token.

## Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Deployment shape | Docker sidecar in `docker-compose.yml` | Matches existing `msp-poller`/`threat-intel` pattern; clean isolation; trivial reuse by future clients |
| Transport | HTTP/SSE (primary) + stdio (dev/test) | Containerized sidecar → HTTP/SSE is the production path for Claude Code and future UIs. stdio remains available when running the server as a local Python process for debugging. |
| LLM provider | Claude API (external) | Best trend-narration quality; user accepts the data-leaving-premises tradeoff |
| Data model | Stateless; every query hits live OpenSearch | No cache; no hallucinated staleness |
| OpenSearch auth | Dedicated `mcp_read` user with read-only role on `wazuh-alerts-*`, `wazuh-monitoring-*` | Least privilege; defense in depth against prompt injection |
| Write tools | None in MVP | Hard safety boundary; added deliberately later if ever |
| Code structure | Layered: client → service → tool layer | Service layer has zero MCP imports and is reusable by future UIs |
| HTTP binding | `127.0.0.1` only, bearer-token header required | Localhost-only trust boundary; token scoped per-key |
| Language / framework | Python 3.12 + FastMCP + opensearch-py | Matches existing sidecars' Python stack |

---

## 1. Architecture

```
                          ┌───────────────────────────────────────┐
                          │        /opt/wazuh-docker/single-node  │
                          │                                       │
 Claude Code ─── SSE ───▶ │  wazuh-mcp  (FastMCP server)          │
 (your terminal)          │    │                                  │
                          │    │ reads (mcp_read, read-only)      │
                          │    ▼                                  │
                          │  wazuh.indexer (OpenSearch :9200)     │
                          │    indices: wazuh-alerts-*,           │
                          │             wazuh-monitoring-*        │
                          │                                       │
                          │  wazuh-mcp writes heartbeat/errors    │
                          │  → sidecar-status.json (volume)       │
                          │    ─▶ ingested by wazuh.manager       │
                          │    ─▶ Sidecar Monitoring dashboard    │
                          └───────────────────────────────────────┘
```

**Boundaries:**
- Stateless. No database, no state file. Live queries only.
- HTTP binds `127.0.0.1:<port>` inside the Docker network; host-mapped via compose for Claude Code.
- Bearer-token auth on HTTP/SSE (token in `.env`, same trust boundary as existing creds).
- Read-only OpenSearch user, provisioned once via OpenSearch Security API (script in repo).

## 2. Components

```
mcp-server/
├── Dockerfile                  # python:3.12-slim
├── requirements.txt            # mcp, opensearch-py, python-dotenv, pydantic
├── .env.example                # template for MCP_OS_USER, MCP_API_KEY, etc.
├── src/
│   ├── config.py               # loads + validates env
│   ├── wazuh_client.py         # thin OpenSearch client (auth, retry, timeout)
│   ├── wazuh_service.py        # WazuhDataService: one method per capability
│   ├── mcp_server.py           # FastMCP tool definitions (thin wrappers)
│   ├── limits.py               # rate limiter + result-size caps
│   └── logging_setup.py        # JSON logs + heartbeat writer
├── scripts/
│   └── create_mcp_user.sh      # one-shot OpenSearch role+user provisioner
└── tests/
    ├── test_service_unit.py    # mock OpenSearch; fast
    └── test_service_integ.py   # real OpenSearch in compose; slow
```

**Layer responsibilities (strict — no back-references):**

- **`config.py`** — loads `.env`, validates `MCP_OS_USER`, `MCP_OS_PASSWORD`, `MCP_API_KEY`, `MCP_HTTP_PORT`, `OPENSEARCH_URL`. Fails loud on missing/invalid.

- **`wazuh_client.py`** — `WazuhClient` wraps `opensearch-py`. TLS (verify=False for self-signed, logs warning), auth, pooling, 10s timeout, one retry on transient. Exposes `search(index, body)` and `count(index, body)` — nothing domain-specific.

- **`wazuh_service.py`** — `WazuhDataService` with one public method per tool. Builds OpenSearch queries, shapes responses into compact LLM-friendly dicts. **No MCP imports.** This is the reusable layer.

- **`mcp_server.py`** — FastMCP app. Each of 8 tools is a `@mcp.tool()` function: Pydantic-validated inputs, rate-limit check, service call, result-cap enforcement, return. Tool descriptions enumerate sources and common fields for the LLM. Registers both stdio and HTTP/SSE transports.

- **`limits.py`** — (1) per-key token-bucket rate limiter (60/min, burst 10, in-process); (2) `limit_results(rows, cap=100) -> {results, truncated, total_matched}`.

- **`logging_setup.py`** — JSON structured logs to stdout. Background thread writes heartbeat + error counters to `/var/ossec/logs/sidecar-status/sidecar-status.json` every 60s, schema compatible with rules 100500-100504.

## 3. Data Flow

A user turn from Claude Code:

1. **Claude Code** reads MCP config, discovers `wazuh-mcp` at `http://localhost:<port>/sse`. Sends user turn + tool catalog to Claude API.
2. **Claude API** decides to call one or more tools; returns `tool_use` blocks.
3. **Claude Code** issues parallel tool calls over SSE to `wazuh-mcp`, with bearer token.
4. **`wazuh-mcp`** for each call: auth check → rate limit → Pydantic validate → service method → query OpenSearch → truncate → return compact JSON.
5. **Claude Code** returns `tool_results` to Claude API, which synthesizes a narrative response.

**Invariants:**
- Claude never touches OpenSearch directly — it only sees what `wazuh_service` returns. Stops hallucinated statistics.
- Every tool call is stateless. No session tracking; rate limiter keyed by bearer token only.
- Response shape is LLM-friendly: flattened aggregation buckets, not raw OpenSearch response objects.
- Time ranges travel as ISO-8601 strings; the service converts to OpenSearch date math.
- Drill-down is emergent — follow-up questions become new tool calls through the same path.

**Logging:**
- Per-call JSON log line (tool, key fingerprint, duration, result count, truncated, error) → stdout → `docker logs`.
- Heartbeat every 60s → `sidecar-status.json` → ingestion → dashboard. Stale >5min triggers rule 100504 (level 10).

## 4. Tool Specifications

All 8 tools are read-only. Tool descriptions visible to the LLM enumerate current data sources (`firewalla-msp`, `windows-srp`, `threat-intel`, `ossec`, `syscheck`, `malicious-ioc`) and common searchable fields. Source catalog is one constant — adding a new source is one edit.

**`time_range` format (all tools):** either a relative shorthand (`"last_24h"`, `"last_7d"`, `"last_30d"`) or an explicit ISO-8601 range (`"2026-04-20T00:00:00Z/2026-04-24T00:00:00Z"`). The service converts to OpenSearch date math. Maximum span 90 days (enforced).

### 4.1 `search_alerts`
Find individual alerts matching structured filters or a Lucene query.

- **Inputs:** `filters` (optional dict, `field: value` or `field: [values]`), `lucene` (optional string), `time_range` (required), `sort_by` (`@timestamp` | `rule.level`, default `@timestamp` desc), `limit` (≤100, default 25). One of `filters` or `lucene` required.
- **Returns:** `{results: [{id, @timestamp, agent, rule, data}], total_matched, truncated}`

### 4.2 `aggregate_alerts`
Group-and-count on any field. Workhorse for trend narration.

- **Inputs:** `group_by_field` (required), `filters` (optional), `time_range` (required), `top_n` (default 10, max 50).
- **Returns:** `{buckets: [{key, count}], total_in_scope, time_range}`

### 4.3 `alert_overview`
Pre-canned dashboard in JSON — single call answers "what's going on?".

- **Inputs:** `time_range` (required).
- **Returns:**
```json
{
  "total_alerts": 12847,
  "by_source": {"firewalla-msp": 9201, "windows-srp": 2103, "threat-intel": 12, "ossec": 1531},
  "by_severity": {"low (0-3)": 8120, "medium (4-7)": 4703, "high (8-12)": 24},
  "top_rule_groups": [{"key": "dns", "count": 2341}],
  "top_agents": [{"key": "kids-laptop", "count": 1903}],
  "top_src_ips": [],
  "top_dst_ips": [],
  "threat_intel_hits": 12,
  "time_range": "..."
}
```

### 4.4 `trend_delta`
Compare a metric between two windows.

- **Inputs:** `metric` (enum: `total_alerts`, `alerts_by_source`, `alerts_by_rule_group`, `alerts_by_agent`, `threat_intel_hits`), `current_window`, `prior_window`, `filters` (optional), `top_n` (default 10).
- **Returns:** `{current, prior, delta_pct, movers: [top-N entities with largest change]}`

### 4.5 `threat_intel_matches`
CDB-list hits from rules 100450-100453 + built-in `malicious-ioc` rules (99901-99999). Joined with source agent/device.

- **Inputs:** `time_range` (required), `list_filter` (optional: `firewalla-c2`, `urlhaus`, `malware-hashes`, `malicious-ip`, `malicious-domains`, `all`).
- **Returns:** `{matches: [{@timestamp, list, ioc, agent, src_ip, dst_ip, rule_id}], total}`

### 4.6 `sidecar_health`
Health of msp-poller, threat-intel, wazuh-mcp.

- **Inputs:** none.
- **Returns:** `{sidecars: [{name, status, last_heartbeat, error_count_10m, last_error}], summary}`

### 4.7 `get_alert`
Full detail for one alert by ID.

- **Inputs:** `alert_id` (required).
- **Returns:** full `_source` object. 404 if not found.

### 4.8 `entity_activity`
Multi-source pivot on one entity. The service internally maps each `entity_type` to the relevant set of fields (e.g., `ip` → `data.srcip` OR `data.dstip`; `user` → `data.srp.user` OR `data.win.eventdata.user`).

- **Inputs:** `entity_type` (`ip` | `agent` | `device` | `user` | `process` | `hash` | `domain`), `entity_value`, `time_range`, `top_n` (default 10, max 50).
- **Returns:**
```json
{
  "entity": {"type": "ip", "value": "203.0.113.10"},
  "total_alerts": 47,
  "by_source": {"firewalla-msp": 40, "threat-intel": 7},
  "by_rule": [{"rule_id": "100450", "description": "...", "count": 7}],
  "first_seen": "2026-04-20T01:14:22Z",
  "last_seen": "2026-04-24T09:02:10Z",
  "related_agents": [{"name": "agent-a", "count": 23}],
  "sample_alerts": [{"id": "...", "@timestamp": "...", "rule": {"id": "...", "level": 10}}]
}
```
`sample_alerts` is the 5 most recent matches for drill-down.

## 5. Error Handling & Guardrails

| Failure | Server behavior | LLM sees |
|---|---|---|
| OpenSearch down / 5xx | 1 retry with 500ms backoff, then fail | `{"error": "opensearch_unavailable", "message"}` |
| Malformed DSL / bad field | No retry | `{"error": "invalid_query", "message", "hint": "valid fields: ..."}` |
| Timeout >10s | Abort | `{"error": "timeout", "time_range_hint": "narrow window"}` |
| Rate limit (60/min/key) | 429 + `Retry-After` | Propagated |
| Auth failure | 401 | Claude Code surfaces config error |
| Input validation | 422 before service call | `{"error": "invalid_input", "details"}` |
| Result >100 rows | Silent truncation | `truncated: true, total_matched: N` — LLM narrows |
| Unexpected exception | Caught at tool boundary, logged with stack trace + request_id | `{"error": "internal", "request_id": "<uuid>"}` — never leak internals |

**Hard limits:**
- Per-call result cap: 100 records, 50 aggregation buckets.
- Per-call wall clock: 10s to OpenSearch.
- Per-key rate: 60 calls/min (burst 10), in-process token bucket.
- Max `time_range` span: 90 days.
- Zero write operations — enforced by read-only OpenSearch role.

**Prompt-injection mitigations:**
- Attacker-controlled alert content (URLs, hostnames, paths, DNS queries) returns to Claude as structured JSON, not free text — harder to misread as instructions.
- No destructive tools to hijack.
- Bearer token + read-only OpenSearch user scope blast radius if Claude is manipulated.

**Observability:**
- Per-call log line (JSON) → stdout → `docker logs wazuh-mcp`.
- Heartbeat file updated every 60s with status, uptime, error count → feeds existing rules 100500-100504.
- Startup self-check: ping OpenSearch + trivial `wazuh-alerts-*` query; exit non-zero on failure so `restart: unless-stopped` kicks in.

## 6. Testing

**Unit tests** (`tests/test_service_unit.py`) — mock `WazuhClient`, assert DSL construction. Covers: time range parsing, filters → DSL translation, bucket flattening, result capping, `trend_delta` math, `entity_activity` source-joining per entity type. Fast (<1s), runs on every change.

**Integration tests** (`tests/test_service_integ.py`) — ephemeral OpenSearch in `docker-compose.test.yml`, seed ~500 synthetic Wazuh-shaped alerts, run each tool end-to-end. One test per tool, not covering every input permutation. CI + pre-release; opt-in local.

**Manual smoke test** — `docs/mcp-smoke-test.md` with ~8 Claude Code questions and expected answer shapes (not exact numbers). Run after deploy. 5 minutes.

**Out of scope:** LLM narration quality (Claude's job), load testing (single-user), cross-version OpenSearch compatibility (pinned to 4.14.x).

**CI:** pre-commit hook runs unit tests on changes under `mcp-server/`. Integration tests run on push to main.

## 7. Operational Notes (Inherited Patterns)

These follow existing sidecar conventions without re-litigation.

- **Secrets in `.env`** alongside `MSP_TOKEN`: `MCP_OS_USER`, `MCP_OS_PASSWORD`, `MCP_API_KEY`, `MCP_HTTP_PORT`, `OPENSEARCH_URL`.
- **Git workflow:** edit + test in `/opt/wazuh-docker/single-node/mcp-server/`, copy to `/path/to/firewalla-wazuh/mcp-server/`, commit from the git repo. Never commit from `/opt/wazuh-docker/`.
- **Log rotation:** 10MB, 2 backups, env-configurable via `MAX_LOG_SIZE` / `MAX_LOG_BACKUPS`.
- **Wazuh dashboard:** no new dashboard in MVP — status events feed into the existing Sidecar Monitoring dashboard.
- **Container restart policy:** `restart: unless-stopped`, matching other sidecars.
- **OpenSearch user provisioning:** a one-shot script in `mcp-server/scripts/create_mcp_user.sh` creates the `mcp_read` role + user via the OpenSearch Security API. Idempotent. Run manually once; not on every container start.

## 8. Future Work (Explicitly Deferred)

- **Dashboard chatbot (option A from brainstorming)** — OpenSearch Dashboards plugin or iframe chat UI consuming this same MCP server over HTTP/SSE.
- **Alert enrichment on high-severity events (option C)** — integration script calls the MCP server (or Claude directly with bounded context) to enrich specific alerts. Privacy-scoped carefully.
- **Write tools** — e.g., "add this IP to the blocklist," "create a suppression rule." Only after the MVP is trusted and a sane approval/audit workflow is designed.
- **Scheduled insight reports** — nightly/weekly LLM-narrated summaries posted to Slack or a dashboard panel.
- **Additional tools** — agent inventory, rule/decoder introspection, SCA/vulnerability queries — as use cases emerge.
