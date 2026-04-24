# Wazuh MCP Server

Read-only MCP server that exposes Wazuh SIEM analytics as tools for LLM clients (Claude Code, future UIs).

See design spec: `../docs/specs/2026-04-24-wazuh-mcp-server-design.md`

## Layout

- `src/config.py` — env loading
- `src/wazuh_client.py` — OpenSearch client
- `src/wazuh_service.py` — domain logic (no MCP imports; reusable)
- `src/mcp_server.py` — FastMCP tool wrappers
- `src/limits.py` — rate limiting + result caps
- `src/logging_setup.py` — structured logs + heartbeat
- `scripts/create_mcp_user.sh` — one-shot OpenSearch role + user provisioner

## Local dev

```bash
cp .env.example .env  # edit values
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                # unit tests only
pytest -m integration                 # integration (needs live OpenSearch)
```

## Deployment

See `../../../docs/plans/2026-04-24-wazuh-mcp-server-implementation.md` Task 22.
