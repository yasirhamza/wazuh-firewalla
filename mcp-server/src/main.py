"""Entry point: load config, build services, run MCP SSE (with auth) or stdio."""
import argparse
import logging
from pathlib import Path

import uvicorn

from src.config import load_settings
from src.http_app import build_http_app
from src.limits import RateLimiter
from src.logging_setup import HeartbeatWriter, configure_json_logging
from src.mcp_server import build_app, startup_self_check
from src.wazuh_client import WazuhClient
from src.wazuh_service import WazuhDataService

STATUS_FILE = Path("/var/ossec/logs/sidecar-status/sidecar-status.json")
ALERTS_INDEX = "wazuh-alerts-*"

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport", choices=["sse", "stdio"], default="sse",
        help="Transport: 'sse' (HTTP/SSE, production) or 'stdio' (local dev).",
    )
    args = parser.parse_args()

    configure_json_logging()
    settings = load_settings()

    client = WazuhClient(
        url=settings.opensearch_url,
        user=settings.os_user,
        password=settings.os_password,
    )
    startup_self_check(client, alerts_index=ALERTS_INDEX)

    service = WazuhDataService(
        client, alerts_index=ALERTS_INDEX, status_file=STATUS_FILE,
    )

    heartbeat = HeartbeatWriter(
        sidecar="wazuh-mcp",
        path=STATUS_FILE,
        interval=60,
        max_size=settings.max_log_size,
        max_backups=settings.max_log_backups,
    )
    heartbeat._emit_heartbeat()  # seed the stream on startup
    heartbeat.start()

    rate_limiter = RateLimiter(
        per_min=settings.rate_limit_per_min, burst=settings.rate_limit_burst
    )

    mcp_app = build_app(service=service, rate_limiter=rate_limiter)

    if args.transport == "stdio":
        logger.info("starting stdio transport")
        mcp_app.run(transport="stdio")
        return

    # HTTP/SSE: wrap the FastMCP SSE app with auth + /healthz, run via uvicorn.
    sse_app = mcp_app.sse_app()
    http_app = build_http_app(inner_app=sse_app, api_key=settings.api_key)
    logger.info("starting SSE on 127.0.0.1:%d", settings.http_port)
    uvicorn.run(
        http_app,
        host="127.0.0.1",
        port=settings.http_port,
        log_config=None,   # don't override our JSON logger
    )


if __name__ == "__main__":
    main()
