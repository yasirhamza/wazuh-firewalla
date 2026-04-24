"""Standalone entrypoint for the first-seen-scanner sidecar.

Separate concern from the MCP server: this runs scheduled batch scans
(no LLM, no HTTP, no tool catalog) and emits one sidecar_status event
per device per cycle into the shared sidecar-status JSONL stream.

Ships in the same Docker image as wazuh-mcp for build simplicity —
docker-compose picks which entrypoint to run via different `command:`
overrides. The two services are otherwise independent processes with
their own lifecycles.
"""
import logging
import signal
import sys
import threading
from pathlib import Path

from src.config import load_settings
from src.first_seen_scheduler import FirstSeenScheduler
from src.logging_setup import HeartbeatWriter, configure_json_logging
from src.wazuh_client import WazuhClient
from src.wazuh_service import WazuhDataService

STATUS_FILE = Path("/var/ossec/logs/sidecar-status/sidecar-status.json")
ALERTS_INDEX = "wazuh-alerts-*"
SIDECAR_NAME = "first-seen-scanner"

logger = logging.getLogger(__name__)


def main() -> None:
    configure_json_logging()
    settings = load_settings()

    if not settings.first_seen_enabled:
        logger.info("first-seen scanner disabled via FIRST_SEEN_ENABLED=false; exiting")
        sys.exit(0)

    client = WazuhClient(
        url=settings.opensearch_url,
        user=settings.os_user,
        password=settings.os_password,
    )
    service = WazuhDataService(
        client, alerts_index=ALERTS_INDEX, status_file=STATUS_FILE,
    )

    heartbeat = HeartbeatWriter(
        sidecar=SIDECAR_NAME,
        path=STATUS_FILE,
        interval=60,
        max_size=settings.max_log_size,
        max_backups=settings.max_log_backups,
    )
    heartbeat.emit_once()  # seed stream so sidecar_health sees us immediately
    heartbeat.start()

    scheduler = FirstSeenScheduler(
        service=service,
        heartbeat=heartbeat,
        interval_sec=settings.first_seen_scan_interval_sec,
        recent_window=settings.first_seen_recent_window,
        baseline_days=settings.first_seen_baseline_days,
    )
    scheduler.start()
    logger.info(
        "first-seen scanner running",
        extra={
            "interval_sec": settings.first_seen_scan_interval_sec,
            "recent_window": settings.first_seen_recent_window,
            "baseline_days": settings.first_seen_baseline_days,
        },
    )

    # Block forever; graceful shutdown on SIGTERM (docker stop) or SIGINT.
    stop_evt = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_evt.set())
    signal.signal(signal.SIGINT, lambda *_: stop_evt.set())
    stop_evt.wait()

    logger.info("first-seen scanner shutting down")
    scheduler.stop()
    heartbeat.stop()


if __name__ == "__main__":
    main()
