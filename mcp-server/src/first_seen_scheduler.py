"""Background scheduler: runs first-seen-domain scans on a timer and
emits one event per device into the shared sidecar-status JSONL stream.

Lives in-process alongside the MCP server. Calls WazuhDataService directly
(no HTTP/MCP hop) — the service layer's "no MCP imports" invariant is what
makes this reuse clean.
"""
import logging
import threading
import time

from src.logging_setup import HeartbeatWriter
from src.wazuh_service import WazuhDataService

logger = logging.getLogger(__name__)


class FirstSeenScheduler:
    """Periodic scanner. Stoppable via stop(); daemon-thread for container exit.

    Runs one scan cycle every `interval_sec`. The first run fires after an
    initial warm-up delay (default 60s) so container startup doesn't get
    blocked by a potentially-expensive scan.
    """

    def __init__(
        self,
        service: WazuhDataService,
        heartbeat: HeartbeatWriter,
        interval_sec: int = 86400,       # 24h default
        warmup_sec: int = 60,            # delay before first scan
        recent_window: str = "last_7d",
        baseline_days: int = 90,
    ):
        self._service = service
        self._heartbeat = heartbeat
        self._interval = interval_sec
        self._warmup = warmup_sec
        self._recent = recent_window
        self._baseline = baseline_days
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="first-seen-scheduler"
        )
        self._thread.start()
        logger.info(
            "first_seen_scheduler started",
            extra={"interval_sec": self._interval, "warmup_sec": self._warmup},
        )

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Warm-up: don't scan the moment the container is up — gives OpenSearch
        # time to be ready and avoids competing with startup_self_check.
        if self._stop_evt.wait(self._warmup):
            return
        while True:
            try:
                self._run_one_cycle()
            except Exception:
                logger.exception("first_seen_scheduler: scan cycle failed")
                # Keep scheduling; a transient OpenSearch blip shouldn't kill
                # the thread. A persistent failure will show up as zero
                # reports landing and a pile of errors in the container log.
            if self._stop_evt.wait(self._interval):
                return

    def _run_one_cycle(self) -> None:
        start = time.monotonic()
        reports = self._service.scan_first_seen_for_all_devices(
            recent_window=self._recent,
            baseline_days=self._baseline,
        )
        for report in reports:
            self._heartbeat.record_first_seen(report)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "first_seen_scheduler cycle complete",
            extra={
                "devices_scanned": len(reports),
                "duration_ms": duration_ms,
                "total_new_domains": sum(
                    r.get("new_domain_count", 0) for r in reports
                ),
            },
        )
