"""JSON stdout logging + shared JSONL heartbeat writer.

Appends events to the sidecar-status.json stream shared with msp-poller and
threat-intel. Events are ingested by rule chain 100500-100504.
"""
import json
import logging
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    _SKIP = frozenset({
        "args", "msg", "levelname", "name", "created", "msecs",
        "relativeCreated", "levelno", "pathname", "filename", "module",
        "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "thread", "threadName", "processName", "process", "getMessage",
        "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "component": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in self._SKIP:
                continue
            base[k] = v
        return json.dumps(base, default=str)


def configure_json_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(logging.INFO)


class HeartbeatWriter:
    """Appends sidecar-status events (JSONL) to the shared status file.

    Schema matches the existing msp-poller / threat-intel StatusReporter, so the
    same rule chain (100500-100504) ingests our events.

    Usage:
        hb = HeartbeatWriter(sidecar="wazuh-mcp", path=Path("/var/ossec/logs/sidecar-status/sidecar-status.json"))
        hb.start()                                       # begins periodic heartbeats
        hb.record_ok(job_type="tool_call")               # in-memory counter only
        hb.record_error("bad DSL", job_type="tool_call") # writes error event immediately
        hb.stop()                                        # on shutdown
    """

    def __init__(
        self,
        sidecar: str,
        path: Path,
        interval: int = 60,
        max_size: int = 10 * 1024 * 1024,
        max_backups: int = 2,
    ):
        self._sidecar = sidecar
        self._path = Path(path)
        self._interval = interval
        self._max_size = max_size
        self._max_backups = max_backups
        self._started = time.time()
        self._ok_count = 0
        self._errors: deque[tuple[float, str]] = deque()  # (ts, message)
        self._last_error: str | None = None
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------- lifecycle ----------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ---------- public recording API ----------
    def record_ok(self, job_type: str = "tool_call") -> None:
        """Count a success in memory; no disk write — reduces JSONL churn."""
        with self._lock:
            self._ok_count += 1
            self._prune_locked()

    def record_error(self, message: str, job_type: str = "tool_call") -> None:
        """Append an error event AND track in memory for the next heartbeat."""
        now = time.time()
        with self._lock:
            self._errors.append((now, message))
            self._last_error = message
            self._prune_locked()
        self._append_event({
            "timestamp": _iso(now),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": self._sidecar,
            "job_type": job_type,
            "sync_status": "error",
            "error_message": message,
        })

    # ---------- internals ----------
    def _prune_locked(self) -> None:
        cutoff = time.time() - 600  # 10 min
        while self._errors and self._errors[0][0] < cutoff:
            self._errors.popleft()

    def _run(self) -> None:
        while not self._stop_evt.wait(self._interval):
            self._emit_heartbeat()

    def emit_once(self) -> None:
        """Emit a single heartbeat synchronously. Intended for seeding the
        shared stream at startup before the background thread begins ticking."""
        self._emit_heartbeat()

    def _emit_heartbeat(self) -> None:
        now = time.time()
        with self._lock:
            self._prune_locked()
            stats = {
                "uptime_sec": int(now - self._started),
                "ok_count_total": self._ok_count,
                "error_count_10m": len(self._errors),
                "last_error": self._last_error,
            }
        self._append_event({
            "timestamp": _iso(now),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": self._sidecar,
            "job_type": "heartbeat",
            "sync_status": "running",
            "stats": stats,
        })

    def _append_event(self, event: dict[str, Any]) -> None:
        # Serialize rotate + append: concurrent heartbeat-thread + error-path
        # writes must not interleave with a rename() on rotation.
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with open(self._path, "a") as f:
                f.write(json.dumps(event) + "\n")

    def _rotate_if_needed(self) -> None:
        if not self._path.exists() or self._path.stat().st_size < self._max_size:
            return
        # Drop the oldest backup if we're at capacity.
        oldest = self._path.parent / (self._path.name + f".{self._max_backups}")
        if oldest.exists():
            oldest.unlink()
        # Shift remaining backups: .N-1 -> .N, ..., .1 -> .2
        for i in range(self._max_backups - 1, 0, -1):
            src = self._path.parent / (self._path.name + f".{i}")
            dst = self._path.parent / (self._path.name + f".{i + 1}")
            if src.exists():
                src.rename(dst)
        # Current file -> .1
        self._path.rename(self._path.parent / (self._path.name + ".1"))


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))
