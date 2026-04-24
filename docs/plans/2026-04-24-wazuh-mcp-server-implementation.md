# Wazuh MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only MCP server sidecar that exposes 8 Wazuh SIEM analytics tools (search, aggregation, trend, threat-intel, drill-down) to Claude Code over HTTP/SSE.

**Architecture:** Python FastMCP app running as a Docker sidecar in the existing Wazuh stack. Layered code: `wazuh_client` → `wazuh_service` (no MCP imports) → `mcp_server` (thin tool wrappers). Stateless queries against OpenSearch using a dedicated read-only user. Heartbeat/error events fed into the existing Sidecar Monitoring dashboard.

**Tech Stack:** Python 3.12, FastMCP, opensearch-py, Pydantic, pytest. Docker Compose.

**Working directories:**
- **Primary (author + commit here):** `/path/to/firewalla-wazuh/mcp-server/` — the git repo.
- **Deployment target:** `/opt/wazuh-docker/single-node/mcp-server/` — synced at deployment (Task 22). `docker-compose` runs from this location.
- **Spec reference:** `/path/to/firewalla-wazuh/docs/specs/2026-04-24-wazuh-mcp-server-design.md`

**Important context from `/path/to/repo/CLAUDE.md`:**
- Single-node Wazuh Docker deployment, currently at 4.14.3.
- Custom rules include 100450-100453 (threat intel) and 100500-100504 (sidecar status).
- `wazuh.indexer` is OpenSearch 2.x inside the Docker network; hostname `wazuh.indexer`; TLS uses self-signed certs.
- Existing sidecars write status JSON to a shared `sidecar_status` volume, ingested into rule chain 100500-100504.
- The `/opt/wazuh-docker/single-node/` tree is NOT a git repo — never commit from there.

---

## Task 1: Scaffold the `mcp-server/` directory

**Files:**
- Create: `mcp-server/requirements.txt`
- Create: `mcp-server/pytest.ini`
- Create: `mcp-server/.env.example`
- Create: `mcp-server/src/__init__.py` (empty)
- Create: `mcp-server/tests/__init__.py` (empty)
- Create: `mcp-server/tests/conftest.py` (minimal)
- Create: `mcp-server/.gitignore`
- Create: `mcp-server/README.md`

- [ ] **Step 1: Create the folder skeleton**

Run from `/path/to/firewalla-wazuh/`:

```bash
mkdir -p mcp-server/src mcp-server/tests mcp-server/scripts
touch mcp-server/src/__init__.py mcp-server/tests/__init__.py
```

- [ ] **Step 2: Write `mcp-server/requirements.txt`**

```text
mcp>=1.2.0
opensearch-py>=2.6.0
python-dotenv>=1.0.0
pydantic>=2.7.0
```

Test-only (added via `requirements-dev.txt`):

```text
-r requirements.txt
pytest>=8.0.0
pytest-asyncio>=0.23.0
```

Create `mcp-server/requirements-dev.txt` with the two lines above.

- [ ] **Step 3: Write `mcp-server/pytest.ini`**

```ini
[pytest]
testpaths = tests
addopts = -v --tb=short
markers =
    integration: tests that require a live OpenSearch (skip by default)
asyncio_mode = auto
```

- [ ] **Step 4: Write `mcp-server/.env.example`**

```bash
# OpenSearch access (mcp_read user — see scripts/create_mcp_user.sh)
MCP_OS_USER=mcp_read
MCP_OS_PASSWORD=change-me
OPENSEARCH_URL=https://wazuh.indexer:9200

# MCP server
MCP_API_KEY=change-me-to-a-long-random-string
MCP_HTTP_PORT=8800

# Log rotation (optional)
MAX_LOG_SIZE=10485760
MAX_LOG_BACKUPS=2

# Rate limit (optional)
RATE_LIMIT_PER_MIN=60
RATE_LIMIT_BURST=10
```

- [ ] **Step 5: Write `mcp-server/.gitignore`**

```text
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.coverage
.venv/
venv/
*.egg-info/
.env
.env.local
```

- [ ] **Step 6: Write `mcp-server/README.md` (one page)**

```markdown
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
```

- [ ] **Step 7: Write `mcp-server/tests/conftest.py`**

```python
"""Shared pytest fixtures."""
import pytest


@pytest.fixture
def sample_alert():
    """A minimal Wazuh alert document, shape-accurate for our tools."""
    return {
        "_id": "alert-abc-123",
        "_source": {
            "@timestamp": "2026-04-24T12:00:00.000Z",
            "timestamp": "2026-04-24T12:00:00.000Z",
            "agent": {"id": "001", "name": "kids-laptop", "ip": "192.0.2.50"},
            "rule": {
                "id": "100651",
                "level": 3,
                "description": "SRP allowed executable launch",
                "groups": ["windows", "srp"],
            },
            "data": {
                "source": "windows-srp",
                "srp": {
                    "action": "ALLOWED",
                    "target_path": "C:\\Windows\\system32\\notepad.exe",
                    "user": "alice",
                },
            },
        },
    }
```

- [ ] **Step 8: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/
git commit -m "feat(mcp-server): scaffold directory structure and dev setup"
```

---

## Task 2: Config module (TDD)

**Files:**
- Create: `mcp-server/src/config.py`
- Create: `mcp-server/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Create `mcp-server/tests/test_config.py`:

```python
"""Tests for config loading."""
import os

import pytest

from src.config import Settings, load_settings


def test_load_settings_from_env(monkeypatch):
    monkeypatch.setenv("MCP_OS_USER", "mcp_read")
    monkeypatch.setenv("MCP_OS_PASSWORD", "secret")
    monkeypatch.setenv("MCP_API_KEY", "api-key-xyz")
    monkeypatch.setenv("MCP_HTTP_PORT", "8800")
    monkeypatch.setenv("OPENSEARCH_URL", "https://wazuh.indexer:9200")

    settings = load_settings()

    assert isinstance(settings, Settings)
    assert settings.os_user == "mcp_read"
    assert settings.os_password == "secret"
    assert settings.api_key == "api-key-xyz"
    assert settings.http_port == 8800
    assert settings.opensearch_url == "https://wazuh.indexer:9200"


def test_load_settings_defaults(monkeypatch):
    for var in ("MCP_OS_USER", "MCP_OS_PASSWORD", "MCP_API_KEY", "OPENSEARCH_URL"):
        monkeypatch.setenv(var, "x")
    # defaults should fill in
    settings = load_settings()
    assert settings.http_port == 8800
    assert settings.max_log_size == 10 * 1024 * 1024
    assert settings.max_log_backups == 2
    assert settings.rate_limit_per_min == 60
    assert settings.rate_limit_burst == 10


def test_load_settings_missing_required(monkeypatch):
    monkeypatch.delenv("MCP_OS_USER", raising=False)
    monkeypatch.delenv("MCP_OS_PASSWORD", raising=False)
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    with pytest.raises(ValueError, match="MCP_OS_USER"):
        load_settings()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /path/to/firewalla-wazuh/mcp-server
python -m pytest tests/test_config.py -v
```

Expected: ModuleNotFoundError or ImportError for `src.config`.

- [ ] **Step 3: Write minimal implementation**

Create `mcp-server/src/config.py`:

```python
"""Settings loader with required-var validation."""
import os
from dataclasses import dataclass


REQUIRED = ("MCP_OS_USER", "MCP_OS_PASSWORD", "MCP_API_KEY", "OPENSEARCH_URL")


@dataclass(frozen=True)
class Settings:
    os_user: str
    os_password: str
    api_key: str
    http_port: int
    opensearch_url: str
    max_log_size: int
    max_log_backups: int
    rate_limit_per_min: int
    rate_limit_burst: int


def load_settings() -> Settings:
    missing = [v for v in REQUIRED if not os.environ.get(v)]
    if missing:
        raise ValueError(f"Missing required env vars: {', '.join(missing)}")
    return Settings(
        os_user=os.environ["MCP_OS_USER"],
        os_password=os.environ["MCP_OS_PASSWORD"],
        api_key=os.environ["MCP_API_KEY"],
        http_port=int(os.environ.get("MCP_HTTP_PORT", "8800")),
        opensearch_url=os.environ["OPENSEARCH_URL"],
        max_log_size=int(os.environ.get("MAX_LOG_SIZE", str(10 * 1024 * 1024))),
        max_log_backups=int(os.environ.get("MAX_LOG_BACKUPS", "2")),
        rate_limit_per_min=int(os.environ.get("RATE_LIMIT_PER_MIN", "60")),
        rate_limit_burst=int(os.environ.get("RATE_LIMIT_BURST", "10")),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_config.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/config.py mcp-server/tests/test_config.py
git commit -m "feat(mcp-server): config loader with required-var validation"
```

---

## Task 3: Wazuh OpenSearch client (TDD)

**Files:**
- Create: `mcp-server/src/wazuh_client.py`
- Create: `mcp-server/tests/test_wazuh_client.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_wazuh_client.py`:

```python
"""Tests for the thin OpenSearch client wrapper."""
from unittest.mock import MagicMock, patch

import pytest

from src.wazuh_client import WazuhClient, WazuhClientError


def make_client():
    with patch("src.wazuh_client.OpenSearch") as mock_os_cls:
        mock_os = MagicMock()
        mock_os_cls.return_value = mock_os
        client = WazuhClient(
            url="https://wazuh.indexer:9200",
            user="mcp_read",
            password="secret",
            timeout=10,
        )
        return client, mock_os


def test_search_passes_body_to_opensearch():
    client, mock_os = make_client()
    mock_os.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    body = {"query": {"match_all": {}}}

    result = client.search(index="wazuh-alerts-*", body=body)

    mock_os.search.assert_called_once_with(
        index="wazuh-alerts-*", body=body, request_timeout=10
    )
    assert result["hits"]["total"]["value"] == 0


def test_search_retries_once_on_connection_error():
    client, mock_os = make_client()
    from opensearchpy import ConnectionError

    mock_os.search.side_effect = [ConnectionError("boom"), {"hits": {"total": {"value": 1}, "hits": []}}]

    result = client.search(index="wazuh-alerts-*", body={})

    assert mock_os.search.call_count == 2
    assert result["hits"]["total"]["value"] == 1


def test_search_raises_after_retry_exhausted():
    client, mock_os = make_client()
    from opensearchpy import ConnectionError

    mock_os.search.side_effect = ConnectionError("still dead")

    with pytest.raises(WazuhClientError, match="opensearch_unavailable"):
        client.search(index="wazuh-alerts-*", body={})
    assert mock_os.search.call_count == 2


def test_count_delegates_to_opensearch():
    client, mock_os = make_client()
    mock_os.count.return_value = {"count": 42}

    assert client.count(index="wazuh-alerts-*", body={"query": {"match_all": {}}}) == 42


def test_ping_returns_true_on_success():
    client, mock_os = make_client()
    mock_os.ping.return_value = True
    assert client.ping() is True


def test_ping_returns_false_on_failure():
    client, mock_os = make_client()
    mock_os.ping.side_effect = Exception("nope")
    assert client.ping() is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_wazuh_client.py -v
```

Expected: ImportError for `src.wazuh_client`.

- [ ] **Step 3: Write implementation**

Create `mcp-server/src/wazuh_client.py`:

```python
"""Thin OpenSearch client wrapper with one retry + timeout."""
import logging
import time
from typing import Any

from opensearchpy import OpenSearch, ConnectionError as OSConnectionError, TransportError

logger = logging.getLogger(__name__)


class WazuhClientError(Exception):
    """Categorized error surfaced to the service layer."""

    def __init__(self, code: str, message: str, cause: Exception | None = None):
        self.code = code
        self.message = message
        self.cause = cause
        super().__init__(f"{code}: {message}")


class WazuhClient:
    def __init__(self, url: str, user: str, password: str, timeout: int = 10):
        self._timeout = timeout
        self._os = OpenSearch(
            hosts=[url],
            http_auth=(user, password),
            use_ssl=url.startswith("https"),
            verify_certs=False,  # self-signed certs in the Wazuh stack
            ssl_show_warn=False,
            http_compress=True,
        )
        if not url.startswith("https") or True:
            logger.warning("TLS cert verification disabled (self-signed Wazuh certs)")

    def _retry_once(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (OSConnectionError, TransportError) as e:
            logger.warning("OpenSearch transient error: %s, retrying once", e)
            time.sleep(0.5)
            try:
                return fn(*args, **kwargs)
            except (OSConnectionError, TransportError) as e2:
                raise WazuhClientError(
                    code="opensearch_unavailable",
                    message=str(e2),
                    cause=e2,
                )

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._retry_once(
            self._os.search, index=index, body=body, request_timeout=self._timeout
        )

    def count(self, index: str, body: dict[str, Any]) -> int:
        resp = self._retry_once(
            self._os.count, index=index, body=body, request_timeout=self._timeout
        )
        return resp["count"]

    def ping(self) -> bool:
        try:
            return bool(self._os.ping())
        except Exception:
            return False
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_wazuh_client.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_client.py mcp-server/tests/test_wazuh_client.py
git commit -m "feat(mcp-server): OpenSearch client with retry + categorized errors"
```

---

## Task 4: Limits module — rate limiter + result cap (TDD)

**Files:**
- Create: `mcp-server/src/limits.py`
- Create: `mcp-server/tests/test_limits.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_limits.py`:

```python
"""Tests for rate limiter + result-size cap."""
import time

import pytest

from src.limits import RateLimiter, RateLimitExceeded, cap_results


def test_rate_limiter_allows_within_burst():
    rl = RateLimiter(per_min=60, burst=10)
    for _ in range(10):
        rl.check("key-a")  # does not raise


def test_rate_limiter_blocks_over_burst():
    rl = RateLimiter(per_min=60, burst=3)
    rl.check("k"); rl.check("k"); rl.check("k")
    with pytest.raises(RateLimitExceeded) as exc:
        rl.check("k")
    assert exc.value.retry_after > 0


def test_rate_limiter_refills_over_time(monkeypatch):
    current = [1000.0]
    monkeypatch.setattr("src.limits.time.monotonic", lambda: current[0])
    rl = RateLimiter(per_min=60, burst=3)  # 1 token/sec
    rl.check("k"); rl.check("k"); rl.check("k")
    current[0] += 1.0  # 1 second later
    rl.check("k")  # should pass — 1 token refilled


def test_rate_limiter_keys_are_independent():
    rl = RateLimiter(per_min=60, burst=2)
    rl.check("a"); rl.check("a")
    rl.check("b"); rl.check("b")  # different key, still ok


def test_cap_results_below_cap():
    out = cap_results([1, 2, 3], cap=10, total_matched=3)
    assert out == {"results": [1, 2, 3], "truncated": False, "total_matched": 3}


def test_cap_results_truncates():
    rows = list(range(150))
    out = cap_results(rows, cap=100, total_matched=250)
    assert out["results"] == rows[:100]
    assert out["truncated"] is True
    assert out["total_matched"] == 250
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_limits.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write implementation**

Create `mcp-server/src/limits.py`:

```python
"""Rate limiter (token bucket, per-key, in-process) + result cap helper."""
import math
import time
from dataclasses import dataclass
from threading import Lock


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded, retry in {retry_after:.1f}s")


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token-bucket per key. refill_rate tokens/sec, capped at burst."""

    def __init__(self, per_min: int, burst: int):
        self._refill = per_min / 60.0
        self._burst = float(burst)
        self._lock = Lock()
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                self._buckets[key] = _Bucket(tokens=self._burst - 1, updated=now)
                return
            # refill
            elapsed = now - b.updated
            b.tokens = min(self._burst, b.tokens + elapsed * self._refill)
            b.updated = now
            if b.tokens >= 1:
                b.tokens -= 1
                return
            deficit = 1 - b.tokens
            raise RateLimitExceeded(retry_after=math.ceil(deficit / self._refill))


def cap_results(rows: list, cap: int, total_matched: int) -> dict:
    truncated = len(rows) > cap or total_matched > cap
    return {
        "results": rows[:cap],
        "truncated": truncated,
        "total_matched": total_matched,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_limits.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/limits.py mcp-server/tests/test_limits.py
git commit -m "feat(mcp-server): token-bucket rate limiter + result-cap helper"
```

---

## Task 5: Logging + heartbeat writer (TDD)

**Files:**
- Create: `mcp-server/src/logging_setup.py`
- Create: `mcp-server/tests/test_logging_setup.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_logging_setup.py`:

```python
"""Tests for structured logging + heartbeat writer."""
import json
import time
from pathlib import Path

from src.logging_setup import HeartbeatWriter, configure_json_logging


def test_configure_json_logging_emits_json(capsys):
    configure_json_logging("test")
    import logging

    logging.getLogger("x").info("hello", extra={"tool": "foo"})
    out = capsys.readouterr().out.strip().splitlines()
    last = json.loads(out[-1])
    assert last["msg"] == "hello"
    assert last["tool"] == "foo"
    assert last["level"] == "INFO"


def test_heartbeat_writer_writes_status(tmp_path: Path):
    target = tmp_path / "status.json"
    hb = HeartbeatWriter(
        component="wazuh-mcp", path=target, interval=60
    )
    hb.record_ok()
    hb._flush()
    data = json.loads(target.read_text())
    assert data["component"] == "wazuh-mcp"
    assert data["status"] == "ok"
    assert "last_heartbeat" in data


def test_heartbeat_writer_records_errors(tmp_path: Path):
    target = tmp_path / "status.json"
    hb = HeartbeatWriter(component="wazuh-mcp", path=target, interval=60)
    hb.record_error("opensearch_unavailable: timeout")
    hb._flush()
    data = json.loads(target.read_text())
    assert data["status"] == "error"
    assert data["last_error"] == "opensearch_unavailable: timeout"
    assert data["error_count_10m"] == 1


def test_heartbeat_writer_rolls_error_count_over_window(tmp_path: Path, monkeypatch):
    target = tmp_path / "status.json"
    now = [1000.0]
    monkeypatch.setattr("src.logging_setup.time.time", lambda: now[0])
    hb = HeartbeatWriter(component="wazuh-mcp", path=target, interval=60)
    hb.record_error("e1")
    now[0] += 700  # >10 min elapsed
    hb.record_error("e2")
    hb._flush()
    data = json.loads(target.read_text())
    assert data["error_count_10m"] == 1  # old error rolled off
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_logging_setup.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write implementation**

Create `mcp-server/src/logging_setup.py`:

```python
"""JSON stdout logging + sidecar-status heartbeat file.

Heartbeat schema matches rules 100500-100504 in wazuh-config/rules/.
"""
import json
import logging
import sys
import threading
import time
from collections import deque
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "component": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in ("args", "msg", "levelname", "name", "created", "msecs",
                     "relativeCreated", "levelno", "pathname", "filename",
                     "module", "exc_info", "exc_text", "stack_info", "lineno",
                     "funcName", "thread", "threadName", "processName",
                     "process", "getMessage"):
                continue
            base[k] = v
        return json.dumps(base, default=str)


def configure_json_logging(service: str) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(logging.INFO)


class HeartbeatWriter:
    """Thread-safe writer for sidecar-status.json.

    Call record_ok() on each successful tool call and record_error() on
    each failure. A background thread flushes the JSON file every `interval`
    seconds; _flush() is also public for test use.
    """

    def __init__(self, component: str, path: Path, interval: int = 60):
        self._component = component
        self._path = Path(path)
        self._interval = interval
        self._start = time.time()
        self._last_error: str | None = None
        self._errors: deque[tuple[float, str]] = deque()  # (ts, message)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def record_ok(self) -> None:
        with self._lock:
            self._prune_locked()

    def record_error(self, message: str) -> None:
        with self._lock:
            self._errors.append((time.time(), message))
            self._last_error = message
            self._prune_locked()

    def _prune_locked(self) -> None:
        cutoff = time.time() - 600  # 10 min
        while self._errors and self._errors[0][0] < cutoff:
            self._errors.popleft()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            self._prune_locked()
            err_count = len(self._errors)
            payload = {
                "component": self._component,
                "status": "error" if err_count > 0 else "ok",
                "last_heartbeat": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "uptime_sec": int(time.time() - self._start),
                "error_count_10m": err_count,
                "last_error": self._last_error,
            }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(payload))
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_logging_setup.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/logging_setup.py mcp-server/tests/test_logging_setup.py
git commit -m "feat(mcp-server): JSON logging + thread-safe heartbeat writer"
```

---

## Task 6: Time-range parser (TDD)

Single shared helper used by all service methods.

**Files:**
- Create: `mcp-server/src/time_range.py`
- Create: `mcp-server/tests/test_time_range.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_time_range.py`:

```python
"""Tests for time_range parsing."""
import pytest

from src.time_range import parse_time_range, TimeRangeError


def test_parse_last_24h():
    assert parse_time_range("last_24h") == {"gte": "now-24h/h", "lte": "now"}


def test_parse_last_7d():
    assert parse_time_range("last_7d") == {"gte": "now-7d/d", "lte": "now"}


def test_parse_last_30d():
    assert parse_time_range("last_30d") == {"gte": "now-30d/d", "lte": "now"}


def test_parse_iso_range():
    got = parse_time_range("2026-04-20T00:00:00Z/2026-04-24T00:00:00Z")
    assert got == {
        "gte": "2026-04-20T00:00:00Z",
        "lte": "2026-04-24T00:00:00Z",
    }


def test_parse_rejects_unknown_shorthand():
    with pytest.raises(TimeRangeError, match="unsupported"):
        parse_time_range("last_century")


def test_parse_rejects_backward_range():
    with pytest.raises(TimeRangeError, match="must be before"):
        parse_time_range("2026-04-24T00:00:00Z/2026-04-20T00:00:00Z")


def test_parse_rejects_span_over_90_days():
    with pytest.raises(TimeRangeError, match="90 days"):
        parse_time_range("2026-01-01T00:00:00Z/2026-04-30T00:00:00Z")


def test_parse_rejects_malformed():
    with pytest.raises(TimeRangeError):
        parse_time_range("not-a-range")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_time_range.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write implementation**

Create `mcp-server/src/time_range.py`:

```python
"""Parse user-friendly time_range strings into OpenSearch date-math dicts."""
from datetime import datetime, timezone


SHORTHAND = {
    "last_1h": {"gte": "now-1h/h", "lte": "now"},
    "last_6h": {"gte": "now-6h/h", "lte": "now"},
    "last_24h": {"gte": "now-24h/h", "lte": "now"},
    "last_7d": {"gte": "now-7d/d", "lte": "now"},
    "last_30d": {"gte": "now-30d/d", "lte": "now"},
    "last_90d": {"gte": "now-90d/d", "lte": "now"},
}

MAX_SPAN_DAYS = 90


class TimeRangeError(ValueError):
    """Raised for malformed or out-of-bounds time_range inputs."""


def parse_time_range(value: str) -> dict[str, str]:
    if value in SHORTHAND:
        return SHORTHAND[value]
    if "/" in value:
        try:
            start_s, end_s = value.split("/", 1)
            start = datetime.fromisoformat(start_s.replace("Z", "+00:00"))
            end = datetime.fromisoformat(end_s.replace("Z", "+00:00"))
        except ValueError as e:
            raise TimeRangeError(f"malformed iso range: {e}") from e
        if end <= start:
            raise TimeRangeError("end must be before start")
        span = (end - start).total_seconds() / 86400
        if span > MAX_SPAN_DAYS:
            raise TimeRangeError(f"time range exceeds 90 days (got {span:.1f}d)")
        return {"gte": start_s, "lte": end_s}
    raise TimeRangeError(
        f"unsupported time_range: {value!r}. Use shorthand ({', '.join(SHORTHAND)}) "
        "or an ISO-8601 range 'START/END'."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_time_range.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/time_range.py mcp-server/tests/test_time_range.py
git commit -m "feat(mcp-server): time_range parser with 90-day span cap"
```

---

## Task 7: Service skeleton + `search_alerts` (TDD)

**Files:**
- Create: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_search.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_search.py`:

```python
"""Tests for WazuhDataService.search_alerts."""
from unittest.mock import MagicMock

import pytest

from src.wazuh_service import WazuhDataService


def make_service(search_response):
    client = MagicMock()
    client.search.return_value = search_response
    return WazuhDataService(client, alerts_index="wazuh-alerts-*"), client


def test_search_alerts_with_filters_builds_term_queries():
    svc, client = make_service({
        "hits": {"total": {"value": 1}, "hits": [
            {"_id": "a1", "_source": {
                "@timestamp": "2026-04-24T00:00:00Z",
                "agent": {"name": "h"}, "rule": {"id": "1", "level": 3},
                "data": {}}
            }
        ]}
    })
    out = svc.search_alerts(
        filters={"agent.name": "kids-laptop", "rule.level": 7},
        time_range="last_24h",
        limit=25,
    )
    body = client.search.call_args.kwargs["body"]
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"agent.name": "kids-laptop"}} in filters
    assert {"term": {"rule.level": 7}} in filters
    assert any("@timestamp" in f.get("range", {}) for f in filters)
    assert body["size"] == 25
    assert out["total_matched"] == 1
    assert out["truncated"] is False


def test_search_alerts_with_list_values_uses_terms():
    svc, client = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    svc.search_alerts(
        filters={"rule.level": [7, 10, 12]}, time_range="last_24h"
    )
    filters = client.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    assert {"terms": {"rule.level": [7, 10, 12]}} in filters


def test_search_alerts_with_lucene_uses_query_string():
    svc, client = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    svc.search_alerts(lucene='rule.groups: "dns"', time_range="last_24h")
    body = client.search.call_args.kwargs["body"]
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == 'rule.groups: "dns"'


def test_search_alerts_enforces_limit_cap():
    svc, client = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    svc.search_alerts(filters={"agent.name": "h"}, time_range="last_24h", limit=500)
    body = client.search.call_args.kwargs["body"]
    assert body["size"] == 100  # hard cap


def test_search_alerts_marks_truncated_when_total_exceeds_limit():
    hits = [{"_id": f"a{i}", "_source": {"@timestamp": "t", "agent": {}, "rule": {}, "data": {}}} for i in range(25)]
    svc, client = make_service({"hits": {"total": {"value": 500}, "hits": hits}})
    out = svc.search_alerts(filters={"agent.name": "h"}, time_range="last_24h", limit=25)
    assert out["truncated"] is True
    assert out["total_matched"] == 500


def test_search_alerts_requires_one_of_filters_or_lucene():
    svc, _ = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    with pytest.raises(ValueError, match="filters"):
        svc.search_alerts(time_range="last_24h")


def test_search_alerts_default_sort_is_timestamp_desc():
    svc, client = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    svc.search_alerts(filters={"agent.name": "h"}, time_range="last_24h")
    sort = client.search.call_args.kwargs["body"]["sort"]
    assert sort == [{"@timestamp": "desc"}]


def test_search_alerts_respects_sort_by_rule_level():
    svc, client = make_service({"hits": {"total": {"value": 0}, "hits": []}})
    svc.search_alerts(
        filters={"agent.name": "h"}, time_range="last_24h", sort_by="rule.level"
    )
    sort = client.search.call_args.kwargs["body"]["sort"]
    assert sort == [{"rule.level": "desc"}]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_search.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write implementation**

Create `mcp-server/src/wazuh_service.py`:

```python
"""Domain logic for Wazuh SIEM queries. No MCP imports — reusable by any UI."""
from typing import Any

from src.time_range import parse_time_range


ALERTS_INDEX_DEFAULT = "wazuh-alerts-*"
HARD_RESULT_CAP = 100


class WazuhDataService:
    """One public method per MCP tool. Stateless."""

    def __init__(self, client, alerts_index: str = ALERTS_INDEX_DEFAULT):
        self._client = client
        self._alerts_index = alerts_index

    # ---------- helpers ----------

    def _time_filter(self, time_range: str) -> dict[str, Any]:
        return {"range": {"@timestamp": parse_time_range(time_range)}}

    def _build_filter_clauses(
        self, filters: dict[str, Any] | None, time_range: str
    ) -> list[dict[str, Any]]:
        clauses: list[dict[str, Any]] = [self._time_filter(time_range)]
        for k, v in (filters or {}).items():
            if isinstance(v, list):
                clauses.append({"terms": {k: v}})
            else:
                clauses.append({"term": {k: v}})
        return clauses

    def _shape_hit(self, hit: dict[str, Any]) -> dict[str, Any]:
        src = hit.get("_source", {})
        return {
            "id": hit["_id"],
            "@timestamp": src.get("@timestamp"),
            "agent": src.get("agent", {}),
            "rule": src.get("rule", {}),
            "data": src.get("data", {}),
        }

    # ---------- tools ----------

    def search_alerts(
        self,
        time_range: str,
        filters: dict[str, Any] | None = None,
        lucene: str | None = None,
        sort_by: str = "@timestamp",
        limit: int = 25,
    ) -> dict[str, Any]:
        if not filters and not lucene:
            raise ValueError("one of filters or lucene is required")
        size = min(limit, HARD_RESULT_CAP)
        must: list[dict[str, Any]] = []
        if lucene:
            must.append({"query_string": {"query": lucene}})
        body: dict[str, Any] = {
            "size": size,
            "sort": [{sort_by: "desc"}],
            "query": {
                "bool": {
                    "must": must,
                    "filter": self._build_filter_clauses(filters, time_range),
                }
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        total = resp["hits"]["total"]["value"]
        rows = [self._shape_hit(h) for h in resp["hits"]["hits"]]
        return {
            "results": rows,
            "total_matched": total,
            "truncated": total > len(rows),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_search.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_search.py
git commit -m "feat(mcp-server): WazuhDataService.search_alerts with filters/lucene"
```

---

## Task 8: `aggregate_alerts` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_aggregate.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_aggregate.py`:

```python
"""Tests for WazuhDataService.aggregate_alerts."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def test_aggregate_alerts_builds_terms_agg():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 500}},
        "aggregations": {
            "by_field": {
                "buckets": [
                    {"key": "dns", "doc_count": 120},
                    {"key": "firewall", "doc_count": 80},
                ]
            }
        },
    }
    svc = WazuhDataService(client)
    out = svc.aggregate_alerts(
        group_by_field="rule.groups", time_range="last_24h", top_n=5
    )
    body = client.search.call_args.kwargs["body"]
    assert body["size"] == 0
    assert body["aggs"]["by_field"]["terms"]["field"] == "rule.groups"
    assert body["aggs"]["by_field"]["terms"]["size"] == 5
    assert out["buckets"] == [
        {"key": "dns", "count": 120},
        {"key": "firewall", "count": 80},
    ]
    assert out["total_in_scope"] == 500


def test_aggregate_alerts_honors_filters():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 0}},
        "aggregations": {"by_field": {"buckets": []}},
    }
    svc = WazuhDataService(client)
    svc.aggregate_alerts(
        group_by_field="agent.name",
        time_range="last_7d",
        filters={"rule.level": [7, 10]},
    )
    filters = client.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    assert {"terms": {"rule.level": [7, 10]}} in filters


def test_aggregate_alerts_caps_top_n():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 0}},
        "aggregations": {"by_field": {"buckets": []}},
    }
    svc = WazuhDataService(client)
    svc.aggregate_alerts(group_by_field="x", time_range="last_24h", top_n=500)
    size = client.search.call_args.kwargs["body"]["aggs"]["by_field"]["terms"]["size"]
    assert size == 50  # hard cap
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_aggregate.py -v
```

Expected: AttributeError (method missing).

- [ ] **Step 3: Add method to `WazuhDataService`**

Append to `mcp-server/src/wazuh_service.py`:

```python
    def aggregate_alerts(
        self,
        group_by_field: str,
        time_range: str,
        filters: dict[str, Any] | None = None,
        top_n: int = 10,
    ) -> dict[str, Any]:
        size = min(top_n, 50)  # hard cap on bucket count
        body = {
            "size": 0,
            "query": {
                "bool": {"filter": self._build_filter_clauses(filters, time_range)}
            },
            "aggs": {
                "by_field": {"terms": {"field": group_by_field, "size": size}}
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        buckets = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in resp["aggregations"]["by_field"]["buckets"]
        ]
        return {
            "buckets": buckets,
            "total_in_scope": resp["hits"]["total"]["value"],
            "time_range": time_range,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_aggregate.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_aggregate.py
git commit -m "feat(mcp-server): aggregate_alerts for trend narration"
```

---

## Task 9: `alert_overview` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_overview.py`

- [ ] **Step 1: Write the failing test**

Create `mcp-server/tests/test_service_overview.py`:

```python
"""Tests for WazuhDataService.alert_overview."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def test_alert_overview_runs_single_multi_agg_query():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 12847}},
        "aggregations": {
            "by_source": {"buckets": [
                {"key": "firewalla-msp", "doc_count": 9201},
                {"key": "windows-srp", "doc_count": 2103},
            ]},
            "by_severity": {"buckets": [
                {"key": "low", "from": 0, "to": 4, "doc_count": 8120},
                {"key": "medium", "from": 4, "to": 8, "doc_count": 4703},
                {"key": "high", "from": 8, "to": 16, "doc_count": 24},
            ]},
            "top_rule_groups": {"buckets": [{"key": "dns", "doc_count": 2341}]},
            "top_agents": {"buckets": [{"key": "kids-laptop", "doc_count": 1903}]},
            "top_src_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 500}]},
            "top_dst_ips": {"buckets": [{"key": "203.0.113.10", "doc_count": 800}]},
            "threat_intel_hits": {"doc_count": 12},
        },
    }
    svc = WazuhDataService(client)
    out = svc.alert_overview(time_range="last_7d")

    # Only one OpenSearch call (single multi-agg query).
    assert client.search.call_count == 1
    assert out["total_alerts"] == 12847
    assert out["by_source"] == {"firewalla-msp": 9201, "windows-srp": 2103}
    assert out["by_severity"]["low (0-3)"] == 8120
    assert out["by_severity"]["medium (4-7)"] == 4703
    assert out["by_severity"]["high (8-12)"] == 24
    assert out["top_rule_groups"][0] == {"key": "dns", "count": 2341}
    assert out["threat_intel_hits"] == 12
    assert out["time_range"] == "last_7d"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_service_overview.py -v
```

Expected: AttributeError.

- [ ] **Step 3: Add method**

Append to `mcp-server/src/wazuh_service.py`:

```python
    def alert_overview(self, time_range: str) -> dict[str, Any]:
        body = {
            "size": 0,
            "query": {
                "bool": {"filter": self._build_filter_clauses(None, time_range)}
            },
            "aggs": {
                "by_source": {
                    "terms": {"field": "data.source", "size": 10, "missing": "unknown"}
                },
                "by_severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "from": 0, "to": 4},
                            {"key": "medium", "from": 4, "to": 8},
                            {"key": "high", "from": 8, "to": 16},
                        ],
                    }
                },
                "top_rule_groups": {"terms": {"field": "rule.groups", "size": 10}},
                "top_agents": {"terms": {"field": "agent.name", "size": 10}},
                "top_src_ips": {"terms": {"field": "data.srcip", "size": 10}},
                "top_dst_ips": {"terms": {"field": "data.dstip", "size": 10}},
                "threat_intel_hits": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                                {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
                            ]
                        }
                    }
                },
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        aggs = resp["aggregations"]

        severity_keymap = {"low": "low (0-3)", "medium": "medium (4-7)", "high": "high (8-12)"}
        return {
            "total_alerts": resp["hits"]["total"]["value"],
            "by_source": {b["key"]: b["doc_count"] for b in aggs["by_source"]["buckets"]},
            "by_severity": {
                severity_keymap[b["key"]]: b["doc_count"]
                for b in aggs["by_severity"]["buckets"]
            },
            "top_rule_groups": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_rule_groups"]["buckets"]
            ],
            "top_agents": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_agents"]["buckets"]
            ],
            "top_src_ips": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_src_ips"]["buckets"]
            ],
            "top_dst_ips": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_dst_ips"]["buckets"]
            ],
            "threat_intel_hits": aggs["threat_intel_hits"]["doc_count"],
            "time_range": time_range,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_overview.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_overview.py
git commit -m "feat(mcp-server): alert_overview pre-canned dashboard"
```

---

## Task 10: `trend_delta` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_trend.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_trend.py`:

```python
"""Tests for WazuhDataService.trend_delta."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def test_trend_delta_total_alerts():
    client = MagicMock()
    client.search.side_effect = [
        {"hits": {"total": {"value": 300}}, "aggregations": {}},  # current
        {"hits": {"total": {"value": 100}}, "aggregations": {}},  # prior
    ]
    svc = WazuhDataService(client)
    out = svc.trend_delta(
        metric="total_alerts",
        current_window="last_7d",
        prior_window="last_30d",
    )
    assert out["current"] == 300
    assert out["prior"] == 100
    assert out["delta_pct"] == 200.0  # 300 vs 100 → +200%


def test_trend_delta_by_agent_computes_movers():
    client = MagicMock()
    client.search.side_effect = [
        # current window
        {"hits": {"total": {"value": 0}}, "aggregations": {"by_field": {"buckets": [
            {"key": "kids-laptop", "doc_count": 400},
            {"key": "office-pc", "doc_count": 100},
        ]}}},
        # prior window
        {"hits": {"total": {"value": 0}}, "aggregations": {"by_field": {"buckets": [
            {"key": "kids-laptop", "doc_count": 100},
            {"key": "office-pc", "doc_count": 120},
        ]}}},
    ]
    svc = WazuhDataService(client)
    out = svc.trend_delta(
        metric="alerts_by_agent",
        current_window="last_7d",
        prior_window="last_30d",
        top_n=5,
    )
    kids = next(m for m in out["movers"] if m["key"] == "kids-laptop")
    assert kids["current"] == 400
    assert kids["prior"] == 100
    assert kids["delta_pct"] == 300.0
    # office-pc went from 120 to 100 → -16.7%
    office = next(m for m in out["movers"] if m["key"] == "office-pc")
    assert office["delta_pct"] == pytest_approx(-16.67, 0.01)


def test_trend_delta_handles_zero_prior():
    client = MagicMock()
    client.search.side_effect = [
        {"hits": {"total": {"value": 50}}, "aggregations": {}},
        {"hits": {"total": {"value": 0}}, "aggregations": {}},
    ]
    svc = WazuhDataService(client)
    out = svc.trend_delta(
        metric="total_alerts",
        current_window="last_7d",
        prior_window="last_30d",
    )
    assert out["delta_pct"] is None  # undefined when prior=0


def pytest_approx(val, tol):
    from pytest import approx
    return approx(val, abs=tol)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_trend.py -v
```

Expected: AttributeError.

- [ ] **Step 3: Add method**

Append to `mcp-server/src/wazuh_service.py`:

```python
    _METRIC_FIELD = {
        "total_alerts": None,  # pure count, no agg field
        "alerts_by_source": "data.source",
        "alerts_by_rule_group": "rule.groups",
        "alerts_by_agent": "agent.name",
        "threat_intel_hits": None,  # count of TI-rule matches
    }

    def _count_or_group(
        self,
        time_range: str,
        metric: str,
        filters: dict[str, Any] | None,
        top_n: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return (total, groups). Groups is [] when metric has no group field."""
        clauses = self._build_filter_clauses(filters, time_range)
        if metric == "threat_intel_hits":
            clauses.append({
                "bool": {"should": [
                    {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                    {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
                ]}
            })
        body: dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"filter": clauses}},
            "track_total_hits": True,
        }
        field = self._METRIC_FIELD[metric]
        if field is not None:
            body["aggs"] = {"by_field": {"terms": {"field": field, "size": min(top_n, 50)}}}
        resp = self._client.search(index=self._alerts_index, body=body)
        total = resp["hits"]["total"]["value"]
        groups = []
        if field is not None:
            groups = [
                {"key": b["key"], "count": b["doc_count"]}
                for b in resp["aggregations"]["by_field"]["buckets"]
            ]
        return total, groups

    @staticmethod
    def _pct_change(current: int, prior: int) -> float | None:
        if prior == 0:
            return None
        return round((current - prior) / prior * 100.0, 2)

    def trend_delta(
        self,
        metric: str,
        current_window: str,
        prior_window: str,
        filters: dict[str, Any] | None = None,
        top_n: int = 10,
    ) -> dict[str, Any]:
        if metric not in self._METRIC_FIELD:
            raise ValueError(f"unknown metric: {metric}")
        cur_total, cur_groups = self._count_or_group(current_window, metric, filters, top_n)
        pri_total, pri_groups = self._count_or_group(prior_window, metric, filters, top_n)

        out: dict[str, Any] = {
            "metric": metric,
            "current_window": current_window,
            "prior_window": prior_window,
            "current": cur_total,
            "prior": pri_total,
            "delta_pct": self._pct_change(cur_total, pri_total),
        }
        if cur_groups or pri_groups:
            pri_map = {g["key"]: g["count"] for g in pri_groups}
            cur_map = {g["key"]: g["count"] for g in cur_groups}
            keys = set(pri_map) | set(cur_map)
            movers = [
                {
                    "key": k,
                    "current": cur_map.get(k, 0),
                    "prior": pri_map.get(k, 0),
                    "delta_abs": cur_map.get(k, 0) - pri_map.get(k, 0),
                    "delta_pct": self._pct_change(cur_map.get(k, 0), pri_map.get(k, 0)),
                }
                for k in keys
            ]
            movers.sort(key=lambda m: abs(m["delta_abs"]), reverse=True)
            out["movers"] = movers[:top_n]
        return out
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_trend.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_trend.py
git commit -m "feat(mcp-server): trend_delta with per-entity movers"
```

---

## Task 11: `threat_intel_matches` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_threat_intel.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_threat_intel.py`:

```python
"""Tests for WazuhDataService.threat_intel_matches."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def _hit(rule_id, ioc="198.51.100.10", list_name="firewalla-c2"):
    return {
        "_id": f"ti-{rule_id}",
        "_source": {
            "@timestamp": "2026-04-24T10:00:00Z",
            "agent": {"name": "agent-a"},
            "rule": {"id": rule_id},
            "data": {
                "srcip": "10.0.0.5",
                "dstip": ioc,
                "threat_intel": {"list": list_name, "ioc": ioc},
            },
        },
    }


def test_threat_intel_matches_queries_both_rule_ranges():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 2}, "hits": [_hit("100450"), _hit("99901")]}
    }
    svc = WazuhDataService(client)
    out = svc.threat_intel_matches(time_range="last_24h")
    body = client.search.call_args.kwargs["body"]
    # filter should OR the two rule sources
    should = body["query"]["bool"]["filter"][-1]["bool"]["should"]
    terms = [s for s in should if "terms" in s][0]["terms"]["rule.id"]
    assert {"100450", "100451", "100452", "100453"}.issubset(set(terms))
    rng = [s for s in should if "range" in s][0]["range"]["rule.id"]
    assert rng == {"gte": "99901", "lte": "99999"}
    assert out["total"] == 2
    assert len(out["matches"]) == 2


def test_threat_intel_matches_with_list_filter_adds_term():
    client = MagicMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    svc = WazuhDataService(client)
    svc.threat_intel_matches(time_range="last_24h", list_filter="urlhaus")
    filters = client.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    assert any(
        f == {"term": {"data.threat_intel.list": "urlhaus"}} for f in filters
    )


def test_threat_intel_matches_list_filter_all_adds_no_filter():
    client = MagicMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    svc = WazuhDataService(client)
    svc.threat_intel_matches(time_range="last_24h", list_filter="all")
    filters = client.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    assert not any("data.threat_intel.list" in str(f) for f in filters)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_threat_intel.py -v
```

Expected: AttributeError.

- [ ] **Step 3: Add method**

Append to `mcp-server/src/wazuh_service.py`:

```python
    def threat_intel_matches(
        self,
        time_range: str,
        list_filter: str = "all",
        top_n: int = 100,
    ) -> dict[str, Any]:
        ti_filter = {
            "bool": {"should": [
                {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
            ]}
        }
        clauses = self._build_filter_clauses(None, time_range)
        if list_filter and list_filter != "all":
            clauses.append({"term": {"data.threat_intel.list": list_filter}})
        clauses.append(ti_filter)

        body = {
            "size": min(top_n, HARD_RESULT_CAP),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": clauses}},
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        matches = []
        for h in resp["hits"]["hits"]:
            src = h.get("_source", {})
            ti = src.get("data", {}).get("threat_intel", {})
            matches.append({
                "id": h["_id"],
                "@timestamp": src.get("@timestamp"),
                "list": ti.get("list"),
                "ioc": ti.get("ioc"),
                "agent": src.get("agent", {}).get("name"),
                "src_ip": src.get("data", {}).get("srcip"),
                "dst_ip": src.get("data", {}).get("dstip"),
                "rule_id": src.get("rule", {}).get("id"),
            })
        return {"matches": matches, "total": resp["hits"]["total"]["value"]}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_threat_intel.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_threat_intel.py
git commit -m "feat(mcp-server): threat_intel_matches over custom + built-in lists"
```

---

## Task 12: `sidecar_health` (TDD)

Reads the sidecar-status JSON files from the shared volume.

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_health.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_health.py`:

```python
"""Tests for WazuhDataService.sidecar_health."""
import json
from pathlib import Path
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def _write_status(dir: Path, name: str, status: str, last_error=None, errors=0):
    (dir / f"{name}.json").write_text(json.dumps({
        "component": name,
        "status": status,
        "last_heartbeat": "2026-04-24T10:00:00Z",
        "uptime_sec": 3600,
        "error_count_10m": errors,
        "last_error": last_error,
    }))


def test_sidecar_health_reads_all_status_files(tmp_path: Path):
    _write_status(tmp_path, "msp-poller", "ok")
    _write_status(tmp_path, "threat-intel", "ok")
    _write_status(tmp_path, "wazuh-mcp", "error", "opensearch_unavailable", 3)
    svc = WazuhDataService(MagicMock(), status_dir=tmp_path)

    out = svc.sidecar_health()

    names = {s["name"]: s for s in out["sidecars"]}
    assert set(names) == {"msp-poller", "threat-intel", "wazuh-mcp"}
    assert names["wazuh-mcp"]["status"] == "error"
    assert names["wazuh-mcp"]["error_count_10m"] == 3
    assert out["summary"]["any_errors"] is True
    assert out["summary"]["count_ok"] == 2
    assert out["summary"]["count_error"] == 1


def test_sidecar_health_reports_stale_heartbeat(tmp_path: Path, monkeypatch):
    (tmp_path / "msp-poller.json").write_text(json.dumps({
        "component": "msp-poller",
        "status": "ok",
        "last_heartbeat": "2026-04-24T08:00:00Z",  # 2 hours ago
        "uptime_sec": 100,
        "error_count_10m": 0,
        "last_error": None,
    }))
    monkeypatch.setattr(
        "src.wazuh_service.time.time",
        lambda: 1745489000.0,  # ~2026-04-24T10:03:20Z
    )
    svc = WazuhDataService(MagicMock(), status_dir=tmp_path)
    out = svc.sidecar_health()
    assert out["sidecars"][0]["status"] == "stale"


def test_sidecar_health_empty_dir(tmp_path: Path):
    svc = WazuhDataService(MagicMock(), status_dir=tmp_path)
    out = svc.sidecar_health()
    assert out["sidecars"] == []
    assert out["summary"]["count_ok"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_health.py -v
```

Expected: `WazuhDataService.__init__()` got an unexpected keyword argument `status_dir`.

- [ ] **Step 3: Update the service constructor and add the method**

Replace the `__init__` in `mcp-server/src/wazuh_service.py`:

```python
import time as _time  # add at top with other imports
from datetime import datetime, timezone
from pathlib import Path

# Make this module-level alias so tests can monkeypatch src.wazuh_service.time
time = _time
```

Change the class signature:

```python
    def __init__(
        self,
        client,
        alerts_index: str = ALERTS_INDEX_DEFAULT,
        status_dir: Path | None = None,
    ):
        self._client = client
        self._alerts_index = alerts_index
        self._status_dir = Path(status_dir) if status_dir else None
```

Add the method:

```python
    _STALE_SECONDS = 300  # 5 minutes

    def sidecar_health(self) -> dict[str, Any]:
        now = time.time()
        sidecars: list[dict[str, Any]] = []
        if self._status_dir and self._status_dir.exists():
            for p in sorted(self._status_dir.glob("*.json")):
                try:
                    data = json.loads(p.read_text())
                except Exception:
                    continue
                last_hb = data.get("last_heartbeat")
                stale = False
                if last_hb:
                    try:
                        dt = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
                        age = now - dt.timestamp()
                        stale = age > self._STALE_SECONDS
                    except ValueError:
                        stale = True
                sidecars.append({
                    "name": data.get("component", p.stem),
                    "status": "stale" if stale else data.get("status", "unknown"),
                    "last_heartbeat": last_hb,
                    "error_count_10m": data.get("error_count_10m", 0),
                    "last_error": data.get("last_error"),
                })
        ok = sum(1 for s in sidecars if s["status"] == "ok")
        err = sum(1 for s in sidecars if s["status"] in ("error", "stale"))
        return {
            "sidecars": sidecars,
            "summary": {
                "count_ok": ok,
                "count_error": err,
                "any_errors": err > 0,
            },
        }
```

Add `import json` at the top of the module if not already present.

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_health.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Run all service tests to check we didn't break anything**

```bash
python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_health.py
git commit -m "feat(mcp-server): sidecar_health reads shared status volume"
```

---

## Task 13: `get_alert` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_get_alert.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_get_alert.py`:

```python
"""Tests for WazuhDataService.get_alert."""
from unittest.mock import MagicMock

import pytest

from src.wazuh_service import AlertNotFound, WazuhDataService


def test_get_alert_returns_source():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 1}, "hits": [
            {"_id": "a1", "_source": {"rule": {"id": "100451"}, "agent": {"name": "h"}}}
        ]}
    }
    svc = WazuhDataService(client)
    out = svc.get_alert("a1")
    assert out == {"_id": "a1", "rule": {"id": "100451"}, "agent": {"name": "h"}}


def test_get_alert_raises_when_missing():
    client = MagicMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    svc = WazuhDataService(client)
    with pytest.raises(AlertNotFound):
        svc.get_alert("nope")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_get_alert.py -v
```

Expected: ImportError for `AlertNotFound`.

- [ ] **Step 3: Add `AlertNotFound` + method**

At the top of `mcp-server/src/wazuh_service.py`, add:

```python
class AlertNotFound(LookupError):
    """Raised when get_alert cannot find the requested alert_id."""
```

Add the method on `WazuhDataService`:

```python
    def get_alert(self, alert_id: str) -> dict[str, Any]:
        resp = self._client.search(
            index=self._alerts_index,
            body={
                "size": 1,
                "query": {"term": {"_id": alert_id}},
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise AlertNotFound(alert_id)
        return {"_id": hits[0]["_id"], **hits[0]["_source"]}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_get_alert.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_get_alert.py
git commit -m "feat(mcp-server): get_alert with typed not-found exception"
```

---

## Task 14: `entity_activity` (TDD)

**Files:**
- Modify: `mcp-server/src/wazuh_service.py`
- Create: `mcp-server/tests/test_service_entity.py`

Entity-type → fields mapping (IP searches src OR dst; user spans SRP + Windows event data; etc.):

| entity_type | fields searched (OR) |
|---|---|
| `ip` | `data.srcip`, `data.dstip` |
| `agent` | `agent.name`, `agent.id` |
| `device` | `data.device.name`, `data.device.mac`, `agent.ip` |
| `user` | `data.srp.user`, `data.win.eventdata.user` |
| `process` | `data.srp.target_path`, `data.win.eventdata.image` |
| `hash` | `syscheck.sha256_after`, `syscheck.md5_after`, `data.win.eventdata.hashes` |
| `domain` | `data.domain`, `dns.question.name` |

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_service_entity.py`:

```python
"""Tests for WazuhDataService.entity_activity."""
from unittest.mock import MagicMock

import pytest

from src.wazuh_service import WazuhDataService


def _empty_resp():
    return {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_source": {"buckets": []},
            "by_rule": {"buckets": []},
            "related_agents": {"buckets": []},
            "first_seen": {"value": None, "value_as_string": None},
            "last_seen": {"value": None, "value_as_string": None},
        },
    }


def test_entity_activity_ip_searches_src_or_dst():
    client = MagicMock()
    client.search.return_value = _empty_resp()
    svc = WazuhDataService(client)
    svc.entity_activity(entity_type="ip", entity_value="10.0.0.5", time_range="last_24h")
    body = client.search.call_args.kwargs["body"]
    should = body["query"]["bool"]["must"][0]["bool"]["should"]
    assert {"term": {"data.srcip": "10.0.0.5"}} in should
    assert {"term": {"data.dstip": "10.0.0.5"}} in should


def test_entity_activity_user_spans_srp_and_win():
    client = MagicMock()
    client.search.return_value = _empty_resp()
    svc = WazuhDataService(client)
    svc.entity_activity(entity_type="user", entity_value="alice", time_range="last_7d")
    should = client.search.call_args.kwargs["body"]["query"]["bool"]["must"][0]["bool"]["should"]
    assert {"term": {"data.srp.user": "alice"}} in should
    assert {"term": {"data.win.eventdata.user": "alice"}} in should


def test_entity_activity_unknown_type_raises():
    svc = WazuhDataService(MagicMock())
    with pytest.raises(ValueError, match="unknown entity_type"):
        svc.entity_activity(entity_type="bogus", entity_value="x", time_range="last_24h")


def test_entity_activity_shapes_response():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 47}, "hits": [
            {"_id": f"a{i}", "_source": {"@timestamp": f"2026-04-2{i}T12:00:00Z",
                                          "rule": {"id": "100450", "level": 10}}} for i in range(5)
        ]},
        "aggregations": {
            "by_source": {"buckets": [
                {"key": "firewalla-msp", "doc_count": 40},
                {"key": "threat-intel", "doc_count": 7},
            ]},
            "by_rule": {"buckets": [
                {"key": "100450", "doc_count": 7, "rule_desc": {"buckets": [
                    {"key": "Outbound connection to known C2"}]}}
            ]},
            "related_agents": {"buckets": [{"key": "agent-a", "doc_count": 23}]},
            "first_seen": {"value": 1745470000000, "value_as_string": "2026-04-20T01:14:22Z"},
            "last_seen": {"value": 1745489000000, "value_as_string": "2026-04-24T09:02:10Z"},
        },
    }
    svc = WazuhDataService(client)
    out = svc.entity_activity(entity_type="ip", entity_value="203.0.113.10", time_range="last_7d")
    assert out["entity"] == {"type": "ip", "value": "203.0.113.10"}
    assert out["total_alerts"] == 47
    assert out["by_source"] == {"firewalla-msp": 40, "threat-intel": 7}
    assert out["first_seen"] == "2026-04-20T01:14:22Z"
    assert out["last_seen"] == "2026-04-24T09:02:10Z"
    assert len(out["sample_alerts"]) == 5
    assert out["related_agents"][0] == {"name": "agent-a", "count": 23}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_service_entity.py -v
```

Expected: AttributeError.

- [ ] **Step 3: Add method**

Append to `mcp-server/src/wazuh_service.py`:

```python
    _ENTITY_FIELDS: dict[str, list[str]] = {
        "ip": ["data.srcip", "data.dstip"],
        "agent": ["agent.name", "agent.id"],
        "device": ["data.device.name", "data.device.mac", "agent.ip"],
        "user": ["data.srp.user", "data.win.eventdata.user"],
        "process": ["data.srp.target_path", "data.win.eventdata.image"],
        "hash": ["syscheck.sha256_after", "syscheck.md5_after", "data.win.eventdata.hashes"],
        "domain": ["data.domain", "dns.question.name"],
    }

    def entity_activity(
        self,
        entity_type: str,
        entity_value: str,
        time_range: str,
        top_n: int = 10,
    ) -> dict[str, Any]:
        fields = self._ENTITY_FIELDS.get(entity_type)
        if not fields:
            raise ValueError(
                f"unknown entity_type: {entity_type!r}. Expected one of {list(self._ENTITY_FIELDS)}"
            )
        size_n = min(top_n, 50)
        body = {
            "size": 5,  # most recent samples
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [{
                        "bool": {"should": [{"term": {f: entity_value}} for f in fields], "minimum_should_match": 1}
                    }],
                    "filter": self._build_filter_clauses(None, time_range),
                }
            },
            "aggs": {
                "by_source": {"terms": {"field": "data.source", "size": size_n}},
                "by_rule": {"terms": {"field": "rule.id", "size": size_n}},
                "related_agents": {"terms": {"field": "agent.name", "size": size_n}},
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        aggs = resp["aggregations"]
        return {
            "entity": {"type": entity_type, "value": entity_value},
            "total_alerts": resp["hits"]["total"]["value"],
            "by_source": {b["key"]: b["doc_count"] for b in aggs["by_source"]["buckets"]},
            "by_rule": [
                {"rule_id": b["key"], "count": b["doc_count"]}
                for b in aggs["by_rule"]["buckets"]
            ],
            "first_seen": aggs["first_seen"].get("value_as_string"),
            "last_seen": aggs["last_seen"].get("value_as_string"),
            "related_agents": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in aggs["related_agents"]["buckets"]
            ],
            "sample_alerts": [
                {
                    "id": h["_id"],
                    "@timestamp": h["_source"].get("@timestamp"),
                    "rule": h["_source"].get("rule", {}),
                }
                for h in resp["hits"]["hits"]
            ],
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_service_entity.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Run the full service test suite to check coverage**

```bash
python -m pytest tests/ -v
```

Expected: all service tests pass.

- [ ] **Step 6: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/wazuh_service.py mcp-server/tests/test_service_entity.py
git commit -m "feat(mcp-server): entity_activity multi-source pivot"
```

---

## Task 15: MCP server bootstrap (app, auth, transports, startup check)

**Files:**
- Create: `mcp-server/src/mcp_server.py`
- Create: `mcp-server/tests/test_mcp_server_bootstrap.py`

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_mcp_server_bootstrap.py`:

```python
"""Tests for MCP server bootstrap: startup self-check and auth hook."""
from unittest.mock import MagicMock

import pytest

from src.mcp_server import build_app, startup_self_check


def test_startup_self_check_succeeds_when_ping_and_query_pass():
    client = MagicMock()
    client.ping.return_value = True
    client.count.return_value = 0
    startup_self_check(client, alerts_index="wazuh-alerts-*")  # no raise


def test_startup_self_check_fails_on_ping_false():
    client = MagicMock()
    client.ping.return_value = False
    with pytest.raises(RuntimeError, match="ping"):
        startup_self_check(client, alerts_index="wazuh-alerts-*")


def test_build_app_returns_fastmcp_instance():
    app = build_app(service=MagicMock(), api_key="k", rate_limiter=MagicMock())
    # FastMCP apps expose a 'run' method
    assert hasattr(app, "run")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_mcp_server_bootstrap.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write bootstrap**

Create `mcp-server/src/mcp_server.py`:

```python
"""FastMCP app factory + tool definitions.

Tool functions are thin adapters over WazuhDataService. They validate input
(via Pydantic), enforce rate limits, call the service, enforce result caps,
and shape errors into a stable envelope visible to the LLM.
"""
import logging
import uuid
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from src.limits import RateLimitExceeded, RateLimiter, cap_results
from src.time_range import TimeRangeError
from src.wazuh_client import WazuhClientError
from src.wazuh_service import AlertNotFound, WazuhDataService

logger = logging.getLogger(__name__)

SOURCES_DESC = (
    "Current alert sources (field: data.source): "
    "'firewalla-msp' (network alarms/flows), "
    "'windows-srp' (executable allow/block on Windows endpoints), "
    "'threat-intel' (CDB-list matches from rules 100450-100453), "
    "'ossec'/'syscheck' (native Wazuh host and FIM events), "
    "'malicious-ioc' (built-in Wazuh IP/domain/hash feeds, rules 99901-99999)."
)

COMMON_FIELDS_DESC = (
    "Common searchable fields: agent.name, agent.id, agent.ip, "
    "rule.id, rule.level, rule.groups, data.source, data.srcip, data.dstip, "
    "data.srp.target_path, data.srp.user, data.win.eventdata.user."
)


def startup_self_check(client, alerts_index: str) -> None:
    if not client.ping():
        raise RuntimeError("OpenSearch ping failed at startup")
    try:
        client.count(index=alerts_index, body={"query": {"match_all": {}}})
    except Exception as e:
        raise RuntimeError(f"OpenSearch query self-check failed: {e}")
    logger.info("startup self-check ok")


def _error_envelope(code: str, message: str, **extra) -> dict[str, Any]:
    out = {"error": code, "message": message}
    out.update(extra)
    return out


def _key_fingerprint(api_key: str) -> str:
    return api_key[:4] + "…" + api_key[-2:] if len(api_key) >= 6 else "redacted"


def _wrap(tool_name: str, rate_limiter: RateLimiter, api_key: str, fn, kwargs):
    req_id = uuid.uuid4().hex[:8]
    key_fp = _key_fingerprint(api_key)
    try:
        rate_limiter.check(api_key)
    except RateLimitExceeded as e:
        logger.warning("rate_limited tool=%s key=%s", tool_name, key_fp)
        return _error_envelope("rate_limited", str(e), retry_after=e.retry_after)
    try:
        result = fn(**kwargs)
        logger.info(
            "tool_ok",
            extra={"tool": tool_name, "key_fp": key_fp, "req_id": req_id},
        )
        return result
    except TimeRangeError as e:
        return _error_envelope("invalid_input", str(e), field="time_range")
    except ValueError as e:
        return _error_envelope("invalid_input", str(e))
    except AlertNotFound as e:
        return _error_envelope("not_found", str(e))
    except WazuhClientError as e:
        logger.error(
            "client_error",
            extra={"tool": tool_name, "req_id": req_id, "code": e.code, "msg": e.message},
        )
        return _error_envelope(e.code, e.message)
    except Exception as e:  # defense in depth
        logger.exception("internal tool=%s req_id=%s", tool_name, req_id)
        return _error_envelope("internal", "unexpected error", request_id=req_id)


# ---------- Pydantic models (tool input schemas) ----------

class SearchAlertsInput(BaseModel):
    time_range: str = Field(..., description="e.g. 'last_24h', 'last_7d', or ISO range 'A/B'")
    filters: dict[str, Any] | None = Field(default=None)
    lucene: str | None = Field(default=None)
    sort_by: Literal["@timestamp", "rule.level"] = "@timestamp"
    limit: int = Field(default=25, ge=1, le=100)


class AggregateAlertsInput(BaseModel):
    group_by_field: str
    time_range: str
    filters: dict[str, Any] | None = None
    top_n: int = Field(default=10, ge=1, le=50)


class AlertOverviewInput(BaseModel):
    time_range: str


class TrendDeltaInput(BaseModel):
    metric: Literal[
        "total_alerts", "alerts_by_source", "alerts_by_rule_group",
        "alerts_by_agent", "threat_intel_hits",
    ]
    current_window: str
    prior_window: str
    filters: dict[str, Any] | None = None
    top_n: int = Field(default=10, ge=1, le=50)


class ThreatIntelInput(BaseModel):
    time_range: str
    list_filter: Literal[
        "firewalla-c2", "urlhaus", "malware-hashes",
        "malicious-ip", "malicious-domains", "all",
    ] = "all"


class GetAlertInput(BaseModel):
    alert_id: str


class EntityActivityInput(BaseModel):
    entity_type: Literal["ip", "agent", "device", "user", "process", "hash", "domain"]
    entity_value: str
    time_range: str
    top_n: int = Field(default=10, ge=1, le=50)


def build_app(service: WazuhDataService, api_key: str, rate_limiter: RateLimiter) -> FastMCP:
    app = FastMCP("wazuh-mcp")

    @app.tool(
        name="search_alerts",
        description=(
            "Find individual Wazuh alerts matching structured filters or a Lucene "
            "query. Returns up to `limit` records. " + SOURCES_DESC + " " + COMMON_FIELDS_DESC
        ),
    )
    def search_alerts(input: SearchAlertsInput) -> dict[str, Any]:
        def _call():
            raw = service.search_alerts(
                time_range=input.time_range,
                filters=input.filters,
                lucene=input.lucene,
                sort_by=input.sort_by,
                limit=input.limit,
            )
            return cap_results(
                raw["results"], cap=input.limit, total_matched=raw["total_matched"]
            )
        return _wrap("search_alerts", rate_limiter, api_key, _call, {})

    @app.tool(
        name="aggregate_alerts",
        description=(
            "Group-and-count alerts by any field (e.g. rule.groups, agent.name, "
            "data.source). Returns top-N buckets. " + COMMON_FIELDS_DESC
        ),
    )
    def aggregate_alerts(input: AggregateAlertsInput) -> dict[str, Any]:
        return _wrap(
            "aggregate_alerts", rate_limiter, api_key,
            service.aggregate_alerts,
            {"group_by_field": input.group_by_field, "time_range": input.time_range,
             "filters": input.filters, "top_n": input.top_n},
        )

    @app.tool(
        name="alert_overview",
        description=(
            "Pre-canned dashboard in JSON: totals, per-source breakdown, "
            "severity distribution, top rule groups / agents / IPs, threat-intel "
            "hit count. One call answers 'what's going on?'. " + SOURCES_DESC
        ),
    )
    def alert_overview(input: AlertOverviewInput) -> dict[str, Any]:
        return _wrap("alert_overview", rate_limiter, api_key,
                     service.alert_overview, {"time_range": input.time_range})

    @app.tool(
        name="trend_delta",
        description=(
            "Compare a metric between two windows to surface trends "
            "(e.g. 'DNS alerts 3x week-over-week'). Returns current/prior counts "
            "and top-N movers."
        ),
    )
    def trend_delta(input: TrendDeltaInput) -> dict[str, Any]:
        return _wrap("trend_delta", rate_limiter, api_key, service.trend_delta, {
            "metric": input.metric, "current_window": input.current_window,
            "prior_window": input.prior_window, "filters": input.filters,
            "top_n": input.top_n,
        })

    @app.tool(
        name="threat_intel_matches",
        description=(
            "Return recent threat-intel matches (rules 100450-100453 + built-in "
            "malicious-ioc 99901-99999), joined with source agent and IPs."
        ),
    )
    def threat_intel_matches(input: ThreatIntelInput) -> dict[str, Any]:
        return _wrap("threat_intel_matches", rate_limiter, api_key,
                     service.threat_intel_matches, {
                         "time_range": input.time_range,
                         "list_filter": input.list_filter,
                     })

    @app.tool(
        name="sidecar_health",
        description=(
            "Report health of data-collection sidecars (msp-poller, threat-intel, "
            "wazuh-mcp itself). Useful when queries return empty or stale data."
        ),
    )
    def sidecar_health() -> dict[str, Any]:
        return _wrap("sidecar_health", rate_limiter, api_key,
                     service.sidecar_health, {})

    @app.tool(
        name="get_alert",
        description="Fetch full detail of one alert by _id. Returns 'not_found' if missing.",
    )
    def get_alert(input: GetAlertInput) -> dict[str, Any]:
        return _wrap("get_alert", rate_limiter, api_key,
                     service.get_alert, {"alert_id": input.alert_id})

    @app.tool(
        name="entity_activity",
        description=(
            "Multi-source pivot on one entity. entity_type is one of: "
            "ip, agent, device, user, process, hash, domain. Returns total count, "
            "source breakdown, first/last seen, related agents, and 5 recent samples."
        ),
    )
    def entity_activity(input: EntityActivityInput) -> dict[str, Any]:
        return _wrap("entity_activity", rate_limiter, api_key,
                     service.entity_activity, {
                         "entity_type": input.entity_type,
                         "entity_value": input.entity_value,
                         "time_range": input.time_range,
                         "top_n": input.top_n,
                     })

    return app
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_mcp_server_bootstrap.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/mcp_server.py mcp-server/tests/test_mcp_server_bootstrap.py
git commit -m "feat(mcp-server): FastMCP app with 8 tool wrappers + error envelope"
```

---

## Task 16: Entrypoint — main.py that wires it all together

**Files:**
- Create: `mcp-server/src/main.py`

No unit test here — this is pure wiring (covered by integration tests in Task 19).

- [ ] **Step 1: Write `mcp-server/src/main.py`**

```python
"""Entry point: load config, build services, run FastMCP over HTTP/SSE or stdio."""
import argparse
import logging
from pathlib import Path

from src.config import load_settings
from src.limits import RateLimiter
from src.logging_setup import HeartbeatWriter, configure_json_logging
from src.mcp_server import build_app, startup_self_check
from src.wazuh_client import WazuhClient
from src.wazuh_service import WazuhDataService

STATUS_FILE = Path("/var/ossec/logs/sidecar-status/wazuh-mcp.json")
ALERTS_INDEX = "wazuh-alerts-*"

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport", choices=["sse", "stdio"], default="sse",
        help="Transport: 'sse' (HTTP/SSE, production) or 'stdio' (local dev).",
    )
    args = parser.parse_args()

    configure_json_logging("wazuh-mcp")
    settings = load_settings()

    client = WazuhClient(
        url=settings.opensearch_url,
        user=settings.os_user,
        password=settings.os_password,
        timeout=10,
    )
    startup_self_check(client, alerts_index=ALERTS_INDEX)

    status_dir = STATUS_FILE.parent
    service = WazuhDataService(
        client, alerts_index=ALERTS_INDEX, status_dir=status_dir
    )

    heartbeat = HeartbeatWriter(
        component="wazuh-mcp", path=STATUS_FILE, interval=60
    )
    heartbeat.record_ok()  # seed file on startup
    heartbeat.start()

    rate_limiter = RateLimiter(
        per_min=settings.rate_limit_per_min, burst=settings.rate_limit_burst
    )

    app = build_app(service=service, api_key=settings.api_key, rate_limiter=rate_limiter)

    if args.transport == "sse":
        logger.info("starting SSE on 127.0.0.1:%d", settings.http_port)
        app.run(transport="sse", host="127.0.0.1", port=settings.http_port)
    else:
        logger.info("starting stdio transport")
        app.run(transport="stdio")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/src/main.py
git commit -m "feat(mcp-server): main.py entrypoint with --transport flag"
```

---

## Task 17: Dockerfile

**Files:**
- Create: `mcp-server/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

Create `mcp-server/Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# System deps (curl for healthcheck; certs already bundled)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Unbuffered output so docker logs streams in real time.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Default to SSE transport on 8800 (override with args).
EXPOSE 8800
CMD ["python", "-m", "src.main", "--transport", "sse"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -sf -H "Authorization: Bearer ${MCP_API_KEY}" \
        http://127.0.0.1:${MCP_HTTP_PORT:-8800}/sse || exit 1
```

- [ ] **Step 2: Smoke-build locally to verify syntax**

```bash
cd /path/to/firewalla-wazuh/mcp-server
docker build -t wazuh-mcp:local .
```

Expected: image builds successfully.

- [ ] **Step 3: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/Dockerfile
git commit -m "feat(mcp-server): Dockerfile (python 3.12-slim, SSE default)"
```

---

## Task 18: OpenSearch read-only user provisioning script

**Files:**
- Create: `mcp-server/scripts/create_mcp_user.sh`

- [ ] **Step 1: Write the script**

Create `mcp-server/scripts/create_mcp_user.sh`:

```bash
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
            "index_patterns": ["wazuh-alerts-*", "wazuh-monitoring-*"],
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
```

- [ ] **Step 2: Make executable and smoke-test the bash syntax**

```bash
cd /path/to/firewalla-wazuh
chmod +x mcp-server/scripts/create_mcp_user.sh
bash -n mcp-server/scripts/create_mcp_user.sh
```

Expected: no output (syntax OK).

- [ ] **Step 3: Commit**

```bash
git add mcp-server/scripts/create_mcp_user.sh
git commit -m "feat(mcp-server): idempotent OpenSearch read-only user provisioner"
```

---

## Task 19: Integration test harness + one test per tool

**Files:**
- Create: `mcp-server/tests/docker-compose.test.yml`
- Create: `mcp-server/tests/seed_alerts.py`
- Create: `mcp-server/tests/test_service_integration.py`

These hit a real OpenSearch container. Marked `@pytest.mark.integration` — skipped by default; run with `pytest -m integration`.

- [ ] **Step 1: Write the ephemeral compose file**

Create `mcp-server/tests/docker-compose.test.yml`:

```yaml
services:
  opensearch-test:
    image: opensearchproject/opensearch:2.14.0
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
      - bootstrap.memory_lock=true
      - OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m
    ulimits:
      memlock: {soft: -1, hard: -1}
    ports:
      - "19200:9200"
```

- [ ] **Step 2: Write the seed data generator**

Create `mcp-server/tests/seed_alerts.py`:

```python
"""Seed ~500 synthetic Wazuh-shaped alerts into OpenSearch for integration tests."""
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Iterator

from opensearchpy import OpenSearch, helpers


SOURCES = ["firewalla-msp", "windows-srp", "threat-intel", "ossec", "syscheck"]
AGENTS = ["kids-laptop", "office-pc", "nas-1", "router", "iot-cam-1"]
RULE_IDS_BY_SOURCE = {
    "firewalla-msp": ["100200", "100210", "100450", "100451"],
    "windows-srp": ["100651", "100652", "100660"],
    "threat-intel": ["100452", "100453", "99905", "99912"],
    "ossec": ["5712", "5715"],
    "syscheck": ["550", "553"],
}


def _gen(n: int = 500) -> Iterator[dict]:
    rnd = random.Random(42)
    now = datetime.now(timezone.utc)
    for i in range(n):
        src = rnd.choice(SOURCES)
        rule_id = rnd.choice(RULE_IDS_BY_SOURCE[src])
        agent = rnd.choice(AGENTS)
        ts = now - timedelta(seconds=rnd.randint(0, 7 * 24 * 3600))
        doc = {
            "@timestamp": ts.isoformat().replace("+00:00", "Z"),
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "agent": {"id": f"{AGENTS.index(agent):03d}", "name": agent},
            "rule": {
                "id": rule_id,
                "level": rnd.choice([3, 3, 3, 7, 7, 10, 12]),
                "description": f"test rule {rule_id}",
                "groups": ["test", src],
            },
            "data": {
                "source": src,
                "srcip": f"10.0.0.{rnd.randint(1, 50)}",
                "dstip": f"203.0.113.{rnd.randint(1, 50)}",
            },
        }
        if src == "windows-srp":
            doc["data"]["srp"] = {
                "action": rnd.choice(["ALLOWED", "BLOCKED"]),
                "target_path": f"C:\\apps\\app{rnd.randint(1,5)}.exe",
                "user": rnd.choice(["alice", "bob"]),
            }
        if src == "threat-intel":
            doc["data"]["threat_intel"] = {
                "list": rnd.choice(["firewalla-c2", "urlhaus"]),
                "ioc": doc["data"]["dstip"],
            }
        yield {"_index": f"wazuh-alerts-4.x-{ts.strftime('%Y.%m.%d')}", "_source": doc}


def seed(os_url: str = "http://localhost:19200", count: int = 500) -> None:
    os_ = OpenSearch(hosts=[os_url])
    os_.indices.delete(index="wazuh-alerts-*", ignore=[400, 404])
    helpers.bulk(os_, _gen(count), refresh=True)
    print(f"seeded {count} alerts into {os_url}")


if __name__ == "__main__":
    import sys

    seed(count=int(sys.argv[1]) if len(sys.argv) > 1 else 500)
```

- [ ] **Step 3: Write the integration tests**

Create `mcp-server/tests/test_service_integration.py`:

```python
"""Integration tests — one per tool — against a real OpenSearch."""
import os
import time

import pytest

from src.wazuh_client import WazuhClient
from src.wazuh_service import WazuhDataService
from tests.seed_alerts import seed


OS_URL = os.environ.get("TEST_OS_URL", "http://localhost:19200")


@pytest.fixture(scope="module")
def service():
    # wait for opensearch to be up
    for _ in range(30):
        try:
            import requests
            if requests.get(OS_URL).status_code == 200:
                break
        except Exception:
            time.sleep(1)
    seed(OS_URL, 500)
    client = WazuhClient(url=OS_URL, user="", password="", timeout=10)
    # override: when security is disabled, http_auth is ignored
    return WazuhDataService(client, alerts_index="wazuh-alerts-*")


@pytest.mark.integration
def test_search_alerts_end_to_end(service):
    out = service.search_alerts(
        filters={"data.source": "windows-srp"}, time_range="last_7d", limit=10
    )
    assert out["total_matched"] > 0
    for row in out["results"]:
        assert row["data"].get("source") == "windows-srp"


@pytest.mark.integration
def test_aggregate_alerts_end_to_end(service):
    out = service.aggregate_alerts(
        group_by_field="data.source", time_range="last_7d", top_n=10
    )
    keys = {b["key"] for b in out["buckets"]}
    assert {"firewalla-msp", "windows-srp", "threat-intel"}.issubset(keys)


@pytest.mark.integration
def test_alert_overview_end_to_end(service):
    out = service.alert_overview(time_range="last_7d")
    assert out["total_alerts"] == 500
    assert sum(out["by_source"].values()) == 500


@pytest.mark.integration
def test_trend_delta_end_to_end(service):
    out = service.trend_delta(
        metric="alerts_by_agent",
        current_window="last_24h",
        prior_window="last_7d",
    )
    assert "movers" in out
    assert all("delta_pct" in m for m in out["movers"])


@pytest.mark.integration
def test_threat_intel_matches_end_to_end(service):
    out = service.threat_intel_matches(time_range="last_7d")
    assert out["total"] > 0
    for m in out["matches"]:
        assert m["list"] in ("firewalla-c2", "urlhaus") or m["rule_id"] in ("99905", "99912")


@pytest.mark.integration
def test_get_alert_end_to_end(service):
    some = service.search_alerts(
        filters={"data.source": "ossec"}, time_range="last_7d", limit=1
    )
    alert_id = some["results"][0]["id"]
    detail = service.get_alert(alert_id)
    assert detail["_id"] == alert_id


@pytest.mark.integration
def test_entity_activity_end_to_end(service):
    out = service.entity_activity(
        entity_type="ip", entity_value="10.0.0.10", time_range="last_7d"
    )
    assert "entity" in out
    assert out["entity"]["type"] == "ip"
```

- [ ] **Step 4: Run integration tests locally**

```bash
cd /path/to/firewalla-wazuh/mcp-server
docker compose -f tests/docker-compose.test.yml up -d
sleep 15  # wait for opensearch
python -m pytest tests/test_service_integration.py -v -m integration
docker compose -f tests/docker-compose.test.yml down -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/tests/docker-compose.test.yml mcp-server/tests/seed_alerts.py mcp-server/tests/test_service_integration.py
git commit -m "test(mcp-server): integration tests against real OpenSearch"
```

---

## Task 20: docker-compose integration

**Files:**
- Modify: `docker-compose.yml` (both in `/opt/wazuh-docker/single-node/` and `/path/to/firewalla-wazuh/`)
- Modify: `.env.example`
- Modify: `/opt/wazuh-docker/single-node/.env` (local only — don't commit)

- [ ] **Step 1: Add new vars to `.env.example` in the repo**

Append to `/path/to/firewalla-wazuh/.env.example`:

```bash

# ---- Wazuh MCP Server ----
MCP_OS_USER=mcp_read
MCP_OS_PASSWORD=change-me
MCP_API_KEY=change-me-to-a-long-random-string
MCP_HTTP_PORT=8800
```

- [ ] **Step 2: Add the sidecar service to both docker-compose files**

Add this service block under `services:` in both files (git repo copy and deployment copy), placed after `threat-intel`:

```yaml
  wazuh-mcp:
    build: ./mcp-server
    container_name: single-node-wazuh-mcp
    hostname: wazuh-mcp
    restart: unless-stopped
    environment:
      - MCP_OS_USER=${MCP_OS_USER}
      - MCP_OS_PASSWORD=${MCP_OS_PASSWORD}
      - MCP_API_KEY=${MCP_API_KEY}
      - MCP_HTTP_PORT=${MCP_HTTP_PORT:-8800}
      - OPENSEARCH_URL=https://wazuh.indexer:9200
      - MAX_LOG_SIZE=${MAX_LOG_SIZE:-10485760}
      - MAX_LOG_BACKUPS=${MAX_LOG_BACKUPS:-2}
      - RATE_LIMIT_PER_MIN=${RATE_LIMIT_PER_MIN:-60}
      - RATE_LIMIT_BURST=${RATE_LIMIT_BURST:-10}
    ports:
      - "127.0.0.1:${MCP_HTTP_PORT:-8800}:${MCP_HTTP_PORT:-8800}"
    volumes:
      - sidecar_status:/var/ossec/logs/sidecar-status
    depends_on:
      wazuh.indexer:
        condition: service_started
      wazuh.manager:
        condition: service_healthy
```

The service does NOT need the `msp_logs` volume — it reads OpenSearch, not files.

- [ ] **Step 3: Commit (repo copy only)**

```bash
cd /path/to/firewalla-wazuh
git add docker-compose.yml .env.example
git commit -m "feat: add wazuh-mcp sidecar to compose stack"
```

---

## Task 21: Smoke-test document

**Files:**
- Create: `mcp-server/docs/smoke-test.md`

- [ ] **Step 1: Write the smoke-test doc**

Create `mcp-server/docs/smoke-test.md`:

```markdown
# wazuh-mcp Smoke Test

Run these 8 questions in Claude Code after adding the wazuh-mcp MCP server
to its config. Each question should trigger the named tool and produce a
response matching the expected shape (not exact numbers — those vary).

**Pre-req:** Add to Claude Code's MCP config (e.g., `~/.claude.json` under `mcpServers`):

\`\`\`json
{
  "wazuh": {
    "transport": "sse",
    "url": "http://localhost:8800/sse",
    "headers": {"Authorization": "Bearer <MCP_API_KEY>"}
  }
}
\`\`\`

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
```

- [ ] **Step 2: Commit**

```bash
cd /path/to/firewalla-wazuh
git add mcp-server/docs/smoke-test.md
git commit -m "docs(mcp-server): 8-question smoke test for post-deploy verification"
```

---

## Task 22: First-time deployment + verification

This is the one task where we touch `/opt/wazuh-docker/single-node/`. Not a TDD task — just ordered ops.

- [ ] **Step 1: Copy the `mcp-server/` tree from the repo to the deployment**

```bash
rsync -av --delete \
    /path/to/firewalla-wazuh/mcp-server/ \
    /opt/wazuh-docker/single-node/mcp-server/
```

Verify:

```bash
ls /opt/wazuh-docker/single-node/mcp-server/
# expect: Dockerfile  README.md  docs  requirements-dev.txt  requirements.txt  scripts  src  tests
```

- [ ] **Step 2: Apply the docker-compose edit to the deployment copy**

Open `/opt/wazuh-docker/single-node/docker-compose.yml` and insert the `wazuh-mcp` service block from Task 20 Step 2 after `threat-intel`.

Verify:

```bash
grep -A 2 "wazuh-mcp:" /opt/wazuh-docker/single-node/docker-compose.yml
```

- [ ] **Step 3: Add MCP vars to `/opt/wazuh-docker/single-node/.env`**

Append (values: choose a strong random `MCP_API_KEY`, pick a secure `MCP_OS_PASSWORD`):

```bash

# ---- Wazuh MCP Server ----
MCP_OS_USER=mcp_read
MCP_OS_PASSWORD=<CHOOSE-A-PASSWORD>
MCP_API_KEY=<GENERATE: openssl rand -hex 32>
MCP_HTTP_PORT=8800
```

- [ ] **Step 4: Provision the read-only OpenSearch user**

From `/opt/wazuh-docker/single-node/`:

```bash
set -a; . ./.env; set +a
INDEXER_PASSWORD="$INDEXER_PASSWORD" \
MCP_OS_USER="$MCP_OS_USER" \
MCP_OS_PASSWORD="$MCP_OS_PASSWORD" \
./mcp-server/scripts/create_mcp_user.sh
```

Expected output: three `HTTP 200` or `HTTP 201` lines.

Verify:

```bash
curl -sk -u "${MCP_OS_USER}:${MCP_OS_PASSWORD}" \
    https://localhost:9200/wazuh-alerts-*/_count
# expect: {"count": <some number>, ...}
```

- [ ] **Step 5: Build and start the sidecar**

```bash
cd /opt/wazuh-docker/single-node/
docker compose build wazuh-mcp
docker compose up -d wazuh-mcp
```

Verify:

```bash
docker compose ps wazuh-mcp        # State: Up (healthy)
docker logs single-node-wazuh-mcp --tail 20
# expect: JSON log line "starting SSE on 127.0.0.1:8800"
```

- [ ] **Step 6: Probe HTTP endpoint**

```bash
curl -sf -H "Authorization: Bearer $MCP_API_KEY" \
    http://127.0.0.1:8800/sse | head -5
```

Expected: SSE stream (headers + events starting to flow).

- [ ] **Step 7: Configure Claude Code to use the server**

Edit `~/.claude.json` (or wherever MCP config lives in your Claude Code install). Add under `mcpServers`:

```json
"wazuh": {
  "transport": "sse",
  "url": "http://localhost:8800/sse",
  "headers": {"Authorization": "Bearer <your MCP_API_KEY>"}
}
```

Restart Claude Code so it picks up the new server.

- [ ] **Step 8: Run the smoke test**

Open Claude Code and ask each of the 8 questions from `mcp-server/docs/smoke-test.md`. Tick them off. Document any failures.

- [ ] **Step 9: Confirm heartbeat is flowing**

```bash
docker exec single-node-wazuh.manager-1 cat /var/ossec/logs/sidecar-status/wazuh-mcp.json
```

Expected: `{"component": "wazuh-mcp", "status": "ok", ...}`

In the Wazuh dashboard → Sidecar Monitoring, `wazuh-mcp` should appear.

- [ ] **Step 10: Commit the deployment-side nothing (the repo already reflects it)**

If the smoke test revealed fixes, apply them in the repo, sync to `/opt/`, and restart:

```bash
rsync -av /path/to/firewalla-wazuh/mcp-server/ /opt/wazuh-docker/single-node/mcp-server/
cd /opt/wazuh-docker/single-node/ && docker compose up -d --build wazuh-mcp
```

- [ ] **Step 11: Push to private remote**

```bash
cd /path/to/firewalla-wazuh
git log --oneline -10   # sanity
git push origin main
```

---

## Self-Review Checklist (done by plan author)

**Spec coverage:**

- [x] Architecture (sidecar, stateless, bearer-token auth, read-only user): Tasks 17, 18, 20, 22.
- [x] Components (config, client, service, mcp_server, limits, logging_setup): Tasks 2-5, 15, 16.
- [x] Data flow (request path with auth → rate limit → Pydantic → service → cap): covered by the `_wrap` helper in Task 15.
- [x] All 8 tools with input/output shapes: Tasks 7-14 (service) + Task 15 (MCP wrappers).
- [x] Error envelope (opensearch_unavailable, invalid_query, timeout, rate_limited, invalid_input, not_found, internal): Task 3 (client errors), Task 15 (`_wrap`).
- [x] Hard limits (100 results/call, 50 buckets, 10s timeout, 60/min rate limit, 90-day span): Tasks 3, 4, 6, 7, 8.
- [x] Observability (per-call JSON log, heartbeat, startup self-check): Tasks 5, 15, 16.
- [x] Testing layers (unit, integration, manual smoke): Tasks 2-15 (unit), 19 (integration), 21 (smoke).
- [x] Operational (secrets, git workflow, log rotation, user provisioning): Tasks 1, 18, 22.

**Placeholder scan:** clean — every step has runnable code or commands.

**Type/name consistency:**
- `WazuhClient.search` / `.count` / `.ping` — consistent Task 3 → 15 → 19.
- `WazuhDataService` method names match between service tasks (7-14), wrapper task (15), and integration tests (19).
- Field `data.source` used consistently in alert_overview, trend_delta metric `alerts_by_source`, entity_activity breakdown.
- `HeartbeatWriter` API (`record_ok`, `record_error`, `start`, `_flush`) consistent between Task 5 and Task 16.

Plan is internally consistent.

---

## Execution Handoff

**Plan complete and saved to `docs/plans/2026-04-24-wazuh-mcp-server-implementation.md`. Two execution options:**

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

2. **Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

**Which approach?**
