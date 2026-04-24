"""Tests for WazuhDataService.sidecar_health — reads JSONL stream."""
import json
from pathlib import Path
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def _append(path: Path, event: dict) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(event) + "\n")


def _heartbeat(sidecar: str, ts: str, error_count: int = 0, last_error=None) -> dict:
    return {
        "timestamp": ts,
        "event_type": "sidecar_status",
        "source": "sidecar-status",
        "sidecar": sidecar,
        "job_type": "heartbeat",
        "sync_status": "running",
        "stats": {
            "uptime_sec": 3600,
            "ok_count_total": 42,
            "error_count_10m": error_count,
            "last_error": last_error,
        },
    }


def _error(sidecar: str, ts: str, message: str) -> dict:
    return {
        "timestamp": ts,
        "event_type": "sidecar_status",
        "source": "sidecar-status",
        "sidecar": sidecar,
        "job_type": "tool_call",
        "sync_status": "error",
        "error_message": message,
    }


def test_sidecar_health_reports_latest_per_sidecar(tmp_path: Path, monkeypatch):
    # Freeze "now" at 2026-04-24T10:05:00Z — same moment as the latest events.
    monkeypatch.setattr("src.wazuh_service.time.time", lambda: 1777025100.0)
    stream = tmp_path / "sidecar-status.json"
    _append(stream, _heartbeat("msp-poller",  "2026-04-24T10:03:00"))
    _append(stream, _heartbeat("threat-intel", "2026-04-24T10:04:00"))
    _append(stream, _error("wazuh-mcp", "2026-04-24T10:04:30", "opensearch_unavailable"))
    _append(stream, _heartbeat("wazuh-mcp", "2026-04-24T10:05:00", error_count=3, last_error="opensearch_unavailable"))

    svc = WazuhDataService(MagicMock(), status_file=stream)
    out = svc.sidecar_health()

    names = {s["name"]: s for s in out["sidecars"]}
    assert set(names) == {"msp-poller", "threat-intel", "wazuh-mcp"}
    assert names["wazuh-mcp"]["error_count_10m"] == 3
    assert names["wazuh-mcp"]["last_error"] == "opensearch_unavailable"
    # latest event for wazuh-mcp is the heartbeat (running), not the error.
    assert names["wazuh-mcp"]["status"] == "running"
    assert out["summary"]["count_ok"] == 3
    assert out["summary"]["any_errors"] is False  # no sidecar is 'error' or 'stale' currently


def test_sidecar_health_flags_stale_heartbeat(tmp_path: Path, monkeypatch):
    # Freeze "now" to +10 min past the only heartbeat.
    monkeypatch.setattr("src.wazuh_service.time.time", lambda: 1777025400.0)  # 2026-04-24T10:10:00Z
    stream = tmp_path / "sidecar-status.json"
    _append(stream, _heartbeat("msp-poller", "2026-04-24T10:00:00"))

    svc = WazuhDataService(MagicMock(), status_file=stream)
    out = svc.sidecar_health()
    assert out["sidecars"][0]["status"] == "stale"
    assert out["summary"]["any_errors"] is True


def test_sidecar_health_missing_file_returns_empty(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("src.wazuh_service.time.time", lambda: 1777629900.0)
    svc = WazuhDataService(MagicMock(), status_file=tmp_path / "nope.json")
    out = svc.sidecar_health()
    assert out["sidecars"] == []
    assert out["summary"]["count_ok"] == 0


def test_sidecar_health_skips_malformed_lines(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("src.wazuh_service.time.time", lambda: 1777629900.0)
    stream = tmp_path / "sidecar-status.json"
    stream.write_text(
        "not-json\n"
        + json.dumps(_heartbeat("msp-poller", "2026-04-24T10:03:00")) + "\n"
        + "{broken\n"
    )
    svc = WazuhDataService(MagicMock(), status_file=stream)
    out = svc.sidecar_health()
    assert len(out["sidecars"]) == 1
    assert out["sidecars"][0]["name"] == "msp-poller"
