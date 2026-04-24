"""Tests for structured logging + shared JSONL heartbeat writer."""
import json
from pathlib import Path

import pytest

from src.logging_setup import HeartbeatWriter, configure_json_logging


def _read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_configure_json_logging_emits_json(capsys):
    configure_json_logging()
    import logging

    logging.getLogger("x").info("hello", extra={"tool": "foo"})
    out = capsys.readouterr().out.strip().splitlines()
    last = json.loads(out[-1])
    assert last["msg"] == "hello"
    assert last["tool"] == "foo"
    assert last["level"] == "INFO"


def test_heartbeat_writer_appends_heartbeat_event(tmp_path: Path):
    target = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="wazuh-mcp", path=target, interval=60)
    hb._emit_heartbeat()
    events = _read_events(target)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "sidecar_status"
    assert ev["source"] == "sidecar-status"
    assert ev["sidecar"] == "wazuh-mcp"
    assert ev["job_type"] == "heartbeat"
    assert ev["sync_status"] == "running"


def test_heartbeat_writer_appends_error_event_immediately(tmp_path: Path):
    target = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="wazuh-mcp", path=target, interval=60)
    hb.record_error("opensearch_unavailable: timeout", job_type="tool_call")
    events = _read_events(target)
    assert len(events) == 1
    ev = events[0]
    assert ev["sync_status"] == "error"
    assert ev["error_message"] == "opensearch_unavailable: timeout"
    assert ev["job_type"] == "tool_call"
    assert ev["sidecar"] == "wazuh-mcp"


def test_heartbeat_writer_tracks_error_count_in_heartbeat_stats(tmp_path: Path, monkeypatch):
    target = tmp_path / "sidecar-status.json"
    now = [1000.0]
    monkeypatch.setattr("src.logging_setup.time.time", lambda: now[0])
    hb = HeartbeatWriter(sidecar="wazuh-mcp", path=target, interval=60)
    hb.record_error("e1", job_type="tool_call")
    now[0] += 700  # >10 min elapsed — old error should roll off
    hb.record_error("e2", job_type="tool_call")
    hb._emit_heartbeat()
    events = _read_events(target)
    heartbeats = [e for e in events if e["job_type"] == "heartbeat"]
    assert len(heartbeats) == 1
    assert heartbeats[0]["stats"]["error_count_10m"] == 1  # e1 rolled off


def test_heartbeat_writer_rotates_at_max_size(tmp_path: Path):
    target = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(
        sidecar="wazuh-mcp", path=target, interval=60,
        max_size=200, max_backups=1,
    )
    for i in range(50):
        hb.record_error(f"msg-{i}", job_type="tool_call")
    assert (tmp_path / "sidecar-status.json.1").exists()
    assert target.exists()
    # current file must be smaller than rotation threshold after last rotate
    assert target.stat().st_size <= 400  # some slack for the final write


def test_heartbeat_writer_record_ok_does_not_write_event(tmp_path: Path):
    """record_ok() tracks in memory; only heartbeats and errors write events."""
    target = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="wazuh-mcp", path=target, interval=60)
    hb.record_ok(job_type="tool_call")
    hb.record_ok(job_type="tool_call")
    assert not target.exists()
