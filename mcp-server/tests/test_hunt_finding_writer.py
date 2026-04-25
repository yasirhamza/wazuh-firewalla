"""Tests for HeartbeatWriter.record_hunt_finding."""
import json
from pathlib import Path

from src.logging_setup import HeartbeatWriter


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_record_hunt_finding_writes_jsonl(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    hb.record_hunt_finding({
        "hypothesis_id": "H-2026-001",
        "run_id": "H-2026-001-20260425T2200Z",
        "finding_id": "F-2026-001-a",
        "attack_technique": "T1071.001",
        "attack_tactic": "command-and-control",
        "confidence": "medium",
        "analyst": "alice",
        "summary": "test summary",
        "recommendation": "test rec",
        "evidence": {"agent_name": "host-1", "flow_count": 47},
    })

    events = _read_lines(status)
    assert len(events) == 1
    e = events[0]
    assert e["event_type"] == "sidecar_status"
    assert e["job_type"] == "hunt_finding"
    assert e["sync_status"] == "reported"
    assert e["sidecar"] == "hunt-runner"
    assert e["hunt"]["hypothesis_id"] == "H-2026-001"
    assert e["hunt"]["confidence"] == "medium"
    assert e["hunt"]["attack_technique"] == "T1071.001"
    assert "timestamp" in e


def test_record_hunt_finding_rejects_invalid_confidence(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    import pytest
    with pytest.raises(ValueError, match="confidence"):
        hb.record_hunt_finding({
            "hypothesis_id": "H-2026-001",
            "run_id": "X", "finding_id": "Y",
            "attack_technique": "T1071", "attack_tactic": "c2",
            "confidence": "wandering",   # invalid
            "analyst": "a", "summary": "s", "recommendation": "r",
            "evidence": {},
        })


def test_record_hunt_finding_rejects_missing_required_fields(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    import pytest
    with pytest.raises(ValueError, match="hypothesis_id"):
        hb.record_hunt_finding({
            # hypothesis_id missing
            "run_id": "X", "finding_id": "Y",
            "attack_technique": "T1071", "attack_tactic": "c2",
            "confidence": "low",
            "analyst": "a", "summary": "s", "recommendation": "r",
            "evidence": {},
        })
