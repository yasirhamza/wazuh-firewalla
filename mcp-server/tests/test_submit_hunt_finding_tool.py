"""End-to-end test of the submit_hunt_finding MCP tool wrapper."""
import json
from pathlib import Path
from unittest.mock import MagicMock

from src.logging_setup import HeartbeatWriter
from src.mcp_server import build_app


def test_submit_hunt_finding_tool_writes_event(tmp_path: Path) -> None:
    status_path = tmp_path / "sidecar-status.json"
    hunt_writer = HeartbeatWriter(sidecar="hunt-runner", path=status_path)

    service = MagicMock()
    rate_limiter = MagicMock()
    app = build_app(service=service, rate_limiter=rate_limiter, hunt_writer=hunt_writer)

    # FastMCP exposes registered tools via app._tool_manager._tools (private but
    # stable enough for tests; alternatively, call through MCP transport).
    tool = app._tool_manager._tools.get("submit_hunt_finding")
    assert tool is not None, "submit_hunt_finding tool not registered"

    finding = {
        "hypothesis_id": "H-2026-001",
        "run_id": "H-2026-001-T",
        "finding_id": "F-2026-001-a",
        "attack_technique": "T1071.001",
        "attack_tactic": "command-and-control",
        "confidence": "medium",
        "analyst": "alice",
        "summary": "test",
        "recommendation": "test",
        "evidence": {"agent_name": "host-1"},
    }
    result = tool.fn(finding=finding)
    assert result["status"] == "submitted"
    assert result["finding_id"] == "F-2026-001-a"

    events = [json.loads(line) for line in status_path.read_text().splitlines() if line]
    assert len(events) == 1
    assert events[0]["job_type"] == "hunt_finding"
    assert events[0]["sidecar"] == "hunt-runner"
