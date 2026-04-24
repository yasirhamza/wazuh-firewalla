"""Tests for MCP server bootstrap: startup self-check, tool wiring, error envelope."""
from unittest.mock import MagicMock

import pytest

from src.limits import RateLimitExceeded, RateLimiter
from src.mcp_server import (
    build_app, startup_self_check, _wrap_call, _classify_client_error,
)
from src.time_range import TimeRangeError
from src.wazuh_client import WazuhClientError
from src.wazuh_service import AlertNotFound


def test_startup_self_check_succeeds_when_count_works():
    client = MagicMock()
    client.count.return_value = 0
    startup_self_check(client, alerts_index="wazuh-alerts-*")  # no raise


def test_startup_self_check_fails_when_count_raises():
    client = MagicMock()
    client.count.side_effect = RuntimeError("network down")
    with pytest.raises(RuntimeError, match="self-check failed"):
        startup_self_check(client, alerts_index="wazuh-alerts-*")


def test_build_app_returns_fastmcp_instance_with_eight_tools():
    app = build_app(service=MagicMock(), rate_limiter=MagicMock())
    assert hasattr(app, "run")  # FastMCP app
    # Retrieve the registered tool names.
    names = {t.name for t in app._tool_manager.list_tools()}  # internal API but stable in mcp>=1.2
    expected = {
        "search_alerts", "aggregate_alerts", "alert_overview", "trend_delta",
        "threat_intel_matches", "sidecar_health", "get_alert", "entity_activity",
    }
    assert expected.issubset(names)


def test_wrap_returns_rate_limited_envelope():
    rl = MagicMock()
    rl.check.side_effect = RateLimitExceeded(retry_after=5)
    result = _wrap_call("t", rl, lambda: "ok")
    assert result["error"] == "rate_limited"
    assert result["retry_after"] == 5


def test_wrap_returns_timeout_envelope():
    rl = MagicMock()
    def boom():
        raise WazuhClientError(code="timeout", message="too slow")
    result = _wrap_call("t", rl, boom)
    assert result["error"] == "timeout"
    assert "time_range_hint" in result


def test_wrap_returns_invalid_query_envelope_for_transport_parser_errors():
    rl = MagicMock()
    def boom():
        raise WazuhClientError(code="opensearch_unavailable",
                                message="parse_exception: unknown field [bogus]")
    result = _wrap_call("t", rl, boom)
    # Opensearch parser errors are reclassified as invalid_query with a hint.
    assert result["error"] == "invalid_query"
    assert "hint" in result


def test_wrap_returns_not_found_for_alert_not_found():
    rl = MagicMock()
    def boom():
        raise AlertNotFound("abc")
    assert _wrap_call("t", rl, boom)["error"] == "not_found"


def test_wrap_returns_invalid_input_for_time_range_error():
    rl = MagicMock()
    def boom():
        raise TimeRangeError("bad span")
    out = _wrap_call("t", rl, boom)
    assert out["error"] == "invalid_input"
    assert out["field"] == "time_range"


def test_wrap_returns_internal_with_request_id_for_unexpected_exception():
    rl = MagicMock()
    def boom():
        raise RuntimeError("???")
    out = _wrap_call("t", rl, boom)
    assert out["error"] == "internal"
    assert "request_id" in out


def test_classify_client_error_detects_parser_patterns():
    e = WazuhClientError(code="opensearch_unavailable",
                         message="parse_exception: unknown field")
    assert _classify_client_error(e) == "invalid_query"

    e2 = WazuhClientError(code="opensearch_unavailable",
                          message="ConnectionError: no route")
    assert _classify_client_error(e2) == "opensearch_unavailable"
