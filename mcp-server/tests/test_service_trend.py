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
