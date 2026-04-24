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
