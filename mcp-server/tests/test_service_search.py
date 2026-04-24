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
