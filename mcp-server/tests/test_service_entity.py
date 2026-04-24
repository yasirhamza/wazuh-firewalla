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
