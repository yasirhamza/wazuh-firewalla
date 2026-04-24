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


def test_threat_intel_matches_enumerates_custom_and_ioc_rule_ids():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 2}, "hits": [_hit("100450"), _hit("99901")]}
    }
    svc = WazuhDataService(client)
    out = svc.threat_intel_matches(time_range="last_24h")
    body = client.search.call_args.kwargs["body"]
    # Last filter clause is a terms query over both custom (100450-100453) and
    # built-in malicious-ioc (99901-99999) rule IDs. Keyword ranges are
    # deliberately avoided — see _TI_ALL_RULE_IDS in wazuh_service.
    rule_ids = body["query"]["bool"]["filter"][-1]["terms"]["rule.id"]
    assert {"100450", "100451", "100452", "100453"}.issubset(set(rule_ids))
    assert {"99901", "99950", "99999"}.issubset(set(rule_ids))
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
