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


def test_threat_intel_matches_derives_list_from_rule_id_when_missing():
    """When data.threat_intel.list is absent, fall back to the rule-id map."""
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 3}, "hits": [
            # rule 100452 → urlhaus
            {"_id": "a1", "_source": {"rule": {"id": "100452"},
                                       "data": {"srcip": "10.0.0.1", "dstip": "198.51.100.10"}}},
            # rule 99950 → malicious-ioc (built-in bucket)
            {"_id": "a2", "_source": {"rule": {"id": "99950"},
                                       "data": {"srcip": "10.0.0.2", "dstip": "203.0.113.10"}}},
            # decoder-supplied list wins over the fallback map
            {"_id": "a3", "_source": {"rule": {"id": "100452"},
                                       "data": {"srcip": "10.0.0.3", "dstip": "203.0.113.20",
                                                "threat_intel": {"list": "custom-feed", "ioc": "attacker.tld"}}}},
        ]}
    }
    svc = WazuhDataService(client)
    out = svc.threat_intel_matches(time_range="last_24h")
    by_id = {m["id"]: m for m in out["matches"]}
    assert by_id["a1"]["list"] == "urlhaus"
    assert by_id["a1"]["ioc"] == "198.51.100.10"   # fallback to dst_ip
    assert by_id["a2"]["list"] == "malicious-ioc"
    assert by_id["a3"]["list"] == "custom-feed"    # decoder-supplied wins
    assert by_id["a3"]["ioc"] == "attacker.tld"
