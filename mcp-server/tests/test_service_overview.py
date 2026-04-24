"""Tests for WazuhDataService.alert_overview."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def test_alert_overview_runs_single_multi_agg_query():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 12847}},
        "aggregations": {
            "by_source": {"buckets": [
                {"key": "firewalla-msp", "doc_count": 9201},
                {"key": "windows-srp", "doc_count": 2103},
            ]},
            "by_severity": {"buckets": [
                {"key": "low", "from": 0, "to": 4, "doc_count": 8120},
                {"key": "medium", "from": 4, "to": 8, "doc_count": 4703},
                {"key": "high", "from": 8, "to": 16, "doc_count": 24},
            ]},
            "top_rule_groups": {"buckets": [{"key": "dns", "doc_count": 2341}]},
            "top_agents": {"buckets": [{"key": "kids-laptop", "doc_count": 1903}]},
            "top_src_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 500}]},
            "top_dst_ips": {"buckets": [{"key": "203.0.113.10", "doc_count": 800}]},
            "threat_intel_hits": {"doc_count": 12},
        },
    }
    svc = WazuhDataService(client)
    out = svc.alert_overview(time_range="last_7d")

    # Only one OpenSearch call (single multi-agg query).
    assert client.search.call_count == 1
    assert out["total_alerts"] == 12847
    assert out["by_source"] == {"firewalla-msp": 9201, "windows-srp": 2103}
    assert out["by_severity"]["low (0-3)"] == 8120
    assert out["by_severity"]["medium (4-7)"] == 4703
    assert out["by_severity"]["high (8-12)"] == 24
    assert out["top_rule_groups"][0] == {"key": "dns", "count": 2341}
    assert out["threat_intel_hits"] == 12
    assert out["time_range"] == "last_7d"
