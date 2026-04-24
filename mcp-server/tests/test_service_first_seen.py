"""Tests for WazuhDataService.first_seen_domains."""
from unittest.mock import MagicMock

import pytest

from src.wazuh_service import WazuhDataService


def _resp(domains: list[str]) -> dict:
    return {
        "hits": {"total": {"value": len(domains)}},
        "aggregations": {"domains": {"buckets": [
            {"key": d, "doc_count": 1} for d in domains
        ]}},
    }


def test_first_seen_domains_returns_set_difference():
    client = MagicMock()
    # First search = recent window; second = baseline window.
    client.search.side_effect = [
        _resp(["a.com", "b.com", "new1.com", "new2.com"]),
        _resp(["a.com", "b.com", "c.com"]),
    ]
    svc = WazuhDataService(client)
    out = svc.first_seen_domains(device_name="the-ipad", recent_window="last_7d")

    assert out["device"] == "the-ipad"
    assert out["recent_unique_domains"] == 4
    assert out["baseline_unique_domains"] == 3
    assert out["new_domain_count"] == 2
    assert sorted(out["new_domains"]) == ["new1.com", "new2.com"]
    assert out["truncated"] is False


def test_first_seen_domains_derives_baseline_from_recent_window():
    client = MagicMock()
    client.search.side_effect = [_resp([]), _resp([])]
    svc = WazuhDataService(client)
    svc.first_seen_domains(
        device_name="d", recent_window="last_7d", baseline_days=90
    )
    # Two searches must have been issued with different time ranges:
    # recent = now-7d/d .. now
    # baseline = now-97d/d .. now-7d/d   (recent_days + baseline_days)
    bodies = [call.kwargs["body"] for call in client.search.call_args_list]
    ranges = [b["query"]["bool"]["filter"][0]["range"]["@timestamp"] for b in bodies]
    assert ranges[0] == {"gte": "now-7d/d", "lte": "now"}
    assert ranges[1] == {"gte": "now-97d/d", "lte": "now-7d/d"}


def test_first_seen_domains_hours_window_converted_to_days():
    client = MagicMock()
    client.search.side_effect = [_resp([]), _resp([])]
    svc = WazuhDataService(client)
    svc.first_seen_domains(
        device_name="d", recent_window="last_24h", baseline_days=30
    )
    bodies = [call.kwargs["body"] for call in client.search.call_args_list]
    ranges = [b["query"]["bool"]["filter"][0]["range"]["@timestamp"] for b in bodies]
    assert ranges[0] == {"gte": "now-24h/h", "lte": "now"}
    # 24h → 1 day; baseline = 1 + 30 = 31 days total, ending at "now-24h/h".
    assert ranges[1] == {"gte": "now-31d/d", "lte": "now-24h/h"}


def test_first_seen_domains_filters_by_device_and_alarm_type():
    client = MagicMock()
    client.search.side_effect = [_resp([]), _resp([])]
    svc = WazuhDataService(client)
    svc.first_seen_domains(device_name="Kids iPad", recent_window="last_7d")
    body = client.search.call_args_list[0].kwargs["body"]
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"data.event_type": "alarm"}} in filters
    assert {"term": {"data.device.name": "Kids iPad"}} in filters
    assert {"exists": {"field": "data.raw.remote.domain"}} in filters


def test_first_seen_domains_rejects_iso_range():
    svc = WazuhDataService(MagicMock())
    with pytest.raises(ValueError, match="shorthand"):
        svc.first_seen_domains(
            device_name="d",
            recent_window="2026-04-17T00:00:00Z/2026-04-24T00:00:00Z",
        )


def test_first_seen_domains_truncates_large_new_set():
    new_domains = [f"new-{i}.example" for i in range(150)]
    client = MagicMock()
    client.search.side_effect = [_resp(new_domains), _resp([])]
    svc = WazuhDataService(client)
    out = svc.first_seen_domains(
        device_name="d", recent_window="last_7d", top_n=100
    )
    assert out["new_domain_count"] == 150
    assert len(out["new_domains"]) == 100
    assert out["truncated"] is True
