"""Tests for the scan_first_seen_for_all_devices and enumerate_devices helpers."""
from unittest.mock import MagicMock

from src.wazuh_service import WazuhDataService


def _make_service_with_fixed_first_seen(per_device_results):
    """WazuhDataService whose first_seen_domains returns pre-baked results
    keyed by device name — lets us test the scan orchestration without
    exercising the full DSL plumbing again."""
    client = MagicMock()
    svc = WazuhDataService(client)
    svc.first_seen_domains = MagicMock(
        side_effect=lambda device_name, **kw: per_device_results[device_name]
    )
    return svc, client


def test_enumerate_devices_returns_sorted_unique_device_names():
    client = MagicMock()
    client.search.return_value = {
        "aggregations": {"devices": {"buckets": [
            {"key": "demo-device", "doc_count": 2498},
            {"key": "laptop-1", "doc_count": 305},
            {"key": "host-c", "doc_count": 337},
            {"key": "iPhone", "doc_count": 109},
        ]}}
    }
    svc = WazuhDataService(client)

    devices = svc.enumerate_devices(time_range="last_30d")

    assert devices == sorted(["demo-device", "laptop-1", "host-c", "iPhone"])
    body = client.search.call_args.kwargs["body"]
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"data.event_type": "alarm"}} in filters
    assert {"exists": {"field": "data.device.name"}} in filters


def test_scan_first_seen_runs_per_device():
    devices_resp = {
        "aggregations": {"devices": {"buckets": [
            {"key": "iPad", "doc_count": 40},
            {"key": "Windows", "doc_count": 100},
        ]}}
    }
    per_device = {
        "iPad": {"device": "iPad", "new_domain_count": 2, "new_domains": ["a.com", "b.com"]},
        "Windows": {"device": "Windows", "new_domain_count": 0, "new_domains": []},
    }
    svc, client = _make_service_with_fixed_first_seen(per_device)
    client.search.return_value = devices_resp

    out = svc.scan_first_seen_for_all_devices(recent_window="last_7d")

    # Results preserve enumerate-order (sorted); one entry per device.
    assert len(out) == 2
    assert [r["device"] for r in out] == ["Windows", "iPad"]  # sorted
    assert out[1]["new_domains"] == ["a.com", "b.com"]
    # first_seen_domains called with the forwarded kwargs.
    calls = svc.first_seen_domains.call_args_list
    assert calls[0].kwargs["device_name"] == "Windows"
    assert calls[0].kwargs["recent_window"] == "last_7d"


def test_scan_first_seen_records_per_device_errors_without_aborting():
    devices_resp = {
        "aggregations": {"devices": {"buckets": [
            {"key": "good-device", "doc_count": 50},
            {"key": "bad-device", "doc_count": 30},
            {"key": "another-good", "doc_count": 20},
        ]}}
    }
    def fake_first_seen(device_name, **kw):
        if device_name == "bad-device":
            raise ValueError("synthetic failure")
        return {"device": device_name, "new_domain_count": 0, "new_domains": []}

    client = MagicMock()
    client.search.return_value = devices_resp
    svc = WazuhDataService(client)
    svc.first_seen_domains = MagicMock(side_effect=fake_first_seen)

    out = svc.scan_first_seen_for_all_devices()

    assert len(out) == 3
    by_device = {r["device"]: r for r in out}
    assert "error" not in by_device["good-device"]
    assert "error" not in by_device["another-good"]
    assert by_device["bad-device"]["error"].startswith("ValueError:")
