"""Tests for WazuhDataService.get_alert."""
from unittest.mock import MagicMock

import pytest

from src.wazuh_service import AlertNotFound, WazuhDataService


def test_get_alert_returns_source():
    client = MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 1}, "hits": [
            {"_id": "a1", "_source": {"rule": {"id": "100451"}, "agent": {"name": "h"}}}
        ]}
    }
    svc = WazuhDataService(client)
    out = svc.get_alert("a1")
    assert out == {"_id": "a1", "rule": {"id": "100451"}, "agent": {"name": "h"}}
    # Verify the correct query form — `ids`, not `term: _id`.
    body = client.search.call_args.kwargs["body"]
    assert body["query"] == {"ids": {"values": ["a1"]}}


def test_get_alert_raises_when_missing():
    client = MagicMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    svc = WazuhDataService(client)
    with pytest.raises(AlertNotFound):
        svc.get_alert("nope")
