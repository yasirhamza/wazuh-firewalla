"""Tests for the thin OpenSearch client wrapper."""
from unittest.mock import MagicMock, patch

import pytest

from src.wazuh_client import WazuhClient, WazuhClientError


def make_client():
    with patch("src.wazuh_client.OpenSearch") as mock_os_cls:
        mock_os = MagicMock()
        mock_os_cls.return_value = mock_os
        client = WazuhClient(
            url="https://wazuh.indexer:9200",
            user="mcp_read",
            password="secret",
            timeout=10,
        )
        return client, mock_os


def test_search_passes_body_to_opensearch():
    client, mock_os = make_client()
    mock_os.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    body = {"query": {"match_all": {}}}

    result = client.search(index="wazuh-alerts-*", body=body)

    # Per-attempt timeout is 5s (half of the 10s wall-clock deadline).
    mock_os.search.assert_called_once_with(
        index="wazuh-alerts-*", body=body, request_timeout=5.0
    )
    assert result["hits"]["total"]["value"] == 0


def test_search_retries_once_on_connection_error():
    client, mock_os = make_client()
    from opensearchpy import ConnectionError

    mock_os.search.side_effect = [ConnectionError("N/A", "boom", {}), {"hits": {"total": {"value": 1}, "hits": []}}]

    result = client.search(index="wazuh-alerts-*", body={})

    assert mock_os.search.call_count == 2
    assert result["hits"]["total"]["value"] == 1


def test_search_raises_after_retry_exhausted():
    client, mock_os = make_client()
    from opensearchpy import ConnectionError

    mock_os.search.side_effect = ConnectionError("N/A", "still dead", {})

    with pytest.raises(WazuhClientError, match="opensearch_unavailable"):
        client.search(index="wazuh-alerts-*", body={})
    assert mock_os.search.call_count == 2


def test_search_raises_timeout_when_deadline_exceeded(monkeypatch):
    """If a retry pushes the total wall-clock past the deadline, raise 'timeout'."""
    client, mock_os = make_client()
    from opensearchpy import ConnectionError

    # Fake monotonic: first call at t=0, deadline is +10; after first attempt
    # fails we jump past the deadline.
    t = [0.0]
    monkeypatch.setattr("src.wazuh_client.time.monotonic", lambda: t[0])

    def fail_and_advance(*a, **kw):
        t[0] += 11.0
        raise ConnectionError("N/A", "slow", {})

    mock_os.search.side_effect = fail_and_advance
    with pytest.raises(WazuhClientError, match="timeout"):
        client.search(index="wazuh-alerts-*", body={})
    # Only one attempt should have happened — the retry is skipped when the
    # deadline has already passed.
    assert mock_os.search.call_count == 1


def test_count_delegates_to_opensearch():
    client, mock_os = make_client()
    mock_os.count.return_value = {"count": 42}

    assert client.count(index="wazuh-alerts-*", body={"query": {"match_all": {}}}) == 42


def test_ping_returns_true_on_success():
    client, mock_os = make_client()
    mock_os.ping.return_value = True
    assert client.ping() is True


def test_ping_returns_false_on_failure():
    client, mock_os = make_client()
    mock_os.ping.side_effect = Exception("nope")
    assert client.ping() is False
