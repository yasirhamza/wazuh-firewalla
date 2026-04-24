"""Integration tests — one per tool — against a real OpenSearch."""
import os
import time

import pytest

from src.wazuh_client import WazuhClient
from src.wazuh_service import WazuhDataService
from tests.seed_alerts import seed


OS_URL = os.environ.get("TEST_OS_URL", "http://localhost:19200")


@pytest.fixture(scope="module")
def service():
    # Wait for opensearch to be up. We use httpx (already a dev dep) to avoid
    # pulling in the full requests package.
    import httpx
    for _ in range(30):
        try:
            if httpx.get(OS_URL, timeout=2).status_code == 200:
                break
        except Exception:
            time.sleep(1)
    seed(OS_URL, 500)
    # When security is disabled on the test OS, the client passes http_auth=None
    # (user="" triggers the no-auth branch in WazuhClient).
    client = WazuhClient(url=OS_URL, user="", password="")
    return WazuhDataService(client, alerts_index="wazuh-alerts-*")


@pytest.mark.integration
def test_search_alerts_end_to_end(service):
    out = service.search_alerts(
        filters={"data.source": "windows-srp"}, time_range="last_7d", limit=10
    )
    assert out["total_matched"] > 0
    for row in out["results"]:
        assert row["data"].get("source") == "windows-srp"


@pytest.mark.integration
def test_aggregate_alerts_end_to_end(service):
    out = service.aggregate_alerts(
        group_by_field="data.source", time_range="last_7d", top_n=10
    )
    keys = {b["key"] for b in out["buckets"]}
    assert {"firewalla-msp", "windows-srp", "threat-intel"}.issubset(keys)


@pytest.mark.integration
def test_alert_overview_end_to_end(service):
    out = service.alert_overview(time_range="last_7d")
    # Not an exact 500: `now-7d/d` rounds to the day boundary, so a few
    # seed records near the edge may fall in or out of scope. Tolerate ±10.
    assert out["total_alerts"] >= 490
    assert sum(out["by_source"].values()) == out["total_alerts"]


@pytest.mark.integration
def test_trend_delta_end_to_end(service):
    out = service.trend_delta(
        metric="alerts_by_agent",
        current_window="last_24h",
        prior_window="last_7d",
    )
    assert "movers" in out
    assert all("delta_pct" in m for m in out["movers"])


@pytest.mark.integration
def test_threat_intel_matches_end_to_end(service):
    out = service.threat_intel_matches(time_range="last_7d")
    assert out["total"] > 0
    for m in out["matches"]:
        assert m["list"] in ("firewalla-c2", "urlhaus") or m["rule_id"] in ("99905", "99912")


@pytest.mark.integration
def test_get_alert_end_to_end(service):
    some = service.search_alerts(
        filters={"data.source": "ossec"}, time_range="last_7d", limit=1
    )
    alert_id = some["results"][0]["id"]
    detail = service.get_alert(alert_id)
    assert detail["_id"] == alert_id


@pytest.mark.integration
def test_entity_activity_end_to_end(service):
    out = service.entity_activity(
        entity_type="ip", entity_value="10.0.0.10", time_range="last_7d"
    )
    assert "entity" in out
    assert out["entity"]["type"] == "ip"
