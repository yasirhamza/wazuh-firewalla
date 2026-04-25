#!/usr/bin/env python3
"""Build and import the 'Threat Hunting Program' OpenSearch dashboard.

Panels:
  - Hunts run (time series, stacked by outcome)
  - Hypotheses by status (bar)
  - Findings by confidence (pie)
  - MITRE technique coverage (heatmap)
  - Top hypotheses by finding volume (table)
  - Detection promotions (count over time)
  - Hunt findings table (drill-down)

Run:
    DASHBOARD_PASSWORD=... python3 scripts/create_hunting_dashboard.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

DASH_TITLE = "Threat Hunting Program"
DASH_ID = "threat-hunting-program"
INDEX_PATTERN = "wazuh-alerts-*"
BASE_URL = os.environ.get("DASHBOARD_URL", "https://localhost")
USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
PASSWORD = os.environ.get("DASHBOARD_PASSWORD")


def _viz_hunts_run_timeseries() -> dict:
    return {
        "id": "hunting-runs-timeseries",
        "type": "visualization",
        "attributes": {
            "title": "Hunt findings over time (stacked by confidence)",
            "visState": json.dumps({
                "title": "Hunt findings over time",
                "type": "histogram",
                "params": {"type": "histogram"},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "date_histogram", "schema": "segment",
                     "params": {"field": "@timestamp", "interval": "auto"}},
                    {"id": "3", "type": "terms", "schema": "group",
                     "params": {"field": "data.hunt.confidence", "size": 3,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_findings_by_confidence() -> dict:
    return {
        "id": "hunting-findings-by-confidence",
        "type": "visualization",
        "attributes": {
            "title": "Findings by confidence",
            "visState": json.dumps({
                "title": "Findings by confidence",
                "type": "pie",
                "params": {"type": "pie", "isDonut": True},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "segment",
                     "params": {"field": "data.hunt.confidence", "size": 3}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100801 and rule.id <= 100803"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_mitre_coverage() -> dict:
    return {
        "id": "hunting-mitre-coverage",
        "type": "visualization",
        "attributes": {
            "title": "MITRE technique coverage (hunted last 30d)",
            "visState": json.dumps({
                "title": "MITRE coverage",
                "type": "table",
                "params": {"perPage": 20},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "bucket",
                     "params": {"field": "data.hunt.attack_technique", "size": 50,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_top_hypotheses() -> dict:
    return {
        "id": "hunting-top-hypotheses",
        "type": "visualization",
        "attributes": {
            "title": "Top hypotheses by finding volume",
            "visState": json.dumps({
                "title": "Top hypotheses by finding volume",
                "type": "table",
                "params": {"perPage": 20},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "bucket",
                     "params": {"field": "data.hunt.hypothesis_id", "size": 20,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_findings_table() -> dict:
    return {
        "id": "hunting-findings-table",
        "type": "search",
        "attributes": {
            "title": "Hunt findings (drill-down)",
            "columns": [
                "data.hunt.hypothesis_id",
                "data.hunt.attack_technique",
                "data.hunt.confidence",
                "data.hunt.summary",
                "agent.name",
            ],
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _build_dashboard(viz_ids: list[str]) -> dict:
    panels = []
    for i, vid in enumerate(viz_ids):
        x = (i % 2) * 24
        y = (i // 2) * 12
        panels.append({
            "version": "2.x",
            "type": "visualization" if vid != "hunting-findings-table" else "search",
            "gridData": {"x": x, "y": y, "w": 24, "h": 12, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {},
            "panelRefName": f"panel_{i}",
        })
    return {
        "id": DASH_ID,
        "type": "dashboard",
        "attributes": {
            "title": DASH_TITLE,
            "description": "TaHiTI-driven hunt program: cadence, MITRE coverage, finding volume, drill-down.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []}),
            },
        },
        "references": [
            {"name": f"panel_{i}",
             "type": "visualization" if vid != "hunting-findings-table" else "search",
             "id": vid}
            for i, vid in enumerate(viz_ids)
        ],
    }


def _import(objects: list[dict]) -> None:
    if not PASSWORD:
        print("DASHBOARD_PASSWORD not set", file=sys.stderr)
        sys.exit(2)

    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    ndjson = "\n".join(json.dumps(o) for o in objects).encode()
    boundary = "----HuntDashImport"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="hunting.ndjson"\r\n'
        "Content-Type: application/x-ndjson\r\n\r\n"
    ).encode() + ndjson + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{BASE_URL}/api/saved_objects/_import?overwrite=true",
        data=body,
        method="POST",
        headers={
            "osd-xsrf": "true",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    import base64
    auth = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    visualizations = [
        _viz_hunts_run_timeseries(),
        _viz_findings_by_confidence(),
        _viz_mitre_coverage(),
        _viz_top_hypotheses(),
    ]
    findings_table = _viz_findings_table()
    viz_ids = [v["id"] for v in visualizations] + [findings_table["id"]]
    dashboard = _build_dashboard(viz_ids)

    _import(visualizations + [findings_table, dashboard])
    print(f"Dashboard '{DASH_TITLE}' imported.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
