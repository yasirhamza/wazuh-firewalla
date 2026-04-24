#!/usr/bin/env python3
"""Patch the Firewalla Security Dashboard NDJSON in-place.

Applies two specific changes recommended by the dashboard-analysis work:

1. REMOVE the "Firewalla: Threat Intel Matches" panel. Individual-IOC
   tables are low-signal once the network has category-level policy
   coverage — the underlying IOCs decay faster than the table refreshes.
2. ADD a "Firewalla: ALARM_INTEL rate by device" timeseries panel. That's
   the durable signal — per-device rate of Firewalla's own intel classifier
   firing (rule.id:100212). A device whose rate jumps week-over-week has
   almost certainly picked up a new app/SDK with shady ad-tech or worse.

Idempotent: running twice is safe. Existing state is detected.

Usage:
    python3 scripts/patch_firewalla_dashboard.py [--dry-run] [--path PATH]

After patching, re-import the NDJSON via Dashboards → Stack Management →
Saved Objects → Import → pick the updated file → overwrite conflicts.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO_ROOT / "dashboards" / "firewalla-dashboard.ndjson"

# Panel we're removing.
REMOVE_VIZ_ID = "firewalla-threat-intel-table"
REMOVE_VIZ_TITLE = "Firewalla: Threat Intel Matches"

# Panel we're adding.
ADD_VIZ_ID = "firewalla-alarm-intel-rate"
ADD_VIZ_TITLE = "Firewalla: ALARM_INTEL rate by device"

DASHBOARD_ID = "firewalla-security-dashboard"
INDEX_PATTERN_ID = "wazuh-alerts-*"


def _alarm_intel_rate_viz() -> dict:
    """Stacked-histogram timeseries: ALARM_INTEL count by device over time.

    Modeled on the existing `firewalla-alert-timeline` viz in this dashboard
    so it inherits the same styling and time-field convention.
    """
    vis_state = {
        "title": ADD_VIZ_TITLE,
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "params": {
                    "field": "timestamp",
                    "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedOpenSearchInterval": True,
                    "scaleMetricValues": False,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {},
                },
                "schema": "segment",
            },
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "params": {
                    "field": "data.device.name",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "otherBucketLabel": "Other",
                    "missingBucket": False,
                    "missingBucketLabel": "Missing",
                },
                "schema": "group",
            },
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "ALARM_INTEL hits"},
            }],
            "seriesParams": [{
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True,
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "thresholdLine": {
                "show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C",
            },
        },
    }

    search_source = {
        # Filter to rule 100212 (Firewalla ALARM_INTEL). Level-10 description:
        # "Firewalla: Threat intelligence match" (the HIGH-precision stream,
        # distinct from the noisier URLhaus-domain stream rule 100452).
        "query": {"query": "rule.id: \"100212\"", "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }

    return {
        "attributes": {
            "description": (
                "Per-device rate of Firewalla's ALARM_INTEL classifier "
                "(rule 100212). A rising trend for a single device is the "
                "durable signal that a new app/SDK started reaching out to "
                "flagged infrastructure — more useful than any individual-IOC "
                "table since malvertising/C2 domains decay faster than "
                "blocklists refresh."
            ),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)},
            "title": ADD_VIZ_TITLE,
            "uiStateJSON": "{}",
            "version": 1,
            "visState": json.dumps(vis_state),
        },
        "id": ADD_VIZ_ID,
        "migrationVersion": {"visualization": "7.10.0"},
        "references": [{
            "id": INDEX_PATTERN_ID,
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
        }],
        "type": "visualization",
        "updated_at": "2026-04-24T00:00:00.000Z",
        "version": "1",
    }


def _load(path: Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def _save(path: Path, objs: list[dict]) -> None:
    # NDJSON: one object per line, no trailing newline on the last line
    # (matches the original file's formatting).
    with path.open("w") as f:
        f.write("\n".join(json.dumps(o) for o in objs))


def _find_dashboard(objs: list[dict], dash_id: str) -> dict | None:
    for o in objs:
        if o.get("type") == "dashboard" and o.get("id") == dash_id:
            return o
    return None


def _remove_viz_and_panel(objs: list[dict], viz_id: str) -> tuple[list[dict], bool]:
    """Remove a visualization saved object and its dashboard panel reference.

    Returns (new_objs, removed?). Idempotent: returns removed=False if the
    viz wasn't present to begin with.
    """
    viz_present = any(o.get("type") == "visualization" and o.get("id") == viz_id for o in objs)
    if not viz_present:
        return objs, False

    # Strip the viz line.
    new_objs = [o for o in objs if not (o.get("type") == "visualization" and o.get("id") == viz_id)]

    # Clean up any dashboard that referenced it.
    for obj in new_objs:
        if obj.get("type") != "dashboard":
            continue
        panels = json.loads(obj["attributes"]["panelsJSON"])
        refs = obj["references"]
        # Find the reference name for this viz (e.g. panel_7).
        drop_names = {r["name"] for r in refs if r.get("id") == viz_id and r.get("type") == "visualization"}
        if not drop_names:
            continue
        new_panels = [p for p in panels if p.get("panelRefName") not in drop_names]
        new_refs = [r for r in refs if r.get("name") not in drop_names]
        obj["attributes"]["panelsJSON"] = json.dumps(new_panels)
        obj["references"] = new_refs

    return new_objs, True


def _add_viz_and_panel(objs: list[dict], viz: dict, dash_id: str) -> tuple[list[dict], bool]:
    """Add a visualization and wire it into the named dashboard as a bottom panel.

    Returns (new_objs, added?). Idempotent: returns added=False if the viz
    is already present.
    """
    if any(o.get("type") == "visualization" and o.get("id") == viz["id"] for o in objs):
        return objs, False

    dashboard = _find_dashboard(objs, dash_id)
    if dashboard is None:
        raise RuntimeError(f"dashboard not found: {dash_id}")

    new_objs = list(objs)
    # Insert the viz just before the dashboard (keeps the viz→dashboard order).
    dash_idx = new_objs.index(dashboard)
    new_objs.insert(dash_idx, viz)

    # Wire panel + reference into the dashboard.
    panels = json.loads(dashboard["attributes"]["panelsJSON"])
    refs = dashboard["references"]

    # Find the next free panelIndex and the next free panelRefName.
    existing_indices = [int(p.get("panelIndex", "0")) for p in panels]
    next_index = max(existing_indices) + 1 if existing_indices else 1
    existing_refnames = [r["name"] for r in refs if r["name"].startswith("panel_")]
    next_refnum = max(int(n.split("_", 1)[1]) for n in existing_refnames) + 1 if existing_refnames else 0
    refname = f"panel_{next_refnum}"

    # Place at the bottom, full-width. Existing dashboard uses 48-column grid
    # with panels up to y=32+10=42. Drop ours at y=44 full-width.
    max_y = max((p["gridData"]["y"] + p["gridData"]["h"]) for p in panels) if panels else 0
    panels.append({
        "version": "7.10.0",
        "gridData": {"x": 0, "y": max_y, "w": 48, "h": 12, "i": str(next_index)},
        "panelIndex": str(next_index),
        "embeddableConfig": {},
        "panelRefName": refname,
    })
    refs.append({
        "id": viz["id"],
        "name": refname,
        "type": "visualization",
    })
    dashboard["attributes"]["panelsJSON"] = json.dumps(panels)
    dashboard["references"] = refs

    return new_objs, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH,
                        help=f"NDJSON file to patch (default: {DEFAULT_PATH})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would change without writing.")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2

    objs = _load(args.path)
    original = copy.deepcopy(objs)

    objs, removed = _remove_viz_and_panel(objs, REMOVE_VIZ_ID)
    objs, added = _add_viz_and_panel(objs, _alarm_intel_rate_viz(), DASHBOARD_ID)

    if not removed and not added:
        print("already patched — no changes needed.")
        return 0

    print("Changes:")
    if removed:
        print(f"  - REMOVED visualization '{REMOVE_VIZ_TITLE}' ({REMOVE_VIZ_ID}) "
              f"and its dashboard panel.")
    else:
        print(f"  - already absent: '{REMOVE_VIZ_TITLE}'")
    if added:
        print(f"  + ADDED visualization '{ADD_VIZ_TITLE}' ({ADD_VIZ_ID}) "
              f"as new panel at the bottom of '{DASHBOARD_ID}'.")
    else:
        print(f"  + already present: '{ADD_VIZ_TITLE}'")

    # Confidence check: every reference in the dashboard should resolve to
    # an object we still have (or to the wazuh-alerts-* index pattern).
    dash = _find_dashboard(objs, DASHBOARD_ID)
    known_ids = {(o.get("type"), o.get("id")) for o in objs} | {("index-pattern", INDEX_PATTERN_ID)}
    dangling = [r for r in dash["references"] if (r["type"], r["id"]) not in known_ids]
    if dangling:
        print("\nwarning: dangling references detected:", file=sys.stderr)
        for r in dangling:
            print(f"  {r}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n[dry-run] would write {len(objs)} saved objects "
              f"(was {len(original)}) to {args.path}")
        return 0

    _save(args.path, objs)
    print(f"\nwrote {len(objs)} saved objects to {args.path}")
    print("\nNext step: import via Dashboards UI →")
    print("  Stack Management → Saved Objects → Import →")
    print(f"  pick {args.path} → 'Automatically overwrite conflicts'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
