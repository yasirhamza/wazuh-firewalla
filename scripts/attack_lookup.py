#!/usr/bin/env python3
"""MITRE ATT&CK technique lookup against the cached STIX bundle.

CLI usage:
    python3 scripts/attack_lookup.py T1071.001

Library usage:
    from scripts.attack_lookup import lookup
    result = lookup("T1071.001")
"""
from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path

ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
BUNDLE_PATH = Path(__file__).resolve().parent.parent / "cti-cache" / "attack" / "enterprise-attack.json"


class AttackBundleNotFound(FileNotFoundError):
    pass


@lru_cache(maxsize=1)
def _load_bundle() -> dict:
    if not BUNDLE_PATH.exists():
        raise AttackBundleNotFound(
            f"ATT&CK bundle not found at {BUNDLE_PATH}. "
            f"Run scripts/refresh_attack.sh first."
        )
    with BUNDLE_PATH.open() as f:
        return json.load(f)


def _index() -> dict[str, dict]:
    """Build a flat index: external_id (T1071, T1071.001, etc.) -> object."""
    out: dict[str, dict] = {}
    bundle = _load_bundle()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                out[ref["external_id"]] = obj
    return out


def lookup(technique_id: str) -> dict | None:
    """Look up a MITRE ATT&CK technique by ID.

    Returns None if the ID is not found. Raises ValueError on malformed input.
    """
    if not ATTACK_TECHNIQUE_RE.match(technique_id):
        raise ValueError(
            f"invalid technique id: {technique_id!r} (expected T1071 or T1071.001)"
        )
    idx = _index()
    obj = idx.get(technique_id)
    if obj is None:
        return None

    tactics = [
        phase.get("phase_name", "")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]
    sub_techniques = [
        ext_id for ext_id in idx
        if ext_id.startswith(technique_id + ".") and ext_id != technique_id
    ]
    return {
        "id": technique_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", "")[:1000],
        "tactics": tactics,
        "data_sources": obj.get("x_mitre_data_sources", []),
        "detection": obj.get("x_mitre_detection", "")[:2000],
        "sub_techniques": sorted(sub_techniques),
        "url": next(
            (r.get("url") for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        ),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: attack_lookup.py <TECHNIQUE_ID>", file=sys.stderr)
        return 2
    try:
        result = lookup(argv[1])
    except (ValueError, AttackBundleNotFound) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if result is None:
        print(f"technique {argv[1]} not found in bundle", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
