#!/usr/bin/env python3
"""Weekly health audit of the hypothesis backlog.

Checks:
  - Every backlog YAML still validates against the schema.
  - All referenced ATT&CK technique IDs still exist in the cached bundle.
  - Hypotheses in `proposed` status >90 days are flagged as stale.
  - cti_sources URLs are reachable (HEAD request; warn-only).

Output is plain text suitable for piping to a log or notifying via email.
Exit 0 always (audit, not gate).

Wire as a /schedule weekly cron.
"""
from __future__ import annotations

import sys
import urllib.request
from datetime import date, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from scripts.attack_lookup import lookup as attack_lookup, AttackBundleNotFound  # noqa: E402
from scripts.hypothesis_schema import Hypothesis  # noqa: E402

BACKLOG = REPO / "hunts" / "backlog"
STALE_DAYS = 90


def _check_url(url: str) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "firewalla-wazuh-hunting/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def main() -> int:
    today = date.today()
    issues: list[str] = []
    n_files = 0

    for path in sorted(BACKLOG.glob("H-*.yaml")):
        n_files += 1
        try:
            data = yaml.safe_load(path.read_text())
            h = Hypothesis(**data)
        except Exception as e:
            issues.append(f"[SCHEMA] {path.name}: {e}")
            continue

        # ATT&CK technique freshness
        for tech in h.attack.techniques:
            try:
                if attack_lookup(tech) is None:
                    issues.append(f"[ATTACK] {path.name}: technique {tech} not in cached bundle")
            except AttackBundleNotFound:
                issues.append("[ATTACK] cache missing — run scripts/refresh_attack.sh")
                break

        # Stale-proposed check
        if h.status.value == "proposed":
            age = (today - h.created).days
            if age > STALE_DAYS:
                issues.append(f"[STALE] {path.name}: proposed for {age}d (>{STALE_DAYS})")

        # CTI URL reachability (warn-only)
        for src in h.cti_sources:
            if src.url is not None and not _check_url(str(src.url)):
                issues.append(f"[URL] {path.name}: {src.url} unreachable")

    print(f"Audited {n_files} hypotheses; {len(issues)} issue(s).")
    for line in issues:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
