#!/usr/bin/env python3
"""Pull recent CISA cybersecurity advisories from the public RSS feed.

CLI: python3 scripts/cisa_recent.py [N]    # default N=10
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime

CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
AA_ID_RE = re.compile(r"\b(AA\d{2}-\d{3}[A-Z])\b")


def parse_advisories_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    out: list[dict] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        desc = (item.findtext("description") or "").strip()

        m = AA_ID_RE.search(title)
        aa_id = m.group(1) if m else None

        # Strip "AAxx-xxxX: " prefix from title for cleaner display.
        clean_title = title
        if aa_id and title.startswith(aa_id):
            clean_title = title[len(aa_id):].lstrip(": ").strip()

        try:
            iso_date = parsedate_to_datetime(pub_date_raw).date().isoformat()
        except (TypeError, ValueError):
            iso_date = None

        out.append({
            "id": aa_id,
            "title": clean_title,
            "url": link,
            "date": iso_date,
            "summary": desc[:500],
        })
    return out


def fetch_recent(limit: int = 10) -> list[dict]:
    req = urllib.request.Request(
        CISA_RSS_URL,
        headers={"User-Agent": "firewalla-wazuh-hunting/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    items = parse_advisories_xml(body)
    return items[:limit]


def main(argv: list[str]) -> int:
    limit = int(argv[1]) if len(argv) > 1 else 10
    try:
        items = fetch_recent(limit=limit)
    except Exception as e:
        print(f"error fetching CISA RSS: {e}", file=sys.stderr)
        return 1
    print(json.dumps(items, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
