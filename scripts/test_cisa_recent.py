"""Tests for the CISA advisory parser (input fixture, not live HTTP)."""
from pathlib import Path

from scripts.cisa_recent import parse_advisories_xml


SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access</title>
      <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a</link>
      <pubDate>Wed, 07 Feb 2024 11:00:00 EST</pubDate>
      <description>CISA, NSA, and FBI assess that PRC state-sponsored cyber actors are seeking to pre-position themselves on IT networks ...</description>
    </item>
    <item>
      <title>AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure</title>
      <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b</link>
      <pubDate>Thu, 29 Feb 2024 11:00:00 EST</pubDate>
      <description>CISA and authoring organizations are releasing this joint Cybersecurity Advisory ...</description>
    </item>
  </channel>
</rss>
"""


def test_parse_extracts_id_title_url_date_summary():
    items = parse_advisories_xml(SAMPLE_XML)
    assert len(items) == 2

    first = items[0]
    assert first["id"] == "AA24-038A"
    assert first["title"].startswith("PRC State-Sponsored")
    assert first["url"] == "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"
    assert first["date"] == "2024-02-07"
    assert "PRC state-sponsored" in first["summary"]


def test_id_extraction_handles_missing_aa_prefix():
    xml = SAMPLE_XML.replace("AA24-038A: ", "")
    items = parse_advisories_xml(xml)
    assert items[0]["id"] is None  # no AA-id parseable from title
