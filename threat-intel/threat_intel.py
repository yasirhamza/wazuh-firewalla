#!/usr/bin/env python3
"""
Threat Intelligence Feed Updater for Wazuh CDB Lists

Downloads threat feeds and formats them for Wazuh CDB list matching.
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import requests

# Configuration
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", 86400))  # Default: 24 hours
CDB_DIR = Path(os.environ.get("CDB_DIR", "/lists"))
STATUS_DIR = Path(os.environ.get("STATUS_DIR", "/status"))

# Log rotation settings
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", 10 * 1024 * 1024))  # 10MB for status logs

# Feed definitions: name -> (url, parser_function)
#
# DISABLED: urlhaus-domains. 30-day analysis showed 5,612 matches, 100% of
# which were false positives against shared cloud/CDN infrastructure
# (Azure, GitHub Pages, Fastly, Cloudflare) that URLhaus listed because
# some past malware sample transited the same shared endpoint. For a
# home/SMB environment this feed produces only noise; it masks real
# signal from the other three feeds. Parser and downloader kept below
# in case the feed is re-enabled (e.g., paired with a CDN/ASN allow-list).
FEEDS = {
    "feodo-ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "Feodo Tracker Botnet C2 IPs (Emotet, Dridex, TrickBot, QakBot)",
        "parser": "parse_feodo_ips"
    },
    "threatfox-ips": {
        "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "description": "ThreatFox Recent C2 IPs (broad malware coverage)",
        "parser": "parse_threatfox_ips"
    },
    "malwarebazaar-hashes": {
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "description": "MalwareBazaar Recent SHA256 Hashes (CSV export)",
        "parser": "parse_malwarebazaar_hashes"
    },
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


class StatusReporter:
    """Reports sync job status to a JSON log for Wazuh monitoring"""

    def __init__(self, status_dir: Path):
        self.status_dir = status_dir
        self.status_dir.mkdir(parents=True, exist_ok=True)
        self.status_file = self.status_dir / "sidecar-status.json"
        self.stats = {
            "feeds_updated": 0,
            "total_entries": 0,
            "last_success": None,
            "last_error": None,
            "error_count": 0
        }

    def report_success(self, feeds_count: int, total_entries: int, feed_details: dict = None):
        """Report successful feed update"""
        now = datetime.now()
        self.stats["feeds_updated"] += feeds_count
        self.stats["total_entries"] = total_entries
        self.stats["last_success"] = now.isoformat()

        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "threat-intel",
            "job_type": "feed_update",
            "sync_status": "success",
            "feeds_count": feeds_count,
            "total_entries": total_entries,
            "error_count": self.stats["error_count"]
        }
        if feed_details:
            event["feed_details"] = feed_details

        self._write_event(event)

    def report_error(self, feed_name: str, error_msg: str):
        """Report feed update error"""
        now = datetime.now()
        self.stats["last_error"] = now.isoformat()
        self.stats["error_count"] += 1

        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "threat-intel",
            "job_type": "feed_update",
            "sync_status": "error",
            "feed_name": feed_name,
            "error_message": error_msg,
            "error_count": self.stats["error_count"]
        }
        self._write_event(event)

    def report_heartbeat(self):
        """Report periodic heartbeat"""
        now = datetime.now()
        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "threat-intel",
            "job_type": "heartbeat",
            "sync_status": "running",
            "stats": self.stats
        }
        self._write_event(event)

    def _write_event(self, event: dict):
        """Append status event to log file with rotation"""
        self._rotate_if_needed()
        with open(self.status_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def _rotate_if_needed(self):
        """Rotate status log if it exceeds MAX_LOG_SIZE"""
        if not self.status_file.exists():
            return

        if self.status_file.stat().st_size < MAX_LOG_SIZE:
            return

        # Simple rotation: keep only 1 backup for status
        backup = self.status_file.with_suffix(".json.1")
        if backup.exists():
            backup.unlink()
        self.status_file.rename(backup)
        logger.info(f"Rotated status log {self.status_file}")


def parse_sslbl_ips(content: str) -> list:
    """Parse SSLBL IP blacklist CSV"""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            ip = parts[1].strip()
            if ip and not ip.startswith("DstIP"):
                entries.append((ip, "sslbl-c2"))
    return entries


def parse_feodo_ips(content: str) -> list:
    """Parse Feodo Tracker IP blocklist CSV"""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle quoted CSV format: "first_seen","ip","port",...
        parts = line.split(",")
        if len(parts) >= 2:
            ip = parts[1].strip().strip('"')
            # Skip header and validate IP format
            if ip and ip != "dst_ip" and "." in ip:
                entries.append((ip, "feodo-c2"))
    return entries


def parse_threatfox_ips(content: str) -> list:
    """Parse ThreatFox IP:port CSV export"""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: "first_seen","ioc_id","ioc_value","ioc_type",...
        # ioc_value is IP:port like "64.32.48.49:443"
        parts = line.split(",")
        if len(parts) >= 3:
            ioc_value = parts[2].strip().strip('"')
            # Extract IP from IP:port
            if ":" in ioc_value and "." in ioc_value:
                ip = ioc_value.split(":")[0]
                if ip and ip != "ioc_value":
                    entries.append((ip, "threatfox-c2"))
    return entries


def parse_urlhaus_domains(content: str) -> list:
    """Parse URLhaus URL blocklist CSV, extracting unique hostnames"""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
        parts = line.split(",")
        if len(parts) < 3:
            continue
        url = parts[2].strip().strip('"')
        if not url or url == "url":
            continue
        try:
            hostname = urlparse(url).hostname
        except Exception:
            continue
        if not hostname:
            continue
        # Skip pure IPs — already covered by feodo/threatfox IP feeds
        if all(c.isdigit() or c == "." for c in hostname) or ":" in hostname:
            continue
        entries.append((hostname, "urlhaus-malware"))
    return entries


def parse_malwarebazaar_hashes(content: str) -> list:
    """Parse MalwareBazaar recent CSV export, extracting SHA256 hashes"""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 9:
            continue
        sha256 = parts[1].strip().strip('"').lower()
        if not sha256 or len(sha256) != 64:
            continue
        family = parts[8].strip().strip('"').replace(" ", "_")
        if not family or family.lower() == "n/a":
            family = "unknown"
        entries.append((sha256, family))
    return entries


def download_urlhaus_csv(url: str, timeout: int = 30) -> str:
    """Download URLhaus ZIP feed and extract the inner CSV text"""
    import io
    import zipfile
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            # The archive contains a single file (csv.txt)
            csv_filename = zf.namelist()[0]
            return zf.read(csv_filename).decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"Failed to download/extract URLhaus ZIP from {url}: {e}")
        return ""


def download_feed(url: str, timeout: int = 30, post_data: dict = None) -> str:
    """Download feed content via GET or POST"""
    try:
        if post_data:
            response = requests.post(url, data=post_data, timeout=timeout)
        else:
            response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.error(f"Failed to download {url}: {e}")
        return ""


def write_cdb_list(name: str, entries: list, output_dir: Path):
    """Write entries to Wazuh CDB format (key:value)"""
    output_file = output_dir / name

    # Deduplicate
    unique_entries = sorted(set(entries))

    with open(output_file, "w") as f:
        for key, value in unique_entries:
            f.write(f"{key}:{value}\n")

    logger.info(f"Wrote {len(unique_entries)} entries to {output_file}")
    return len(unique_entries)


def update_feeds(status: StatusReporter = None):
    """Download and update all configured feeds"""
    CDB_DIR.mkdir(parents=True, exist_ok=True)

    total_entries = 0
    feed_details = {}
    feeds_updated = 0

    for name, config in FEEDS.items():
        logger.info(f"Updating {name} ({config['description']})...")

        downloader_name = config.get("downloader")
        if downloader_name:
            downloader = globals().get(downloader_name)
            if not downloader:
                logger.error(f"Downloader function '{downloader_name}' not found for feed '{name}'")
                if status:
                    status.report_error(name, f"Downloader function '{downloader_name}' not found")
                continue
            content = downloader(config["url"])
        else:
            content = download_feed(config["url"], post_data=config.get("post_data"))
        if not content:
            logger.warning(f"Skipping {name} - download failed")
            if status:
                status.report_error(name, "Download failed")
            continue

        # Get parser function
        parser_name = config["parser"]
        parser = globals().get(parser_name)
        if not parser:
            logger.error(f"Parser {parser_name} not found")
            if status:
                status.report_error(name, f"Parser {parser_name} not found")
            continue

        entries = parser(content)
        if entries:
            count = write_cdb_list(name, entries, CDB_DIR)
            total_entries += count
            feed_details[name] = count
            feeds_updated += 1
        else:
            logger.warning(f"No entries parsed from {name}")
            if status:
                status.report_error(name, "No entries parsed")

    logger.info(f"Feed update complete. Total entries: {total_entries}")

    if status and feeds_updated > 0:
        status.report_success(feeds_updated, total_entries, feed_details)

    return total_entries


def main():
    logger.info("Threat Intel Feed Updater starting...")
    logger.info(f"Update interval: {UPDATE_INTERVAL}s")
    logger.info(f"CDB output directory: {CDB_DIR}")
    logger.info(f"Status directory: {STATUS_DIR}")

    # Initialize status reporter
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    status = StatusReporter(STATUS_DIR)

    HEARTBEAT_INTERVAL = 60  # 1 min — matches wazuh-mcp so sidecar_health
                             # (stale threshold 5 min) never false-positives.

    last_update = 0.0
    last_heartbeat = 0.0

    while True:
        now = time.time()

        # Run a feed update cycle when UPDATE_INTERVAL has elapsed.
        if now - last_update >= UPDATE_INTERVAL:
            try:
                update_feeds(status)
            except Exception as e:
                logger.exception(f"Error during feed update: {e}")
                status.report_error("all", str(e))
            last_update = now
            logger.info(f"Next feed update in {UPDATE_INTERVAL}s.")

        # Emit a heartbeat every HEARTBEAT_INTERVAL, independent of feed updates.
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            status.report_heartbeat()
            last_heartbeat = now

        time.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    main()
