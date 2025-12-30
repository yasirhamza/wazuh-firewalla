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

import requests

# Configuration
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", 86400))  # Default: 24 hours
CDB_DIR = Path(os.environ.get("CDB_DIR", "/lists"))
STATUS_DIR = Path(os.environ.get("STATUS_DIR", "/status"))

# Log rotation settings
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", 10 * 1024 * 1024))  # 10MB for status logs

# Feed definitions: name -> (url, parser_function)
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
    }
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


def download_feed(url: str, timeout: int = 30) -> str:
    """Download feed content"""
    try:
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

        content = download_feed(config["url"])
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

    last_heartbeat = 0
    heartbeat_interval = 3600  # 1 hour (since updates are every 24h)

    while True:
        try:
            update_feeds(status)
        except Exception as e:
            logger.exception(f"Error during feed update: {e}")
            status.report_error("all", str(e))

        # Send heartbeat periodically
        now = time.time()
        if now - last_heartbeat >= heartbeat_interval:
            status.report_heartbeat()
            last_heartbeat = now

        logger.info(f"Sleeping for {UPDATE_INTERVAL}s until next update...")
        time.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    main()
