#!/usr/bin/env python3
"""
Firewalla MSP API Poller for Wazuh SIEM Integration

Polls the Firewalla MSP API for alarms, flows, and device changes,
writing them to JSON log files for Wazuh to ingest.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

import requests
from dateutil import parser as dateparser

# Configuration from environment
MSP_DOMAIN = os.environ.get("MSP_DOMAIN", "")
MSP_TOKEN = os.environ.get("MSP_TOKEN", "")
POLL_INTERVAL_ALARMS = int(os.environ.get("POLL_INTERVAL_ALARMS", 300))
POLL_INTERVAL_FLOWS = int(os.environ.get("POLL_INTERVAL_FLOWS", 900))
POLL_INTERVAL_DEVICES = int(os.environ.get("POLL_INTERVAL_DEVICES", 86400))

LOG_DIR = Path(os.environ.get("LOG_DIR", "/logs"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
STATUS_DIR = Path(os.environ.get("STATUS_DIR", "/status"))

# Log rotation settings
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", 50 * 1024 * 1024))  # 50MB default
MAX_LOG_BACKUPS = int(os.environ.get("MAX_LOG_BACKUPS", 2))  # Keep 2 backup files

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


class FirewallaMSPClient:
    """Client for Firewalla MSP API"""

    def __init__(self, domain: str, token: str):
        self.base_url = f"https://{domain}"
        self.headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def get_alarms(self, since_ts: int = None, max_pages: int = 50) -> list:
        """Fetch alarms from MSP API with pagination support"""
        url = f"{self.base_url}/v2/alarms"
        all_alarms = []
        cursor = None
        page = 0

        while page < max_pages:
            params = {"limit": 200}
            if since_ts:
                params["ts"] = since_ts
            if cursor:
                params["cursor"] = cursor

            try:
                response = self.session.get(url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                # Handle paginated response
                if isinstance(data, dict):
                    alarms = data.get("results", [])
                    cursor = data.get("next_cursor")
                    all_alarms.extend(alarms)

                    if not cursor or not alarms:
                        break
                    page += 1
                    logger.debug(f"Fetched page {page}, got {len(alarms)} alarms, total: {len(all_alarms)}")
                else:
                    # Legacy list response
                    all_alarms.extend(data if isinstance(data, list) else [])
                    break

            except requests.RequestException as e:
                logger.error(f"Failed to fetch alarms (page {page}): {e}")
                break

        if page > 0:
            logger.info(f"Fetched {page + 1} pages, total {len(all_alarms)} alarms")
        return all_alarms

    def get_devices(self) -> list:
        """Fetch all devices from MSP API"""
        url = f"{self.base_url}/v2/devices"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch devices: {e}")
            return []

    def get_boxes(self) -> list:
        """Fetch all Firewalla boxes from MSP API"""
        url = f"{self.base_url}/v2/boxes"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch boxes: {e}")
            return []

    def get_flows(self, since_ts: float = None, max_pages: int = 20) -> list:
        """Fetch network flows from MSP API with pagination support"""
        url = f"{self.base_url}/v2/flows"
        all_flows = []
        cursor = None
        page = 0

        while page < max_pages:
            params = {"limit": 500}
            if since_ts:
                params["ts"] = since_ts
            if cursor:
                params["cursor"] = cursor

            try:
                response = self.session.get(url, params=params, timeout=60)
                response.raise_for_status()
                data = response.json()

                # Handle paginated response
                if isinstance(data, dict):
                    flows = data.get("results", [])
                    cursor = data.get("next_cursor")
                    all_flows.extend(flows)

                    if not cursor or not flows:
                        break
                    page += 1
                    logger.debug(f"Fetched flow page {page}, got {len(flows)} flows, total: {len(all_flows)}")
                else:
                    # Legacy list response
                    all_flows.extend(data if isinstance(data, list) else [])
                    break

            except requests.RequestException as e:
                logger.error(f"Failed to fetch flows (page {page}): {e}")
                break

        if page > 0:
            logger.info(f"Fetched {page + 1} flow pages, total {len(all_flows)} flows")
        return all_flows


class StateManager:
    """Manages persistent state between polling cycles"""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def get_last_alarm_ts(self) -> float:
        """Get timestamp of last processed alarm (in seconds)"""
        state_file = self.state_dir / "last_alarm_ts.txt"
        if state_file.exists():
            try:
                return float(state_file.read_text().strip())
            except ValueError:
                pass
        # Default: 7 days ago for initial backfill (in seconds)
        return (datetime.now() - timedelta(days=7)).timestamp()

    def set_last_alarm_ts(self, ts: int):
        """Save timestamp of last processed alarm"""
        state_file = self.state_dir / "last_alarm_ts.txt"
        state_file.write_text(str(ts))

    def get_last_flow_ts(self) -> float:
        """Get timestamp of last processed flow (in seconds)"""
        state_file = self.state_dir / "last_flow_ts.txt"
        if state_file.exists():
            try:
                return float(state_file.read_text().strip())
            except ValueError:
                pass
        # Default: 1 hour ago for initial fetch
        return (datetime.now() - timedelta(hours=1)).timestamp()

    def set_last_flow_ts(self, ts: float):
        """Save timestamp of last processed flow"""
        state_file = self.state_dir / "last_flow_ts.txt"
        state_file.write_text(str(ts))

    def get_device_baseline(self) -> dict:
        """Get baseline device inventory"""
        state_file = self.state_dir / "device_baseline.json"
        if state_file.exists():
            try:
                return json.loads(state_file.read_text())
            except json.JSONDecodeError:
                pass
        return {}

    def set_device_baseline(self, devices: dict):
        """Save baseline device inventory"""
        state_file = self.state_dir / "device_baseline.json"
        state_file.write_text(json.dumps(devices, indent=2))


class StatusReporter:
    """Reports sync job status to a JSON log for Wazuh monitoring"""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.status_file = self.log_dir / "sidecar-status.json"
        self.stats = {
            "alarms": {"last_success": None, "last_error": None, "items_processed": 0, "error_count": 0},
            "flows": {"last_success": None, "last_error": None, "items_processed": 0, "error_count": 0},
            "devices": {"last_success": None, "last_error": None, "items_processed": 0, "error_count": 0}
        }

    def report_success(self, job_type: str, items_count: int, details: dict = None):
        """Report successful sync job completion"""
        now = datetime.now()
        self.stats[job_type]["last_success"] = now.isoformat()
        self.stats[job_type]["items_processed"] += items_count

        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "msp-poller",
            "job_type": job_type,
            "sync_status": "success",
            "items_count": items_count,
            "total_processed": self.stats[job_type]["items_processed"],
            "error_count": self.stats[job_type]["error_count"]
        }
        if details:
            event["details"] = details

        self._write_event(event)

    def report_error(self, job_type: str, error_msg: str):
        """Report sync job error"""
        now = datetime.now()
        self.stats[job_type]["last_error"] = now.isoformat()
        self.stats[job_type]["error_count"] += 1

        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "msp-poller",
            "job_type": job_type,
            "sync_status": "error",
            "error_message": error_msg,
            "error_count": self.stats[job_type]["error_count"]
        }
        self._write_event(event)

    def report_heartbeat(self):
        """Report periodic heartbeat with overall status"""
        now = datetime.now()
        event = {
            "timestamp": now.isoformat(),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "msp-poller",
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

        # Use smaller size for status logs (10MB)
        max_size = min(MAX_LOG_SIZE, 10 * 1024 * 1024)
        if self.status_file.stat().st_size < max_size:
            return

        # Simple rotation: keep only 1 backup for status
        backup = self.status_file.with_suffix(".json.1")
        if backup.exists():
            backup.unlink()
        self.status_file.rename(backup)
        logger.info(f"Rotated status log {self.status_file}")


class LogWriter:
    """Writes events to JSON log files for Wazuh ingestion"""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def write_alarm(self, alarm: dict):
        """Write alarm event to log file"""
        log_file = self.log_dir / "firewalla-alarms.json"
        event = self._format_alarm(alarm)
        self._append_json(log_file, event)

    def write_device_change(self, change_type: str, device: dict, old_device: dict = None):
        """Write device change event to log file"""
        log_file = self.log_dir / "firewalla-changes.json"
        event = self._format_device_change(change_type, device, old_device)
        self._append_json(log_file, event)

    def write_flow(self, flow: dict):
        """Write flow event to log file"""
        log_file = self.log_dir / "firewalla-flows.json"
        event = self._format_flow(flow)
        self._append_json(log_file, event)

    def _format_flow(self, flow: dict) -> dict:
        """Format flow for Wazuh ingestion using standard data model"""
        source = flow.get("source", {})
        dest = flow.get("destination", {})
        device = flow.get("device", {})
        network = flow.get("network", {})

        # Use original Firewalla timestamp for store-and-forward resilience
        flow_ts = flow.get("ts", 0)
        event_time = datetime.fromtimestamp(flow_ts).isoformat() if flow_ts else datetime.now().isoformat()

        # Use Wazuh standard field names for network data
        return {
            "timestamp": event_time,
            "source": "firewalla-msp",
            "event_type": "flow",
            # Standard Wazuh network fields
            "srcip": source.get("ip", device.get("ip", "")),
            "srcport": source.get("portInfo", {}).get("port", 0),
            "srcuser": source.get("name", device.get("name", "")),  # Device name
            "dstip": dest.get("ip", ""),
            "dstport": dest.get("portInfo", {}).get("port", 0),
            "protocol": flow.get("protocol", ""),
            "url": dest.get("name", ""),  # Full hostname (e.g., notifications-pa.googleapis.com)
            # Firewalla-specific fields (use 'flow' not 'data' to avoid data.data mapping conflict)
            "flow": {
                "srcmac": source.get("id", device.get("id", "")),
                "srctype": source.get("deviceType", device.get("deviceType", "")),
                "domain": flow.get("domain", ""),  # Root domain (e.g., googleapis.com)
                "bytes_in": flow.get("download", 0),
                "bytes_out": flow.get("upload", 0),
                "bytes_total": flow.get("total", 0),
                "duration": flow.get("duration", 0),
                "blocked": flow.get("block", False),
                "blocked_by": flow.get("blockedby", ""),
                "category": flow.get("category", ""),
                "country": flow.get("country", ""),
                "network": network.get("name", ""),
                "flow_ts": flow.get("ts", 0)
            }
        }

    def _format_alarm(self, alarm: dict) -> dict:
        """Format alarm for Wazuh ingestion"""
        # Extract device info if present
        device = alarm.get("device", {})

        # Use original Firewalla timestamp for store-and-forward resilience
        alarm_ts = alarm.get("ts", 0)
        event_time = datetime.fromtimestamp(alarm_ts).isoformat() if alarm_ts else datetime.now().isoformat()

        return {
            "timestamp": event_time,
            "source": "firewalla-msp",
            "event_type": "alarm",
            "alarm_id": alarm.get("aid", ""),
            "alarm_type": alarm.get("_type", alarm.get("type", "")),
            "message": alarm.get("message", ""),
            "severity": alarm.get("severity", "info"),
            "alarm_ts": alarm_ts,
            "device": {
                "name": device.get("name", ""),
                "ip": device.get("ip", ""),
                "mac": device.get("id", ""),
                "vendor": device.get("macVendor", "")
            },
            "raw": alarm
        }

    def _format_device_change(self, change_type: str, device: dict, old_device: dict = None) -> dict:
        """Format device change event for Wazuh ingestion"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "source": "firewalla-msp",
            "event_type": "device_change",
            "change_type": change_type,
            "device": {
                "name": device.get("name", ""),
                "ip": device.get("ip", ""),
                "mac": device.get("id", ""),
                "vendor": device.get("macVendor", ""),
                "online": device.get("online", False),
                "network": device.get("network", {}).get("name", "")
            }
        }

        if old_device:
            event["old_device"] = {
                "name": old_device.get("name", ""),
                "ip": old_device.get("ip", ""),
                "network": old_device.get("network", {}).get("name", "")
            }

        return event

    def _append_json(self, log_file: Path, event: dict):
        """Append JSON event to log file with rotation"""
        self._rotate_if_needed(log_file)
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def _rotate_if_needed(self, log_file: Path):
        """Rotate log file if it exceeds MAX_LOG_SIZE"""
        if not log_file.exists():
            return

        if log_file.stat().st_size < MAX_LOG_SIZE:
            return

        # Rotate: .json -> .json.1 -> .json.2 (delete oldest)
        for i in range(MAX_LOG_BACKUPS, 0, -1):
            old_backup = log_file.with_suffix(f".json.{i}")
            new_backup = log_file.with_suffix(f".json.{i+1}") if i < MAX_LOG_BACKUPS else None

            if old_backup.exists():
                if new_backup:
                    old_backup.rename(new_backup)
                else:
                    old_backup.unlink()  # Delete oldest backup

        # Rotate current file to .json.1
        backup = log_file.with_suffix(".json.1")
        log_file.rename(backup)
        logger.info(f"Rotated {log_file} ({backup.stat().st_size / 1024 / 1024:.1f}MB)")


def wait_for_directories(log_dir: Path, state_dir: Path, timeout: int = 300):
    """Wait for directories to be accessible"""
    start = time.time()

    while True:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            state_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Directories ready: {log_dir}, {state_dir}")
            return True
        except Exception as e:
            if time.time() - start > timeout:
                logger.error(f"Timeout waiting for directories: {e}")
                return False
            logger.warning(f"Waiting for directories... ({e})")
            time.sleep(5)


def poll_alarms(client: FirewallaMSPClient, state: StateManager, writer: LogWriter, status: StatusReporter = None):
    """Poll for new alarms with full pagination support"""
    last_ts = state.get_last_alarm_ts()
    logger.info(f"Polling alarms since {datetime.fromtimestamp(last_ts)}")

    # get_alarms now handles pagination internally and returns flat list
    alarms = client.get_alarms(since_ts=last_ts)

    if not alarms:
        logger.info("No new alarms")
        if status:
            status.report_success("alarms", 0)
        return

    logger.info(f"Retrieved {len(alarms)} total alarms from API")

    # Filter and sort alarms by timestamp (ascending) for proper processing
    valid_alarms = [a for a in alarms if isinstance(a, dict) and a.get("ts", 0) > last_ts]
    valid_alarms.sort(key=lambda a: a.get("ts", 0))

    if not valid_alarms:
        logger.info(f"No new alarms after filtering (all {len(alarms)} were already processed)")
        if status:
            status.report_success("alarms", 0)
        return

    logger.info(f"Found {len(valid_alarms)} new alarms to process")

    max_ts = last_ts
    for alarm in valid_alarms:
        alarm_ts = alarm.get("ts", 0)
        writer.write_alarm(alarm)
        alarm_type = alarm.get("_type", alarm.get("type", "unknown"))
        alarm_msg = alarm.get("message", "")[:50] if alarm.get("message") else ""
        logger.debug(f"Wrote alarm: {alarm_type} @ {datetime.fromtimestamp(alarm_ts)} - {alarm_msg}")
        max_ts = max(max_ts, alarm_ts)

    state.set_last_alarm_ts(max_ts)
    logger.info(f"Processed {len(valid_alarms)} alarms, updated timestamp to {datetime.fromtimestamp(max_ts)}")

    if status:
        status.report_success("alarms", len(valid_alarms))


def poll_devices(client: FirewallaMSPClient, state: StateManager, writer: LogWriter, status: StatusReporter = None):
    """Poll for device inventory changes"""
    logger.info("Polling device inventory")

    devices = client.get_devices()
    if not devices:
        logger.warning("No devices retrieved")
        if status:
            status.report_success("devices", 0)
        return

    # Create lookup by MAC address
    current = {d.get("id"): d for d in devices if d.get("id")}
    baseline = state.get_device_baseline()

    # First run - just establish baseline
    if not baseline:
        logger.info(f"Establishing baseline with {len(current)} devices")
        state.set_device_baseline(current)
        if status:
            status.report_success("devices", len(current), {"action": "baseline_established"})
        return

    changes_count = 0

    # Detect new devices
    for mac, device in current.items():
        if mac not in baseline:
            writer.write_device_change("new_device", device)
            logger.info(f"New device: {device.get('name', mac)}")
            changes_count += 1

    # Detect removed devices
    for mac, device in baseline.items():
        if mac not in current:
            writer.write_device_change("device_removed", device)
            logger.info(f"Device removed: {device.get('name', mac)}")
            changes_count += 1

    # Detect changes (name, IP, network)
    for mac, device in current.items():
        if mac in baseline:
            old = baseline[mac]
            if (device.get("name") != old.get("name") or
                device.get("ip") != old.get("ip") or
                device.get("network", {}).get("name") != old.get("network", {}).get("name")):
                writer.write_device_change("device_changed", device, old)
                logger.info(f"Device changed: {device.get('name', mac)}")
                changes_count += 1

    # Update baseline
    state.set_device_baseline(current)
    logger.info(f"Device inventory updated: {len(current)} devices")

    if status:
        status.report_success("devices", changes_count, {"total_devices": len(current)})


def poll_flows(client: FirewallaMSPClient, state: StateManager, writer: LogWriter, status: StatusReporter = None):
    """Poll for network flows with full pagination support"""
    last_ts = state.get_last_flow_ts()
    logger.info(f"Polling flows since {datetime.fromtimestamp(last_ts)}")

    # get_flows now handles pagination internally and returns flat list
    flows = client.get_flows(since_ts=last_ts)

    if not flows:
        logger.info("No new flows")
        if status:
            status.report_success("flows", 0)
        return

    logger.info(f"Retrieved {len(flows)} total flows from API")

    # Filter for new flows and sort by timestamp (ascending)
    valid_flows = [f for f in flows if isinstance(f, dict) and f.get("ts", 0) > last_ts]
    valid_flows.sort(key=lambda f: f.get("ts", 0))

    if not valid_flows:
        logger.info(f"No new flows after filtering (all {len(flows)} were already processed)")
        if status:
            status.report_success("flows", 0)
        return

    max_ts = last_ts
    blocked_count = 0
    written_count = 0

    for flow in valid_flows:
        flow_ts = flow.get("ts", 0)

        # Only log interesting flows: blocked, high bandwidth, or uncategorized
        is_blocked = flow.get("block", False)
        bytes_total = flow.get("total", 0)
        category = flow.get("category", "")

        # Log: blocked flows, high bandwidth (>1MB), or uncategorized
        should_log = is_blocked or bytes_total > 1000000 or category in ("", "uncategorized")

        if should_log:
            writer.write_flow(flow)
            written_count += 1
            if is_blocked:
                blocked_count += 1

        max_ts = max(max_ts, flow_ts)

    state.set_last_flow_ts(max_ts)
    logger.info(f"Processed {len(valid_flows)} flows ({written_count} written, {blocked_count} blocked), updated timestamp to {datetime.fromtimestamp(max_ts)}")

    if status:
        status.report_success("flows", written_count, {"blocked": blocked_count, "total_new": len(valid_flows)})


def main():
    """Main entry point"""
    # Validate configuration
    if not MSP_DOMAIN or not MSP_TOKEN:
        logger.error("MSP_DOMAIN and MSP_TOKEN environment variables are required")
        sys.exit(1)

    logger.info(f"Starting Firewalla MSP Poller")
    logger.info(f"MSP Domain: {MSP_DOMAIN}")
    logger.info(f"Alarm poll interval: {POLL_INTERVAL_ALARMS}s")
    logger.info(f"Flow poll interval: {POLL_INTERVAL_FLOWS}s")
    logger.info(f"Device poll interval: {POLL_INTERVAL_DEVICES}s")

    # Wait for directories
    if not wait_for_directories(LOG_DIR, STATE_DIR):
        sys.exit(1)

    # Initialize components
    client = FirewallaMSPClient(MSP_DOMAIN, MSP_TOKEN)
    state = StateManager(STATE_DIR)
    writer = LogWriter(LOG_DIR)
    status = StatusReporter(STATUS_DIR)

    # Test API connectivity
    logger.info("Testing API connectivity...")
    boxes = client.get_boxes()
    if boxes:
        logger.info(f"Connected successfully. Found {len(boxes)} Firewalla boxes.")
    else:
        logger.warning("Could not retrieve boxes. Check API credentials.")

    # Polling loop
    last_alarm_poll = 0
    last_flow_poll = 0
    last_device_poll = 0
    last_heartbeat = 0
    heartbeat_interval = 300  # 5 minutes

    while True:
        now = time.time()

        # Poll alarms
        if now - last_alarm_poll >= POLL_INTERVAL_ALARMS:
            try:
                poll_alarms(client, state, writer, status)
            except Exception as e:
                logger.error(f"Alarm polling failed: {e}")
                status.report_error("alarms", str(e))
            last_alarm_poll = now

        # Poll flows
        if now - last_flow_poll >= POLL_INTERVAL_FLOWS:
            try:
                poll_flows(client, state, writer, status)
            except Exception as e:
                logger.error(f"Flow polling failed: {e}")
                status.report_error("flows", str(e))
            last_flow_poll = now

        # Poll devices
        if now - last_device_poll >= POLL_INTERVAL_DEVICES:
            try:
                poll_devices(client, state, writer, status)
            except Exception as e:
                logger.error(f"Device polling failed: {e}")
                status.report_error("devices", str(e))
            last_device_poll = now

        # Send heartbeat
        if now - last_heartbeat >= heartbeat_interval:
            status.report_heartbeat()
            last_heartbeat = now

        # Sleep before next cycle
        time.sleep(30)


if __name__ == "__main__":
    main()
