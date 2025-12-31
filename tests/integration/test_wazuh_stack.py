#!/usr/bin/env python3
"""
Wazuh-Firewalla Integration Tests

Tests the complete Wazuh stack including:
- Container health and connectivity
- Wazuh rule matching via wazuh-logtest
- Event flow from sidecars to OpenSearch
- API endpoints

Based on integration-testing skill patterns from skillsmp.com
"""

import os
import json
import subprocess
import pytest

# Container names
WAZUH_MANAGER = "single-node-wazuh.manager-1"
WAZUH_INDEXER = "single-node-wazuh.indexer-1"
MSP_POLLER = "single-node-msp-poller"
THREAT_INTEL = "single-node-threat-intel"

# Credentials from environment (default matches docker-compose.yml)
INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD", "55uF3wo466JMScZV")


def docker_exec(container: str, command: list) -> subprocess.CompletedProcess:
    """Execute command in Docker container using subprocess.run with list args"""
    return subprocess.run(
        ["docker", "exec", container] + command,
        capture_output=True,
        text=True,
        timeout=60
    )


def docker_exec_shell(container: str, shell_cmd: str) -> subprocess.CompletedProcess:
    """Execute shell command in Docker container"""
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", shell_cmd],
        capture_output=True,
        text=True,
        timeout=60
    )


class TestContainerHealth:
    """Test that all containers are running and healthy"""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Verify Docker is available"""
        result = subprocess.run(["docker", "ps"], capture_output=True)
        if result.returncode != 0:
            pytest.skip("Docker not available")

    def test_wazuh_manager_running(self):
        """Verify Wazuh manager container is running"""
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={WAZUH_MANAGER}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, f"Manager not running: {result.stdout}"

    def test_wazuh_indexer_running(self):
        """Verify Wazuh indexer container is running"""
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={WAZUH_INDEXER}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, f"Indexer not running: {result.stdout}"

    def test_msp_poller_running(self):
        """Verify MSP poller sidecar is running"""
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={MSP_POLLER}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, f"MSP poller not running: {result.stdout}"

    def test_threat_intel_running(self):
        """Verify threat-intel sidecar is running"""
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={THREAT_INTEL}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, f"Threat-intel not running: {result.stdout}"

    def test_wazuh_manager_healthy(self):
        """Verify Wazuh manager core services are running"""
        result = docker_exec(WAZUH_MANAGER, ["/var/ossec/bin/wazuh-control", "status"])
        # Note: returncode may be 1 if optional services (clusterd, maild) aren't running
        # We only check core services are running
        assert "wazuh-analysisd is running" in result.stdout
        assert "wazuh-logcollector is running" in result.stdout
        assert "wazuh-remoted is running" in result.stdout


class TestWazuhRules:
    """Test Wazuh rule matching with wazuh-logtest"""

    def test_sidecar_status_rule_match(self):
        """Test sidecar status events match rule 100500+"""
        test_event = json.dumps({
            "timestamp": "2025-01-01T00:00:00.000000",
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": "msp-poller",
            "job_type": "alarms",
            "sync_status": "success",
            "items_count": 0
        })

        result = subprocess.run(
            ["docker", "exec", "-i", WAZUH_MANAGER, "/var/ossec/bin/wazuh-logtest"],
            input=test_event,
            capture_output=True,
            text=True,
            timeout=30
        )

        # wazuh-logtest writes to stderr, not stdout
        output = result.stderr
        assert "Phase 3: Completed filtering (rules)" in output
        # Should match sidecar rules 100500-100504
        assert any(rid in output for rid in ["100500", "100501", "100502", "100503"])

    def test_srp_allowed_rule_match(self):
        """Test Windows SRP allowed event matches decoder and SRP rules"""
        test_event = 'svchost.exe (PID = 1234) identified C:\\Windows\\system32\\notepad.exe as Unrestricted using path rule, Guid = {test-guid}'

        result = subprocess.run(
            ["docker", "exec", "-i", WAZUH_MANAGER, "/var/ossec/bin/wazuh-logtest"],
            input=test_event,
            capture_output=True,
            text=True,
            timeout=30
        )

        # wazuh-logtest writes to stderr
        output = result.stderr
        assert "windows-srp" in output  # Decoder match
        # May hit 100651 (allowed) or 100660 (new executable) depending on baseline
        assert any(rid in output for rid in ["100651", "100660"])

    def test_srp_blocked_rule_match(self):
        """Test Windows SRP blocked event matches blocked rules"""
        test_event = 'explorer.exe (PID = 5678) identified C:\\Users\\test\\malware.exe as Disallowed using path rule, Guid = {test-guid}'

        result = subprocess.run(
            ["docker", "exec", "-i", WAZUH_MANAGER, "/var/ossec/bin/wazuh-logtest"],
            input=test_event,
            capture_output=True,
            text=True,
            timeout=30
        )

        # wazuh-logtest writes to stderr
        output = result.stderr
        assert "windows-srp" in output
        # 100652 (generic blocked) or 100653 (blocked in user profile)
        assert any(rid in output for rid in ["100652", "100653"])


class TestSidecarStatus:
    """Test sidecar containers are producing status events"""

    def test_msp_poller_status_file_exists(self):
        """Verify MSP poller writes to status file"""
        result = docker_exec(MSP_POLLER, ["ls", "-la", "/status/sidecar-status.json"])
        assert "sidecar-status.json" in result.stdout

    def test_msp_poller_recent_events(self):
        """Check MSP poller has recent status events"""
        result = docker_exec_shell(MSP_POLLER, "tail -1 /status/sidecar-status.json")
        assert result.returncode == 0
        event = json.loads(result.stdout)
        assert event["sidecar"] == "msp-poller"
        assert "timestamp" in event

    def test_threat_intel_lists_exist(self):
        """Verify threat intel CDB lists are created"""
        result = docker_exec(THREAT_INTEL, ["ls", "/lists/"])
        assert "feodo-ips" in result.stdout or "threatfox-ips" in result.stdout


class TestOpenSearchIntegration:
    """Test OpenSearch indexer connectivity and data"""

    def test_indexer_health(self):
        """Check OpenSearch cluster health"""
        result = docker_exec_shell(
            WAZUH_INDEXER,
            f"curl -sk -u {INDEXER_USER}:{INDEXER_PASSWORD} https://localhost:9200/_cluster/health"
        )
        assert result.returncode == 0
        health = json.loads(result.stdout)
        assert health["status"] in ["green", "yellow"]

    def test_wazuh_alerts_index_exists(self):
        """Verify wazuh-alerts index pattern exists"""
        result = docker_exec_shell(
            WAZUH_INDEXER,
            f"curl -sk -u {INDEXER_USER}:{INDEXER_PASSWORD} 'https://localhost:9200/_cat/indices/wazuh-alerts-*?format=json'"
        )
        assert result.returncode == 0
        indices = json.loads(result.stdout)
        assert len(indices) > 0, "No wazuh-alerts indices found"


class TestEventFlow:
    """Test end-to-end event flow through the stack"""

    def test_sidecar_events_reaching_alerts(self):
        """Verify sidecar status events are being indexed as alerts"""
        result = docker_exec_shell(
            WAZUH_MANAGER,
            "grep 'sidecar_status' /var/ossec/logs/alerts/alerts.json | tail -1"
        )
        if result.stdout.strip():
            event = json.loads(result.stdout)
            assert "rule" in event
            assert event["rule"]["id"] in ["100500", "100501", "100502", "100503", "100504"]

    def test_logcollector_monitoring_files(self):
        """Verify logcollector is reading monitored files"""
        result = docker_exec(
            WAZUH_MANAGER,
            ["cat", "/var/ossec/var/run/wazuh-logcollector.state"]
        )
        assert result.returncode == 0
        state = json.loads(result.stdout)

        # Check that sidecar-status is being monitored
        files = state.get("global", {}).get("files", [])
        sidecar_files = [f for f in files if "sidecar-status" in f.get("location", "")]
        assert len(sidecar_files) > 0, "Sidecar status file not being monitored"


class TestConfiguration:
    """Test configuration files are properly loaded"""

    def test_ossec_conf_exists(self):
        """Verify ossec.conf is present"""
        result = docker_exec(WAZUH_MANAGER, ["ls", "-la", "/var/ossec/etc/ossec.conf"])
        assert "ossec.conf" in result.stdout

    def test_custom_rules_loaded(self):
        """Verify custom rules are loaded"""
        result = docker_exec(WAZUH_MANAGER, ["ls", "/var/ossec/etc/rules/"])
        assert "firewalla_rules.xml" in result.stdout
        assert "windows_srp_rules.xml" in result.stdout

    def test_custom_decoders_loaded(self):
        """Verify custom decoders are loaded"""
        result = docker_exec(WAZUH_MANAGER, ["ls", "/var/ossec/etc/decoders/"])
        assert "firewalla_decoders.xml" in result.stdout
        assert "windows_srp_decoders.xml" in result.stdout

    def test_cdb_lists_loaded(self):
        """Verify CDB lists are accessible"""
        result = docker_exec(WAZUH_MANAGER, ["ls", "/var/ossec/etc/lists/srp/"])
        assert "srp_baseline" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
