"""Shared pytest fixtures."""
import pytest


@pytest.fixture
def sample_alert():
    """A minimal Wazuh alert document, shape-accurate for our tools."""
    return {
        "_id": "alert-abc-123",
        "_source": {
            "@timestamp": "2026-04-24T12:00:00.000Z",
            "timestamp": "2026-04-24T12:00:00.000Z",
            "agent": {"id": "001", "name": "kids-laptop", "ip": "192.0.2.50"},
            "rule": {
                "id": "100651",
                "level": 3,
                "description": "SRP allowed executable launch",
                "groups": ["windows", "srp"],
            },
            "data": {
                "source": "windows-srp",
                "srp": {
                    "action": "ALLOWED",
                    "target_path": "C:\\Windows\\system32\\notepad.exe",
                    "user": "alice",
                },
            },
        },
    }
