"""Tests for config loading."""
import os

import pytest

from src.config import Settings, load_settings


def test_load_settings_from_env(monkeypatch):
    monkeypatch.setenv("MCP_OS_USER", "mcp_read")
    monkeypatch.setenv("MCP_OS_PASSWORD", "secret")
    monkeypatch.setenv("MCP_API_KEY", "api-key-xyz")
    monkeypatch.setenv("MCP_HTTP_PORT", "8800")
    monkeypatch.setenv("OPENSEARCH_URL", "https://wazuh.indexer:9200")

    settings = load_settings()

    assert isinstance(settings, Settings)
    assert settings.os_user == "mcp_read"
    assert settings.os_password == "secret"
    assert settings.api_key == "api-key-xyz"
    assert settings.http_port == 8800
    assert settings.opensearch_url == "https://wazuh.indexer:9200"


def test_load_settings_defaults(monkeypatch):
    for var in ("MCP_OS_USER", "MCP_OS_PASSWORD", "MCP_API_KEY", "OPENSEARCH_URL"):
        monkeypatch.setenv(var, "x")
    # defaults should fill in
    settings = load_settings()
    assert settings.http_port == 8800
    assert settings.max_log_size == 10 * 1024 * 1024
    assert settings.max_log_backups == 2
    assert settings.rate_limit_per_min == 60
    assert settings.rate_limit_burst == 10


def test_load_settings_missing_required(monkeypatch):
    monkeypatch.delenv("MCP_OS_USER", raising=False)
    monkeypatch.delenv("MCP_OS_PASSWORD", raising=False)
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    with pytest.raises(ValueError, match="MCP_OS_USER"):
        load_settings()
