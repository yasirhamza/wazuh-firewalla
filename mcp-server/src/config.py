"""Settings loader with required-var validation."""
import os
from dataclasses import dataclass


REQUIRED = ("MCP_OS_USER", "MCP_OS_PASSWORD", "MCP_API_KEY", "OPENSEARCH_URL")


@dataclass(frozen=True)
class Settings:
    os_user: str
    os_password: str
    api_key: str
    http_port: int
    opensearch_url: str
    max_log_size: int
    max_log_backups: int
    rate_limit_per_min: int
    rate_limit_burst: int


def load_settings() -> Settings:
    missing = [v for v in REQUIRED if not os.environ.get(v)]
    if missing:
        raise ValueError(f"Missing required env vars: {', '.join(missing)}")
    return Settings(
        os_user=os.environ["MCP_OS_USER"],
        os_password=os.environ["MCP_OS_PASSWORD"],
        api_key=os.environ["MCP_API_KEY"],
        http_port=int(os.environ.get("MCP_HTTP_PORT", "8800")),
        opensearch_url=os.environ["OPENSEARCH_URL"],
        max_log_size=int(os.environ.get("MAX_LOG_SIZE", str(10 * 1024 * 1024))),
        max_log_backups=int(os.environ.get("MAX_LOG_BACKUPS", "2")),
        rate_limit_per_min=int(os.environ.get("RATE_LIMIT_PER_MIN", "60")),
        rate_limit_burst=int(os.environ.get("RATE_LIMIT_BURST", "10")),
    )
