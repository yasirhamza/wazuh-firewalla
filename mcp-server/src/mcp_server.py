"""FastMCP app factory + tool definitions.

Tools are thin adapters over WazuhDataService. Each tool declares individual
arguments (NOT a single Pydantic-model wrapper) so FastMCP produces a flat
JSON schema that Claude Code and other MCP clients call naturally.

Bearer-token auth is enforced by a starlette middleware in main.py, BEFORE
tool code runs. By the time a tool function is entered, the request is already
authenticated.
"""
import logging
import uuid
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from src.limits import RateLimitExceeded, RateLimiter
from src.time_range import TimeRangeError
from src.wazuh_client import WazuhClientError
from src.wazuh_service import AlertNotFound, WazuhDataService

logger = logging.getLogger(__name__)

SOURCES_DESC = (
    "Data sources present in `data.source` (sidecar-generated events): "
    "'firewalla-msp' (network alarms/flows), "
    "'windows-srp' (executable allow/block on Windows endpoints), "
    "'threat-intel' (CDB-list matches from rules 100450-100453). "
    "Native Wazuh events (OSSEC host, syscheck/FIM, built-in malicious-ioc "
    "99901-99999) do NOT populate `data.source` — they are filterable via "
    "`rule.groups` and `rule.id`."
)

COMMON_FIELDS_DESC = (
    "Common searchable fields: agent.name, agent.id, agent.ip, "
    "rule.id, rule.level, rule.groups, data.source, data.srcip, data.dstip, "
    "data.srp.target_path, data.srp.user, data.win.eventdata.user."
)


def startup_self_check(client, alerts_index: str) -> None:
    if not client.ping():
        raise RuntimeError("OpenSearch ping failed at startup")
    try:
        client.count(index=alerts_index, body={"query": {"match_all": {}}})
    except Exception as e:
        raise RuntimeError(f"OpenSearch query self-check failed: {e}")
    logger.info("startup self-check ok")


# ---------- Error envelope ----------

def _envelope(code: str, message: str, **extra) -> dict[str, Any]:
    out = {"error": code, "message": message}
    out.update(extra)
    return out


_PARSER_HINT = (
    "Check field names and Lucene syntax. Common fields: "
    "agent.name, rule.id, rule.level, rule.groups, data.source, "
    "data.srcip, data.dstip, data.srp.target_path."
)


def _classify_client_error(e: WazuhClientError) -> str:
    """Map ambiguous client errors to spec error codes.

    OpenSearch returns DSL parser errors via TransportError — our client wraps
    them as 'opensearch_unavailable', but they really are 'invalid_query'. We
    sniff the message for common parser markers.
    """
    if e.code != "opensearch_unavailable":
        return e.code
    msg = (e.message or "").lower()
    if any(m in msg for m in (
        "parse_exception", "parsing_exception", "no mapping found",
        "x_content_parse_exception", "illegal_argument_exception: field",
    )):
        return "invalid_query"
    return "opensearch_unavailable"


def _wrap_call(tool_name: str, rate_limiter: RateLimiter, fn) -> Any:
    """Single-bucket rate limit + error envelope.

    Rate limit is global for MVP (single authenticated user = single key). If
    multi-user auth is added later, switch the rate-limit key to something per-
    caller (e.g., hashed presented token, exposed via FastMCP Context).
    """
    req_id = uuid.uuid4().hex[:8]
    try:
        rate_limiter.check("global")
    except RateLimitExceeded as e:
        logger.warning("rate_limited tool=%s", tool_name)
        return _envelope("rate_limited", str(e), retry_after=e.retry_after)
    try:
        result = fn()
        logger.info("tool_ok", extra={"tool": tool_name, "req_id": req_id})
        return result
    except TimeRangeError as e:
        return _envelope("invalid_input", str(e), field="time_range")
    except AlertNotFound as e:
        return _envelope("not_found", str(e))
    except WazuhClientError as e:
        code = _classify_client_error(e)
        if code == "timeout":
            return _envelope("timeout", e.message,
                             time_range_hint="try a narrower time_range or reduce top_n")
        if code == "invalid_query":
            return _envelope("invalid_query", e.message, hint=_PARSER_HINT)
        logger.error("client_error",
                     extra={"tool": tool_name, "req_id": req_id, "code": code})
        return _envelope(code, e.message)
    except ValueError as e:  # tool-level validation (e.g., unknown entity_type)
        return _envelope("invalid_input", str(e))
    except Exception:  # defense in depth
        logger.exception("internal tool=%s req_id=%s", tool_name, req_id)
        return _envelope("internal", "unexpected error", request_id=req_id)


# ---------- App factory ----------

def build_app(service: WazuhDataService, rate_limiter: RateLimiter) -> FastMCP:
    app = FastMCP("wazuh-mcp")

    # --- search_alerts ---
    @app.tool(
        description=(
            "Find individual Wazuh alerts matching structured filters or a "
            "Lucene query. Returns up to `limit` records. "
            + SOURCES_DESC + " " + COMMON_FIELDS_DESC
        ),
    )
    def search_alerts(
        time_range: Annotated[str, Field(
            description="'last_24h', 'last_7d', 'last_30d', or ISO range 'START/END'")],
        filters: Annotated[dict[str, Any] | None, Field(
            description="Structured filters: {field: value} or {field: [values]}. "
                        "Either `filters` or `lucene` is required.")] = None,
        lucene: Annotated[str | None, Field(
            description="Lucene query string. Alternative to `filters`.")] = None,
        sort_by: Annotated[Literal["@timestamp", "rule.level"], Field()] = "@timestamp",
        limit: Annotated[int, Field(ge=1, le=100)] = 25,
    ) -> dict[str, Any]:
        # The service applies min(limit, HARD_RESULT_CAP) and emits its own
        # `truncated` flag — don't re-cap here (that overwrote the service's
        # contract and double-truncated in ways the service couldn't see).
        return _wrap_call("search_alerts", rate_limiter, lambda: service.search_alerts(
            time_range=time_range, filters=filters, lucene=lucene,
            sort_by=sort_by, limit=limit,
        ))

    # --- aggregate_alerts ---
    @app.tool(
        description=(
            "Group-and-count alerts by any field (e.g. rule.groups, agent.name, "
            "data.source). Returns top-N buckets. " + COMMON_FIELDS_DESC
        ),
    )
    def aggregate_alerts(
        group_by_field: Annotated[str, Field(description="Field to group by.")],
        time_range: Annotated[str, Field()],
        filters: Annotated[dict[str, Any] | None, Field()] = None,
        top_n: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> dict[str, Any]:
        return _wrap_call("aggregate_alerts", rate_limiter, lambda: service.aggregate_alerts(
            group_by_field=group_by_field, time_range=time_range,
            filters=filters, top_n=top_n,
        ))

    # --- alert_overview ---
    @app.tool(
        description=(
            "Pre-canned dashboard in JSON: totals, per-source breakdown (plus "
            "an 'unknown' bucket for native OSSEC/syscheck events), severity "
            "distribution, top rule groups / agents / IPs, threat-intel hit "
            "count. One call answers 'what's going on?'. " + SOURCES_DESC
        ),
    )
    def alert_overview(
        time_range: Annotated[str, Field()],
    ) -> dict[str, Any]:
        return _wrap_call("alert_overview", rate_limiter,
                          lambda: service.alert_overview(time_range=time_range))

    # --- trend_delta ---
    @app.tool(
        description=(
            "Compare a metric between two windows to surface trends (e.g. "
            "'DNS alerts 3x week-over-week'). Returns current/prior counts and "
            "top-N movers."
        ),
    )
    def trend_delta(
        metric: Annotated[Literal[
            "total_alerts", "alerts_by_source", "alerts_by_rule_group",
            "alerts_by_agent", "threat_intel_hits",
        ], Field()],
        current_window: Annotated[str, Field()],
        prior_window: Annotated[str, Field()],
        filters: Annotated[dict[str, Any] | None, Field()] = None,
        top_n: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> dict[str, Any]:
        return _wrap_call("trend_delta", rate_limiter, lambda: service.trend_delta(
            metric=metric, current_window=current_window,
            prior_window=prior_window, filters=filters, top_n=top_n,
        ))

    # --- threat_intel_matches ---
    @app.tool(
        description=(
            "Return recent threat-intel matches (rules 100450-100453 + built-in "
            "malicious-ioc 99901-99999), joined with source agent and IPs."
        ),
    )
    def threat_intel_matches(
        time_range: Annotated[str, Field()],
        list_filter: Annotated[Literal[
            "firewalla-c2", "urlhaus", "malware-hashes",
            "malicious-ip", "malicious-domains", "all",
        ], Field()] = "all",
    ) -> dict[str, Any]:
        return _wrap_call("threat_intel_matches", rate_limiter,
                          lambda: service.threat_intel_matches(
                              time_range=time_range, list_filter=list_filter))

    # --- sidecar_health ---
    @app.tool(
        description=(
            "Report health of data-collection sidecars (msp-poller, threat-intel, "
            "wazuh-mcp itself). Useful when queries return empty or stale data."
        ),
    )
    def sidecar_health() -> dict[str, Any]:
        return _wrap_call("sidecar_health", rate_limiter, service.sidecar_health)

    # --- get_alert ---
    @app.tool(
        description="Fetch full detail of one alert by _id. Returns 'not_found' if missing.",
    )
    def get_alert(
        alert_id: Annotated[str, Field(description="The _id of the alert.")],
    ) -> dict[str, Any]:
        return _wrap_call("get_alert", rate_limiter,
                          lambda: service.get_alert(alert_id=alert_id))

    # --- entity_activity ---
    @app.tool(
        description=(
            "Multi-source pivot on one entity. entity_type is one of: "
            "ip, agent, device, user, process, hash, domain. Returns total "
            "count, source breakdown, first/last seen, related agents, and "
            "5 recent samples."
        ),
    )
    def entity_activity(
        entity_type: Annotated[Literal[
            "ip", "agent", "device", "user", "process", "hash", "domain",
        ], Field()],
        entity_value: Annotated[str, Field()],
        time_range: Annotated[str, Field()],
        top_n: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> dict[str, Any]:
        return _wrap_call("entity_activity", rate_limiter,
                          lambda: service.entity_activity(
                              entity_type=entity_type, entity_value=entity_value,
                              time_range=time_range, top_n=top_n,
                          ))

    return app
