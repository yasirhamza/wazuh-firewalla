"""Parse user-friendly time_range strings into OpenSearch date-math dicts."""
from datetime import datetime, timezone


SHORTHAND = {
    # Current windows.
    "last_1h": {"gte": "now-1h/h", "lte": "now"},
    "last_6h": {"gte": "now-6h/h", "lte": "now"},
    "last_24h": {"gte": "now-24h/h", "lte": "now"},
    "last_7d": {"gte": "now-7d/d", "lte": "now"},
    "last_30d": {"gte": "now-30d/d", "lte": "now"},
    "last_90d": {"gte": "now-90d/d", "lte": "now"},
    # Prior (disjoint) windows — pair with the matching current window in
    # trend_delta for meaningful period-over-period comparisons. e.g.
    # current_window="last_7d", prior_window="last_prior_7d" gives a real
    # week-over-week delta.
    "last_prior_24h": {"gte": "now-48h/h", "lte": "now-24h/h"},
    "last_prior_7d": {"gte": "now-14d/d", "lte": "now-7d/d"},
    "last_prior_30d": {"gte": "now-60d/d", "lte": "now-30d/d"},
    "last_prior_90d": {"gte": "now-180d/d", "lte": "now-90d/d"},
}

MAX_SPAN_DAYS = 90


class TimeRangeError(ValueError):
    """Raised for malformed or out-of-bounds time_range inputs."""


def parse_time_range(value: str) -> dict[str, str]:
    if value in SHORTHAND:
        return SHORTHAND[value]
    if "/" in value:
        try:
            start_s, end_s = value.split("/", 1)
            start = datetime.fromisoformat(start_s.replace("Z", "+00:00"))
            end = datetime.fromisoformat(end_s.replace("Z", "+00:00"))
        except ValueError as e:
            raise TimeRangeError(f"malformed iso range: {e}") from e
        if end <= start:
            raise TimeRangeError("end must be before start")
        span = (end - start).total_seconds() / 86400
        if span > MAX_SPAN_DAYS:
            raise TimeRangeError(f"time range exceeds 90 days (got {span:.1f}d)")
        return {"gte": start_s, "lte": end_s}
    raise TimeRangeError(
        f"unsupported time_range: {value!r}. Use shorthand ({', '.join(SHORTHAND)}) "
        "or an ISO-8601 range 'START/END'."
    )
