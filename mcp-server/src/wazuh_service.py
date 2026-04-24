"""Domain logic for Wazuh SIEM queries. No MCP imports — reusable by any UI."""
from typing import Any

from src.time_range import parse_time_range


ALERTS_INDEX_DEFAULT = "wazuh-alerts-*"
HARD_RESULT_CAP = 100


class WazuhDataService:
    """One public method per MCP tool. Stateless."""

    def __init__(self, client, alerts_index: str = ALERTS_INDEX_DEFAULT):
        self._client = client
        self._alerts_index = alerts_index

    # ---------- helpers ----------

    def _time_filter(self, time_range: str) -> dict[str, Any]:
        return {"range": {"@timestamp": parse_time_range(time_range)}}

    def _build_filter_clauses(
        self, filters: dict[str, Any] | None, time_range: str
    ) -> list[dict[str, Any]]:
        clauses: list[dict[str, Any]] = [self._time_filter(time_range)]
        for k, v in (filters or {}).items():
            if isinstance(v, list):
                clauses.append({"terms": {k: v}})
            else:
                clauses.append({"term": {k: v}})
        return clauses

    def _shape_hit(self, hit: dict[str, Any]) -> dict[str, Any]:
        src = hit.get("_source", {})
        return {
            "id": hit["_id"],
            "@timestamp": src.get("@timestamp"),
            "agent": src.get("agent", {}),
            "rule": src.get("rule", {}),
            "data": src.get("data", {}),
        }

    # ---------- tools ----------

    def search_alerts(
        self,
        time_range: str,
        filters: dict[str, Any] | None = None,
        lucene: str | None = None,
        sort_by: str = "@timestamp",
        limit: int = 25,
    ) -> dict[str, Any]:
        if not filters and not lucene:
            raise ValueError("one of filters or lucene is required")
        size = min(limit, HARD_RESULT_CAP)
        must: list[dict[str, Any]] = []
        if lucene:
            must.append({"query_string": {"query": lucene}})
        body: dict[str, Any] = {
            "size": size,
            "sort": [{sort_by: "desc"}],
            "query": {
                "bool": {
                    "must": must,
                    "filter": self._build_filter_clauses(filters, time_range),
                }
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        total = resp["hits"]["total"]["value"]
        rows = [self._shape_hit(h) for h in resp["hits"]["hits"]]
        return {
            "results": rows,
            "total_matched": total,
            "truncated": total > len(rows),
        }

    def aggregate_alerts(
        self,
        group_by_field: str,
        time_range: str,
        filters: dict[str, Any] | None = None,
        top_n: int = 10,
    ) -> dict[str, Any]:
        size = min(top_n, 50)  # hard cap on bucket count
        body = {
            "size": 0,
            "query": {
                "bool": {"filter": self._build_filter_clauses(filters, time_range)}
            },
            "aggs": {
                "by_field": {"terms": {"field": group_by_field, "size": size}}
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        buckets = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in resp["aggregations"]["by_field"]["buckets"]
        ]
        return {
            "buckets": buckets,
            "total_in_scope": resp["hits"]["total"]["value"],
            "time_range": time_range,
        }

    def alert_overview(self, time_range: str) -> dict[str, Any]:
        # NOTE: `data.source` is populated by our sidecars (firewalla-msp,
        # windows-srp, threat-intel) but NOT by native OSSEC/syscheck rules.
        # We pair it with a rule-groups breakdown so OSSEC/syscheck events
        # remain visible even though they fall into the "unknown" source bucket.
        body = {
            "size": 0,
            "query": {
                "bool": {"filter": self._build_filter_clauses(None, time_range)}
            },
            "aggs": {
                "by_source": {
                    "terms": {"field": "data.source", "size": 10, "missing": "unknown"}
                },
                "by_severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "from": 0, "to": 4},
                            {"key": "medium", "from": 4, "to": 8},
                            {"key": "high", "from": 8, "to": 16},
                        ],
                    }
                },
                "top_rule_groups": {"terms": {"field": "rule.groups", "size": 10}},
                "top_agents": {"terms": {"field": "agent.name", "size": 10}},
                "top_src_ips": {"terms": {"field": "data.srcip", "size": 10}},
                "top_dst_ips": {"terms": {"field": "data.dstip", "size": 10}},
                "threat_intel_hits": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                                {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
                            ]
                        }
                    }
                },
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        aggs = resp["aggregations"]

        severity_keymap = {"low": "low (0-3)", "medium": "medium (4-7)", "high": "high (8-12)"}
        return {
            "total_alerts": resp["hits"]["total"]["value"],
            "by_source": {b["key"]: b["doc_count"] for b in aggs["by_source"]["buckets"]},
            "by_severity": {
                severity_keymap[b["key"]]: b["doc_count"]
                for b in aggs["by_severity"]["buckets"]
            },
            "top_rule_groups": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_rule_groups"]["buckets"]
            ],
            "top_agents": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_agents"]["buckets"]
            ],
            "top_src_ips": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_src_ips"]["buckets"]
            ],
            "top_dst_ips": [
                {"key": b["key"], "count": b["doc_count"]}
                for b in aggs["top_dst_ips"]["buckets"]
            ],
            "threat_intel_hits": aggs["threat_intel_hits"]["doc_count"],
            "time_range": time_range,
        }
