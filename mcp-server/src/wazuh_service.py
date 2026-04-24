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

    _METRIC_FIELD = {
        "total_alerts": None,  # pure count, no agg field
        "alerts_by_source": "data.source",
        "alerts_by_rule_group": "rule.groups",
        "alerts_by_agent": "agent.name",
        "threat_intel_hits": None,  # count of TI-rule matches
    }

    def _count_or_group(
        self,
        time_range: str,
        metric: str,
        filters: dict[str, Any] | None,
        top_n: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return (total, groups). Groups is [] when metric has no group field."""
        clauses = self._build_filter_clauses(filters, time_range)
        if metric == "threat_intel_hits":
            clauses.append({
                "bool": {"should": [
                    {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                    {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
                ]}
            })
        body: dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"filter": clauses}},
            "track_total_hits": True,
        }
        field = self._METRIC_FIELD[metric]
        if field is not None:
            body["aggs"] = {"by_field": {"terms": {"field": field, "size": min(top_n, 50)}}}
        resp = self._client.search(index=self._alerts_index, body=body)
        total = resp["hits"]["total"]["value"]
        groups = []
        if field is not None:
            groups = [
                {"key": b["key"], "count": b["doc_count"]}
                for b in resp["aggregations"]["by_field"]["buckets"]
            ]
        return total, groups

    @staticmethod
    def _pct_change(current: int, prior: int) -> float | None:
        if prior == 0:
            return None
        return round((current - prior) / prior * 100.0, 2)

    def trend_delta(
        self,
        metric: str,
        current_window: str,
        prior_window: str,
        filters: dict[str, Any] | None = None,
        top_n: int = 10,
    ) -> dict[str, Any]:
        if metric not in self._METRIC_FIELD:
            raise ValueError(f"unknown metric: {metric}")
        cur_total, cur_groups = self._count_or_group(current_window, metric, filters, top_n)
        pri_total, pri_groups = self._count_or_group(prior_window, metric, filters, top_n)

        out: dict[str, Any] = {
            "metric": metric,
            "current_window": current_window,
            "prior_window": prior_window,
            "current": cur_total,
            "prior": pri_total,
            "delta_pct": self._pct_change(cur_total, pri_total),
        }
        if cur_groups or pri_groups:
            pri_map = {g["key"]: g["count"] for g in pri_groups}
            cur_map = {g["key"]: g["count"] for g in cur_groups}
            keys = set(pri_map) | set(cur_map)
            movers = [
                {
                    "key": k,
                    "current": cur_map.get(k, 0),
                    "prior": pri_map.get(k, 0),
                    "delta_abs": cur_map.get(k, 0) - pri_map.get(k, 0),
                    "delta_pct": self._pct_change(cur_map.get(k, 0), pri_map.get(k, 0)),
                }
                for k in keys
            ]
            movers.sort(key=lambda m: abs(m["delta_abs"]), reverse=True)
            out["movers"] = movers[:top_n]
        return out

    def threat_intel_matches(
        self,
        time_range: str,
        list_filter: str = "all",
        top_n: int = 100,
    ) -> dict[str, Any]:
        ti_filter = {
            "bool": {"should": [
                {"terms": {"rule.id": ["100450", "100451", "100452", "100453"]}},
                {"range": {"rule.id": {"gte": "99901", "lte": "99999"}}},
            ]}
        }
        clauses = self._build_filter_clauses(None, time_range)
        if list_filter and list_filter != "all":
            clauses.append({"term": {"data.threat_intel.list": list_filter}})
        clauses.append(ti_filter)

        body = {
            "size": min(top_n, HARD_RESULT_CAP),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": clauses}},
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        matches = []
        for h in resp["hits"]["hits"]:
            src = h.get("_source", {})
            ti = src.get("data", {}).get("threat_intel", {})
            matches.append({
                "id": h["_id"],
                "@timestamp": src.get("@timestamp"),
                "list": ti.get("list"),
                "ioc": ti.get("ioc"),
                "agent": src.get("agent", {}).get("name"),
                "src_ip": src.get("data", {}).get("srcip"),
                "dst_ip": src.get("data", {}).get("dstip"),
                "rule_id": src.get("rule", {}).get("id"),
            })
        return {"matches": matches, "total": resp["hits"]["total"]["value"]}
