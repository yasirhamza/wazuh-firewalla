"""Domain logic for Wazuh SIEM queries. No MCP imports — reusable by any UI."""
import json
import time as _time
from datetime import datetime
from pathlib import Path
from typing import Any

from src.time_range import parse_time_range

# Module-level alias so tests can monkeypatch src.wazuh_service.time.
time = _time


ALERTS_INDEX_DEFAULT = "wazuh-alerts-*"
HARD_RESULT_CAP = 100


class AlertNotFound(LookupError):
    """Raised when get_alert cannot find the requested alert_id."""


class WazuhDataService:
    """One public method per MCP tool. Stateless."""

    def __init__(
        self,
        client,
        alerts_index: str = ALERTS_INDEX_DEFAULT,
        status_file: Path | None = None,
    ):
        self._client = client
        self._alerts_index = alerts_index
        self._status_file = Path(status_file) if status_file else None

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

    _STALE_SECONDS = 300  # 5 min; spec §5 says >5min stale triggers rule 100504

    # Read up to this many trailing bytes — enough to cover many minutes of
    # heartbeats even in a busy stream.
    _TAIL_BYTES = 256 * 1024

    def sidecar_health(self) -> dict[str, Any]:
        now = time.time()
        latest: dict[str, dict[str, Any]] = {}

        if self._status_file and self._status_file.exists():
            data = self._tail_read(self._status_file, self._TAIL_BYTES)
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                name = ev.get("sidecar") or ev.get("component")
                if not name:
                    continue
                prev = latest.get(name)
                # Keep whichever event is newer for this sidecar.
                if prev is None or ev.get("timestamp", "") >= prev.get("timestamp", ""):
                    latest[name] = ev

        sidecars: list[dict[str, Any]] = []
        for name in sorted(latest):
            ev = latest[name]
            stats = ev.get("stats") or {}
            last_hb = ev.get("timestamp")
            stale = self._is_stale(last_hb, now)
            status = "stale" if stale else ev.get("sync_status", "unknown")
            sidecars.append({
                "name": name,
                "status": status,
                "last_heartbeat": last_hb,
                "error_count_10m": stats.get("error_count_10m", 0),
                "last_error": stats.get("last_error") or ev.get("error_message"),
            })
        ok = sum(1 for s in sidecars if s["status"] in ("running", "success"))
        err = sum(1 for s in sidecars if s["status"] in ("error", "stale"))
        return {
            "sidecars": sidecars,
            "summary": {
                "count_ok": ok,
                "count_error": err,
                "any_errors": err > 0,
            },
        }

    @staticmethod
    def _tail_read(path: Path, n: int) -> str:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            start = max(0, size - n)
            f.seek(start)
            data = f.read()
        # Drop the first (possibly partial) line if we didn't start at byte 0.
        text = data.decode("utf-8", errors="replace")
        if start > 0:
            nl = text.find("\n")
            text = text[nl + 1 :] if nl >= 0 else ""
        return text

    @staticmethod
    def _is_stale(last_hb: str | None, now: float) -> bool:
        if not last_hb:
            return True
        try:
            # Accept both "2026-04-24T10:00:00" and "...Z" forms.
            dt = datetime.fromisoformat(last_hb.replace("Z", "+00:00"))
            # Naive timestamps: assume UTC (matches HeartbeatWriter).
            if dt.tzinfo is None:
                from datetime import timezone
                dt = dt.replace(tzinfo=timezone.utc)
            return (now - dt.timestamp()) > WazuhDataService._STALE_SECONDS
        except ValueError:
            return True

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        # Use the `ids` query, not `term: _id` — the latter is deprecated and
        # will fail on newer OpenSearch versions.
        resp = self._client.search(
            index=self._alerts_index,
            body={
                "size": 1,
                "query": {"ids": {"values": [alert_id]}},
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise AlertNotFound(alert_id)
        return {"_id": hits[0]["_id"], **hits[0]["_source"]}

    _ENTITY_FIELDS: dict[str, list[str]] = {
        "ip": ["data.srcip", "data.dstip"],
        "agent": ["agent.name", "agent.id"],
        "device": ["data.device.name", "data.device.mac", "agent.ip"],
        "user": ["data.srp.user", "data.win.eventdata.user"],
        "process": ["data.srp.target_path", "data.win.eventdata.image"],
        "hash": ["syscheck.sha256_after", "syscheck.md5_after", "data.win.eventdata.hashes"],
        "domain": ["data.domain", "dns.question.name"],
    }

    def entity_activity(
        self,
        entity_type: str,
        entity_value: str,
        time_range: str,
        top_n: int = 10,
    ) -> dict[str, Any]:
        fields = self._ENTITY_FIELDS.get(entity_type)
        if not fields:
            raise ValueError(
                f"unknown entity_type: {entity_type!r}. Expected one of {list(self._ENTITY_FIELDS)}"
            )
        size_n = min(top_n, 50)
        body = {
            "size": 5,  # most recent samples
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [{
                        "bool": {"should": [{"term": {f: entity_value}} for f in fields], "minimum_should_match": 1}
                    }],
                    "filter": self._build_filter_clauses(None, time_range),
                }
            },
            "aggs": {
                "by_source": {"terms": {"field": "data.source", "size": size_n}},
                "by_rule": {"terms": {"field": "rule.id", "size": size_n}},
                "related_agents": {"terms": {"field": "agent.name", "size": size_n}},
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
            },
            "track_total_hits": True,
        }
        resp = self._client.search(index=self._alerts_index, body=body)
        aggs = resp["aggregations"]
        return {
            "entity": {"type": entity_type, "value": entity_value},
            "total_alerts": resp["hits"]["total"]["value"],
            "by_source": {b["key"]: b["doc_count"] for b in aggs["by_source"]["buckets"]},
            "by_rule": [
                {"rule_id": b["key"], "count": b["doc_count"]}
                for b in aggs["by_rule"]["buckets"]
            ],
            "first_seen": aggs["first_seen"].get("value_as_string"),
            "last_seen": aggs["last_seen"].get("value_as_string"),
            "related_agents": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in aggs["related_agents"]["buckets"]
            ],
            "sample_alerts": [
                {
                    "id": h["_id"],
                    "@timestamp": h["_source"].get("@timestamp"),
                    "rule": h["_source"].get("rule", {}),
                }
                for h in resp["hits"]["hits"]
            ],
        }
