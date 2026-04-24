"""Seed ~500 synthetic Wazuh-shaped alerts into OpenSearch for integration tests."""
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Iterator

from opensearchpy import OpenSearch, helpers


SOURCES = ["firewalla-msp", "windows-srp", "threat-intel", "ossec", "syscheck"]
AGENTS = ["kids-laptop", "office-pc", "nas-1", "router", "iot-cam-1"]
RULE_IDS_BY_SOURCE = {
    "firewalla-msp": ["100200", "100210", "100450", "100451"],
    "windows-srp": ["100651", "100652", "100660"],
    "threat-intel": ["100452", "100453", "99905", "99912"],
    "ossec": ["5712", "5715"],
    "syscheck": ["550", "553"],
}


def _gen(n: int = 500) -> Iterator[dict]:
    rnd = random.Random(42)
    now = datetime.now(timezone.utc)
    for i in range(n):
        src = rnd.choice(SOURCES)
        rule_id = rnd.choice(RULE_IDS_BY_SOURCE[src])
        agent = rnd.choice(AGENTS)
        ts = now - timedelta(seconds=rnd.randint(0, 7 * 24 * 3600))
        doc = {
            "@timestamp": ts.isoformat().replace("+00:00", "Z"),
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "agent": {"id": f"{AGENTS.index(agent):03d}", "name": agent},
            "rule": {
                "id": rule_id,
                "level": rnd.choice([3, 3, 3, 7, 7, 10, 12]),
                "description": f"test rule {rule_id}",
                "groups": ["test", src],
            },
            "data": {
                "source": src,
                "srcip": f"10.0.0.{rnd.randint(1, 50)}",
                "dstip": f"203.0.113.{rnd.randint(1, 50)}",
            },
        }
        if src == "windows-srp":
            doc["data"]["srp"] = {
                "action": rnd.choice(["ALLOWED", "BLOCKED"]),
                "target_path": f"C:\\apps\\app{rnd.randint(1,5)}.exe",
                "user": rnd.choice(["alice", "bob"]),
            }
        if src == "threat-intel":
            doc["data"]["threat_intel"] = {
                "list": rnd.choice(["firewalla-c2", "urlhaus"]),
                "ioc": doc["data"]["dstip"],
            }
        yield {"_index": f"wazuh-alerts-4.x-{ts.strftime('%Y.%m.%d')}", "_source": doc}


# Minimal index template. Mirrors the `keyword` mapping for the fields our
# tools query/aggregate on — the real Wazuh template is far broader, but this
# covers everything the integration tests exercise. Without it, the ephemeral
# cluster auto-maps strings as `text` and aggregations/term-queries fail.
_TEST_TEMPLATE = {
    "index_patterns": ["wazuh-alerts-*"],
    "template": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "timestamp": {"type": "date"},
                "agent": {"properties": {
                    "id": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "ip": {"type": "keyword"},
                }},
                "rule": {"properties": {
                    "id": {"type": "keyword"},
                    "level": {"type": "integer"},
                    "description": {"type": "keyword"},
                    "groups": {"type": "keyword"},
                }},
                "data": {"properties": {
                    "source": {"type": "keyword"},
                    "srcip": {"type": "keyword"},
                    "dstip": {"type": "keyword"},
                    "domain": {"type": "keyword"},
                    "srp": {"properties": {
                        "action": {"type": "keyword"},
                        "target_path": {"type": "keyword"},
                        "user": {"type": "keyword"},
                    }},
                    "threat_intel": {"properties": {
                        "list": {"type": "keyword"},
                        "ioc": {"type": "keyword"},
                    }},
                }},
            }
        }
    },
}


def seed(os_url: str = "http://localhost:19200", count: int = 500) -> None:
    os_ = OpenSearch(hosts=[os_url])
    # Put template BEFORE writing so mappings apply at index creation.
    os_.indices.put_index_template(name="wazuh-alerts-test", body=_TEST_TEMPLATE)
    os_.indices.delete(index="wazuh-alerts-*", ignore=[400, 404])
    helpers.bulk(os_, _gen(count), refresh=True)
    print(f"seeded {count} alerts into {os_url}")


if __name__ == "__main__":
    import sys

    seed(count=int(sys.argv[1]) if len(sys.argv) > 1 else 500)
