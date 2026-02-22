# Indexer-Confirmed State Sync Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** At startup, the msp-poller queries OpenSearch for the latest indexed firewalla timestamp and rewinds its state files if the indexer is behind — ensuring any events dropped while analysisd was down are automatically re-fetched on the next restart.

**Architecture:** Add an `IndexerClient` class that queries `wazuh-alerts-4.x-*` for the latest `@timestamp` per event type (`alarm`, `flow`). A `sync_state_from_indexer()` function runs once at startup, comparing indexer results against state files and rewinding whichever is ahead. Pass OpenSearch credentials to the msp-poller container via docker-compose environment.

**Tech Stack:** Python `requests` (already in use), OpenSearch REST API, Docker Compose env vars.

---

### Task 1: Add IndexerClient class to msp_poller.py

**Files:**
- Modify: `msp-poller/msp_poller.py` (insert after line 200, before `class StateManager`)

**Context:** The `@timestamp` field in OpenSearch reflects the original Firewalla event time (thanks to the custom ingest pipeline in `config/filebeat_pipeline/pipeline.json`). Querying it sorted descending gives the latest original event time that was successfully indexed.

OpenSearch field mapping for firewalla events:
- `data.source` = `"firewalla-msp"`
- `data.event_type` = `"alarm"` or `"flow"`
- `@timestamp` = original event time (ISO 8601, e.g. `2026-02-21T12:33:00.000Z`)

**Step 1: Insert IndexerClient class**

Add this block immediately after line 200 (`return all_flows`) and before line 203 (`class StateManager:`):

```python
class IndexerClient:
    """Queries OpenSearch to find the latest indexed firewalla event timestamps."""

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip("/")
        self.auth = (username, password)

    def get_latest_event_ts(self, event_type: str) -> float | None:
        """Return Unix timestamp of the latest indexed firewalla event of the given type.

        Returns None if OpenSearch is unreachable or has no matching events.
        """
        try:
            response = requests.post(
                f"{self.url}/wazuh-alerts-4.x-*/_search",
                auth=self.auth,
                verify=False,
                timeout=10,
                json={
                    "size": 1,
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"data.source": "firewalla-msp"}},
                                {"term": {"data.event_type": event_type}}
                            ]
                        }
                    },
                    "sort": [{"@timestamp": "desc"}],
                    "_source": ["@timestamp"]
                }
            )
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            if not hits:
                return None
            ts_str = hits[0]["_source"]["@timestamp"]
            # Parse ISO 8601 → Unix timestamp
            from datetime import timezone
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).timestamp()
        except Exception as e:
            logger.warning(f"IndexerClient: failed to query OpenSearch for {event_type}: {e}")
            return None
```

**Step 2: Suppress urllib3 SSL warnings for internal calls**

Add this import at the top of the file, after the existing imports (after line 18, `import requests`):

```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

**Step 3: Verify syntax**

```bash
cd /opt/wazuh-docker/single-node/msp-poller
python3 -c "import ast; ast.parse(open('msp_poller.py').read()); print('syntax OK')"
```

Expected: `syntax OK`

**Step 4: Commit**

```bash
cd /home/yasir/firewalla-wazuh
git add msp-poller/msp_poller.py
git commit -m "feat: add IndexerClient to query OpenSearch for latest event timestamps"
```

---

### Task 2: Add sync_state_from_indexer() and wire up in main()

**Files:**
- Modify: `msp-poller/msp_poller.py`
  - Insert `sync_state_from_indexer()` after `wait_for_directories()` (after line 515)
  - Modify `main()` to call it (around line 705, after API connectivity test)
  - Add env var reads at top of file (after the existing env var block, around line 28)

**Step 1: Add environment variable reads**

After the existing env var block (after line 29, `STATUS_DIR = ...`), add:

```python
# OpenSearch connection for startup state sync
INDEXER_URL = os.environ.get("INDEXER_URL", "")
INDEXER_USERNAME = os.environ.get("INDEXER_USERNAME", "admin")
INDEXER_PASSWORD = os.environ.get("INDEXER_PASSWORD", "")
```

**Step 2: Add sync_state_from_indexer() function**

Insert this function after `wait_for_directories()` (after its closing `return False` line):

```python
def sync_state_from_indexer(state: StateManager, indexer: IndexerClient):
    """At startup, rewind state files to match the latest indexed timestamps.

    If analysisd was down during a previous run, events written to log files
    may have been dropped. This rewinds the state so the next poll re-fetches
    the gap from the MSP API (which retains 30 days of data).
    """
    if not INDEXER_URL:
        logger.info("INDEXER_URL not set, skipping indexer state sync")
        return

    logger.info("Syncing state with OpenSearch indexer...")

    for event_type, get_ts, set_ts, label in [
        ("alarm", state.get_last_alarm_ts, state.set_last_alarm_ts, "alarm"),
        ("flow",  state.get_last_flow_ts,  state.set_last_flow_ts,  "flow"),
    ]:
        state_ts = get_ts()
        indexer_ts = indexer.get_latest_event_ts(event_type)

        if indexer_ts is None:
            logger.warning(f"  {label}: indexer unreachable or no data — using state file ({datetime.fromtimestamp(state_ts)})")
            continue

        if indexer_ts < state_ts:
            logger.info(
                f"  {label}: rewinding state from {datetime.fromtimestamp(state_ts)} "
                f"→ {datetime.fromtimestamp(indexer_ts)} (gap: {(state_ts - indexer_ts)/3600:.1f}h)"
            )
            set_ts(indexer_ts)
        else:
            logger.info(f"  {label}: in sync at {datetime.fromtimestamp(indexer_ts)}")
```

**Step 3: Wire up in main()**

In `main()`, after the API connectivity test block (after the `if boxes:` / `else:` block, before the `# Polling loop` comment), add:

```python
    # Sync state with OpenSearch to recover any events dropped while analysisd was down
    if INDEXER_URL:
        indexer = IndexerClient(INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD)
        sync_state_from_indexer(state, indexer)
```

**Step 4: Verify syntax**

```bash
cd /opt/wazuh-docker/single-node/msp-poller
python3 -c "import ast; ast.parse(open('msp_poller.py').read()); print('syntax OK')"
```

Expected: `syntax OK`

**Step 5: Commit**

```bash
cd /home/yasir/firewalla-wazuh
git add msp-poller/msp_poller.py
git commit -m "feat: add sync_state_from_indexer() to rewind state on startup if events were dropped"
```

---

### Task 3: Add OpenSearch env vars to msp-poller in docker-compose.yml

**Files:**
- Modify: `docker-compose.yml` (msp-poller service, `environment` block around line 121)

**Step 1: Add environment variables**

In the `msp-poller` service `environment` block, add after `- STATUS_DIR=/status`:

```yaml
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${INDEXER_PASSWORD}
```

**Step 2: Verify docker-compose is valid**

```bash
cd /opt/wazuh-docker/single-node
docker compose config --quiet && echo "compose OK"
```

Expected: `compose OK`

**Step 3: Commit**

```bash
cd /home/yasir/firewalla-wazuh
git add docker-compose.yml
git commit -m "feat: pass OpenSearch credentials to msp-poller for startup state sync"
```

---

### Task 4: Deploy and verify

**Step 1: Copy files to running deployment**

```bash
cp /home/yasir/firewalla-wazuh/msp-poller/msp_poller.py \
   /opt/wazuh-docker/single-node/msp-poller/msp_poller.py

cp /home/yasir/firewalla-wazuh/docker-compose.yml \
   /opt/wazuh-docker/single-node/docker-compose.yml
```

**Step 2: Rebuild and restart the msp-poller**

```bash
cd /opt/wazuh-docker/single-node
docker compose build msp-poller
docker compose up -d msp-poller
```

**Step 3: Verify startup sync runs**

```bash
docker logs single-node-msp-poller --tail 30 2>&1
```

Expected output to contain:
```
Syncing state with OpenSearch indexer...
  alarm: in sync at 2026-...
  flow: in sync at 2026-...
```

(If state was already in sync, "in sync" messages confirm the indexer query worked.)

**Step 4: Simulate a gap and verify rewind (optional smoke test)**

```bash
# Set state files back 2 hours to simulate a gap
docker exec single-node-msp-poller python3 -c "
import time
ts = str(time.time() - 7200)  # 2 hours ago
open('/state/last_flow_ts.txt', 'w').write(ts)
print('Set flow state to', ts)
"

# Restart the poller and watch it rewind... but then re-fetch from API
# NOTE: this will actually re-fetch 2h of flow data, which is fine
docker compose restart msp-poller
docker logs single-node-msp-poller -f 2>&1 | head -20
```

Expected: sync logs show `in sync` (because the indexer IS caught up to now — the rewind only triggers when indexer < state, not when state < indexer).

**Better smoke test — set state AHEAD of indexer:**

```bash
docker exec single-node-msp-poller python3 -c "
import time
ts = str(time.time() + 86400)  # 24h in the future
open('/state/last_flow_ts.txt', 'w').write(ts)
print('Set flow state to future:', ts)
"
docker compose restart msp-poller
docker logs single-node-msp-poller --tail 20 2>&1
```

Expected: `flow: rewinding state from 2026-02-23T... → 2026-02-22T...`

Then clean up:
```bash
docker compose restart msp-poller  # restarts fresh with correct state
```

**Step 5: Push to GitHub**

```bash
cd /home/yasir/firewalla-wazuh
git push
```

---

## Summary of Changes

| File | Change |
|------|--------|
| `msp-poller/msp_poller.py` | Add `IndexerClient` class, `sync_state_from_indexer()` function, 3 env var reads, call in `main()` |
| `docker-compose.yml` | Add `INDEXER_URL`, `INDEXER_USERNAME`, `INDEXER_PASSWORD` to msp-poller env |

No new dependencies. `requests` and `urllib3` are already present in the container image.
