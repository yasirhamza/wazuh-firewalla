# Design: Indexer-Confirmed State Sync for MSP Poller

**Date:** 2026-02-22
**Status:** Approved

## Problem

The msp-poller advances its state files (`last_alarm_ts.txt`, `last_flow_ts.txt`) the moment events are written to JSON log files. It has no knowledge of whether Wazuh's pipeline actually processed those events.

If `wazuh-analysisd` is down when `wazuh-logcollector` reads the files, events are silently dropped. If the log file also rotates before analysisd recovers, the data is permanently stranded in the rotated file and never indexed.

This was observed on 2026-02-22: a stale PID file caused analysisd to not start after a container restart. The msp-poller fetched ~30 hours of historical flow data (49,000 events), wrote it to `firewalla-flows.json`, but logcollector consumed and discarded those events. The file then rotated. After analysisd was manually started, logcollector was already past the historical data. Result: a 30-hour gap in the dashboard.

## Root Cause

The state advance is decoupled from confirmed indexing:

```
MSP API → msp-poller → JSON files → logcollector → analysisd → OpenSearch
               ↑
        state advances here (write to file)
                                          ↑
                              events can be silently lost here
```

## Solution: Startup State Sync from OpenSearch

At startup, before the polling loop begins, the msp-poller queries OpenSearch for the actual latest indexed timestamp for each event type (`alarm`, `flow`). If the indexer is behind the state file, the state file is rewound to match — ensuring the next poll re-fetches anything that was dropped.

### Data Flow

**Startup (new):**
```
1. Query OpenSearch → latest @timestamp where data.source=firewalla-msp, data.event_type=alarm
2. Query OpenSearch → latest @timestamp where data.source=firewalla-msp, data.event_type=flow
3. For each: if indexer_ts < state_file_ts → rewind state file to indexer_ts
4. Log the sync result (rewound / in-sync / indexer unreachable)
5. Begin normal polling loop
```

**Normal polling loop (unchanged):**
```
Read state_ts → fetch from MSP API → write to JSON log → advance state_ts
```

### Components

**`msp_poller.py` changes:**

1. Add `IndexerClient` class with a single method:
   - `get_latest_event_ts(event_type: str) -> float | None`
   - Queries `wazuh-alerts-4.x-*` index for the latest `@timestamp` where `data.source == "firewalla-msp"` and `data.event_type == event_type`
   - Returns Unix timestamp (float) or `None` if unreachable/no data

2. Add `sync_state_from_indexer(state, indexer_client)` function:
   - Calls `get_latest_event_ts` for both `"alarm"` and `"flow"`
   - Compares with `state.get_last_alarm_ts()` and `state.get_last_flow_ts()`
   - Rewinds whichever is ahead of the indexer
   - Logs outcome for each type: `rewound`, `in-sync`, or `skipped (indexer unreachable)`

3. Call `sync_state_from_indexer()` in `main()` after API connectivity test, before the polling loop.

**`docker-compose.yml` changes:**

Add environment variables to the `msp-poller` service so it can reach OpenSearch:
```yaml
environment:
  - INDEXER_URL=https://wazuh.indexer:9200
  - INDEXER_USERNAME=admin
  - INDEXER_PASSWORD=${INDEXER_PASSWORD}
```

### Error Handling

- OpenSearch unreachable at startup → log warning, proceed with state file unchanged. No crash, no blocking.
- OpenSearch returns no firewalla events (fresh deployment) → treat as no data, proceed with state file.
- OpenSearch ahead of state file (shouldn't happen) → use state file, don't advance.
- SSL: use `verify=False` for the internal OpenSearch call (single-node deployment, internal network).

### Why This Works

On a restart after analysisd was down:
1. msp-poller starts, state file says `Feb 22 19:13` (last API fetch)
2. OpenSearch query returns `Feb 21 12:33` (last successfully indexed event)
3. State files rewound to `Feb 21 12:33`
4. Next poll fetches Feb 21 12:33 → now, re-filling the gap
5. analysisd is running (self-healed by healthcheck within 30s), events get indexed

The MSP API's 30-day retention means re-fetching the gap is always possible.

## What This Does Not Fix

- analysisd going down **mid-run** (between polls). This is handled by the healthcheck self-heal (30s recovery window). A mid-run loss would be re-fetched on the next container restart.
- Duplicate events for any data that was partially indexed before the failure. Small-window duplicates are acceptable given the self-healing nature.

## Alternatives Considered

- **Wazuh Events API (direct injection):** POST events directly, state advances only on HTTP 200. Cleanest solution but requires reformatting events and larger architectural change.
- **Continuous OpenSearch lag monitoring:** Verify each batch appears in OpenSearch before advancing state. Adds 30-60s latency per cycle, complex partial-rollback logic.
