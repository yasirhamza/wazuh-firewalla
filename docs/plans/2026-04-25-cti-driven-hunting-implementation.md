# CTI-Driven Threat Hunting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CTI-driven, manually-triggered, agentic threat-hunting workflow that runs inside Claude Code, follows TaHiTI methodology, and writes confirmed findings back to Wazuh as alerts (rule IDs `100800-100899`).

**Architecture:** Three layers — (1) **artifacts** in the repo (`hunts/`, `proposed-rules/`, `cti-cache/`); (2) **backend** in the existing mcp-server container (new `HuntFindingWriter` + new MCP tool `submit_hunt_finding`, writing to the shared `sidecar_status` JSONL stream); (3) **rule chain** `100800-100899` chained off the existing `100500` sidecar-status base rule. Plus a `/hunt` skill in `.claude/skills/hunt/`, three CTI helper scripts (`scripts/attack_lookup.py`, `scripts/cisa_recent.py`, `scripts/audit_hypotheses.py`), and a new "Threat Hunting Program" OpenSearch dashboard.

**Tech Stack:** Python 3.12, Pydantic, FastMCP, opensearch-py, pytest, Wazuh 4.14.3, OpenSearch 2.x, Claude Code skill format.

**Working directories:**
- **Primary (author + commit here):** `/path/to/firewalla-wazuh/` — the git repo.
- **Deployment target:** `/opt/wazuh-docker/single-node/` — synced at deployment (Tasks 7, 9, 23). `docker-compose` runs from this location.
- **Spec reference:** `/path/to/firewalla-wazuh/docs/specs/2026-04-25-cti-driven-hunting-design.md`

**Important context from `/path/to/firewalla-wazuh/CLAUDE.md`:**
- Single-node Wazuh Docker deployment, currently at 4.14.3.
- Custom rules include 100200-100299 (Firewalla), 100450-100453 (threat intel), 100500-100504 (sidecar status), 100600-100699 (Windows SRP), 100720 (first-seen). New range `100800-100899` is reserved for hunting.
- All sidecars write status JSON to `/var/ossec/logs/sidecar-status/sidecar-status.json` via the shared `sidecar_status` Docker volume; ingested via rule chain `100500-100504` (and now `100800+`).
- `mcp-server` already has the volume mounted rw (see `docker-compose.yml:209`) — no compose change needed for finding submission.
- The `/opt/wazuh-docker/single-node/` tree is NOT a git repo — never commit from there.
- Wazuh manager loads user rules from `/var/ossec/etc/rules/` — bind-mount new rule files in `docker-compose.yml`.
- Rule files are bind-mounted by inode; after editing, either `cat host_file > same_path` (preserves inode) or `docker compose up -d --force-recreate wazuh.manager`.

**Out of scope (deferred to later sub-projects):**
- MISP integration (Phase 2)
- Scheduled / autonomous hunts (Phase 3)
- Web hunt console UI (Phase 4)
- PEAK Baseline track (separate spec)

---

## Task 1: Scaffold hunt directory structure

**Files:**
- Create: `hunts/README.md`
- Create: `hunts/backlog/.gitkeep`
- Create: `hunts/runs/.gitkeep`
- Create: `proposed-rules/README.md`
- Create: `proposed-rules/RULE_ID_REGISTER.md`
- Create: `cti-cache/attack/.gitkeep`
- Create: `cti-cache/vendor-bookmarks.md`

- [ ] **Step 1: Create directories**

Run from `/path/to/firewalla-wazuh/`:

```bash
mkdir -p hunts/backlog hunts/runs proposed-rules cti-cache/attack
touch hunts/backlog/.gitkeep hunts/runs/.gitkeep cti-cache/attack/.gitkeep
```

- [ ] **Step 2: Write `hunts/README.md`**

```markdown
# Hunts

CTI-driven threat hunting artifacts. See `docs/specs/2026-04-25-cti-driven-hunting-design.md` for the full design.

## Layout

- `backlog/` — hypothesis YAMLs (one per hunt). Format: `H-YYYY-NNN.yaml`.
- `backlog/INDEX.yaml` — prioritization index (queued / in_progress / recently_completed).
- `runs/` — investigation abstracts (one per hunt run). Format: `H-YYYY-NNN-YYYYMMDDTHHmmZ.md`.

## Workflow

1. **Initiate:** Create or pick a hypothesis (`/hunt --new`, `/hunt --from <url>`, or `/hunt H-NNNN`).
2. **Hunt:** Claude executes the investigation under analyst supervision (HitL).
3. **Finalize:** Confirmed findings → Wazuh alert via `submit_hunt_finding`. Detection candidates → drafted XML in `proposed-rules/`.

## Schema

Hypotheses validated by `scripts/validate_hypothesis.py` (CI checks every `backlog/*.yaml`).
```

- [ ] **Step 3: Write `proposed-rules/README.md`**

```markdown
# Proposed Detection Rules

Drafted Wazuh rule XMLs produced by the hunt workflow. Authored by Claude during a hunt's Phase 3 (Finalize), reviewed by the analyst, committed here.

## Promotion path

Rules in this directory are NOT live. To promote:

1. Run `wazuh-logtest` against the sibling `<id>-<slug>.test.json` to validate.
2. Move the XML to `config/wazuh_rules/`.
3. Mount in `docker-compose.yml` (or include in an existing rule file).
4. Sync to `/opt/wazuh-docker/single-node/` and restart wazuh.manager.
5. Verify the rule fires against a live event.

See `docs/specs/2026-04-25-cti-driven-hunting-design.md` §7.
```

- [ ] **Step 4: Write `proposed-rules/RULE_ID_REGISTER.md`**

```markdown
# Hunt rule ID register (100800-100899)

Tracks claimed IDs in the hunting range. Update when a new proposed rule is committed.

| ID    | Status   | Slug                        | Hunt run                              |
|-------|----------|-----------------------------|---------------------------------------|
| 100800| live     | hunt-finding-base           | (Task 6 — base rule)                  |
| 100801| live     | hunt-finding-low-conf       | (Task 6)                              |
| 100802| live     | hunt-finding-medium-conf    | (Task 6)                              |
| 100803| live     | hunt-finding-high-conf      | (Task 6)                              |
| 100810-100819 | reserved | actor-attributed         | (future)                              |
| 100820-100899 | reserved | future expansion         | (future)                              |
```

- [ ] **Step 5: Write `cti-cache/vendor-bookmarks.md`**

```markdown
# Vendor TI bookmarks

Curated list of trusted vendor sources. `/hunt --new` and free-form hunts consult this list when looking for context.

## Reports / blogs
- Mandiant: https://cloud.google.com/security/resources/insights/m-trends
- Sekoia: https://blog.sekoia.io/
- Volexity: https://www.volexity.com/blog/
- CrowdStrike Falcon: https://www.crowdstrike.com/blog/
- Microsoft Threat Intelligence: https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/
- Recorded Future Insikt: https://www.recordedfuture.com/research

## Advisories / feeds
- CISA Advisories: https://www.cisa.gov/news-events/cybersecurity-advisories
- MITRE ATT&CK: https://attack.mitre.org/
- abuse.ch ThreatFox: https://threatfox.abuse.ch/
```

- [ ] **Step 6: Commit**

```bash
cd /path/to/firewalla-wazuh
git add hunts/ proposed-rules/ cti-cache/
git commit -m "feat(hunting): scaffold hunt artifact directories"
```

---

## Task 2: Hypothesis Pydantic schema + validator

**Files:**
- Create: `scripts/__init__.py` (if not exists)
- Create: `scripts/hypothesis_schema.py`
- Create: `scripts/test_hypothesis_schema.py`

- [ ] **Step 1: Write the failing test**

Create `scripts/test_hypothesis_schema.py`:

```python
"""Tests for the TaHiTI hypothesis schema."""
import pytest
from pydantic import ValidationError

from scripts.hypothesis_schema import Hypothesis, HypothesisStatus, Confidence

VALID_YAML_DICT = {
    "id": "H-2026-001",
    "title": "Beaconing to low-reputation infrastructure",
    "created": "2026-04-25",
    "updated": "2026-04-25",
    "owner": "yasirhamza",
    "status": "proposed",
    "priority": "medium",
    "threat_actor": None,
    "attack": {
        "techniques": ["T1071.001"],
        "tactics": ["command-and-control"],
    },
    "cti_sources": [
        {"type": "mitre", "ref": "T1071.001",
         "url": "https://attack.mitre.org/techniques/T1071/001/"},
    ],
    "abstract": "C2 over HTTP(S) with regular beaconing.",
    "hypothesis": "If a Windows endpoint is beaconing to attacker C2, we should see ...",
    "data_sources": ["wazuh-alerts-* (data.source: firewalla-msp)"],
    "scope": {
        "time_range": "last_7d",
        "agents": "all_windows",
        "exclude": [],
    },
    "success_criteria": "Confirm: ...; Refute: ...",
    "investigation_steps": ["Aggregate flows by (agent, dst)"],
    "tags": ["c2", "beaconing"],
}


def test_valid_hypothesis_parses():
    h = Hypothesis(**VALID_YAML_DICT)
    assert h.id == "H-2026-001"
    assert h.status == HypothesisStatus.PROPOSED
    assert h.attack.techniques == ["T1071.001"]


def test_missing_cti_sources_rejected():
    bad = {**VALID_YAML_DICT, "cti_sources": []}
    with pytest.raises(ValidationError, match="cti_sources"):
        Hypothesis(**bad)


def test_invalid_attack_technique_format_rejected():
    bad = {**VALID_YAML_DICT}
    bad["attack"] = {"techniques": ["not-a-technique"], "tactics": []}
    with pytest.raises(ValidationError, match="techniques"):
        Hypothesis(**bad)


def test_invalid_status_rejected():
    bad = {**VALID_YAML_DICT, "status": "wandering"}
    with pytest.raises(ValidationError):
        Hypothesis(**bad)


def test_id_pattern_enforced():
    bad = {**VALID_YAML_DICT, "id": "HYPO_1"}
    with pytest.raises(ValidationError, match="id"):
        Hypothesis(**bad)
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /path/to/firewalla-wazuh
pip install pydantic pyyaml pytest 2>/dev/null  # if not already installed
python -m pytest scripts/test_hypothesis_schema.py -v
```

Expected: ImportError / ModuleNotFoundError on `scripts.hypothesis_schema`.

- [ ] **Step 3: Write `scripts/hypothesis_schema.py`**

```python
"""TaHiTI hypothesis schema (Pydantic).

Validates the YAML files in hunts/backlog/. Used by:
  - scripts/validate_hypothesis.py (CI / pre-commit)
  - the /hunt skill (Claude reads this to know required fields)
"""
from __future__ import annotations

import re
from datetime import date
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl, field_validator


HYPOTHESIS_ID_RE = re.compile(r"^H-\d{4}-\d{3}$")
ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    DROPPED = "dropped"


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CTISourceType(str, Enum):
    MITRE = "mitre"
    CISA = "cisa"
    VENDOR = "vendor"
    MISP = "misp"   # placeholder for Phase 2


class AttackMapping(BaseModel):
    techniques: list[str] = Field(min_length=1)
    tactics: list[str] = Field(default_factory=list)

    @field_validator("techniques")
    @classmethod
    def _technique_format(cls, v: list[str]) -> list[str]:
        for t in v:
            if not ATTACK_TECHNIQUE_RE.match(t):
                raise ValueError(f"invalid ATT&CK technique id: {t!r} (expected like T1071 or T1071.001)")
        return v


class CTISource(BaseModel):
    type: CTISourceType
    ref: str
    url: HttpUrl | None = None
    date: date | None = None


class Scope(BaseModel):
    time_range: str
    agents: str | list[str]
    exclude: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: str
    title: str
    created: date
    updated: date
    owner: str
    status: HypothesisStatus
    priority: Priority

    threat_actor: str | None = None
    attack: AttackMapping
    cti_sources: list[CTISource] = Field(min_length=1)

    abstract: str
    hypothesis: str
    data_sources: list[str] = Field(min_length=1)
    scope: Scope
    success_criteria: str
    investigation_steps: list[str] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not HYPOTHESIS_ID_RE.match(v):
            raise ValueError(f"hypothesis id must match H-YYYY-NNN, got {v!r}")
        return v
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python -m pytest scripts/test_hypothesis_schema.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/hypothesis_schema.py scripts/test_hypothesis_schema.py
git commit -m "feat(hunting): TaHiTI hypothesis Pydantic schema + tests"
```

---

## Task 3: Hypothesis validator CLI

**Files:**
- Create: `scripts/validate_hypothesis.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Validate hunts/backlog/*.yaml against the TaHiTI hypothesis schema.

Usage:
    python3 scripts/validate_hypothesis.py                   # validate all
    python3 scripts/validate_hypothesis.py path/to/file.yaml # validate one

Exit code 0 = all valid; 1 = any failed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

# Allow running from repo root or scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.hypothesis_schema import Hypothesis  # noqa: E402


def validate_file(path: Path) -> tuple[bool, str]:
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"
    if not isinstance(data, dict):
        return False, "top-level YAML must be a mapping"
    try:
        Hypothesis(**data)
    except ValidationError as e:
        return False, str(e)
    return True, "ok"


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        targets = [Path(p) for p in argv[1:]]
    else:
        backlog = Path(__file__).resolve().parent.parent / "hunts" / "backlog"
        targets = sorted(backlog.glob("H-*.yaml"))

    failures = 0
    for path in targets:
        ok, msg = validate_file(path)
        marker = "PASS" if ok else "FAIL"
        print(f"[{marker}] {path}: {msg if not ok else ''}".rstrip())
        if not ok:
            failures += 1

    if failures:
        print(f"\n{failures} hypothesis file(s) failed validation.", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 2: Make executable and smoke-test**

```bash
chmod +x scripts/validate_hypothesis.py
# No backlog files yet, so should report 0 failures, 0 files:
python3 scripts/validate_hypothesis.py
```

Expected: no output (no files), exit 0.

- [ ] **Step 3: Commit**

```bash
git add scripts/validate_hypothesis.py
git commit -m "feat(hunting): hypothesis YAML validator CLI"
```

---

## Task 4: Seed hypothesis H-2026-001 (beaconing)

**Files:**
- Create: `hunts/backlog/H-2026-001.yaml`

- [ ] **Step 1: Write the hypothesis**

```yaml
id: H-2026-001
title: "Beaconing to low-reputation infrastructure from Windows endpoints"
created: 2026-04-25
updated: 2026-04-25
owner: yasirhamza
status: proposed
priority: medium

threat_actor: null
attack:
  techniques: ["T1071.001", "T1571"]
  tactics: ["command-and-control"]

cti_sources:
  - type: mitre
    ref: "T1071.001"
    url: "https://attack.mitre.org/techniques/T1071/001/"
  - type: cisa
    ref: "AA24-038A"
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"
    date: 2024-02-07

abstract: >
  Adversary establishes C2 over HTTP(S) to attacker-controlled infrastructure.
  Beaconing pattern is regular intervals with consistent payload size.

hypothesis: >
  If a Windows endpoint is beaconing to attacker C2 over HTTP(S), we should
  observe Firewalla flows from that endpoint to a small set of destinations
  with regular timing (jitter <30%) and no corresponding user-initiated
  browsing activity in the same window.

data_sources:
  - "wazuh-alerts-* (data.source: firewalla-msp, event_type: flow)"
  - "wazuh-alerts-* (data.source: windows-srp)"

scope:
  time_range: "last_7d"
  agents: "all_windows"
  exclude: ["known_corporate_proxies"]

success_criteria: >
  Confirm: >=1 Windows endpoint with >=10 outbound flows to a single non-CDN
  destination over >=3 hours, jitter <30%, no concurrent user browsing.
  Refute: no such pattern, or pattern fully explained by known software
  (Windows Update, OneDrive sync, etc.).

investigation_steps:
  - "Aggregate Firewalla flows by (agent.name, data.dstip) over scope"
  - "Filter to destinations with >=10 flows, <=3 unique src ports"
  - "Compute inter-flow timing variance per (agent, dst) pair"
  - "For top candidates, pivot to threat_intel_matches and entity_activity"
  - "Cross-check with Windows SRP for concurrent user activity"

tags: [c2, beaconing, network, windows]
```

- [ ] **Step 2: Validate**

```bash
python3 scripts/validate_hypothesis.py hunts/backlog/H-2026-001.yaml
```

Expected: `[PASS] hunts/backlog/H-2026-001.yaml`, exit 0.

- [ ] **Step 3: Commit**

```bash
git add hunts/backlog/H-2026-001.yaml
git commit -m "feat(hunting): seed hypothesis H-2026-001 (C2 beaconing)"
```

---

## Task 5: Update `.gitignore` for cache + run artifacts

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add hunting-related ignores**

Append to `.gitignore`:

```gitignore

# CTI-driven hunting
cti-cache/attack/enterprise-attack.json    # ~10MB, refreshed weekly
cti-cache/attack/*.json.tmp
hunts/runs/*.md                            # operational artifacts; keep them local-only
!hunts/runs/.gitkeep
```

- [ ] **Step 2: Sanity check**

```bash
cd /path/to/firewalla-wazuh
git check-ignore -v cti-cache/attack/enterprise-attack.json hunts/runs/foo.md
```

Expected: both files reported as ignored.

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore(hunting): gitignore CTI cache and hunt-run artifacts"
```

---

## Task 6: Wazuh hunting rules XML

**Files:**
- Create: `config/wazuh_rules/hunting_rules.xml`
- Modify: `docker-compose.yml` (add bind mount)

- [ ] **Step 1: Write `config/wazuh_rules/hunting_rules.xml`**

```xml
<!--
  CTI-driven hunting rule chain (100800-100899).
  Chains off the existing 100500 sidecar-status base rule.
  Spec: docs/specs/2026-04-25-cti-driven-hunting-design.md
-->
<group name="hunting,sidecar_status,">

  <!-- 100800: base hunt finding (anchor for chained severity rules) -->
  <rule id="100800" level="3">
    <if_sid>100500</if_sid>
    <field name="job_type">^hunt_finding$</field>
    <description>Hunt finding: $(hunt.hypothesis_id) - $(hunt.summary)</description>
    <group>hunting,</group>
    <mitre>
      <id>$(hunt.attack_technique)</id>
    </mitre>
  </rule>

  <!-- 100801: low confidence (level 5) -->
  <rule id="100801" level="5">
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^low$</field>
    <description>Hunt finding (low conf): $(hunt.summary)</description>
    <group>hunting,</group>
  </rule>

  <!-- 100802: medium confidence (level 8) -->
  <rule id="100802" level="8">
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^medium$</field>
    <description>Hunt finding (medium conf): $(hunt.summary)</description>
    <group>hunting,</group>
  </rule>

  <!-- 100803: high confidence (level 12) -->
  <rule id="100803" level="12">
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^high$</field>
    <description>Hunt finding (high conf): $(hunt.summary)</description>
    <group>hunting,</group>
  </rule>

  <!--
    100810-100819: reserved for actor-attributed high-confidence findings
                   (e.g. "Volt Typhoon TTP observed").
    100820-100899: reserved for future expansion.
  -->

</group>
```

- [ ] **Step 2: Add bind mount to `docker-compose.yml`**

In the `wazuh.manager` service `volumes:` block (near line 49-51, alongside `firewalla_rules.xml` and `windows_srp_rules.xml`), add:

```yaml
      - ./config/wazuh_rules/hunting_rules.xml:/var/ossec/etc/rules/hunting_rules.xml:ro
```

- [ ] **Step 3: Sync to deployment**

```bash
cp /path/to/firewalla-wazuh/config/wazuh_rules/hunting_rules.xml \
   /opt/wazuh-docker/single-node/config/wazuh_rules/hunting_rules.xml
cp /path/to/firewalla-wazuh/docker-compose.yml \
   /opt/wazuh-docker/single-node/docker-compose.yml
```

- [ ] **Step 4: Apply mount and restart manager**

```bash
cd /opt/wazuh-docker/single-node
docker compose up -d --force-recreate wazuh.manager
# wait for it to be healthy
sleep 20
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep analysisd
```

Expected: `wazuh-analysisd is running`.

- [ ] **Step 5: Commit (rule file only — docker-compose synced separately)**

```bash
cd /path/to/firewalla-wazuh
git add config/wazuh_rules/hunting_rules.xml docker-compose.yml
git commit -m "feat(hunting): Wazuh rule chain 100800-100803 + bind mount"
```

---

## Task 7: Test hunting rules with wazuh-logtest

**Files:**
- Create: `proposed-rules/hunt-finding-medium-conf.test.json` (move/rename later if needed; reused as a pipeline fixture)

- [ ] **Step 1: Write a sample hunt finding payload**

Create `proposed-rules/hunt-finding-medium-conf.test.json`:

```json
{
  "timestamp": "2026-04-25T22:18:30Z",
  "event_type": "sidecar_status",
  "source": "sidecar-status",
  "sidecar": "hunt-runner",
  "job_type": "hunt_finding",
  "sync_status": "reported",
  "hunt": {
    "hypothesis_id": "H-2026-001",
    "run_id": "H-2026-001-20260425T2200Z",
    "finding_id": "F-2026-001-a",
    "attack_technique": "T1071.001",
    "attack_tactic": "command-and-control",
    "confidence": "medium",
    "analyst": "yasirhamza",
    "summary": "test: medium-confidence finding",
    "recommendation": "test only",
    "evidence": {
      "agent_name": "test-agent",
      "destination_ip": "203.0.113.5",
      "flow_count": 47,
      "supporting_alert_ids": ["test-alert-1"]
    }
  }
}
```

- [ ] **Step 2: Feed through wazuh-logtest**

```bash
cat /path/to/firewalla-wazuh/proposed-rules/hunt-finding-medium-conf.test.json | \
  docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Expected output (key parts):
- `Phase 2: Decoder json` matches
- `Phase 3: Rule matched` shows rule id `100802`, level `8`
- MITRE id `T1071.001` populated

If 100802 does not fire, iterate on the rule XML (Step 1 of Task 6) and re-sync.

- [ ] **Step 3: Commit the fixture**

```bash
cd /path/to/firewalla-wazuh
git add proposed-rules/hunt-finding-medium-conf.test.json
git commit -m "test(hunting): wazuh-logtest fixture for rule 100802"
```

---

## Task 8: `HuntFindingWriter` in mcp-server

**Files:**
- Modify: `mcp-server/src/logging_setup.py` — add `record_hunt_finding` method on `HeartbeatWriter`
- Create: `mcp-server/tests/test_hunt_finding_writer.py`

- [ ] **Step 1: Write the failing test**

Create `mcp-server/tests/test_hunt_finding_writer.py`:

```python
"""Tests for HeartbeatWriter.record_hunt_finding."""
import json
from pathlib import Path

from src.logging_setup import HeartbeatWriter


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_record_hunt_finding_writes_jsonl(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    hb.record_hunt_finding({
        "hypothesis_id": "H-2026-001",
        "run_id": "H-2026-001-20260425T2200Z",
        "finding_id": "F-2026-001-a",
        "attack_technique": "T1071.001",
        "attack_tactic": "command-and-control",
        "confidence": "medium",
        "analyst": "alice",
        "summary": "test summary",
        "recommendation": "test rec",
        "evidence": {"agent_name": "host-1", "flow_count": 47},
    })

    events = _read_lines(status)
    assert len(events) == 1
    e = events[0]
    assert e["event_type"] == "sidecar_status"
    assert e["job_type"] == "hunt_finding"
    assert e["sync_status"] == "reported"
    assert e["sidecar"] == "hunt-runner"
    assert e["hunt"]["hypothesis_id"] == "H-2026-001"
    assert e["hunt"]["confidence"] == "medium"
    assert e["hunt"]["attack_technique"] == "T1071.001"
    assert "timestamp" in e


def test_record_hunt_finding_rejects_invalid_confidence(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    import pytest
    with pytest.raises(ValueError, match="confidence"):
        hb.record_hunt_finding({
            "hypothesis_id": "H-2026-001",
            "run_id": "X", "finding_id": "Y",
            "attack_technique": "T1071", "attack_tactic": "c2",
            "confidence": "wandering",   # invalid
            "analyst": "a", "summary": "s", "recommendation": "r",
            "evidence": {},
        })


def test_record_hunt_finding_rejects_missing_required_fields(tmp_path: Path) -> None:
    status = tmp_path / "sidecar-status.json"
    hb = HeartbeatWriter(sidecar="hunt-runner", path=status)

    import pytest
    with pytest.raises(ValueError, match="hypothesis_id"):
        hb.record_hunt_finding({
            # hypothesis_id missing
            "run_id": "X", "finding_id": "Y",
            "attack_technique": "T1071", "attack_tactic": "c2",
            "confidence": "low",
            "analyst": "a", "summary": "s", "recommendation": "r",
            "evidence": {},
        })
```

- [ ] **Step 2: Run tests, confirm failure**

```bash
cd /path/to/firewalla-wazuh/mcp-server
python -m pytest tests/test_hunt_finding_writer.py -v
```

Expected: AttributeError on `record_hunt_finding`.

- [ ] **Step 3: Add `record_hunt_finding` to `HeartbeatWriter`**

In `mcp-server/src/logging_setup.py`, add after `record_first_seen` (around line 156):

```python
    REQUIRED_HUNT_FINDING_FIELDS = (
        "hypothesis_id", "run_id", "finding_id",
        "attack_technique", "attack_tactic", "confidence",
        "analyst", "summary", "recommendation", "evidence",
    )
    VALID_CONFIDENCE = frozenset({"low", "medium", "high"})

    def record_hunt_finding(self, finding: dict[str, Any]) -> None:
        """Append a hunt finding to the shared sidecar-status stream.

        Validates required fields and the confidence enum locally so a malformed
        payload from the MCP tool surface fails loudly here, not silently in the
        Wazuh decoder.

        Schema documented in docs/specs/2026-04-25-cti-driven-hunting-design.md §4.3.
        """
        for f in self.REQUIRED_HUNT_FINDING_FIELDS:
            if f not in finding:
                raise ValueError(f"hunt finding missing required field: {f}")
        if finding["confidence"] not in self.VALID_CONFIDENCE:
            raise ValueError(
                f"hunt finding confidence must be one of {sorted(self.VALID_CONFIDENCE)}, "
                f"got {finding['confidence']!r}"
            )

        now = time.time()
        event = {
            "timestamp": _iso(now),
            "event_type": "sidecar_status",
            "source": "sidecar-status",
            "sidecar": self._sidecar,
            "job_type": "hunt_finding",
            "sync_status": "reported",
            "hunt": dict(finding),
        }
        self._append_event(event)
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python -m pytest tests/test_hunt_finding_writer.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Sync to deployment + commit**

```bash
cp /path/to/firewalla-wazuh/mcp-server/src/logging_setup.py \
   /opt/wazuh-docker/single-node/mcp-server/src/logging_setup.py

cd /path/to/firewalla-wazuh
git add mcp-server/src/logging_setup.py mcp-server/tests/test_hunt_finding_writer.py
git commit -m "feat(hunting): HeartbeatWriter.record_hunt_finding + tests"
```

---

## Task 9: MCP tool `submit_hunt_finding`

**Files:**
- Modify: `mcp-server/src/mcp_server.py` — extend `build_app` signature with `hunt_writer`, register the new tool
- Modify: `mcp-server/src/main.py` — instantiate a second `HeartbeatWriter` (sidecar="hunt-runner"), pass it into `build_app`
- Create: `mcp-server/tests/test_submit_hunt_finding_tool.py`

The existing factory is `build_app(service: WazuhDataService, rate_limiter: RateLimiter) -> FastMCP` at `mcp-server/src/mcp_server.py:127`. Tools are registered via `@app.tool(...)` inside the factory.

- [ ] **Step 1: Write the failing tool test**

Create `mcp-server/tests/test_submit_hunt_finding_tool.py`:

```python
"""End-to-end test of the submit_hunt_finding MCP tool wrapper."""
import json
from pathlib import Path
from unittest.mock import MagicMock

from src.logging_setup import HeartbeatWriter
from src.mcp_server import build_app


def test_submit_hunt_finding_tool_writes_event(tmp_path: Path) -> None:
    status_path = tmp_path / "sidecar-status.json"
    hunt_writer = HeartbeatWriter(sidecar="hunt-runner", path=status_path)

    service = MagicMock()
    rate_limiter = MagicMock()
    app = build_app(service=service, rate_limiter=rate_limiter, hunt_writer=hunt_writer)

    # FastMCP exposes registered tools via app._tool_manager._tools (private but
    # stable enough for tests; alternatively, call through MCP transport).
    tool = app._tool_manager._tools.get("submit_hunt_finding")
    assert tool is not None, "submit_hunt_finding tool not registered"

    finding = {
        "hypothesis_id": "H-2026-001",
        "run_id": "H-2026-001-T",
        "finding_id": "F-2026-001-a",
        "attack_technique": "T1071.001",
        "attack_tactic": "command-and-control",
        "confidence": "medium",
        "analyst": "alice",
        "summary": "test",
        "recommendation": "test",
        "evidence": {"agent_name": "host-1"},
    }
    result = tool.fn(finding=finding)
    assert result["status"] == "submitted"
    assert result["finding_id"] == "F-2026-001-a"

    events = [json.loads(line) for line in status_path.read_text().splitlines() if line]
    assert len(events) == 1
    assert events[0]["job_type"] == "hunt_finding"
    assert events[0]["sidecar"] == "hunt-runner"
```

> **Note:** if `app._tool_manager._tools` access pattern doesn't work with the installed FastMCP version, switch to using the public MCP transport (instantiate the in-memory client and call the tool by name). Adjust the test but keep the assertions.

- [ ] **Step 2: Run test, confirm failure**

```bash
cd /path/to/firewalla-wazuh/mcp-server
python -m pytest tests/test_submit_hunt_finding_tool.py -v
```

Expected: TypeError on unexpected keyword `hunt_writer` (the parameter doesn't exist yet).

- [ ] **Step 3: Extend `build_app` and register the tool**

In `mcp-server/src/mcp_server.py`:

(a) Update the factory signature at line 127:

```python
def build_app(
    service: WazuhDataService,
    rate_limiter: RateLimiter,
    hunt_writer: "HeartbeatWriter | None" = None,
) -> FastMCP:
```

Add the import at the top of the file:

```python
from typing import Any
from src.logging_setup import HeartbeatWriter  # noqa: F401  (used in type hint)
```

(b) Inside the factory, after the last existing `@app.tool(...)` block (after `first_seen_domains`), add:

```python
    # --- submit_hunt_finding ---
    @app.tool(
        name="submit_hunt_finding",
        description=(
            "Submit a confirmed hunt finding for ingestion as a Wazuh alert. "
            "Required when the analyst confirms a finding during the Finalize "
            "phase of a /hunt session. The finding lands in wazuh-alerts-* via "
            "rule 100800-100803 (severity by confidence). DO NOT call without "
            "explicit analyst confirmation — this writes to the SIEM."
        ),
    )
    def submit_hunt_finding(finding: dict[str, Any]) -> dict[str, str]:
        """Validate and append a hunt finding to the sidecar-status JSONL stream.

        Schema: docs/specs/2026-04-25-cti-driven-hunting-design.md §4.3.
        """
        if hunt_writer is None:
            raise RuntimeError(
                "submit_hunt_finding called but hunt_writer is not configured. "
                "main.py must pass hunt_writer=... into build_app()."
            )
        hunt_writer.record_hunt_finding(finding)
        return {"status": "submitted", "finding_id": finding.get("finding_id", "")}
```

- [ ] **Step 4: Wire `hunt_writer` in `main.py`**

In `mcp-server/src/main.py`, after the existing `heartbeat = HeartbeatWriter(...)` block (around line 44) and BEFORE `build_app` is called (around line 58), add:

```python
    hunt_writer = HeartbeatWriter(
        sidecar="hunt-runner",
        path=heartbeat._path,   # share the same JSONL stream
    )
    # NOTE: do NOT call hunt_writer.start() — it should not emit heartbeats.
    # It exists only so submit_hunt_finding has a writer with sidecar=hunt-runner.
```

Then update the `build_app` call (around line 58):

```python
    mcp_app = build_app(service=service, rate_limiter=rate_limiter, hunt_writer=hunt_writer)
```

- [ ] **Step 5: Run tests, expect pass**

```bash
python -m pytest tests/test_submit_hunt_finding_tool.py tests/test_hunt_finding_writer.py -v
```

Expected: all pass.

- [ ] **Step 6: Sync to deployment + commit**

```bash
cp /path/to/firewalla-wazuh/mcp-server/src/mcp_server.py \
   /opt/wazuh-docker/single-node/mcp-server/src/mcp_server.py
cp /path/to/firewalla-wazuh/mcp-server/src/main.py \
   /opt/wazuh-docker/single-node/mcp-server/src/main.py

cd /opt/wazuh-docker/single-node
docker compose up -d --force-recreate mcp-server
sleep 5
docker logs single-node-mcp-server 2>&1 | tail -20

cd /path/to/firewalla-wazuh
git add mcp-server/src/mcp_server.py mcp-server/src/main.py mcp-server/tests/test_submit_hunt_finding_tool.py
git commit -m "feat(hunting): MCP tool submit_hunt_finding"
```

---

## Task 10: End-to-end finding pipeline test (manual)

**Files:** none (verification only)

- [ ] **Step 1: Reconnect MCP from Claude Code**

In Claude Code: `/mcp` to refresh the session against the rebuilt mcp-server.

- [ ] **Step 2: Submit a test finding via the MCP tool**

In a Claude Code session:

```
Use mcp__wazuh__submit_hunt_finding with:
  finding = { ... payload from Task 7 step 1 ... }
```

Expected: `{"status": "submitted", "finding_id": "F-2026-001-a"}`.

- [ ] **Step 3: Verify it lands in wazuh-alerts-***

Run via the MCP tool `mcp__wazuh__search_alerts`:

```
filters = {"rule.id": "100802"}
time_range = "last_1h"
limit = 5
```

Expected: at least one result with `rule.id=100802`, level=8, mitre.id=`T1071.001`, `data.hunt.finding_id=F-2026-001-a`.

If the alert does not appear within ~30s:

```bash
docker logs single-node-wazuh.manager-1 2>&1 | tail -30
docker exec single-node-wazuh.manager-1 sh -c 'tail -10 /var/ossec/logs/sidecar-status/sidecar-status.json'
```

- [ ] **Step 4: Document pass/fail in the spec retrospective**

Append a one-paragraph note to `docs/specs/2026-04-25-cti-driven-hunting-design.md` under a new `## Implementation log` section: pipeline verified end-to-end on YYYY-MM-DD.

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-04-25-cti-driven-hunting-design.md
git commit -m "docs(hunting): record pipeline verification"
```

---

## Task 11: ATT&CK STIX bundle refresh script

**Files:**
- Create: `scripts/refresh_attack.sh`
- Create: `cti-cache/attack/LAST_REFRESHED.txt` (initial run output)

- [ ] **Step 1: Write the script**

Create `scripts/refresh_attack.sh`:

```bash
#!/usr/bin/env bash
# Refresh the cached MITRE ATT&CK enterprise STIX bundle.
# Run weekly via /schedule. Idempotent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="$REPO_ROOT/cti-cache/attack"
TARGET="$CACHE_DIR/enterprise-attack.json"
TMP="$TARGET.tmp"
URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

mkdir -p "$CACHE_DIR"

echo "Fetching $URL ..."
curl -fsSL --max-time 120 -o "$TMP" "$URL"

# Validate it parses as JSON before swapping in.
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$TMP"

mv "$TMP" "$TARGET"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$CACHE_DIR/LAST_REFRESHED.txt"
SIZE=$(du -h "$TARGET" | cut -f1)
echo "ATT&CK bundle refreshed: $TARGET ($SIZE)"
```

- [ ] **Step 2: Make executable and run**

```bash
chmod +x scripts/refresh_attack.sh
./scripts/refresh_attack.sh
```

Expected: prints `ATT&CK bundle refreshed: ... (~10M)`. File `cti-cache/attack/enterprise-attack.json` exists, gitignored. `LAST_REFRESHED.txt` has a timestamp.

- [ ] **Step 3: Commit script + LAST_REFRESHED**

```bash
git add scripts/refresh_attack.sh cti-cache/attack/LAST_REFRESHED.txt
git commit -m "feat(hunting): MITRE ATT&CK STIX bundle refresh script"
```

---

## Task 12: `attack_lookup.py` helper + tests

**Files:**
- Create: `scripts/attack_lookup.py`
- Create: `scripts/test_attack_lookup.py`

- [ ] **Step 1: Write the failing test**

Create `scripts/test_attack_lookup.py`:

```python
"""Tests for ATT&CK technique lookup."""
import pytest

from scripts.attack_lookup import lookup, AttackBundleNotFound


def test_lookup_known_technique():
    res = lookup("T1071.001")
    assert res is not None
    assert "name" in res
    assert "Application Layer Protocol" in res["name"] or "Web Protocols" in res["name"]
    assert "command-and-control" in [t.lower() for t in res.get("tactics", [])]
    assert "data_sources" in res


def test_lookup_top_level_technique():
    res = lookup("T1071")
    assert res is not None
    assert res.get("sub_techniques"), "expected T1071 to have sub-techniques"


def test_lookup_unknown_technique_returns_none():
    res = lookup("T9999.999")
    assert res is None


def test_lookup_invalid_format_raises():
    with pytest.raises(ValueError, match="technique id"):
        lookup("not-a-technique")
```

- [ ] **Step 2: Run, confirm failure**

```bash
python -m pytest scripts/test_attack_lookup.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `scripts/attack_lookup.py`**

```python
#!/usr/bin/env python3
"""MITRE ATT&CK technique lookup against the cached STIX bundle.

CLI usage:
    python3 scripts/attack_lookup.py T1071.001

Library usage:
    from scripts.attack_lookup import lookup
    result = lookup("T1071.001")
"""
from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path

ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
BUNDLE_PATH = Path(__file__).resolve().parent.parent / "cti-cache" / "attack" / "enterprise-attack.json"


class AttackBundleNotFound(FileNotFoundError):
    pass


@lru_cache(maxsize=1)
def _load_bundle() -> dict:
    if not BUNDLE_PATH.exists():
        raise AttackBundleNotFound(
            f"ATT&CK bundle not found at {BUNDLE_PATH}. "
            f"Run scripts/refresh_attack.sh first."
        )
    with BUNDLE_PATH.open() as f:
        return json.load(f)


def _index() -> dict[str, dict]:
    """Build a flat index: external_id (T1071, T1071.001, etc.) -> object."""
    out: dict[str, dict] = {}
    bundle = _load_bundle()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                out[ref["external_id"]] = obj
    return out


def lookup(technique_id: str) -> dict | None:
    """Look up a MITRE ATT&CK technique by ID.

    Returns None if the ID is not found. Raises ValueError on malformed input.
    """
    if not ATTACK_TECHNIQUE_RE.match(technique_id):
        raise ValueError(
            f"invalid technique id: {technique_id!r} (expected T1071 or T1071.001)"
        )
    idx = _index()
    obj = idx.get(technique_id)
    if obj is None:
        return None

    tactics = [
        phase.get("phase_name", "")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]
    sub_techniques = [
        ext_id for ext_id in idx
        if ext_id.startswith(technique_id + ".") and ext_id != technique_id
    ]
    return {
        "id": technique_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", "")[:1000],
        "tactics": tactics,
        "data_sources": obj.get("x_mitre_data_sources", []),
        "detection": obj.get("x_mitre_detection", "")[:2000],
        "sub_techniques": sorted(sub_techniques),
        "url": next(
            (r.get("url") for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        ),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: attack_lookup.py <TECHNIQUE_ID>", file=sys.stderr)
        return 2
    try:
        result = lookup(argv[1])
    except (ValueError, AttackBundleNotFound) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if result is None:
        print(f"technique {argv[1]} not found in bundle", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python -m pytest scripts/test_attack_lookup.py -v
```

Expected: 4 passed (assumes Task 11 already cached the bundle).

- [ ] **Step 5: Smoke test the CLI**

```bash
python3 scripts/attack_lookup.py T1071.001 | head -30
```

Expected: JSON with `name="Web Protocols"`, `tactics=["command-and-control"]`.

- [ ] **Step 6: Commit**

```bash
git add scripts/attack_lookup.py scripts/test_attack_lookup.py
git commit -m "feat(hunting): MITRE ATT&CK technique lookup helper"
```

---

## Task 13: `cisa_recent.py` helper + tests

**Files:**
- Create: `scripts/cisa_recent.py`
- Create: `scripts/test_cisa_recent.py`

- [ ] **Step 1: Write the failing test**

Create `scripts/test_cisa_recent.py`:

```python
"""Tests for the CISA advisory parser (input fixture, not live HTTP)."""
from pathlib import Path

from scripts.cisa_recent import parse_advisories_xml


SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access</title>
      <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a</link>
      <pubDate>Wed, 07 Feb 2024 11:00:00 EST</pubDate>
      <description>CISA, NSA, and FBI assess that PRC state-sponsored cyber actors are seeking to pre-position themselves on IT networks ...</description>
    </item>
    <item>
      <title>AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure</title>
      <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b</link>
      <pubDate>Thu, 29 Feb 2024 11:00:00 EST</pubDate>
      <description>CISA and authoring organizations are releasing this joint Cybersecurity Advisory ...</description>
    </item>
  </channel>
</rss>
"""


def test_parse_extracts_id_title_url_date_summary():
    items = parse_advisories_xml(SAMPLE_XML)
    assert len(items) == 2

    first = items[0]
    assert first["id"] == "AA24-038A"
    assert first["title"].startswith("PRC State-Sponsored")
    assert first["url"] == "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"
    assert first["date"] == "2024-02-07"
    assert "PRC state-sponsored" in first["summary"]


def test_id_extraction_handles_missing_aa_prefix():
    xml = SAMPLE_XML.replace("AA24-038A: ", "")
    items = parse_advisories_xml(xml)
    assert items[0]["id"] is None  # no AA-id parseable from title
```

- [ ] **Step 2: Run, confirm failure**

```bash
python -m pytest scripts/test_cisa_recent.py -v
```

Expected: ImportError.

- [ ] **Step 3: Write `scripts/cisa_recent.py`**

```python
#!/usr/bin/env python3
"""Pull recent CISA cybersecurity advisories from the public RSS feed.

CLI: python3 scripts/cisa_recent.py [N]    # default N=10
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime

CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
AA_ID_RE = re.compile(r"\b(AA\d{2}-\d{3}[A-Z])\b")


def parse_advisories_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    out: list[dict] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date_raw = (item.findtext("pubDate") or "").strip()
        desc = (item.findtext("description") or "").strip()

        m = AA_ID_RE.search(title)
        aa_id = m.group(1) if m else None

        # Strip "AAxx-xxxX: " prefix from title for cleaner display.
        clean_title = title
        if aa_id and title.startswith(aa_id):
            clean_title = title[len(aa_id):].lstrip(": ").strip()

        try:
            iso_date = parsedate_to_datetime(pub_date_raw).date().isoformat()
        except (TypeError, ValueError):
            iso_date = None

        out.append({
            "id": aa_id,
            "title": clean_title,
            "url": link,
            "date": iso_date,
            "summary": desc[:500],
        })
    return out


def fetch_recent(limit: int = 10) -> list[dict]:
    req = urllib.request.Request(
        CISA_RSS_URL,
        headers={"User-Agent": "firewalla-wazuh-hunting/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    items = parse_advisories_xml(body)
    return items[:limit]


def main(argv: list[str]) -> int:
    limit = int(argv[1]) if len(argv) > 1 else 10
    try:
        items = fetch_recent(limit=limit)
    except Exception as e:
        print(f"error fetching CISA RSS: {e}", file=sys.stderr)
        return 1
    print(json.dumps(items, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 4: Run tests + smoke test**

```bash
python -m pytest scripts/test_cisa_recent.py -v
python3 scripts/cisa_recent.py 3 | head -40   # live fetch
```

Expected: 2 tests pass; live fetch returns 3 advisories with id/title/url/date/summary.

- [ ] **Step 5: Commit**

```bash
git add scripts/cisa_recent.py scripts/test_cisa_recent.py
git commit -m "feat(hunting): CISA advisories RSS fetcher"
```

---

## Task 14: `audit_hypotheses.py` weekly check

**Files:**
- Create: `scripts/audit_hypotheses.py`

- [ ] **Step 1: Write the script**

Create `scripts/audit_hypotheses.py`:

```python
#!/usr/bin/env python3
"""Weekly health audit of the hypothesis backlog.

Checks:
  - Every backlog YAML still validates against the schema.
  - All referenced ATT&CK technique IDs still exist in the cached bundle.
  - Hypotheses in `proposed` status >90 days are flagged as stale.
  - cti_sources URLs are reachable (HEAD request; warn-only).

Output is plain text suitable for piping to a log or notifying via email.
Exit 0 always (audit, not gate).

Wire as a /schedule weekly cron.
"""
from __future__ import annotations

import sys
import urllib.request
from datetime import date, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from scripts.attack_lookup import lookup as attack_lookup, AttackBundleNotFound  # noqa: E402
from scripts.hypothesis_schema import Hypothesis  # noqa: E402

BACKLOG = REPO / "hunts" / "backlog"
STALE_DAYS = 90


def _check_url(url: str) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "firewalla-wazuh-hunting/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def main() -> int:
    today = date.today()
    issues: list[str] = []
    n_files = 0

    for path in sorted(BACKLOG.glob("H-*.yaml")):
        n_files += 1
        try:
            data = yaml.safe_load(path.read_text())
            h = Hypothesis(**data)
        except Exception as e:
            issues.append(f"[SCHEMA] {path.name}: {e}")
            continue

        # ATT&CK technique freshness
        for tech in h.attack.techniques:
            try:
                if attack_lookup(tech) is None:
                    issues.append(f"[ATTACK] {path.name}: technique {tech} not in cached bundle")
            except AttackBundleNotFound:
                issues.append("[ATTACK] cache missing — run scripts/refresh_attack.sh")
                break

        # Stale-proposed check
        if h.status.value == "proposed":
            age = (today - h.created).days
            if age > STALE_DAYS:
                issues.append(f"[STALE] {path.name}: proposed for {age}d (>{STALE_DAYS})")

        # CTI URL reachability (warn-only)
        for src in h.cti_sources:
            if src.url is not None and not _check_url(str(src.url)):
                issues.append(f"[URL] {path.name}: {src.url} unreachable")

    print(f"Audited {n_files} hypotheses; {len(issues)} issue(s).")
    for line in issues:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Smoke test**

```bash
python3 scripts/audit_hypotheses.py
```

Expected: `Audited 1 hypotheses; 0 issue(s).` (the seed hypothesis from Task 4).

- [ ] **Step 3: Commit**

```bash
git add scripts/audit_hypotheses.py
git commit -m "feat(hunting): weekly hypothesis backlog audit script"
```

---

## Task 15: `/hunt` skill SKILL.md

**Files:**
- Create: `.claude/skills/hunt/SKILL.md`
- Create: `.claude/skills/hunt/templates/hypothesis-template.yaml`
- Create: `.claude/skills/hunt/references/tahiti-reference.md`

- [ ] **Step 1: Write the SKILL.md**

Create `.claude/skills/hunt/SKILL.md`:

```markdown
---
name: hunt
description: |
  CTI-driven, manually-triggered, agentic threat hunting following TaHiTI methodology.
  Use when the analyst invokes `/hunt`, `/hunt <id>`, `/hunt --new`, `/hunt --next`,
  or `/hunt --from <url>`.
---

# /hunt — TaHiTI-driven threat hunting

You are conducting a CTI-grounded threat hunt as the agent in a Human-in-the-Loop
workflow. The analyst is in the room. They drive decisions; you drive the
investigation. Follow TaHiTI's three-phase lifecycle precisely.

**Spec reference:** `docs/specs/2026-04-25-cti-driven-hunting-design.md`
**Hypothesis schema:** `scripts/hypothesis_schema.py`

## Invocation modes

| Command                | Action |
|------------------------|--------|
| `/hunt`                | List `proposed` and `queued` hypotheses from `hunts/backlog/INDEX.yaml`. Ask the analyst to pick one. |
| `/hunt H-NNNN-NNN`     | Load that hypothesis from `hunts/backlog/`. |
| `/hunt --next`         | Load the top `queued` hypothesis. |
| `/hunt --new`          | Free-form: ask the analyst for a hypothesis seed (CTI URL, technique ID, threat actor, or natural-language idea). Walk them through generating a TaHiTI-compliant hypothesis YAML using the template at `.claude/skills/hunt/templates/hypothesis-template.yaml`. Validate via `scripts/validate_hypothesis.py`. Save to `hunts/backlog/`, then proceed. |
| `/hunt --from <url>`   | Use `WebFetch` to pull the URL (CISA advisory / MITRE technique page / vendor blog), extract TTPs and adversary attribution, draft a hypothesis YAML, ask the analyst to confirm/edit, save, then proceed. |

## Phase 1 — Initiate

After loading or generating a hypothesis:

1. **Restate** the hypothesis, success criteria, and scope to the analyst in a compact summary.
2. **Pull CTI context:** for each technique in `attack.techniques`, run `python3 scripts/attack_lookup.py <technique>` via `Bash`. Surface relevant `data_sources` and `detection` notes. For each `cti_sources` entry of type `cisa`, optionally `WebFetch` the URL for late-breaking updates.
3. **Flag CTI-data-source mismatches.** If the technique requires data we don't collect (e.g. JA3 fingerprints, full DPI), tell the analyst so they can re-scope or drop the hypothesis.
4. **Set status to `in_progress`** by editing the hypothesis YAML.
5. **HitL gate:** ask the analyst to confirm scope before any data queries run.

## Phase 2 — Hunt

Execute the `investigation_steps` in order, but adapt based on results:

1. After each step, narrate using the fixed protocol:

```
[OBSERVATION]   what I just learned (concrete, with numbers)
[INTERPRETATION] what it means for the hypothesis (still consistent? refuted?)
[PROPOSAL]      the next tool call (specific tool + parameters)
[OPTIONS]       continue / redirect to <X> / stop
```

2. Maintain a **live evidence ledger** as a markdown list. Each entry: timestamp, what you found, which tool call produced it.
3. Before every pivot, restate the original hypothesis and check whether the pivot still serves it. If it doesn't, surface that explicitly to the analyst.
4. **Auto-stop conditions:**
   - Success criteria met (hypothesis confirmed) — go to Phase 3.
   - 30+ tool calls without convergence — escalate to analyst, propose `inconclusive`.
   - Analyst says `stop` — go to Phase 3 with current state.

## Phase 3 — Finalize

1. **Draft the run abstract** in `hunts/runs/<id>-<YYYYMMDDTHHmmZ>.md` per the template:

```markdown
# Hunt run: <id> @ <timestamp>

**Hypothesis:** <title>
**Analyst:** <owner>
**Started:** <ts>  **Finished:** <ts>
**Outcome:** confirmed_threat | no_threat_found | inconclusive | dropped

## Tools used
- mcp__wazuh__... × N

## Investigation
[narrative — query, result, reasoning, next pivot. Include HitL redirects.]

## Findings
[list with confidence; cite supporting alert IDs]

## Detections proposed
[list of proposed-rules/<id>-<slug>.xml drafts]

## Lessons learned / hypothesis refinement
[updates to the backlog YAML]
```

2. **For each confirmed finding:**
   - Show the `submit_hunt_finding` payload to the analyst.
   - On confirmation, call `mcp__wazuh__submit_hunt_finding`.
   - Record the resulting `finding_id` in the run abstract.

3. **For each detection candidate:**
   - Draft a Wazuh rule XML to `proposed-rules/<id>-<slug>.xml`. Take the next available rule ID from `proposed-rules/RULE_ID_REGISTER.md` and update the register.
   - Include MITRE mapping, comment header citing the hunt run, and a sibling `<id>-<slug>.test.json`.
   - Show the analyst, commit on approval.

4. **Update the hypothesis YAML:**
   - `status` → `completed` / `inconclusive` / `dropped`
   - `updated` → today
   - Append a reference to the run file under a new `runs:` field (or whatever your local convention becomes).

5. **HitL gate:** show every artifact (run abstract, finding payload, drafted XML, hypothesis update) to the analyst before any write.

## Tool guardrails

**Allowed (read-only investigation):**
`mcp__wazuh__search_alerts`, `aggregate_alerts`, `entity_activity`, `first_seen_domains`, `threat_intel_matches`, `alert_overview`, `trend_delta`, `get_alert`, `sidecar_health`

**Allowed (write — HitL-gated):**
`mcp__wazuh__submit_hunt_finding`, `Write` (only for `hunts/runs/`, `hunts/backlog/`, `proposed-rules/`)

**Allowed (CTI lookups):**
`WebFetch` (for CISA / MITRE / vendor URLs), `Read` for cached ATT&CK STIX bundle, `WebSearch`, `Bash` (only for `python3 scripts/attack_lookup.py`, `python3 scripts/cisa_recent.py`, `python3 scripts/validate_hypothesis.py`)

**Forbidden during a hunt:**
- General `Bash` (anything other than the three allowed scripts)
- `Edit` outside `hunts/` and `proposed-rules/` trees
- `submit_hunt_finding` without explicit analyst confirmation
- Modifying `config/wazuh_rules/`, `docker-compose.yml`, `mcp-server/`

## Hypothesis quality bar (no ungrounded hunts)

A hypothesis is **not allowed to start** unless:
- `cti_sources` has at least one entry (mitre / cisa / vendor / misp)
- `attack.techniques` has at least one valid ATT&CK ID (e.g. `T1071.001`)
- `success_criteria` is concrete (specific thresholds, not "look for suspicious activity")

If the analyst proposes an ungrounded hunt, push back: ask them which ATT&CK technique or CTI source motivates it. If none, decline and suggest spending the time to find one first.

## References

- `docs/specs/2026-04-25-cti-driven-hunting-design.md` — full design
- `.claude/skills/hunt/templates/hypothesis-template.yaml` — TaHiTI hypothesis skeleton
- `.claude/skills/hunt/references/tahiti-reference.md` — TaHiTI methodology summary
```

- [ ] **Step 2: Write the hypothesis template**

Create `.claude/skills/hunt/templates/hypothesis-template.yaml`:

```yaml
# TaHiTI hypothesis template. Copy to hunts/backlog/H-YYYY-NNN.yaml and fill in.
# Validated by scripts/validate_hypothesis.py (Pydantic schema).

id: H-YYYY-NNN
title: ""
created: YYYY-MM-DD
updated: YYYY-MM-DD
owner: ""
status: proposed   # proposed | queued | in_progress | completed | inconclusive | dropped
priority: medium   # high | medium | low

threat_actor: null   # or string like "Volt Typhoon" if actor-specific

attack:
  techniques: []     # required: at least one ATT&CK ID (e.g. "T1071.001")
  tactics: []        # optional: ATT&CK tactics

cti_sources:         # required: at least one entry
  # - { type: mitre,  ref: "T1071.001", url: "https://attack.mitre.org/techniques/T1071/001/" }
  # - { type: cisa,   ref: "AAxx-yyyN", url: "...", date: YYYY-MM-DD }
  # - { type: vendor, ref: "Mandiant ...", url: "..." }

abstract: >
  One-paragraph summary of what the adversary does.

hypothesis: >
  Testable statement: "If the adversary is doing X, we should observe Y in our [data source]."

data_sources:        # required: which Wazuh data we'll query
  - "wazuh-alerts-* (data.source: ...)"

scope:
  time_range: "last_7d"
  agents: "all"      # or list: ["agent-1", "agent-2"]
  exclude: []

success_criteria: >
  Confirm: <concrete threshold>.
  Refute: <what would refute or fully explain the pattern>.

investigation_steps:
  # Suggested queries / pivots. Claude may deviate based on results.
  - ""

tags: []
```

- [ ] **Step 3: Write the TaHiTI reference doc**

Create `.claude/skills/hunt/references/tahiti-reference.md`:

```markdown
# TaHiTI Methodology Reference

TaHiTI = Targeted Hunting integrating Threat Intelligence (Mehrotra et al., ABN AMRO/Rabobank/ING, 2018-2019).

## Three phases

1. **Initiate** — Generate hypothesis, scope it, prioritize. Output: hypothesis YAML in `hunts/backlog/`.
2. **Hunt** — Investigate. Output: evidence, intermediate findings.
3. **Finalize** — Document, propose detections, refine the hypothesis. Output: run abstract, finding alerts, drafted detection rules.

## Hypothesis template fields (we map each to YAML)

| TaHiTI field          | YAML key            |
|-----------------------|---------------------|
| Title                 | `title`             |
| Date / owner          | `created` / `owner` |
| Status                | `status`            |
| Threat actor          | `threat_actor`      |
| TTP                   | `attack.techniques` |
| Hypothesis            | `hypothesis`        |
| Abstract              | `abstract`          |
| Data sources          | `data_sources`      |
| Suggested techniques  | `investigation_steps`|
| Status / outcome      | `status` (post-hunt)|

## Outcomes

| Outcome             | Meaning |
|---------------------|---------|
| `confirmed_threat`  | Hypothesis confirmed; finding(s) submitted as alerts. |
| `no_threat_found`   | Hypothesis refuted; the absence is itself a useful artifact. |
| `inconclusive`      | Data insufficient or query did not converge. Refine and re-queue. |
| `dropped`           | Hypothesis abandoned (un-investigable in this environment, deprecated TTP, etc.). |

## What "good" looks like

- Hunts/week ≥ 1 (cadence keeps the muscle warm).
- `confirmed_threat` < 20% of completed (low ratio = catching things proactively).
- `inconclusive` < 30% (high = scope/data-source mismatch).
- Detection promotions/month ≥ 1 (program feeds back into detections).
- Stale `proposed` >90 days = 0 (run, refine, or drop — don't let backlog rot).

## Citations

- Mehrotra et al., "TaHiTI: a threat hunting methodology," ABN AMRO et al., 2019. https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf
- Bianco, "The Pyramid of Pain," 2014. https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Sqrrl, "Hunting Loop," 2017.
- MITRE ATT&CK, https://attack.mitre.org/
```

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/hunt/
git commit -m "feat(hunting): /hunt skill (SKILL.md + template + TaHiTI reference)"
```

---

## Task 16: Two more seed hypotheses

**Files:**
- Create: `hunts/backlog/H-2026-002.yaml`
- Create: `hunts/backlog/H-2026-003.yaml`

- [ ] **Step 1: Write H-2026-002 (DNS exfiltration)**

```yaml
id: H-2026-002
title: "DNS-based exfiltration via abnormally long subdomain queries"
created: 2026-04-25
updated: 2026-04-25
owner: yasirhamza
status: proposed
priority: medium

threat_actor: null
attack:
  techniques: ["T1048.003", "T1071.004"]
  tactics: ["exfiltration", "command-and-control"]

cti_sources:
  - type: mitre
    ref: "T1048.003"
    url: "https://attack.mitre.org/techniques/T1048/003/"
  - type: mitre
    ref: "T1071.004"
    url: "https://attack.mitre.org/techniques/T1071/004/"

abstract: >
  DNS exfiltration encodes data in long subdomain labels of TXT/A queries to
  attacker-controlled domains. Indicators: queries with subdomains >50 chars,
  high entropy, and a small set of repeated authoritative servers.

hypothesis: >
  If a host is exfiltrating data over DNS, we should see a sequence of
  Firewalla DNS queries to a single second-level domain with subdomain
  components >50 characters and high label entropy, occurring at a steady
  rate over minutes/hours.

data_sources:
  - "wazuh-alerts-* (data.source: firewalla-msp, event_type: alarm, _type: ALARM_DNS)"
  - "wazuh-alerts-* (rule.id: 100720)  # first-seen domains"

scope:
  time_range: "last_7d"
  agents: "all"
  exclude: ["known_corporate_dns_resolvers"]

success_criteria: >
  Confirm: >=1 host with >=50 DNS queries to a single 2LD where >=10 of the
  queries have subdomain length >50 chars, in a contiguous 60-min window.
  Refute: no such pattern, or pattern explained by software (e.g. ESET LiveGrid,
  AV cloud-lookup services).

investigation_steps:
  - "Aggregate Firewalla DNS-related alarms by (agent.name, second-level domain) over scope"
  - "For top candidates, fetch sample queries and compute subdomain length distribution"
  - "Cross-check second-level domain against threat-intel CDB lists"
  - "Verify whether queries are explained by known software (consult vendor-bookmarks.md)"

tags: [dns, exfiltration, network]
```

- [ ] **Step 2: Write H-2026-003 (Windows credential dumping artifacts)**

```yaml
id: H-2026-003
title: "Windows credential dumping artifacts in SRP / executable launches"
created: 2026-04-25
updated: 2026-04-25
owner: yasirhamza
status: proposed
priority: high

threat_actor: null
attack:
  techniques: ["T1003.001", "T1003.003"]
  tactics: ["credential-access"]

cti_sources:
  - type: mitre
    ref: "T1003.001"
    url: "https://attack.mitre.org/techniques/T1003/001/"
  - type: mitre
    ref: "T1003.003"
    url: "https://attack.mitre.org/techniques/T1003/003/"
  - type: vendor
    ref: "CrowdStrike Falcon: LSASS credential theft trends"
    url: "https://www.crowdstrike.com/blog/"

abstract: >
  Credential dumping via LSASS access (T1003.001) or NTDS.dit extraction
  (T1003.003) commonly leaves artifacts: tools like Mimikatz, ProcDump,
  comsvcs.dll abuse, NTDS-related copies. Detectable in Wazuh via SRP
  events and FIM signals on suspicious executables.

hypothesis: >
  If credential dumping has occurred on a Windows host in our environment,
  we should observe one or more of: SRP allow/block events for known dumpers
  (mimikatz, procdump, lazagne), executions of comsvcs.dll via rundll32,
  or recent file modifications matching ntds*, *.dit, or sam* in unexpected
  paths.

data_sources:
  - "wazuh-alerts-* (data.source: windows-srp)"
  - "wazuh-alerts-* (rule.id: 100660,100661,100662,100663)  # new SRP executables"

scope:
  time_range: "last_30d"
  agents: "all_windows"
  exclude: []

success_criteria: >
  Confirm: any single host with (a) SRP execution of mimikatz/procdump/lazagne,
  OR (b) rundll32 invoking comsvcs.dll MiniDump, OR (c) a new executable
  matching `*\(mimi|proc|laza)*.exe` outside Program Files.
  Refute: no such artifacts, or all matches explained by authorized red-team /
  pentest activity.

investigation_steps:
  - "Search SRP events with target_path matching mimikatz|procdump|lazagne|wce|dumpit"
  - "Aggregate new-executable alerts (100660-100663) for binaries with credential-dumper-like names"
  - "Pivot to entity_activity for any host that matched in steps 1-2"
  - "Cross-check timing against known authorized testing windows"

tags: [credential-access, windows, lsass]
```

- [ ] **Step 3: Validate both**

```bash
python3 scripts/validate_hypothesis.py hunts/backlog/H-2026-002.yaml hunts/backlog/H-2026-003.yaml
```

Expected: 2x `[PASS]`.

- [ ] **Step 4: Commit**

```bash
git add hunts/backlog/H-2026-002.yaml hunts/backlog/H-2026-003.yaml
git commit -m "feat(hunting): seed hypotheses H-2026-002 (DNS exfil), H-2026-003 (cred dumping)"
```

---

## Task 17: Backlog INDEX.yaml

**Files:**
- Create: `hunts/backlog/INDEX.yaml`

- [ ] **Step 1: Write the index**

```yaml
# Backlog index — drives /hunt menu and /hunt --next.
# Maintained by Claude during hunt sessions; analyst can reorder `queued` manually.

queued:
  - H-2026-001
  - H-2026-002
  - H-2026-003

in_progress: []

recently_completed: []
```

- [ ] **Step 2: Commit**

```bash
git add hunts/backlog/INDEX.yaml
git commit -m "feat(hunting): backlog index with three queued hypotheses"
```

---

## Task 18: Threat Hunting Program dashboard

**Files:**
- Create: `scripts/create_hunting_dashboard.py`

- [ ] **Step 1: Write the dashboard creation script**

Model after the existing `scripts/patch_firewalla_dashboard.py`. The script builds an OpenSearch Dashboards saved-objects NDJSON and POSTs it via the Saved Objects API.

Create `scripts/create_hunting_dashboard.py`:

```python
#!/usr/bin/env python3
"""Build and import the 'Threat Hunting Program' OpenSearch dashboard.

Panels:
  - Hunts run (time series, stacked by outcome)
  - Hypotheses by status (bar)
  - Findings by confidence (pie)
  - MITRE technique coverage (heatmap)
  - Top hypotheses by finding volume (table)
  - Detection promotions (count over time)
  - Hunt findings table (drill-down)

Run:
    DASHBOARD_PASSWORD=... python3 scripts/create_hunting_dashboard.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

DASH_TITLE = "Threat Hunting Program"
DASH_ID = "threat-hunting-program"
INDEX_PATTERN = "wazuh-alerts-*"
BASE_URL = os.environ.get("DASHBOARD_URL", "https://localhost")
USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
PASSWORD = os.environ.get("DASHBOARD_PASSWORD")


def _viz_hunts_run_timeseries() -> dict:
    return {
        "id": "hunting-runs-timeseries",
        "type": "visualization",
        "attributes": {
            "title": "Hunt findings over time (stacked by confidence)",
            "visState": json.dumps({
                "title": "Hunt findings over time",
                "type": "histogram",
                "params": {"type": "histogram"},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "date_histogram", "schema": "segment",
                     "params": {"field": "@timestamp", "interval": "auto"}},
                    {"id": "3", "type": "terms", "schema": "group",
                     "params": {"field": "data.hunt.confidence", "size": 3,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_findings_by_confidence() -> dict:
    return {
        "id": "hunting-findings-by-confidence",
        "type": "visualization",
        "attributes": {
            "title": "Findings by confidence",
            "visState": json.dumps({
                "title": "Findings by confidence",
                "type": "pie",
                "params": {"type": "pie", "isDonut": True},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "segment",
                     "params": {"field": "data.hunt.confidence", "size": 3}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100801 and rule.id <= 100803"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_mitre_coverage() -> dict:
    return {
        "id": "hunting-mitre-coverage",
        "type": "visualization",
        "attributes": {
            "title": "MITRE technique coverage (hunted last 30d)",
            "visState": json.dumps({
                "title": "MITRE coverage",
                "type": "table",
                "params": {"perPage": 20},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "bucket",
                     "params": {"field": "data.hunt.attack_technique", "size": 50,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_top_hypotheses() -> dict:
    return {
        "id": "hunting-top-hypotheses",
        "type": "visualization",
        "attributes": {
            "title": "Top hypotheses by finding volume",
            "visState": json.dumps({
                "title": "Top hypotheses by finding volume",
                "type": "table",
                "params": {"perPage": 20},
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "bucket",
                     "params": {"field": "data.hunt.hypothesis_id", "size": 20,
                                "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _viz_findings_table() -> dict:
    return {
        "id": "hunting-findings-table",
        "type": "search",
        "attributes": {
            "title": "Hunt findings (drill-down)",
            "columns": [
                "data.hunt.hypothesis_id",
                "data.hunt.attack_technique",
                "data.hunt.confidence",
                "data.hunt.summary",
                "agent.name",
            ],
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": INDEX_PATTERN,
                    "query": {"language": "kuery",
                              "query": "rule.id >= 100800 and rule.id <= 100899"},
                    "filter": [],
                }),
            },
        },
    }


def _build_dashboard(viz_ids: list[str]) -> dict:
    panels = []
    for i, vid in enumerate(viz_ids):
        x = (i % 2) * 24
        y = (i // 2) * 12
        panels.append({
            "version": "2.x",
            "type": "visualization" if vid != "hunting-findings-table" else "search",
            "gridData": {"x": x, "y": y, "w": 24, "h": 12, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {},
            "panelRefName": f"panel_{i}",
        })
    return {
        "id": DASH_ID,
        "type": "dashboard",
        "attributes": {
            "title": DASH_TITLE,
            "description": "TaHiTI-driven hunt program: cadence, MITRE coverage, finding volume, drill-down.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []}),
            },
        },
        "references": [
            {"name": f"panel_{i}",
             "type": "visualization" if vid != "hunting-findings-table" else "search",
             "id": vid}
            for i, vid in enumerate(viz_ids)
        ],
    }


def _import(objects: list[dict]) -> None:
    if not PASSWORD:
        print("DASHBOARD_PASSWORD not set", file=sys.stderr)
        sys.exit(2)

    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    ndjson = "\n".join(json.dumps(o) for o in objects).encode()
    boundary = "----HuntDashImport"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="hunting.ndjson"\r\n'
        "Content-Type: application/x-ndjson\r\n\r\n"
    ).encode() + ndjson + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{BASE_URL}/api/saved_objects/_import?overwrite=true",
        data=body,
        method="POST",
        headers={
            "osd-xsrf": "true",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    import base64
    auth = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    visualizations = [
        _viz_hunts_run_timeseries(),
        _viz_findings_by_confidence(),
        _viz_mitre_coverage(),
        _viz_top_hypotheses(),
    ]
    findings_table = _viz_findings_table()
    viz_ids = [v["id"] for v in visualizations] + [findings_table["id"]]
    dashboard = _build_dashboard(viz_ids)

    _import(visualizations + [findings_table, dashboard])
    print(f"Dashboard '{DASH_TITLE}' imported.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run the import**

```bash
DASHBOARD_PASSWORD=55uF3wo466JMScZV python3 scripts/create_hunting_dashboard.py
```

Expected: prints success JSON from the Saved Objects API; "Threat Hunting Program" dashboard appears at https://localhost/app/dashboards.

- [ ] **Step 3: Verify in browser**

Open the dashboard, confirm panels render. The findings table should show the test finding from Task 10.

- [ ] **Step 4: Commit**

```bash
git add scripts/create_hunting_dashboard.py
git commit -m "feat(hunting): Threat Hunting Program dashboard"
```

---

## Task 19: Operational test — run one hunt end-to-end

**Files:**
- Create: `hunts/runs/H-2026-001-<TIMESTAMP>.md` (will exist after the run)

- [ ] **Step 1: Reconnect MCP**

In Claude Code: `/mcp` (refresh against latest mcp-server).

- [ ] **Step 2: Run the seed hypothesis**

```
/hunt H-2026-001
```

Follow the Phase 1/2/3 flow. Expected:
- Phase 1: Claude restates scope, runs `attack_lookup.py T1071.001` and `T1571`, flags any data-source mismatches, asks for confirmation.
- Phase 2: Multi-step investigation using read-only MCP tools, with HitL gates at every pivot.
- Phase 3: Run abstract drafted, any findings shown for confirmation, hypothesis updated.

- [ ] **Step 3: Verify artifacts**

```bash
ls hunts/runs/                      # one new H-2026-001-*.md
ls proposed-rules/                  # any new XML drafts
git diff hunts/backlog/H-2026-001.yaml      # status update
```

- [ ] **Step 4: Verify Wazuh side**

If any findings were submitted, confirm via the dashboard or:

```
mcp__wazuh__search_alerts(filters={"data.hunt.hypothesis_id": "H-2026-001"}, time_range="last_1h")
```

- [ ] **Step 5: Capture friction**

Append a short retrospective to `docs/specs/2026-04-25-cti-driven-hunting-design.md` under the `## Implementation log` section: what was awkward, what to refine in `SKILL.md` or the schema. Make any small fixes inline.

- [ ] **Step 6: Commit run artifacts and any inline fixes**

```bash
# Note: hunts/runs/*.md is gitignored — commit only if you decide to share this run.
# For the operational test, commit it as evidence:
git add -f hunts/runs/H-2026-001-*.md
git add hunts/backlog/H-2026-001.yaml hunts/backlog/INDEX.yaml docs/specs/2026-04-25-cti-driven-hunting-design.md
git commit -m "test(hunting): first operational hunt run for H-2026-001 + retrospective"
```

---

## Task 20: Update CLAUDE.md with hunting docs

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a "CTI-Driven Threat Hunting" section**

Find the table of contents area (after "Lessons Learned"), append:

```markdown
## CTI-Driven Threat Hunting

TaHiTI-methodology hunt workflow. Manually triggered, agentic, HitL.

**Spec:** `docs/specs/2026-04-25-cti-driven-hunting-design.md`
**Plan:** `docs/plans/2026-04-25-cti-driven-hunting-implementation.md`

### Layout

| Path | Purpose |
|------|---------|
| `hunts/backlog/` | Hypothesis YAMLs (TaHiTI template). Validated by `scripts/validate_hypothesis.py`. |
| `hunts/runs/` | Investigation abstracts (one per hunt run). Gitignored by default. |
| `proposed-rules/` | Drafted Wazuh rule XMLs from hunt findings. Promoted manually to `config/wazuh_rules/`. |
| `cti-cache/attack/` | MITRE ATT&CK STIX bundle (gitignored, refreshed weekly via `scripts/refresh_attack.sh`). |
| `cti-cache/vendor-bookmarks.md` | Curated trusted-vendor TI sources. |
| `.claude/skills/hunt/` | The `/hunt` skill. |

### Helper scripts

| Script | Purpose |
|--------|---------|
| `scripts/refresh_attack.sh` | Refresh MITRE ATT&CK cache. Run weekly via `/schedule`. |
| `scripts/attack_lookup.py` | Look up an ATT&CK technique by ID. CLI + library. |
| `scripts/cisa_recent.py` | Pull recent CISA advisories from RSS. |
| `scripts/audit_hypotheses.py` | Weekly backlog audit (stale hypotheses, broken URLs, deprecated technique IDs). |
| `scripts/validate_hypothesis.py` | YAML schema validation. CI / pre-commit. |
| `scripts/create_hunting_dashboard.py` | Build and import "Threat Hunting Program" OpenSearch dashboard. |

### Rule chain (`100800-100899`)

| ID | Level | Description |
|----|-------|-------------|
| 100800 | 3 | Base hunt finding (anchor). |
| 100801 | 5 | Hunt finding — low confidence. |
| 100802 | 8 | Hunt finding — medium confidence. |
| 100803 | 12 | Hunt finding — high confidence. |
| 100810-100819 | reserved | Actor-attributed findings. |
| 100820-100899 | reserved | Future expansion. |

### Workflow

In Claude Code:
- `/hunt` — list backlog, pick.
- `/hunt H-2026-001` — load specific hypothesis.
- `/hunt --next` — run top of `INDEX.yaml.queued`.
- `/hunt --new` — free-form (Claude walks you through a TaHiTI hypothesis).
- `/hunt --from <url>` — generate hypothesis from a CISA / MITRE / vendor URL.

Findings land in `wazuh-alerts-*` via rule chain `100800-100803`. Visible in the "Threat Hunting Program" dashboard.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(hunting): document CTI-driven hunting workflow in CLAUDE.md"
```

---

## Task 21: Schedule weekly maintenance

**Files:** none (scheduling via `/schedule` skill)

- [ ] **Step 1: Schedule the ATT&CK refresh**

In Claude Code:

```
/schedule weekly: run /path/to/firewalla-wazuh/scripts/refresh_attack.sh
```

Confirm the routine appears in `/schedule list`.

- [ ] **Step 2: Schedule the backlog audit**

```
/schedule weekly: run python3 /path/to/firewalla-wazuh/scripts/audit_hypotheses.py
```

Confirm the routine appears in `/schedule list`.

- [ ] **Step 3: Document in CLAUDE.md** (one-line addition)

Under the "Helper scripts" table (Task 20), add a note:

```markdown
> Both `refresh_attack.sh` and `audit_hypotheses.py` are scheduled weekly via `/schedule`.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(hunting): note weekly /schedule routines for ATT&CK refresh + audit"
```

---

## Task 22: Final sync to deployment + push

**Files:** none (sync only)

- [ ] **Step 1: Sync any remaining changes to `/opt/wazuh-docker/single-node/`**

```bash
rsync -av --exclude='.git' --exclude='cti-cache/attack/enterprise-attack.json' \
  /path/to/firewalla-wazuh/ /opt/wazuh-docker/single-node/
```

- [ ] **Step 2: Verify Wazuh manager is healthy**

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | head -10
```

Expected: all daemons running.

- [ ] **Step 3: Push to private remote**

```bash
cd /path/to/firewalla-wazuh
git status
git push origin main
```

- [ ] **Step 4: Sanitize-and-push to public remote (if and only if no sensitive content)**

Per the project's public-repo workflow (see `MEMORY.md`):

```bash
# Review every changed file in the unpushed delta:
git log public/main..main --stat

# Confirm:
# - No real device names (use placeholders only)
# - No real IPs / users / domains beyond what's already public
# - hunts/backlog/*.yaml: review content for sensitive identifiers
# - hunts/runs/ is gitignored (good)

# If clean:
git push public main
```

If any hunt artifact contains sensitive identifiers, do NOT push to public. Either sanitize, or exclude that file from the public mirror via `.gitignore`-pathing.

---

## Done criteria (from spec §11)

- [ ] `/hunt`, `/hunt <id>`, `/hunt --new`, `/hunt --next`, `/hunt --from <url>` all functional (Tasks 15, 19)
- [ ] 3 seed hypotheses authored in `hunts/backlog/`, each grounded in real CTI (Tasks 4, 16)
- [ ] One end-to-end hunt run completed with finding submitted to Wazuh and visible in the new dashboard (Tasks 10, 19)
- [ ] One detection promoted (drafted rule XML in `proposed-rules/`) — produced naturally during Task 19, or back-fill if none surfaced
- [ ] "Threat Hunting Program" dashboard live with all panels populated (Task 18)
- [ ] Unit + integration tests passing (`pytest mcp-server/tests/ scripts/test_*.py`)

## Known follow-ups (deferred from this plan)

These are aware-but-deferred. Worth a small follow-up plan after the operational test surfaces real friction.

- **Backlog-coverage panel** (spec §8.1): the MITRE coverage heatmap currently only aggregates from rule-100800+ alerts (techniques you've actually hunted). The richer view also surfaces techniques in the backlog YAMLs that you've *intended* to hunt but haven't yet. Implementation: a small `scripts/export_backlog_to_status.py` that emits one sidecar-status event per `hunts/backlog/*.yaml` nightly, plus a third panel that joins on `data.hunt.attack_technique`.
- **Export dashboard NDJSON to repo** (consistency with `dashboards/firewalla-dashboard.ndjson`): after Task 18 imports, also save the NDJSON to `dashboards/threat-hunting-dashboard.ndjson` for diff-ability and disaster recovery.
- **Pre-commit hook for `validate_hypothesis.py`**: wire `scripts/validate_hypothesis.py` into `.githooks/pre-commit` (it currently runs only as the CI job — fine for now, but immediate feedback at commit time would catch invalid YAML faster).
- **MISP integration** (spec §6.5 Phase 2): own design + plan cycle once the manual hunt workflow has stabilized.

---
