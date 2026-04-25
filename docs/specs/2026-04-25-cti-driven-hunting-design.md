# CTI-Driven Threat Hunting — Design

**Date:** 2026-04-25
**Owner:** yasirhamza
**Status:** Draft

## 1. Overview

This project adds a manually-triggered, agentic threat-hunting workflow to the Firewalla/Wazuh stack. Hunts are CTI-grounded, follow TaHiTI methodology end-to-end, run inside Claude Code with the analyst in the loop at every decision point, and produce findings that land in Wazuh as alerts (rule IDs `100800-100899`).

The homelab is treated as a SOC simulator. Vocabulary, artifacts, and workflows are designed to scale to a multi-analyst enterprise SOC; the fact that there's currently one analyst is incidental.

### 1.1 Scope

**In scope:**
- TaHiTI-compliant hypothesis template, hunt lifecycle, and artifacts
- A `/hunt` skill (manual trigger, interactive HitL session)
- CTI integration: MITRE ATT&CK (cached), CISA advisories (RSS), vendor reports (web fetch)
- New MCP tool `mcp__wazuh__submit_hunt_finding`
- New Wazuh rule chain `100800-100899`
- "Threat Hunting Program" Wazuh dashboard
- Detection-promotion path: hunt finding → drafted Wazuh rule XML in `proposed-rules/`

**Explicitly deferred to later sub-projects:**

| Sub-project | Deferred work |
|------------|---------------|
| Phase 2 | MISP self-hosted deployment + `mcp__wazuh__misp_*` tools |
| Phase 3 | Scheduled / autonomous hunts (cron-driven `hunt-runner` sidecar) |
| Phase 4 | Web hunt console UI (multi-user, real-time hunt streaming) |
| Separate spec | PEAK "Baseline" hunt track (statistical anomaly detection) |
| Out entirely | Sigma → Wazuh rule conversion (LLM-driven approach supersedes) |

## 2. TaHiTI lifecycle (in our environment)

| Phase | What happens | Artifact produced |
|-------|-------------|-------------------|
| **Initiate** | Analyst picks (or generates) a CTI-grounded hypothesis. Claude pulls relevant CTI context (ATT&CK technique details, CISA advisory, vendor report) and helps the analyst flesh out a TaHiTI hypothesis. | `hunts/backlog/<id>.yaml` (status: `proposed`) |
| **Hunt** | Analyst runs `/hunt <id>` (or `/hunt --new` for free-form). Claude executes the investigation as multi-step MCP tool calls, narrating findings, asking the analyst at each decision point. | `hunts/runs/<id>-<timestamp>.md` (investigation abstract — written for every run, including null results) |
| **Finalize** | Confirmed findings → Wazuh alert via new MCP tool. Improvement candidates → drafted Wazuh rule XML in `proposed-rules/`. Hypothesis status updated. | Wazuh alerts, drafted detection rules, updated backlog |

## 3. Components

1. **`/hunt` skill** at `.claude/skills/hunt/SKILL.md` — primary entry point; routes between backlog/free-form/CTI-URL modes; primes Claude with TaHiTI process discipline.
2. **`hunts/` directory** — git-tracked, holds the hypothesis backlog, run abstracts, and proposed detection rules.
3. **CTI fetch layer** — small helper modules (`scripts/attack_lookup.py`, `scripts/cisa_recent.py`) plus the cached ATT&CK STIX bundle. Exposed to Claude via existing tool surface (`Read`, `WebFetch`, `WebSearch`, `Bash`). No new sidecar.
4. **`mcp__wazuh__submit_hunt_finding`** — new MCP tool; writes a structured finding to the sidecar-status JSONL stream so it's ingested via the existing rule-chain pattern.
5. **Wazuh rules `100800-100899`** — base hunt-finding rule, severity-by-confidence chain, reserved ranges for actor-attributed and proposed-detection signals.
6. **"Threat Hunting Program" dashboard** — new OpenSearch dashboard with hunt-cadence, MITRE-coverage, and finding-confidence panels.

## 4. Data structures

### 4.1 Hypothesis (`hunts/backlog/<id>.yaml`)

Mirrors the TaHiTI hypothesis template field-for-field.

```yaml
id: H-2026-001
title: "Beaconing to low-reputation infrastructure from Windows endpoints"
created: 2026-04-25
updated: 2026-04-25
owner: yasirhamza
status: proposed   # proposed | queued | in_progress | completed | inconclusive | dropped
priority: medium   # high | medium | low

# CTI grounding (required — no ungrounded hypotheses)
threat_actor: null   # null is OK; e.g. "Volt Typhoon" if actor-specific
attack:
  techniques: ["T1071.001", "T1571"]   # MITRE ATT&CK technique IDs
  tactics: ["command-and-control"]
cti_sources:
  - { type: mitre,  ref: "T1071.001", url: "https://attack.mitre.org/techniques/T1071/001/" }
  - { type: cisa,   ref: "AA24-038A", url: "https://www.cisa.gov/news-events/...", date: 2024-02-07 }
  - { type: vendor, ref: "Mandiant M-Trends 2025", url: "..." }

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
  agents: "all_windows"        # shorthand keyword resolved at hunt time (e.g. "all_windows", "all", "<list of agent names>"). Resolver implementation TBD in plan.
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

### 4.2 Run abstract (`hunts/runs/<id>-<timestamp>.md`)

Written every time a hunt runs, including null results.

```markdown
# Hunt run: H-2026-001 @ 2026-04-25T22:00Z

**Hypothesis:** Beaconing to low-reputation infrastructure from Windows endpoints
**Analyst:** yasirhamza
**Started:** 2026-04-25T22:00Z  **Finished:** 2026-04-25T22:18Z
**Outcome:** inconclusive   <!-- confirmed_threat | no_threat_found | inconclusive | dropped -->

## Tools used
- mcp__wazuh__aggregate_alerts x 4
- mcp__wazuh__search_alerts x 7
- mcp__wazuh__entity_activity x 2
- mcp__wazuh__threat_intel_matches x 1

## Investigation
[Claude's narrative — query, result, reasoning, next pivot. Includes
HitL decision points where the analyst redirected.]

## Findings
1. **Medium confidence** — `oehpsd` shows 47 flows over 6h to `34.117.65.55`
   (Google), jitter 8%. Concurrent SRP shows Chrome — likely Google Sync.
   Submitted as alert: rule 100802, hunt_finding_id=`F-2026-001-a`.

## Detections proposed
- None this run. Suggest baseline tuning if same pattern persists.

## Lessons learned / hypothesis refinement
- Need to exclude Google/Microsoft ASNs from candidate set.
- Update H-2026-001 `scope.exclude` to add ASN allowlist.
```

### 4.3 Hunt finding (alert payload)

Written by `mcp__wazuh__submit_hunt_finding` to the sidecar-status JSONL stream so it gets ingested via the existing rule chain.

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
    "summary": "oehpsd: 47 flows to 34.117.65.55 over 6h, jitter 8%",
    "recommendation": "Likely benign Google Sync; baseline this destination.",
    "evidence": {
      "agent_name": "oehpsd",
      "destination_ip": "34.117.65.55",
      "flow_count": 47,
      "time_window": "2026-04-25T16:00Z/2026-04-25T22:00Z",
      "supporting_alert_ids": ["abc123...", "def456..."]
    }
  }
}
```

### 4.4 Wazuh rule chain (`100800-100899`)

```xml
<group name="hunting,">
  <!-- 100800: base hunt finding (anchor) -->
  <rule id="100800" level="3">
    <if_sid>100500</if_sid>
    <field name="job_type">^hunt_finding$</field>
    <description>Hunt finding: $(hunt.hypothesis_id) - $(hunt.summary)</description>
    <group>hunting,</group>
    <mitre><id>$(hunt.attack_technique)</id></mitre>
  </rule>

  <!-- Severity by confidence -->
  <rule id="100801" level="5">  <!-- low -->
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^low$</field>
    <description>Hunt finding (low conf): $(hunt.summary)</description>
  </rule>
  <rule id="100802" level="8">  <!-- medium -->
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^medium$</field>
  </rule>
  <rule id="100803" level="12"> <!-- high -->
    <if_sid>100800</if_sid>
    <field name="hunt.confidence">^high$</field>
  </rule>

  <!-- 100810-100819: reserved for actor-attributed high-confidence findings (e.g. Volt Typhoon TTPs observed) -->
  <!-- 100820-100899: reserved for future expansion (e.g. hypothesis-refinement signals, baseline-anomaly findings) -->
</group>
```

### 4.5 Backlog index (`hunts/backlog/INDEX.yaml`)

```yaml
queued:
  - H-2026-001
  - H-2026-005
  - H-2026-007
in_progress:
  - H-2026-003
recently_completed:
  - { id: H-2026-002, completed: 2026-04-23, outcome: no_threat_found }
  - { id: H-2026-004, completed: 2026-04-20, outcome: confirmed_threat }
```

## 5. The `/hunt` skill flow

### 5.1 Invocation modes

| Command | What it does |
|---------|-------------|
| `/hunt` | List proposed/queued backlog hypotheses, ask analyst to pick one. |
| `/hunt H-2026-001` | Load that hypothesis from `hunts/backlog/H-2026-001.yaml`. |
| `/hunt --next` | Run the top item from `INDEX.yaml.queued` without the menu. |
| `/hunt --new` | Free-form: prompt the analyst for a hypothesis seed (CTI URL, technique ID, threat actor, or natural-language idea). Claude walks them through generating a TaHiTI-compliant hypothesis, writes it to the backlog, then proceeds to hunt. |
| `/hunt --from <url>` | Generate a hypothesis from a CTI source (CISA advisory URL, MITRE technique URL, vendor blog post). Claude fetches, extracts TTPs, drafts hypothesis YAML, asks analyst to confirm/edit, then proceeds. |

### 5.2 Phase structure (driven by SKILL.md)

```
PHASE 1: Initiate
  - Restate hypothesis, success criteria, and scope to the analyst
  - Pull CTI context (ATT&CK detection notes, CISA advisory body if any)
  - Flag CTI-data-source mismatches before running queries
  - Set hypothesis status: in_progress
  - HitL gate: analyst confirms before any queries run

PHASE 2: Hunt
  - Execute investigation_steps from the hypothesis as MCP tool calls
  - After each step: narrate the result, state what it implies, propose next pivot
  - HitL gate at each pivot
  - Maintain a live evidence ledger
  - Auto-stop conditions:
    * Success criteria met (confirmed)
    * 30+ tool calls without convergence (escalate to analyst)
    * Analyst says "stop"

PHASE 3: Finalize
  - Draft the run abstract
  - For each confirmed finding: draft submit_hunt_finding payload, show analyst,
    submit on confirmation
  - For each proposed detection: draft Wazuh rule XML to proposed-rules/<id>.xml,
    show analyst, commit on confirmation
  - Update hypothesis: status, updated date, append run reference
  - HitL gate before any write
```

### 5.3 Tool guardrails

The SKILL.md explicitly enumerates:

- **Read-only investigation:** `mcp__wazuh__search_alerts`, `aggregate_alerts`, `entity_activity`, `first_seen_domains`, `threat_intel_matches`, `alert_overview`, `trend_delta`, `get_alert`, `sidecar_health`
- **Write (HitL-gated):** `mcp__wazuh__submit_hunt_finding`, `Write` (only for `hunts/runs/`, `hunts/backlog/`, `proposed-rules/`)
- **CTI lookups:** `WebFetch`, `Read` for the cached ATT&CK STIX bundle, `WebSearch`, `Bash` (only for `python3 scripts/attack_lookup.py` and `python3 scripts/cisa_recent.py`)
- **Forbidden during hunts:** general `Bash`, `Edit` outside the `hunts/` and `proposed-rules/` trees, `submit_hunt_finding` without analyst confirmation

### 5.4 HitL decision protocol

Every HitL gate uses a fixed protocol so the analyst's mental model is consistent:

```
[OBSERVATION]  what I just learned
[INTERPRETATION]  what it means for the hypothesis
[PROPOSAL]  next step (specific tool call + parameters)
[OPTIONS]  continue / redirect to <X> / stop
```

The analyst replies with `continue`, `redirect: <new direction>`, `stop`, or just describes what they want.

## 6. CTI integration

Three sources, three access patterns. All read-only, no new sidecars.

### 6.1 MITRE ATT&CK (cached locally, refreshed weekly)

The full enterprise STIX 2.1 bundle (~10MB) cached at `cti-cache/attack/enterprise-attack.json`. Refresh via a scheduled `/schedule` cron:

```bash
# scripts/refresh_attack.sh
curl -fsSL -o /tmp/attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
mv /tmp/attack.json /path/to/firewalla-wazuh/cti-cache/attack/enterprise-attack.json
date -u +"%Y-%m-%dT%H:%M:%SZ" > /path/to/firewalla-wazuh/cti-cache/attack/LAST_REFRESHED.txt
```

Helper module `scripts/attack_lookup.py`:

```python
# Returns {name, tactic, description, detection, data_sources, sub_techniques, references}
def lookup(technique_id: str) -> dict:
    ...
```

### 6.2 CISA advisories (RSS, fetched on demand)

CISA publishes to a public RSS feed (`https://www.cisa.gov/cybersecurity-advisories/all.xml`). No cache — fetched on demand via `WebFetch`.

`scripts/cisa_recent.py` returns the last N advisories with `id`, `title`, `date`, `url`, `summary`. Used by `/hunt --new` to surface candidate hypotheses.

`/hunt --from <CISA_URL>` uses `WebFetch` directly to pull the advisory body; Claude extracts TTPs, IOCs, and adversary attribution into a hypothesis YAML.

### 6.3 Vendor reports (web fetch on demand)

No cache, no curated list of feeds. Analyst pastes a URL into `/hunt --from <url>` and Claude uses `WebFetch` + `WebSearch` to extract TTPs.

A small `cti-cache/vendor-bookmarks.md` file lists trusted vendors (Mandiant, Sekoia, Volexity, CrowdStrike, ...) — Claude consults this during free-form hunts when context is needed.

### 6.4 Repo layout (CTI side)

```
cti-cache/
  attack/
    enterprise-attack.json      # 10MB, .gitignored
    LAST_REFRESHED.txt          # tracked
  vendor-bookmarks.md           # tracked

scripts/
  attack_lookup.py
  cisa_recent.py
  refresh_attack.sh
  audit_hypotheses.py           # weekly check for stale technique refs / dead URLs
```

### 6.5 Phase 2 placeholder (MISP)

The CTI module is structured so MISP can slot in as a fourth source without changing anything else:

- New `scripts/misp_lookup.py` alongside `attack_lookup.py`
- New `mcp__wazuh__misp_search_event` MCP tool
- Hypothesis YAML gains `cti_sources: [{type: misp, ref: <event-uuid>}]`

No structural change to `/hunt`, no schema migration.

## 7. Detection promotion

Three outcomes for any hunt finding, decided during Phase 3 (Finalize):

| Outcome | What happens |
|---------|-------------|
| One-off observation | Submit as a hunt finding alert (rule `100801-100803`), no rule promotion. |
| Promote to detection | Claude drafts Wazuh rule XML in `proposed-rules/<id>-<slug>.xml`, opens for analyst review, commits to repo on approval. Rule deployment (move to `config/wazuh_rules/`, validate with `wazuh-logtest`, restart manager) is a separate manual step. |
| Refine the hypothesis | Update the backlog YAML (`scope.exclude`, `success_criteria`, `investigation_steps`). Hypothesis status: `completed` (refined for next run). |

The promotion path stops at "drafted XML committed to `proposed-rules/`." Claude does **not** modify live rules in `config/wazuh_rules/`, restart the manager, or test rule deployment. That stays a deliberate human action.

The drafted rule includes:
- Next available rule ID from `100800-100899` (tracked in `proposed-rules/RULE_ID_REGISTER.md`)
- MITRE mapping (the technique from the hypothesis)
- Comment header citing the hunt run that produced it
- Sibling `proposed-rules/<id>-<slug>.test.json` for `wazuh-logtest` validation

## 8. Observability

### 8.1 "Threat Hunting Program" dashboard

A new OpenSearch dashboard alongside Firewalla and Sidecar Monitoring.

**Panels:**
- **Hunts run (time series)** — runs/day, stacked by outcome
- **Hypotheses by status** — bar chart of proposed/queued/in_progress/completed/inconclusive/dropped
- **Findings by confidence** — pie of low/medium/high
- **MITRE coverage heatmap** — which ATT&CK techniques have hypotheses, which have been hunted recently. Driven by aggregating `data.hunt.attack_technique` from rule 100800 alerts plus reading the backlog YAMLs.
- **Top hypotheses by finding volume** — high signal or high noise; both worth knowing
- **Detection promotions** — count of `proposed-rules/` files committed per month
- **Hunt findings table** — drill-down filterable by hypothesis_id, technique, confidence, outcome

Backlog/MITRE coverage panels read from a small periodic export of `hunts/backlog/*.yaml` to a sidecar status event (one event per hypothesis, refreshed nightly via cron skill).

### 8.2 Program-health metrics

Tracked on the dashboard so the analyst can spot drift. Not enforced by tooling.

| Metric | Target | Why it matters |
|--------|--------|----------------|
| Hunts/week | >=1 | Cadence keeps the muscle warm |
| Hypotheses with `confirmed_threat` | <20% of completed | Low = catching things proactively. >50% suggests too-obvious hypotheses |
| Hypotheses with `inconclusive` | <30% | High = scope/data-source mismatch problem |
| Detection promotions/month | >=1 | Hunt program feeding back into detections |
| Stale hypotheses (proposed >90 days) | =0 | Run, refine, or drop — don't let backlog rot |

### 8.3 Audit trail

Everything is git-tracked. A complete audit of any hunt:

- `hunts/backlog/<id>.yaml` (with full git history of refinements)
- `hunts/runs/<id>-<timestamp>.md` (one file per run)
- `proposed-rules/<id>-<slug>.xml` (drafted detection)
- `wazuh-alerts-*` documents with `data.hunt.run_id` (queryable from dashboard)
- Git log for the hunt commit

No separate "hunt management database." The repo + the SIEM are the system of record.

## 9. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Hallucinated findings | HitL gate before `submit_hunt_finding`. Phase 3 preview shows the exact payload, including `evidence.supporting_alert_ids`. Analyst can `mcp__wazuh__get_alert <id>` on each one to verify. |
| Hypothesis drift mid-hunt | Phase-2 HitL gate at every pivot. SKILL.md instructs Claude to restate the hypothesis before proposing a pivot. |
| Cost runaway | Auto-stop after 30 tool calls without convergence. SKILL.md instructs batching of read-only queries. Token cost shown to analyst at end. |
| Finding noise | Promotion HitL-gated; analyst can drop a finding at Phase 3. The "confirmed_threat <20%" target gives early warning. |
| CTI source rot | ATT&CK refreshes weekly. Hypothesis YAMLs with deprecated technique IDs surface in `scripts/audit_hypotheses.py` (weekly cron). 404'd vendor URLs surface in Phase 1. |
| Negative-result fatigue | TaHiTI explicitly treats null findings as success. Dashboard shows `no_threat_found` as a positive metric. Refinements count as promotion. |
| Detection-promotion blast radius | Promotion path stops at `proposed-rules/`. Drafted XML ships with a `.test.json` companion for `wazuh-logtest`. |
| Sensitive-finding leak to public repo | All hunt artifacts in private repo only. Pre-commit hook (`scripts/check_sensitive.py`) blocks the patterns we care about. Public repo `.gitignore` excludes `hunts/` and `proposed-rules/`. |

## 10. Testing strategy

**Unit tests (`mcp-server/tests/`):**
- `test_submit_hunt_finding.py` — schema validation, JSONL append, error paths
- `test_attack_lookup.py` — technique lookup, missing-ID handling, sub-technique walking
- `test_hypothesis_validator.py` — YAML schema validation (every hypothesis must have grounded `cti_sources`, valid `attack.techniques`, declared `success_criteria`)

**Integration tests:**
- End-to-end finding pipeline: write a `submit_hunt_finding` event, assert it appears in `wazuh-alerts-*` within 5s with the expected `rule.id` and MITRE mapping
- Hypothesis loader: load every YAML in `hunts/backlog/`, assert all schemas pass
- ATT&CK staleness check: parse the cached bundle, assert all hypothesis-referenced technique IDs still exist

**Operational tests (the only honest test of the actual hunting):**
- Run the first 3-5 hunts manually end-to-end against real Wazuh data. Capture friction in a retrospective. Refine SKILL.md and hypothesis template based on what was awkward.
- Adversarial hunt — author a hypothesis you *know* should confirm (craft a Firewalla flow matching T1071.001 patterns). Confirm the hunt finds it.
- Null-result hunt — author a hypothesis you *know* won't confirm. Confirm the run abstract is still produced and the outcome is `no_threat_found`.

## 11. Done criteria

- `/hunt`, `/hunt <id>`, `/hunt --new`, `/hunt --next`, `/hunt --from <url>` all functional
- 3-5 seed hypotheses authored in `hunts/backlog/`, each grounded in real CTI
- One end-to-end hunt run completed manually, with finding submitted to Wazuh and visible in the new dashboard
- One detection promoted (drafted rule XML in `proposed-rules/`)
- "Threat Hunting Program" dashboard live with all panels populated
- Unit + integration tests passing in CI

## 12. Implementation log

**2026-04-25 — Pipeline verified end-to-end.** Submitted a medium-confidence test finding via `mcp__wazuh__submit_hunt_finding` (finding_id `F-2026-001-a`); alert appeared in `wazuh-alerts-*` within ~15s with `rule.id=100802`, `rule.level=8`, `rule.description="Hunt finding (medium conf): test: medium-confidence finding"`, `rule.groups=[hunting,sidecar_status]`, and full `data.hunt.*` payload (hypothesis_id, run_id, finding_id, attack_technique=`T1071.001`, attack_tactic, confidence, analyst, evidence). Backend (`HeartbeatWriter.record_hunt_finding` → shared `sidecar-status.json` JSONL → Wazuh JSON decoder → rule chain `100500 → 100800 → 100802`) is operational.

**Known limitation:** `rule.mitre` is null on hunt-finding alerts because Wazuh's `<mitre><id>` element does not expand `$(field)` substitutions — only literal technique IDs. The plan accommodates this: rule slots `100810-100819` are reserved for actor-/technique-specific rules with hardcoded MITRE IDs. Dashboards (Task 18) read the technique from `data.hunt.attack_technique` instead of `rule.mitre`. Native Wazuh MITRE features (Security Events module, ATT&CK Navigator export) will not surface hunting findings until matching 100810+ rules are authored.

**2026-04-25 — First operational hunt (H-2026-001) complete.** Outcome: `no_threat_found`. Run abstract: `hunts/runs/H-2026-001-20260425T1305Z.md`. The run produced one detection candidate (`proposed-rules/100454-urlhaus-ip-shared-cdn-suppression.xml`) addressing a high-volume FP class observed during the hunt: rule 100452 (URLhaus IP match) is firing ~96/day against shared CDN infrastructure (GitHub Pages, Fastly, Cloudflare, Azure CDN) — same FP failure mode previously documented for the URLhaus-domains feed.

**Friction captured for skill / schema iteration:**
1. **Hypothesis success criterion was unverifiable** as written (the "no concurrent user browsing" clause requires browser-history or process-tree data we don't collect). SKILL.md should explicitly walk the analyst through "is this success criterion measurable from our data sources?" during Phase 1, not just "are the techniques covered." Hypothesis schema should require `success_criteria` to reference at least one available `data_sources` entry.
2. **`attack_lookup.py` returns thin data** for many techniques — `data_sources` and `detection` came back empty for both T1071.001 and T1571 because those fields live in separate STIX relationship objects in the upstream bundle. Worth a follow-up to enrich the helper.
3. **`runs:` field on hypothesis YAMLs** — convention not yet defined. The run-abstract pointer was appended ad hoc. Define this in the schema (`Hypothesis` Pydantic model) before the next run.
4. **Native SRP rule events** (rule.groups: `srp`) coexist with the planned `data.source: windows-srp` sidecar source; both index alongside each other but have different field shapes. Future hypotheses scoping to "Windows SRP data" should specify which path.
