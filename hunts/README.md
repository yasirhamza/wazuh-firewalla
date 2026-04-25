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
