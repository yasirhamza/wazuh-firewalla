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
