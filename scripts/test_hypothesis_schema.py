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
