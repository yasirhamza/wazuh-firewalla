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
