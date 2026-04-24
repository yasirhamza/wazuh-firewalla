"""Tests for time_range parsing."""
import pytest

from src.time_range import parse_time_range, TimeRangeError


def test_parse_last_24h():
    assert parse_time_range("last_24h") == {"gte": "now-24h/h", "lte": "now"}


def test_parse_last_7d():
    assert parse_time_range("last_7d") == {"gte": "now-7d/d", "lte": "now"}


def test_parse_last_30d():
    assert parse_time_range("last_30d") == {"gte": "now-30d/d", "lte": "now"}


def test_parse_iso_range():
    got = parse_time_range("2026-04-20T00:00:00Z/2026-04-24T00:00:00Z")
    assert got == {
        "gte": "2026-04-20T00:00:00Z",
        "lte": "2026-04-24T00:00:00Z",
    }


def test_parse_rejects_unknown_shorthand():
    with pytest.raises(TimeRangeError, match="unsupported"):
        parse_time_range("last_century")


def test_parse_rejects_backward_range():
    with pytest.raises(TimeRangeError, match="must be before"):
        parse_time_range("2026-04-24T00:00:00Z/2026-04-20T00:00:00Z")


def test_parse_rejects_span_over_90_days():
    with pytest.raises(TimeRangeError, match="90 days"):
        parse_time_range("2026-01-01T00:00:00Z/2026-04-30T00:00:00Z")


def test_parse_rejects_malformed():
    with pytest.raises(TimeRangeError):
        parse_time_range("not-a-range")
