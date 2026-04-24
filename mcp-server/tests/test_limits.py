"""Tests for rate limiter + result-size cap."""
import time

import pytest

from src.limits import RateLimiter, RateLimitExceeded, cap_results


def test_rate_limiter_allows_within_burst():
    rl = RateLimiter(per_min=60, burst=10)
    for _ in range(10):
        rl.check("key-a")  # does not raise


def test_rate_limiter_blocks_over_burst():
    rl = RateLimiter(per_min=60, burst=3)
    rl.check("k"); rl.check("k"); rl.check("k")
    with pytest.raises(RateLimitExceeded) as exc:
        rl.check("k")
    assert exc.value.retry_after > 0


def test_rate_limiter_refills_over_time(monkeypatch):
    current = [1000.0]
    monkeypatch.setattr("src.limits.time.monotonic", lambda: current[0])
    rl = RateLimiter(per_min=60, burst=3)  # 1 token/sec
    rl.check("k"); rl.check("k"); rl.check("k")
    current[0] += 1.0  # 1 second later
    rl.check("k")  # should pass — 1 token refilled


def test_rate_limiter_keys_are_independent():
    rl = RateLimiter(per_min=60, burst=2)
    rl.check("a"); rl.check("a")
    rl.check("b"); rl.check("b")  # different key, still ok


def test_cap_results_below_cap():
    out = cap_results([1, 2, 3], cap=10, total_matched=3)
    assert out == {"results": [1, 2, 3], "truncated": False, "total_matched": 3}


def test_cap_results_truncates():
    rows = list(range(150))
    out = cap_results(rows, cap=100, total_matched=250)
    assert out["results"] == rows[:100]
    assert out["truncated"] is True
    assert out["total_matched"] == 250
