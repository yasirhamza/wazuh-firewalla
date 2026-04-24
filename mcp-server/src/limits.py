"""Rate limiter (token bucket, per-key, in-process) + result cap helper."""
import math
import time
from dataclasses import dataclass
from threading import Lock


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded, retry in {retry_after:.1f}s")


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token-bucket per key. refill_rate tokens/sec, capped at burst."""

    def __init__(self, per_min: int, burst: int):
        self._refill = per_min / 60.0
        self._burst = float(burst)
        self._lock = Lock()
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                self._buckets[key] = _Bucket(tokens=self._burst - 1, updated=now)
                return
            # refill
            elapsed = now - b.updated
            b.tokens = min(self._burst, b.tokens + elapsed * self._refill)
            b.updated = now
            if b.tokens >= 1:
                b.tokens -= 1
                return
            deficit = 1 - b.tokens
            raise RateLimitExceeded(retry_after=math.ceil(deficit / self._refill))


def cap_results(rows: list, cap: int, total_matched: int) -> dict:
    truncated = len(rows) > cap or total_matched > cap
    return {
        "results": rows[:cap],
        "truncated": truncated,
        "total_matched": total_matched,
    }
