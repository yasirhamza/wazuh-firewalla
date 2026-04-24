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
    """Token-bucket per key. refill_rate tokens/sec, capped at burst.

    Buckets that have been idle longer than `_BUCKET_TTL_SEC` are dropped
    opportunistically (when we notice we haven't pruned in a while). This
    keeps the dict bounded if the caller ever switches from a single
    'global' key to per-caller keying.
    """

    _PRUNE_INTERVAL_SEC = 60.0
    _BUCKET_TTL_SEC = 300.0

    def __init__(self, per_min: int, burst: int):
        self._refill = per_min / 60.0
        self._burst = float(burst)
        self._lock = Lock()
        self._buckets: dict[str, _Bucket] = {}
        self._last_prune = time.monotonic()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_prune > self._PRUNE_INTERVAL_SEC:
                cutoff = now - self._BUCKET_TTL_SEC
                stale = [k for k, b in self._buckets.items() if b.updated < cutoff]
                for k in stale:
                    del self._buckets[k]
                self._last_prune = now

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
