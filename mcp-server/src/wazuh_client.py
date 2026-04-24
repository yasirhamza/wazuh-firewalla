"""Thin OpenSearch client wrapper with one retry + wall-clock deadline."""
import logging
import time
from typing import Any

from opensearchpy import OpenSearch, ConnectionError as OSConnectionError, TransportError

logger = logging.getLogger(__name__)

# Total wall-clock budget for a single client call (search/count), across any retry.
# When the budget is exceeded, raise WazuhClientError(code="timeout").
CALL_DEADLINE_SEC = 10.0

# Per-attempt request_timeout is half the deadline so the retry fits within budget.
PER_ATTEMPT_TIMEOUT = 5.0


class WazuhClientError(Exception):
    """Categorized error surfaced to the service layer."""

    def __init__(self, code: str, message: str, cause: Exception | None = None):
        self.code = code
        self.message = message
        self.cause = cause
        super().__init__(f"{code}: {message}")


class WazuhClient:
    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        timeout: float = CALL_DEADLINE_SEC,
    ):
        self._deadline = timeout
        self._os = OpenSearch(
            hosts=[url],
            http_auth=(user, password) if user else None,
            use_ssl=url.startswith("https"),
            verify_certs=False,  # self-signed certs in the Wazuh stack
            ssl_show_warn=False,
            http_compress=True,
        )
        if url.startswith("https"):
            logger.warning("TLS cert verification disabled (self-signed Wazuh certs)")

    def _call_with_retry(self, fn, **kwargs):
        """Run fn with up to one retry, bounded by a monotonic deadline.

        If the first attempt fails AND the deadline has already passed, raise
        'timeout' without retrying. If both attempts fail, raise
        'opensearch_unavailable'.
        """
        start = time.monotonic()
        try:
            return fn(request_timeout=PER_ATTEMPT_TIMEOUT, **kwargs)
        except (OSConnectionError, TransportError) as e:
            elapsed = time.monotonic() - start
            remaining = self._deadline - elapsed
            if remaining <= 0:
                raise WazuhClientError(code="timeout", message=str(e), cause=e)
            logger.warning("OpenSearch transient error: %s, retrying once (remaining=%.1fs)", e, remaining)
            # Small backoff, but never beyond the remaining budget.
            sleep_for = min(0.5, max(0.0, remaining - 0.1))
            time.sleep(sleep_for)
            try:
                return fn(request_timeout=min(PER_ATTEMPT_TIMEOUT, remaining), **kwargs)
            except (OSConnectionError, TransportError) as e2:
                # If we exhausted the wall clock specifically, surface as 'timeout'
                # so the LLM gets a useful hint per the spec error table.
                if time.monotonic() - start >= self._deadline:
                    raise WazuhClientError(code="timeout", message=str(e2), cause=e2)
                raise WazuhClientError(
                    code="opensearch_unavailable",
                    message=str(e2),
                    cause=e2,
                )

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._call_with_retry(self._os.search, index=index, body=body)

    def count(self, index: str, body: dict[str, Any]) -> int:
        resp = self._call_with_retry(self._os.count, index=index, body=body)
        return resp["count"]

    def ping(self) -> bool:
        try:
            return bool(self._os.ping())
        except Exception:
            return False
