import time
from collections import defaultdict, deque

# MVP placeholder -- NOT a universally "correct" number. The right limit
# depends on company size, number of calling applications, and expected
# traffic (see Phase 6 notes). Adjust for your real deployment.
DEFAULT_LIMIT = 100
DEFAULT_WINDOW_SECONDS = 60


class InMemoryRateLimiter:
    """Simple sliding-window limiter, keyed by client IP.

    KNOWN LIMITATIONS (explicit, not hidden):
    - In-memory only: state resets on restart, and is NOT shared across
      multiple worker processes or machines -- running with >1 Uvicorn
      worker effectively multiplies the real limit. Fine for a single-
      process MVP; a real multi-instance deployment needs a shared store
      (e.g. Redis) instead.
    - Keyed by IP, which is easy to spoof/share (e.g. behind a corporate
      NAT, many real users share one IP). Good enough to blunt accidental
      traffic storms; not a defense against a determined attacker.
    """

    def __init__(self, limit: int = DEFAULT_LIMIT, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> None:
        self._limit = limit
        self._window = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client_id: str) -> bool:
        now = time.monotonic()
        timestamps = self._requests[client_id]
        while timestamps and now - timestamps[0] > self._window:
            timestamps.popleft()
        if len(timestamps) >= self._limit:
            return False
        timestamps.append(now)
        return True
