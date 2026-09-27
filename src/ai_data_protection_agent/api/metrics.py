import threading
from collections import deque

_LOCK = threading.Lock()

_ACTION_COUNTER_KEYS = {
    "ALLOW": "allowed_requests",
    "WARN": "warned_requests",
    "SANITIZE": "sanitized_requests",
    "BLOCK": "blocked_requests",
}
_ERROR_COUNTER_KEYS = {
    "detector": "detector_errors",
    "policy_engine": "policy_errors",
    "sanitizer": "sanitizer_errors",
}

_counters = {
    "total_requests": 0,
    "allowed_requests": 0,
    "warned_requests": 0,
    "sanitized_requests": 0,
    "blocked_requests": 0,
    "detector_errors": 0,
    "policy_errors": 0,
    "sanitizer_errors": 0,
}
_latencies_seconds: deque[float] = deque(maxlen=1000)  # bounded -- constant memory


def record_result(action_name: str, elapsed_seconds: float) -> None:
    with _LOCK:
        _counters["total_requests"] += 1
        _counters[_ACTION_COUNTER_KEYS[action_name]] += 1
        _latencies_seconds.append(elapsed_seconds)


def record_error(component: str) -> None:
    with _LOCK:
        _counters["total_requests"] += 1
        key = _ERROR_COUNTER_KEYS.get(component)
        if key:
            _counters[key] += 1


def _percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    index = min(len(sorted_values) - 1, int(len(sorted_values) * p))
    return round(sorted_values[index] * 1000, 2)  # milliseconds


def snapshot() -> dict:
    """Numbers only -- entity types, counts, and timings. Never any request
    text, so this is always safe to expose or export, unlike logs."""
    with _LOCK:
        result = dict(_counters)
        latencies = sorted(_latencies_seconds)
    result["p50_latency_ms"] = _percentile(latencies, 0.50)
    result["p95_latency_ms"] = _percentile(latencies, 0.95)
    result["p99_latency_ms"] = _percentile(latencies, 0.99)
    return result
