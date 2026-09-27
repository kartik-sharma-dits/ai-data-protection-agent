"""Manual dev tool -- NOT part of the pytest suite. Sends N requests to a
running local server and reports basic latency/throughput numbers, using
only safe dummy text (never real sensitive data).

Usage: uv run python scripts/loadtest.py [request_count]
"""

import sys
import time

import httpx

URL = "http://127.0.0.1:8000/v1/protect"
SAMPLE_TEXTS = [
    "Write a blog post about AI agents.",
    "Contact John Smith at john@example.com.",
    "See https://example.com for details.",
]


def percentile(sorted_values: list[float], p: float) -> float:
    index = min(len(sorted_values) - 1, int(len(sorted_values) * p))
    return round(sorted_values[index] * 1000, 2)


def main(count: int) -> None:
    latencies = []
    errors = 0
    with httpx.Client(timeout=10.0) as client:
        start_all = time.perf_counter()
        for i in range(count):
            text = SAMPLE_TEXTS[i % len(SAMPLE_TEXTS)]
            start = time.perf_counter()
            try:
                response = client.post(URL, json={"text": text})
                if response.status_code not in (200, 403):
                    errors += 1
            except httpx.HTTPError:
                errors += 1
            latencies.append(time.perf_counter() - start)
        total_seconds = time.perf_counter() - start_all

    latencies.sort()
    print(f"requests: {count}")
    print(f"errors: {errors}")
    print(f"total time: {total_seconds:.2f}s")
    print(f"requests/sec: {count / total_seconds:.1f}")
    print(f"p50 latency: {percentile(latencies, 0.50)} ms")
    print(f"p95 latency: {percentile(latencies, 0.95)} ms")
    print(f"p99 latency: {percentile(latencies, 0.99)} ms")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    main(n)
