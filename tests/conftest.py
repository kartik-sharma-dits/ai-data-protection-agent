import pytest

from ai_data_protection_agent.api import app as app_module
from ai_data_protection_agent.api.rate_limit import InMemoryRateLimiter
from ai_data_protection_agent.detection.detector import PIIDetector


@pytest.fixture(scope="session")
def detector() -> PIIDetector:
    # Session-scoped: building the analyzer loads the spaCy model, which is
    # slow. Build it once and reuse across every test in the run.
    return PIIDetector()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # Without this, the rate limiter's state (module-level, shared across
    # the whole test session) accumulates across every test that hits the
    # API -- as the suite grows, unrelated tests would eventually start
    # failing with 429s from OUR OWN test traffic, not real rate-limiting
    # behavior. Reset before every test so rate-limit tests stay isolated.
    app_module._rate_limiter = InMemoryRateLimiter()
    yield
