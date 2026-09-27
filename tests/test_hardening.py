import importlib

from fastapi.testclient import TestClient

from ai_data_protection_agent.api import app as app_module
from ai_data_protection_agent.api.auth import API_KEY_ENV_VAR
from ai_data_protection_agent.api.rate_limit import InMemoryRateLimiter

client = TestClient(app_module.app)


# --- Auth (Section 15) ------------------------------------------------------


def test_auth_disabled_when_no_env_var_set(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    response = client.post("/v1/protect", json={"text": "hello"})
    assert response.status_code == 200


def test_auth_rejects_missing_key_when_configured(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "correct-key")
    response = client.post("/v1/protect", json={"text": "hello"})
    assert response.status_code == 401


def test_auth_rejects_wrong_key_when_configured(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "correct-key")
    response = client.post(
        "/v1/protect", json={"text": "hello"}, headers={"X-API-Key": "wrong-key"}
    )
    assert response.status_code == 401


def test_auth_accepts_correct_key_when_configured(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "correct-key")
    response = client.post(
        "/v1/protect", json={"text": "hello"}, headers={"X-API-Key": "correct-key"}
    )
    assert response.status_code == 200


def test_api_key_read_from_environment_not_hardcoded():
    import ai_data_protection_agent.api.auth as auth_module

    source = importlib.util.find_spec(auth_module.__name__).origin
    with open(source) as f:
        content = f.read()
    assert "os.environ" in content
    # The line assigning `expected` must read from environ, not a literal
    expected_line = next(line for line in content.splitlines() if "expected =" in line)
    assert "os.environ" in expected_line


# --- Rate limiting (Section 16) --------------------------------------------


def test_rate_limiter_blocks_after_limit():
    limiter = InMemoryRateLimiter(limit=3, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is False  # 4th request in the window


def test_rate_limiter_tracks_clients_independently():
    limiter = InMemoryRateLimiter(limit=1, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-b") is True  # different client, separate quota
    assert limiter.allow("client-a") is False


def test_rate_limit_returns_429_via_api(monkeypatch):
    monkeypatch.setattr(app_module, "_rate_limiter", InMemoryRateLimiter(limit=2, window_seconds=60))
    r1 = client.post("/v1/protect", json={"text": "hi"})
    r2 = client.post("/v1/protect", json={"text": "hi"})
    r3 = client.post("/v1/protect", json={"text": "hi"})
    assert r1.status_code != 429
    assert r2.status_code != 429
    assert r3.status_code == 429


# --- Security headers (Section 17) -----------------------------------------


def test_security_header_present():
    response = client.post("/v1/protect", json={"text": "hello"})
    assert response.headers.get("x-content-type-options") == "nosniff"


# --- Metrics (Section 24) ---------------------------------------------------


def test_metrics_endpoint_shape(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    client.post("/v1/protect", json={"text": "Contact John Smith at john@example.com"})
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.json()
    for key in [
        "total_requests",
        "allowed_requests",
        "warned_requests",
        "sanitized_requests",
        "blocked_requests",
        "detector_errors",
        "policy_errors",
        "sanitizer_errors",
        "p50_latency_ms",
        "p95_latency_ms",
        "p99_latency_ms",
    ]:
        assert key in body
    assert body["total_requests"] >= 1


def test_metrics_never_contain_pii(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    client.post("/v1/protect", json={"text": "Contact Priya Patel at priya@example.com"})
    response = client.get("/metrics")
    assert "priya@example.com" not in response.text
    assert "Priya" not in response.text
