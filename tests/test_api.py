import logging

import pytest
from fastapi.testclient import TestClient

from ai_data_protection_agent.api import app as app_module
from ai_data_protection_agent.api.app import app
from ai_data_protection_agent.api.service import ProtectionError


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_allow_request(client):
    response = client.post("/v1/protect", json={"text": "Hello, how are you?"})
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is True
    assert body["action"] == "ALLOW"
    assert body["text"] == "Hello, how are you?"


def test_sanitize_request(client):
    response = client.post("/v1/protect", json={"text": "Contact John Smith at john@example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "SANITIZE"
    assert "john@example.com" not in body["text"]
    assert "John Smith" not in body["text"]


def test_block_request(client):
    response = client.post("/v1/protect", json={"text": "Card number is 4111111111111111."})
    assert response.status_code == 403
    body = response.json()
    assert body["allowed"] is False
    assert body["text"] is None


def test_warn_request(client):
    response = client.post("/v1/protect", json={"text": "See https://example.com for details."})
    assert response.status_code == 200
    assert response.json()["action"] == "WARN"


def test_empty_text(client):
    response = client.post("/v1/protect", json={"text": ""})
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "ALLOW"
    assert body["entities_detected"] == 0


def test_invalid_request_missing_text(client):
    response = client.post("/v1/protect", json={})
    assert response.status_code == 422


def test_very_large_request_rejected(client):
    huge_text = "a" * 150_000
    response = client.post("/v1/protect", json={"text": huge_text})
    assert response.status_code == 413


def test_unknown_destination(client):
    response = client.post("/v1/protect", json={"text": "hi", "destination": "not_a_real_destination"})
    assert response.status_code == 422


def test_multiple_pii_entities(client):
    response = client.post(
        "/v1/protect",
        json={"text": "John Smith's email is john@example.com and phone number is 9876543210."},
    )
    assert response.json()["entities_detected"] >= 2


def test_critical_entity_blocks(client):
    response = client.post("/v1/protect", json={"text": "4111111111111111"})
    assert response.status_code == 403
    assert "CREDIT_CARD" in response.json()["reason"]


def test_detector_failure_returns_500(client, monkeypatch):
    class BrokenService:
        def protect(self, text, destination="external_llm"):
            raise ProtectionError("detector", RuntimeError("boom"))

    monkeypatch.setattr(app_module, "get_protection_service", lambda: BrokenService())
    response = client.post("/v1/protect", json={"text": "anything"})
    assert response.status_code == 500
    assert "boom" not in response.text  # raw exception message never reaches the caller


def test_policy_engine_failure_returns_500(client, monkeypatch):
    class BrokenService:
        def protect(self, text, destination="external_llm"):
            raise ProtectionError("policy_engine", RuntimeError("boom"))

    monkeypatch.setattr(app_module, "get_protection_service", lambda: BrokenService())
    response = client.post("/v1/protect", json={"text": "anything"})
    assert response.status_code == 500


def test_sanitizer_failure_returns_500(client, monkeypatch):
    class BrokenService:
        def protect(self, text, destination="external_llm"):
            raise ProtectionError("sanitizer", RuntimeError("boom"))

    monkeypatch.setattr(app_module, "get_protection_service", lambda: BrokenService())
    response = client.post("/v1/protect", json={"text": "anything"})
    assert response.status_code == 500


def test_original_pii_not_in_response(client):
    # Full name, not just a first name -- en_core_web_sm reliably recognizes
    # "Priya Patel" as PERSON but often misses a bare first name like
    # "Priya" (a known false-negative limitation noted back in Phase 2).
    response = client.post("/v1/protect", json={"text": "Contact Priya Patel at priya@example.com"})
    assert "priya@example.com" not in response.text
    assert "Priya Patel" not in response.text


def test_mapping_never_returned(client):
    response = client.post("/v1/protect", json={"text": "Contact Priya Patel at priya@example.com"})
    body = response.json()
    assert "mapping" not in body
    assert set(body.keys()) == {"allowed", "action", "text", "entities_detected", "reason"}


def test_no_pii_written_to_logs(client, caplog):
    with caplog.at_level(logging.INFO):
        client.post("/v1/protect", json={"text": "Contact Priya Patel at priya@example.com"})
    assert "Priya" not in caplog.text
    assert "priya@example.com" not in caplog.text
