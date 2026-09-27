"""Permanent security regression suite (Phase 6, Section 21).

Every test here documents a REAL finding or a REAL security guarantee this
project depends on. Once a test is added here, it must never be deleted --
only extended -- so a future change can never silently reintroduce a fixed
vulnerability.
"""

import logging
import time

from fastapi.testclient import TestClient

from ai_data_protection_agent.api.app import app
from ai_data_protection_agent.detection.detector import PIIDetector
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.policy.models import Action

client = TestClient(app)
detector = PIIDetector()


# --- Finding: secrets were previously undetectable at all (fixed this phase) ---


def test_regression_api_key_now_detected():
    entities = detector.detect("My key is sk-abcdefghijklmnopqrstuvwx")
    assert any(e.entity_type == "API_KEY" for e in entities)


def test_regression_jwt_access_token_now_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    entities = detector.detect(f"access_token: {jwt}")
    assert any(e.entity_type == "ACCESS_TOKEN" for e in entities)


def test_regression_db_connection_string_now_detected():
    text = "Server=db.internal;Database=prod;User Id=admin;Password=SuperSecret123;"
    entities = detector.detect(text)
    assert any(e.entity_type == "DATABASE_CONNECTION_STRING" for e in entities)


def test_regression_secrets_are_blocked_end_to_end():
    for text in [
        "My key is sk-abcdefghijklmnopqrstuvwx",
        "Server=db.internal;Database=prod;User Id=admin;Password=SuperSecret123;",
    ]:
        response = client.post("/v1/protect", json={"text": text})
        assert response.status_code == 403, f"expected BLOCK for: {text}"


# --- Finding: the ADO.NET connection-string regex caused a ReDoS (fixed this phase) ---


def test_regression_no_redos_on_large_input():
    # Same size used elsewhere in the suite (~20,500 chars); normal full
    # detection here takes well under a second. Before the Phase 6 regex
    # fix, the ADO.NET connection-string pattern alone took 17+ seconds on
    # text this size due to catastrophic backtracking -- this threshold is
    # set to comfortably catch that class of regression without being
    # sensitive to normal spaCy NLP timing variance.
    large_text = "Normal sentence with no sensitive data. " * 500
    start = time.monotonic()
    detector.detect(large_text)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"detection took {elapsed:.1f}s -- possible regex backtracking regression"


# --- Policy precedence combinations (Section 8) ---


def test_precedence_allow_plus_warn_is_warn():
    text = "See https://example.com for the release notes today."
    entities = detector.detect(text)
    evaluation = PolicyEngine().evaluate(entities)
    assert evaluation.overall_action == Action.WARN


def test_precedence_allow_plus_sanitize_is_sanitize():
    entities = detector.detect("Contact John Smith today for details.")
    evaluation = PolicyEngine().evaluate(entities)
    assert evaluation.overall_action == Action.SANITIZE


def test_precedence_sanitize_plus_block_is_block():
    entities = detector.detect("Contact John Smith. Card number 4111111111111111.")
    evaluation = PolicyEngine().evaluate(entities)
    assert evaluation.overall_action == Action.BLOCK


def test_precedence_warn_plus_block_is_block():
    entities = detector.detect("See https://example.com. Card number 4111111111111111.")
    evaluation = PolicyEngine().evaluate(entities)
    assert evaluation.overall_action == Action.BLOCK


def test_precedence_multiple_block_entities_still_block():
    text = "Card 4111111111111111 and Server=db.internal;Database=x;User Id=a;Password=b;"
    entities = detector.detect(text)
    evaluation = PolicyEngine().evaluate(entities)
    assert evaluation.overall_action == Action.BLOCK


# --- Destination is threaded through, not silently dropped (Section 9) ---


def test_destination_reaches_policy_engine_without_error():
    entities = detector.detect("hello")
    # Must accept a destination kwarg at all -- this call raising TypeError
    # would mean the parameter was removed/broken.
    evaluation = PolicyEngine().evaluate(entities, destination="internal_llm")
    assert evaluation.overall_action == Action.ALLOW


def test_destination_is_visible_in_service_logs(caplog):
    from ai_data_protection_agent.api.service import ProtectionService
    from ai_data_protection_agent.sanitization.sanitizer import PIISanitizer

    service = ProtectionService(detector, PolicyEngine(), PIISanitizer())
    with caplog.at_level(logging.INFO):
        service.protect("hello", destination="self_hosted_llm")
    assert "destination=self_hosted_llm" in caplog.text


# --- PII must never leak into responses, across every risky entity type (Section 10) ---


def test_no_pii_leaks_for_any_entity_type_in_response():
    samples = {
        "person/email": "Contact John Smith at john@example.com",
        "credit_card": "Card number 4111111111111111",
        "api_key": "My key is sk-abcdefghijklmnopqrstuvwx",
        "db_connection": "Server=db.internal;Database=x;User Id=a;Password=hunter2;",
    }
    for label, text in samples.items():
        response = client.post("/v1/protect", json={"text": text})
        assert text not in response.text, f"{label}: original text leaked into response"
        assert "hunter2" not in response.text
        assert "sk-abcdefghijklmnopqrstuvwx" not in response.text


# --- PII must never leak into logs (Section 11) ---


def test_no_pii_in_logs_across_all_actions(caplog):
    samples = [
        "Hello there",  # ALLOW
        "See https://example.com",  # WARN
        "Contact John Smith at john@example.com",  # SANITIZE
        "Card number 4111111111111111",  # BLOCK
    ]
    with caplog.at_level(logging.INFO):
        for text in samples:
            client.post("/v1/protect", json={"text": text})
    assert "john@example.com" not in caplog.text
    assert "John Smith" not in caplog.text
    assert "4111111111111111" not in caplog.text


# --- Safe exception handling: errors must never echo request content (Section 20) ---


def test_error_response_never_echoes_input(monkeypatch):
    import ai_data_protection_agent.api.app as app_module
    from ai_data_protection_agent.api.service import ProtectionError

    class BrokenService:
        def protect(self, text, destination="external_llm"):
            # Simulate a bug where the underlying exception message happens
            # to contain a fragment of the input -- the handler must not
            # forward this to the caller regardless.
            raise ProtectionError("detector", RuntimeError(f"failed on {text}"))

    monkeypatch.setattr(app_module, "get_protection_service", lambda: BrokenService())
    secret_text = "super-secret-value-should-not-leak"
    response = client.post("/v1/protect", json={"text": secret_text})
    assert response.status_code == 500
    assert secret_text not in response.text
