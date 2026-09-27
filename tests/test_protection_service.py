import logging

import pytest

from ai_data_protection_agent.api.service import ProtectionError, ProtectionService
from ai_data_protection_agent.detection.models import DetectedEntity
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.sanitization.sanitizer import PIISanitizer


class FakeDetector:
    def __init__(self, entities=None, raises=None):
        self._entities = entities or []
        self._raises = raises

    def detect(self, text):
        if self._raises:
            raise self._raises
        return self._entities


class FailingPolicyEngine:
    def evaluate(self, entities):
        raise RuntimeError("policy engine exploded")


class FailingSanitizer:
    def sanitize(self, text, entities):
        raise RuntimeError("sanitizer exploded")


def entity(entity_type, text, start, end, confidence=0.9):
    return DetectedEntity(entity_type=entity_type, text=text, start=start, end=end, confidence=confidence)


def make_service(detector, policy_engine=None, sanitizer=None):
    return ProtectionService(
        detector=detector,
        policy_engine=policy_engine or PolicyEngine(),
        sanitizer=sanitizer or PIISanitizer(),
    )


def test_allow_when_no_entities():
    service = make_service(FakeDetector(entities=[]))
    result = service.protect("hello there")
    assert result.allowed is True
    assert result.text == "hello there"
    assert result.entities_detected == 0


def test_sanitize_replaces_text():
    text = "My email is john@example.com"
    start = text.index("john@example.com")
    e = entity("EMAIL_ADDRESS", "john@example.com", start, start + len("john@example.com"))
    service = make_service(FakeDetector(entities=[e]))
    result = service.protect(text)
    assert result.allowed is True
    assert result.text == "My email is <EMAIL_1>"
    assert "john@example.com" not in result.text


def test_block_returns_no_text():
    e = entity("CREDIT_CARD", "4111111111111111", 0, 16)
    service = make_service(FakeDetector(entities=[e]))
    result = service.protect("4111111111111111")
    assert result.allowed is False
    assert result.text is None
    assert "CREDIT_CARD" in result.reason


def test_warn_passes_text_unchanged():
    e = entity("URL", "https://example.com", 4, 24)
    service = make_service(FakeDetector(entities=[e]))
    text = "See https://example.com"
    result = service.protect(text)
    assert result.allowed is True
    assert result.text == text  # unchanged, not sanitized
    assert "URL" in result.reason


def test_multiple_entities_report_full_count():
    entities = [
        entity("PERSON", "John", 0, 4),
        entity("EMAIL_ADDRESS", "john@example.com", 13, 29),
    ]
    service = make_service(FakeDetector(entities=entities))
    result = service.protect("John emailed john@example.com")
    assert result.entities_detected == 2


def test_critical_entity_blocks_even_with_other_entities():
    entities = [
        entity("PERSON", "John", 0, 4),
        entity("API_KEY", "sk-xxx", 20, 26),
    ]
    service = make_service(FakeDetector(entities=entities))
    result = service.protect("John's key is sk-xxx")
    assert result.allowed is False


def test_detector_failure_raises_protection_error():
    service = make_service(FakeDetector(raises=RuntimeError("boom")))
    with pytest.raises(ProtectionError) as exc_info:
        service.protect("some text")
    assert exc_info.value.component == "detector"


def test_policy_engine_failure_raises_protection_error():
    service = make_service(FakeDetector(entities=[]), policy_engine=FailingPolicyEngine())
    with pytest.raises(ProtectionError) as exc_info:
        service.protect("some text")
    assert exc_info.value.component == "policy_engine"


def test_sanitizer_failure_raises_protection_error():
    e = entity("EMAIL_ADDRESS", "john@example.com", 0, 16)
    service = make_service(FakeDetector(entities=[e]), sanitizer=FailingSanitizer())
    with pytest.raises(ProtectionError) as exc_info:
        service.protect("john@example.com")
    assert exc_info.value.component == "sanitizer"


def test_no_path_returns_allowed_true_on_failure():
    # Structural fail-closed check: every failure path must raise, never
    # return a ProtectionResult with allowed=True.
    service = make_service(FakeDetector(raises=RuntimeError("boom")))
    try:
        service.protect("x")
        assert False, "expected ProtectionError"
    except ProtectionError:
        pass


def test_service_does_not_log_original_pii(caplog):
    e = entity("PERSON", "John Smith", 0, 10)
    service = make_service(FakeDetector(entities=[e]))
    with caplog.at_level(logging.INFO):
        service.protect("John Smith")
    assert "John Smith" not in caplog.text


def test_failure_logging_excludes_exception_message(caplog):
    # The exception message itself is never logged, only the component name
    # and exception TYPE -- in case a future exception message ever echoed
    # part of the input.
    service = make_service(FakeDetector(raises=RuntimeError("contains john@example.com")))
    with caplog.at_level(logging.INFO):
        try:
            service.protect("x")
        except ProtectionError:
            pass
    assert "john@example.com" not in caplog.text
