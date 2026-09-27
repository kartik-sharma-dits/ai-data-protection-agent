import logging

from ai_data_protection_agent.detection.models import DetectedEntity
from ai_data_protection_agent.sanitization.logging_utils import log_sanitization_summary
from ai_data_protection_agent.sanitization.sanitizer import PIISanitizer


def entity(entity_type, text, start, end, confidence=0.9):
    return DetectedEntity(entity_type=entity_type, text=text, start=start, end=end, confidence=confidence)


def test_no_pii():
    text = "This is a normal sentence."
    result = PIISanitizer().sanitize(text, [])
    assert result.sanitized_text == text
    assert result.mapping == {}
    assert result.entities_sanitized == 0


def test_one_entity():
    text = "My email is john@example.com"
    start = text.index("john@example.com")
    e = entity("EMAIL_ADDRESS", "john@example.com", start, start + len("john@example.com"))
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "My email is <EMAIL_1>"
    assert result.mapping == {"<EMAIL_1>": "john@example.com"}


def test_multiple_entities():
    text = "John emailed john@example.com"
    entities = [
        entity("PERSON", "John", 0, 4),
        entity("EMAIL_ADDRESS", "john@example.com", 13, 29),
    ]
    result = PIISanitizer().sanitize(text, entities)
    assert result.sanitized_text == "<PERSON_1> emailed <EMAIL_1>"
    assert result.entities_sanitized == 2


def test_repeated_value_reuses_placeholder():
    text = "John Smith called. John Smith emailed too."
    entities = [
        entity("PERSON", "John Smith", 0, 10),
        entity("PERSON", "John Smith", 19, 29),
    ]
    result = PIISanitizer().sanitize(text, entities)
    assert result.sanitized_text == "<PERSON_1> called. <PERSON_1> emailed too."
    assert result.mapping == {"<PERSON_1>": "John Smith"}


def test_different_people_get_different_placeholders():
    text = "John met Priya."
    entities = [entity("PERSON", "John", 0, 4), entity("PERSON", "Priya", 9, 14)]
    result = PIISanitizer().sanitize(text, entities)
    assert result.sanitized_text == "<PERSON_1> met <PERSON_2>."


def test_different_emails_get_different_placeholders():
    text = "a@example.com and b@example.com"
    entities = [
        entity("EMAIL_ADDRESS", "a@example.com", 0, 13),
        entity("EMAIL_ADDRESS", "b@example.com", 18, 31),
    ]
    result = PIISanitizer().sanitize(text, entities)
    assert result.sanitized_text == "<EMAIL_1> and <EMAIL_2>"


def test_custom_customer_id():
    text = "Customer CUS-10234 has an issue."
    e = entity("CUSTOMER_ID", "CUS-10234", 9, 18)
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "Customer <CUSTOMER_ID_1> has an issue."


def test_pii_at_start():
    text = "John called support."
    e = entity("PERSON", "John", 0, 4)
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "<PERSON_1> called support."


def test_pii_at_end():
    text = "Please contact John"
    e = entity("PERSON", "John", 15, 19)
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "Please contact <PERSON_1>"


def test_pii_next_to_punctuation():
    text = "Email: john@example.com."
    e = entity("EMAIL_ADDRESS", "john@example.com", 7, 23)
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "Email: <EMAIL_1>."


def test_multiple_entities_close_together():
    text = "John,Priya"
    entities = [entity("PERSON", "John", 0, 4), entity("PERSON", "Priya", 5, 10)]
    result = PIISanitizer().sanitize(text, entities)
    assert result.sanitized_text == "<PERSON_1>,<PERSON_2>"


def test_overlapping_entities_keep_longer_match():
    # Simulates EMAIL_ADDRESS (whole) overlapping URL (the domain part).
    text = "john@example.com"
    entities = [
        entity("EMAIL_ADDRESS", "john@example.com", 0, 16, confidence=1.0),
        entity("URL", "example.com", 5, 16, confidence=0.5),
    ]
    result = PIISanitizer().sanitize(text, entities)
    # Only one placeholder -- the shorter, nested URL match was dropped and
    # none of the original characters leaked through.
    assert result.sanitized_text == "<EMAIL_1>"
    assert "example.com" not in result.sanitized_text


def test_empty_text():
    result = PIISanitizer().sanitize("", [])
    assert result.sanitized_text == ""
    assert result.mapping == {}


def test_unicode_text():
    text = "Escríbeme a maría@example.com"
    value = "maría@example.com"
    start = text.index(value)
    e = entity("EMAIL_ADDRESS", value, start, start + len(value))
    result = PIISanitizer().sanitize(text, [e])
    assert result.sanitized_text == "Escríbeme a <EMAIL_1>"


def test_large_text():
    filler = "Normal sentence with no sensitive data. " * 500
    text = filler + "Contact john@example.com."
    start = text.index("john@example.com")
    end = start + len("john@example.com")
    e = entity("EMAIL_ADDRESS", "john@example.com", start, end)
    result = PIISanitizer().sanitize(text, [e])
    assert "john@example.com" not in result.sanitized_text
    assert "<EMAIL_1>" in result.sanitized_text


# --- Security tests (Step 15) ---------------------------------------------


def test_original_pii_not_in_sanitized_text():
    text = "Contact John Smith at john@example.com."
    entities = [
        entity("PERSON", "John Smith", 8, 18),
        entity("EMAIL_ADDRESS", "john@example.com", 22, 38),
    ]
    result = PIISanitizer().sanitize(text, entities)
    assert "John Smith" not in result.sanitized_text
    assert "john@example.com" not in result.sanitized_text


def test_mapping_only_in_memory_object():
    # There is no file, DB, or cache handle anywhere in this call -- the
    # mapping only ever exists as this local Python dict.
    e = entity("PERSON", "John", 0, 4)
    result = PIISanitizer().sanitize("John", [e])
    assert isinstance(result.mapping, dict)
    assert result.mapping["<PERSON_1>"] == "John"


def test_sanitizer_does_not_log_original_pii(caplog):
    e = entity("PERSON", "John Smith", 0, 10)
    result = PIISanitizer().sanitize("John Smith", [e])
    with caplog.at_level(logging.INFO):
        log_sanitization_summary(result)
    assert "John Smith" not in caplog.text
    assert "<PERSON_1>" in caplog.text


def test_empty_input_is_safe():
    result = PIISanitizer().sanitize("", [])
    assert result.entities_sanitized == 0


def test_malformed_detection_results_do_not_crash():
    text = "short"
    malformed = [
        entity("PERSON", "bad", 100, 200),  # way out of range
        entity("PERSON", "bad", -1, 3),  # negative start
        entity("PERSON", "bad", 3, 1),  # end before start
    ]
    result = PIISanitizer().sanitize(text, malformed)
    assert result.sanitized_text == text
    assert result.entities_sanitized == 0
