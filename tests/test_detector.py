def _types(entities):
    return {e.entity_type for e in entities}


def test_no_pii(detector):
    # Plain text should not trigger any detection. Deliberately avoids
    # date/time words like "today" -- DATE_TIME matches those (see
    # test_known_false_positive_documented for why that's expected, not a bug).
    assert detector.detect("This is a normal sentence with no sensitive data.") == []


def test_email(detector):
    results = detector.detect("Contact me at john@example.com")
    assert "EMAIL_ADDRESS" in _types(results)


def test_phone_number(detector):
    # "phone number" context words boost the recognizer's confidence.
    results = detector.detect("My phone number is +1 415-555-2671.")
    phones = [e for e in results if e.entity_type == "PHONE_NUMBER"]
    assert phones and phones[0].confidence > 0.5


def test_person(detector):
    results = detector.detect("John Smith joined the meeting.")
    assert "PERSON" in _types(results)


def test_multiple_entities(detector):
    text = "John Smith's email is john@example.com and his ID is CUS-10234."
    types = _types(detector.detect(text))
    assert {"PERSON", "EMAIL_ADDRESS", "CUSTOMER_ID"} <= types


def test_credit_card(detector):
    results = detector.detect("Card number: 4111111111111111")
    assert "CREDIT_CARD" in _types(results)


def test_ip_address(detector):
    results = detector.detect("Server IP is 192.168.1.1")
    assert "IP_ADDRESS" in _types(results)


def test_custom_customer_id(detector):
    results = detector.detect("Customer ID: CUS-10234")
    match = next(e for e in results if e.entity_type == "CUSTOMER_ID")
    assert match.text == "CUS-10234"
    assert match.confidence == 0.9


def test_known_false_positive_documented(detector):
    # A plain 10-digit number is wrongly matched as a UK NHS number at full
    # confidence. This is a DOCUMENTED limitation of Presidio's default
    # recognizers (tuned for US/UK formats), not a bug in our code -- it's
    # exactly why the Policy Engine must not blindly trust confidence==1.0.
    results = detector.detect("His phone number is 9876543210.")
    assert "UK_NHS" in _types(results)


def test_empty_text(detector):
    assert detector.detect("") == []


def test_large_text(detector):
    filler = "This is a normal sentence with no sensitive data. " * 500
    text = filler + "Contact john@example.com for details."
    results = detector.detect(text)
    assert "EMAIL_ADDRESS" in _types(results)


def test_unicode_text(detector):
    # Regex-based recognizers (like EMAIL_ADDRESS) work regardless of
    # surrounding language, even though our NLP model (en_core_web_sm) is
    # English-only and won't reliably find PERSON/LOCATION in other languages.
    results = detector.detect("Escríbeme a maria@example.com por favor.")
    assert "EMAIL_ADDRESS" in _types(results)
