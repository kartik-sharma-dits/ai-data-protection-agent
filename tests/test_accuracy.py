"""False positive / false negative / edge-case coverage (Phase 6, Sections 4-6).

These tests check END-TO-END POLICY OUTCOMES, not raw detection labels --
a noisy detection label is only a real problem if it leads to the wrong
security decision. Where the detector has a genuine known gap, the test
documents it honestly rather than hiding it.
"""

from fastapi.testclient import TestClient

from ai_data_protection_agent.api.app import app

client = TestClient(app)


# --- False positives: noisy labels that must still resolve safely --------


def test_order_number_does_not_get_blocked_or_sanitized():
    # Trips a low-confidence US_DRIVER_LICENSE false positive (unknown to
    # DEFAULT_POLICIES) which the fail-safe design floors at WARN, never
    # fully ALLOW -- see Phase 4/6 notes. The point of this test isn't "zero
    # noise", it's "noise on ordinary business text must never rise to
    # SANITIZE or BLOCK".
    response = client.post("/v1/protect", json={"text": "Order number: 123456"})
    assert response.json()["action"] in ("ALLOW", "WARN")


def test_version_string_allowed():
    response = client.post("/v1/protect", json={"text": "Version: 1.2.3"})
    assert response.json()["action"] == "ALLOW"


def test_server_port_allowed():
    response = client.post("/v1/protect", json={"text": "Server port: 8080"})
    assert response.json()["action"] == "ALLOW"


def test_release_date_allowed():
    response = client.post("/v1/protect", json={"text": "Release date: 2026-09-20"})
    assert response.json()["action"] == "ALLOW"


# --- False negatives: honestly documented, not silently accepted ---------


def test_known_gap_obfuscated_email_not_sanitized():
    # "john [at] example.com" is a common human trick to dodge email
    # regexes and is NOT currently detected. Documenting this as a known
    # limitation (Phase 6) rather than pretending detection is complete --
    # closing this class of gap is future recognizer work, not solved by
    # this test.
    response = client.post("/v1/protect", json={"text": "Reach me at john [at] example.com"})
    assert "john [at] example.com" in response.json()["text"] or response.json()["action"] == "ALLOW"


def test_email_detected_regardless_of_case():
    response = client.post("/v1/protect", json={"text": "Contact JOHN@EXAMPLE.COM"})
    assert response.json()["action"] == "SANITIZE"
    assert "JOHN@EXAMPLE.COM" not in response.json()["text"]


def test_international_phone_format_detected_with_context():
    response = client.post("/v1/protect", json={"text": "My phone number is +91 9876543210."})
    assert response.json()["action"] in ("SANITIZE", "WARN")  # never silently ALLOW-ed


# --- Edge cases (Section 4) -----------------------------------------------


def test_whitespace_only_input():
    response = client.post("/v1/protect", json={"text": "   \n\t  "})
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"


def test_emoji_input():
    response = client.post("/v1/protect", json={"text": "Great job team! 🎉🚀"})
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"


def test_multiple_languages_email_still_detected():
    response = client.post("/v1/protect", json={"text": "Escríbeme a maria@example.com por favor"})
    assert response.json()["action"] == "SANITIZE"


def test_json_like_text_does_not_crash():
    text = '{"user": "John Smith", "email": "john@example.com"}'
    response = client.post("/v1/protect", json={"text": text})
    assert response.status_code in (200, 403)


def test_html_like_text_does_not_crash():
    text = "<p>Contact <b>John Smith</b> at john@example.com</p>"
    response = client.post("/v1/protect", json={"text": text})
    assert response.status_code in (200, 403)


def test_code_snippet_does_not_crash():
    text = "def send_email(to='john@example.com'):\n    pass"
    response = client.post("/v1/protect", json={"text": text})
    assert response.status_code in (200, 403)


def test_number_that_should_not_be_pii():
    response = client.post("/v1/protect", json={"text": "The recipe needs 2 cups of flour."})
    assert response.json()["action"] == "ALLOW"


def test_entity_at_start_of_text():
    response = client.post("/v1/protect", json={"text": "john@example.com is our contact."})
    assert "john@example.com" not in response.json()["text"]


def test_entity_at_end_of_text():
    response = client.post("/v1/protect", json={"text": "Our contact is john@example.com"})
    assert "john@example.com" not in response.json()["text"]


def test_adjacent_entities_no_corruption():
    response = client.post("/v1/protect", json={"text": "a@example.com,b@example.com"})
    body = response.json()
    assert "a@example.com" not in body["text"]
    assert "b@example.com" not in body["text"]
