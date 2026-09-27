from ai_data_protection_agent.detection.detector import PIIDetector

detector = PIIDetector()


def types_of(text):
    return {e.entity_type for e in detector.detect(text)}


# --- CUSTOMER_ID -----------------------------------------------------------


def test_customer_id_valid():
    assert "CUSTOMER_ID" in types_of("Customer CUS-10234 called in.")


def test_customer_id_invalid_format_not_matched():
    assert "CUSTOMER_ID" not in types_of("Customer CUST-10234 called in.")


def test_customer_id_too_short_not_matched():
    assert "CUSTOMER_ID" not in types_of("Customer CUS-1 called in.")


# --- API_KEY -----------------------------------------------------------


def test_api_key_valid():
    assert "API_KEY" in types_of("key=sk-abcdefghijklmnopqrstuvwx")


def test_api_key_too_short_not_matched():
    assert "API_KEY" not in types_of("key=sk-short")


def test_api_key_false_positive_check_ordinary_prefix_word():
    # "skateboard123456789012345" starts with letters but not the "sk-"
    # (with dash) shape our pattern requires.
    assert "API_KEY" not in types_of("My skateboard123456789012345 is red.")


# --- ACCESS_TOKEN (JWT) -----------------------------------------------------


def test_jwt_valid():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "ACCESS_TOKEN" in types_of(jwt)


def test_jwt_malformed_two_segments_not_matched():
    not_a_jwt = "eyJhbGciOiJIUzI1NiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "ACCESS_TOKEN" not in types_of(not_a_jwt)


# --- DATABASE_CONNECTION_STRING --------------------------------------------


def test_db_connection_url_style_valid():
    assert "DATABASE_CONNECTION_STRING" in types_of("postgres://user:pass@db.internal:5432/prod")


def test_db_connection_ado_net_style_valid():
    text = "Server=db.internal;Database=prod;User Id=admin;Password=SuperSecret123;"
    assert "DATABASE_CONNECTION_STRING" in types_of(text)


def test_db_connection_url_without_credentials_not_matched():
    # A bare scheme with no host/credentials shouldn't match -- there's
    # nothing sensitive in "postgres://" alone.
    assert "DATABASE_CONNECTION_STRING" not in types_of("We use postgres:// as our URL scheme.")


def test_db_connection_server_without_password_not_matched():
    # Server= alone (no Password=) is just a hostname reference, not a
    # credential -- shouldn't be treated as a full connection string.
    assert "DATABASE_CONNECTION_STRING" not in types_of("Server=db.internal;Database=prod;")
