from presidio_analyzer import Pattern, PatternRecognizer

# Example company ID format: CUS-10234
CUSTOMER_ID_RECOGNIZER = PatternRecognizer(
    supported_entity="CUSTOMER_ID",
    patterns=[Pattern(name="customer_id_pattern", regex=r"\bCUS-\d{4,6}\b", score=0.9)],
)

# Known secret-key prefixes (OpenAI/Anthropic/Stripe-style) + a generic
# "api_key: <value>" context pattern. Regex can only catch RECOGNIZABLE
# formats -- a proprietary in-house key format with no distinct prefix will
# not match either pattern. That's a real, honest limitation (see Phase 6
# notes), not something regex can fully close.
API_KEY_RECOGNIZER = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[
        Pattern(name="prefixed_key", regex=r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b", score=0.85),
        Pattern(
            name="labeled_key",
            regex=r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}",
            score=0.75,
        ),
    ],
)

# JWTs have a very distinctive, hard-to-fake shape: three base64url segments
# separated by dots, and the header segment always starts with "eyJ"
# (base64 of the literal characters `{"`). This makes JWTs one of the few
# secret formats regex detects with genuinely high confidence.
ACCESS_TOKEN_RECOGNIZER = PatternRecognizer(
    supported_entity="ACCESS_TOKEN",
    patterns=[
        Pattern(name="jwt", regex=r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", score=0.9),
        Pattern(
            name="labeled_token",
            regex=r"(?i)\baccess[_-]?token\b\s*[:=]\s*['\"]?[A-Za-z0-9\-_.]{16,}",
            score=0.75,
        ),
    ],
)

# Two shapes: URL-style connection strings (postgres://user:pass@host/db)
# and Windows/ADO.NET-style key=value strings that combine a server and a
# password in one line.
DATABASE_CONNECTION_STRING_RECOGNIZER = PatternRecognizer(
    supported_entity="DATABASE_CONNECTION_STRING",
    patterns=[
        Pattern(
            name="url_style",
            regex=r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://\S+",
            score=0.9,
        ),
        # Bounded segment lengths and no unbounded lookahead (`.*`) --
        # avoids catastrophic backtracking on large inputs (see Phase 6
        # ReDoS finding). Matches the common field order
        # Server=...;...;Password=...; and won't catch other field orders --
        # an honest, documented limitation rather than a performance risk.
        Pattern(
            name="ado_net_style",
            regex=r"(?i)\b(?:server|data source)\s*=[^;\n]{1,100};(?:[^;\n]{1,100};){0,5}\s*password\s*=[^;\n]{1,100}",
            score=0.85,
        ),
    ],
)

ALL_CUSTOM_RECOGNIZERS = [
    CUSTOMER_ID_RECOGNIZER,
    API_KEY_RECOGNIZER,
    ACCESS_TOKEN_RECOGNIZER,
    DATABASE_CONNECTION_STRING_RECOGNIZER,
]
