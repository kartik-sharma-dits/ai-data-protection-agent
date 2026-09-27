from dataclasses import dataclass, field


@dataclass
class SanitizationResult:
    """Result of sanitizing one piece of text.

    `mapping` is sensitive (placeholder -> original value) and is an
    in-memory Python object only. It must never be logged, persisted, or
    returned directly in an HTTP/API response (see Step 16 discussion).
    """

    sanitized_text: str
    mapping: dict[str, str] = field(default_factory=dict)
    entities_sanitized: int = 0
