from dataclasses import dataclass


@dataclass(frozen=True)
class DetectedEntity:
    """One piece of sensitive information found in text."""

    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
