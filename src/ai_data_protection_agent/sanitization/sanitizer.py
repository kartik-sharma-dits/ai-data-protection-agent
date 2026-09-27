from collections import defaultdict
from typing import Literal

from ai_data_protection_agent.detection.models import DetectedEntity

from .models import SanitizationResult

# Purely cosmetic, data-driven label shortening (e.g. EMAIL_ADDRESS -> EMAIL).
# Falls back to the raw entity_type for anything not listed here, so adding a
# new entity type (like CUSTOMER_ID) never requires touching this file.
_SHORT_LABELS = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
}

Strategy = Literal["placeholder", "redact"]


def _resolve_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    ordered = sorted(
        entities, key=lambda e: (e.start, -(e.end - e.start), -e.confidence)
    )
    kept: list[DetectedEntity] = []
    last_end = -1
    for entity in ordered:
        if entity.start < last_end:
            continue  # overlaps a match we already kept -- skip it
        kept.append(entity)
        last_end = entity.end
    return kept


def _valid(entity: DetectedEntity, text_length: int) -> bool:
    # Defends against malformed detection results (Step 15, security test 7):
    # a corrupted or hand-built DetectedEntity with out-of-range positions
    # must be skipped, not crash the sanitizer.
    return 0 <= entity.start < entity.end <= text_length


class PIISanitizer:
    """Replaces detected entities in text with placeholders. Sanitization only
    -- no detection logic, no policy decisions (allow/block)."""

    def __init__(self, strategy: Strategy = "placeholder") -> None:
        self._strategy = strategy

    def sanitize(self, text: str, entities: list[DetectedEntity]) -> SanitizationResult:
        valid_entities = [e for e in entities if _valid(e, len(text))]
        resolved = _resolve_overlaps(valid_entities)

        mapping: dict[str, str] = {}
        value_to_placeholder: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = defaultdict(int)
        replacements: list[tuple[int, int, str]] = []

        for entity in resolved:
            placeholder = self._placeholder_for(
                entity, mapping, value_to_placeholder, counters
            )
            replacements.append((entity.start, entity.end, placeholder))

        sanitized = text
        for start, end, placeholder in sorted(replacements, reverse=True):
            sanitized = sanitized[:start] + placeholder + sanitized[end:]

        return SanitizationResult(
            sanitized_text=sanitized,
            mapping=mapping,
            entities_sanitized=len(resolved),
        )

    def _placeholder_for(
        self,
        entity: DetectedEntity,
        mapping: dict[str, str],
        value_to_placeholder: dict[tuple[str, str], str],
        counters: dict[str, int],
    ) -> str:
        if self._strategy == "redact":
            return "[REDACTED]"

        # "placeholder" strategy: same normalized value + same entity type
        # reuses the same placeholder, so repeated mentions stay consistent.
        normalized = entity.text.strip().casefold()
        key = (entity.entity_type, normalized)
        if key in value_to_placeholder:
            return value_to_placeholder[key]

        counters[entity.entity_type] += 1
        label = _SHORT_LABELS.get(entity.entity_type, entity.entity_type)
        placeholder = f"<{label}_{counters[entity.entity_type]}>"
        value_to_placeholder[key] = placeholder
        mapping[placeholder] = entity.text
        return placeholder
