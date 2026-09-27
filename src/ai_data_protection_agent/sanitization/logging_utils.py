import logging

from .models import SanitizationResult

logger = logging.getLogger("ai_data_protection_agent.sanitization")


def log_sanitization_summary(result: SanitizationResult) -> None:
    """Log what was sanitized without ever logging original values or the mapping."""
    logger.info(
        "Sanitized %d entities: %s",
        result.entities_sanitized,
        sorted(result.mapping.keys()),  # placeholders only, e.g. <PERSON_1>
    )
