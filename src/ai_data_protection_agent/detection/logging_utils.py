import logging

from .models import DetectedEntity

logger = logging.getLogger("ai_data_protection_agent.detection")


def log_detection_summary(entities: list[DetectedEntity]) -> None:
    """Log what was found without ever logging the sensitive text itself."""
    for e in entities:
        logger.info("Detected %s at position %d-%d", e.entity_type, e.start, e.end)
