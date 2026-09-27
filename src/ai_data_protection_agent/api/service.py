import logging
from dataclasses import dataclass

from ai_data_protection_agent.detection.detector import PIIDetector
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.policy.models import Action, PolicyEvaluation
from ai_data_protection_agent.sanitization.sanitizer import PIISanitizer

logger = logging.getLogger("ai_data_protection_agent.api")


class ProtectionError(Exception):
    """Raised when a step (detect/evaluate/sanitize) fails. Carries only the
    component name for safe logging -- never the original text."""

    def __init__(self, component: str, cause: Exception) -> None:
        super().__init__(f"{component} failed: {type(cause).__name__}")
        self.component = component


@dataclass
class ProtectionResult:
    allowed: bool
    action: Action
    text: str | None
    entities_detected: int
    reason: str | None


def _reason_for(evaluation: PolicyEvaluation) -> str | None:
    if evaluation.overall_action in (Action.ALLOW, Action.SANITIZE):
        return None
    # Only the entity TYPES that caused this action -- never any value.
    triggering_types = sorted(
        {d.entity_type for d in evaluation.entities if d.action == evaluation.overall_action}
    )
    verb = "Blocked" if evaluation.overall_action == Action.BLOCK else "Warning"
    return f"{verb} due to: {', '.join(triggering_types)}"


class ProtectionService:
    """Orchestrates detection -> policy -> sanitization. Contains no
    detection, policy, or sanitization logic of its own -- only calls out to
    the three existing engines and assembles their results."""

    def __init__(
        self,
        detector: PIIDetector,
        policy_engine: PolicyEngine,
        sanitizer: PIISanitizer,
    ) -> None:
        self._detector = detector
        self._policy_engine = policy_engine
        self._sanitizer = sanitizer

    def protect(self, text: str, destination: str = "external_llm") -> ProtectionResult:
        entities = self._call("detector", self._detector.detect, text)
        evaluation = self._call(
            "policy_engine", self._policy_engine.evaluate, entities, destination
        )

        if evaluation.overall_action == Action.BLOCK:
            logger.info("Request blocked. entities=%d destination=%s", len(entities), destination)
            return ProtectionResult(
                allowed=False,
                action=Action.BLOCK,
                text=None,
                entities_detected=len(entities),
                reason=_reason_for(evaluation),
            )

        if evaluation.overall_action == Action.SANITIZE:
            result = self._call("sanitizer", self._sanitizer.sanitize, text, entities)
            output_text = result.sanitized_text
        else:
            output_text = text  # ALLOW or WARN: text passes through unchanged

        logger.info(
            "Request processed. action=%s entities=%d destination=%s",
            evaluation.overall_action.name,
            len(entities),
            destination,
        )
        return ProtectionResult(
            allowed=True,
            action=evaluation.overall_action,
            text=output_text,
            entities_detected=len(entities),
            reason=_reason_for(evaluation),
        )

    @staticmethod
    def _call(component: str, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001 -- intentionally broad, re-raised as ProtectionError
            logger.error("Component failure: %s (%s)", component, type(exc).__name__)
            raise ProtectionError(component, exc) from exc
