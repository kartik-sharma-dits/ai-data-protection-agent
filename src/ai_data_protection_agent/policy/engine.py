from ai_data_protection_agent.detection.models import DetectedEntity

from .config import DEFAULT_POLICIES, UNKNOWN_ENTITY_POLICY
from .models import Action, EntityDecision, PolicyEvaluation, PolicyRule, RiskLevel

# Risk levels below this are eligible for confidence-based softening.
# HIGH/CRITICAL entities always get their configured action (Step 5).
_SOFTENABLE_RISK = {RiskLevel.LOW, RiskLevel.MEDIUM}

# Below this confidence, a softenable action is downgraded one step
# (e.g. SANITIZE -> WARN, WARN -> ALLOW).
_LOW_CONFIDENCE_THRESHOLD = 0.5

_SOFTER_ACTION = {
    Action.BLOCK: Action.BLOCK,  # never auto-softened, regardless of risk
    Action.SANITIZE: Action.WARN,
    Action.WARN: Action.ALLOW,
    Action.ALLOW: Action.ALLOW,
}


class PolicyEngine:
    """Turns detection results into a security decision. Makes decisions
    only -- no detection, no sanitization, no knowledge of the destination."""

    def __init__(
        self,
        policies: dict[str, PolicyRule] | None = None,
        unknown_policy: PolicyRule = UNKNOWN_ENTITY_POLICY,
    ) -> None:
        self._policies = policies if policies is not None else DEFAULT_POLICIES
        self._unknown_policy = unknown_policy

    def evaluate(
        self, entities: list[DetectedEntity], destination: str | None = None
    ) -> PolicyEvaluation:
        # `destination` is accepted and threaded through end-to-end (see
        # Phase 6, Section 9) but does not yet change any decision --
        # destination-aware policy dicts are a deliberately deferred
        # feature (Phase 4). It's here so the seam is provably wired, not
        # silently dropped, before that feature is ever built.
        decisions = [self._decide(entity) for entity in entities]
        overall = max((d.action for d in decisions), default=Action.ALLOW)
        return PolicyEvaluation(overall_action=overall, entities=decisions)

    def _decide(self, entity: DetectedEntity) -> EntityDecision:
        rule = self._policies.get(entity.entity_type, self._unknown_policy)
        confidence = entity.confidence if entity.confidence is not None else 0.0

        action = rule.action
        if rule.risk in _SOFTENABLE_RISK and confidence < _LOW_CONFIDENCE_THRESHOLD:
            action = _SOFTER_ACTION[action]

        return EntityDecision(
            entity_type=entity.entity_type,
            action=action,
            risk=rule.risk,
            confidence=confidence,
        )
