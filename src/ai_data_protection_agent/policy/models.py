from dataclasses import dataclass, field
from enum import IntEnum


class Action(IntEnum):
    """Ordered by severity: comparisons like `max(actions)` pick the safest one."""

    ALLOW = 0
    WARN = 1
    SANITIZE = 2
    BLOCK = 3


class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass(frozen=True)
class PolicyRule:
    """Configuration for one entity type: what to do, how risky it is, and
    how much we trust low-confidence detections of it."""

    action: Action
    risk: RiskLevel
    min_confidence: float = 0.0

    def __post_init__(self) -> None:
        # Fail fast on a malformed rule (e.g. a typo'd string instead of an
        # Action) at configuration time, not silently at decision time.
        if not isinstance(self.action, Action):
            raise TypeError(f"PolicyRule.action must be an Action, got {self.action!r}")
        if not isinstance(self.risk, RiskLevel):
            raise TypeError(f"PolicyRule.risk must be a RiskLevel, got {self.risk!r}")


@dataclass
class EntityDecision:
    """One entity's policy decision. Deliberately holds no PII text -- only
    the entity type and metadata needed to act on it."""

    entity_type: str
    action: Action
    risk: RiskLevel
    confidence: float


@dataclass
class PolicyEvaluation:
    overall_action: Action
    entities: list[EntityDecision] = field(default_factory=list)
