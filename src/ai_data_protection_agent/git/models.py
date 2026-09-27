from dataclasses import dataclass, field

from ai_data_protection_agent.policy.models import Action, RiskLevel


@dataclass
class Finding:
    """One policy-relevant entity found in a staged file. No entity TEXT
    is ever stored here -- same discipline as policy/models.py."""

    file: str
    line: int | None
    entity_type: str
    action: Action
    risk: RiskLevel


@dataclass
class CommitDecision:
    action: Action
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_too_large: list[str] = field(default_factory=list)
