import logging

from ai_data_protection_agent.detection.detector import PIIDetector
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.policy.models import Action

from . import config
from .models import CommitDecision, Finding
from .staged_content import get_staged_content, is_binary, list_staged_files

logger = logging.getLogger("ai_data_protection_agent.git")

_DELETED_STATUS = "D"


def should_block_commit(action: Action) -> bool:
    """The Git-specific mapping from a policy Action to a commit decision.

    ALLOW     -> allow
    WARN      -> allow (shows a warning) unless config.WARN_BLOCKS_COMMIT
    SANITIZE  -> BLOCK -- the MVP never auto-rewrites staged content, so
                 "sanitize" has nothing safe to do except ask the developer
                 to fix it themselves and re-add/re-commit.
    BLOCK     -> BLOCK
    """
    if action == Action.BLOCK:
        return True
    if action == Action.SANITIZE:
        return True
    if action == Action.WARN:
        return config.WARN_BLOCKS_COMMIT
    return False


class GitProtectionService:
    """Scans the STAGED git snapshot using the existing PIIDetector and
    PolicyEngine. No separate detection logic, no sanitization, no
    automatic file modification -- this component only decides and reports."""

    def __init__(self, detector: PIIDetector | None = None, policy_engine: PolicyEngine | None = None) -> None:
        self._detector = detector
        self._policy_engine = policy_engine or PolicyEngine()

    def _get_detector(self) -> PIIDetector:
        # Built lazily: a commit with nothing staged (or only excluded/
        # binary files) should never pay the cost of loading the spaCy
        # model at all.
        if self._detector is None:
            self._detector = PIIDetector()
        return self._detector

    def scan_staged(self) -> CommitDecision:
        staged = list_staged_files()
        decision = CommitDecision(action=Action.ALLOW)

        for status, path in staged:
            if status[0] == _DELETED_STATUS:
                continue  # nothing new to scan -- there is no staged content
            if config.is_excluded(path):
                continue

            content = get_staged_content(path)

            if is_binary(content):
                decision.files_skipped_binary += 1
                continue

            if len(content) > config.MAX_FILE_BYTES:
                # Conservative: an unscanned file is a reason to block, not
                # something to silently let through.
                decision.files_skipped_too_large.append(path)
                decision.action = max(decision.action, Action.BLOCK)
                continue

            text = content.decode("utf-8", errors="replace")
            entities = self._get_detector().detect(text)
            decision.files_scanned += 1
            if not entities:
                continue

            evaluation = self._policy_engine.evaluate(entities)
            for raw_entity, entity_decision in zip(entities, evaluation.entities, strict=True):
                line = text[: raw_entity.start].count("\n") + 1
                decision.findings.append(
                    Finding(
                        file=path,
                        line=line,
                        entity_type=entity_decision.entity_type,
                        action=entity_decision.action,
                        risk=entity_decision.risk,
                    )
                )
            decision.action = max(decision.action, evaluation.overall_action)

        logger.info(
            "Git scan complete. files_scanned=%d action=%s",
            decision.files_scanned,
            decision.action.name,
        )
        return decision
