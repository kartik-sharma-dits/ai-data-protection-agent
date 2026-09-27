import sys

from ai_data_protection_agent.policy.models import Action

from . import config
from .models import CommitDecision
from .scanner import GitProtectionService, should_block_commit

BANNER = "AI Data Protection Agent"


def _print_finding(finding) -> None:
    location = f"File: {finding.file}"
    if finding.line is not None:
        location += f" (line {finding.line})"
    print(location)
    print(f"Entity: {finding.entity_type}")
    print(f"Action: {finding.action.name}")
    print(f"Risk: {finding.risk.name}")
    print()


def _print_report(decision: CommitDecision) -> None:
    print(BANNER)
    print()

    if decision.action == Action.ALLOW:
        print("[OK] No sensitive data detected.")
        print("[OK] Commit allowed.")
        return

    if decision.action == Action.WARN:
        print("[WARNING]")
        print("Potentially sensitive information detected.")
        print()
        for finding in decision.findings:
            if finding.action == Action.WARN:
                _print_finding(finding)
        print("Commit allowed.")
        return

    # SANITIZE or BLOCK -> commit blocked (see should_block_commit)
    print("[BLOCKED] Commit blocked.")
    print()
    print("Sensitive information detected.")
    print()
    for finding in decision.findings:
        if finding.action in (Action.SANITIZE, Action.BLOCK):
            _print_finding(finding)

    if decision.files_skipped_too_large:
        print("Some files exceeded the scan size limit and are treated as unsafe by default:")
        for path in decision.files_skipped_too_large:
            print(f"  - {path}")
        print()

    print("Remove or protect the sensitive information and try again.")


def scan_staged_command() -> int:
    if not config.ENABLED:
        print(f"{BANNER}\nGit protection is disabled (GIT_PROTECTION_ENABLED=false). Commit allowed.")
        return 0

    try:
        decision = GitProtectionService().scan_staged()
    except Exception as exc:  # noqa: BLE001 -- fail-closed: any scanner failure blocks the commit
        print(BANNER)
        print()
        print("[BLOCKED] Commit blocked.")
        print()
        print(f"The protection scanner failed to run ({type(exc).__name__}).")
        print("Fix the scanner or contact your security team before committing.")
        return 1

    _print_report(decision)
    return 1 if should_block_commit(decision.action) else 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "scan-staged":
        print("Usage: uv run python -m ai_data_protection_agent.git.cli scan-staged")
        return 2
    return scan_staged_command()


if __name__ == "__main__":
    sys.exit(main())
