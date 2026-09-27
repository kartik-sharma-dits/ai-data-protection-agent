from .models import Action, PolicyRule, RiskLevel

# EXAMPLE starting policy -- not a universally "correct" security policy.
# A real company should review and adjust this list; it's meant to be a
# reasonable, editable default, not a hard-coded law of the system.
DEFAULT_POLICIES: dict[str, PolicyRule] = {
    # Common PII (Phase 2 built-in entities)
    "PERSON": PolicyRule(Action.SANITIZE, RiskLevel.LOW),
    "EMAIL_ADDRESS": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "PHONE_NUMBER": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "CREDIT_CARD": PolicyRule(Action.BLOCK, RiskLevel.HIGH),
    "IP_ADDRESS": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "LOCATION": PolicyRule(Action.SANITIZE, RiskLevel.LOW),
    "DATE_TIME": PolicyRule(Action.ALLOW, RiskLevel.LOW),
    "URL": PolicyRule(Action.WARN, RiskLevel.LOW),
    # Company-specific custom entities (Phase 2 custom recognizers)
    "CUSTOMER_ID": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "EMPLOYEE_ID": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "CLIENT_ID": PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM),
    "PROJECT_ID": PolicyRule(Action.WARN, RiskLevel.LOW),
    "INTERNAL_DOMAIN": PolicyRule(Action.WARN, RiskLevel.MEDIUM),
    "INTERNAL_SERVER": PolicyRule(Action.BLOCK, RiskLevel.HIGH),
    "API_KEY": PolicyRule(Action.BLOCK, RiskLevel.CRITICAL),
    "ACCESS_TOKEN": PolicyRule(Action.BLOCK, RiskLevel.CRITICAL),
    "DATABASE_CONNECTION_STRING": PolicyRule(Action.BLOCK, RiskLevel.CRITICAL),
    "INTERNAL_URL": PolicyRule(Action.WARN, RiskLevel.MEDIUM),
}

# Applied when a detected entity_type has no entry in the policies dict above
# (see Step 13 for the reasoning behind SANITIZE as the default).
UNKNOWN_ENTITY_POLICY = PolicyRule(Action.SANITIZE, RiskLevel.MEDIUM)
