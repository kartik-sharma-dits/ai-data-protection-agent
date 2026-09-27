from ai_data_protection_agent.detection.models import DetectedEntity
from ai_data_protection_agent.policy.engine import PolicyEngine
from ai_data_protection_agent.policy.models import Action, PolicyRule, RiskLevel


def entity(entity_type, confidence=0.9, text="value", start=0, end=5):
    return DetectedEntity(entity_type=entity_type, text=text, start=start, end=end, confidence=confidence)


def test_no_pii_allows():
    result = PolicyEngine().evaluate([])
    assert result.overall_action == Action.ALLOW
    assert result.entities == []


def test_email_sanitizes():
    result = PolicyEngine().evaluate([entity("EMAIL_ADDRESS", confidence=0.99)])
    assert result.overall_action == Action.SANITIZE


def test_phone_sanitizes():
    result = PolicyEngine().evaluate([entity("PHONE_NUMBER", confidence=0.9)])
    assert result.overall_action == Action.SANITIZE


def test_api_key_blocks():
    result = PolicyEngine().evaluate([entity("API_KEY", confidence=0.96)])
    assert result.overall_action == Action.BLOCK


def test_multiple_sanitize_entities_stays_sanitize():
    entities = [entity("PERSON", confidence=0.9), entity("EMAIL_ADDRESS", confidence=0.9)]
    result = PolicyEngine().evaluate(entities)
    assert result.overall_action == Action.SANITIZE


def test_sanitize_plus_block_escalates_to_block():
    entities = [entity("EMAIL_ADDRESS", confidence=0.9), entity("API_KEY", confidence=0.96)]
    result = PolicyEngine().evaluate(entities)
    assert result.overall_action == Action.BLOCK


def test_warn_plus_sanitize_stays_sanitize():
    entities = [entity("URL", confidence=0.9), entity("EMAIL_ADDRESS", confidence=0.9)]
    result = PolicyEngine().evaluate(entities)
    assert result.overall_action == Action.SANITIZE


def test_unknown_entity_defaults_to_sanitize():
    result = PolicyEngine().evaluate([entity("UNKNOWN_SENSITIVE_ENTITY", confidence=0.9)])
    assert result.entities[0].action == Action.SANITIZE
    assert result.entities[0].risk == RiskLevel.MEDIUM


def test_low_confidence_low_risk_entity_is_softened():
    # PERSON is configured SANITIZE/LOW; below the confidence threshold it
    # should be softened one step to WARN.
    result = PolicyEngine().evaluate([entity("PERSON", confidence=0.2)])
    assert result.entities[0].action == Action.WARN


def test_high_risk_entity_with_low_confidence_is_not_softened():
    # API_KEY is CRITICAL risk -- confidence must never soften it.
    result = PolicyEngine().evaluate([entity("API_KEY", confidence=0.1)])
    assert result.entities[0].action == Action.BLOCK


def test_missing_confidence_treated_as_zero():
    e = entity("PERSON", confidence=None)
    result = PolicyEngine().evaluate([e])
    # confidence None -> 0.0 -> below threshold -> softened, same as low confidence
    assert result.entities[0].action == Action.WARN
    assert result.entities[0].confidence == 0.0


def test_invalid_policy_rule_rejected():
    try:
        PolicyRule(action="BLOCK", risk=RiskLevel.LOW)  # wrong type on purpose
        assert False, "expected TypeError"
    except TypeError:
        pass


def test_empty_detection_results():
    result = PolicyEngine().evaluate([])
    assert result.overall_action == Action.ALLOW


def test_multiple_entity_types():
    entities = [
        entity("PERSON", confidence=0.9),
        entity("EMAIL_ADDRESS", confidence=0.9),
        entity("URL", confidence=0.9),
        entity("DATE_TIME", confidence=0.9),
    ]
    result = PolicyEngine().evaluate(entities)
    actions = {d.entity_type: d.action for d in result.entities}
    assert actions["PERSON"] == Action.SANITIZE
    assert actions["EMAIL_ADDRESS"] == Action.SANITIZE
    assert actions["URL"] == Action.WARN
    assert actions["DATE_TIME"] == Action.ALLOW
    assert result.overall_action == Action.SANITIZE


def test_custom_customer_id_sanitizes():
    result = PolicyEngine().evaluate([entity("CUSTOMER_ID", confidence=0.9)])
    assert result.overall_action == Action.SANITIZE


def test_custom_api_key_blocks():
    result = PolicyEngine().evaluate([entity("API_KEY", confidence=0.9)])
    assert result.overall_action == Action.BLOCK


# --- Security tests (Step 15) -----------------------------------------------


def test_evaluation_never_holds_entity_text():
    result = PolicyEngine().evaluate([entity("PERSON", confidence=0.9, text="John Smith")])
    decision = result.entities[0]
    assert not hasattr(decision, "text")
    assert "John Smith" not in repr(decision)
    assert "John Smith" not in repr(result)
