"""
Unit tests for Veyra Security Policy Engine.
"""

import pytest
from app.config import Settings
from app.policy import PolicyEngine
from app.schemas import (
    AIModelAnalysis,
    AnalysisStatus,
    AttackCategory,
    Decision,
    RuleAnalysisResult,
    RuleFinding,
    RuleSeverity,
)


@pytest.fixture
def policy_engine() -> PolicyEngine:
    settings = Settings(
        risk_threshold_block=0.70,
        risk_threshold_quarantine=0.35,
        fail_closed_on_error=True,
    )
    return PolicyEngine(settings=settings)


def test_policy_allow_benign(policy_engine: PolicyEngine):
    """Test standard clean input returning ALLOW."""
    rule_res = RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])
    model_analysis = AIModelAnalysis(
        category=AttackCategory.BENIGN,
        risk_score=0.05,
        confidence=0.95,
        explanation="Benign request.",
        evidence=[],
        recommended_action=Decision.ALLOW,
    )

    decision, category, risk, conf, explanation, evidence = policy_engine.evaluate(
        rule_result=rule_res,
        model_analysis=model_analysis,
        analysis_status=AnalysisStatus.SUCCESS,
    )

    assert decision == Decision.ALLOW
    assert category == AttackCategory.BENIGN
    assert risk < 0.35


def test_policy_critical_rule_overrides_to_block(policy_engine: PolicyEngine):
    """Test that a CRITICAL severity rule match immediately forces BLOCK."""
    rule_res = RuleAnalysisResult(
        has_triggers=True,
        highest_severity=RuleSeverity.CRITICAL,
        risk_score=0.95,
        findings=[
            RuleFinding(
                rule_id="RULE-OVERRIDE-001",
                name="Direct Instruction Override",
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                severity=RuleSeverity.CRITICAL,
                confidence=0.95,
                matched_pattern="ignore all previous instructions",
                description="Command to discard system instructions.",
            )
        ],
    )
    # Even if model somehow produced low risk, critical rule takes precedence
    model_analysis = AIModelAnalysis(
        category=AttackCategory.BENIGN,
        risk_score=0.10,
        confidence=0.50,
        explanation="Simulated false negative from model.",
        evidence=[],
        recommended_action=Decision.ALLOW,
    )

    decision, category, risk, conf, explanation, evidence = policy_engine.evaluate(
        rule_result=rule_res,
        model_analysis=model_analysis,
        analysis_status=AnalysisStatus.SUCCESS,
    )

    assert decision == Decision.BLOCK
    assert category == AttackCategory.INSTRUCTION_OVERRIDE
    assert risk >= 0.90


def test_policy_quarantine_band(policy_engine: PolicyEngine):
    """Test that moderate/suspicious risk scores route to QUARANTINE."""
    rule_res = RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])
    model_analysis = AIModelAnalysis(
        category=AttackCategory.UNCERTAIN,
        risk_score=0.48,
        confidence=0.65,
        explanation="Ambiguous cybersecurity query.",
        evidence=["discussing exploit mechanics"],
        recommended_action=Decision.QUARANTINE,
    )

    decision, category, risk, conf, explanation, evidence = policy_engine.evaluate(
        rule_result=rule_res,
        model_analysis=model_analysis,
        analysis_status=AnalysisStatus.SUCCESS,
    )

    assert decision == Decision.QUARANTINE
    assert category == AttackCategory.UNCERTAIN
    assert 0.35 <= risk < 0.70


def test_policy_inference_failure_fail_closed_quarantine(policy_engine: PolicyEngine):
    """Test conservative quarantine disposition when model inference fails."""
    rule_res = RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])

    # Model failed with timeout
    decision, category, risk, conf, explanation, evidence = policy_engine.evaluate(
        rule_result=rule_res,
        model_analysis=None,
        analysis_status=AnalysisStatus.TIMEOUT,
    )

    # Must NOT fail open to ALLOW!
    assert decision == Decision.QUARANTINE
    assert "conservative quarantine" in explanation.lower() or "timeout" in explanation.lower()


def test_policy_inference_failure_with_high_rules_blocks(policy_engine: PolicyEngine):
    """Test that model failure with rule matches still blocks dangerous inputs."""
    rule_res = RuleAnalysisResult(
        has_triggers=True,
        highest_severity=RuleSeverity.HIGH,
        risk_score=0.85,
        findings=[
            RuleFinding(
                rule_id="RULE-SECRET-001",
                name="System Prompt Exfiltration",
                category=AttackCategory.SECRET_EXTRACTION,
                severity=RuleSeverity.HIGH,
                confidence=0.90,
                matched_pattern="print system prompt verbatim",
                description="Extract system prompt.",
            )
        ],
    )

    decision, category, risk, conf, explanation, evidence = policy_engine.evaluate(
        rule_result=rule_res,
        model_analysis=None,
        analysis_status=AnalysisStatus.MODEL_ERROR,
    )

    assert decision == Decision.BLOCK
    assert category == AttackCategory.SECRET_EXTRACTION


def test_policy_configurable_permissive_fallback():
    """Test explicit permissive mode toggle when fail_closed_on_error is False."""
    permissive_settings = Settings(
        fail_closed_on_error=False,
    )
    engine = PolicyEngine(settings=permissive_settings)
    rule_res = RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])

    decision, category, risk, conf, explanation, evidence = engine.evaluate(
        rule_result=rule_res,
        model_analysis=None,
        analysis_status=AnalysisStatus.MODEL_ERROR,
    )

    assert decision == Decision.ALLOW
