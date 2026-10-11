"""
Security Policy Engine for Veyra.

Combines deterministic rule findings, open-weight AI model outputs, and execution status
into an authoritative security decision (ALLOW, BLOCK, QUARANTINE).
Enforces fail-closed isolation when inference fails, ensuring suspicious content is never
automatically allowed.
"""

from typing import List, Optional, Tuple
from app.config import Settings, get_settings
from app.schemas import (
    AIModelAnalysis,
    AnalysisStatus,
    AttackCategory,
    Decision,
    RuleAnalysisResult,
    RuleFinding,
    RuleSeverity,
)


class PolicyEngine:
    """
    Evaluates composite security risk across rule patterns and model inference.
    Independent of any web framework.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def evaluate(
        self,
        rule_result: RuleAnalysisResult,
        model_analysis: Optional[AIModelAnalysis],
        analysis_status: AnalysisStatus,
    ) -> Tuple[Decision, AttackCategory, float, float, str, List[str]]:
        """
        Synthesize multi-signal input into a security decision.

        Returns:
            Tuple of (
                decision: Decision,
                category: AttackCategory,
                risk_score: float (0.0 to 1.0),
                confidence: float (0.0 to 1.0),
                explanation: str,
                evidence: List[str]
            )
        """
        evidence: List[str] = []
        for finding in rule_result.findings:
            evidence.append(f"[{finding.rule_id}] {finding.matched_pattern}")

        # ---------------------------------------------------------
        # Case 1: Hard Rule Triggers (Critical Severity)
        # ---------------------------------------------------------
        if rule_result.has_triggers and rule_result.highest_severity == RuleSeverity.CRITICAL:
            lead_finding = next(
                f for f in rule_result.findings if f.severity == RuleSeverity.CRITICAL
            )
            composite_risk = max(0.92, rule_result.risk_score)
            explanation = (
                f"Critical security rule triggered ({lead_finding.rule_id}: {lead_finding.name}). "
                f"{lead_finding.description}"
            )
            return (
                Decision.BLOCK,
                lead_finding.category,
                composite_risk,
                lead_finding.confidence,
                explanation,
                evidence,
            )

        # ---------------------------------------------------------
        # Case 2: Inference Failure / Model Unavailable
        # ---------------------------------------------------------
        if model_analysis is None or analysis_status in (
            AnalysisStatus.MODEL_ERROR,
            AnalysisStatus.TIMEOUT,
            AnalysisStatus.FALLBACK_RULES_ONLY,
        ):
            return self._handle_inference_failure(rule_result, analysis_status, evidence)

        # ---------------------------------------------------------
        # Case 3: Complete Evaluation (Rules + Model Available)
        # ---------------------------------------------------------
        # Incorporate model evidence
        for ev in model_analysis.evidence:
            if ev and ev not in evidence:
                evidence.append(ev)

        # Calculate composite risk score
        if rule_result.has_triggers:
            # When rules trigger, blend rule risk and model risk with bias towards maximum threat
            composite_risk = max(
                rule_result.risk_score,
                round(0.6 * rule_result.risk_score + 0.4 * model_analysis.risk_score, 3),
            )
            # Use rule category if rule was HIGH severity, otherwise model category
            if rule_result.highest_severity == RuleSeverity.HIGH:
                lead_finding = next(
                    f for f in rule_result.findings if f.severity == RuleSeverity.HIGH
                )
                assigned_category = lead_finding.category
            else:
                assigned_category = (
                    model_analysis.category
                    if model_analysis.category != AttackCategory.BENIGN
                    else rule_result.findings[0].category
                )
            composite_confidence = round(
                (rule_result.findings[0].confidence + model_analysis.confidence) / 2.0, 3
            )
        else:
            composite_risk = model_analysis.risk_score
            assigned_category = model_analysis.category
            composite_confidence = model_analysis.confidence

        # Decision thresholding
        if composite_risk >= self.settings.risk_threshold_block or model_analysis.recommended_action == Decision.BLOCK:
            decision = Decision.BLOCK
            explanation = (
                f"High risk detected ({composite_risk:.2f} >= threshold {self.settings.risk_threshold_block:.2f}). "
                f"Model evaluation: {model_analysis.explanation}"
            )
        elif (
            composite_risk >= self.settings.risk_threshold_quarantine
            or assigned_category in (AttackCategory.INDIRECT_INJECTION, AttackCategory.UNCERTAIN)
            or model_analysis.recommended_action == Decision.QUARANTINE
        ):
            decision = Decision.QUARANTINE
            explanation = (
                f"Input routed to quarantine for isolation. Risk score ({composite_risk:.2f}) "
                f"indicates suspicious or ambiguous content ({assigned_category.value}). {model_analysis.explanation}"
            )
        else:
            decision = Decision.ALLOW
            explanation = f"Input verified benign. Risk score ({composite_risk:.2f}) within acceptable policy limits."

        return (
            decision,
            assigned_category,
            composite_risk,
            composite_confidence,
            explanation,
            evidence,
        )

    def _handle_inference_failure(
        self,
        rule_result: RuleAnalysisResult,
        analysis_status: AnalysisStatus,
        evidence: List[str],
    ) -> Tuple[Decision, AttackCategory, float, float, str, List[str]]:
        """
        Enforce safe fallback policy when AI model inference fails.
        Guarantees that suspicious or unverified content is never blindly allowed.
        """
        if rule_result.has_triggers:
            lead_finding = rule_result.findings[0]
            if rule_result.highest_severity in (RuleSeverity.CRITICAL, RuleSeverity.HIGH):
                decision = Decision.BLOCK
                explanation = (
                    f"Model inference failed ({analysis_status.value}), but deterministic rules detected "
                    f"high-severity threat ({lead_finding.rule_id}: {lead_finding.name}). Blocked."
                )
            else:
                decision = Decision.QUARANTINE
                explanation = (
                    f"Model inference failed ({analysis_status.value}) and suspicious patterns were detected "
                    f"({lead_finding.rule_id}). Quarantined."
                )
            return (
                decision,
                lead_finding.category,
                rule_result.risk_score,
                lead_finding.confidence,
                explanation,
                evidence,
            )

        # No rules triggered, but model failed to verify
        if self.settings.fail_closed_on_error:
            # Conservative quarantine posture
            decision = Decision.QUARANTINE
            category = AttackCategory.UNCERTAIN
            risk_score = 0.50
            confidence = 0.40
            explanation = (
                f"Inference failure ({analysis_status.value}). Untrusted input routed to conservative "
                f"quarantine under fail-closed security posture. Human review or re-analysis required."
            )
            evidence.append(f"Inference pipeline status: {analysis_status.value}")
        else:
            # Permissive fallback (discouraged, but configurable)
            decision = Decision.ALLOW
            category = AttackCategory.BENIGN
            risk_score = 0.10
            confidence = 0.30
            explanation = (
                f"Inference failure ({analysis_status.value}). Permissive fallback permitted unanalyzed input."
            )

        return (
            decision,
            category,
            risk_score,
            confidence,
            explanation,
            evidence,
        )
