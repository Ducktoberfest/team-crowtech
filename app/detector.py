"""
Primary detection orchestrator for Veyra AI Security Engine.

Coordinates the multi-stage security pipeline:
Untrusted input -> deterministic rules -> open-weight AI analysis -> policy engine -> security decision.
Exposes the stable interface `analyze_prompt(prompt: str)`.
"""

import time
from typing import Optional

from app.config import Settings, get_settings
from app.ollama_client import (
    InferenceError,
    InferenceTimeoutError,
    OllamaClient,
)
from app.policy import PolicyEngine
from app.rules import evaluate_rules
from app.schemas import (
    AIModelAnalysis,
    AnalysisStatus,
    Decision,
    InferenceMode,
    PromptAnalysisResult,
    RuleAnalysisResult,
)


class PromptDetector:
    """
    Orchestrates deterministic rule filtering, LLM inference, and policy resolution.
    """

    def __init__(
        self,
        client: Optional[OllamaClient] = None,
        policy: Optional[PolicyEngine] = None,
        settings: Optional[Settings] = None,
    ):
        self.settings = settings or get_settings()
        self.client = client or OllamaClient()
        self.policy = policy or PolicyEngine(settings=self.settings)

    def analyze(self, prompt: str) -> PromptAnalysisResult:
        """
        Execute full end-to-end security pipeline for an untrusted prompt or document.
        """
        start_time = time.perf_counter()

        if not isinstance(prompt, str) or not prompt.strip():
            latency = (time.perf_counter() - start_time) * 1000.0
            return PromptAnalysisResult(
                category="benign",  # normalized by schema validator
                risk_score=0.0,
                confidence=1.0,
                explanation="Empty prompt evaluated as benign.",
                evidence=[],
                recommended_action=Decision.ALLOW,
                analysis_status=AnalysisStatus.SUCCESS,
                inference_mode=InferenceMode.NONE,
                decision=Decision.ALLOW,
                rule_findings=[],
                pipeline_latency_ms=round(latency, 2),
                metadata={"prompt_length": 0},
            )

        # Stage 1: Deterministic Security Rules
        rule_result: RuleAnalysisResult = evaluate_rules(prompt)

        # Stage 2: Open-weight Model Inference
        model_analysis: Optional[AIModelAnalysis] = None
        inference_mode: InferenceMode = InferenceMode.REAL if not self.client.demo_mode else InferenceMode.DEMO
        analysis_status: AnalysisStatus = AnalysisStatus.SUCCESS

        try:
            model_analysis, inference_mode, analysis_status = self.client.analyze(prompt)
        except InferenceTimeoutError as exc:
            analysis_status = AnalysisStatus.TIMEOUT
            inference_mode = InferenceMode.REAL
            model_analysis = None
        except InferenceError as exc:
            analysis_status = AnalysisStatus.MODEL_ERROR
            inference_mode = InferenceMode.REAL
            model_analysis = None
        except Exception as exc:
            analysis_status = AnalysisStatus.MODEL_ERROR
            inference_mode = InferenceMode.REAL
            model_analysis = None

        # Stage 3: Security Policy Resolution
        decision, category, risk_score, confidence, explanation, evidence = self.policy.evaluate(
            rule_result=rule_result,
            model_analysis=model_analysis,
            analysis_status=analysis_status,
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        metadata = {
            "model_configured": self.client.model,
            "rule_matches_count": len(rule_result.findings),
            "prompt_length": len(prompt),
        }
        if model_analysis and model_analysis.raw_response:
            metadata["raw_response_snippet"] = model_analysis.raw_response[:200]

        return PromptAnalysisResult(
            category=category,
            risk_score=risk_score,
            confidence=confidence,
            explanation=explanation,
            evidence=evidence,
            recommended_action=decision,
            analysis_status=analysis_status,
            inference_mode=inference_mode,
            decision=decision,
            rule_findings=rule_result.findings,
            pipeline_latency_ms=round(latency_ms, 2),
            metadata=metadata,
        )


# Global default detector instance
_default_detector: Optional[PromptDetector] = None


def get_default_detector() -> PromptDetector:
    """Retrieve or initialize default global detector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = PromptDetector()
    return _default_detector


def analyze_prompt(prompt: str) -> PromptAnalysisResult:
    """
    Main stable entry point for analyzing untrusted prompts and documents.
    
    Pipeline:
        Untrusted input -> deterministic rules -> open-weight AI analysis -> policy engine -> security decision.
        
    Args:
        prompt: Raw untrusted string from user, agent input, or third-party document.
        
    Returns:
        PromptAnalysisResult: Validated Pydantic model with decision, category, risk_score,
                              confidence, explanation, evidence, analysis_status, and inference_mode.
    """
    detector = get_default_detector()
    return detector.analyze(prompt)
