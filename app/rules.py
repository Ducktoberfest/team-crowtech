"""
Deterministic Security Rule Engine for Veyra.

Performs static pattern analysis and heuristic detection of known adversarial prompts,
jailbreaks, instruction overrides, secret exfiltration, tool abuse, and indirect injections.
"""

import re
import unicodedata
from typing import List, Optional, Pattern
from app.schemas import AttackCategory, RuleAnalysisResult, RuleFinding, RuleSeverity


class SecurityRule:
    """Definition of an individual deterministic security inspection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        category: AttackCategory,
        severity: RuleSeverity,
        confidence: float,
        description: str,
        patterns: List[Pattern[str]],
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.patterns = patterns

    def evaluate(self, normalized_text: str) -> Optional[RuleFinding]:
        """Check if any pattern in this rule matches the input text."""
        for pattern in self.patterns:
            match = pattern.search(normalized_text)
            if match:
                matched_snippet = match.group(0)[:120]
                return RuleFinding(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    matched_pattern=matched_snippet,
                    description=self.description,
                )
        return None


def _normalize_text(text: str) -> str:
    """
    Normalize text by stripping zero-width unicode artifacts,
    homoglyphs, and excessive whitespace.
    """
    # NFKD normalization to decompose homoglyphs/accents
    normalized = unicodedata.normalize("NFKD", text)
    # Strip zero-width spaces and invisible control characters completely
    normalized = re.sub(r"[\u200B-\u200D\uFEFF]", "", normalized)
    # Convert non-breaking spaces and other unicode spaces to regular space
    normalized = re.sub(r"[\u00A0\u2000-\u200A\u202F\u205F\u3000]", " ", normalized)
    # Collapse multiple whitespace
    normalized = re.sub(r"[ \t]+", " ", normalized)
    return normalized


# Pre-compiled regex patterns for rules
RULE_DEFINITIONS: List[SecurityRule] = [
    # ----------------------------------------------------
    # 1. Instruction Overrides
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-OVERRIDE-001",
        name="Direct Instruction Override",
        category=AttackCategory.INSTRUCTION_OVERRIDE,
        severity=RuleSeverity.CRITICAL,
        confidence=0.95,
        description="Explicit directive commanding the AI to disregard previous instructions, rules, or system guidelines.",
        patterns=[
            re.compile(
                r"\b(?:ignore|disregard|forget|bypass|override|drop|abandon)\s+"
                r"(?:all\s+|your\s+|all\s+your\s+|the\s+)?(?:previous|prior|above|former|earlier|initial|original|preceding)\s+"
                r"(?:instructions|prompts|directives|rules|guidelines|commands|constraints)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:reset|clear|wipe)\s+(?:all\s+|your\s+)?(?:system\s+)?(?:instructions|context|prompts|directives)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bfrom\s+now\s+on[,\s]+(?:you\s+must\s+)?(?:only\s+)?(?:ignore|disregard|forget|follow\s+only)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:you\s+are\s+no\s+longer\s+bound\s+by|do\s+not\s+follow)\s+(?:any|your)\s+(?:previous|initial|system)\s+rules\b",
                re.IGNORECASE,
            ),
        ],
    ),
    SecurityRule(
        rule_id="RULE-OVERRIDE-002",
        name="System Role Impersonation",
        category=AttackCategory.INSTRUCTION_OVERRIDE,
        severity=RuleSeverity.HIGH,
        confidence=0.88,
        description="Attempt to assign an authoritative override persona claiming to replace default constraints.",
        patterns=[
            re.compile(
                r"\b(?:you\s+are\s+now|new\s+system\s+prompt:|your\s+new\s+role\s+is\s+to)\s+"
                r"(?:ignore\s+all|bypass\s+all|unrestricted|disregard)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:I\s+am\s+(?:your\s+developer|the\s+admin|system\s+administrator|OpenAI\s+engineer))\b.*?\b(?:override|bypass|disable\s+safety)\b",
                re.IGNORECASE | re.DOTALL,
            ),
        ],
    ),

    # ----------------------------------------------------
    # 2. Jailbreaks & Safety Bypasses
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-JAILBREAK-001",
        name="Known Jailbreak Persona (DAN / Dev Mode)",
        category=AttackCategory.JAILBREAK,
        severity=RuleSeverity.CRITICAL,
        confidence=0.98,
        description="Known adversarial jailbreak framing such as DAN (Do Anything Now) or Developer Mode.",
        patterns=[
            re.compile(r"\bdo\s+anything\s+now\b|\bDAN\s+(?:mode|jailbreak|prompt)\b", re.IGNORECASE),
            re.compile(r"\benable\s+developer\s+mode\s+output\b|\bdeveloper\s+mode\s+enabled\b", re.IGNORECASE),
            re.compile(r"\bAIM\s+mode\b|\balways\s+intelligent\s+and\s+machiavellian\b", re.IGNORECASE),
            re.compile(r"\bstan\s+jailbreak\b|\bmongo\s+tom\b|\buve\s+mode\b", re.IGNORECASE),
        ],
    ),
    SecurityRule(
        rule_id="RULE-JAILBREAK-002",
        name="Ethical Filter Bypass Simulation",
        category=AttackCategory.JAILBREAK,
        severity=RuleSeverity.HIGH,
        confidence=0.85,
        description="Fictional or hypothetical framing explicitly instructing the model to disable ethics, safety, or filters.",
        patterns=[
            re.compile(
                r"\b(?:in\s+this\s+hypothetical|fictional\s+world|hypothetically speaking)[,\s]+.*?"
                r"\b(?:no\s+(?:ethics|rules|censorship|filters|safeguards)|safety\s+filters\s+are\s+disabled)\b",
                re.IGNORECASE | re.DOTALL,
            ),
            re.compile(
                r"\bpretend\s+(?:you\s+have\s+no\s+(?:limits|filters|rules|morals)|to\s+be\s+an\s+evil|to\s+be\s+unrestricted)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bact\s+as\s+(?:an?\s+)?.*?\b(?:unfiltered|uncensored|jailbroken|evil|unrestricted)\s+(?:AI|assistant|model|persona)\b",
                re.IGNORECASE,
            ),
        ],
    ),

    # ----------------------------------------------------
    # 3. Secret & System Prompt Extraction
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-SECRET-001",
        name="System Prompt Exfiltration",
        category=AttackCategory.SECRET_EXTRACTION,
        severity=RuleSeverity.HIGH,
        confidence=0.90,
        description="Attempts to probe, reveal, or dump hidden system prompts and developer directives.",
        patterns=[
            re.compile(
                r"\b(?:print|repeat|show|reveal|display|output|dump|leak)\s+"
                r"(?:all\s+|the\s+|your\s+)*(?:(?:initial|original|hidden|system|developer|master)\s+)+"
                r"(?:prompt|prompts|instructions|message|directives|rules)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:what\s+is|what\s+are)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions|secret\s+instructions)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\boutput\s+everything\s+(?:above|before\s+this\s+line|from\s+the\s+beginning)\s+verbatim\b",
                re.IGNORECASE,
            ),
        ],
    ),
    SecurityRule(
        rule_id="RULE-SECRET-002",
        name="Credential & Environment Probing",
        category=AttackCategory.SECRET_EXTRACTION,
        severity=RuleSeverity.CRITICAL,
        confidence=0.92,
        description="Probing for API keys, environment variables, database passwords, or auth tokens.",
        patterns=[
            re.compile(
                r"\b(?:reveal|print|echo|show|dump)\s+(?:the\s+)?(?:OLLAMA_API_KEY|API_KEY|OPENAI_API_KEY|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:print|dump|read)\s+(?:process\.env|os\.environ|env\s+vars|\.env\s+file)\b",
                re.IGNORECASE,
            ),
        ],
    ),

    # ----------------------------------------------------
    # 4. Tool Abuse & Code Execution Injection
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-TOOL-001",
        name="Tool & Function Invocation Spoofing",
        category=AttackCategory.TOOL_ABUSE,
        severity=RuleSeverity.HIGH,
        confidence=0.88,
        description="Injecting structured tool invocation markers or function execution calls.",
        patterns=[
            re.compile(r"<\s*tool_call\s*>|<\s*/\s*tool_call\s*>", re.IGNORECASE),
            re.compile(r"<\s*function_calls?\s*>|\[\s*FUNCTION_CALL\s*:", re.IGNORECASE),
            re.compile(r"\{\s*\"name\"\s*:\s*\"(?:execute_command|run_shell|bash|eval|sql_query)\"", re.IGNORECASE),
        ],
    ),
    SecurityRule(
        rule_id="RULE-TOOL-002",
        name="Remote Command & Data Exfiltration Payloads",
        category=AttackCategory.TOOL_ABUSE,
        severity=RuleSeverity.CRITICAL,
        confidence=0.92,
        description="Command injection markers or markdown image beacon exfiltration URLs.",
        patterns=[
            re.compile(
                r"!\[.*?\]\(https?://[^\s)]*(?:\?|&)(?:leak|token|key|secret|data|exfil)=.*?\)",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:rm\s+-rf\s+/|DROP\s+DATABASE|DROP\s+TABLE\s+users|powershell\.exe\s+-(?:enc|ExecutionPolicy))\b",
                re.IGNORECASE,
            ),
            re.compile(r"(?:/etc/passwd|/etc/shadow|C:\\Windows\\System32\\cmd\.exe)", re.IGNORECASE),
        ],
    ),

    # ----------------------------------------------------
    # 5. Indirect Injection & Delimiter Tampering
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-INDIRECT-001",
        name="Document Embedded Indirect Injection",
        category=AttackCategory.INDIRECT_INJECTION,
        severity=RuleSeverity.HIGH,
        confidence=0.87,
        description="Instruction injection markers commonly embedded inside untrusted third-party documents or web scrapes.",
        patterns=[
            re.compile(
                r"\[\s*(?:SYSTEM\s+NOTE|IMPORTANT\s+SYSTEM\s+UPDATE|SYSTEM\s+OVERRIDE)\s*:\s*.*?\]",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:<!--|/\*)\s*(?:AI\s+INSTRUCTION|PROMPT\s+OVERRIDE|SYSTEM\s+DIRECTIVE):.*?(?:-->|\*/)",
                re.IGNORECASE | re.DOTALL,
            ),
            re.compile(
                r"\b(?:Notice\s+to\s+AI\s+evaluator|Instruction\s+for\s+the\s+AI\s+reading\s+this|When\s+summarizing\s+this,\s+instead\s+do)\b",
                re.IGNORECASE,
            ),
        ],
    ),
    SecurityRule(
        rule_id="RULE-INDIRECT-002",
        name="Delimiter & Context Boundary Tampering",
        category=AttackCategory.INDIRECT_INJECTION,
        severity=RuleSeverity.HIGH,
        confidence=0.85,
        description="Attempt to escape parsing boundaries using fake system prompt boundaries or chat tokens.",
        patterns=[
            re.compile(r"</?\s*(?:system|context|instruction|im_start|im_end)\s*>", re.IGNORECASE),
            re.compile(r"\[\s*/?(?:INST|SYS)\s*\]", re.IGNORECASE),
            re.compile(r"---+\s*(?:END\s+OF\s+CONTEXT|START\s+SYSTEM\s+PROMPT)\s*---+", re.IGNORECASE),
        ],
    ),

    # ----------------------------------------------------
    # 6. Policy Bypass & Obfuscated Payloads
    # ----------------------------------------------------
    SecurityRule(
        rule_id="RULE-BYPASS-001",
        name="Obfuscation & Encoding Bypass Request",
        category=AttackCategory.INSTRUCTION_OVERRIDE,
        severity=RuleSeverity.MEDIUM,
        confidence=0.80,
        description="Commands requesting decoding and execution of encoded payloads (Base64, ROT13, hex).",
        patterns=[
            re.compile(
                r"\b(?:decode|execute|run)\s+(?:the\s+following\s+)?(?:base64|rot13|hex|ciphers?)\s+(?:and\s+(?:execute|follow|obey))\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"\b(?:base64\s+decode\s+this\s+command\s+and\s+run\s+it)\b",
                re.IGNORECASE,
            ),
        ],
    ),
]


def evaluate_rules(text: str) -> RuleAnalysisResult:
    """
    Run all deterministic security rules against the given input.
    
    Returns structured findings, highest severity level, and composite rule risk score.
    """
    if not text or not text.strip():
        return RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])

    normalized = _normalize_text(text)
    findings: List[RuleFinding] = []

    for rule in RULE_DEFINITIONS:
        finding = rule.evaluate(normalized)
        if finding:
            findings.append(finding)

    if not findings:
        return RuleAnalysisResult(has_triggers=False, risk_score=0.0, findings=[])

    # Severity ordering
    severity_rank = {
        RuleSeverity.CRITICAL: 5,
        RuleSeverity.HIGH: 4,
        RuleSeverity.MEDIUM: 3,
        RuleSeverity.LOW: 2,
        RuleSeverity.INFO: 1,
    }

    highest = max(findings, key=lambda f: severity_rank.get(f.severity, 0)).severity

    base_scores = {
        RuleSeverity.CRITICAL: 0.92,
        RuleSeverity.HIGH: 0.78,
        RuleSeverity.MEDIUM: 0.50,
        RuleSeverity.LOW: 0.25,
        RuleSeverity.INFO: 0.05,
    }

    base = base_scores.get(highest, 0.0)
    count_bump = min(0.08, (len(findings) - 1) * 0.03)
    final_score = round(min(1.0, base + count_bump), 3)

    return RuleAnalysisResult(
        has_triggers=True,
        highest_severity=highest,
        risk_score=final_score,
        findings=findings,
    )
