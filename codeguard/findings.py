"""Core data types shared by every detection layer."""
from __future__ import annotations

from dataclasses import dataclass, field

CATEGORIES: tuple[str, ...] = (
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One piece of evidence produced by an analyzer.

    severity is the analyzer's confidence (0-1) that this alone makes the
    snippet unsafe for `category`. Fusion combines findings into a verdict.
    """

    category: str
    severity: float
    lines: tuple[int, ...]
    rule: str
    message: str
    layer: str
    # Hard negatives: a finding with severity < 0 is a benign-context signal
    # that suppresses the category instead of raising it.


@dataclass(slots=True)
class Analysis:
    verdict: str
    risk_score: float
    categories: list[str]
    code_language: str
    reason: str
    vulnerable_lines: list[int]
    findings: list[Finding] = field(default_factory=list)
    category_scores: dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_response(self) -> dict:
        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "code_language": self.code_language,
            "reason": self.reason,
            "vulnerable_lines": self.vulnerable_lines,
        }
