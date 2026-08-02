from __future__ import annotations

from abc import ABC, abstractmethod

from zhack.checks.english_guidance import build_english_guidance
from zhack.core.context import ScanContext
from zhack.core.models import Finding, Severity
from zhack.core.redaction import redact_sensitive


class BaseCheck(ABC):
    name: str = "base"
    mass: bool = False
    requires_active: bool = False

    @abstractmethod
    async def run(self, ctx: ScanContext) -> None: ...

    def make(
        self,
        ctx: ScanContext,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
        url: str = "",
        evidence: str = "",
        attacker_impact: str = "",
        attack_scenario: str = "",
        safe_validation: str = "",
        confidence: str = "alta",
        manual_review: bool = False,
    ) -> Finding:
        default_impact, default_scenario, default_validation = build_english_guidance(
            self.name, title
        )
        return Finding(
            check=self.name,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            url=redact_sensitive(url or ctx.url),
            evidence=redact_sensitive(evidence)[:400],
            attacker_impact=attacker_impact or default_impact,
            attack_scenario=attack_scenario or default_scenario,
            safe_validation=safe_validation or default_validation,
            confidence=confidence,
            manual_review=manual_review,
        )
