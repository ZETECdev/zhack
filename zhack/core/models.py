from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "critico"
    HIGH = "alto"
    MEDIUM = "medio"
    LOW = "bajo"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critico": 5, "alto": 4, "medio": 3, "bajo": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "critico": "#d0021b",
            "alto": "#f5a623",
            "medio": "#d9a400",
            "bajo": "#4a90d9",
            "info": "#9b9b9b",
        }[self.value]


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    description: str
    remediation: str
    url: str = ""
    evidence: str = ""
    attacker_impact: str = ""
    attack_scenario: str = ""
    safe_validation: str = ""
    confidence: str = "alta"
    manual_review: bool = False


@dataclass
class TargetResult:
    url: str
    status: Optional[int] = None
    final_url: str = ""
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.score)
