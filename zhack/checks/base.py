from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from zhack.core.context import ScanContext
from zhack.core.models import Finding, Severity


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
    ) -> Finding:
        return Finding(
            check=self.name,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            url=url or ctx.url,
            evidence=evidence[:400],
        )
