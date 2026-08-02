from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.crawler import extract_forms
from zhack.core.models import Severity

_URL_INPUT_RE = re.compile(
    r"(?:^|[-_])(?:url|uri|callback|webhook|endpoint|image|avatar|feed|remote|fetch|proxy|source|site|link)(?:$|[-_])",
    re.I,
)


class SsrfHintsCheck(BaseCheck):
    """Marca entradas que merecen revisión SSRF sin probar redes internas."""

    name = "ssrf_hints"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        findings: list[str] = []
        for action, method, inputs in extract_forms(main.text):
            names = [name for name in inputs if _URL_INPUT_RE.search(name)]
            if names:
                findings.append(f"form action={action or '/'} method={method}: {', '.join(names[:4])}")

        if not findings:
            return
        ctx.add(
            self.make(
                ctx,
                Severity.MEDIUM,
                "Posibles entradas controlables para SSRF",
                "Se observan parámetros o patrones de recuperación remota que podrían permitir al backend solicitar URLs elegidas por un usuario. Es una señal estática y requiere revisar el flujo server-side.",
                "Usa allowlists de esquemas, hosts y puertos; bloquea loopback, link-local, rangos privados y redirecciones; resuelve DNS de forma segura y aplica egress filtering.",
                evidence="; ".join(findings[:4]),
                confidence="baja",
                manual_review=True,
            )
        )
