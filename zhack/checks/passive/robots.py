from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


_DISALLOW_RE = re.compile(r"^\s*Disallow\s*:\s*(/[^\s#]*)", re.I | re.M)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:\.git|\.env(?:$|\.)|admin(?:$|/)|backup|backups|debug|internal|private|"
    r"config|swagger|api-docs|server-status|actuator|database|dump)(?:$|/|\.)",
    re.I,
)


class RobotsDisclosureCheck(BaseCheck):
    """Detecta rutas internas interesantes reveladas por robots.txt."""

    name = "robots_disclosure"
    mass = True

    async def run(self, ctx) -> None:
        base = ctx.url.rstrip("/")
        res = await ctx.fetch("GET", base + "/robots.txt")
        if not (res.ok and res.status == 200 and res.body):
            return

        sensitive = []
        for match in _DISALLOW_RE.finditer(res.text):
            path = match.group(1)
            if path != "/" and _SENSITIVE_PATH_RE.search(path):
                sensitive.append(path)

        sensitive = list(dict.fromkeys(sensitive))
        if not sensitive:
            return

        ctx.add(
            self.make(
                ctx,
                Severity.INFO,
                "robots.txt revela rutas internas sensibles",
                "robots.txt es público y enumera rutas administrativas, de depuración o de respaldo que podrían facilitar el reconocimiento de la superficie expuesta.",
                "No uses robots.txt como control de acceso. Elimina rutas innecesarias y protege cada recurso con autenticación y reglas del servidor.",
                url=base + "/robots.txt",
                evidence="Disallow: " + ", ".join(sensitive[:8]),
            )
        )
