from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_TAG_RE = re.compile(r"<(?:script|link)\b[^>]*>", re.I)
_URL_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', re.I)
_INTEGRITY_RE = re.compile(r"integrity\s*=", re.I)
_CROSS_ORIGIN_RE = re.compile(r"crossorigin\s*", re.I)


class SubresourceIntegrityCheck(BaseCheck):
    """Detecta recursos externos (CDN) sin atributo integrity (riesgo de supply chain)."""

    name = "sri"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        missing: list = []
        for m in _TAG_RE.finditer(main.text):
            tag = m.group()
            url_m = _URL_RE.search(tag)
            if not url_m:
                continue
            url = url_m.group(1)
            if not url.startswith(("http://", "https://")):
                continue
            if url.startswith(ctx.url.rstrip("/")):
                continue
            if _INTEGRITY_RE.search(tag):
                continue
            missing.append(url)

        if missing:
            unique = sorted(set(missing))[:5]
            ctx.add(
                self.make(
                    ctx,
                    Severity.LOW,
                    f"{len(missing)} recurso(s) externo(s) sin SRI (integrity)",
                    "Scripts/estilos cargados desde CDNs de terceros sin atributo integrity: si el CDN o el repositorio del proveedor es comprometido, se ejecuta código malicioso en el sitio (riesgo de supply chain).",
                    "Añade el atributo integrity (SRI) a todos los recursos cross-origin y usa crossorigin=\"anonymous\".",
                    evidence="; ".join(unique),
                )
            )
