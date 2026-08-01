from __future__ import annotations

import re
from urllib.parse import urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_HTTP_RESOURCE_RE = re.compile(
    r'(?:src|href|url)\s*=\s*["\']http://', re.I
)


class MixedContentCheck(BaseCheck):
    """Detecta contenido mixto (recursos HTTP en páginas HTTPS)."""

    name = "mixed_content"
    mass = True

    async def run(self, ctx) -> None:
        if not ctx.url.startswith("https://"):
            return

        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        matches = _HTTP_RESOURCE_RE.findall(main.text)
        if matches:
            count = len(matches)
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    f"Contenido mixto: {count} recurso(s) HTTP en página HTTPS",
                    "La página se sirve por HTTPS pero carga recursos (scripts, imágenes, CSS) por HTTP. Los navegadores los bloquean parcialmente (mixed active) y exponen los pasivos a manipulación.",
                    "Cambia todas las URLs de recursos a protocolo relativo (//) o https://. Usa la cabecera Content-Security-Policy: upgrade-insecure-requests.",
                    evidence=f"Se detectaron {count} referencias a http:// en el HTML",
                )
            )
