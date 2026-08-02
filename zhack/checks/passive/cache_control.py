from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


_SESSION_COOKIE_RE = re.compile(
    r"(?:^|[-_])(session|sess|auth|token|jwt|sid|login|user)(?:$|[-_])",
    re.I,
)


class CacheControlCheck(BaseCheck):
    """Busca respuestas autenticadas que podrían quedar en cachés compartidas."""

    name = "cache_control"
    mass = True

    async def run(self, ctx) -> None:
        res = await ctx.get_main()
        if not res.ok or not res.headers:
            return

        cookie_names = self._session_cookie_names(res.headers)
        if not cookie_names:
            return

        cache_control = (res.headers.get("cache-control") or "").lower()
        if any(token in cache_control for token in ("no-store", "private", "no-cache")):
            return

        shared_cache = any(token in cache_control for token in ("public", "s-maxage", "max-age"))
        severity = Severity.MEDIUM if shared_cache else Severity.LOW
        directive = cache_control or "ausente"
        ctx.add(
            self.make(
                ctx,
                severity,
                "Respuesta con cookie de sesión potencialmente cacheable",
                "La respuesta establece una cookie relacionada con la sesión pero no indica que deba mantenerse privada o no almacenarse. Una caché compartida podría servir contenido autenticado a otro usuario.",
                "Para páginas autenticadas envía Cache-Control: no-store (o, como mínimo, private, no-cache) y revisa la configuración del CDN.",
                evidence=f"cookies={', '.join(cookie_names)}; Cache-Control={directive}",
            )
        )

    @staticmethod
    def _session_cookie_names(headers) -> list[str]:
        names: list[str] = []
        for raw in headers.getall("Set-Cookie", []):
            name = raw.split("=", 1)[0].strip()
            if name and _SESSION_COOKIE_RE.search(name):
                names.append(name)
        return list(dict.fromkeys(names))
