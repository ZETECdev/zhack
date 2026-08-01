from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]


class TraversalCheck(BaseCheck):
    """Detecta path traversal (lectura de archivos arbitrarios).

    Solo intenta leer archivos estándar de lectura (etc/passwd, win.ini) para confirmar.
    Nunca escribe ni ejecuta nada.
    """

    name = "traversal"
    requires_active = True

    async def run(self, ctx) -> None:
        for candidate in ctx.candidates:
            parsed = urlparse(candidate)
            if not parsed.query:
                continue
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for key, value in params:
                for payload in _TRAVERSAL_PAYLOADS:
                    query = urlencode(
                        [(k, payload if k == key else v) for k, v in params], doseq=True
                    )
                    probe_url = urlunparse(parsed._replace(query=query))
                    res = await ctx.http.fetch("GET", probe_url)
                    if not res.ok or not res.body:
                        continue
                    text = res.text
                    if ("root:" in text and "/bin/bash" in text) or ("; for 16-bit app support" in text and "boot loader" in text.lower()):
                        ctx.add(
                            self.make(
                                ctx,
                                Severity.CRITICAL,
                                f"Path traversal en el parámetro '{key}' (lectura de archivos del sistema)",
                                "El servidor permite salir de la raíz web y leer archivos arbitrarios del sistema operativo.",
                                "Valida y normaliza rutas, usa una whitelist de archivos permitidos y nunca concatenes entrada del usuario en rutas.",
                                url=probe_url,
                                evidence=text[:300],
                            )
                        )
                        return
