from __future__ import annotations

import random
import string
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


class ReflectedXSSCheck(BaseCheck):
    """Detecta XSS reflejado con payloads inofensivos (solo observación)."""

    name = "xss"
    requires_active = True

    async def run(self, ctx) -> None:
        token = "ZH" + "".join(random.choices(string.ascii_letters, k=8))
        payloads = [
            f'<script>ZHACKXSS="{token}"</script>',
            f'"><svg onload=ZHACKXSS("{token}")>',
        ]
        for candidate in ctx.candidates:
            parsed = urlparse(candidate)
            if not parsed.query:
                continue
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for key, value in params:
                for payload in payloads:
                    query = urlencode(
                        [(k, payload if k == key else v) for k, v in params], doseq=True
                    )
                    probe_url = urlunparse(parsed._replace(query=query))
                    res = await ctx.http.fetch("GET", probe_url)
                    if res.ok and res.body and payload in res.text:
                        ctx.add(
                            self.make(
                                ctx,
                                Severity.HIGH,
                                f"Reflejo sin escapar de '{key}' (posible XSS)",
                                "El parámetro se refleja en la respuesta SIN escaparse. Un atacante puede ejecutar JavaScript en el navegador de la víctima.",
                                "Escapa/desinfecta toda salida (HTML-encode <, >, \", ') y usa plantillas seguras + CSP.",
                                url=probe_url,
                                evidence=res.text[:300],
                            )
                        )
                        break
