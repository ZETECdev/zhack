from __future__ import annotations

from urllib.parse import urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


class HTTPSCheck(BaseCheck):
    """Comprueba que el sitio fuerza HTTPS y que HTTP redirige a HTTPS."""

    name = "https"
    mass = True

    async def run(self, ctx) -> None:
        parsed = urlparse(ctx.url)
        if parsed.scheme == "https":
            http_url = f"http://{parsed.netloc}/"
            res = await ctx.http.fetch("GET", http_url, allow_redirects=True)
            if res.error:
                return
            final = res.final_url or http_url
            if not final.startswith("https://"):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "HTTP no redirige a HTTPS",
                        "El sitio responde por HTTP y no redirige a HTTPS. El tráfico (contraseñas, cookies, datos) viaja en claro y puede ser interceptado.",
                        "Configura una redirección 301 de http:// a https:// a nivel de servidor y activa HSTS.",
                        url=ctx.url,
                        evidence=f"{http_url} -> {final}",
                    )
                )
            return

        res = await ctx.http.fetch("GET", ctx.url, allow_redirects=True)
        final = res.final_url or ctx.url
        if final.startswith("https://"):
            return
        ctx.add(
            self.make(
                ctx,
                Severity.HIGH,
                "El sitio solo sirve por HTTP (sin cifrado)",
                "La web no ofrece conexión HTTPS ni redirige a ella. Toda la comunicación va sin cifrar.",
                "Instala un certificado TLS (Let's Encrypt es gratuito) y fuerza HTTPS con redirección 301.",
                url=ctx.url,
                evidence=ctx.url,
            )
        )
