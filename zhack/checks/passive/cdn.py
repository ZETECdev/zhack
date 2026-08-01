from __future__ import annotations

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


class CdnDetectCheck(BaseCheck):
    """Identifica el CDN/WAF frontal (reconocimiento, info)."""

    name = "cdn"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.headers:
            return

        headers = main.headers
        hints = []

        if headers.get("cf-ray") or "cloudflare" in headers.get("server", "").lower():
            hints.append("Cloudflare")
        if headers.get("x-amz-cf-id") or "amazon" in headers.get("server", "").lower():
            hints.append("CloudFront")
        if (
            "akamai" in headers.get("server", "").lower()
            or any(k.lower().startswith("x-akamai") for k in headers)
        ):
            hints.append("Akamai")
        if "fastly" in headers.get("server", "").lower():
            hints.append("Fastly")
        if headers.get("x-cache") and "cdn" in headers.get("x-cache", "").lower():
            hints.append("CDN genérico (X-Cache)")

        if hints:
            ctx.add(
                self.make(
                    ctx,
                    Severity.INFO,
                    "CDN/WAF detectado: " + ", ".join(hints),
                    "Identificación del CDN/WAF frontal para entender la infraestructura y qué protecciones hay delante del origen.",
                    "Mantén el origen oculto (solo accesible desde el CDN) y revisa las reglas WAF periódicamente.",
                    evidence=", ".join(hints),
                )
            )
