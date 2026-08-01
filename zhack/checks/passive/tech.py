from __future__ import annotations

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


class TechFingerprintCheck(BaseCheck):
    """Identifica el stack tecnológico para priorizar actualizaciones (info)."""

    name = "tech"
    mass = True

    async def run(self, ctx) -> None:
        res = await ctx.get_main()
        if not res.ok or res.status is None:
            return

        hints = set()
        server = (res.headers.get("server") or "") + " " + (res.headers.get("x-powered-by") or "")
        lowered = server.lower()
        if "wordpress" in lowered or "wp" in lowered:
            hints.add("WordPress")
        if "joomla" in lowered:
            hints.add("Joomla")
        if "drupal" in lowered:
            hints.add("Drupal")

        body = res.body[:100_000].decode("utf-8", errors="ignore").lower()
        if "wp-content" in body or "wordpress" in body:
            hints.add("WordPress")
        if "joomla" in body:
            hints.add("Joomla")
        if "drupal" in body:
            hints.add("Drupal")
        if "ng-version" in body or "data-ng-version" in body:
            hints.add("Angular")
        if "_next/" in body or "__next" in body:
            hints.add("Next.js")
        if "laravel" in body:
            hints.add("Laravel")
        if "django" in body or "csrfmiddlewaretoken" in body:
            hints.add("Django")
        if "react" in body:
            hints.add("React")
        if "sap-idp" in body or "sap" in lowered:
            hints.add("SAP")

        if hints:
            ctx.add(
                self.make(
                    ctx,
                    Severity.INFO,
                    "Tecnologías detectadas: " + ", ".join(sorted(hints)),
                    "Identificación del stack para priorizar actualizaciones de seguridad.",
                    "Mantén el framework/CMS y sus plugins siempre actualizados y suscríbete a sus boletines de seguridad.",
                    evidence=", ".join(sorted(hints)),
                )
            )
