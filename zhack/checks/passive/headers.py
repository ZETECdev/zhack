from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.I)


class SecurityHeadersCheck(BaseCheck):
    """Revisa las cabeceras de seguridad más importantes."""

    name = "security_headers"
    mass = True

    async def run(self, ctx) -> None:
        res = await ctx.get_main()
        if not res.ok or res.status is None or not res.headers:
            return

        headers = res.headers

        checks = [
            (
                "content-security-policy",
                Severity.MEDIUM,
                "Falta Content-Security-Policy (CSP)",
                "Sin CSP, las inyecciones XSS y otros ataques pueden ejecutarse con menos obstáculos.",
                "Define una CSP estricta, p.ej.: default-src 'self'; script-src 'self'; object-src 'none'",
            ),
            (
                "strict-transport-security",
                Severity.MEDIUM,
                "Falta Strict-Transport-Security (HSTS)",
                "Sin HSTS el navegador no fuerza HTTPS y un atacante podría degradar la conexión a HTTP.",
                "Envía: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ),
            (
                "x-frame-options",
                Severity.MEDIUM,
                "Falta X-Frame-Options",
                "Sin protección de framing el sitio puede incrustarse en iframes de otros dominios (clickjacking).",
                "Envía X-Frame-Options: DENY o SAMEORIGIN (o usa CSP frame-ancestors).",
            ),
            (
                "x-content-type-options",
                Severity.LOW,
                "Falta X-Content-Type-Options",
                "Los navegadores podrían interpretar archivos con un MIME incorrecto (MIME sniffing).",
                "Envía: X-Content-Type-Options: nosniff",
            ),
            (
                "referrer-policy",
                Severity.LOW,
                "Falta Referrer-Policy",
                "Se envía la URL completa como Referer a sitios externos, filtrando información interna.",
                "Envía: Referrer-Policy: strict-origin-when-cross-origin",
            ),
            (
                "permissions-policy",
                Severity.LOW,
                "Falta Permissions-Policy",
                "APIs sensibles (cámara, micrófono, geolocalización) quedan disponibles por defecto.",
                "Envía: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            ),
        ]

        for header_name, severity, title, description, remediation in checks:
            if header_name not in headers:
                ctx.add(self.make(ctx, severity, title, description, remediation))

        csp = headers.get("content-security-policy", "")
        if "unsafe-inline" in csp:
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    "CSP debilitada: usa 'unsafe-inline'",
                    "La política CSP permite código inline, lo que facilita la ejecución de XSS.",
                    "Elimina 'unsafe-inline' de script-src/style-src usando hashes o nonces.",
                    evidence=csp,
                )
            )

        hsts = headers.get("strict-transport-security", "")
        m = _HSTS_MAX_AGE_RE.search(hsts)
        if hsts and m and int(m.group(1)) < 15552000:
            ctx.add(
                self.make(
                    ctx,
                    Severity.LOW,
                    "HSTS con max-age corto",
                    "El HSTS caduca antes de 6 meses; el navegador deja de forzar HTTPS pronto.",
                    "Usa max-age=31536000 (1 año) o más, con includeSubDomains.",
                    evidence=hsts,
                )
            )
