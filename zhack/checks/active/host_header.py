from __future__ import annotations

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_PROBE_HOST = "zhack-host-probe.example"


class HostHeaderCheck(BaseCheck):
    """Detecta reflexión del Host controlado sin probar poisoning ni mutaciones."""

    name = "host_header"
    requires_active = True

    async def run(self, ctx) -> None:
        reported: set[str] = set()
        for candidate in ctx.candidates[:5]:
            if candidate in reported:
                continue
            res = await ctx.http.fetch(
                "GET",
                candidate,
                headers={"Host": _PROBE_HOST},
                allow_redirects=False,
            )
            if not res.ok:
                continue
            location = res.headers.get("location", "") if res.headers else ""
            reflected_in_location = _PROBE_HOST in location
            reflected_in_body = bool(res.body and _PROBE_HOST in res.text)
            if not reflected_in_location and not reflected_in_body:
                continue
            reported.add(candidate)
            context = "Location" if reflected_in_location else "cuerpo HTML"
            severity = Severity.HIGH if reflected_in_location else Severity.MEDIUM
            ctx.add(
                self.make(
                    ctx,
                    severity,
                    "Host header controlable reflejado en la respuesta",
                    f"El valor Host enviado por el cliente aparece en {context}. Un proxy o aplicación que confíe en ese valor puede generar enlaces, redirects o contenido con un dominio controlado por un atacante.",
                    "Usa una allowlist de hosts canónicos en el proxy y la aplicación, construye URLs con una configuración fija y no confíes en X-Forwarded-Host sin validación. Revisa cachés solo en staging.",
                    url=candidate,
                    evidence=f"Host: {_PROBE_HOST}; ubicación={context}",
                    confidence="alta",
                )
            )
