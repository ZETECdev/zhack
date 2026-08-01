from __future__ import annotations

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_DANGEROUS_METHODS = {
    "TRACE": (Severity.MEDIUM, "Método HTTP TRACE habilitado",
              "TRACE está habilitado y puede usarse para cross-site tracing (XST); combinado con XSS roba cookies HttpOnly.",
              "Desactiva el método TRACE en el servidor (TraceEnable off en Apache)."),
    "PUT": (Severity.HIGH, "Método HTTP PUT habilitado",
            "PUT permite subir archivos al servidor web; un atacante podría alojar contenido malicioso o defacear el sitio.",
            "Desactiva PUT, DELETE y métodos no necesarios. Solo permite GET/POST/HEAD."),
    "DELETE": (Severity.HIGH, "Método HTTP DELETE habilitado",
              "DELETE permite borrar recursos del servidor vía HTTP.",
              "Desactiva DELETE, PUT y métodos no necesarios. Solo permite GET/POST/HEAD."),
    "PATCH": (Severity.MEDIUM, "Método HTTP PATCH habilitado",
              "PATCH permite modificar recursos parcialmente sin autenticación.",
              "Restringe PATCH a usuarios autenticados o desactívalo si no se usa."),
}


class HTTPMethodsCheck(BaseCheck):
    """Detecta métodos HTTP peligrosos habilitados vía header Allow (OPTIONS)."""

    name = "http_methods"
    requires_active = True

    async def run(self, ctx) -> None:
        for candidate in ctx.candidates[:5]:
            res = await ctx.http.fetch("OPTIONS", candidate)
            if not res.ok or not res.headers:
                continue
            allow = res.headers.get("allow", "")
            if not allow:
                continue
            enabled = {m.strip().upper() for m in allow.split(",")}
            for method, (severity, title, description, remediation) in _DANGEROUS_METHODS.items():
                if method in enabled:
                    ctx.add(
                        self.make(
                            ctx,
                            severity,
                            title,
                            description,
                            remediation,
                            url=candidate,
                            evidence=f"Allow: {allow.strip()}",
                        )
                    )
