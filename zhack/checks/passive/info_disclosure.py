from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_SERVER_VERSION_RE = re.compile(
    r"(apache|nginx|microsoft-iis|openresty|lighttpd|tomcat|express|envoy|traefik|caddy)", re.I
)
_VERSION_LEAK_RE = re.compile(r"\d+\.\d+(\.\d+)?")
_STACK_TRACE_RE = re.compile(
    r"traceback \(|stack trace|fatal error|warning:|notice:|sqlstate|mysql_|ora-\d+|"
    r"undefined (variable|index|property)|exception thrown|java\.lang\.",
    re.I,
)


class InfoDisclosureCheck(BaseCheck):
    """Detecta revelación de versiones, tecnologías y trazas de error."""

    name = "info_disclosure"
    mass = True

    async def run(self, ctx) -> None:
        res = await ctx.get_main()
        if not res.ok or res.status is None or not res.headers:
            return

        server = res.headers.get("server", "")
        if server and _SERVER_VERSION_RE.search(server) and _VERSION_LEAK_RE.search(server):
            ctx.add(
                self.make(
                    ctx,
                    Severity.LOW,
                    f"Versión del servidor revelada ('{server}')",
                    "El header Server revela software y versión; los atacantes buscan exploits conocidos para esa versión.",
                    "Oculta la versión (ServerTokens Prod en Apache, server_tokens off en nginx).",
                    evidence=server,
                )
            )

        for header_name, label in [
            ("x-powered-by", "X-Powered-By"),
            ("x-aspnet-version", "ASP.NET Version"),
            ("x-aspnetmvc-version", "ASP.NET MVC Version"),
            ("x-generator", "X-Generator"),
        ]:
            value = res.headers.get(header_name)
            if value:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.LOW,
                        f"Tecnología revelada: {label}",
                        f"La cabecera {label} expone la tecnología usada, ayudando a los atacantes a elegir exploits.",
                        "Elimina la cabecera en la configuración del framework.",
                        evidence=value,
                    )
                )

        probe = await ctx.http.fetch("GET", ctx.url.rstrip("/") + "/z_hack_error_probe_not_exists_123456")
        if probe.ok and probe.body and _STACK_TRACE_RE.search(probe.text):
            ctx.add(
                self.make(
                    ctx,
                    Severity.HIGH,
                    "Las páginas de error filtran trazas/errores internos",
                    "Una petición inválida devuelve trazas de pila o errores del framework, revelando código y rutas internas.",
                    "Activa el modo producción (ocultar errores) y personaliza las páginas 404/500.",
                    evidence=probe.text[:300],
                )
            )
