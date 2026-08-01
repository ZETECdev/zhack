from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_EVIL_ORIGIN = "https://evil.zhack.example"

# URLs de endpoints RPC dentro de comillas en el HTML/JS (relativas o absolutas)
_RPC_URL_RE = re.compile(
    r"""["']((?:https?://)?[^"'\\ ]*(?:rpc|infura\.io|alchemy\.com|quicknode\.com|chainstack\.com|helius|drpc)[^"'\\ ]*)["']""",
    re.I,
)

_MAX_RPC_URLS = 3


class RpcCorsCheck(BaseCheck):
    """Verifica endpoints RPC detectados en el frontend: CORS y accesibilidad."""

    name = "rpc_cors"
    requires_active = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        found: List[str] = []
        for m in _RPC_URL_RE.finditer(main.text):
            raw = m.group(1).strip()
            if not raw or raw.startswith("http://"):
                continue
            url = urljoin(ctx.url, raw)
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue
            if url not in found:
                found.append(url)

        for url in found[: _MAX_RPC_URLS]:
            res = await ctx.http.fetch("OPTIONS", url, headers={"Origin": _EVIL_ORIGIN})
            if not res.ok or not res.headers:
                continue
            acao = res.headers.get("access-control-allow-origin", "")
            acac = res.headers.get("access-control-allow-credentials", "")
            if _EVIL_ORIGIN in acao:
                with_creds = acac.lower() == "true"
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH if with_creds else Severity.MEDIUM,
                        "Endpoint RPC con CORS mal configurado" + (" y credenciales" if with_creds else ""),
                        f"El endpoint RPC {url} refleja el origen '{_EVIL_ORIGIN}' en Access-Control-Allow-Origin"
                        + (", permitiendo credenciales." if with_creds else ".")
                        + " Un sitio malicioso podría hacer llamadas RPC desde el navegador de la víctima (abusar del nodo, leer datos).",
                        "No reflejes orígenes arbitrarios en endpoints RPC: restringe por whitelist y, si aplica, exige auth por token desde el backend.",
                        url=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                    )
                )
            elif acao == "*" and acac.lower() == "true":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Endpoint RPC: CORS wildcard con credenciales",
                        "Access-Control-Allow-Origin: * junto con Allow-Credentials: true en un endpoint RPC es una configuración inválida y peligrosa.",
                        "Restringe el CORS del endpoint RPC a orígenes de confianza sin credenciales wildcard.",
                        url=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                    )
                )

            get = await ctx.http.fetch("GET", url)
            if get.ok and get.body and b"jsonrpc" in get.body:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.INFO,
                        "Endpoint RPC responde públicamente",
                        "El endpoint RPC responde a peticiones GET sin autenticación aparente. Verifica qué métodos expone.",
                        "Revisa la lista de métodos permitidos y restringe el acceso al RPC si no debe ser público.",
                        url=url,
                        evidence=f"HTTP {get.status}, respuesta JSON-RPC",
                    )
                )
