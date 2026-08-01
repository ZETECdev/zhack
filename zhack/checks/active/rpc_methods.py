from __future__ import annotations

import json
import re
from typing import List
from urllib.parse import urljoin, urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_RPC_URL_RE = re.compile(
    r"""["']((?:https?://)?[^"'\\ ]*(?:rpc|infura\.io|alchemy\.com|quicknode\.com|chainstack\.com|helius|drpc|blastapi|tatum)[^"'\\ ]*)["']""",
    re.I,
)

_MAX_RPC_URLS = 3

_READ_ONLY_CALLS = [
    ("eth_blockNumber", None, "accesible"),
    ("eth_chainId", None, "cadena"),
    ("net_version", None, "red"),
    ("eth_accounts", None, "cuentas"),
]


class RpcMethodsCheck(BaseCheck):
    """Consulta métodos JSON-RPC de solo lectura vía GET para detectar nodos públicos mal configurados."""

    name = "rpc_methods"
    requires_active = True

    async def run(self, ctx) -> None:
        rpcs: List[str] = []
        main = await ctx.get_main()
        sources = [main.text] if main.body else []
        for candidate in ctx.candidates[:5]:
            if candidate == ctx.url:
                continue
            res = await ctx.fetch("GET", candidate)
            if res.ok and res.body:
                sources.append(res.text)

        for text in sources:
            for m in _RPC_URL_RE.finditer(text):
                raw = m.group(1).strip()
                url = urljoin(ctx.url, raw) if raw.startswith("/") else raw
                parsed = urlparse(url)
                if parsed.scheme in ("http", "https") and url not in rpcs:
                    rpcs.append(url)

        for rpc in rpcs[: _MAX_RPC_URLS]:
            await self._probe(ctx, rpc)

    async def _probe(self, ctx, rpc: str) -> None:
        base = rpc.split("?")[0]
        for method, _, label in _READ_ONLY_CALLS:
            url = f"{base}?method={method}&params=[]"
            res = await ctx.fetch("GET", url)
            if not res.ok or not res.body:
                continue
            try:
                data = json.loads(res.text)
                result = data.get("result")
            except (ValueError, TypeError):
                continue
            if result is None:
                continue
            if method == "eth_accounts":
                if isinstance(result, list) and len(result) > 0:
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.HIGH,
                            "Nodo RPC expone cuentas desbloqueadas (eth_accounts)",
                            "El RPC público devuelve cuentas en eth_accounts: el nodo podría tener cuentas desbloqueadas y permitir firmar/operar sin autorización.",
                            "Desactiva eth_accounts en nodos públicos (personal_* y eth_accounts solo en localhost) y protege el RPC con autenticación.",
                            url=base,
                            evidence=f"eth_accounts -> {result[:3]}",
                        )
                    )
            elif method == "eth_blockNumber":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.INFO,
                        "Nodo RPC público accesible",
                        "El endpoint RPC responde a llamadas JSON-RPC sin autenticación (eth_blockNumber). Verifica qué métodos expone y si consume cuota/coste.",
                        "Si el RPC no debe ser público, protege el endpoint con autenticación y rate limiting.",
                        url=base,
                        evidence=f"eth_blockNumber -> {result}",
                    )
                )
            elif method in ("eth_chainId", "net_version"):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.INFO,
                        "Cadena identificada vía RPC",
                        "Se identifica la red del nodo a través del RPC público.",
                        "Información de recon; no requiere remediación directa.",
                        url=base,
                        evidence=f"{method} -> {result}",
                    )
                )
