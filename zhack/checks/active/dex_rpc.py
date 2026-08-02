from __future__ import annotations

import json
import re
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from zhack.checks.base import BaseCheck
from zhack.checks.dex_common import (
    collect_frontend_sources,
    extract_dex_addresses,
    extract_rpc_urls,
    is_dex_text,
)
from zhack.core.models import Severity

_CHAINID_RE = (
    r'\bchainId\s*[:=]\s*["\']?(0x[0-9a-fA-F]+|\d{1,10})["\']?'
)


def _parse_chain(value: str):
    value = value.strip().strip('"').strip("'")
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


class DexRpcCheck(BaseCheck):
    """Comprueba por RPC de solo lectura routers DEX, chainId y despliegues."""

    name = "dex_rpc"
    requires_active = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        sources = await collect_frontend_sources(ctx, main.text)
        combined = "\n".join(text for _, text in sources)
        if not is_dex_text(combined):
            return

        rpcs = extract_rpc_urls(ctx.url, sources)[:3]
        if not rpcs:
            return

        addresses = [
            (label, address)
            for label, address in extract_dex_addresses(sources)
            if label in {"router", "factory", "quoter", "vault", "permit2", "multicall"}
        ][:8]

        declared_chains: List[int] = []
        for _, source in sources:
            for match in re.finditer(_CHAINID_RE, source):
                chain = _parse_chain(match.group(1))
                if chain is not None and chain not in declared_chains:
                    declared_chains.append(chain)

        reported: set[tuple[str, str]] = set()
        for rpc in rpcs:
            for label, address in addresses:
                if (rpc, address) in reported:
                    continue
                reported.add((rpc, address))
                res = await ctx.fetch("GET", self._probe_url(rpc, address))
                if not res.ok or not res.body:
                    continue
                try:
                    code = json.loads(res.text).get("result")
                except (TypeError, ValueError):
                    continue
                if isinstance(code, str) and code.lower() in {"0x", "0x0"}:
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.HIGH,
                            f"{label} DEX sin bytecode en la red consultada",
                            "La dirección configurada para un componente crítico del DEX no tiene bytecode en el RPC configurado. Puede indicar chainId equivocado, despliegue inexistente, dirección suplantada o contrato destruido.",
                            "Verifica chainId, checksum, bytecode y fuente verificada antes de permitir aprobaciones o swaps; usa una whitelist por red.",
                            url=rpc,
                            evidence=f"{label}={address}; eth_getCode={code}",
                        )
                    )

        if declared_chains:
            for rpc in rpcs[:2]:
                res = await ctx.fetch("GET", self._method_url(rpc, "eth_chainId", []))
                if not res.ok or not res.body:
                    continue
                try:
                    chain_result = json.loads(res.text).get("result")
                except (TypeError, ValueError):
                    continue
                rpc_chain = _parse_chain(str(chain_result)) if chain_result is not None else None
                if rpc_chain is None:
                    continue
                if rpc_chain not in declared_chains:
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.HIGH,
                            "chainId del frontend no coincide con el RPC configurado",
                            "El frontend declara una red (chainId) distinta de la que responde el RPC. Los swaps y aprobaciones se firmarían para otra red: fondos perdidos, aprobaciones en la red equivocada o transacciones fallidas en cadena.",
                            "Fija un chainId único por entorno, valídalo contra eth_chainId al iniciar la app y bloquea la interfaz ante discrepancias.",
                            url=rpc,
                            evidence=f"frontend={declared_chains}; eth_chainId={chain_result}",
                        )
                    )

    @staticmethod
    def _method_url(rpc: str, method: str, params: list) -> str:
        parsed = urlparse(rpc)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.extend(
            [
                ("method", method),
                ("params", json.dumps(params, separators=(",", ":"))),
            ]
        )
        return urlunparse(parsed._replace(query=urlencode(query)))

    @staticmethod
    def _probe_url(rpc: str, address: str) -> str:
        return DexRpcCheck._method_url(rpc, "eth_getCode", [address, "latest"])
