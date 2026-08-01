from __future__ import annotations

import re
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_JS_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_CONTRACT_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_EXPLORER_RE = re.compile(
    r"(etherscan\.io|bscscan\.com|polygonscan\.com|arbiscan\.io|optimistic\.etherscan\.io|"
    r"base\.org|snowtrace\.io|ftmscan\.com|cronoscan\.com|roninchain\.com|avascan\.info|"
    r"explorer[.-]|blockscout|solanafm|helius|tonviewer|explorer\.hyperliquid)"
    r"[^\"'\s]*(?:address|token)[^\"'\s]*",
    re.I,
)
_MAX_JS_FILES = 3

# Rutas de configuración de proyectos Web3 (revelan stack, a veces claves)
_CONFIG_PATHS = [
    (
        "/hardhat.config.js", rb"module\.exports|solidity", Severity.LOW,
        "Configuración de Hardhat expuesta",
        "hardhat.config.js expuesto: revela red, compilador y a veces credenciales de despliegue.",
        "No sirvas archivos de configuración del proyecto en producción.",
    ),
    (
        "/foundry.toml", rb"\[profile|solc|rpc_endpoints", Severity.LOW,
        "Configuración de Foundry expuesta",
        "foundry.toml expuesto: revela perfiles, versión del compilador y endpoints RPC.",
        "No sirvas archivos de configuración del proyecto en producción.",
    ),
    (
        "/truffle-config.js", rb"module\.exports", Severity.LOW,
        "Configuración de Truffle expuesta",
        "truffle-config.js expuesto: revela red y configuración de despliegue.",
        "No sirvas archivos de configuración del proyecto en producción.",
    ),
    (
        "/remappings.txt", b"@", Severity.INFO,
        "Remappings de Foundry expuestos",
        "remappings.txt expuesto: revela la estructura de dependencias del proyecto Solidity.",
        "No sirvas archivos del proyecto en producción.",
    ),
]


class ContractExposureCheck(BaseCheck):
    """Detecta direcciones de contrato, explorers y configs de proyectos Web3 en el frontend."""

    name = "contract_exposure"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        text = main.text
        scripts = _JS_SRC_RE.findall(text)
        for src in scripts[: _MAX_JS_FILES]:
            res = await ctx.fetch("GET", urljoin(ctx.url, src))
            if res.ok and res.body:
                text += "\n" + res.text

        addresses = _CONTRACT_RE.findall(text)
        if addresses:
            unique = list(dict.fromkeys(addr.lower() for addr in addresses))
            ctx.add(
                self.make(
                    ctx,
                    Severity.INFO,
                    f"{len(unique)} dirección(es) de contrato detectada(s)",
                    "Se detectan direcciones de contratos en el frontend. Verifica contra el código del protocolo (fuentes verificadas en el explorer) que sean las oficiales y que el sitio no apunte a contratos maliciosos.",
                    "Publica las fuentes verificadas en el explorer y documenta las direcciones oficiales en la doc.",
                    evidence=", ".join(unique[:5]),
                )
            )

        if _EXPLORER_RE.search(text):
            ctx.add(
                self.make(
                    ctx,
                    Severity.INFO,
                    "Enlaces a block explorers detectados",
                    "La web enlaza a block explorers; útil para mapear contratos y confirmar direcciones oficiales.",
                    "Verifica que los enlaces apunten a los contratos correctos (riesgo de direcciones suplantadas).",
                    evidence="explorer links presentes en el HTML/JS",
                )
            )

        base = ctx.url.rstrip("/")
        for path, expected, severity, title, description, remediation in _CONFIG_PATHS:
            res = await ctx.fetch("GET", base + path)
            if res.ok and res.status == 200 and res.body and re.search(expected, res.body, re.I):
                ctx.add(
                    self.make(ctx, severity, title, description, remediation,
                              url=base + path, evidence=f"HTTP 200")
                )
