from __future__ import annotations

import re
from typing import List, Optional, Tuple

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]+\bsrc\s*=\s*([\"'])(.*?)\1", re.I | re.S)
_CDN_HOST_RE = re.compile(
    r"(?:unpkg\.com|cdn\.jsdelivr\.net|esm\.sh|esm\.run|cdnjs\.cloudflare\.com|"
    r"cdn\.skypack\.dev|cdn\.statically\.io|rawgit(?:her)?\.com)",
    re.I,
)
_VERSIONED_LIB_RE = re.compile(
    r"(?P<lib>ethers|web3|web3modal|viem|wagmi|rainbowkit|"
    r"@walletconnect/[a-z0-9-]+|@solana/web3\.js)"
    r"(?:@(?P<v_at>\d+(?:\.\d+){0,2})|/(?P<v_path>\d+(?:\.\d+){0,2})/)",
    re.I,
)
_LIBS = ("ethers", "web3", "web3modal", "viem", "wagmi", "rainbowkit", "@solana/web3.js")
_SOLANA_COMPROMISED = ("1.95.8", "1.95.9")


def _major_minor(version: str) -> Tuple[int, int]:
    parts = (version.split(".") + ["0", "0"])[:2]
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return 0, 0


class Web3SupplyChainCheck(BaseCheck):
    """Detecta librerías Web3 obsoletas o de versión mutable cargadas desde CDNs."""

    name = "web3_supply_chain"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        reported: set[Tuple[str, str]] = set()
        for _, src in _SCRIPT_SRC_RE.findall(main.text):
            if not _CDN_HOST_RE.search(src):
                continue
            for match in _VERSIONED_LIB_RE.finditer(src):
                lib = match.group("lib").lower()
                version = match.group("v_at") or match.group("v_path") or ""
                if (lib, version) in reported:
                    continue
                finding = self._assess(lib, version)
                if not finding:
                    continue
                reported.add((lib, version))
                severity, title, description, remediation = finding
                ctx.add(
                    self.make(
                        ctx,
                        severity,
                        title,
                        description,
                        remediation,
                        url=src,
                        evidence=f"{lib}@{version} cargado desde CDN",
                    )
                )
            mutable_lib = self._mutable_lib(src)
            if mutable_lib and (mutable_lib, "mutable") not in reported:
                reported.add((mutable_lib, "mutable"))
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"{mutable_lib} cargado sin versión fijada desde un CDN",
                        "El frontend carga la librería con @latest o sin versión: cualquier publicación nueva (incluida una comprometida) se servirá automáticamente a todos los usuarios del DEX.",
                        "Fija una versión exacta auditada, añade SRI (integrity) y considera self-hosting o un lockfile de CDN.",
                        url=src,
                        evidence=f"URL mutable: {src}",
                    )
                )

    def _assess(
        self, lib: str, version: str
    ) -> Optional[Tuple[Severity, str, str, str]]:
        major, minor = _major_minor(version)
        if lib == "ethers":
            if major <= 4:
                return (
                    Severity.HIGH,
                    f"ethers.js {version} (rama EOL) cargado en el frontend",
                    "ethers v4 está fuera de soporte y acumula vulnerabilidades y bugs de firma/serialización corregidos solo en ramas mantenidas. En un sitio que maneja fondos, una librería de firma obsoleta es un riesgo directo.",
                    "Actualiza a una rama mantenida (ethers v6 o v5 parcheado), fija la versión y añade SRI.",
                )
            if major == 5 and minor < 7:
                return (
                    Severity.MEDIUM,
                    f"ethers.js {version} desactualizado",
                    "Versión antigua de ethers 5.x sin los parches posteriores. Revisa el changelog de seguridad y actualiza.",
                    "Actualiza a la última 5.7.x o migra a v6, fija la versión y añade SRI.",
                )
        elif lib == "web3" and major == 0:
            return (
                Severity.MEDIUM,
                f"web3.js {version} (rama 0.x) cargado en el frontend",
                "web3 0.x es una rama muy antigua y sin mantenimiento, con dependencias vulnerables conocidas.",
                "Migra a web3 4.x (o a viem/ethers), fija la versión y añade SRI.",
            )
        elif lib == "web3modal" and major <= 1:
            return (
                Severity.MEDIUM,
                f"Web3Modal {version} (WalletConnect v1) detectado",
                "Web3Modal v1 depende de WalletConnect v1, cuyo relay fue apagado en 2023. Los clones de bridge maliciosos se usan para phishing de wallets.",
                "Migra a Web3Modal/AppKit v3+ con WalletConnect v2 y verifica el dominio del bridge.",
            )
        elif lib.startswith("@walletconnect/") and major <= 1:
            return (
                Severity.MEDIUM,
                f"WalletConnect v1 ({lib}@{version}) detectado",
                "WalletConnect v1 fue deprecado y su relay oficial apagado en 2023. Mantenerlo empuja a los usuarios hacia bridges no oficiales usados en campañas de phishing.",
                "Migra a WalletConnect v2 (Sign/Auth API) y elimina dependencias v1.",
            )
        elif lib == "@solana/web3.js" and version in _SOLANA_COMPROMISED:
            return (
                Severity.HIGH,
                f"@solana/web3.js {version}: versión comprometida publicada en npm",
                "Las versiones 1.95.8/1.95.9 del paquete oficial @solana/web3.js se publicaron con código malicioso que exfiltraba claves privadas a través de proveedores externos. Cualquier dapp que las cargue expone las wallets de sus usuarios.",
                "Actualiza a una versión parcheada (>= 1.95.10 o la última estable), verifica el checksum del paquete y añade SRI; revisa los logs de npm si llegaste a instalarla.",
            )
        return None

    @staticmethod
    def _mutable_lib(src: str) -> Optional[str]:
        lowered = src.lower()
        for lib in _LIBS:
            if f"{lib}@latest" in lowered:
                return lib
            if f"unpkg.com/{lib}/" in lowered and f"{lib}@" not in lowered:
                return lib
            if f"jsdelivr.net/npm/{lib}/" in lowered and f"{lib}@" not in lowered:
                return lib
        return None
