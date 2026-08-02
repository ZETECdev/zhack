from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.checks.dex_common import collect_frontend_sources
from zhack.core.models import Severity

_WEB3_HINT_RE = re.compile(
    r"(?:window\.ethereum|eth_requestAccounts|personal_sign|eth_sign|signTypedData|"
    r"\bweb3\b|\bethers\b|\bviem\b|\bwagmi\b|walletconnect)",
    re.I,
)
_ETH_SIGN_RE = re.compile(r"\beth_sign\b")
_PERSONAL_SIGN_RE = re.compile(r"\bpersonal_sign\b")
_SIWE_RE = re.compile(r"(?:Sign-In with Ethereum|EIP-4361|\bsiwe\b)", re.I)
_TYPED_PERMIT_RE = re.compile(
    r"(?:eth_signTypedData|signTypedData)[\s\S]{0,900}?\bpermit\b|"
    r"\bpermit\b[\s\S]{0,900}?(?:eth_signTypedData|signTypedData)",
    re.I,
)
_STORAGE_RE = (
    r"(?:localStorage|sessionStorage)\s*"
    r"(?:\.\s*(?:setItem|getItem)\s*\(\s*[\"']|\[\s*[\"'])"
)
_STORAGE_SECRET_RE = re.compile(
    _STORAGE_RE + r"[^\"']*(?:private[_-]?key|mnemonic|seed|secret|password|keystore)[^\"']*",
    re.I,
)
_STORAGE_TOKEN_RE = re.compile(
    _STORAGE_RE + r"[^\"']*(?:auth[_-]?token|access[_-]?token|jwt|session[_-]?token|id[_-]?token)[^\"']*",
    re.I,
)
_CLEARTEXT_WS_RE = re.compile(
    r"\bws://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?:[:/]|$))[^\s\"'<>]{3,120}",
    re.I,
)
_CLIPBOARD_RE = re.compile(r"navigator\s*\.\s*clipboard\s*\.\s*writeText")
_CLEARTEXT_RPC_RE = re.compile(
    r"(?<!s)http://[^\s\"'<>]{0,40}?"
    r"(?:rpc|infura\.io|alchemy\.com|quicknode|chainstack|helius|drpc|blastapi|tatum)"
    r"[^\s\"'<>]{0,80}",
    re.I,
)
_AUTO_CONNECT_RE = re.compile(
    r"(?:window\.addEventListener\s*\(\s*[\"']load[\"']|"
    r"window\.(?:onload|onready)|DOMContentLoaded)[\s\S]{0,800}?eth_requestAccounts",
    re.I,
)


class WalletSecurityCheck(BaseCheck):
    """Higiene de firmas, almacenamiento y transporte en frontends Web3/wallet."""

    name = "wallet_security"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        sources = await collect_frontend_sources(ctx, main.text)
        text = "\n".join(source for _, source in sources)
        if not _WEB3_HINT_RE.search(text):
            return

        reported: set[str] = set()

        self._once(
            ctx,
            reported,
            "eth_sign",
            _ETH_SIGN_RE,
            Severity.HIGH,
            "Firma ciega con eth_sign habilitada en el frontend",
            "eth_sign pide a la wallet firmar un hash opaco que no puede mostrarse de forma legible. Es el vector clásico de los drainers: la víctima firma sin poder entender qué autoriza (puede ser el hash de una transferencia o un permit).",
            "Elimina eth_sign por completo. Usa personal_sign o EIP-712 (eth_signTypedData) con dominio verificable y mensaje legible para el usuario.",
            text,
        )

        if (
            "personal_sign_sin_siwe" not in reported
            and _PERSONAL_SIGN_RE.search(text)
            and not _SIWE_RE.search(text)
        ):
            reported.add("personal_sign_sin_siwe")
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    "personal_sign sin vinculación de dominio (sin SIWE/EIP-4361)",
                    "El frontend solicita personal_sign sin el formato Sign-In with Ethereum (EIP-4361). Una firma sin dominio, URI, nonce ni chainId puede ser reutilizada por un sitio malicioso para suplantar al usuario o confundirla con otra autorización.",
                    "Adopta SIWE (EIP-4361): incluye dominio, URI, chainId, nonce y expiración en el mensaje firmado y valídalos en el backend.",
                    evidence=self._evidence(text, _PERSONAL_SIGN_RE),
                )
            )

        self._once(
            ctx,
            reported,
            "typed_data_permit",
            _TYPED_PERMIT_RE,
            Severity.HIGH,
            "Permisos de tokens firmados con typed data (Permit/Permit2) en el frontend",
            "El frontend construye firmas EIP-712 de tipo Permit. Si la interfaz no muestra claramente spender, cantidad y deadline, un phishing visualmente idéntico puede conseguir una aprobación válida para vaciar los tokens del usuario.",
            "Muestra spender, importe y expiración antes de firmar, usa deadlines cortos, valida el dominio EIP-712 (nombre, versión, chainId, verifyingContract) y considera simulación previa a la firma.",
            text,
        )

        self._once(
            ctx,
            reported,
            "storage_secret",
            _STORAGE_SECRET_RE,
            Severity.HIGH,
            "Secretos de wallet guardados en Web Storage",
            "El código escribe o lee claves privadas, semillas o secretos en localStorage/sessionStorage. Cualquier XSS, extensión maliciosa o dependencia comprometida puede leerlos: Web Storage es accesible desde todo el JavaScript de la página.",
            "Nunca persistas claves ni semillas en el navegador. Usa wallets externas (EIP-1193), y si hay sesiones, cookies HttpOnly + Secure + SameSite.",
            text,
        )

        self._once(
            ctx,
            reported,
            "storage_token",
            _STORAGE_TOKEN_RE,
            Severity.MEDIUM,
            "Tokens de sesión en Web Storage accesibles a JavaScript",
            "Los tokens de autenticación guardados en localStorage/sessionStorage son robables con cualquier XSS. En un DEX, robar la sesión puede permitir operar como la víctima en los servicios off-chain (órdenes, API keys, retiros).",
            "Migra los tokens de sesión a cookies HttpOnly + Secure + SameSite y reduce el tiempo de vida de los tokens.",
            text,
        )

        self._once(
            ctx,
            reported,
            "cleartext_ws",
            _CLEARTEXT_WS_RE,
            Severity.MEDIUM,
            "WebSocket en claro (ws://) en un frontend Web3",
            "Un WebSocket sin cifrar permite a un atacante en la red leer y modificar el tráfico: precios, orderbooks o incluso payloads de transacciones mostradas al usuario antes de firmar.",
            "Usa siempre wss:// (TLS) y valida en cliente que los datos críticos (precios, direcciones) coinciden con una fuente firmada o on-chain.",
            text,
        )

        self._once(
            ctx,
            reported,
            "clipboard",
            _CLIPBOARD_RE,
            Severity.LOW,
            "Escritura en el portapapeles en contexto Web3",
            "El frontend escribe en el portapapeles. Si existe cualquier XSS, un atacante puede sustituir direcciones copiadas por direcciones parecidas del atacante (address poisoning).",
            "Muestra siempre la dirección completa para confirmación, ofrece copia con verificación visual y considera checksums ENS/EA-691 en la UI.",
            text,
        )

        self._once(
            ctx,
            reported,
            "cleartext_rpc",
            _CLEARTEXT_RPC_RE,
            Severity.MEDIUM,
            "Endpoint RPC en claro (http://) en el frontend",
            "El frontend apunta a un RPC sin cifrar: la comunicación con la cadena puede ser interceptada y alterada (datos falsos, respuestas manipuladas) por un atacante en la red.",
            "Usa exclusivamente HTTPS para los endpoints RPC y proxifica el tráfico desde el backend.",
            text,
        )

        self._once(
            ctx,
            reported,
            "auto_connect",
            _AUTO_CONNECT_RE,
            Severity.INFO,
            "La wallet se conecta automáticamente al cargar la página",
            "El frontend pide eth_requestAccounts al cargar, sin interacción del usuario. Es una señal habitual en páginas de phishing/drainers que quieren pedir aprobaciones en cuanto el usuario entra.",
            "Conecta la wallet solo ante una acción explícita del usuario y pide aprobaciones por operación, nunca al cargar.",
            text,
        )

    def _once(
        self,
        ctx,
        reported: set[str],
        key: str,
        pattern: re.Pattern,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
        text: str,
    ) -> None:
        match = pattern.search(text)
        if not match or key in reported:
            return
        reported.add(key)
        ctx.add(
            self.make(
                ctx,
                severity,
                title,
                description,
                remediation,
                evidence=match.group(0)[:200],
            )
        )

    @staticmethod
    def _evidence(text: str, pattern: re.Pattern) -> str:
        match = pattern.search(text)
        return match.group(0)[:200] if match else "señales Web3 relacionadas"
