from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_JS_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_MAX_JS_FILES = 5


def _context(text: str, m: re.Match, width: int = 120) -> str:
    start = max(0, m.start() - width)
    end = min(len(text), m.end() + width)
    return text[start:end].replace("\n", " ")


# (regex, severidad, plantilla de título, descripción, remediación)
_PATTERNS: List[Tuple[re.Pattern, Severity, str, str, str]] = [
    # ---- Claves privadas y wallets (Web3) ----
    (
        re.compile(r"(?i)(?:private[_-]?key|secret[_-]?key|wallet[_-]?key|keystore[_-]?key|pk)\s*[:=]\s*[\"']?(0x[0-9a-fA-F]{64})"),
        Severity.CRITICAL,
        "Clave privada Ethereum expuesta en el frontend",
        "Una clave privada de wallet (0x + 64 hex) está embebida en el código público. Cualquiera puede robar los fondos asociados.",
        "Rota la wallet inmediatamente, mueve los fondos y elimina la clave del código. Las claves privadas jamás deben estar en el frontend.",
    ),
    (
        re.compile(r'(?i)"crypto"\s*:\s*\{[^}]*"ciphertext"'),
        Severity.CRITICAL,
        "Archivo keystore JSON de wallet expuesto",
        "Un keystore JSON de Ethereum (UTC--...) con ciphertext cifrado está expuesto; es atacable por fuerza bruta si la contraseña es débil.",
        "Retira el keystore del servidor público y rota la wallet. Usa siempre un hardware wallet para fondos reales.",
    ),
    (
        re.compile(r"(?i)(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)\s*[:=]\s*[\"']([a-z ]{30,240})[\"']"),
        Severity.CRITICAL,
        "Frase semilla (mnemonic) expuesta",
        "Una frase de recuperación de wallet está embebida en el frontend. Da acceso total a los fondos.",
        "Rota la wallet completa y elimina la frase del código. Nunca almacenes semillas en el cliente.",
    ),
    (
        re.compile(r'[\'"]([a-z]{3,8}(?: [a-z]{3,8}){11})[\'"]'),
        Severity.HIGH,
        "Posible frase semilla BIP39 (12 palabras)",
        "Se detecta una cadena de 12 palabras en minúsculas entre comillas en el código. Podría ser una frase semilla de wallet. Requiere verificación manual.",
        "Si es una frase semilla real: mueve los fondos y elimínala del código. Verifica manualmente antes de reportar.",
    ),
    # ---- Proveedores RPC Web3 (claves API) ----
    (
        re.compile(r"infura\.io/v3/([0-9a-fA-F]{32})"),
        Severity.HIGH,
        "Project ID de Infura expuesto",
        "El Project ID de Infura está expuesto. Permite usar el servicio RPC de la cuenta de la víctima (cuotas y costes) e identificar la infraestructura.",
        "Rota el Project ID en el panel de Infura y súbelo a un proxy/backend que lo oculte.",
    ),
    (
        re.compile(r"alchemy\.com/v2/([0-9A-Za-z_-]{32,})"),
        Severity.HIGH,
        "API key de Alchemy expuesta",
        "La API key de Alchemy está expuesta en el frontend; puede usarse el RPC sin autorización y consumir la cuota del propietario.",
        "Rota la key en el dashboard de Alchemy y proxifica las llamadas RPC desde el backend.",
    ),
    (
        re.compile(r"(?:quicknode\.com|@quicknode)/[0-9A-Za-z_-]{20,}"),
        Severity.HIGH,
        "Endpoint de QuickNode con clave expuesta",
        "Una URL de QuickNode con credenciales incorporadas está expuesta, dando acceso al RPC de la cuenta.",
        "Rota el endpoint en QuickNode y sirve el RPC solo desde el backend.",
    ),
    (
        re.compile(r"(?i)chainstack\.com/"),
        Severity.HIGH,
        "Endpoint de Chainstack expuesto",
        "Un endpoint RPC de Chainstack aparece en el código; puede exponer acceso al nodo de la cuenta.",
        "Rota las credenciales de Chainstack y oculta el endpoint detrás del backend.",
    ),
    (
        re.compile(r"(?i)(?:helius|drpc|blastapi|tatum|moralis|web3\.storage)[^\"' ]*(?:api[_-]?key|token|rpc)[^\"' ]*"),
        Severity.HIGH,
        "Credencial de proveedor Web3 expuesta",
        "Se detecta una credencial/endpoint de un proveedor de infraestructura blockchain (Helius, dRPC, Tatum, Moralis, Web3.Storage, etc.) en el código público.",
        "Rota la credencial en el panel del proveedor y muévela al backend.",
    ),
    (
        re.compile(r"projectId\s*[:=]\s*[\"']([0-9a-fA-F]{32})[\"']"),
        Severity.MEDIUM,
        "Project ID de WalletConnect expuesto",
        "El projectId de WalletConnect está embebido; permite abusar del relay y potencialmente identificar la app de forma no autorizada.",
        "Mantén el projectId fuera del cliente si es posible y revisa los límites del proyecto en WalletConnect Cloud.",
    ),
    # ---- Secretos generales ----
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "Access Key de AWS expuesta",
        "Una Access Key de AWS está embebida en el código público. Da acceso a los recursos de la cuenta AWS.",
        "Rota la clave en IAM, elimínala del repositorio/sitio y audita el uso de la cuenta.",
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.HIGH,
        "API key de Google expuesta",
        "Una API key de Google (maps, cloud, firebase) está expuesta; puede abusarse de cuotas y de servicios mal configurados.",
        "Rota la key y restringe su uso por referrer/IP y por API concreta en Google Cloud Console.",
    ),
    (
        re.compile(r"\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
        Severity.CRITICAL,
        "Token de GitHub expuesto",
        "Un token personal de GitHub está expuesto; da acceso a repositorios privados con los permisos del token.",
        "Revoca el token en GitHub (Settings → Developer settings) y elimínalo del código.",
    ),
    (
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        "Token de Slack expuesto",
        "Un token de Slack (xox*) está expuesto y permite leer/enviar mensajes en el workspace.",
        "Revoca el token en api.slack.com y elimínalo del código.",
    ),
    (
        re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"),
        Severity.CRITICAL,
        "Clave secreta de Stripe expuesta",
        "Una clave secreta de Stripe (sk_live_/rk_live_) está expuesta; permite cobrar/emitir reembolsos y acceder a datos de pagos.",
        "Rota la clave en el dashboard de Stripe y revísala como incidente de seguridad.",
    ),
    (
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,}"),
        Severity.CRITICAL,
        "Webhook de Discord expuesto",
        "Un webhook de Discord está expuesto; cualquiera puede publicar mensajes en el canal asociado (spam, phishing).",
        "Elimina el webhook en Discord y crea uno nuevo. Nunca lo incrustes en el frontend.",
    ),
    (
        re.compile(r"\b[0-9]{8,10}:[0-9A-Za-z_-]{35}\b"),
        Severity.HIGH,
        "Token de bot de Telegram expuesto",
        "Un bot token de Telegram está expuesto; permite controlar el bot, leer mensajes y enviar como él.",
        "Revoca el token con @BotFather y elimínalo del código.",
    ),
    (
        re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"),
        Severity.CRITICAL,
        "API key de SendGrid expuesta",
        "Una API key de SendGrid está expuesta; permite enviar correos como la organización y abusar de la reputación del dominio.",
        "Rota la key en SendGrid y elimínala del código.",
    ),
    (
        re.compile(r"\bkey-[0-9a-fA-F]{32}\b"),
        Severity.HIGH,
        "API key de Mailgun expuesta",
        "Una API key de Mailgun (key-…) está expuesta; permite enviar correos en nombre del dominio.",
        "Rota la key en el panel de Mailgun y elimínala del código.",
    ),
    (
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        Severity.HIGH,
        "Credencial de Twilio expuesta",
        "Una credencial de Twilio (SK-…) está expuesta; permite enviar SMS y llamadas en nombre de la cuenta.",
        "Rota la credencial en Twilio y elimínala del código.",
    ),
    (
        re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b"),
        Severity.CRITICAL,
        "Client secret de Google OAuth expuesto",
        "Un client secret de Google OAuth está expuesto; permite suplantar la identidad de la app en flujos OAuth.",
        "Rota el client secret en Google Cloud Console y elimínalo del cliente.",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Clave privada (PEM) expuesta",
        "Una clave privada RSA/EC en formato PEM está embebida en el código. Compromete SSH, JWT o TLS según su uso.",
        "Rota la clave inmediatamente y elimínala del código público.",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
        Severity.LOW,
        "Posible JWT expuesto en el frontend",
        "Se detecta un JWT en el código. Los tokens de sesión no deberían estar incrustados en el HTML/JS estático.",
        "Revisa si es un token de sesión real; si lo es, rótalo y muévelo a una cookie HttpOnly.",
    ),
    (
        re.compile(r"(?i)firebaseconfig\s*=\s*\{[^}]{100,600}?\"apiKey\"\s*:\s*\"(AIza[0-9A-Za-z_-]{35})\""),
        Severity.HIGH,
        "Configuración de Firebase expuesta",
        "firebaseConfig con API key, authDomain y databaseURL está expuesta. Si las reglas de Firestore/Storage son débiles, permite lectura/escritura no autorizada.",
        "Revisa las reglas de Firestore/Storage (deben ser deny por defecto) y restringe la API key por dominio.",
    ),
    (
        re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*[\"']([^\"']{12,64})[\"']"),
        Severity.MEDIUM,
        "Posible credencial genérica embebida",
        "Se detecta una asignación de apiKey/secret/token en el código público. Puede ser una credencial real o una falsa para pruebas.",
        "Verifica manualmente si la credencial es válida; si lo es, rótala y muévela al backend.",
    ),
]


class SecretScanCheck(BaseCheck):
    """Busca secretos y claves expuestas en HTML y JavaScript del frontend."""

    name = "secret_scan"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        await self._scan_text(ctx, main.text, "HTML principal")

        scripts = _JS_SRC_RE.findall(main.text)
        seen: set = set()
        fetched = 0
        for src in scripts:
            url = urljoin(ctx.url, src)
            if url in seen or fetched >= _MAX_JS_FILES:
                continue
            seen.add(url)
            fetched += 1
            res = await ctx.fetch("GET", url)
            if res.ok and res.body:
                await self._scan_text(ctx, res.text, url)

    async def _scan_text(self, ctx, text: str, source: str) -> None:
        for regex, severity, title, description, remediation in _PATTERNS:
            for m in regex.finditer(text):
                ctx.add(
                    self.make(
                        ctx,
                        severity,
                        title,
                        description,
                        remediation,
                        evidence=f"[{source}] ...{_context(text, m)}...",
                    )
                )
                break
