from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.I | re.S)
_SCRIPT_SRC_RE = re.compile(r'<script\b[^>]+\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_IMPLICIT_RE = re.compile(
    r"(?:response_type\s*[=:]\s*[\"']?token\b|"
    r"(?:oauth|authorize|authorization)[^\n]{0,180}\bresponse_type=token\b)",
    re.I,
)
_HASH_TOKEN_RE = re.compile(
    r"(?:location\s*\.\s*(?:hash|href)|window\s*\.\s*location)[^\n;]{0,180}"
    r"(?:access_token|id_token)|(?:access_token|id_token)[^\n;]{0,180}location\s*\.\s*hash",
    re.I,
)


def _decode_header(token: str) -> dict:
    encoded = token.split(".", 1)[0]
    encoded += "=" * (-len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(encoded.encode("ascii"))
    value = json.loads(decoded.decode("utf-8"))
    return value if isinstance(value, dict) else {}


class JwtOAuthCheck(BaseCheck):
    """Detecta señales estáticas de JWT/OAuth frágiles sin validar ni usar tokens."""

    name = "jwt_oauth"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        sources: list[tuple[str, str]] = [("HTML principal", main.text)]
        for match in _SCRIPT_RE.finditer(main.text):
            if match.group(1).strip():
                sources.append(("script inline", match.group(1)))

        seen_scripts: set[str] = set()
        for raw_url in _SCRIPT_SRC_RE.findall(main.text)[:4]:
            script_url = urljoin(ctx.url, raw_url)
            if script_url in seen_scripts:
                continue
            seen_scripts.add(script_url)
            res = await ctx.fetch("GET", script_url)
            if res.ok and res.body:
                sources.append((script_url, res.text))

        reported: set[str] = set()
        for source_name, text in sources:
            for token_match in _JWT_RE.finditer(text):
                try:
                    header = _decode_header(token_match.group(0))
                except (ValueError, TypeError, UnicodeError):
                    continue
                if str(header.get("alg", "")).lower() == "none" and "alg_none" not in reported:
                    reported.add("alg_none")
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.HIGH,
                            "JWT acepta el algoritmo none",
                            "Se detecta un JWT cuyo header declara alg=none. Si el backend lo acepta, un atacante puede fabricar tokens sin una firma criptográfica válida.",
                            "Rechaza siempre alg=none en el backend, permite únicamente algoritmos explícitos y valida issuer, audience, expiración y firma.",
                            evidence=f"fuente={source_name}; JWT con alg=none",
                            confidence="alta",
                        )
                    )
                    break

            if _IMPLICIT_RE.search(text) and "oauth_implicit" not in reported:
                reported.add("oauth_implicit")
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "OAuth usa el flujo implícito con access_token en la URL",
                        "El flujo OAuth implícito expone tokens en el historial, fragmentos, herramientas de analítica y posibles referers. Requiere revisión del proveedor y del backend.",
                        "Migra a Authorization Code con PKCE, evita tokens en URLs y revoca cualquier token que haya podido quedar registrado.",
                        url=source_name if source_name.startswith(("http://", "https://")) else ctx.url,
                        evidence=_IMPLICIT_RE.search(text).group(0)[:240],
                        confidence="media",
                        manual_review=True,
                    )
                )

            if _HASH_TOKEN_RE.search(text) and "hash_token" not in reported:
                reported.add("hash_token")
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Token OAuth leído desde location.hash",
                        "El frontend procesa access_token o id_token desde la URL. Un XSS, una extensión o una fuga de historial puede capturar el token antes de que se elimine.",
                        "Usa Authorization Code + PKCE, procesa códigos de un solo uso y limpia la URL inmediatamente sin almacenar tokens en el navegador.",
                        url=source_name if source_name.startswith(("http://", "https://")) else ctx.url,
                        evidence=_HASH_TOKEN_RE.search(text).group(0)[:240],
                        confidence="media",
                        manual_review=True,
                    )
                )
