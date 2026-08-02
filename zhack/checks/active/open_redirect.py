from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_url",
    "returnto",
    "dest",
    "destination",
    "target",
    "rurl",
    "out",
    "view",
    "login_url",
    "go",
    "u",
    "continue",
]

_EVIL_HOST = "openredirect.zhack.local"
_REDIRECT_STATUS = (301, 302, 303, 307, 308)


def _is_open_redirect(location: str) -> bool:
    """El marcador debe estar en el destino (host o path), no solo reflejado
    en la query de una redirección canónica que preserva parámetros."""
    if not location:
        return False
    parsed = urlparse(location)
    if _EVIL_HOST in parsed.netloc:
        return True
    return _EVIL_HOST in parsed.path


class OpenRedirectCheck(BaseCheck):
    """Detecta redirecciones abiertas (usadas para phishing)."""

    name = "open_redirect"
    requires_active = True

    async def run(self, ctx) -> None:
        reported: set[str] = set()
        for candidate in ctx.candidates:
            parsed = urlparse(candidate)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            tested = False

            if params:
                for key, value in params:
                    if key.lower() in _REDIRECT_PARAMS:
                        tested = True
                        await self._probe(ctx, parsed, params, key, reported)
            else:
                for key in _REDIRECT_PARAMS[:5]:
                    if await self._probe_new(ctx, parsed, key, reported):
                        break

    async def _probe(self, ctx, parsed, params, key, reported) -> None:
        if key.lower() in reported:
            return
        test = f"https://{_EVIL_HOST}/{key}"
        query = urlencode([(k, test if k == key else v) for k, v in params], doseq=True)
        probe_url = urlunparse(parsed._replace(query=query))
        res = await ctx.http.fetch("GET", probe_url, allow_redirects=False)
        if res.ok and res.status in _REDIRECT_STATUS:
            location = res.headers.get("location", "")
            if _is_open_redirect(location):
                reported.add(key.lower())
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Redirección abierta en el parámetro '{key}'",
                        "El parámetro de redirección acepta dominios externos sin validar; se usa para phishing (links 'seguros' que llevan a webs maliciosas).",
                        "Valida que la redirección solo apunte a dominios internos (whitelist).",
                        url=probe_url,
                        evidence=f"Location: {location}",
                    )
                )

    async def _probe_new(self, ctx, parsed, key, reported) -> bool:
        if key.lower() in reported:
            return False
        test = f"https://{_EVIL_HOST}/test"
        probe_url = urlunparse(parsed._replace(query=urlencode({key: test})))
        res = await ctx.http.fetch("GET", probe_url, allow_redirects=False)
        if res.ok and res.status in _REDIRECT_STATUS:
            location = res.headers.get("location", "")
            if _is_open_redirect(location):
                reported.add(key.lower())
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Redirección abierta vía parámetro '{key}'",
                        "El sitio redirige a dominios externos usando el parámetro sin validar; vector de phishing.",
                        "Valida que la redirección solo apunte a dominios internos (whitelist).",
                        url=probe_url,
                        evidence=f"Location: {location}",
                    )
                )
                return True
        return False
