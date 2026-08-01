from __future__ import annotations

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_EVIL_ORIGIN = "https://evil.zhack.example"


class CORSCheck(BaseCheck):
    """Detecta CORS mal configurado (eco de cualquier Origin)."""

    name = "cors"
    requires_active = True

    async def run(self, ctx) -> None:
        for candidate in ctx.candidates:
            res = await ctx.http.fetch("GET", candidate, headers={"Origin": _EVIL_ORIGIN})
            if not res.ok or not res.headers:
                continue
            acao = res.headers.get("access-control-allow-origin", "")
            acac = res.headers.get("access-control-allow-credentials", "")
            if _EVIL_ORIGIN in acao:
                with_credentials = acac.lower() == "true"
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH if with_credentials else Severity.MEDIUM,
                        "CORS mal configurado: refleja cualquier Origin" + (" y permite credenciales" if with_credentials else ""),
                        f"El servidor refleja el origen '{_EVIL_ORIGIN}' en Access-Control-Allow-Origin"
                        + (", permitiendo credenciales." if with_credentials else ".")
                        + " Un sitio malicioso podría leer datos del sitio autenticado.",
                        "No reflejes orígenes arbitrarios: usa una whitelist de dominios de confianza y no combines ACAO reflejado con credenciales.",
                        url=candidate,
                        evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                    )
                )
            elif acao == "*" and acac.lower() == "true":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "CORS: wildcard (*) combinado con credenciales",
                        "Access-Control-Allow-Origin: * junto a Allow-Credentials: true es una configuración inválida y peligrosa.",
                        "Usa una whitelist de orígenes de confianza con Allow-Credentials: true.",
                        url=candidate,
                        evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                    )
                )
