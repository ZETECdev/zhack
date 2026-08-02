from __future__ import annotations

from http.cookies import SimpleCookie
import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_SESSION_COOKIE_RE = re.compile(
    r"(?:^|[-_])(session|sess|auth|token|jwt|sid|login|user)(?:$|[-_])", re.I
)


class CookieFlagsCheck(BaseCheck):
    """Revisa los flags de seguridad de las cookies de sesión."""

    name = "cookies"
    mass = True

    async def run(self, ctx) -> None:
        res = await ctx.get_main()
        if not res.ok or res.status is None or not res.headers:
            return

        raw_cookies = res.headers.getall("Set-Cookie", [])
        seen: dict = {}
        for raw in raw_cookies:
            try:
                cookie = SimpleCookie()
                cookie.load(raw)
            except Exception:
                continue
            for name, morsel in cookie.items():
                info = seen.setdefault(
                    name,
                    {
                        "secure": True,
                        "httponly": True,
                        "samesite": "",
                        "samesite_missing": False,
                        "raw": raw,
                    },
                )
                if not morsel["secure"]:
                    info["secure"] = False
                if not morsel["httponly"]:
                    info["httponly"] = False
                if not morsel["samesite"]:
                    info["samesite_missing"] = True
                elif morsel["samesite"].lower() == "none":
                    info["samesite"] = "none"

        over_http = ctx.url.startswith("http://")
        for name, info in seen.items():
            if not info["secure"]:
                if over_http:
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.HIGH,
                            f"Cookie '{name}' sin flag Secure en conexión HTTP",
                            "La cookie se transmite sin cifrar; puede ser interceptada en la red.",
                            "Marca la cookie como Secure y fuerza HTTPS en todo el sitio.",
                            evidence=info["raw"],
                        )
                    )
                else:
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.MEDIUM,
                            f"Cookie '{name}' sin flag Secure",
                            "La cookie podría enviarse por HTTP si la conexión se degrada.",
                            "Añade el atributo Secure a la cookie.",
                            evidence=info["raw"],
                        )
                    )
            if not info["httponly"]:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Cookie '{name}' sin flag HttpOnly",
                        "La cookie puede leerse desde JavaScript; un XSS permite robarla directamente.",
                        "Añade el atributo HttpOnly a las cookies de sesión.",
                        evidence=info["raw"],
                    )
                )
            if info["samesite"] == "none":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Cookie '{name}' con SameSite=None",
                        "La cookie se envía en peticiones cross-site; aumenta el riesgo de CSRF.",
                        "Usa SameSite=Lax o Strict salvo que SameSite=None sea imprescindible (entonces exige Secure).",
                        evidence=info["raw"],
                    )
                )
            if info["samesite_missing"] and _SESSION_COOKIE_RE.search(name):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Cookie de sesión '{name}' sin SameSite explícito",
                        "La cookie parece pertenecer a una sesión pero no declara SameSite. El comportamiento por defecto del navegador no sustituye una política explícita en flujos sensibles.",
                        "Declara SameSite=Lax o Strict en cookies de sesión; usa None solo cuando sea imprescindible y siempre junto con Secure.",
                        evidence=info["raw"],
                    )
                )
            if info["samesite"] == "none" and not info["secure"]:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        f"Cookie '{name}' usa SameSite=None sin Secure",
                        "Los navegadores rechazan o tratan de forma insegura una cookie SameSite=None que no esté protegida con Secure.",
                        "Añade Secure o cambia a SameSite=Lax/Strict si no necesitas contexto cross-site.",
                        evidence=info["raw"],
                    )
                )
