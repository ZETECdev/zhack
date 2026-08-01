from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.crawler import extract_forms
from zhack.core.models import Severity

_CSRF_TOKEN_NAMES = re.compile(
    r"csrf|xsrf|_token|nonce|authenticity_token|__requestverificationtoken", re.I
)


class CSRFCheck(BaseCheck):
    """Detecta formularios sin protección CSRF."""

    name = "csrf"
    mass = False

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        forms = extract_forms(main.text)
        for action, method, inputs in forms:
            if method.upper() == "GET":
                continue

            has_csrf = any(_CSRF_TOKEN_NAMES.search(inp) for inp in inputs)
            if not has_csrf:
                form_id = action or "(sin acción)"
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        f"Formulario POST sin token CSRF ({form_id})",
                        "Un formulario que modifica datos (POST) no incluye token CSRF; un atacante puede forzar acciones en nombre del usuario autenticado.",
                        "Añade un token CSRF único por sesión a cada formulario y verifícalo en el servidor. Usa SameSite=Lax como capa adicional.",
                        evidence=f"action={action or '/'}, inputs={inputs[:5]}",
                    )
                )
