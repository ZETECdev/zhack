from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)(?=</form\s*>|$)", re.I | re.S)
_ACTION_RE = re.compile(
    r"""\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I | re.S
)
_METHOD_RE = re.compile(
    r"""\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I
)
_PASSWORD_RE = re.compile(
    r"""<input\b[^>]*(?:\btype\s*=\s*(?:"password"|'password'|password\b)|
    \bname\s*=\s*(?:"(?:password|passwd|pass|pwd)"|'(?:password|passwd|pass|pwd)'|(?:password|passwd|pass|pwd)\b))""",
    re.I | re.X,
)


class FormSecurityCheck(BaseCheck):
    """Comprueba que formularios con credenciales no viajen por HTTP."""

    name = "form_security"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        page_scheme = urlparse(ctx.url).scheme.lower()
        for match in _FORM_RE.finditer(main.text):
            tag_end = main.text.find(">", match.start(), match.end())
            if tag_end == -1:
                continue
            form_tag = main.text[match.start() : tag_end + 1]
            action_match = _ACTION_RE.search(form_tag)
            action = next((value for value in action_match.groups() if value is not None), "").strip() if action_match else ""
            action_url = urljoin(ctx.url, action or ctx.url)
            action_scheme = urlparse(action_url).scheme.lower()
            method_match = _METHOD_RE.search(form_tag)
            method = next((value for value in method_match.groups() if value is not None), "GET").upper() if method_match else "GET"
            has_password = bool(_PASSWORD_RE.search(match.group()))

            if has_password and (page_scheme == "http" or action_scheme == "http"):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Formulario de contraseña enviado por HTTP",
                        "El formulario contiene un campo de contraseña y la página o su destino no usa HTTPS. Las credenciales pueden interceptarse en tránsito.",
                        "Sirve la página y el endpoint del formulario exclusivamente por HTTPS y fuerza la redirección desde HTTP.",
                        url=action_url,
                        evidence=f"method={method}; action={action_url}",
                    )
                )
            elif method not in ("GET", "") and page_scheme == "https" and action_scheme == "http":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "Formulario HTTPS enviado a un endpoint HTTP",
                        "Un formulario de la página segura envía datos a un endpoint sin cifrado.",
                        "Cambia el destino del formulario a HTTPS y bloquea endpoints HTTP en producción.",
                        url=action_url,
                        evidence=f"method={method}; action={action_url}",
                    )
                )
