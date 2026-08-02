from __future__ import annotations

import re

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

# Formularios que piden semillas/claves: o un fallo grave de la propia web,
# o un clon de phishing que cosecha wallets.
_ATTRS = r"(?:name|id|placeholder|label|title)\s*=\s*[\"'][^\"']*"
_KEYWORDS = (
    r"(?:seed\s?phrase|seedphrase|mnemonic|secret\s?recovery|recovery\s?phrase|"
    r"private\s?key|privatekey|keystore\s?password)"
)
_HARVEST_INPUT_RE = re.compile(
    r"<(?:input|textarea)\b[^>]{0,300}?" + _ATTRS + _KEYWORDS + r"[^\"']*[\"']",
    re.I | re.S,
)
_HARVEST_TEXT_RE = re.compile(
    r"(?:enter|paste|type|write)[^<>]{0,60}?(?:your\s+(?:12|15|18|21|24|25)\s*-?\s*"
    r"word\s+(?:seed\s+)?phrase|your\s+seed\s+phrase|your\s+(?:private\s+)?key|"
    r"your\s+mnemonic)",
    re.I | re.S,
)


class SeedHarvestCheck(BaseCheck):
    """Detecta webs que piden la frase semilla o clave privada de la wallet."""

    name = "seed_harvest"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        text = main.text
        match = _HARVEST_INPUT_RE.search(text) or _HARVEST_TEXT_RE.search(text)
        if not match:
            return

        ctx.add(
            self.make(
                ctx,
                Severity.CRITICAL,
                "La web pide la frase semilla o clave privada del usuario",
                "El formulario solicita la frase semilla, clave privada o contraseña del keystore. Ninguna aplicación legítima debe pedir nunca estos datos: quien los ingrese entrega el control total de su wallet. Puede ser un clon de phishing de la marca o un fallo crítico de diseño.",
                "Nunca solicites semillas ni claves en la web; si la página es un clon, bloquea el dominio, avisa a los usuarios y denúncialo ante el registrador y los buscadores.",
                evidence=match.group(0)[:200],
            )
        )
