from __future__ import annotations

import re
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity


_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.I | re.S)
_SCRIPT_SRC_RE = re.compile(r"\bsrc\s*=\s*([\"'])(.*?)\1", re.I)
_SOURCE_RE = re.compile(
    r"(?:location\.(?:hash|search|href)|document\.URL|document\.referrer|window\.name)",
    re.I,
)
_SINKS = (
    ("innerHTML", re.compile(r"\.innerHTML\s*=", re.I)),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(", re.I)),
    ("document.write", re.compile(r"document\.write\s*\(", re.I)),
    ("eval", re.compile(r"\beval\s*\(", re.I)),
    ("new Function", re.compile(r"\bnew\s+Function\s*\(", re.I)),
)
_MAX_JS_FILES = 5


class DOMXSSCheck(BaseCheck):
    """Busca patrones de fuente controlable y sink peligroso en JavaScript."""

    name = "dom_xss"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        sources: list[tuple[str, str]] = []
        for script in _SCRIPT_RE.finditer(main.text):
            sources.append(("script inline", script.group(1)))

        for tag in re.finditer(r"<script\b[^>]*>", main.text, re.I):
            src_match = _SCRIPT_SRC_RE.search(tag.group())
            if not src_match:
                continue
            js_url = urljoin(ctx.url, src_match.group(2))
            if len(sources) >= _MAX_JS_FILES + 1:
                break
            res = await ctx.fetch("GET", js_url)
            if res.ok and res.body:
                sources.append((js_url, res.text))

        for source_name, text in sources:
            if not _SOURCE_RE.search(text):
                continue
            for sink_name, sink_re in _SINKS:
                if sink_re.search(text):
                    ctx.add(
                        self.make(
                            ctx,
                            Severity.MEDIUM,
                            f"Posible DOM XSS: {sink_name} usa una fuente controlable",
                            "El JavaScript lee datos controlables desde la URL o el navegador y los envía a un sink peligroso. Es una heurística que requiere revisión manual del flujo de datos.",
                            "Valida y escapa la entrada antes de insertarla en el DOM; evita innerHTML/eval y usa APIs seguras como textContent.",
                            url=source_name if source_name.startswith(("http://", "https://")) else ctx.url,
                            evidence=f"fuente={_SOURCE_RE.search(text).group()}; sink={sink_name}",
                        )
                    )
                    break
