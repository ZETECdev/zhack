from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)(?=</form\s*>|$)", re.I | re.S)
_ACTION_RE = re.compile(r"\baction\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_METHOD_RE = re.compile(r"\bmethod\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_FILE_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*(?:\"file\"|'file'|file\b)", re.I)
_ENCTYPE_RE = re.compile(r"\benctype\s*=\s*(?:\"multipart/form-data\"|'multipart/form-data'|multipart/form-data\b)", re.I)
_ACCEPT_RE = re.compile(r"\baccept\s*=", re.I)


def _first(match: re.Match | None, default: str = "") -> str:
    return next((value for value in match.groups() if value is not None), default) if match else default


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


class UploadSurfaceCheck(BaseCheck):
    """Revisa formularios de subida sin transferir archivos ni modificar el servidor."""

    name = "upload_surface"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        for match in _FORM_RE.finditer(main.text):
            form_tag_end = main.text.find(">", match.start(), match.end())
            if form_tag_end == -1 or not _FILE_RE.search(match.group(1)):
                continue
            form_tag = main.text[match.start() : form_tag_end + 1]
            action = _first(_ACTION_RE.search(form_tag), ctx.url).strip() or ctx.url
            action_url = urljoin(ctx.url, action)
            method = _first(_METHOD_RE.search(form_tag), "GET").upper()
            action_parts = urlparse(action_url)
            evidence = f"method={method}; action={action_url}"

            if urlparse(ctx.url).scheme == "http" or action_parts.scheme == "http":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Formulario de subida de archivos por HTTP",
                        "El archivo y posiblemente datos asociados viajarían sin cifrado, permitiendo su interceptación o manipulación en tránsito.",
                        "Sirve la página y el endpoint de subida exclusivamente por HTTPS y fuerza HSTS.",
                        url=action_url,
                        evidence=evidence,
                        confidence="alta",
                    )
                )
                continue

            if _origin(action_url) != _origin(ctx.url):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Formulario de subida envía archivos a un origen externo",
                        "La página entrega archivos seleccionados por el usuario a un origen distinto del sitio. Puede provocar fuga de documentos o datos personales.",
                        "Usa un endpoint propio y controlado, documenta el proveedor externo y aplica consentimiento, autenticación y controles de contenido.",
                        url=action_url,
                        evidence=evidence,
                        confidence="media",
                        manual_review=True,
                    )
                )
                continue

            if not _ENCTYPE_RE.search(form_tag):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "Formulario de subida sin enctype multipart/form-data",
                        "Se detecta un campo de archivo en un formulario que no declara el enctype habitual para recibirlo. La implementación puede estar rota o tratar el contenido de forma inesperada.",
                        "Declara multipart/form-data y valida en el servidor tamaño, tipo real, extensión, nombre, almacenamiento y autorización; nunca confíes solo en accept.",
                        url=action_url,
                        evidence=evidence,
                        confidence="media",
                        manual_review=True,
                    )
                )
            elif not _ACCEPT_RE.search(match.group(1)):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.LOW,
                        "Formulario de subida sin restricción de tipos declarada",
                        "El formulario no comunica tipos permitidos al navegador. Esto no prueba una subida insegura, pero aumenta el riesgo de que falten validaciones server-side.",
                        "Valida el tipo MIME real y el contenido en el servidor, limita tamaño y almacena fuera del webroot; usa accept solo como ayuda de interfaz.",
                        url=action_url,
                        evidence=evidence,
                        confidence="baja",
                        manual_review=True,
                    )
                )
