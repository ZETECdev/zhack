from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_JS_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s\"']+)")
_MAX_JS_FILES = 3

# Marcadores de SPA: si la respuesta contiene varios, es el fallback de la app, no un endpoint real
_SPA_MARKERS = (
    b'id="root"',
    b'id="app"',
    b"__NEXT_DATA__",
    b"__NUXT__",
    b"data-astro-cid",
    b"/_next/static/",
    b"/_nuxt/",
    b'<div id="__next"',
)


def _is_spa_fallback(body: bytes, main_sample: bytes) -> bool:
    """True si la respuesta es el HTML de la app (SPA catch-all), no un endpoint real."""
    if not body:
        return False
    lowered = body.lower()
    hits = sum(1 for m in _SPA_MARKERS if m in lowered)
    if hits >= 2:
        return True
    if main_sample and len(body) > 2000 and main_sample in body:
        return True
    return False


# (path, contenido esperado (None = heurística), severidad, título, descripción, remediación)
_PATHS: List[Tuple[str, Optional[bytes], Severity, str, str, str]] = [
    (
        "/swagger-ui.html", b"swagger|api-docs", Severity.INFO,
        "Interfaz Swagger UI expuesta",
        "La documentación interactiva de la API (Swagger UI) es pública; revela endpoints, parámetros y a veces esquemas internos.",
        "Restringe /swagger* y /api-docs a entornos de desarrollo o autenticación.",
    ),
    (
        "/swagger/index.html", b"swagger|api-docs", Severity.INFO,
        "Interfaz Swagger UI expuesta",
        "La documentación interactiva de la API es pública.",
        "Restringe /swagger* a entornos de desarrollo o autenticación.",
    ),
    (
        "/api-docs", b"swagger|openapi", Severity.INFO,
        "Documentación de API expuesta",
        "La especificación de la API (Swagger/OpenAPI) es descargable; revela el diseño completo de los endpoints.",
        "Desactiva la documentación en producción o protégete con autenticación.",
    ),
    (
        "/v2/api-docs", b"swagger|openapi", Severity.INFO,
        "Documentación de API expuesta",
        "La especificación de la API (Swagger/OpenAPI) es descargable.",
        "Desactiva la documentación en producción o protégete con autenticación.",
    ),
    (
        "/v3/api-docs", b"swagger|openapi", Severity.INFO,
        "Documentación de API expuesta",
        "La especificación OpenAPI v3 es descargable públicamente.",
        "Desactiva la documentación en producción o protégete con autenticación.",
    ),
    (
        "/openapi.json", b"openapi|swagger", Severity.INFO,
        "Especificación OpenAPI expuesta",
        "El archivo openapi.json es accesible; revela todos los endpoints y modelos de datos.",
        "Restringe el acceso a openapi.json en producción.",
    ),
    (
        "/openapi.yaml", b"openapi|swagger", Severity.INFO,
        "Especificación OpenAPI expuesta",
        "El archivo openapi.yaml es accesible públicamente.",
        "Restringe el acceso a openapi.yaml en producción.",
    ),
    (
        "/admin", None, Severity.LOW,
        "Panel de administración detectado",
        "Se detecta una ruta de administración pública (/admin). Es un objetivo típico de ataques de fuerza bruta y vulnerabilidades de autenticación.",
        "Protege el panel con autenticación fuerte, 2FA y restricción por IP.",
    ),
    (
        "/administrator", None, Severity.LOW,
        "Panel de administración detectado",
        "Se detecta una ruta de administración (/administrator, típica de Joomla).",
        "Protege el panel con autenticación fuerte y restricción por IP.",
    ),
    (
        "/wp-admin", None, Severity.LOW,
        "Panel de WordPress detectado",
        "Se detecta /wp-admin. Es objetivo constante de fuerza bruta y exploits de plugins.",
        "Mantén WordPress y plugins actualizados, usa 2FA y limita intentos de login.",
    ),
    (
        "/server-status", b"server status|apache", Severity.LOW,
        "server-status de Apache expuesto",
        "El estado del servidor Apache es accesible públicamente.",
        "Restringe /server-status a IPs internas.",
    ),
    (
        "/nginx_status", b"active connections|server accepts", Severity.LOW,
        "nginx_status expuesto",
        "El módulo de estado de nginx responde públicamente.",
        "Restringe /nginx_status a IPs internas o monitorización.",
    ),
]


class EndpointExposureCheck(BaseCheck):
    """Busca documentación de API, GraphQL, source maps y paneles de administración expuestos."""

    name = "endpoint_exposure"
    mass = True

    async def run(self, ctx) -> None:
        base = ctx.url.rstrip("/")
        main = await ctx.get_main()
        main_sample = main.text[:500].encode("utf-8", errors="replace") if main.ok else b""

        for path, expected, severity, title, description, remediation in _PATHS:
            res = await ctx.fetch("GET", base + path)
            if res.status in (404, None):
                continue
            if expected is not None:
                if res.ok and res.body and re.search(expected, res.body, re.I):
                    ctx.add(
                        self.make(ctx, severity, title, description, remediation,
                                  url=base + path, evidence=f"HTTP {res.status}")
                    )
                continue
            # Heurística: ruta admin real solo si NO es el fallback de la SPA
            if res.status == 200 and not _is_spa_fallback(res.body, main_sample):
                ctx.add(
                    self.make(ctx, severity, title, description, remediation,
                              url=base + path, evidence=f"HTTP {res.status}")
                )

        # GraphQL se detecta por respuesta 400/405 (ruta real, GET no permitido) con cuerpo NO html
        for path in ("/graphql", "/graphiql"):
            res = await ctx.fetch("GET", base + path)
            if res.status in (404, None):
                continue
            content_type = (res.headers.get("content-type", "") if res.headers else "") or ""
            is_html = "text/html" in content_type
            is_real = (res.ok and res.body and re.search(b"graphql", res.body, re.I)) or (
                res.status in (400, 405) and not is_html
            )
            if is_real:
                ctx.add(
                    self.make(ctx, Severity.MEDIUM, title, description, remediation,
                              url=base + path, evidence=f"HTTP {res.status}")
                )

        if not main.ok or not main.body:
            return
        html = main.text
        maps = _SOURCE_MAP_RE.findall(html)
        scripts = _JS_SRC_RE.findall(html)
        for src in scripts[: _MAX_JS_FILES]:
            js_url = urljoin(ctx.url, src)
            res = await ctx.fetch("GET", js_url)
            if res.ok and res.body:
                maps.extend(_SOURCE_MAP_RE.findall(res.text))

        seen: set = set()
        for map_path in maps:
            if map_path in seen:
                continue
            seen.add(map_path)
            map_url = urljoin(ctx.url, map_path)
            res = await ctx.fetch("GET", map_url)
            if res.ok and res.body and b'"version"' in res.body:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "Source map (código fuente) expuesto",
                        "Un archivo .js.map es descargable: expone el código fuente original, comentarios y estructura interna de la aplicación.",
                        "Elimina los source maps de producción o no los subas al CDN. Build en modo producción.",
                        url=map_url,
                        evidence=f"HTTP {res.status}, .map descargable",
                    )
                )
