from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import urljoin

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_JS_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_MAX_JS_FILES = 3
_MAX_BUCKETS = 4

# (servicio, regex para localizar el bucket, constructor de la URL de listado, marca de listado)
_S3_VIRTUAL_RE = re.compile(
    r"https?://(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-][a-z0-9-]*\.?amazonaws\.com",
    re.I,
)
_S3_PATH_RE = re.compile(
    r"https?://s3[.-][a-z0-9-]*\.?amazonaws\.com/(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
    re.I,
)
_GCS_RE = re.compile(
    r"https?://storage\.googleapis\.com/(?P<bucket>[a-z0-9][a-z0-9._-]{1,61}[a-z0-9])",
    re.I,
)
_AZURE_RE = re.compile(
    r"https?://(?P<account>[a-z0-9]{3,24})\.blob\.core\.windows\.net/(?P<container>[a-z0-9][a-z0-9-]{1,61}[a-z0-9])",
    re.I,
)
# Proveedores S3-compatibles con listado XML (ListBucketResult)
_EXTRA_RE = [
    ("DigitalOcean Spaces", re.compile(
        r"https?://(?P<host>[a-z0-9][a-z0-9.-]{2,}?\.digitaloceanspaces\.com)(?:/|$)", re.I)),
    ("Cloudflare R2", re.compile(
        r"https?://(?P<host>[a-z0-9-]{1,63}\.r2\.cloudflarestorage\.com)(?:/|$)", re.I)),
    ("Backblaze B2", re.compile(
        r"https?://(?P<host>[a-z0-9-]{1,50}\.[a-z0-9-]+\.s3[.-][a-z0-9-]+\.backblazeb2\.com)(?:/|$)", re.I)),
    ("Alibaba OSS", re.compile(
        r"https?://(?P<host>[a-z0-9][a-z0-9-]{1,61}\.oss[.-][a-z0-9-]+\.aliyuncs\.com)(?:/|$)", re.I)),
    ("Tencent COS", re.compile(
        r"https?://(?P<host>[a-z0-9-]{1,63}\.cos[.-][a-z0-9-]+\.myqcloud\.com)(?:/|$)", re.I)),
    ("Wasabi", re.compile(
        r"https?://(?P<host>[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.wasabisys\.com)(?:/|$)", re.I)),
]


def _candidate_urls(text: str) -> List[Tuple[str, str, bytes]]:
    """Devuelve (etiqueta, url_de_listado, marca_de_listado) únicas."""
    found: List[Tuple[str, str, bytes]] = []
    seen: set[str] = set()

    def add(key: str, label: str, url: str, marker: bytes) -> None:
        if key in seen or len(found) >= _MAX_BUCKETS:
            return
        seen.add(key)
        found.append((label, url, marker))

    for m in _S3_VIRTUAL_RE.finditer(text):
        bucket = m.group("bucket")
        add(f"s3:{bucket}", f"S3 bucket '{bucket}'",
            f"https://{bucket}.s3.amazonaws.com/?max-keys=1", b"ListBucketResult")
    for m in _S3_PATH_RE.finditer(text):
        bucket = m.group("bucket")
        add(f"s3:{bucket}", f"S3 bucket '{bucket}'",
            f"https://s3.amazonaws.com/{bucket}/?max-keys=1", b"ListBucketResult")
    for m in _GCS_RE.finditer(text):
        bucket = m.group("bucket")
        add(f"gcs:{bucket}", f"GCS bucket '{bucket}'",
            f"https://storage.googleapis.com/{bucket}/?max-keys=1", b"ListBucketResult")
    for m in _AZURE_RE.finditer(text):
        account, container = m.group("account"), m.group("container")
        add(f"azure:{account}/{container}", f"Azure container '{account}/{container}'",
            f"https://{account}.blob.core.windows.net/{container}"
            f"?restype=container&comp=list&maxresults=1",
            b"EnumerationResults")
    for service, regex in _EXTRA_RE:
        for m in regex.finditer(text):
            host = m.group("host")
            add(f"{service}:{host}", f"{service} bucket '{host}'",
                f"https://{host}/?max-keys=1", b"ListBucketResult")
    return found


class BucketExposureCheck(BaseCheck):
    """Detecta buckets S3/GCS/Azure referenciados por la web y comprueba si son listables."""

    name = "bucket_exposure"
    mass = True

    async def run(self, ctx) -> None:
        main = await ctx.get_main()
        if not main.ok or not main.body:
            return

        text = main.text
        scripts = _JS_SRC_RE.findall(text)
        fetched = 0
        seen_src: set[str] = set()
        for src in scripts:
            url = urljoin(ctx.url, src)
            if url in seen_src or fetched >= _MAX_JS_FILES:
                continue
            seen_src.add(url)
            fetched += 1
            res = await ctx.fetch("GET", url)
            if res.ok and res.body:
                text += "\n" + res.text

        candidates = _candidate_urls(text)
        if not candidates:
            return

        for label, list_url, marker in candidates:
            res = await ctx.fetch("GET", list_url)
            if not res.body:
                continue
            if res.ok and marker in res.body:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        f"{label} con listado público habilitado",
                        "El almacenamiento en la nube referenciado por la web permite enumerar (y potencialmente descargar) todos sus objetos sin autenticación: copias de seguridad, datos de usuarios, código o secretos pueden estar expuestos.",
                        "Desactiva el acceso público de listado/lectura en el bucket, aplica políticas de mínimo privilegio (block public access en AWS, uniform bucket-level access en GCS, acceso privado en Azure) y audita los objetos ya expuestos.",
                        url=list_url,
                        evidence=f"HTTP {res.status}; respuesta contiene {marker.decode()}",
                    )
                )
            elif res.ok:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.INFO,
                        f"{label} accesible públicamente",
                        "El almacenamiento responde públicamente. No se pudo enumerar, pero conviene verificar que solo los objetos estrictamente públicos sean accesibles.",
                        "Revisa los permisos del bucket y niega por defecto cualquier acceso anónimo no necesario.",
                        url=list_url,
                        evidence=f"HTTP {res.status}",
                    )
                )
