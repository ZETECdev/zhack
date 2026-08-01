from __future__ import annotations

from typing import List
from urllib.parse import urlparse


def normalize_url(entry: str) -> str:
    """Normaliza una entrada (dominio o URL completa) a URL absoluta."""
    entry = entry.strip()
    if not entry:
        return ""
    if "://" not in entry:
        entry = "https://" + entry
    parsed = urlparse(entry)
    if not parsed.hostname:
        return ""
    path = parsed.path or "/"
    if parsed.path in ("", "."):
        path = "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def load_targets(path: str) -> List[str]:
    """Carga una lista de webs desde un archivo.

    Formato: una web por línea, se ignoran líneas vacías y las que empiezan por #.
    Soporta CSV simple (primera columna = URL).
    """
    targets: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            url = line.split(",")[0].strip().strip('"')
            norm = normalize_url(url)
            if norm and norm not in targets:
                targets.append(norm)
    return targets
