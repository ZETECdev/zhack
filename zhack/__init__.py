"""ZHack - Escáner de seguridad web (masivo y profundo).

Solo para webs propias o con autorización escrita.
Solo realiza peticiones de LECTURA (GET/HEAD/OPTIONS) y jamás modifica una web.
"""

from zhack.core.scanner import scan_all, scan_all_sync

__version__ = "1.2.0"

__all__ = ["scan_all", "scan_all_sync", "__version__"]
