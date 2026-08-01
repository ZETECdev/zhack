from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import aiohttp

READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")

_RETRYABLE_ERRORS = ("timeout", "conn")
_MAX_RETRIES = 2


@dataclass
class FetchResult:
    url: str
    status: Optional[int] = None
    headers: Optional[aiohttp.CIMultiDict] = None
    body: bytes = b""
    final_url: str = ""
    error: Optional[str] = None
    error_type: Optional[str] = None

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


class HttpClient:
    """Cliente HTTP asíncrono.

    Garantías de seguridad de ZHack:
    - SOLO permite métodos de lectura (GET/HEAD/OPTIONS).
    - Limita la concurrencia global y por host (no satura una web).
    - Timeout global y tamaño máximo de cuerpo descargado.
    """

    def __init__(
        self,
        timeout: int = 10,
        global_concurrency: int = 100,
        per_host: int = 5,
        max_body: int = 250_000,
        max_redirects: int = 5,
        custom_headers: Optional[Dict[str, str]] = None,
        retries: int = _MAX_RETRIES,
    ):
        self.timeout = timeout
        self.global_sem = asyncio.Semaphore(global_concurrency)
        self.per_host = per_host
        self.max_body = max_body
        self.max_redirects = max_redirects
        self.custom_headers = custom_headers or {}
        self.retries = retries
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._host_lock = asyncio.Lock()
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "HttpClient":
        base_headers = {"User-Agent": "ZHack-SecurityScanner/1.0 (escaneo autorizado)"}
        base_headers.update(self.custom_headers)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout),
            headers=base_headers,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self.session:
            await self.session.close()

    async def _host_sem(self, host: str) -> asyncio.Semaphore:
        async with self._host_lock:
            sem = self._host_sems.get(host)
            if sem is None:
                sem = asyncio.Semaphore(self.per_host)
                self._host_sems[host] = sem
            return sem

    async def fetch(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> FetchResult:
        if method.upper() not in READ_ONLY_METHODS:
            raise ValueError(f"Método no permitido (solo lectura): {method}")
        host = urlparse(url).hostname or "?"
        async with self.global_sem:
            async with await self._host_sem(host):
                for attempt in range(self.retries + 1):
                    result = await self._do_request(method, url, headers, allow_redirects)
                    if attempt < self.retries and result.error_type in _RETRYABLE_ERRORS:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    return result
                return result

    async def _do_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> FetchResult:
        try:
            async with self.session.request(
                method,
                url,
                headers=headers,
                allow_redirects=allow_redirects,
                max_redirects=self.max_redirects,
            ) as resp:
                body = b""
                if method.upper() != "HEAD" and allow_redirects:
                    body = await resp.content.read(self.max_body)
                return FetchResult(
                    url=url,
                    status=resp.status,
                    headers=resp.headers,
                    body=body,
                    final_url=str(resp.url),
                )
        except aiohttp.ClientResponseError as e:
            return FetchResult(url=url, status=e.status, error=str(e), error_type="http")
        except (ssl.SSLCertVerificationError, aiohttp.ClientConnectorSSLError) as e:
            return FetchResult(url=url, error=str(e), error_type="ssl_cert")
        except aiohttp.ClientConnectorError as e:
            return FetchResult(url=url, error=str(e), error_type="conn")
        except aiohttp.ClientError as e:
            return FetchResult(url=url, error=str(e), error_type="http")
        except asyncio.TimeoutError:
            return FetchResult(url=url, error="timeout", error_type="timeout")
        except (OSError, ConnectionError) as e:
            return FetchResult(url=url, error=str(e), error_type="conn")
