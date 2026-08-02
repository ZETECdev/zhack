from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")

_RETRYABLE_ERRORS = ("timeout", "conn")
_MAX_RETRIES = 2
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_SAFE_CROSS_ORIGIN_HEADERS = {"accept", "accept-language", "content-type", "origin", "range"}


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
        target_url: str = "",
        shared_global_sem: Optional[asyncio.Semaphore] = None,
        shared_host_sems: Optional[Dict[str, asyncio.Semaphore]] = None,
        shared_host_lock: Optional[asyncio.Lock] = None,
    ):
        self.timeout = timeout
        self.global_sem = shared_global_sem if shared_global_sem is not None else asyncio.Semaphore(global_concurrency)
        self.per_host = per_host
        self.max_body = max_body
        self.max_redirects = max_redirects
        self.custom_headers = custom_headers or {}
        self.retries = retries
        self.target_url = target_url
        self._host_sems: Dict[str, asyncio.Semaphore] = (
            shared_host_sems if shared_host_sems is not None else {}
        )
        self._host_lock = shared_host_lock if shared_host_lock is not None else asyncio.Lock()
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "HttpClient":
        base_headers = {"User-Agent": "ZHack-SecurityScanner/1.0 (escaneo autorizado)"}
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

    @staticmethod
    def _host_key(url: str) -> str:
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
        return f"{(parsed.hostname or '?').lower()}:{port}"

    @classmethod
    def _same_authority(cls, left: str, right: str) -> bool:
        return cls._host_key(left) == cls._host_key(right)

    @classmethod
    def _allowed_redirect(cls, current: str, target: str) -> bool:
        """Permite solo el mismo host y nunca una degradación HTTPS -> HTTP."""
        current_parsed = urlparse(current)
        target_parsed = urlparse(target)
        if target_parsed.scheme not in ("http", "https"):
            return False
        if (current_parsed.hostname or "").lower() != (target_parsed.hostname or "").lower():
            return False
        if current_parsed.scheme == "https" and target_parsed.scheme != "https":
            return False
        if cls._same_authority(current, target):
            return True
        return (
            current_parsed.scheme == "http"
            and target_parsed.scheme == "https"
            and cls._host_key(current).endswith(":80")
            and cls._host_key(target).endswith(":443")
        )

    def _headers_for(self, url: str, headers: Optional[dict]) -> dict:
        """No envía cookies/API keys a scripts, buckets o RPCs de terceros."""
        supplied = dict(headers or {})
        target = self.target_url or url
        same_origin = self._same_authority(url, target) and (
            urlparse(url).scheme.lower() == urlparse(target).scheme.lower()
        )
        if not same_origin:
            supplied = {
                name: value
                for name, value in supplied.items()
                if name.lower() in _SAFE_CROSS_ORIGIN_HEADERS
            }
            return supplied
        merged = dict(self.custom_headers)
        merged.update(supplied)
        return merged

    async def fetch(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> FetchResult:
        if method.upper() not in READ_ONLY_METHODS:
            raise ValueError(f"Método no permitido (solo lectura): {method}")
        requested_url = url
        host = self._host_key(url)
        async with self.global_sem:
            async with await self._host_sem(host):
                for attempt in range(self.retries + 1):
                    result = await self._fetch_chain(method, url, headers, allow_redirects)
                    result.url = requested_url
                    if attempt < self.retries and result.error_type in _RETRYABLE_ERRORS:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    return result
                return result

    async def _fetch_chain(
        self,
        method: str,
        url: str,
        headers: Optional[dict],
        allow_redirects: bool,
    ) -> FetchResult:
        current_url = url
        visited = {url}
        for _ in range(self.max_redirects + 1):
            result = await self._do_request(
                method,
                current_url,
                self._headers_for(current_url, headers),
                allow_redirects=False,
            )
            result.final_url = current_url
            if not allow_redirects or result.status not in _REDIRECT_STATUSES:
                return result
            location = result.headers.get("location", "") if result.headers else ""
            if not location:
                return result
            next_url = urljoin(current_url, location)
            if next_url in visited or not self._allowed_redirect(current_url, next_url):
                return result
            visited.add(next_url)
            current_url = next_url

        result.error = "demasiadas redirecciones"
        result.error_type = "http"
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
                if method.upper() != "HEAD":
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
