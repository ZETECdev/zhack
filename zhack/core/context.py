from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from zhack.core.http_client import FetchResult, HttpClient
from zhack.core.models import Finding, TargetResult


@dataclass
class ScanOptions:
    timeout: int = 10
    concurrency: int = 100
    active: bool = False
    mass: bool = False
    check_tls: bool = True
    max_body: int = 250_000


class ScanContext:
    """Comparte entre checks: cliente HTTP, objetivo, candidatos y resultado."""

    def __init__(self, url: str, http: HttpClient, opts: ScanOptions, result: TargetResult):
        self.url = url
        self.http = http
        self.opts = opts
        self.result = result
        self.candidates: List[str] = [url]
        self.forms: List = []
        self._main: Optional[FetchResult] = None
        self._main_lock = asyncio.Lock()

    async def get_main(self) -> FetchResult:
        if self._main is None:
            async with self._main_lock:
                if self._main is None:
                    self._main = await self.http.fetch("GET", self.url)
                    self.result.status = self._main.status
                    self.result.final_url = self._main.final_url or self.url
        return self._main

    def add(self, finding: Finding) -> None:
        self.result.findings.append(finding)
