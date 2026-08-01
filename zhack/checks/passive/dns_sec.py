from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_DOH_URL = "https://cloudflare-dns.com/dns-query"
_HEADERS = {"Accept": "application/dns-json"}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class DnsSecurityCheck(BaseCheck):
    """Comprueba SPF y DMARC (anti suplantación de email) vía DNS público."""

    name = "dns_sec"
    mass = True

    async def run(self, ctx) -> None:
        host = urlparse(ctx.url).hostname or ""
        if not host or _is_ip(host) or host.count(".") < 1:
            return

        spf = await self._txt(ctx, host)
        if spf is None:
            return
        if not any("v=spf1" in t for t in spf):
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    "Sin registro SPF en el dominio",
                    "El dominio no publica SPF (v=spf1). Los atacantes pueden enviar correos suplantando el dominio (phishing dirigido a usuarios del exchange).",
                    "Publica un registro TXT SPF: v=spf1 include:<proveedor> ~all (o -all).",
                    evidence="TXT SPF no encontrado",
                )
            )

        dmarc = await self._txt(ctx, "_dmarc." + host)
        if dmarc is None:
            return
        if not any("v=DMARC1" in t for t in dmarc):
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    "Sin registro DMARC en el dominio",
                    "El dominio no publica DMARC. Sin DMARC, los correos suplantados no pueden ser rechazados de forma fiable; aumenta el phishing de la marca.",
                    "Publica un TXT en _dmarc.<dominio>: v=DMARC1; p=reject; rua=mailto:dmarc@<dominio>.",
                    evidence="TXT DMARC no encontrado",
                )
            )

    async def _txt(self, ctx, name: str):
        try:
            url = f"{_DOH_URL}?name={name}&type=TXT"
            res = await ctx.http.fetch("GET", url, headers=_HEADERS)
            if not res.ok or not res.body:
                return None
            data = json.loads(res.text)
            answers = data.get("Answer") or []
            values = [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
            return values or []
        except Exception:
            return None
