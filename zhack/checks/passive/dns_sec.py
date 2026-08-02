from __future__ import annotations

import ipaddress
import json
import re
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
        if not any("v=spf1" in t.lower() for t in spf):
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
        else:
            spf_records = [t for t in spf if "v=spf1" in t.lower()]
            if len(spf_records) > 1:
                ctx.add(
                    self.make(
                        ctx,
                        Severity.HIGH,
                        "Múltiples registros SPF publicados",
                        "El dominio publica más de un registro SPF. Los receptores pueden considerar el SPF inválido y aceptar correos suplantados.",
                        "Combina los mecanismos en un único registro SPF y mantén el número de consultas DNS dentro del límite del estándar.",
                        evidence=f"registros SPF detectados: {len(spf_records)}",
                    )
                )
            if not any(re.search(r"(?:^|\s)[~-]all(?:\s|$)", record, re.I) for record in spf_records):
                ctx.add(
                    self.make(
                        ctx,
                        Severity.LOW,
                        "SPF sin política all explícita",
                        "El registro SPF no termina con una política ~all o -all clara; remitentes no autorizados pueden no quedar tratados como fallos.",
                        "Define una política final explícita, comienza con ~all durante la migración y evoluciona a -all cuando todos los emisores legítimos estén inventariados.",
                        evidence=spf_records[0][:240],
                        confidence="media",
                        manual_review=True,
                    )
                )

        dmarc = await self._txt(ctx, "_dmarc." + host)
        if dmarc is None:
            return
        dmarc_records = [t for t in dmarc if "v=dmarc1" in t.lower()]
        if not dmarc_records:
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
        else:
            policy = re.search(r"(?:^|;)\s*p\s*=\s*([^;\s]+)", dmarc_records[0], re.I)
            if not policy or policy.group(1).lower() == "none":
                ctx.add(
                    self.make(
                        ctx,
                        Severity.MEDIUM,
                        "DMARC publicado solo en modo monitorización",
                        "DMARC existe pero usa p=none o no declara una política aplicable. Los mensajes fraudulentos se reportan, pero no se rechazan ni ponen en cuarentena.",
                        "Analiza los informes rua y evoluciona a p=quarantine o p=reject tras validar los emisores legítimos.",
                        evidence=dmarc_records[0][:240],
                        confidence="alta",
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
