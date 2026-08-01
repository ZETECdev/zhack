from __future__ import annotations

import random
import re
import string
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity

_SQL_ERROR_RE = re.compile(
    r"sql (syntax|state)|mysql_fetch|mysqli|pdoexception|sqlalchemy|ora-\d+|postgresql|"
    r"sqlite|unclosed quotation mark|syntax error|supplied argument is not a valid|"
    r"microsoft ole db|incorrect syntax near|you have an error in your sql",
    re.I,
)


class SQLiCheck(BaseCheck):
    """Detecta inyección SQL de forma INOFENSIVA.

    Solo envía payloads de detección (comillas/booleanos) y observa errores de SQL.
    Jamás envía UPDATE/DELETE/DROP, jamás escribe nada.
    """

    name = "sqli"
    requires_active = True

    async def run(self, ctx) -> None:
        for candidate in ctx.candidates:
            parsed = urlparse(candidate)
            if not parsed.query:
                continue
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for key, value in params:
                for payload in (value + "'", value + "' OR '1'='1' -- ", value + '"'):
                    query = urlencode(
                        [(k, payload if k == key else v) for k, v in params], doseq=True
                    )
                    probe_url = urlunparse(parsed._replace(query=query))
                    res = await ctx.http.fetch("GET", probe_url)
                    if res.ok and res.body and _SQL_ERROR_RE.search(res.text):
                        ctx.add(
                            self.make(
                                ctx,
                                Severity.CRITICAL,
                                f"Posible inyección SQL en el parámetro '{key}'",
                                "El servidor devuelve errores de SQL al enviar comillas en el parámetro: las consultas se construyen concatenando entrada del usuario.",
                                "Usa consultas parametrizadas (prepared statements) en TODAS las consultas; nunca concatenes entrada del usuario en SQL.",
                                url=probe_url,
                                evidence=res.text[:300],
                            )
                        )
                        break
