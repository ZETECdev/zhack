from __future__ import annotations

from urllib.parse import urlparse

from zhack.checks.base import BaseCheck
from zhack.core.models import Severity
from zhack.core.tls import check_tls


class TLSCheck(BaseCheck):
    """Comprueba versión de TLS y validez del certificado."""

    name = "tls"
    mass = True

    async def run(self, ctx) -> None:
        if not ctx.opts.check_tls:
            return
        parsed = urlparse(ctx.url)
        host = parsed.hostname or ""
        if not host:
            return
        port = parsed.port or 443

        report = await check_tls(host, port, timeout=ctx.opts.timeout)
        if report.error:
            if not ctx.opts.mass:
                ctx.result.errors.append(f"TLS {host}:{port}: {report.error}")
            return

        if report.insecure_version:
            ctx.add(
                self.make(
                    ctx,
                    Severity.HIGH,
                    f"Protocolo TLS antiguo ({report.version})",
                    f"El servidor negocia {report.version}, protocolo obsoleto con vulnerabilidades conocidas (p.ej. BEAST, POODLE).",
                    "Habilita TLS 1.2 o superior y desactiva TLS 1.0/1.1 y SSLv3.",
                    evidence=report.version,
                )
            )

        if report.cert_expired:
            days = report.cert_expiry_days
            ctx.add(
                self.make(
                    ctx,
                    Severity.CRITICAL,
                    "Certificado TLS caducado",
                    "El certificado SSL ha expirado. Los navegadores bloquearán la web y el cifrado deja de ser fiable.",
                    "Renueva el certificado inmediatamente (certbot renew o tu proveedor SSL).",
                    evidence=f"caducó hace {-days} días" if days is not None else "",
                )
            )
        elif report.cert_expiry_days is not None and report.cert_expiry_days <= 30:
            ctx.add(
                self.make(
                    ctx,
                    Severity.MEDIUM,
                    f"Certificado TLS a punto de caducar ({report.cert_expiry_days} días)",
                    "El certificado expira pronto; si caduca, la web dejará de ser accesible de forma segura.",
                    "Renueva antes de que caduque. Si usas Let's Encrypt, automatiza la renovación.",
                    evidence=f"días restantes: {report.cert_expiry_days}",
                )
            )

        if report.cert_self_signed:
            ctx.add(
                self.make(
                    ctx,
                    Severity.HIGH,
                    "Certificado TLS autofirmado",
                    "El certificado es autofirmado y no lo emite una CA de confianza: los navegadores muestran advertencias y no es fiable.",
                    "Obtén un certificado de una CA de confianza (Let's Encrypt, etc.).",
                    evidence=report.issuer,
                )
            )

        if report.hostname_mismatch:
            ctx.add(
                self.make(
                    ctx,
                    Severity.CRITICAL,
                    "Certificado TLS no válido para este dominio",
                    "El certificado no corresponde al dominio solicitado (hostname mismatch).",
                    "Reemite el certificado incluyendo el dominio correcto en las SANs.",
                    evidence=f"host={host}",
                )
            )
