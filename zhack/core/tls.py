from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import ssl
import tempfile
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class TLSReport:
    ok: bool = True
    version: str = ""
    insecure_version: bool = False
    cert_expired: bool = False
    cert_expiry_days: Optional[int] = None
    cert_self_signed: bool = False
    hostname_mismatch: bool = False
    issuer: str = ""
    subject: str = ""
    error: str = ""


def _parse_not_after(cert) -> Optional[datetime]:
    raw = cert.get("notAfter")
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            clean = re.sub(r"\s+", " ", raw.strip())
            return datetime.strptime(clean, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _hostname_matches(host: str, cert) -> bool:
    names: List[str] = []
    for kind, value in cert.get("subjectAltName", ()):
        if kind in ("DNS", "IP Address"):
            names.append(value)
    if not names:
        for entries in cert.get("subject", ()):
            for key, value in entries:
                if key == "commonName":
                    names.append(value)
    try:
        ip = ipaddress.ip_address(host)
        return any(s == host for s in names)
    except ValueError:
        pass
    for entry in names:
        if entry == host:
            return True
        if entry.startswith("*."):
            suffix = entry[1:]
            prefix = host[: -len(suffix)]
            if host.endswith(suffix) and prefix and "." not in prefix:
                return True
    return False


def _decode_peer_certificate(binary_cert: bytes) -> dict:
    """Decodifica el certificado DER usando solo la biblioteca estándar."""
    if not binary_cert:
        return {}
    path = ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(binary_cert)
        with tempfile.NamedTemporaryFile("w", encoding="ascii", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError, TypeError, ValueError):
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


async def check_tls(host: str, port: int = 443, timeout: float = 10.0) -> TLSReport:
    """Comprueba TLS del host: versión negociada y validez del certificado."""
    report = TLSReport()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    writer = None
    ssl_obj = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout
        )
        ssl_obj = writer.get_extra_info("ssl_object")
    except (ssl.SSLError, OSError, asyncio.TimeoutError, ConnectionError):
        ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_old.check_hostname = False
        ctx_old.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx_old.minimum_version = ssl.TLSVersion.TLSv1
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx_old, server_hostname=host), timeout=timeout
            )
            ssl_obj = writer.get_extra_info("ssl_object")
        except (ssl.SSLError, OSError, asyncio.TimeoutError, ConnectionError) as e:
            report.ok = False
            report.error = f"handshake TLS fallido: {type(e).__name__}"
            return report

    if ssl_obj is not None:
        report.version = ssl_obj.version() or ""
        if report.version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            report.insecure_version = True

    if writer:
        try:
            raw_cert = ssl_obj.getpeercert(binary_form=True)
            cert = raw_cert if isinstance(raw_cert, dict) else _decode_peer_certificate(raw_cert)
            if cert:
                report.subject = str(cert.get("subject", ""))
                report.issuer = str(cert.get("issuer", ""))
                not_after = _parse_not_after(cert)
                if not_after:
                    report.cert_expiry_days = (not_after - datetime.now(timezone.utc)).days
                    report.cert_expired = report.cert_expiry_days < 0
                if not _hostname_matches(host, cert):
                    report.hostname_mismatch = True
                if report.subject == report.issuer:
                    report.cert_self_signed = True
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return report
