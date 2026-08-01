"""Tests de ZHack contra el servidor local deliberadamente vulnerable."""

import socket

import pytest
from aiohttp import web

from zhack.core.context import ScanOptions
from zhack.core.scanner import deep_scan, mass_scan
from tests.vuln_server import build_app

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def server():
    app = build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


async def test_deep_scan_encuentra_vulnerabilidades(server):
    opts = ScanOptions(timeout=10, concurrency=20, active=True)
    result = await deep_scan(server + "/", opts)

    checks = {f.check for f in result.findings}
    assert "https" in checks, "debería detectar que HTTP no redirige a HTTPS"
    assert "security_headers" in checks, "debería detectar cabeceras de seguridad ausentes"
    assert "cookies" in checks, "debería detectar cookies sin flags"
    assert "exposed_files" in checks, "debería detectar .env/.git/backup expuestos"
    assert "info_disclosure" in checks, "debería detectar versión de servidor revelada"
    assert "sqli" in checks, "debería detectar inyección SQL"
    assert "xss" in checks, "debería detectar XSS reflejado"
    assert "open_redirect" in checks, "debería detectar redirección abierta"
    assert "traversal" in checks, "debería detectar path traversal"
    assert "cors" in checks, "debería detectar CORS mal configurado"
    assert "http_methods" in checks, "debería detectar métodos HTTP peligrosos"
    assert "csrf" in checks, "debería detectar formularios sin CSRF"

    critico = [f for f in result.findings if f.severity.value == "critico"]
    assert any(f.check == "exposed_files" for f in critico), "debe haber hallazgos críticos"
    assert any(f.check == "sqli" for f in critico), "SQLi debe ser crítico"


async def test_checks_activos_no_pasan_a_mass(server):
    opts = ScanOptions(timeout=10, concurrency=10, mass=True, active=False)
    results = await mass_scan([server + "/", server + "/safe"], opts)
    assert len(results) == 2
    for r in results:
        checks = {f.check for f in r.findings}
        assert "sqli" not in checks, "el modo masivo no debe lanzar payloads activos"
        assert "xss" not in checks
        assert "http_methods" not in checks, "http_methods es activo, no debe ejecutarse en mass"


async def test_pagina_segura_no_genera_falsos_positivos(server):
    opts = ScanOptions(timeout=10, concurrency=10, mass=True, active=False)
    results = await mass_scan([server + "/safe"], opts)
    r = results[0]
    headers_check = {f.check for f in r.findings}
    assert "security_headers" not in headers_check, "/safe tiene todas las cabeceras correctas"
    assert "cookies" not in headers_check, "/safe no envía cookies"


async def test_targets_loader():
    from zhack.core.targets import normalize_url

    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("http://x.com/path") == "http://x.com/path"
    assert normalize_url("  ") == ""
