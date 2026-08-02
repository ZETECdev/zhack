"""Tests de ZHack contra el servidor local deliberadamente vulnerable."""

import socket

import pytest
from aiohttp import web

from zhack import scan_all
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
    assert "secret_scan" in checks, "debería detectar secretos expuestos en el frontend"
    assert "endpoint_exposure" in checks, "debería detectar swagger/source maps expuestos"
    assert "rpc_cors" in checks, "debería detectar CORS mal configurado en endpoints RPC"
    assert "sri" in checks, "debería detectar scripts de CDN sin integrity"
    assert "cdn" in checks, "debería detectar el CDN frontal"
    assert "contract_exposure" in checks, "debería detectar contratos/explorers/configs Web3"
    assert "rpc_methods" in checks, "debería detectar nodos RPC públicos accesibles"

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
        assert "rpc_cors" not in checks, "rpc_cors es activo, no debe ejecutarse en mass"
        assert "rpc_methods" not in checks, "rpc_methods es activo, no debe ejecutarse en mass"
        assert "dex_rpc" not in checks, "dex_rpc es activo, no debe ejecutarse en mass"


async def test_scan_all_es_la_api_principal_y_ejecuta_todos_los_checks(server):
    results = await scan_all(
        [server + "/", server + "/"],
        ScanOptions(timeout=10, concurrency=20, active=False, mass=True),
    )

    assert len(results) == 1, "scan_all debe normalizar y deduplicar objetivos"
    checks = {f.check for f in results[0].findings}
    assert "sqli" in checks, "scan_all debe activar los checks activos"
    assert "form_security" in checks, "debe revisar formularios sensibles"
    assert "cache_control" in checks, "debe revisar la caché de respuestas con sesión"


async def test_checks_dex_detectan_slippage_allowance_permit_y_router_sin_bytecode():
    from zhack.checks.active.dex_rpc import DexRpcCheck
    from zhack.checks.passive.dex_security import DexSecurityCheck
    from zhack.core.http_client import FetchResult
    from zhack.core.models import TargetResult
    from zhack.reporting.csv_report import write_csv
    from zhack.reporting.html_report import build_html
    from zhack.reporting.json_report import result_to_dict

    router = "0x1111111111111111111111111111111111111111"
    html = f"""
    <html><body><script>
      const routerAddress = "{router}";
      const rpcUrl = "/rpc";
      const swap = {{ amountOutMin: 0, slippageBps: 10000 }};
      token.approve(routerAddress, MaxUint256);
      token.permit({{ deadline: MaxUint256 }});
    </script></body></html>
    """

    class FakeCtx:
        url = "https://dex.example/"

        def __init__(self):
            self.findings = []
            self.requests = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            self.requests.append((method, url))
            return FetchResult(
                url=url,
                status=200,
                body=b'{"jsonrpc":"2.0","id":1,"result":"0x"}',
            )

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await DexSecurityCheck().run(ctx)
    titles = {finding.title for finding in ctx.findings}
    assert any("slippage" in title.lower() for title in titles)
    assert any("aprobación" in title.lower() for title in titles)
    assert any("permit" in title.lower() for title in titles)
    finding = ctx.findings[0]
    assert finding.attacker_impact
    assert finding.attack_scenario
    assert finding.safe_validation

    report = result_to_dict(TargetResult(url=ctx.url, findings=[finding]))
    serialized_finding = report["hallazgos"][0]
    assert serialized_finding["attacker_impact"]
    assert serialized_finding["attack_scenario"]
    assert serialized_finding["safe_validation"]
    assert "Attacker impact:" in build_html([TargetResult(url=ctx.url, findings=[finding])])
    csv_path = "reports/test_dex_finding.csv"
    write_csv([TargetResult(url=ctx.url, findings=[finding])], csv_path)
    with open(csv_path, encoding="utf-8") as csv_file:
        csv_text = csv_file.read()
    assert "attacker_impact" in csv_text
    assert "High-level scenario" in csv_text

    ctx = FakeCtx()
    await DexRpcCheck().run(ctx)
    assert any(finding.check == "dex_rpc" for finding in ctx.findings)
    assert any(method == "GET" and "eth_getCode" in url for method, url in ctx.requests)


async def test_wallet_security_detecta_higiene_de_wallet(server):
    opts = ScanOptions(timeout=10, concurrency=20, active=False)
    result = await deep_scan(server + "/dapp", opts)
    wallet = [f for f in result.findings if f.check == "wallet_security"]
    titles = " ".join(f.title.lower() for f in wallet)
    assert "eth_sign" in titles, "debe detectar firma ciega eth_sign"
    assert "personal_sign" in titles, "debe detectar personal_sign sin SIWE"
    assert "web storage" in titles, "debe detectar secretos en Web Storage"
    assert "websocket" in titles, "debe detectar WebSocket en claro"
    assert "portapapeles" in titles, "debe detectar escritura en el portapapeles"
    assert "rpc en claro" in titles, "debe detectar el endpoint RPC en http"
    assert "automáticamente" in titles, "debe detectar el auto-connect de la wallet"
    for f in wallet:
        assert f.attacker_impact and f.attack_scenario and f.safe_validation
    harvest = [f for f in result.findings if f.check == "seed_harvest"]
    assert harvest and harvest[0].severity.value == "critico", "debe detectar el formulario que pide la semilla"


async def test_web3_supply_chain_detecta_librerias_obsoletas_y_mutables():
    from zhack.checks.passive.web3_supply_chain import Web3SupplyChainCheck
    from zhack.core.http_client import FetchResult

    html = """
    <html><head>
      <script src="https://unpkg.com/ethers@4.0.48/dist/ethers.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/web3@0.20.7/dist/web3.min.js"></script>
      <script src="https://unpkg.com/web3/dist/web3.min.js"></script>
      <script src="https://unpkg.com/@walletconnect/web3-provider@1.8.0/dist/umd/index.min.js"></script>
      <script src="https://unpkg.com/ethers@6.13.2/dist/ethers.min.js"></script>
      <script src="https://unpkg.com/@solana/web3.js@1.95.8/bundle.min.js"></script>
      <script src="https://unpkg.com/viem@latest/dist/index.mjs"></script>
    </head><body></body></html>
    """

    class FakeCtx:
        url = "https://dex.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await Web3SupplyChainCheck().run(ctx)
    titles = " ".join(f.title.lower() for f in ctx.findings)
    assert "ethers.js 4.0.48" in titles, "debe avisar de ethers v4 (EOL)"
    assert "web3.js 0.20.7" in titles, "debe avisar de web3 0.x"
    assert "sin versión fijada" in titles, "debe avisar de la URL mutable de web3"
    assert "walletconnect v1" in titles, "debe avisar de WalletConnect v1"
    assert "solana" in titles, "debe avisar de @solana/web3.js comprometido"
    assert "viem" in titles, "debe avisar de viem@latest mutable"
    assert "6.13.2" not in titles, "una versión mantenida no debe generar hallazgo"


async def test_dex_security_detecta_mint_y_blacklist():
    from zhack.checks.passive.dex_security import DexSecurityCheck
    from zhack.core.http_client import FetchResult

    router = "0x1111111111111111111111111111111111111111"
    html = f"""
    <html><body><script>
      const routerAddress = "{router}";
      const swap = {{ amountOutMin: 100 }};
      // pragma solidity ^0.8.24;
      // function mint(address to, uint256 amount) external onlyOwner {{ _mint(to, amount); }}
      // mapping(address => bool) private _blacklist;
    </script></body></html>
    """

    class FakeCtx:
        url = "https://dex.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            return FetchResult(url=url, status=404, body=b"")

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await DexSecurityCheck().run(ctx)
    titles = " ".join(f.title.lower() for f in ctx.findings if f.check == "dex_security")
    assert "mint" in titles, "debe detectar mint controlado por el owner"
    assert "blacklist" in titles, "debe detectar la función de blacklist"


async def test_bucket_exposure_detecta_listado_publico():
    from zhack.checks.passive.bucket_exposure import BucketExposureCheck
    from zhack.core.http_client import FetchResult

    html = (
        '<html><body><img src="https://media-miapp.s3.amazonaws.com/logo.png">'
        '<img src="https://cdn-miapp.fra1.digitaloceanspaces.com/img.png">'
        "</body></html>"
    )

    class FakeCtx:
        url = "https://app.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            if "s3.amazonaws.com" in url or "digitaloceanspaces.com" in url:
                return FetchResult(
                    url=url,
                    status=200,
                    body=b'<?xml version="1.0"?><ListBucketResult><Name>bucket</Name>'
                         b"<Contents><Key>backup.sql</Key></Contents></ListBucketResult>",
                )
            return FetchResult(url=url, status=404, body=b"")

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await BucketExposureCheck().run(ctx)
    assert any(
        f.check == "bucket_exposure" and f.severity.value == "alto" for f in ctx.findings
    ), "debe detectar el bucket con listado público como alto"
    labels = " ".join(f.title for f in ctx.findings)
    assert "S3 bucket" in labels and "DigitalOcean" in labels, "debe cubrir varios proveedores"


async def test_checks_web3_soportan_scripts_externos():
    from zhack.checks.dex_common import collect_frontend_sources
    from zhack.checks.passive.wallet_security import WalletSecurityCheck
    from zhack.core.http_client import FetchResult

    html = (
        '<html><head><script src="https://cdn.example/app.js"></script></head>'
        '<body><script>'
        "window.ethereum.request({ method: 'eth_sign', params: [accounts[0], msg] });"
        "</script></body></html>"
    )

    class FakeCtx:
        url = "https://dex.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            if "cdn.example" in url:
                return FetchResult(url=url, status=200, body=b"window.ethereum = {};")
            return FetchResult(url=url, status=404, body=b"")

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    sources = await collect_frontend_sources(ctx, html)
    assert len(sources) >= 2, "debe recoger el script externo sin lanzar TypeError"
    await WalletSecurityCheck().run(ctx)
    assert any(
        f.check == "wallet_security" and "eth_sign" in f.title.lower()
        for f in ctx.findings
    ), "con scripts externos el check debe seguir detectando eth_sign"


async def test_seed_harvest_detecta_formularios_que_piden_la_semilla():
    from zhack.checks.passive.seed_harvest import SeedHarvestCheck
    from zhack.core.http_client import FetchResult

    html = (
        '<html><body><form method="POST" action="/recover">'
        '<input name="email">'
        '<textarea name="seed_phrase" placeholder="Enter your 12 word seed phrase"></textarea>'
        '<button type="submit">Recover wallet</button></form></body></html>'
    )

    class FakeCtx:
        url = "https://wallet-fake.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await SeedHarvestCheck().run(ctx)
    assert ctx.findings, "debe detectar el formulario que pide la semilla"
    assert ctx.findings[0].check == "seed_harvest"
    assert ctx.findings[0].severity.value == "critico"


async def test_dex_rpc_detecta_chainid_incorrecto():
    from zhack.checks.active.dex_rpc import DexRpcCheck
    from zhack.core.http_client import FetchResult

    router = "0x1111111111111111111111111111111111111111"
    html = f"""
    <html><body><script>
      const routerAddress = "{router}";
      const rpcUrl = "/rpc";
      const chainId = 1;
      const swap = {{ amountOutMin: 100, tokenOut: "0x2222222222222222222222222222222222222222" }};
    </script></body></html>
    """

    class FakeCtx:
        url = "https://dex.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            if "eth_chainId" in url:
                body = '{"jsonrpc":"2.0","id":1,"result":"0x89"}'
            else:
                body = '{"jsonrpc":"2.0","id":1,"result":"0x600580600b6000396000f3"}'
            return FetchResult(url=url, status=200, body=body.encode())

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await DexRpcCheck().run(ctx)
    assert any(
        f.check == "dex_rpc" and "chainid" in f.title.lower() for f in ctx.findings
    ), "debe detectar el chainId del frontend distinto al del RPC"


async def test_endpoint_exposure_detecta_introspeccion_graphql(server):
    opts = ScanOptions(timeout=10, concurrency=20, active=False)
    result = await deep_scan(server + "/", opts)
    titles = [f.title.lower() for f in result.findings if f.check == "endpoint_exposure"]
    assert any("introspección" in t for t in titles), "debe detectar introspección GraphQL habilitada"


async def test_reporte_en_ingles_contiene_riesgo_y_ejemplo_criminal(server):
    from zhack.reporting.en_report import build_en_markdown

    opts = ScanOptions(timeout=10, concurrency=20, active=True)
    result = await deep_scan(server + "/dapp", opts)
    md = build_en_markdown([result])
    assert "# ZHack Security Assessment Report" in md
    assert "## Executive summary" in md
    assert "**What is the bug?**" in md
    assert "**What the company risks if it is not fixed**" in md
    assert "**How a criminal could exploit it**" in md
    assert "**Recommended fix**" in md
    assert "Blind signing enabled (eth_sign)" in md
    assert "ZH-001" in md
    assert "CWE" in md


async def test_pagina_segura_no_genera_falsos_positivos(server):
    opts = ScanOptions(timeout=10, concurrency=10, mass=True, active=False)
    results = await mass_scan([server + "/safe"], opts)
    r = results[0]
    headers_check = {f.check for f in r.findings}
    assert "security_headers" not in headers_check, "/safe tiene todas las cabeceras correctas"
    assert "cookies" not in headers_check, "/safe no envía cookies"
    assert "sri" not in headers_check, "/safe no carga recursos externos"
    assert "cdn" not in headers_check, "/safe no revela CDN"
    assert "contract_exposure" not in headers_check, "/safe no expone contratos ni configs"
    assert "cache_control" not in headers_check, "/safe no establece cookies de sesión"
    assert "form_security" not in headers_check, "/safe no contiene formularios"
    assert "robots_disclosure" not in headers_check, "/safe no revela robots.txt"
    assert "dom_xss" not in headers_check, "/safe no contiene JavaScript"
    assert "wallet_security" not in headers_check, "/safe no contiene patrones de wallet"
    assert "web3_supply_chain" not in headers_check, "/safe no carga librerías Web3"
    assert "bucket_exposure" not in headers_check, "/safe no referencia buckets"
    assert "seed_harvest" not in headers_check, "/safe no pide semillas"


async def test_dns_sec_detecta_falta_de_spf_y_dmarc(monkeypatch):
    from zhack.checks.passive.dns_sec import DnsSecurityCheck
    from zhack.core.http_client import FetchResult

    class FakeCtx:
        url = "https://example.com/"

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=b"<html></html>")

        def __init__(self):
            self.findings = []

        def add(self, finding):
            self.findings.append(finding)

    async def fake_txt(self, ctx, name):
        if name.startswith("_dmarc"):
            return []
        return ["v=spf1 -all"]

    monkeypatch.setattr(DnsSecurityCheck, "_txt", fake_txt)
    ctx = FakeCtx()
    await DnsSecurityCheck().run(ctx)
    checks = {f.check for f in ctx.findings}
    assert "dns_sec" in checks, "debería detectar la falta de DMARC"
    titles = {f.title for f in ctx.findings}
    assert any("SPF" not in t for t in titles), "SPF existe, no debe avisar de SPF"
    assert any("DMARC" in t for t in titles), "debe avisar de la falta de DMARC"


async def test_targets_loader():
    from zhack.core.targets import normalize_url

    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("http://x.com/path") == "http://x.com/path"
    assert normalize_url("http://x.com/search?q=1") == "http://x.com/search?q=1"
    assert normalize_url("ftp://x.com/file") == ""
    assert normalize_url("  ") == ""
