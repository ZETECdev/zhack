"""Tests de ZHack contra el servidor local deliberadamente vulnerable."""

import asyncio
import socket
import base64

import pytest
from aiohttp import web

from zhack import scan_all
from zhack.checks import build_checks
from zhack.core.context import ScanContext, ScanOptions
from zhack.core.scanner import deep_scan, mass_scan
from zhack.core.http_client import FetchResult, HttpClient
from zhack.core.models import TargetResult
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
        assert "host_header" not in checks, "host_header es activo, no debe ejecutarse en mass"
    assert "csrf" in {f.check for f in results[0].findings}, "CSRF es pasivo y debe funcionar en mass"


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


async def test_checks_dex_detectan_slippage_allowance_permit_y_router_sin_bytecode(tmp_path):
    from zhack.checks.active.dex_rpc import DexRpcCheck
    from zhack.checks.passive.dex_security import DexSecurityCheck
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
    csv_path = tmp_path / "test_dex_finding.csv"
    write_csv([TargetResult(url=ctx.url, findings=[finding])], str(csv_path))
    with csv_path.open(encoding="utf-8") as csv_file:
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


async def test_crawler_no_sale_del_mismo_host_a_otro_puerto():
    from zhack.core.crawler import extract_candidate_urls, extract_forms

    html = '<a href="/ok">ok</a><a href="http://example.com:8443/admin">other</a>'
    found = extract_candidate_urls("http://example.com:8080/", html)
    assert found == ["http://example.com:8080/ok"]
    forms = extract_forms('<form action=/save method=post><textarea name=callback_url></textarea><select name="role"></select></form>')
    assert forms == [("/save", "POST", ["callback_url", "role"])]


async def test_nuevos_checks_pasivos_detectan_jwt_oauth_upload_y_ssrf():
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1234567890"}').decode().rstrip("=")
    html = f"""
    <html><body>
      <script>
        const token = "{header}.{payload}.unsignedsig";
        const oauth = "/oauth/authorize?response_type=token&client_id=demo";
        const access_token = window.location.hash;
      </script>
      <form action="/upload" method="POST">
        <input type="file" name="document">
      </form>
      <form action="/fetch" method="GET">
        <input name="callback_url">
      </form>
    </body></html>
    """

    class FakeCtx:
        url = "https://app.example/login"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        async def fetch(self, method, url, headers=None):
            return FetchResult(url=url, status=404, body=b"")

        def add(self, finding):
            self.findings.append(finding)

    from zhack.checks.passive.jwt_oauth import JwtOAuthCheck
    from zhack.checks.passive.ssrf_hints import SsrfHintsCheck
    from zhack.checks.passive.upload_surface import UploadSurfaceCheck

    ctx = FakeCtx()
    await JwtOAuthCheck().run(ctx)
    titles = " ".join(f.title.lower() for f in ctx.findings)
    assert "algoritmo none" in titles
    assert "flujo implícito" in titles
    assert "location.hash" in titles

    ctx = FakeCtx()
    await UploadSurfaceCheck().run(ctx)
    assert any(f.check == "upload_surface" and f.severity.value == "medio" for f in ctx.findings)
    assert all(f.manual_review for f in ctx.findings)

    ctx = FakeCtx()
    await SsrfHintsCheck().run(ctx)
    assert ctx.findings and ctx.findings[0].check == "ssrf_hints"
    assert ctx.findings[0].manual_review
    assert ctx.findings[0].confidence == "baja"


async def test_nuevos_checks_estan_registrados_y_no_se_ejecutan_en_mass_como_activos():
    mass_names = {check.name for check in build_checks(mass=True, active=False)}
    assert {"jwt_oauth", "upload_surface", "ssrf_hints"} <= mass_names
    assert "sqli" not in mass_names
    assert "xss" not in mass_names


async def test_todos_los_checks_tienen_guidance_y_advisory():
    from zhack.checks.english_guidance import _GUIDANCE
    from zhack.reporting.en_advisories import advisory_for

    for check in build_checks(active=True, mass=False):
        assert check.name in _GUIDANCE, f"falta guidance para {check.name}"
        assert advisory_for(check.name, "hallazgo").title != "Security weakness detected", (
            f"falta advisory específico para {check.name}"
        )


async def test_host_header_detecta_reflexion_sin_seguir_redirects():
    from zhack.checks.active.host_header import HostHeaderCheck

    class FakeHttp:
        def __init__(self):
            self.calls = []

        async def fetch(self, method, url, headers=None, allow_redirects=True):
            self.calls.append((method, url, headers, allow_redirects))
            return FetchResult(
                url=url,
                status=302,
                headers={"location": "https://zhack-host-probe.example/reset"},
            )

    class FakeCtx:
        url = "https://app.example/"
        candidates = [url]

        def __init__(self):
            self.http = FakeHttp()
            self.findings = []

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await HostHeaderCheck().run(ctx)
    assert ctx.findings and ctx.findings[0].check == "host_header"
    assert ctx.findings[0].severity.value == "alto"
    assert ctx.http.calls[0][0] == "GET"
    assert ctx.http.calls[0][3] is False


async def test_evidencia_y_urls_redactan_secretos():
    from zhack.checks.passive.secret_scan import SecretScanCheck
    from zhack.reporting.json_report import result_to_dict

    secret = "sk_live_" + "51HZaXxExampleTestKey123456"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234"
    html = f'<script>const apiKey = "{secret}"; const token = "{jwt}";</script>'

    class FakeCtx:
        url = "https://app.example/?token=real-secret"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(url=self.url, status=200, body=html.encode())

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await SecretScanCheck().run(ctx)
    assert ctx.findings
    serialized = str(result_to_dict(TargetResult(url=ctx.url, findings=ctx.findings)))
    assert secret not in serialized
    assert jwt not in serialized
    assert "<REDACTED" in serialized


async def test_context_fetch_acepta_url_sin_repetir_method():
    class FakeHttp:
        def __init__(self):
            self.calls = []

        async def fetch(self, method, url, headers=None):
            self.calls.append((method, url, headers))
            return FetchResult(url=url, status=200, body=b"ok")

    http = FakeHttp()
    ctx = ScanContext(
        "https://app.example/login",
        http,
        ScanOptions(),
        TargetResult(url="https://app.example/login"),
    )
    result = await ctx.fetch("https://app.example/profile")
    assert result.ok
    assert http.calls == [("GET", "https://app.example/profile", None)]


async def test_http_client_no_reenvia_headers_sensibles_a_otro_host():
    client = HttpClient(
        custom_headers={
            "Authorization": "Bearer secret",
            "Cookie": "session=secret",
            "X-Internal-Secret": "secret",
        },
        target_url="https://app.example/login",
    )
    same = client._headers_for("https://app.example/api", None)
    external = client._headers_for("https://cdn.example/assets.js", {"Origin": "https://evil.example"})
    assert same["Authorization"] == "Bearer secret"
    assert same["Cookie"] == "session=secret"
    assert "Authorization" not in client._headers_for("http://app.example/api", None)
    assert "Authorization" not in external
    assert "Cookie" not in external
    assert "X-Internal-Secret" not in external
    assert external["Origin"] == "https://evil.example"


async def test_http_client_comparte_limitador_por_host_entre_clientes():
    shared_hosts = {}
    shared_lock = asyncio.Lock()
    first = HttpClient(shared_host_sems=shared_hosts, shared_host_lock=shared_lock)
    second = HttpClient(shared_host_sems=shared_hosts, shared_host_lock=shared_lock)
    first_sem = await first._host_sem("example.com:443")
    second_sem = await second._host_sem("example.com:443")
    other_sem = await second._host_sem("example.com:8443")
    assert first._host_sems is shared_hosts
    assert second._host_sems is shared_hosts
    assert first_sem is second_sem
    assert other_sem is not first_sem


async def test_csp_frame_ancestors_sustituye_x_frame_options():
    from zhack.checks.passive.headers import SecurityHeadersCheck

    class FakeCtx:
        url = "https://app.example/"

        def __init__(self):
            self.findings = []

        async def get_main(self):
            return FetchResult(
                url=self.url,
                status=200,
                headers={
                    "content-security-policy": "default-src 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'",
                    "strict-transport-security": "max-age=31536000",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin",
                    "permissions-policy": "camera=(), microphone=(), geolocation=()",
                },
                body=b"ok",
            )

        def add(self, finding):
            self.findings.append(finding)

    ctx = FakeCtx()
    await SecurityHeadersCheck().run(ctx)
    titles = " ".join(f.title for f in ctx.findings)
    assert "Falta X-Frame-Options" not in titles
    assert "unsafe-inline" not in titles


async def test_tls_inspecciona_certificado_binario_y_wildcards(monkeypatch):
    from zhack.core.tls import _hostname_matches, check_tls

    cert = {"subjectAltName": (("DNS", "*.example.com"),)}
    assert _hostname_matches("app.example.com", cert)
    assert not _hostname_matches("deep.app.example.com", cert)

    class FakeSSL:
        def version(self):
            return "TLSv1.2"

        def getpeercert(self, binary_form=False):
            return b"" if binary_form else {}

    class FakeWriter:
        def get_extra_info(self, name):
            return FakeSSL() if name == "ssl_object" else None

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(*args, **kwargs):
        return None, FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    report = await check_tls("example.com", 443, timeout=1)
    assert report.version == "TLSv1.2"
    assert not report.insecure_version


async def test_redirects_tls_y_host_scope():
    assert HttpClient._allowed_redirect("http://app.example/", "https://app.example/")
    assert HttpClient._allowed_redirect("https://app.example/a", "https://app.example/b")
    assert not HttpClient._allowed_redirect("https://app.example/", "http://app.example/")
    assert not HttpClient._allowed_redirect("https://app.example/", "https://cdn.example/")
    assert not HttpClient._allowed_redirect("https://app.example/", "https://app.example:8443/")


async def test_http_client_bloquea_redirect_externo_y_conserva_header_en_mismo_host():
    external_seen = []
    same_host_seen = []

    async def external_capture(request):
        external_seen.append(request.headers.get("Authorization"))
        return web.Response(text="external")

    external_app = web.Application()
    external_app.router.add_get("/capture", external_capture)
    external_runner = web.AppRunner(external_app)
    await external_runner.setup()
    external_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    external_socket.bind(("127.0.0.1", 0))
    external_port = external_socket.getsockname()[1]
    external_socket.close()
    external_site = web.TCPSite(external_runner, "127.0.0.1", external_port)
    await external_site.start()

    async def external_redirect(request):
        return web.Response(status=302, headers={"Location": f"http://127.0.0.1:{external_port}/capture"})

    async def same_capture(request):
        same_host_seen.append(request.headers.get("Authorization"))
        return web.Response(text="same-host")

    async def same_redirect(request):
        return web.Response(status=302, headers={"Location": "/capture"})

    target_app = web.Application()
    target_app.router.add_get("/external", external_redirect)
    target_app.router.add_get("/same", same_redirect)
    target_app.router.add_get("/capture", same_capture)
    target_runner = web.AppRunner(target_app)
    await target_runner.setup()
    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_socket.bind(("127.0.0.1", 0))
    target_port = target_socket.getsockname()[1]
    target_socket.close()
    target_site = web.TCPSite(target_runner, "127.0.0.1", target_port)
    await target_site.start()

    try:
        target = f"http://127.0.0.1:{target_port}/"
        async with HttpClient(
            timeout=2,
            retries=0,
            target_url=target,
            custom_headers={"Authorization": "Bearer test-secret"},
        ) as client:
            external = await client.fetch("GET", target + "external")
            same = await client.fetch("GET", target + "same")
        assert external.status == 302
        assert external.final_url == target + "external"
        assert external_seen == []
        assert same.status == 200
        assert same_host_seen == ["Bearer test-secret"]
    finally:
        await target_runner.cleanup()
        await external_runner.cleanup()
