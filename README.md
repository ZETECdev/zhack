# ZHack — Escáner de seguridad web

Escáner de seguridad web en Python con **dos modos**:

- **`mass`** — escanea **miles de webs** a la vez (concurrencia asíncrona) con checks pasivos rápidos.
- **`deep`** — escaneo profundo de una web con checks pasivos + detección activa inofensiva.
- **`batch`** — escaneo profundo (todos los checks, pasivos + activos) contra una lista de webs.
- **`run_all.py`** — archivo principal: ejecuta **todos los checks** contra una lista de webs y consolida reportes (JSON + HTML + opcional CSV).

Genera reportes **HTML** (con severidades y cómo reparar cada fallo) y **JSON** (datos crudos).

> ⚠️ **Aviso legal:** ZHack solo debe usarse sobre webs que **TÚ posees** o sobre las que tienes **autorización escrita**. Escanear webs de terceros sin permiso puede ser ilegal en tu país. Esta es una herramienta de defensa, no de ataque.

## Instalación

```bash
cd D:\DEV\ZHack
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Uso

```bash
# Escaneo masivo de una lista de webs (checks pasivos, rápido)
python -m zhack mass targets.txt -y

# Escaneo profundo (pasivo)
python -m zhack deep https://miweb.com -y

# Escaneo profundo CON detección activa (SQLi/XSS/traversal/CORS — siempre inofensiva)
python -m zhack deep https://miweb.com --active -y

# TODO el arsenal contra una lista de webs (pasivo + activo, reporte consolidado)
python run_all.py targets.txt -y --csv

# Ver un reporte generado
python -m zhack report reports\zhack_mass_20260801_120000.json --open
```

Opciones útiles:

- `-c 200` — concurrencia del escaneo masivo (por defecto 100).
- `-t 5` — timeout por petición en segundos.
- `--no-tls` — omite los checks TLS (más rápido).
- `-o carpeta` — dónde guardar los reportes (por defecto `reports/`).
- `--csv` — exporta también los hallazgos a CSV (útil para triage en Excel).
- `--header "Authorization: Bearer xxx"` — header HTTP para todas las peticiones (repetible). Útil para zonas autenticadas.
- `--cookie "session=abc123"` — cookie de sesión para todas las peticiones.
- `--no-active` (solo `run_all.py`) — equivale al modo `mass` (solo pasivos).
- Sin `-y` se muestra la confirmación de autorización antes de escanear.

También puedes instalar el comando global: `pip install -e .` y usar `zhack mass ...` directamente.

## API principal

Para integrar ZHack en otro programa, basta con pasar una lista. `scan_all` normaliza URLs,
elimina duplicados y ejecuta siempre todos los checks, incluidos los activos inofensivos:

```python
from zhack import scan_all

resultados = await scan_all([
    "https://miweb.com",
    "https://otra-web.com/login",
])

for resultado in resultados:
    print(resultado.url, resultado.max_severity, len(resultado.findings))
```

En un script síncrono puede usarse `from zhack import scan_all_sync`.
Opcionalmente se puede pasar `ScanOptions` como segundo argumento para cambiar timeout,
concurrencia, headers, cookies o desactivar TLS sin desactivar el conjunto de checks.

## Probar sin riesgo (servidor vulnerable local)

ZHack incluye un servidor local **deliberadamente vulnerable** para que pruebes todo sin tocar webs reales:

```bash
# Terminal 1: arranca el servidor vulnerable
python tests\vuln_server.py --port 8070

# Terminal 2: escanéalo
python -m zhack deep http://127.0.0.1:8070 --active -y
```

Verás detectados: `.env`/`.git`/backups expuestos, SQLi, XSS reflejado, redirección abierta, path traversal, CORS mal configurado, cabeceras ausentes, cookies sin flags y más.

## Checks incluidos

| Check | Modo | Severidad típica |
|---|---|---|
| HTTP sin redirección a HTTPS | mass + deep | alto |
| TLS < 1.2 / SSLv3 | mass + deep | alto |
| Certificado caducado / autofirmado / hostname incorrecto | mass + deep | crítico/alto |
| Cabeceras ausentes (CSP, HSTS, X-Frame-Options, nosniff...) | mass + deep | medio/bajo |
| Cookies sin Secure / HttpOnly / SameSite explícito | mass + deep | medio/alto |
| Respuestas con cookies de sesión sin protección de caché | mass + deep | bajo/medio |
| Archivos expuestos (`.env`, `.git`, backups, `phpinfo`, volcados SQL...) | mass + deep | crítico |
| Listado de directorios | mass + deep | medio |
| Versión de servidor / tecnología revelada | mass + deep | bajo |
| Trazas de error / stack traces | mass + deep | alto |
| Secretos en frontend (AWS, Stripe, GitHub, Infura, Alchemy, claves privadas, mnemónicos...) | mass + deep | crítico/alto |
| Endpoints expuestos (Swagger, OpenAPI, GraphQL, source maps, paneles admin) | mass + deep | medio/info |
| Recursos de CDN sin SRI (`integrity`) — riesgo de supply chain | mass + deep | bajo |
| SPF / DMARC ausentes (anti suplantación de email) | mass + deep | medio |
| CDN/WAF frontal identificado (reconocimiento) | mass + deep | info |
| Contratos / block explorers / configs Web3 (Hardhat, Foundry...) expuestos | mass + deep | bajo/info |
| Contenido mixto (recursos HTTP en HTTPS) | mass + deep | medio |
| Formularios POST sin token CSRF | mass + deep | medio |
| Formularios de contraseña enviados por HTTP | mass + deep | alto |
| Rutas internas sensibles reveladas en `robots.txt` | mass + deep | info |
| Posible DOM XSS (fuente controlable + sink peligroso) | mass + deep | medio |
| JWT con `alg=none`, OAuth implícito o tokens en `location.hash` | mass + deep | alto/medio |
| Formularios de subida sin transporte/enctype/restricciones declaradas | mass + deep | alto/medio/bajo |
| Parámetros URL/callback/webhook con posible SSRF (solo heurística) | mass + deep | medio |
| Riesgos DEX: `amountOutMin=0`, slippage extrema, approvals ilimitadas y `permit` sin expiración | mass + deep | alto |
| Patrones peligrosos en Solidity expuesto (`tx.origin`, `selfdestruct`, `delegatecall`, reentrancia, oracle spot) | mass + deep | alto/crítico |
| Inyección SQL (detección) | deep `--active` | crítico |
| XSS reflejado (detección) | deep `--active` | alto |
| Redirección abierta | deep `--active` | medio |
| Path traversal | deep `--active` | crítico |
| CORS mal configurado | deep `--active` | alto/medio |
| Host header reflejado en redirects o contenido | deep `--active` | alto/medio |
| Métodos HTTP peligrosos (TRACE, PUT, DELETE) | deep `--active` | alto/medio |
| Endpoints RPC con CORS mal configurado / acceso público | deep `--active` | alto/medio |
| Nodos RPC públicos accesibles y métodos JSON-RPC expuestos (`eth_accounts`, etc.) | deep `--active` | alto/info |
| Router/factory/vault DEX sin bytecode en el RPC configurado | deep `--active` | alto |

## Garantías de seguridad del propio escáner

- **Solo peticiones de LECTURA** (`GET`/`HEAD`/`OPTIONS`). Jamás escribe, borra ni modifica nada en una web.
- **Payloads activos inofensivos**: solo detección (comillas, marcadores de texto). Nunca `UPDATE`/`DELETE`/`DROP`, nunca stacked queries, nunca código que se ejecute en la víctima.
- **Checks DEX sin mutaciones**: `dex_rpc` solo consulta `eth_getCode` mediante `GET`; no firma transacciones ni llama métodos que cambien estado.
- **Límites de concurrencia** por host (5 peticiones simultáneas) y global, compartidos entre objetivos del mismo escaneo, con timeouts: no satura las webs escaneadas.
- **Headers autenticados aislados**: cookies, `Authorization` y API keys no se envían a scripts, CDNs, buckets, RPCs ni redirects de otros hosts.
- **Redirects acotados**: solo se siguen redirects del mismo host, además del upgrade HTTP→HTTPS; nunca se sigue una degradación HTTPS→HTTP ni un salto a otro host.
- **Evidencia redactada**: tokens, JWT, claves privadas, AWS keys y valores sensibles en URLs se ocultan antes de escribir JSON, HTML, Markdown o CSV.
- Cada hallazgo incluye **confianza** y marca de **revisión manual** cuando es una heurística estática.
- Confirmación de autorización obligatoria al arrancar.

Los checks DEX son análisis de superficie y heurísticas. Pueden descubrir configuraciones frontend peligrosas,
direcciones equivocadas y fuentes Solidity expuestas, pero no sustituyen una auditoría formal del contrato,
pruebas con fuzzing ni una revisión on-chain de permisos, proxies, oráculos y economía del protocolo.

## Estructura

```
zhack/
├── cli.py                  # interfaz de comandos
├── core/                   # http client async, TLS, targets, crawler, scanner
├── checks/
│   ├── passive/            # solo lectura de respuestas
│   └── active/             # detección inofensiva (solo deep --active)
└── reporting/              # reportes HTML, JSON y CSV
run_all.py                  # ejecuta todos los checks sobre una lista de webs
tests/vuln_server.py        # servidor vulnerable para pruebas
tests/test_zhack.py         # tests (pytest)
```

## Ejecutar los tests

```bash
python -m pytest tests -v
```

La suite incluye servidor vulnerable local, página segura, checks Web3, GraphQL/RPC,
redacción de secretos, TLS simulado, redirects cross-host y aislamiento de headers.

## Reparación

Cada hallazgo del reporte incluye una columna **"Cómo repararlo"** con el paso concreto (ej.: añadir tal cabecera, activar prepared statements, bloquear `/.git`). Corrige primero lo **crítico** (credenciales expuestas, SQLi, certificados caducados), rota secretos y vuelve a escanear para verificar.
