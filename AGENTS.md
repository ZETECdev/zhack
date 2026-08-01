# AGENTS.md

ZHack: async Python (3.10+) web security scanner. Two modes: `mass` (many targets, passive checks only) and `deep` (one site; active detection only with `--active`). CLI lives in `zhack/cli.py`; no linter/typechecker is configured — **pytest is the only verification** (`python -m pytest tests -v`). The suite is fast and needs no external network (see tests).

## Commands

```bash
pip install -r requirements.txt        # deps; or: pip install -e . for the `zhack` console script
python -m pytest tests -v              # run all tests (also works via zhack.bat on Windows)
python -m zhack mass targets.txt -y    # mass scan; -y skips the authorization prompt
python -m zhack deep <url> --active -y # deep scan with active checks
python -m zhack batch targets.txt -y   # batch: deep+active against a list of targets
python run_all.py targets.txt -y --csv # all checks (passive+active), consolidated report + CSV
```

`pyproject.toml` sets `asyncio_mode = "auto"` for pytest-asyncio — async tests need no decorators (though `pytestmark = pytest.mark.asyncio` is used in `tests/test_zhack.py`).

## Adding a check

Checks subclass `BaseCheck` (`zhack/checks/base.py`) with class attrs `name`, `mass` (runs in mass mode) and `requires_active` (runs only with `deep --active`). Files go in `zhack/checks/passive/` or `zhack/checks/active/`, **and must be registered manually** in `_ALL_CHECK_CLASSES` in `zhack/checks/__init__.py` — unregistered checks silently never run. Checks share one `ScanContext` (see `zhack/core/context.py`); use `ctx.fetch(url)` (cached, prefer this for repeated GETs), `ctx.http.fetch(...)` (uncached, for custom headers/methods) or `ctx.get_main()` (cached main page). A throwing check only records an error, never aborts the scan.

## Hard constraints (enforced by tests)

- `HttpClient` (`zhack/core/http_client.py`) refuses any method outside `READ_ONLY_METHODS` (`GET`/`HEAD`/`OPTIONS`) — never add mutating requests.
- Active payloads must be harmless detection only (quotes/markers that trigger error responses — see `checks/active/sqli.py`). No `UPDATE`/`DELETE`/`DROP`, no stacked queries, no code execution. `test_checks_activos_no_pasan_a_mass` asserts active checks never fire in mass mode.
- Don't remove the per-host (5) / global semaphores or timeouts — they're an explicit design guarantee.

## Test gotchas

- Tests scan an **in-process deliberately vulnerable server** (`tests/vuln_server.py` `build_app()` on a random port) — no external target required. Use it to reproduce findings.
- `test_deep_scan_encuentra_vulnerabilidades` pins check `name` values (`https`, `security_headers`, `cookies`, `exposed_files`, `info_disclosure`, `sqli`, `xss`, `open_redirect`, `traversal`, `cors`, `http_methods`, `csrf`, `secret_scan`, `endpoint_exposure`, `rpc_cors`, `sri`, `cdn`, `contract_exposure`, `rpc_methods`); renaming a check breaks tests. `test_pagina_segura_no_genera_falsos_positivos` requires the `/safe` route to produce zero findings — keep it clean (no scripts, no forms, no secrets, no CDN headers, no external resources in `/safe`).
- `dns_sec` needs external DNS (DoH to cloudflare-dns.com) and skips IP/localhost targets; it's unit-tested in `test_dns_sec_detecta_falta_de_spf_y_dmarc` via a monkeypatched `_txt` (no network in the suite).
- `normalize_url` semantics are pinned by `test_targets_loader` (bare domain → `https://<domain>/`).

## Conventions

- All user-facing strings, docstrings, and report content are in **Spanish**; new code should match.
- Findings are created via `BaseCheck.make()` (truncates evidence to 400 chars).
- Reports are written to `reports/` (gitignored) as timestamped `zhack_{mode}_{stamp}.json` + `.html`.
