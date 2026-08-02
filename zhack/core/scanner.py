from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Callable, Iterable, List, Optional

from zhack.checks import build_checks
from zhack.core.context import ScanContext, ScanOptions
from zhack.core.crawler import extract_candidate_urls, extract_forms
from zhack.core.http_client import HttpClient
from zhack.core.models import TargetResult
from zhack.core.targets import normalize_url


async def _run_check(check, ctx: ScanContext) -> None:
    try:
        await check.run(ctx)
    except Exception as e:  # un check nunca debe tumbar el escaneo
        ctx.result.errors.append(f"{check.name}: {type(e).__name__}: {e}")


async def deep_scan(url: str, opts: ScanOptions) -> TargetResult:
    """Escaneo profundo de una web (pasivo + activo si opts.active)."""
    result = TargetResult(url=url)
    async with HttpClient(
        timeout=opts.timeout,
        global_concurrency=opts.concurrency,
        max_body=opts.max_body,
        custom_headers=opts.custom_headers,
    ) as http:
        ctx = ScanContext(url, http, opts, result)
        if opts.active:
            main = await ctx.get_main()
            if main.body:
                ctx.candidates = [url] + extract_candidate_urls(url, main.text)
                ctx.forms = extract_forms(main.text)
        checks = build_checks(active=opts.active, mass=False)
        await asyncio.gather(*[_run_check(c, ctx) for c in checks])
    return result


async def mass_scan(
    targets: List[str],
    opts: ScanOptions,
    on_target_done: Optional[Callable[[TargetResult], None]] = None,
) -> List[TargetResult]:
    """Escaneo masivo: una web por objetivo, checks pasivos, alta concurrencia."""
    sem = asyncio.Semaphore(opts.concurrency)

    async def worker(url: str) -> TargetResult:
        async with sem:
            result = TargetResult(url=url)
            try:
                async with HttpClient(
                    timeout=opts.timeout,
                    global_concurrency=opts.concurrency,
                    max_body=opts.max_body,
                    custom_headers=opts.custom_headers,
                ) as http:
                    ctx = ScanContext(url, http, opts, result)
                    checks = build_checks(active=False, mass=True)
                    await asyncio.gather(*[_run_check(c, ctx) for c in checks])
            except Exception as e:
                result.errors.append(f"scan: {type(e).__name__}: {e}")
            if on_target_done:
                on_target_done(result)
            return result

    return list(await asyncio.gather(*[worker(u) for u in targets]))


async def batch_scan(
    targets: List[str],
    opts: ScanOptions,
    on_target_done: Optional[Callable[[TargetResult], None]] = None,
) -> List[TargetResult]:
    """Escaneo profundo por lotes: deep scan + activos contra múltiples webs."""
    sem = asyncio.Semaphore(opts.concurrency)

    async def worker(url: str) -> TargetResult:
        async with sem:
            result = TargetResult(url=url)
            try:
                async with HttpClient(
                    timeout=opts.timeout,
                    global_concurrency=opts.concurrency,
                    max_body=opts.max_body,
                    custom_headers=opts.custom_headers,
                ) as http:
                    ctx = ScanContext(url, http, opts, result)
                    main = await ctx.get_main()
                    if main.body:
                        ctx.candidates = [url] + extract_candidate_urls(url, main.text)
                        ctx.forms = extract_forms(main.text)
                    checks = build_checks(active=opts.active, mass=False)
                    await asyncio.gather(*[_run_check(c, ctx) for c in checks])
            except Exception as e:
                result.errors.append(f"batch_scan: {type(e).__name__}: {e}")
            if on_target_done:
                on_target_done(result)
            return result

    return list(await asyncio.gather(*[worker(u) for u in targets]))


async def scan_all(
    targets: Iterable[str],
    opts: Optional[ScanOptions] = None,
    on_target_done: Optional[Callable[[TargetResult], None]] = None,
) -> List[TargetResult]:
    """Ejecuta todos los checks sobre una lista de webs.

    Es la API principal para integraciones: normaliza y deduplica los objetivos,
    activa los checks pasivos y los activos inofensivos, y devuelve un resultado
    independiente por web. `opts` es opcional para ajustar timeout, concurrencia,
    TLS o headers sin cambiar el comportamiento de "todos los checks".
    """
    prepared: List[str] = []
    seen: set[str] = set()
    for target in targets:
        normalized = normalize_url(str(target))
        if normalized and normalized not in seen:
            seen.add(normalized)
            prepared.append(normalized)

    if not prepared:
        return []

    options = replace(opts, active=True, mass=False) if opts else ScanOptions(active=True, mass=False)
    return await batch_scan(prepared, options, on_target_done=on_target_done)


def scan_all_sync(
    targets: Iterable[str],
    opts: Optional[ScanOptions] = None,
    on_target_done: Optional[Callable[[TargetResult], None]] = None,
) -> List[TargetResult]:
    """Versión síncrona de :func:`scan_all` para scripts sencillos."""
    return asyncio.run(scan_all(targets, opts=opts, on_target_done=on_target_done))
