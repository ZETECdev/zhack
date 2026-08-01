from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from zhack.core.context import ScanOptions
from zhack.core.models import Severity, TargetResult
from zhack.core.scanner import batch_scan, deep_scan, mass_scan
from zhack.core.targets import load_targets, normalize_url
from zhack.reporting.html_report import build_html
from zhack.reporting.json_report import write_json

console = Console()

_SEV_LABELS = {
    "critico": "criticas",
    "alto": "altas",
    "medio": "medias",
    "bajo": "bajas",
    "info": "informativas",
}


def _confirm_authorization() -> bool:
    console.print(
        Panel(
            "[bold red]AVISO LEGAL[/bold red]\n\n"
            "ZHack solo debe usarse sobre webs que [bold]TÚ posees[/bold] o sobre las que tienes\n"
            "[bold]autorización escrita[/bold]. Escanear webs de terceros sin permiso puede ser\n"
            "ilegal en tu país (acceso indebido / hacking).\n\n"
            "ZHack es una herramienta de DEFENSA: solo hace peticiones de lectura\n"
            "(GET/HEAD/OPTIONS) y [bold]jamás modifica ni daña una web[/bold].",
            title="ZHack",
            border_style="red",
        )
    )
    try:
        ans = input("¿Confirmas que tienes autorización para escanear estos objetivos? (s/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("s", "si", "sí", "y", "yes")


def _save(results, mode: str, output: str):
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"zhack_{mode}_{stamp}"
    write_json(results, str(base) + ".json")
    with open(str(base) + ".html", "w", encoding="utf-8") as fh:
        fh.write(build_html(results))
    console.print(f"[green]Reporte JSON:[/green] {base}.json")
    console.print(f"[green]Reporte HTML:[/green] {base}.html")


def _summary_table(results) -> None:
    counts = {s: 0 for s in Severity}
    ok = 0
    for r in results:
        if r.max_severity:
            counts[r.max_severity] += 1
        else:
            ok += 1
    table = Table(title=f"Sitios escaneados: {len(results)}")
    table.add_column("Peor severidad", style="bold")
    table.add_column("Sitios")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        table.add_row(sev.value, str(counts[sev]))
    table.add_row("Sin hallazgos", str(ok))
    console.print(table)


def _findings_table(results) -> None:
    ordered = sorted(
        results,
        key=lambda r: (r.max_severity.score if r.max_severity else 0),
        reverse=True,
    )
    for r in ordered:
        if not r.findings and not r.errors:
            continue
        worst = r.max_severity.value if r.max_severity else "ninguno"
        console.print(Panel(f"[bold]{r.url}[/bold]  ·  peor severidad: {worst}", border_style="yellow"))
        if r.errors:
            console.print("[red]  errores:[/red] " + "; ".join(r.errors[:5]))
        table = Table(box=None)
        table.add_column("Sev", width=9, style="bold")
        table.add_column("Check", width=18)
        table.add_column("Hallazgo")
        for f in sorted(r.findings, key=lambda f: f.severity.score, reverse=True):
            table.add_row(f.severity.value, f.check, f.title)
        console.print(table)
        console.print()


def cmd_mass(args) -> None:
    if not args.yes and not _confirm_authorization():
        console.print("[red]Cancelado: se requiere autorización para escanear.[/red]")
        sys.exit(1)
    targets = load_targets(args.targets)
    if not targets:
        console.print("[red]No se cargaron objetivos. Revisa el archivo.[/red]")
        sys.exit(1)
    console.print(
        f"[bold cyan]Escaneo masivo de {len(targets)} webs[/bold cyan] "
        f"(concurrencia {args.concurrency}, timeout {args.timeout}s)"
    )
    opts = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        mass=True,
        active=False,
        check_tls=not args.no_tls,
    )
    t0 = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("{task.fields[status]}"),
    ) as progress:
        task = progress.add_task("Escaneando...", total=len(targets), status="")

        def on_done(r: TargetResult) -> None:
            status = r.max_severity.value if r.max_severity else "ok"
            progress.update(task, advance=1, status=f"[{status}] {r.url[:40]}")

        results = asyncio.run(mass_scan(targets, opts, on_target_done=on_done))
        progress.update(task, refresh=True)

    elapsed = time.time() - t0
    _summary_table(results)
    _save(results, "mass", args.output)
    console.print(f"[green]Escaneo terminado en {elapsed:.1f}s.[/green]")


def cmd_deep(args) -> None:
    if not args.yes and not _confirm_authorization():
        console.print("[red]Cancelado: se requiere autorización para escanear.[/red]")
        sys.exit(1)
    url = normalize_url(args.url)
    if not url:
        console.print(f"[red]URL inválida: {args.url}[/red]")
        sys.exit(1)
    mode = "activo" if args.active else "pasivo"
    console.print(f"[bold cyan]Escaneo profundo ({mode}) de {url}[/bold cyan]")
    opts = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        active=args.active,
        mass=False,
        check_tls=not args.no_tls,
    )
    t0 = time.time()
    result = asyncio.run(deep_scan(url, opts))
    elapsed = time.time() - t0
    _findings_table([result])
    _save([result], "deep", args.output)
    console.print(f"[green]Escaneo terminado en {elapsed:.1f}s.[/green]")


def cmd_batch(args) -> None:
    if not args.yes and not _confirm_authorization():
        console.print("[red]Cancelado: se requiere autorización para escanear.[/red]")
        sys.exit(1)
    targets = load_targets(args.targets)
    if not targets:
        console.print("[red]No se cargaron objetivos. Revisa el archivo.[/red]")
        sys.exit(1)
    console.print(
        f"[bold cyan]Escaneo por lotes de {len(targets)} webs[/bold cyan] "
        f"(deep + checks activos, concurrencia {args.concurrency}, timeout {args.timeout}s)"
    )
    opts = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        active=True,
        mass=False,
        check_tls=not args.no_tls,
    )
    t0 = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("{task.fields[status]}"),
    ) as progress:
        task = progress.add_task("Escaneando...", total=len(targets), status="")

        def on_done(r: TargetResult) -> None:
            status = r.max_severity.value if r.max_severity else "ok"
            progress.update(task, advance=1, status=f"[{status}] {r.url[:40]}")

        results = asyncio.run(batch_scan(targets, opts, on_target_done=on_done))
        progress.update(task, refresh=True)

    elapsed = time.time() - t0
    _summary_table(results)
    _save(results, "batch", args.output)
    _findings_table(results)
    console.print(f"[green]Escaneo terminado en {elapsed:.1f}s.[/green]")


def cmd_report(args) -> None:
    path = Path(args.path)
    if not path.exists():
        console.print(f"[red]No existe: {path}[/red]")
        sys.exit(1)
    if path.suffix.lower() == ".html":
        if args.open:
            webbrowser.open(path.resolve().as_uri())
        console.print(f"Reporte HTML: [cyan]{path}[/cyan]")
        return
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    resumen = data.get("resumen", {})
    console.print("[bold]Resumen:[/bold]")
    for key, value in resumen.items():
        label = _SEV_LABELS.get(key, key)
        console.print(f"  {label}: {value}")
    if args.open:
        html_path = path.with_suffix(".html")
        if html_path.exists():
            webbrowser.open(html_path.resolve().as_uri())
        else:
            console.print("[yellow]No hay HTML junto al JSON para abrir.[/yellow]")


def main(argv=None) -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="zhack",
        description="ZHack — Escáner de seguridad web (solo webs propias o autorizadas).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_mass = sub.add_parser("mass", help="Escaneo masivo de muchas webs (checks pasivos, rápido)")
    p_mass.add_argument("targets", help="Archivo con una web por línea (txt/csv)")
    p_mass.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrencia (por defecto 100)")
    p_mass.add_argument("-t", "--timeout", type=int, default=10, help="Timeout por petición en segundos")
    p_mass.add_argument("-o", "--output", default="reports", help="Directorio de salida")
    p_mass.add_argument("-y", "--yes", action="store_true", help="Confirma la autorización sin preguntar")
    p_mass.add_argument("--no-tls", action="store_true", help="Desactiva los checks TLS (más rápido)")
    p_mass.set_defaults(func=cmd_mass)

    p_deep = sub.add_parser("deep", help="Escaneo profundo de una web (pasivo + activo con --active)")
    p_deep.add_argument("url", help="URL a escanear, p.ej. https://miweb.com")
    p_deep.add_argument("--active", action="store_true", help="Activa pruebas de detección (SQLi/XSS/traversal/CORS, siempre inofensivas)")
    p_deep.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrencia (por defecto 100)")
    p_deep.add_argument("-t", "--timeout", type=int, default=10)
    p_deep.add_argument("-o", "--output", default="reports")
    p_deep.add_argument("-y", "--yes", action="store_true", help="Confirma la autorización sin preguntar")
    p_deep.add_argument("--no-tls", action="store_true", help="Desactiva los checks TLS")
    p_deep.set_defaults(func=cmd_deep)

    p_batch = sub.add_parser("batch", help="Escaneo en lote de muchas webs (deep + checks activos)")
    p_batch.add_argument("targets", help="Archivo con una web por línea (txt/csv)")
    p_batch.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrencia (por defecto 100)")
    p_batch.add_argument("-t", "--timeout", type=int, default=10, help="Timeout por petición en segundos")
    p_batch.add_argument("-o", "--output", default="reports", help="Directorio de salida")
    p_batch.add_argument("-y", "--yes", action="store_true", help="Confirma la autorización sin preguntar")
    p_batch.add_argument("--no-tls", action="store_true", help="Desactiva los checks TLS")
    p_batch.set_defaults(func=cmd_batch)

    p_report = sub.add_parser("report", help="Resumen de un reporte JSON o HTML generado")
    p_report.add_argument("path", help="Ruta al archivo .json o .html")
    p_report.add_argument("--open", action="store_true", help="Abre el reporte HTML en el navegador")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
