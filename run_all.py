"""run_all.py — ZHack: ejecuta TODOS los checks (pasivos + activos) contra una lista de webs.

Uso:
    python run_all.py targets.txt -y
    python run_all.py targets.txt -y --csv --header "Authorization: Bearer xxx" --cookie "session=abc"

Genera en reports/ un reporte JSON y HTML consolidado (y CSV con --csv).
Solo hace peticiones de lectura (GET/HEAD/OPTIONS).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from zhack.core.context import ScanOptions
from zhack.core.models import Severity, TargetResult
from zhack.core.scanner import mass_scan, scan_all
from zhack.core.targets import load_targets
from zhack.reporting.csv_report import write_csv
from zhack.reporting.en_report import write_en_report
from zhack.reporting.html_report import build_html
from zhack.reporting.json_report import write_json

console = Console()


def _parse_headers(args) -> dict:
    headers: dict = {}
    for item in args.header or []:
        if ":" not in item:
            console.print(f"[red]Header inválido (se ignora): {item}[/red] (usa \"Nombre: valor\")")
            continue
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    return headers


def _confirm_authorization() -> bool:
    console.print(
        Panel(
            "[bold red]AVISO LEGAL[/bold red]\n\n"
            "ZHack solo debe usarse sobre webs que [bold]TÚ posees[/bold] o sobre las que tienes\n"
            "[bold]autorización escrita[/bold]. Escanear webs de terceros sin permiso puede ser\n"
            "ilegal en tu país (acceso indebido / hacking).\n\n"
            "Solo hace peticiones de lectura (GET/HEAD/OPTIONS) y jamás modifica una web.",
            title="ZHack run_all",
            border_style="red",
        )
    )
    try:
        ans = input("¿Confirmas que tienes autorización para escanear estos objetivos? (s/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("s", "si", "sí", "y", "yes")


def _save(results, mode: str, output: str, with_csv: bool = False):
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"zhack_{mode}_{stamp}"
    write_json(results, str(base) + ".json")
    with open(str(base) + ".html", "w", encoding="utf-8") as fh:
        fh.write(build_html(results))
    write_en_report(results, str(base) + "_en.md")
    console.print(f"[green]Reporte JSON:[/green] {base}.json")
    console.print(f"[green]Reporte HTML:[/green] {base}.html")
    console.print(f"[green]Reporte EN (bug bounty):[/green] {base}_en.md")
    if with_csv:
        write_csv(results, str(base) + ".csv")
        console.print(f"[green]Reporte CSV:[/green] {base}.csv")


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
        table.add_column("Check", width=20)
        table.add_column("Hallazgo")
        for f in sorted(r.findings, key=lambda f: f.severity.score, reverse=True):
            table.add_row(f.severity.value, f.check, f.title)
        console.print(table)
        console.print()


def main(argv=None) -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="run_all",
        description="ZHack — ejecuta TODOS los checks (pasivos + activos) sobre una lista de webs.",
    )
    parser.add_argument("targets", help="Archivo con una web por línea (txt/csv)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrencia (por defecto 100)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout por petición en segundos")
    parser.add_argument("-o", "--output", default="reports", help="Directorio de salida")
    parser.add_argument("-y", "--yes", action="store_true", help="Confirma la autorización sin preguntar")
    parser.add_argument("--no-tls", action="store_true", help="Desactiva los checks TLS (más rápido)")
    parser.add_argument("--no-active", action="store_true", help="Solo checks pasivos (equivale a mass)")
    parser.add_argument("--csv", action="store_true", help="Exporta además los hallazgos a CSV")
    parser.add_argument(
        "--header", action="append", metavar='"Nombre: valor"',
        help="Header HTTP a añadir a todas las peticiones (repetible). P.ej. \"Authorization: Bearer ...\"",
    )
    parser.add_argument(
        "--cookie", metavar="COOKIE",
        help="Cookie a enviar en todas las peticiones, p.ej. \"session=abc123\"",
    )
    args = parser.parse_args(argv)

    if not args.yes and not _confirm_authorization():
        console.print("[red]Cancelado: se requiere autorización para escanear.[/red]")
        sys.exit(1)

    targets = load_targets(args.targets)
    if not targets:
        console.print("[red]No se cargaron objetivos. Revisa el archivo.[/red]")
        sys.exit(1)

    headers = _parse_headers(args)
    mode = "mass" if args.no_active else "batch"
    console.print(
        f"[bold cyan]ZHack run_all: {len(targets)} webs[/bold cyan] "
        f"({'pasivo' if args.no_active else 'todos los checks (deep + activos)'}, "
        f"concurrencia {args.concurrency}, timeout {args.timeout}s)"
    )

    opts = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        active=not args.no_active,
        mass=args.no_active,
        check_tls=not args.no_tls,
        custom_headers=headers,
    )
    if headers:
        console.print(f"[dim]Headers personalizados: {list(headers)}[/dim]")

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

        if args.no_active:
            results = asyncio.run(mass_scan(targets, opts, on_target_done=on_done))
        else:
            results = asyncio.run(scan_all(targets, opts, on_target_done=on_done))
        progress.update(task, refresh=True)

    elapsed = time.time() - t0
    _summary_table(results)
    _save(results, mode, args.output, with_csv=args.csv)
    _findings_table(results)
    console.print(f"[green]Escaneo terminado en {elapsed:.1f}s.[/green]")


if __name__ == "__main__":
    main()
