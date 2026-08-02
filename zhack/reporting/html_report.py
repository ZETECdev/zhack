from __future__ import annotations

import html
from datetime import datetime
from typing import List

from zhack.core.models import Severity, TargetResult

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def _badge(sev: Severity) -> str:
    return (
        f'<span class="badge" style="background:{sev.color}">{_esc(sev.value)}</span>'
    )


def _severity_summary_counts(results: List[TargetResult]) -> dict:
    return {
        sev: sum(1 for r in results for f in r.findings if f.severity == sev)
        for sev in _SEV_ORDER
    }


def build_html(results: List[TargetResult], generated: str = "") -> str:
    generated = generated or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_sites = len(results)
    total_findings = sum(len(r.findings) for r in results)
    sev_counts = _severity_summary_counts(results)

    sites = sorted(
        results,
        key=lambda r: (r.max_severity.score if r.max_severity else 0),
        reverse=True,
    )

    summary_cells = "".join(
        f'<div class="stat"><span class="num" style="color:{sev.color}">{sev_counts[sev]}</span>'
        f'<span class="lbl">{_esc(sev.value)}</span></div>'
        for sev in _SEV_ORDER
    )

    site_sections = []
    for r in sites:
        if not r.findings and not r.errors:
            continue
        sev = r.max_severity
        badge = _badge(sev) if sev else '<span class="badge" style="background:#27ae60">ok</span>'
        status = f"HTTP {r.status}" if r.status else "sin respuesta"
        rows = []
        for f in sorted(r.findings, key=lambda f: f.severity.score, reverse=True):
            rows.append(
                f"""
                <tr>
                  <td>{_badge(f.severity)}</td>
                  <td class="mono">{_esc(f.check)}</td>
                   <td>
                     <strong>{_esc(f.title)}</strong>
                     <div class="desc">{_esc(f.description)}</div>
                     <div class="en-report">
                       <div><strong>Attacker impact:</strong> {_esc(f.attacker_impact)}</div>
                       <div><strong>High-level attack scenario:</strong> {_esc(f.attack_scenario)}</div>
                       <div><strong>Safe validation and remediation:</strong> {_esc(f.safe_validation)}</div>
                     </div>
                     {"<div class='evid'>Evidencia: <code>" + _esc(f.evidence) + "</code></div>" if f.evidence else ""}
                    {"<div class='u'>URL: <code>" + _esc(f.url) + "</code></div>" if f.url and f.url != r.url else ""}
                  </td>
                  <td class="fix">{_esc(f.remediation)}</td>
                </tr>
                """
            )
        errors_html = ""
        if r.errors:
            errors_html = (
                '<div class="errors"><strong>Errores de escaneo:</strong><ul>'
                + "".join(f"<li>{_esc(e)}</li>" for e in r.errors[:8])
                + "</ul></div>"
            )
        site_sections.append(
            f"""
            <details open>
              <summary>
                <span class="site-url">{_esc(r.url)}</span>
                {badge}
                <span class="status">{_esc(status)}</span>
              </summary>
              {errors_html}
              <table>
                <thead><tr><th>Severidad</th><th>Check</th><th>Hallazgo</th><th>Cómo repararlo</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
              </table>
            </details>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZHack — Reporte de seguridad</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #0f1420; color: #e6e9f0; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  h1 {{ margin: 0 0 4px; }}
  .sub {{ color: #8b93a7; font-size: 14px; margin-bottom: 20px; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }}
  .stat {{ background: #1a2133; border-radius: 10px; padding: 14px 22px; text-align: center; }}
  .num {{ font-size: 28px; font-weight: 700; }}
  .lbl {{ display: block; font-size: 12px; color: #8b93a7; text-transform: uppercase; letter-spacing: .05em; }}
  details {{ background: #161d2e; border: 1px solid #232c44; border-radius: 10px; margin-bottom: 14px; overflow: hidden; }}
  summary {{ cursor: pointer; padding: 14px 18px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  summary:hover {{ background: #1a2133; }}
  .site-url {{ font-weight: 700; font-family: Consolas, monospace; }}
  .status {{ color: #8b93a7; font-size: 13px; }}
  .badge {{ color: #fff; border-radius: 20px; padding: 3px 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-size: 12px; text-transform: uppercase; color: #8b93a7; padding: 10px 18px; border-top: 1px solid #232c44; }}
  td {{ padding: 12px 18px; border-top: 1px solid #20283d; vertical-align: top; font-size: 14px; }}
   .desc {{ color: #aab3c7; margin-top: 4px; font-size: 13px; }}
   .en-report {{ margin-top: 10px; padding: 10px 12px; background: #111827; border-left: 3px solid #6c8cff; color: #d7def0; font-size: 13px; line-height: 1.5; }}
   .en-report strong {{ color: #9fb5ff; }}
   .evid {{ margin-top: 6px; font-size: 12px; color: #8b93a7; }}
  .u {{ font-size: 12px; color: #8b93a7; }}
  .fix {{ color: #7ee0a3; font-size: 13px; }}
  code {{ background: #0f1420; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; }}
  .mono {{ font-family: Consolas, monospace; font-size: 12px; color: #8b93a7; }}
  .errors {{ margin: 0 18px; padding: 10px 14px; background: #2a1620; border-radius: 8px; font-size: 13px; }}
  footer {{ margin-top: 30px; color: #5c6480; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>ZHack — Reporte de seguridad web</h1>
  <div class="sub">Generado: {generated} · {total_sites} sitios escaneados · {total_findings} hallazgos</div>
  <div class="stats">{summary_cells}</div>
  {''.join(site_sections)}
  <footer>ZHack es una herramienta de defensa: solo peticiones de lectura, para webs propias o autorizadas.</footer>
</div>
</body>
</html>"""
