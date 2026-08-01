from __future__ import annotations

import csv
from typing import List

from zhack.core.models import TargetResult


def write_csv(results: List[TargetResult], path: str) -> None:
    """Exporta los hallazgos a CSV (una fila por hallazgo)."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "url",
                "severidad",
                "check",
                "titulo",
                "evidencia",
                "remediacion",
            ]
        )
        for r in results:
            for f in r.findings:
                writer.writerow(
                    [r.url, f.severity.value, f.check, f.title, f.evidence, f.remediation]
                )
