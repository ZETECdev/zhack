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
                "attacker_impact",
                "attack_scenario",
                "safe_validation",
            ]
        )
        for r in results:
            for f in r.findings:
                writer.writerow(
                    [
                        r.url,
                        f.severity.value,
                        f.check,
                        f.title,
                        f.evidence,
                        f.remediation,
                        f.attacker_impact,
                        f.attack_scenario,
                        f.safe_validation,
                    ]
                )
