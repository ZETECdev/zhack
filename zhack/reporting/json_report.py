from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from zhack.core.models import TargetResult


def result_to_dict(r: TargetResult) -> Dict[str, Any]:
    return {
        "url": r.url,
        "status": r.status,
        "final_url": r.final_url,
        "max_severidad": r.max_severity.value if r.max_severity else None,
        "errores": r.errors,
        "hallazgos": [
            {
                "check": f.check,
                "severidad": f.severity.value,
                "titulo": f.title,
                "descripcion": f.description,
                "remediacion": f.remediation,
                "url": f.url,
                "evidencia": f.evidence,
                "attacker_impact": f.attacker_impact,
                "attack_scenario": f.attack_scenario,
                "safe_validation": f.safe_validation,
            }
            for f in r.findings
        ],
    }


def summarize(results: List[TargetResult]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in results:
        key = r.max_severity.value if r.max_severity else "sin_hallazgos"
        counts[key] = counts.get(key, 0) + 1
    return counts


def serialize(results: List[TargetResult]) -> Dict[str, Any]:
    return {
        "generado": datetime.now().isoformat(timespec="seconds"),
        "resumen": summarize(results),
        "sites": [result_to_dict(r) for r in results],
    }


def write_json(results: List[TargetResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(serialize(results), fh, ensure_ascii=False, indent=2)
