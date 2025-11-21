from dataclasses import asdict
from typing import Any


def summarize_results(heuristic_findings, ml_findings) -> dict[str, Any]:
    return {
        "total_heuristics": len(heuristic_findings),
        "total_ml": len(ml_findings),
        "heuristics": [asdict(f) for f in heuristic_findings],
        "ml": [asdict(f) for f in ml_findings],
    }