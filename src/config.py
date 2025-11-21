from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalyzerConfig:
    heuristics_threshold: float = 0.7
    ml_score_threshold: float = 0.65
    baseline_stats_path: Path = Path("baseline_stats.json")
    model_path: Path = Path("models/isolation_forest.joblib")
    max_packets: int | None = None 


CONFIG = AnalyzerConfig()
