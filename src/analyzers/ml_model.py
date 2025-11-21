from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass
class MLFinding:
    score: float
    summary: str
    context: dict


def _flow_to_vector(flow) -> list[float]:
    return [
        flow.packet_count,
        flow.byte_count,
        flow.syn_count,
        flow.ack_count,
        flow.entropy,
    ]


def train_model(flows: Iterable, model_path: Path) -> None:
    X = np.array([_flow_to_vector(flow) for flow in flows])
    model = IsolationForest(contamination=0.02, random_state=42).fit(X)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)


def score_flows(flows: Iterable, model_path: Path, threshold: float) -> list[MLFinding]:
    model: IsolationForest = joblib.load(model_path)
    X = np.array([_flow_to_vector(flow) for flow in flows])
    scores = model.decision_function(X)
    findings: list[MLFinding] = []
    for flow, score in zip(flows, scores):
        if score < threshold:
            findings.append(
                MLFinding(
                    score=float(score),
                    summary="ML anomaly detected",
                    context={"flow": flow},
                )
            )
    return findings