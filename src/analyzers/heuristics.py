from dataclasses import dataclass
from typing import Any


@dataclass
class HeuristicFinding:
    severity: str
    summary: str
    remediation: str
    context: dict[str, Any]


def detect_syn_flood(flow) -> HeuristicFinding | None:
    if flow.syn_count >= 10 and flow.ack_count == 0:
        return HeuristicFinding(
            severity="high",
            summary="Potential SYN flood",
            remediation="Rate limit ingress SYNs or enable SYN cookies.",
            context={"src_ip": flow.src_ip, "dst_ip": flow.dst_ip, "syn_count": flow.syn_count},
        )
    return None


def detect_high_entropy(flow) -> HeuristicFinding | None:
    if flow.entropy > 6.0:
        return HeuristicFinding(
            severity="medium",
            summary="High payload entropy (possible tunneling)",
            remediation="Inspect payload content; block suspicious domains/tunnels.",
            context={"entropy": flow.entropy, "flow": flow},
        )
    return None


def run_heuristics(flows):
    findings = []
    for flow in flows:
        for detector in (detect_syn_flood, detect_high_entropy):
            finding = detector(flow)
            if finding:
                findings.append(finding)
    return findings