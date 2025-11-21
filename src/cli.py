import argparse
import json
from pathlib import Path

from .config import CONFIG
from .packet_loader import load_packets
from .engineering import packets_to_flows
from .analyzers.heuristics import run_heuristics
from .analyzers.ml_model import score_flows


def main():
    parser = argparse.ArgumentParser(description="Packet analyzer and anomaly detector")
    parser.add_argument("pcap", help="Path to pcap/pcapng file")
    parser.add_argument("--max-packets", type=int, default=CONFIG.max_packets)
    parser.add_argument("--model-path", type=Path, default=CONFIG.model_path)
    parser.add_argument("--ml-threshold", type=float, default=CONFIG.ml_score_threshold)
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    args = parser.parse_args()

    packets = list(load_packets(args.pcap, args.max_packets))
    flows = packets_to_flows(packets)
    heuristic_findings = run_heuristics(flows)
    ml_findings = score_flows(flows, args.model_path, args.ml_threshold)

    from .reporting import summarize_results

    report = summarize_results(heuristic_findings, ml_findings)
    args.output.write_text(json.dumps(report, indent=2))
    print(f"Analysis complete. Report written to {args.output}")


if __name__ == "__main__":
    main()