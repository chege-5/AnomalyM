
from pathlib import Path
import argparse

from src.config import CONFIG
from src.packet_loader import load_packets
from src.engineering import packets_to_flows
from src.analyzers.ml_model import train_model


def main():
    parser = argparse.ArgumentParser(description="Train IsolationForest baseline")
    parser.add_argument("pcap", help="pcap/pcapng file containing benign traffic")
    parser.add_argument("--max-packets", type=int, default=CONFIG.max_packets)
    parser.add_argument("--model-path", type=Path, default=CONFIG.model_path)
    args = parser.parse_args()

    packets = list(load_packets(args.pcap, args.max_packets))
    flows = packets_to_flows(packets)

    if not flows:
        raise SystemExit("No flows extracted from baseline capture; aborting.")

    train_model(flows, args.model_path)
    print(f"Model trained and saved to {args.model_path}")


if __name__ == "__main__":
    main()