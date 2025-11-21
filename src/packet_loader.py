from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pyshark


def load_packets(pcap_path: str | Path, max_packets: int | None = None) -> Iterator[Any]:
    """
    Load packets from a pcap/pcapng file with raw bytes included for feature extraction.

    Args:
        pcap_path: Path to the PCAP file.
        max_packets: Optional max number of packets to load.

    Yields:
        PyShark Packet objects with raw bytes accessible via get_raw_packet().
    """
    capture = pyshark.FileCapture(
        str(pcap_path),
        keep_packets=False,
        use_json=True,      # required for include_raw
        include_raw=True    # include raw bytes so entropy can be calculated
    )
    try:
        for idx, packet in enumerate(capture):
            if max_packets is not None and idx >= max_packets:
                break
            yield packet
    finally:
        capture.close()
