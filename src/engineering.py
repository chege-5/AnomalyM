import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class FlowFeatures:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    syn_count: int
    ack_count: int
    entropy: float


def _calc_entropy(payload: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    """
    if not payload:
        return 0.0

    freq = defaultdict(int)
    for byte in payload:
        freq[byte] += 1

    entropy = 0.0
    length = len(payload)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def packets_to_flows(packets: list[Any]) -> list[FlowFeatures]:
    """
    Convert a list of packets into aggregated flows with statistics.
    Supports IPv4, IPv6, TCP/UDP ports, SYN/ACK counts, and payload entropy.
    Skips packets that don’t contain IP layers.
    """
    flows: dict[tuple, FlowFeatures] = {}

    for pkt in packets:
        # Determine IP layer
        if hasattr(pkt, "ip"):
            src_ip = getattr(pkt.ip, "src", "0.0.0.0")
            dst_ip = getattr(pkt.ip, "dst", "0.0.0.0")
        elif hasattr(pkt, "ipv6"):
            src_ip = getattr(pkt.ipv6, "src", "::")
            dst_ip = getattr(pkt.ipv6, "dst", "::")
        else:
            # Skip non-IP packets
            continue

        # Determine ports
        src_port = int(getattr(getattr(pkt, "tcp", None), "srcport",
                               getattr(getattr(pkt, "udp", None), "srcport", 0)) or 0)
        dst_port = int(getattr(getattr(pkt, "tcp", None), "dstport",
                               getattr(getattr(pkt, "udp", None), "dstport", 0)) or 0)

        proto = pkt.highest_layer

        # Safely get raw payload; default to empty bytes
        try:
            payload = bytes(pkt.get_raw_packet())
        except (AssertionError, AttributeError):
            payload = b""

        five_tuple = (src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows.get(five_tuple)

        if flow is None:
            flow = FlowFeatures(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                packet_count=0,
                byte_count=0,
                syn_count=0,
                ack_count=0,
                entropy=0.0
            )
            flows[five_tuple] = flow

        # Aggregate metrics
        flow.packet_count += 1
        flow.byte_count += len(payload)

        if hasattr(pkt, "tcp"):
            if getattr(pkt.tcp, "flags_syn", "0") == "1":
                flow.syn_count += 1
            if getattr(pkt.tcp, "flags_ack", "0") == "1":
                flow.ack_count += 1

        # Running average of entropy
        flow.entropy = (flow.entropy + _calc_entropy(payload)) / 2

    return list(flows.values())
