import types

from anomaly_detector.engineering import packets_to_flows
from anomaly_detector.analyzers.heuristics import run_heuristics


def _fake_packet(src_ip, dst_ip, src_port, dst_port, syn=False, ack=False, payload=b""):
    pkt = types.SimpleNamespace()
    pkt.ip = types.SimpleNamespace(src=src_ip, dst=dst_ip)
    pkt.highest_layer = "TCP"
    pkt.tcp = types.SimpleNamespace(
        srcport=str(src_port),
        dstport=str(dst_port),
        flags_syn="1" if syn else "0",
        flags_ack="1" if ack else "0",
    )
    pkt.get_raw_packet = lambda: payload
    return pkt


def test_packets_to_flows_basic():
    packets = [
        _fake_packet("10.0.0.1", "10.0.0.2", 1234, 80, syn=True, payload=b"A"),
        _fake_packet("10.0.0.1", "10.0.0.2", 1234, 80, ack=True, payload=b"B"),
    ]
    flows = packets_to_flows(packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.packet_count == 2
    assert flow.syn_count == 1
    assert flow.ack_count == 1
    assert flow.byte_count == 2


def test_heuristics_detects_syn_flood():
    packets = [_fake_packet("1.1.1.1", "2.2.2.2", 4444, 80, syn=True) for _ in range(12)]
    flows = packets_to_flows(packets)
    findings = run_heuristics(flows)
    assert any("SYN flood" in f.summary for f in findings)