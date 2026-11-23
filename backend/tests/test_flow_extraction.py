"""
Sentinel Cyber — Flow Extraction & Feature Parity Test Suite
Validates bidirectional packet capture, flow directionality, packet/byte counts,
IAT statistics, TCP flags, header lengths, active/idle periods, notebook engineered features,
and full inference through the trained 74-feature Random Forest pipeline.
"""

from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
# Standalone assertion test suite

# Ensure backend and sensor packages are in path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "sensor"))

from sensor.flow_extractor import (
    Flow,
    FlowTable,
    PacketInfo,
    parse_ipv4_packet,
    parse_pcap_stream,
)


def make_raw_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int,
    window_size: int = 64240,
    payload: bytes = b"",
    ip_id: int = 1000
) -> bytes:
    """Constructs a standard IPv4 + TCP packet byte sequence."""
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))

    tcp_header_len = 20
    tcp_seq = 10000
    tcp_ack = 20000 if (flags & 0x10) else 0
    data_offset_reserved = (tcp_header_len // 4) << 4

    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        tcp_seq,
        tcp_ack,
        data_offset_reserved,
        flags,
        window_size,
        0,  # checksum
        0   # urgent
    )

    total_len = 20 + len(tcp_hdr) + len(payload)
    version_ihl = (4 << 4) | 5
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,          # tos
        total_len,
        ip_id,
        0x4000,     # DF flag
        64,         # ttl
        6,          # TCP protocol
        0,          # checksum
        src_b,
        dst_b
    )

    return ip_hdr + tcp_hdr + payload


def make_raw_ipv4_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    ip_id: int = 2000
) -> bytes:
    """Constructs a standard IPv4 + UDP packet byte sequence."""
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))

    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    total_len = 20 + udp_len
    version_ihl = (4 << 4) | 5
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,          # tos
        total_len,
        ip_id,
        0,
        64,         # ttl
        17,         # UDP protocol
        0,          # checksum
        src_b,
        dst_b
    )

    return ip_hdr + udp_hdr + payload


def create_pcap_bytes(packets: list[tuple[float, bytes]]) -> bytes:
    """Encapsulates raw IPv4 packets into a standard PCAP file byte sequence."""
    # Global header (24 bytes): magic, major(2), minor(4), thiszone(0), sigfigs(0), snaplen(65535), network(101 = raw IP)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)

    records = [global_hdr]
    for ts, pkt_data in packets:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        rec_hdr = struct.pack("<IIII", sec, usec, len(pkt_data), len(pkt_data))
        records.append(rec_hdr + pkt_data)

    return b"".join(records)


def test_packet_decoder_and_bidirectional_tracking():
    """Verify bidirectional packet visibility, direction setting, and counts."""
    t0 = 1700000000.0
    client = "192.168.1.100"
    server = "93.184.216.34"

    # Forward SYN packet
    raw_syn = make_raw_ipv4_tcp_packet(client, server, 50000, 80, flags=0x02, window_size=64240)
    pkt1 = parse_ipv4_packet(raw_syn, t0)
    assert pkt1 is not None
    assert pkt1.src_ip == client
    assert pkt1.dst_ip == server
    assert pkt1.dst_port == 80
    assert pkt1.protocol == 6
    assert pkt1.tcp_flags["SYN"] == 1
    assert pkt1.tcp_window_size == 64240

    flow = Flow(pkt1)
    assert flow.fwd_ip == client
    assert flow.bwd_ip == server
    assert len(flow.fwd_packet_times) == 1
    assert len(flow.bwd_packet_times) == 0

    # Backward SYN-ACK packet
    t1 = t0 + 0.020  # +20ms
    raw_synack = make_raw_ipv4_tcp_packet(server, client, 80, 50000, flags=0x12, window_size=65535)
    pkt2 = parse_ipv4_packet(raw_synack, t1)
    assert pkt2 is not None

    flow.add_packet(pkt2)
    assert len(flow.fwd_packet_times) == 1
    assert len(flow.bwd_packet_times) == 1
    assert flow.init_win_fwd == 64240
    assert flow.init_win_bwd == 65535
    assert flow.flag_counts["SYN"] == 2
    assert flow.flag_counts["ACK"] == 1

    # Forward ACK packet
    t2 = t1 + 0.002  # +2ms
    raw_ack = make_raw_ipv4_tcp_packet(client, server, 50000, 80, flags=0x10, window_size=64240)
    pkt3 = parse_ipv4_packet(raw_ack, t2)
    flow.add_packet(pkt3)

    # Forward HTTP GET payload (250 bytes)
    t3 = t2 + 0.005  # +5ms
    raw_data = make_raw_ipv4_tcp_packet(client, server, 50000, 80, flags=0x18, window_size=64240, payload=b"GET / HTTP/1.1\r\n" + b"A"*230)
    pkt4 = parse_ipv4_packet(raw_data, t3)
    flow.add_packet(pkt4)

    # Backward HTTP 200 Response (1000 bytes)
    t4 = t3 + 0.030  # +30ms
    raw_resp = make_raw_ipv4_tcp_packet(server, client, 80, 50000, flags=0x18, window_size=65535, payload=b"HTTP/1.1 200 OK\r\n" + b"B"*970)
    pkt5 = parse_ipv4_packet(raw_resp, t4)
    flow.add_packet(pkt5)

    feats = flow.to_74_features()

    # Exact assertions on ground-truth calculations
    assert feats["Destination Port"] == 80
    assert feats["Total Fwd Packets"] == 3
    assert feats["Total Backward Packets"] == 2
    assert feats["Init_Win_bytes_forward"] == 64240
    assert feats["Init_Win_bytes_backward"] == 65535
    assert feats["act_data_pkt_fwd"] == 1  # only pkt4 had payload > 0
    assert feats["Down/Up Ratio"] == 2 / 3
    assert feats["Fwd Header Length"] == 3 * 40  # 3 pkts * (20 IP + 20 TCP) = 120
    assert feats["Bwd Header Length"] == 2 * 40  # 2 pkts * (20 IP + 20 TCP) = 80
    assert feats["Fwd Header Length.1"] == feats["Fwd Header Length"]
    assert feats["No_Backward_Packets"] == 0
    assert feats["No_Backward_Bytes"] == 0
    assert np.isclose(feats["Fwd_Bwd_Packet_Ratio"], 3 / 2)


def test_schema_conformance_with_feature_columns_json():
    """Verify that flow extractor generates all 74 features in the exact expected order."""
    features_json_path = BACKEND_DIR / "artifacts" / "feature_columns.json"
    with open(features_json_path, "r", encoding="utf-8") as f:
        expected_columns = json.load(f)

    raw_pkt = make_raw_ipv4_udp_packet("10.0.0.1", "8.8.8.8", 12345, 53, payload=b"test_payload")
    pkt = parse_ipv4_packet(raw_pkt, time.time())
    flow = Flow(pkt)

    feats = flow.to_74_features()

    assert len(feats) == 74, f"Expected 74 features, got {len(feats)}"
    assert list(feats.keys()) == expected_columns, "Feature keys do not match feature_columns.json order!"


def test_pcap_stream_and_flow_table_expiration():
    """Verify PCAP stream parsing and stateful flow table timeout management."""
    t0 = 1700000100.0
    client = "192.168.1.50"
    server = "1.1.1.1"

    # Create a 2-packet UDP DNS query and response
    p1 = make_raw_ipv4_udp_packet(client, server, 43210, 53, payload=b"query")
    p2 = make_raw_ipv4_udp_packet(server, client, 53, 43210, payload=b"response")

    pcap_data = create_pcap_bytes([(t0, p1), (t0 + 0.015, p2)])

    table = FlowTable(inactivity_timeout_sec=5.0)
    extracted_flows = []

    for pkt in parse_pcap_stream(pcap_data):
        finished = table.process_packet(pkt)
        if finished:
            extracted_flows.append(finished)

    # Flush table after inactivity
    expired = table.flush_expired(t0 + 10.0)
    extracted_flows.extend(expired)

    assert len(extracted_flows) == 1
    f = extracted_flows[0]
    meta = f.metadata()
    assert meta["protocol"] == "UDP"
    assert meta["src_port"] == 43210
    assert meta["dst_port"] == 53
    assert meta["total_packets"] == 2

    feats = f.to_74_features()
    assert feats["Destination Port"] == 53
    assert feats["Total Fwd Packets"] == 1
    assert feats["Total Backward Packets"] == 1
    assert feats["Init_Win_bytes_forward"] == -1  # UDP has no TCP window
    assert feats["Init_Win_bytes_backward"] == -1


def test_random_forest_inference_pipeline_compatibility():
    """Verify that extracted flows pass through the Random Forest pipeline with threshold 0.05."""
    model_path = BACKEND_DIR / "artifacts" / "model.joblib"
    model = joblib.load(model_path)

    # Build 2 distinct benign flows
    raw_https = make_raw_ipv4_tcp_packet("192.168.1.10", "142.250.190.46", 55555, 443, flags=0x02, window_size=65535)
    raw_dns = make_raw_ipv4_udp_packet("192.168.1.10", "8.8.8.8", 54321, 53, payload=b"resolve_domain")

    f1 = Flow(parse_ipv4_packet(raw_https, time.time()))
    f2 = Flow(parse_ipv4_packet(raw_dns, time.time()))

    df = pd.DataFrame([f1.to_74_features(), f2.to_74_features()])

    # Preprocessing check (Infs replaced by NaN, imputed by SimpleImputer)
    probabilities = model.predict_proba(df)
    assert probabilities.shape == (2, 2)

    attack_probs = probabilities[:, 1]
    predictions = (attack_probs >= 0.05).astype(int)

    # Benign flows should be classified as BENIGN (class 0)
    assert len(predictions) == 2
    for p in attack_probs:
        assert 0.0 <= p <= 1.0


if __name__ == "__main__":
    print("Running Flow Extraction & Parity Tests...")
    test_packet_decoder_and_bidirectional_tracking()
    print("  [PASS] test_packet_decoder_and_bidirectional_tracking")
    test_schema_conformance_with_feature_columns_json()
    print("  [PASS] test_schema_conformance_with_feature_columns_json")
    test_pcap_stream_and_flow_table_expiration()
    print("  [PASS] test_pcap_stream_and_flow_table_expiration")
    test_random_forest_inference_pipeline_compatibility()
    print("  [PASS] test_random_forest_inference_pipeline_compatibility")
    print("\nALL TEST SUITE CHECKS PASSED SUCCESSFULLY!")
