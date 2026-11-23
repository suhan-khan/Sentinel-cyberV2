"""
Sentinel Cyber — Isolated Proof of Concept Test
Simulates authorized, genuine raw network packet streams, extracts full 74-feature
records using FlowEngine, validates schema alignment against feature_columns.json,
and executes inference using the existing Random Forest model pipeline.
"""

from __future__ import annotations

import json
import struct
import time
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd

from flow_engine import Flow, PacketInfo, parse_ipv4_packet


def build_raw_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int,
    window_size: int = 64240,
    payload: bytes = b"",
    ip_id: int = 54321
) -> bytes:
    """Builds a valid raw IPv4 + TCP packet byte sequence."""
    src_ip_bytes = bytes(map(int, src_ip.split(".")))
    dst_ip_bytes = bytes(map(int, dst_ip.split(".")))

    tcp_header_len = 20
    tcp_seq = 1000
    tcp_ack = 0
    data_offset_reserved = (tcp_header_len // 4) << 4
    tcp_checksum = 0
    tcp_urgent = 0

    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        tcp_seq,
        tcp_ack,
        data_offset_reserved,
        flags,
        window_size,
        tcp_checksum,
        tcp_urgent
    )

    total_len = 20 + len(tcp_hdr) + len(payload)
    version_ihl = (4 << 4) | 5
    tos = 0
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    protocol = 6  # TCP
    ip_checksum = 0

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_fragment,
        ttl,
        protocol,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    return ip_hdr + tcp_hdr + payload


def build_raw_ipv4_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    ip_id: int = 12345
) -> bytes:
    """Builds a valid raw IPv4 + UDP packet byte sequence."""
    src_ip_bytes = bytes(map(int, src_ip.split(".")))
    dst_ip_bytes = bytes(map(int, dst_ip.split(".")))

    udp_len = 8 + len(payload)
    udp_checksum = 0
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_checksum)

    total_len = 20 + udp_len
    version_ihl = (4 << 4) | 5
    tos = 0
    flags_fragment = 0
    ttl = 64
    protocol = 17  # UDP
    ip_checksum = 0

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ip_id,
        flags_fragment,
        ttl,
        protocol,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    return ip_hdr + udp_hdr + payload


def run_proof_of_concept():
    print("=" * 70)
    print("  SENTINEL CYBER — PROOF OF CONCEPT: 74-FEATURE EXTRACTION & ML TEST")
    print("=" * 70)

    # 1. Load artifacts
    base_dir = Path(__file__).resolve().parent.parent
    features_path = base_dir / "backend" / "artifacts" / "feature_columns.json"
    model_path = base_dir / "backend" / "artifacts" / "model.joblib"

    print(f"[1] Loading feature columns: {features_path.name} ...")
    with open(features_path, "r", encoding="utf-8") as f:
        expected_columns = json.load(f)
    print(f"    Loaded {len(expected_columns)} feature names.")

    print(f"[2] Loading Random Forest pipeline: {model_path.name} ...")
    model = joblib.load(model_path)
    print(f"    Model pipeline steps: {list(model.named_steps.keys())}")
    print(f"    Classifier classes: {model.classes_}")

    # 2. Simulate 3 distinct realistic network flows
    print("\n[3] Generating simulated test traffic...")
    now = time.time()
    flows: List[Flow] = []

    # FLOW A: Legitimate Bidirectional HTTPS web transaction (Port 443)
    print("    - Flow A: Legitimate HTTPS session (TCP 192.168.1.105:51234 <-> 104.26.12.31:443)")
    t = now
    client_ip = "192.168.1.105"
    server_ip = "104.26.12.31"
    client_port = 51234
    server_port = 443

    # Packets sequence:
    # 1. SYN from client (window 64240)
    pkt1 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(client_ip, server_ip, client_port, server_port, flags=0x02, window_size=64240), t)
    flow_a = Flow(pkt1)

    # 2. SYN-ACK from server (window 65535) after 15ms
    t += 0.015
    pkt2 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(server_ip, client_ip, server_port, client_port, flags=0x12, window_size=65535), t)
    flow_a.add_packet(pkt2)

    # 3. ACK from client after 2ms
    t += 0.002
    pkt3 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(client_ip, server_ip, client_port, server_port, flags=0x10, window_size=64240), t)
    flow_a.add_packet(pkt3)

    # 4. TLS Client Hello (517 bytes payload) after 5ms
    t += 0.005
    pkt4 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(client_ip, server_ip, client_port, server_port, flags=0x18, window_size=64240, payload=b"X" * 517), t)
    flow_a.add_packet(pkt4)

    # 5. TLS Server Hello + Certificate (1420 bytes payload) after 22ms
    t += 0.022
    pkt5 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(server_ip, client_ip, server_port, client_port, flags=0x18, window_size=65535, payload=b"Y" * 1420), t)
    flow_a.add_packet(pkt5)

    # 6. FIN-ACK from client
    t += 0.050
    pkt6 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(client_ip, server_ip, client_port, server_port, flags=0x11, window_size=64240), t)
    flow_a.add_packet(pkt6)

    flows.append(flow_a)

    # FLOW B: Legitimate DNS Query/Response (UDP Port 53)
    print("    - Flow B: Legitimate DNS Query/Response (UDP 192.168.1.105:58432 <-> 8.8.8.8:53)")
    t = now + 1.0
    dns_client_ip = "192.168.1.105"
    dns_server_ip = "8.8.8.8"
    dns_client_port = 58432
    dns_server_port = 53

    # Query: 32 bytes payload
    pkt_dns1 = parse_ipv4_packet(build_raw_ipv4_udp_packet(dns_client_ip, dns_server_ip, dns_client_port, dns_server_port, payload=b"D" * 32), t)
    flow_b = Flow(pkt_dns1)

    # Response: 76 bytes payload after 18ms
    t += 0.018
    pkt_dns2 = parse_ipv4_packet(build_raw_ipv4_udp_packet(dns_server_ip, dns_client_ip, dns_server_port, dns_client_port, payload=b"R" * 76), t)
    flow_b.add_packet(pkt_dns2)

    flows.append(flow_b)

    # FLOW C: Suspicious SYN Scan (Unanswered TCP SYN to Destination Port 445 / SMB)
    print("    - Flow C: Suspicious Unanswered SYN Scan (TCP 10.0.0.99:49152 -> 192.168.1.105:445)")
    t = now + 2.0
    scan_ip = "10.0.0.99"
    victim_ip = "192.168.1.105"
    scan_port = 49152
    target_port = 445

    # Rapid unanswered SYNs with small window (1024)
    pkt_scan1 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(scan_ip, victim_ip, scan_port, target_port, flags=0x02, window_size=1024), t)
    flow_c = Flow(pkt_scan1)

    t += 0.001
    pkt_scan2 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(scan_ip, victim_ip, scan_port, target_port, flags=0x02, window_size=1024), t)
    flow_c.add_packet(pkt_scan2)

    t += 0.001
    pkt_scan3 = parse_ipv4_packet(build_raw_ipv4_tcp_packet(scan_ip, victim_ip, scan_port, target_port, flags=0x02, window_size=1024), t)
    flow_c.add_packet(pkt_scan3)

    flows.append(flow_c)

    # 3. Extract 74 features from each flow
    print("\n[4] Extracting 74-feature vectors from flows...")
    flow_records = []
    meta_records = []

    for idx, f in enumerate(flows):
        feats = f.to_74_features()
        meta = f.metadata()
        flow_records.append(feats)
        meta_records.append(meta)
        print(f"    Flow {idx+1} ({meta['protocol']} {meta['src_ip']}:{meta['src_port']} -> {meta['dst_ip']}:{meta['dst_port']}):")
        print(f"      Packets: {meta['total_packets']}, Bytes: {meta['total_bytes']}, Duration: {feats['Flow Duration']} us")
        print(f"      Fwd_Bwd_Byte_Ratio: {feats['Fwd_Bwd_Byte_Ratio']}, Init_Win_Fwd: {feats['Init_Win_bytes_forward']}, Init_Win_Bwd: {feats['Init_Win_bytes_backward']}")

    df_flows = pd.DataFrame(flow_records)

    # 4. Schema Validation
    print("\n[5] Validating schema against expected feature_columns.json...")
    assert len(df_flows.columns) == 74, f"Expected 74 columns, got {len(df_flows.columns)}"
    assert list(df_flows.columns) == expected_columns, "Column names or ordering do NOT match feature_columns.json!"
    print("    [PASS] Exact 74 feature names and ordering match perfectly.")

    # 5. Run Random Forest Inference
    print("\n[6] Running genuine Random Forest inference...")
    THRESHOLD = 0.05
    probabilities = model.predict_proba(df_flows)
    attack_probabilities = probabilities[:, 1]
    predictions_binary = (attack_probabilities >= THRESHOLD).astype(int)

    print("\n" + "=" * 70)
    print("  INFERENCE RESULTS (Threshold = 0.05)")
    print("=" * 70)
    for idx, meta in enumerate(meta_records):
        prob = attack_probabilities[idx]
        is_attack = bool(predictions_binary[idx])
        label = "ATTACK" if is_attack else "BENIGN"
        confidence = prob if is_attack else (1.0 - prob)

        print(f"Flow {idx+1}: {meta['protocol']} {meta['src_ip']}:{meta['src_port']} -> {meta['dst_ip']}:{meta['dst_port']}")
        print(f"  Classification:     {label}")
        print(f"  Attack Probability: {prob:.4f} ({prob*100:.2f}%)")
        print(f"  Confidence:         {confidence:.4f} ({confidence*100:.2f}%)")
        print(f"  Flow Duration:      {df_flows.loc[idx, 'Flow Duration']} us")
        print("-" * 70)

    print("\n[SUCCESS] Proof of concept passed with 100% schema and model compatibility!")
    return True


if __name__ == "__main__":
    run_proof_of_concept()
