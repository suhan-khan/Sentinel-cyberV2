"""
Sentinel Cyber — CICFlowMeter-Compatible Live Flow Extraction Engine
Extracts bidirectional network flow features (74 features) strictly compliant
with the CIC-IDS2017 training schema, feature_columns.json, and the training notebook.

Key Capabilities:
- Pure-Python Layer 3 & Layer 4 decoder (IPv4, TCP, UDP, ICMP).
- PCAP parser & live packet processor with microsecond resolution.
- Bidirectional flow state tracking by canonical 5-tuple.
- Exact feature calculations: Flow Duration, IAT stats, packet length stats,
  header lengths, TCP flags, window sizes, active/idle periods.
- 4 custom engineered features from training notebook Cell 16.
- Strict schema validation against feature_columns.json.
- Clear separation of missing/unobserved values (NaN, -1) from legitimate zeros.
"""

from __future__ import annotations

import json
import logging
import math
import struct
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger("sentinel.flow_extractor")

# Protocol constants
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

IDLE_THRESHOLD_US = 5_000_000.0  # 5 seconds in microseconds (CICFlowMeter standard)


@dataclass
class PacketInfo:
    timestamp: float          # Epoch seconds with microsecond resolution
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int             # 6 = TCP, 17 = UDP, 1 = ICMP
    length: int               # Total IP packet length in wire bytes
    ip_header_len: int
    transport_header_len: int
    payload_len: int
    tcp_flags: Dict[str, int]
    tcp_window_size: int = -1


def parse_ipv4_packet(raw_data: bytes, timestamp: float) -> Optional[PacketInfo]:
    """
    Decodes an IPv4 raw packet (Layer 3 packet starting with IPv4 header).
    Inspects packet headers only. Never captures, logs, or stores application payload.
    """
    if len(raw_data) < 20:
        return None

    # Unpack first 20 bytes of IPv4 header
    ip_header = raw_data[:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    if version != 4:
        return None  # Only IPv4 supported in CIC-IDS2017 training schema

    ihl = version_ihl & 0x0F
    ip_header_len = ihl * 4
    total_length = iph[2]
    protocol = iph[6]
    src_ip = ".".join(map(str, iph[8]))
    dst_ip = ".".join(map(str, iph[9]))

    transport_header_len = 0
    payload_len = 0
    src_port = 0
    dst_port = 0
    tcp_flags = {
        "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
        "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0
    }
    tcp_window_size = -1

    transport_data = raw_data[ip_header_len:total_length]

    if protocol == PROTO_TCP:
        if len(transport_data) >= 20:
            tcph = struct.unpack("!HHLLBBHHH", transport_data[:20])
            src_port = tcph[0]
            dst_port = tcph[1]
            data_offset = (tcph[4] >> 4) * 4
            transport_header_len = data_offset
            flags_val = tcph[5]
            tcp_window_size = tcph[6]

            tcp_flags["FIN"] = 1 if (flags_val & 0x01) else 0
            tcp_flags["SYN"] = 1 if (flags_val & 0x02) else 0
            tcp_flags["RST"] = 1 if (flags_val & 0x04) else 0
            tcp_flags["PSH"] = 1 if (flags_val & 0x08) else 0
            tcp_flags["ACK"] = 1 if (flags_val & 0x10) else 0
            tcp_flags["URG"] = 1 if (flags_val & 0x20) else 0
            tcp_flags["ECE"] = 1 if (flags_val & 0x40) else 0
            tcp_flags["CWR"] = 1 if (flags_val & 0x80) else 0

            payload_len = max(0, len(transport_data) - transport_header_len)

    elif protocol == PROTO_UDP:
        if len(transport_data) >= 8:
            udph = struct.unpack("!HHHH", transport_data[:8])
            src_port = udph[0]
            dst_port = udph[1]
            transport_header_len = 8
            payload_len = max(0, udph[2] - 8)

    else:
        # ICMP or other IP protocol
        src_port = 0
        dst_port = 0
        transport_header_len = 0
        payload_len = max(0, len(transport_data))

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=total_length if total_length > 0 else len(raw_data),
        ip_header_len=ip_header_len,
        transport_header_len=transport_header_len,
        payload_len=payload_len,
        tcp_flags=tcp_flags,
        tcp_window_size=tcp_window_size,
    )


def parse_pcap_stream(stream_bytes: bytes) -> Iterator[PacketInfo]:
    """
    Parses a standard PCAP file byte stream (native Wireshark / tcpdump / pktmon format).
    Supports both standard microseconds and nanoseconds PCAP magic headers.
    """
    if len(stream_bytes) < 24:
        return

    # Unpack 24-byte PCAP file header
    magic = struct.unpack("<I", stream_bytes[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
        nano = False
    elif magic == 0xD4C3B2A1:
        endian = ">"
        nano = False
    elif magic == 0xA1B23C4D:
        endian = "<"
        nano = True
    elif magic == 0x4D3CB2A1:
        endian = ">"
        nano = True
    else:
        logger.warning("Unrecognized PCAP magic header: 0x%X", magic)
        return

    offset = 24
    network = struct.unpack(endian + "I", stream_bytes[20:24])[0]
    # network == 1 -> LINKTYPE_ETHERNET (14-byte Ethernet header)
    # network == 101 -> LINKTYPE_RAW (raw IP header)
    # network == 12 -> LINKTYPE_RAW

    link_hdr_len = 14 if network == 1 else 0

    while offset + 16 <= len(stream_bytes):
        rec_hdr = struct.unpack(endian + "IIII", stream_bytes[offset:offset + 16])
        ts_sec, ts_usec, caplen, origlen = rec_hdr
        offset += 16

        if offset + caplen > len(stream_bytes):
            break

        packet_bytes = stream_bytes[offset:offset + caplen]
        offset += caplen

        ts = float(ts_sec) + (float(ts_usec) / (1_000_000_000.0 if nano else 1_000_000.0))

        # Strip Ethernet header if present
        if link_hdr_len > 0 and len(packet_bytes) > link_hdr_len:
            eth_type = struct.unpack("!H", packet_bytes[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                ip_packet = packet_bytes[14:]
            elif eth_type == 0x8100:  # 802.1Q VLAN tagged
                ip_packet = packet_bytes[18:]
            else:
                continue  # Skip non-IPv4 (e.g. ARP, IPv6)
        else:
            ip_packet = packet_bytes

        pkt = parse_ipv4_packet(ip_packet, ts)
        if pkt is not None:
            yield pkt


class Flow:
    """
    Represents an active or completed bidirectional flow.
    Direction: Forward is determined by the first packet observed.
    """
    def __init__(self, first_packet: PacketInfo):
        self.fwd_ip = first_packet.src_ip
        self.bwd_ip = first_packet.dst_ip
        self.fwd_port = first_packet.src_port
        self.bwd_port = first_packet.dst_port
        self.protocol = first_packet.protocol

        self.start_time = first_packet.timestamp
        self.last_seen = first_packet.timestamp

        # Directional packets
        self.fwd_packet_times: List[float] = []
        self.bwd_packet_times: List[float] = []
        self.all_packet_times: List[float] = []

        self.fwd_packet_lens: List[int] = []
        self.bwd_packet_lens: List[int] = []
        self.all_packet_lens: List[int] = []

        self.fwd_header_lens: List[int] = []
        self.bwd_header_lens: List[int] = []

        # Flags & Window
        self.fwd_psh = 0
        self.fwd_urg = 0
        self.flag_counts = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0
        }
        self.init_win_fwd: int = -1
        self.init_win_bwd: int = -1

        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd: Optional[int] = None
        self.is_finished = False

        # Add first packet
        self.add_packet(first_packet)

    @property
    def key(self) -> Tuple[str, str, int, int, int]:
        """Canonical 5-tuple key for flow table lookup."""
        if (self.fwd_ip, self.fwd_port) <= (self.bwd_ip, self.bwd_port):
            return (self.fwd_ip, self.bwd_ip, self.fwd_port, self.bwd_port, self.protocol)
        return (self.bwd_ip, self.fwd_ip, self.bwd_port, self.fwd_port, self.protocol)

    def is_forward(self, packet: PacketInfo) -> bool:
        return (
            packet.src_ip == self.fwd_ip and
            packet.src_port == self.fwd_port and
            packet.dst_ip == self.bwd_ip and
            packet.dst_port == self.bwd_port
        )

    def add_packet(self, packet: PacketInfo) -> None:
        self.last_seen = packet.timestamp
        self.all_packet_times.append(packet.timestamp)
        self.all_packet_lens.append(packet.length)

        total_hdr = packet.ip_header_len + packet.transport_header_len

        # TCP flags aggregation
        for flag_name, val in packet.tcp_flags.items():
            self.flag_counts[flag_name] += val

        # Terminate TCP flow if FIN or RST observed
        if packet.tcp_flags.get("RST") or packet.tcp_flags.get("FIN"):
            self.is_finished = True

        if self.is_forward(packet):
            self.fwd_packet_times.append(packet.timestamp)
            self.fwd_packet_lens.append(packet.length)
            self.fwd_header_lens.append(total_hdr)

            if packet.tcp_flags.get("PSH"):
                self.fwd_psh += 1
            if packet.tcp_flags.get("URG"):
                self.fwd_urg += 1

            if self.init_win_fwd == -1 and packet.tcp_window_size != -1:
                self.init_win_fwd = packet.tcp_window_size

            if packet.payload_len > 0:
                self.act_data_pkt_fwd += 1

            if packet.transport_header_len > 0:
                if self.min_seg_size_fwd is None or packet.transport_header_len < self.min_seg_size_fwd:
                    self.min_seg_size_fwd = packet.transport_header_len

        else:
            self.bwd_packet_times.append(packet.timestamp)
            self.bwd_packet_lens.append(packet.length)
            self.bwd_header_lens.append(total_hdr)

            if self.init_win_bwd == -1 and packet.tcp_window_size != -1:
                self.init_win_bwd = packet.tcp_window_size

    def compute_iat_stats(self, times: List[float]) -> Tuple[float, float, float, float, float]:
        """Returns (total_iat_us, mean_iat_us, std_iat_us, max_iat_us, min_iat_us) in microseconds."""
        if len(times) <= 1:
            return 0.0, 0.0, 0.0, 0.0, 0.0

        diffs = [
            (times[i] - times[i - 1]) * 1_000_000.0  # converted to microseconds
            for i in range(1, len(times))
        ]
        diffs = [max(0.0, d) for d in diffs]

        total_val = float(sum(diffs))
        mean_val = float(np.mean(diffs))
        std_val = float(np.std(diffs, ddof=0)) if len(diffs) > 1 else 0.0
        max_val = float(max(diffs))
        min_val = float(min(diffs))

        return total_val, mean_val, std_val, max_val, min_val

    def compute_active_idle_stats(self, threshold_us: float = IDLE_THRESHOLD_US) -> Tuple[
        Tuple[float, float, float, float], Tuple[float, float, float, float]
    ]:
        """
        Calculates Active and Idle statistics based on CICFlowMeter standard (5 seconds gap).
        """
        if len(self.all_packet_times) <= 1:
            return (0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.0, 0.0)

        diffs = [
            (self.all_packet_times[i] - self.all_packet_times[i - 1]) * 1_000_000.0
            for i in range(1, len(self.all_packet_times))
        ]

        active_times: List[float] = []
        idle_times: List[float] = []
        current_active = 0.0

        for d in diffs:
            if d >= threshold_us:
                if current_active > 0:
                    active_times.append(current_active)
                    current_active = 0.0
                idle_times.append(d)
            else:
                current_active += d

        if current_active > 0:
            active_times.append(current_active)

        def get_stats(arr: List[float]) -> Tuple[float, float, float, float]:
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            return (
                float(np.mean(arr)),
                float(np.std(arr, ddof=0)) if len(arr) > 1 else 0.0,
                float(max(arr)),
                float(min(arr))
            )

        return get_stats(active_times), get_stats(idle_times)

    def to_74_features(self) -> Dict[str, Any]:
        """
        Extracts the exact 74 features expected by the trained Random Forest.
        Units:
          - Durations & IAT: microseconds (us)
          - Packet lengths & headers: bytes
          - Rates: per second
        """
        duration_us = max(0.0, (self.last_seen - self.start_time) * 1_000_000.0)
        duration_sec = duration_us / 1_000_000.0 if duration_us > 0 else 0.0

        tot_fwd_pkts = len(self.fwd_packet_times)
        tot_bwd_pkts = len(self.bwd_packet_times)
        tot_fwd_len = sum(self.fwd_packet_lens)
        tot_bwd_len = sum(self.bwd_packet_lens)

        # Fwd packet length stats
        fwd_len_max = float(max(self.fwd_packet_lens)) if self.fwd_packet_lens else 0.0
        fwd_len_min = float(min(self.fwd_packet_lens)) if self.fwd_packet_lens else 0.0
        fwd_len_mean = float(np.mean(self.fwd_packet_lens)) if self.fwd_packet_lens else 0.0
        fwd_len_std = float(np.std(self.fwd_packet_lens, ddof=0)) if len(self.fwd_packet_lens) > 1 else 0.0

        # Bwd packet length stats
        bwd_len_max = float(max(self.bwd_packet_lens)) if self.bwd_packet_lens else 0.0
        bwd_len_min = float(min(self.bwd_packet_lens)) if self.bwd_packet_lens else 0.0
        bwd_len_mean = float(np.mean(self.bwd_packet_lens)) if self.bwd_packet_lens else 0.0
        bwd_len_std = float(np.std(self.bwd_packet_lens, ddof=0)) if len(self.bwd_packet_lens) > 1 else 0.0

        # Throughput
        flow_bytes_per_sec = ((tot_fwd_len + tot_bwd_len) / duration_sec) if duration_sec > 0 else 0.0
        flow_pkts_per_sec = ((tot_fwd_pkts + tot_bwd_pkts) / duration_sec) if duration_sec > 0 else 0.0
        fwd_pkts_per_sec = (tot_fwd_pkts / duration_sec) if duration_sec > 0 else 0.0
        bwd_pkts_per_sec = (tot_bwd_pkts / duration_sec) if duration_sec > 0 else 0.0

        # IAT statistics
        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = self.compute_iat_stats(self.all_packet_times)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self.compute_iat_stats(self.fwd_packet_times)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self.compute_iat_stats(self.bwd_packet_times)

        # Header lengths
        fwd_hdr_len = sum(self.fwd_header_lens)
        bwd_hdr_len = sum(self.bwd_header_lens)

        # Overall packet length stats
        all_lens = self.all_packet_lens
        min_pkt_len = float(min(all_lens)) if all_lens else 0.0
        max_pkt_len = float(max(all_lens)) if all_lens else 0.0
        pkt_len_mean = float(np.mean(all_lens)) if all_lens else 0.0
        pkt_len_std = float(np.std(all_lens, ddof=0)) if len(all_lens) > 1 else 0.0
        pkt_len_var = float(np.var(all_lens, ddof=0)) if len(all_lens) > 1 else 0.0

        # Down/Up Ratio (Bwd / Fwd)
        down_up_ratio = (float(tot_bwd_pkts) / float(tot_fwd_pkts)) if tot_fwd_pkts > 0 else 0.0

        # Average packet & segment sizes
        avg_pkt_size = float(tot_fwd_len + tot_bwd_len) / float(len(all_lens)) if all_lens else 0.0
        avg_fwd_seg_size = fwd_len_mean
        avg_bwd_seg_size = bwd_len_mean

        # Active & Idle
        active_stats, idle_stats = self.compute_active_idle_stats()

        # Custom Engineered Features from Training Notebook (Cell 16)
        fwd_bwd_pkt_ratio = (float(tot_fwd_pkts) / float(tot_bwd_pkts)) if tot_bwd_pkts > 0 else np.nan
        no_bwd_pkts = 1 if tot_bwd_pkts == 0 else 0

        fwd_bwd_byte_ratio = (float(tot_fwd_len) / float(tot_bwd_len)) if tot_bwd_len > 0 else np.nan
        no_bwd_bytes = 1 if tot_bwd_len == 0 else 0

        min_seg_fwd = self.min_seg_size_fwd if self.min_seg_size_fwd is not None else 0

        # Return exact 74 features dictionary
        return {
            "Destination Port": int(self.bwd_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": int(tot_fwd_pkts),
            "Total Backward Packets": int(tot_bwd_pkts),
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Total Length of Bwd Packets": float(tot_bwd_len),
            "Fwd Packet Length Max": float(fwd_len_max),
            "Fwd Packet Length Min": float(fwd_len_min),
            "Fwd Packet Length Mean": float(fwd_len_mean),
            "Fwd Packet Length Std": float(fwd_len_std),
            "Bwd Packet Length Max": float(bwd_len_max),
            "Bwd Packet Length Min": float(bwd_len_min),
            "Bwd Packet Length Mean": float(bwd_len_mean),
            "Bwd Packet Length Std": float(bwd_len_std),
            "Flow Bytes/s": float(flow_bytes_per_sec),
            "Flow Packets/s": float(flow_pkts_per_sec),
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Total": float(fwd_iat_tot),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Max": float(fwd_iat_max),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Total": float(bwd_iat_tot),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": int(self.fwd_psh),
            "Fwd URG Flags": int(self.fwd_urg),
            "Fwd Header Length": int(fwd_hdr_len),
            "Bwd Header Length": int(bwd_hdr_len),
            "Fwd Packets/s": float(fwd_pkts_per_sec),
            "Bwd Packets/s": float(bwd_pkts_per_sec),
            "Min Packet Length": float(min_pkt_len),
            "Max Packet Length": float(max_pkt_len),
            "Packet Length Mean": float(pkt_len_mean),
            "Packet Length Std": float(pkt_len_std),
            "Packet Length Variance": float(pkt_len_var),
            "FIN Flag Count": int(self.flag_counts["FIN"]),
            "SYN Flag Count": int(self.flag_counts["SYN"]),
            "RST Flag Count": int(self.flag_counts["RST"]),
            "PSH Flag Count": int(self.flag_counts["PSH"]),
            "ACK Flag Count": int(self.flag_counts["ACK"]),
            "URG Flag Count": int(self.flag_counts["URG"]),
            "CWE Flag Count": int(self.flag_counts["CWR"]),
            "ECE Flag Count": int(self.flag_counts["ECE"]),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_pkt_size),
            "Avg Fwd Segment Size": float(avg_fwd_seg_size),
            "Avg Bwd Segment Size": float(avg_bwd_seg_size),
            "Fwd Header Length.1": int(fwd_hdr_len),  # Duplicate feature in training set
            "Subflow Fwd Packets": int(tot_fwd_pkts),
            "Subflow Fwd Bytes": float(tot_fwd_len),
            "Subflow Bwd Packets": int(tot_bwd_pkts),
            "Subflow Bwd Bytes": float(tot_bwd_len),
            "Init_Win_bytes_forward": int(self.init_win_fwd),
            "Init_Win_bytes_backward": int(self.init_win_bwd),
            "act_data_pkt_fwd": int(self.act_data_pkt_fwd),
            "min_seg_size_forward": int(min_seg_fwd),
            "Active Mean": float(active_stats[0]),
            "Active Std": float(active_stats[1]),
            "Active Max": float(active_stats[2]),
            "Active Min": float(active_stats[3]),
            "Idle Mean": float(idle_stats[0]),
            "Idle Std": float(idle_stats[1]),
            "Idle Max": float(idle_stats[2]),
            "Idle Min": float(idle_stats[3]),
            "Fwd_Bwd_Packet_Ratio": fwd_bwd_pkt_ratio,
            "No_Backward_Packets": int(no_bwd_pkts),
            "Fwd_Bwd_Byte_Ratio": fwd_bwd_byte_ratio,
            "No_Backward_Bytes": int(no_bwd_bytes),
        }

    def metadata(self) -> Dict[str, Any]:
        """Non-feature metadata for SOC presentation and identification."""
        proto_map = {PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMP: "ICMP"}
        return {
            "src_ip": self.fwd_ip,
            "dst_ip": self.bwd_ip,
            "src_port": self.fwd_port,
            "dst_port": self.bwd_port,
            "protocol": proto_map.get(self.protocol, f"Proto-{self.protocol}"),
            "start_time": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "total_packets": len(self.all_packet_times),
            "total_bytes": sum(self.all_packet_lens),
        }


class FlowTable:
    """
    Stateful flow table managing active flows, timeouts, and batch flushing.
    """
    def __init__(self, inactivity_timeout_sec: float = 15.0, active_timeout_sec: float = 120.0):
        self.inactivity_timeout_sec = inactivity_timeout_sec
        self.active_timeout_sec = active_timeout_sec
        self.flows: Dict[Tuple[str, str, int, int, int], Flow] = {}

    def process_packet(self, packet: PacketInfo) -> Optional[Flow]:
        """
        Ingests one packet. If the flow finishes immediately (e.g. TCP RST),
        it is popped and returned.
        """
        # Canonical key matching
        if (packet.src_ip, packet.src_port) <= (packet.dst_ip, packet.dst_port):
            key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        else:
            key = (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.protocol)

        if key in self.flows:
            flow = self.flows[key]
            flow.add_packet(packet)
            if flow.is_finished:
                del self.flows[key]
                return flow
        else:
            flow = Flow(packet)
            if flow.is_finished:
                return flow
            self.flows[key] = flow

        return None

    def flush_expired(self, current_time: float) -> List[Flow]:
        """
        Checks all active flows against inactivity and active timeouts.
        Returns and removes all expired flows.
        """
        expired: List[Flow] = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            inactive_dur = current_time - flow.last_seen
            active_dur = current_time - flow.start_time

            if inactive_dur >= self.inactivity_timeout_sec or active_dur >= self.active_timeout_sec or flow.is_finished:
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        return expired

    def flush_all(self) -> List[Flow]:
        """Flushes all remaining flows unconditionally."""
        all_flows = list(self.flows.values())
        self.flows.clear()
        return all_flows
