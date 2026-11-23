"""
Sentinel Cyber — Windows Live Network Telemetry & Flow Extraction Sensor
Collects host network interface telemetry (via psutil) AND extracts
bidirectional network flows (74 features) for live ML threat classification.

Security & Privacy:
- Never inspects or stores application payloads.
- Authenticates securely via X-Sentinel-Token.
- Resilient reconnection with backoff.
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Attempt to load .env from multiple probable locations
try:
    from dotenv import load_dotenv
    sensor_dir = Path(__file__).resolve().parent
    backend_dir = sensor_dir.parent
    project_root = backend_dir.parent

    for env_file in [sensor_dir / ".env", backend_dir / ".env", project_root / ".env", Path.cwd() / ".env"]:
        if env_file.exists():
            load_dotenv(env_file)
            break
except ImportError:
    pass

# Import the Flow Extraction Engine
try:
    from flow_extractor import (
        Flow,
        FlowTable,
        PacketInfo,
        parse_ipv4_packet,
        parse_pcap_stream,
    )
except ImportError:
    # If run from another directory, add sensor dir to sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from flow_extractor import (
        Flow,
        FlowTable,
        PacketInfo,
        parse_ipv4_packet,
        parse_pcap_stream,
    )

DEFAULT_API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_SENSOR_TOKEN = os.getenv("SENTINEL_SENSOR_TOKEN", "sentinel-local-dev-token")


class WindowsMonitor:
    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        token: str = DEFAULT_SENSOR_TOKEN,
        capture_mode: str = "auto",
        pcap_file: Optional[str] = None
    ):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.capture_mode = capture_mode
        self.pcap_file = pcap_file

        self.running = False
        self.previous_stats = None
        self.previous_time = None

        # Flow Engine
        self.flow_table = FlowTable(inactivity_timeout_sec=10.0, active_timeout_sec=60.0)
        self.raw_socket = None
        self.local_ip: Optional[str] = None
        self.active_capture_method = "host_counters"
        self.sniff_thread: Optional[threading.Thread] = None

        # Configure resilient HTTP session
        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def detect_local_ip(self) -> str:
        """Find the local IPv4 address connected to the primary gateway."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def init_raw_socket(self) -> bool:
        """
        Attempts to initialize a Windows raw socket (SIO_RCVALL).
        Requires Administrator privileges.
        """
        if sys.platform != "win32":
            return False

        try:
            self.local_ip = self.detect_local_ip()
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable SIO_RCVALL on Windows
            if hasattr(socket, "SIO_RCVALL"):
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            s.setblocking(False)
            self.raw_socket = s
            self.active_capture_method = f"windows_raw_socket ({self.local_ip})"
            print(f"[CAPTURE] Native Windows raw socket bound to {self.local_ip} (SIO_RCVALL enabled).")
            return True
        except PermissionError:
            print("[CAPTURE] Administrator privilege required for native Windows raw sockets.")
            print("          Running in host telemetry mode. (Run as Administrator for live packet capture).")
            return False
        except Exception as exc:
            print(f"[CAPTURE] Native raw socket could not be initialized: {exc}")
            return False

    def get_active_interface_stats(self) -> tuple[str, dict | None]:
        """Detect the primary network interface and its counters."""
        stats = psutil.net_io_counters(pernic=True)

        for preferred in ["Wi-Fi", "Ethernet", "WLAN", "eth0", "en0"]:
            if preferred in stats and (stats[preferred].bytes_sent > 0 or stats[preferred].bytes_recv > 0):
                counter = stats[preferred]
                return preferred, {
                    "bytes_sent": counter.bytes_sent,
                    "bytes_received": counter.bytes_recv,
                    "packets_sent": counter.packets_sent,
                    "packets_received": counter.packets_recv,
                    "errors_in": counter.errin,
                    "errors_out": counter.errout,
                }

        active = [
            (name, counter)
            for name, counter in stats.items()
            if counter.bytes_sent > 0 or counter.bytes_recv > 0
        ]

        if active:
            name, counter = active[0]
            return name, {
                "bytes_sent": counter.bytes_sent,
                "bytes_received": counter.bytes_recv,
                "packets_sent": counter.packets_sent,
                "packets_received": counter.packets_recv,
                "errors_in": counter.errin,
                "errors_out": counter.errout,
            }

        total = psutil.net_io_counters()
        return "All Interfaces", {
            "bytes_sent": total.bytes_sent,
            "bytes_received": total.bytes_recv,
            "packets_sent": total.packets_sent,
            "packets_received": total.packets_recv,
            "errors_in": total.errin,
            "errors_out": total.errout,
        }

    def get_connection_stats(self) -> dict:
        """Count active sockets by protocol and state with graceful permission fallback."""
        try:
            connections = psutil.net_connections(kind="inet")
            tcp = sum(1 for c in connections if c.type == socket.SOCK_STREAM)
            udp = sum(1 for c in connections if c.type == socket.SOCK_DGRAM)
            established = sum(1 for c in connections if getattr(c, "status", "") == "ESTABLISHED")
            return {
                "total": len(connections),
                "tcp": tcp,
                "udp": udp,
                "established": established,
            }
        except Exception:
            return {"total": 0, "tcp": 0, "udp": 0, "established": 0}

    def collect_snapshot(self) -> dict | None:
        """Compute delta throughput and assemble a telemetry snapshot."""
        interface, current = self.get_active_interface_stats()
        if current is None:
            return None

        now = time.time()
        upload_speed = 0.0
        download_speed = 0.0

        if self.previous_stats is not None and self.previous_time is not None:
            elapsed = now - self.previous_time
            if elapsed > 0:
                upload_speed = max(0, current["bytes_sent"] - self.previous_stats["bytes_sent"]) / elapsed / 1024
                download_speed = max(0, current["bytes_received"] - self.previous_stats["bytes_received"]) / elapsed / 1024

        self.previous_stats = current
        self.previous_time = now

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device": socket.gethostname(),
            "interface": interface,
            "upload_kbps": round(upload_speed, 2),
            "download_kbps": round(download_speed, 2),
            "bytes_sent_total": current["bytes_sent"],
            "bytes_received_total": current["bytes_received"],
            "packets_sent": current["packets_sent"],
            "packets_received": current["packets_recv"],
            "errors_in": current["errors_in"],
            "errors_out": current["errors_out"],
            "connections": self.get_connection_stats(),
        }

    def send_snapshot(self, snapshot: dict) -> bool:
        """Transmit telemetry payload to the FastAPI backend over HTTPS or HTTP."""
        url = f"{self.api_url}/api/sensor/snapshot"
        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Token": self.token,
        }

        try:
            response = self.session.post(url, json=snapshot, headers=headers, timeout=5.0)
            return response.status_code == 200
        except Exception:
            return False

    def send_flows(self, flows: List[Flow]) -> tuple[bool, int, int]:
        """
        Extracts 74 features from completed flows, validates schema, and
        transmits flow batch to /api/sensor/flows for ML classification.
        Returns: (success, total_flows, attacks_detected)
        """
        if not flows:
            return True, 0, 0

        flow_items = []
        for f in flows:
            feats = f.to_74_features()
            meta = f.metadata()
            flow_items.append({
                "metadata": meta,
                "features": feats
            })

        payload = {
            "device": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "capture_method": self.active_capture_method,
            "flows": flow_items
        }

        url = f"{self.api_url}/api/sensor/flows"
        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Token": self.token,
        }

        try:
            response = self.session.post(url, json=payload, headers=headers, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                processed = data.get("processed_count", len(flows))
                malicious = data.get("malicious_count", 0)
                return True, processed, malicious
            else:
                return False, 0, 0
        except Exception:
            return False, 0, 0

    def poll_packets(self, max_packets: int = 50) -> int:
        """Non-blocking poll of raw socket for incoming packets."""
        if not self.raw_socket:
            return 0

        count = 0
        now = time.time()

        while count < max_packets:
            try:
                r, _, _ = select.select([self.raw_socket], [], [], 0.0)
                if not r:
                    break
                raw_bytes, _ = self.raw_socket.recvfrom(65535)
                pkt = parse_ipv4_packet(raw_bytes, now)
                if pkt is not None:
                    self.flow_table.process_packet(pkt)
                    count += 1
            except Exception:
                break

        return count

    def load_pcap_file(self, pcap_path: str):
        """Loads and processes packets from an offline PCAP capture file."""
        p = Path(pcap_path)
        if not p.exists():
            print(f"[WARN] PCAP file not found: {pcap_path}")
            return

        print(f"[CAPTURE] Ingesting packets from PCAP: {p.name} ...")
        content = p.read_bytes()
        count = 0
        for pkt in parse_pcap_stream(content):
            self.flow_table.process_packet(pkt)
            count += 1
        self.active_capture_method = f"pcap_file ({p.name})"
        print(f"[CAPTURE] Ingested {count} packets from PCAP.")

    def start(self, interval: int = 3):
        self.running = True

        print("\n" + "=" * 65)
        print("          SENTINEL CYBER — LIVE NETWORK SENSOR v2.0")
        print("=" * 65)
        print(f"Device:             {socket.gethostname()}")
        print(f"Target Backend:     {self.api_url}")
        print(f"Auth Token:         {'[Configured: ' + self.token[:4] + '***]' if self.token else '[None / Default Dev]'}")
        print(f"Sampling Interval:  {interval} seconds")
        print(f"Capture Mode:       {self.capture_mode}")

        # Setup sniffer
        if self.pcap_file:
            self.load_pcap_file(self.pcap_file)
        elif self.capture_mode in ["auto", "socket"]:
            self.init_raw_socket()

        print(f"Active Capture:     {self.active_capture_method}")
        print("=" * 65)
        print("Press CTRL+C to terminate sensor.\n")

        consecutive_failures = 0

        try:
            while self.running:
                loop_start = time.time()

                # 1. Poll packets if live sniffer is active
                pkts_captured = self.poll_packets(max_packets=100)

                # 2. Check for expired flows to classify
                expired_flows = self.flow_table.flush_expired(loop_start)
                flows_ok, flows_processed, flows_attack = self.send_flows(expired_flows)

                # 3. Collect & send host interface telemetry
                snapshot = self.collect_snapshot()
                telemetry_ok = self.send_snapshot(snapshot) if snapshot else False

                if telemetry_ok:
                    consecutive_failures = 0
                    status_flag = "SUCCESS (LIVE)"
                else:
                    consecutive_failures += 1
                    status_flag = f"RETRYING ({consecutive_failures} fails)"

                c = snapshot["connections"] if snapshot else {"total": 0, "tcp": 0, "udp": 0}
                ts_str = snapshot["timestamp"][11:19] if snapshot else time.strftime("%H:%M:%S")

                flow_status_str = (
                    f"Flows: {flows_processed} classified ({flows_attack} attacks)"
                    if flows_processed > 0
                    else "Flows: 0 active"
                )

                print(
                    f"[{ts_str}] "
                    f"NIC: {snapshot['interface'][:8]:<8} | "
                    f"Up: {snapshot['upload_kbps']:>6.1f}KB/s | "
                    f"Down: {snapshot['download_kbps']:>6.1f}KB/s | "
                    f"Sockets: {c['total']:<3} | "
                    f"{flow_status_str:<26} | "
                    f"API: {status_flag}"
                )

                elapsed = time.time() - loop_start
                sleep_time = max(0.1, interval - elapsed)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            self.running = False
            # Flush any remaining flows before stopping
            final_flows = self.flow_table.flush_all()
            if final_flows:
                print(f"\n[FLUSH] Flushing remaining {len(final_flows)} flows before shutdown...")
                self.send_flows(final_flows)
            print("\n[STOP] Sentinel live network sensor terminated cleanly.")
        finally:
            if self.raw_socket:
                try:
                    if hasattr(socket, "SIO_RCVALL"):
                        self.raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    self.raw_socket.close()
                except Exception:
                    pass
            self.session.close()


def main():
    parser = argparse.ArgumentParser(description="Sentinel Cyber Windows Network Sensor v2.0")
    parser.add_argument("--url", default=DEFAULT_API_URL, help="Backend URL (default: http://127.0.0.1:8000 or from .env)")
    parser.add_argument("--token", default=DEFAULT_SENSOR_TOKEN, help="X-Sentinel-Token")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds (default: 3)")
    parser.add_argument("--capture", default="auto", choices=["auto", "socket", "pcap", "none"], help="Capture mode")
    parser.add_argument("--pcap", default=None, help="Path to PCAP file to ingest")

    args = parser.parse_args()
    monitor = WindowsMonitor(
        api_url=args.url,
        token=args.token,
        capture_mode=args.capture,
        pcap_file=args.pcap
    )
    monitor.start(interval=args.interval)


if __name__ == "__main__":
    main()
