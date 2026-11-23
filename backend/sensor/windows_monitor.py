
"""
Sentinel Cyber V2 — Windows Network Telemetry Sensor
Collects host network interface telemetry and optionally processes
network flow metadata for defensive ML classification.

Privacy:
- Does not inspect application payloads.
- Authenticates with X-Sentinel-Token.
- Reports diagnostic HTTP errors without exposing the token.
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import psutil
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# --------------------------------------------------
# ENVIRONMENT CONFIGURATION
# --------------------------------------------------

try:
    from dotenv import load_dotenv

    sensor_dir = Path(__file__).resolve().parent
    backend_dir = sensor_dir.parent
    project_root = backend_dir.parent

    for env_file in [
        sensor_dir / ".env",
        backend_dir / ".env",
        project_root / ".env",
        Path.cwd() / ".env",
    ]:
        if env_file.exists():
            load_dotenv(env_file)
            break

except ImportError:
    pass


# --------------------------------------------------
# FLOW EXTRACTION ENGINE
# --------------------------------------------------

try:
    from flow_extractor import (
        Flow,
        FlowTable,
        parse_ipv4_packet,
        parse_pcap_stream,
    )

except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    from flow_extractor import (
        Flow,
        FlowTable,
        parse_ipv4_packet,
        parse_pcap_stream,
    )


# --------------------------------------------------
# DEFAULT CONFIGURATION
# --------------------------------------------------

DEFAULT_API_URL = os.getenv(
    "SENTINEL_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

DEFAULT_SENSOR_TOKEN = os.getenv(
    "SENTINEL_SENSOR_TOKEN",
    "sentinel-local-dev-token",
)


# --------------------------------------------------
# WINDOWS MONITOR
# --------------------------------------------------

class WindowsMonitor:

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        token: str = DEFAULT_SENSOR_TOKEN,
        capture_mode: str = "auto",
        pcap_file: Optional[str] = None,
    ):

        self.api_url = api_url.rstrip("/")
        self.token = token
        self.capture_mode = capture_mode
        self.pcap_file = pcap_file

        self.running = False
        self.previous_stats = None
        self.previous_time = None

        self.flow_table = FlowTable(
            inactivity_timeout_sec=10.0,
            active_timeout_sec=60.0,
        )

        self.raw_socket = None
        self.local_ip: Optional[str] = None
        self.active_capture_method = "host_counters"

        self.session = requests.Session()

        retries = Retry(
            total=3,
            connect=3,
            read=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )

        adapter = HTTPAdapter(max_retries=retries)

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # --------------------------------------------------
    # NETWORK INTERFACE DETECTION
    # --------------------------------------------------

    def detect_local_ip(self) -> str:

        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            ) as s:

                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]

        except Exception:
            return "127.0.0.1"

    # --------------------------------------------------
    # OPTIONAL RAW SOCKET INITIALIZATION
    # --------------------------------------------------

    def init_raw_socket(self) -> bool:

        if sys.platform != "win32":
            return False

        try:
            self.local_ip = self.detect_local_ip()

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP,
            )

            s.bind((self.local_ip, 0))

            s.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_HDRINCL,
                1,
            )

            if hasattr(socket, "SIO_RCVALL"):
                s.ioctl(
                    socket.SIO_RCVALL,
                    socket.RCVALL_ON,
                )

            s.setblocking(False)
            self.raw_socket = s

            self.active_capture_method = (
                f"windows_raw_socket ({self.local_ip})"
            )

            print(
                f"[CAPTURE] Native socket initialized "
                f"on {self.local_ip}."
            )

            return True

        except PermissionError:
            print(
                "[CAPTURE] Required permission unavailable. "
                "Using host telemetry only."
            )
            return False

        except Exception as exc:
            print(f"[CAPTURE] Initialization failed: {exc}")
            return False

    # --------------------------------------------------
    # INTERFACE STATISTICS
    # --------------------------------------------------

    def get_active_interface_stats(self) -> tuple[str, dict | None]:

        stats = psutil.net_io_counters(pernic=True)

        preferred_names = [
            "Wi-Fi",
            "Ethernet",
            "WLAN",
            "eth0",
            "en0",
        ]

        for preferred in preferred_names:

            if preferred in stats:

                counter = stats[preferred]

                if counter.bytes_sent > 0 or counter.bytes_recv > 0:
                    return preferred, self._counter_dict(counter)

        active = [
            (name, counter)
            for name, counter in stats.items()
            if counter.bytes_sent > 0 or counter.bytes_recv > 0
        ]

        if active:
            name, counter = active[0]
            return name, self._counter_dict(counter)

        total = psutil.net_io_counters()

        if total is None:
            return "Unknown", None

        return "All Interfaces", self._counter_dict(total)

    @staticmethod
    def _counter_dict(counter) -> dict:

        return {
            "bytes_sent": counter.bytes_sent,
            "bytes_received": counter.bytes_recv,
            "packets_sent": counter.packets_sent,
            "packets_received": counter.packets_recv,
            "errors_in": counter.errin,
            "errors_out": counter.errout,
        }

    # --------------------------------------------------
    # CONNECTION STATISTICS
    # --------------------------------------------------

    def get_connection_stats(self) -> dict:

        try:
            connections = psutil.net_connections(kind="inet")

            tcp = sum(
                1 for c in connections
                if c.type == socket.SOCK_STREAM
            )

            udp = sum(
                1 for c in connections
                if c.type == socket.SOCK_DGRAM
            )

            established = sum(
                1 for c in connections
                if getattr(c, "status", "") == "ESTABLISHED"
            )

            return {
                "total": len(connections),
                "tcp": tcp,
                "udp": udp,
                "established": established,
            }

        except Exception as exc:
            print(f"[SENSOR] Connection statistics unavailable: {exc}")

            return {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "established": 0,
            }

    # --------------------------------------------------
    # SNAPSHOT COLLECTION
    # --------------------------------------------------

    def collect_snapshot(self) -> dict | None:

        interface, current = self.get_active_interface_stats()

        if current is None:
            return None

        now = time.time()

        upload_speed = 0.0
        download_speed = 0.0

        if (
            self.previous_stats is not None
            and self.previous_time is not None
        ):

            elapsed = now - self.previous_time

            if elapsed > 0:

                upload_speed = max(
                    0,
                    current["bytes_sent"]
                    - self.previous_stats["bytes_sent"],
                ) / elapsed / 1024

                download_speed = max(
                    0,
                    current["bytes_received"]
                    - self.previous_stats["bytes_received"],
                ) / elapsed / 1024

        self.previous_stats = current
        self.previous_time = now

        return {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "device": socket.gethostname(),
            "interface": interface,

            "upload_kbps": round(upload_speed, 2),
            "download_kbps": round(download_speed, 2),

            "bytes_sent_total": current["bytes_sent"],
            "bytes_received_total": current["bytes_received"],

            "packets_sent": current["packets_sent"],
            "packets_received": current["packets_received"],

            "errors_in": current["errors_in"],
            "errors_out": current["errors_out"],

            "connections": self.get_connection_stats(),
        }

    # --------------------------------------------------
    # HTTP DIAGNOSTICS
    # --------------------------------------------------

    @staticmethod
    def print_http_error(response, url: str, label: str):

        print(
            f"\n[API] {label} rejected: "
            f"HTTP {response.status_code}"
        )

        print(
            f"[API] Response headers: "
            f"{dict(response.headers)}"
        )

        print(
            f"[API] Response body: "
            f"{response.text[:1000]!r}"
        )

        print(f"[API] Request URL: {url}\n")

    # --------------------------------------------------
    # SNAPSHOT TRANSMISSION
    # --------------------------------------------------

    def send_snapshot(self, snapshot: dict) -> bool:

        if not isinstance(snapshot, dict):
            print("[API] Cannot send an empty or invalid snapshot.")
            return False

        url = f"{self.api_url}/api/sensor/snapshot"

        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Token": self.token,
        }

        try:
            response = self.session.post(
                url,
                json=snapshot,
                headers=headers,
                timeout=10.0,
            )

            if response.status_code != 200:
                self.print_http_error(
                    response,
                    url,
                    "Snapshot",
                )
                return False

            return True

        except requests.RequestException as exc:
            print(
                f"[API] Snapshot request failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return False

    # --------------------------------------------------
    # FLOW TRANSMISSION
    # --------------------------------------------------

    def send_flows(
        self,
        flows: List[Flow],
    ) -> tuple[bool, int, int]:

        if not flows:
            return True, 0, 0

        flow_items = []

        for flow in flows:
            flow_items.append({
                "metadata": flow.metadata(),
                "features": flow.to_74_features(),
            })

        payload = {
            "device": socket.gethostname(),

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "capture_method": self.active_capture_method,
            "flows": flow_items,
        }

        url = f"{self.api_url}/api/sensor/flows"

        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Token": self.token,
        }

        try:
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=10.0,
            )

            if response.status_code == 200:

                data = response.json()

                return (
                    True,
                    data.get("processed_count", len(flows)),
                    data.get("malicious_count", 0),
                )

            self.print_http_error(
                response,
                url,
                "Flow submission",
            )

            return False, 0, 0

        except requests.RequestException as exc:
            print(
                f"[API] Flow request failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return False, 0, 0

        except ValueError as exc:
            print(f"[API] Invalid flow response: {exc}")
            return False, 0, 0

    # --------------------------------------------------
    # PACKET POLLING
    # --------------------------------------------------

    def poll_packets(self, max_packets: int = 50) -> int:

        if not self.raw_socket:
            return 0

        count = 0
        now = time.time()

        while count < max_packets:

            try:
                readable, _, _ = select.select(
                    [self.raw_socket],
                    [],
                    [],
                    0.0,
                )

                if not readable:
                    break

                raw_bytes, _ = self.raw_socket.recvfrom(65535)

                packet = parse_ipv4_packet(raw_bytes, now)

                if packet is not None:
                    self.flow_table.process_packet(packet)
                    count += 1

            except Exception:
                break

        return count

    # --------------------------------------------------
    # PCAP PROCESSING
    # --------------------------------------------------

    def load_pcap_file(self, pcap_path: str):

        path = Path(pcap_path)

        if not path.exists():
            print(f"[WARN] PCAP file not found: {pcap_path}")
            return

        print(f"[CAPTURE] Processing PCAP file: {path.name}")

        content = path.read_bytes()
        count = 0

        for packet in parse_pcap_stream(content):
            self.flow_table.process_packet(packet)
            count += 1

        self.active_capture_method = f"pcap_file ({path.name})"

        print(f"[CAPTURE] Processed {count} packets.")

    # --------------------------------------------------
    # MAIN SENSOR LOOP
    # --------------------------------------------------

    def start(self, interval: int = 3):

        if interval < 1:
            raise ValueError("Sampling interval must be at least 1 second.")

        self.running = True

        print("\n" + "=" * 65)
        print("          SENTINEL CYBER — LIVE NETWORK SENSOR V2")
        print("=" * 65)

        print(f"Device:             {socket.gethostname()}")
        print(f"Target Backend:     {self.api_url}")
        print(f"Auth Token:         {'[Configured]' if self.token else '[Missing]'}")
        print(f"Sampling Interval:  {interval} seconds")
        print(f"Capture Mode:       {self.capture_mode}")

        if self.pcap_file:
            self.load_pcap_file(self.pcap_file)

        elif self.capture_mode in ["auto", "socket"]:
            self.init_raw_socket()

        print(f"Active Capture:     {self.active_capture_method}")
        print("=" * 65)
        print("Press CTRL+C to stop the sensor.\n")

        consecutive_failures = 0

        try:
            while self.running:

                loop_start = time.time()

                self.poll_packets(max_packets=100)

                expired_flows = self.flow_table.flush_expired(
                    loop_start
                )

                if expired_flows:
                    self.send_flows(expired_flows)

                snapshot = self.collect_snapshot()

                telemetry_ok = (
                    self.send_snapshot(snapshot)
                    if snapshot is not None
                    else False
                )

                if telemetry_ok:
                    consecutive_failures = 0
                    status_flag = "SUCCESS (LIVE)"

                else:
                    consecutive_failures += 1
                    status_flag = f"RETRYING ({consecutive_failures} fails)"

                connections = (
                    snapshot["connections"]
                    if snapshot
                    else {"total": 0}
                )

                timestamp = (
                    snapshot["timestamp"][11:19]
                    if snapshot
                    else time.strftime("%H:%M:%S")
                )

                print(
                    f"[{timestamp}] "
                    f"NIC: {snapshot['interface'][:8]:<8} | "
                    f"Up: {snapshot['upload_kbps']:>6.1f} KB/s | "
                    f"Down: {snapshot['download_kbps']:>6.1f} KB/s | "
                    f"Sockets: {connections['total']:<3} | "
                    f"API: {status_flag}"
                    if snapshot
                    else f"[{timestamp}] No snapshot available | API: {status_flag}"
                )

                elapsed = time.time() - loop_start

                time.sleep(max(0.1, interval - elapsed))

        except KeyboardInterrupt:
            self.running = False

            final_flows = self.flow_table.flush_all()

            if final_flows:
                print(
                    f"\n[FLUSH] Processing "
                    f"{len(final_flows)} remaining flows."
                )
                self.send_flows(final_flows)

            print("\n[STOP] Sensor stopped cleanly.")

        finally:
            if self.raw_socket:
                try:
                    if hasattr(socket, "SIO_RCVALL"):
                        self.raw_socket.ioctl(
                            socket.SIO_RCVALL,
                            socket.RCVALL_OFF,
                        )

                    self.raw_socket.close()

                except Exception:
                    pass

                self.raw_socket = None

            self.session.close()


# --------------------------------------------------
# COMMAND LINE ENTRY POINT
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Sentinel Cyber V2 Windows Network Sensor"
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_API_URL,
        help="Backend URL",
    )

    parser.add_argument(
        "--token",
        default=DEFAULT_SENSOR_TOKEN,
        help="Sensor authentication token",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=3,
        help="Sampling interval in seconds",
    )

    parser.add_argument(
        "--capture",
        default="auto",
        choices=["auto", "socket", "pcap", "none"],
        help="Capture mode",
    )

    parser.add_argument(
        "--pcap",
        default=None,
        help="PCAP file path",
    )

    args = parser.parse_args()

    monitor = WindowsMonitor(
        api_url=args.url,
        token=args.token,
        capture_mode=args.capture,
        pcap_file=args.pcap,
    )

    monitor.start(interval=args.interval)


if __name__ == "__main__":
    main()
