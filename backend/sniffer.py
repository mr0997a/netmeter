import socket
import struct
import threading
import time
import random
import ipaddress
import ctypes
import os
import sys
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict, deque

# SIO_RCVALL constants for Windows raw socket promiscuous capture
SIO_RCVALL = 0x98000001
RCVALL_OFF = 0
RCVALL_ON = 1
RCVALL_SOCKETLEVELONLY = 2


def is_admin() -> bool:
    """Check if current process has Administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class NetworkSniffer:
    def __init__(self, local_ip: str, subnet_cidr: str = "192.168.1.0/24"):
        self.local_ip = local_ip
        self.subnet_cidr = subnet_cidr
        self.subnet = ipaddress.IPv4Network(subnet_cidr, strict=False)
        self.running = False
        self.mode = "init"  # "raw_socket", "scapy", "simulation"
        self.admin = is_admin()

        # Threading & locks
        self._lock = threading.Lock()
        self._worker_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._rate_thread: Optional[threading.Thread] = None

        # Real-time state per IP
        # Format: ip -> {'bytes_in': int, 'bytes_out': int, 'packets_in': int, 'packets_out': int, 'protocols': {}}
        self.pending_traffic = defaultdict(lambda: {
            'bytes_in': 0,
            'bytes_out': 0,
            'packets_in': 0,
            'packets_out': 0,
            'proto_breakdown': defaultdict(lambda: {'bytes': 0, 'packets': 0})
        })

        # Rolling speed window: ip -> deque of (timestamp, bytes_in, bytes_out)
        self.speed_windows = defaultdict(lambda: deque(maxlen=10))

        # Computed current rates (updated every 1s): ip -> {'rate_in_kb': float, 'rate_out_kb': float}
        self.current_rates = defaultdict(lambda: {'rate_in_kb': 0.0, 'rate_out_kb': 0.0, 'total_rate_kb': 0.0})

        # Callback for database flushes
        self.on_flush_callback = None

        # Statistics
        self.total_packets_captured = 0
        self.total_bytes_captured = 0
        self.start_time = time.time()
        self.simulation_enabled = False

    def is_in_subnet(self, ip_str: str) -> bool:
        """Check if an IP address belongs to the monitored subnet."""
        try:
            return ipaddress.IPv4Address(ip_str) in self.subnet
        except Exception:
            return False

    def process_packet(self, src_ip: str, dst_ip: str, length: int, protocol_name: str):
        """Account for packet transfer direction, lengths, and protocols."""
        with self._lock:
            self.total_packets_captured += 1
            self.total_bytes_captured += length
            now = time.time()

            src_in = self.is_in_subnet(src_ip)
            dst_in = self.is_in_subnet(dst_ip)

            # If source is in subnet, it is OUTBOUND / UPLOAD for that device
            if src_in:
                item = self.pending_traffic[src_ip]
                item['bytes_out'] += length
                item['packets_out'] += 1
                proto_item = item['proto_breakdown'][protocol_name]
                proto_item['bytes'] += length
                proto_item['packets'] += 1
                self.speed_windows[src_ip].append((now, 0, length))

            # If destination is in subnet, it is INBOUND / DOWNLOAD for that device
            if dst_in:
                item = self.pending_traffic[dst_ip]
                item['bytes_in'] += length
                item['packets_in'] += 1
                proto_item = item['proto_breakdown'][protocol_name]
                proto_item['bytes'] += length
                proto_item['packets'] += 1
                self.speed_windows[dst_ip].append((now, length, 0))

    def _parse_ip_header(self, raw_data: bytes) -> Optional[Tuple[str, str, int, str]]:
        """Parse IPv4 packet header from raw socket payload."""
        if len(raw_data) < 20:
            return None

        # First byte: Version (4 bits) + IHL (4 bits)
        first_byte = raw_data[0]
        version = first_byte >> 4
        if version != 4:
            return None  # Only IPv4 for now

        ihl = (first_byte & 0xF) * 4
        if len(raw_data) < ihl:
            return None

        # Unpack IPv4 header
        # Bytes: 0(V/IHL), 1(DSCP/ECN), 2-3(Total Length), 4-5(ID), 6-7(Flags/Frag), 8(TTL), 9(Protocol), 10-11(Checksum), 12-15(Src), 16-19(Dst)
        try:
            iph = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
            total_len = iph[2]
            protocol_num = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            # Length of this packet (fallback to len(raw_data) if total_len is 0)
            pkt_len = total_len if total_len > 0 else len(raw_data)

            # Identify protocol and port if available
            protocol_name = "OTHER"
            if protocol_num == 6:
                protocol_name = "TCP"
                if len(raw_data) >= ihl + 4:
                    sport, dport = struct.unpack('!HH', raw_data[ihl:ihl + 4])
                    if sport == 443 or dport == 443:
                        protocol_name = "HTTPS"
                    elif sport == 80 or dport == 80:
                        protocol_name = "HTTP"
                    elif sport == 22 or dport == 22:
                        protocol_name = "SSH"
            elif protocol_num == 17:
                protocol_name = "UDP"
                if len(raw_data) >= ihl + 4:
                    sport, dport = struct.unpack('!HH', raw_data[ihl:ihl + 4])
                    if sport == 53 or dport == 53:
                        protocol_name = "DNS"
                    elif sport == 443 or dport == 443:
                        protocol_name = "QUIC"
                    elif sport in (67, 68) or dport in (67, 68):
                        protocol_name = "DHCP"
            elif protocol_num == 1:
                protocol_name = "ICMP"

            return src_ip, dst_ip, pkt_len, protocol_name
        except Exception:
            return None

    def _run_raw_socket(self):
        """Sniff packets using native Windows Raw Socket with SIO_RCVALL."""
        s = None
        try:
            # Create raw IP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode on Windows
            if os.name == 'nt':
                s.ioctl(SIO_RCVALL, RCVALL_ON)

            self.mode = "raw_socket"
            s.settimeout(1.0)

            while self.running and not self.simulation_enabled:
                try:
                    packet, _ = s.recvfrom(65535)
                    parsed = self._parse_ip_header(packet)
                    if parsed:
                        src_ip, dst_ip, length, proto = parsed
                        self.process_packet(src_ip, dst_ip, length, proto)
                except socket.timeout:
                    continue
                except Exception:
                    if not self.running:
                        break
        except Exception as e:
            # If raw socket fails (e.g., non-admin or permission denied), fallback to simulation
            print(f"[Sniffer] Raw socket initialization failed: {e}. Falling back to simulation mode.")
            self.start_simulation()
        finally:
            if s:
                try:
                    if os.name == 'nt':
                        s.ioctl(SIO_RCVALL, RCVALL_OFF)
                    s.close()
                except Exception:
                    pass

    def _run_scapy(self):
        """Sniff packets using Scapy if available and preferred."""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
            self.mode = "scapy"

            def scapy_callback(pkt):
                if not self.running or self.simulation_enabled:
                    return
                if IP in pkt:
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    length = len(pkt)
                    proto = "OTHER"

                    if TCP in pkt:
                        proto = "TCP"
                        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            proto = "HTTPS"
                        elif pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                            proto = "HTTP"
                    elif UDP in pkt:
                        proto = "UDP"
                        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                            proto = "DNS"
                    elif ICMP in pkt:
                        proto = "ICMP"

                    self.process_packet(src_ip, dst_ip, length, proto)

            sniff(prn=scapy_callback, filter="ip", store=0, stop_filter=lambda x: not self.running or self.simulation_enabled)
        except Exception as e:
            print(f"[Sniffer] Scapy sniffing failed: {e}. Falling back to simulation mode.")
            self.start_simulation()

    def _run_simulation(self):
        """
        Synthesize realistic subnet traffic.
        Simulates:
        - 192.168.1.1 (Gateway): continuous DNS & control
        - 192.168.1.11 (Host Machine): active web browsing / dev work
        - 192.168.1.45 (Smart TV): 4K streaming (Netflix/YouTube), heavy inbound
        - 192.168.1.72 (iPhone): intermittent notification push, social media
        - 192.168.1.108 (MacBook Pro): video call (Zoom/Teams), symmetric upload/download
        - 192.168.1.200 (Home NAS / Media Server): file transfers
        """
        self.mode = "simulation"

        sim_devices = [
            {"ip": "192.168.1.1", "name": "Gateway Router", "weight": 5, "profile": "dns"},
            {"ip": self.local_ip, "name": "Monitoring Host", "weight": 20, "profile": "web"},
            {"ip": "192.168.1.45", "name": "Living Room 4K TV", "weight": 40, "profile": "streaming"},
            {"ip": "192.168.1.72", "name": "Personal iPhone", "weight": 10, "profile": "mobile"},
            {"ip": "192.168.1.108", "name": "Work Laptop", "weight": 25, "profile": "videocall"},
            {"ip": "192.168.1.200", "name": "Synology NAS", "weight": 15, "profile": "nas"}
        ]

        # External destinations
        destinations = [
            "142.250.190.46",  # Google
            "104.244.42.1",    # Twitter / X
            "151.101.1.140",   # Reddit
            "52.94.233.129",   # Amazon AWS
            "198.41.0.4",      # Root DNS
            "13.107.42.16"     # Microsoft
        ]

        while self.running and (self.simulation_enabled or self.mode == "simulation"):
            # Choose active device based on weight
            dev = random.choices(sim_devices, weights=[d["weight"] for d in sim_devices])[0]
            ip = dev["ip"]
            profile = dev["profile"]
            ext_ip = random.choice(destinations)

            if profile == "streaming":
                # High download: chunks of 1500 byte packets
                burst_pkts = random.randint(15, 60)
                for _ in range(burst_pkts):
                    self.process_packet(ext_ip, ip, 1460, "HTTPS")
                self.process_packet(ip, ext_ip, 64, "TCP")  # ACK

            elif profile == "videocall":
                # Both download and upload
                for _ in range(random.randint(5, 20)):
                    self.process_packet(ext_ip, ip, random.randint(800, 1400), "UDP")
                    self.process_packet(ip, ext_ip, random.randint(600, 1200), "UDP")

            elif profile == "nas":
                # High local burst
                for _ in range(random.randint(10, 30)):
                    self.process_packet(self.local_ip, ip, 1460, "TCP")

            elif profile == "dns":
                self.process_packet(ip, ext_ip, random.randint(60, 180), "DNS")
                self.process_packet(ext_ip, ip, random.randint(90, 400), "DNS")

            elif profile == "web":
                for _ in range(random.randint(2, 10)):
                    self.process_packet(ext_ip, ip, random.randint(500, 1460), "HTTPS")
                    self.process_packet(ip, ext_ip, random.randint(100, 500), "HTTPS")

            else:  # mobile
                self.process_packet(ext_ip, ip, random.randint(200, 1200), "HTTPS")
                self.process_packet(ip, ext_ip, random.randint(80, 250), "HTTPS")

            time.sleep(random.uniform(0.05, 0.25))

    def _rate_calculator_loop(self):
        """Calculate transfer speeds (KB/s) across a rolling time window."""
        while self.running:
            time.sleep(1.0)
            now = time.time()
            cutoff = now - 3.0  # 3-second moving window

            with self._lock:
                for ip, window in list(self.speed_windows.items()):
                    # Purge old samples
                    while window and window[0][0] < cutoff:
                        window.popleft()

                    if not window:
                        self.current_rates[ip] = {'rate_in_kb': 0.0, 'rate_out_kb': 0.0, 'total_rate_kb': 0.0}
                        continue

                    # Sum bytes in window
                    duration = max(0.5, now - window[0][0])
                    bytes_in_win = sum(sample[1] for sample in window)
                    bytes_out_win = sum(sample[2] for sample in window)

                    rate_in_kb = round((bytes_in_win / duration) / 1024, 2)
                    rate_out_kb = round((bytes_out_win / duration) / 1024, 2)
                    total_rate_kb = round(rate_in_kb + rate_out_kb, 2)

                    self.current_rates[ip] = {
                        'rate_in_kb': rate_in_kb,
                        'rate_out_kb': rate_out_kb,
                        'total_rate_kb': total_rate_kb
                    }

    def _flush_loop(self):
        """Periodically dump pending traffic to the database callback."""
        while self.running:
            time.sleep(2.0)
            updates_to_flush = []
            with self._lock:
                for ip, data in list(self.pending_traffic.items()):
                    if data['bytes_in'] > 0 or data['bytes_out'] > 0:
                        proto_dict = {
                            p: {'bytes': s['bytes'], 'packets': s['packets']}
                            for p, s in data['proto_breakdown'].items()
                        }
                        updates_to_flush.append({
                            'ip': ip,
                            'bytes_in': data['bytes_in'],
                            'bytes_out': data['bytes_out'],
                            'packets_in': data['packets_in'],
                            'packets_out': data['packets_out'],
                            'proto_breakdown': proto_dict
                        })
                        # Reset deltas
                        data['bytes_in'] = 0
                        data['bytes_out'] = 0
                        data['packets_in'] = 0
                        data['packets_out'] = 0
                        data['proto_breakdown'].clear()

            if updates_to_flush and self.on_flush_callback:
                try:
                    self.on_flush_callback(updates_to_flush)
                except Exception as e:
                    print(f"[Sniffer] Error flushing to database: {e}")

    def start(self, preferred_mode: Optional[str] = None):
        """Start sniffer engine."""
        if self.running:
            return

        self.running = True
        self.start_time = time.time()

        # Start rate and flush background threads
        self._rate_thread = threading.Thread(target=self._rate_calculator_loop, daemon=True)
        self._rate_thread.start()

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

        if preferred_mode == "simulation":
            self.simulation_enabled = True
            self._worker_thread = threading.Thread(target=self._run_simulation, daemon=True)
            self._worker_thread.start()
            return

        # Attempt raw socket if admin, otherwise scapy or fallback to simulation
        if self.admin:
            self._worker_thread = threading.Thread(target=self._run_raw_socket, daemon=True)
        else:
            # Non-admin: Start simulation generator so dashboard is instantly active and useful
            print("[Sniffer] Not running as Administrator. Starting in simulation mode for testing.")
            self.simulation_enabled = True
            self._worker_thread = threading.Thread(target=self._run_simulation, daemon=True)

        self._worker_thread.start()

    def start_simulation(self):
        """Switch or activate simulation mode."""
        self.simulation_enabled = True
        if self._worker_thread and self._worker_thread.is_alive():
            # Will naturally transition or pick up
            pass
        sim_thread = threading.Thread(target=self._run_simulation, daemon=True)
        sim_thread.start()

    def toggle_simulation(self) -> bool:
        """Toggle simulation mode on/off."""
        self.simulation_enabled = not self.simulation_enabled
        if self.simulation_enabled:
            threading.Thread(target=self._run_simulation, daemon=True).start()
        return self.simulation_enabled

    def stop(self):
        """Stop all background worker threads."""
        self.running = False

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic metrics about the sniffer."""
        uptime = int(time.time() - self.start_time)
        return {
            "mode": self.mode,
            "is_admin": self.admin,
            "simulation_enabled": self.simulation_enabled,
            "running": self.running,
            "local_ip": self.local_ip,
            "subnet": self.subnet_cidr,
            "total_packets": self.total_packets_captured,
            "total_bytes": self.total_bytes_captured,
            "total_mb": round(self.total_bytes_captured / (1024 * 1024), 2),
            "uptime_seconds": uptime
        }
