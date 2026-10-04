import socket
import subprocess
import re
import ipaddress
import psutil
from typing import Dict, List, Tuple, Optional

# Well-known MAC OUI vendor prefix table
OUI_MAP = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "00:1a:2b": "Cisco",
    "08:00:27": "Oracle VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Apple",
    "ac:bc:32": "Apple",
    "f0:18:98": "Apple",
    "3c:22:fb": "Apple",
    "70:ec:e4": "Apple",
    "f4:d4:88": "Apple",
    "a4:83:e7": "Apple",
    "bc:d0:74": "Apple",
    "00:26:08": "Apple",
    "34:36:3b": "Apple",
    "40:4e:36": "Apple",
    "50:bc:96": "Apple",
    "78:7b:8a": "Apple",
    "9c:20:7b": "Apple",
    "00:1e:65": "Intel",
    "34:13:e8": "Intel",
    "8c:85:90": "Intel",
    "00:09:b0": "Samsung",
    "00:12:47": "Samsung",
    "50:85:69": "Samsung",
    "e4:7c:f9": "Samsung",
    "70:2c:1f": "Samsung",
    "b0:c5:54": "Samsung",
    "54:04:a6": "ASUSTek",
    "00:1f:c6": "ASUSTek",
    "18:31:bf": "ASUSTek",
    "50:46:5d": "TP-Link",
    "70:4f:57": "TP-Link",
    "98:48:27": "TP-Link",
    "c0:06:c3": "TP-Link",
    "e8:48:b8": "TP-Link",
    "14:cc:20": "TP-Link",
    "20:4e:7f": "Netgear",
    "28:80:88": "Netgear",
    "a0:04:60": "Netgear",
    "00:14:bf": "Linksys",
    "20:aa:4b": "Linksys",
    "00:04:4b": "NVIDIA",
    "48:b0:2d": "NVIDIA",
    "00:17:88": "Philips Hue",
    "ec:b5:fa": "Philips Hue",
    "00:04:20": "Slim Devices (Logitech)",
    "fc:65:de": "Amazon",
    "68:54:fd": "Amazon",
    "74:c2:46": "Amazon",
    "cc:9e:00": "Amazon",
    "40:b4:cd": "Amazon",
    "00:11:32": "Synology",
    "00:08:9b": "QNAP",
    "70:9e:29": "Sony",
    "00:15:c1": "HP",
    "a0:d3:c1": "HP",
    "00:24:81": "Hewlett Packard",
    "00:1a:a0": "Dell",
    "18:66:da": "Dell",
    "b8:ac:6f": "Dell",
    "f8:db:88": "Dell",
    "00:23:24": "LG Electronics",
    "10:f9:ee": "LG Electronics",
    "20:3d:66": "LG Electronics",
    "b4:e6:2d": "LG Electronics",
    "00:1d:d8": "Microsoft",
    "dc:98:40": "Microsoft",
    "7c:1e:52": "Microsoft",
    "48:2c:6a": "Xiaomi",
    "78:11:dc": "Xiaomi",
    "ac:c1:ee": "Xiaomi",
}


def lookup_vendor(mac: str) -> str:
    """Return hardware vendor from MAC OUI if matched, or fallback."""
    if not mac or mac == "Unknown":
        return "Unknown"
    norm = mac.lower().replace("-", ":")
    prefix = ":".join(norm.split(":")[:3])
    return OUI_MAP.get(prefix, "Network Device")


def get_default_interface_info() -> Tuple[str, str, str]:
    """
    Find the default active IPv4 address, interface name, and subnet CIDR.
    Returns (local_ip, interface_name, subnet_cidr)
    """
    local_ip = "127.0.0.1"
    netmask = "255.255.255.0"
    if_name = "Ethernet"

    # Find active non-loopback IP that routes outbound
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Find the corresponding interface and netmask using psutil
    addrs = psutil.net_if_addrs()
    for name, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                if_name = name
                if addr.netmask:
                    netmask = addr.netmask
                break

    # Calculate subnet CIDR
    try:
        net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        subnet_cidr = str(net)
    except Exception:
        subnet_cidr = "192.168.1.0/24"

    return local_ip, if_name, subnet_cidr


def scan_arp_table() -> List[Dict[str, str]]:
    """
    Read Windows ARP table using 'arp -a' or PowerShell Get-NetNeighbor.
    Returns list of {'ip': ip, 'mac': mac, 'vendor': vendor, 'hostname': host}
    """
    devices = []
    seen_ips = set()

    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        # Parse lines like: 192.168.1.1       c0-06-c3-aa-bb-cc     dynamic
        for line in output.splitlines():
            line = line.strip()
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                device_type = match.group(3).lower()

                # Filter out multicast/broadcast addresses
                if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255":
                    continue
                if ip in seen_ips:
                    continue

                seen_ips.add(ip)
                vendor = lookup_vendor(mac)
                hostname = resolve_hostname(ip)

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "type": device_type
                })
    except Exception:
        pass

    return devices


def resolve_hostname(ip: str) -> str:
    """Attempt fast reverse DNS lookup without blocking startup."""
    try:
        import threading
        res = [""]
        def _lookup():
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                if host.endswith(".lan") or host.endswith(".local"):
                    host = host.split(".")[0]
                res[0] = host
            except Exception:
                pass
        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        t.join(timeout=0.3)
        return res[0]
    except Exception:
        return ""


def sweep_subnet(subnet_cidr: str = "192.168.1.0/24") -> List[Dict[str, str]]:
    """
    Rapidly ping sweep the entire subnet to force all connected AirFiber
    devices (phones, TVs, laptops, smart home devices) to reply and populate
    the operating system ARP cache.
    """
    from concurrent.futures import ThreadPoolExecutor

    def probe(ip_str: str):
        try:
            # Fast ping with 200ms timeout
            subprocess.run(
                ['ping', '-n', '1', '-w', '220', ip_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    try:
        net = ipaddress.IPv4Network(subnet_cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        # Concurrently probe all 254 subnet addresses
        with ThreadPoolExecutor(max_workers=60) as executor:
            list(executor.map(probe, hosts))
    except Exception as e:
        print(f"[Discovery] Subnet sweep error: {e}")

    # Read and return the freshly populated ARP table
    return scan_arp_table()
