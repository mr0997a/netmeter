# NetMeter — Local Subnet Data Usage Monitor

A local full-stack network traffic analysis and per-device bandwidth monitoring system. Specifically engineered to track and meter local network devices connected to a home/office router (such as `192.168.1.x` subnets), tracking download/upload bytes in MB and GB, live throughput rates, and protocol distributions.

---

## Key Features

1. **Multi-Mode Packet Capture Engine**:
   - **Native Windows Raw Socket Promiscuous Sniffer**: Uses `socket.SOCK_RAW` with Windows `SIO_RCVALL` ioctl. Intercepts and parses IPv4 traffic traversing the active interface without needing third-party drivers.
   - **Scapy Packet Engine**: Fallback engine leveraging Scapy and Npcap/WinPcap if installed.
   - **Automatic ARP Discovery**: Periodically discovers active devices, MAC addresses, hostnames, and resolves hardware vendors via an internal IEEE OUI prefix database.
   - **Synthetic Simulation Mode**: Built-in realistic traffic generator that models streaming (4K Apple TV), video calls (Zoom), mobile push, and NAS backup traffic across the subnet. Useful for instant testing or environments where raw socket privileges are restricted.

2. **Real-Time Web Dashboard**:
   - **Modern Dark Glassmorphic UI**: Ambient glow backdrops, frosted glass cards, Outfit & Plus Jakarta Sans typography.
   - **Live Throughput Chart**: High-performance HTML5 Canvas bezier area chart displaying rolling download/upload bandwidth in real time.
   - **Per-Device Meters**: Tracks IP address, MAC, vendor, total download (MB/GB), total upload (MB/GB), live rate (KB/s, MB/s), and packet counts.
   - **Custom Device Nicknames**: Inline editable aliases (e.g., "Living Room TV", "Dad's Phone") saved persistently to the database.
   - **Deep Device Inspection Modal**: Detailed protocol breakdown (HTTPS, HTTP, DNS, UDP, TCP, etc.) and time-series traffic history.
   - **Live WebSocket Stream**: Push-based 1Hz live telemetry with automatic HTTP polling fallback.

3. **Persistent SQLite Database**:
   - Stores device profiles, cumulative upload/download tallies, protocol counters, and time-series deltas across app restarts in `traffic_monitor.db`.

---

## Directory Structure

```text
C:\netmeter\
├── backend/
│   ├── database.py       # SQLite schema, transactions, migrations & queries
│   ├── discovery.py      # ARP scanning, host resolution & MAC OUI matching
│   ├── sniffer.py        # Multi-mode packet capture engine & rolling rate math
│   └── main.py           # FastAPI REST API, WebSocket server & static routing
├── frontend/
│   ├── index.html        # Glassmorphic single page dashboard
│   ├── style.css         # Modern design tokens, animations & responsive styling
│   └── app.js            # WebSocket client, Canvas live chart & UI interactions
├── tests/
│   └── test_backend.py   # Pytest suite for database, packet parsing & API routes
├── Dockerfile            # Container definition with NET_RAW capabilities
├── requirements.txt      # Python dependencies
├── run.bat               # Windows launcher script
├── run_admin.bat         # Elevated Administrator launcher for raw sniffing
└── README.md             # Documentation
```

---

## Quick Start (Windows)

### Option 1: Standard Run
Double-click `run.bat` or execute in PowerShell / Command Prompt:
```powershell
cd C:\netmeter
.\run.bat
```
Then open your browser to **[http://127.0.0.1:8000](http://127.0.0.1:8000)**.

### Option 2: Run with Administrator Privileges (For Raw Packet Sniffing)
Raw socket packet sniffing (`SIO_RCVALL` promiscuous mode) on Windows requires Administrator rights. 
Simply right-click `run_admin.bat` and select **Run as administrator**, or run:
```powershell
cd C:\netmeter
.\run_admin.bat
```
Windows UAC will prompt for elevation, and NetMeter will start with full raw promiscuous capture active.

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/devices` | List of all detected subnet devices with MB/GB usage, live speeds, and status |
| `GET` | `/api/devices/{ip}` | Detailed device metadata, protocol breakdown, and history |
| `PATCH` | `/api/devices/{ip}/rename` | Update custom device nickname (Payload: `{"custom_name": "My Device"}`) |
| `GET` | `/api/traffic/summary` | Overall network totals, current live speed, and sniffer diagnostics |
| `GET` | `/api/traffic/history` | Historical time-series data points for charting |
| `GET` | `/api/system/status` | Current capture mode, interface, admin rights, and packet counters |
| `POST` | `/api/system/toggle-simulation` | Toggle between live packet sniffer and synthetic demo generator |
| `WS` | `/ws/live` | WebSocket streaming 1Hz live telemetry updates |

---

## Notes on Router Subnet Packet Monitoring

On switched Ethernet and modern WPA2/WPA3 Wi-Fi networks:
- A PC running in standard promiscuous mode captures:
  1. All traffic to and from the monitoring PC.
  2. Broadcast packets (ARP requests, DHCP discovery, NetBIOS, mDNS).
  3. Multicast streams (SSDP, Chromecast announcements, UPnP).
- To capture unicast traffic between *other* wireless clients and the internet on standard consumer routers without network mirroring:
  - **Port Mirroring / SPAN**: Configure a mirror port on managed switches.
  - **Router Tap**: Run NetMeter directly on a Linux/OpenWrt router or gateway.
  - **NetMeter Simulation Mode**: For testing and visual validation, NetMeter includes an automated simulation mode that accurately mirrors heavy video streaming, conferencing, and file transfers across `192.168.1.x` devices.
