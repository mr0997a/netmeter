import os
import time
import asyncio
import threading
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .database import (
    init_db, upsert_device, rename_device, record_traffic_delta,
    get_all_devices, get_device_detail, get_traffic_history, get_network_totals
)
from .discovery import get_default_interface_info, scan_arp_table, sweep_subnet
from .sniffer import NetworkSniffer, is_admin

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Discover local networking
LOCAL_IP, INTERFACE_NAME, SUBNET_CIDR = get_default_interface_info()

# Sniffer instance
sniffer = NetworkSniffer(local_ip=LOCAL_IP, subnet_cidr=SUBNET_CIDR)
sniffer.on_flush_callback = record_traffic_delta

# Active WebSocket connections
active_connections: List[WebSocket] = []

# Ensure tables exist on load
init_db()


class RenamePayload(BaseModel):
    custom_name: str


class DeviceCreatePayload(BaseModel):
    ip: str
    custom_name: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None


def background_arp_discovery():
    """Periodically scan ARP table and sweep subnet to discover new AirFiber clients."""
    loop_count = 0
    while True:
        try:
            loop_count += 1
            # Deep ping sweep every 3 cycles (~60s), lighter ARP check every 20s
            if loop_count % 3 == 0:
                devices = sweep_subnet(SUBNET_CIDR)
            else:
                devices = scan_arp_table()

            for dev in devices:
                upsert_device(
                    ip=dev["ip"],
                    mac=dev["mac"],
                    hostname=dev["hostname"],
                    vendor=dev["vendor"]
                )

            # Also ensure local host is registered
            upsert_device(
                ip=LOCAL_IP,
                hostname="Host Machine",
                vendor="Local Host",
                custom_name="Host Machine (This PC)"
            )
        except Exception as e:
            print(f"[Discovery] ARP scan error: {e}")

        time.sleep(20)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"[Startup] Initializing NetMeter on {LOCAL_IP} ({INTERFACE_NAME}), Subnet: {SUBNET_CIDR}")
    init_db()

    # Initial ARP scan
    devices = scan_arp_table()
    for dev in devices:
        upsert_device(ip=dev["ip"], mac=dev["mac"], hostname=dev["hostname"], vendor=dev["vendor"])

    # Seed mock devices if in simulation or database is sparse
    if sniffer.admin is False:
        # Pre-populate some recognizable devices for demo/simulation
        mock_devices = [
            ("192.168.1.1", "c0:06:c3:22:11:00", "Router.lan", "TP-Link", "Main Router / Gateway"),
            ("192.168.1.45", "70:ec:e4:33:44:55", "apple-tv", "Apple", "Living Room 4K Apple TV"),
            ("192.168.1.72", "3c:22:fb:88:99:aa", "iPhone-15", "Apple", "Sarah's iPhone"),
            ("192.168.1.108", "8c:85:90:dd:ee:ff", "dell-xps", "Dell", "Alex's Work Laptop"),
            ("192.168.1.200", "00:11:32:12:34:56", "synology-nas", "Synology", "Home Backup NAS"),
        ]
        for ip, mac, host, vendor, name in mock_devices:
            upsert_device(ip=ip, mac=mac, hostname=host, vendor=vendor, custom_name=name)

    # Start sniffer
    sniffer.start()

    # Start discovery background thread
    discovery_thread = threading.Thread(target=background_arp_discovery, daemon=True)
    discovery_thread.start()

    # Start WebSocket broadcaster task
    broadcast_task = asyncio.create_task(websocket_broadcast_loop())

    yield

    # Shutdown
    print("[Shutdown] Stopping Sniffer and background tasks...")
    broadcast_task.cancel()
    sniffer.stop()


app = FastAPI(title="NetMeter - Network Traffic Monitor", lifespan=lifespan)


async def websocket_broadcast_loop():
    """Push live rate and telemetry stream to all connected WebSocket clients."""
    while True:
        try:
            await asyncio.sleep(1.0)
            if not active_connections:
                continue

            devices = get_all_devices()
            # Enrich with real-time rolling speeds
            for d in devices:
                ip = d["ip"]
                rates = sniffer.current_rates[ip]
                d["rate_in_kb"] = rates["rate_in_kb"]
                d["rate_out_kb"] = rates["rate_out_kb"]
                d["total_rate_kb"] = rates["total_rate_kb"]

            totals = get_network_totals()
            status = sniffer.get_status()

            # Compute current total live bandwidth (KB/s and MB/s)
            live_rate_in_kb = sum(sniffer.current_rates[ip]["rate_in_kb"] for ip in sniffer.current_rates)
            live_rate_out_kb = sum(sniffer.current_rates[ip]["rate_out_kb"] for ip in sniffer.current_rates)
            live_rate_total_kb = round(live_rate_in_kb + live_rate_out_kb, 2)

            payload = {
                "timestamp": time.time(),
                "devices": devices,
                "totals": totals,
                "live_bandwidth": {
                    "in_kb": round(live_rate_in_kb, 2),
                    "out_kb": round(live_rate_out_kb, 2),
                    "total_kb": live_rate_total_kb,
                    "in_mb": round(live_rate_in_kb / 1024, 2),
                    "out_mb": round(live_rate_out_kb / 1024, 2),
                    "total_mb": round(live_rate_total_kb / 1024, 2)
                },
                "status": status
            }

            # Broadcast to all connected clients
            for ws in list(active_connections):
                try:
                    await ws.send_json(payload)
                except Exception:
                    if ws in active_connections:
                        active_connections.remove(ws)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[WS Broadcaster] Error: {e}")


# --- API Routes ---

@app.get("/api/devices")
def api_get_devices():
    """Retrieve all monitored devices with data usage in MB and GB, plus live speeds."""
    devices = get_all_devices()
    for d in devices:
        ip = d["ip"]
        rates = sniffer.current_rates[ip]
        d["rate_in_kb"] = rates["rate_in_kb"]
        d["rate_out_kb"] = rates["rate_out_kb"]
        d["total_rate_kb"] = rates["total_rate_kb"]
    return {"devices": devices}


@app.get("/api/devices/{ip}")
def api_get_device_detail(ip: str):
    """Retrieve detailed stats, protocols, and history for a specific device."""
    detail = get_device_detail(ip)
    if not detail:
        raise HTTPException(status_code=404, detail="Device not found")
    rates = sniffer.current_rates[ip]
    detail["rate_in_kb"] = rates["rate_in_kb"]
    detail["rate_out_kb"] = rates["rate_out_kb"]
    detail["total_rate_kb"] = rates["total_rate_kb"]
    return detail


@app.patch("/api/devices/{ip}/rename")
def api_rename_device(ip: str, payload: RenamePayload):
    """Assign or update a user-friendly custom nickname for a device."""
    success = rename_device(ip, payload.custom_name)
    if not success:
        # Create device entry if not exists
        upsert_device(ip=ip, custom_name=payload.custom_name)
    return {"status": "success", "ip": ip, "custom_name": payload.custom_name}


@app.post("/api/devices")
def api_create_device(payload: DeviceCreatePayload):
    """Manually add an AirFiber device by IP and optional nickname/MAC."""
    upsert_device(
        ip=payload.ip.strip(),
        mac=payload.mac.strip() if payload.mac else "Unknown",
        vendor=payload.vendor.strip() if payload.vendor else "AirFiber Client",
        custom_name=payload.custom_name.strip() if payload.custom_name else None
    )
    return {"status": "success", "device": payload}


@app.post("/api/discovery/scan")
def api_sweep_subnet():
    """Trigger an active ping sweep to discover all connected AirFiber devices."""
    devices = sweep_subnet(SUBNET_CIDR)
    for dev in devices:
        upsert_device(ip=dev["ip"], mac=dev["mac"], hostname=dev["hostname"], vendor=dev["vendor"])
    all_devices = get_all_devices()
    return {
        "status": "success",
        "devices_found": len(devices),
        "total_tracked": len(all_devices)
    }


@app.get("/api/traffic/summary")
def api_traffic_summary():
    """Get aggregated network totals and peak statistics."""
    totals = get_network_totals()
    status = sniffer.get_status()
    live_rate_in_kb = sum(sniffer.current_rates[ip]["rate_in_kb"] for ip in sniffer.current_rates)
    live_rate_out_kb = sum(sniffer.current_rates[ip]["rate_out_kb"] for ip in sniffer.current_rates)

    return {
        "totals": totals,
        "live_speed": {
            "rate_in_kb": round(live_rate_in_kb, 2),
            "rate_out_kb": round(live_rate_out_kb, 2),
            "rate_total_kb": round(live_rate_in_kb + live_rate_out_kb, 2),
            "rate_total_mb": round((live_rate_in_kb + live_rate_out_kb) / 1024, 2)
        },
        "system": status
    }


@app.get("/api/traffic/history")
def api_traffic_history(points: int = 40):
    """Get time-series historical data points for charts."""
    history = get_traffic_history(limit_points=points)
    return {"history": history}


@app.get("/api/system/status")
def api_system_status():
    """Check capture engine status, admin privilege level, and network interface."""
    return sniffer.get_status()


@app.post("/api/system/toggle-simulation")
def api_toggle_simulation():
    """Toggle simulation mode on/off."""
    active = sniffer.toggle_simulation()
    return {"simulation_active": active}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time live telemetry stream WebSocket endpoint."""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep-alive receive
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
    except Exception:
        if websocket in active_connections:
            active_connections.remove(websocket)


# Mount static assets
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.api_route("/", methods=["GET", "HEAD"])
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "NetMeter API is running. Place index.html in frontend/ directory."}
