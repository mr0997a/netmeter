import os
import sys
import tempfile
import pytest
from starlette.testclient import TestClient

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.database import (
    init_db, upsert_device, rename_device, record_traffic_delta,
    get_all_devices, get_device_detail, get_network_totals
)
from backend.sniffer import NetworkSniffer
from backend.main import app


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_traffic.db")
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)


def test_database_crud(temp_db):
    # Test device insertion and ARP info
    upsert_device(ip="192.168.1.50", mac="00:11:22:33:44:55", hostname="nas-box", vendor="Synology", db_path=temp_db)
    devices = get_all_devices(db_path=temp_db)
    assert len(devices) == 1
    assert devices[0]["ip"] == "192.168.1.50"
    assert devices[0]["vendor"] == "Synology"

    # Test renaming device
    rename_device("192.168.1.50", "Backup Storage Server", db_path=temp_db)
    dev = get_device_detail("192.168.1.50", db_path=temp_db)
    assert dev is not None
    assert dev["custom_name"] == "Backup Storage Server"
    assert dev["display_name"] == "Backup Storage Server"

    # Test traffic update
    updates = [{
        "ip": "192.168.1.50",
        "bytes_in": 10485760,  # 10 MB
        "bytes_out": 20971520, # 20 MB
        "packets_in": 7000,
        "packets_out": 14000,
        "proto_breakdown": {
            "HTTPS": {"bytes": 10485760, "packets": 7000},
            "TCP": {"bytes": 20971520, "packets": 14000}
        }
    }]
    record_traffic_delta(updates, db_path=temp_db)

    # Check cumulative stats
    dev_after = get_device_detail("192.168.1.50", db_path=temp_db)
    assert dev_after["mb_in"] == 10.0
    assert dev_after["mb_out"] == 20.0
    assert dev_after["total_mb"] == 30.0
    assert "HTTPS" in dev_after["protocols"]

    # Check network totals
    totals = get_network_totals(db_path=temp_db)
    assert totals["total_devices"] == 1
    assert totals["total_mb"] == 30.0


def test_sniffer_subnet_logic():
    sniffer = NetworkSniffer(local_ip="192.168.1.11", subnet_cidr="192.168.1.0/24")
    assert sniffer.is_in_subnet("192.168.1.1") is True
    assert sniffer.is_in_subnet("192.168.1.100") is True
    assert sniffer.is_in_subnet("8.8.8.8") is False
    assert sniffer.is_in_subnet("10.0.0.1") is False

    # Simulate packet processing
    sniffer.process_packet("192.168.1.45", "142.250.190.46", 1460, "HTTPS")
    # 192.168.1.45 sent to external -> bytes_out for that device
    assert sniffer.pending_traffic["192.168.1.45"]["bytes_out"] == 1460

    # External sent to 192.168.1.45 -> bytes_in for that device
    sniffer.process_packet("142.250.190.46", "192.168.1.45", 1460, "HTTPS")
    assert sniffer.pending_traffic["192.168.1.45"]["bytes_in"] == 1460


def test_fastapi_endpoints():
    with TestClient(app) as client:
        # Check root serves HTML or message
        res = client.get("/")
        assert res.status_code == 200

        # Check system status endpoint
        res = client.get("/api/system/status")
        assert res.status_code == 200
        data = res.json()
        assert "mode" in data
        assert "subnet" in data

        # Check devices endpoint
        res = client.get("/api/devices")
        assert res.status_code == 200
        assert "devices" in res.json()

        # Check traffic summary endpoint
        res = client.get("/api/traffic/summary")
        assert res.status_code == 200
        assert "totals" in res.json()
        assert "live_speed" in res.json()

        # Check rename endpoint
        rename_res = client.patch("/api/devices/192.168.1.99/rename", json={"custom_name": "Test Device 99"})
        assert rename_res.status_code == 200
        assert rename_res.json()["custom_name"] == "Test Device 99"

        # Check traffic history endpoint
        hist_res = client.get("/api/traffic/history")
        assert hist_res.status_code == 200
        assert "history" in hist_res.json()
