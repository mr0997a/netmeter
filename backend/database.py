import sqlite3
import time
import os
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "traffic_monitor.db")


def get_db_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_FILE):
    """Initialize database tables and indexes."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            custom_name TEXT,
            vendor TEXT,
            first_seen REAL,
            last_seen REAL,
            is_active INTEGER DEFAULT 1
        )
    """)

    # Traffic aggregates
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_traffic (
            ip TEXT PRIMARY KEY,
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            packets_in INTEGER DEFAULT 0,
            packets_out INTEGER DEFAULT 0,
            updated_at REAL,
            FOREIGN KEY(ip) REFERENCES devices(ip) ON DELETE CASCADE
        )
    """)

    # Protocol breakdown
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_protocols (
            ip TEXT,
            protocol TEXT,
            bytes INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            PRIMARY KEY(ip, protocol)
        )
    """)

    # Time series history (for charts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            ip TEXT,
            bytes_in_delta INTEGER DEFAULT 0,
            bytes_out_delta INTEGER DEFAULT 0
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_time ON traffic_history(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_ip ON traffic_history(ip)")

    # System settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()


def upsert_device(ip: str, mac: Optional[str] = None, hostname: Optional[str] = None,
                  vendor: Optional[str] = None, custom_name: Optional[str] = None,
                  db_path: str = DB_FILE):
    """Insert or update device discovery information."""
    now = time.time()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT ip, mac, hostname, vendor, custom_name, first_seen FROM devices WHERE ip = ?", (ip,))
    row = cursor.fetchone()

    if row is None:
        cursor.execute("""
            INSERT INTO devices (ip, mac, hostname, vendor, custom_name, first_seen, last_seen, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (ip, mac or "Unknown", hostname or "", vendor or "Generic Device", custom_name or "", now, now))
        cursor.execute("""
            INSERT OR IGNORE INTO device_traffic (ip, bytes_in, bytes_out, packets_in, packets_out, updated_at)
            VALUES (?, 0, 0, 0, 0, ?)
        """, (ip, now))
    else:
        new_mac = mac if mac and mac != "Unknown" else row["mac"]
        new_host = hostname if hostname else row["hostname"]
        new_vendor = vendor if vendor and vendor != "Generic Device" else row["vendor"]
        new_name = custom_name if custom_name is not None else row["custom_name"]
        cursor.execute("""
            UPDATE devices
            SET mac = ?, hostname = ?, vendor = ?, custom_name = ?, last_seen = ?, is_active = 1
            WHERE ip = ?
        """, (new_mac, new_host, new_vendor, new_name, now, ip))

    conn.commit()
    conn.close()


def rename_device(ip: str, custom_name: str, db_path: str = DB_FILE) -> bool:
    """Set custom alias/name for a device."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET custom_name = ? WHERE ip = ?", (custom_name.strip(), ip))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def record_traffic_delta(updates: List[Dict[str, Any]], db_path: str = DB_FILE):
    """
    Batch update traffic and write time-series delta.
    updates is list of dict: {
        'ip': str,
        'bytes_in': int,
        'bytes_out': int,
        'packets_in': int,
        'packets_out': int,
        'proto_breakdown': dict (proto -> {'bytes': int, 'packets': int})
    }
    """
    if not updates:
        return

    now = time.time()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    for item in updates:
        ip = item['ip']
        b_in = item.get('bytes_in', 0)
        b_out = item.get('bytes_out', 0)
        p_in = item.get('packets_in', 0)
        p_out = item.get('packets_out', 0)

        # Ensure device exists
        cursor.execute("SELECT ip FROM devices WHERE ip = ?", (ip,))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, custom_name, first_seen, last_seen, is_active)
                VALUES (?, 'Unknown', '', 'Generic Device', '', ?, ?, 1)
            """, (ip, now, now))

        # Update cumulative traffic
        cursor.execute("""
            INSERT INTO device_traffic (ip, bytes_in, bytes_out, packets_in, packets_out, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                bytes_in = bytes_in + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out,
                packets_in = packets_in + excluded.packets_in,
                packets_out = packets_out + excluded.packets_out,
                updated_at = excluded.updated_at
        """, (ip, b_in, b_out, p_in, p_out, now))

        # Update device last_seen
        cursor.execute("UPDATE devices SET last_seen = ?, is_active = 1 WHERE ip = ?", (now, ip))

        # Record time series delta if there was traffic
        if b_in > 0 or b_out > 0:
            cursor.execute("""
                INSERT INTO traffic_history (timestamp, ip, bytes_in_delta, bytes_out_delta)
                VALUES (?, ?, ?, ?)
            """, (now, ip, b_in, b_out))

        # Update protocol breakdown
        proto_breakdown = item.get('proto_breakdown', {})
        for proto, stats in proto_breakdown.items():
            p_bytes = stats.get('bytes', 0)
            p_pkts = stats.get('packets', 0)
            if p_bytes > 0 or p_pkts > 0:
                cursor.execute("""
                    INSERT INTO device_protocols (ip, protocol, bytes, packets)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip, protocol) DO UPDATE SET
                        bytes = bytes + excluded.bytes,
                        packets = packets + excluded.packets
                """, (ip, proto, p_bytes, p_pkts))

    conn.commit()
    conn.close()


def get_all_devices(db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Return all devices with their cumulative traffic stats."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            d.ip,
            d.mac,
            d.hostname,
            d.custom_name,
            d.vendor,
            d.first_seen,
            d.last_seen,
            d.is_active,
            COALESCE(t.bytes_in, 0) AS bytes_in,
            COALESCE(t.bytes_out, 0) AS bytes_out,
            COALESCE(t.packets_in, 0) AS packets_in,
            COALESCE(t.packets_out, 0) AS packets_out,
            t.updated_at
        FROM devices d
        LEFT JOIN device_traffic t ON d.ip = t.ip
        ORDER BY (COALESCE(t.bytes_in, 0) + COALESCE(t.bytes_out, 0)) DESC
    """)

    rows = cursor.fetchall()
    devices = []
    now = time.time()

    for r in rows:
        b_in = r["bytes_in"]
        b_out = r["bytes_out"]
        total_bytes = b_in + b_out
        last_seen = r["last_seen"]
        # Mark inactive if not seen in 120 seconds
        is_active = 1 if (now - last_seen) < 120 else 0

        devices.append({
            "ip": r["ip"],
            "mac": r["mac"] or "Unknown",
            "hostname": r["hostname"] or "",
            "custom_name": r["custom_name"] or "",
            "display_name": r["custom_name"] or r["hostname"] or f"Device ({r['ip'].split('.')[-1]})",
            "vendor": r["vendor"] or "Generic Device",
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "is_active": bool(is_active),
            "bytes_in": b_in,
            "bytes_out": b_out,
            "total_bytes": total_bytes,
            "mb_in": round(b_in / (1024 * 1024), 2),
            "mb_out": round(b_out / (1024 * 1024), 2),
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "gb_in": round(b_in / (1024 * 1024 * 1024), 3),
            "gb_out": round(b_out / (1024 * 1024 * 1024), 3),
            "total_gb": round(total_bytes / (1024 * 1024 * 1024), 3),
            "packets_in": r["packets_in"],
            "packets_out": r["packets_out"],
            "total_packets": r["packets_in"] + r["packets_out"],
            "updated_at": r["updated_at"]
        })

    conn.close()
    return devices


def get_device_detail(ip: str, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Return comprehensive detail for a single device, including protocol breakdown."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            d.ip, d.mac, d.hostname, d.custom_name, d.vendor, d.first_seen, d.last_seen, d.is_active,
            COALESCE(t.bytes_in, 0) AS bytes_in,
            COALESCE(t.bytes_out, 0) AS bytes_out,
            COALESCE(t.packets_in, 0) AS packets_in,
            COALESCE(t.packets_out, 0) AS packets_out
        FROM devices d
        LEFT JOIN device_traffic t ON d.ip = t.ip
        WHERE d.ip = ?
    """, (ip,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    # Fetch protocols
    cursor.execute("SELECT protocol, bytes, packets FROM device_protocols WHERE ip = ? ORDER BY bytes DESC", (ip,))
    proto_rows = cursor.fetchall()
    protocols = {p["protocol"]: {"bytes": p["bytes"], "packets": p["packets"]} for p in proto_rows}

    # Fetch recent history (last 50 data points)
    cursor.execute("""
        SELECT timestamp, bytes_in_delta, bytes_out_delta
        FROM traffic_history
        WHERE ip = ?
        ORDER BY timestamp DESC
        LIMIT 50
    """, (ip,))
    history_rows = cursor.fetchall()
    history = [{"timestamp": h["timestamp"], "in": h["bytes_in_delta"], "out": h["bytes_out_delta"]} for h in reversed(history_rows)]

    conn.close()

    b_in = row["bytes_in"]
    b_out = row["bytes_out"]
    total = b_in + b_out

    return {
        "ip": row["ip"],
        "mac": row["mac"],
        "hostname": row["hostname"],
        "custom_name": row["custom_name"],
        "display_name": row["custom_name"] or row["hostname"] or f"Device ({row['ip'].split('.')[-1]})",
        "vendor": row["vendor"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "bytes_in": b_in,
        "bytes_out": b_out,
        "total_bytes": total,
        "mb_in": round(b_in / (1024 * 1024), 2),
        "mb_out": round(b_out / (1024 * 1024), 2),
        "total_mb": round(total / (1024 * 1024), 2),
        "gb_in": round(b_in / (1024 * 1024 * 1024), 3),
        "gb_out": round(b_out / (1024 * 1024 * 1024), 3),
        "total_gb": round(total / (1024 * 1024 * 1024), 3),
        "packets_in": row["packets_in"],
        "packets_out": row["packets_out"],
        "protocols": protocols,
        "history": history
    }


def get_traffic_history(limit_points: int = 30, db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Retrieve grouped time-series traffic for chart rendering."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Bucket into recent intervals
    cursor.execute("""
        SELECT 
            CAST(timestamp / 5 AS INTEGER) * 5 AS time_bucket,
            SUM(bytes_in_delta) AS total_in,
            SUM(bytes_out_delta) AS total_out
        FROM traffic_history
        GROUP BY time_bucket
        ORDER BY time_bucket DESC
        LIMIT ?
    """, (limit_points,))

    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in reversed(rows):
        result.append({
            "timestamp": r["time_bucket"],
            "bytes_in": r["total_in"] or 0,
            "bytes_out": r["total_out"] or 0,
            "kb_in": round((r["total_in"] or 0) / 1024, 2),
            "kb_out": round((r["total_out"] or 0) / 1024, 2),
            "mb_in": round((r["total_in"] or 0) / (1024 * 1024), 3),
            "mb_out": round((r["total_out"] or 0) / (1024 * 1024), 3)
        })
    return result


def get_network_totals(db_path: str = DB_FILE) -> Dict[str, Any]:
    """Get overall aggregated network stats."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            COUNT(DISTINCT d.ip) AS total_devices,
            SUM(COALESCE(t.bytes_in, 0)) AS total_bytes_in,
            SUM(COALESCE(t.bytes_out, 0)) AS total_bytes_out,
            SUM(COALESCE(t.packets_in, 0) + COALESCE(t.packets_out, 0)) AS total_packets
        FROM devices d
        LEFT JOIN device_traffic t ON d.ip = t.ip
    """)
    row = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS active_count FROM devices WHERE is_active = 1")
    active_row = cursor.fetchone()

    conn.close()

    b_in = row["total_bytes_in"] or 0
    b_out = row["total_bytes_out"] or 0
    total = b_in + b_out

    return {
        "total_devices": row["total_devices"] or 0,
        "active_devices": active_row["active_count"] or 0,
        "total_bytes_in": b_in,
        "total_bytes_out": b_out,
        "total_bytes": total,
        "total_mb_in": round(b_in / (1024 * 1024), 2),
        "total_mb_out": round(b_out / (1024 * 1024), 2),
        "total_mb": round(total / (1024 * 1024), 2),
        "total_gb_in": round(b_in / (1024 * 1024 * 1024), 3),
        "total_gb_out": round(b_out / (1024 * 1024 * 1024), 3),
        "total_gb": round(total / (1024 * 1024 * 1024), 3),
        "total_packets": row["total_packets"] or 0
    }
