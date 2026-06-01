"""
SysMon Multi-User Database Layer
Manages persistent storage for devices and metrics
"""
import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'sysmon.db')


def init_db():
    """Initialize database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Devices table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        device_name TEXT NOT NULL,
        hostname TEXT,
        os_info TEXT,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Metrics table (stores latest metrics per device)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS latest_metrics (
        device_id TEXT PRIMARY KEY,
        timestamp TIMESTAMP,
        cpu_percent REAL,
        ram_percent REAL,
        cpu_cores INTEGER,
        cpu_threads INTEGER,
        cpu_freq_mhz REAL,
        memory_total_gb REAL,
        memory_used_gb REAL,
        disk_usage_percent REAL,
        network_sent_mb REAL,
        network_recv_mb REAL,
        processes_count INTEGER,
        battery_percent REAL,
        battery_charging INTEGER,
        full_metrics TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(device_id)
    )
    ''')
    
    # Historical metrics (for trending)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS metrics_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        cpu_percent REAL,
        ram_percent REAL,
        network_sent_mb REAL,
        network_recv_mb REAL,
        FOREIGN KEY(device_id) REFERENCES devices(device_id)
    )
    ''')
    
    # Create index for faster queries
    cursor.execute('''
    CREATE INDEX IF NOT EXISTS idx_device_timestamp 
    ON metrics_history(device_id, timestamp DESC)
    ''')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized")


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def register_device(device_id, device_name, hostname, os_info):
    """Register a new device or update existing."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO devices 
        (device_id, device_name, hostname, os_info, registered_at, last_seen)
        VALUES (?, ?, ?, ?, 
            COALESCE((SELECT registered_at FROM devices WHERE device_id = ?), CURRENT_TIMESTAMP),
            CURRENT_TIMESTAMP
        )
        ''', (device_id, device_name, hostname, os_info, device_id))
        conn.commit()
    print(f"✓ Device registered: {device_name} ({device_id})")


def get_all_devices():
    """Get list of all registered devices."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT device_id, device_name, hostname, os_info, registered_at, last_seen
        FROM devices
        ORDER BY last_seen DESC
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_device(device_id):
    """Get device information."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT device_id, device_name, hostname, os_info, registered_at, last_seen
        FROM devices WHERE device_id = ?
        ''', (device_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def save_metrics(device_id, metrics):
    """Save metrics for a device."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        timestamp = metrics.get('timestamp', datetime.now().isoformat())
        cpu = metrics.get('cpu', {})
        memory = metrics.get('memory', {})
        network = metrics.get('network', {})
        battery = metrics.get('battery', {})
        system = metrics.get('system', {})
        
        # Update latest metrics
        cursor.execute('''
        INSERT OR REPLACE INTO latest_metrics
        (device_id, timestamp, cpu_percent, ram_percent, cpu_cores, cpu_threads, 
         cpu_freq_mhz, memory_total_gb, memory_used_gb, disk_usage_percent,
         network_sent_mb, network_recv_mb, processes_count, battery_percent, 
         battery_charging, full_metrics)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            timestamp,
            cpu.get('usage_percent', 0),
            memory.get('percent', 0),
            cpu.get('core_count', 0),
            cpu.get('thread_count', 0),
            cpu.get('frequency_mhz', 0),
            memory.get('total_gb', 0),
            memory.get('used_gb', 0),
            metrics.get('disks', [{}])[0].get('percent', 0) if metrics.get('disks') else 0,
            network.get('bytes_sent_mb', 0),
            network.get('bytes_recv_mb', 0),
            metrics.get('processes', 0),
            battery.get('percent', 0) if battery else 0,
            1 if battery and battery.get('charging') else 0,
            str(metrics)
        ))
        
        # Add to history (keep it lightweight)
        cursor.execute('''
        INSERT INTO metrics_history
        (device_id, timestamp, cpu_percent, ram_percent, network_sent_mb, network_recv_mb)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            timestamp,
            cpu.get('usage_percent', 0),
            memory.get('percent', 0),
            network.get('bytes_sent_mb', 0),
            network.get('bytes_recv_mb', 0)
        ))
        
        # Update device last_seen
        cursor.execute('''
        UPDATE devices SET last_seen = CURRENT_TIMESTAMP 
        WHERE device_id = ?
        ''', (device_id,))
        
        conn.commit()


def get_latest_metrics(device_id):
    """Get latest metrics for a device."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM latest_metrics WHERE device_id = ?
        ''', (device_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_metrics_history(device_id, limit=1800):
    """Get metric history for a device (default: 1 hour at 2s intervals)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT timestamp, cpu_percent, ram_percent, network_sent_mb, network_recv_mb
        FROM metrics_history 
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
        ''', (device_id, limit))
        rows = cursor.fetchall()
        return [dict(row) for row in reversed(rows)]


def cleanup_old_metrics(days=7):
    """Remove metrics older than specified days."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        DELETE FROM metrics_history 
        WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        deleted = cursor.rowcount
        conn.commit()
    if deleted > 0:
        print(f"✓ Cleaned up {deleted} old metric records")


def get_device_count():
    """Get count of registered devices."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        return cursor.fetchone()[0]


def get_active_devices():
    """Get devices that sent metrics in last 5 minutes."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT device_id, device_name, hostname, last_seen
        FROM devices
        WHERE last_seen > datetime('now', '-5 minutes')
        ORDER BY last_seen DESC
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
