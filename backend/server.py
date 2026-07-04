"""
SysMon Pro - System Monitoring & Security Scanner Backend
Flask server providing system metrics, security scanning, and report generation.
Multi-user support with device identification and persistent storage.
"""
import json
import ast
from collections import deque
import csv
import io
import subprocess
import platform
import datetime
import socket
import psutil
import os
import uuid
import tempfile
from flask import Flask, jsonify, Response, send_from_directory, request
from flask_cors import CORS
from fpdf import FPDF
from database import (
    init_db, register_device, get_all_devices, get_device,
    save_metrics, get_latest_metrics, get_latest_metrics_for_user,
    get_metrics_history, get_metrics_history_for_user,
    get_device_count, get_active_devices,
    get_all_latest_metrics_for_user
)

app = Flask(__name__)
CORS(app)

# Initialize database
init_db()

# ─────────────────────────────────────────────
# HISTORY BUFFER  (max 1800 snapshots ≈ 1 hour @ 2s poll)
# ─────────────────────────────────────────────
HISTORY_MAX = 1800
history_buffer: deque = deque(maxlen=HISTORY_MAX)

# ─────────────────────────────────────────────
# PC AGENT STORAGE (for metrics from local PC)
# ─────────────────────────────────────────────
pc_agent_metrics = None  # Store latest metrics from PC agent
use_pc_agent = False  # Flag to use PC agent metrics instead of server metrics


def get_request_user_id():
    """Resolve the current user scope from the request."""
    return (
        request.args.get("user_id")
        or request.headers.get("X-SysMon-User-Id")
        or request.headers.get("X-User-Id")
        or "public"
    )


def get_request_device_id():
    """Resolve the current device selection from the request."""
    return request.args.get("device_id")


def build_metrics_payload(metrics_row, device_row=None):
    """Convert a database row into the frontend metrics payload shape."""
    if not metrics_row:
        return None

    raw = metrics_row.get("full_metrics")
    data = None
    if raw:
        try:
            data = ast.literal_eval(raw)
        except Exception:
            data = None

    if not data:
        device_row = device_row or {}
        data = {
            "timestamp": metrics_row.get("timestamp", datetime.datetime.now().isoformat()),
            "device_id": metrics_row.get("device_id"),
            "device_name": device_row.get("device_name", "Unknown Device"),
            "system": {
                "os": device_row.get("os_info", "unknown"),
                "version": "",
                "machine": "",
                "processor": "",
                "hostname": device_row.get("hostname", "unknown"),
                "uptime": "",
                "boot_time": "",
            },
            "cpu": {
                "usage_percent": metrics_row.get("cpu_percent", 0),
                "per_core": [],
                "core_count": metrics_row.get("cpu_cores", 0),
                "thread_count": metrics_row.get("cpu_threads", 0),
                "frequency_mhz": metrics_row.get("cpu_freq_mhz", 0),
                "freq_max_mhz": None,
            },
            "memory": {
                "total_gb": metrics_row.get("memory_total_gb", 0),
                "used_gb": metrics_row.get("memory_used_gb", 0),
                "available_gb": 0,
                "percent": metrics_row.get("ram_percent", 0),
                "swap_total_gb": 0,
                "swap_used_gb": 0,
                "swap_percent": 0,
            },
            "disks": [],
            "network": {
                "bytes_sent_mb": metrics_row.get("network_sent_mb", 0),
                "bytes_recv_mb": metrics_row.get("network_recv_mb", 0),
                "packets_sent": 0,
                "packets_recv": 0,
                "interfaces": {},
            },
            "battery": {
                "percent": metrics_row.get("battery_percent", 0),
                "charging": bool(metrics_row.get("battery_charging", 0)),
                "time_left_mins": None,
            } if metrics_row.get("battery_percent") is not None else None,
            "processes": metrics_row.get("processes_count", 0),
        }

    if device_row:
        data.setdefault("device_id", device_row.get("device_id", metrics_row.get("device_id")))
        data.setdefault("device_name", device_row.get("device_name", "Unknown Device"))
    else:
        data.setdefault("device_id", metrics_row.get("device_id"))

    return data


def resolve_user_metrics(user_id, device_id=None):
    """Resolve the latest metrics for a user's selected device."""
    metrics_row = get_latest_metrics_for_user(user_id, device_id)
    if not metrics_row:
        return None, None

    device_row = get_device(metrics_row.get("device_id"), user_id)
    data = build_metrics_payload(metrics_row, device_row)
    return data, device_row


def build_device_health_scan(metrics):
    """Build a device-health summary from device metrics instead of server state."""
    findings = []
    cpu = metrics.get("cpu", {})
    memory = metrics.get("memory", {})
    battery = metrics.get("battery") or {}
    system = metrics.get("system", {})

    hostname = system.get("hostname", "Unknown device")
    findings.append({
        "category": "Device",
        "name": "Selected Device",
        "status": "PASS",
        "details": f"Showing analysis for {metrics.get('device_name', hostname)} ({hostname})",
        "recommendation": "",
    })

    cpu_pct = float(cpu.get("usage_percent", 0) or 0)
    cpu_status = "PASS" if cpu_pct < 75 else ("WARN" if cpu_pct < 90 else "FAIL")
    findings.append({
        "category": "Performance",
        "name": "CPU Usage",
        "status": cpu_status,
        "details": f"Current CPU load: {cpu_pct:.1f}%",
        "recommendation": "Close heavy apps or background tasks." if cpu_status != "PASS" else "",
    })

    ram_pct = float(memory.get("percent", 0) or 0)
    ram_status = "PASS" if ram_pct < 75 else ("WARN" if ram_pct < 90 else "FAIL")
    findings.append({
        "category": "Performance",
        "name": "Memory Usage",
        "status": ram_status,
        "details": f"Current RAM usage: {ram_pct:.1f}%",
        "recommendation": "Close unused apps or increase available memory." if ram_status != "PASS" else "",
    })

    swap_pct = float(memory.get("swap_percent", 0) or 0)
    swap_status = "PASS" if swap_pct < 50 else "WARN"
    findings.append({
        "category": "Performance",
        "name": "Swap Usage",
        "status": swap_status,
        "details": f"Current swap usage: {swap_pct:.1f}%",
        "recommendation": "Reduce memory pressure to avoid swapping." if swap_status != "PASS" else "",
    })

    if battery:
        battery_pct = float(battery.get("percent", 0) or 0)
        charging = bool(battery.get("charging"))
        battery_status = "PASS" if charging or battery_pct >= 30 else "WARN"
        findings.append({
            "category": "Power",
            "name": "Battery",
            "status": battery_status,
            "details": f"Battery at {battery_pct:.1f}% ({'charging' if charging else 'on battery'})",
            "recommendation": "Plug in the device soon." if battery_status != "PASS" else "",
        })

    process_count = int(metrics.get("processes", 0) or 0)
    proc_status = "PASS" if process_count < 400 else ("WARN" if process_count < 700 else "FAIL")
    findings.append({
        "category": "Activity",
        "name": "Running Processes",
        "status": proc_status,
        "details": f"{process_count} processes currently running",
        "recommendation": "Review startup items and background tasks." if proc_status != "PASS" else "",
    })

    pass_count = len([f for f in findings if f["status"] == "PASS"])
    warn_count = len([f for f in findings if f["status"] == "WARN"])
    fail_count = len([f for f in findings if f["status"] == "FAIL"])
    info_count = len([f for f in findings if f["status"] == "INFO"])
    total = len(findings) or 1

    if fail_count > 0:
        overall = "AT RISK"
    elif warn_count > 1:
        overall = "FAIR"
    elif warn_count > 0:
        overall = "GOOD"
    else:
        overall = "EXCELLENT"

    score = max(0, int(((pass_count + info_count * 0.5) / total) * 100))

    return {
        "timestamp": metrics.get("timestamp", datetime.datetime.now().isoformat()),
        "overall_status": overall,
        "score": score,
        "summary": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "info": info_count,
            "total": len(findings),
        },
        "findings": findings,
    }

def get_os_name():
    """Get user-friendly OS name, with special Windows 11 detection support."""
    if platform.system() == "Windows":
        release = "10"
        try:
            ver_parts = platform.win32_ver()[1].split('.')
            if len(ver_parts) >= 3 and int(ver_parts[2]) >= 22000:
                release = "11"
        except:
            pass
        
        edition = ""
        try:
            if hasattr(platform, 'win32_edition'):
                edt = platform.win32_edition()
                if edt == "Core":
                    edition = "Home"
                elif edt == "CoreSingleLanguage":
                    edition = "Home Single Language"
                elif edt == "Professional":
                    edition = "Pro"
                elif edt:
                    edition = edt
        except:
            pass
            
        os_name = f"Windows {release}"
        if edition:
            os_name += f" {edition}"
        return os_name
    return f"{platform.system()} {platform.release()}"


# ─────────────────────────────────────────────
# SYSTEM METRICS
# ─────────────────────────────────────────────

def get_system_metrics():
    """Gather comprehensive system metrics."""
    cpu_per_core = psutil.cpu_percent(interval=0.5, percpu=True)
    cpu_percent = round(sum(cpu_per_core) / len(cpu_per_core), 1) if cpu_per_core else 0.0
    cpu_freq = psutil.cpu_freq()

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "percent": usage.percent,
            })
        except PermissionError:
            continue

    net_io = psutil.net_io_counters()
    net_addrs = psutil.net_if_addrs()
    network_interfaces = {}
    for iface, addrs in net_addrs.items():
        ips = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        if ips:
            network_interfaces[iface] = ips[0]

    battery = None
    bat = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    if bat:
        battery = {
            "percent": round(bat.percent, 1),
            "charging": bat.power_plugged,
            "time_left_mins": round(bat.secsleft / 60, 1) if bat.secsleft > 0 else None,
        }

    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime_seconds = (datetime.datetime.now() - boot_time).total_seconds()
    uptime_str = str(datetime.timedelta(seconds=int(uptime_seconds)))

    process_count = len(psutil.pids())
    uname = platform.uname()

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "system": {
            "os": get_os_name(),
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor or platform.processor(),
            "hostname": uname.node,
            "uptime": uptime_str,
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "cpu": {
            "usage_percent": cpu_percent,
            "per_core": cpu_per_core,
            "core_count": len(cpu_per_core),
            "thread_count": psutil.cpu_count(logical=True),
            "frequency_mhz": round(cpu_freq.current, 1) if cpu_freq else None,
            "freq_max_mhz": round(cpu_freq.max, 1) if cpu_freq else None,
        },
        "memory": {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "percent": mem.percent,
            "swap_total_gb": round(swap.total / (1024 ** 3), 2),
            "swap_used_gb": round(swap.used / (1024 ** 3), 2),
            "swap_percent": swap.percent,
        },
        "disks": disks,
        "network": {
            "bytes_sent_mb": round(net_io.bytes_sent / (1024 ** 2), 2),
            "bytes_recv_mb": round(net_io.bytes_recv / (1024 ** 2), 2),
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "interfaces": network_interfaces,
        },
        "battery": battery,
        "processes": process_count,
    }


# ─────────────────────────────────────────────
# SECURITY SCAN
# ─────────────────────────────────────────────

def run_ps(cmd):
    try:
        if platform.system() != "Windows":
            return "Not supported on this OS"

        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def get_security_scan():
    """Perform a basic Windows security scan using PowerShell."""
    findings = []
    print("LOG: Starting security scan...")

    # 1. Windows Firewall Status
    fw_output = run_ps(
        "(Get-NetFirewallProfile | Select-Object Name, Enabled | "
        "ForEach-Object { $_.Name + ':' + $_.Enabled }) -join '|'"
    )
    firewall_profiles = {}
    if fw_output and "ERROR" not in fw_output:
        for item in fw_output.split("|"):
            parts = item.split(":")
            if len(parts) == 2:
                firewall_profiles[parts[0]] = parts[1].strip() == "True"
    all_fw_on = all(firewall_profiles.values()) if firewall_profiles else False
    fw_detail = ", ".join(f"{k}: {'ON' if v else 'OFF'}" for k, v in firewall_profiles.items()) if firewall_profiles else fw_output
    findings.append({
        "category": "Firewall", "name": "Windows Firewall", "status": "PASS" if all_fw_on else "WARN",
        "details": fw_detail, "recommendation": "" if all_fw_on else "Enable all Windows Firewall profiles.",
    })

    # 2. & 3. Windows Defender & RTP (OPTIMIZED: One call)
    print("LOG: Checking Defender status...")
    av_raw = run_ps("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json")
    av_enabled = False
    rtp_enabled = False
    try:
        av_data = json.loads(av_raw)
        av_enabled = av_data.get("AntivirusEnabled") is True
        rtp_enabled = av_data.get("RealTimeProtectionEnabled") is True
    except: pass

    findings.append({
        "category": "Antivirus", "name": "Windows Defender", "status": "PASS" if av_enabled else "WARN",
        "details": f"Antivirus enabled: {av_enabled}", "recommendation": "" if av_enabled else "Enable Windows Defender.",
    })
    findings.append({
        "category": "Antivirus", "name": "Real-Time Protection", "status": "PASS" if rtp_enabled else "WARN",
        "details": f"Real-time protection enabled: {rtp_enabled}", "recommendation": "" if rtp_enabled else "Enable RTP.",
    })

    # 4. Windows Update status (OPTIMIZED)
    upd_output = run_ps("$last = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install' -ErrorAction SilentlyContinue).LastSuccessTime; if ($last) { (New-TimeSpan -Start $last -End (Get-Date)).Days } else { -1 }")
    try:
        days_since_update = int(upd_output.strip())
        if days_since_update == -1:
            upd_status = "WARN"
            upd_rec = "Windows Update has never succeeded or information is missing."
            upd_detail = "Unknown"
        elif days_since_update > 30:
            upd_status = "FAIL"
            upd_rec = f"Last update was {days_since_update} days ago. Run Windows Update."
            upd_detail = f"Last successful update: {days_since_update} days ago"
        elif days_since_update > 14:
            upd_status = "WARN"
            upd_rec = f"Last update was {days_since_update} days ago. Run Windows Update."
            upd_detail = f"Last successful update: {days_since_update} days ago"
        else:
            upd_status = "PASS"
            upd_rec = ""
            upd_detail = f"Last successful update: {days_since_update} days ago"
    except:
        upd_status = "INFO"
        upd_detail = "Could not verify update status"
        upd_rec = "Check updates manually."
    
    findings.append({
        "category": "Updates", "name": "Windows Update Status", "status": upd_status,
        "details": upd_detail, "recommendation": upd_rec,
    })

    # 5. Password policy
    pp_output = run_ps("net accounts | Select-String 'Maximum password age'")
    pp_status = "INFO"
    if pp_output:
        if "Unlimited" in pp_output or "Never" in pp_output:
            pp_status = "WARN"
            pp_rec = "Password never expires. Set a maximum password age."
        else:
            try:
                days = int(''.join(filter(str.isdigit, pp_output)))
                if days > 90:
                    pp_status = "WARN"
                    pp_rec = "Password age is > 90 days. Recommend lowering."
                else:
                    pp_status = "PASS"
                    pp_rec = ""
            except:
                pp_rec = "Set age to 90 days or less."
    else:
        pp_rec = "Set age to 90 days or less."

    findings.append({
        "category": "Account Policy", "name": "Password Policy", "status": pp_status,
        "details": pp_output or "N/A", "recommendation": pp_rec,
    })

    # 6. Auto-run entries count
    autorun_output = run_ps("(Get-CimInstance Win32_StartupCommand).Count")
    try: 
        autorun_count = int(autorun_output.strip())
        autorun_status = "WARN" if autorun_count >= 10 else "PASS"
    except: 
        autorun_count = -1
        autorun_status = "INFO"
        
    findings.append({
        "category": "Startup", "name": "Startup Programs", "status": autorun_status,
        "details": f"{autorun_count} registered", "recommendation": "Review startup apps." if autorun_count >= 10 else "",
    })

    # 7. Open listening ports
    risky_ports = {21: 'FTP', 23: 'Telnet', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM-S', 135: 'RPC', 139: 'NetBIOS'}
    try:
        connections = psutil.net_connections(kind='inet')
        listening = [conn for conn in connections if conn.status == 'LISTEN' and conn.laddr]
        listening_ports = sorted(set(conn.laddr.port for conn in listening))
        port_count = len(listening_ports)

        # Check for risky ports
        found_risky = {p: risky_ports[p] for p in listening_ports if p in risky_ports}

        if found_risky:
            port_status = 'WARN'
            risky_str = ', '.join(f'{p} ({n})' for p, n in found_risky.items())
            port_detail = f'{port_count} ports listening · Risky: {risky_str}'
            port_rec = f'Review and close unnecessary ports: {risky_str}'
        elif port_count >= 25:
            port_status = 'WARN'
            port_detail = f'{port_count} ports listening (high count)'
            port_rec = 'Many open ports detected. Review for unnecessary services.'
        else:
            port_status = 'PASS'
            port_detail = f'{port_count} ports listening'
            port_rec = ''

        # Include top ports in details
        shown = listening_ports[:20]
        port_detail += ' · Ports: ' + ', '.join(str(p) for p in shown)
        if port_count > 20:
            port_detail += f' (+{port_count - 20} more)'
    except (psutil.AccessDenied, PermissionError):
        listening_ports = []
        port_count = 0
        port_status = 'INFO'
        port_detail = 'Access denied — run as Administrator for full port scan'
        port_rec = 'Run as Administrator to see all open ports.'
        found_risky = {}

    findings.append({
        'category': 'Network Security', 'name': 'Open Listening Ports', 'status': port_status,
        'details': port_detail, 'recommendation': port_rec,
        'ports_list': listening_ports,
        'risky_ports': {str(k): v for k, v in found_risky.items()},
    })

    # 8. UAC Status
    uac_output = run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
    uac_enabled = uac_output.strip() == "1"
    findings.append({
        "category": "Account Policy", "name": "User Account Control (UAC)", "status": "PASS" if uac_enabled else "FAIL",
        "details": f"UAC Enabled: {uac_enabled}", "recommendation": "" if uac_enabled else "Enable UAC immediately.",
    })

    # 9. Drive Free Space
    try:
        c_usage = psutil.disk_usage("C:\\" if platform.system() == "Windows" else "/")
        free_gb = c_usage.free / (1024**3)
        percent_used = c_usage.percent
        if percent_used > 90 or free_gb < 10:
            disk_status = "FAIL"
            disk_rec = "Free up space on the system drive immediately."
        elif percent_used > 80 or free_gb < 20:
            disk_status = "WARN"
            disk_rec = "System drive is getting full. Free up some space."
        else:
            disk_status = "PASS"
            disk_rec = ""
        disk_detail = f"System drive: {percent_used}% used ({free_gb:.1f} GB free)"
    except:
        disk_status = "INFO"
        disk_detail = "Could not read system drive space."
        disk_rec = ""
    findings.append({
        "category": "Storage", "name": "System Drive Space", "status": disk_status,
        "details": disk_detail, "recommendation": disk_rec,
    })

    # 10. Admin Rights
    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        pass
    findings.append({
        "category": "Privileges", "name": "Admin Rights", "status": "WARN" if is_admin else "PASS",
        "details": "Running as Administrator" if is_admin else "Running as standard user",
        "recommendation": "Avoid running daily tasks as Administrator." if is_admin else "",
    })

    # 11. System Uptime Check
    try:
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime_delta = datetime.datetime.now() - boot_time
        uptime_days = uptime_delta.days
        uptime_str = str(datetime.timedelta(seconds=int(uptime_delta.total_seconds())))
        if uptime_days > 30:
            up_status = 'FAIL'
            up_rec = f'System has not rebooted in {uptime_days} days. Restart to apply pending updates and free resources.'
        elif uptime_days > 14:
            up_status = 'WARN'
            up_rec = f'System has been running for {uptime_days} days. Consider restarting.'
        else:
            up_status = 'PASS'
            up_rec = ''
        up_detail = f'System uptime: {uptime_str} ({uptime_days} days)'
    except:
        up_status = 'INFO'
        up_detail = 'Could not determine uptime'
        up_rec = ''
    findings.append({
        'category': 'Maintenance', 'name': 'System Uptime', 'status': up_status,
        'details': up_detail, 'recommendation': up_rec,
    })

    # 12. RDP Status
    rdp_output = run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
    try:
        rdp_denied = int(rdp_output.strip())
        rdp_enabled = rdp_denied == 0
        rdp_status = 'WARN' if rdp_enabled else 'PASS'
        rdp_detail = 'Remote Desktop is ENABLED' if rdp_enabled else 'Remote Desktop is DISABLED'
        rdp_rec = 'Disable RDP if not needed. It exposes port 3389 to potential attacks.' if rdp_enabled else ''
    except:
        rdp_status = 'INFO'
        rdp_detail = 'Could not determine RDP status'
        rdp_rec = ''
    findings.append({
        'category': 'Access Control', 'name': 'Remote Desktop (RDP)', 'status': rdp_status,
        'details': rdp_detail, 'recommendation': rdp_rec,
    })

    # 13. Guest Account Status
    guest_output = run_ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    if guest_output and 'ERROR' not in guest_output:
        guest_enabled = guest_output.strip().lower() == 'true'
        guest_status = 'WARN' if guest_enabled else 'PASS'
        guest_detail = 'Guest account is ENABLED' if guest_enabled else 'Guest account is disabled'
        guest_rec = 'Disable the Guest account for better security.' if guest_enabled else ''
    else:
        guest_status = 'PASS'
        guest_detail = 'Guest account not found or disabled'
        guest_rec = ''
    findings.append({
        'category': 'Access Control', 'name': 'Guest Account', 'status': guest_status,
        'details': guest_detail, 'recommendation': guest_rec,
    })

    # 14. Secure Boot Status
    sb_output = run_ps("Confirm-SecureBoot -ErrorAction SilentlyContinue")
    if sb_output and 'ERROR' not in sb_output:
        sb_enabled = sb_output.strip().lower() == 'true'
        sb_status = 'PASS' if sb_enabled else 'WARN'
        sb_detail = 'Secure Boot is ENABLED' if sb_enabled else 'Secure Boot is DISABLED'
        sb_rec = '' if sb_enabled else 'Enable Secure Boot in BIOS/UEFI for rootkit protection.'
    else:
        sb_status = 'INFO'
        sb_detail = 'Could not determine Secure Boot status'
        sb_rec = ''
    findings.append({
        'category': 'System Security', 'name': 'Secure Boot', 'status': sb_status,
        'details': sb_detail, 'recommendation': sb_rec,
    })

    print("LOG: Security scan complete.")

    pass_count = len([f for f in findings if f["status"] == "PASS"])
    warn_count = len([f for f in findings if f["status"] == "WARN"])
    fail_count = len([f for f in findings if f["status"] == "FAIL"])
    info_count = len([f for f in findings if f["status"] == "INFO"])
    total = len(findings)

    if fail_count > 0:
        overall = "CRITICAL"
    elif warn_count > 2:
        overall = "AT RISK"
    elif warn_count > 0:
        overall = "FAIR"
    else:
        overall = "SECURE"

    score = max(0, int(((pass_count + info_count * 0.5) / total) * 100)) if total > 0 else 0

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "overall_status": overall,
        "score": score,
        "summary": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "info": info_count,
            "total": total,
        },
        "findings": findings,
    }


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def pdf_clean(text):
    """Sanitize text for PDF core fonts (Helvetica) which only support Latin-1."""
    if text is None: return ""
    # Map common problematic Unicode characters to ASCII equivalents
    replacements = {
        "\u2013": "-", "\u2014": "--", "\u2022": "*",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00b0": " deg", "\u00ae": "(R)",
        "\u00a9": "(C)", "\u2122": "(TM)", "\u00d7": "x",
        "\u2260": "!=", "\u2264": "<=", "\u2265": ">=",
        "\u00e9": "e", "\u00e8": "e", "\u00ea": "e",
        "\u00e0": "a", "\u00e2": "a", "\u00f4": "o",
        # Processor name special chars
        "\u00fc": "u", "\u00dc": "U", "\u00f6": "o", "\u00d6": "O",
    }
    s = str(text)
    for k, v in replacements.items():
        s = s.replace(k, v)
    # Aggressive fallback: replace anything outside printable Latin-1 range with '?'
    cleaned = []
    for ch in s:
        cp = ord(ch)
        if cp < 256:
            cleaned.append(ch)
        else:
            cleaned.append('?')
    return ''.join(cleaned)



# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def pdf_clean(text):
    """Sanitize text for PDF core fonts (Helvetica) which only support Latin-1."""
    if text is None: return ""
    replacements = {
        "\u2013": "-", "\u2014": "--", "\u2022": "*",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00b0": " deg", "\u00ae": "(R)",
        "\u00a9": "(C)", "\u2122": "(TM)", "\u00d7": "x",
        "\u2260": "!=", "\u2264": "<=", "\u2265": ">=",
        "\u00e9": "e", "\u00e8": "e", "\u00ea": "e",
        "\u00e0": "a", "\u00e2": "a", "\u00f4": "o",
        "\u00fc": "u", "\u00dc": "U", "\u00f6": "o", "\u00d6": "O",
    }
    s = str(text)
    for k, v in replacements.items():
        s = s.replace(k, v)
    cleaned = []
    for ch in s:
        cp = ord(ch)
        if cp < 256:
            cleaned.append(ch)
        else:
            cleaned.append('?')
    return ''.join(cleaned)


class SysMonPDF(FPDF):
    def __init__(self, metrics, scan):
        super().__init__()
        self.metrics = metrics
        self.scan = scan or {}
        self.page_num = 0
        self.report_id = str(uuid.uuid4()).upper()[:12]
        
        # ── Dark Professional Palette (Google Dark) ──────────────
        self.C_BG       = (32, 33, 36)    # #202124
        self.C_CARD     = (41, 42, 45)    # #292a2d
        self.C_CARD2    = (60, 64, 67)    # #3c4043
        self.C_BORDER   = (95, 99, 104)   # #5f6368
        self.C_ACCENT   = (138, 180, 248) # #8ab4f8
        self.C_ACCENT2  = (215, 174, 251) # #d7aefb
        self.C_TEXT     = (232, 234, 237) # #e8eaed
        self.C_MUTED    = (154, 160, 166) # #9aa0a6
        self.C_STRIPE   = (41, 42, 45)    # #292a2d
        self.C_WHITE    = (255, 255, 255)
        self.C_GREEN    = (129, 201, 149) # #81c995
        self.C_AMBER    = (253, 214, 99)  # #fdd663
        self.C_RED      = (242, 139, 130) # #f28b82
        self.C_INDIGO   = (179, 157, 219) # #b39ddb

    def header(self):
        self.set_fill_color(*self.C_BG)
        self.rect(0, 0, 210, 297, 'F')
        
        if self.page_no() == 1:
            return
            
        self.set_fill_color(*self.C_CARD)
        self.rect(0, 0, 210, 15, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(0, 15, 210, 1.2, 'F')
        
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*self.C_MUTED)
        self.set_y(4)
        self.cell(0, 4, pdf_clean("SYSMON PRO | INFRASTRUCTURE AUDIT REPORT"), align="L", new_x="LMARGIN", new_y="NEXT")
        
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*self.C_ACCENT)
        self.set_xy(15, 9)
        hostname = self.metrics.get('system', {}).get('hostname', 'Unknown')
        self.cell(0, 4, pdf_clean(f"CONFIDENTIAL — {hostname}"), align="L")
        
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*self.C_MUTED)
        self.set_xy(10, 6)
        self.cell(190, 4, pdf_clean(f"PAGE {self.page_no()}"), align="R")
        self.ln(10)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-18)
        self.set_fill_color(*self.C_CARD)
        self.rect(0, self.get_y() - 1, 210, 19, 'F')
        self.set_fill_color(*self.C_BORDER)
        self.rect(0, self.get_y() - 1, 210, 0.8, 'F')
        
        self.set_font("Helvetica", "I", 6.5)
        self.set_text_color(*self.C_MUTED)
        ts = self.metrics.get('timestamp', '')[:19].replace('T', ' ')
        hostname = self.metrics.get('system', {}).get('hostname', 'Unknown')
        
        self.set_y(-15)
        self.cell(0, 5, pdf_clean(f"CONFIDENTIAL — {hostname} — Generated {ts} — SysMon Pro v2.0"), align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 5, pdf_clean("For authorized personnel only. Always verify critical findings with dedicated security tooling."), align="C")

    # ── Helpers ───────────────────────────────────
    def section_header(self, title, top_pad=6, center=True):
        if self.get_y() + 55 > self.page_break_trigger:
            self.add_page()
        self.ln(top_pad)
        y = self.get_y()
        self.set_fill_color(*self.C_CARD)
        self.rect(self.l_margin, y, self.epw, 10, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(self.l_margin, y, 2.5, 10, 'F')
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_ACCENT)
        align = "C" if center else "L"
        # Offset X if left aligned to avoid colored bar
        if not center:
            self.set_x(self.l_margin + 5)
        text = pdf_clean(title.upper())
        self.cell(0, 10, text, align=align, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def kv_row(self, key, value, shade=False, key_w=65):
        bg = self.C_STRIPE if shade else self.C_CARD
        self.set_fill_color(*bg)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*self.C_MUTED)
        self.cell(key_w, 7, pdf_clean(f"  {key}"), fill=True)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*self.C_TEXT)
        self.cell(0, 7, pdf_clean(str(value)), fill=True, new_x="LMARGIN", new_y="NEXT")

    def draw_inline_bar(self, label, percent, color=None):
        if color is None:
            color = self.C_GREEN if percent <= 60 else (self.C_AMBER if percent <= 85 else self.C_RED)
        label_w = 34
        bar_w   = 112
        row_h   = 9
        y = self.get_y()
        self.set_fill_color(*self.C_CARD)
        self.rect(15, y, 180, row_h, 'F')
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*self.C_MUTED)
        self.set_xy(15, y + 1)
        self.cell(label_w, 7, pdf_clean(label), align="C")
        bx = 15 + label_w + 4
        by = y + 3.5
        self.set_fill_color(*self.C_BORDER)
        self.rect(bx, by, bar_w, 2.5, 'F')
        fill_w = max(2.5, int(bar_w * min(percent, 100) / 100))
        self.set_fill_color(*color)
        self.rect(bx, by, fill_w, 2.5, 'F')
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_xy(bx + bar_w + 4, y + 1)
        self.cell(22, 7, pdf_clean(f"{percent:.1f}%"), align="C")
        self.set_y(y + row_h + 2)

    def two_col(self, left_fn, right_fn, left_w=88, gap=8):
        start_y = self.get_y()
        self.set_left_margin(15)
        self.set_right_margin(15 + (180 - left_w) + gap)
        left_fn()
        left_end_y = self.get_y()
        right_x = 15 + left_w + gap
        self.set_xy(right_x, start_y)
        self.set_left_margin(right_x)
        self.set_right_margin(15)
        right_fn()
        right_end_y = self.get_y()
        self.set_left_margin(15)
        self.set_right_margin(15)
        self.set_y(max(left_end_y, right_end_y) + 2)

    # ── Page Builders ─────────────────────────────
    def build_cover(self):
        W = 210
        self.add_page()
        
        # Classification banner
        self.set_fill_color(*self.C_RED)
        self.rect(0, 0, W, 12, 'F')
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_BG)
        self.set_y(3)
        self.cell(0, 6, "CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY", align="C")
        
        # Logo / Brand
        cy = 50
        self.set_fill_color(*self.C_CARD2)
        self.set_draw_color(*self.C_ACCENT)
        self.set_line_width(0.8)
        self.rect(15, cy, 24, 24, 'DF')
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*self.C_WHITE)
        self.set_xy(15, cy)
        self.cell(24, 24, "SP", align="C")
        
        self.set_xy(45, cy + 2)
        self.set_font("Helvetica", "B", 24)
        self.set_text_color(*self.C_WHITE)
        self.cell(0, 10, "SYSMON PRO", new_x="LMARGIN", new_y="NEXT")
        self.set_xy(45, cy + 12)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*self.C_ACCENT)
        self.cell(0, 10, "INFRASTRUCTURE SECURITY & PERFORMANCE AUDIT")
        
        self.set_y(100)
        self.set_fill_color(*self.C_CARD)
        self.rect(15, self.get_y(), 180, 50, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(15, self.get_y(), 3, 50, 'F')
        
        self.set_y(105)
        self.set_x(25)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_MUTED)
        self.cell(40, 7, "Report ID:")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*self.C_WHITE)
        self.cell(0, 7, self.report_id, new_x="LMARGIN", new_y="NEXT")
        
        self.set_x(25)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_MUTED)
        self.cell(40, 7, "Target Host:")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*self.C_ACCENT2)
        self.cell(0, 7, pdf_clean(self.metrics.get('system', {}).get('hostname', 'Unknown')), new_x="LMARGIN", new_y="NEXT")
        
        self.set_x(25)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_MUTED)
        self.cell(40, 7, "Generated:")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*self.C_WHITE)
        ts = self.metrics.get('timestamp', '')[:19].replace('T', ' ')
        self.cell(0, 7, ts, new_x="LMARGIN", new_y="NEXT")
        
        self.set_x(25)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_MUTED)
        self.cell(40, 7, "Classification:")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*self.C_RED)
        self.cell(0, 7, "CONFIDENTIAL", new_x="LMARGIN", new_y="NEXT")

        # Security Gauge or Overall Status
        self.set_y(170)
        if self.scan:
            score = self.scan.get('score', 0)
            status = self.scan.get('overall_status', 'UNKNOWN')
            color = self.C_GREEN if score >= 80 else (self.C_AMBER if score >= 55 else self.C_RED)
            
            self.set_fill_color(*self.C_CARD)
            self.rect(15, self.get_y(), 180, 60, 'F')
            
            self.set_y(180)
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(*self.C_WHITE)
            self.cell(0, 8, "OVERALL SECURITY POSTURE", align="C", new_x="LMARGIN", new_y="NEXT")
            
            self.set_font("Helvetica", "B", 32)
            self.set_text_color(*color)
            self.cell(0, 16, f"{status}", align="C", new_x="LMARGIN", new_y="NEXT")
            
            self.set_font("Helvetica", "B", 12)
            self.set_text_color(*self.C_MUTED)
            self.cell(0, 10, f"Score: {score}/100", align="C", new_x="LMARGIN", new_y="NEXT")
            
            # Sub-metrics
            s = self.scan.get('summary', {})
            px = 45
            self.set_y(245)
            w_box = 30
            for lbl, val, col in [("PASS", s.get('pass',0), self.C_GREEN), 
                                  ("WARN", s.get('warn',0), self.C_AMBER), 
                                  ("FAIL", s.get('fail',0), self.C_RED),
                                  ("INFO", s.get('info',0), self.C_INDIGO)]:
                self.set_fill_color(*self.C_CARD)
                self.rect(px, 240, w_box, 20, 'F')
                self.set_fill_color(*col)
                self.rect(px, 240, w_box, 2, 'F')
                
                self.set_xy(px, 244)
                self.set_font("Helvetica", "B", 12)
                self.set_text_color(*col)
                self.cell(w_box, 8, str(val), align="C", new_x="LMARGIN", new_y="NEXT")
                self.set_xy(px, 252)
                self.set_font("Helvetica", "B", 7)
                self.set_text_color(*self.C_MUTED)
                self.cell(w_box, 5, lbl, align="C")
                px += w_box + 10
                
    def build_toc(self):
        self.add_page()
        self.section_header("Table of Contents", top_pad=10, center=False)
        self.ln(5)
        
        sections = [
            ("1. Executive Summary", 3),
            ("2. System & Hardware Inventory", 4),
            ("3. Performance Dashboard", 5),
            ("4. Security Audit Results", 6),
            ("5. Network Port Audit", 7),
            ("6. Recommendations & Action Items", 8)
        ]
        
        self.set_fill_color(*self.C_CARD)
        for title, pagenum in sections:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*self.C_TEXT)
            
            # Simple dotted line effect
            w_title = self.get_string_width(title) + 5
            self.cell(w_title, 10, title)
            self.set_text_color(*self.C_BORDER)
            self.cell(170 - w_title, 10, "." * int((170 - w_title)/1.5))
            
            self.set_text_color(*self.C_ACCENT)
            self.cell(10, 10, str(pagenum), align="R", new_x="LMARGIN", new_y="NEXT")
            self.ln(2)

    def build_exec_summary(self):
        self.add_page()
        self.section_header("1. Executive Summary", top_pad=4, center=False)
        
        status = self.scan.get('overall_status', 'UNKNOWN')
        score = self.scan.get('score', 0)
        status_text = {
            "SECURE":   "The host is in an excellent security posture. All critical controls are enabled and performance is optimal. No immediate actions are required.",
            "FAIR":     "The host maintains a fair security posture but has several warnings. It is recommended to review the identified risks, particularly regarding open network ports or disabled minor security features.",
            "AT RISK":  "The host is at risk. Multiple security controls are failing or absent. Prompt remediation is strongly advised to prevent potential exploitation.",
            "CRITICAL": "The host is in a CRITICAL state. Immediate remediation is required to address failing security checks and severe vulnerabilities.",
        }.get(status, "System analysis overview.")
        
        score_color = self.C_GREEN if score >= 80 else (self.C_AMBER if score >= 55 else self.C_RED)
        
        self.set_fill_color(*self.C_CARD2)
        self.rect(15, self.get_y(), 180, 24, 'F')
        self.set_fill_color(*score_color)
        self.rect(15, self.get_y(), 3, 24, 'F')
        
        self.set_xy(22, self.get_y() + 3)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*score_color)
        self.cell(0, 6, pdf_clean(f"Assessment: {status} ({score}/100)"), new_x="LMARGIN", new_y="NEXT")
        
        self.set_xy(22, self.get_y())
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*self.C_TEXT)
        self.multi_cell(165, 5, pdf_clean(status_text))
        
        self.ln(6)
        self.section_header("Key Performance Indicators", top_pad=4, center=False)
        
        kpi_items = [
            ("CPU Load",   f"{self.metrics['cpu']['usage_percent']:.1f}%",   self.C_ACCENT),
            ("RAM Usage",   f"{self.metrics['memory']['percent']:.1f}%",       self.C_ACCENT2),
            ("Swap Usage",  f"{self.metrics['memory']['swap_percent']:.1f}%",  self.C_GREEN),
            ("Logical Cores", str(self.metrics['cpu']['thread_count']),            self.C_MUTED),
            ("Disk Volumes", str(len(self.metrics['disks'])),                   self.C_AMBER),
            ("Active Procs", str(self.metrics['processes']),                    self.C_MUTED),
        ]
        
        stat_w = 56
        stat_h = 22
        gap = 6
        sx = 15
        py = self.get_y()
        
        for i, (lbl, val, col) in enumerate(kpi_items):
            row = i // 3
            col_idx = i % 3
            px = sx + col_idx * (stat_w + gap)
            cy = py + row * (stat_h + gap)
            
            self.set_fill_color(*self.C_CARD)
            self.set_draw_color(*self.C_BORDER)
            self.set_line_width(0.2)
            self.rect(px, cy, stat_w, stat_h, 'DF')
            self.set_fill_color(*col)
            self.rect(px, cy, stat_w, 2.5, 'F')
            
            self.set_font("Helvetica", "B", 12)
            self.set_text_color(*self.C_WHITE)
            self.set_xy(px, cy + 5)
            self.cell(stat_w, 8, pdf_clean(val), align="C")
            
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*self.C_MUTED)
            self.set_xy(px, cy + 14)
            self.cell(stat_w, 5, pdf_clean(lbl.upper()), align="C")
            
        self.set_y(py + (stat_h + gap) * 2 + 4)
        
        # Top 3 Findings summary
        findings = self.scan.get('findings', [])
        attention_items = [f for f in findings if f.get('status') in ['FAIL', 'WARN']]
        
        self.section_header("Key Issues Identified", top_pad=4, center=False)
        if not attention_items:
            self.set_fill_color(*self.C_CARD)
            self.rect(15, self.get_y(), 180, 15, 'F')
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(*self.C_GREEN)
            self.set_xy(15, self.get_y() + 5)
            self.cell(180, 5, "No critical or warning-level issues detected.", align="C")
        else:
            for i, f in enumerate(attention_items[:4]): # Show up to 4
                bg = self.C_STRIPE if i % 2 == 0 else self.C_CARD
                self.set_fill_color(*bg)
                self.rect(15, self.get_y(), 180, 8, 'F')
                sc = self.C_RED if f['status'] == 'FAIL' else self.C_AMBER
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(*sc)
                self.set_x(17)
                self.cell(15, 8, f['status'])
                self.set_text_color(*self.C_WHITE)
                self.cell(50, 8, pdf_clean(f['name']))
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*self.C_MUTED)
                det = f['details'][:70] + ("..." if len(f['details'])>70 else "")
                self.cell(100, 8, pdf_clean(det), new_x="LMARGIN", new_y="NEXT")

    def build_system_inventory(self):
        self.add_page()
        self.section_header("2. System & Hardware Inventory", top_pad=4, center=False)
        
        sys_rows = [
            ("OS",          self.metrics['system']['os']),
            ("Version",     (self.metrics['system']['version'] or 'N/A')[:32]),
            ("Hostname",    self.metrics['system']['hostname']),
            ("Architecture",self.metrics['system'].get('machine', 'N/A')),
            ("Uptime",      self.metrics['system']['uptime']),
            ("Last Boot",   self.metrics['system']['boot_time']),
            ("Processes",   str(self.metrics['processes'])),
            ("Processor",   (self.metrics['system']['processor'] or 'N/A')[:38]),
        ]
        mem = self.metrics['memory']
        mem_rows = [
            ("Total RAM",   f"{mem['total_gb']} GB"),
            ("Used RAM",    f"{mem['used_gb']} GB"),
            ("Available",   f"{mem['available_gb']} GB"),
            ("RAM Usage",   f"{mem['percent']:.1f}%"),
            ("Swap Total",  f"{mem['swap_total_gb']} GB"),
            ("Swap Used",   f"{mem['swap_used_gb']} GB"),
            ("Swap Usage",  f"{mem['swap_percent']:.1f}%"),
        ]

        def left_block():
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*self.C_ACCENT)
            self.cell(0, 8, "SYSTEM DETAILS", new_x="LMARGIN", new_y="NEXT")
            for i, (k, v) in enumerate(sys_rows):
                self.kv_row(k, v, shade=(i % 2 == 0), key_w=30)

        def right_block():
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*self.C_ACCENT)
            self.cell(0, 8, "MEMORY SNAPSHOT", new_x="LMARGIN", new_y="NEXT")
            for i, (k, v) in enumerate(mem_rows):
                self.kv_row(k, v, shade=(i % 2 == 0), key_w=30)

        self.two_col(left_block, right_block, left_w=88, gap=6)
        
        self.ln(6)
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*self.C_ACCENT)
        self.cell(0, 8, "RESOURCE UTILIZATION PROGRESS", new_x="LMARGIN", new_y="NEXT")
        self.draw_inline_bar("CPU", self.metrics['cpu']['usage_percent'])
        self.draw_inline_bar("RAM", mem['percent'])
        self.draw_inline_bar("Swap", mem['swap_percent'])
        
        self.ln(6)
        hw_rows = [
            ("Physical Cores", str(self.metrics['cpu']['core_count'])),
            ("Logical Threads", str(self.metrics['cpu']['thread_count'])),
            ("CPU Freq", f"{self.metrics['cpu']['frequency_mhz'] or 'N/A'} MHz"),
            ("Max Freq", f"{self.metrics['cpu']['freq_max_mhz'] or 'N/A'} MHz"),
        ]
        net = self.metrics['network']
        net_rows = [
            ("Bytes Sent",    f"{net['bytes_sent_mb']:.2f} MB"),
            ("Bytes Recv",    f"{net['bytes_recv_mb']:.2f} MB"),
            ("Packets Sent",  str(net['packets_sent'])),
            ("Packets Recv",  str(net['packets_recv'])),
        ]
        def hw_block():
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*self.C_ACCENT)
            self.cell(0, 8, "HARDWARE OVERVIEW", new_x="LMARGIN", new_y="NEXT")
            for i, (k, v) in enumerate(hw_rows):
                self.kv_row(k, v, shade=(i % 2 == 0), key_w=30)

        def net_block():
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*self.C_ACCENT)
            self.cell(0, 8, "NETWORK OVERVIEW", new_x="LMARGIN", new_y="NEXT")
            for i, (k, v) in enumerate(net_rows):
                self.kv_row(k, v, shade=(i % 2 == 0), key_w=30)
            if self.metrics.get('battery'):
                bat = self.metrics['battery']
                self.ln(2)
                self.kv_row("Battery Level", f"{bat['percent']:.0f}%", shade=True, key_w=30)
                self.kv_row("Power Status", "Charging" if bat['charging'] else "On Battery", shade=False, key_w=30)

        self.two_col(hw_block, net_block, left_w=88, gap=6)

    def build_performance_charts(self, chart_path):
        self.add_page()
        self.section_header("3. Performance Dashboard", top_pad=4, center=False)
        self.image(chart_path, x=10, y=self.get_y(), w=190)

    def build_security_audit(self):
        self.add_page()
        self.section_header("4. Security Audit Results", top_pad=4, center=False)
        
        # Disk Volumes
        if self.metrics.get('disks'):
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*self.C_ACCENT)
            self.cell(0, 8, "DISK VOLUMES", new_x="LMARGIN", new_y="NEXT")
            
            cols = [("Device", 40), ("Mount", 40), ("FS", 18), ("Total", 23), ("Used", 23), ("Usage", 30)]
            self.set_fill_color(*self.C_CARD2)
            self.set_font("Helvetica", "B", 7.5)
            self.set_text_color(*self.C_WHITE)
            for lbl, w in cols:
                self.cell(w, 8, pdf_clean(f"  {lbl}"), fill=True)
            self.ln()
            self.set_font("Helvetica", "", 7.5)
            for i, disk in enumerate(self.metrics['disks'][:8]):
                bg = self.C_STRIPE if i % 2 == 0 else self.C_CARD
                self.set_fill_color(*bg)
                self.set_text_color(*self.C_TEXT)
                row = [
                    (disk['device'][:18], 40),
                    (disk['mountpoint'][:18], 40),
                    (disk['fstype'][:8], 18),
                    (f"{disk['total_gb']:.1f} GB", 23),
                    (f"{disk['used_gb']:.1f} GB", 23),
                ]
                for txt, w in row:
                    self.cell(w, 7, pdf_clean(f"  {txt}"), fill=True)
                pct_col = self.C_GREEN if disk['percent'] <= 60 else (self.C_AMBER if disk['percent'] <= 85 else self.C_RED)
                self.set_font("Helvetica", "B", 7.5)
                self.set_text_color(*pct_col)
                self.cell(30, 7, pdf_clean(f"  {disk['percent']:.0f}%"), fill=True, new_x="LMARGIN", new_y="NEXT")
            self.ln(6)
            
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*self.C_ACCENT)
        self.cell(0, 8, "DETAILED AUDIT FINDINGS", new_x="LMARGIN", new_y="NEXT")
        
        cols = [("Category", 30), ("Check", 50), ("Status", 18), ("Details", 82)]
        self.set_fill_color(*self.C_CARD2)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*self.C_WHITE)
        for lbl, w in cols:
            self.cell(w, 8, pdf_clean(f"  {lbl.upper()}"), fill=True)
        self.ln()
        
        status_color_map = {
            "PASS": self.C_GREEN, "WARN": self.C_AMBER,
            "FAIL": self.C_RED,   "INFO": self.C_INDIGO
        }
        
        findings = self.scan.get('findings', [])
        # Ignore port findings here to put them in the dedicated page
        general_findings = [f for f in findings if f['name'] != 'Open Listening Ports']
        
        for i, f in enumerate(general_findings):
            bg = self.C_STRIPE if i % 2 == 0 else self.C_CARD
            self.set_fill_color(*bg)
            sc = status_color_map.get(f['status'], self.C_MUTED)
            
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*self.C_TEXT)
            self.cell(30, 7, pdf_clean(f"  {f['category']}"), fill=True)
            self.cell(50, 7, pdf_clean(f"  {f['name']}"), fill=True)
            
            # Badge for status
            # self.set_fill_color(*sc)
            # self.set_text_color(*self.C_BG)
            # self.cell(16, 5, pdf_clean(f"  {f['status']}"), fill=True) 
            # text color
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*sc)
            self.cell(18, 7, pdf_clean(f"  {f['status']}"), fill=True)
            
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*self.C_TEXT)
            details = f['details'][:72] + ("..." if len(f['details']) > 72 else "")
            self.cell(82, 7, pdf_clean(f"  {details}"), fill=True, new_x="LMARGIN", new_y="NEXT")

    def build_network_ports(self):
        self.add_page()
        self.section_header("5. Network Port Audit", top_pad=4, center=False)
        
        port_finding = next((f for f in self.scan.get('findings', []) if f['name'] == 'Open Listening Ports'), None)
        
        if not port_finding:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(*self.C_MUTED)
            self.cell(0, 10, "Network port audit data is not available for this host.", new_x="LMARGIN", new_y="NEXT")
            return
            
        import re
        details = port_finding.get('details', '')
        
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*self.C_TEXT)
        self.multi_cell(0, 6, pdf_clean("The following TCP/UDP ports were found listening on the system interfaces. Ports marked as RISKY are commonly targeted by ransomware and exploits."))
        self.ln(4)
        
        # Extract ports
        ports_match = re.search(r"Ports:\s*([0-9,\s]+)", details)
        risky_match = re.search(r"Risky:\s*([^■]+)", details)
        
        risky_str = risky_match.group(1).strip() if risky_match else ""
        ports_str = ports_match.group(1).strip() if ports_match else ""
        
        risky_ports_set = set()
        for r in risky_str.split(','):
            rm = re.search(r"(\d+)", r)
            if rm:
                risky_ports_set.add(rm.group(1))
                
        all_ports = []
        if ports_str:
            for p in ports_str.split(','):
                p = p.strip()
                if p:
                    all_ports.append(p)
                    
        # Render Table
        cols = [("Port", 30), ("Status", 30), ("Risk Level", 40), ("Notes", 80)]
        self.set_fill_color(*self.C_CARD2)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*self.C_WHITE)
        for lbl, w in cols:
            self.cell(w, 8, pdf_clean(f"  {lbl.upper()}"), fill=True)
        self.ln()
        
        for i, port in enumerate(sorted(all_ports, key=lambda x: int(x))):
            bg = self.C_STRIPE if i % 2 == 0 else self.C_CARD
            self.set_fill_color(*bg)
            
            is_risky = port in risky_ports_set
            
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*self.C_WHITE)
            self.cell(30, 7, pdf_clean(f"  {port}"), fill=True)
            
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*self.C_TEXT)
            self.cell(30, 7, pdf_clean("  LISTENING"), fill=True)
            
            if is_risky:
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(*self.C_RED)
                self.cell(40, 7, pdf_clean("  HIGH RISK"), fill=True)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*self.C_TEXT)
                # Map some common ports
                note = "SMB / RPC / NetBIOS" if port in ['135','139','445'] else "Vulnerable port"
                self.cell(80, 7, pdf_clean(f"  {note}"), fill=True, new_x="LMARGIN", new_y="NEXT")
            else:
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*self.C_GREEN)
                self.cell(40, 7, pdf_clean("  STANDARD"), fill=True)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*self.C_TEXT)
                self.cell(80, 7, pdf_clean("  Standard application port"), fill=True, new_x="LMARGIN", new_y="NEXT")
        
        self.ln(10)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_AMBER)
        self.cell(0, 6, pdf_clean(f"Recommendation: {port_finding.get('recommendation', 'Review and close unnecessary ports.')}"), new_x="LMARGIN", new_y="NEXT")

    def build_recommendations(self):
        self.add_page()
        self.section_header("6. Recommendations & Action Items", top_pad=4, center=False)
        
        recs = []
        for f in self.scan.get('findings', []):
            if f.get('recommendation'):
                # Assign priority
                priority = "CRITICAL" if f['status'] == "FAIL" else ("HIGH" if f['name'] == 'Open Listening Ports' else "MEDIUM")
                recs.append((priority, f['name'], f['recommendation']))
                
        # Sort by priority
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recs.sort(key=lambda x: order.get(x[0], 99))
        
        if not recs:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(*self.C_GREEN)
            self.cell(0, 10, "No actionable recommendations. System is properly configured.", new_x="LMARGIN", new_y="NEXT")
            return
            
        cols = [("Priority", 25), ("Check Name", 45), ("Action Required", 85), ("Owner", 25)]
        self.set_fill_color(*self.C_CARD2)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*self.C_WHITE)
        for lbl, w in cols:
            self.cell(w, 9, pdf_clean(f"  {lbl.upper()}"), fill=True)
        self.ln()
        
        for i, (pri, name, rec) in enumerate(recs):
            bg = self.C_STRIPE if i % 2 == 0 else self.C_CARD
            self.set_fill_color(*bg)
            
            pri_col = self.C_RED if pri in ["CRITICAL", "HIGH"] else self.C_AMBER
            
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*pri_col)
            self.cell(25, 10, pdf_clean(f"  {pri}"), fill=True)
            
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*self.C_WHITE)
            self.cell(45, 10, pdf_clean(f"  {name[:28]}"), fill=True)
            
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*self.C_TEXT)
            disp = rec[:95] + ("..." if len(rec)>95 else "")
            self.cell(85, 10, pdf_clean(f"  {disp}"), fill=True)
            
            # Blank box for manual writing or placeholder
            self.cell(25, 10, "", fill=True, new_x="LMARGIN", new_y="NEXT")

def render_report_charts(metrics, scan=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    
    P = {
        'bg':    '#202124',
        'card':  '#292a2d',
        'grid':  '#5f6368',
        'text':  '#e8eaed',
        'muted': '#9aa0a6',
        'b1':    '#8ab4f8',
        'b2':    '#d7aefb',
        'green': '#81c995',
        'amber': '#fdd663',
        'red':   '#f28b82',
    }
    def bar_color(pct):
        return P['green'] if pct <= 60 else (P['amber'] if pct <= 85 else P['red'])

    fig = plt.figure(figsize=(16, 16.5), facecolor=P['bg'], constrained_layout=True)
    spec = fig.add_gridspec(2, 2, hspace=0.25, wspace=0.25)
    ax0 = fig.add_subplot(spec[0, 0])
    ax1 = fig.add_subplot(spec[0, 1])
    ax2 = fig.add_subplot(spec[1, 0])
    ax3 = fig.add_subplot(spec[1, 1])

    for ax in (ax0, ax1, ax2, ax3):
        ax.set_facecolor(P['card'])
        for spine in ax.spines.values():
            spine.set_edgecolor(P['grid'])
        ax.tick_params(colors=P['muted'], labelcolor=P['muted'], labelsize=10)
        ax.xaxis.label.set_color(P['muted'])
        ax.yaxis.label.set_color(P['muted'])

    labels0 = ['CPU', 'RAM', 'Swap']
    vals0   = [metrics['cpu']['usage_percent'],
               metrics['memory']['percent'],
               metrics['memory']['swap_percent']]
    colors0 = [bar_color(v) for v in vals0]
    bars0   = ax0.bar(labels0, vals0, color=colors0, width=0.55, zorder=3)
    ax0.set_ylim(0, 110)
    ax0.set_title('Resource Utilization', color=P['text'], fontsize=13.5, pad=10, fontweight='bold')
    ax0.yaxis.grid(True, color=P['grid'], linewidth=0.85, zorder=0)
    ax0.set_axisbelow(True)
    for bar, v in zip(bars0, vals0):
        ax0.text(bar.get_x() + bar.get_width() / 2, v + 3,
                 f'{v:.1f}%', ha='center', va='bottom',
                 color=P['text'], fontsize=11, fontweight='bold')
    ax0.set_ylabel('%', color=P['muted'], fontsize=10.5)

    disks = metrics.get('disks', [])[:6]
    if disks:
        dlabels = [d['device'].replace('\\', '').replace('/', '') for d in disks]
        dvals   = [d['percent'] for d in disks]
        dcolors = [bar_color(v) for v in dvals]
        barsh = ax1.barh(dlabels, dvals, color=dcolors, height=0.5, zorder=3)
        ax1.set_xlim(0, 115)
        ax1.invert_yaxis()
        ax1.xaxis.grid(True, color=P['grid'], linewidth=0.85, zorder=0)
        ax1.set_axisbelow(True)
        for bar in barsh:
            ax1.text(bar.get_width() + 2, bar.get_y() + bar.get_height() / 2,
                     f'{bar.get_width():.0f}%', va='center',
                     color=P['text'], fontsize=10, fontweight='bold')
    else:
        ax1.text(0.5, 0.5, 'No disk data available', color=P['muted'], ha='center', va='center')
    ax1.set_title('Disk Utilization', color=P['text'], fontsize=13.5, pad=10, fontweight='bold')
    ax1.set_xlabel('%', color=P['muted'], fontsize=10.5)

    cores = metrics['cpu'].get('per_core', [])
    if cores:
        cx = [f'C{i}' for i in range(len(cores))]
        ccolors = [bar_color(v) for v in cores]
        ax2.bar(cx, cores, color=ccolors, width=0.7, zorder=3)
        ax2.set_ylim(0, 110)
        ax2.yaxis.grid(True, color=P['grid'], linewidth=0.85, zorder=0)
        ax2.set_axisbelow(True)
    else:
        ax2.text(0.5, 0.5, 'No per-core data', color=P['muted'], ha='center', va='center')
    ax2.set_title('Per-Core CPU Usage', color=P['text'], fontsize=13.5, pad=10, fontweight='bold')
    ax2.set_ylabel('%', color=P['muted'], fontsize=10.5)
    ax2.tick_params(axis='x', labelsize=8.5)

    net = metrics['network']
    net_labels  = ['Sent', 'Received']
    net_vals    = [net['bytes_sent_mb'], net['bytes_recv_mb']]
    net_colors  = [P['b1'], P['b2']]
    barsn = ax3.bar(net_labels, net_vals, color=net_colors, width=0.5, zorder=3)
    ax3.yaxis.grid(True, color=P['grid'], linewidth=0.85, zorder=0)
    ax3.set_axisbelow(True)
    for bar, v in zip(barsn, net_vals):
        ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                 f'{v:.1f} MB', ha='center', va='bottom',
                 color=P['text'], fontsize=10, fontweight='bold')
    ax3.set_title('Network I/O', color=P['text'], fontsize=13.5, pad=10, fontweight='bold')
    ax3.set_ylabel('MB', color=P['muted'], fontsize=10.5)

    if scan:
        score = scan['score']
        sc = P['green'] if score >= 80 else (P['amber'] if score >= 55 else P['red'])
        ax3.annotate(f"Security: {score}/100", xy=(0.95, 0.90),
                     xycoords='axes fraction', ha='right', va='top',
                     color=sc, fontsize=11.5, fontweight='bold',
                     bbox=dict(facecolor=P['card'], edgecolor=sc, linewidth=0.9, pad=4))

    tmp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    fig.savefig(tmp.name, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    tmp.close()
    return tmp.name

def build_pdf_report(metrics, scan):
    pdf = SysMonPDF(metrics, scan)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)
    
    pdf.build_cover()
    pdf.build_toc()
    pdf.build_exec_summary()
    pdf.build_system_inventory()
    
    chart_path = render_report_charts(metrics, scan)
    pdf.build_performance_charts(chart_path)
    os.remove(chart_path)
    
    pdf.build_security_audit()
    pdf.build_network_ports()
    pdf.build_recommendations()
    
    return bytes(pdf.output())


# ─────────────────────────────────────────────
# CSV REPORT - NEAT FORMAT
# ─────────────────────────────────────────────

def build_csv_report(metrics, scan):
    output = io.StringIO()
    writer = csv.writer(output)
    ts = metrics['timestamp'][:19].replace('T', ' ')

    def section(title):
        writer.writerow([])
        writer.writerow([f"### {title.upper()} ###"])

    def header_row(*cols):
        writer.writerow(list(cols))

    def kv(key, value):
        writer.writerow([key, value])

    # ── Report Metadata ─────────────────────────────
    writer.writerow(["=== SYSMON PRO - SYSTEM ANALYSIS REPORT ==="])
    writer.writerow([f"Generated At:  {ts}"])
    writer.writerow([f"Hostname:      {metrics['system']['hostname']}"])
    writer.writerow([f"Operating System: {metrics['system']['os']}"])
    writer.writerow([f"Security Score: {scan['score']}/100  ({scan['overall_status']})"])

    # ── System Information ──────────────────────────
    section("System Information")
    header_row("Property", "Value")
    kv("Operating System",  metrics['system']['os'])
    kv("OS Version",        metrics['system']['version'])
    kv("Hostname",          metrics['system']['hostname'])
    kv("Architecture",      metrics['system']['machine'])
    kv("Processor",         metrics['system']['processor'])
    kv("System Uptime",     metrics['system']['uptime'])
    kv("Last Boot Time",    metrics['system']['boot_time'])
    kv("Running Processes", metrics['processes'])

    # ── CPU ─────────────────────────────────────────
    section("CPU - Processor")
    header_row("Property", "Value")
    cpu = metrics['cpu']
    kv("Overall Usage (%)", cpu['usage_percent'])
    kv("Physical Core Count",   cpu['core_count'])
    kv("Logical Thread Count",  cpu['thread_count'])
    kv("Current Frequency (MHz)", cpu['frequency_mhz'] or "N/A")
    kv("Max Frequency (MHz)",   cpu['freq_max_mhz'] or "N/A")
    writer.writerow([])
    header_row("Core", "Usage (%)")
    for i, pct in enumerate(cpu['per_core']):
        writer.writerow([f"Core {i}", pct])

    # ── Memory ──────────────────────────────────────
    section("Memory - RAM & Swap")
    header_row("Property", "Value")
    mem = metrics['memory']
    kv("Total RAM (GB)",     mem['total_gb'])
    kv("Used RAM (GB)",      mem['used_gb'])
    kv("Available RAM (GB)", mem['available_gb'])
    kv("RAM Usage (%)",      mem['percent'])
    kv("Swap Total (GB)",    mem['swap_total_gb'])
    kv("Swap Used (GB)",     mem['swap_used_gb'])
    kv("Swap Usage (%)",     mem['swap_percent'])

    # ── Disks ───────────────────────────────────────
    section("Storage - Disk Volumes")
    header_row("Device", "Mountpoint", "File System", "Total (GB)", "Used (GB)", "Free (GB)", "Used (%)")
    for disk in metrics['disks']:
        writer.writerow([
            disk['device'], disk['mountpoint'], disk['fstype'],
            disk['total_gb'], disk['used_gb'], disk['free_gb'], disk['percent']
        ])

    # ── Network ─────────────────────────────────────
    section("Network - I/O & Interfaces")
    net = metrics['network']
    header_row("Property", "Value")
    kv("Total Sent (MB)",     f"{net['bytes_sent_mb']:.2f}")
    kv("Total Received (MB)", f"{net['bytes_recv_mb']:.2f}")
    kv("Packets Sent",        net['packets_sent'])
    kv("Packets Received",    net['packets_recv'])
    if net['interfaces']:
        writer.writerow([])
        header_row("Interface", "IP Address")
        for iface, ip in net['interfaces'].items():
            writer.writerow([iface, ip])

    # ── Battery ─────────────────────────────────────
    if metrics.get('battery'):
        bat = metrics['battery']
        section("Battery / Power")
        header_row("Property", "Value")
        kv("Battery Level (%)", bat['percent'])
        kv("Power Status",      "Charging" if bat['charging'] else "On Battery")
        if bat.get('time_left_mins') and bat['time_left_mins'] > 0:
            kv("Time Remaining (min)", bat['time_left_mins'])

    # ── Security Scan ────────────────────────────────
    section("Security Scan Results")
    s = scan['summary']
    header_row("Property", "Value")
    kv("Overall Status",    scan['overall_status'])
    kv("Security Score",    f"{scan['score']}/100")
    kv("Scan Timestamp",    scan['timestamp'][:19].replace('T', ' '))
    kv("Checks Passed",     s['pass'])
    kv("Checks Warning",    s['warn'])
    kv("Checks Failed",     s['fail'])
    kv("Informational",     s['info'])
    kv("Total Checks",      s['total'])
    writer.writerow([])
    header_row("Category", "Check Name", "Status", "Details", "Recommendation")
    for f in scan['findings']:
        writer.writerow([
            f['category'], f['name'], f['status'],
            f['details'], f.get('recommendation', '')
        ])

    # ── Recommendations ──────────────────────────────
    recs = [(f['name'], f['recommendation']) for f in scan['findings'] if f.get('recommendation')]
    if recs:
        section("Recommendations")
        header_row("Check Name", "Recommendation")
        for name, rec in recs:
            writer.writerow([name, rec])

    return output.getvalue()


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/api/status")
def status():
    user_id = get_request_user_id()
    return jsonify({
        "status": "running",
        "message": "SysMon backend active",
        "pc_agent_connected": use_pc_agent and pc_agent_metrics is not None,
        "connected_devices": get_device_count(user_id),
        "active_devices": len(get_active_devices(user_id)),
        "user_id": user_id,
    })


@app.route("/api/receive-metrics", methods=["POST"])
def receive_metrics():
    """Endpoint for PC monitoring agent to send metrics."""
    global pc_agent_metrics, use_pc_agent
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        user_id = data.get("user_id") or request.headers.get("X-SysMon-User-Id") or "public"
        
        # Get device info from metrics
        device_id = data.get("device_id", "default")
        device_name = data.get("device_name", "Unknown Device")
        system = data.get("system", {})
        hostname = system.get("hostname", "unknown")
        os_info = system.get("os", "unknown")
        
        # Sanitize Windows 19 (from older cached web agent) to Windows 11
        if "Windows 19" in os_info:
            os_info = os_info.replace("Windows 19", "Windows 11")
            system["os"] = os_info
            if "Windows 19" in device_name:
                device_name = device_name.replace("Windows 19", "Windows 11")
                data["device_name"] = device_name
        
        # Register/update device
        register_device(device_id, device_name, hostname, os_info, user_id=user_id)
        
        # Save metrics to database
        save_metrics(device_id, data)
        
        # Also keep in-memory for backward compatibility
        pc_agent_metrics = data
        use_pc_agent = True
        
        cpu_pct = data.get('cpu', {}).get('usage_percent', 0)
        print(f"LOG: Metrics received from device '{device_name}' ({device_id}) for user '{user_id}' - CPU: {cpu_pct}%")
        
        return jsonify({"status": "received", "device_id": device_id}), 200
    except Exception as e:
        print(f"ERROR: Failed to receive metrics: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/metrics")
def metrics():
    user_id = get_request_user_id()
    device_id = get_request_device_id()

    data, device = resolve_user_metrics(user_id, device_id)
    if not data:
        return jsonify({"error": f"No metrics available for user '{user_id}'"}), 404

    if device_id and not device:
        return jsonify({"error": f"Device {device_id} not found for this user"}), 404

    print(f"LOG: Serving metrics for user {user_id} device {data.get('device_id')}")
    
    # Save a lightweight snapshot to the history buffer
    if "cpu" in data and "memory" in data:
        history_buffer.append({
            "timestamp": data.get("timestamp", datetime.datetime.now().isoformat()),
            "cpu": data["cpu"].get("usage_percent", 0),
            "ram": data["memory"].get("percent", 0),
            "net_sent_mb": data.get("network", {}).get("bytes_sent_mb", 0),
            "net_recv_mb": data.get("network", {}).get("bytes_recv_mb", 0),
            "processes": data.get("processes", 0),
        })
    return jsonify(data)


@app.route("/api/system-metrics")
def system_metrics_live():
    """Return real-time system metrics directly from this machine via psutil.
    No database lookup — always returns fresh data from the host OS."""
    try:
        data = get_system_metrics()
        data["source"] = "backend"
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/security-scan-live')
def security_scan_live():
    '''Run a real-time security scan directly on this machine.
    Combines get_system_metrics() performance data with get_security_scan() findings.'''
    try:
        metrics = get_system_metrics()
        # Get performance findings from metrics
        perf_scan = build_device_health_scan(metrics)
        # Get real security findings from the OS
        sec_scan = get_security_scan()

        # Merge: use security scan as base, prepend performance findings
        # Remove device info from perf (already in sec), keep performance checks
        perf_findings = [f for f in perf_scan['findings'] if f['category'] == 'Performance' or f['category'] == 'Power']

        combined_findings = perf_findings + sec_scan['findings']

        # Recalculate totals
        pass_count = len([f for f in combined_findings if f['status'] == 'PASS'])
        warn_count = len([f for f in combined_findings if f['status'] == 'WARN'])
        fail_count = len([f for f in combined_findings if f['status'] == 'FAIL'])
        info_count = len([f for f in combined_findings if f['status'] == 'INFO'])
        total = len(combined_findings)

        if fail_count > 0:
            overall = 'CRITICAL'
        elif warn_count > 2:
            overall = 'AT RISK'
        elif warn_count > 0:
            overall = 'FAIR'
        else:
            overall = 'SECURE'

        score = max(0, int(((pass_count + info_count * 0.5) / total) * 100)) if total > 0 else 0

        return jsonify({
            'timestamp': datetime.datetime.now().isoformat(),
            'overall_status': overall,
            'score': score,
            'summary': {
                'pass': pass_count,
                'warn': warn_count,
                'fail': fail_count,
                'info': info_count,
                'total': total,
            },
            'findings': combined_findings,
            'system': metrics.get('system', {}),
            'source': 'live',
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route("/api/history")
def history():
    """Return the in-memory history buffer as a JSON list."""
    user_id = get_request_user_id()
    device_id = get_request_device_id()

    db_history = get_metrics_history_for_user(user_id, device_id)
    if db_history:
        return jsonify(db_history)

    return jsonify([])


@app.route("/api/metrics/all")
def metrics_all():
    """Return latest metrics for ALL of the user's registered devices at once."""
    user_id = get_request_user_id()
    active = get_active_devices(user_id)
    active_ids = {d['device_id'] for d in active}

    rows = get_all_latest_metrics_for_user(user_id)
    result = []
    for row in rows:
        device_row = {
            "device_id":   row.get("device_id"),
            "device_name": row.get("device_name", "Unknown Device"),
            "hostname":    row.get("hostname", "unknown"),
            "os_info":     row.get("os_info", ""),
            "last_seen":   row.get("last_seen", ""),
        }
        payload = build_metrics_payload(row, device_row)
        if payload:
            payload["is_active"] = row.get("device_id") in active_ids
            result.append(payload)

    return jsonify({
        "user_id": user_id,
        "total": len(result),
        "active": sum(1 for d in result if d.get("is_active")),
        "devices": result
    })


@app.route("/api/devices")
def devices():
    """Get list of all registered devices."""
    user_id = get_request_user_id()
    all_devices = get_all_devices(user_id)
    active = get_active_devices(user_id)
    active_ids = {d['device_id'] for d in active}
    
    for device in all_devices:
        device['is_active'] = device['device_id'] in active_ids
    
    return jsonify({
        "total": len(all_devices),
        "active": len(active),
        "user_id": user_id,
        "devices": all_devices
    })


@app.route("/api/device/<device_id>")
def device_info(device_id):
    """Get specific device information and latest metrics."""
    user_id = get_request_user_id()
    device = get_device(device_id, user_id)
    if not device:
        return jsonify({"error": f"Device {device_id} not found"}), 404

    metrics, _ = resolve_user_metrics(user_id, device_id)
    
    return jsonify({
        "device": device,
        "metrics": metrics
    })


@app.route("/api/security-scan")
def security_scan():
    user_id = get_request_user_id()
    device_id = get_request_device_id()
    metrics, _ = resolve_user_metrics(user_id, device_id)
    if not metrics:
        return jsonify({"error": f"No metrics available for user '{user_id}'"}), 404
    data = build_device_health_scan(metrics)
    return jsonify(data)


def resolve_report_metrics_and_scan(user_id, device_id):
    """Always fetch fresh real-time metrics and OS security scan for reports.
    The backend IS the host machine, so reports should always reflect current state
    regardless of which device_id the frontend sends."""
    # Always fetch live system metrics from the host OS via psutil
    metrics_data = get_system_metrics()
    metrics_data["device_name"] = metrics_data.get("system", {}).get("hostname", "Local System")
    metrics_data["device_id"] = device_id or "local-system"
    metrics_data["source"] = "backend"

    # Always run the full live OS security scan + performance scan
    try:
        sec_scan = get_security_scan()
        perf_scan = build_device_health_scan(metrics_data)
        perf_findings = [f for f in perf_scan['findings'] if f['category'] == 'Performance' or f['category'] == 'Power']
        combined_findings = perf_findings + sec_scan['findings']

        pass_count = len([f for f in combined_findings if f['status'] == 'PASS'])
        warn_count = len([f for f in combined_findings if f['status'] == 'WARN'])
        fail_count = len([f for f in combined_findings if f['status'] == 'FAIL'])
        info_count = len([f for f in combined_findings if f['status'] == 'INFO'])
        total = len(combined_findings)

        if fail_count > 0:
            overall = 'CRITICAL'
        elif warn_count > 2:
            overall = 'AT RISK'
        elif warn_count > 0:
            overall = 'FAIR'
        else:
            overall = 'SECURE'

        score = max(0, int(((pass_count + info_count * 0.5) / total) * 100)) if total > 0 else 0
        scan_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'overall_status': overall,
            'score': score,
            'summary': {
                'pass': pass_count,
                'warn': warn_count,
                'fail': fail_count,
                'info': info_count,
                'total': total,
            },
            'findings': combined_findings,
        }
    except Exception as se:
        print(f"ERROR: Live security scan failed for report: {se}")
        import traceback
        traceback.print_exc()
        scan_data = build_device_health_scan(metrics_data)

    return metrics_data, scan_data


@app.route("/api/report/csv")
def report_csv():
    print("LOG: GET /api/report/csv - Starting")
    try:
        user_id = get_request_user_id()
        device_id = get_request_device_id()
        metrics_data, scan_data = resolve_report_metrics_and_scan(user_id, device_id)
        print("LOG: Metrics & analysis resolved.")
        csv_data = build_csv_report(metrics_data, scan_data)
        print("LOG: CSV build complete.")
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=sysmon_report.csv"}
        )
    except Exception as e:
        print(f"ERROR: CSV report generation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/pdf")
def report_pdf():
    print("LOG: GET /api/report/pdf - Starting")
    try:
        user_id = get_request_user_id()
        device_id = get_request_device_id()
        metrics_data, scan_data = resolve_report_metrics_and_scan(user_id, device_id)
        print("LOG: Metrics & analysis resolved.")
        pdf_bytes = build_pdf_report(metrics_data, scan_data)
        print(f"LOG: PDF build complete ({len(pdf_bytes)} bytes).")
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=sysmon_report.pdf",
                "Content-Length": str(len(pdf_bytes)),
            }
        )
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"ERROR: PDF report generation failed: {e}")
        print(tb)
        return jsonify({"error": str(e), "traceback": tb}), 500


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """Serve the frontend web app from the backend process."""
    frontend_dir = os.path.abspath(os.path.join(app.root_path, "..", "frontend"))

    if path == "" or path == "index.html":
        return send_from_directory(frontend_dir, "index.html")

    requested = os.path.abspath(os.path.join(frontend_dir, path))
    if os.path.commonpath([requested, frontend_dir]) != frontend_dir:
        # Prevent path traversal attacks.
        return jsonify({"error": "Invalid path"}), 400

    if os.path.exists(requested) and os.path.isfile(requested):
        return send_from_directory(frontend_dir, path)

    return send_from_directory(frontend_dir, "index.html")


def main():
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()