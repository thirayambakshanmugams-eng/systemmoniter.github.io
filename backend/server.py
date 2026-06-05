"""
SysMon Pro - System Monitoring & Security Scanner Backend
Flask server providing system metrics, security scanning, and report generation.
Multi-user support with device identification and persistent storage.
"""
import json
from collections import deque
import csv
import io
import subprocess
import platform
import datetime
import socket
import psutil
import os
import tempfile
from flask import Flask, jsonify, Response, send_from_directory, request
from flask_cors import CORS
from fpdf import FPDF
from database import (
    init_db, register_device, get_all_devices, get_device,
    save_metrics, get_latest_metrics, get_metrics_history,
    get_device_count, get_active_devices
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
    upd_output = run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install' -ErrorAction SilentlyContinue).LastSuccessTime")
    findings.append({
        "category": "Updates", "name": "Windows Update Status", "status": "INFO",
        "details": f"Last success: {upd_output or 'Unknown'}", "recommendation": "Check updates manually.",
    })

    # 5. Password policy
    pp_output = run_ps("net accounts | Select-String 'Maximum password age'")
    findings.append({
        "category": "Account Policy", "name": "Password Policy", "status": "INFO",
        "details": pp_output or "N/A", "recommendation": "Set age to 90 days or less.",
    })

    # 6. Auto-run entries count
    autorun_output = run_ps("(Get-CimInstance Win32_StartupCommand).Count")
    try: autorun_count = int(autorun_output.strip()); autorun_status = "INFO" if autorun_count < 10 else "WARN"
    except: autorun_count = -1; autorun_status = "INFO"
    findings.append({
        "category": "Startup", "name": "Startup Programs", "status": autorun_status,
        "details": f"{autorun_count} registered", "recommendation": "Review startup apps." if autorun_count >= 10 else "",
    })

    # 7. Open listening ports
    try:
        listening_ports = sorted(set(conn.laddr.port for conn in psutil.net_connections(kind='inet') if conn.status == 'LISTEN' and conn.laddr))
        port_count = len(listening_ports)
        port_status = "INFO" if port_count < 20 else "WARN"
        port_detail = f"{port_count} ports active"
    except (psutil.AccessDenied, PermissionError):
        port_count = 0
        port_status = "INFO"
        port_detail = "Access denied (run as Administrator for port scan)"
    findings.append({
        "category": "Network", "name": "Open Listening Ports", "status": port_status,
        "details": port_detail, "recommendation": "Review open ports." if port_count >= 20 else "",
    })

    # 8. UAC Status
    uac_output = run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
    uac_enabled = uac_output.strip() == "1"
    findings.append({
        "category": "Account Policy", "name": "User Account Control (UAC)", "status": "PASS" if uac_enabled else "FAIL",
        "details": f"UAC Enabled: {uac_enabled}", "recommendation": "" if uac_enabled else "Enable UAC immediately.",
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
    def __init__(self):
        super().__init__()
        self.page_num = 0
        # ── Dark Professional Palette ──────────────
        self.C_BG       = (7,  17,  35)   # near-black navy
        self.C_CARD     = (14, 27,  52)   # dark card
        self.C_CARD2    = (20, 36,  68)   # slightly lighter card
        self.C_BORDER   = (32, 56, 100)   # subtle border
        self.C_ACCENT   = (79, 140, 255)  # vivid blue
        self.C_ACCENT2  = (99, 102, 241)  # indigo
        self.C_TEXT     = (218, 230, 248) # near-white
        self.C_MUTED    = (120, 148, 182) # steel blue-grey
        self.C_STRIPE   = (18,  33,  60)  # table stripe
        self.C_WHITE    = (255, 255, 255)
        self.C_GREEN    = (52,  211, 153) # emerald
        self.C_AMBER    = (251, 191,  36) # golden amber
        self.C_RED      = (248, 113, 113) # soft red
        self.C_INDIGO   = (129, 140, 248) # light indigo

    # ── Page background + header bar ──────────────
    def header(self):
        # Dark background covers every page
        self.set_fill_color(*self.C_BG)
        self.rect(0, 0, 210, 297, 'F')

        if self.page_no() == 1:
            return

        # Top nav bar
        self.set_fill_color(*self.C_CARD)
        self.rect(0, 0, 210, 12, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(0, 12, 210, 1.2, 'F')

        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*self.C_MUTED)
        self.set_y(2.5)
        self.cell(0, 3.5, pdf_clean("SYSMON PRO"), align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "B", 5.5)
        self.cell(0, 3.5, pdf_clean("SYSTEM ANALYSIS REPORT"), align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "B", 6.5)
        self.set_y(4.2)
        self.cell(0, 4, pdf_clean(f"PAGE {self.page_no()}"), align="R")
        self.ln(8)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_fill_color(*self.C_CARD)
        self.rect(0, self.get_y() - 1, 210, 14, 'F')
        self.set_fill_color(*self.C_BORDER)
        self.rect(0, self.get_y() - 1, 210, 0.8, 'F')
        self.set_font("Helvetica", "I", 6.5)
        self.set_text_color(*self.C_MUTED)
        self.cell(0, 5, pdf_clean("SysMon Pro - For internal use only. Always verify scan results with a dedicated tool."), align="C")

    # ── Cover Page ────────────────────────────────
    def cover_page(self, metrics, scan):
        W = 210

        # Hero gradient bands (simulated)
        for i in range(75):
            ratio = i / 75
            r = int(7  + (20 - 7)  * ratio)
            g = int(17 + (45 - 17) * ratio)
            b = int(35 + (90 - 35) * ratio)
            self.set_fill_color(r, g, b)
            self.rect(0, i, W, 1.5, 'F')

        # Blue accent strip at bottom of hero
        self.set_fill_color(*self.C_ACCENT)
        self.rect(0, 74, W, 2.5, 'F')

        # Brand mark circle
        cx, cy, cr = W / 2, 32, 12
        self.set_fill_color(*self.C_ACCENT)
        self.ellipse(cx - cr, cy - cr, cr * 2, cr * 2, 'F')
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*self.C_WHITE)
        self.set_xy(cx - cr, cy - 5)
        self.cell(cr * 2, 10, pdf_clean("S"), align="C")

        # Title
        self.set_y(50)
        self.set_font("Helvetica", "B", 30)
        self.set_text_color(*self.C_TEXT)
        self.cell(0, 14, pdf_clean("SysMon Pro"), align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 12)
        self.set_text_color(*self.C_MUTED)
        self.cell(0, 7, pdf_clean("System Analysis & Security Report"), align="C", new_x="LMARGIN", new_y="NEXT")

        # ── Meta info card ─────────────────────────
        card_x, card_y, card_w, card_h = 25, 85, 160, 52
        self.set_fill_color(*self.C_CARD)
        self.rect(card_x, card_y, card_w, card_h, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(card_x, card_y, 2.5, card_h, 'F')
        self.set_fill_color(*self.C_BORDER)
        self.rect(card_x, card_y, card_w, 0.6, 'F')
        self.rect(card_x, card_y + card_h - 0.6, card_w, 0.6, 'F')

        def meta_row(label, value, color=None):
            self.set_font("Helvetica", "B", 7.5)
            self.set_text_color(*self.C_MUTED)
            self.set_x(card_x + 8)
            self.cell(38, 6.5, pdf_clean(label.upper()))
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*(color or self.C_TEXT))
            self.cell(0, 6.5, pdf_clean(str(value)), new_x="LMARGIN", new_y="NEXT")

        self.set_y(card_y + 5)
        ts = metrics['timestamp'][:19].replace('T', ' ')
        meta_row("Generated", ts)
        meta_row("Hostname", metrics['system']['hostname'])
        meta_row("Operating System", metrics['system']['os'])
        meta_row("Processor", (metrics['system']['processor'] or 'N/A')[:54])
        score_color = self.C_GREEN if scan['score'] >= 80 else (self.C_AMBER if scan['score'] >= 55 else self.C_RED)
        meta_row("Security Status", f"{scan['overall_status']}  |  Score: {scan['score']}/100", color=score_color)

        # ── KPI stat boxes ──────────────────────────
        stats = [
            ("CPU Usage",    f"{metrics['cpu']['usage_percent']:.1f}%",   self.C_ACCENT),
            ("RAM Used",     f"{metrics['memory']['percent']:.1f}%",       self.C_ACCENT2),
            ("Disk Volumes", str(len(metrics['disks'])),                   self.C_GREEN),
            ("Processes",    str(metrics['processes']),                    self.C_AMBER),
        ]
        box_w, box_h = 38, 26
        gap = 5
        total_w = len(stats) * box_w + (len(stats) - 1) * gap
        sx = (W - total_w) / 2
        sy = 147

        for i, (lbl, val, col) in enumerate(stats):
            bx = sx + i * (box_w + gap)
            self.set_fill_color(*self.C_CARD2)
            self.rect(bx, sy, box_w, box_h, 'F')
            self.set_fill_color(*col)
            self.rect(bx, sy, box_w, 2, 'F')
            self.set_font("Helvetica", "B", 13)
            self.set_text_color(*col)
            self.set_xy(bx, sy + 5)
            self.cell(box_w, 8, pdf_clean(val), align="C", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*self.C_MUTED)
            self.set_x(bx)
            self.cell(box_w, 5, pdf_clean(lbl.upper()), align="C", new_x="LMARGIN", new_y="NEXT")

        # ── Bottom branding (disable auto-break to avoid phantom page) ──
        self.set_auto_page_break(False)
        self.set_fill_color(*self.C_CARD)
        self.rect(0, 287, W, 10, 'F')
        self.set_font("Helvetica", "", 6.5)
        self.set_text_color(*self.C_MUTED)
        self.set_y(290)
        self.cell(0, 4, pdf_clean(f"Generated: {ts}   |   For internal use only"), align="C")
        self.set_auto_page_break(True, margin=18)

    # ── Helpers ───────────────────────────────────
    def section_header(self, title, top_pad=6, center=True):
        if self.get_y() + 55 > self.page_break_trigger:
            self.add_page()
        self.ln(top_pad)
        y = self.get_y()
        self.set_fill_color(*self.C_CARD)
        self.rect(self.l_margin, y, self.epw, 9, 'F')
        self.set_fill_color(*self.C_ACCENT)
        self.rect(self.l_margin, y, 2.5, 9, 'F')
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*self.C_ACCENT)
        align = "C" if center else "L"
        text = pdf_clean(title)
        self.cell(0, 9, text, align=align, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def kv_row(self, key, value, shade=False, key_w=65):
        bg = self.C_STRIPE if shade else self.C_CARD
        self.set_fill_color(*bg)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*self.C_MUTED)
        self.cell(key_w, 6.5, pdf_clean(f"  {key}"), fill=True)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*self.C_TEXT)
        self.cell(0, 6.5, pdf_clean(str(value)), fill=True, new_x="LMARGIN", new_y="NEXT")

    def draw_inline_bar(self, label, percent, color=None):
        """Draw a labelled progress bar inline."""
        if color is None:
            color = self.C_GREEN if percent <= 60 else (self.C_AMBER if percent <= 85 else self.C_RED)
        label_w = 34
        bar_w   = 112
        row_h   = 9
        y = self.get_y()
        self.set_fill_color(*self.C_CARD)
        self.rect(15, y, 180, row_h, 'F')
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*self.C_MUTED)
        self.set_xy(15, y + 1)
        self.cell(label_w, 5, pdf_clean(label), align="C")
        bx = 15 + label_w + 4
        by = y + 3
        # Track
        self.set_fill_color(*self.C_BORDER)
        self.rect(bx, by, bar_w, 3, 'F')
        # Fill
        fill_w = max(3, int(bar_w * min(percent, 100) / 100))
        self.set_fill_color(*color)
        self.rect(bx, by, fill_w, 3, 'F')
        # Value
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_xy(bx + bar_w + 4, y + 1)
        self.cell(22, 5, pdf_clean(f"{percent:.1f}%"), align="C")
        self.set_y(y + row_h + 2)

    def two_col(self, left_fn, right_fn, left_w=88, gap=8):
        """Run two functions side-by-side in two columns."""
        start_y = self.get_y()
        # Left column
        self.set_left_margin(15)
        self.set_right_margin(15 + (180 - left_w) + gap)
        left_fn()
        left_end_y = self.get_y()
        # Right column
        right_x = 15 + left_w + gap
        self.set_xy(right_x, start_y)
        self.set_left_margin(right_x)
        self.set_right_margin(15)
        right_fn()
        right_end_y = self.get_y()
        # Reset margins, move to the lower of the two columns
        self.set_left_margin(15)
        self.set_right_margin(15)
        self.set_y(max(left_end_y, right_end_y) + 2)


def render_report_charts(metrics, scan=None):
    """Render a 2x2 dark-theme chart grid and return the temp file path."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np

    P = {
        'bg':    '#07111f',
        'card':  '#0e1b34',
        'grid':  '#284572',
        'text':  '#ffffff',
        'muted': '#a5bdf2',
        'b1':    '#4f8cff',
        'b2':    '#6366f1',
        'green': '#34d399',
        'amber': '#fbbf24',
        'red':   '#f87171',
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

    # ── Chart 1: CPU / RAM / Swap utilization ──────
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

    # ── Chart 2: Disk Utilization (horizontal) ──────
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

    # ── Chart 3: Per-core CPU usage ─────────────────
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

    # ── Chart 4: Network + Security Score ──────────
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

    # Security score annotation in chart 4
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
    pdf = SysMonPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)

    # ══════════════════════════════════════════════
    # PAGE 1 ── COVER
    # ══════════════════════════════════════════════
    pdf.add_page()
    pdf.cover_page(metrics, scan)

    # ══════════════════════════════════════════════
    # PAGE 2 ── OVERVIEW: Summary · System · Memory · Hardware
    # ══════════════════════════════════════════════
    pdf.add_page()

    # Executive summary card
    pdf.section_header("Executive Summary", top_pad=4)
    status_text = {
        "SECURE":   "The host is in good shape with only minor findings.",
        "FAIR":     "A few warnings were detected; review the recommendations below.",
        "AT RISK":  "There are multiple areas that need attention.",
        "CRITICAL": "Immediate remediation is required for critical issues.",
    }.get(scan['overall_status'], "System analysis overview.")

    score_color = pdf.C_GREEN if scan['score'] >= 80 else (pdf.C_AMBER if scan['score'] >= 55 else pdf.C_RED)
    pdf.set_fill_color(*pdf.C_CARD2)
    pdf.rect(15, pdf.get_y(), 180, 18, 'F')
    pdf.set_fill_color(*score_color)
    pdf.rect(15, pdf.get_y(), 3, 18, 'F')
    sy_top = pdf.get_y() + 2
    pdf.set_xy(20, sy_top)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*score_color)
    pdf.cell(0, 6, pdf_clean(f"{scan['overall_status']} — {scan['score']}/100"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(20, pdf.get_y())
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*pdf.C_TEXT)
    pdf.multi_cell(172, 5, pdf_clean(
        f"{metrics['system']['hostname']} is running {metrics['system']['os']}. {status_text}"
    ))
    pdf.ln(4)

    kpi_items = [
        ("CPU",   f"{metrics['cpu']['usage_percent']:.1f}%",   pdf.C_ACCENT),
        ("RAM",   f"{metrics['memory']['percent']:.1f}%",       pdf.C_ACCENT2),
        ("Swap",  f"{metrics['memory']['swap_percent']:.1f}%",  pdf.C_GREEN),
        ("Cores", str(metrics['cpu']['core_count']),            pdf.C_MUTED),
        ("Disks", str(len(metrics['disks'])),                   pdf.C_AMBER),
        ("Procs", str(metrics['processes']),                    pdf.C_MUTED),
    ]
    stat_w = 26
    stat_h = 26
    gap = 4.5
    total_w = len(kpi_items) * stat_w + (len(kpi_items) - 1) * gap
    sx = 15 + (180 - total_w) / 2
    py = pdf.get_y()
    for i, (lbl, val, col) in enumerate(kpi_items):
        px = sx + i * (stat_w + gap)
        pdf.set_fill_color(*pdf.C_CARD)
        pdf.set_draw_color(*pdf.C_BORDER)
        pdf.set_line_width(0.2)
        pdf.rect(px, py, stat_w, stat_h, 'DF')
        pdf.set_fill_color(*col)
        pdf.rect(px, py, stat_w, 3, 'F')
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*col)
        pdf.set_xy(px, py + 6)
        pdf.cell(stat_w, 7, pdf_clean(val), align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*pdf.C_MUTED)
        pdf.set_xy(px, py + 14)
        pdf.cell(stat_w, 5, pdf_clean(lbl), align="C")
    pdf.set_y(py + stat_h + 4)
    pdf.ln(2)

    sys_rows = [
        ("OS",          metrics['system']['os']),
        ("Version",     (metrics['system']['version'] or 'N/A')[:32]),
        ("Hostname",    metrics['system']['hostname']),
        ("Architecture",metrics['system'].get('machine', 'N/A')),
        ("Uptime",      metrics['system']['uptime']),
        ("Last Boot",   metrics['system']['boot_time']),
        ("Processes",   str(metrics['processes'])),
        ("Processor",   (metrics['system']['processor'] or 'N/A')[:38]),
    ]
    mem = metrics['memory']
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
        pdf.section_header("System Details", top_pad=0)
        for i, (k, v) in enumerate(sys_rows):
            pdf.kv_row(k, v, shade=(i % 2 == 0), key_w=35)

    def right_block():
        pdf.section_header("Memory Snapshot", top_pad=0, center=True)
        for i, (k, v) in enumerate(mem_rows):
            pdf.kv_row(k, v, shade=(i % 2 == 0), key_w=35)

    pdf.two_col(left_block, right_block, left_w=88, gap=6)

    # Bring Performance Indicators to a new line!
    pdf.section_header("Performance Indicators", top_pad=4, center=True)
    pdf.draw_inline_bar("CPU", metrics['cpu']['usage_percent'])
    pdf.draw_inline_bar("RAM", mem['percent'])
    pdf.draw_inline_bar("Swap", mem['swap_percent'])

    pdf.ln(4)
    hw_rows = [
        ("Physical Cores", str(metrics['cpu']['core_count'])),
        ("Logical Threads", str(metrics['cpu']['thread_count'])),
        ("CPU Freq", f"{metrics['cpu']['frequency_mhz'] or 'N/A'} MHz"),
        ("Max Freq", f"{metrics['cpu']['freq_max_mhz'] or 'N/A'} MHz"),
    ]
    net = metrics['network']
    net_rows = [
        ("Bytes Sent",    f"{net['bytes_sent_mb']:.2f} MB"),
        ("Bytes Recv",    f"{net['bytes_recv_mb']:.2f} MB"),
        ("Packets Sent",  str(net['packets_sent'])),
        ("Packets Recv",  str(net['packets_recv'])),
    ]

    def hw_block():
        pdf.section_header("Hardware Overview", top_pad=0)
        for i, (k, v) in enumerate(hw_rows):
            pdf.kv_row(k, v, shade=(i % 2 == 0), key_w=35)

    def net_block():
        pdf.section_header("Network Overview", top_pad=0)
        for i, (k, v) in enumerate(net_rows):
            pdf.kv_row(k, v, shade=(i % 2 == 0), key_w=35)
        if metrics['battery']:
            bat = metrics['battery']
            pdf.ln(2)
            pdf.kv_row("Battery", "", shade=False, key_w=35)
            pdf.kv_row("Level",  f"{bat['percent']:.0f}%", shade=True, key_w=35)
            pdf.kv_row("Status", "Charging" if bat['charging'] else "On Battery", shade=False, key_w=35)

    pdf.two_col(hw_block, net_block, left_w=88, gap=6)

    # ══════════════════════════════════════════════
    # PAGE 3 ── PERFORMANCE CHARTS + STORAGE
    # ══════════════════════════════════════════════
    pdf.add_page()
    pdf.section_header("Performance Dashboard", top_pad=4)

    chart_path = render_report_charts(metrics, scan)
    chart_y = pdf.get_y()
    pdf.image(chart_path, x=10, y=chart_y, w=190, h=196)
    os.remove(chart_path)
    pdf.set_y(chart_y + 201)

    # ══════════════════════════════════════════════
    # PAGE 4 ── SECURITY SCAN + RECOMMENDATIONS
    # ══════════════════════════════════════════════
    pdf.add_page()
    pdf.section_header("Security Scan Results", top_pad=4)

    s = scan['summary']
    score_color = pdf.C_GREEN if scan['score'] >= 80 else (pdf.C_AMBER if scan['score'] >= 55 else pdf.C_RED)

    # Score badge
    badge_y = pdf.get_y()
    pdf.set_fill_color(*pdf.C_CARD2)
    pdf.rect(15, badge_y, 180, 20, 'F')
    pdf.set_fill_color(*score_color)
    pdf.rect(15, badge_y, 2.5, 20, 'F')

    # Score circle
    cx, cy = 33, badge_y + 10
    pdf.set_fill_color(*pdf.C_CARD)
    pdf.ellipse(cx - 8, cy - 8, 16, 16, 'F')
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*score_color)
    pdf.set_xy(cx - 8, cy - 5)
    pdf.cell(16, 10, pdf_clean(str(scan['score'])), align="C")

    pdf.set_xy(46, badge_y + 3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*score_color)
    pdf.cell(0, 7, pdf_clean(f"Overall Status: {scan['overall_status']}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(46, pdf.get_y())
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.cell(0, 5, pdf_clean(
        f"PASS: {s['pass']}   |   WARN: {s['warn']}   |   FAIL: {s['fail']}   |   INFO: {s['info']}   |   Total: {s['total']}  |  Scanned: {scan['timestamp'][:19].replace('T',' ')}"
    ), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    if metrics['disks']:
        pdf.section_header("Disk Volumes")
        cols = [("Device", 40), ("Mount", 40), ("FS", 18), ("Total", 23), ("Used", 23), ("Usage", 30)]
        pdf.set_fill_color(*pdf.C_CARD2)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*pdf.C_ACCENT)
        for lbl, w in cols:
            pdf.cell(w, 7.5, pdf_clean(f"  {lbl}"), fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 7.5)
        for i, disk in enumerate(metrics['disks'][:6]):
            bg = pdf.C_STRIPE if i % 2 == 0 else pdf.C_CARD
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*pdf.C_TEXT)
            row = [
                (disk['device'][:18], 40),
                (disk['mountpoint'][:18], 40),
                (disk['fstype'][:8], 18),
                (f"{disk['total_gb']:.1f} GB", 23),
                (f"{disk['used_gb']:.1f} GB", 23),
            ]
            for txt, w in row:
                pdf.cell(w, 6.5, pdf_clean(f"  {txt}"), fill=True)
            pct_col = pdf.C_GREEN if disk['percent'] <= 60 else (pdf.C_AMBER if disk['percent'] <= 85 else pdf.C_RED)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.set_text_color(*pct_col)
            pdf.cell(30, 6.5, pdf_clean(f"  {disk['percent']:.0f}%"), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Findings table header
    cols = [("Category", 30), ("Check", 55), ("Status", 18), ("Details", 77)]
    pdf.set_fill_color(*pdf.C_CARD2)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*pdf.C_ACCENT)
    for lbl, w in cols:
        pdf.cell(w, 7, pdf_clean(f"  {lbl.upper()}"), fill=True)
    pdf.ln()

    status_color_map = {
        "PASS": pdf.C_GREEN, "WARN": pdf.C_AMBER,
        "FAIL": pdf.C_RED,   "INFO": pdf.C_INDIGO
    }

    for i, f in enumerate(scan['findings']):
        bg = pdf.C_STRIPE if i % 2 == 0 else pdf.C_CARD
        pdf.set_fill_color(*bg)
        sc = status_color_map.get(f['status'], pdf.C_MUTED)

        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*pdf.C_TEXT)
        pdf.cell(30, 6.5, pdf_clean(f"  {f['category']}"), fill=True)
        pdf.cell(55, 6.5, pdf_clean(f"  {f['name']}"), fill=True)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*sc)
        pdf.cell(18, 6.5, pdf_clean(f"  {f['status']}"), fill=True)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*pdf.C_TEXT)
        details = f['details'][:68] + ("..." if len(f['details']) > 68 else "")
        pdf.cell(77, 6.5, pdf_clean(f"  {details}"), fill=True, new_x="LMARGIN", new_y="NEXT")

        if f.get('recommendation'):
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "I", 6.5)
            pdf.set_text_color(*pdf.C_AMBER)
            pdf.set_x(15)
            pdf.cell(30, 4.5, "", fill=True)
            pdf.cell(0, 4.5, pdf_clean(f"  -> {f['recommendation']}"), fill=True, new_x="LMARGIN", new_y="NEXT")

    # ── Recommendations Summary ───────────────────
    recs = [(f['name'], f['recommendation']) for f in scan['findings'] if f.get('recommendation')]
    if recs:
        pdf.ln(3)
        pdf.section_header("Recommendations")
        for j, (name, rec) in enumerate(recs):
            bg = pdf.C_STRIPE if j % 2 == 0 else pdf.C_CARD
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.set_text_color(*pdf.C_AMBER)
            pdf.cell(58, 6.5, pdf_clean(f"  {name}"), fill=True)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.set_text_color(*pdf.C_TEXT)
            disp = rec[:95] + ("..." if len(rec) > 95 else "")
            pdf.cell(0, 6.5, pdf_clean(f"  {disp}"), fill=True, new_x="LMARGIN", new_y="NEXT")

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
    return jsonify({
        "status": "running",
        "message": "SysMon backend active",
        "pc_agent_connected": use_pc_agent and pc_agent_metrics is not None,
        "connected_devices": get_device_count(),
        "active_devices": len(get_active_devices())
    })


@app.route("/api/receive-metrics", methods=["POST"])
def receive_metrics():
    """Endpoint for PC monitoring agent to send metrics."""
    global pc_agent_metrics, use_pc_agent
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Get device info from metrics
        device_id = data.get("device_id", "default")
        device_name = data.get("device_name", "Unknown Device")
        system = data.get("system", {})
        hostname = system.get("hostname", "unknown")
        os_info = system.get("os", "unknown")
        
        # Register/update device
        register_device(device_id, device_name, hostname, os_info)
        
        # Save metrics to database
        save_metrics(device_id, data)
        
        # Also keep in-memory for backward compatibility
        pc_agent_metrics = data
        use_pc_agent = True
        
        cpu_pct = data.get('cpu', {}).get('usage_percent', 0)
        print(f"LOG: Metrics received from device '{device_name}' ({device_id}) - CPU: {cpu_pct}%")
        
        return jsonify({"status": "received", "device_id": device_id}), 200
    except Exception as e:
        print(f"ERROR: Failed to receive metrics: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/metrics")
def metrics():
    global pc_agent_metrics, use_pc_agent
    
    # Check if device_id is specified in query params
    device_id = request.args.get("device_id")
    
    if device_id:
        # Get metrics for specific device from database
        metrics_data = get_latest_metrics(device_id)
        if metrics_data:
            # Parse full_metrics if available
            if metrics_data.get('full_metrics'):
                import ast
                try:
                    data = ast.literal_eval(metrics_data['full_metrics'])
                except:
                    data = pc_agent_metrics or get_system_metrics()
            else:
                data = pc_agent_metrics or get_system_metrics()
            print(f"LOG: Serving metrics for device {device_id}")
        else:
            data = {"error": f"No metrics for device {device_id}"}
    else:
        # Use PC agent metrics if available, otherwise use server metrics
        if use_pc_agent and pc_agent_metrics:
            data = pc_agent_metrics
            print("LOG: Serving PC agent metrics (default)")
        else:
            data = get_system_metrics()
            print("LOG: Serving server metrics (default)")
    
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


@app.route("/api/history")
def history():
    """Return the in-memory history buffer as a JSON list."""
    device_id = request.args.get("device_id")
    
    if device_id:
        # Get history for specific device from database
        db_history = get_metrics_history(device_id)
        return jsonify(db_history)
    else:
        # Return in-memory history (backward compat)
        return jsonify(list(history_buffer))


@app.route("/api/devices")
def devices():
    """Get list of all registered devices."""
    all_devices = get_all_devices()
    active = get_active_devices()
    active_ids = {d['device_id'] for d in active}
    
    for device in all_devices:
        device['is_active'] = device['device_id'] in active_ids
    
    return jsonify({
        "total": len(all_devices),
        "active": len(active),
        "devices": all_devices
    })


@app.route("/api/device/<device_id>")
def device_info(device_id):
    """Get specific device information and latest metrics."""
    device = get_device(device_id)
    if not device:
        return jsonify({"error": f"Device {device_id} not found"}), 404
    
    metrics = get_latest_metrics(device_id)
    
    return jsonify({
        "device": device,
        "metrics": metrics
    })


@app.route("/api/security-scan")
def security_scan():
    data = get_security_scan()
    return jsonify(data)


@app.route("/api/report/csv")
def report_csv():
    print("LOG: GET /api/report/csv - Starting")
    try:
        metrics_data = get_system_metrics()
        print("LOG: Metrics gathered.")
        scan_data = get_security_scan()
        print("LOG: Scan gathered.")
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
        metrics_data = get_system_metrics()
        print("LOG: Metrics gathered.")
        scan_data = get_security_scan()
        print("LOG: Scan gathered.")
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