"""
SysMon Pro - System Monitoring & Security Scanner Backend
Flask server providing system metrics, security scanning, and report generation.
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
from flask import Flask, jsonify, Response, send_from_directory
from flask_cors import CORS
from fpdf import FPDF

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# HISTORY BUFFER  (max 1800 snapshots ≈ 1 hour @ 2s poll)
# ─────────────────────────────────────────────
HISTORY_MAX = 1800
history_buffer: deque = deque(maxlen=HISTORY_MAX)

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
            "os": f"{uname.system} {uname.release}",
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
            "core_count": psutil.cpu_count(logical=False),
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


class SysMonPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.page_num = 0
        # Professional Light/Corporate Colors
        self.C_BG      = (255, 255, 255)
        self.C_NAVY    = (30, 58, 138)
        self.C_ACCENT  = (37, 99, 235)
        self.C_TEXT    = (30, 41, 59)
        self.C_MUTED   = (100, 116, 139)
        self.C_LIGHT   = (248, 250, 252)
        self.C_STRIPE  = (241, 245, 249)
        self.C_WHITE   = (255, 255, 255)
        self.C_GREEN   = (22, 163, 74)
        self.C_AMBER   = (217, 119, 6)
        self.C_RED     = (220, 38, 38)
        self.C_INDIGO  = (79, 70, 229)

    def header(self):
        if self.page_no() == 1:
            return
        # Slim top bar
        self.set_fill_color(*self.C_STRIPE)
        self.rect(0, 0, 210, 12, 'F')
        self.set_fill_color(*self.C_NAVY)
        self.rect(0, 0, 210, 2, 'F')
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*self.C_MUTED)
        self.set_y(4)
        self.cell(0, 6, pdf_clean("SYSMON PRO  |  SYSTEM ANALYSIS REPORT"), align="L", new_x="LMARGIN", new_y="NEXT")
        self.set_y(4)
        self.cell(0, 6, pdf_clean(f"PAGE {self.page_no()}"), align="R")
        self.ln(6)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_draw_color(*self.C_LIGHT)
        self.line(15, self.get_y(), 195, self.get_y())
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*self.C_MUTED)
        self.set_y(-12)
        self.cell(0, 5, pdf_clean("SysMon Pro - For internal use only. Always verify scan results with a dedicated tool."), align="C")

    def cover_page(self, metrics, scan):
        """Draw a styled cover page."""
        self.set_fill_color(*self.C_BG)
        self.rect(0, 0, 210, 297, 'F')

        # Corporate top banner
        self.set_fill_color(*self.C_NAVY)
        self.rect(0, 0, 210, 80, 'F')
        
        self.set_fill_color(*self.C_ACCENT)
        self.rect(0, 80, 210, 4, 'F')

        # Title / Header
        self.set_y(30)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(*self.C_WHITE)
        self.cell(0, 16, pdf_clean("SysMon Pro"), align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 14)
        self.set_text_color(200, 215, 240)
        self.cell(0, 8, pdf_clean("System Analysis & Security Report"), align="C", new_x="LMARGIN", new_y="NEXT")
        
        # Meta info box
        self.set_y(100)
        box_y = self.get_y()
        self.set_fill_color(*self.C_LIGHT)
        self.set_draw_color(*self.C_STRIPE)
        self.rect(30, box_y, 150, 52, 'FD')
        self.set_y(box_y + 6)

        def cover_row(label, value, color=None):
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*self.C_MUTED)
            self.set_x(40)
            self.cell(40, 6, pdf_clean(label.upper()))
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*(color or self.C_TEXT))
            self.cell(0, 6, pdf_clean(value), new_x="LMARGIN", new_y="NEXT")

        ts = metrics['timestamp'][:19].replace('T', ' ')
        cover_row("Generated", ts)
        cover_row("Hostname", metrics['system']['hostname'])
        cover_row("Operating System", metrics['system']['os'])
        cover_row("Processor", (metrics['system']['processor'] or 'N/A')[:55])

        score_color = self.C_GREEN if scan['score'] >= 80 else (self.C_AMBER if scan['score'] >= 55 else self.C_RED)
        cover_row("Security Status", f"{scan['overall_status']}  |  Score: {scan['score']}/100", color=score_color)

        # Quick stats row
        self.ln(18)
        stats = [
            ("CPU Usage", f"{metrics['cpu']['usage_percent']:.1f}%"),
            ("RAM Used", f"{metrics['memory']['used_gb']} / {metrics['memory']['total_gb']} GB"),
            ("Disk Volumes", str(len(metrics['disks']))),
            ("Processes", str(metrics['processes'])),
        ]
        box_w = 36
        start_x = (210 - box_w * 4 - 6 * 3) / 2
        stat_y = self.get_y()
        for i, (lbl, val) in enumerate(stats):
            bx = start_x + i * (box_w + 6)
            self.set_fill_color(*self.C_WHITE)
            self.set_draw_color(*self.C_STRIPE)
            self.rect(bx, stat_y, box_w, 22, 'FD')
            self.set_fill_color(*self.C_NAVY)
            self.rect(bx, stat_y, box_w, 2, 'F')
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*self.C_TEXT)
            self.set_xy(bx, stat_y + 4)
            self.cell(box_w, 6, val, align="C", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 6.5)
            self.set_text_color(*self.C_MUTED)
            self.set_x(bx)
            self.cell(box_w, 5, lbl.upper(), align="C", new_x="LMARGIN", new_y="NEXT")

        # Bottom accent
        self.set_fill_color(*self.C_STRIPE)
        self.rect(0, 293, 210, 4, 'F')

    def section_header(self, title, icon=""):
        self.ln(4)
        self.set_fill_color(*self.C_LIGHT)
        self.set_draw_color(*self.C_STRIPE)
        self.rect(15, self.get_y(), 180, 9, 'FD')
        self.set_fill_color(*self.C_NAVY)
        self.rect(15, self.get_y(), 3, 9, 'F')
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.C_NAVY)
        text = pdf_clean(f"   {icon}  {title}" if icon else f"   {title}")
        self.cell(0, 9, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def kv_row(self, key, value, shade=False, key_w=65):
        if shade:
            self.set_fill_color(*self.C_STRIPE)
        else:
            self.set_fill_color(*self.C_WHITE)
            
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*self.C_MUTED)
        self.cell(key_w, 6.5, pdf_clean(f"  {key}"), fill=True)
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*self.C_TEXT)
        self.cell(0, 6.5, pdf_clean(str(value)), fill=True, new_x="LMARGIN", new_y="NEXT")

    def draw_bar(self, percent, bar_w=110, height=3, x_offset=80):
        color = self.C_RED if percent > 85 else (self.C_AMBER if percent > 60 else self.C_ACCENT)
        bx = 15 + x_offset
        by = self.get_y() + 1.5
        self.set_fill_color(*self.C_STRIPE)
        self.rect(bx, by, bar_w, height, 'F')
        filled_w = max(1, int(percent / 100 * bar_w))
        self.set_fill_color(*color)
        self.rect(bx, by, filled_w, height, 'F')
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_x(bx + bar_w + 3)
        self.cell(20, 6, f"{percent:.1f}%", new_x="LMARGIN", new_y="NEXT")

    def table_header(self, cols):
        self.set_fill_color(*self.C_STRIPE)
        self.set_draw_color(220, 226, 230)
        self.set_line_width(0.2)
        self.set_text_color(*self.C_MUTED)
        self.set_font("Helvetica", "B", 7.5)
        for label, w in cols:
            self.cell(w, 7, pdf_clean(f"  {label.upper()}"), fill=True, border='B')
        self.ln()

    def table_row(self, cols_values, shade=False):
        bg = self.C_LIGHT if shade else self.C_WHITE
        self.set_fill_color(*bg)
        self.set_text_color(*self.C_TEXT)
        self.set_font("Helvetica", "", 8)
        for text, w in cols_values:
            self.cell(w, 6.5, pdf_clean(f"  {str(text)[:int(w/1.8)]}"), fill=True)
        self.ln()


def build_pdf_report(metrics, scan):
    pdf = SysMonPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)

    # ── Cover page ───────────────────────────────────────
    pdf.add_page()
    pdf.cover_page(metrics, scan)

    # ── Page 2: System Overview ──────────────────────────
    pdf.add_page()

    # Executive Summary box
    pdf.section_header("Executive Summary")
    s_score = scan['score']
    score_color = pdf.C_GREEN if s_score >= 80 else (pdf.C_AMBER if s_score >= 55 else pdf.C_RED)
    status_map = {
        "SECURE": "System is well-protected. All major security controls are in place.",
        "FAIR":   "System has some security warnings. Review recommendations below.",
        "AT RISK":"Multiple security warnings detected. Immediate action recommended.",
        "CRITICAL":"Critical security failures found. Urgent remediation required.",
    }
    summary_text = status_map.get(scan['overall_status'], "")

    pdf.set_fill_color(248, 250, 252)
    pdf.rect(15, pdf.get_y(), 180, 22, 'F')
    pdf.set_fill_color(*score_color)
    pdf.rect(15, pdf.get_y(), 3, 22, 'F')
    pdf.set_y(pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*score_color)
    pdf.set_x(22)
    pdf.cell(0, 6, pdf_clean(f"Security Status: {scan['overall_status']}  -  Score: {s_score} / 100"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.set_x(22)
    pdf.cell(0, 5, pdf_clean(summary_text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Key Metrics row
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.cell(0, 5, "  KEY METRICS AT A GLANCE", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    metrics_row = [
        ("CPU Usage",     f"{metrics['cpu']['usage_percent']:.1f}%",   metrics['cpu']['usage_percent']),
        ("RAM Usage",     f"{metrics['memory']['percent']:.1f}%",       metrics['memory']['percent']),
        ("Swap Usage",    f"{metrics['memory']['swap_percent']:.1f}%",  metrics['memory']['swap_percent']),
    ]
    for lbl, val_str, pct in metrics_row:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*pdf.C_TEXT)
        pdf.set_x(15)
        pdf.cell(65, 6, pdf_clean(f"  {lbl}"))
        color = pdf.C_RED if pct > 85 else (pdf.C_AMBER if pct > 60 else pdf.C_ACCENT)
        # bar bg
        bx = pdf.get_x()
        by = pdf.get_y() + 1
        pdf.set_fill_color(*pdf.C_STRIPE)
        pdf.rect(bx, by, 90, 3, 'F')
        filled = max(1, int(pct / 100 * 90))
        pdf.set_fill_color(*color)
        pdf.rect(bx, by, filled, 3, 'F')
        pdf.set_x(bx + 92)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*color)
        pdf.cell(20, 6, pdf_clean(val_str), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # ── System Information ────────────────────────────────
    pdf.section_header("System Information")
    sys_items = [
        ("Operating System",   metrics['system']['os']),
        ("OS Version",         (metrics['system']['version'] or 'N/A')[:80]),
        ("Hostname",           metrics['system']['hostname']),
        ("Architecture",       metrics['system']['machine']),
        ("Processor",          (metrics['system']['processor'] or 'N/A')[:70]),
        ("System Uptime",      metrics['system']['uptime']),
        ("Last Boot Time",     metrics['system']['boot_time']),
        ("Running Processes",  str(metrics['processes'])),
    ]
    for i, (k, v) in enumerate(sys_items):
        pdf.kv_row(k, v, shade=(i % 2 == 0))
    pdf.ln(5)

    # ── CPU ──────────────────────────────────────────────
    pdf.section_header("CPU - Processor Details")
    cpu = metrics['cpu']
    color_c = pdf.C_RED if cpu['usage_percent'] > 85 else (pdf.C_AMBER if cpu['usage_percent'] > 60 else pdf.C_ACCENT)
    pdf.kv_row("Physical Cores", str(cpu['core_count']), shade=True)
    pdf.kv_row("Logical Threads", str(cpu['thread_count']), shade=False)
    if cpu['frequency_mhz']:
        pdf.kv_row("Current Frequency", f"{cpu['frequency_mhz']} MHz", shade=True)
        pdf.kv_row("Max Frequency", f"{cpu['freq_max_mhz']} MHz", shade=False)
    pdf.kv_row("Overall Usage", f"{cpu['usage_percent']:.1f}%", shade=True)
    pdf.ln(3)

    # Per-core usage
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.cell(0, 6, "  PER-CORE USAGE", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    cols_per_row = 2
    core_data = cpu['per_core']
    for i in range(0, len(core_data), cols_per_row):
        row_y = pdf.get_y()
        for j in range(cols_per_row):
            if i + j >= len(core_data):
                break
            idx = i + j
            pct = core_data[idx]
            c = pdf.C_RED if pct > 85 else (pdf.C_AMBER if pct > 60 else pdf.C_ACCENT)
            shade = (i // cols_per_row) % 2 == 0
            bg = pdf.C_STRIPE if shade else pdf.C_WHITE
            pdf.set_fill_color(*bg)
            col_x = 15 + j * 90
            pdf.set_xy(col_x, row_y)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*pdf.C_TEXT)
            pdf.cell(20, 6, f"  Core {idx}", fill=True)
            # bar
            bx = col_x + 20
            by = row_y + 1.5
            pdf.set_fill_color(*pdf.C_STRIPE)
            pdf.rect(bx, by, 55, 3, 'F')
            filled = max(1, int(pct / 100 * 55))
            pdf.set_fill_color(*c)
            pdf.rect(bx, by, filled, 3, 'F')
            pdf.set_xy(bx + 57, row_y)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*c)
            pdf.cell(13, 6, f"{pct:.1f}%", fill=False, new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(row_y + 6)
    pdf.ln(5)

    # ── Memory ──────────────────────────────────────────
    pdf.section_header("Memory - RAM & Swap")
    mem = metrics['memory']
    pdf.kv_row("Total RAM",       f"{mem['total_gb']} GB", shade=True)
    pdf.kv_row("Used RAM",        f"{mem['used_gb']} GB", shade=False)
    pdf.kv_row("Available RAM",   f"{mem['available_gb']} GB", shade=True)

    # RAM bar
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*pdf.C_TEXT)
    pdf.set_x(15)
    pdf.cell(65, 6, "  RAM Usage")
    bx = pdf.get_x()
    by = pdf.get_y() + 1.5
    ram_color = pdf.C_RED if mem['percent'] > 85 else (pdf.C_AMBER if mem['percent'] > 60 else pdf.C_ACCENT)
    pdf.set_fill_color(*pdf.C_STRIPE)
    pdf.rect(bx, by, 90, 3, 'F')
    pdf.set_fill_color(*ram_color)
    pdf.rect(bx, by, max(1, int(mem['percent'] / 100 * 90)), 3, 'F')
    pdf.set_x(bx + 92)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*ram_color)
    pdf.cell(30, 6, f"{mem['percent']:.1f}%", new_x="LMARGIN", new_y="NEXT")

    pdf.kv_row("Swap Total",  f"{mem['swap_total_gb']} GB", shade=True)
    pdf.kv_row("Swap Used",   f"{mem['swap_used_gb']} GB ({mem['swap_percent']:.1f}%)", shade=False)
    pdf.ln(5)

    # ── Disks ───────────────────────────────────────────
    pdf.section_header("Storage - Disk Volumes")
    for i, disk in enumerate(metrics['disks']):
        shade = i % 2 == 0
        dc = pdf.C_RED if disk['percent'] > 90 else (pdf.C_AMBER if disk['percent'] > 70 else pdf.C_ACCENT)
        bg = pdf.C_STRIPE if shade else pdf.C_WHITE
        pdf.set_fill_color(*bg)

        row_y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*pdf.C_TEXT)
        pdf.cell(45, 6, f"  {disk['device'][:20]}", fill=True)
        pdf.cell(30, 6, disk['mountpoint'][:12], fill=True)
        pdf.cell(18, 6, disk['fstype'], fill=True)
        pdf.cell(22, 6, f"{disk['total_gb']} GB", fill=True)
        pdf.cell(22, 6, f"{disk['used_gb']} GB", fill=True)

        # Inline bar
        bx = pdf.get_x()
        by = row_y + 1.5
        pdf.set_fill_color(*pdf.C_STRIPE)
        pdf.rect(bx, by, 28, 3, 'F')
        pdf.set_fill_color(*dc)
        pdf.rect(bx, by, max(1, int(disk['percent'] / 100 * 28)), 3, 'F')
        pdf.set_x(bx + 30)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*dc)
        pdf.cell(18, 6, f"{disk['percent']:.0f}%", fill=False, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # ── Network ────────────────────────────────────────
    pdf.section_header("Network - I/O & Interfaces")
    net = metrics['network']
    pdf.kv_row("Total Sent",     f"{net['bytes_sent_mb']:.2f} MB", shade=True)
    pdf.kv_row("Total Received", f"{net['bytes_recv_mb']:.2f} MB", shade=False)
    pdf.kv_row("Packets Sent",   f"{net['packets_sent']:,}", shade=True)
    pdf.kv_row("Packets Recv",   f"{net['packets_recv']:,}", shade=False)
    if net['interfaces']:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*pdf.C_MUTED)
        pdf.cell(0, 5, "  NETWORK INTERFACES", new_x="LMARGIN", new_y="NEXT")
        for j, (iface, ip) in enumerate(net['interfaces'].items()):
            pdf.kv_row(iface, ip, shade=j % 2 == 0)
    pdf.ln(5)

    # ── Battery ────────────────────────────────────────
    if metrics.get('battery'):
        bat = metrics['battery']
        pdf.section_header("Battery / Power")
        bc = pdf.C_RED if bat['percent'] < 20 else (pdf.C_AMBER if bat['percent'] < 40 else pdf.C_GREEN)
        pdf.kv_row("Battery Level",   f"{bat['percent']}%", shade=True)
        pdf.kv_row("Power Status",    "Charging" if bat['charging'] else "On Battery", shade=False)
        if bat.get('time_left_mins') and bat['time_left_mins'] > 0:
            pdf.kv_row("Time Remaining", f"{bat['time_left_mins']} min", shade=True)
        pdf.ln(5)

    # ── Security Scan ──  new page ─────────────────────
    pdf.add_page()
    pdf.section_header("Security Scan Results")

    # Score summary box
    s = scan['summary']
    score_color = pdf.C_GREEN if scan['score'] >= 80 else (pdf.C_AMBER if scan['score'] >= 55 else pdf.C_RED)
    pdf.set_fill_color(*pdf.C_LIGHT)
    pdf.set_draw_color(*pdf.C_STRIPE)
    pdf.rect(15, pdf.get_y(), 180, 28, 'FD')
    pdf.set_fill_color(*score_color)
    pdf.rect(15, pdf.get_y(), 3, 28, 'F')

    box_y2 = pdf.get_y() + 3
    pdf.set_xy(22, box_y2)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*score_color)
    pdf.cell(0, 8, pdf_clean(f"Overall Status: {scan['overall_status']}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(22, pdf.get_y())
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*pdf.C_TEXT)
    pdf.cell(0, 6, pdf_clean(f"Security Score:  {scan['score']} / 100"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(22, pdf.get_y())
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.cell(0, 5, pdf_clean(f"PASS: {s['pass']}   |   WARN: {s['warn']}   |   FAIL: {s['fail']}   |   INFO: {s['info']}   |   Total checks: {s['total']}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Findings table header
    status_color_map = {
        "PASS": pdf.C_GREEN, "WARN": pdf.C_AMBER,
        "FAIL": pdf.C_RED,   "INFO": pdf.C_INDIGO
    }
    pdf.set_font("Helvetica", "B", 7.5)
    headers = [("Category", 32), ("Check Name", 58), ("Status", 20), ("Details", 70)]
    pdf.set_fill_color(*pdf.C_STRIPE)
    pdf.set_text_color(*pdf.C_MUTED)
    pdf.set_draw_color(220, 226, 230)
    pdf.set_line_width(0.2)
    for lbl, w in headers:
        pdf.cell(w, 7, pdf_clean(f"  {lbl.upper()}"), fill=True, border='B')
    pdf.ln()

    for i, f in enumerate(scan['findings']):
        shade = i % 2 == 0
        bg = pdf.C_STRIPE if shade else pdf.C_WHITE
        pdf.set_fill_color(*bg)
        sc = status_color_map.get(f['status'], pdf.C_MUTED)
        row_y = pdf.get_y()

        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*pdf.C_TEXT)
        pdf.cell(32, 6.5, pdf_clean(f"  {f['category']}"), fill=True)
        pdf.cell(58, 6.5, pdf_clean(f"  {f['name']}"), fill=True)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*sc)
        pdf.cell(20, 6.5, pdf_clean(f"  {f['status']}"), fill=True)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*pdf.C_TEXT)
        # Full details - wrap safely
        details = f['details']
        if len(details) > 62:
            details = details[:62] + "..."
        pdf.cell(70, 6.5, pdf_clean(f"  {details}"), fill=True, new_x="LMARGIN", new_y="NEXT")

        # Recommendation
        if f.get('recommendation'):
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(160, 110, 0)
            pdf.set_x(15)
            pdf.cell(32, 5, "", fill=True)
            pdf.cell(0, 5, pdf_clean(f"  -> Recommendation: {f['recommendation']}"), fill=True, new_x="LMARGIN", new_y="NEXT")

    # Consolidated recommendations
    recs = [(f['name'], f['recommendation']) for f in scan['findings'] if f.get('recommendation')]
    if recs:
        pdf.ln(6)
        pdf.section_header("Recommendations Summary")
        pdf.set_font("Helvetica", "", 8.5)
        for j, (name, rec) in enumerate(recs):
            shade = j % 2 == 0
            bg = pdf.C_STRIPE if shade else pdf.C_WHITE
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*pdf.C_AMBER)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(60, 6, pdf_clean(f"  {name}"), fill=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*pdf.C_TEXT)
            rec_disp = rec if len(rec) <= 100 else rec[:100] + "..."
            pdf.cell(0, 6, pdf_clean(f"  {rec_disp}"), fill=True, new_x="LMARGIN", new_y="NEXT")

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

@app.route("/")
def index():
    return jsonify({
        "status": "running",
        "message": "SysMon backend active"
    })


@app.route("/api/metrics")
def metrics():
    data = get_system_metrics()
    # Save a lightweight snapshot to the history buffer
    history_buffer.append({
        "timestamp": data["timestamp"],
        "cpu": data["cpu"]["usage_percent"],
        "ram": data["memory"]["percent"],
        "net_sent_mb": data["network"]["bytes_sent_mb"],
        "net_recv_mb": data["network"]["bytes_recv_mb"],
        "processes": data["processes"],
    })
    return jsonify(data)


@app.route("/api/history")
def history():
    """Return the in-memory history buffer as a JSON list."""
    return jsonify(list(history_buffer))


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


def main():
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()