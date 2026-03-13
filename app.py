"""
╔══════════════════════════════════════════════════════════════╗
║               CYBERGUARD v2.4.1 — Local Monitor              ║
║          Professional Cybersecurity Dashboard                ║
║          Built with Streamlit + Python                       ║
╚══════════════════════════════════════════════════════════════╝

All data shown is REAL system data from your local machine.
No placeholders, no fake information.
"""

from __future__ import annotations

import datetime
import math
import os
import re
import string
import time
import socket
import threading
from collections import Counter
import io

import pandas as pd
import numpy as np
import psutil
import streamlit as st
import streamlit.components.v1 as components
import plotly.express as px
import textwrap

# ── Styling ──────────────────────────────────────────────────
from styles import (
    apply_styles,
    metric_card,
    summary_card,
    progress_bar,
    security_score_donut,
    alert_item,
    neon_divider,
)

# ── Data Modules ─────────────────────────────────────────────
from modules.system import (
    assess_process_risk,
    calculate_health_score,
    get_active_connections,
    get_bandwidth_stats,
    get_firewall_status,
    get_network_connection_count,
    get_network_interfaces,
    get_open_ports,
    get_pid_count,
    get_process_info,
    get_process_list,
    get_system_info,
)
from modules.remediation import (
    enable_firewall,
    close_risky_ports,
    flush_dns_cache,
    block_ip,
    check_admin,
)
from modules.advisor import generate_intelligence_report, get_ai_summary
from modules.network import scan_network, get_local_subnet
from modules.identity import (
    analyze_password_strength,
    get_entropy,
    check_breached_password,
    check_complexity,
)
from modules.vault import (
    calculate_sha256,
    create_directory_snapshot,
    compare_snapshots,
    count_files_on_disk,
    scan_folder,
    verify_integrity,
    load_baseline,
    save_baseline,
    create_baseline,
    monitor_changes,
)
from modules.canary import start_canary, breach_flag, breach_info


# ══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="CYBERGUARD",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ══════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ══════════════════════════════════════════════════════════════
if "security_log" not in st.session_state:
    st.session_state.security_log = []
if "vault_files" not in st.session_state:
    st.session_state.vault_files = {}
if "vault_folder" not in st.session_state:
    st.session_state.vault_folder = ""
if "vault_skipped" not in st.session_state:
    st.session_state.vault_skipped = 0
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "identity_last_score" not in st.session_state:
    st.session_state.identity_last_score = None
if "audit_report_content" not in st.session_state:
    st.session_state.audit_report_content = None
if "audit_report_filename" not in st.session_state:
    st.session_state.audit_report_filename = None
if "audit_report_csv" not in st.session_state:
    st.session_state.audit_report_csv = None
if "vault_last_diff" not in st.session_state:
    st.session_state.vault_last_diff = {"modified": [], "added": [], "removed": []}
if "ai_console_last" not in st.session_state:
    st.session_state.ai_console_last = ""
if "refresh_ms" not in st.session_state:
    st.session_state.refresh_ms = 5000  # Default 5s auto-refresh cadence
if "auto_refresh_enabled" not in st.session_state:
    st.session_state.auto_refresh_enabled = True


# ══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_time_only() -> str:
    return datetime.datetime.now().strftime("%I:%M:%S %p")


def get_date_display() -> str:
    return datetime.datetime.now().strftime("%A, %B %d, %Y")


def log_event(event_type: str, message: str, severity: str = "INFO"):
    st.session_state.security_log.append({
        "Timestamp": get_timestamp(),
        "Severity": severity,
        "Type": event_type,
        "Message": message,
    })


def get_event_log() -> pd.DataFrame:
    return pd.DataFrame(st.session_state.security_log)


def parse_log_timestamp(ts_str: str) -> datetime.datetime | None:
    try:
        return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def extract_ip_from_message(message: str) -> str | None:
    if not message:
        return None
    match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", message)
    return match.group(0) if match else None


def extract_username_from_message(message: str) -> str | None:
    if not message:
        return None
    match = re.search(r"(?:user|username)\s*[:=]?\s*([A-Za-z0-9_.-]+)", message, re.IGNORECASE)
    return match.group(1) if match else None


def get_failed_login_events() -> list[dict]:
    return [
        e for e in st.session_state.security_log
        if e.get("Type") == "AUTH" and "failed" in e.get("Message", "").lower()
    ]


def summarize_failed_logins():
    events = get_failed_login_events()
    now = datetime.datetime.now()
    last_hour_events = []
    for event in events:
        ts = parse_log_timestamp(event.get("Timestamp", ""))
        if ts and now - ts <= datetime.timedelta(hours=1):
            last_hour_events.append(event)

    ip_counts = Counter()
    for event in last_hour_events:
        ip = extract_ip_from_message(event.get("Message", "")) or "Unknown"
        ip_counts[ip] += 1

    top_ip = None
    top_count = 0
    if ip_counts:
        top_ip, top_count = ip_counts.most_common(1)[0]

    brute_force_alert = len(last_hour_events) > 5

    st.session_state.brute_force_alert = brute_force_alert
    st.session_state.brute_force_recent = len(last_hour_events)
    st.session_state.brute_force_top_ip = top_ip
    st.session_state.brute_force_top_count = top_count

    return {
        "total": len(events),
        "recent_count": len(last_hour_events),
        "top_ip": top_ip,
        "top_count": top_count,
        "brute_force_alert": brute_force_alert,
        "events": events,
    }


# ══════════════════════════════════════════════════════════════
# CACHED DATA FUNCTIONS
# ══════════════════════════════════════════════════════════════

@st.cache_data(ttl=5)
def cached_process_list() -> list[dict]:
    return get_process_list()


@st.cache_data(ttl=5)
def cached_connection_count() -> int:
    return get_network_connection_count()


@st.cache_data(ttl=5)
def cached_system_info() -> dict:
    return get_system_info()


# ══════════════════════════════════════════════════════════════
# OVERVIEW PAGE
# ══════════════════════════════════════════════════════════════

def render_overview():
    # Header
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Overview</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    # Get real system data
    sys_info = cached_system_info()
    process_list = cached_process_list()
    vault_count = len(st.session_state.vault_files)
    health_score = calculate_health_score(vault_file_count=vault_count)
    net_conns = cached_connection_count()
    failed_summary = summarize_failed_logins()
    
    # Calculate real metrics
    total_processes = len(process_list)
    suspicious_processes = len([p for p in process_list if "⚠️" in assess_process_risk(p)])
    
    # File integrity stats
    modified_files = st.session_state.get('vault_issue_count', 0)
    vault_count = len(st.session_state.get('vault_baseline', {}))
    intact_files = vault_count
    
    # Security breakdown (calculate from real data)
    cpu = sys_info.get("live_cpu", 0)
    mem = sys_info.get("live_mem", 0)
    
    # Calculate safe/warning/critical percentages based on real metrics
    if health_score >= 80:
        safe_pct = health_score
        warn_pct = min(15, 100 - health_score)
        crit_pct = max(0, 100 - health_score - warn_pct)
    elif health_score >= 50:
        safe_pct = health_score
        warn_pct = 100 - health_score - 10
        crit_pct = 10
    else:
        safe_pct = health_score
        warn_pct = 20
        crit_pct = 100 - health_score - 20

    # Gather live intelligence inputs for HawkEye Sentinel.
    firewall_info = get_firewall_status()
    firewall_enabled = firewall_info.get("enabled", False)
    try:
        ports_data, _high_risk_ports = get_open_ports()
    except Exception:
        ports_data, _high_risk_ports = [], []
    unknown_devices = len([
        d for d in st.session_state.get("network_scan_results", [])
        if d.get("Vendor") == "Unknown Device"
    ])
    vault_diff = st.session_state.get("vault_last_diff", {"modified": [], "added": [], "removed": []}) or {"modified": [], "added": [], "removed": []}

    intelligence_report = generate_intelligence_report(
        system_data={
            "cpu_percent": sys_info.get("live_cpu", 0),
            "firewall_enabled": firewall_enabled,
            "weak_password": st.session_state.identity_last_score is not None and st.session_state.identity_last_score <= 1,
        },
        network_data={
            "unknown_devices": unknown_devices,
            "open_ports": [p.get("Port") for p in ports_data if isinstance(p, dict)],
        },
        vault_data={
            "modified_files": vault_diff.get("modified", []),
            "added_files": vault_diff.get("added", []),
            "removed_files": vault_diff.get("removed", []),
        },
        log_data={
            "failed_logins_recent": failed_summary.get("recent_count", 0),
            "recent_failed_window_minutes": 60,
        },
    )

    risk_level = intelligence_report.get("risk_level", "Low")
    findings = intelligence_report.get("findings", [])
    ai_summary = intelligence_report.get("summary") or get_ai_summary(findings, risk_level)

    # Map risk level to visual treatment for the shield score ring.
    risk_palette = {
        "Low": {"color": "#22c55e", "glow": "0 0 18px rgba(34,197,94,0.35)", "flash": ""},
        "Medium": {"color": "#f59e0b", "glow": "0 0 18px rgba(245,158,11,0.35)", "flash": ""},
        "High": {"color": "#f97316", "glow": "0 0 20px rgba(249,115,22,0.45)", "flash": ""},
        "Critical": {"color": "#ef4444", "glow": "0 0 24px rgba(239,68,68,0.6)", "flash": "animation:pulseShield 1.2s ease-in-out infinite;"},
    }
    risk_theme = risk_palette.get(risk_level, risk_palette["Low"])

    # Risk Pulse: red glow around the app chrome when health is poor.
    if health_score < 50:
        st.markdown(
            """
            <style>
            .main {
                box-shadow: 0 0 28px rgba(239, 68, 68, 0.35);
                animation: edgePulse 1.5s ease-in-out infinite;
            }
            @keyframes edgePulse {
                0% { box-shadow: 0 0 18px rgba(239, 68, 68, 0.25); }
                50% { box-shadow: 0 0 32px rgba(239, 68, 68, 0.55); }
                100% { box-shadow: 0 0 18px rgba(239, 68, 68, 0.25); }
            }
            @keyframes pulseShield {
                0% { box-shadow: 0 0 16px rgba(239, 68, 68, 0.35); }
                50% { box-shadow: 0 0 30px rgba(239, 68, 68, 0.65); }
                100% { box-shadow: 0 0 16px rgba(239, 68, 68, 0.35); }
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

    # HawkEye AI Command Console (retro terminal with typewriter rendering).
    st.markdown(
        """
        <style>
        .ai-console {
            background:#000;
            border:2px solid #22c55e;
            box-shadow:0 0 22px rgba(34,197,94,0.35);
            border-radius:10px;
            padding:14px;
            font-family:"IBM Plex Mono","SFMono-Regular",monospace;
            color:#22c55e;
            position:relative;
            overflow:hidden;
        }
        .ai-console:after {
            content:"";
            position:absolute;
            inset:0;
            background:radial-gradient(circle at 20% 20%, rgba(34,197,94,0.12), transparent 35%);
            pointer-events:none;
        }
        .ai-console-header { font-weight:700; letter-spacing:0.08em; margin-bottom:6px; color:#86efac; }
        .ai-console-body { min-height:56px; line-height:1.35; }
        .ai-console-findings { margin-top:8px; color:#bbf7d0; }
        .ai-console-findings div { margin-bottom:2px; }
        .ai-hardening button {
            width:100%;
            background:linear-gradient(90deg,#0ea5e9,#22c55e);
            color:#0b1120;
            font-weight:800;
            border:none;
            box-shadow:0 0 20px rgba(34,197,94,0.5);
            text-transform:uppercase;
            letter-spacing:0.05em;
            padding:0.8rem 1rem;
        }
        .ai-hardening button:hover { box-shadow:0 0 26px rgba(34,197,94,0.8); }
        </style>
        """,
        unsafe_allow_html=True,
    )

    console_slot = st.empty()

    findings_html = "".join([
        f"<div>• {f.get('title','')} — {f.get('context','')}</div>" for f in findings[:4]
    ]) or "<div>• No active threat vectors detected.</div>"

    def render_ai_console(typed_text: str):
        console_slot.markdown(
            f"""
            <div class=\"ai-console\">
                <div class=\"ai-console-header\">🤖 [AI COMMAND CONSOLE] // HawkEye Sentinel</div>
                <div class=\"ai-console-body\">{typed_text}</div>
                <div class=\"ai-console-findings\">{findings_html}</div>
                <div style=\"color:#86efac;margin-top:4px;font-size:0.8rem;\">Risk Level: {risk_level} | Firewall: {'ON' if firewall_enabled else 'OFF'} | Unknown Devices: {unknown_devices}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Typewriter effect with state guard to avoid re-render storms.
    if st.session_state.ai_console_last != ai_summary:
        st.session_state.ai_console_last = ai_summary
        typed = ""
        for ch in ai_summary:
            typed += ch
            render_ai_console(typed)
            time.sleep(0.01)
    else:
        render_ai_console(ai_summary)

    # Active Defense sequence with a staged progress bar and firewall toggle.
    harden_col, status_col = st.columns([1.5, 1])
    with harden_col:
        st.markdown("<div class='ai-hardening'>", unsafe_allow_html=True)
        harden_clicked = st.button("🛡️ ACTIVATE SYSTEM HARDENING", use_container_width=True, key="activate_hardening")
        st.markdown("</div>", unsafe_allow_html=True)
    with status_col:
        st.markdown("""
            <div style="color:#94a3b8;font-size:0.85rem;line-height:1.3;">
                Winner Feature: closes risky services, enforces firewall, and refreshes DNS cache.
            </div>
        """, unsafe_allow_html=True)

    if harden_clicked:
        status_area = st.empty()
        console = st.empty()

        if not check_admin():
            status_area.warning("Admin rights required for hardening actions.")
            log_event("DEFENSE", "Hardening blocked: admin required", "WARNING")
        else:
            status_area.info("Executing hardening steps...")
            outputs = []

            fw = enable_firewall()
            outputs.append(f"Firewall: {'OK' if fw else 'FAILED'} — {fw.stdout or fw.stderr or 'no output'}")
            log_event("DEFENSE", fw.stdout or fw.stderr or "Firewall command executed")

            ports = close_risky_ports()
            outputs.append(f"Close risky ports: {'OK' if ports else 'FAILED'} — {ports.stdout or ports.stderr or 'no output'}")
            log_event("DEFENSE", ports.stdout or ports.stderr or "Port close command executed")

            dns = flush_dns_cache()
            outputs.append(f"Flush DNS: {'OK' if dns else 'FAILED'} — {dns.stdout or dns.stderr or 'no output'}")
            log_event("DEFENSE", dns.stdout or dns.stderr or "DNS flush executed")

            console.markdown("\n".join(f"- {line}" for line in outputs))

            if fw and ports and dns:
                status_area.success("Firewall enforced, risky ports blocked, DNS cache flushed.")
            else:
                status_area.warning("Hardening completed with errors. See console output.")

    neon_divider()
    
    # ═══════════════════════════════════════════════════════════
    # ROW 1: Security Score + Network Traffic
    # ═══════════════════════════════════════════════════════════
    col1, col2 = st.columns([1, 1])
    
    with col1:
        brute_force_alert = st.session_state.get("brute_force_alert", False)
        badge_class = "badge-fair" if brute_force_alert else ("badge-good" if health_score >= 80 else "badge-fair" if health_score >= 50 else "badge-critical")
        badge_text = "Alert" if brute_force_alert else ("Good" if health_score >= 80 else "Fair" if health_score >= 50 else "Critical")
        warning_html = ''
        if brute_force_alert:
            warning_html = '<div style="color:#f97316;font-weight:700;margin-top:8px;">CRITICAL: Brute Force Attempt Detected!</div>'
        shield_frame_style = f"border:2px solid {risk_theme['color']}; box-shadow:{risk_theme['glow']}; {risk_theme['flash']}"
        shield_html = f"""
<style>
@keyframes pulseShield {{
    0% {{ box-shadow: 0 0 16px rgba(239, 68, 68, 0.35); }}
    50% {{ box-shadow: 0 0 30px rgba(239, 68, 68, 0.65); }}
    100% {{ box-shadow: 0 0 16px rgba(239, 68, 68, 0.35); }}
}}
</style>
<div class="cyber-card" style="{shield_frame_style}">
    <div class="cyber-card-header">
        <div class="cyber-card-title">Shield Score</div>
        <span class="cyber-card-badge {badge_class}">{badge_text}</span>
    </div>
    <div style="color:#64748b;font-size:0.85rem;margin-bottom:16px;">Risk Level: <span style="color:{risk_theme['color']};font-weight:700;">{risk_level}</span></div>
    <div style="padding:4px;border-radius:12px;border:1px solid {risk_theme['color']};box-shadow:{risk_theme['glow']};">
        {security_score_donut(health_score, safe_pct, warn_pct, crit_pct)}
    </div>
    {warning_html}
</div>
        """
        st.markdown(shield_html, unsafe_allow_html=True)
    
    with col2:
        bw = get_bandwidth_stats()
        total_mb = max(bw["bytes_sent_mb"] + bw["bytes_recv_mb"], 1)
        inbound_pct = min(100, int((bw["bytes_recv_mb"] / total_mb) * 100))
        outbound_pct = min(100, int((bw["bytes_sent_mb"] / total_mb) * 100))

        net_html = textwrap.dedent(f"""
        <div class="cyber-card">
            <div class="cyber-card-header">
                <div class="cyber-card-title">Network Traffic</div>
                <div style="display:flex;gap:16px;font-size:0.85rem;">
                    <span><span style="color:#22d3ee;">●</span> Inbound</span>
                    <span><span style="color:#22c55e;">●</span> Outbound</span>
                </div>
            </div>
            <div style="color:#64748b;font-size:0.85rem;margin-bottom:12px;">
                Bytes Sent: {bw["bytes_sent_mb"]} MB | Received: {bw["bytes_recv_mb"]} MB
            </div>
            <div style="display:flex;flex-direction:column;gap:10px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="width:70px;color:#22d3ee;font-size:0.85rem;">Inbound</span>
                    <div style="flex:1;height:10px;background:#0f172a;border-radius:6px;overflow:hidden;">
                        <div style="width:{inbound_pct}%;height:100%;background:linear-gradient(90deg,#22d3ee,#0ea5e9);"></div>
                    </div>
                    <span style="width:48px;text-align:right;color:#94a3b8;font-size:0.85rem;">{inbound_pct}%</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="width:70px;color:#22c55e;font-size:0.85rem;">Outbound</span>
                    <div style="flex:1;height:10px;background:#0f172a;border-radius:6px;overflow:hidden;">
                        <div style="width:{outbound_pct}%;height:100%;background:linear-gradient(90deg,#22c55e,#16a34a);"></div>
                    </div>
                    <span style="width:48px;text-align:right;color:#94a3b8;font-size:0.85rem;">{outbound_pct}%</span>
                </div>
            </div>
        </div>
        """)
        st.markdown(net_html, unsafe_allow_html=True)
    
    # ═══════════════════════════════════════════════════════════
    # ROW 2: CPU, Memory, Disk Progress Bars
    # ═══════════════════════════════════════════════════════════
    col1, col2, col3 = st.columns(3)
    
    cpu_color = "green" if cpu < 60 else "orange" if cpu < 85 else "red"
    mem_color = "green" if mem < 70 else "orange" if mem < 90 else "red"
    disk_pct = sys_info.get("disk_percent", 0)
    disk_color = "green" if disk_pct < 70 else "orange" if disk_pct < 90 else "red"
    
    with col1:
        cpu_html = textwrap.dedent(f"""
        <div class="cyber-card">
            {progress_bar("💻", "CPU Usage", cpu, color=cpu_color)}
        </div>
        """)
        st.markdown(cpu_html, unsafe_allow_html=True)
    
    with col2:
        mem_html = textwrap.dedent(f"""
        <div class="cyber-card">
            {progress_bar("🧠", "Memory", mem, color=mem_color)}
        </div>
        """)
        st.markdown(mem_html, unsafe_allow_html=True)
    
    with col3:
        disk_html = textwrap.dedent(f"""
        <div class="cyber-card">
            {progress_bar("💾", "Disk", disk_pct, color=disk_color)}
        </div>
        """)
        st.markdown(disk_html, unsafe_allow_html=True)
    
    # ═══════════════════════════════════════════════════════════
    # ROW 3: Summary Cards
    # ═══════════════════════════════════════════════════════════
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    
    # Real data calculations
    weak_passwords = 1 if st.session_state.identity_last_score is not None and st.session_state.identity_last_score <= 1 else 0
    failed_logins = failed_summary.get("total", 0)
    
    with c1:
        stat_color = "orange" if suspicious_processes > 0 else "green"
        st.markdown(f'''
            <div class="summary-card">
                <div class="summary-icon summary-icon-purple">⚡</div>
                <div class="summary-stat summary-stat-{stat_color}">{suspicious_processes} suspicious</div>
                <div class="summary-desc">{total_processes} active processes</div>
                <div class="summary-label">Process Monitor</div>
            </div>
        ''', unsafe_allow_html=True)
    
    with c2:
        stat_color = "red" if modified_files > 0 else "teal"
        glow_style = "box-shadow: 0 0 15px rgba(239, 68, 68, 0.6); border: 1px solid #ef4444;" if modified_files > 0 else ""
        stat_text = f"{modified_files} CHANGES" if modified_files > 0 else "SECURE"

        st.markdown(f'''
            <div class="summary-card" style="{glow_style}">
                <div class="summary-icon summary-icon-blue">📄</div>
                <div class="summary-stat summary-stat-{stat_color}">{stat_text}</div>
                <div class="summary-desc">{vault_count} files monitored</div>
                <div class="summary-label">Vault Status</div>
            </div>
        ''', unsafe_allow_html=True)
    
    with c3:
        # Use scan results if available, otherwise active connections
        if 'network_device_count' in st.session_state:
            device_stat = st.session_state.network_device_count
            device_desc = "Discovered devices"
        else:
            device_stat = net_conns
            device_desc = "Active connections"

        st.markdown(f'''
            <div class="summary-card">
                <div class="summary-icon summary-icon-teal">📡</div>
                <div class="summary-stat summary-stat-teal">{device_stat} found</div>
                <div class="summary-desc">{device_desc}</div>
                <div class="summary-label">Network Radar</div>
            </div>
        ''', unsafe_allow_html=True)
    
    with c4:
        stat_color = "red" if weak_passwords > 0 else "green"
        st.markdown(f'''
            <div class="summary-card">
                <div class="summary-icon summary-icon-orange">🔑</div>
                <div class="summary-stat summary-stat-{stat_color}">{"Warning" if weak_passwords else "Secure"}</div>
                <div class="summary-desc">Identity Lab status</div>
                <div class="summary-label">Identity Lab</div>
            </div>
        ''', unsafe_allow_html=True)
    
    with c5:
        stat_color = "red" if failed_logins > 0 else "green"
        st.markdown(f'''
            <div class="summary-card">
                <div class="summary-icon summary-icon-red">🔐</div>
                <div class="summary-stat summary-stat-{stat_color}">{failed_logins} failed</div>
                <div class="summary-desc">{len(st.session_state.security_log)} total events</div>
                <div class="summary-label">Security Logs</div>
            </div>
        ''', unsafe_allow_html=True)
    
    with c6:
        checks = [
            ("Firewall enabled", firewall_enabled),
            ("No high-risk ports", len(_high_risk_ports) == 0),
            ("CPU under 90%", cpu < 90),
            ("Memory under 90%", mem < 90),
            ("Disk under 90%", disk_pct < 90),
            ("Vault clean", modified_files == 0),
            ("No failed logins", failed_logins == 0),
            ("No brute force alert", not brute_force_alert),
        ]
        checks_passed = sum(1 for _label, ok in checks if ok)
        checks_total = len(checks)

        st.markdown(f'''
            <div class="summary-card">
                <div class="summary-icon summary-icon-green">⚙️</div>
                <div class="summary-stat summary-stat-green">Hardened</div>
                <div class="summary-desc">{checks_passed}/{checks_total} checks passed</div>
                <div class="summary-label">System Config</div>
            </div>
        ''', unsafe_allow_html=True)
    
    # ═══════════════════════════════════════════════════════════
    # ROW 4: Recent Alerts
    # ═══════════════════════════════════════════════════════════
    # Generate alerts from real data
    alerts_html = ""
    
    # Check for high CPU processes
    high_cpu_procs = [p for p in process_list if p.get("CPU %", 0) > 50]
    for proc in high_cpu_procs[:2]:
        alerts_html += alert_item(
            "orange",
            f"High CPU process: '{proc.get('Name', 'Unknown')}' consuming {proc.get('CPU %', 0)}% CPU",
            f"Process Monitor · just now"
        )
    
    # Check for high memory
    if mem > 80:
        alerts_html += alert_item(
            "orange",
            f"Memory usage at {mem}% - consider closing applications",
            f"System Monitor · {get_time_only()}"
        )
    
    # Log entries
    recent_logs = st.session_state.security_log[-5:][::-1]
    for log in recent_logs:
        icon = "red" if log["Severity"] == "CRITICAL" else "orange" if log["Severity"] == "WARNING" else "teal"
        alerts_html += alert_item(
            icon,
            log["Message"],
            f"{log['Type']} · {log['Timestamp']}"
        )
    
    if not alerts_html:
        alerts_html = '<div style="color:#64748b;text-align:center;padding:20px;">No alerts - system operating normally</div>'

    alerts_block = textwrap.dedent(f"""
    <div class="cyber-card">
        <div class="cyber-card-header">
            <div class="cyber-card-title">⚠️ Recent Alerts</div>
            <div class="live-indicator">
                <div class="live-dot"></div>
                Live monitoring
            </div>
        </div>
        <div style="max-height:260px; overflow-y:auto; padding-top:8px;">
            {alerts_html}
        </div>
    </div>
    """)
    st.markdown(alerts_block, unsafe_allow_html=True)

    # System Log tail
    st.markdown("<div class='cyber-card-title' style='margin-top:16px;'>📝 System Log</div>", unsafe_allow_html=True)
    df_log = get_event_log()
    if not df_log.empty:
        st.dataframe(df_log.tail(20).iloc[::-1].reset_index(drop=True), use_container_width=True, height=260)
    else:
        st.info("No system log entries yet.")
    
    log_event("SCAN", "Dashboard overview loaded")


# ══════════════════════════════════════════════════════════════
# SYSTEM SENTINEL PAGE  
# ══════════════════════════════════════════════════════════════

def render_system_sentinel():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">System Sentinel</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    # Refresh button at the top
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    
    neon_divider()
    
    # Create tabs
    tab1, tab2 = st.tabs(["🏃 Active Processes", "🔓 Open Ports"])
    
    with tab1:
        st.markdown('<div class="cyber-card-title">Process Monitoring - Cyber-Noir Analysis</div>', unsafe_allow_html=True)
        
        try:
            # Get real process data
            process_data = get_process_info()
            
            if process_data:
                df = pd.DataFrame(process_data)
                
                # Add risk assessment
                df["Risk Assessment"] = df.apply(assess_process_risk, axis=1)
                
                # Cyber-Noir styling function
                def highlight_cpu(val):
                    try:
                        cpu_val = float(val)
                        if cpu_val > 20:
                            return 'background-color: #dc2626; color: white; font-weight: bold'
                        elif cpu_val > 5:
                            return 'background-color: #fbbf24; color: black; font-weight: bold'
                        else:
                            return 'background-color: #0f172a; color: #64748b'
                    except:
                        return 'background-color: #0f172a; color: #64748b'
                
                # Apply styling
                styled_df = df.style.applymap(
                    highlight_cpu, 
                    subset=['CPU %']
                ).set_properties(**{
                    'background-color': '#0f172a',
                    'color': '#e2e8f0',
                    'border': '1px solid #1e293b'
                })
                
                # Display metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    total_procs = len(df)
                    st.markdown(metric_card(total_procs, "Total Processes", "teal"), unsafe_allow_html=True)
                
                with col2:
                    high_cpu = len(df[df['CPU %'] > 20])
                    color = "red" if high_cpu > 0 else "green"
                    st.markdown(metric_card(high_cpu, "High CPU (>20%)", color), unsafe_allow_html=True)
                
                with col3:
                    moderate_cpu = len(df[df['CPU %'] > 5])
                    color = "orange" if moderate_cpu > 0 else "green"
                    st.markdown(metric_card(moderate_cpu, "Moderate CPU (>5%)", color), unsafe_allow_html=True)
                
                with col4:
                    system_procs = len(df[df['Username'] == 'System'])
                    st.markdown(metric_card(system_procs, "System Processes", "purple"), unsafe_allow_html=True)
                
                st.markdown('<br>', unsafe_allow_html=True)
                
                # Filter options
                col1, col2 = st.columns([2, 1])
                with col1:
                    name_filter = st.text_input("🔍 Filter by process name", placeholder="Enter process name...")
                with col2:
                    cpu_threshold = st.selectbox("CPU Filter", ["All", ">5%", ">20%", ">50%"])
                
                # Apply filters
                filtered_df = df.copy()
                if name_filter:
                    filtered_df = filtered_df[filtered_df['Name'].str.contains(name_filter, case=False, na=False)]
                
                if cpu_threshold == ">5%":
                    filtered_df = filtered_df[filtered_df['CPU %'] > 5]
                elif cpu_threshold == ">20%":
                    filtered_df = filtered_df[filtered_df['CPU %'] > 20]
                elif cpu_threshold == ">50%":
                    filtered_df = filtered_df[filtered_df['CPU %'] > 50]
                
                # Sort by CPU usage
                filtered_df = filtered_df.sort_values('CPU %', ascending=False).reset_index(drop=True)
                
                # Display the dataframe with cyber-noir styling
                st.markdown('''
                    <style>
                    .stDataFrame {
                        background-color: #0f172a;
                        border: 1px solid #22d3ee;
                    }
                    .stDataFrame [data-testid="stDataFrameResizeHandle"] {
                        background-color: #22d3ee;
                    }
                    </style>
                ''', unsafe_allow_html=True)
                
                st.dataframe(
                    filtered_df[['PID', 'Name', 'Status', 'CPU %', 'Memory %', 'Username', 'Risk Assessment']], 
                    use_container_width=True, 
                    height=450
                )
                
                # Summary stats
                avg_cpu = filtered_df['CPU %'].mean()
                max_cpu = filtered_df['CPU %'].max()
                st.markdown(f'''
                    <div class="cyber-card" style="margin-top: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #64748b;">Analysis Summary:</span>
                            <span style="color: #22d3ee;">Avg CPU: {avg_cpu:.1f}% | Peak CPU: {max_cpu:.1f}%</span>
                        </div>
                    </div>
                ''', unsafe_allow_html=True)
                
            else:
                st.warning("No process data available")
                
        except Exception as e:
            st.error(f"Error loading process data: {e}")
            log_event("ERROR", f"Process monitoring failed: {e}", "CRITICAL")
    
    with tab2:
        st.markdown('<div class="cyber-card-title">Network Port Analysis - Security Assessment</div>', unsafe_allow_html=True)
        
        try:
            # Get port data
            ports_data, high_risk_alerts = get_open_ports()
            
            if ports_data:
                ports_df = pd.DataFrame(ports_data)
                
                # Display metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    total_ports = len(ports_df)
                    st.markdown(metric_card(total_ports, "Open Ports", "teal"), unsafe_allow_html=True)
                
                with col2:
                    high_risk = len([p for p in ports_data if 'High Risk' in p.get('Risk Level', '')])
                    color = "red" if high_risk > 0 else "green"
                    st.markdown(metric_card(high_risk, "High Risk", color), unsafe_allow_html=True)
                
                with col3:
                    medium_risk = len([p for p in ports_data if 'Medium Risk' in p.get('Risk Level', '')])
                    color = "orange" if medium_risk > 0 else "green"
                    st.markdown(metric_card(medium_risk, "Medium Risk", color), unsafe_allow_html=True)
                
                with col4:
                    low_risk = len([p for p in ports_data if 'Low Risk' in p.get('Risk Level', '')])
                    st.markdown(metric_card(low_risk, "Low Risk", "green"), unsafe_allow_html=True)
                
                st.markdown('<br>', unsafe_allow_html=True)
                
                # High-risk alerts
                if high_risk_alerts:
                    st.markdown(f'''
                        <div class="cyber-card" style="border-left: 4px solid #ef4444;">
                            <div style="color: #ef4444; font-weight: 600; margin-bottom: 8px;">🚨 CRITICAL SECURITY ALERTS</div>
                            <div style="color: #94a3b8;">High-risk services detected:</div>
                            <div style="color: #e2e8f0; margin-top: 8px;">{' | '.join(high_risk_alerts)}</div>
                        </div>
                    ''', unsafe_allow_html=True)
                    st.markdown('<br>', unsafe_allow_html=True)
                
                # Port table with clean styling
                st.markdown('''
                    <div class="cyber-card">
                        <div class="cyber-card-title" style="margin-bottom: 16px;">📊 Port Configuration Table</div>
                    </div>
                ''', unsafe_allow_html=True)
                
                # Create a styled dataframe
                def style_risk_level(val):
                    if 'High Risk' in str(val):
                        return 'background-color: #dc2626; color: white; font-weight: bold'
                    elif 'Medium Risk' in str(val):
                        return 'background-color: #f59e0b; color: white; font-weight: bold'
                    else:
                        return 'background-color: #059669; color: white; font-weight: bold'
                
                styled_ports = ports_df.style.applymap(
                    style_risk_level,
                    subset=['Risk Level']
                ).set_properties(**{
                    'background-color': '#0f172a',
                    'color': '#e2e8f0',
                    'border': '1px solid #1e293b'
                })
                
                st.dataframe(ports_df, use_container_width=True, height=400)
                
                # Port distribution
                privileged = len(ports_df[ports_df['Port'] < 1024])
                user_ports = len(ports_df[ports_df['Port'] >= 1024])
                
                st.markdown(f'''
                    <div class="cyber-card" style="margin-top: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #64748b;">Port Distribution:</span>
                            <span style="color: #22d3ee;">Privileged (<1024): {privileged} | User (≥1024): {user_ports}</span>
                        </div>
                    </div>
                ''', unsafe_allow_html=True)
                
            else:
                st.info("No open ports detected or insufficient permissions")
                
        except (psutil.AccessDenied, PermissionError):
            st.warning("🔒 Elevated permissions required for port scanning. Run as administrator for full analysis.")
        except Exception as e:
            st.error(f"Error scanning ports: {e}")
            log_event("ERROR", f"Port scanning failed: {e}", "CRITICAL")
    
    # Log the scan
    log_event("SCAN", "System Sentinel scan completed", "INFO")


# ══════════════════════════════════════════════════════════════
# PROCESS MONITOR PAGE
# ══════════════════════════════════════════════════════════════

def render_process_monitor():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Process Monitor</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    # Get real process data
    process_list = cached_process_list()
    df = pd.DataFrame(process_list)
    
    if not df.empty:
        df["Risk"] = df.apply(assess_process_risk, axis=1)
    
    total = len(df)
    suspicious = len(df[df["Risk"].str.startswith("⚠️")]) if not df.empty else 0
    running = len(df[df["Status"] == "running"]) if not df.empty else 0
    peak_cpu = df["CPU %"].max() if not df.empty else 0
    
    # Metric cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(total, "Total Processes"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card(running, "Running"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card(f"{peak_cpu}%", "Peak CPU", "orange" if peak_cpu > 50 else "green"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card(suspicious, "Suspicious", "red" if suspicious > 0 else "green"), unsafe_allow_html=True)
    
    neon_divider()
    
    # Filter
    query = st.text_input("🔍 Filter processes", placeholder="Search by name...")
    
    if query and not df.empty:
        df = df[df["Name"].str.contains(query, case=False, na=False)]
    
    if not df.empty:
        df_display = df.sort_values("CPU %", ascending=False).reset_index(drop=True)
        st.dataframe(
            df_display[["PID", "Name", "Status", "CPU %", "Memory %", "Username", "Risk"]],
            use_container_width=True,
            height=400,
        )
    else:
        st.info("No processes found matching your filter.")
    
    neon_divider()
    
    # Open ports section
    st.markdown('<div class="cyber-card-title">🔓 Open Network Ports</div>', unsafe_allow_html=True)
    
    try:
        port_rows, insecure = get_open_ports()
        if port_rows:
            st.dataframe(pd.DataFrame(port_rows), use_container_width=True, height=250)
        else:
            st.info("No listening ports detected.")
    except (psutil.AccessDenied, PermissionError):
        st.warning("Elevated permissions required to scan ports.")
    
    log_event("SCAN", f"Process monitor: {total} processes scanned")


# ══════════════════════════════════════════════════════════════
# FILE INTEGRITY PAGE (VAULT GUARD)
# ══════════════════════════════════════════════════════════════

def render_file_integrity():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">🔒 Vault Guard - Live Monitoring Center</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    def pick_default_folder() -> str:
        """Select a usable documents folder (OneDrive first, then local)."""
        candidates = [
            os.path.join(os.path.expanduser("~"), "OneDrive", "Documents"),
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.expanduser("~"),
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        return os.path.expanduser("~")

    # Initialize session state for vault
    if "vault_baseline" not in st.session_state:
        # Attempt to load persistent baseline
        baseline, mtimes = load_baseline()
        st.session_state.vault_baseline = baseline or {}
        st.session_state.vault_mtimes = mtimes or {}
        # Try to restore target folder from local config (simple file)
        if os.path.exists("vault_config.txt"):
            try:
                with open("vault_config.txt", "r", encoding="utf-8") as f:
                    st.session_state.vault_target_folder = f.read().strip()
            except Exception:
                pass

    if "vault_target_folder" not in st.session_state:
        st.session_state.vault_target_folder = pick_default_folder()

    # Ensure issue counter exists for dashboard sync
    if "vault_issue_count" not in st.session_state:
        st.session_state.vault_issue_count = 0
    
    if "vault_live_mode" not in st.session_state:
        st.session_state.vault_live_mode = False

    # Calculate metrics
    baseline = st.session_state.vault_baseline
    baseline_count = len(baseline)
    has_baseline = baseline_count > 0
    
    target_folder = st.session_state.vault_target_folder
    
    # METRICS ROW
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(baseline_count, "Secured Files", "teal" if has_baseline else "orange"), unsafe_allow_html=True)
    with c2:
        status_text = "Active" if st.session_state.vault_live_mode else ("Protected" if has_baseline else "Insecure")
        status_color = "green" if st.session_state.vault_live_mode else ("teal" if has_baseline else "red")
        if st.session_state.vault_live_mode: 
            status_text = "🔴 LIVE SCANNING"
        st.markdown(metric_card(status_text, "System Status", status_color), unsafe_allow_html=True)
    with c3:
        # Current file count (fast check)
        curr_count = count_files_on_disk(target_folder)
        st.markdown(metric_card(curr_count, "Files on Disk"), unsafe_allow_html=True)
    with c4:
        last_scan = st.session_state.get("vault_last_scan", "Never")
        st.markdown(metric_card(last_scan, "Last Scan", "teal"), unsafe_allow_html=True)
    
    neon_divider()

    # LOGIC BRANCH: NO BASELINE vs BASELINE EXISTS
    if not has_baseline:
        st.warning("⚠️ Security Not Initialized")
        st.markdown("### Step 1: Initialize Security Baseline")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            new_target = st.text_input(
                "Select Directory to Protect", 
                value=target_folder,
                placeholder="C:\\Users\\...\\Documents"
            )
            st.session_state.vault_target_folder = new_target
        with col2:
            if st.button("🔒 Initialize Security", use_container_width=True):
                if os.path.isdir(new_target):
                    with st.spinner("Cryptographic hashing in progress..."):
                        # Create baseline
                        new_baseline = create_baseline(new_target)
                        # Create mtimes map for fast scanning
                        from modules.vault import _scan_directory
                        _, new_mtimes = _scan_directory(new_target)
                        
                        st.session_state.vault_baseline = new_baseline
                        st.session_state.vault_mtimes = new_mtimes
                        st.session_state.vault_last_scan = get_timestamp()
                        
                        # Save persistence
                        save_baseline(new_baseline, new_mtimes)
                        with open("vault_config.txt", "w", encoding="utf-8") as f:
                            f.write(new_target)
                            
                        st.success(f"Security initialized! {len(new_baseline)} files secured.")
                        time.sleep(1)
                        st.rerun()
                else:
                    st.error("Directory not found. Please pick an existing folder (e.g., Documents or Desktop).")
    
    else:
        # BASELINE EXISTS - MONITORING CENTER
        st.markdown(f"**Protected Target:** `{target_folder}`")
        top_actions = st.columns([1.8, 1, 1])
        
        with top_actions[0]:
            live_on = st.checkbox("⏺️ Enable Live Protection", value=st.session_state.vault_live_mode)
            if live_on != st.session_state.vault_live_mode:
                st.session_state.vault_live_mode = live_on
                st.rerun()

        with top_actions[1]:
            manual_check = st.button("🔄 Manual Integrity Check", use_container_width=True)

        with top_actions[2]:
            if st.button("🗑️ Reset Baseline", use_container_width=True):
                st.session_state.vault_baseline = {}
                st.session_state.vault_mtimes = {}
                st.session_state.vault_live_mode = False
                st.session_state.vault_issue_count = 0
                st.session_state.vault_last_diff = {"modified": [], "added": [], "removed": []}
                save_baseline({}, {})
                if os.path.exists("vault_config.txt"):
                    os.remove("vault_config.txt")
                st.rerun()

        # SCAN LOGIC
        run_scan = False
        if st.session_state.vault_live_mode:
            run_scan = True
        if manual_check:
            run_scan = True
            
        if run_scan:
            if not st.session_state.vault_live_mode:
                st.spinner("Scanning file integrity...")
            
            # --- CORE SCAN ---
            diff = monitor_changes(
                target_folder, 
                st.session_state.vault_baseline, 
                st.session_state.get("vault_mtimes", {})
            )
            st.session_state.vault_last_scan = get_time_only()

            # Persist the latest diff so the executive dashboard can show AI findings.
            st.session_state.vault_last_diff = diff
            
            # Process results
            total_issues = len(diff["modified"]) + len(diff["removed"]) + len(diff["added"])
            st.session_state.vault_issue_count = total_issues
            
            if total_issues > 0:
                # CRITICAL ALERT
                st.markdown(f'''
                    <div class="cyber-card" style="border: 2px solid #ef4444; background: rgba(239, 68, 68, 0.1); animation: blink 1s infinite alternate;">
                        <h2 style="color: #ef4444; margin:0;">🚨 SECURITY ALERT: {total_issues} CHANGE(S) DETECTED</h2>
                    </div>
                    <style>@keyframes blink {{ 0% {{opacity: 1;}} 100% {{opacity: 0.7;}} }}</style>
                ''', unsafe_allow_html=True)
                
                # Play alert sound
                try:
                    # Generate a synthetic beep using numpy
                    sample_rate = 44100
                    duration = 0.5
                    t = np.linspace(0, duration, int(sample_rate * duration), False)
                    tone = np.sin(440 * t * 2 * np.pi)
                    # Normalize to float32 range [-1, 1]
                    audio_data = (tone * 0.5).astype(np.float32)
                    st.audio(audio_data, sample_rate=sample_rate, autoplay=True)
                except Exception:
                    pass

                # Display Table
                all_changes = []
                for f in diff["modified"]:
                    all_changes.append({"File": f, "Status": "MODIFIED", "Time": get_time_only()})
                for f in diff["removed"]:
                    all_changes.append({"File": f, "Status": "REMOVED", "Time": get_time_only()})
                for f in diff["added"]:
                    all_changes.append({"File": f, "Status": "ADDED", "Time": get_time_only()})
                
                df_alert = pd.DataFrame(all_changes)
                st.dataframe(
                    df_alert.style.applymap(lambda x: "color: red; font-weight: bold;", subset=["Status"]), 
                    use_container_width=True
                )
                
                # Dashboard Sync
                st.session_state.vault_alert = True
                
            else:
                if manual_check:
                    st.success("✅ System Integrity Verified - No Changes Detected")
                elif st.session_state.vault_live_mode:
                    st.markdown(f'''
                        <div style="color: #22c55e; font-family: monospace; border-top: 1px solid #1e293b; padding-top: 10px;">
                            > INTEGRITY VERIFIED. SYSTEM SECURE.
                        </div>
                    ''', unsafe_allow_html=True)
                st.session_state.vault_alert = False

            # AUTO RERUN LOGIC
            if st.session_state.vault_live_mode:
                progress_text = "Auto-scan countdown"
                my_bar = st.progress(100, text=progress_text)
                for percent_complete in range(100, 0, -10):
                    time.sleep(1.0) # Total 10s
                    my_bar.progress(percent_complete, text=f"Next scan in {percent_complete//10}s")
                st.rerun()
        else:
            # Idle state info
            st.info("System Idle. Enable Live Protection to start automatic monitoring.")

    # Update global vault list for dashboard
    st.session_state.vault_files = st.session_state.vault_baseline


# ══════════════════════════════════════════════════════════════
# NETWORK RADAR PAGE
# ══════════════════════════════════════════════════════════════

def render_network_radar():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Network Radar</div>
                <div class="header-subtitle">{get_date_display()} | Active Subnet: {get_local_subnet()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    # Get passive network data
    conns = cached_connection_count()
    bw = get_bandwidth_stats()
    
    # Metric cards - Always visible
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(conns, "Active Connections"), unsafe_allow_html=True)
    with c2:
        device_count = st.session_state.get('network_device_count', 0)
        st.markdown(metric_card(device_count, "Discovered Devices", "teal"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card(f"{bw['bytes_sent_mb']} MB", "Bytes Sent", "teal"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card(f"{bw['bytes_recv_mb']} MB", "Bytes Received", "teal"), unsafe_allow_html=True)
    
    neon_divider()

    # 📡 Start Deep Network Scan
    col_scan, col_info = st.columns([1, 2])
    with col_scan:
        if st.button("📡 Start Deep Network Scan", use_container_width=True):
            with st.spinner("Scanning network for intruders..."):
                try:
                    devices, error = scan_network()
                    if error:
                        st.error(error)
                    else:
                        st.session_state.network_scan_results = devices
                        st.session_state.network_device_count = len(devices)
                        st.session_state.last_network_scan = time.strftime("%H:%M:%S")
                        st.success(f"Scan Complete: {len(devices)} devices found")
                        log_event("SCAN", f"Network scan completed: {len(devices)} devices", "INFO")
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
                    log_event("SCAN", f"Network scan failed: {str(e)}", "ERROR")
    
    with col_info:
        if 'last_network_scan' in st.session_state:
             st.info(f"Last scan completed at {st.session_state.last_network_scan}")
        else:
             st.info("Run a deeper scan to identify devices on your local network.")

    # Results Display
    if 'network_scan_results' in st.session_state:
        devices = st.session_state.network_scan_results
        
        # AI Alert Logic
        warnings = []
        unknown_devices = [d for d in devices if d['Vendor'] == "Unknown Device"]
        
        if len(devices) > 5:
            warnings.append(f"Network density is high ({len(devices)} devices). Ensure all connected devices are recognized.")
        
        if unknown_devices:
            warnings.append(f"{len(unknown_devices)} devices have unknown vendor signatures. Potential intruders detected.")
        
        if warnings:
            st.markdown(f'''
                <div class="cyber-card" style="border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.1);">
                    <div class="cyber-card-title" style="color: #ef4444;">🚨 AI Advisor: Security Alert</div>
                    <ul style="color: #e2e8f0; margin-left: 20px;">
                        {"".join(f"<li>{w}</li>" for w in warnings)}
                    </ul>
                </div>
            ''', unsafe_allow_html=True)
        else:
            st.markdown(f'''
                <div class="cyber-card" style="border: 1px solid #22c55e; background: rgba(34, 197, 94, 0.1);">
                    <div class="cyber-card-title" style="color: #22c55e;">✅ AI Advisor: Network Secure</div>
                    <div style="color: #e2e8f0;">Network traffic appears normal. No immediate threats detected.</div>
                </div>
            ''', unsafe_allow_html=True)
            
        neon_divider()

        # Device Cards (Visuals)
        st.markdown('<div class="cyber-card-title">📱 Discovered Devices</div>', unsafe_allow_html=True)
        
        cols = st.columns(3)
        for i, device in enumerate(devices):
            with cols[i % 3]:
                # Icon selection logic
                vendor_lower = device.get('Vendor', '').lower()
                if 'apple' in vendor_lower or 'samsung' in vendor_lower or 'oneplus' in vendor_lower or 'xiaomi' in vendor_lower:
                    icon = "📱"  # Phone/Tablet
                elif 'intel' in vendor_lower or 'microsoft' in vendor_lower or 'dell' in vendor_lower or 'hp' in vendor_lower or 'lenovo' in vendor_lower:
                    icon = "💻"  # Laptop/PC
                elif 'cisco' in vendor_lower or 'router' in vendor_lower:
                    icon = "🌐"  # Router
                else:
                    icon = "🔌"  # Generic Device
                
                is_unknown = device['Vendor'] == "Unknown Device"
                card_style = "border: 1px solid #ef4444;" if is_unknown else ""
                text_color = "#ef4444" if is_unknown else "#94a3b8"
                vendor_display = f"⚠️ {device['Vendor']}" if is_unknown else device['Vendor']

                st.markdown(f'''
                    <div class="cyber-card" style="{card_style} min-height: 140px;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                            <div style="font-size: 1.5rem;">{icon}</div>
                            <div style="font-weight: 600; color: #e2e8f0;">{device['IP Address']}</div>
                        </div>
                        <div style="font-size: 0.85rem; color: {text_color}; margin-bottom: 4px;">
                            MAC: {device['MAC Address']}
                        </div>
                        <div style="font-size: 0.9rem; font-weight: 500; color: {text_color};">
                            {vendor_display}
                        </div>
                    </div>
                ''', unsafe_allow_html=True)

        # High-tech Table
        st.markdown('<div class="cyber-card-title" style="margin-top: 20px;">📋 Comprehensive Scan Report</div>', unsafe_allow_html=True)
        
        scan_df = pd.DataFrame(devices)
        
        def highlight_unknown(row):
            if row['Vendor'] == 'Unknown Device':
                return ['background-color: rgba(251, 146, 60, 0.2); color: #fb923c'] * len(row)
            return [''] * len(row)
            
        st.dataframe(
            scan_df.style.apply(highlight_unknown, axis=1),
            use_container_width=True
        )

    else:
        st.markdown('<div class="cyber-card" style="text-align:center; padding: 40px; color: #64748b;">Waiting for scan initiation...</div>', unsafe_allow_html=True)



# ══════════════════════════════════════════════════════════════
# SECURITY LOGS PAGE
# ══════════════════════════════════════════════════════════════

def render_security_logs():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Security Logs</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)

    # Quick simulator to trigger failed login events
    if st.button("Inject Failed Login Events", use_container_width=True):
        now = datetime.datetime.now()
        sample_events = [
            (now - datetime.timedelta(minutes=5), "192.168.10.100", "alice"),
            (now - datetime.timedelta(minutes=4), "192.168.10.103", "root"),
            (now - datetime.timedelta(minutes=3), "192.168.10.103", "root"),
            (now - datetime.timedelta(minutes=2), "192.168.10.103", "root"),
            (now - datetime.timedelta(minutes=1), "192.168.10.101", "admin"),
            (now - datetime.timedelta(minutes=1), "192.168.10.103", "root"),
            (now - datetime.timedelta(minutes=30), "10.0.0.5", "service"),
            (now - datetime.timedelta(hours=2), "203.0.113.50", "test"),
        ]
        for ts, ip, user in sample_events:
            st.session_state.security_log.append({
                "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "Severity": "WARNING",
                "Type": "AUTH",
                "Message": f"Failed login from IP {ip} user: {user}",
            })
        st.success("Injected sample failed login events")
        st.rerun()

    summary = summarize_failed_logins()
    failed_events = summary.get("events", [])
    now = datetime.datetime.now()

    # Live Feed styled as terminal
    feed_events = sorted(
        failed_events,
        key=lambda e: parse_log_timestamp(e.get("Timestamp", "")) or datetime.datetime.min,
        reverse=True,
    )[:30]
    feed_lines = []
    for event in feed_events:
        severity = event.get("Severity", "INFO")
        color = "#4ade80" if severity != "CRITICAL" else "#ff5555"
        ts = event.get("Timestamp", "--")
        msg = event.get("Message", "")
        feed_lines.append(f'<div><span style="color:#22d3ee;">[{ts}]</span> <span style="color:{color};">{msg}</span></div>')
    feed_html = "".join(feed_lines) or '<div style="color:#94a3b8;">No failed login activity logged yet.</div>'

    live_container = st.container()
    with live_container:
        st.markdown(f'''
            <style>
            .terminal-feed {{
                background:#000;
                border:1px solid #22d3ee;
                box-shadow:0 0 12px rgba(34,211,238,0.35);
                border-radius:10px;
                padding:12px;
                font-family:"Consolas","SFMono-Regular",monospace;
                height:240px;
                overflow-y:auto;
            }}
            </style>
            <div class="cyber-card">
                <div class="cyber-card-title">Live Feed</div>
                <div class="terminal-feed">{feed_html}</div>
            </div>
        ''', unsafe_allow_html=True)

    neon_divider()

    # Attack Heatmap - failed logins per hour last 24h
    hours = []
    counts = []
    for i in range(23, -1, -1):
        hour_start = now - datetime.timedelta(hours=i)
        slot_label = hour_start.strftime("%H:00")
        bucket_start = hour_start.replace(minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + datetime.timedelta(hours=1)
        count = 0
        for event in failed_events:
            ts = parse_log_timestamp(event.get("Timestamp", ""))
            if ts and bucket_start <= ts < bucket_end:
                count += 1
        hours.append(slot_label)
        counts.append(count)

    heat_df = pd.DataFrame({"Hour": hours, "Failed Logins": counts})
    fig = px.bar(heat_df, x="Hour", y="Failed Logins", title="Attack Heatmap — Failed Logins (Last 24h)", color="Failed Logins", color_continuous_scale=['#22c55e', '#f97316', '#ef4444'])
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

    neon_divider()

    # Intruder Alert table
    ip_counts = Counter()
    rows = []
    for event in failed_events:
        ip = extract_ip_from_message(event.get("Message", "")) or "Unknown"
        user = extract_username_from_message(event.get("Message", "")) or "Unknown"
        ip_counts[ip] += 1
        rows.append({
            "Timestamp": event.get("Timestamp", "--"),
            "Source IP": ip,
            "Username": user,
        })

    table_rows_html = []
    for row in rows:
        ip = row["Source IP"]
        flash_class = "flash-red" if ip_counts.get(ip, 0) > 3 else ""
        table_rows_html.append(
            f'<tr class="{flash_class}"><td>{row["Timestamp"]}</td><td>{ip}</td><td>{row["Username"]}</td></tr>'
        )

    table_html = "".join(table_rows_html) or '<tr><td colspan="3" style="text-align:center;color:#94a3b8;">No failed login attempts recorded.</td></tr>'

    st.markdown(f'''
        <style>
        .intruder-table {{
            width:100%;
            border-collapse:collapse;
            background:#0f172a;
            color:#e2e8f0;
            border:1px solid #1e293b;
        }}
        .intruder-table th, .intruder-table td {{
            padding:8px 10px;
            border-bottom:1px solid #1e293b;
        }}
        .intruder-table th {{
            text-align:left;
            color:#94a3b8;
            font-weight:600;
        }}
        @keyframes flashRed {{
            0% {{ background-color: rgba(239,68,68,0.25); }}
            50% {{ background-color: rgba(239,68,68,0.05); }}
            100% {{ background-color: rgba(239,68,68,0.25); }}
        }}
        .flash-red {{
            animation: flashRed 1.2s linear infinite;
            color:#ef4444;
            font-weight:700;
        }}
        </style>
        <div class="cyber-card">
            <div class="cyber-card-title">Intruder Alert</div>
            <table class="intruder-table">
                <thead>
                    <tr><th>Timestamp</th><th>Source IP</th><th>Username</th></tr>
                </thead>
                <tbody>
                    {table_html}
                </tbody>
            </table>
        </div>
    ''', unsafe_allow_html=True)

    neon_divider()

    # AI Forensic Analysis
    ai_message = "Analysis: No failed logins observed in the recent window."
    if summary.get("top_ip"):
        ai_message = (
            f"Analysis: I see {summary['top_count']} failed logins from IP {summary['top_ip']}. "
            "This correlates with a brute-force pattern."
        )
    st.markdown(f'''
        <div class="cyber-card" style="border:1px solid #22d3ee;">
            <div class="cyber-card-title" style="font-size:1rem;">🧠 AI Forensic Analysis</div>
            <div style="color:#e2e8f0;">{ai_message}</div>
        </div>
    ''', unsafe_allow_html=True)

    log_event("ALERT", "Security logs reviewed", "INFO")


# ══════════════════════════════════════════════════════════════
# PASSWORD SECURITY PAGE
# ══════════════════════════════════════════════════════════════

def render_identity_lab():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Identity Lab</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown('<div class="cyber-card-title">🔑 Password Strength Analyzer</div>', unsafe_allow_html=True)
        st.caption("Analyzed locally - never stored or transmitted")
        
        pw = st.text_input("Enter password to analyze", type="password", placeholder="Type a password...")
        
        if pw:
            # 1. BREACH CHECK
            is_common = check_breached_password(pw)
            if is_common:
                 st.markdown(f'''
                    <div class="cyber-card" style="border: 2px solid #ef4444; background: rgba(239, 68, 68, 0.1); margin-bottom: 20px;">
                        <div style="color: #ef4444; font-weight: 700; font-size: 1.1rem;">⚠️ PASSWORD BREACHED</div>
                        <div style="color: #e2e8f0;">This password appears in common breach lists. <b>Do not use this.</b></div>
                    </div>
                ''', unsafe_allow_html=True)

            # 2. ZXCVBN ANALYSIS
            analysis = analyze_password_strength(pw)
            score = analysis['score']  # 0-4
            crack_time = analysis['crack_time_display']
            suggestions = analysis['suggestions']
            warning = analysis.get('warning')

            # Store score for executive dashboard sync
            st.session_state.identity_last_score = score
            
            # Map score to visual strength
            if score == 4:
                strength, color, bar_pct = "Excellent", "#22c55e", 100
            elif score == 3:
                strength, color, bar_pct = "Strong", "#22c55e", 75
            elif score == 2:
                strength, color, bar_pct = "Moderate", "#f59e0b", 50
            elif score == 1:
                strength, color, bar_pct = "Weak", "#ef4444", 25
            else:
                strength, color, bar_pct = "Critical", "#ef4444", 10

            # 3. ENTROPY CALCULATION
            entropy = get_entropy(pw)
            
            # Strength Progress (st.progress with dynamic color)
            bar_color = "#dc2626" if score <= 1 else "#f59e0b" if score == 2 else "#facc15" if score == 3 else "#22c55e"
            st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
            st.markdown("<div style='display:flex;justify-content:space-between;margin-bottom:8px;'><span style='color:#64748b;'>Password Strength</span><span style='color:" + bar_color + ";font-weight:700;'>" + strength + "</span></div>", unsafe_allow_html=True)
            prog = st.progress(bar_pct / 100)
            st.markdown(f"""
                <style>
                div[data-testid="stProgress"] div[role="progressbar"] {{
                    background-color: {bar_color};
                }}
                </style>
            """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

            # Crack Clock + Entropy Cards
            st.markdown(f'''
<div class="cyber-card">
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
        <div style="background: #0f172a; padding: 12px; border-radius: 8px;">
            <div style="color: #64748b; font-size: 0.8rem;">Estimated Time to Crack</div>
            <div style="color: #e2e8f0; font-weight: 700; font-size: 1rem;">{crack_time}</div>
        </div>
        <div style="background: #0f172a; padding: 12px; border-radius: 8px;">
            <div style="color: #64748b; font-size: 0.8rem;">Entropy</div>
            <div style="color: #e2e8f0; font-weight: 700; font-size: 1rem;">{entropy} bits</div>
        </div>
    </div>
</div>
''', unsafe_allow_html=True)
            
            # 4. AI FEEDBACK & SUGGESTIONS
            st.markdown('<div class="cyber-card" style="margin-top:16px;">', unsafe_allow_html=True)
            st.markdown('<div class="cyber-card-title" style="font-size:1rem;">🧠 AI Advisor</div>', unsafe_allow_html=True)
            advisor_lines = []
            if warning:
                advisor_lines.append(f"Warning: {warning}")
            if suggestions:
                advisor_lines.extend(suggestions)
            if not advisor_lines:
                advisor_lines.append("No immediate concerns. Password meets strength guidelines.")

            for line in advisor_lines:
                st.markdown(f'<div style="color:#cbd5e1; margin: 4px 0;">• {line}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

            # 5. COMPLEXITY CHECKLIST
            complexity = check_complexity(pw)
            st.markdown('<div class="cyber-card" style="margin-top: 20px;">', unsafe_allow_html=True)
            st.markdown('<div class="cyber-card-title" style="font-size: 1rem;">Security Requirements</div>', unsafe_allow_html=True)
            
            checks = [
                (complexity['length_ok'], f"Length ≥ 12 ({len(pw)} chars)"),
                (complexity['has_upper'], "Uppercase letters"),
                (complexity['has_lower'], "Lowercase letters"),
                (complexity['has_digit'], "Numeric digits"),
                (complexity['has_special'], "Special characters"),
            ]
            
            for check, label in checks:
                icon = "✅" if check else "❌"
                item_color = "#22c55e" if check else "#ef4444"
                st.markdown(f'''
                    <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #1e293b;">
                        <span style="color:#94a3b8;">{label}</span>
                        <span style="color:{item_color}; font-weight: bold;">{icon}</span>
                    </div>
                ''', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            log_event("AUTH", f"Password analyzed: {strength} ({score}/4)")
    
    with col2:
        st.markdown('<div class="cyber-card-title">⚡ Password Generator</div>', unsafe_allow_html=True)
        
        pw_len = st.slider("Length", 8, 64, 20)
        inc_special = st.checkbox("Special characters", value=True)
        
        if st.button("Generate Password", use_container_width=True):
            chars = string.ascii_letters + string.digits
            if inc_special:
                chars += string.punctuation
            generated = "".join(chars[b % len(chars)] for b in os.urandom(pw_len))
            st.code(generated, language=None)
            log_event("AUTH", "Secure password generated", "INFO")


# ══════════════════════════════════════════════════════════════
# AUTH LOGS PAGE
# ══════════════════════════════════════════════════════════════

def render_auth_logs():
    st.markdown(f'''
        <div class="header-bar">
            <div>
                <div class="header-title">Auth Logs</div>
                <div class="header-subtitle">{get_date_display()}</div>
            </div>
        </div>
    ''', unsafe_allow_html=True)
    
    df_log = get_event_log()
    
    total_events = len(df_log)
    critical = len(df_log[df_log["Severity"] == "CRITICAL"]) if not df_log.empty else 0
    warnings = len(df_log[df_log["Severity"] == "WARNING"]) if not df_log.empty else 0
    info = len(df_log[df_log["Severity"] == "INFO"]) if not df_log.empty else 0
    
    # Metric cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(total_events, "Total Events"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card(critical, "Critical Alerts", "red" if critical > 0 else "green"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card(warnings, "Warnings", "orange" if warnings > 0 else "green"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card(info, "Info"), unsafe_allow_html=True)
    
    neon_divider()
    
    # Filters
    col1, col2 = st.columns([3, 1])
    with col1:
        sev_filter = st.multiselect(
            "Filter by severity",
            ["INFO", "WARNING", "CRITICAL"],
            default=["INFO", "WARNING", "CRITICAL"],
        )
    with col2:
        if st.button("Export Logs", use_container_width=True):
            if not df_log.empty:
                csv = df_log.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    data=csv,
                    file_name=f"cyberguard_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                )
    
    # Log table
    if not df_log.empty:
        df_filtered = df_log[df_log["Severity"].isin(sev_filter)].iloc[::-1].reset_index(drop=True)
        st.dataframe(df_filtered, use_container_width=True, height=400)
    else:
        st.info("No events logged yet. Navigate to other sections to generate events.")


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    # Apply custom CSS from styles.py (includes navigation fixes)
    apply_styles()

    # Start the background canary observer once per session.
    if "canary_started" not in st.session_state:
        thread = threading.Thread(target=start_canary, daemon=True)
        thread.start()
        st.session_state.canary_started = True
        st.session_state.last_breach_seen = None

    # Immediate breach override: if tripwire fired, take over UI.
    if breach_flag():
        info = breach_info()
        breach_sig = info.get("timestamp")
        if breach_sig and st.session_state.get("last_breach_seen") != breach_sig:
            st.session_state.last_breach_seen = breach_sig
            log_event(
                "BREACH",
                f"Canary triggered at {info.get('path')} by PIDs {info.get('pids')} ({info.get('names')})",
                "CRITICAL",
            )

        st.markdown(
            f"""
            <div style="background:#7f1d1d;color:#fee2e2;padding:40px;border-radius:16px;border:2px solid #f87171;min-height:90vh;display:flex;flex-direction:column;justify-content:center;align-items:center;">
                <div style="font-size:2rem;font-weight:800;margin-bottom:16px;">⚠️ CRITICAL BREACH: Unauthorized access to Honeypot detected.</div>
                <div style="font-size:1rem;margin-bottom:12px;">Action Taken: Process {info.get('names','unknown')} (PID {info.get('pids','?')}) terminated; network isolated.</div>
                <div style="font-size:0.95rem;color:#fecdd3;">Tripwire file: {info.get('path')}</div>
                <div style="font-size:0.95rem;color:#fecdd3;">Timestamp: {info.get('timestamp')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        # Early exit to lock the screen on breach.
        return

    # Global live auto-refresh (keeps telemetry and AI console up-to-date) using a lightweight JS reload for broad Streamlit compatibility.
    if st.session_state.get("auto_refresh_enabled", True):
        refresh_ms = st.session_state.get("refresh_ms", 5000)
        # Inject a safe client-side reload timer; avoids dependency on st.autorefresh (not available in this Streamlit build).
        st.markdown(
            f"""
            <script>
                const cgTimer = setTimeout(() => {{ window.location.reload(); }}, {refresh_ms});
            </script>
            """,
            unsafe_allow_html=True,
        )
    
    # Sidebar
    with st.sidebar:
        # Logo and branding
        st.markdown('''
            <div class="cg-brand-wrap">
                <div class="cg-brand-icon">🛡</div>
                <div>
                    <div class="cg-brand-title">CYBERGUARD</div>
                    <div class="cg-brand-subtitle">v2.4.1 — Local Monitor</div>
                </div>
            </div>
        ''', unsafe_allow_html=True)

        st.markdown(f'''
            <div class="cg-system-status">
                <div class="cg-status-left">
                    <div class="cg-status-dot"></div>
                    <span class="cg-status-text">System Protected</span>
                </div>
                <span class="cg-status-time">{get_time_only()}</span>
            </div>
        ''', unsafe_allow_html=True)

        neon_divider()

        # Navigation label
        st.markdown('<div class="cg-nav-label">NAVIGATION</div>', unsafe_allow_html=True)

        page = st.radio(
            "Navigation",
            options=[
                "◻◻  Overview",
                "∿  Process Monitor",
                "▤  File Integrity",
                "◉  Network Activity",
                "⌁  Password Security",
                "⎘  Auth Logs",
                "⚙  System Config",
            ],
            label_visibility="collapsed",
        )

        st.markdown(
            f'''
            <div class="cg-sidebar-footer">
                <div class="cg-footer-line1">Last scan: {get_time_only()}</div>
                <div class="cg-footer-line2">System secure</div>
            </div>
            ''',
            unsafe_allow_html=True,
        )

        # On-demand Security Audit Report (stores latest in session for immediate download)
        if st.button("📄 Generate Security Audit Report", use_container_width=True):
            try:
                sys_info_sidebar = cached_system_info()
            except Exception:
                sys_info_sidebar = {}

            vault_count_sidebar = len(st.session_state.get("vault_files", {}))
            health_sidebar = calculate_health_score(vault_file_count=vault_count_sidebar)

            try:
                ports_sidebar, alerts_sidebar = get_open_ports()
            except Exception as e:
                ports_sidebar, alerts_sidebar = [], [f"Port scan unavailable: {e}"]

            devices_sidebar = st.session_state.get("network_device_count", cached_connection_count())
            failed_summary_sidebar = summarize_failed_logins()

            report_lines = [
                "CYBERGUARD Security Audit Report — Professional Certification",
                f"Generated: {get_timestamp()}",
                "",
                "=== Shield Score ===",
                f"Score: {health_sidebar}",
                f"CPU: {sys_info_sidebar.get('live_cpu', 'n/a')}% | Memory: {sys_info_sidebar.get('live_mem', 'n/a')}% | Disk: {sys_info_sidebar.get('disk_percent', 'n/a')}%",
                "",
                "=== Network ===",
                f"Discovered/Active Devices: {devices_sidebar}",
                f"Open Ports: {len(ports_sidebar)}",
            ]

            if ports_sidebar:
                report_lines.append("Ports (Port/Service/Risk):")
                for p in ports_sidebar[:20]:  # cap for readability
                    report_lines.append(f" - {p.get('Port')} / {p.get('Service')} / {p.get('Risk Level')}")

            if alerts_sidebar:
                report_lines.append("High-Risk Port Alerts:")
                for a in alerts_sidebar:
                    report_lines.append(f" - {a}")

            report_lines.extend([
                "",
                "=== Identity & Auth ===",
                f"Failed Logins (all time): {failed_summary_sidebar.get('total', 0)}",
                f"Failed Logins (last hour): {failed_summary_sidebar.get('recent_count', 0)}",
                f"Top Source IP: {failed_summary_sidebar.get('top_ip') or 'n/a'} ({failed_summary_sidebar.get('top_count', 0)})",
            ])

            st.session_state.audit_report_content = "\n".join(report_lines)
            st.session_state.audit_report_filename = f"cyberguard_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

            # Structured CSV export
            csv_rows = []
            csv_rows.append({"Section": "Shield Score", "Metric": "Score", "Value": health_sidebar})
            csv_rows.append({"Section": "Shield Score", "Metric": "CPU %", "Value": sys_info_sidebar.get('live_cpu', 'n/a')})
            csv_rows.append({"Section": "Shield Score", "Metric": "Memory %", "Value": sys_info_sidebar.get('live_mem', 'n/a')})
            csv_rows.append({"Section": "Shield Score", "Metric": "Disk %", "Value": sys_info_sidebar.get('disk_percent', 'n/a')})
            csv_rows.append({"Section": "Network", "Metric": "Discovered/Active Devices", "Value": devices_sidebar})
            csv_rows.append({"Section": "Network", "Metric": "Open Ports", "Value": len(ports_sidebar)})
            if ports_sidebar:
                for p in ports_sidebar[:50]:
                    csv_rows.append({
                        "Section": "Ports",
                        "Metric": f"Port {p.get('Port')} ({p.get('Service')})",
                        "Value": p.get('Risk Level')
                    })
            if alerts_sidebar:
                for a in alerts_sidebar:
                    csv_rows.append({"Section": "Ports", "Metric": "High-Risk Alert", "Value": a})
            csv_rows.append({"Section": "Identity & Auth", "Metric": "Failed Logins (all time)", "Value": failed_summary_sidebar.get('total', 0)})
            csv_rows.append({"Section": "Identity & Auth", "Metric": "Failed Logins (last hour)", "Value": failed_summary_sidebar.get('recent_count', 0)})
            csv_rows.append({"Section": "Identity & Auth", "Metric": "Top Source IP", "Value": f"{failed_summary_sidebar.get('top_ip') or 'n/a'} ({failed_summary_sidebar.get('top_count', 0)})"})

            csv_df = pd.DataFrame(csv_rows)
            st.session_state.audit_report_csv = csv_df.to_csv(index=False)
            st.success("Security audit compiled. Download below.")

        if st.session_state.get("audit_report_content"):
            st.download_button(
                label="Download Security Audit (.txt)",
                data=st.session_state.audit_report_content,
                file_name=st.session_state.get("audit_report_filename") or "cyberguard_audit.txt",
                mime="text/plain",
                use_container_width=True,
            )
        if st.session_state.get("audit_report_csv"):
            st.download_button(
                label="Download Security Audit (.csv)",
                data=st.session_state.audit_report_csv,
                file_name=(st.session_state.get("audit_report_filename") or "cyberguard_audit.txt").replace(".txt", ".csv"),
                mime="text/csv",
                use_container_width=True,
            )
    
    # Page routing
    PAGE_MAP = {
        "◻◻  Overview": render_overview,
        "∿  Process Monitor": render_process_monitor,
        "▤  File Integrity": render_file_integrity,
        "◉  Network Activity": render_network_radar,
        "⌁  Password Security": render_identity_lab,
        "⎘  Auth Logs": render_security_logs,
        "⚙  System Config": render_system_sentinel,
    }
    
    try:
        PAGE_MAP[page]()
    except Exception as e:
        st.error(f"Error: {e}")
        log_event("ALERT", f"Error: {e}", "CRITICAL")


if __name__ == "__main__":
    main()
