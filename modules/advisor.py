"""
HawkEye Sentinel Intelligence Engine
-----------------------------------
Lead SOC + Tier-3 threat hunting logic for multi-vector correlation.
Outputs are structured for direct use in Streamlit typewriter-style rendering.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

# Remediation knowledge base
REMEDIATION_DB: Dict[str, str] = {
    "cryptojacking_or_exfil": "Isolate host, kill high-CPU processes, inspect outbound traffic, rotate credentials, and run a full malware sweep.",
    "unauthorized_system_manipulation": "Disable compromised accounts, review recent logons, restore affected system files from trusted backups, and enable auditing on system directories.",
    "weak_password_firewall_off": "Enforce strong-password policy immediately, enable firewall profiles, and close all non-essential inbound ports.",
    "open_ports": "Review firewall rules and close exposed ports; restrict to least privilege and monitor for repeated connection attempts.",
    "unknown_devices": "Identify unknown MAC/IP, segment or block at the switch/AP, and verify no rogue access points exist.",
}

Severity = str  # Literal values: "low", "medium", "high", "critical"


def _risk_score_to_level(score: int) -> str:
    if score >= 8:
        return "Critical"
    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def _add_finding(findings: List[Dict[str, Any]], title: str, severity: Severity, context: str, threat_key: str) -> None:
    findings.append({
        "title": title,
        "severity": severity.title(),
        "context": context,
        "remediation": REMEDIATION_DB.get(threat_key, "Review and contain the threat vector; apply least privilege and monitor."),
    })


def generate_intelligence_report(
    system_data: Dict[str, Any],
    network_data: Dict[str, Any],
    vault_data: Dict[str, Any],
    log_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Perform multi-vector correlation across system, network, vault, and auth logs."""
    findings: List[Dict[str, Any]] = []
    score = 0

    cpu_pct = float(system_data.get("cpu_percent", 0.0))
    firewall_enabled = bool(system_data.get("firewall_enabled", True))
    weak_password = bool(system_data.get("weak_password", False))

    unknown_devices = int(network_data.get("unknown_devices", 0))

    modified_files: List[str] = vault_data.get("modified_files", []) or []
    added_files: List[str] = vault_data.get("added_files", []) or []
    removed_files: List[str] = vault_data.get("removed_files", []) or []

    failed_logins_recent = int(log_data.get("failed_logins_recent", 0))
    recent_failed_window = log_data.get("recent_failed_window_minutes", 60)

    # Threat correlation 1: Unknown device + high CPU
    if unknown_devices > 0 and cpu_pct >= 80:
        _add_finding(
            findings,
            "⚠️ Potential Cryptojacking or Data Exfiltration",
            "high",
            f"Unknown devices detected ({unknown_devices}) while CPU is elevated at {cpu_pct:.1f}%.",
            "cryptojacking_or_exfil",
        )
        score += 3

    # Threat correlation 2: System folder modification + recent failed login
    if failed_logins_recent > 0:
        for path in modified_files:
            pl = path.lower()
            if "windows\\system32" in pl or "/etc" in pl or "system" in pl:
                _add_finding(
                    findings,
                    "🚨 Critical: Unauthorized System Manipulation Detected",
                    "critical",
                    f"System directory change ({path}) plus {failed_logins_recent} failed login(s) in last {recent_failed_window} minutes.",
                    "unauthorized_system_manipulation",
                )
                score += 4
                break

    # Threat correlation 3: Weak password + firewall off
    if weak_password and not firewall_enabled:
        _add_finding(
            findings,
            "❌ High Vulnerability: Extreme Attack Surface",
            "high",
            "Password policy weak while firewall is disabled, exposing the host to lateral movement and payload delivery.",
            "weak_password_firewall_off",
        )
        score += 3

    # Additional signals: open ports
    open_ports = network_data.get("open_ports", []) or []
    if open_ports:
        port_list = ", ".join(str(p) for p in open_ports[:10])
        _add_finding(
            findings,
            "Open Ports Detected",
            "medium",
            f"Exposed services on ports: {port_list}.",
            "open_ports",
        )
        score += 2

    # Additional signals: unknown devices alone
    if unknown_devices > 0 and cpu_pct < 80:
        _add_finding(
            findings,
            "Unidentified Network Presence",
            "medium",
            f"{unknown_devices} device(s) lack attribution; investigate for rogue assets.",
            "unknown_devices",
        )
        score += 1

    risk_level = _risk_score_to_level(score)

    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "risk_level": risk_level,
        "risk_score": score,
        "findings": findings,
        "summary": get_ai_summary(findings, risk_level),
    }


def get_ai_summary(findings: List[Dict[str, Any]], risk_level: str) -> str:
    """Summarize findings in a cyber-noir tone for a typewriter effect."""
    if not findings:
        return (
            "HawkEye Sentinel scans the lanes—no hostile threat vectors, no payloads staged. "
            "Perimeter steady; continue passive telemetry and hold the line."
        )

    fragments = []
    for f in findings:
        fragments.append(
            f"Threat Vector: {f['title']} (Severity: {f['severity']}). Context: {f['context']}"
        )

    return (
        f"Risk Level: {risk_level}. "
        " | ".join(fragments)
        + " — Recommend immediate containment to halt lateral movement and disrupt any exfiltration chain."
    )


__all__ = [
    "generate_intelligence_report",
    "get_ai_summary",
    "REMEDIATION_DB",
]
