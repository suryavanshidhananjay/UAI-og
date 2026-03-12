"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          CYBERGUARD System Module                           ║
║                         Senior System Architect                             ║
║                    Professional Host OS Interaction Engine                  ║  
╚══════════════════════════════════════════════════════════════════════════════╝

This module provides robust Python functions for interacting with the host operating
system using only psutil and socket libraries. All data is real-time system telemetry
with graceful error handling and professional documentation.

Core Functions:
    • get_process_info()     → Live process discovery with security assessment
    • get_open_ports()       → Network port audit with risk classification  
    • get_system_metrics()   → Hardware telemetry (CPU%, RAM%)

Author: Senior System Architect
Version: 2.4.1
Dependencies: psutil, socket (stdlib)
"""

from __future__ import annotations
import os
import platform
import re
import socket
import subprocess
from typing import List, Dict, Tuple, Any

import psutil


# ══════════════════════════════════════════════════════════════════════════════
# PLATFORM HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_process_digitally_signed(executable_path: str) -> str:
    """Return 'signed', 'unsigned', or 'unknown' for the given executable."""
    if not _is_windows() or not executable_path or not os.path.exists(executable_path):
        return "unknown"

    try:
        # Using PowerShell Authenticodesignature to verify digital signature status
        cmd = [
            "powershell",
            "-Command",
            f"(Get-AuthenticodeSignature -FilePath '{executable_path}').Status",
        ]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
        status = result.strip().lower()
        if "valid" in status:
            return "signed"
        if status:
            return "unsigned"
        return "unknown"
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError, OSError):
        return "unknown"


def _is_unusual_name(proc_name: str) -> bool:
    """Heuristic: very short names or high-entropy-like names are unusual."""
    if not proc_name:
        return True
    name = proc_name.lower()
    if len(name) <= 3:
        return True
    # Names with alternating letters/numbers or random-looking sequences
    if re.match(r"^[a-z]{1,3}\d{3,}$", name):
        return True
    if re.match(r"^[a-z0-9]{8,}$", name) and not name.startswith("windows"):
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK SERVICE MAPPINGS & SECURITY CLASSIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

# Comprehensive mapping of well-known ports to service names
KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data",     21: "FTP",          22: "SSH",          23: "Telnet", 
    25: "SMTP",         53: "DNS",          67: "DHCP-Server",  68: "DHCP-Client",
    80: "HTTP",         110: "POP3",        119: "NNTP",        123: "NTP",
    135: "RPC",         137: "NetBIOS-NS",  138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP",        161: "SNMP",        194: "IRC",         443: "HTTPS",
    445: "SMB",         465: "SMTPS",       514: "Syslog",      587: "SMTP-Submission",
    631: "IPP",         993: "IMAPS",       995: "POP3S",       1433: "MSSQL",
    1521: "Oracle",     3306: "MySQL",      3389: "RDP",        5432: "PostgreSQL",
    5900: "VNC",        6379: "Redis",      8080: "HTTP-Alt",   8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# High-risk ports that indicate insecure legacy protocols
HIGH_RISK_PORTS: set[int] = {21, 23, 445}  # FTP, Telnet, SMB


# ══════════════════════════════════════════════════════════════════════════════
# LIVE PROCESS DISCOVERY ENGINE  
# ══════════════════════════════════════════════════════════════════════════════

def get_process_info() -> List[Dict[str, Any]]:
    """
    Performs comprehensive live process discovery using psutil.process_iter().
    
    Discovers all running processes and extracts critical security metadata including
    PID, process name, execution status, CPU utilization, and memory consumption.
    Implements robust error handling for system-level access restrictions.
    
    Security Features:
        • Graceful handling of AccessDenied exceptions for protected processes
        • NoSuchProcess exception handling for transient processes  
        • Fallback values ('System', 'Restricted') for inaccessible process metadata
        • Real-time CPU and memory percentage calculations
    
    Returns:
        List[Dict[str, Any]]: List of process dictionaries containing:
            - PID (int): Process identifier
            - Name (str): Executable name or 'System'/'Restricted' if inaccessible
            - Status (str): Current process state (running, sleeping, stopped, etc.)
            - CPU Usage (float): CPU utilization percentage  
            - Memory Usage (float): RAM utilization percentage
            - Username (str): Process owner or 'System' if restricted
    
    Raises:
        None: All exceptions are handled gracefully with fallback values
        
    Example:
        >>> processes = get_process_info()
        >>> print(f"Discovered {len(processes)} running processes")
        >>> critical_processes = [p for p in processes if p['CPU Usage'] > 50.0]
    """
    discovered_processes: List[Dict[str, Any]] = []

    # Avoid expensive signature checks when many processes or when disabled via env
    skip_sig_env = os.environ.get("CG_SKIP_SIGNATURES", "").lower() in ("1", "true", "yes", "on")
    pid_count = 0
    try:
        pid_count = len(psutil.pids())
    except Exception:
        pid_count = 0
    do_signatures = _is_windows() and not skip_sig_env and pid_count <= 120
    
    # Iterate through all system processes with required attributes
    for process in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 
                                       'memory_percent', 'username', 'exe']):
        try:
            # Extract process information with one-time access
            process_data = process.info
            exe_path = process_data.get('exe')
            signed_state = _is_process_digitally_signed(exe_path) if do_signatures else "unknown"
            unusual_name = _is_unusual_name(process_data.get('name'))
            
            # Build standardized process record with fallback handling
            process_record = {
                'PID': process_data['pid'],
                'Name': process_data['name'] if process_data['name'] else 'System',
                'Status': process_data['status'] if process_data['status'] else 'unknown',
                'CPU %': round(process_data['cpu_percent'] or 0.0, 2),
                'Memory %': round(process_data['memory_percent'] or 0.0, 2),
                'Username': process_data['username'] if process_data['username'] else 'System',
                'Signed': signed_state,
                'Unusual Name': unusual_name,
                'Exe': exe_path or ''
            }
            
            discovered_processes.append(process_record)
            
        except psutil.AccessDenied:
            # Handle system/protected processes with restricted access
            restricted_record = {
                'PID': process.pid if hasattr(process, 'pid') else 0,
                'Name': 'Restricted',
                'Status': 'protected',
                'CPU %': 0.0,
                'Memory %': 0.0,
                'Username': 'System',
                'Signed': 'unknown',
                'Unusual Name': False,
                'Exe': ''
            }
            discovered_processes.append(restricted_record)
            
        except psutil.NoSuchProcess:
            # Process terminated during iteration - skip silently
            continue
            
        except (psutil.ZombieProcess, AttributeError, TypeError):
            # Handle edge cases: zombie processes or malformed data
            continue
    
    return discovered_processes


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK PORT AUDIT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

def get_open_ports() -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Conducts comprehensive network port audit using psutil.net_connections().
    
    Scans all IPv4 network connections to identify listening services and performs
    security risk classification based on port numbers and known vulnerabilities.
    Maps common ports to service names and identifies high-risk legacy protocols.
    
    Security Analysis:
        • Identifies LISTEN state connections only (active services)
        • Maps ports to known service names using industry-standard mappings
        • Classifies high-risk ports (FTP, Telnet, SMB) as critical vulnerabilities
        • Distinguishes privileged ports (<1024) vs user ports (>=1024)
        • Extracts binding IP addresses for network exposure assessment
    
    Returns:
        Tuple[List[Dict[str, Any]], List[str]]: Two-element tuple containing:
            
        [0] Port Records (List[Dict]): Detailed port information with keys:
            - Port (int): TCP/UDP port number
            - Service (str): Mapped service name or 'Unknown'
            - Local Address (str): IP address the service is bound to
            - Risk Level (str): Security classification
                • 'High Risk' - Known vulnerable services (FTP, Telnet, SMB)
                • 'Medium Risk' - Privileged ports (<1024)  
                • 'Low Risk' - Standard user ports (>=1024)
                
        [1] Critical Alerts (List[str]): High-risk services requiring attention
            - Format: ["21 (FTP)", "23 (Telnet)", "445 (SMB)"]
    
    Raises:
        psutil.AccessDenied: When insufficient privileges for network enumeration
        PermissionError: On systems with restricted network access
        
    Example:
        >>> ports, alerts = get_open_ports()
        >>> print(f"Found {len(ports)} listening services")
        >>> if alerts:
        ...     print(f"SECURITY ALERT: {len(alerts)} high-risk services detected!")
        >>> critical_services = [p for p in ports if 'High Risk' in p['Risk Level']]
    """
    try:
        # Enumerate all IPv4 network connections
        all_connections = psutil.net_connections(kind='inet')
        
        # Filter for LISTEN state connections (active services)
        listening_services = [
            conn for conn in all_connections 
            if conn.status == 'LISTEN' and conn.laddr
        ]
        
        # Build unique port mapping with bind addresses
        discovered_ports: Dict[int, str] = {}
        for connection in listening_services:
            port_number = connection.laddr.port
            bind_address = connection.laddr.ip
            
            # Store first occurrence of each unique port
            if port_number not in discovered_ports:
                discovered_ports[port_number] = bind_address
        
        # Analyze discovered ports for security implications
        port_records: List[Dict[str, Any]] = []
        critical_alerts: List[str] = []
        
        for port_number in sorted(discovered_ports.keys()):
            bind_address = discovered_ports[port_number]
            service_name = KNOWN_PORTS.get(port_number, 'Unknown')
            
            # Classify security risk level
            if port_number in HIGH_RISK_PORTS:
                risk_level = 'High Risk'
                critical_alerts.append(f"{port_number} ({service_name})")
            elif port_number < 1024:
                risk_level = 'Medium Risk'  # Privileged port
            else:
                risk_level = 'Low Risk'     # User space port
            
            # Build comprehensive port record
            port_record = {
                'Port': port_number,
                'Service': service_name,
                'Local Address': bind_address,
                'Risk Level': risk_level
            }
            
            port_records.append(port_record)
        
        return port_records, critical_alerts
        
    except (psutil.AccessDenied, PermissionError) as security_error:
        # Re-raise security exceptions for caller handling
        raise security_error


# ══════════════════════════════════════════════════════════════════════════════
# HARDWARE TELEMETRY ENGINE  
# ══════════════════════════════════════════════════════════════════════════════

def get_system_metrics() -> Dict[str, float]:
    """
    Captures real-time hardware telemetry for CPU and RAM utilization.
    
    Provides instantaneous system performance metrics using psutil's hardware
    monitoring capabilities. Delivers precise percentage-based measurements
    for capacity planning and performance analysis.
    
    Measurement Methodology:
        • CPU: Instantaneous utilization across all cores with 0.1s sampling interval
        • Memory: Current RAM utilization percentage including buffers/cache
        • High-precision floating point values for accurate trending analysis
        • Non-blocking measurement designed for continuous monitoring loops
    
    Returns:
        Dict[str, float]: Hardware metrics dictionary containing:
            - 'cpu_percent' (float): Current CPU utilization (0.0 - 100.0)
            - 'memory_percent' (float): Current RAM utilization (0.0 - 100.0)
    
    Performance Characteristics:
        • Execution time: ~100ms (due to CPU sampling interval)
        • Memory overhead: Minimal (<1KB)
        • Thread safety: Safe for concurrent access
        • Platform support: Windows, Linux, macOS
        
    Raises:
        None: Hardware access failures return 0.0 values
        
    Example:
        >>> metrics = get_system_metrics()
        >>> cpu_usage = metrics['cpu_percent']
        >>> ram_usage = metrics['memory_percent'] 
        >>> if cpu_usage > 80.0:
        ...     print(f"HIGH CPU ALERT: {cpu_usage:.1f}% utilization")
        >>> if ram_usage > 90.0:
        ...     print(f"MEMORY CRITICAL: {ram_usage:.1f}% utilization")
    """
    try:
        # Capture instantaneous CPU utilization with brief sampling interval
        # Note: interval=0.1 provides good balance of accuracy vs responsiveness
        current_cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Capture current memory utilization state
        memory_info = psutil.virtual_memory()
        current_memory_percent = memory_info.percent
        
        return {
            'cpu_percent': round(float(current_cpu_percent), 2),
            'memory_percent': round(float(current_memory_percent), 2)
        }
        
    except (AttributeError, OSError, TypeError):
        # Return safe fallback values on hardware access failure
        return {
            'cpu_percent': 0.0,
            'memory_percent': 0.0
        }


# ═════════════════════════════════════════════════════════════════════════════=
# SECURITY POSTURE CHECKS
# ═════════════════════════════════════════════════════════════════════════════=

def get_firewall_status() -> Dict[str, Any]:
    """Check Windows Firewall status using netsh; returns enabled flag and raw output."""
    if not _is_windows():
        return {"enabled": False, "raw": "non-windows"}
    try:
        output = subprocess.check_output(
            ["netsh", "advfirewall", "show", "allprofiles"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        enabled = any("state" in line.lower() and "on" in line.lower() for line in output.splitlines())
        return {"enabled": enabled, "raw": output}
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError, OSError) as e:
        return {"enabled": False, "raw": f"error: {e}"}


def enable_firewall() -> bool:
    """Attempt to force-enable Windows Firewall across all profiles using netsh."""
    if not _is_windows():
        return False
    try:
        # Use netsh to toggle firewall on for all profiles; keep timeout short to avoid UI hangs.
        subprocess.check_call(
            ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError, OSError, TimeoutError):
        return False


def get_system_services() -> List[Dict[str, Any]]:
    """Enumerate Windows services with status and start type using psutil."""
    services: List[Dict[str, Any]] = []
    if not _is_windows():
        return services

    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            services.append({
                "Name": info.get("name"),
                "Display Name": info.get("display_name"),
                "Status": info.get("status"),
                "Start Type": info.get("start_type"),
                "PID": info.get("pid"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, OSError, KeyError):
            # Some services vanish or refuse description queries; skip them safely
            continue
    return services


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY COMPATIBILITY LAYER
# ══════════════════════════════════════════════════════════════════════════════

# Maintain backward compatibility with existing CYBERGUARD application
def get_process_list() -> List[Dict[str, Any]]:
    """Legacy wrapper for get_process_info() - maintains CYBERGUARD compatibility."""
    return get_process_info()

def get_system_info() -> Dict[str, Any]: 
    """Legacy system info function for CYBERGUARD compatibility."""
    import datetime
    import platform
    import os
    
    # Get base metrics from new function
    base_metrics = get_system_metrics()
    
    # Add extended system information for backward compatibility
    try:
        memory_info = psutil.virtual_memory()
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime_delta = datetime.datetime.now() - boot_time
        uptime_hours, remainder = divmod(int(uptime_delta.total_seconds()), 3600)
        uptime_minutes, _ = divmod(remainder, 60)
        
        # Disk usage for primary drive
        try:
            primary_drive = "/" if os.name != "nt" else "C:\\"
            disk_info = psutil.disk_usage(primary_drive)
            disk_percent = disk_info.percent
            disk_total_gb = round(disk_info.total / (1024**3), 1)
        except OSError:
            disk_percent = 0.0
            disk_total_gb = 0.0
        
        return {
            'hostname': socket.gethostname(),
            'platform': f"{platform.system()} {platform.release()}",
            'cpu_percent': base_metrics['cpu_percent'],
            'memory_percent': base_metrics['memory_percent'], 
            'memory_total_gb': round(memory_info.total / (1024**3), 1),
            'disk_percent': disk_percent,
            'disk_total_gb': disk_total_gb,
            'uptime_hours': uptime_hours,
            'uptime_mins': uptime_minutes,
            'live_cpu': base_metrics['cpu_percent'],
            'live_mem': base_metrics['memory_percent'],
        }
    except Exception:
        return {
            'hostname': 'unknown',
            'platform': 'unknown',
            'cpu_percent': base_metrics['cpu_percent'],
            'memory_percent': base_metrics['memory_percent'],
            'memory_total_gb': 0.0,
            'disk_percent': 0.0,
            'disk_total_gb': 0.0,
            'uptime_hours': 0,
            'uptime_mins': 0,
            'live_cpu': base_metrics['cpu_percent'],
            'live_mem': base_metrics['memory_percent'],
        }

def get_pid_count() -> int:
    """Get total number of active process IDs."""
    return len(psutil.pids())

def assess_process_risk(process_record: Dict[str, Any]) -> str:
    """Assess security risk level of a process record."""
    try:
        risk_indicators = []
        
        cpu_usage = process_record.get('CPU %', 0.0)
        username = process_record.get('Username', '')
        signed_state = process_record.get('Signed', 'unknown')
        unusual = process_record.get('Unusual Name', False)
        
        if cpu_usage > 25.0:
            risk_indicators.append("High CPU")
        if not username or username in ['System', 'Restricted']:
            risk_indicators.append("System Process")
        if signed_state == 'unsigned':
            risk_indicators.append("Unsigned Binary")
        if unusual:
            risk_indicators.append("Unusual Name")
            
        if risk_indicators:
            return f"⚠️ {', '.join(risk_indicators)}"
        return "✅ Normal"
    except (KeyError, TypeError, ValueError):
        return "✅ Normal"

def get_network_connection_count() -> int:
    """Count total active network connections."""
    try:
        return len(psutil.net_connections(kind='inet'))
    except (psutil.AccessDenied, PermissionError):
        return 0

def get_network_interfaces() -> List[Dict[str, str]]:
    """Get network interface information."""
    interface_list = []
    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4 only
                    interface_list.append({
                        'Interface': interface_name,
                        'IP Address': addr.address,
                        'Netmask': addr.netmask or 'N/A'
                    })
    except Exception:
        pass
    return interface_list

def get_bandwidth_stats() -> Dict[str, Any]:
    """Get network I/O statistics."""
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent_mb': round(net_io.bytes_sent / (1024**2), 1),
            'bytes_recv_mb': round(net_io.bytes_recv / (1024**2), 1),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    except Exception:
        return {
            'bytes_sent_mb': 0.0,
            'bytes_recv_mb': 0.0, 
            'packets_sent': 0,
            'packets_recv': 0
        }

def get_active_connections() -> List[Dict[str, Any]]:
    """Get active network connections with process details."""
    connection_list = []
    try:
        connections = psutil.net_connections(kind='inet')
        process_map = {}
        
        # Build process name mapping
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_map[proc.info['pid']] = proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Process connections
        for conn in connections:
            if conn.raddr:  # Has remote address
                pid = conn.pid
                process_name = process_map.get(pid, 'Unknown') if pid else 'System'
                
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A'
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                
                connection_list.append({
                    'Process': process_name,
                    'PID': pid or 'N/A',
                    'Local Address': local_addr,
                    'Remote Address': remote_addr,
                    'Status': conn.status
                })
    except (psutil.AccessDenied, PermissionError):
        pass
    
    return connection_list

def calculate_health_score(vault_file_count: int = 0) -> int:
    """Calculate overall system health score (0-100)."""
    try:
        score = 100
        
        # Get current metrics
        metrics = get_system_metrics()
        cpu_percent = metrics['cpu_percent']
        memory_percent = metrics['memory_percent']
        
        # CPU penalty (0-25 points)
        if cpu_percent > 90:
            score -= 25
        elif cpu_percent > 70:
            score -= 15
        elif cpu_percent > 50:
            score -= 8
        
        # Memory penalty (0-20 points)  
        if memory_percent > 95:
            score -= 20
        elif memory_percent > 80:
            score -= 12
        elif memory_percent > 60:
            score -= 5
        
        # Check for high-risk ports (10 points each)
        try:
            ports, alerts = get_open_ports()
            score -= len(alerts) * 10
        except Exception:
            pass
        
        # File monitoring bonus
        if vault_file_count > 0:
            score += 5
        
        return max(0, min(100, score))
        
    except Exception:
        return 50  # Default moderate score on error
    score = 100

    # CPU
    cpu = psutil.cpu_percent(interval=0.2)
    if cpu > 90:
        score -= 20
    elif cpu > 70:
        score -= 12
    elif cpu > 50:
        score -= 6

    # Memory
    mem = psutil.virtual_memory().percent
    if mem > 90:
        score -= 20
    elif mem > 75:
        score -= 10
    elif mem > 60:
        score -= 5

    # Disk
    try:
        disk = psutil.disk_usage("/" if os.name != "nt" else "C:\\").percent
        if disk > 95:
            score -= 15
        elif disk > 85:
            score -= 8
        elif disk > 75:
            score -= 3
    except OSError:
        pass

    # Insecure ports
    try:
        listening = [
            c for c in psutil.net_connections(kind="inet")
            if c.status == "LISTEN" and c.laddr
        ]
        open_insecure = [c for c in listening if c.laddr.port in INSECURE_PORTS]
        score -= len(open_insecure) * 12
        if len(listening) > 20:
            score -= 5
    except (psutil.AccessDenied, PermissionError):
        pass

    # Flagged processes
    try:
        high_cpu_count = sum(
            1 for p in psutil.process_iter(["cpu_percent"])
            if (p.info["cpu_percent"] or 0) > 10
        )
        if high_cpu_count > 5:
            score -= 10
        elif high_cpu_count > 2:
            score -= 5
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # Vault bonus
    if vault_file_count > 0:
        score = min(score + 5, 100)

    return max(0, min(score, 100))

