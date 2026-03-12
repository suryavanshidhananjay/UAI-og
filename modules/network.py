"""
CYBERGUARD Network Scanning Module
----------------------------------

This module provides real-time network discovery capabilities for CYBERGUARD.
It attempts to use Scapy for Layer-2 ARP probing (requires Npcap/WinPcap on Windows).
If Layer-2 access is unavailable (common on default Windows installs), it gracefully
falls back to a "Ping Sweep + ARP Table" method using standard system tools.

Requirements Covered:
    - local subnet detection with automatic /24 inference.
    - Real-time ARP scanning via scapy.srp() (Primary).
    - Fallback scanning via threaded Ping + ARP parsing (Secondary).
    - Vendor lookup using known OUI prefixes.
    - Explicit permission error messaging.

Dependencies:
    - scapy
    - socket
    - ipaddress
    - getmac
    - threading/subprocess (for fallback)
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import logging
from typing import Dict, List, Optional, Tuple

# Vendor prefixes (OUI → Vendor name). Extend as needed for better coverage.
MAC_VENDOR_PREFIXES: Dict[str, str] = {
    "00:1A:79": "Apple",
    "00:1B:63": "Apple",
    "00:1E:C2": "Dell",
    "00:1F:3B": "Sony",
    "00:21:5C": "Samsung",
    "00:24:E8": "Cisco",
    "00:25:86": "Intel",
    "00:26:08": "Asus",
    "00:50:56": "VMware",
    "00:90:27": "Hewlett Packard",
    "3C:5A:B4": "Google",
    "3C:D9:2B": "Xiaomi",
    "44:65:0D": "Amazon",
    "AC:CF:5C": "OnePlus",
    "B4:2E:99": "Microsoft",
    "D8:BB:2C": "Lenovo",
    "FC:FB:FB": "Facebook/Meta",
}


def _normalize_mac(mac_address: str) -> str:
    """Normalize MAC address to uppercase colon-separated format."""
    return mac_address.upper().replace("-", ":")


def get_mac_vendor(mac_address: str) -> str:
    """Return the vendor/manufacturer name inferred from MAC OUI."""
    if not mac_address:
        return "Unknown Device"
    normalized = _normalize_mac(mac_address)
    prefix = normalized[:8]
    return MAC_VENDOR_PREFIXES.get(prefix, "Unknown Device")


def get_local_subnet(default_cidr: int = 24) -> str:
    """Detect the local host IP and infer a subnet (default /24)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
    except OSError:
        local_ip = socket.gethostbyname(socket.gethostname())

    network = ipaddress.ip_network(f"{local_ip}/{default_cidr}", strict=False)
    return str(network)


def _ping_host(ip: str) -> bool:
    """Ping a host to populate the local ARP cache."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Short timeout (200ms) to speed up scan
    extra_args = ['-w', '200'] if platform.system().lower() == 'windows' else ['-W', '1']
    
    command = ['ping', param, '1', ip] + extra_args
    try:
        if platform.system().lower() == "windows":
             # Create startupinfo to hide console window
             startupinfo = subprocess.STARTUPINFO()
             startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
             return subprocess.call(command, startupinfo=startupinfo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        else:
             return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def _fallback_scan(target_ip_range: str) -> Tuple[List[Dict[str, str]], Optional[str]]:
    """
    Execute a robust fallback scan using system Ping + ARP table.
    Used when raw sockets (WinPcap/Npcap) are unavailable.
    """
    try:
        # 1. Parse Target Range
        network = ipaddress.ip_network(target_ip_range, strict=False)
        # Limit to 254 hosts max for performance
        try:
            hosts = [str(ip) for ip in list(network.hosts())[:254]]
        except Exception:
            # If network.hosts() fails (e.g. single IP), just use basic list
            hosts = [str(network.network_address)]

        # 2. Multi-threaded Ping Sweep (Active Discovery)
        # This forces the OS to resolve MAC addresses for active hosts
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(_ping_host, hosts))
            
        # 3. Read System ARP Table (Passive Collection)
        # We read the OS's cache which is now populated with fresh data
        arp_output = subprocess.check_output(['arp', '-a'], text=True)
        devices = []
        
        # Regex to capture IP and MAC from 'arp -a' output
        # Matches: "  192.168.1.1          00-11-22-33-44-55     dynamic"
        pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})')
        
        # Helper check for IP in subnet
        def is_in_subnet(ip_str):
            try:
                return ipaddress.ip_address(ip_str) in network
            except ValueError:
                return False

        for line in arp_output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac = match.groups()
                # Ensure the IP belongs to our target subnet
                if is_in_subnet(ip):
                    normalized_mac = mac.replace('-', ':').upper()
                    # Filter out multicast/broadcast MACs
                    if not normalized_mac.startswith('FF:FF'):
                        devices.append({
                            "IP Address": ip,
                            "MAC Address": normalized_mac,
                            "Vendor": get_mac_vendor(normalized_mac),
                        })
        
        # Sort by IP address for clean display
        devices.sort(key=lambda x: ipaddress.ip_address(x['IP Address']))
        return devices, None

    except Exception as e:
        return [], f"Fallback scan failed: {str(e)}"


def scan_network(target_ip_range: str | None = None, timeout: int = 2) -> Tuple[List[Dict[str, str]], Optional[str]]:
    """
    Perform a network scan using the best available method.
    
    1. Tries Scapy Layer-2 ARP Scan (Fastest, requires Npcap/Admin).
    2. Fallbacks to Ping Sweep + ARP Table (Slower, works everywhere).
    """
    if target_ip_range is None:
        target_ip_range = get_local_subnet()

    try:
        # ATTEMPT 1: Scapy Layer-2 ARP Scan (Lazy Loaded)
        
        # Suppress Scapy warning about missing libpcap
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import ARP, Ether, srp  # type: ignore

        # This requires WinPcap/Npcap driver
        arp_request = ARP(pdst=target_ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        # If Npcap is missing, this line will raise RuntimeError or Scapy_Exception
        answered, _ = srp(packet, timeout=timeout, verbose=0)

        devices: List[Dict[str, str]] = []
        for _sent, received in answered:
            devices.append(
                {
                    "IP Address": received.psrc,
                    "MAC Address": received.hwsrc,
                    "Vendor": get_mac_vendor(received.hwsrc),
                }
            )
        
        # Sort results
        devices.sort(key=lambda x: ipaddress.ip_address(x['IP Address']))
        return devices, None

    except Exception:
        # Catch ALL exceptions including Scapy_Exception, RuntimeError, etc.
        # If the primary scan fails for ANY reason (no driver, no admin, etc.), fallback.
        try:
             return _fallback_scan(target_ip_range)
        except Exception as e_fallback:
             return [], f"All scan methods failed. Root cause: {e_fallback}"


__all__ = [
    "get_local_subnet",
    "scan_network",
    "get_mac_vendor",
]
