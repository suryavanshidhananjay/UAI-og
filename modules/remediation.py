"""
Real system hardening routines for Windows hosts.
Executes firewall and DNS actions using native utilities; requires Administrator.
"""
from __future__ import annotations

import ctypes
import platform
import subprocess
from typing import Iterable

from modules.system import get_open_ports

INSECURE_PORTS: tuple[int, ...] = (21, 23, 445)


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    if not _is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd: str) -> bool:
    """Run a shell command with strict failure handling."""
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return True
    except Exception:
        return False


def enable_firewall() -> bool:
    """Force-enable Windows Firewall for all profiles via netsh."""
    if not (_is_windows() and is_admin()):
        return False
    return _run("netsh advfirewall set allprofiles state on")


def block_malicious_ip(ip: str) -> bool:
    """Create inbound and outbound firewall block rules for a specific IP."""
    if not (_is_windows() and is_admin()):
        return False
    inbound = _run(f"netsh advfirewall firewall add rule name=CG_BLOCK_IN_{ip} dir=in action=block remoteip={ip}")
    outbound = _run(f"netsh advfirewall firewall add rule name=CG_BLOCK_OUT_{ip} dir=out action=block remoteip={ip}")
    return inbound and outbound


def _block_port(port: int) -> bool:
    """Block a single port for inbound and outbound traffic."""
    inbound = _run(f"netsh advfirewall firewall add rule name=CG_BLOCK_IN_{port} dir=in action=block protocol=TCP localport={port}")
    outbound = _run(f"netsh advfirewall firewall add rule name=CG_BLOCK_OUT_{port} dir=out action=block protocol=TCP localport={port}")
    return inbound and outbound


def close_insecure_ports(ports: Iterable[int] | None = None) -> bool:
    """Detect insecure open ports and block them using firewall rules."""
    if not (_is_windows() and is_admin()):
        return False

    target_ports = tuple(ports) if ports is not None else INSECURE_PORTS
    try:
        open_ports, _alerts = get_open_ports()
        open_set = {p.get("Port") for p in open_ports if isinstance(p, dict)}
    except Exception:
        open_set = set()

    success = True
    for port in target_ports:
        if port in open_set:
            success = _block_port(port) and success
    return success


def flush_dns_cache() -> bool:
    """Flush the DNS cache to clear potential poisoning."""
    if not (_is_windows() and is_admin()):
        return False
    return _run("ipconfig /flushdns")


__all__ = [
    "enable_firewall",
    "block_malicious_ip",
    "close_insecure_ports",
    "flush_dns_cache",
    "is_admin",
    "INSECURE_PORTS",
]
