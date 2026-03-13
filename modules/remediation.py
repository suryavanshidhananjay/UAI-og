"""Active remediation engine for Windows hosts (real commands, no simulation)."""
from __future__ import annotations

import ctypes
import platform
import subprocess
from dataclasses import dataclass
from typing import Iterable

INSECURE_PORTS: tuple[int, ...] = (21, 23, 445)


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def check_admin() -> bool:
    """Return True only if running with Administrator privileges."""
    if not _is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@dataclass
class CommandResult:
    cmd: str
    success: bool
    stdout: str
    stderr: str
    returncode: int

    def __bool__(self) -> bool:
        return self.success


def _run(cmd: list[str]) -> CommandResult:
    """Execute a command with captured output for UI reporting."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            shell=False,
        )
        return CommandResult(
            cmd=" ".join(cmd),
            success=completed.returncode == 0,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            returncode=completed.returncode,
        )
    except Exception as exc:
        return CommandResult(cmd=" ".join(cmd), success=False, stdout="", stderr=str(exc), returncode=-1)


def enable_firewall() -> CommandResult:
    """Execute netsh to force-enable the firewall on all profiles."""
    if not (_is_windows() and check_admin()):
        return CommandResult("netsh advfirewall set allprofiles state on", False, "", "Admin rights or Windows required", -1)
    return _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])


def close_risky_ports(ports: Iterable[int] | None = None) -> CommandResult:
    """Identify and close risky ports (FTP, Telnet, SMB) using PowerShell."""
    target_ports = tuple(ports) if ports is not None else INSECURE_PORTS
    if not (_is_windows() and check_admin()):
        return CommandResult("powershell close risky ports", False, "", "Admin rights or Windows required", -1)

    # PowerShell script: stop listeners and add firewall blocks for each target port.
    ps_script = r"""
$ports = @({ports});
$messages = @();
foreach ($p in $ports) {{
    $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue;
    foreach ($c in $conns) {{
        try {{
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue;
            $messages += "Stopped PID $($c.OwningProcess) on port $p";
        }} catch {{
            $messages += "Failed to stop PID $($c.OwningProcess) on port $p: $($_.Exception.Message)";
        }}
    }}
    netsh advfirewall firewall add rule name="CG_BLOCK_IN_$p" dir=in action=block protocol=TCP localport=$p | Out-Null;
    netsh advfirewall firewall add rule name="CG_BLOCK_OUT_$p" dir=out action=block protocol=TCP localport=$p | Out-Null;
    $messages += "Firewall rules added for port $p";
}}
$messages -join "`n"
""".format(ports=",".join(str(p) for p in target_ports))

    return _run(["powershell", "-NoProfile", "-Command", ps_script])


def block_ip(ip_address: str) -> CommandResult:
    """Block all inbound/outbound traffic for the specified IP via firewall rules."""
    if not (_is_windows() and check_admin()):
        return CommandResult(f"block_ip {ip_address}", False, "", "Admin rights or Windows required", -1)

    ps_script = rf"""
netsh advfirewall firewall add rule name="CG_BLOCK_IN_{ip_address}" dir=in action=block remoteip={ip_address} | Out-Null;
netsh advfirewall firewall add rule name="CG_BLOCK_OUT_{ip_address}" dir=out action=block remoteip={ip_address} | Out-Null;
Write-Output "Firewall blocks added for {ip_address}";
"""
    return _run(["powershell", "-NoProfile", "-Command", ps_script])


def flush_dns_cache() -> CommandResult:
    """Flush the DNS cache to clear potential poisoning."""
    if not (_is_windows() and check_admin()):
        return CommandResult("ipconfig /flushdns", False, "", "Admin rights or Windows required", -1)
    return _run(["ipconfig", "/flushdns"])


__all__ = [
    "enable_firewall",
    "close_risky_ports",
    "block_ip",
    "flush_dns_cache",
    "check_admin",
    "CommandResult",
    "INSECURE_PORTS",
]
