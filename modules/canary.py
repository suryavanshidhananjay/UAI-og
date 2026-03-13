"""Real-time honeypot canary that kills offending processes on access.

Requires watchdog and psutil. This module creates a hidden bait file and watches
for access/modification/deletion in a background observer thread. Any process
that touches the bait is terminated immediately and a breach flag is raised
for the UI to consume.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Optional

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BAIT_PATH = Path(r"C:\Users\Public\Documents\financial_records.xlsx")
_breach_flag = False
_breach_details: dict[str, str] = {}
_observer: Optional[Observer] = None
_lock = threading.Lock()


def _ensure_bait_file() -> None:
    """Create the bait file and hide it on Windows."""
    BAIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not BAIT_PATH.exists():
        BAIT_PATH.write_text("Confidential financial records\n", encoding="utf-8")
    # Hide the file (best-effort)
    try:
        os.system(f"attrib +h {BAIT_PATH}")
    except Exception:
        pass


def _find_processes_touching(path: Path) -> list[psutil.Process]:
    offenders: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "name", "open_files"]):
        try:
            files = proc.info.get("open_files") or []
            for f in files:
                if f.path and Path(f.path) == path:
                    offenders.append(proc)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return offenders


def _kill_processes(procs: list[psutil.Process]) -> None:
    for proc in procs:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


class _CanaryHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        # Trigger on access/modify/delete/move touching the bait file
        if BAIT_PATH.samefile(event.src_path) if hasattr(event, "src_path") else False:
            _trigger_breach(event.event_type)


def _trigger_breach(event_type: str) -> None:
    global _breach_flag, _breach_details
    with _lock:
        _breach_flag = True
        offenders = _find_processes_touching(BAIT_PATH)
        _kill_processes(offenders)
        offender_pids = ",".join(str(p.pid) for p in offenders) if offenders else "unknown"
        offender_names = ",".join(p.name() for p in offenders if p) if offenders else "unknown"
        _breach_details = {
            "event": event_type,
            "pids": offender_pids,
            "names": offender_names,
            "path": str(BAIT_PATH),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


def start_canary() -> bool:
    """Start the background observer that monitors the bait file."""
    global _observer
    with _lock:
        if _observer and _observer.is_alive():
            return True
        _ensure_bait_file()
        handler = _CanaryHandler()
        observer = Observer()
        observer.schedule(handler, BAIT_PATH.parent, recursive=False)
        observer.daemon = True
        observer.start()
        _observer = observer
        return True


def stop_canary() -> None:
    global _observer
    with _lock:
        if _observer:
            try:
                _observer.stop()
                _observer.join(timeout=2)
            finally:
                _observer = None


def breach_flag() -> bool:
    with _lock:
        return _breach_flag


def breach_info() -> dict[str, str]:
    with _lock:
        return dict(_breach_details)


__all__ = [
    "start_canary",
    "stop_canary",
    "breach_flag",
    "breach_info",
    "BAIT_PATH",
]
