"""
CYBERGUARD Vault Module — Persistent File Integrity Monitoring

Core capabilities:
- get_file_hash: SHA-256 hashing with binary reads for any file type
- create_baseline: Recursive baseline map {path: hash} for a directory
- monitor_changes: Fast diff with mtime short-circuit before hashing
- save_baseline / load_baseline: Persist baselines to vault_db.json so the
  "Original" state survives app restarts

All functions are defensive: inaccessible files are skipped, and errors do not
halt the scan.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional, Tuple

# Baseline persistence location (workspace root by default)
VAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vault_db.json"))


# ══════════════════════════════════════════════════════════════
# Hashing
# ══════════════════════════════════════════════════════════════

def get_file_hash(path: str) -> Optional[str]:
    """Return SHA-256 hash for a file using chunked binary reads; None on error."""
    try:
        sha = hashlib.sha256()
        with open(path, "rb", buffering=65536) as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except (OSError, PermissionError, FileNotFoundError):
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# Baseline creation and change monitoring
# ══════════════════════════════════════════════════════════════

def _scan_directory(directory: str) -> Tuple[Dict[str, str], Dict[str, float]]:
    """Internal scan helper that returns hashes and mtimes for all regular files."""
    hashes: Dict[str, str] = {}
    mtimes: Dict[str, float] = {}

    root_dir = os.path.abspath(directory)
    if not os.path.isdir(root_dir):
        return hashes, mtimes

    for current_root, _, files in os.walk(root_dir):
        for name in files:
            path = os.path.abspath(os.path.join(current_root, name))
            if not os.path.isfile(path):
                continue
            try:
                mt = os.path.getmtime(path)
                file_hash = get_file_hash(path)
                if file_hash is None:
                    continue
                hashes[path] = file_hash
                mtimes[path] = mt
            except (OSError, PermissionError, FileNotFoundError):
                continue
            except Exception:
                continue

    return hashes, mtimes


def create_baseline(directory: str) -> Dict[str, str]:
    """Create and return a baseline mapping {path: hash} for the directory."""
    hashes, _ = _scan_directory(directory)
    return hashes


def monitor_changes(directory: str, baseline: Dict[str, str], baseline_mtimes: Optional[Dict[str, float]] = None) -> Dict[str, List[str]]:
    """
    Scan the directory and report modifications relative to the baseline.

    Uses mtime short-circuiting: if a file's mtime matches the stored mtime,
    hashing is skipped for speed on large folders.
    """
    baseline_mtimes = baseline_mtimes or {}
    modified: List[str] = []
    added: List[str] = []
    removed: List[str] = []

    current_hashes: Dict[str, str] = {}
    current_mtimes: Dict[str, float] = {}

    root_dir = os.path.abspath(directory)
    if os.path.isdir(root_dir):
        for current_root, _, files in os.walk(root_dir):
            for name in files:
                path = os.path.abspath(os.path.join(current_root, name))
                if not os.path.isfile(path):
                    continue

                try:
                    mt = os.path.getmtime(path)
                except (OSError, PermissionError, FileNotFoundError):
                    continue

                # Fast path: unchanged mtime means unchanged content (skip hash)
                if path in baseline and baseline_mtimes.get(path) == mt:
                    current_mtimes[path] = mt
                    continue

                file_hash = get_file_hash(path)
                if file_hash is None:
                    continue
                current_hashes[path] = file_hash
                current_mtimes[path] = mt

                if path in baseline:
                    if file_hash != baseline[path]:
                        modified.append(path)
                else:
                    added.append(path)

    # Removed files: in baseline but not present now
    present_paths = set(current_hashes.keys()) | set(current_mtimes.keys())
    for path in baseline:
        if path not in present_paths:
            removed.append(path)

    modified.sort()
    added.sort()
    removed.sort()

    return {"modified": modified, "added": added, "removed": removed}


# ══════════════════════════════════════════════════════════════
# Persistence
# ══════════════════════════════════════════════════════════════

def save_baseline(baseline: Dict[str, str], baseline_mtimes: Optional[Dict[str, float]] = None, db_path: str = VAULT_DB_PATH) -> bool:
    """Persist baseline (and optional mtimes) to vault_db.json."""
    payload = {
        "baseline": baseline,
        "mtimes": baseline_mtimes or {},
    }
    try:
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return True
    except Exception:
        return False


def load_baseline(db_path: str = VAULT_DB_PATH) -> Tuple[Dict[str, str], Dict[str, float]]:
    """Load baseline and mtimes from vault_db.json; returns empty dicts on failure."""
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        baseline = data.get("baseline", {}) or {}
        mtimes = data.get("mtimes", {}) or {}
        return baseline, mtimes
    except Exception:
        return {}, {}


# ══════════════════════════════════════════════════════════════
# Legacy compatibility for existing app imports
# ══════════════════════════════════════════════════════════════

def calculate_sha256(file_path: str) -> Optional[str]:
    return get_file_hash(file_path)


def create_directory_snapshot(dir_path: str) -> Dict[str, str]:
    return create_baseline(dir_path)


def compare_snapshots(old_snapshot: Dict[str, str], new_snapshot: Dict[str, str]) -> Tuple[List[str], List[str], List[str]]:
    modified: List[str] = []
    added: List[str] = []
    deleted: List[str] = []

    old_norm = {os.path.normpath(p): h for p, h in old_snapshot.items()}
    new_norm = {os.path.normpath(p): h for p, h in new_snapshot.items()}

    for path, old_hash in old_norm.items():
        if path in new_norm:
            if old_hash != new_norm[path]:
                modified.append(path)
        else:
            deleted.append(path)

    for path in new_norm:
        if path not in old_norm:
            added.append(path)

    return sorted(modified), sorted(added), sorted(deleted)


def hash_file(filepath: str) -> Optional[str]:
    return calculate_sha256(filepath)


def scan_folder(folder_path: str) -> Dict[str, str]:
    return create_directory_snapshot(folder_path)


def count_files_on_disk(folder_path: str) -> int:
    try:
        total = 0
        for _, _, files in os.walk(os.path.abspath(folder_path)):
            total += len(files)
        return total
    except (OSError, PermissionError):
        return 0


def verify_integrity(baseline: Dict[str, str], folder_path: str) -> Tuple[Dict[str, str], List[str], List[str], List[str]]:
    current_snapshot, _ = _scan_directory(folder_path)
    diff = monitor_changes(folder_path, baseline)
    # Preserve legacy return order: current, modified, deleted, added
    return current_snapshot, diff["modified"], diff["removed"], diff["added"]
