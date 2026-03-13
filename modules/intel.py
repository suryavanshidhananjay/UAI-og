"""
Threat intelligence helper for IP reputation lookups.
Uses public APIs when available; falls back to local blacklist scoring for demos.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any, Dict, List, Optional

import requests

# Local blacklist ranges for demo/offline detection (malicious/command-and-control archetypes)
LOCAL_BLACKLIST_CIDRS: List[str] = [
    "45.134.26.0/24",
    "79.137.192.0/21",
    "80.82.77.0/24",
    "91.132.137.0/24",
    "103.27.124.0/22",
    "103.72.19.0/24",
    "141.98.10.0/24",
    "156.146.34.0/24",
    "185.220.100.0/22",
    "185.56.80.0/22",
    "198.144.121.0/24",
    "212.102.32.0/22",
    "5.182.211.0/24",
    "89.248.163.0/24",
    "94.102.49.0/24",
    "109.70.100.0/24",
    "116.98.0.0/16",
    "185.191.34.0/23",
    "45.95.169.0/24",
    "107.189.1.0/24",
]


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _in_blacklist(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in LOCAL_BLACKLIST_CIDRS:
        try:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def _geo_lookup(ip: str) -> Dict[str, Any]:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
    except Exception:
        pass
    return {"country": None, "city": None, "lat": None, "lon": None}


def _abuseipdb_score(ip: str, api_key: str) -> Optional[int]:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            # AbuseIPDB returns confidence of abuse (0-100). Convert to trust score.
            abuse_confidence = int(data.get("abuseConfidenceScore", 0))
            return max(0, min(100, 100 - abuse_confidence))
    except Exception:
        return None
    return None


def check_ip_reputation(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Return reputation summary with trust score (0-100) and geo data."""
    result: Dict[str, Any] = {
        "ip": ip,
        "is_private": False,
        "trust_score": 100,
        "source": "local",
        "geo": {"country": None, "city": None, "lat": None, "lon": None},
        "high_priority": False,
        "notes": [],
    }

    if _is_private_ip(ip):
        result.update({"is_private": True, "notes": ["Private/local address – skipped."], "source": "local"})
        return result

    # Geo lookup first for context
    result["geo"] = _geo_lookup(ip)

    # Start from neutral trust and adjust
    trust = 100

    # Use AbuseIPDB if key present
    api_key = api_key or os.getenv("ABUSEIPDB_KEY")
    if api_key:
        abuse_trust = _abuseipdb_score(ip, api_key)
        if abuse_trust is not None:
            trust = abuse_trust
            result["source"] = "abuseipdb"
            result["notes"].append("AbuseIPDB score applied")

    # Local blacklist demo/fallback
    if _in_blacklist(ip):
        trust = min(trust, 15)
        result["source"] = "local_blacklist"
        result["notes"].append("Matched local blacklist range")

    # If no external data and no blacklist hit, keep default 100
    result["trust_score"] = trust
    result["high_priority"] = trust < 50
    return result


__all__ = ["check_ip_reputation", "LOCAL_BLACKLIST_CIDRS"]
