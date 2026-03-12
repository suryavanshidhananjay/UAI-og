"""
CYBERGUARD Identity & Password Analysis Module
----------------------------------------------
Advanced cryptographic analysis for password strength, entropy calculation,
and breach detection using the zxcvbn engine.

Dependencies:
    - zxcvbn (pip install zxcvbn)
    - math (stdlib)
"""

import math
import string
from typing import Any, Dict, List, Tuple, Union

try:
    from zxcvbn import zxcvbn
except ImportError:
    # Fallback if library not found, though we installed it.
    zxcvbn = None  # type: ignore

# Top 20 most common passwords (a small local blacklist for immediate checks)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "admin", "welcome", "google", "princess", "123123",
    "football", "monkey", "charlie", "jordan", "michael"
}

DICTIONARY_ATTACK_LIST = [
    "admin", "password", "welcome", "p@ssword", "root", "user", 
    "login", "guest", "default", "123456", "secret", "pass",
    "qwerty", "system", "support"
]

def is_dictionary_word(password: str) -> Union[str, None]:
    """
    Check if the password contains common dictionary terms.
    Returns a warning string if a match is found, otherwise None.
    """
    if not password:
        return None
        
    pwd_lower = password.lower()
    # Check for direct dictionary words or common substitutions
    for word in DICTIONARY_ATTACK_LIST:
        if word in pwd_lower:
             return "High Risk: Dictionary Attack Vulnerable"
    return None

def analyze_password_strength(password: str) -> Dict[str, Any]:
    """
    Perform deep analysis using zxcvbn engine.
    
    Returns:
        dict: Containing 'score' (0-4), 'crack_time_display', 'suggestions',
              and raw calculation data.
    """
    if not password:
        return {
            "score": 0,
            "crack_time_display": "Instant",
            "suggestions": ["Password cannot be empty"],
            "feedback": None
        }

    dict_warning = is_dictionary_word(password)

    if zxcvbn:
        results = zxcvbn(password)
        feedback = results.get("feedback", {})
        crack_times = results.get("crack_times_display", {})
        
        warning = feedback.get("warning", "")
        if dict_warning:
            if warning:
                warning = f"{warning}. {dict_warning}"
            else:
                warning = dict_warning

        return {
            "score": results["score"],  # 0-4
            "crack_time_display": crack_times.get("offline_slow_hashing_1e4_per_second", "Unknown"),
            "suggestions": feedback.get("suggestions", []),
            "warning": warning,
            "guesses_log10": results.get("guesses_log10", 0)
        }
    else:
        # Fallback if zxcvbn is missing
        return {
            "score": 0,
            "crack_time_display": "Unknown (Library Missing)",
            "suggestions": ["Install 'zxcvbn' for deep analysis"],
            "warning": dict_warning if dict_warning else "Analysis engine unavailable"
        }

def get_entropy(password: str) -> float:
    """
    Calculate the Shannon entropy (in bits) of the password based on character pool size.
    
    Formula: L * log2(R)
    Where L = length of password
          R = size of character pool (26 lower + 26 upper + 10 digits + 32 symbols)
    """
    if not password:
        return 0.0
        
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    
    # Avoid log(0) if characters are outside standard ascii sets
    if pool_size == 0:
        pool_size = 1  # Minimum pool size
        
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def check_breached_password(password: str) -> bool:
    """
    Check if the password exists in a local list of commonly leaked passwords.
    Returns: True if breached/common, False if unique locally.
    """
    return password.lower() in COMMON_PASSWORDS

def check_complexity(password: str) -> Dict[str, bool]:
    """
    Verify presence of character types (Uppercase, Lowercase, Numbers, Special).
    """
    return {
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(c in string.punctuation for c in password),
        "length_ok": len(password) >= 12
    }

__all__ = [
    "analyze_password_strength",
    "get_entropy",
    "check_breached_password",
    "check_complexity",
    "is_dictionary_word"
]
