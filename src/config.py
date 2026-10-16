"""
CBOM Scanner - Central Configuration
Saari settings ek jagah. Environment variables se load hoti hain.
"""

import os
from pathlib import Path

# ============================================================
# BASE PATHS
# ============================================================

# Project root (jahan se app run ho raha hai)
BASE_DIR = Path(__file__).resolve().parent.parent

# Vercel serverless pe sirf /tmp writable hota hai
IS_VERCEL = bool(os.getenv("VERCEL"))
WRITABLE_DIR = Path("/tmp") if IS_VERCEL else BASE_DIR

# Reports folder
REPORTS_DIR = Path(os.getenv("CBOM_REPORTS_DIR", WRITABLE_DIR / "reports"))
try:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    # Read-only filesystem pe import crash nahi hona chahiye
    pass

# Database path (legacy SQLite, ab PostgreSQL use hota hai)
DB_PATH = os.getenv("CBOM_DB_PATH", str(WRITABLE_DIR / "cbom_scanner.db"))

# Web directory
WEB_DIR = BASE_DIR / "web"
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"


# ============================================================
# ADMIN AUTH (Environment variables se)
# ============================================================

ADMIN_USERNAME = os.getenv("CBOM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("CBOM_ADMIN_PASS")

# Agar password set nahi hai to error do (production safety)
if not ADMIN_PASSWORD:
    # Development ke liye default, lekin warning print karo
    import warnings
    warnings.warn(
        "⚠️  CBOM_ADMIN_PASS environment variable set nahi hai! "
        "Default insecure password use ho raha hai. "
        "Production me ise set karo.",
        RuntimeWarning
    )
    ADMIN_PASSWORD = "change-me-in-production"


# ============================================================
# SESSION / SECURITY
# ============================================================

# Session token validity (days)
SESSION_EXPIRY_DAYS = int(os.getenv("CBOM_SESSION_DAYS", "7"))

# Cookie security (production me True)
COOKIE_SECURE = os.getenv("CBOM_COOKIE_SECURE", "false").lower() == "true"

# Cookie SameSite policy
COOKIE_SAMESITE = os.getenv("CBOM_COOKIE_SAMESITE", "lax")

# Password minimum length
MIN_PASSWORD_LENGTH = int(os.getenv("CBOM_MIN_PASSWORD_LEN", "8"))


# ============================================================
# SCAN PROFILES
# ============================================================

# Quick scan - common ports
QUICK_PORTS = [443, 22, 8443, 993, 995, 465, 636]

# Standard scan - well-known ports (1-1024)
STANDARD_PORTS = list(range(1, 1025))

# Full scan - all ports (slow)
FULL_PORTS = list(range(1, 65536))

# Multi-host scan limit (max hosts per file)
MAX_MULTI_HOSTS = int(os.getenv("CBOM_MAX_MULTI_HOSTS", "50"))

# Scan timeout (seconds)
SCAN_TIMEOUT = int(os.getenv("CBOM_SCAN_TIMEOUT", "10"))
PORT_TIMEOUT = int(os.getenv("CBOM_PORT_TIMEOUT", "3"))

# Concurrent workers for port scanning
MAX_WORKERS = int(os.getenv("CBOM_MAX_WORKERS", "50"))


# ============================================================
# SCAN PROFILES MAP (UI ke liye)
# ============================================================

SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Common ports (7 ports) - fastest",
        "ports": QUICK_PORTS,
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Well-known ports (1-1024) - balanced",
        "ports": STANDARD_PORTS,
    },
    "full": {
        "name": "Full Scan",
        "description": "All 65535 ports - slowest but thorough",
        "ports": FULL_PORTS,
    },
}


# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = os.getenv("CBOM_LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ============================================================
# APP INFO
# ============================================================

APP_NAME = "CBOM Scanner"
APP_VERSION = "0.9.0"
APP_DESCRIPTION = "Cryptographic Bill of Materials Scanner for PQC Migration"


# ============================================================
# PQC REPLACEMENT MAPPING (NIST Standards)
# ============================================================

PQC_REPLACEMENTS = {
    "RSA": {
        "replacement": "ML-KEM (Kyber) / ML-DSA (Dilithium)",
        "standard": "NIST FIPS 203 / FIPS 204",
        "note": "RSA key exchange → ML-KEM; RSA signatures → ML-DSA",
    },
    "ECDSA": {
        "replacement": "ML-DSA (Dilithium)",
        "standard": "NIST FIPS 204",
        "note": "Elliptic curve signatures → ML-DSA",
    },
    "ECDH": {
        "replacement": "ML-KEM (Kyber)",
        "standard": "NIST FIPS 203",
        "note": "Elliptic curve key agreement → ML-KEM",
    },
    "DH": {
        "replacement": "ML-KEM (Kyber)",
        "standard": "NIST FIPS 203",
        "note": "Diffie-Hellman key exchange → ML-KEM",
    },
    "DSA": {
        "replacement": "ML-DSA (Dilithium)",
        "standard": "NIST FIPS 204",
        "note": "DSA signatures → ML-DSA",
    },
    "SHA-1": {
        "replacement": "SHA-3 / SHAKE",
        "standard": "NIST FIPS 202",
        "note": "SHA-1 deprecated → SHA-3",
    },
    "MD5": {
        "replacement": "SHA-3",
        "standard": "NIST FIPS 202",
        "note": "MD5 broken → SHA-3",
    },
    "3DES": {
        "replacement": "AES-256-GCM",
        "standard": "NIST SP 800-38D",
        "note": "3DES vulnerable to Sweet32 → AES-256",
    },
    "RC4": {
        "replacement": "AES-256-GCM / ChaCha20-Poly1305",
        "standard": "NIST SP 800-38D / RFC 8439",
        "note": "RC4 broken → AES or ChaCha20",
    },
    "DES": {
        "replacement": "AES-256-GCM",
        "standard": "NIST SP 800-38D",
        "note": "DES 56-bit key → AES-256",
    },
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_scan_profile(profile_name: str) -> list:
    """Profile name se ports list return karo."""
    profile = SCAN_PROFILES.get(profile_name.lower())
    if profile:
        return profile["ports"]
    # Default to quick
    return QUICK_PORTS


def is_production() -> bool:
    """Check karo ki production mode me hain ya nahi."""
    return os.getenv("CBOM_ENV", "development").lower() == "production"