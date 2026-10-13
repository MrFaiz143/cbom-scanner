# CBOM Scanner

**Cryptographic Bill of Materials (CBOM) Scanner for Post-Quantum Cryptography (PQC) Migration**

Aligned with **India's National Quantum Mission (NQM) Roadmap 2027-2028**

---

## Overview

CBOM Scanner ek **cybersecurity tool** hai jo organizations ke systems aur networks mein use hone wale cryptographic algorithms ko detect karta hai aur **CycloneDX 1.6 format** mein CBOM report generate karta hai.

Yeh tool **quantum computing** ke aane wale khatre se bachne ke liye banaya gaya hai. Jab quantum computers aayenge, tab aaj ke RSA, ECDSA, ECDH jaise algorithms **toot jayenge**. Isliye organizations ko **Post-Quantum Cryptography (PQC)** pe migrate karna hoga — aur uske liye pehle **CBOM** banana zaroori hai.

---

## Features

### 1. Folder Scanner
- Code files scan karta hai (Python, Java, JS, C/C++, Go, etc.)
- Quantum-vulnerable algorithms detect karta hai: RSA, ECDSA, ECDH, DSA, DH, SHA-1, MD5
- Context-aware detection (comments, license text skip)
- Self-detection avoid karta hai
- False positives 95% kam

### 2. Network Scanner
- Live TLS/SSH servers scan karta hai
- Top 5000+ ports support
- TLS versions detect: TLS 1.0, 1.1, 1.2, 1.3
- Cipher suites detect
- Certificate parsing (Subject, Issuer, Validity, Public Key, SAN)
- SSH algorithms detect (KEX, Ciphers, Host Keys)
- LDAP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis detection

### 3. CBOM Report Generator
- CycloneDX 1.6 format output
- India NQM roadmap structure
- Risk-based prioritization (HIGH/MEDIUM/LOW)
- JSON + Text reports
- Timestamped filenames

---

## Tech Stack

- **Python 3.12+**
- **Libraries:**
  - `cryptography` — Crypto algorithms detect
  - `requests` — HTTP requests
  - `pyyaml` — Config files
  - `cyclonedx-python-lib` — CBOM format
  - `paramiko` — SSH scanning
  - `pyopenssl` — Certificate parsing

---

## Installation

### Step 1: Repository Clone Karo

```bash
git clone https://github.com/MrFaiz143/cbom-scanner.git
cd cbom-scanner