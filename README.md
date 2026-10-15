# 🔐 CBOM Scanner

**Cryptographic Bill of Materials (CBOM) Scanner for Post-Quantum Cryptography (PQC) Migration**

Aligned with **India's National Quantum Mission (NQM) Roadmap 2027-2028**

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg)](https://fastapi.tiangolo.com/)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-blue.svg)](https://cyclonedx.org/)

---

## 📖 Overview

**CBOM Scanner** ek cybersecurity tool hai jo organizations ke **code**, **networks**, aur **TLS/SSH servers** mein use hone wale cryptographic algorithms ko detect karta hai aur **CycloneDX 1.6 format** mein **CBOM (Cryptographic Bill of Materials)** report generate karta hai.

Yeh tool **quantum computing** ke aane wale khatre se bachne ke liye banaya gaya hai. Jab quantum computers aayenge (2030-2035), tab aaj ke **RSA**, **ECDSA**, **ECDH** jaise algorithms **Shor's algorithm** se toot jayenge. Isliye organizations ko **Post-Quantum Cryptography (PQC)** pe migrate karna hoga — aur uske liye pehle **CBOM** banana zaroori hai.

### 🇮🇳 India NQM Roadmap

| Year | Milestone |
|------|-----------|
| **2027** | Critical Information Infrastructure (CII) PQC ready |
| **2028** | Enterprise PQC ready |
| **2033** | Full migration |

---

## ✨ Features

### 1. 📁 Folder Scanner
- **Code files scan** karta hai (Python, Java, JS, TS, C/C++, Go, Rust, PHP, Ruby, C#, Kotlin, Swift, etc.)
- **Quantum-vulnerable algorithms** detect karta hai:
  - RSA, ECDSA, ECDH, DSA, DH, SHA-1, MD5
- **Context-aware detection** — comments, license text, TypeScript type definitions skip
- **Self-detection avoid** — apne scanner ke files skip karta hai
- **False positives 95% kam** (652 → 25 findings)
- **Config files, YAML, JSON, .env, .pem** bhi scan karta hai

### 2. 🌐 Network Scanner
- **Live TLS/SSH servers** scan karta hai
- **Port scanning** — Quick (7 ports), Standard (1-1024), Full (1-65535)
- **TLS versions detect:** TLS 1.0, 1.1, 1.2, 1.3
- **Cipher suites detect**
- **Certificate parsing:**
  - Subject, Issuer, Validity, Serial Number
  - Public Key (RSA-2048, EC-256, etc.)
  - Signature Algorithm
  - Subject Alt Names (SAN)
  - Expiry Status (Valid / ExpiringSoon / Expired)
- **SSH algorithms detect:** KEX, Ciphers, Host Keys
- **LDAP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis** detection

### 3. 📋 Multi-Host Scanner
- **Multiple hosts** ek saath scan karo (`hosts.txt` file se)
- **Combined report** generate karta hai
- **Duplicate hosts** automatically skip karta hai
- **Configurable limit** (default: 50 hosts)

### 4. 📊 Data Visualization
- **HTML report** with interactive charts:
  - TLS Version Distribution (Doughnut)
  - Quantum-Vulnerable Algorithms (Bar)
  - Certificate Issuers (Horizontal Bar)
  - Public Key Types (Pie)
- **Per-host details** table
- **Dark mode** UI

### 5. 📄 CBOM Report Generator
- **CycloneDX 1.6 format** output
- **PQC replacement suggestions** (NIST standards)
- **India NQM roadmap** structure
- **Risk-based prioritization** (HIGH/MEDIUM/LOW)
- **JSON + Text reports**
- **Timestamped filenames**

### 6. 🖥️ Web Dashboard
- **FastAPI-based** web interface
- **User authentication** (signup/login)
- **User-specific scans** — apne reports alag
- **Interactive charts** (Chart.js)
- **PDF export** (WeasyPrint)
- **Dark professional UI**

---

## 🔐 Security Features

Yeh tool **security-first** design kiya gaya hai:

| Feature | Implementation |
|---------|----------------|
| **Password Hashing** | bcrypt (SHA-256 nahi) |
| **CSRF Protection** | Double-submit cookie pattern |
| **Session Management** | Secure httponly cookies, configurable expiry |
| **Rate Limiting** | Login/signup pe 5-10 attempts per 5 min |
| **Path Traversal Protection** | `realpath` + separator check |
| **Admin Credentials** | Environment variables (hardcoded nahi) |
| **Password Strength** | 8+ chars, uppercase, lowercase, number |
| **SQL Injection** | Parameterized queries |
| **User Isolation** | Users sirf apne reports access kar sakte hain |

---

## 📊 Real-World Data (October 2026)

Humne **388 Indian websites** scan kiye — banks, government, IT companies, e-commerce, telecom, healthcare, education, stock exchanges, startups, manufacturing, media, aur travel.

### Key Findings

| Metric | Value |
|--------|-------|
| **Total Hosts Scanned** | 388 |
| **Successful Scans** | 330 (85%) |
| **Total Findings** | 578 |
| **TLSv1.3** | 72% |
| **TLSv1.2** | 13% |
| **No Data / Failed** | 15% |
| **Quantum-Vulnerable** | **100%** |
| **Expired Certificates** | **15%** |

### 🚨 Critical Findings

| Host | Issue | Priority |
|------|-------|----------|
| `cowin.gov.in` | Certificate EXPIRED | 🔴 HIGH |
| `kalyanjewellers.com` | Certificate EXPIRED | 🔴 HIGH |
| `iimnagpur.ac.in` | Certificate EXPIRED | 🔴 HIGH |
| `mtnl.net.in` | Certificate EXPIRED | 🔴 HIGH |
| `eicher.com` | Certificate EXPIRED | 🔴 HIGH |
| `india.gov.in` | Expiring in 4 days | 🟡 MEDIUM |
| `gem.gov.in` | TLSv1.2 + Expiring | 🔴 HIGH |
| `meta.com` | Expiring in 7 days | 🟡 MEDIUM |

### 📈 Algorithm Distribution

| Algorithm | Count | Risk | PQC Replacement |
|-----------|-------|------|-----------------|
| **RSA** | 400+ | 🔴 HIGH | ML-KEM (Kyber) / ML-DSA (Dilithium) |
| **ECDSA** | 80+ | 🔴 HIGH | ML-DSA (Dilithium) |
| **ECDH** | 60+ | 🔴 HIGH | ML-KEM (Kyber) |
| **DH** | 60+ | 🔴 HIGH | ML-KEM (Kyber) |
| **Certificate-ExpiringSoon** | 30+ | 🟡 MEDIUM | Renew certificate |
| **Certificate-Expired** | 5+ | 🔴 HIGH | Renew immediately |

### 🔬 Key Research Finding

> **"India ki 72% websites TLSv1.3 use kar rahi hain, lekin 100% websites quantum-vulnerable algorithms (RSA, ECDSA, ECDH) use kar rahi hain. 15% websites ke certificates expire ho chuke hain ya jaldi expire ho rahe hain. India ke NQM Roadmap 2027-2028 ke according, in sabko PQC pe migrate karna hoga."**

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.12+ |
| **Web Framework** | FastAPI + Uvicorn |
| **Templating** | Jinja2 |
| **Database** | SQLite (WAL mode) |
| **Crypto** | `cryptography`, `pyopenssl` |
| **SSH** | `paramiko` |
| **CBOM Format** | `cyclonedx-python-lib` |
| **PDF Export** | WeasyPrint |
| **Charts** | Chart.js |
| **Password Hashing** | `passlib[bcrypt]` |
| **Frontend** | HTML5 + CSS3 + Vanilla JS |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher
- pip
- Git

### Step 1: Clone Repository

```bash
git clone https://github.com/MrFaiz143/cbom-scanner.git
cd cbom-scanner