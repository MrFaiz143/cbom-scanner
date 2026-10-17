"""
CBOM Scanner - Web Dashboard (v1.0.1)
FastAPI-based secure web interface for CBOM Scanner.
Vercel + Neon (PostgreSQL) deployment ready.

v1.0.1 Changes:
- passlib hata diya, bcrypt direct use (72-byte error fix)
- is_strong_password wapas add kiya
- Professional PDF report (fpdf2) - WeasyPrint hata diya
- PDF me IST time, quantum-vulnerable vs weak algorithms alag
- asyncpg pool: statement_cache_size=0 (Neon pooled connection ke liye)
"""

# ============================================================
# VERCEL PATH SETUP (SABSE PEHLE)
# ============================================================
import os
import sys

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(WEB_DIR)
SRC_DIR = os.path.join(ROOT_DIR, 'src')

# Saare paths add karo - config, scanner, network_scanner ke liye
for path in [SRC_DIR, WEB_DIR, ROOT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# ============================================================
# STANDARD IMPORTS
# ============================================================
import json
import secrets
import logging
import asyncpg
import time
from datetime import datetime, timedelta
from typing import Optional, List
from collections import Counter, defaultdict
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI, Request, Form, UploadFile, File, Depends,
    HTTPException, status, Cookie, Header
)
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse, Response
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ============================================================
# CONFIG IMPORTS
# ============================================================
from config import (
    ADMIN_USERNAME, ADMIN_PASSWORD,
    SESSION_EXPIRY_DAYS, COOKIE_SECURE, COOKIE_SAMESITE,
    MIN_PASSWORD_LENGTH, MAX_MULTI_HOSTS,
    PORT_TIMEOUT, MAX_WORKERS,
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    PQC_REPLACEMENTS,
    LOG_LEVEL,
)

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
logger = logging.getLogger("cbom.app")

# ============================================================
# DATABASE URL
# ============================================================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable required")

# Reports dir (Vercel me /tmp)
REPORTS_DIR = "/tmp/cbom_reports" if os.getenv("VERCEL") else os.path.join(ROOT_DIR, "reports")
try:
    os.makedirs(REPORTS_DIR, exist_ok=True)
except OSError:
    pass

# ============================================================
# SRC IMPORTS
# ============================================================
from scanner import scan_folder
from network_scanner import scan_host

# ============================================================
# PASSWORD HASHING (bcrypt direct)
# ============================================================
import bcrypt


def _password_bytes(password: str) -> bytes:
    # bcrypt sirf pehle 72 bytes use karta hai
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password),
            hashed_password.encode("utf-8"),
        )
    except Exception as e:
        logger.warning(f"Password verify failed: {e}")
        return False


def is_strong_password(password: str) -> tuple:
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password kam se kam {MIN_PASSWORD_LENGTH} characters ka hona chahiye"
    if not any(c.isupper() for c in password):
        return False, "Password me kam se kam 1 uppercase letter hona chahiye"
    if not any(c.islower() for c in password):
        return False, "Password me kam se kam 1 lowercase letter hona chahiye"
    if not any(c.isdigit() for c in password):
        return False, "Password me kam se kam 1 number hona chahiye"
    return True, "OK"


# ============================================================
# CSRF
# ============================================================
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_csrf(cookie_token: Optional[str], header_token: Optional[str]) -> bool:
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


# ============================================================
# RATE LIMITING
# ============================================================
_rate_limit_store = defaultdict(list)


def check_rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    now = time.time()
    timestamps = _rate_limit_store[key]
    timestamps[:] = [t for t in timestamps if now - t < window_seconds]
    if len(timestamps) >= max_requests:
        return False
    timestamps.append(now)
    return True


# ============================================================
# DATABASE POOL
# ============================================================
_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            command_timeout=30,
            # Neon pooled (pgbouncer) connection ke liye zaroori
            statement_cache_size=0,
        )
    return _pool


async def init_db():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                report_data JSONB,
                total_findings INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)')

    logger.info("Database initialized (PostgreSQL)")


async def cleanup_expired_sessions():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP')


# ============================================================
# USER MANAGEMENT
# ============================================================
async def create_user(username: str, email: str, password: str):
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
                username, email, hash_password(password)
            )
        return True, "User created"
    except asyncpg.UniqueViolationError as e:
        if 'username' in str(e).lower():
            return False, "Username already exists"
        if 'email' in str(e).lower():
            return False, "Email already exists"
        return False, "User already exists"
    except Exception as e:
        logger.exception("create_user failed")
        return False, str(e)[:100]


async def verify_user(username: str, password: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT id, username, email, password_hash FROM users WHERE username = $1',
            username
        )
        if not row:
            return None
        if not verify_password(password, row['password_hash']):
            return None
        await conn.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            row['id']
        )
        return {'id': row['id'], 'username': row['username'], 'email': row['email']}


# ============================================================
# SESSION MANAGEMENT
# ============================================================
async def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=SESSION_EXPIRY_DAYS)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            'INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
            token, user_id, expires_at
        )
    return token


async def get_user_from_session(token: Optional[str]):
    if not token:
        return None
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT u.id, u.username, u.email
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = $1 AND s.expires_at > CURRENT_TIMESTAMP
        ''', token)
        if row:
            return {'id': row['id'], 'username': row['username'], 'email': row['email']}
        return None


async def delete_session(token: str):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM sessions WHERE token = $1', token)


# ============================================================
# SCAN TRACKING
# ============================================================
async def save_scan_to_db(user_id: int, scan_type: str, target: str,
                          report_data: dict, total_findings: int) -> int:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            '''INSERT INTO scans (user_id, scan_type, target, report_data, total_findings)
               VALUES ($1, $2, $3, $4, $5) RETURNING id''',
            user_id, scan_type, target, json.dumps(report_data), total_findings
        )
        return row['id']


async def get_user_scans(user_id: int) -> List[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('''
            SELECT id, scan_type, target, total_findings, created_at
            FROM scans WHERE user_id = $1
            ORDER BY created_at DESC
        ''', user_id)
        return [dict(r) for r in rows]


async def get_scan_by_id(user_id: int, scan_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT id, scan_type, target, report_data, total_findings, created_at
            FROM scans WHERE id = $1 AND user_id = $2
        ''', scan_id, user_id)
        return dict(row) if row else None


# ============================================================
# LIFESPAN
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    try:
        await init_db()
        await cleanup_expired_sessions()
    except Exception as e:
        logger.exception(f"DB init failed: {e}")
    yield
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
    logger.info(f"Shutting down {APP_NAME}")


# ============================================================
# APP
# ============================================================
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

templates = Jinja2Templates(directory=os.path.join(WEB_DIR, 'templates'))

static_dir = os.path.join(WEB_DIR, 'static')
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ============================================================
# ADMIN AUTH
# ============================================================
security = HTTPBasic()


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username.encode(), ADMIN_USERNAME.encode())
    correct_password = secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# ============================================================
# PAGE ROUTES
# ============================================================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    return templates.TemplateResponse(request=request, name="scan.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": user})


# ============================================================
# AUTH API
# ============================================================
@app.post("/api/auth/signup")
async def api_signup(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"signup:{client_ip}", max_requests=5, window_seconds=300):
        return JSONResponse({"error": "Too many signup attempts"}, status_code=429)

    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return JSONResponse({"error": "Username 3-50 characters ka hona chahiye"}, status_code=400)

    email = email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return JSONResponse({"error": "Valid email daalo"}, status_code=400)

    ok, msg = is_strong_password(password)
    if not ok:
        return JSONResponse({"error": msg}, status_code=400)

    success, msg = await create_user(username, email, password)
    if success:
        return JSONResponse({"success": True, "message": "User created successfully"})
    return JSONResponse({"error": msg}, status_code=400)


@app.post("/api/auth/login")
async def api_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"login:{client_ip}", max_requests=10, window_seconds=300):
        return JSONResponse({"error": "Too many login attempts"}, status_code=429)

    user = await verify_user(username, password)
    if not user:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    token = await create_session(user['id'])
    csrf_token = generate_csrf_token()

    response = JSONResponse({
        "success": True,
        "message": "Login successful",
        "user": user,
        "csrf_token": csrf_token,
    })
    response.set_cookie(
        key="session_token", value=token,
        httponly=True, secure=COOKIE_SECURE,
        max_age=SESSION_EXPIRY_DAYS * 24 * 60 * 60,
        samesite=COOKIE_SAMESITE,
    )
    response.set_cookie(
        key="csrf_token", value=csrf_token,
        httponly=False, secure=COOKIE_SECURE,
        max_age=SESSION_EXPIRY_DAYS * 24 * 60 * 60,
        samesite=COOKIE_SAMESITE,
    )
    return response


@app.get("/api/auth/logout")
async def api_logout(session_token: Optional[str] = Cookie(None)):
    if session_token:
        await delete_session(session_token)
    response = JSONResponse({"success": True, "message": "Logged out"})
    response.delete_cookie("session_token")
    response.delete_cookie("csrf_token")
    return response


@app.get("/api/auth/me")
async def api_me(session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse({"user": user})


# ============================================================
# CSRF DEPENDENCY
# ============================================================
async def require_csrf(
    csrf_token: Optional[str] = Cookie(None),
    x_csrf_token: Optional[str] = Header(None),
):
    if not validate_csrf(csrf_token, x_csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


# ============================================================
# SCAN API
# ============================================================
@app.post("/api/scan/folder")
async def api_scan_folder(
    request: Request,
    folder_path: str = Form(...),
    session_token: Optional[str] = Cookie(None),
    _csrf: None = Depends(require_csrf),
):
    if not folder_path or not folder_path.strip():
        return JSONResponse({"error": "Folder path required"}, status_code=400)

    folder_path = folder_path.strip().strip('"').strip("'")

    if not os.path.exists(folder_path):
        return JSONResponse({"error": f"Path does not exist: {folder_path}"}, status_code=400)
    if not os.path.isdir(folder_path):
        return JSONResponse({"error": f"Not a directory: {folder_path}"}, status_code=400)

    user = await get_user_from_session(session_token)

    try:
        results = scan_folder(folder_path)
        total_findings = results.get('total_findings', 0)

        scan_id = None
        if user:
            scan_id = await save_scan_to_db(
                user['id'], 'folder', folder_path, results, total_findings
            )

        return JSONResponse({
            "success": True,
            "scan_type": "folder",
            "scan_id": scan_id,
            "folder": folder_path,
            "files_scanned": results.get('files_scanned', 0),
            "total_findings": total_findings,
            "findings": results.get('findings', [])[:50],
        })
    except Exception as e:
        logger.exception("Folder scan failed")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/scan/network")
async def api_scan_network(
    request: Request,
    host: str = Form(...),
    port_option: str = Form("quick"),
    session_token: Optional[str] = Cookie(None),
    _csrf: None = Depends(require_csrf),
):
    if not host or not host.strip():
        return JSONResponse({"error": "Host is required"}, status_code=400)

    host = host.strip()
    if len(host) > 253 or any(c in host for c in [' ', ';', '|', '&', '$']):
        return JSONResponse({"error": "Invalid hostname"}, status_code=400)

    user = await get_user_from_session(session_token)

    # Vercel timeout ke liye sirf quick
    if os.getenv("VERCEL") and port_option != "quick":
        port_option = "quick"

    ports_map = {
        "quick": [443, 22, 8443, 993, 995, 465, 636],
        "standard": list(range(1, 1025)),
        "full": list(range(1, 65536)),
    }
    ports = ports_map.get(port_option, ports_map["quick"])

    try:
        results = scan_host(host, ports=ports, timeout=PORT_TIMEOUT, max_workers=MAX_WORKERS)
        total_findings = sum(len(s.get('findings', [])) for s in results.get('services', []))

        scan_id = None
        if user:
            scan_id = await save_scan_to_db(
                user['id'], 'network', host, results, total_findings
            )

        return JSONResponse({
            "success": True,
            "scan_type": "network",
            "scan_id": scan_id,
            "host": host,
            "open_ports": results.get('open_ports', []),
            "services": results.get('services', []),
            "total_findings": total_findings,
        })
    except Exception as e:
        logger.exception("Network scan failed")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/scan/multi")
async def api_scan_multi(
    request: Request,
    file: UploadFile = File(...),
    session_token: Optional[str] = Cookie(None),
    _csrf: None = Depends(require_csrf),
):
    user = await get_user_from_session(session_token)

    try:
        content = await file.read()
        if len(content) > 1024 * 1024:
            return JSONResponse({"error": "File too large"}, status_code=400)

        hosts = [
            line.strip()
            for line in content.decode('utf-8', errors='ignore').split('\n')
            if line.strip() and not line.startswith('#')
        ]

        seen = set()
        unique_hosts = []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                unique_hosts.append(h)

        if not unique_hosts:
            return JSONResponse({"error": "File is empty"}, status_code=400)

        if len(unique_hosts) > MAX_MULTI_HOSTS:
            return JSONResponse({"error": f"Too many hosts (max {MAX_MULTI_HOSTS})"}, status_code=400)

        if os.getenv("VERCEL"):
            unique_hosts = unique_hosts[:5]

        results = []
        quick_ports = [443, 22, 8443, 993, 995]
        for host in unique_hosts:
            try:
                result = scan_host(host, ports=quick_ports, timeout=PORT_TIMEOUT, max_workers=MAX_WORKERS)
                results.append(result)
            except Exception as e:
                results.append({"host": host, "error": str(e)[:100], "services": []})

        total_findings = sum(
            len(s.get('findings', []))
            for r in results
            for s in r.get('services', [])
        )

        combined = {'hosts': results, 'total_hosts': len(results), 'total_findings': total_findings}

        scan_id = None
        if user:
            scan_id = await save_scan_to_db(
                user['id'], 'multi', f'{len(unique_hosts)} hosts', combined, total_findings
            )

        return JSONResponse({
            "success": True,
            "scan_type": "multi",
            "scan_id": scan_id,
            "total_hosts": len(results),
            "results": results,
        })
    except Exception as e:
        logger.exception("Multi-host scan failed")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# CHARTS DATA
# ============================================================
@app.get("/api/charts/data")
async def api_charts_data(session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return JSONResponse({
            'total_hosts': 0, 'total_findings': 0,
            'tls_versions': {}, 'algorithms': {}, 'weak_algorithms': {},
            'issuers': {}, 'public_key_types': {}, 'expiry_status': {},
        })

    stats = {
        'total_hosts': 0,
        'total_findings': 0,
        'tls_versions': Counter(),
        'algorithms': Counter(),        # sirf quantum-vulnerable
        'weak_algorithms': Counter(),   # MD5, SHA-1, 3DES, RC4, DES
        'issuers': Counter(),
        'public_key_types': Counter(),
        'expiry_status': Counter(),
    }

    scans = await get_user_scans(user['id'])

    for scan in scans:
        full_scan = await get_scan_by_id(user['id'], scan['id'])
        if not full_scan or not full_scan.get('report_data'):
            continue

        data = full_scan['report_data']
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                continue

        hosts_list = data.get('hosts') if isinstance(data, dict) and 'hosts' in data else [data]

        for host in hosts_list:
            if not isinstance(host, dict):
                continue
            stats['total_hosts'] += 1
            for service in host.get('services', []):
                if service.get('tls_version'):
                    stats['tls_versions'][service['tls_version']] += 1
                cert = service.get('certificate', {})
                if cert and isinstance(cert, dict):
                    if cert.get('issuer', {}).get('CN'):
                        stats['issuers'][cert['issuer']['CN']] += 1
                    if cert.get('public_key', {}).get('type'):
                        kt = f"{cert['public_key']['type']}-{cert['public_key'].get('bits', '?')}"
                        stats['public_key_types'][kt] += 1
                    if cert.get('expiry_status'):
                        stats['expiry_status'][cert['expiry_status']] += 1
                for finding in service.get('findings', []):
                    algo = finding.get('algorithm', 'Unknown')
                    stats['total_findings'] += 1
                    category = _classify_algo(algo)
                    if category == "Quantum-vulnerable":
                        stats['algorithms'][algo] += 1
                    elif category == "Weak / deprecated":
                        stats['weak_algorithms'][algo] += 1

    return JSONResponse({
        'total_hosts': stats['total_hosts'],
        'total_findings': stats['total_findings'],
        'tls_versions': dict(stats['tls_versions']),
        'algorithms': dict(stats['algorithms'].most_common(10)),
        'weak_algorithms': dict(stats['weak_algorithms'].most_common(10)),
        'issuers': dict(stats['issuers'].most_common(10)),
        'public_key_types': dict(stats['public_key_types']),
        'expiry_status': dict(stats['expiry_status']),
    })

# ============================================================
# REPORTS API
# ============================================================
@app.get("/api/reports")
async def list_reports(session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return JSONResponse({"reports": []})

    scans = await get_user_scans(user['id'])
    reports = [{
        'id': s['id'],
        'name': f"scan_{s['id']}.json",
        'scan_type': s['scan_type'],
        'target': s['target'],
        'total_findings': s['total_findings'],
        'created_at': s['created_at'].isoformat() if s['created_at'] else None,
    } for s in scans]

    return JSONResponse({"reports": reports})


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: int, session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    scan = await get_scan_by_id(user['id'], scan_id)
    if not scan:
        return JSONResponse({"error": "Report not found"}, status_code=404)

    data = scan['report_data']
    if isinstance(data, str):
        data = json.loads(data)

    return JSONResponse(data)


# ============================================================
# PDF EXPORT (fpdf2) - Professional report
# ============================================================
PDF_BLUE = (11, 60, 120)
RISK_COLORS = {"HIGH": (207, 34, 46), "MEDIUM": (191, 100, 0), "LOW": (26, 127, 55)}
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Shor's algorithm se tootne wale (quantum-vulnerable)
QUANTUM_VULN_PREFIXES = (
    "RSA", "ECDSA", "ECDH", "EC", "DH", "DSA", "DIFFIE",
    "ED25519", "ED448", "X25519", "X448",
)
# Classically weak (quantum ki wajah se nahi)
WEAK_ALGO_PREFIXES = ("MD5", "SHA-1", "SHA1", "3DES", "DES", "RC4")

# Helvetica ye characters render nahi kar paata, isliye replace
_PDF_CHAR_MAP = {
    "\u2192": "->", "\u2190": "<-", "\u2013": "-", "\u2014": "-",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2022": "-", "\u2026": "...", "\u2265": ">=", "\u2264": "<=",
}


def _classify_algo(algo) -> str:
    a = str(algo or "").upper().replace(" ", "")
    if a.startswith(WEAK_ALGO_PREFIXES):
        return "Weak / deprecated"
    if a.startswith(QUANTUM_VULN_PREFIXES):
        return "Quantum-vulnerable"
    return "Other"


def _pqc_for(algo) -> dict:
    a = str(algo or "").upper()
    if a in PQC_REPLACEMENTS:
        return PQC_REPLACEMENTS[a]
    for key, value in PQC_REPLACEMENTS.items():
        if a.startswith(key.upper()):
            return value
    return {}


def _pdf_text(value, max_len: int = 300) -> str:
    """Latin-1 safe text, lambe words todke (fpdf2 width error se bachne ke liye)."""
    text = "" if value is None else str(value)
    for src, dst in _PDF_CHAR_MAP.items():
        text = text.replace(src, dst)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    if len(text) > max_len:
        text = text[:max_len - 3] + "..."
    words = []
    for word in text.split(" "):
        while len(word) > 60:
            words.append(word[:60])
            word = word[60:]
        words.append(word)
    return " ".join(words)


class CBOMReportPDF(FPDF):
    def header(self):
        self.set_fill_color(*PDF_BLUE)
        self.rect(0, 0, self.w, 14, style="F")
        self.set_xy(self.l_margin, 4)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(self.epw / 2, 6, "CBOM Scanner", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.cell(self.epw / 2, 6, "Cryptographic Bill of Materials", align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(22)

    def footer(self):
        self.set_y(-14)
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_font("Helvetica", "", 8)
        self.set_text_color(110, 110, 110)
        self.cell(self.epw * 0.75, 8, f"{APP_NAME} v{APP_VERSION} | Scan authorized targets only",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(self.epw * 0.25, 8, f"Page {self.page_no()}/{{nb}}", align="R")
        self.set_text_color(0, 0, 0)


def _pdf_line(pdf, text, size: int = 10, style: str = "", height: float = 6, indent: float = 0):
    pdf.set_font("Helvetica", style, size)
    pdf.set_x(pdf.l_margin + indent)
    pdf.multi_cell(
        pdf.epw - indent, height, _pdf_text(text) or " ",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )


def _pdf_section(pdf, title, min_space: int = 45):
    if pdf.get_y() > pdf.h - min_space:
        pdf.add_page()
    pdf.ln(4)
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*PDF_BLUE)
    pdf.cell(pdf.epw, 8, _pdf_text(title, 80), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*PDF_BLUE)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)


def _pdf_kv(pdf, label, value, label_w: float = 42):
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(label_w, 6, _pdf_text(label, 40), new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(pdf.epw - label_w, 6, _pdf_text(value) or "-",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _pdf_boxes(pdf, items):
    """items = [(label, value, (r, g, b)), ...] - ek row me barabar boxes."""
    gap = 4
    w = (pdf.epw - gap * (len(items) - 1)) / len(items)
    y0 = pdf.get_y()
    for i, (label, value, color) in enumerate(items):
        x = pdf.l_margin + i * (w + gap)
        pdf.set_fill_color(246, 248, 250)
        pdf.set_draw_color(208, 215, 222)
        pdf.rect(x, y0, w, 22, style="DF")
        pdf.set_xy(x, y0 + 3)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*color)
        pdf.cell(w, 9, _pdf_text(value, 12), align="C")
        pdf.set_xy(x, y0 + 13)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(90, 90, 90)
        pdf.cell(w, 6, _pdf_text(label, 30), align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(pdf.l_margin, y0 + 26)


def _sort_findings(findings):
    items = [f for f in (findings or []) if isinstance(f, dict)]
    return sorted(items, key=lambda f: RISK_ORDER.get(str(f.get("risk", "")).upper(), 3))


def _all_findings(data):
    out = []
    if "hosts" in data:
        for h in data.get("hosts", []) or []:
            if isinstance(h, dict):
                for s in h.get("services", []) or []:
                    if isinstance(s, dict):
                        out.extend(x for x in (s.get("findings") or []) if isinstance(x, dict))
    elif "services" in data:
        for s in data.get("services", []) or []:
            if isinstance(s, dict):
                out.extend(x for x in (s.get("findings") or []) if isinstance(x, dict))
    else:
        out.extend(x for x in (data.get("findings") or []) if isinstance(x, dict))
    return out


def _pdf_finding(pdf, f):
    if pdf.get_y() > pdf.h - 55:
        pdf.add_page()
    risk = str(f.get("risk") or "INFO").upper()
    color = RISK_COLORS.get(risk, (90, 90, 90))
    algo = f.get("algorithm", "Unknown")

    pdf.set_x(pdf.l_margin)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(20, 6, _pdf_text(risk, 10), fill=True, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(pdf.epw - 20, 6, "  " + _pdf_text(algo, 40) + "  -  " + _classify_algo(algo),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if f.get("file"):
        loc = str(f.get("file"))
        if f.get("line"):
            loc += f":{f.get('line')}"
        _pdf_line(pdf, f"Location: {loc}", 9, indent=4)
    if f.get("reason"):
        _pdf_line(pdf, f"Reason: {f.get('reason')}", 9, indent=4)
    pqc = _pqc_for(algo).get("replacement")
    if pqc:
        _pdf_line(pdf, f"PQC replacement: {pqc}", 9, indent=4)
    pdf.ln(2)


def _pdf_services(pdf, services):
    for s in services or []:
        if not isinstance(s, dict):
            continue
        if pdf.get_y() > pdf.h - 70:
            pdf.add_page()
        _pdf_line(pdf, f"{s.get('protocol', '')} on {s.get('target', '')}", 11, "B", 7)
        cipher = s.get("cipher_suite")
        if isinstance(cipher, (list, tuple)) and cipher:
            cipher = cipher[0]
        _pdf_kv(pdf, "TLS version", s.get("tls_version") or "N/A")
        _pdf_kv(pdf, "Cipher suite", cipher or "N/A")
        cert = s.get("certificate")
        if isinstance(cert, dict):
            subject = (cert.get("subject") or {}).get("CN", "N/A")
            issuer = (cert.get("issuer") or {}).get("CN", "N/A")
            _pdf_kv(pdf, "Certificate subject", subject)
            _pdf_kv(pdf, "Issuer", issuer)
            pk = cert.get("public_key") or {}
            if pk.get("type"):
                _pdf_kv(pdf, "Public key", f"{pk.get('type')}-{pk.get('bits', '?')}")
            _pdf_kv(pdf, "Valid until", cert.get("not_after") or "N/A")
            _pdf_kv(pdf, "Expiry status", cert.get("expiry_status") or "N/A")
        pdf.ln(2)
        findings = _sort_findings(s.get("findings", []))
        if findings:
            for f in findings:
                _pdf_finding(pdf, f)
        else:
            _pdf_line(pdf, "No findings for this service.", 9, indent=4)
        pdf.ln(3)


def generate_pdf_bytes(data, scan=None) -> bytes:
    """Professional CBOM report (folder / network / multi teeno)."""
    if not isinstance(data, dict):
        data = {}
    scan = scan or {}

    pdf = CBOMReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ---------- Title + metadata ----------
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*PDF_BLUE)
    pdf.cell(pdf.epw, 12, "Quantum-Readiness Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(pdf.epw, 7, "Cryptographic inventory and PQC migration findings",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # DB me time UTC hai, report me IST dikhao
    created = scan.get("created_at")
    created_text = (
        (created + timedelta(hours=5, minutes=30)).strftime("%d %b %Y, %H:%M IST")
        if hasattr(created, "strftime") else "N/A"
    )
    if "hosts" in data:
        kind = "Multi-host scan"
    elif "services" in data:
        kind = "Network scan"
    else:
        kind = "Folder scan"
    if scan.get("id") is not None:
        _pdf_kv(pdf, "Report ID", f"#{scan.get('id')}")
    _pdf_kv(pdf, "Scan type", kind)
    _pdf_kv(pdf, "Target", scan.get("target") or "N/A")
    _pdf_kv(pdf, "Scan date", created_text)
    _pdf_kv(pdf, "Generated by", f"{APP_NAME} v{APP_VERSION}")

    # ---------- Executive summary ----------
    findings_all = _all_findings(data)[:500]
    high = sum(1 for f in findings_all if str(f.get("risk", "")).upper() == "HIGH")
    medium = sum(1 for f in findings_all if str(f.get("risk", "")).upper() == "MEDIUM")
    low = sum(1 for f in findings_all if str(f.get("risk", "")).upper() == "LOW")
    quantum = sum(1 for f in findings_all if _classify_algo(f.get("algorithm")) == "Quantum-vulnerable")
    weak = sum(1 for f in findings_all if _classify_algo(f.get("algorithm")) == "Weak / deprecated")

    if "hosts" in data:
        scope_label, scope_value = "Hosts scanned", len(data.get("hosts", []))
    elif "services" in data:
        scope_label, scope_value = "Services scanned", len(data.get("services", []))
    else:
        scope_label, scope_value = "Files scanned", data.get("files_scanned", 0)

    _pdf_section(pdf, "Executive Summary")
    _pdf_boxes(pdf, [
        ("Total findings", len(findings_all), PDF_BLUE),
        ("High risk", high, RISK_COLORS["HIGH"]),
        ("Medium risk", medium, RISK_COLORS["MEDIUM"]),
        ("Low risk", low, RISK_COLORS["LOW"]),
    ])
    _pdf_boxes(pdf, [
        ("Quantum-vulnerable", quantum, (111, 66, 193)),
        ("Weak / deprecated", weak, (191, 100, 0)),
        (scope_label, scope_value, PDF_BLUE),
    ])
    pdf.ln(2)
    pdf.set_text_color(90, 90, 90)
    _pdf_line(
        pdf,
        "Quantum-vulnerable algorithms (RSA, ECDSA, ECDH, DH) can be broken by Shor's algorithm "
        "on a large quantum computer. Weak / deprecated algorithms (MD5, SHA-1, 3DES, RC4) are "
        "classically broken and are listed separately.",
        9, height=5,
    )
    pdf.set_text_color(0, 0, 0)

    # ---------- Detailed findings ----------
    _pdf_section(pdf, "Detailed Findings")
    if "hosts" in data:
        for h in data.get("hosts", []):
            if not isinstance(h, dict):
                continue
            if pdf.get_y() > pdf.h - 60:
                pdf.add_page()
            _pdf_line(pdf, f"Host: {h.get('host', '')}", 12, "B", 8)
            if h.get("error"):
                _pdf_line(pdf, f"Error: {h.get('error')}", 10)
            else:
                ports = ", ".join(str(p) for p in h.get("open_ports", []))
                _pdf_kv(pdf, "Open ports", ports or "None")
                pdf.ln(1)
                _pdf_services(pdf, h.get("services", []))
            pdf.ln(2)
    elif "services" in data:
        ports = ", ".join(str(p) for p in data.get("open_ports", []))
        _pdf_kv(pdf, "Open ports", ports or "None")
        pdf.ln(2)
        _pdf_services(pdf, data.get("services", []))
    else:
        _pdf_kv(pdf, "Files scanned", data.get("files_scanned", 0))
        pdf.ln(2)
        folder_findings = _sort_findings(data.get("findings", []))[:300]
        if folder_findings:
            for f in folder_findings:
                _pdf_finding(pdf, f)
        else:
            _pdf_line(pdf, "No findings.", 10)

    # ---------- PQC migration recommendations ----------
    seen = []
    for f in findings_all:
        algo = str(f.get("algorithm", "")).strip()
        if algo and algo not in seen:
            seen.append(algo)
    if seen:
        _pdf_section(pdf, "PQC Migration Recommendations", min_space=70)
        for algo in seen:
            info = _pqc_for(algo)
            if not info:
                continue
            if pdf.get_y() > pdf.h - 45:
                pdf.add_page()
            _pdf_line(pdf, f"{algo}  ->  {info.get('replacement', '')}", 10, "B")
            if info.get("standard"):
                _pdf_line(pdf, f"Standard: {info.get('standard')}", 9, indent=4)
            if info.get("note"):
                _pdf_line(pdf, info.get("note"), 9, indent=4)
            pdf.ln(2)

    return bytes(pdf.output())


@app.get("/api/report/{scan_id}/pdf")
async def export_report_pdf(scan_id: int, session_token: Optional[str] = Cookie(None)):
    user = await get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    scan = await get_scan_by_id(user['id'], scan_id)
    if not scan:
        return JSONResponse({"error": "Report not found"}, status_code=404)

    data = scan['report_data']
    if isinstance(data, str):
        data = json.loads(data)

    try:
        pdf_bytes = generate_pdf_bytes(data, scan)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=cbom_report_{scan_id}.pdf"},
        )
    except Exception as e:
        logger.exception("PDF export failed")
        return JSONResponse({"error": f"PDF export failed: {str(e)[:150]}"}, status_code=500)


# ============================================================
# ADMIN DOCS
# ============================================================
@app.get("/docs", include_in_schema=False)
async def custom_docs(username: str = Depends(verify_admin)):
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{APP_NAME} - Admin API Docs")


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi(username: str = Depends(verify_admin)):
    return app.openapi()


# ============================================================
# HEALTH CHECK
# ============================================================
@app.get("/health")
async def health():
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        return {"status": "ok", "app": APP_NAME, "version": APP_VERSION, "database": "connected"}
    except Exception as e:
        return {"status": "degraded", "app": APP_NAME, "version": APP_VERSION, "database": str(e)[:100]}


# ============================================================
# MAIN (local dev)
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)