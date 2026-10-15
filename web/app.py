"""
CBOM Scanner - Web Dashboard (v0.9.0)
FastAPI-based secure web interface for CBOM Scanner.

v0.9.0 Security & Quality Changes:
- bcrypt password hashing (SHA-256 hataya)
- Admin credentials via environment variables
- CSRF protection (double-submit cookie)
- Cookie secure flag (config se)
- Path traversal fix (realpath + separator)
- Lifespan events (init_db module load pe nahi)
- Logging system (debug prints hataye)
- Rate limiting (simple in-memory)
- Session cleanup (expired auto-delete)
- Config.py se central configuration
- Better error handling (specific exceptions)
"""

import os
import sys
import json
import secrets
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional
from collections import Counter, defaultdict
from io import BytesIO
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

# ============================================================
# PATH SETUP
# ============================================================

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(WEB_DIR)
SRC_DIR = os.path.join(ROOT_DIR, 'src')

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# ============================================================
# LOGGING SETUP
# ============================================================

from config import (
    ADMIN_USERNAME, ADMIN_PASSWORD,
    DB_PATH, REPORTS_DIR,
    SESSION_EXPIRY_DAYS, COOKIE_SECURE, COOKIE_SAMESITE,
    MIN_PASSWORD_LENGTH, MAX_MULTI_HOSTS,
    SCAN_TIMEOUT, PORT_TIMEOUT, MAX_WORKERS,
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    PQC_REPLACEMENTS, SCAN_PROFILES, get_scan_profile,
    LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT,
)

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
logger = logging.getLogger("cbom.app")

# ============================================================
# IMPORTS FROM SRC
# ============================================================

from scanner import scan_folder
from network_scanner import scan_host

# ============================================================
# SECURITY: PASSWORD HASHING (bcrypt)
# ============================================================

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """bcrypt se password hash karo."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Password verify karo."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.warning(f"Password verify failed: {e}")
        return False


def is_strong_password(password: str) -> tuple[bool, str]:
    """Password strength check karo."""
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
# SECURITY: CSRF PROTECTION
# ============================================================

def generate_csrf_token() -> str:
    """CSRF token generate karo."""
    return secrets.token_urlsafe(32)


def validate_csrf(cookie_token: Optional[str], header_token: Optional[str]) -> bool:
    """CSRF token validate karo (double-submit cookie pattern)."""
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


# ============================================================
# SECURITY: RATE LIMITING (simple in-memory)
# ============================================================

_rate_limit_store = defaultdict(list)


def check_rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    """Rate limit check karo. Returns True agar allowed hai."""
    now = time.time()
    timestamps = _rate_limit_store[key]
    # Purane timestamps hatao
    timestamps[:] = [t for t in timestamps if now - t < window_seconds]
    if len(timestamps) >= max_requests:
        return False
    timestamps.append(now)
    return True


# ============================================================
# DATABASE
# ============================================================

def get_db():
    """Database connection (WAL mode + timeout)."""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db():
    """Database tables banao."""
    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                report_path TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        conn.commit()
        logger.info(f"Database initialized: {DB_PATH}")
    finally:
        conn.close()


def cleanup_expired_sessions():
    """Expired sessions delete karo."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP')
        deleted = cursor.rowcount
        conn.commit()
        if deleted:
            logger.info(f"Cleaned up {deleted} expired sessions")
    finally:
        conn.close()


# ============================================================
# USER MANAGEMENT
# ============================================================

def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """Naya user banao."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, hash_password(password))
        )
        conn.commit()
        return True, "User created"
    except sqlite3.IntegrityError as e:
        if 'username' in str(e).lower():
            return False, "Username already exists"
        if 'email' in str(e).lower():
            return False, "Email already exists"
        return False, "User already exists"
    finally:
        conn.close()


def verify_user(username: str, password: str) -> Optional[dict]:
    """User verify karo."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, username, email, password_hash FROM users WHERE username = ?',
            (username,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        user_id, uname, email, password_hash = row

        if not verify_password(password, password_hash):
            return None

        cursor.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            (user_id,)
        )
        conn.commit()

        return {'id': user_id, 'username': uname, 'email': email}
    finally:
        conn.close()


# ============================================================
# SESSION MANAGEMENT
# ============================================================

def create_session(user_id: int) -> str:
    """Naya session banao."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=SESSION_EXPIRY_DAYS)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
            (token, user_id, expires_at)
        )
        conn.commit()
    finally:
        conn.close()

    return token


def get_user_from_session(token: Optional[str]) -> Optional[dict]:
    """Session se user nikalo."""
    if not token:
        return None

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP
        ''', (token,))
        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'username': row[1], 'email': row[2]}
        return None
    finally:
        conn.close()


def delete_session(token: str):
    """Session delete karo."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
        conn.commit()
    finally:
        conn.close()


# ============================================================
# SCAN TRACKING
# ============================================================

def save_scan_to_db(user_id: int, scan_type: str, target: str,
                    report_path: str, total_findings: int):
    """Scan record save karo."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (user_id, scan_type, target, report_path, total_findings) '
            'VALUES (?, ?, ?, ?, ?)',
            (user_id, scan_type, target, report_path, total_findings)
        )
        conn.commit()
    finally:
        conn.close()


def user_owns_report(user_id: int, report_path: str) -> bool:
    """Check karo report user ki hai ya nahi."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT 1 FROM scans WHERE user_id = ? AND report_path = ? LIMIT 1',
            (user_id, report_path)
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()


# ============================================================
# LIFESPAN (init_db module load pe nahi)
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown events."""
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    init_db()
    cleanup_expired_sessions()
    yield
    logger.info(f"Shutting down {APP_NAME}")


# ============================================================
# APP SETUP
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

# Static files (agar folder exist kare)
static_dir = os.path.join(WEB_DIR, 'static')
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ============================================================
# ADMIN BASIC AUTH
# ============================================================

security = HTTPBasic()


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Admin credentials verify karo (env vars se)."""
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        ADMIN_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        ADMIN_PASSWORD.encode("utf8")
    )
    if not (correct_username and correct_password):
        logger.warning(f"Failed admin login attempt: {credentials.username}")
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
    user = get_user_from_session(session_token)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        request=request, name="dashboard.html", context={"user": user}
    )


# ============================================================
# AUTH ROUTES
# ============================================================

@app.post("/api/auth/signup")
async def api_signup(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """Signup API."""
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"signup:{client_ip}", max_requests=5, window_seconds=300):
        return JSONResponse({"error": "Too many signup attempts. Try again later."}, status_code=429)

    # Username validation
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return JSONResponse({"error": "Username 3-50 characters ka hona chahiye"}, status_code=400)

    # Email validation (basic)
    email = email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return JSONResponse({"error": "Valid email daalo"}, status_code=400)

    # Password strength
    ok, msg = is_strong_password(password)
    if not ok:
        return JSONResponse({"error": msg}, status_code=400)

    success, msg = create_user(username, email, password)
    if success:
        logger.info(f"New user created: {username}")
        return JSONResponse({"success": True, "message": "User created successfully"})
    return JSONResponse({"error": msg}, status_code=400)


@app.post("/api/auth/login")
async def api_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Login API."""
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"login:{client_ip}", max_requests=10, window_seconds=300):
        return JSONResponse({"error": "Too many login attempts. Try again later."}, status_code=429)

    user = verify_user(username, password)
    if not user:
        logger.warning(f"Failed login: {username} from {client_ip}")
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    token = create_session(user['id'])
    csrf_token = generate_csrf_token()

    logger.info(f"Login success: {username} from {client_ip}")

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
        delete_session(session_token)
    response = JSONResponse({"success": True, "message": "Logged out"})
    response.delete_cookie("session_token")
    response.delete_cookie("csrf_token")
    return response


@app.get("/api/auth/me")
async def api_me(session_token: Optional[str] = Cookie(None)):
    user = get_user_from_session(session_token)
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
    """CSRF validation dependency."""
    if not validate_csrf(csrf_token, x_csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


# ============================================================
# SCAN API ROUTES
# ============================================================

@app.post("/api/scan/folder")
async def api_scan_folder(
    request: Request,
    folder_path: str = Form(...),
    session_token: Optional[str] = Cookie(None),
    _csrf: None = Depends(require_csrf),
):
    """Folder scan API."""
    if not folder_path or not folder_path.strip():
        return JSONResponse({"error": "Folder path required"}, status_code=400)

    folder_path = folder_path.strip().strip('"').strip("'")

    if not os.path.exists(folder_path):
        return JSONResponse({"error": f"Path does not exist: {folder_path}"}, status_code=400)
    if not os.path.isdir(folder_path):
        return JSONResponse({"error": f"Not a directory: {folder_path}"}, status_code=400)

    user = get_user_from_session(session_token)

    try:
        logger.info(f"Folder scan started: {folder_path}")
        results = scan_folder(folder_path)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f'web_scan_{timestamp}.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        if user:
            save_scan_to_db(user['id'], 'folder', folder_path, report_path,
                            results.get('total_findings', 0))

        logger.info(f"Folder scan complete: {results.get('total_findings', 0)} findings")

        return JSONResponse({
            "success": True,
            "scan_type": "folder",
            "folder": folder_path,
            "files_scanned": results.get('files_scanned', 0),
            "total_findings": results.get('total_findings', 0),
            "findings": results.get('findings', [])[:50],
            "report_path": report_path,
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
    """Network scan API."""
    if not host or not host.strip():
        return JSONResponse({"error": "Host is required"}, status_code=400)

    host = host.strip()

    # Basic host validation
    if len(host) > 253 or any(c in host for c in [' ', ';', '|', '&', '$']):
        return JSONResponse({"error": "Invalid hostname"}, status_code=400)

    user = get_user_from_session(session_token)

    try:
        ports = get_scan_profile(port_option)
        logger.info(f"Network scan started: {host} (profile={port_option})")

        results = scan_host(host, ports=ports, timeout=PORT_TIMEOUT, max_workers=MAX_WORKERS)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f'web_network_{timestamp}.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        total_findings = sum(len(s.get('findings', [])) for s in results.get('services', []))

        if user:
            save_scan_to_db(user['id'], 'network', host, report_path, total_findings)

        logger.info(f"Network scan complete: {total_findings} findings")

        return JSONResponse({
            "success": True,
            "scan_type": "network",
            "host": host,
            "open_ports": results.get('open_ports', []),
            "services": results.get('services', []),
            "total_findings": total_findings,
            "report_path": report_path,
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
    """Multi-host scan API."""
    user = get_user_from_session(session_token)

    try:
        content = await file.read()

        # File size check (1 MB max)
        if len(content) > 1024 * 1024:
            return JSONResponse({"error": "File too large (max 1 MB)"}, status_code=400)

        hosts = [
            line.strip()
            for line in content.decode('utf-8', errors='ignore').split('\n')
            if line.strip() and not line.startswith('#')
        ]

        # Deduplicate while preserving order
        seen = set()
        unique_hosts = []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                unique_hosts.append(h)

        if not unique_hosts:
            return JSONResponse({"error": "File is empty"}, status_code=400)

        if len(unique_hosts) > MAX_MULTI_HOSTS:
            return JSONResponse(
                {"error": f"Too many hosts (max {MAX_MULTI_HOSTS})"},
                status_code=400
            )

        logger.info(f"Multi-host scan started: {len(unique_hosts)} hosts")

        results = []
        quick_ports = get_scan_profile("quick")
        for host in unique_hosts:
            try:
                result = scan_host(host, ports=quick_ports,
                                   timeout=PORT_TIMEOUT, max_workers=MAX_WORKERS)
                results.append(result)
            except Exception as e:
                logger.warning(f"Host scan failed: {host} - {e}")
                results.append({"host": host, "error": str(e)})

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f'web_multi_{timestamp}.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({'hosts': results, 'total_hosts': len(results)}, f, indent=2)

        total_findings = sum(
            len(s.get('findings', []))
            for r in results
            for s in r.get('services', [])
        )

        if user:
            save_scan_to_db(user['id'], 'multi', f'{len(unique_hosts)} hosts',
                            report_path, total_findings)

        logger.info(f"Multi-host scan complete: {total_findings} findings")

        return JSONResponse({
            "success": True,
            "scan_type": "multi",
            "total_hosts": len(results),
            "results": results,
        })
    except Exception as e:
        logger.exception("Multi-host scan failed")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# CHARTS DATA API (User-Specific)
# ============================================================

@app.get("/api/charts/data")
async def api_charts_data(session_token: Optional[str] = Cookie(None)):
    """User-specific charts data."""
    user = get_user_from_session(session_token)
    if not user:
        return JSONResponse({
            'total_hosts': 0, 'total_findings': 0,
            'tls_versions': {}, 'algorithms': {},
            'issuers': {}, 'public_key_types': {}, 'expiry_status': {},
        })

    stats = {
        'total_hosts': 0,
        'total_findings': 0,
        'tls_versions': Counter(),
        'algorithms': Counter(),
        'issuers': Counter(),
        'public_key_types': Counter(),
        'expiry_status': Counter(),
    }

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT report_path FROM scans WHERE user_id = ?', (user['id'],))
        scan_reports = cursor.fetchall()
    finally:
        conn.close()

    for (report_path,) in scan_reports:
        # Security: only read from REPORTS_DIR
        try:
            real_path = os.path.realpath(report_path)
            if not real_path.startswith(os.path.realpath(REPORTS_DIR) + os.sep):
                continue
            if not os.path.exists(real_path):
                continue
            with open(real_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot read report {report_path}: {e}")
            continue

        hosts_list = data.get('hosts') if 'hosts' in data else [data]
        for host in hosts_list:
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
                    stats['algorithms'][finding.get('algorithm', 'Unknown')] += 1
                    stats['total_findings'] += 1

    return JSONResponse({
        'total_hosts': stats['total_hosts'],
        'total_findings': stats['total_findings'],
        'tls_versions': dict(stats['tls_versions']),
        'algorithms': dict(stats['algorithms'].most_common(10)),
        'issuers': dict(stats['issuers'].most_common(10)),
        'public_key_types': dict(stats['public_key_types']),
        'expiry_status': dict(stats['expiry_status']),
    })


# ============================================================
# REPORT ROUTES (with secure path handling)
# ============================================================

def _safe_report_path(filename: str) -> Optional[str]:
    """Filename ko safe path me convert karo. None return karo agar invalid."""
    # Reject suspicious filenames
    if not filename or '/' in filename or '\\' in filename or '..' in filename:
        return None
    filepath = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    reports_real = os.path.realpath(REPORTS_DIR)
    if not filepath.startswith(reports_real + os.sep):
        return None
    return filepath


@app.get("/api/reports")
async def list_reports(session_token: Optional[str] = Cookie(None)):
    """User ke reports list karo."""
    user = get_user_from_session(session_token)
    if not user:
        return JSONResponse({"reports": []})

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT report_path, scan_type, target, total_findings, created_at
            FROM scans WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user['id'],))
        rows = cursor.fetchall()
    finally:
        conn.close()

    reports = []
    for row in rows:
        report_path, scan_type, target, total_findings, created_at = row
        if os.path.exists(report_path):
            reports.append({
                'name': os.path.basename(report_path),
                'path': report_path,
                'scan_type': scan_type,
                'target': target,
                'total_findings': total_findings,
                'created_at': created_at,
            })

    return JSONResponse({"reports": reports})


@app.get("/api/report/{filename}")
async def get_report(filename: str, session_token: Optional[str] = Cookie(None)):
    """Specific report get karo (auth + ownership check)."""
    user = get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    filepath = _safe_report_path(filename)
    if not filepath:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    if not os.path.exists(filepath):
        return JSONResponse({"error": "Report not found"}, status_code=404)

    if not user_owns_report(user['id'], filepath):
        return JSONResponse({"error": "Access denied"}, status_code=403)

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    return JSONResponse(data)


# ============================================================
# PDF EXPORT
# ============================================================

@app.get("/api/report/{filename}/pdf")
async def export_report_pdf(filename: str, session_token: Optional[str] = Cookie(None)):
    """Report PDF me export karo (auth + ownership check)."""
    user = get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    filepath = _safe_report_path(filename)
    if not filepath:
        return JSONResponse({"error": "Invalid filename"}, status_code=400)

    if not os.path.exists(filepath):
        return JSONResponse({"error": "Report not found"}, status_code=404)

    if not user_owns_report(user['id'], filepath):
        return JSONResponse({"error": "Access denied"}, status_code=403)

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    html_content = generate_pdf_html(data, filename)

    try:
        from weasyprint import HTML
        pdf_buffer = BytesIO()
        HTML(string=html_content).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        return Response(
            content=pdf_buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=cbom_report_{filename.replace('.json', '.pdf')}"},
        )
    except ImportError:
        return JSONResponse({"error": "WeasyPrint not installed. Run: pip install weasyprint"}, status_code=500)
    except Exception as e:
        logger.exception("PDF export failed")
        return JSONResponse({"error": str(e)}, status_code=500)


def generate_pdf_html(data, filename):
    """PDF ke liye HTML generate karo."""
    scan_time = data.get('scan_time', 'N/A')
    total_hosts = data.get('total_hosts', 0)
    total_findings = data.get('total_findings', 0)

    hosts_html = ""
    hosts = data.get('hosts', [])

    if not hosts and 'services' in data:
        hosts = [{
            'host': data.get('host', 'Unknown'),
            'open_ports': data.get('open_ports', []),
            'services': data.get('services', []),
        }]

    for host_data in hosts:
        host_name = host_data.get('host', 'Unknown')
        services = host_data.get('services', [])
        if not services:
            continue

        hosts_html += f'<div class="host-section"><h2>🌐 {host_name}</h2>'
        for service in services:
            protocol = service.get('protocol', 'N/A')
            target = service.get('target', 'N/A')
            tls_version = service.get('tls_version', 'N/A')
            cipher = service.get('cipher_suite')
            cipher_name = cipher[0] if isinstance(cipher, list) else str(cipher)

            hosts_html += f'''
            <div class="service">
                <h3>📡 {protocol} on {target}</h3>
                <table class="info-table">
                    <tr><td><strong>TLS Version:</strong></td><td>{tls_version}</td></tr>
                    <tr><td><strong>Cipher Suite:</strong></td><td>{cipher_name}</td></tr>
                </table>'''

            cert = service.get('certificate', {})
            if cert and isinstance(cert, dict):
                subject = cert.get('subject', {})
                issuer = cert.get('issuer', {})
                pubkey = cert.get('public_key', {})
                hosts_html += '<h4>📜 Certificate Details</h4><table class="info-table">'
                if subject.get('CN'):
                    hosts_html += f"<tr><td><strong>Subject:</strong></td><td>{subject['CN']}</td></tr>"
                if issuer.get('CN'):
                    hosts_html += f"<tr><td><strong>Issuer:</strong></td><td>{issuer['CN']}</td></tr>"
                if cert.get('not_before'):
                    hosts_html += f"<tr><td><strong>Valid From:</strong></td><td>{cert['not_before']}</td></tr>"
                if cert.get('not_after'):
                    hosts_html += f"<tr><td><strong>Valid Until:</strong></td><td>{cert['not_after']}</td></tr>"
                if cert.get('expiry_status'):
                    hosts_html += f"<tr><td><strong>Expiry Status:</strong></td><td>{cert['expiry_status']}</td></tr>"
                if pubkey.get('type'):
                    hosts_html += f"<tr><td><strong>Public Key:</strong></td><td>{pubkey['type']}-{pubkey.get('bits', '?')} bits</td></tr>"
                if cert.get('signature_algorithm'):
                    hosts_html += f"<tr><td><strong>Signature:</strong></td><td>{cert['signature_algorithm']}</td></tr>"
                hosts_html += '</table>'

            findings = service.get('findings', [])
            if findings:
                hosts_html += "<h4>🔍 Findings</h4><ul class='findings'>"
                for finding in findings:
                    risk = finding.get('risk', 'UNKNOWN')
                    algo = finding.get('algorithm', 'Unknown')
                    reason = finding.get('reason', '')
                    pqc = PQC_REPLACEMENTS.get(algo, {})
                    risk_class = 'risk-high' if risk == 'HIGH' else 'risk-medium' if risk == 'MEDIUM' else 'risk-low'

                    replacement_info = ""
                    if pqc:
                        replacement_info = f"<br><em>➡️ Recommended: {pqc['replacement']} ({pqc['standard']})</em>"

                    hosts_html += f'''
                    <li class="{risk_class}">
                        <strong>[{risk}] {algo}</strong><br>
                        <span>{reason}</span>{replacement_info}
                    </li>'''
                hosts_html += '</ul>'
            hosts_html += '</div>'
        hosts_html += '</div>'

    html = f'''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
@page {{ size: A4; margin: 2cm; @bottom-center {{ content: "CBOM Scanner Report | Page " counter(page) " of " counter(pages); font-size: 10px; color: #666; }} }}
body {{ font-family: Arial, sans-serif; color: #333; line-height: 1.6; }}
.header {{ text-align: center; padding-bottom: 20px; border-bottom: 3px solid #58a6ff; margin-bottom: 30px; }}
.header h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 10px; }}
.header p {{ color: #666; font-size: 12px; }}
.summary {{ background: #f6f8fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid #58a6ff; }}
.summary h2 {{ color: #58a6ff; margin-bottom: 15px; font-size: 18px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }}
.summary-item {{ text-align: center; padding: 15px; background: white; border-radius: 6px; }}
.summary-item .value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
.summary-item .label {{ font-size: 11px; color: #666; margin-top: 5px; }}
.host-section {{ margin-bottom: 30px; page-break-inside: avoid; }}
.host-section h2 {{ color: #58a6ff; font-size: 20px; border-bottom: 2px solid #e1e4e8; padding-bottom: 8px; margin-bottom: 15px; }}
.service {{ background: #f6f8fa; padding: 15px; border-radius: 6px; margin-bottom: 15px; }}
.service h3 {{ color: #333; font-size: 14px; margin-bottom: 10px; }}
.service h4 {{ color: #555; font-size: 13px; margin-top: 15px; margin-bottom: 8px; }}
.info-table {{ width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 10px; }}
.info-table td {{ padding: 5px 10px; border-bottom: 1px solid #e1e4e8; }}
.info-table td:first-child {{ width: 35%; color: #555; }}
.findings {{ list-style: none; padding: 0; }}
.findings li {{ padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; font-size: 11px; border-left: 4px solid #ccc; }}
.risk-high {{ background: #ffeaea; border-left-color: #f85149; }}
.risk-medium {{ background: #fff8e6; border-left-color: #f0883e; }}
.risk-low {{ background: #e8f7ec; border-left-color: #3fb950; }}
.footer {{ margin-top: 40px; padding-top: 20px; border-top: 2px solid #e1e4e8; text-align: center; font-size: 10px; color: #666; }}
</style>
</head>
<body>
<div class="header">
<h1>🔐 CBOM Scanner Report</h1>
<p>Cryptographic Bill of Materials — Post-Quantum Cryptography Migration</p>
<p>Aligned with India NQM Roadmap 2027-2028</p>
<p><strong>Scan Time:</strong> {scan_time}</p>
</div>
<div class="summary">
<h2>📊 Executive Summary</h2>
<div class="summary-grid">
<div class="summary-item"><div class="value">{total_hosts}</div><div class="label">Total Hosts</div></div>
<div class="summary-item"><div class="value">{total_findings}</div><div class="label">Total Findings</div></div>
<div class="summary-item"><div class="value">100%</div><div class="label">Quantum-Vulnerable</div></div>
</div>
</div>
<h2 style="color: #58a6ff; margin-bottom: 20px;">📋 Detailed Findings</h2>
{hosts_html}
<div class="footer">
<p><strong>Generated by CBOM Scanner v{APP_VERSION}</strong></p>
<p>© 2026 CBOM Scanner. Licensed under MIT License.</p>
<p>⚠️ This report is based on publicly available information. No unauthorized access was performed.</p>
</div>
</body>
</html>'''
    return html


# ============================================================
# ADMIN DOCS
# ============================================================

@app.get("/docs", include_in_schema=False)
async def custom_docs(username: str = Depends(verify_admin)):
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{APP_NAME} - Admin API Docs"
    )


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi(username: str = Depends(verify_admin)):
    return app.openapi()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    print("\n" + "=" * 60)
    print(f"  {APP_NAME} v{APP_VERSION}")
    print("=" * 60)
    print(f"  Web Dashboard:  http://localhost:8000")
    print(f"  Login:          http://localhost:8000/login")
    print(f"  Signup:         http://localhost:8000/signup")
    print(f"  Dashboard:      http://localhost:8000/dashboard")
    print(f"  Admin Docs:     http://localhost:8000/docs")
    print(f"  Health:         http://localhost:8000/health")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)