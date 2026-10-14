"""
CBOM Scanner - Web Dashboard (v0.7.1)
FastAPI-based web interface for CBOM Scanner.

v0.7.1 Changes:
- Fixed SQLite "database is locked" error
- Added connection timeout
- Proper connection close with try/finally
"""

import os
import sys
import json
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
from collections import Counter
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException, status, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# ============================================================
# PATH SETUP
# ============================================================

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(WEB_DIR)
SRC_DIR = os.path.join(ROOT_DIR, 'src')

sys.path.insert(0, SRC_DIR)

print(f"[DEBUG] WEB_DIR: {WEB_DIR}")
print(f"[DEBUG] ROOT_DIR: {ROOT_DIR}")
print(f"[DEBUG] SRC_DIR: {SRC_DIR}")

from scanner import scan_folder
from network_scanner import scan_host, TOP_1000_PORTS

# ============================================================
# DATABASE SETUP
# ============================================================

DB_PATH = os.path.join(ROOT_DIR, 'cbom_scanner.db')
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)


def get_db():
    """Database connection lo (timeout ke saath)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging
    return conn


def init_db():
    """Database initialize karo."""
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
        
        conn.commit()
        print(f"[INFO] Database initialized: {DB_PATH}")
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Password ko hash karo."""
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username: str, email: str, password: str) -> bool:
    """Naya user banao."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, hash_password(password))
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def verify_user(username: str, password: str) -> Optional[dict]:
    """User verify karo."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, username, email FROM users WHERE username = ? AND password_hash = ?',
            (username, hash_password(password))
        )
        user = cursor.fetchone()
        
        if user:
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user[0],)
            )
            conn.commit()
        
        if user:
            return {'id': user[0], 'username': user[1], 'email': user[2]}
        return None
    finally:
        conn.close()


def create_session(user_id: int) -> str:
    """Session token banao."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=7)
    
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


def get_user_from_session(token: str) -> Optional[dict]:
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
        user = cursor.fetchone()
        
        if user:
            return {'id': user[0], 'username': user[1], 'email': user[2]}
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


init_db()

# ============================================================
# APP SETUP
# ============================================================

app = FastAPI(
    title="CBOM Scanner",
    description="Cryptographic Bill of Materials Scanner for PQC Migration",
    version="0.7.1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

templates = Jinja2Templates(directory=os.path.join(WEB_DIR, 'templates'))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(WEB_DIR, 'static')),
    name="static"
)

# ============================================================
# BASIC AUTH (Admin)
# ============================================================

security = HTTPBasic()
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "cbom@2026"


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Admin credentials verify karo."""
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        ADMIN_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        ADMIN_PASSWORD.encode("utf8")
    )
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
    """Home page."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Scan page."""
    return templates.TemplateResponse(request=request, name="scan.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse(request=request, name="login.html")


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    """Signup page."""
    return templates.TemplateResponse(request=request, name="signup.html")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, session_token: Optional[str] = Cookie(None)):
    """Dashboard page (requires auth)."""
    user = get_user_from_session(session_token)
    if not user:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"user": user}
    )


# ============================================================
# AUTH ROUTES
# ============================================================

@app.post("/api/auth/signup")
async def api_signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    """Signup API."""
    if len(password) < 6:
        return JSONResponse({"error": "Password must be at least 6 characters"}, status_code=400)
    
    if create_user(username, email, password):
        return JSONResponse({"success": True, "message": "User created successfully"})
    else:
        return JSONResponse({"error": "Username or email already exists"}, status_code=400)


@app.post("/api/auth/login")
async def api_login(
    username: str = Form(...),
    password: str = Form(...)
):
    """Login API."""
    user = verify_user(username, password)
    
    if not user:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    
    token = create_session(user['id'])
    
    response = JSONResponse({
        "success": True,
        "message": "Login successful",
        "user": user
    })
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        max_age=7*24*60*60,
        samesite="lax"
    )
    
    return response


@app.get("/api/auth/logout")
async def api_logout(session_token: Optional[str] = Cookie(None)):
    """Logout API."""
    if session_token:
        delete_session(session_token)
    
    response = JSONResponse({"success": True, "message": "Logged out"})
    response.delete_cookie("session_token")
    return response


@app.get("/api/auth/me")
async def api_me(session_token: Optional[str] = Cookie(None)):
    """Current user info."""
    user = get_user_from_session(session_token)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse({"user": user})


# ============================================================
# SCAN API ROUTES
# ============================================================

@app.post("/api/scan/folder")
async def api_scan_folder(request: Request, folder_path: str = Form(...)):
    """Folder scan API."""
    if not folder_path or not folder_path.strip():
        return JSONResponse({"error": "Folder path is required"}, status_code=400)
    
    if not os.path.exists(folder_path):
        return JSONResponse(
            {"error": f"Path does not exist: {folder_path}"},
            status_code=400
        )
    
    try:
        results = scan_folder(folder_path)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f'web_scan_{timestamp}.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        return JSONResponse({
            "success": True,
            "scan_type": "folder",
            "folder": folder_path,
            "files_scanned": results.get('files_scanned', 0),
            "total_findings": results.get('total_findings', 0),
            "findings": results.get('findings', [])[:50],
            "report_path": report_path
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/scan/network")
async def api_scan_network(
    request: Request,
    host: str = Form(...),
    port_option: str = Form("1")
):
    """Network scan API."""
    if not host or not host.strip():
        return JSONResponse({"error": "Host is required"}, status_code=400)
    
    try:
        if port_option == "2":
            ports = TOP_1000_PORTS
        else:
            ports = [443, 22, 8443, 993, 995]
        
        results = scan_host(host, ports=ports)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(REPORTS_DIR, f'web_network_{timestamp}.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        total_findings = sum(
            len(s.get('findings', []))
            for s in results.get('services', [])
        )
        
        return JSONResponse({
            "success": True,
            "scan_type": "network",
            "host": host,
            "open_ports": results.get('open_ports', []),
            "services": results.get('services', []),
            "total_findings": total_findings,
            "report_path": report_path
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/scan/multi")
async def api_scan_multi(request: Request, file: UploadFile = File(...)):
    """Multi-host scan API."""
    try:
        content = await file.read()
        hosts = [
            line.strip()
            for line in content.decode('utf-8').split('\n')
            if line.strip() and not line.startswith('#')
        ]
        
        if not hosts:
            return JSONResponse({"error": "File is empty"}, status_code=400)
        
        results = []
        for host in hosts[:20]:
            try:
                result = scan_host(host, ports=[443, 22, 8443, 993, 995])
                results.append(result)
            except Exception as e:
                results.append({"host": host, "error": str(e)})
        
        return JSONResponse({
            "success": True,
            "scan_type": "multi",
            "total_hosts": len(results),
            "results": results
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# CHARTS DATA API
# ============================================================

@app.get("/api/charts/data")
async def api_charts_data():
    """Charts ke liye data aggregate karo."""
    stats = {
        'total_hosts': 0,
        'total_findings': 0,
        'tls_versions': Counter(),
        'algorithms': Counter(),
        'issuers': Counter(),
        'public_key_types': Counter(),
        'expiry_status': Counter()
    }
    
    if not os.path.exists(REPORTS_DIR):
        return JSONResponse({
            'total_hosts': 0, 'total_findings': 0,
            'tls_versions': {}, 'algorithms': {},
            'issuers': {}, 'public_key_types': {}, 'expiry_status': {}
        })
    
    for file in os.listdir(REPORTS_DIR):
        if not file.endswith('.json'):
            continue
        
        try:
            with open(os.path.join(REPORTS_DIR, file), 'r', encoding='utf-8') as f:
                data = json.load(f)
        except:
            continue
        
        if 'hosts' in data:
            for host in data['hosts']:
                stats['total_hosts'] += 1
                for service in host.get('services', []):
                    if service.get('tls_version'):
                        stats['tls_versions'][service['tls_version']] += 1
                    
                    cert = service.get('certificate', {})
                    if cert and isinstance(cert, dict):
                        if cert.get('issuer', {}).get('CN'):
                            stats['issuers'][cert['issuer']['CN']] += 1
                        if cert.get('public_key', {}).get('type'):
                            key_type = f"{cert['public_key']['type']}-{cert['public_key'].get('bits', '?')}"
                            stats['public_key_types'][key_type] += 1
                        if cert.get('expiry_status'):
                            stats['expiry_status'][cert['expiry_status']] += 1
                    
                    for finding in service.get('findings', []):
                        stats['algorithms'][finding.get('algorithm', 'Unknown')] += 1
                        stats['total_findings'] += 1
        
        elif 'services' in data:
            stats['total_hosts'] += 1
            for service in data.get('services', []):
                if service.get('tls_version'):
                    stats['tls_versions'][service['tls_version']] += 1
                
                cert = service.get('certificate', {})
                if cert and isinstance(cert, dict):
                    if cert.get('issuer', {}).get('CN'):
                        stats['issuers'][cert['issuer']['CN']] += 1
                    if cert.get('public_key', {}).get('type'):
                        key_type = f"{cert['public_key']['type']}-{cert['public_key'].get('bits', '?')}"
                        stats['public_key_types'][key_type] += 1
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
        'expiry_status': dict(stats['expiry_status'])
    })


# ============================================================
# REPORT ROUTES
# ============================================================

@app.get("/api/reports")
async def list_reports():
    """List all reports."""
    reports = []
    if os.path.exists(REPORTS_DIR):
        for file in os.listdir(REPORTS_DIR):
            if file.endswith('.json'):
                filepath = os.path.join(REPORTS_DIR, file)
                reports.append({
                    'name': file,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).isoformat()
                })
    
    return JSONResponse({
        "reports": sorted(
            reports,
            key=lambda x: x['modified'],
            reverse=True
        )
    })


@app.get("/api/report/{filename}")
async def get_report(filename: str):
    """Get specific report."""
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return JSONResponse({"error": "Report not found"}, status_code=404)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return JSONResponse(data)


# ============================================================
# ADMIN DOCS
# ============================================================

@app.get("/docs", include_in_schema=False)
async def custom_docs(username: str = Depends(verify_admin)):
    """Custom Swagger UI with admin auth."""
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="CBOM Scanner - Admin API Docs"
    )


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi(username: str = Depends(verify_admin)):
    """OpenAPI schema with admin auth."""
    return app.openapi()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("CBOM SCANNER - WEB DASHBOARD v0.7.1")
    print("=" * 60)
    print(f"Web Dashboard:  http://localhost:8000")
    print(f"Login:          http://localhost:8000/login")
    print(f"Signup:         http://localhost:8000/signup")
    print(f"Dashboard:      http://localhost:8000/dashboard")
    print(f"Admin Docs:     http://localhost:8000/docs")
    print(f"Admin Login:    {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)