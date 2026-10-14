"""
CBOM Scanner - Web Dashboard (v0.5.2)
FastAPI-based web interface for CBOM Scanner.

v0.5.2 Changes:
- Fixed TemplateResponse syntax for new Starlette versions
- Added debug paths for troubleshooting
"""

import os
import sys
import json
from datetime import datetime
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ============================================================
# PATH SETUP
# ============================================================

# Get absolute paths
WEB_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(WEB_DIR)
SRC_DIR = os.path.join(ROOT_DIR, 'src')

# Add src folder to path
sys.path.insert(0, SRC_DIR)

# Debug: Print paths
print(f"[DEBUG] WEB_DIR: {WEB_DIR}")
print(f"[DEBUG] ROOT_DIR: {ROOT_DIR}")
print(f"[DEBUG] SRC_DIR: {SRC_DIR}")
print(f"[DEBUG] SRC files: {os.listdir(SRC_DIR) if os.path.exists(SRC_DIR) else 'NOT FOUND'}")

# Import scanner modules
from scanner import scan_folder
from network_scanner import scan_host, TOP_1000_PORTS

# ============================================================
# APP SETUP
# ============================================================

app = FastAPI(
    title="CBOM Scanner",
    description="Cryptographic Bill of Materials Scanner for PQC Migration",
    version="0.5.2"
)

# Setup templates and static files (using absolute paths)
templates = Jinja2Templates(directory=os.path.join(WEB_DIR, 'templates'))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(WEB_DIR, 'static')),
    name="static"
)

# Reports directory
REPORTS_DIR = os.path.join(ROOT_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)


# ============================================================
# PAGE ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page."""
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Scan page."""
    return templates.TemplateResponse(
        request=request,
        name="scan.html"
    )


# ============================================================
# API ROUTES
# ============================================================

@app.post("/api/scan/folder")
async def api_scan_folder(request: Request, folder_path: str = Form(...)):
    """Folder scan API."""
    if not os.path.exists(folder_path):
        return JSONResponse(
            {"error": f"Path does not exist: {folder_path}"},
            status_code=400
        )
    
    try:
        results = scan_folder(folder_path)
        
        # Save report
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
    if not host:
        return JSONResponse({"error": "Host is required"}, status_code=400)
    
    try:
        # Determine ports
        if port_option == "2":
            ports = TOP_1000_PORTS
        else:
            ports = [443, 22, 8443, 993, 995]
        
        results = scan_host(host, ports=ports)
        
        # Save report
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
        for host in hosts[:20]:  # Limit to 20 for MVP
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
# MAIN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)