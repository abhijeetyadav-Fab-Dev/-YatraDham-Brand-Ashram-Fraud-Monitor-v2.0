"""
YatraDham Brand & Ashram Fraud Monitor — Production FastAPI Backend Server.
Provides REST APIs for real-time scanning, automated sweep orchestration,
forensic enrichment, takedown generation, and verified registry management.
"""
import asyncio
import csv
import io
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure local imports work
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.models import FraudFinding, ThreatCategory, RiskBand, EvidenceItem
from core.entity_cross_reference import EntityCrossReferencer
from core.enrichment import ForensicEnricher
from core.scorer import FraudRiskScorer
from core.detector_engine import DetectionEngine
from core.takedown_generator import TakedownGenerator
from core.notifier import AlertDispatcher
from run_sweep import FraudSweepRunner, FINDINGS_PATH, DATA_DIR

# ---------------------------------------------------------------------------
# Server Runtime State & Diagnostics
# ---------------------------------------------------------------------------
SERVER_START_TIME = time.time()
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("yatradham-fraud-monitor")

def get_memory_info() -> Dict[str, float]:
    """Measures process working set and virtual memory portably on Windows and Linux/Render."""
    res = {"rss_mb": 0.0, "vms_mb": 0.0}
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes
            class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
                _fields_ = [
                    ('cb', wintypes.DWORD),
                    ('PageFaultCount', wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t),
                    ('PrivateUsage', ctypes.c_size_t),
                ]
            GetProcessMemoryInfo = ctypes.windll.psapi.GetProcessMemoryInfo
            GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
            GetProcessMemoryInfo.restype = wintypes.BOOL
            counters = PROCESS_MEMORY_COUNTERS_EX()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                res["rss_mb"] = round(counters.WorkingSetSize / (1024 * 1024), 2)
                res["vms_mb"] = round(counters.PagefileUsage / (1024 * 1024), 2)
        elif os.path.exists("/proc/self/status"):
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        res["rss_mb"] = round(int(line.split()[1]) / 1024, 2)
                    elif line.startswith("VmSize:"):
                        res["vms_mb"] = round(int(line.split()[1]) / 1024, 2)
    except Exception:
        pass
    return res

def test_network_connectivity() -> Dict[str, Any]:
    """Tests egress DNS resolution and target reachability."""
    import socket
    dns_ok = False
    try:
        socket.gethostbyname("google.com")
        dns_ok = True
    except Exception:
        dns_ok = False
    return {
        "dns_resolution": dns_ok,
        "crt_sh_endpoint": "https://crt.sh",
        "ncrp_portal_endpoint": "https://cybercrime.gov.in"
    }

app = FastAPI(
    title="YatraDham Brand & Ashram Fraud Monitor API",
    description="Live Cyber Threat Intelligence and Fraud Prevention API for Dharamshalas and Ashrams — Initiative from YatraDham.Org",
    version="2.0.0",
    debug=DEBUG_MODE
)

# Enable CORS for external dashboards / integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global State & Sweep Orchestration
# ---------------------------------------------------------------------------
runner = FraudSweepRunner()

sweep_state = {
    "status": "idle",             # "idle" | "running" | "completed" | "error"
    "progress_percent": 0,
    "current_step": "System Ready",
    "started_at": None,
    "finished_at": None,
    "duration_s": 0.0,
    "last_error": None,
    "mode": None
}
sweep_lock = threading.Lock()

def background_sweep_worker(quick: bool):
    global sweep_state
    try:
        with sweep_lock:
            sweep_state["status"] = "running"
            sweep_state["progress_percent"] = 10
            sweep_state["current_step"] = "Initializing detector & loading verified registry..."
            sweep_state["started_at"] = datetime.now(timezone.utc).isoformat()
            sweep_state["mode"] = "quick" if quick else "full"
            sweep_state["last_error"] = None

        time.sleep(1.0)
        with sweep_lock:
            sweep_state["progress_percent"] = 30
            sweep_state["current_step"] = "Running multi-channel sweeps (DNS, crt.sh, open web)..."

        # Execute actual sweep
        payload = runner.run_sweep(quick=quick)

        with sweep_lock:
            sweep_state["status"] = "completed"
            sweep_state["progress_percent"] = 100
            sweep_state["current_step"] = f"Completed sweep on {payload.get('hosts_examined', 0)} hosts"
            sweep_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            sweep_state["duration_s"] = payload.get("duration_s", 0)

    except Exception as e:
        with sweep_lock:
            sweep_state["status"] = "error"
            sweep_state["last_error"] = str(e)
            sweep_state["current_step"] = f"Error: {e}"

# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., description="Suspect URL, domain, phone number, WhatsApp link, or UPI handle")
    debug: Optional[bool] = Field(default=False, description="Whether to include detailed step-by-step diagnostic trace in response")

class DebugToggleRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable deep debug diagnostics")

class AddInstitutionRequest(BaseModel):
    id: str
    name: str
    city: str
    state: str
    category: str = "Dharamshala"
    official_website: str
    verified_phones: List[str]
    verified_emails: List[str] = []
    payment_policy: str
    vulnerability_level: str = "HIGH"
    keywords: List[str] = []

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", tags=["System"])
def get_health():
    """Returns server operational health, active engine status, and sweep metadata."""
    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    return {
        "status": "healthy",
        "service": "YatraDham Brand & Ashram Fraud Monitor",
        "framework": "Initiative from YatraDham.Org",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
        "debug_mode": DEBUG_MODE,
        "render_detected": is_render,
        "verified_institutions_loaded": len(runner.ecr.institutions),
        "active_records_cached": len(runner.history),
        "sweep_status": sweep_state["status"]
    }

@app.get("/api/debug/system", tags=["Debugging & Diagnostics"])
def get_debug_system_info():
    """Returns deep internal system diagnostics, memory usage, threads, and environment flags."""
    global DEBUG_MODE
    findings_count = 0
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                findings_count = len(json.load(f).get("findings", []))
        except Exception:
            pass

    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    return {
        "debug_mode": DEBUG_MODE,
        "server_uptime_seconds": round(time.time() - SERVER_START_TIME, 2),
        "system": {
            "python_version": sys.version,
            "platform": sys.platform,
            "pid": os.getpid(),
            "active_threads": threading.active_count(),
            "thread_names": [t.name for t in threading.enumerate()],
            "memory": get_memory_info()
        },
        "environment": {
            "is_render": is_render,
            "render_service_id": os.environ.get("RENDER_SERVICE_ID", "local"),
            "port": os.environ.get("PORT", "8090"),
            "host": os.environ.get("HOST", "0.0.0.0" if is_render else "127.0.0.1"),
            "debug_env": os.environ.get("DEBUG", "false")
        },
        "storage": {
            "findings_path": FINDINGS_PATH,
            "findings_exists": os.path.exists(FINDINGS_PATH),
            "findings_size_bytes": os.path.getsize(FINDINGS_PATH) if os.path.exists(FINDINGS_PATH) else 0,
            "cached_findings_count": findings_count,
            "data_directory": DATA_DIR,
            "verified_institutions_count": len(runner.ecr.institutions)
        },
        "network": test_network_connectivity()
    }

@app.post("/api/debug/toggle", tags=["Debugging & Diagnostics"])
def toggle_debug_mode(req: DebugToggleRequest):
    """Dynamically activates or deactivates Debug Mode at runtime."""
    global DEBUG_MODE
    DEBUG_MODE = req.enabled
    logging.getLogger().setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
    logger.info(f"Debug Mode toggled to: {DEBUG_MODE}")
    return {
        "status": "success",
        "debug_mode": DEBUG_MODE,
        "message": f"Debug mode is now {'ENABLED' if DEBUG_MODE else 'DISABLED'}"
    }

@app.get("/api/stats", tags=["Analytics"])
def get_stats():
    """Returns live KPI counters and threat telemetry across all channels."""
    findings = []
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
        except Exception:
            pass

    hi = [f for f in findings if f.get("risk_score", 0) >= 55 and f.get("risk_band") != "BRAND-OWNED"]
    crit = [f for f in findings if f.get("risk_score", 0) >= 75 and f.get("risk_band") != "BRAND-OWNED"]
    med = [f for f in findings if 35 <= f.get("risk_score", 0) < 55]
    low = [f for f in findings if 0 < f.get("risk_score", 0) < 35]
    owned = [f for f in findings if f.get("risk_band") == "BRAND-OWNED"]
    ashram_attacks = [f for f in findings if f.get("targeted_institution_name") and f.get("risk_score", 0) >= 35]
    phone_attacks = [f for f in findings if (f.get("page", {}).get("copied_phones") or [])]
    upi_attacks = [f for f in findings if (f.get("page", {}).get("upi_ids") or [])]

    return {
        "total_hosts_examined": len(findings),
        "critical_threats": len(crit),
        "high_risk_alerts": len(hi),
        "medium_risk_watch": len(med),
        "low_risk": len(low),
        "cleared_defensive_domains": len(owned),
        "ashram_impersonations": len(ashram_attacks),
        "fraudulent_helplines_detected": len(phone_attacks),
        "scammer_upi_handles_detected": len(upi_attacks),
        "last_sweep_timestamp": sweep_state.get("finished_at") or datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/findings", tags=["Findings"])
def list_findings(
    risk_band: Optional[str] = None,
    threat_category: Optional[str] = None,
    search: Optional[str] = None,
    min_score: int = 0,
    limit: int = 100,
    offset: int = 0
):
    """Lists scanned hosts with flexible filtering and pagination."""
    findings = []
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
        except Exception:
            pass

    # Filtering
    filtered = []
    for f in findings:
        score = f.get("risk_score", 0)
        if score < min_score:
            continue
        if risk_band and f.get("risk_band", "").upper() != risk_band.upper():
            continue
        if threat_category and f.get("threat_category", "").upper() != threat_category.upper():
            continue
        if search:
            s = search.lower()
            host = f.get("host", "").lower()
            inst = (f.get("targeted_institution_name") or "").lower()
            phones = " ".join(f.get("page", {}).get("copied_phones", [])).lower()
            upis = " ".join(f.get("page", {}).get("upi_ids", [])).lower()
            if s not in host and s not in inst and s not in phones and s not in upis:
                continue
        filtered.append(f)

    # Sort descending by score
    filtered.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "results": filtered[offset : offset + limit]
    }

@app.get("/api/findings/{host:path}", tags=["Findings"])
def get_finding_detail(host: str):
    """Retrieves full forensic attribution, signals, and takedown packet for a specific host."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("findings", []):
                    if item.get("host", "").lower() == clean_host:
                        return item
        except Exception:
            pass

    # If not in cache, inspect live
    live_finding = runner.inspect_single_host(clean_host)
    return live_finding.to_dict()

@app.post("/api/scan", tags=["Live Scanning"])
def scan_target(req: ScanRequest):
    """
    On-Demand Live Forensic Inspection Endpoint.
    Analyzes any suspect URL, domain, WhatsApp link, phone, or UPI handle in real time.
    Supports detailed deep diagnostic trace when debug=True or when server DEBUG_MODE is active.
    """
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    include_debug = req.debug or DEBUG_MODE
    t0 = time.perf_counter()

    finding = runner.inspect_single_host(target)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    resp = {
        "status": "success",
        "target": target,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "finding": finding.to_dict()
    }

    if include_debug:
        resp["debug_trace"] = {
            "inspection_time_ms": elapsed_ms,
            "resolved_ip": finding.ip,
            "dns_host_info": finding.host_info.__dict__ if hasattr(finding.host_info, "__dict__") else finding.host_info,
            "rdap_registrar": finding.whois.registrar if hasattr(finding.whois, "registrar") else "",
            "crawler_reachable": finding.page.reachable if hasattr(finding.page, "reachable") else False,
            "crawler_status_code": getattr(finding.page, "status_code", None),
            "matched_institution": finding.targeted_institution_name,
            "risk_reasons_count": len(finding.risk_reasons),
            "risk_reasons": finding.risk_reasons,
            "raw_score": finding.risk_score,
            "assigned_band": finding.risk_band.value if hasattr(finding.risk_band, "value") else str(finding.risk_band)
        }

    return resp

@app.post("/api/sweep/trigger", tags=["Sweep Management"])
def trigger_sweep(quick: bool = False, background_tasks: BackgroundTasks = BackgroundTasks()):
    """Triggers an automated multi-channel sweep in a background worker."""
    global sweep_state
    if sweep_state["status"] == "running":
        return {
            "status": "already_running",
            "message": "A sweep is currently in progress",
            "sweep_state": sweep_state
        }

    t = threading.Thread(target=background_sweep_worker, args=(quick,))
    t.daemon = True
    t.start()

    return {
        "status": "started",
        "mode": "quick" if quick else "full",
        "message": "Sweep initiated successfully in background"
    }

@app.get("/api/sweep/status", tags=["Sweep Management"])
def get_sweep_status():
    """Returns live progress percentage and status of the current or last sweep."""
    return sweep_state

@app.get("/api/institutions", tags=["Registry"])
def list_institutions():
    """Returns official verified Dharamshalas and Ashrams (Ground Truth Directory)."""
    return {
        "total": len(runner.ecr.institutions),
        "brand": runner.ecr.brand_data,
        "institutions": runner.ecr.institutions
    }

@app.post("/api/institutions", tags=["Registry"])
def add_institution(inst: AddInstitutionRequest):
    """Registers a new Dharamshala or Ashram in the verified ground-truth directory."""
    db_file = os.path.join(DATA_DIR, "verified_institutions.json")
    with open(db_file, "r", encoding="utf-8") as f:
        d = json.load(f)

    # Check duplicate
    for existing in d.get("institutions", []):
        if existing["id"] == inst.id:
            raise HTTPException(status_code=400, detail=f"Institution '{inst.id}' already exists")

    d["institutions"].append(inst.dict())
    with open(db_file, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

    runner.ecr.load_database()
    return {"status": "success", "message": f"Added '{inst.name}' to verified directory"}

@app.get("/api/takedown/{host:path}/packet", tags=["Takedown"])
def get_takedown_packet(host: str):
    """Returns formatted legal filing packets (NCRP CyberCrime, Police Memo, Registrar, NPCI)."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
    finding_data = None
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("findings", []):
                    if item.get("host", "").lower() == clean_host:
                        finding_data = item
                        break
        except Exception:
            pass

    if not finding_data:
        finding_data = runner.inspect_single_host(clean_host).to_dict()

    return {
        "host": clean_host,
        "target_institution": finding_data.get("targeted_institution_name"),
        "risk_score": finding_data.get("risk_score"),
        "takedown": finding_data.get("takedown", {})
    }

@app.get("/api/export/csv", tags=["Export"])
def export_csv():
    """Generates and streams a forensic CSV report for Law Enforcement."""
    findings = []
    if os.path.exists(FINDINGS_PATH):
        try:
            with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
        except Exception:
            pass

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Host", "Risk Score", "Risk Band", "Targeted Entity",
        "Server IP", "Hosting Provider", "ASN", "Country",
        "Registrar", "Registered On", "Scammer Helplines", "Scammer UPIs",
        "Detected Via", "Key Triggers"
    ])

    for f in findings:
        h = f.get("host_info", {})
        w = f.get("whois", {})
        p = f.get("page", {})
        writer.writerow([
            f.get("host"),
            f.get("risk_score"),
            f.get("risk_band"),
            f.get("targeted_institution_name", "General"),
            f.get("ip"),
            h.get("hosting_provider"),
            h.get("asn"),
            h.get("host_country"),
            w.get("registrar"),
            (w.get("created") or "")[:10],
            "; ".join(p.get("copied_phones", [])),
            "; ".join(p.get("upi_ids", [])),
            ", ".join(f.get("sources", [])),
            " | ".join(f.get("risk_reasons", []))
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=yatradham_fraud_findings.csv"}
    )

@app.get("/api/export/json", tags=["Export"])
def export_json():
    """Streams full JSON database."""
    if os.path.exists(FINDINGS_PATH):
        with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content=content, media_type="application/json")
    return JSONResponse(content={"findings": []})

# ---------------------------------------------------------------------------
# Mount Static Dashboard & UI Route
# ---------------------------------------------------------------------------
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

@app.get("/", response_class=HTMLResponse, tags=["Dashboard UI"])
def serve_dashboard():
    """Serves the live interactive dashboard UI."""
    index_file = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard index.html not found</h1>"

@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon():
    """Serves the project favicon directly."""
    fav_path = os.path.join(DASHBOARD_DIR, "favicon.ico")
    if os.path.exists(fav_path):
        return FileResponse(fav_path)
    return Response(status_code=204)

def find_available_port(start_port: int = 8090, max_attempts: int = 20) -> int:
    import socket
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start_port

if __name__ == "__main__":
    is_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    default_host = "0.0.0.0" if is_render else "127.0.0.1"
    host = os.environ.get("HOST", default_host)
    requested_port = int(os.environ.get("PORT", 8090))

    if is_render or host == "0.0.0.0":
        port = requested_port
    else:
        port = find_available_port(requested_port)
        if port != requested_port:
            logger.warning(f"Port {requested_port} is currently in use. Auto-switched to available port {port}.")

    print(f"\n==================================================================")
    print(f"🛡️ YatraDham Brand & Ashram Fraud Monitor Server v2.0")
    print(f"📡 API Docs: http://{host}:{port}/docs")
    print(f"🖥️ Live Dashboard: http://{host}:{port}/")
    print(f"🐞 Debug Mode: {'ENABLED' if DEBUG_MODE else 'DISABLED'}")
    print(f"☁️ Cloud Host: {'Render.com Container' if is_render else 'Local Server'}")
    print(f"==================================================================\n")
    uvicorn.run("server:app", host=host, port=port, reload=(not is_render and DEBUG_MODE))
